#!/usr/bin/env python3
"""Collect a ranked snapshot of .au email-authentication DNS records."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = 1
TRANCO_TOP_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/download/{list_id}/{limit}"
USER_AGENT = "au-mail-auth-observatory/1.0"
DNS_TIMEOUT_SECONDS = 2.0
DNS_RETRIES = 1
DOMAIN_DELAY_SECONDS = 0.15
MISSING_MARKERS = (
    "does not exist",
    "doesn't exist",
    "not found",
    "no answer",
    "no record",
    "no records",
    "nxdomain",
)
INVALID_MARKERS = (
    "invalid",
    "syntax",
    "multiple spf",
    "multiple dmarc",
    "too many dns",
    "too many lookup",
    "include loop",
    "redirect loop",
)
TRANSIENT_MARKERS = (
    "timeout",
    "timed out",
    "servfail",
    "no nameserver",
    "connection refused",
    "temporary failure",
    "network is unreachable",
)
OUTCOME_LABELS = {
    "pass": "Pass (+all)",
    "fail": "Hard fail (-all)",
    "softfail": "Softfail (~all)",
    "neutral": "Neutral (?all)",
}


class ScanError(RuntimeError):
    """Raised when a source list or snapshot cannot be trusted."""


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def is_au_domain(domain: str) -> bool:
    """Match an .au suffix at a DNS label boundary; do not collapse subdomains."""
    value = normalize_domain(domain)
    return value.endswith(".au") and value != "au"


def parse_ranked_csv(content: str, rank_limit: int) -> list[dict[str, Any]]:
    """Parse Tranco's rank,domain CSV and require a complete requested prefix."""
    if rank_limit < 1:
        raise ValueError("rank_limit must be greater than zero")

    entries: list[dict[str, Any]] = []
    seen_ranks: set[int] = set()
    for row in csv.reader(io.StringIO(content)):
        if len(row) < 2:
            continue
        try:
            rank = int(row[0].strip())
        except ValueError:
            # The downloadable Tranco CSV may include a header.
            continue
        if rank < 1 or rank > rank_limit:
            continue
        domain = normalize_domain(row[1])
        if not domain:
            continue
        if rank in seen_ranks:
            raise ScanError(f"Tranco list contains duplicate rank {rank}")
        seen_ranks.add(rank)
        entries.append({"rank": rank, "domain": domain})

    if len(entries) < rank_limit:
        raise ScanError(
            f"Tranco returned {len(entries)} ranked entries; expected at least {rank_limit}"
        )
    entries.sort(key=lambda item: item["rank"])
    return entries


def _csv_bytes_from_download(payload: bytes) -> bytes:
    buffer = io.BytesIO(payload)
    if not zipfile.is_zipfile(buffer):
        return payload

    buffer.seek(0)
    with zipfile.ZipFile(buffer) as archive:
        candidates = [name for name in archive.namelist() if name.lower().endswith(".csv")]
        if not candidates:
            raise ScanError("Tranco download is a ZIP file without a CSV member")
        return archive.read(sorted(candidates)[0])


def _http_get(url: str, timeout: float = 45.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError) as error:
        raise ScanError(f"Failed to download {url}: {error}") from error


def fetch_tranco(rank_limit: int = 1_000_000) -> tuple[str, list[dict[str, Any]]]:
    raw_id = _http_get(TRANCO_TOP_ID_URL).decode("utf-8-sig").strip()
    list_id = raw_id.splitlines()[0].strip() if raw_id else ""
    if not re.fullmatch(r"[A-Za-z0-9]{4,20}", list_id):
        raise ScanError(f"Tranco returned an unexpected list ID: {list_id!r}")

    url = TRANCO_DOWNLOAD_URL.format(list_id=list_id, limit=rank_limit)
    csv_bytes = _csv_bytes_from_download(_http_get(url))
    try:
        csv_text = csv_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ScanError("Tranco CSV is not UTF-8") from error
    return list_id, parse_ranked_csv(csv_text, rank_limit)


def json_safe(value: Any) -> Any:
    """Convert checkdmarc result objects to plain JSON-safe values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, BaseException):
        return f"{type(value).__name__}: {value}"
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if is_dataclass(value):
        return json_safe(asdict(value))
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if hasattr(value, "items"):
        try:
            return {str(key): json_safe(item) for key, item in value.items()}
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return json_safe(vars(value))
    return str(value)


def classify_record(section: Any) -> str:
    """Classify a DNS check without treating transient errors as absence."""
    if not isinstance(section, Mapping):
        return "lookup_error"

    record = section.get("record")
    if isinstance(record, str) and record.strip():
        error_text = str(section.get("error") or "").lower()
        if any(marker in error_text for marker in TRANSIENT_MARKERS):
            return "lookup_error"
        return "present_valid" if section.get("valid") is not False else "present_invalid"

    error = str(section.get("error") or "").strip()
    lowered = error.lower()
    if any(marker in lowered for marker in TRANSIENT_MARKERS):
        return "lookup_error"
    if any(marker in lowered for marker in INVALID_MARKERS):
        return "present_invalid"
    if any(marker in lowered for marker in MISSING_MARKERS):
        return "absent"
    if error:
        return "lookup_error"

    if section.get("valid") is True:
        return "present_valid"
    return "absent"


def _all_token(record: str | None) -> str | None:
    if not record:
        return None
    for token in record.split()[1:]:
        if re.fullmatch(r"[+?~\-]?all", token, flags=re.IGNORECASE):
            return token.lower()
    return None


def _spf_outcome(token: str | None, parsed: Mapping[str, Any] | None = None) -> str:
    if token:
        qualifier = token[:-3]
        return {"+": "pass", "": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(
            qualifier, "unknown"
        )
    if isinstance(parsed, Mapping):
        return str(parsed.get("all") or "neutral").lower()
    return "neutral"


def effective_spf_terminal(
    record: str | None,
    parsed: Any,
    depth: int = 0,
) -> dict[str, Any]:
    """Return the effective SPF default marker, following RFC 7208 redirect only."""
    safe_parsed = parsed if isinstance(parsed, Mapping) else {}
    token = _all_token(record)
    if token:
        outcome = _spf_outcome(token, safe_parsed)
        return {
            "token": token,
            "outcome": outcome,
            "label": OUTCOME_LABELS.get(outcome, outcome.title()),
            "redirect_domain": None,
            "implicit": False,
        }

    redirect = safe_parsed.get("redirect")
    if isinstance(redirect, Mapping) and depth < 12:
        target = normalize_domain(str(redirect.get("domain") or "")) or None
        nested = effective_spf_terminal(
            redirect.get("record"), redirect.get("parsed"), depth + 1
        )
        return {
            **nested,
            "redirect_domain": target or nested.get("redirect_domain"),
            "implicit": nested.get("implicit", True),
        }

    # checkdmarc resolves redirect= and writes the resulting default to parsed.all.
    if redirect:
        outcome = _spf_outcome(None, safe_parsed)
        return {
            "token": None,
            "outcome": outcome,
            "label": f"Redirected · {OUTCOME_LABELS.get(outcome, outcome.title())}",
            "redirect_domain": normalize_domain(str(redirect.get("domain") or "")) or None,
            "implicit": True,
        }

    return {
        "token": None,
        "outcome": "neutral",
        "label": "Implicit neutral (no all or redirect)",
        "redirect_domain": None,
        "implicit": True,
    }


def _spf_targets(parsed: Any, depth: int = 0) -> list[str]:
    if not isinstance(parsed, Mapping) or depth > 12:
        return []
    found: list[str] = []
    for mechanism in parsed.get("mechanisms", []) or []:
        if not isinstance(mechanism, Mapping):
            continue
        name = str(mechanism.get("mechanism") or "").lower()
        value = normalize_domain(str(mechanism.get("value") or ""))
        if name == "include" and value:
            found.append(value)
        found.extend(_spf_targets(mechanism.get("parsed"), depth + 1))
    redirect = parsed.get("redirect")
    if isinstance(redirect, Mapping):
        target = normalize_domain(str(redirect.get("domain") or ""))
        if target:
            found.append(target)
        found.extend(_spf_targets(redirect.get("parsed"), depth + 1))
    return list(dict.fromkeys(found))


def _root_mechanisms(parsed: Any) -> list[dict[str, Any]]:
    if not isinstance(parsed, Mapping):
        return []
    result: list[dict[str, Any]] = []
    for item in parsed.get("mechanisms", []) or []:
        if isinstance(item, Mapping):
            result.append(
                {
                    "mechanism": item.get("mechanism"),
                    "action": item.get("action"),
                    "value": item.get("value"),
                }
            )
    return result


def _section_warnings(section: Any) -> list[str]:
    if not isinstance(section, Mapping):
        return []
    warnings = section.get("warnings") or []
    if isinstance(warnings, str):
        return [warnings]
    return [str(item) for item in warnings]


def _report_destinations(tags: Any) -> list[str]:
    if not isinstance(tags, Mapping):
        return []
    values: list[Any] = []
    for tag in ("rua", "ruf"):
        item = tags.get(tag)
        if isinstance(item, Mapping):
            item = item.get("value")
        if isinstance(item, (str, list, tuple)):
            values.extend(item if isinstance(item, (list, tuple)) else [item])

    destinations: list[str] = []
    for item in values:
        if isinstance(item, Mapping):
            uri = item.get("uri") or item.get("address") or item.get("value")
        else:
            uri = item
        if not isinstance(uri, str):
            continue
        for raw_uri in uri.split(","):
            candidate = raw_uri.strip().split("!", 1)[0]
            candidate = re.sub(r"^mailto:", "", candidate, flags=re.IGNORECASE)
            if "@" in candidate:
                host = candidate.rsplit("@", 1)[1]
            else:
                host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", candidate, flags=re.IGNORECASE)
                host = host.split("/", 1)[0].split(":", 1)[0]
            host = normalize_domain(host)
            if host and "." in host:
                destinations.append(host)
    return list(dict.fromkeys(destinations))


def _tag_value(tags: Any, name: str) -> Any:
    if not isinstance(tags, Mapping):
        return None
    item = tags.get(name)
    return item.get("value") if isinstance(item, Mapping) else item


def _tag_explicit(tags: Any, name: str) -> bool | None:
    if not isinstance(tags, Mapping):
        return None
    item = tags.get(name)
    return bool(item.get("explicit")) if isinstance(item, Mapping) and "explicit" in item else None


def _domain_location(location: Any) -> str | None:
    if not isinstance(location, str) or not location:
        return None
    value = normalize_domain(location)
    if value.startswith("_dmarc."):
        value = value[len("_dmarc.") :]
    return value or None


def _mx_hosts(mx: Any) -> list[dict[str, Any]]:
    if not isinstance(mx, Mapping):
        return []
    hosts = mx.get("hosts") or []
    result: list[dict[str, Any]] = []
    for host in hosts:
        if not isinstance(host, Mapping):
            continue
        hostname = normalize_domain(str(host.get("hostname") or ""))
        if hostname == ".":
            hostname = ""
        result.append(
            {
                "preference": host.get("preference"),
                "hostname": hostname or ".",
                "addresses": host.get("addresses") or [],
                "dnssec": host.get("dnssec"),
            }
        )
    return result


def _host_matches(host: str, suffix: str) -> bool:
    host_value = normalize_domain(host)
    suffix_value = normalize_domain(suffix)
    return bool(host_value and suffix_value and (host_value == suffix_value or host_value.endswith("." + suffix_value)))


def infer_provider_clues(
    spf_targets: list[str],
    mx_hosts: list[dict[str, Any]],
    report_hosts: list[str],
    catalog: Mapping[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    providers = catalog.get("providers", []) if isinstance(catalog, Mapping) else []
    result: dict[str, list[dict[str, Any]]] = {"outbound": [], "inbound": [], "reporting": []}
    source_hosts = {
        "outbound": spf_targets,
        "inbound": [str(item.get("hostname") or "") for item in mx_hosts],
        "reporting": report_hosts,
    }

    for role, hosts in source_hosts.items():
        matches: dict[str, dict[str, Any]] = {}
        for host in filter(None, (normalize_domain(value) for value in hosts)):
            best: tuple[int, str] | None = None
            for provider in providers:
                if not isinstance(provider, Mapping):
                    continue
                for suffix in provider.get(role, []) or []:
                    suffix_text = normalize_domain(str(suffix))
                    if _host_matches(host, suffix_text):
                        candidate = (len(suffix_text), str(provider.get("name") or "Unknown"))
                        if best is None or candidate[0] > best[0]:
                            best = candidate
            name = best[1] if best else "Unclassified"
            entry = matches.setdefault(name, {"name": name, "observed_hosts": []})
            if host not in entry["observed_hosts"]:
                entry["observed_hosts"].append(host)
        result[role] = list(matches.values())
    return result


def normalize_domain_result(
    domain: str,
    rank: int,
    raw_result: Any,
    provider_catalog: Mapping[str, Any] | None = None,
    collection_error: str | None = None,
) -> dict[str, Any]:
    result = json_safe(raw_result)
    if not isinstance(result, Mapping):
        result = {}

    spf = result.get("spf")
    dmarc = result.get("dmarc")
    mx = result.get("mx")
    mta_sts = result.get("mta_sts")
    tls_report = result.get("smtp_tls_reporting") or result.get("tls_rpt")

    if collection_error:
        failure = {"valid": False, "error": collection_error}
        spf = spf or failure
        dmarc = dmarc or failure
        mx = mx or failure

    spf_map = spf if isinstance(spf, Mapping) else {}
    spf_status = classify_record(spf_map)
    spf_record = spf_map.get("record")
    spf_parsed = spf_map.get("parsed") if isinstance(spf_map.get("parsed"), Mapping) else {}
    terminal = effective_spf_terminal(
        str(spf_record) if spf_record else None,
        spf_parsed,
    )
    spf_targets = _spf_targets(spf_parsed)
    spf_data = {
        "status": spf_status,
        "record": spf_record,
        "valid": True if spf_status == "present_valid" else False if spf_status == "present_invalid" else None,
        "error": str(spf_map.get("error")) if spf_map.get("error") else None,
        "dns_lookups": spf_map.get("dns_lookups"),
        "void_dns_lookups": spf_map.get("void_dns_lookups"),
        "terminal": terminal if spf_status.startswith("present_") else None,
        "mechanisms": _root_mechanisms(spf_parsed),
        "service_targets": spf_targets,
        "warnings": _section_warnings(spf_map),
    }

    dmarc_map = dmarc if isinstance(dmarc, Mapping) else {}
    dmarc_status = classify_record(dmarc_map)
    dmarc_record = dmarc_map.get("record")
    tags = dmarc_map.get("tags")
    location = dmarc_map.get("location") or dmarc_map.get("domain")
    source_domain = _domain_location(location)
    discovery_source = (
        "direct" if source_domain == normalize_domain(domain) else "inherited"
    ) if source_domain else None
    dmarc_data = {
        "status": dmarc_status,
        "record": dmarc_record,
        "valid": True if dmarc_status == "present_valid" else False if dmarc_status == "present_invalid" else None,
        "error": str(dmarc_map.get("error")) if dmarc_map.get("error") else None,
        "location": source_domain,
        "discovery_source": discovery_source,
        "policy": {
            "p": _tag_value(tags, "p"),
            "p_explicit": _tag_explicit(tags, "p"),
            "sp": _tag_value(tags, "sp"),
            "sp_explicit": _tag_explicit(tags, "sp"),
            "np": _tag_value(tags, "np"),
            "np_explicit": _tag_explicit(tags, "np"),
        },
        "alignment": {
            "adkim": _tag_value(tags, "adkim") or "r",
            "aspf": _tag_value(tags, "aspf") or "r",
        },
        "test_mode": _tag_value(tags, "t") or "n",
        "reporting_uris": {
            "rua": _tag_value(tags, "rua"),
            "ruf": _tag_value(tags, "ruf"),
        },
        "reporting_hosts": _report_destinations(tags),
        "warnings": _section_warnings(dmarc_map),
    }

    mx_map = mx if isinstance(mx, Mapping) else {}
    mx_hosts = _mx_hosts(mx_map)
    mx_error = mx_map.get("error")
    mx_null = bool(mx_map.get("null_mx") or mx_map.get("nullmx"))
    mx_status = "present_valid" if mx_hosts or mx_null else classify_record(mx_map)
    mx_data = {
        "status": mx_status,
        "null_mx": mx_null,
        "hosts": mx_hosts,
        "error": str(mx_error) if mx_error else None,
        "warnings": _section_warnings(mx_map),
    }

    def extra_signal(section: Any) -> dict[str, Any]:
        section_map = section if isinstance(section, Mapping) else {}
        valid = section_map.get("valid")
        if valid is True:
            status = "present_valid"
        elif valid is False:
            status = classify_record(section_map)
        elif section is None:
            status = "absent"
        elif section_map.get("error"):
            status = classify_record(section_map)
        else:
            status = "absent"
        return {
            "status": status,
            "valid": valid if isinstance(valid, bool) else None,
            "record": section_map.get("record"),
            "policy": section_map.get("policy"),
            "error": str(section_map.get("error")) if section_map.get("error") else None,
            "warnings": _section_warnings(section_map),
        }

    report_hosts = dmarc_data["reporting_hosts"]
    providers = infer_provider_clues(
        spf_targets,
        mx_hosts,
        report_hosts,
        provider_catalog or {},
    )

    dnssec = result.get("dnssec")
    dnssec_data = {
        "status": "validated" if dnssec is True else "not_validated" if dnssec is False else "unknown",
        "validated": dnssec if isinstance(dnssec, bool) else None,
    }

    errors = {
        key: value
        for key, value in {
            "spf": spf_data["error"],
            "dmarc": dmarc_data["error"],
            "mx": mx_data["error"],
            "mta_sts": extra_signal(mta_sts)["error"],
            "tls_reporting": extra_signal(tls_report)["error"],
            "collection": collection_error,
        }.items()
        if value
    }
    return {
        "rank": rank,
        "domain": normalize_domain(domain),
        "spf": spf_data,
        "dmarc": dmarc_data,
        "mx": mx_data,
        "mta_sts": extra_signal(mta_sts),
        "tls_reporting": extra_signal(tls_report),
        "dnssec": dnssec_data,
        "provider_clues": providers,
        "errors": errors,
    }


def snapshot_summary(domains: list[Mapping[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {"domain_count": len(domains)}
    for family in ("spf", "dmarc", "mx", "mta_sts", "tls_reporting"):
        family_counts = {key: 0 for key in ("present_valid", "present_invalid", "absent", "lookup_error")}
        for domain in domains:
            section = domain.get(family)
            if isinstance(section, Mapping):
                status = section.get("status")
                if status in family_counts:
                    family_counts[str(status)] += 1
        summary[family] = family_counts

    spf_qualifiers: dict[str, int] = {}
    dmarc_policies: dict[str, int] = {}
    for domain in domains:
        spf = domain.get("spf")
        terminal = spf.get("terminal") if isinstance(spf, Mapping) else None
        qualifier = terminal.get("outcome") if isinstance(terminal, Mapping) else None
        if qualifier and isinstance(spf, Mapping) and spf.get("status") == "present_valid":
            spf_qualifiers[str(qualifier)] = spf_qualifiers.get(str(qualifier), 0) + 1
        dmarc = domain.get("dmarc")
        policy = dmarc.get("policy") if isinstance(dmarc, Mapping) else None
        p_value = policy.get("p") if isinstance(policy, Mapping) else None
        if p_value and isinstance(dmarc, Mapping) and dmarc.get("status") == "present_valid":
            value = str(p_value).lower()
            dmarc_policies[value] = dmarc_policies.get(value, 0) + 1
    summary["spf_qualifiers"] = spf_qualifiers
    summary["dmarc_policies"] = dmarc_policies
    return summary


def load_provider_catalog(path: Path) -> Mapping[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScanError(f"Unable to read provider catalog {path}: {error}") from error
    if not isinstance(data, Mapping):
        raise ScanError("Provider catalog must be a JSON object")
    return data


def load_index(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "latest": None, "snapshots": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScanError(f"Existing snapshot index is unreadable; preserving it: {error}") from error
    if not isinstance(value, dict) or not isinstance(value.get("snapshots"), list):
        raise ScanError("Existing snapshot index has an unexpected format; preserving it")
    if not all(isinstance(item, dict) for item in value["snapshots"]):
        raise ScanError("Existing snapshot index contains an invalid entry; preserving it")
    return value


def write_snapshot(
    output_dir: Path,
    list_id: str,
    rank_limit: int,
    ranked_domains: list[dict[str, Any]],
    checker: Callable[[str], Any],
    provider_catalog: Mapping[str, Any],
    generated_at: dt.datetime | None = None,
    delay_seconds: float = DOMAIN_DELAY_SECONDS,
) -> dict[str, Any]:
    generated_at = generated_at or dt.datetime.now(dt.timezone.utc)
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=dt.timezone.utc)
    generated_at = generated_at.astimezone(dt.timezone.utc)
    iso_time = generated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    snapshot_id = generated_at.strftime("%Y%m%dT%H%M%SZ")

    au_entries = [entry for entry in ranked_domains if is_au_domain(str(entry["domain"]))]
    if not au_entries:
        raise ScanError("The ranked source list yielded no .au entries; refusing to publish an empty snapshot")

    domains: list[dict[str, Any]] = []
    for index, entry in enumerate(au_entries):
        domain = normalize_domain(str(entry["domain"]))
        rank = int(entry["rank"])
        raw: Any = {}
        collection_error = None
        try:
            raw = checker(domain)
            if isinstance(raw, list):
                raw = raw[0] if raw else {}
        except Exception as error:  # Preserve an error row rather than dropping a ranked name.
            collection_error = f"{type(error).__name__}: {error}"
        domains.append(
            normalize_domain_result(
                domain,
                rank,
                raw,
                provider_catalog=provider_catalog,
                collection_error=collection_error,
            )
        )
        if delay_seconds > 0 and index + 1 < len(au_entries):
            time.sleep(delay_seconds)

    summary = snapshot_summary(domains)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": iso_time,
        "source": {
            "name": "Tranco",
            "list_id": list_id,
            "rank_limit": rank_limit,
            "ranked_entry_count": len(ranked_domains),
            "au_entry_count": len(au_entries),
        },
        "checker": {"name": "checkdmarc", "version": "6.0.3"},
        "summary": summary,
        "domains": domains,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    snapshots_dir = output_dir / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    index_path = output_dir / "index.json"
    index = load_index(index_path)
    snapshot_path = snapshots_dir / f"{snapshot_id}.json"
    if snapshot_path.exists():
        # Multiple manual scans in the same second are exceedingly unlikely, but
        # preserving both is preferable to silently replacing a historical scan.
        suffix = 1
        while (snapshots_dir / f"{snapshot_id}-{suffix}.json").exists():
            suffix += 1
        snapshot_path = snapshots_dir / f"{snapshot_id}-{suffix}.json"
        snapshot_id = snapshot_path.stem

    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    relative_path = f"snapshots/{snapshot_path.name}"
    entry = {
        "id": snapshot_id,
        "path": relative_path,
        "generated_at": iso_time,
        "domain_count": summary["domain_count"],
        "summary": summary,
    }
    prior = [item for item in index["snapshots"] if item.get("id") != snapshot_id]
    index["schema_version"] = SCHEMA_VERSION
    index["latest"] = relative_path
    index["snapshots"] = sorted([entry, *prior], key=lambda item: str(item.get("generated_at", "")), reverse=True)
    index_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return snapshot


def check_domain(domain: str) -> Any:
    """Run a DNS-only email posture check. SMTP probing is disabled."""
    try:
        import checkdmarc
    except ImportError as error:
        raise ScanError("checkdmarc is not installed; install requirements.txt first") from error

    nameservers = getattr(checkdmarc, "RECOMMENDED_DNS_NAMESERVERS", None)
    kwargs: dict[str, Any] = {
        "timeout": DNS_TIMEOUT_SECONDS,
        "retries": DNS_RETRIES,
        "wait": 0.0,
        "check_mx_tls": False,
        "bimi_selector": None,
    }
    if nameservers:
        kwargs["nameservers"] = nameservers
    result = checkdmarc.check_domains([domain], **kwargs)
    return result[0] if isinstance(result, list) and result else result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("site/data"))
    parser.add_argument("--rank-limit", type=int, default=1_000_000)
    parser.add_argument("--delay-seconds", type=float, default=DOMAIN_DELAY_SECONDS)
    args = parser.parse_args(argv)

    try:
        list_id, ranked = fetch_tranco(args.rank_limit)
        catalog = load_provider_catalog(Path(__file__).with_name("providers.json"))
        snapshot = write_snapshot(
            args.output_dir,
            list_id,
            args.rank_limit,
            ranked,
            check_domain,
            catalog,
            delay_seconds=args.delay_seconds,
        )
    except Exception as error:
        print(f"Collection failed: {error}", file=sys.stderr)
        return 1

    print(
        f"Saved Tranco {list_id}: {snapshot['summary']['domain_count']} .au entries "
        f"to {args.output_dir}"
    )
    print(json.dumps(snapshot["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
