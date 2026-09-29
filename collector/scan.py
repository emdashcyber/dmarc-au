#!/usr/bin/env python3
"""Collect ranked email posture and limited security.txt observations for .au names."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import gzip
import io
import json
import logging
import re
import sys
import time
import urllib.error
import urllib.request
import warnings
import zipfile
import zlib
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable

from collector.web_checks import probe_root_head, probe_security_txt


SCHEMA_VERSION = 5
SHARD_SIZE = 200
MAX_GENERATED_FILE_BYTES = 45 * 1024 * 1024
PROGRESS_INTERVAL = 25
DOMAIN_WORKERS_PER_SHARD = 4
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


class _DiagnosticCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if message and message not in self.messages:
            self.messages.append(message)


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


_WEB_EVIDENCE_KEYS = {
    "security_txt",
    "web",
    "web_dns",
    "web_provider_clues",
    "security_txt_objects",
    "certificate_objects",
    "certificates",
    "certificate_metadata",
    "homepage_body",
    "homepage_html",
    "response_body",
}


def remove_web_evidence(value: Any) -> Any:
    """Strip web response/certificate evidence recursively from raw email records."""
    if isinstance(value, Mapping):
        return {
            str(key): remove_web_evidence(item)
            for key, item in value.items()
            if str(key).lower() not in _WEB_EVIDENCE_KEYS
        }
    if isinstance(value, list):
        return [remove_web_evidence(item) for item in value]
    if isinstance(value, tuple):
        return [remove_web_evidence(item) for item in value]
    return value


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


def _tls_reporting_destinations(section: Any) -> list[str]:
    if not isinstance(section, Mapping):
        return []
    tags = section.get("tags")
    hosts = _report_destinations(tags if isinstance(tags, Mapping) else section)
    record = section.get("record")
    if isinstance(record, str):
        match = re.search(r"(?:^|;)\s*rua\s*=\s*([^;]+)", record, re.IGNORECASE)
        if match:
            hosts.extend(_report_destinations({"rua": match.group(1)}))
    return list(dict.fromkeys(hosts))


def _dnssec_mx_diagnostics(messages: Any) -> list[dict[str, Any]]:
    if not isinstance(messages, (list, tuple)):
        return []
    result: dict[str, dict[str, Any]] = {}
    for value in messages:
        message = str(value)
        lowered = message.lower()
        host = ""
        status = "unknown"
        if "could not check dnssec for " in lowered:
            tail = message[lowered.index("could not check dnssec for ") + len("could not check dnssec for ") :]
            host = tail.split(":", 1)[0].strip()
            status = "lookup_error"
        elif "publishes a dnskey record" in lowered and "no ds record" in lowered:
            host = message.split(" publishes a DNSKEY record", 1)[0].strip()
            status = "unsigned"
        elif "dnssec" in lowered and any(token in lowered for token in ("failed to validate", "signature verification failed", "chain validation failed")):
            match = re.search(r"(?:for|on)\s+([a-z0-9_.-]+)", message, re.IGNORECASE)
            host = match.group(1) if match else ""
            status = "broken"
        host = normalize_domain(host)
        if host:
            candidate = {"hostname": host, "status": status, "diagnostic": message}
            previous = result.get(host)
            priority = {"unknown": 0, "lookup_error": 1, "unsigned": 2, "broken": 3}
            if previous is None or priority[status] > priority.get(str(previous["status"]), 0):
                result[host] = candidate
    return list(result.values())


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
    rank: int | None,
    raw_result: Any,
    provider_catalog: Mapping[str, Any] | None = None,
    collection_error: str | None = None,
    rank_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = json_safe(raw_result)
    if not isinstance(result, Mapping):
        result = {}

    auxiliary: Mapping[str, Any] = {}
    if isinstance(result.get("checkdmarc"), Mapping):
        auxiliary = result
        result = result["checkdmarc"]
    if collection_error is None and auxiliary.get("email_collection_error"):
        collection_error = str(auxiliary.get("email_collection_error"))

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
    dnssec_evidence_root = auxiliary.get("dnssec_evidence") if isinstance(auxiliary, Mapping) else None
    mx_dnssec_evidence = dnssec_evidence_root.get("mx_hosts", []) if isinstance(dnssec_evidence_root, Mapping) else []
    if not isinstance(mx_dnssec_evidence, list):
        mx_dnssec_evidence = []
    mx_evidence_by_host = {
        normalize_domain(str(item.get("hostname") or "")): item
        for item in mx_dnssec_evidence
        if isinstance(item, Mapping) and item.get("hostname")
    }
    for mx_host in mx_hosts:
        host_evidence = mx_evidence_by_host.get(normalize_domain(str(mx_host.get("hostname") or "")))
        mx_host["dnssec_status"] = (
            host_evidence.get("status") if isinstance(host_evidence, Mapping)
            else "secure" if mx_host.get("dnssec") is True
            else "unknown"
        )
        mx_host["dnssec_evidence"] = (
            host_evidence.get("evidence") or host_evidence.get("diagnostic")
            if isinstance(host_evidence, Mapping) else None
        )
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
            "reporting_hosts": _tls_reporting_destinations(section),
            "error": str(section_map.get("error")) if section_map.get("error") else None,
            "warnings": _section_warnings(section_map),
        }

    report_hosts = list(dmarc_data["reporting_hosts"])
    report_hosts.extend(_tls_reporting_destinations(tls_report))
    report_hosts = list(dict.fromkeys(report_hosts))
    providers = infer_provider_clues(
        spf_targets,
        mx_hosts,
        report_hosts,
        provider_catalog or {},
    )

    dnssec = result.get("dnssec")
    dnssec_evidence = auxiliary.get("dnssec_evidence") if isinstance(auxiliary, Mapping) else None
    dnssec_evidence = dnssec_evidence if isinstance(dnssec_evidence, Mapping) else {}
    evidence_status = dnssec_evidence.get("status")
    if evidence_status in {"secure", "unsigned", "broken", "lookup_error", "unknown"}:
        dnssec_status = str(evidence_status)
    elif dnssec is True:
        dnssec_status = "secure"
    else:
        # checkdmarc's False value intentionally covers both unsigned and broken
        # chains. Without DS evidence it cannot be classified more narrowly.
        dnssec_status = "unknown"
    dnssec_validated = (
        True if dnssec_status == "secure"
        else False if dnssec_status in {"unsigned", "broken"}
        else None
    )
    dnssec_data = {
        "status": dnssec_status,
        "validated": dnssec_validated,
        "checker_validated": dnssec if isinstance(dnssec, bool) else None,
        "ds": dnssec_evidence.get("ds"),
        "dnskey": dnssec_evidence.get("dnskey"),
        "explanation": dnssec_evidence.get("explanation"),
        "mx_hosts": mx_dnssec_evidence,
    }

    nameservers = result.get("ns")
    soa = result.get("soa")
    security_txt = auxiliary.get("security_txt") if isinstance(auxiliary.get("security_txt"), Mapping) else None
    root_head = auxiliary.get("root_head") if isinstance(auxiliary.get("root_head"), Mapping) else None
    root_head_data = json_safe(root_head) if root_head else {
        "method": "HEAD",
        "path": "/",
        "state": "not_collected",
        "status_code": None,
        "final_url": None,
        "upgrades_to_https": None,
        "upgrade_state": "unknown",
        "tls_certificate": "not_observed",
        "headers": {},
        "hops": [],
    }
    security_txt_data = json_safe(security_txt) if security_txt else {
        "availability": "not_collected",
        "content_validity": "not_assessable",
        "freshness": "unknown",
        "tls_certificate": "not_observed",
        "request": {"fallback_attempted": False, "redirects_to_https": False, "cross_host_redirect": False, "attempts": []},
        "validation": {"reasons": []},
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
    rank_info = dict(rank_metadata or {})
    rank_status = rank_info.get("rank_status", "in_top_1m" if rank is not None else "outside_top_1m")
    rank_display = rank_info.get("rank_display", f"#{rank:,}" if rank is not None else ">1,000,000")
    return {
        "rank": rank,
        "rank_status": rank_status,
        "rank_display": rank_display,
        "au_rank": rank_info.get("au_rank"),
        "au_rank_total": rank_info.get("au_rank_total"),
        "last_rank": rank_info.get("last_rank", rank),
        "last_au_rank": rank_info.get("last_au_rank", rank_info.get("au_rank")),
        "last_rank_list_id": rank_info.get("last_rank_list_id"),
        "last_ranked_at": rank_info.get("last_ranked_at"),
        "first_seen_at": rank_info.get("first_seen_at"),
        "domain": normalize_domain(domain),
        "spf": spf_data,
        "dmarc": dmarc_data,
        "mx": mx_data,
        "mta_sts": extra_signal(mta_sts),
        "tls_reporting": extra_signal(tls_report),
        "dnssec": dnssec_data,
        "runtime_diagnostics": auxiliary.get("runtime_diagnostics", []) if isinstance(auxiliary, Mapping) else [],
        "nameservers": json_safe(nameservers),
        "soa": json_safe(soa),
        "provider_clues": providers,
        "root_head": root_head_data,
        "security_txt": security_txt_data,
        "errors": errors,
    }


def snapshot_summary(domains: list[Mapping[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {"domain_count": len(domains)}
    rank_counts = {"in_top_1m": 0, "outside_top_1m": 0}
    availability_counts = {key: 0 for key in ("present", "absent", "lookup_error", "http_error", "not_collected")}
    content_counts = {key: 0 for key in ("valid", "invalid", "not_assessable")}
    freshness_counts = {key: 0 for key in ("current", "expired", "unknown")}
    certificate_counts = {key: 0 for key in ("valid", "invalid", "not_observed", "error")}
    header_counts: dict[str, int] = {}
    https_redirect_count = 0
    https_response_count = 0
    root_upgrade_counts = {key: 0 for key in ("upgraded", "not_upgraded", "unknown")}
    root_head_hsts_count = 0
    root_head_header_counts: dict[str, int] = {}
    for domain in domains:
        rank_status = str(domain.get("rank_status") or "in_top_1m")
        rank_counts[rank_status] = rank_counts.get(rank_status, 0) + 1
        security_txt = domain.get("security_txt") if isinstance(domain.get("security_txt"), Mapping) else {}
        availability = str(security_txt.get("availability") or "not_collected")
        content_validity = str(security_txt.get("content_validity") or "not_assessable")
        freshness = str(security_txt.get("freshness") or "unknown")
        certificate_status = str(security_txt.get("tls_certificate") or "not_observed")
        if availability in availability_counts:
            availability_counts[availability] += 1
        if content_validity in content_counts:
            content_counts[content_validity] += 1
        if freshness in freshness_counts:
            freshness_counts[freshness] += 1
        if certificate_status in certificate_counts:
            certificate_counts[certificate_status] += 1
        request = security_txt.get("request") if isinstance(security_txt.get("request"), Mapping) else {}
        if request.get("redirects_to_https"):
            https_redirect_count += 1
        if request.get("https_response_received"):
            https_response_count += 1
        observed_headers: set[str] = set()
        for attempt in request.get("attempts", []) or []:
            if not isinstance(attempt, Mapping):
                continue
            for hop in attempt.get("hops", []) or []:
                if not isinstance(hop, Mapping):
                    continue
                headers = hop.get("headers") if isinstance(hop.get("headers"), Mapping) else {}
                observed_headers.update(str(key) for key, value in headers.items() if value)
        for header in observed_headers:
            header_counts[header] = header_counts.get(header, 0) + 1
        root_head = domain.get("root_head") if isinstance(domain.get("root_head"), Mapping) else {}
        upgrade_state = str(root_head.get("upgrade_state") or "unknown")
        if upgrade_state not in root_upgrade_counts:
            upgrade_state = "unknown"
        root_upgrade_counts[upgrade_state] += 1
        root_headers_seen: set[str] = set()
        for hop in root_head.get("hops", []) or []:
            if not isinstance(hop, Mapping):
                continue
            headers = hop.get("headers") if isinstance(hop.get("headers"), Mapping) else {}
            root_headers_seen.update(str(key) for key, value in headers.items() if value)
        if "strict-transport-security" in root_headers_seen:
            root_head_hsts_count += 1
        for header in root_headers_seen:
            root_head_header_counts[header] = root_head_header_counts.get(header, 0) + 1
    summary["rank_status"] = rank_counts
    summary["security_txt"] = availability_counts
    summary["security_txt_content_validity"] = content_counts
    summary["security_txt_freshness"] = freshness_counts
    summary["security_txt_tls_certificate"] = certificate_counts
    summary["security_txt_headers"] = header_counts
    summary["security_txt_redirects_to_https"] = https_redirect_count
    summary["security_txt_https_responses"] = https_response_count
    summary["root_head_https_upgrade"] = root_upgrade_counts
    summary["root_head_hsts_present"] = root_head_hsts_count
    summary["root_head_headers"] = root_head_header_counts
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

    dnssec_counts = {key: 0 for key in ("secure", "unsigned", "broken", "lookup_error", "unknown")}
    mx_dnssec_counts = {key: 0 for key in ("secure", "unsigned", "broken", "lookup_error", "unknown")}
    for domain in domains:
        dnssec = domain.get("dnssec")
        if isinstance(dnssec, Mapping) and dnssec.get("status") in dnssec_counts:
            dnssec_counts[str(dnssec["status"])] += 1
        mx = domain.get("mx")
        if isinstance(mx, Mapping):
            for host in mx.get("hosts", []) or []:
                if isinstance(host, Mapping) and host.get("dnssec_status") in mx_dnssec_counts:
                    mx_dnssec_counts[str(host["dnssec_status"])] += 1
    summary["dnssec"] = dnssec_counts
    summary["mx_dnssec"] = mx_dnssec_counts
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
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ScanError(
            f"Snapshot index schema {value.get('schema_version')} is incompatible with schema {SCHEMA_VERSION}; reset site/data first"
        )
    if not all(isinstance(item, dict) for item in value["snapshots"]):
        raise ScanError("Existing snapshot index contains an invalid entry; preserving it")
    return value


def field_size_report(
    value: Mapping[str, Any],
    raw_records: list[Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, int]]:
    """Estimate serialized and gzip sizes per snapshot and per-domain field."""
    report: dict[str, dict[str, int]] = {}
    for key, field_value in value.items():
        if key == "domains" and isinstance(field_value, list):
            domain_fields = sorted({
                str(field)
                for domain in field_value
                if isinstance(domain, Mapping)
                for field in domain
            })
            for field in domain_fields:
                report[f"domains.{field}"] = _serialized_size([
                    domain.get(field) for domain in field_value if isinstance(domain, Mapping)
                ])
            continue
        report[str(key)] = _serialized_size(field_value)
    if raw_records is not None:
        raw_fields = sorted({str(field) for record in raw_records for field in record})
        for field in raw_fields:
            report[f"raw.{field}"] = _serialized_size([record.get(field) for record in raw_records])
    return report


def _serialized_size(field_value: Any) -> dict[str, int]:
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
    compressor = zlib.compressobj(level=9, wbits=31)
    serialized_bytes = 0
    gzip_bytes = 0
    for chunk in encoder.iterencode(field_value):
        encoded = chunk.encode("utf-8")
        serialized_bytes += len(encoded)
        gzip_bytes += len(compressor.compress(encoded))
    gzip_bytes += len(compressor.flush())
    return {"serialized_bytes": serialized_bytes, "gzip_bytes": gzip_bytes}


def _print_size_report(
    snapshot: Mapping[str, Any],
    snapshot_path: Path,
    raw_path: Path,
    raw_records: list[Mapping[str, Any]],
) -> dict[str, dict[str, int]]:
    report = field_size_report(snapshot, raw_records)
    print("Snapshot and raw field sizes (serialized / gzip bytes):", flush=True)
    for field, sizes in sorted(report.items(), key=lambda item: item[1]["serialized_bytes"], reverse=True):
        print(f"  {field}: {sizes['serialized_bytes']:,} / {sizes['gzip_bytes']:,}", flush=True)
    print(
        f"Snapshot files: {snapshot_path.stat().st_size:,} bytes compressed JSON snapshot; "
        f"{raw_path.stat().st_size:,} bytes compressed raw archive",
        flush=True,
    )
    return report


def _query_dns(name: str, record_type: str) -> list[str]:
    try:
        import checkdmarc
        from checkdmarc.utils import query_dns
    except ImportError as error:
        raise ScanError("checkdmarc and its DNS dependencies are required") from error

    nameservers = getattr(checkdmarc, "RECOMMENDED_DNS_NAMESERVERS", None)
    values = query_dns(
        name,
        record_type,
        nameservers=nameservers,
        timeout=DNS_TIMEOUT_SECONDS,
        retries=0,
    )
    return [str(value) for value in (values or [])]


def _dns_error_status(error: BaseException) -> str:
    label = f"{type(error).__name__}: {error}".lower()
    if any(marker in label for marker in MISSING_MARKERS) or any(
        marker in label for marker in ("noanswer", "nxdomain", "nodata", "no data")
    ):
        return "absent"
    return "lookup_error"


def _query_evidence(
    name: str,
    record_type: str,
    query: Callable[[str, str], list[str]] = _query_dns,
) -> dict[str, Any]:
    try:
        records = query(name, record_type)
        return {"status": "present" if records else "absent", "records": records, "error": None}
    except Exception as error:
        return {
            "status": _dns_error_status(error),
            "records": [],
            "error": f"{type(error).__name__}: {error}",
        }


def probe_dnssec(
    domain: str,
    checker_validated: bool | None,
    query: Callable[[str, str], list[str]] = _query_dns,
) -> dict[str, Any]:
    """Add DS/DNSKEY evidence to checkdmarc's intentionally broad boolean."""
    if checker_validated is True:
        return {
            "status": "secure",
            "ds": {"status": "not_queried", "records": [], "error": None},
            "dnskey": {"status": "not_queried", "records": [], "error": None},
            "explanation": "checkdmarc validated the DNSSEC chain; duplicate DS/DNSKEY queries were skipped.",
        }
    ds = _query_evidence(domain, "DS", query)
    dnskey = _query_evidence(domain, "DNSKEY", query)
    if ds["status"] == "lookup_error" or (ds["status"] == "present" and dnskey["status"] == "lookup_error"):
        status = "lookup_error"
        explanation = "A DS or DNSKEY lookup failed, so the chain state is unknown."
    elif ds["status"] == "present":
        status = "broken" if checker_validated is False else "unknown"
        explanation = (
            "A parent DS exists, but the checker could not validate the chain."
            if status == "broken"
            else "A parent DS exists, but validation did not return a result."
        )
    elif checker_validated is False:
        status = "unsigned"
        explanation = "No parent DS record was found; a child DNSKEY without DS is unsigned."
    else:
        status = "unknown"
        explanation = "DNSSEC validation and DS evidence were inconclusive."
    return {"status": status, "ds": ds, "dnskey": dnskey, "explanation": explanation}


def collect_domain(domain: str) -> dict[str, Any]:
    """Collect email/DNS findings, then HEAD / before the security.txt GET."""
    email_error = None
    try:
        checked = check_domain(domain)
    except Exception as error:
        checked = {}
        email_error = f"{type(error).__name__}: {error}"
    if isinstance(checked, Mapping) and isinstance(checked.get("checkdmarc"), Mapping):
        checkdmarc_result = checked["checkdmarc"]
        runtime_diagnostics = checked.get("runtime_diagnostics", [])
    else:
        checkdmarc_result = checked
        runtime_diagnostics = []
    dnssec_value = checkdmarc_result.get("dnssec") if isinstance(checkdmarc_result, Mapping) else None
    try:
        dnssec_evidence = {
            **probe_dnssec(domain, dnssec_value if isinstance(dnssec_value, bool) else None),
            "mx_hosts": _dnssec_mx_diagnostics(runtime_diagnostics),
        }
    except Exception as error:
        dnssec_evidence = {"status": "lookup_error", "ds": {}, "dnskey": {}, "mx_hosts": [], "explanation": str(error)}
    try:
        root_head = probe_root_head(domain)
    except Exception as error:
        root_head = {
            "method": "HEAD",
            "path": "/",
            "state": "request_error",
            "status_code": None,
            "final_url": f"http://{normalize_domain(domain)}/",
            "upgrades_to_https": None,
            "upgrade_state": "unknown",
            "tls_certificate": "not_observed",
            "headers": {},
            "hops": [],
            "error_kind": type(error).__name__,
        }
    try:
        security_txt = probe_security_txt(domain)
    except Exception as error:
        security_txt = {
            "availability": "lookup_error",
            "content_validity": "not_assessable",
            "freshness": "unknown",
            "tls_certificate": "error",
            "request": {
                "fallback_attempted": False,
                "redirects_to_https": False,
                "attempts": [{"state": "request_error", "error_kind": type(error).__name__, "hops": []}],
            },
            "validation": {"reasons": []},
        }
    return {
        "checkdmarc": json_safe(checkdmarc_result),
        "email_collection_error": email_error,
        "runtime_diagnostics": json_safe(runtime_diagnostics),
        "dnssec_evidence": json_safe(dnssec_evidence),
        "root_head": json_safe(root_head),
        "security_txt": json_safe(security_txt),
    }


def _scan_entries(
    entries: list[dict[str, Any]],
    checker: Callable[[str], Any],
    provider_catalog: Mapping[str, Any],
    delay_seconds: float,
    progress_interval: int = PROGRESS_INTERVAL,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    normalized: list[dict[str, Any] | None] = [None] * len(entries)
    raw_records: list[dict[str, Any] | None] = [None] * len(entries)
    counts: dict[str, int] = {}
    started = time.monotonic()
    total = len(entries)
    completed_count = 0

    def collect_one(index: int, entry: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        domain = normalize_domain(str(entry["domain"]))
        rank = int(entry["rank"]) if entry.get("rank") is not None else None
        raw: Any = {}
        collection_error = None
        try:
            raw = checker(domain)
            if isinstance(raw, list):
                raw = raw[0] if raw else {}
        except Exception as error:  # Store one failure row; it must not erase the ranked name.
            collection_error = f"{type(error).__name__}: {error}"
        normalized_row = normalize_domain_result(
            domain,
            rank,
            raw,
            provider_catalog=provider_catalog,
            collection_error=collection_error,
            rank_metadata=entry,
        )
        raw_email = remove_web_evidence(json_safe(raw))
        raw_record = {
            "rank": rank,
            "rank_status": normalized_row["rank_status"],
            "au_rank": normalized_row["au_rank"],
            "au_rank_total": normalized_row["au_rank_total"],
            "last_rank": normalized_row["last_rank"],
            "last_au_rank": normalized_row["last_au_rank"],
            "domain": domain,
            "raw": raw_email,
            "collection_error": collection_error,
        }
        return normalized_row, raw_record

    def report_progress(completed_domain: str) -> None:
        nonlocal completed_count
        completed_count += 1
        # Counts are computed over completed rows; the bounded future set keeps this cheap.
        counts.clear()
        for row in normalized:
            if row is None:
                continue
            for family in ("spf", "dmarc"):
                section = row.get(family) or {}
                key = f"{family}_{section.get('status', 'unknown')}"
                counts[key] = counts.get(key, 0) + 1
            dnssec_status = str((row.get("dnssec") or {}).get("status", "unknown"))
            counts[f"dnssec_{dnssec_status}"] = counts.get(f"dnssec_{dnssec_status}", 0) + 1
            security_status = str((row.get("security_txt") or {}).get("availability", "unknown"))
            counts[f"security_txt_{security_status}"] = counts.get(f"security_txt_{security_status}", 0) + 1
        if completed_count % progress_interval == 0 or completed_count == total:
            elapsed = max(0.001, time.monotonic() - started)
            rate = completed_count / elapsed
            eta_seconds = (total - completed_count) / rate if rate else 0
            spf_counts = "/".join(str(counts.get(f"spf_{status}", 0)) for status in ("present_valid", "absent", "present_invalid", "lookup_error"))
            dmarc_counts = "/".join(str(counts.get(f"dmarc_{status}", 0)) for status in ("present_valid", "absent", "present_invalid", "lookup_error"))
            dnssec_counts = "/".join(str(counts.get(f"dnssec_{status}", 0)) for status in ("secure", "unsigned", "broken", "lookup_error", "unknown"))
            outside_count = sum(1 for row in normalized if row and row.get("rank_status") == "outside_top_1m")
            security_present = counts.get("security_txt_present", 0)
            print(
                f"Progress {completed_count}/{total} ({completed_count / total:.0%}) · {completed_domain} · "
                f"{rate:.2f} domains/s · elapsed {elapsed / 60:.1f}m · ETA {eta_seconds / 60:.1f}m · "
                f"outside top-1M {outside_count} · security.txt present {security_present} · "
                f"SPF valid/absent/invalid/error {spf_counts} · "
                f"DMARC valid/absent/invalid/error {dmarc_counts} · "
                f"DNSSEC secure/unsigned/broken/error/unknown {dnssec_counts}",
                flush=True,
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=DOMAIN_WORKERS_PER_SHARD) as executor:
        pending: dict[concurrent.futures.Future[tuple[dict[str, Any], dict[str, Any]]], int] = {}
        next_index = 0
        last_submit = 0.0
        while next_index < total or pending:
            while next_index < total and len(pending) < DOMAIN_WORKERS_PER_SHARD:
                if delay_seconds > 0 and last_submit:
                    pause = delay_seconds - (time.monotonic() - last_submit)
                    if pause > 0:
                        time.sleep(pause)
                future = executor.submit(collect_one, next_index, entries[next_index])
                pending[future] = next_index
                next_index += 1
                last_submit = time.monotonic()
            if not pending:
                continue
            done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                index = pending.pop(future)
                try:
                    normalized[index], raw_records[index] = future.result()
                except Exception as error:
                    entry = entries[index]
                    domain = normalize_domain(str(entry["domain"]))
                    rank = int(entry["rank"]) if entry.get("rank") is not None else None
                    message = f"{type(error).__name__}: {error}"
                    normalized[index] = normalize_domain_result(
                        domain, rank, {}, provider_catalog=provider_catalog,
                        collection_error=message, rank_metadata=entry,
                    )
                    raw_records[index] = {
                        "rank": rank,
                        "rank_status": normalized[index]["rank_status"],
                        "au_rank": normalized[index]["au_rank"],
                        "au_rank_total": normalized[index]["au_rank_total"],
                        "last_rank": normalized[index]["last_rank"],
                        "last_au_rank": normalized[index]["last_au_rank"],
                        "domain": domain,
                        "raw": {},
                        "collection_error": message,
                    }
                report_progress(str(entries[index]["domain"]))
    return [row for row in normalized if row is not None], [row for row in raw_records if row is not None]


def publish_snapshot(
    output_dir: Path,
    list_id: str,
    rank_limit: int,
    ranked_entry_count: int,
    au_entry_count: int,
    domains: list[dict[str, Any]],
    raw_records: list[dict[str, Any]],
    generated_at: dt.datetime,
    collection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not domains or au_entry_count < 0 or len(raw_records) != len(domains):
        raise ScanError("Refusing to publish an incomplete or empty merged scan")
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=dt.timezone.utc)
    generated_at = generated_at.astimezone(dt.timezone.utc)
    iso_time = generated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    snapshot_id = generated_at.strftime("%Y%m%dT%H%M%SZ")

    output_dir.mkdir(parents=True, exist_ok=True)
    snapshots_dir = output_dir / "snapshots"
    raw_dir = output_dir / "raw"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    index_path = output_dir / "index.json"
    index = load_index(index_path)
    snapshot_path = snapshots_dir / f"{snapshot_id}.json.gz"
    if snapshot_path.exists():
        suffix = 1
        while (snapshots_dir / f"{snapshot_id}-{suffix}.json.gz").exists():
            suffix += 1
        snapshot_id = f"{snapshot_id}-{suffix}"
        snapshot_path = snapshots_dir / f"{snapshot_id}.json.gz"

    raw_path = raw_dir / f"{snapshot_id}.jsonl.gz"
    with gzip.open(raw_path, "wt", encoding="utf-8", newline="\n") as archive:
        for record in sorted(raw_records, key=_domain_sort_key):
            archive.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    relative_path = f"snapshots/{snapshot_path.name}"
    raw_relative_path = f"raw/{raw_path.name}"
    summary = snapshot_summary(domains)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": iso_time,
        "source": {
            "name": "Tranco",
            "list_id": list_id,
            "rank_limit": rank_limit,
            "ranked_entry_count": ranked_entry_count,
            "au_entry_count": au_entry_count,
            "tracked_domain_count": len(domains),
        },
        "checker": {
            "name": "checkdmarc",
            "version": "6.0.3",
            "dns_library": "dnspython",
            "dns_library_version": "2.8.0",
        },
        "collection": json_safe(collection or {}),
        "raw_archive": raw_relative_path,
        "summary": summary,
        "domains": sorted(domains, key=_domain_sort_key),
    }
    with gzip.open(snapshot_path, "wt", encoding="utf-8", newline="\n", compresslevel=6) as stream:
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
        for chunk in encoder.iterencode(snapshot):
            stream.write(chunk)
        stream.write("\n")
    _print_size_report(snapshot, snapshot_path, raw_path, raw_records)
    oversized = [path for path in (snapshot_path, raw_path) if path.stat().st_size > MAX_GENERATED_FILE_BYTES]
    if oversized:
        details = ", ".join(f"{path.name}={path.stat().st_size:,} bytes" for path in oversized)
        raise ScanError(
            f"Generated compressed data exceeds the {MAX_GENERATED_FILE_BYTES:,}-byte per-file guard: {details}. "
            "See the preceding per-field serialized/gzip size report."
        )
    entry = {
        "id": snapshot_id,
        "path": relative_path,
        "raw_archive": raw_relative_path,
        "generated_at": iso_time,
        "domain_count": summary["domain_count"],
        "summary": summary,
    }
    prior = [item for item in index["snapshots"] if item.get("id") != snapshot_id]
    index["schema_version"] = SCHEMA_VERSION
    index["latest"] = relative_path
    index["snapshots"] = sorted(
        [entry, *prior], key=lambda item: str(item.get("generated_at", "")), reverse=True
    )
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return snapshot


def _domain_sort_key(item: Mapping[str, Any]) -> tuple[int, int, str]:
    domain = normalize_domain(str(item.get("domain") or ""))
    rank = item.get("rank")
    if rank is not None:
        try:
            return (0, int(rank), domain)
        except (TypeError, ValueError):
            pass
    last_rank = item.get("last_rank")
    try:
        last_rank_value = int(last_rank) if last_rank is not None else 2_000_000
    except (TypeError, ValueError):
        last_rank_value = 2_000_000
    return (1, last_rank_value, domain)


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
    ranked = sorted(ranked_domains, key=lambda item: int(item["rank"]))
    au_entries = [entry for entry in ranked if is_au_domain(str(entry["domain"]))]
    if not au_entries:
        raise ScanError("The ranked source list yielded no .au entries; refusing to publish an empty snapshot")
    prepared = []
    for au_rank, entry in enumerate(au_entries, start=1):
        rank = int(entry["rank"])
        prepared.append({
            **entry,
            "rank_status": "in_top_1m",
            "rank_display": f"#{rank:,}",
            "au_rank": au_rank,
            "au_rank_total": len(au_entries),
            "last_rank": rank,
            "last_au_rank": au_rank,
        })
    domains, raw_records = _scan_entries(prepared, checker, provider_catalog, delay_seconds)
    return publish_snapshot(
        output_dir,
        list_id,
        rank_limit,
        len(ranked_domains),
        len(au_entries),
        domains,
        raw_records,
        generated_at,
        {"shard_size": SHARD_SIZE, "parallelism": 1, "delay_seconds": delay_seconds},
    )


def check_domain(domain: str) -> Any:
    """Run the email-authentication and DNS portions of collection. SMTP probing is disabled."""
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
    diagnostic_capture = _DiagnosticCapture()
    root_logger = logging.getLogger()
    root_logger.addHandler(diagnostic_capture)
    try:
        with warnings.catch_warnings(record=True) as captured_warnings:
            warnings.simplefilter("always")
            result = checkdmarc.check_domains([domain], **kwargs)
    finally:
        root_logger.removeHandler(diagnostic_capture)
    warning_messages = [str(item.message) for item in captured_warnings]
    diagnostics = list(dict.fromkeys([*diagnostic_capture.messages, *warning_messages]))
    checked = result[0] if isinstance(result, list) and result else result
    return {"checkdmarc": checked, "runtime_diagnostics": diagnostics}


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
            collect_domain,
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
