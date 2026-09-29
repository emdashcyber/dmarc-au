"""GitHub Actions stages for preparing, sharding, and merging Tranco scans."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import re
import sys
from pathlib import Path
from typing import Any

from collector.scan import (
    DOMAIN_DELAY_SECONDS,
    DOMAIN_WORKERS_PER_SHARD,
    SCHEMA_VERSION,
    SHARD_SIZE,
    ScanError,
    _scan_entries,
    collect_domain,
    fetch_tranco,
    is_au_domain,
    load_provider_catalog,
    normalize_domain,
    publish_snapshot,
)
from collector.web_checks import HTTP_TIMEOUT_SECONDS, MAX_PAGE_BYTES, MAX_REDIRECTS, MAX_SECURITY_TXT_BYTES


SHARD_FILE = re.compile(r"^shard-(\d+)-attempt-(\d+)\.jsonl\.gz$")
REGISTRY_VERSION = 1
SHARD_PARALLELISM = 8


def split_domains(domains: list[dict[str, Any]], shard_size: int = SHARD_SIZE) -> list[list[dict[str, Any]]]:
    if shard_size < 1:
        raise ValueError("shard_size must be greater than zero")
    return [domains[start : start + shard_size] for start in range(0, len(domains), shard_size)]


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_registry(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": REGISTRY_VERSION, "domains": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScanError(f"Unable to read tracked-domain registry {path}: {error}") from error
    if not isinstance(value, dict) or value.get("schema_version") != REGISTRY_VERSION or not isinstance(value.get("domains"), dict):
        raise ScanError("Tracked-domain registry has an unsupported format")
    normalized: dict[str, dict[str, Any]] = {}
    for key, record in value["domains"].items():
        domain = normalize_domain(str(key))
        if not is_au_domain(domain) or not isinstance(record, dict):
            raise ScanError(f"Invalid entry in tracked-domain registry: {key!r}")
        normalized[domain] = {**record, "domain": domain}
    return {"schema_version": REGISTRY_VERSION, "domains": normalized}


def _last_rank_order(domain: str, record: dict[str, Any]) -> tuple[int, str]:
    try:
        rank = int(record.get("last_rank") or 2_000_000)
    except (TypeError, ValueError):
        rank = 2_000_000
    return rank, domain


def prepare_scan(
    output: Path,
    rank_limit: int = 1_000_000,
    shard_size: int = SHARD_SIZE,
    github_output: Path | None = None,
    registry_path: Path = Path("site/data/registry.json"),
) -> dict[str, Any]:
    if shard_size < 1:
        raise ValueError("shard_size must be greater than zero")
    list_id, ranked = fetch_tranco(rank_limit)
    current = sorted(
        (entry for entry in ranked if is_au_domain(str(entry["domain"]))),
        key=lambda item: int(item["rank"]),
    )
    registry = load_registry(registry_path)
    old_domains: dict[str, dict[str, Any]] = registry["domains"]
    if not current and not old_domains:
        raise ScanError("The latest Tranco list contains no .au entries and the tracked roster is empty")
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    next_registry: dict[str, dict[str, Any]] = {name: dict(item) for name, item in old_domains.items()}
    current_names = {str(item["domain"]) for item in current}
    au_total = len(current)
    tracked: list[dict[str, Any]] = []

    for au_rank, item in enumerate(current, start=1):
        domain = normalize_domain(str(item["domain"]))
        rank = int(item["rank"])
        old = old_domains.get(domain, {})
        record = {
            "domain": domain,
            "rank": rank,
            "rank_status": "in_top_1m",
            "rank_display": f"#{rank:,}",
            "au_rank": au_rank,
            "au_rank_total": au_total,
            "last_rank": rank,
            "last_au_rank": au_rank,
            "last_rank_list_id": list_id,
            "last_ranked_at": generated_at,
            "first_seen_at": old.get("first_seen_at") or generated_at,
            "last_checked_at": generated_at,
        }
        next_registry[domain] = {
            "domain": domain,
            "first_seen_at": record["first_seen_at"],
            "last_rank": rank,
            "last_au_rank": au_rank,
            "last_rank_list_id": list_id,
            "last_ranked_at": generated_at,
            "last_checked_at": generated_at,
        }
        tracked.append(record)

    for domain in sorted(set(old_domains) - current_names, key=lambda name: _last_rank_order(name, old_domains[name])):
        old = old_domains[domain]
        tracked.append({
            "domain": domain,
            "rank": None,
            "rank_status": "outside_top_1m",
            "rank_display": ">1,000,000",
            "au_rank": None,
            "au_rank_total": au_total,
            "last_rank": old.get("last_rank"),
            "last_au_rank": old.get("last_au_rank"),
            "last_rank_list_id": old.get("last_rank_list_id"),
            "last_ranked_at": old.get("last_ranked_at"),
            "first_seen_at": old.get("first_seen_at"),
            "last_checked_at": generated_at,
        })
        next_registry[domain] = {**old, "domain": domain, "last_checked_at": generated_at}

    chunks = split_domains(tracked, shard_size)
    prepared = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "source": {
            "name": "Tranco",
            "list_id": list_id,
            "rank_limit": rank_limit,
            "ranked_entry_count": len(ranked),
            "au_entry_count": au_total,
            "tracked_domain_count": len(tracked),
        },
        "shard_size": shard_size,
        "shard_count": len(chunks),
        "domains": tracked,
        "registry": {"schema_version": REGISTRY_VERSION, "domains": next_registry},
    }
    _write_json(output, prepared)
    matrix = {"include": [{"shard": index} for index in range(len(chunks))]}
    if github_output:
        with github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"matrix={json.dumps(matrix, separators=(',', ':'))}\n")
            stream.write(f"au_count={au_total}\n")
            stream.write(f"tracked_count={len(tracked)}\n")
            stream.write(f"shard_count={len(chunks)}\n")
            stream.write(f"list_id={list_id}\n")
    outside_count = len(tracked) - au_total
    print(
        f"Prepared Tranco {list_id}: {len(ranked):,} ranked entries, {au_total:,} current .au entries, "
        f"{outside_count:,} previously tracked domains outside the top 1M, "
        f"{len(chunks)} shards of up to {shard_size}.",
        flush=True,
    )
    return prepared


def scan_shard(
    prepared_path: Path,
    shard_index: int,
    output: Path,
    delay_seconds: float = DOMAIN_DELAY_SECONDS,
) -> int:
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    domains = prepared.get("domains")
    shard_size = int(prepared.get("shard_size", SHARD_SIZE))
    shard_count = int(prepared.get("shard_count", 0))
    if not isinstance(domains, list) or shard_index < 0 or shard_index >= shard_count:
        raise ScanError(f"Invalid shard index {shard_index} for prepared input")
    entries = split_domains(domains, shard_size)[shard_index]
    if not entries:
        raise ScanError(f"Shard {shard_index} contains no domain entries")

    catalog = load_provider_catalog(Path(__file__).with_name("providers.json"))
    normalized, raw_records = _scan_entries(entries, collect_domain, catalog, delay_seconds)
    output.parent.mkdir(parents=True, exist_ok=True)
    attempt = 1
    match = re.search(r"attempt-(\d+)", output.name)
    if match:
        attempt = int(match.group(1))
    with gzip.open(output, "wt", encoding="utf-8", newline="\n") as stream:
        for ranked, result, raw in zip(entries, normalized, raw_records, strict=True):
            stream.write(json.dumps({
                "shard": shard_index,
                "rank": ranked.get("rank"),
                "rank_status": ranked.get("rank_status"),
                "au_rank": ranked.get("au_rank"),
                "domain": str(ranked["domain"]),
                "normalized": result,
                "raw": raw.get("raw"),
                "collection_error": raw.get("collection_error"),
                "attempt": attempt,
            }, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(f"Shard {shard_index} complete: {len(entries)} domains written to {output}", flush=True)
    return len(entries)


def _selected_shard_files(directory: Path, expected_shards: int) -> dict[int, Path]:
    selected: dict[int, tuple[int, Path]] = {}
    for path in directory.glob("shard-*-attempt-*.jsonl.gz"):
        match = SHARD_FILE.match(path.name)
        if not match:
            continue
        shard_index, attempt = int(match.group(1)), int(match.group(2))
        if shard_index < 0 or shard_index >= expected_shards:
            raise ScanError(f"Unexpected shard output {path.name}")
        prior = selected.get(shard_index)
        if prior is None or attempt > prior[0]:
            selected[shard_index] = (attempt, path)
    missing = sorted(set(range(expected_shards)) - selected.keys())
    if missing:
        raise ScanError(f"Cannot publish an incomplete scan; missing shard outputs: {missing}")
    return {index: item[1] for index, item in selected.items()}


def _ranked_first(item: dict[str, Any]) -> tuple[int, int, str]:
    rank = item.get("rank")
    if rank is not None:
        return 0, int(rank), normalize_domain(str(item.get("domain") or ""))
    last = item.get("last_rank")
    return 1, int(last) if last is not None else 2_000_000, normalize_domain(str(item.get("domain") or ""))


def merge_scan(
    prepared_path: Path,
    shard_directory: Path,
    output_dir: Path,
) -> dict[str, Any]:
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    entries = prepared.get("domains")
    registry = prepared.get("registry")
    if not isinstance(entries, list) or not entries:
        raise ScanError("Prepared scan input is missing its tracked .au domain list")
    if not isinstance(registry, dict) or not isinstance(registry.get("domains"), dict):
        raise ScanError("Prepared scan input is missing its candidate domain registry")
    shard_size = int(prepared["shard_size"])
    expected_shards = int(prepared["shard_count"])
    shards = _selected_shard_files(shard_directory, expected_shards)

    expected: dict[str, int] = {}
    expected_rows: dict[str, dict[str, Any]] = {}
    for position, item in enumerate(entries):
        domain = normalize_domain(str(item["domain"]))
        if domain in expected:
            raise ScanError(f"Prepared Tranco input contains a duplicate domain: {domain}")
        expected[domain] = position // shard_size
        expected_rows[domain] = item

    normalized: list[dict[str, Any]] = []
    raw_records: list[dict[str, Any]] = []
    from collector.scan import _extract_evidence_objects

    observed: set[str] = set()
    for shard_index, path in sorted(shards.items()):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ScanError(f"Invalid JSON in {path.name}:{line_number}: {error}") from error
                domain = normalize_domain(str(row.get("domain") or ""))
                if domain not in expected or expected[domain] != shard_index:
                    raise ScanError(f"Unexpected domain row in shard {shard_index}: {domain}")
                if domain in observed:
                    raise ScanError(f"Duplicate scanned domain row: {domain}")
                result = row.get("normalized")
                source_row = expected_rows[domain]
                if (
                    not isinstance(result, dict)
                    or normalize_domain(str(result.get("domain") or "")) != domain
                    or result.get("rank") != source_row.get("rank")
                    or result.get("rank_status") != source_row.get("rank_status")
                    or result.get("au_rank") != source_row.get("au_rank")
                ):
                    raise ScanError(f"Normalized row does not match its prepared source row: {domain}")
                observed.add(domain)
                normalized.append(result)
                raw_records.append({
                    "rank": source_row.get("rank"),
                    "rank_status": source_row.get("rank_status"),
                    "au_rank": source_row.get("au_rank"),
                    "au_rank_total": source_row.get("au_rank_total"),
                    "last_rank": source_row.get("last_rank"),
                    "last_au_rank": source_row.get("last_au_rank"),
                    "domain": domain,
                    "raw": row.get("raw"),
                    "collection_error": row.get("collection_error"),
                })

    if observed != expected.keys():
        missing = sorted(expected.keys() - observed)
        raise ScanError(f"Cannot publish an incomplete scan; {len(missing)} tracked domains are missing")
    if set(normalize_domain(str(name)) for name in registry["domains"]) != expected.keys():
        raise ScanError("Candidate registry does not exactly match the prepared tracked domain set")

    security_txt_objects, certificate_objects = _extract_evidence_objects(raw_records)

    generated_at = dt.datetime.fromisoformat(str(prepared["generated_at"]).replace("Z", "+00:00"))
    source = prepared["source"]
    snapshot = publish_snapshot(
        output_dir=output_dir,
        list_id=str(source["list_id"]),
        rank_limit=int(source["rank_limit"]),
        ranked_entry_count=int(source["ranked_entry_count"]),
        au_entry_count=int(source["au_entry_count"]),
        domains=normalized,
        raw_records=raw_records,
        generated_at=generated_at,
        collection={
            "shard_size": shard_size,
            "shard_count": expected_shards,
            "parallelism": SHARD_PARALLELISM,
            "domain_workers_per_shard": DOMAIN_WORKERS_PER_SHARD,
            "delay_seconds": DOMAIN_DELAY_SECONDS,
            "web_probe": {
                "methods": ["HEAD", "GET"],
                "schemes": ["http", "https"],
                "request_chain_deadline_seconds": HTTP_TIMEOUT_SECONDS,
                "max_redirects": MAX_REDIRECTS,
                "homepage_body_limit_bytes": MAX_PAGE_BYTES,
                "security_txt_body_limit_bytes": MAX_SECURITY_TXT_BYTES,
                "security_txt_paths": ["/.well-known/security.txt"],
                "certificate_diagnostic_handshake": "TLS-only after certificate validation failure",
                "reuses_captured_a_aaaa_for_initial_hostname": True,
            },
            "web_dns_record_types": ["A", "AAAA", "CNAME", "CAA", "HTTPS"],
            "roster_policy": "union_of_current_tranco_au_and_prior_registry",
        },
        security_txt_objects=security_txt_objects,
        certificate_objects=certificate_objects,
    )
    _write_json(output_dir / "registry.json", registry)
    print(
        f"Merged Tranco {source['list_id']} snapshot with {len(normalized):,} tracked .au domains "
        f"({source['au_entry_count']:,} currently in the top 1M).",
        flush=True,
    )
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="download Tranco and create the tracked .au shard input")
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--rank-limit", type=int, default=1_000_000)
    prepare.add_argument("--shard-size", type=int, default=SHARD_SIZE)
    prepare.add_argument("--registry", type=Path, default=Path("site/data/registry.json"))
    prepare.add_argument("--github-output", type=Path)

    shard = subparsers.add_parser("scan-shard", help="scan one 200-domain matrix shard")
    shard.add_argument("--input", type=Path, required=True)
    shard.add_argument("--shard", type=int, required=True)
    shard.add_argument("--output", type=Path, required=True)
    shard.add_argument("--delay-seconds", type=float, default=DOMAIN_DELAY_SECONDS)

    merge = subparsers.add_parser("merge", help="validate all shards and publish the complete snapshot")
    merge.add_argument("--input", type=Path, required=True)
    merge.add_argument("--shards", type=Path, required=True)
    merge.add_argument("--output-dir", type=Path, default=Path("site/data"))

    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare_scan(args.output, args.rank_limit, args.shard_size, args.github_output, args.registry)
        elif args.command == "scan-shard":
            scan_shard(args.input, args.shard, args.output, args.delay_seconds)
        else:
            merge_scan(args.input, args.shards, args.output_dir)
    except Exception as error:
        print(f"{args.command} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
