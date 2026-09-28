"""GitHub Actions stages for preparing, sharding, and merging a Tranco scan."""

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
    DKIM_SELECTORS,
    DOMAIN_DELAY_SECONDS,
    SHARD_SIZE,
    ScanError,
    _scan_entries,
    collect_domain,
    fetch_tranco,
    is_au_domain,
    json_safe,
    load_provider_catalog,
    publish_snapshot,
)


SHARD_FILE = re.compile(r"^shard-(\d+)-attempt-(\d+)\.jsonl\.gz$")


def split_domains(domains: list[dict[str, Any]], shard_size: int = SHARD_SIZE) -> list[list[dict[str, Any]]]:
    if shard_size < 1:
        raise ValueError("shard_size must be greater than zero")
    return [domains[start : start + shard_size] for start in range(0, len(domains), shard_size)]


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepare_scan(
    output: Path,
    rank_limit: int = 1_000_000,
    shard_size: int = SHARD_SIZE,
    github_output: Path | None = None,
) -> dict[str, Any]:
    if shard_size < 1:
        raise ValueError("shard_size must be greater than zero")
    list_id, ranked = fetch_tranco(rank_limit)
    au_entries = [entry for entry in ranked if is_au_domain(str(entry["domain"]))]
    if not au_entries:
        raise ScanError("The latest Tranco list contains no .au entries; refusing to scan")
    chunks = split_domains(au_entries, shard_size)
    shard_count = len(chunks)
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    prepared = {
        "schema_version": 1,
        "generated_at": generated_at,
        "source": {
            "name": "Tranco",
            "list_id": list_id,
            "rank_limit": rank_limit,
            "ranked_entry_count": len(ranked),
            "au_entry_count": len(au_entries),
        },
        "shard_size": shard_size,
        "shard_count": shard_count,
        "domains": au_entries,
    }
    _write_json(output, prepared)
    matrix = {"include": [{"shard": index} for index in range(shard_count)]}
    if github_output:
        with github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"matrix={json.dumps(matrix, separators=(',', ':'))}\n")
            stream.write(f"au_count={len(au_entries)}\n")
            stream.write(f"shard_count={shard_count}\n")
            stream.write(f"list_id={list_id}\n")
    print(
        f"Prepared Tranco {list_id}: {len(ranked):,} ranked entries, "
        f"{len(au_entries):,} .au entries, {shard_count} flat shards of up to {shard_size}.",
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
    # The workflow passes the attempt explicitly in the file path; keep a safe
    # default for local invocations.
    match = re.search(r"attempt-(\d+)", output.name)
    if match:
        attempt = int(match.group(1))
    with gzip.open(output, "wt", encoding="utf-8", newline="\n") as stream:
        for ranked, result, raw in zip(entries, normalized, raw_records, strict=True):
            stream.write(json.dumps({
                "shard": shard_index,
                "rank": int(ranked["rank"]),
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


def merge_scan(
    prepared_path: Path,
    shard_directory: Path,
    output_dir: Path,
) -> dict[str, Any]:
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    entries = prepared.get("domains")
    if not isinstance(entries, list) or not entries:
        raise ScanError("Prepared scan input is missing its .au domain list")
    shard_size = int(prepared["shard_size"])
    expected_shards = int(prepared["shard_count"])
    shards = _selected_shard_files(shard_directory, expected_shards)

    expected: dict[tuple[int, str], int] = {}
    for position, item in enumerate(entries):
        key = (int(item["rank"]), str(item["domain"]))
        if key in expected:
            raise ScanError(f"Prepared Tranco input contains a duplicate entry: {key}")
        expected[key] = position // shard_size

    normalized: list[dict[str, Any]] = []
    raw_records: list[dict[str, Any]] = []
    observed: set[tuple[int, str]] = set()
    for shard_index, path in sorted(shards.items()):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ScanError(f"Invalid JSON in {path.name}:{line_number}: {error}") from error
                key = (int(row.get("rank", 0)), str(row.get("domain", "")))
                if key not in expected or expected[key] != shard_index:
                    raise ScanError(f"Unexpected domain row in shard {shard_index}: {key}")
                if key in observed:
                    raise ScanError(f"Duplicate scanned domain row: {key}")
                result = row.get("normalized")
                if not isinstance(result, dict) or result.get("rank") != key[0] or result.get("domain") != key[1]:
                    raise ScanError(f"Normalized row does not match its Tranco source row: {key}")
                observed.add(key)
                normalized.append(result)
                raw_records.append({
                    "rank": key[0],
                    "domain": key[1],
                    "raw": row.get("raw"),
                    "collection_error": row.get("collection_error"),
                })

    if observed != expected.keys():
        missing = sorted(expected.keys() - observed)
        raise ScanError(f"Cannot publish an incomplete scan; {len(missing)} ranked domains are missing")

    generated_at = dt.datetime.fromisoformat(str(prepared["generated_at"]).replace("Z", "+00:00"))
    source = prepared["source"]
    snapshot = publish_snapshot(
        output_dir=output_dir,
        list_id=str(source["list_id"]),
        rank_limit=int(source["rank_limit"]),
        ranked_entry_count=int(source["ranked_entry_count"]),
        au_entry_count=len(entries),
        domains=normalized,
        raw_records=raw_records,
        generated_at=generated_at,
        collection={
            "shard_size": shard_size,
            "shard_count": expected_shards,
            "parallelism": 4,
            "delay_seconds": DOMAIN_DELAY_SECONDS,
            "dkim_selectors": list(DKIM_SELECTORS),
        },
    )
    print(
        f"Merged complete Tranco {source['list_id']} snapshot with {len(normalized):,} .au domains.",
        flush=True,
    )
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="download Tranco and create the flat .au shard input")
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--rank-limit", type=int, default=1_000_000)
    prepare.add_argument("--shard-size", type=int, default=SHARD_SIZE)
    prepare.add_argument("--github-output", type=Path)

    shard = subparsers.add_parser("scan-shard", help="scan one 200-domain matrix shard")
    shard.add_argument("--input", type=Path, required=True)
    shard.add_argument("--shard", type=int, required=True)
    shard.add_argument("--output", type=Path, required=True)
    shard.add_argument("--delay-seconds", type=float, default=DOMAIN_DELAY_SECONDS)

    merge = subparsers.add_parser("merge", help="validate all shards and publish the merged snapshot")
    merge.add_argument("--input", type=Path, required=True)
    merge.add_argument("--shards", type=Path, required=True)
    merge.add_argument("--output-dir", type=Path, default=Path("site/data"))

    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare_scan(args.output, args.rank_limit, args.shard_size, args.github_output)
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
