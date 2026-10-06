import gzip
import json
import unittest
from pathlib import Path

from collector.scan import infer_provider_clues, load_provider_catalog


ROOT = Path(__file__).parents[1]


class PublishedDataTests(unittest.TestCase):
    def test_oldest_scan_was_pruned_without_losing_the_roster_or_latest_pointer(self):
        data_dir = ROOT / "site" / "data"
        index = json.loads((data_dir / "index.json").read_text(encoding="utf-8"))
        removed_id = "20260929T135254Z"
        self.assertNotIn(removed_id, {item["id"] for item in index["snapshots"]})
        self.assertFalse((data_dir / "snapshots" / f"{removed_id}.json.gz").exists())
        self.assertFalse((data_dir / "raw" / f"{removed_id}.jsonl.gz").exists())
        latest = max(index["snapshots"], key=lambda item: item["generated_at"])
        self.assertEqual(index["latest"], latest["path"])
        registry = json.loads((data_dir / "registry.json").read_text(encoding="utf-8"))
        self.assertGreater(len(registry.get("domains", {})), 0)

    def test_retained_snapshots_provider_clues_match_the_documented_catalog(self):
        data_dir = ROOT / "site" / "data"
        index = json.loads((data_dir / "index.json").read_text(encoding="utf-8"))
        catalog = load_provider_catalog(ROOT / "collector" / "providers.json")
        for item in index["snapshots"]:
            path = data_dir / item["path"]
            with self.subTest(snapshot=item["id"]), gzip.open(path, "rt", encoding="utf-8") as stream:
                snapshot = json.load(stream)
            for row in snapshot["domains"]:
                dmarc = row.get("dmarc") or {}
                tls = row.get("tls_reporting") or {}
                reporting = list(dict.fromkeys([*(dmarc.get("reporting_hosts") or []), *(tls.get("reporting_hosts") or [])]))
                expected = infer_provider_clues(
                    (row.get("spf") or {}).get("service_targets") or [],
                    (row.get("mx") or {}).get("hosts") or [],
                    reporting,
                    catalog,
                )
                self.assertEqual(row.get("provider_clues"), expected, row.get("domain"))


if __name__ == "__main__":
    unittest.main()
