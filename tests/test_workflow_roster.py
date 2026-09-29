import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collector.scan import ScanError, normalize_domain_result
from collector.workflow import prepare_scan, scan_shard


class PersistentRosterTests(unittest.TestCase):
    def test_first_scan_seeds_empty_roster_with_current_rank_and_au_position(self):
        ranked = [
            {"rank": 1, "domain": "example.com.au"},
            {"rank": 2, "domain": "example.au.com"},
            {"rank": 3, "domain": "mail.service.au"},
            {"rank": 4, "domain": "other.net"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "registry.json"
            registry_path.write_text('{"schema_version":1,"domains":{}}', encoding="utf-8")
            with patch("collector.workflow.fetch_tranco", return_value=("ABC123", ranked)):
                prepared = prepare_scan(root / "prepared.json", 4, 200, registry_path=registry_path)

            entries = prepared["domains"]
            self.assertEqual([row["domain"] for row in entries], ["example.com.au", "mail.service.au"])
            self.assertEqual([row["rank"] for row in entries], [1, 3])
            self.assertEqual([row["au_rank"] for row in entries], [1, 2])
            self.assertTrue(all(row["au_rank_total"] == 2 for row in entries))
            self.assertEqual(set(prepared["registry"]["domains"]), {"example.com.au", "mail.service.au"})

    def test_roster_adds_new_names_and_keeps_dropped_domains_with_last_rank(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "registry.json"
            initial = [
                {"rank": 12, "domain": "retained.example.au"},
                {"rank": 30, "domain": "dropped.example.au"},
            ]
            with patch("collector.workflow.fetch_tranco", return_value=("FIRST1", initial)):
                first = prepare_scan(root / "first.json", 2, 200, registry_path=registry_path)
            registry_path.write_text(json.dumps(first["registry"]), encoding="utf-8")

            following = [
                {"rank": 5, "domain": "new.gov.au"},
                {"rank": 20, "domain": "retained.example.au"},
                {"rank": 50, "domain": "new.net.au"},
                {"rank": 80, "domain": "ordinary.example.net"},
            ]
            with patch("collector.workflow.fetch_tranco", return_value=("SECOND2", following)):
                second = prepare_scan(root / "second.json", 4, 2, registry_path=registry_path)

            by_name = {item["domain"]: item for item in second["domains"]}
            self.assertEqual(set(by_name), {"new.gov.au", "retained.example.au", "new.net.au", "dropped.example.au"})
            self.assertEqual(by_name["new.gov.au"]["au_rank"], 1)
            self.assertEqual(by_name["new.net.au"]["au_rank"], 3)
            dropped = by_name["dropped.example.au"]
            self.assertIsNone(dropped["rank"])
            self.assertEqual(dropped["rank_status"], "outside_top_1m")
            self.assertEqual(dropped["rank_display"], ">1,000,000")
            self.assertEqual(dropped["last_rank"], 30)
            self.assertEqual(dropped["last_rank_list_id"], "FIRST1")
            self.assertEqual(dropped["last_au_rank"], 2)
            self.assertEqual(second["source"]["au_entry_count"], 3)
            self.assertEqual(len(second["registry"]["domains"]), 4)

    def test_failed_list_fetch_does_not_mark_roster_outside_or_replace_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "registry.json"
            original = {"schema_version": 1, "domains": {"known.example.au": {
                "domain": "known.example.au", "last_rank": 33, "last_au_rank": 4, "last_rank_list_id": "OLD01",
            }}}
            registry_path.write_text(json.dumps(original), encoding="utf-8")
            output = root / "prepared.json"
            with patch("collector.workflow.fetch_tranco", side_effect=ScanError("Tranco download failed")):
                with self.assertRaisesRegex(ScanError, "Tranco download failed"):
                    prepare_scan(output, 1, 200, registry_path=registry_path)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(registry_path.read_text(encoding="utf-8")), original)

    def test_roster_can_continue_if_a_valid_list_has_zero_current_au_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "registry.json"
            registry = {"schema_version": 1, "domains": {"retained.example.au": {
                "domain": "retained.example.au", "last_rank": 100, "last_au_rank": 8, "last_rank_list_id": "PREV1",
            }}}
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            ranked = [{"rank": rank, "domain": f"rank{rank}.example.net"} for rank in range(1, 5)]
            with patch("collector.workflow.fetch_tranco", return_value=("EMPTY1", ranked)):
                prepared = prepare_scan(root / "prepared.json", 4, 200, registry_path=registry_path)
            self.assertEqual(len(prepared["domains"]), 1)
            self.assertEqual(prepared["domains"][0]["rank_status"], "outside_top_1m")

    def test_roster_only_domain_is_still_given_to_the_next_shard_scan(self):
        outside = {
            "domain": "kept.example.au", "rank": None, "rank_status": "outside_top_1m",
            "rank_display": ">1,000,000", "au_rank": None, "au_rank_total": 10,
            "last_rank": 4000, "last_au_rank": 30, "last_rank_list_id": "OLD01",
            "last_ranked_at": "2026-09-01T00:00:00Z",
        }
        prepared = {"domains": [outside], "shard_size": 200, "shard_count": 1}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "prepared.json"
            input_path.write_text(json.dumps(prepared), encoding="utf-8")
            seen = []

            def fake_scan(entries, checker, catalog, delay_seconds):
                seen.extend(entry["domain"] for entry in entries)
                normalized = [normalize_domain_result(entry["domain"], None, {}, rank_metadata=entry) for entry in entries]
                raw = [{"domain": entry["domain"], "raw": {}, "collection_error": None} for entry in entries]
                return normalized, raw

            with patch("collector.workflow._scan_entries", side_effect=fake_scan):
                output = root / "shard-0-attempt-1.jsonl.gz"
                count = scan_shard(input_path, 0, output, 0)
            self.assertEqual(count, 1)
            self.assertEqual(seen, ["kept.example.au"])
            with gzip.open(output, "rt", encoding="utf-8") as stream:
                row = json.loads(stream.readline())
            self.assertEqual(row["rank_status"], "outside_top_1m")
            self.assertEqual(row["normalized"]["rank_display"], ">1,000,000")


if __name__ == "__main__":
    unittest.main()
