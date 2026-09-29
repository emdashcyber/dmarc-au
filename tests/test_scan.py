import datetime as dt
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from collector.scan import (
    classify_record,
    _dnssec_mx_diagnostics,
    effective_spf_terminal,
    infer_provider_clues,
    infer_web_provider_clues,
    is_au_domain,
    normalize_domain_result,
    parse_ranked_csv,
    probe_dnssec,
    field_size_report,
    snapshot_summary,
    write_snapshot,
)
from collector.workflow import merge_scan, split_domains


PROVIDERS = {
    "providers": [
        {"name": "Google Workspace", "outbound": ["_spf.google.com"], "inbound": ["aspmx.l.google.com"], "reporting": []},
        {"name": "dmarcian", "outbound": [], "inbound": [], "reporting": ["dmarcian.com"]},
    ]
}


class DomainFilterTests(unittest.TestCase):
    def test_matches_au_at_label_boundary_and_keeps_subdomains(self):
        self.assertTrue(is_au_domain("example.com.au"))
        self.assertTrue(is_au_domain("mail.example.au."))
        self.assertFalse(is_au_domain("example.au.com"))
        self.assertFalse(is_au_domain("au"))

    def test_tranco_rows_keep_rank_and_normalize_domain(self):
        content = "rank,domain\n1,Example.com.au\n2,example.com\n3,mx.service.example.au.\n"
        rows = parse_ranked_csv(content, 3)
        self.assertEqual(rows, [
            {"rank": 1, "domain": "example.com.au"},
            {"rank": 2, "domain": "example.com"},
            {"rank": 3, "domain": "mx.service.example.au"},
        ])

    def test_flat_shards_are_rank_ordered_and_at_most_200(self):
        entries = [{"rank": rank, "domain": f"d{rank}.{'com.au' if rank % 2 else 'gov.au'}"} for rank in range(1, 402)]
        chunks = split_domains(entries, 200)
        self.assertEqual([len(chunk) for chunk in chunks], [200, 200, 1])
        self.assertEqual(chunks[0][0]["rank"], 1)
        self.assertEqual(chunks[1][0]["rank"], 201)
        self.assertEqual(chunks[2][0]["rank"], 401)


class SPFTests(unittest.TestCase):
    def test_terminal_qualifiers(self):
        examples = {
            "v=spf1 -all": ("fail", "-all"),
            "v=spf1 ~all": ("softfail", "~all"),
            "v=spf1 ?all": ("neutral", "?all"),
            "v=spf1 +all": ("pass", "+all"),
            "v=spf1 all": ("pass", "all"),
        }
        for record, expected in examples.items():
            with self.subTest(record=record):
                result = effective_spf_terminal(record, {"all": expected[0]})
                self.assertEqual((result["outcome"], result["token"]), expected)

    def test_redirect_uses_effective_redirect_record(self):
        result = effective_spf_terminal(
            "v=spf1 redirect=_spf.example.au",
            {
                "all": "softfail",
                "redirect": {
                    "domain": "_spf.example.au",
                    "record": "v=spf1 ~all",
                    "parsed": {"all": "softfail", "redirect": None},
                },
            },
        )
        self.assertEqual(result["token"], "~all")
        self.assertEqual(result["outcome"], "softfail")
        self.assertEqual(result["redirect_domain"], "_spf.example.au")
        self.assertFalse(result["implicit"])

    def test_no_terminal_mechanism_is_implicit_neutral(self):
        result = effective_spf_terminal("v=spf1 include:_spf.example.au", {"all": "neutral"})
        self.assertIsNone(result["token"])
        self.assertEqual(result["outcome"], "neutral")
        self.assertTrue(result["implicit"])


class StatusAndNormalizationTests(unittest.TestCase):
    def test_missing_invalid_and_transient_errors_are_distinct(self):
        self.assertEqual(classify_record({"record": None, "valid": False, "error": "An SPF record does not exist."}), "absent")
        self.assertEqual(classify_record({"record": None, "valid": False, "error": "DNSExceptionNXDOMAIN: The domain does not exist."}), "absent")
        self.assertEqual(classify_record({"record": None, "valid": False, "error": "DNS query timed out"}), "lookup_error")
        self.assertEqual(classify_record({"record": "v=spf1 include:", "valid": False}), "present_invalid")
        self.assertEqual(classify_record({"record": None, "valid": False, "error": "The domain has multiple SPF TXT records"}), "present_invalid")
        self.assertEqual(classify_record({"record": "v=spf1 include:_spf.example.au -all", "valid": False, "error": "DNS query timed out resolving include"}), "lookup_error")

    def test_provider_hints_keep_observed_hosts(self):
        clues = infer_provider_clues(
            ["_spf.google.com"],
            [{"hostname": "aspmx.l.google.com"}],
            ["dmarcian.com"],
            PROVIDERS,
        )
        self.assertEqual(clues["outbound"][0]["name"], "Google Workspace")
        self.assertEqual(clues["outbound"][0]["observed_hosts"], ["_spf.google.com"])
        self.assertEqual(clues["inbound"][0]["name"], "Google Workspace")
        self.assertEqual(clues["reporting"][0]["name"], "dmarcian")

    def test_web_provider_hints_retain_dns_and_header_evidence(self):
        clues = infer_web_provider_clues(
            {"cname": {"status": "present", "records": ["edge.cloudflare.net."]}},
            {"headers": {"server": "cloudflare", "x-powered-by": "nginx"}},
            {"providers": [
                {"name": "Cloudflare", "web_hosts": ["cloudflare.net"], "web_headers": [{"name": "server", "contains": "cloudflare"}]},
                {"name": "nginx", "web_headers": [{"name": "x-powered-by", "contains": "nginx"}]},
            ]},
        )
        by_name = {item["name"]: item for item in clues}
        self.assertEqual(by_name["Cloudflare"]["observed_hosts"], ["edge.cloudflare.net"])
        self.assertEqual(by_name["Cloudflare"]["observed_headers"][0]["name"], "server")
        self.assertEqual(by_name["nginx"]["observed_headers"][0]["value"], "nginx")

    def test_normalized_domain_has_effective_dmarc_source_and_signals(self):
        result = normalize_domain_result(
            "mail.example.com.au",
            21,
            {
                "spf": {
                    "record": "v=spf1 include:_spf.google.com -all",
                    "valid": True,
                    "dns_lookups": 3,
                    "void_dns_lookups": 0,
                    "parsed": {
                        "all": "fail",
                        "mechanisms": [{"mechanism": "include", "action": "pass", "value": "_spf.google.com"}],
                    },
                    "warnings": [],
                },
                "dmarc": {
                    "record": "v=DMARC1; p=reject; rua=mailto:reports@dmarcian.com",
                    "valid": True,
                    "location": "_dmarc.example.com.au",
                    "tags": {
                        "p": {"value": "reject", "explicit": True},
                        "sp": {"value": "quarantine", "explicit": True},
                        "np": {"value": "reject", "explicit": True},
                        "adkim": {"value": "s", "explicit": True},
                        "aspf": {"value": "r", "explicit": True},
                        "t": {"value": "n", "explicit": False},
                        "rua": {"value": [{"uri": "mailto:reports@dmarcian.com"}], "explicit": True},
                    },
                },
                "mx": {"hosts": [{"preference": 10, "hostname": "aspmx.l.google.com.", "addresses": ["192.0.2.1"]}]},
                "mta_sts": {"valid": True, "record": "v=STSv1; id=123", "policy": {"mode": "enforce"}},
                "smtp_tls_reporting": {"valid": True, "record": "v=TLSRPTv1; rua=mailto:tls@example.com"},
                "dnssec": True,
            },
            provider_catalog=PROVIDERS,
        )
        self.assertEqual(result["rank"], 21)
        self.assertEqual(result["spf"]["status"], "present_valid")
        self.assertEqual(result["spf"]["terminal"]["outcome"], "fail")
        self.assertEqual(result["dmarc"]["discovery_source"], "inherited")
        self.assertEqual(result["dmarc"]["policy"]["p"], "reject")
        self.assertEqual(result["dmarc"]["policy"]["sp"], "quarantine")
        self.assertEqual(result["dmarc"]["reporting_hosts"], ["dmarcian.com"])
        self.assertEqual(result["provider_clues"]["outbound"][0]["name"], "Google Workspace")
        self.assertEqual(result["provider_clues"]["inbound"][0]["name"], "Google Workspace")
        self.assertEqual(result["provider_clues"]["reporting"][0]["name"], "dmarcian")
        self.assertEqual(result["dnssec"]["status"], "secure")

    def test_normalization_preserves_roster_rank_metadata(self):
        result = normalize_domain_result(
            "old.example.au", None, {}, rank_metadata={
                "rank_status": "outside_top_1m", "rank_display": ">1,000,000",
                "au_rank_total": 400, "last_rank": 94321, "last_au_rank": 900,
                "last_rank_list_id": "ABCD1", "last_ranked_at": "2026-09-01T00:00:00Z",
            },
        )
        self.assertIsNone(result["rank"])
        self.assertEqual(result["rank_display"], ">1,000,000")
        self.assertEqual(result["last_rank"], 94321)
        self.assertEqual(result["last_rank_list_id"], "ABCD1")

    def test_dmarc_policies_are_preserved(self):
        for policy in ("none", "quarantine", "reject"):
            with self.subTest(policy=policy):
                result = normalize_domain_result(
                    "example.com.au",
                    1,
                    {
                        "dmarc": {
                            "record": f"v=DMARC1; p={policy}",
                            "valid": True,
                            "location": "_dmarc.example.com.au",
                            "tags": {"p": {"value": policy, "explicit": True}},
                        }
                    },
                    provider_catalog=PROVIDERS,
                )
                self.assertEqual(result["dmarc"]["policy"]["p"], policy)

    def test_malformed_dmarc_and_dns_timeout_are_not_absent(self):
        malformed = normalize_domain_result(
            "broken.example.au",
            5,
            {"dmarc": {"record": "v=DMARC1; p=maybe", "valid": False, "error": "Invalid DMARC policy value"}},
            provider_catalog=PROVIDERS,
        )
        timeout = normalize_domain_result(
            "slow.example.au",
            6,
            {"dmarc": {"record": None, "valid": False, "error": "DNS query timed out"}},
            provider_catalog=PROVIDERS,
        )
        self.assertEqual(malformed["dmarc"]["status"], "present_invalid")
        self.assertEqual(timeout["dmarc"]["status"], "lookup_error")

    def test_dnssec_evidence_distinguishes_unsigned_broken_and_lookup_error(self):
        unsigned = probe_dnssec(
            "unsigned.example.au",
            False,
            lambda name, kind: ["DNSKEY 257 3 13 abc"] if kind == "DNSKEY" else [],
        )
        broken = probe_dnssec(
            "broken.example.au",
            False,
            lambda name, kind: ["DS 12345 13 2 digest"] if kind == "DS" else ["DNSKEY 257 3 13 abc"],
        )
        failed = probe_dnssec(
            "timeout.example.au",
            False,
            lambda name, kind: (_ for _ in ()).throw(TimeoutError("DNS SERVFAIL")),
        )
        failed_key_lookup = probe_dnssec(
            "key-timeout.example.au",
            False,
            lambda name, kind: ["DS 12345 13 2 digest"] if kind == "DS" else (_ for _ in ()).throw(TimeoutError("DNS SERVFAIL")),
        )
        self.assertEqual(unsigned["status"], "unsigned")
        self.assertEqual(unsigned["dnskey"]["status"], "present")
        self.assertEqual(broken["status"], "broken")
        self.assertEqual(failed["status"], "lookup_error")
        self.assertEqual(failed_key_lookup["status"], "lookup_error")

    def test_checkdmarc_runtime_dnssec_messages_are_structured_for_mx_hosts(self):
        states = _dnssec_mx_diagnostics([
            "Could not check DNSSEC for mx1.example.au: the DS query for mx1.example.au failed with SERVFAIL",
            "mx2.example.au publishes a DNSKEY record, but its parent zone publishes no DS record for it, so validators treat it as unsigned",
        ])
        result = normalize_domain_result(
            "example.au",
            1,
            {
                "checkdmarc": {
                    "dnssec": True,
                    "mx": {"hosts": [
                        {"hostname": "mx1.example.au.", "dnssec": False},
                        {"hostname": "mx2.example.au.", "dnssec": False},
                    ]},
                },
                "runtime_diagnostics": [item["diagnostic"] for item in states],
                "dnssec_evidence": {"status": "secure", "mx_hosts": states},
            },
            provider_catalog=PROVIDERS,
        )
        host_states = {host["hostname"]: host["dnssec_status"] for host in result["mx"]["hosts"]}
        self.assertEqual(host_states, {"mx1.example.au": "lookup_error", "mx2.example.au": "unsigned"})

class SnapshotTests(unittest.TestCase):
    def test_snapshot_history_is_timestamped_and_summary_is_counted(self):
        ranked = [
            {"rank": 1, "domain": "example.com.au"},
            {"rank": 2, "domain": "example.au.com"},
            {"rank": 3, "domain": "service.example.au"},
        ]
        fixture = {
            "spf": {"record": "v=spf1 -all", "valid": True, "parsed": {"all": "fail"}},
            "dmarc": {"record": "v=DMARC1; p=reject", "valid": True, "location": "_dmarc.example.com.au", "tags": {"p": {"value": "reject", "explicit": True}}},
            "mx": {"hosts": []},
            "dnssec": False,
        }
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            first_time = dt.datetime(2026, 9, 28, 2, 0, 0, tzinfo=dt.timezone.utc)
            first = write_snapshot(output, "ABC12", 3, ranked, lambda _: fixture, PROVIDERS, first_time, 0)
            second_time = dt.datetime(2026, 10, 5, 2, 0, 0, tzinfo=dt.timezone.utc)
            write_snapshot(output, "XYZ34", 3, ranked, lambda _: fixture, PROVIDERS, second_time, 0)

            self.assertEqual(first["source"]["au_entry_count"], 2)
            self.assertEqual([item["domain"] for item in first["domains"]], ["example.com.au", "service.example.au"])
            self.assertEqual(first["summary"]["dmarc_policies"]["reject"], 2)
            index = json.loads((output / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(len(index["snapshots"]), 2)
            self.assertIn("20261005", index["latest"])
            self.assertTrue((output / index["latest"]).exists())
            raw_archive = output / index["snapshots"][0]["raw_archive"]
            self.assertTrue(raw_archive.exists())

    def test_failed_domain_check_stays_in_snapshot_as_lookup_error(self):
        ranked = [{"rank": 1, "domain": "example.com.au"}]
        with tempfile.TemporaryDirectory() as temp:
            snapshot = write_snapshot(
                Path(temp),
                "ABC12",
                1,
                ranked,
                lambda _: (_ for _ in ()).throw(TimeoutError("DNS query timed out")),
                PROVIDERS,
                dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc),
                0,
            )
        self.assertEqual(snapshot["domains"][0]["spf"]["status"], "lookup_error")
        self.assertEqual(snapshot["domains"][0]["dmarc"]["status"], "lookup_error")
        self.assertEqual(snapshot["summary"]["spf"]["lookup_error"], 1)

    def test_evidence_objects_are_deduplicated_and_raw_rows_keep_only_references(self):
        import base64
        import hashlib

        security_body = b"Contact: mailto:security@example.au\nExpires: 2027-09-29T00:00:00Z\n"
        security_hash = hashlib.sha256(security_body).hexdigest()
        certificate_hash = "a" * 64
        certificate_metadata = {
            "sha256_fingerprint": certificate_hash,
            "subject": "CN=example.au",
            "issuer": "CN=CA",
            "subject_alt_names": [{"type": "DNSName", "value": "example.au"}],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
        }
        def checker(_domain):
            return {
                "checkdmarc": {"spf": {"record": "v=spf1 -all", "valid": True, "parsed": {"all": "fail"}}},
                "web": {
                    "security_txt": {
                        "status": "present", "validity_status": "valid", "sha256": security_hash,
                        "preferred_scheme": "https", "resources": [{"path": "/.well-known/security.txt", "sha256": security_hash}],
                    },
                    "tls": {"status": "valid", "certificates": [{"status": "valid", "sha256_fingerprint": certificate_hash, "days_until_expiry_at_scan": 94.0}]},
                    "security_txt_objects": {security_hash: base64.b64encode(security_body).decode("ascii")},
                    "certificate_objects": {certificate_hash: certificate_metadata},
                },
            }

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            snapshot = write_snapshot(
                output,
                "ABC12",
                2,
                [{"rank": 1, "domain": "one.example.au"}, {"rank": 2, "domain": "two.example.au"}],
                checker,
                PROVIDERS,
                dt.datetime(2026, 9, 29, tzinfo=dt.timezone.utc),
                0,
            )
            self.assertEqual((output / "security-txt" / f"{security_hash}.txt").read_bytes(), security_body)
            self.assertEqual(json.loads((output / "certificates" / f"{certificate_hash}.json").read_text()), certificate_metadata)
            self.assertEqual(len(list((output / "security-txt").glob("*.txt"))), 1)
            self.assertEqual(len(list((output / "certificates").glob("*.json"))), 1)
            self.assertEqual(snapshot["domains"][0]["security_txt"]["sha256"], security_hash)
            self.assertEqual(snapshot["domains"][0]["web"]["tls"]["certificates"][0]["sha256_fingerprint"], certificate_hash)
            self.assertNotIn("security_txt_objects", snapshot["domains"][0]["web"])
            with gzip.open(output / snapshot["raw_archive"], "rt", encoding="utf-8") as stream:
                raw_text = stream.read()
            self.assertNotIn("security_txt_objects", raw_text)
            self.assertNotIn("certificate_objects", raw_text)
            self.assertNotIn(base64.b64encode(security_body).decode("ascii"), raw_text)
            self.assertNotIn(security_body.decode("ascii"), raw_text)
            self.assertNotIn("CN=example.au", raw_text)
            self.assertIn(security_hash, raw_text)
            self.assertIn(certificate_hash, raw_text)

    def test_per_field_size_report_includes_normalized_and_raw_fields(self):
        report = field_size_report(
            {"generated_at": "now", "domains": [{"spf": {"record": "x"}, "web": {"title": "y"}}]},
            [{"raw": {"spf": "x"}, "domain": "example.au"}],
        )
        self.assertIn("domains.spf", report)
        self.assertIn("domains.web", report)
        self.assertIn("raw.raw", report)
        self.assertGreater(report["domains.spf"]["serialized_bytes"], 0)
        self.assertGreater(report["raw.raw"]["gzip_bytes"], 0)

    def test_changed_security_txt_body_is_retained_as_a_new_hash_object(self):
        import base64
        import hashlib

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            for index, body in enumerate((b"Contact: mailto:a@example.au\n", b"Contact: mailto:b@example.au\n"), start=1):
                digest = hashlib.sha256(body).hexdigest()
                def checker(_domain):
                    return {
                        "web": {
                            "security_txt": {"status": "present", "validity_status": "invalid", "sha256": digest, "resources": [{"sha256": digest}]},
                            "security_txt_objects": {digest: base64.b64encode(body).decode("ascii")},
                        },
                    }
                write_snapshot(
                    output,
                    f"ABC1{index}",
                    1,
                    [{"rank": 1, "domain": "example.au"}],
                    checker,
                    PROVIDERS,
                    dt.datetime(2026, 10, index, tzinfo=dt.timezone.utc),
                    0,
                )
            hashes = {hashlib.sha256(path.read_bytes()).hexdigest() for path in (output / "security-txt").glob("*.txt")}
            self.assertEqual(len(hashes), 2)
            self.assertEqual(len(list((output / "security-txt").glob("*.txt"))), 2)

    def test_merge_requires_every_shard_and_keeps_latest_retry_attempt(self):
        prepared = {
            "generated_at": "2026-09-28T00:00:00Z",
            "source": {"list_id": "ABCD1", "rank_limit": 2, "ranked_entry_count": 2, "au_entry_count": 2, "tracked_domain_count": 2},
            "shard_size": 1,
            "shard_count": 2,
            "registry": {"schema_version": 1, "domains": {
                "one.example.au": {"domain": "one.example.au", "last_rank": 1},
                "two.example.au": {"domain": "two.example.au", "last_rank": 2},
            }},
            "domains": [
                {"rank": 1, "rank_status": "in_top_1m", "rank_display": "#1", "au_rank": 1, "au_rank_total": 2, "last_rank": 1, "last_au_rank": 1, "domain": "one.example.au"},
                {"rank": 2, "rank_status": "in_top_1m", "rank_display": "#2", "au_rank": 2, "au_rank_total": 2, "last_rank": 2, "last_au_rank": 2, "domain": "two.example.au"},
            ],
        }
        sample_rows = []
        for entry in prepared["domains"]:
            normalized = normalize_domain_result(
                entry["domain"],
                entry["rank"],
                {"spf": {"record": None, "valid": False, "error": "SPF record does not exist"}},
                provider_catalog=PROVIDERS,
                rank_metadata=entry,
            )
            sample_rows.append({
                "rank": entry["rank"],
                "rank_status": entry["rank_status"],
                "au_rank": entry["au_rank"],
                "domain": entry["domain"],
                "normalized": normalized,
                "raw": {"checkdmarc": {"spf": {"record": None}}},
                "collection_error": None,
            })
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            input_path = root / "input.json"
            input_path.write_text(json.dumps(prepared), encoding="utf-8")
            shard_dir = root / "shards"
            shard_dir.mkdir()

            def write_shard(index, attempt, row):
                with gzip.open(shard_dir / f"shard-{index}-attempt-{attempt}.jsonl.gz", "wt", encoding="utf-8") as stream:
                    stream.write(json.dumps({"shard": index, "attempt": attempt, **row}) + "\n")

            write_shard(0, 1, sample_rows[0])
            write_shard(0, 2, sample_rows[0])
            write_shard(1, 1, sample_rows[1])
            output = root / "data"
            snapshot = merge_scan(input_path, shard_dir, output)
            self.assertEqual([row["rank"] for row in snapshot["domains"]], [1, 2])
            self.assertTrue((output / snapshot["raw_archive"]).exists())
            self.assertTrue((output / "registry.json").exists())

            (shard_dir / "shard-1-attempt-1.jsonl.gz").unlink()
            with self.assertRaisesRegex(RuntimeError, "missing shard outputs"):
                merge_scan(input_path, shard_dir, root / "incomplete")


if __name__ == "__main__":
    unittest.main()
