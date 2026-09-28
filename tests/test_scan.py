import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from collector.scan import (
    classify_record,
    effective_spf_terminal,
    infer_provider_clues,
    is_au_domain,
    normalize_domain_result,
    parse_ranked_csv,
    snapshot_summary,
    write_snapshot,
)


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
        self.assertEqual(result["dnssec"]["status"], "validated")

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


if __name__ == "__main__":
    unittest.main()
