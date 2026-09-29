import datetime as dt
import unittest
from unittest.mock import patch

from collector import web_checks


NOW = dt.datetime(2026, 9, 29, tzinfo=dt.timezone.utc)
VALID_TEXT = b"Contact: mailto:security@example.au\nExpires: 2027-09-29T00:00:00Z\n"
HEADERS = {"content-type": "text/plain; charset=utf-8", "server": "test-httpd"}


def response(url="http://example.au/.well-known/security.txt", body=VALID_TEXT, status=200, **overrides):
    result = {
        "url": url,
        "final_url": url,
        "state": "response",
        "status_code": status,
        "headers": dict(HEADERS),
        "redirects_to_https": False,
        "hops": [{"url": url, "status_code": status, "headers": dict(HEADERS), "tls_certificate": "not_observed"}],
        "tls_certificate": "not_observed",
        "body_complete": True,
    }
    result.update(overrides)
    return result, body


class SecurityTxtProbeTests(unittest.TestCase):
    def test_http_get_is_first_and_content_values_are_discarded(self):
        calls = []

        def request(url, **_kwargs):
            calls.append(url)
            return response(url)

        with patch.object(web_checks, "request_chain", side_effect=request):
            result = web_checks.probe_security_txt("Example.AU", now=NOW)

        self.assertEqual(calls, ["http://example.au/.well-known/security.txt"])
        self.assertEqual(result["availability"], "present")
        self.assertEqual(result["content_validity"], "valid")
        self.assertEqual(result["freshness"], "current")
        self.assertEqual(result["tls_certificate"], "not_observed")
        serialized = repr(result)
        self.assertNotIn("security@example.au", serialized)
        self.assertNotIn(VALID_TEXT.decode(), serialized)
        self.assertNotIn("sha256", serialized.lower())

    def test_http_404_and_other_http_errors_do_not_trigger_https_fallback(self):
        for code, expected in ((404, "absent"), (410, "absent"), (403, "http_error"), (500, "http_error")):
            with self.subTest(code=code):
                calls = []

                def request(url, **_kwargs):
                    calls.append(url)
                    return response(url, body=b"", status=code)

                with patch.object(web_checks, "request_chain", side_effect=request):
                    result = web_checks.probe_security_txt("example.au", now=NOW)
                self.assertEqual(calls, ["http://example.au/.well-known/security.txt"])
                self.assertEqual(result["availability"], expected)
                self.assertEqual(result["content_validity"], "not_assessable")

    def test_connection_failure_triggers_one_direct_https_attempt(self):
        calls = []

        def request(url, **_kwargs):
            calls.append(url)
            if url.startswith("http:"):
                return ({"url": url, "final_url": url, "state": "lookup_error", "error_kind": "lookup_error", "status_code": None, "hops": [{"state": "lookup_error"}], "tls_certificate": "not_observed"}, b"")
            return response(url.replace("http:", "https:"), body=VALID_TEXT, tls_certificate="valid", hops=[{"url": url.replace("http:", "https:"), "status_code": 200, "headers": dict(HEADERS), "tls_certificate": "valid"}])[0:2]

        with patch.object(web_checks, "request_chain", side_effect=request):
            result = web_checks.probe_security_txt("example.au", now=NOW)

        self.assertEqual(calls, ["http://example.au/.well-known/security.txt", "https://example.au/.well-known/security.txt"])
        self.assertTrue(result["request"]["fallback_attempted"])
        self.assertEqual(result["availability"], "present")
        self.assertEqual(result["content_validity"], "valid")
        self.assertEqual(result["tls_certificate"], "valid")
        self.assertTrue(result["request"]["https_response_received"])

    def test_pre_response_request_error_triggers_https_fallback(self):
        calls = []

        def request(url, **_kwargs):
            calls.append(url)
            if url.startswith("http:"):
                return ({"url": url, "final_url": url, "state": "request_error", "status_code": None, "hops": [{"state": "request_error"}], "tls_certificate": "not_observed"}, b"")
            return response(url.replace("http:", "https:"), body=VALID_TEXT, tls_certificate="valid", hops=[{"url": url.replace("http:", "https:"), "status_code": 200, "headers": dict(HEADERS), "tls_certificate": "valid"}])

        with patch.object(web_checks, "request_chain", side_effect=request):
            result = web_checks.probe_security_txt("example.au", now=NOW)

        self.assertEqual(calls, ["http://example.au/.well-known/security.txt", "https://example.au/.well-known/security.txt"])
        self.assertTrue(result["request"]["fallback_attempted"])
        self.assertEqual(result["availability"], "present")

    def test_http_redirect_to_https_is_followed_in_one_chain(self):
        url = "http://example.au/.well-known/security.txt"
        target = "https://example.au/.well-known/security.txt"
        chain = {
            "url": url,
            "final_url": target,
            "state": "response",
            "status_code": 200,
            "headers": dict(HEADERS),
            "redirects_to_https": True,
            "hops": [
                {"url": url, "status_code": 301, "redirect_to": target, "headers": {"server": "edge"}},
                {"url": target, "status_code": 200, "headers": dict(HEADERS), "tls_certificate": "valid"},
            ],
            "tls_certificate": "valid",
            "body_complete": True,
        }
        with patch.object(web_checks, "request_chain", return_value=(chain, VALID_TEXT)) as request:
            result = web_checks.probe_security_txt("example.au", now=NOW)
        request.assert_called_once()
        self.assertTrue(result["request"]["redirects_to_https"])
        self.assertTrue(result["request"]["https_response_received"])
        self.assertEqual(result["request"]["attempts"][0]["hops"][0]["redirect_to"], target)
        self.assertEqual(result["tls_certificate"], "valid")

    def test_redirect_chain_failure_does_not_start_a_second_https_chain(self):
        url = "http://example.au/.well-known/security.txt"
        chain = {
            "url": url,
            "final_url": "https://example.au/.well-known/security.txt",
            "state": "lookup_error",
            "status_code": None,
            "hops": [{"url": url, "status_code": 302, "redirect_to": "https://example.au/.well-known/security.txt", "headers": {"location": "https://example.au/.well-known/security.txt"}}, {"state": "lookup_error"}],
            "tls_certificate": "not_observed",
        }
        with patch.object(web_checks, "request_chain", return_value=(chain, b"")) as request:
            result = web_checks.probe_security_txt("example.au", now=NOW)
        request.assert_called_once()
        self.assertFalse(result["request"]["fallback_attempted"])
        self.assertEqual(result["availability"], "lookup_error")
        self.assertTrue(result["request"]["redirects_to_https"])

    def test_invalid_https_certificate_is_distinct_from_no_response(self):
        calls = []

        def request(url, **_kwargs):
            calls.append(url)
            if url.startswith("http:"):
                return ({"url": url, "state": "lookup_error", "status_code": None, "hops": [{"state": "lookup_error"}], "tls_certificate": "not_observed"}, b"")
            return ({"url": url, "state": "tls_error", "error_kind": "tls_error", "status_code": None, "hops": [{"url": url, "state": "tls_error", "tls_certificate": "invalid"}], "tls_certificate": "invalid"}, b"")

        with patch.object(web_checks, "request_chain", side_effect=request):
            result = web_checks.probe_security_txt("example.au", now=NOW)
        self.assertEqual(result["availability"], "lookup_error")
        self.assertEqual(result["tls_certificate"], "invalid")
        serialized = repr(result).lower()
        for detail in ("fingerprint", "subject_alt_names", "issuer", "not_after", "certificate_invalid"):
            self.assertNotIn(detail, serialized)
        self.assertEqual(len(calls), 2)

    def test_content_validation_distinguishes_bad_utf8_type_fields_and_expiry(self):
        samples = [
            (b"Contact: mailto:a@example.au\nExpires: 2027-09-29T00:00:00Z\n", {**HEADERS, "content-type": "text/html"}, "invalid", "content_type_invalid"),
            (b"Contact: mailto:a@example.au\nExpires: 2027-09-29T00:00:00Z\n\xff", HEADERS, "invalid", "utf8_invalid"),
            (b"Expires: 2027-09-29T00:00:00Z\n", HEADERS, "invalid", "contact_missing"),
            (b"Contact: mailto:a@example.au\n", HEADERS, "invalid", "expires_missing"),
            (b"Contact: mailto:a@example.au\nExpires: 2027-02-30T00:00:00Z\n", HEADERS, "invalid", "expires_malformed"),
        ]
        for body, headers, expected, reason in samples:
            with self.subTest(reason=reason):
                result_value, _ = response(body=body)
                result_value["headers"] = headers
                result_value["hops"][0]["headers"] = headers
                with patch.object(web_checks, "request_chain", return_value=(result_value, body)):
                    result = web_checks.probe_security_txt("example.au", now=NOW)
                self.assertEqual(result["content_validity"], expected)
                self.assertIn(reason, result["validation"]["reasons"])

    def test_rfc3339_expires_accepts_lowercase_case_fraction_and_offsets(self):
        values = (
            "2027-09-29T00:00:00Z",
            "2027-09-29t00:00:00z",
            "2027-09-29T00:00:00.123456789Z",
            "2027-09-29T10:30:00+10:30",
            "2027-09-28T13:30:00-10:30",
        )
        for value in values:
            body = f"Contact: mailto:a@example.au\nExpires: {value}\n".encode()
            with self.subTest(value=value), patch.object(web_checks, "request_chain", return_value=response(body=body)):
                result = web_checks.probe_security_txt("example.au", now=NOW)
            self.assertEqual(result["content_validity"], "valid")
            self.assertEqual(result["freshness"], "current")
            self.assertTrue(result["validation"]["expires_valid"])

    def test_expired_security_txt_is_format_valid_but_stale(self):
        body = b"Contact: mailto:a@example.au\nExpires: 2025-09-29T00:00:00Z\n"
        with patch.object(web_checks, "request_chain", return_value=response(body=body)):
            result = web_checks.probe_security_txt("example.au", now=NOW)
        self.assertEqual(result["content_validity"], "valid")
        self.assertEqual(result["freshness"], "expired")
        self.assertTrue(result["validation"]["expired"])
        self.assertTrue(result["validation"]["expires_valid"])
        self.assertNotIn("expired", result["validation"]["reasons"])

    def test_leap_seconds_are_accepted_only_at_announced_utc_instants(self):
        valid = web_checks._parse_security_txt(
            "Contact: mailto:a@example.au\nExpires: 2016-12-31T23:59:60Z\n", NOW
        )
        self.assertTrue(valid["expires_valid"])
        self.assertEqual(valid["freshness"], "expired")
        invalid = web_checks._parse_security_txt(
            "Contact: mailto:a@example.au\nExpires: 2017-12-31T23:59:60Z\n", NOW
        )
        self.assertFalse(invalid["expires_valid"])
        self.assertIn("expires_malformed", invalid["reasons"])

    def test_duplicate_expires_is_invalid_even_when_both_dates_parse(self):
        parsed = web_checks._parse_security_txt(
            "Contact: mailto:a@example.au\n"
            "Expires: 2027-09-29T00:00:00Z\n"
            "Expires: 2028-09-29T00:00:00Z\n",
            NOW,
        )
        self.assertIn("expires_multiple", parsed["reasons"])
        self.assertFalse(parsed["expires_valid"])
        self.assertEqual(parsed["freshness"], "unknown")

    def test_expires_requires_ascii_rfc3339_digits(self):
        parsed = web_checks._parse_security_txt(
            "Contact: mailto:a@example.au\nExpires: ٢٠٢٧-09-29T00:00:00Z\n", NOW
        )
        self.assertFalse(parsed["expires_valid"])
        self.assertIn("expires_malformed", parsed["reasons"])

    def test_contact_schemes_and_https_urls_without_paths(self):
        for contact in (
            "mailto:security@example.au",
            "tel:+61-2-1234-5678",
            "https://example.au",
        ):
            with self.subTest(contact=contact):
                parsed = web_checks._parse_security_txt(
                    f"Contact: {contact}\nExpires: 2027-09-29T00:00:00Z\n", NOW
                )
                self.assertTrue(parsed["contact_valid"])
                self.assertEqual(parsed["reasons"], [])
        for contact in ("http://example.au/contact", "mailto:", "tel:", "https://"):
            with self.subTest(contact=contact):
                parsed = web_checks._parse_security_txt(
                    f"Contact: {contact}\nExpires: 2027-09-29T00:00:00Z\n", NOW
                )
                self.assertFalse(parsed["contact_valid"])
                self.assertIn("contact_invalid", parsed["reasons"])

    def test_optional_fields_extensions_and_language_tags(self):
        valid = (
            "contact: mailto:security@example.au\n"
            "Contact: tel:+61-2-1234-5678\n"
            "Preferred-Languages: en, en-AU, zh-Hant-TW\n"
            "Policy: https://example.au/disclosure\n"
            "Encryption: dns:example.au?type=OPENPGPKEY\n"
            "X-Research-Note: extension field is accepted\n"
            "Expires: 2027-09-29T00:00:00Z\n"
        )
        parsed = web_checks._parse_security_txt(valid, NOW)
        self.assertEqual(parsed["reasons"], [])
        self.assertTrue(parsed["uri_fields_valid"])
        self.assertTrue(parsed["preferred_languages_valid"])

        invalid_samples = (
            "Contact: mailto:a@example.au\nPreferred-Languages: en,,fr\nExpires: 2027-09-29T00:00:00Z\n",
            "Contact: mailto:a@example.au\nPreferred-Languages: en\nPreferred-Languages: fr\nExpires: 2027-09-29T00:00:00Z\n",
            "Contact: mailto:a@example.au\nPolicy: http://example.au/policy\nExpires: 2027-09-29T00:00:00Z\n",
            "Contact: mailto:a@example.au\nPolicy: https://example.au/%zz\nExpires: 2027-09-29T00:00:00Z\n",
        )
        for value in invalid_samples:
            with self.subTest(value=value):
                self.assertTrue(web_checks._parse_security_txt(value, NOW)["reasons"])

    def test_field_grammar_line_endings_and_net_unicode(self):
        valid_lf = "# comment\nContact: mailto:a@example.au\n\nExpires: 2027-09-29T00:00:00Z\n"
        valid_mixed = "Contact: mailto:a@example.au\r\nExpires: 2027-09-29T00:00:00Z\n"
        self.assertEqual(web_checks._parse_security_txt(valid_lf, NOW)["reasons"], [])
        self.assertEqual(web_checks._parse_security_txt(valid_mixed, NOW)["reasons"], [])
        invalid = (
            "Contact: mailto:a@example.au\nExpires: 2027-09-29T00:00:00Z",
            " Contact: mailto:a@example.au\nExpires: 2027-09-29T00:00:00Z\n",
            "# ok\nContact: mailto:a@example.au\rExpires: 2027-09-29T00:00:00Z\n",
            "Contact: mailto:a@example.au\n\ufeffExpires: 2027-09-29T00:00:00Z\n",
            "Contact: mailto:a@example.au\nX-Field: invalid\u0085control\nExpires: 2027-09-29T00:00:00Z\n",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertTrue(web_checks._parse_security_txt(value, NOW)["reasons"])

    def test_resource_limits_are_not_assessed_as_invalid(self):
        too_many_lines = "Contact: mailto:a@example.au\n" + "# line\n" * 999 + "Expires: 2027-09-29T00:00:00Z\n"
        too_long_field = "Contact: mailto:a@example.au\nX-Note: " + ("x" * 2048) + "\nExpires: 2027-09-29T00:00:00Z\n"
        for value in (too_many_lines, too_long_field):
            with self.subTest(length=len(value)):
                parsed = web_checks._parse_security_txt(value, NOW)
                self.assertTrue(parsed["not_assessable"])
                self.assertEqual(parsed["reasons"], ["parser_limit_exceeded"])

    def test_signed_file_structure_is_accepted_but_not_verified(self):
        signed = (
            "-----BEGIN PGP SIGNED MESSAGE-----\r\n"
            "Hash: SHA256\r\n\r\n"
            "Contact: mailto:security@example.au\r\n"
            "Expires: 2027-09-29T00:00:00Z\r\n"
            "-----BEGIN PGP SIGNATURE-----\r\n"
            "Version: GnuPG v2.2\r\n\r\n"
            "YWJjZA==\r\n"
            "-----END PGP SIGNATURE-----\r\n"
        )
        parsed = web_checks._parse_security_txt(signed, NOW)
        self.assertEqual(parsed["reasons"], [])
        self.assertEqual(parsed["signature_status"], "present_unverified")
        malformed = web_checks._parse_security_txt(
            "-----BEGIN PGP SIGNED MESSAGE-----\nContact: mailto:a@example.au\n", NOW
        )
        self.assertEqual(malformed["signature_status"], "invalid")
        self.assertIn("signed_format_invalid", malformed["reasons"])

    def test_cross_host_redirect_is_reported_without_invalidating_content(self):
        url = "http://example.au/.well-known/security.txt"
        target = "https://www.example.au/.well-known/security.txt"
        chain = {
            "url": url, "final_url": target, "state": "response", "status_code": 200,
            "headers": dict(HEADERS), "redirects_to_https": True,
            "hops": [
                {"url": url, "status_code": 301, "redirect_to": target, "headers": {"location": target}},
                {"url": target, "status_code": 200, "headers": dict(HEADERS), "tls_certificate": "valid"},
            ], "tls_certificate": "valid", "body_complete": True,
        }
        with patch.object(web_checks, "request_chain", return_value=(chain, VALID_TEXT)):
            result = web_checks.probe_security_txt("example.au", now=NOW)
        self.assertEqual(result["content_validity"], "valid")
        self.assertTrue(result["request"]["cross_host_redirect"])

    def test_content_type_requires_text_plain_and_well_formed_utf8_charset(self):
        accepted = (
            "text/plain", "Text/Plain; charset=utf-8", "text/plain; charset=\"UTF-8\"",
            'text/plain; title="research; contact"; charset=utf-8',
        )
        rejected = (
            "text/html", "text/plain; charset=latin1", "text/plain; charset",
            "text/plain; charset=", "text/plain; charset=utf-8; charset=utf-8",
        )
        for value in accepted:
            self.assertTrue(web_checks._content_type_valid({"content-type": value}), value)
        for value in rejected:
            self.assertFalse(web_checks._content_type_valid({"content-type": value}), value)

    def test_truncated_body_is_not_assessed_as_invalid(self):
        result_value, body = response(body=VALID_TEXT, body_complete=False, body_truncated=True)
        with patch.object(web_checks, "request_chain", return_value=(result_value, body)):
            result = web_checks.probe_security_txt("example.au", now=NOW)
        self.assertEqual(result["availability"], "present")
        self.assertEqual(result["content_validity"], "not_assessable")
        self.assertEqual(result["validation"]["reasons"], ["body_incomplete"])

    def test_complete_response_over_body_limit_is_not_assessed(self):
        body = b"x" * (web_checks.MAX_SECURITY_TXT_BYTES + 1)
        result_value, _ = response(body=body)
        with patch.object(web_checks, "request_chain", return_value=(result_value, body)):
            result = web_checks.probe_security_txt("example.au", now=NOW)
        self.assertEqual(result["availability"], "present")
        self.assertEqual(result["content_validity"], "not_assessable")
        self.assertEqual(result["freshness"], "unknown")
        self.assertEqual(result["validation"]["reasons"], ["parser_limit_exceeded"])

    def test_request_chain_follows_bounded_redirects_and_keeps_only_selected_headers(self):
        start = "http://example.au/.well-known/security.txt"
        secure = "https://example.au/.well-known/security.txt"
        calls = []

        def once(url, _deadline, _limit, _resolver):
            calls.append(url)
            if len(calls) == 1:
                return ({"url": url, "state": "response", "status_code": 302, "location": secure, "headers": {"server": "edge"}, "tls_certificate": "not_observed"}, b"")
            return ({"url": url, "state": "response", "status_code": 200, "location": None, "headers": {"content-type": "text/plain"}, "tls_certificate": "valid", "body_complete": True}, VALID_TEXT)

        with patch.object(web_checks, "_request_once", side_effect=once):
            result, body = web_checks.request_chain(start, address_resolver=lambda *_: (["8.8.8.8"], None))
        self.assertEqual(calls, [start, secure])
        self.assertTrue(result["redirects_to_https"])
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(body, VALID_TEXT)
        serialized = repr(result).lower()
        self.assertNotIn("set-cookie", serialized)
        self.assertNotIn("secret=123", serialized)

    def test_private_destinations_are_blocked(self):
        result, body = web_checks._request_once(
            "http://example.au/.well-known/security.txt",
            web_checks.time.monotonic() + 2,
            1024,
            lambda _host, _timeout: (["127.0.0.1"], None),
        )
        self.assertEqual(result["state"], "blocked_destination")
        self.assertEqual(body, b"")

    def test_body_reader_never_exceeds_the_security_txt_limit(self):
        class FakeSocket:
            def settimeout(self, _value): pass

        class FakeResponse:
            def __init__(self):
                self.chunks = [b"abcd", b"ef"]
                self.length = 6
            def read1(self, size):
                chunk = self.chunks.pop(0)[:size] if self.chunks else b""
                self.length -= len(chunk)
                return chunk

        class FakeConnection:
            sock = FakeSocket()

        body, truncated = web_checks._read_bounded_body(
            FakeResponse(), FakeConnection(), 4, web_checks.time.monotonic() + 2
        )
        self.assertEqual(body, b"abcd")
        self.assertTrue(truncated)

    def test_only_allowlisted_response_headers_are_retained(self):
        class Headers:
            values = {
                "server": ["example-server"],
                "content-type": ["text/plain; charset=utf-8"],
                "set-cookie": ["session=private-value; Secure"],
                "x-unrelated": ["private-value"],
            }

            def get_all(self, name):
                return self.values.get(name)

        class Response:
            headers = Headers()

        selected = web_checks._selected_headers(Response())
        self.assertEqual(selected["server"], "example-server")
        self.assertEqual(selected["content-type"], "text/plain; charset=utf-8")
        self.assertNotIn("set-cookie", selected)
        self.assertNotIn("x-unrelated", selected)
        self.assertNotIn("private-value", repr(selected))


if __name__ == "__main__":
    unittest.main()
