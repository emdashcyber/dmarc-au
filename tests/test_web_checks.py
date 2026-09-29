import datetime as dt
import ssl
import unittest
from unittest.mock import patch

from collector import web_checks


NOW = dt.datetime(2026, 9, 29, tzinfo=dt.timezone.utc)
VALID_TEXT = "Contact: mailto:security@example.au\nExpires: 2027-09-29T00:00:00Z\nCanonical: https://example.au/.well-known/security.txt\n"


def resource(path="/.well-known/security.txt", scheme="https", raw_text=VALID_TEXT, **overrides):
    value = {
        "url": f"{scheme}://example.au{path}",
        "final_url": f"{scheme}://example.au{path}",
        "scheme": scheme,
        "path": path,
        "state": "response",
        "status_code": 200,
        "headers": {"content-type": "text/plain; charset=utf-8"},
        "tls": {"status": "valid"} if scheme == "https" else None,
        "raw_text": raw_text,
        "encoding_valid": True,
        "body_truncated": False,
    }
    value.update(overrides)
    return value


class SecurityTxtTests(unittest.TestCase):
    def test_well_known_valid_record_wins_and_both_contents_are_compared(self):
        legacy_text = VALID_TEXT.replace("security@example.au", "team@example.au")
        result = web_checks.validate_security_txt(
            "example.au",
            [
                resource("/security.txt", raw_text=legacy_text),
                resource("/.well-known/security.txt", raw_text=VALID_TEXT),
            ],
            NOW,
        )
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["preferred_path"], "/.well-known/security.txt")
        self.assertEqual(result["raw_text"], VALID_TEXT)
        self.assertTrue(result["duplicate_content_differs"])

    def test_valid_legacy_location_is_distinguished(self):
        result = web_checks.validate_security_txt("example.au", [resource("/security.txt")], NOW)
        self.assertEqual(result["status"], "valid_legacy")
        self.assertTrue(result["resources"][0]["validation"]["https_valid"])

    def test_expired_malformed_utf8_wrong_content_type_and_truncation_are_invalid(self):
        expired = VALID_TEXT.replace("2027-09-29", "2025-09-29")
        cases = [
            (resource(raw_text=expired), "expired"),
            (resource(raw_text="Expires: 2027-09-29T00:00:00Z\n"), "invalid"),
            (resource(headers={"content-type": "application/octet-stream"}), "invalid"),
            (resource(encoding_valid=False), "invalid"),
            (resource(body_truncated=True), "invalid"),
        ]
        for item, expected in cases:
            with self.subTest(item=item):
                result = web_checks.validate_security_txt("example.au", [item], NOW)
                self.assertEqual(result["status"], expected)

    def test_http_only_is_insecure_and_dns_failures_are_not_absent(self):
        insecure = web_checks.validate_security_txt("example.au", [resource(scheme="http")], NOW)
        self.assertEqual(insecure["status"], "insecure_transport")
        errors = [
            {"scheme": "https", "path": path, "state": "lookup_error", "error": "SERVFAIL"}
            for path in ("/.well-known/security.txt", "/security.txt")
        ]
        unavailable = web_checks.validate_security_txt("example.au", errors, NOW)
        self.assertEqual(unavailable["status"], "lookup_error")

    def test_required_contacts_and_rfc3339_expiry_are_checked(self):
        for text in (
            "Expires: 2027-09-29T00:00:00Z\n",
            "Contact: ftp://example.au/security\nExpires: 2027-09-29 00:00:00\n",
        ):
            result = web_checks.validate_security_txt("example.au", [resource(raw_text=text)], NOW)
            self.assertEqual(result["status"], "invalid")


class WebProbeTests(unittest.TestCase):
    def test_title_and_meta_refresh_are_extracted_without_running_scripts(self):
        body = b"<html><head><title>  AU  Research &amp; Security </title><meta http-equiv='refresh' content='0; URL=\"https://www.example.au/path\"'></head><script>document.title='changed'</script></html>"
        result = web_checks.parse_page_metadata(body, "http://example.au/")
        self.assertEqual(result["title"], "AU Research & Security")
        self.assertEqual(result["meta_refresh_targets"], ["https://www.example.au/path"])

    def test_redirect_chain_records_each_hop_and_follows_https_location(self):
        calls = []

        def once(url, method, deadline, body_limit, address_resolver):
            calls.append((url, method, body_limit))
            if len(calls) == 1:
                return ({"url": url, "status_code": 301, "location": "https://example.au/secure", "headers": {}, "tls": None}, b"", None)
            return ({"url": url, "status_code": 200, "location": None, "headers": {}, "tls": {"status": "valid"}}, b"ok", None)

        with patch.object(web_checks, "_request_once", side_effect=once):
            result, body = web_checks.request_chain("http://example.au/", method="GET", body_limit=64)
        self.assertEqual(result["state"], "response")
        self.assertEqual([hop["status_code"] for hop in result["hops"]], [301, 200])
        self.assertEqual(calls[1][0], "https://example.au/secure")
        self.assertEqual(body, b"ok")

    def test_redirect_limit_and_certificate_failure_states_are_retained(self):
        def redirect(url, method, deadline, body_limit, address_resolver):
            return ({"url": url, "status_code": 302, "location": "/again", "headers": {}, "tls": None}, b"", None)

        with patch.object(web_checks, "_request_once", side_effect=redirect):
            result, _ = web_checks.request_chain("http://example.au/", max_redirects=1)
        self.assertEqual(result["state"], "redirect_limit")
        self.assertEqual(len(result["hops"]), 2)
        self.assertEqual(web_checks._exception_state(ssl.SSLCertVerificationError("hostname mismatch")), "certificate_name_mismatch")
        self.assertEqual(web_checks._exception_state(ssl.SSLCertVerificationError("certificate has expired")), "certificate_expired")

    def test_homepage_body_reader_never_exceeds_the_configured_limit(self):
        class FakeSocket:
            def __init__(self):
                self.timeouts = []
            def settimeout(self, value):
                self.timeouts.append(value)

        class FakeResponse:
            def __init__(self):
                self.chunks = [b"abcd", b"ef"]
                self.requested = []
                self.length = 6
            def read1(self, size):
                self.requested.append(size)
                chunk = self.chunks.pop(0)[:size] if self.chunks else b""
                self.length -= len(chunk)
                return chunk

        class FakeConnection:
            def __init__(self):
                self.sock = FakeSocket()

        response = FakeResponse()
        body, truncated = web_checks._read_bounded_body(response, FakeConnection(), 4, web_checks.time.monotonic() + 2)
        self.assertEqual(body, b"abcd")
        self.assertTrue(truncated)
        self.assertEqual(response.requested, [4])

    def test_probe_uses_head_without_body_and_get_for_title_and_headers(self):
        calls = []

        def fake_chain(url, method="GET", body_limit=0, **kwargs):
            calls.append((url, method, body_limit))
            if "/security.txt" in url:
                return ({"url": url, "final_url": url, "state": "response", "status_code": 404, "headers": {}, "hops": []}, b"")
            https = url.startswith("https:")
            headers = {"content-security-policy": "default-src 'self'", "server": "nginx"}
            tls = {"status": "valid", "protocol": "TLSv1.3", "cipher": ["TLS_AES_128_GCM_SHA256", "TLSv1.3", 128]} if https else None
            response = {"url": url, "final_url": url, "state": "response", "status_code": 200, "headers": headers, "tls": tls, "hops": [{"url": url, "status_code": 200, "headers": headers, "tls": tls}]}
            body = (
                b"<title>Research home</title><meta http-equiv='refresh' content='0; url=https://www.example.au/'>"
                if method == "GET" and not https else b"<title>Secure home</title>" if method == "GET" else b""
            )
            return response, body

        with patch.object(web_checks, "request_chain", side_effect=fake_chain):
            result = web_checks.probe_web("example.au")
        self.assertEqual(result["page"]["title"], "Secure home")
        self.assertEqual(result["tls"]["status"], "valid")
        self.assertTrue(result["https_upgrade"]["meta_refresh_to_https"])
        self.assertTrue(result["header_presence"]["content-security-policy"])
        self.assertIn(("http://example.au/", "HEAD", 0), calls)
        self.assertIn(("https://example.au/", "HEAD", 0), calls)
        self.assertTrue(any(url == "https://example.au/" and method == "GET" and limit == web_checks.MAX_PAGE_BYTES for url, method, limit in calls))

    def test_cookie_values_are_never_retained(self):
        result = web_checks._cookie_metadata([
            "session=super-secret; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=60; Expires=Wed, 21 Oct 2030 07:28:00 GMT",
        ])
        serialized = repr(result)
        self.assertNotIn("super-secret", serialized)
        self.assertEqual(result[0]["name"], "session")
        self.assertTrue(result[0]["secure"])
        self.assertTrue(result[0]["httponly"])
        self.assertEqual(result[0]["samesite"], "Lax")
        self.assertEqual(result[0]["max-age"], "60")

    def test_header_notes_are_specific_observations_not_a_score(self):
        notes = web_checks.assess_security_headers(
            {"content-security-policy": "default-src * 'unsafe-inline'", "x-frame-options": "ALLOWALL"},
            {"active": False},
            [{"name": "sid", "secure": False, "httponly": False}],
        )
        self.assertIn("X-Content-Type-Options is absent or is not nosniff", notes)
        self.assertIn("Active HSTS was not observed on a verified HTTPS response", notes)
        self.assertTrue(any("wildcard" in note for note in notes))
        self.assertTrue(any("Cookie sid lacks Secure" in note for note in notes))

    def test_hsts_directives_are_parsed_only_from_https_responses(self):
        observation = web_checks._hsts_observation({
            "https": {"get": {"hops": [{"headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            }}]}},
        })
        self.assertTrue(observation["active"])
        self.assertEqual(observation["max_age"], 31536000)
        self.assertTrue(observation["include_subdomains"])
        self.assertTrue(observation["preload"])

    def test_dns_record_types_and_caa_ancestor_evidence(self):
        seen = []

        def query(name, record_type):
            seen.append((name, record_type))
            if record_type == "CAA" and name == "example.au":
                return {"status": "absent", "records": [], "ttl": None, "error": None, "cname_chain": []}
            if record_type == "CAA" and name == "au":
                return {"status": "present", "records": ["0 issue \"ca.example\""], "ttl": 60, "error": None, "cname_chain": []}
            return {"status": "absent", "records": [], "ttl": None, "error": None, "cname_chain": []}

        with patch.object(web_checks, "_dns_query_record", side_effect=query):
            result = web_checks.probe_web_dns("example.au")
        self.assertEqual(result["caa"]["direct"]["status"], "absent")
        self.assertEqual(result["caa"]["effective"]["status"], "present")
        self.assertEqual(result["caa"]["effective"]["source"], "inherited")
        self.assertEqual(result["caa"]["effective"]["owner"], "au")
        self.assertTrue({"A", "AAAA", "CNAME", "HTTPS", "CAA"}.issubset({kind for _, kind in seen}))

    def test_caa_lookup_error_does_not_become_absent_or_inherited(self):
        def query(name, record_type):
            status = "lookup_error" if record_type == "CAA" and name == "example.au" else "absent"
            return {"status": status, "records": [], "ttl": None, "error": "SERVFAIL" if status == "lookup_error" else None, "cname_chain": []}

        with patch.object(web_checks, "_dns_query_record", side_effect=query):
            result = web_checks.probe_web_dns("example.au")
        self.assertEqual(result["caa"]["effective"]["status"], "lookup_error")
        self.assertEqual(result["caa"]["effective"]["source"], "lookup_error")

    def test_http_probe_reuses_captured_public_a_and_aaaa_and_filters_private_addresses(self):
        resolver = web_checks.cached_address_resolver("example.au", {
            "a": {"status": "present", "records": ["203.0.113.10"]},
            "aaaa": {"status": "absent", "records": []},
        })
        self.assertEqual(resolver("example.au", 1), ([], "All resolved addresses are not globally routable"))
        # Documentation-only addresses are deliberately non-global, as are RFC1918 and loopback.
        with patch.object(web_checks, "_resolve_public_addresses", return_value=(["8.8.8.8"], None)) as fallback:
            self.assertEqual(resolver("www.example.au", 1), (["8.8.8.8"], None))
            fallback.assert_called_once()


if __name__ == "__main__":
    unittest.main()
