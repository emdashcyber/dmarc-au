import datetime as dt
import hashlib
import ssl
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from collector import web_checks


NOW = dt.datetime(2026, 9, 29, tzinfo=dt.timezone.utc)
VALID_TEXT = "Contact: mailto:security@example.au\nExpires: 2027-09-29T00:00:00Z\nCanonical: https://example.au/.well-known/security.txt\n"


def resource(path="/.well-known/security.txt", scheme="https", raw_text=VALID_TEXT, **overrides):
    raw_bytes = raw_text.encode("utf-8") if isinstance(raw_text, str) else b""
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
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "encoding_valid": True,
        "body_truncated": False,
    }
    value.update(overrides)
    return value


class SecurityTxtTests(unittest.TestCase):
    def test_https_well_known_record_is_preferred_and_distinct_bodies_are_hashed(self):
        http_text = VALID_TEXT.replace("security@example.au", "team@example.au")
        result = web_checks.validate_security_txt(
            "example.au",
            [
                resource(scheme="http", raw_text=http_text),
                resource(scheme="https", raw_text=VALID_TEXT),
            ],
            NOW,
        )
        self.assertEqual(result["status"], "present")
        self.assertEqual(result["validity_status"], "valid")
        self.assertEqual(result["preferred_path"], "/.well-known/security.txt")
        self.assertEqual(result["preferred_scheme"], "https")
        self.assertEqual(result["sha256"], hashlib.sha256(VALID_TEXT.encode()).hexdigest())
        self.assertTrue(result["duplicate_content_differs"])

    def test_http_only_well_known_file_is_present_but_insecure(self):
        result = web_checks.validate_security_txt("example.au", [resource(scheme="http")], NOW)
        self.assertEqual(result["status"], "present")
        self.assertEqual(result["validity_status"], "insecure_transport")
        self.assertFalse(result["resources"][0]["validation"]["https_valid"])

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
                self.assertEqual(result["status"], "present")
                self.assertEqual(result["validity_status"], expected)

    def test_http_only_is_insecure_and_dns_failures_are_not_absent(self):
        insecure = web_checks.validate_security_txt("example.au", [resource(scheme="http")], NOW)
        self.assertEqual(insecure["status"], "present")
        self.assertEqual(insecure["validity_status"], "insecure_transport")
        errors = [
            {"scheme": scheme, "path": "/.well-known/security.txt", "state": "lookup_error", "error": "SERVFAIL"}
            for scheme in ("http", "https")
        ]
        unavailable = web_checks.validate_security_txt("example.au", errors, NOW)
        self.assertEqual(unavailable["status"], "lookup_error")
        self.assertEqual(unavailable["validity_status"], "lookup_error")

    def test_both_absent_locations_remain_absent_without_losing_lookup_errors(self):
        result = web_checks.validate_security_txt("example.au", [
            {"scheme": "http", "path": "/.well-known/security.txt", "state": "response", "status_code": 404},
            {"scheme": "https", "path": "/.well-known/security.txt", "state": "response", "status_code": 404},
        ], NOW)
        self.assertEqual(result["status"], "absent")
        self.assertEqual(result["validity_status"], "absent")

    def test_required_contacts_and_rfc3339_expiry_are_checked(self):
        for text in (
            "Expires: 2027-09-29T00:00:00Z\n",
            "Contact: ftp://example.au/security\nExpires: 2027-09-29 00:00:00\n",
        ):
            result = web_checks.validate_security_txt("example.au", [resource(raw_text=text)], NOW)
            self.assertEqual(result["status"], "present")
            self.assertEqual(result["validity_status"], "invalid")


def make_certificate(not_before=None, not_after=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.au")])
    start = not_before or NOW - dt.timedelta(days=2)
    end = not_after or NOW + dt.timedelta(days=30)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start.replace(tzinfo=None))
        .not_valid_after(end.replace(tzinfo=None))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.au"), x509.DNSName("www.example.au")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class WebProbeTests(unittest.TestCase):
    def test_certificate_metadata_includes_subject_sans_dates_and_expiry_at_scan(self):
        der = make_certificate()
        metadata, days = web_checks._certificate_metadata(der, NOW)
        self.assertRegex(metadata["sha256_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(metadata["subject"], "CN=example.au")
        self.assertEqual(metadata["issuer"], "CN=example.au")
        self.assertEqual([item["value"] for item in metadata["subject_alt_names"]], ["example.au", "www.example.au"])
        self.assertEqual(metadata["not_before"], "2026-09-27T00:00:00Z")
        self.assertEqual(metadata["not_after"], "2026-10-29T00:00:00Z")
        self.assertEqual(days, 30.0)

    def test_unverified_certificate_diagnostics_keep_validation_state_and_fields(self):
        der = make_certificate()
        metadata, _ = web_checks._certificate_metadata(der, NOW)
        diagnostic = {
            "status": "certificate_name_mismatch",
            "certificate": metadata,
            "days_until_expiry_at_scan": 30.0,
            "protocol": "TLSv1.3",
            "cipher": ["TLS_AES_128_GCM_SHA256", "TLSv1.3", 128],
            "alpn": "http/1.1",
            "diagnostic_handshake": True,
        }

        class FakeConnection:
            sock = None
            def request(self, *_args, **_kwargs):
                raise ssl.SSLCertVerificationError("hostname mismatch")
            def close(self):
                pass

        with patch.object(web_checks, "_PinnedHTTPSConnection", return_value=FakeConnection()), patch.object(
            web_checks, "_diagnostic_tls_metadata", return_value=diagnostic
        ) as collect_certificate:
            result, _body, state = web_checks._request_once(
                "https://example.au/", "GET", web_checks.time.monotonic() + 2, 64,
                address_resolver=lambda _host, _timeout: (["8.8.8.8"], None),
            )
        self.assertEqual(state, "certificate_name_mismatch")
        self.assertEqual(result["tls"]["status"], "certificate_name_mismatch")
        self.assertTrue(result["tls"]["diagnostic_handshake"])
        self.assertEqual(result["tls"]["certificate"]["subject_alt_names"], metadata["subject_alt_names"])
        self.assertEqual(result["tls"]["days_until_expiry_at_scan"], 30.0)
        collect_certificate.assert_called_once()

    def test_certificate_statuses_are_independent_of_certificate_metadata(self):
        cases = [
            (ssl.SSLCertVerificationError("certificate has expired"), "certificate_expired"),
            (ssl.SSLCertVerificationError("certificate not yet valid"), "certificate_not_yet_valid"),
            (ssl.SSLCertVerificationError("self signed certificate"), "certificate_untrusted"),
            (ssl.SSLCertVerificationError("hostname mismatch"), "certificate_name_mismatch"),
        ]
        der = make_certificate()
        for error, expected in cases:
            with self.subTest(state=expected):
                self.assertEqual(web_checks._exception_state(error), expected)
                cert, days = web_checks._certificate_metadata(der, NOW)
                observation = {"status": expected, "sha256_fingerprint": cert["sha256_fingerprint"], "days_until_expiry_at_scan": days}
                self.assertEqual(observation["status"], expected)
                self.assertEqual(observation["sha256_fingerprint"], cert["sha256_fingerprint"])
                self.assertEqual(observation["days_until_expiry_at_scan"], 30.0)

    def test_expired_and_not_yet_valid_der_still_yield_dates_and_expiry_values(self):
        expired_der = make_certificate(not_before=NOW - dt.timedelta(days=40), not_after=NOW - dt.timedelta(days=10))
        future_der = make_certificate(not_before=NOW + dt.timedelta(days=5), not_after=NOW + dt.timedelta(days=35))
        expired, expired_days = web_checks._certificate_metadata(expired_der, NOW)
        future, future_days = web_checks._certificate_metadata(future_der, NOW)
        self.assertEqual(expired["not_after"], "2026-09-19T00:00:00Z")
        self.assertEqual(expired_days, -10.0)
        self.assertEqual(future["not_before"], "2026-10-04T00:00:00Z")
        self.assertEqual(future_days, 35.0)
        self.assertEqual(expired["subject_alt_names"], future["subject_alt_names"])

    def test_diagnostic_handshake_is_tls_only_and_explicitly_unverified(self):
        der = make_certificate()

        class FakeRawSocket:
            def __init__(self): self.closed = False
            def settimeout(self, _value): pass
            def close(self): self.closed = True

        class FakeTlsSocket:
            def __init__(self): self.closed = False
            def getpeercert(self, binary_form=False): return der if binary_form else {}
            def version(self): return "TLSv1.3"
            def cipher(self): return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
            def selected_alpn_protocol(self): return "http/1.1"
            def close(self): self.closed = True

        class FakeContext:
            def __init__(self):
                self.check_hostname = True
                self.verify_mode = ssl.CERT_REQUIRED
                self.alpn = None
                self.socket = FakeTlsSocket()
                self.server_name = None
            def set_alpn_protocols(self, values): self.alpn = values
            def wrap_socket(self, raw, server_hostname):
                self.server_name = server_hostname
                return self.socket

        raw = FakeRawSocket()
        context = FakeContext()
        with patch.object(web_checks.socket, "create_connection", return_value=raw), patch.object(
            web_checks.ssl, "SSLContext", return_value=context
        ):
            result = web_checks._diagnostic_tls_metadata(
                "example.au", "8.8.8.8", 443, web_checks.time.monotonic() + 2, "certificate_untrusted"
            )
        self.assertEqual(result["status"], "certificate_untrusted")
        self.assertTrue(result["diagnostic_handshake"])
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertEqual(context.alpn, ["http/1.1"])
        self.assertEqual(context.server_name, "example.au")
        self.assertTrue(context.socket.closed)

    def test_changed_security_txt_body_gets_a_new_exact_byte_hash(self):
        one = b"Contact: mailto:a@example.au\nExpires: 2027-09-29T00:00:00Z\n"
        two = one.replace(b"a@example.au", b"b@example.au")
        self.assertNotEqual(hashlib.sha256(one).hexdigest(), hashlib.sha256(two).hexdigest())

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
            if url.endswith("/.well-known/security.txt"):
                text = VALID_TEXT.replace("security@example.au", "team@example.au") if url.startswith("http:") else VALID_TEXT
                tls = {"status": "valid", "protocol": "TLSv1.3", "cipher": ["TLS_AES_128_GCM_SHA256", "TLSv1.3", 128], "alpn": "http/1.1", "certificate": {"sha256_fingerprint": "b" * 64, "subject": "CN=example.au", "issuer": "CN=Test CA", "subject_alt_names": [], "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}, "days_until_expiry_at_scan": 94.0} if url.startswith("https:") else None
                response = {"url": url, "final_url": url, "state": "response", "status_code": 200, "headers": {"content-type": "text/plain; charset=utf-8"}, "tls": tls, "hops": []}
                return response, text.encode("utf-8")
            https = url.startswith("https:")
            headers = {"content-security-policy": "default-src 'self'", "server": "nginx"}
            tls = {"status": "valid", "protocol": "TLSv1.3", "cipher": ["TLS_AES_128_GCM_SHA256", "TLSv1.3", 128], "alpn": "http/1.1", "certificate": {"sha256_fingerprint": "b" * 64, "subject": "CN=example.au", "issuer": "CN=Test CA", "subject_alt_names": [], "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}, "days_until_expiry_at_scan": 94.0} if https else None
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
        self.assertEqual(result["security_txt"]["status"], "present")
        self.assertEqual(result["security_txt"]["validity_status"], "valid")
        self.assertEqual(result["security_txt"]["preferred_scheme"], "https")
        self.assertEqual(len(result["security_txt_objects"]), 2)
        self.assertFalse(any("/security.txt" in url and not url.endswith("/.well-known/security.txt") for url, _, _ in calls))
        self.assertTrue(all(
            path == "/.well-known/security.txt"
            for url, _, _ in calls if "/security.txt" in url
            for path in [url.split("example.au", 1)[1]]
        ))
        self.assertNotIn("raw_text", result["security_txt"])
        self.assertNotIn("raw_text", result["security_txt"]["resources"][0])
        self.assertEqual(result["tls"]["certificates"][0]["sha256_fingerprint"], "b" * 64)
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
