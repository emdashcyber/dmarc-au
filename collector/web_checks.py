"""Bounded HTTP, security.txt, TLS, and web-related DNS observations."""

from __future__ import annotations

import datetime as dt
import email.utils
import base64
import hashlib
import html.parser
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes


HTTP_TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 5
MAX_PAGE_BYTES = 64 * 1024
MAX_SECURITY_TXT_BYTES = 32 * 1024
HTTP_USER_AGENT = "au-mail-auth-observatory/2.0"

SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "server",
    "x-powered-by",
    "content-type",
    "content-length",
    "alt-svc",
    "via",
    "cf-ray",
    "x-served-by",
    "x-vercel-id",
    "x-nf-request-id",
    "x-amz-cf-id",
    "x-cache",
    "x-azure-ref",
)
REDIRECT_CODES = {301, 302, 303, 307, 308}


def _exception_state(error: BaseException) -> str:
    message = str(error).lower()
    if isinstance(error, ssl.SSLCertVerificationError):
        if "expired" in message:
            return "certificate_expired"
        if "not yet valid" in message:
            return "certificate_not_yet_valid"
        if any(token in message for token in ("hostname mismatch", "doesn't match", "not valid for")):
            return "certificate_name_mismatch"
        return "certificate_untrusted"
    if isinstance(error, ssl.SSLError):
        return "tls_error"
    if isinstance(error, (socket.timeout, TimeoutError, ConnectionError, OSError, socket.gaierror)):
        return "lookup_error"
    return "request_error"


def _resolve_public_addresses(host: str, timeout: float) -> tuple[list[str], str | None]:
    """Resolve a destination and return only globally routable addresses."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.is_global:
            return [str(literal)], None
        return [], "Destination is not a globally routable IP address"

    try:
        import dns.resolver
    except ImportError as error:  # pragma: no cover - requirements install dnspython
        return [], f"dnspython is unavailable: {error}"

    resolver = dns.resolver.Resolver(configure=True)
    # Leave time for the connection itself inside the per-chain deadline.
    resolver.timeout = min(1.0, max(0.1, timeout / 3))
    resolver.lifetime = min(1.0, max(0.1, timeout / 3))
    addresses: list[str] = []
    errors: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, record_type, search=False, lifetime=resolver.lifetime)
            addresses.extend(str(item) for item in answer)
        except dns.resolver.NXDOMAIN:
            errors.append("NXDOMAIN")
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, OSError) as error:
            errors.append(f"{type(error).__name__}: {error}")
    public = list(dict.fromkeys(
        address for address in addresses
        if _is_global_address(address)
    ))
    if public:
        return public, None
    if addresses:
        return [], "All resolved addresses are not globally routable"
    if errors:
        return [], "; ".join(errors)
    return [], "No A or AAAA addresses found"


def _is_global_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def cached_address_resolver(domain: str, web_dns: Mapping[str, object]) -> Callable[[str, float], tuple[list[str], str | None]]:
    """Reuse the captured public A/AAAA answers for the initial hostname."""
    canonical_domain = domain.strip().rstrip(".").lower()
    sections = [web_dns.get("a"), web_dns.get("aaaa")]
    complete = all(
        isinstance(section, Mapping) and section.get("status") in {"present", "absent"}
        for section in sections
    )
    observed = [
        str(record)
        for section in sections
        if isinstance(section, Mapping)
        for record in section.get("records", []) or []
    ]
    public = list(dict.fromkeys(address for address in observed if _is_global_address(address)))
    has_non_public = any(not _is_global_address(address) for address in observed)

    def resolve(host: str, timeout: float) -> tuple[list[str], str | None]:
        hostname = host.strip().rstrip(".").lower()
        if hostname != canonical_domain or not complete:
            return _resolve_public_addresses(hostname, timeout)
        if public:
            return public, None
        if has_non_public:
            return [], "All resolved addresses are not globally routable"
        return [], "No A or AAAA addresses found in the captured DNS answers"

    return resolve


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host=host, port=port, timeout=timeout)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _cookie_metadata(values: list[str]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for value in values:
        segments = [part.strip() for part in value.split(";")]
        name = segments[0].split("=", 1)[0].strip() if segments else ""
        attrs: dict[str, object] = {"name": name or None, "secure": False, "httponly": False}
        for segment in segments[1:]:
            key, separator, content = segment.partition("=")
            key = key.strip().lower()
            if key == "secure":
                attrs["secure"] = True
            elif key == "httponly":
                attrs["httponly"] = True
            elif key == "samesite":
                attrs["samesite"] = content.strip() if separator else ""
            elif key in {"path", "domain", "priority", "partitioned", "max-age", "expires"}:
                attrs[key] = content.strip() if separator else True
        result.append(attrs)
    return result


def _selected_headers(response: http.client.HTTPResponse) -> dict[str, object]:
    result: dict[str, object] = {}
    for name in SECURITY_HEADERS:
        values = response.headers.get_all(name) or []
        if values:
            result[name] = values if len(values) > 1 else values[0]
    set_cookies = response.headers.get_all("set-cookie") or []
    if set_cookies:
        result["set-cookie-metadata"] = _cookie_metadata(set_cookies)
    return result


def _read_bounded_body(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPConnection,
    limit: int,
    deadline: float,
) -> tuple[bytes, bool]:
    """Read in deadline-aware chunks and never consume more than the byte limit."""
    chunks: list[bytes] = []
    size = 0
    reader = getattr(response, "read1", None) or response.read
    while size < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Request deadline exceeded while reading response body")
        sock = connection.sock
        if sock is None and response.fp is not None:
            raw = getattr(response.fp, "raw", None)
            sock = getattr(raw, "_sock", None)
        if sock is not None:
            try:
                sock.settimeout(remaining)
            except OSError:
                # A close-delimited response may retain its file descriptor after
                # HTTPConnection has detached its socket reference.
                pass
        chunk = reader(min(8192, limit - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    body = b"".join(chunks)
    remaining = getattr(response, "length", None)
    truncated = size >= limit and (remaining is None or remaining > 0)
    return body[:limit], truncated


def _certificate_metadata(der: bytes, now: dt.datetime | None = None) -> tuple[dict[str, object], float]:
    certificate = x509.load_der_x509_certificate(der)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    days_until_expiry = round((not_after - now.astimezone(dt.timezone.utc)).total_seconds() / 86400, 2)
    try:
        general_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        subject_alt_names = [
            {
                "type": type(name).__name__,
                "value": name.value.hex() if isinstance(name, x509.OtherName) else str(name.value),
            }
            for name in general_names
        ]
    except x509.ExtensionNotFound:
        subject_alt_names = []
    metadata = {
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "subject_alt_names": subject_alt_names,
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
    }
    return metadata, days_until_expiry


def _tls_metadata(connection: http.client.HTTPSConnection | ssl.SSLSocket) -> dict[str, object] | None:
    sock = connection if isinstance(connection, ssl.SSLSocket) else connection.sock
    if sock is None:
        return None
    try:
        der = sock.getpeercert(binary_form=True)
        if not der:
            return None
        certificate, days_until_expiry = _certificate_metadata(der)
        return {
            "status": "valid",
            "certificate": certificate,
            "days_until_expiry_at_scan": days_until_expiry,
            "protocol": sock.version(),
            "cipher": sock.cipher(),
            "alpn": sock.selected_alpn_protocol(),
        }
    except (OSError, ValueError, ssl.SSLError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        return None


def _diagnostic_tls_metadata(
    hostname: str,
    address: str,
    port: int,
    deadline: float,
    validation_status: str,
) -> dict[str, object] | None:
    """Read a peer leaf certificate after validation failed; send no HTTP request."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    raw = None
    tls_sock = None
    try:
        raw = socket.create_connection((address, port), timeout=remaining)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        raw.settimeout(remaining)
        tls_sock = context.wrap_socket(raw, server_hostname=hostname)
        der = tls_sock.getpeercert(binary_form=True)
        if not der:
            return None
        certificate, days_until_expiry = _certificate_metadata(der)
        return {
            "status": validation_status,
            "certificate": certificate,
            "days_until_expiry_at_scan": days_until_expiry,
            "protocol": tls_sock.version(),
            "cipher": tls_sock.cipher(),
            "alpn": tls_sock.selected_alpn_protocol(),
            "diagnostic_handshake": True,
        }
    except (OSError, ValueError, ssl.SSLError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        return None
    finally:
        if tls_sock is not None:
            tls_sock.close()
        elif raw is not None:
            raw.close()


def _request_once(
    url: str,
    method: str,
    deadline: float,
    body_limit: int,
    address_resolver: Callable[[str, float], tuple[list[str], str | None]] = _resolve_public_addresses,
) -> tuple[dict[str, object], bytes, str | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").rstrip(".").lower()
    if scheme not in {"http", "https"} or not hostname or parts.username or parts.password:
        return ({"url": url, "state": "blocked_destination", "error": "Only public HTTP(S) URLs are allowed"}, b"", None)
    port = parts.port or (443 if scheme == "https" else 80)
    if port != (443 if scheme == "https" else 80):
        return ({"url": url, "state": "blocked_destination", "error": "Non-standard destination port blocked"}, b"", None)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return ({"url": url, "state": "lookup_error", "error": "Request deadline exceeded"}, b"", None)
    addresses, resolve_error = address_resolver(hostname, remaining)
    if not addresses:
        state = "blocked_destination" if resolve_error and "not globally routable" in resolve_error else "lookup_error"
        return ({"url": url, "state": state, "error": resolve_error or "No public address"}, b"", None)

    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    errors: list[str] = []
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        conn: http.client.HTTPConnection
        if scheme == "https":
            conn = _PinnedHTTPSConnection(hostname, port, address, remaining)
        else:
            conn = _PinnedHTTPConnection(hostname, port, address, remaining)
        try:
            conn.request(method, path, headers={
                "User-Agent": HTTP_USER_AGENT,
                "Accept": "text/html, text/plain;q=0.9, */*;q=0.5",
            })
            transport_sock = conn.sock
            tls = _tls_metadata(transport_sock) if scheme == "https" and transport_sock is not None else None
            if conn.sock is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Request deadline exceeded before response headers")
                conn.sock.settimeout(remaining)
            response = conn.getresponse()
            headers = _selected_headers(response)
            body = b""
            truncated = False
            if method == "GET" and body_limit > 0:
                body, truncated = _read_bounded_body(response, conn, body_limit, deadline)
            hop = {
                "url": url,
                "status_code": response.status,
                "reason": response.reason,
                "http_version": f"HTTP/{response.version // 10}.{response.version % 10}",
                "location": response.headers.get("Location"),
                "headers": headers,
                "tls": tls,
                "body_truncated": truncated,
                "body_bytes_read": len(body),
            }
            return hop, body, None
        except Exception as error:
            state = _exception_state(error)
            errors.append(f"{state}: {type(error).__name__}: {error}")
            if state.startswith("certificate_"):
                diagnostic = _diagnostic_tls_metadata(hostname, address, port, deadline, state) if scheme == "https" else None
                return ({"url": url, "state": state, "error": errors[-1], "tls": diagnostic}, b"", state)
            if state == "tls_error":
                return ({"url": url, "state": state, "error": errors[-1]}, b"", state)
        finally:
            conn.close()
    state = "lookup_error"
    message = "; ".join(errors) or "Request deadline exceeded"
    return ({"url": url, "state": state, "error": message}, b"", state)


def request_chain(
    url: str,
    method: str = "GET",
    body_limit: int = 0,
    timeout: float = HTTP_TIMEOUT_SECONDS,
    max_redirects: int = MAX_REDIRECTS,
    address_resolver: Callable[[str, float], tuple[list[str], str | None]] = _resolve_public_addresses,
) -> tuple[dict[str, object], bytes]:
    """Fetch one URL, manually following a bounded HTTP(S) redirect chain."""
    deadline = time.monotonic() + timeout
    current = url
    hops: list[dict[str, object]] = []
    body = b""
    for redirect_number in range(max_redirects + 1):
        hop, body, error_state = _request_once(current, method, deadline, body_limit, address_resolver)
        if "status_code" not in hop:
            result = {
                "method": method,
                "url": url,
                "final_url": current,
                "state": str(hop.get("state") or error_state or "lookup_error"),
                "error": hop.get("error"),
                "hops": hops,
            }
            if isinstance(hop.get("tls"), Mapping):
                result["tls"] = hop["tls"]
            return result, b""
        hops.append(hop)
        code = int(hop["status_code"])
        location = hop.get("location")
        if code not in REDIRECT_CODES or not location:
            return {
                "method": method,
                "url": url,
                "final_url": current,
                "state": "response",
                "status_code": code,
                "headers": hop.get("headers", {}),
                "tls": hop.get("tls"),
                "hops": hops,
                "body_truncated": bool(hop.get("body_truncated")),
                "body_bytes_read": int(hop.get("body_bytes_read") or 0),
            }, body
        if redirect_number >= max_redirects:
            return {
                "method": method,
                "url": url,
                "final_url": current,
                "state": "redirect_limit",
                "status_code": code,
                "headers": hop.get("headers", {}),
                "tls": hop.get("tls"),
                "hops": hops,
                "error": f"Redirect limit ({max_redirects}) reached",
            }, b""
        target = urljoin(current, str(location))
        target_parts = urlsplit(target)
        if target_parts.scheme.lower() not in {"http", "https"}:
            return {
                "method": method,
                "url": url,
                "final_url": current,
                "state": "blocked_destination",
                "status_code": code,
                "headers": hop.get("headers", {}),
                "tls": hop.get("tls"),
                "hops": hops,
                "error": "Redirect target is not HTTP(S)",
            }, b""
        current = target
    return {"method": method, "url": url, "final_url": current, "state": "redirect_limit", "hops": hops}, b""


class _PageParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.meta_refresh: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta" and values.get("http-equiv", "").strip().lower() == "refresh":
            content = values.get("content", "")
            match = re.search(r"(?:^|;)\s*url\s*=\s*['\"]?(.+?)['\"]?\s*$", content, re.IGNORECASE)
            if match:
                self.meta_refresh.append(match.group(1).strip())

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


def parse_page_metadata(body: bytes, final_url: str) -> dict[str, object]:
    parser = _PageParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:
        pass
    title = " ".join("".join(parser.title_parts).split())[:512] or None
    refresh = [urljoin(final_url, target) for target in parser.meta_refresh]
    return {"title": title, "meta_refresh_targets": refresh}


def _hsts_observation(web: Mapping[str, object]) -> dict[str, object]:
    values: list[str] = []
    for scheme in ("https",):
        requests = web.get(scheme)
        if not isinstance(requests, Mapping):
            continue
        for method in ("head", "get"):
            result = requests.get(method)
            if not isinstance(result, Mapping):
                continue
            for hop in result.get("hops", []) or []:
                if isinstance(hop, Mapping):
                    headers = hop.get("headers")
                    if isinstance(headers, Mapping):
                        value = headers.get("strict-transport-security")
                        values.extend(value if isinstance(value, list) else [value] if value else [])
    directives: dict[str, str | bool] = {}
    for value in values:
        for segment in str(value).split(";"):
            key, separator, content = segment.strip().partition("=")
            if key:
                directives[key.lower()] = content.strip().strip('"') if separator else True
    try:
        max_age = int(str(directives.get("max-age", "")))
    except ValueError:
        max_age = None
    return {
        "observed": bool(values),
        "values": values,
        "max_age": max_age,
        "active": max_age is not None and max_age > 0,
        "include_subdomains": "includesubdomains" in directives,
        "preload": "preload" in directives,
        "valid": max_age is not None,
    }


def assess_security_headers(headers: Mapping[str, object], hsts: Mapping[str, object], cookies: object) -> list[str]:
    """Produce transparent header-level observations without a composite score."""
    findings: list[str] = []
    csp_values = headers.get("content-security-policy")
    csp = " ".join(csp_values if isinstance(csp_values, list) else [str(csp_values)] if csp_values else []).lower()
    if not csp:
        findings.append("Content-Security-Policy is absent")
    else:
        if "default-src" not in csp:
            findings.append("Content-Security-Policy has no default-src directive")
        if any(value in csp for value in ("'unsafe-inline'", "'unsafe-eval'")):
            findings.append("Content-Security-Policy permits unsafe inline or eval scripts")
        if re.search(r"(?:default-src|script-src)\s+[^;]*\*", csp):
            findings.append("Content-Security-Policy allows a wildcard source for default or script content")
    xfo = str(headers.get("x-frame-options") or "").strip().lower()
    if not xfo:
        findings.append("X-Frame-Options is absent")
    elif xfo not in {"deny", "sameorigin"}:
        findings.append("X-Frame-Options has an unrecognized value")
    xcto = str(headers.get("x-content-type-options") or "").strip().lower()
    if xcto != "nosniff":
        findings.append("X-Content-Type-Options is absent or is not nosniff")
    if not headers.get("referrer-policy"):
        findings.append("Referrer-Policy is absent")
    if not headers.get("permissions-policy"):
        findings.append("Permissions-Policy is absent")
    if not hsts.get("active"):
        findings.append("Active HSTS was not observed on a verified HTTPS response")
    cors_origin = str(headers.get("access-control-allow-origin") or "").strip()
    cors_credentials = str(headers.get("access-control-allow-credentials") or "").strip().lower()
    if cors_origin == "*" and cors_credentials == "true":
        findings.append("CORS advertises wildcard origin and credentials together")
    if isinstance(cookies, list):
        for cookie in cookies:
            if not isinstance(cookie, Mapping):
                continue
            name = str(cookie.get("name") or "(unnamed cookie)")
            if not cookie.get("secure"):
                findings.append(f"Cookie {name} lacks Secure")
            if not cookie.get("httponly"):
                findings.append(f"Cookie {name} lacks HttpOnly")
    return findings


def _externalize_certificate_metadata(web: dict[str, object], security_resources: list[dict[str, object]]) -> tuple[dict[str, dict[str, object]], list[dict[str, object]]]:
    certificate_objects: dict[str, dict[str, object]] = {}
    observations: list[dict[str, object]] = []
    seen: set[str] = set()

    def collect(tls_value: object) -> None:
        if not isinstance(tls_value, dict):
            return
        certificate = tls_value.pop("certificate", None)
        if isinstance(certificate, Mapping):
            fingerprint = str(certificate.get("sha256_fingerprint") or "").lower()
            if fingerprint:
                existing = certificate_objects.get(fingerprint)
                metadata = dict(certificate)
                if existing is not None and existing != metadata:
                    raise ValueError(f"Conflicting certificate metadata for SHA-256 fingerprint {fingerprint}")
                certificate_objects[fingerprint] = metadata
                tls_value["sha256_fingerprint"] = fingerprint
        fingerprint = tls_value.get("sha256_fingerprint")
        if not isinstance(fingerprint, str):
            return
        observation = {
            key: tls_value[key]
            for key in (
                "status", "sha256_fingerprint", "days_until_expiry_at_scan",
                "protocol", "cipher", "alpn", "diagnostic_handshake",
            )
            if key in tls_value
        }
        identity = json.dumps(observation, sort_keys=True, separators=(",", ":"))
        if identity not in seen:
            observations.append(observation)
            seen.add(identity)

    for scheme in ("http", "https"):
        request_group = web.get(scheme)
        if not isinstance(request_group, Mapping):
            continue
        for method in ("head", "get"):
            result = request_group.get(method)
            if not isinstance(result, Mapping):
                continue
            collect(result.get("tls"))
            for hop in result.get("hops", []) or []:
                if isinstance(hop, Mapping):
                    collect(hop.get("tls"))
    for resource in security_resources:
        collect(resource.get("tls"))
    return certificate_objects, observations


def probe_web(domain: str, address_resolver=_resolve_public_addresses) -> dict[str, object]:
    """Probe homepages and only the well-known security.txt path on each scheme."""
    domain = domain.strip().rstrip(".").lower()
    web: dict[str, object] = {"http": {}, "https": {}}
    for scheme in ("http", "https"):
        root = f"{scheme}://{domain}/"
        get_result, body = request_chain(root, "GET", MAX_PAGE_BYTES, address_resolver=address_resolver)
        web[scheme] = {
            "head": request_chain(root, "HEAD", address_resolver=address_resolver),
            "get": get_result,
        }
        if body:
            web[scheme]["page"] = parse_page_metadata(body, str(get_result.get("final_url") or root))
        else:
            web[scheme]["page"] = {"title": None, "meta_refresh_targets": []}

    security_resources: list[dict[str, object]] = []
    security_txt_objects: dict[str, str] = {}
    for scheme in ("http", "https"):
        path = "/.well-known/security.txt"
        result, body = request_chain(
            f"{scheme}://{domain}{path}",
            "GET",
            MAX_SECURITY_TXT_BYTES,
            address_resolver=address_resolver,
        )
        resource = {**result, "scheme": scheme, "path": path}
        if result.get("state") == "response" and isinstance(result.get("status_code"), int) and 200 <= int(result["status_code"]) < 300:
            fingerprint = hashlib.sha256(body).hexdigest()
            resource["sha256"] = fingerprint
            security_txt_objects[fingerprint] = base64.b64encode(body).decode("ascii")
            try:
                resource["raw_text"] = body.decode("utf-8")
                resource["encoding_valid"] = True
            except UnicodeDecodeError:
                resource["raw_text"] = body.decode("utf-8", errors="replace")
                resource["encoding_valid"] = False
        security_resources.append(resource)
    security_txt = validate_security_txt(domain, security_resources)
    for resource in security_txt.get("resources", []):
        if isinstance(resource, dict):
            resource.pop("raw_text", None)
    security_txt.pop("raw_text", None)
    certificate_objects, certificate_observations = _externalize_certificate_metadata(web, security_resources)

    hsts = _hsts_observation(web)
    http_get = web["http"].get("get", {})
    redirect_targets = []
    for hop in http_get.get("hops", []) if isinstance(http_get, Mapping) else []:
        if isinstance(hop, Mapping) and hop.get("location"):
            redirect_targets.append(urljoin(str(hop.get("url") or f"http://{domain}/"), str(hop["location"])))
    redirect_to_https = any(urlsplit(target).scheme.lower() == "https" for target in redirect_targets)
    meta_targets = []
    http_meta_targets = []
    for scheme in ("http", "https"):
        page = web[scheme].get("page", {})
        if isinstance(page, Mapping):
            meta_targets.extend(page.get("meta_refresh_targets", []))
            if scheme == "http":
                http_meta_targets.extend(page.get("meta_refresh_targets", []))
    meta_to_https = any(urlsplit(str(target)).scheme.lower() == "https" for target in http_meta_targets)

    https_get = web["https"].get("get", {})
    cert_states = [
        str(result.get("state")) for result in (web["https"].get("head", {}), https_get)
        if isinstance(result, Mapping) and result.get("state") not in {None, "response"}
    ]
    if any(item.get("status") == "valid" for item in certificate_observations):
        certificate_status = "valid"
    elif cert_states:
        certificate_status = cert_states[0]
    else:
        certificate_status = "unavailable"

    header_source = "https"
    headers = https_get.get("headers", {}) if isinstance(https_get, Mapping) else {}
    if not headers and isinstance(web["http"].get("get"), Mapping):
        headers = web["http"]["get"].get("headers", {})
        header_source = "http_fallback"
    if not isinstance(headers, Mapping):
        headers = {}
    header_presence = {name: bool(headers.get(name)) for name in SECURITY_HEADERS}
    cookies = headers.get("set-cookie-metadata")
    https_page = web["https"].get("page") or {}
    http_page = web["http"].get("page") or {}
    page = https_page if isinstance(https_page, Mapping) and https_page.get("title") else http_page if isinstance(http_page, Mapping) and http_page.get("title") else https_page
    return {
        "status": "collected",
        "requests": web,
        "page": page,
        "headers": headers,
        "headers_source": header_source,
        "header_presence": header_presence,
        "header_findings": assess_security_headers(headers, hsts, cookies),
        "tls": {"status": certificate_status, "certificates": certificate_observations, "errors": cert_states},
        "https_upgrade": {
            "http_redirect_targets": redirect_targets,
            "redirects_to_https": redirect_to_https,
            "meta_refresh_targets": meta_targets,
            "http_meta_refresh_targets": http_meta_targets,
            "meta_refresh_to_https": meta_to_https,
            "hsts": hsts,
        },
        "security_txt": security_txt,
        "security_txt_objects": security_txt_objects,
        "certificate_objects": certificate_objects,
    }


def _parse_security_txt_text(raw_text: str, now: dt.datetime | None = None) -> dict[str, object]:
    now = now or dt.datetime.now(dt.timezone.utc)
    errors: list[str] = []
    warnings: list[str] = []
    fields: dict[str, list[str]] = {}
    for line_number, raw_line in enumerate(raw_text.splitlines(), start=1):
        line = raw_line.strip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)", line)
        if not match:
            errors.append(f"line {line_number}: malformed field")
            continue
        key = match.group(1).lower()
        fields.setdefault(key, []).append(match.group(2).strip())
    contacts = fields.get("contact", [])
    if not contacts:
        errors.append("required Contact field is missing")
    for contact in contacts:
        parsed = urlsplit(contact)
        if parsed.scheme.lower() not in {"mailto", "https"} or not parsed.path or (
            parsed.scheme.lower() == "https" and not parsed.hostname
        ):
            errors.append(f"invalid Contact URI: {contact[:120]}")
    expires = fields.get("expires", [])
    expiry: dt.datetime | None = None
    if not expires:
        errors.append("required Expires field is missing")
    elif len(expires) != 1:
        errors.append("Expires field must appear exactly once")
    else:
        value = expires[0]
        try:
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                value,
            ):
                raise ValueError("not RFC3339")
            expiry = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError("timezone is required")
            if expiry <= now:
                errors.append("security.txt is expired")
        except ValueError:
            errors.append("Expires must be an RFC3339 timestamp with a timezone")
    if "canonical" not in fields:
        warnings.append("Canonical field is absent")
    expired = any("expired" in item for item in errors)
    return {
        "valid": not errors,
        "expired": expired,
        "fields": fields,
        "expires_at": expiry.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z") if expiry else None,
        "errors": errors,
        "warnings": warnings,
    }


def validate_security_txt(
    domain: str,
    resources: list[Mapping[str, object]],
    now: dt.datetime | None = None,
) -> dict[str, object]:
    """Classify the well-known security.txt location and validate any observed body."""
    parsed_resources: list[dict[str, object]] = []
    for resource in resources:
        record = dict(resource)
        status_code = record.get("status_code")
        raw_text = record.get("raw_text")
        if not isinstance(raw_text, str):
            if record.get("state") in {"lookup_error", "blocked_destination", "redirect_limit"}:
                record["presence"] = "lookup_error"
            elif isinstance(status_code, int) and status_code in {404, 410}:
                record["presence"] = "absent"
            elif isinstance(status_code, int):
                record["presence"] = "lookup_error" if status_code >= 400 else "absent"
            else:
                record["presence"] = str(record.get("state") or "lookup_error")
            parsed_resources.append(record)
            continue

        record["presence"] = "present"
        content_type = ""
        headers = record.get("headers")
        if isinstance(headers, Mapping):
            content_type = str(headers.get("content-type") or "")
        content_parts = [part.strip() for part in content_type.split(";")]
        media_type = content_parts[0].lower() if content_parts else ""
        charsets = [
            match.group(1).strip().strip('"').lower()
            for part in content_parts[1:]
            if (match := re.fullmatch(r"charset\s*=\s*(.+)", part, re.IGNORECASE))
        ]
        transport_ok = str(record.get("final_url") or "").lower().startswith("https://")
        tls = record.get("tls")
        cert_ok = isinstance(tls, Mapping) and tls.get("status") == "valid"
        content_type_ok = media_type == "text/plain" and (not charsets or all(value == "utf-8" for value in charsets))
        encoding_ok = record.get("encoding_valid", True) is True
        parsed = _parse_security_txt_text(raw_text, now)
        errors = list(parsed["errors"])
        warnings = list(parsed["warnings"])
        if not transport_ok:
            errors.append("security.txt did not finish over HTTPS")
        if transport_ok and not cert_ok:
            errors.append("HTTPS certificate was not validated")
        if not content_type_ok:
            errors.append("Content-Type must be text/plain with UTF-8 encoding")
        if not encoding_ok:
            errors.append("security.txt is not valid UTF-8")
        if record.get("body_truncated"):
            errors.append(f"security.txt exceeds the {MAX_SECURITY_TXT_BYTES}-byte collection limit")
        well_known = str(record.get("path") or "") == "/.well-known/security.txt"
        final_host = urlsplit(str(record.get("final_url") or "")).hostname or ""
        if final_host.lower().rstrip(".") != domain.lower().rstrip("."):
            warnings.append(f"Redirected to another host: {final_host}")
        canonical_urls = parsed["fields"].get("canonical", [])
        request_url = str(record.get("url") or "")
        if canonical_urls and request_url not in canonical_urls:
            warnings.append("Retrieved URL is not listed in Canonical")
        record["validation"] = {
            **parsed,
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "content_type": content_type,
            "content_type_valid": content_type_ok,
            "https_valid": transport_ok and cert_ok,
            "well_known_location": well_known,
        }
        record["status"] = (
            "expired" if parsed.get("expired") else "invalid" if errors else "valid"
        )
        parsed_resources.append(record)

    relevant = [
        row for row in parsed_resources
        if row.get("scheme") == "https" and row.get("presence") == "present"
    ] or [row for row in parsed_resources if row.get("presence") == "present"]
    preferred = relevant[0] if relevant else None
    if preferred:
        validation = preferred.get("validation")
        validation = validation if isinstance(validation, Mapping) else {}
        if validation.get("valid"):
            validity_status = "valid"
        elif validation.get("expired"):
            validity_status = "expired"
        elif preferred.get("scheme") != "https":
            validity_status = "insecure_transport"
        else:
            validity_status = "invalid"
    elif any(row.get("presence") == "lookup_error" for row in parsed_resources):
        validity_status = "lookup_error"
    else:
        validity_status = "absent"
    if any(row.get("presence") == "present" for row in parsed_resources):
        finding = "present"
    elif any(row.get("presence") == "lookup_error" for row in parsed_resources):
        finding = "lookup_error"
    else:
        finding = "absent"
    texts = [
        str(row.get("raw_text")) for row in parsed_resources
        if row.get("presence") == "present" and row.get("raw_text") is not None
    ]
    return {
        "status": finding,
        "validity_status": validity_status,
        "preferred_path": preferred.get("path") if preferred else None,
        "preferred_scheme": preferred.get("scheme") if preferred else None,
        "sha256": preferred.get("sha256") if preferred else None,
        "resources": parsed_resources,
        "raw_text": preferred.get("raw_text") if preferred else None,
        "duplicate_content_differs": len(set(texts)) > 1,
    }


def _dns_query_record(name: str, record_type: str, timeout: float = 2.0) -> dict[str, object]:
    try:
        import dns.resolver
    except ImportError as error:  # pragma: no cover
        return {"status": "lookup_error", "records": [], "error": str(error), "ttl": None}
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, record_type, search=False, lifetime=timeout, raise_on_no_answer=False)
        rrset = answer.rrset
        records = [item.to_text() for item in rrset] if rrset else []
        response = answer.response
        cnames = []
        for rrset_item in response.answer:
            if rrset_item.rdtype == 5:
                cnames.append({
                    "owner": rrset_item.name.to_text().rstrip("."),
                    "target": [item.target.to_text().rstrip(".") for item in rrset_item],
                    "ttl": rrset_item.ttl,
                })
        return {
            "status": "present" if records else "absent",
            "records": records,
            "ttl": rrset.ttl if rrset else None,
            "answer_owner": rrset.name.to_text().rstrip(".") if rrset else None,
            "cname_chain": cnames,
            "error": None,
        }
    except dns.resolver.NXDOMAIN:
        return {"status": "absent", "records": [], "ttl": None, "cname_chain": [], "error": None}
    except dns.resolver.NoAnswer:
        return {"status": "absent", "records": [], "ttl": None, "cname_chain": [], "error": None}
    except Exception as error:
        return {
            "status": "lookup_error",
            "records": [],
            "ttl": None,
            "cname_chain": [],
            "error": f"{type(error).__name__}: {error}",
        }


def probe_web_dns(domain: str) -> dict[str, object]:
    domain = domain.strip().rstrip(".").lower()
    result = {name.lower(): _dns_query_record(domain, name) for name in ("A", "AAAA", "CNAME", "HTTPS")}
    direct_caa = _dns_query_record(domain, "CAA")
    effective = {
        **direct_caa,
        "owner": domain,
        "source": "direct" if direct_caa["status"] == "present" else "lookup_error" if direct_caa["status"] == "lookup_error" else None,
    }
    if direct_caa["status"] == "absent":
        labels = domain.split(".")
        for offset in range(1, len(labels)):
            owner = ".".join(labels[offset:])
            inherited = _dns_query_record(owner, "CAA")
            if inherited["status"] == "present":
                effective = {**inherited, "owner": owner, "source": "inherited"}
                break
            if inherited["status"] == "lookup_error":
                effective = {**inherited, "owner": owner, "source": "lookup_error"}
                break
        else:
            effective = {"status": "absent", "records": [], "owner": None, "source": None, "ttl": None, "error": None}
    result["caa"] = {"direct": direct_caa, "effective": effective}
    return result
