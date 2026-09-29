"""Bounded security.txt GETs and compact response observations."""

from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import re
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit


HTTP_TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 5
MAX_SECURITY_TXT_BYTES = 32 * 1024
MAX_HEADER_VALUE_CHARS = 4096
HTTP_USER_AGENT = "au-mail-auth-observatory/3.0"
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
    "content-encoding",
    "server",
    "x-powered-by",
    "content-type",
    "content-length",
    "alt-svc",
)
REDIRECT_CODES = {301, 302, 303, 307, 308}


def _is_global_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _resolve_public_addresses(host: str, timeout: float) -> tuple[list[str], str | None]:
    """Resolve a destination and return only globally routable addresses."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return ([str(literal)], None) if literal.is_global else ([], "Destination is not globally routable")

    try:
        import dns.resolver
    except ImportError as error:  # pragma: no cover - requirements install dnspython
        return [], f"dnspython unavailable: {error}"

    resolver = dns.resolver.Resolver(configure=True)
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
            errors.append(type(error).__name__)
    public = list(dict.fromkeys(address for address in addresses if _is_global_address(address)))
    if public:
        return public, None
    if addresses:
        return [], "All resolved addresses are not globally routable"
    if errors:
        return [], "; ".join(errors)
    return [], "No A or AAAA addresses found"


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


def _safe_url(url: str) -> str:
    """Retain the redirect destination but omit userinfo, query strings and fragments."""
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return "[blocked destination]"
        hostname = parts.hostname.lower().rstrip(".")
        if ":" in hostname:
            hostname = f"[{hostname}]"
        port = parts.port
        default_port = 443 if parts.scheme.lower() == "https" else 80
        netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", "", ""))[:2048]
    except ValueError:
        return "[invalid destination]"


def _selected_headers(response: http.client.HTTPResponse) -> dict[str, object]:
    selected: dict[str, object] = {}
    for name in SECURITY_HEADERS:
        values = response.headers.get_all(name) or []
        safe_values = [value[:MAX_HEADER_VALUE_CHARS] for value in values[:3]]
        if safe_values:
            selected[name] = safe_values if len(safe_values) > 1 else safe_values[0]
    return selected


def _read_bounded_body(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPConnection,
    limit: int,
    deadline: float,
) -> tuple[bytes, bool]:
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
                pass
        chunk = reader(min(8192, limit - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    body = b"".join(chunks)
    left = getattr(response, "length", None)
    truncated = size >= limit and (left is None or left > 0)
    return body[:limit], truncated


def _failure_state(error: BaseException) -> tuple[str, str]:
    if isinstance(error, ssl.SSLCertVerificationError):
        return "tls_error", "invalid"
    if isinstance(error, ssl.SSLError):
        return "tls_error", "error"
    if isinstance(error, (socket.timeout, TimeoutError, ConnectionError, OSError, socket.gaierror)):
        return "lookup_error", "not_observed"
    return "request_error", "not_observed"


def _request_once(
    url: str,
    deadline: float,
    body_limit: int,
    address_resolver: Callable[[str, float], tuple[list[str], str | None]],
) -> tuple[dict[str, object], bytes]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").rstrip(".").lower()
    if scheme not in {"http", "https"} or not hostname or parts.username or parts.password:
        return {"url": _safe_url(url), "state": "blocked_destination", "tls_certificate": "not_observed"}, b""
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return {"url": _safe_url(url), "state": "blocked_destination", "tls_certificate": "not_observed"}, b""
    if port != (443 if scheme == "https" else 80):
        return {"url": _safe_url(url), "state": "blocked_destination", "tls_certificate": "not_observed"}, b""

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"url": _safe_url(url), "state": "lookup_error", "tls_certificate": "not_observed"}, b""
    addresses, resolve_error = address_resolver(hostname, remaining)
    had_addresses = bool(addresses)
    addresses = [address for address in addresses if _is_global_address(address)]
    if not addresses:
        state = "blocked_destination" if had_addresses or (resolve_error and "not globally routable" in resolve_error) else "lookup_error"
        return {
            "url": _safe_url(url),
            "state": state,
            "tls_certificate": "not_observed",
        }, b""

    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    failures: list[tuple[str, str]] = []
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        conn: http.client.HTTPConnection
        conn = (
            _PinnedHTTPSConnection(hostname, port, address, remaining)
            if scheme == "https"
            else _PinnedHTTPConnection(hostname, port, address, remaining)
        )
        tls_status = "not_observed"
        try:
            if scheme == "https":
                conn.connect()
                tls_status = "valid"
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Request deadline exceeded after TLS handshake")
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
            conn.request("GET", path, headers={
                "User-Agent": HTTP_USER_AGENT,
                "Accept": "text/plain, */*;q=0.5",
                "Accept-Encoding": "identity",
            })
            if conn.sock is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Request deadline exceeded before response headers")
                conn.sock.settimeout(remaining)
            response = conn.getresponse()
            headers = _selected_headers(response)
            body = b""
            body_truncated = False
            body_complete = True
            if 200 <= response.status < 300:
                try:
                    body, body_truncated = _read_bounded_body(response, conn, body_limit, deadline)
                    body_complete = not body_truncated
                except Exception:
                    body_complete = False
                    body_truncated = True
            return {
                "url": _safe_url(url),
                "state": "response",
                "status_code": response.status,
                "location": response.headers.get("Location"),
                "headers": headers,
                "tls_certificate": tls_status,
                "body_complete": body_complete,
                "body_truncated": body_truncated,
            }, body
        except Exception as error:
            state, failure_tls_status = _failure_state(error)
            if failure_tls_status != "not_observed":
                tls_status = failure_tls_status
            failures.append((state, tls_status))
        finally:
            conn.close()
    tls_status = _combined_tls_status([item[1] for item in failures])
    state = "tls_error" if tls_status in {"invalid", "error"} else (
        failures[-1][0] if failures else "lookup_error"
    )
    if state not in {"lookup_error", "request_error", "tls_error"}:
        state = "lookup_error"
    return {"url": _safe_url(url), "state": state, "tls_certificate": tls_status}, b""


def _combined_tls_status(statuses: list[str]) -> str:
    if "invalid" in statuses:
        return "invalid"
    if "error" in statuses:
        return "error"
    if "valid" in statuses:
        return "valid"
    return "not_observed"


def request_chain(
    url: str,
    body_limit: int = MAX_SECURITY_TXT_BYTES,
    timeout: float = HTTP_TIMEOUT_SECONDS,
    max_redirects: int = MAX_REDIRECTS,
    address_resolver: Callable[[str, float], tuple[list[str], str | None]] = _resolve_public_addresses,
) -> tuple[dict[str, object], bytes]:
    """Fetch one URL with a bounded redirect chain and no retained response body."""
    deadline = time.monotonic() + timeout
    current = url
    hops: list[dict[str, object]] = []
    response_body = b""
    for redirect_number in range(max_redirects + 1):
        hop, body = _request_once(current, deadline, body_limit, address_resolver)
        hops.append(hop)
        code = hop.get("status_code")
        if not isinstance(code, int):
            return {
                "url": _safe_url(url),
                "final_url": _safe_url(current),
                "state": str(hop.get("state") or "lookup_error"),
                "error_kind": str(hop.get("state") or "lookup_error"),
                "status_code": None,
                "headers": {},
                "redirects_to_https": any(
                    urlsplit(str(item.get("redirect_to") or "")).scheme.lower() == "https"
                    for item in hops
                ),
                "hops": hops,
                "tls_certificate": _combined_tls_status([
                    str(item.get("tls_certificate") or "not_observed") for item in hops
                ]),
                "body_complete": False,
            }, b""
        location = hop.get("location")
        if code not in REDIRECT_CODES or not location:
            response_body = body
            return {
                "url": _safe_url(url),
                "final_url": _safe_url(current),
                "state": "response",
                "status_code": code,
                "headers": hop.get("headers", {}),
                "redirects_to_https": any(
                    urlsplit(str(item.get("redirect_to") or "")).scheme.lower() == "https"
                    for item in hops
                ),
                "hops": hops,
                "tls_certificate": _combined_tls_status([
                    str(item.get("tls_certificate") or "not_observed") for item in hops
                ]),
                "body_complete": bool(hop.get("body_complete")),
                "body_truncated": bool(hop.get("body_truncated")),
            }, response_body
        if redirect_number >= max_redirects:
            return {
                "url": _safe_url(url),
                "final_url": _safe_url(current),
                "state": "redirect_limit",
                "error_kind": "redirect_limit",
                "status_code": code,
                "headers": hop.get("headers", {}),
                "redirects_to_https": any(
                    urlsplit(str(item.get("redirect_to") or "")).scheme.lower() == "https"
                    for item in hops
                ),
                "hops": hops,
                "tls_certificate": _combined_tls_status([
                    str(item.get("tls_certificate") or "not_observed") for item in hops
                ]),
                "body_complete": False,
            }, b""
        target = urljoin(current, str(location))
        target_parts = urlsplit(target)
        if target_parts.scheme.lower() not in {"http", "https"} or not target_parts.hostname:
            return {
                "url": _safe_url(url),
                "final_url": _safe_url(current),
                "state": "blocked_destination",
                "error_kind": "blocked_destination",
                "status_code": code,
                "headers": hop.get("headers", {}),
                "redirects_to_https": any(
                    urlsplit(str(item.get("redirect_to") or "")).scheme.lower() == "https"
                    for item in hops
                ),
                "hops": hops,
                "tls_certificate": _combined_tls_status([
                    str(item.get("tls_certificate") or "not_observed") for item in hops
                ]),
                "body_complete": False,
            }, b""
        hop["redirect_to"] = _safe_url(target)
        current = target
    return {"url": _safe_url(url), "final_url": _safe_url(current), "state": "redirect_limit", "hops": hops}, b""


def _parse_security_txt(text: str, now: dt.datetime | None = None) -> dict[str, object]:
    now = now or dt.datetime.now(dt.timezone.utc)
    fields: dict[str, list[str]] = {}
    malformed = False
    for raw_line in text.splitlines():
        line = raw_line.strip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)", line)
        if not match:
            malformed = True
            continue
        fields.setdefault(match.group(1).lower(), []).append(match.group(2).strip())

    contacts = fields.get("contact", [])
    contact_valid = bool(contacts)
    for contact in contacts:
        parts = urlsplit(contact)
        if parts.scheme.lower() not in {"mailto", "https"} or not parts.path or (
            parts.scheme.lower() == "https" and not parts.hostname
        ):
            contact_valid = False
    expires = fields.get("expires", [])
    expiry_valid = False
    expired = False
    if len(expires) == 1:
        value = expires[0]
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value):
            try:
                expiry = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
                expiry_valid = expiry.tzinfo is not None
                expired = expiry <= now.astimezone(dt.timezone.utc) if expiry_valid else False
            except ValueError:
                expiry_valid = False

    reasons: list[str] = []
    if malformed:
        reasons.append("malformed_field")
    if not contacts:
        reasons.append("contact_missing")
    elif not contact_valid:
        reasons.append("contact_invalid")
    if not expires:
        reasons.append("expires_missing")
    elif len(expires) != 1:
        reasons.append("expires_multiple")
    elif not expiry_valid:
        reasons.append("expires_malformed")
    elif expired:
        reasons.append("expired")
    return {
        "contact_present": bool(contacts),
        "contact_valid": contact_valid,
        "expires_present": bool(expires),
        "expires_valid": expiry_valid and not expired,
        "expired": expired,
        "reasons": reasons,
    }


def _content_type_valid(headers: Mapping[str, object]) -> bool:
    content_type = str(headers.get("content-type") or "")
    parts = [part.strip() for part in content_type.split(";")]
    if not parts or parts[0].lower() != "text/plain":
        return False
    for parameter in parts[1:]:
        match = re.fullmatch(r"charset\s*=\s*['\"]?([^'\"]+)['\"]?", parameter, re.IGNORECASE)
        if match and match.group(1).strip().lower() not in {"utf-8", "utf8"}:
            return False
    return True


def _availability(result: Mapping[str, object]) -> str:
    if result.get("state") == "response":
        try:
            status = int(result.get("status_code") or 0)
        except (TypeError, ValueError):
            return "http_error"
        if 200 <= status < 300:
            return "present"
        if status in {404, 410}:
            return "absent"
        return "http_error"
    if result.get("state") == "redirect_limit" or (
        result.get("state") == "blocked_destination" and result.get("status_code") is not None
    ):
        return "http_error"
    return "lookup_error"


def probe_security_txt(
    domain: str,
    address_resolver: Callable[[str, float], tuple[list[str], str | None]] = _resolve_public_addresses,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    """GET the well-known security.txt over HTTP, with one connection-failure fallback."""
    domain = domain.strip().rstrip(".").lower()
    path = "/.well-known/security.txt"
    http_result, http_body = request_chain(
        f"http://{domain}{path}", address_resolver=address_resolver
    )
    attempts = [http_result]
    bodies = [http_body]
    http_received_response = any(isinstance(hop, Mapping) and isinstance(hop.get("status_code"), int) for hop in http_result.get("hops", []))
    fallback_attempted = (
        not http_received_response
        and http_result.get("state") in {"lookup_error", "request_error", "tls_error"}
    )
    if fallback_attempted:
        https_result, https_body = request_chain(
            f"https://{domain}{path}", address_resolver=address_resolver
        )
        attempts.append(https_result)
        bodies.append(https_body)

    selected = attempts[-1] if fallback_attempted else http_result
    body = bodies[-1] if fallback_attempted else http_body
    availability = _availability(selected)
    tls_status = _combined_tls_status([
        str(item.get("tls_certificate") or "not_observed") for item in attempts
    ])
    validation: dict[str, object] = {
        "utf8_valid": None,
        "content_type_valid": None,
        "contact_present": None,
        "contact_valid": None,
        "expires_present": None,
        "expires_valid": None,
        "expired": None,
        "reasons": [],
    }
    content_validity = "not_assessable"
    if availability == "present":
        if not selected.get("body_complete"):
            validation["reasons"] = ["body_incomplete"]
        else:
            try:
                text = body.decode("utf-8")
                validation["utf8_valid"] = True
            except UnicodeDecodeError:
                validation["utf8_valid"] = False
                text = None
            validation["content_type_valid"] = _content_type_valid(
                selected.get("headers") if isinstance(selected.get("headers"), Mapping) else {}
            )
            parsed = _parse_security_txt(text, now) if text is not None else {
                "contact_present": False,
                "contact_valid": False,
                "expires_present": False,
                "expires_valid": False,
                "expired": False,
                "reasons": ["utf8_invalid"],
            }
            for key in ("contact_present", "contact_valid", "expires_present", "expires_valid", "expired"):
                validation[key] = parsed[key]
            reasons = list(parsed["reasons"])
            if validation["utf8_valid"] is False:
                reasons.append("utf8_invalid")
            if validation["content_type_valid"] is False:
                reasons.append("content_type_invalid")
            validation["reasons"] = list(dict.fromkeys(reasons))
            content_validity = "valid" if not reasons and validation["content_type_valid"] else "invalid"

    compact_attempts: list[dict[str, object]] = []
    redirects_to_https = False
    https_response_received = False
    for attempt in attempts:
        hops = []
        for hop in attempt.get("hops", []) or []:
            if not isinstance(hop, Mapping):
                continue
            hop_url = hop.get("url")
            hop_status = hop.get("status_code")
            https_response_received = https_response_received or (
                isinstance(hop_url, str)
                and urlsplit(hop_url).scheme.lower() == "https"
                and isinstance(hop_status, int)
            )
            target = hop.get("redirect_to")
            redirects_to_https = redirects_to_https or (
                isinstance(target, str) and urlsplit(target).scheme.lower() == "https"
            )
            compact_hop: dict[str, object] = {
                "url": hop.get("url"),
                "status_code": hop.get("status_code"),
                "headers": hop.get("headers") if isinstance(hop.get("headers"), Mapping) else {},
            }
            if target:
                compact_hop["redirect_to"] = target
            if hop.get("state") != "response":
                compact_hop["error_kind"] = hop.get("state")
            hops.append(compact_hop)
        compact_attempts.append({
            "url": attempt.get("url"),
            "state": attempt.get("state"),
            "status_code": attempt.get("status_code"),
            "final_url": attempt.get("final_url"),
            "redirects_to_https": bool(attempt.get("redirects_to_https")),
            "error_kind": attempt.get("error_kind"),
            "hops": hops,
        })
    return {
        "availability": availability,
        "content_validity": content_validity,
        "tls_certificate": tls_status,
        "request": {
            "fallback_attempted": fallback_attempted,
            "redirects_to_https": redirects_to_https or any(bool(item.get("redirects_to_https")) for item in attempts),
            "https_response_received": https_response_received,
            "status_code": selected.get("status_code"),
            "final_url": selected.get("final_url"),
            "attempts": compact_attempts,
        },
        "validation": validation,
    }
