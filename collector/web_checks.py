"""Bounded root HEAD and security.txt GET observations."""

from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import re
import socket
import ssl
import time
import unicodedata
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
RFC3339_EXPIRES_RE = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})[Tt]"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<zone>[Zz]|(?P<sign>[+-])(?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))",
    re.ASCII,
)
FIELD_NAME_RE = re.compile(r"[!-9;-~]+", re.ASCII)
URI_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*\Z", re.ASCII)
URI_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
URI_SUBDELIMS = frozenset("!$&'()*+,;=")
LANGUAGE_GRANDFATHERED = frozenset({
    "art-lojban", "cel-gaulish", "en-gb-oed", "i-ami", "i-bnn", "i-default",
    "i-enochian", "i-hak", "i-klingon", "i-lux", "i-mingo", "i-navajo",
    "i-pwn", "i-tao", "i-tay", "i-tsu", "no-bok", "no-nyn", "sgn-be-fr",
    "sgn-be-nl", "sgn-ch-de", "zh-guoyu", "zh-hakka", "zh-min", "zh-min-nan",
    "zh-xiang",
})
LEAP_SECOND_DATES = frozenset({
    "1972-06-30", "1972-12-31", "1973-06-30", "1973-12-31", "1974-12-31",
    "1975-12-31", "1976-12-31", "1977-12-31", "1978-12-31", "1979-12-31",
    "1981-06-30", "1982-06-30", "1983-06-30", "1985-06-30", "1987-12-31",
    "1989-12-31", "1990-12-31", "1992-06-30", "1993-06-30", "1994-06-30",
    "1995-12-31", "1997-06-30", "1998-12-31", "2005-12-31", "2008-12-31",
    "2012-06-30", "2015-06-30", "2016-12-31",
})


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
    method: str = "GET",
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
            conn.request(method, path, headers={
                "User-Agent": HTTP_USER_AGENT,
                "Accept": "*/*",
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
            if method != "HEAD" and 200 <= response.status < 300:
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
    method: str = "GET",
) -> tuple[dict[str, object], bytes]:
    """Fetch one URL with a bounded redirect chain and no retained response body."""
    method = method.upper()
    if method not in {"GET", "HEAD"}:
        raise ValueError("Only GET and HEAD requests are supported")
    deadline = time.monotonic() + timeout
    current = url
    hops: list[dict[str, object]] = []
    response_body = b""
    for redirect_number in range(max_redirects + 1):
        if method == "HEAD":
            hop, body = _request_once(current, deadline, body_limit, address_resolver, method=method)
        else:
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


def probe_root_head(
    domain: str,
    address_resolver: Callable[[str, float], tuple[list[str], str | None]] = _resolve_public_addresses,
) -> dict[str, object]:
    """Observe whether an HTTP HEAD of / redirects into HTTPS and retain selected headers."""
    domain = domain.strip().rstrip(".").lower()
    result, _ = request_chain(
        f"http://{domain}/", body_limit=0, address_resolver=address_resolver, method="HEAD"
    )
    hops = [hop for hop in result.get("hops", []) if isinstance(hop, Mapping)]
    upgrades = any(
        urlsplit(str(hop.get("url") or "")).scheme.lower() == "http"
        and urlsplit(str(hop.get("redirect_to") or "")).scheme.lower() == "https"
        for hop in hops
    )
    status_code = result.get("status_code")
    state = str(result.get("state") or "lookup_error")
    if upgrades:
        upgrade_result: bool | None = True
        upgrade_state = "upgraded"
    elif state == "response" and status_code not in {405, 501}:
        upgrade_result = False
        upgrade_state = "not_upgraded"
    else:
        upgrade_result = None
        upgrade_state = "unknown"
        if state == "response" and status_code in {405, 501}:
            state = "head_unsupported"

    return {
        "method": "HEAD",
        "path": "/",
        "state": state,
        "status_code": status_code if isinstance(status_code, int) else None,
        "final_url": result.get("final_url"),
        "upgrades_to_https": upgrade_result,
        "upgrade_state": upgrade_state,
        "tls_certificate": result.get("tls_certificate", "not_observed"),
        "headers": result.get("headers", {}),
        "hops": [
            {
                key: hop.get(key)
                for key in ("url", "status_code", "redirect_to", "state", "headers", "tls_certificate")
                if hop.get(key) is not None
            }
            for hop in hops
        ],
    }


def _valid_uri(value: str, *, require_https_for_web: bool = False) -> bool:
    """Validate the ASCII URI syntax used by RFC 9116 fields."""
    if not value or any(ord(char) > 0x7E or ord(char) < 0x21 for char in value):
        return False
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return False
    try:
        parts = urlsplit(value)
        if not URI_SCHEME_RE.fullmatch(parts.scheme):
            return False

        def component_valid(component: str, extra: str) -> bool:
            index = 0
            while index < len(component):
                char = component[index]
                if char == "%":
                    if index + 2 >= len(component) or not re.fullmatch(r"[0-9A-Fa-f]{2}", component[index + 1:index + 3]):
                        return False
                    index += 3
                    continue
                if char not in URI_UNRESERVED and char not in URI_SUBDELIMS and char not in extra:
                    return False
                index += 1
            return True

        if not component_valid(parts.path, ":/@"):
            return False
        if not component_valid(parts.query, ":/@/?") or not component_valid(parts.fragment, ":/@/?"):
            return False

        scheme = parts.scheme.lower()
        if parts.netloc:
            authority = parts.netloc
            userinfo, separator, host_port = authority.rpartition("@")
            if separator and ("@" in userinfo or not component_valid(userinfo, ":")):
                return False
            if host_port.startswith("["):
                closing = host_port.find("]")
                if closing < 0:
                    return False
                ip_literal = host_port[1:closing]
                suffix = host_port[closing + 1:]
                if suffix and not re.fullmatch(r":\d*", suffix):
                    return False
                try:
                    ipaddress.IPv6Address(ip_literal)
                except ValueError:
                    if not re.fullmatch(r"[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+", ip_literal):
                        return False
            else:
                if host_port.count(":") > 1:
                    return False
                host, colon, port = host_port.partition(":")
                if colon and port and not port.isdigit():
                    return False
                if not component_valid(host, ""):
                    return False
            # Accessing .port validates numeric and in-range ports when the
            # authority is not an IPvFuture literal.
            try:
                if not host_port.startswith("[") or not re.match(r"\[[vV][0-9A-Fa-f]+\.", host_port):
                    _ = parts.port
            except ValueError:
                return False
        if scheme in {"http", "https", "ftp", "ws", "wss"}:
            if require_https_for_web and scheme != "https":
                return False
            if scheme == "https" and (not parts.netloc or not parts.hostname):
                return False
            if scheme == "http" and not parts.hostname:
                return False
        if scheme in {"mailto", "tel"} and not parts.path:
            return False
    except ValueError:
        return False
    return True


def _valid_language_tag(value: str) -> bool:
    """Check RFC 5646 language-tag syntax without needing registry data."""
    tag = value.lower()
    if tag in LANGUAGE_GRANDFATHERED:
        return True
    parts = tag.split("-")
    if not parts or any(not part or not part.isascii() or not part.isalnum() for part in parts):
        return False
    if parts[0] == "x":
        return len(parts) > 1 and all(1 <= len(part) <= 8 for part in parts[1:])

    language = parts[0]
    if not language.isalpha() or not (2 <= len(language) <= 8):
        return False
    index = 1
    if len(language) <= 3:
        extlangs = 0
        while index < len(parts) and len(parts[index]) == 3 and parts[index].isalpha() and extlangs < 3:
            index += 1
            extlangs += 1
    if index < len(parts) and len(parts[index]) == 4 and parts[index].isalpha():
        index += 1
    if index < len(parts) and (
        (len(parts[index]) == 2 and parts[index].isalpha())
        or (len(parts[index]) == 3 and parts[index].isdigit())
    ):
        index += 1
    variants: set[str] = set()
    while index < len(parts) and (
        5 <= len(parts[index]) <= 8
        or (len(parts[index]) == 4 and parts[index][0].isdigit())
    ):
        if parts[index] in variants:
            return False
        variants.add(parts[index])
        index += 1
    extensions: set[str] = set()
    while index < len(parts) and len(parts[index]) == 1 and parts[index] != "x":
        singleton = parts[index]
        if singleton in extensions:
            return False
        extensions.add(singleton)
        index += 1
        first_subtag = index
        while index < len(parts) and 2 <= len(parts[index]) <= 8:
            index += 1
        if index == first_subtag:
            return False
    if index < len(parts) and parts[index] == "x":
        index += 1
        first_subtag = index
        while index < len(parts) and 1 <= len(parts[index]) <= 8:
            index += 1
        if index == first_subtag:
            return False
    return index == len(parts)


def _parse_expires(value: str, now: dt.datetime) -> tuple[bool, str, bool | None]:
    """Return (syntax_valid, freshness, expired) for an RFC 3339 date-time."""
    match = RFC3339_EXPIRES_RE.fullmatch(value)
    if not match:
        return False, "unknown", None
    try:
        year = int(match.group("year"))
        month = int(match.group("month"))
        day = int(match.group("day"))
        hour = int(match.group("hour"))
        minute = int(match.group("minute"))
        second = int(match.group("second"))
        if hour > 23 or minute > 59 or second > 60:
            return False, "unknown", None

        zone = match.group("zone")
        if zone.lower() == "z":
            offset = dt.timedelta(0)
        else:
            offset_hour = int(match.group("offset_hour"))
            offset_minute = int(match.group("offset_minute"))
            if offset_hour > 23 or offset_minute > 59:
                return False, "unknown", None
            offset = dt.timedelta(hours=offset_hour, minutes=offset_minute)
            if match.group("sign") == "-":
                offset = -offset
        timezone = dt.timezone(offset)
        fraction = match.group("fraction") or ""
        microseconds = int((fraction[:6] + "000000")[:6]) if fraction else 0
        submicrosecond_nonzero = any(char != "0" for char in fraction[6:])

        if second == 60:
            # datetime cannot represent leap seconds. Validate the UTC instant
            # against announced leap-second dates, then map it to the next
            # representable instant for freshness comparison.
            local_base = dt.datetime(year, month, day, hour, minute, 59, tzinfo=timezone)
            utc_base = local_base.astimezone(dt.timezone.utc)
            if utc_base.strftime("%Y-%m-%d") not in LEAP_SECOND_DATES or (utc_base.hour, utc_base.minute) != (23, 59):
                return False, "unknown", None
            # Collapse the unrepresentable leap-second interval to its next
            # representable instant; at that boundary the expiry is stale.
            expiry = utc_base + dt.timedelta(seconds=1)
        else:
            expiry = dt.datetime(year, month, day, hour, minute, second, microseconds, tzinfo=timezone).astimezone(dt.timezone.utc)
    except (OverflowError, ValueError):
        return False, "unknown", None

    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    now_utc = now.astimezone(dt.timezone.utc)
    expired = expiry < now_utc or (expiry == now_utc and not submicrosecond_nonzero)
    return True, "expired" if expired else "current", expired


def _split_security_txt_lines(text: str) -> tuple[list[str] | None, bool, str | None]:
    """Split only RFC 9116 LF/CRLF lines and enforce parser safety bounds."""
    if not text.endswith("\n") or re.search(r"\r(?!\n)", text):
        return None, False, "line_ending_invalid"
    all_crlf = text.count("\n") == text.count("\r\n")
    normalized = text.replace("\r\n", "\n")
    lines = normalized[:-1].split("\n")
    if len(lines) > 1000 or any(len(line) > 2048 for line in lines):
        return None, all_crlf, "parser_limit_exceeded"
    return lines, all_crlf, None


def _extract_signed_cleartext(lines: list[str], all_crlf: bool) -> list[str] | None:
    """Check RFC 9116 clear-signature framing; cryptographic trust is separate."""
    if not all_crlf or not lines or lines[0] != "-----BEGIN PGP SIGNED MESSAGE-----":
        return None
    index = 1
    hash_count = 0
    token = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    while index < len(lines) and lines[index].startswith("Hash: "):
        hashes = lines[index][6:].split(",")
        if not hashes or any(not re.fullmatch(token, value) for value in hashes):
            return None
        hash_count += 1
        index += 1
    if hash_count == 0 or index >= len(lines) or lines[index] != "":
        return None
    index += 1
    try:
        signature_start = lines.index("-----BEGIN PGP SIGNATURE-----", index)
    except ValueError:
        return None
    cleartext = lines[index:signature_start]
    for line in cleartext:
        if line.startswith("- "):
            # RFC 4880 dash escaping prefixes one additional "- " to lines
            # that would otherwise be ambiguous in clear-signed text.
            continue
        if "\r" in line:
            return None

    index = signature_start + 1
    while index < len(lines) and lines[index] != "":
        if not re.fullmatch(rf"{token}: [\x20-\x7e\t]*", lines[index]):
            return None
        index += 1
    if index >= len(lines) or lines[index] != "":
        return None
    index += 1
    data_count = 0
    while index < len(lines) and lines[index] != "-----END PGP SIGNATURE-----":
        if not re.fullmatch(r"[A-Za-z0-9=/+]+", lines[index]):
            return None
        data_count += 1
        index += 1
    if data_count == 0 or index != len(lines) - 1:
        return None
    cleartext = [line[2:] if line.startswith("- ") else line for line in cleartext]
    return cleartext


def _parse_security_txt(text: str, now: dt.datetime | None = None) -> dict[str, object]:
    now = now or dt.datetime.now(dt.timezone.utc)
    lines, all_crlf, limit_or_line_error = _split_security_txt_lines(text)
    if lines is None:
        reason = limit_or_line_error or "line_ending_invalid"
        return {
            "contact_present": False, "contact_valid": False,
            "expires_present": False, "expires_valid": False,
            "expired": None, "freshness": "unknown", "signature_status": "unknown",
            "not_assessable": reason == "parser_limit_exceeded", "reasons": [reason],
        }

    text_without_linebreaks = text.replace("\r", "").replace("\n", "")
    if text.startswith("\ufeff"):
        return {
            "contact_present": False, "contact_valid": False,
            "expires_present": False, "expires_valid": False,
            "expired": None, "freshness": "unknown", "signature_status": "not_signed",
            "not_assessable": False, "reasons": ["utf8_bom"],
        }
    if any(
        (0x80 <= ord(char) <= 0x9F)
        or ord(char) == 0x7F
        or (ord(char) < 0x20 and char not in "\t")
        or char in "\u2028\u2029"
        or unicodedata.category(char) == "Cn"
        for char in text_without_linebreaks
    ):
        return {
            "contact_present": False, "contact_valid": False,
            "expires_present": False, "expires_valid": False,
            "expired": None, "freshness": "unknown", "signature_status": "not_signed",
            "not_assessable": False, "reasons": ["net_unicode_invalid"],
        }

    signature_status = "not_signed"
    if lines and lines[0] == "-----BEGIN PGP SIGNED MESSAGE-----":
        cleartext = _extract_signed_cleartext(lines, all_crlf)
        if cleartext is None:
            return {
                "contact_present": False, "contact_valid": False,
                "expires_present": False, "expires_valid": False,
                "expired": None, "freshness": "unknown", "signature_status": "invalid",
                "not_assessable": False, "reasons": ["signed_format_invalid"],
            }
        lines = cleartext
        signature_status = "present_unverified"

    fields: dict[str, list[str]] = {}
    reasons: list[str] = []
    for line in lines:
        if not line.strip(" \t"):
            continue
        if line.startswith("#"):
            continue
        match = re.fullmatch(r"([^:]+): (.*)", line)
        if not match or not FIELD_NAME_RE.fullmatch(match.group(1)):
            reasons.append("malformed_field")
            continue
        name, value = match.group(1).lower(), match.group(2)
        if not value.strip(" \t"):
            reasons.append("field_value_missing")
            continue
        fields.setdefault(name, []).append(value)

    contacts = fields.get("contact", [])
    contact_valid = bool(contacts) and all(_valid_uri(value, require_https_for_web=True) for value in contacts)
    if not contacts:
        reasons.append("contact_missing")
    elif not contact_valid:
        reasons.append("contact_invalid")

    expires = fields.get("expires", [])
    expires_valid = False
    expired: bool | None = None
    freshness = "unknown"
    if not expires:
        reasons.append("expires_missing")
    elif len(expires) != 1:
        reasons.append("expires_multiple")
    else:
        expires_valid, freshness, expired = _parse_expires(expires[0], now)
        if not expires_valid:
            reasons.append("expires_malformed")

    uri_fields_valid = True
    for field_name in ("acknowledgments", "canonical", "encryption", "hiring", "policy"):
        for value in fields.get(field_name, []):
            if not _valid_uri(value, require_https_for_web=True):
                uri_fields_valid = False
    if not uri_fields_valid:
        reasons.append("uri_field_invalid")

    languages = fields.get("preferred-languages", [])
    languages_valid = True
    if len(languages) > 1:
        languages_valid = False
        reasons.append("preferred_languages_multiple")
    elif languages:
        value = languages[0]
        raw_tags = value.split(",")
        tags = [item.strip(" \t") for item in raw_tags]
        if value != value.strip(" \t") or not tags or any(not _valid_language_tag(tag) for tag in tags):
            languages_valid = False
            reasons.append("preferred_languages_invalid")

    return {
        "contact_present": bool(contacts),
        "contact_valid": contact_valid,
        "expires_present": bool(expires),
        "expires_valid": expires_valid,
        "expired": expired,
        "freshness": freshness,
        "signature_status": signature_status,
        "not_assessable": False,
        "uri_fields_valid": uri_fields_valid,
        "preferred_languages_valid": languages_valid,
        "utf8_nfc": unicodedata.normalize("NFC", text) == text,
        "reasons": list(dict.fromkeys(reasons)),
    }


def _content_type_valid(headers: Mapping[str, object]) -> bool:
    content_type = str(headers.get("content-type") or "")
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in content_type:
        if escaped:
            current.append(char)
            escaped = False
        elif quoted and char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or escaped:
        return False
    parts.append("".join(current).strip())
    if not parts or parts[0].lower() != "text/plain":
        return False
    charset_values: list[str] = []
    parameter_re = re.compile(
        r"([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=\s*(?:\"((?:\\.|[^\"\\])*)\"|([!#$%&'*+.^_`|~0-9A-Za-z-]+))\Z"
    )
    for parameter in parts[1:]:
        match = parameter_re.fullmatch(parameter)
        if not match:
            return False
        if match.group(1).lower() == "charset":
            charset = match.group(2) if match.group(2) is not None else match.group(3)
            charset_values.append(re.sub(r"\\(.)", r"\1", charset))
    return len(charset_values) <= 1 and (not charset_values or charset_values[0].lower() == "utf-8")


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
        "uri_fields_valid": None,
        "preferred_languages_valid": None,
        "signature_status": "unknown",
        "utf8_nfc": None,
        "reasons": [],
    }
    content_validity = "not_assessable"
    freshness = "unknown"
    if availability == "present":
        if not selected.get("body_complete"):
            validation["reasons"] = ["body_incomplete"]
        elif len(body) > MAX_SECURITY_TXT_BYTES:
            validation["reasons"] = ["parser_limit_exceeded"]
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
                "expired": None,
                "freshness": "unknown",
                "uri_fields_valid": False,
                "preferred_languages_valid": False,
                "signature_status": "unknown",
                "utf8_nfc": None,
                "not_assessable": False,
                "reasons": ["utf8_invalid"],
            }
            for key in (
                "contact_present", "contact_valid", "expires_present", "expires_valid", "expired",
                "uri_fields_valid", "preferred_languages_valid", "signature_status", "utf8_nfc",
            ):
                validation[key] = parsed[key]
            freshness = str(parsed.get("freshness") or "unknown")
            reasons = list(parsed["reasons"])
            if validation["utf8_valid"] is False:
                reasons.append("utf8_invalid")
            if validation["content_type_valid"] is False:
                reasons.append("content_type_invalid")
            validation["reasons"] = list(dict.fromkeys(reasons))
            if parsed.get("not_assessable"):
                content_validity = "not_assessable"
            else:
                content_validity = "valid" if not reasons and validation["content_type_valid"] else "invalid"

    compact_attempts: list[dict[str, object]] = []
    redirects_to_https = False
    https_response_received = False
    cross_host_redirect = False
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
            if isinstance(target, str) and isinstance(hop_url, str):
                source_host = urlsplit(hop_url).hostname
                target_host = urlsplit(target).hostname
                cross_host_redirect = cross_host_redirect or (
                    bool(source_host and target_host) and source_host.lower() != target_host.lower()
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
        "freshness": freshness,
        "tls_certificate": tls_status,
        "request": {
            "fallback_attempted": fallback_attempted,
            "redirects_to_https": redirects_to_https or any(bool(item.get("redirects_to_https")) for item in attempts),
            "cross_host_redirect": cross_host_redirect,
            "https_response_received": https_response_received,
            "status_code": selected.get("status_code"),
            "final_url": selected.get("final_url"),
            "attempts": compact_attempts,
        },
        "validation": validation,
    }
