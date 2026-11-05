import html
import ipaddress
import json
import re
import socket
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse

try:
    import jsonschema
    from jsonschema import Draft7Validator
except ImportError:  # pragma: no cover
    jsonschema = None
    Draft7Validator = None

# Pre-compiled signature patterns for SQLi, NoSQLi, XSS, Path Traversal, Command Injection
SQLI_PATTERNS = [
    re.compile(r"(?i)(\bunion\b[\s/\*]+select\b)"),
    re.compile(r"(?i)(\bunion\b\s+\bselect\b)"),
    re.compile(r"(?i)(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"),
    re.compile(r"(?i)('|\")\s*or\s*('|\")1('|\")\s*=\s*('|\")1"),
    re.compile(r"(?i)(;\s*(drop|alter|truncate|delete|insert|update)\s+)"),
    re.compile(r"(?i)(\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\()"),
    re.compile(r"(?i)(information_schema|load_file\s*\(|xp_cmdshell)"),
    re.compile(r"(?i)(--\s|/\*.*?\*/)"),
]

NOSQLI_PATTERNS = [
    re.compile(r"(?i)(\$ne|\$gt|\$lt|\$where|\$regex)\b"),
]

XSS_PATTERNS = [
    re.compile(
        r"(?i)(<\s*script\b[^>]*>|javascript\s*:|onerror\s*=|onload\s*=|onfocus\s*=|ontoggle\s*=|"
        r"<\s*iframe\b|<svg\b[^>]*onload|<\s*img\b[^>]*onerror)"
    ),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(
        r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|\.\.%c0%af|/etc/passwd|/etc/shadow|c:\\windows\\win\.ini)"
    ),
]

CMD_INJECTION_PATTERNS = [
    re.compile(
        r"(?i)(;\s*(cat|ls|whoami|id|curl|wget|nc|bash|sh)\b|\|\|\s*(whoami|id|cat)\b|"
        r"`[^`]+`|\$\([^)]+\)|\$\{IFS\})"
    ),
]

PRIVATE_OR_METADATA_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

URL_LIKE_KEYS = {
    "url",
    "uri",
    "href",
    "link",
    "target",
    "webhook",
    "callback",
    "endpoint",
    "dest",
    "destination",
    "redirect",
    "next",
    "avatar",
    "image",
    "src",
}

MASS_ASSIGNMENT_FORBIDDEN_FIELDS = {
    "is_admin",
    "is_admin_override",
    "is_staff",
    "password_hash",
    "loyalty_balance",
    "internal_role",
    "role",
    "roles",
    "permissions",
    "owner_sub",
}

PAGINATION_KEYS = {"limit", "page_size", "per_page", "count", "first"}

SIGNATURE_RULES = [
    (PATH_TRAVERSAL_PATTERNS, 85, lambda pat: f"Path traversal / sensitive file probe detected matching '{pat.pattern[:32]}'"),
    (SQLI_PATTERNS, 90, lambda _pat: "SQL Injection (SQLi) payload signature detected in request"),
    (NOSQLI_PATTERNS, 85, lambda _pat: "NoSQL Injection operator ($ne/$gt/$where) detected in request"),
    (XSS_PATTERNS, 80, lambda _pat: "Cross-Site Scripting (XSS) payload detected in request"),
    (CMD_INJECTION_PATTERNS, 92, lambda _pat: "OS Command Injection signature detected in request"),
]


def walk_json(data: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    """Yield (json_path, value) for every node in a JSON-like structure."""
    yield path, data
    if isinstance(data, dict):
        for k, v in data.items():
            yield from walk_json(v, f"{path}.{k}")
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            yield from walk_json(item, f"{path}[{idx}]")


def collect_string_values(data: Any) -> List[str]:
    return [str(v) for _, v in walk_json(data) if isinstance(v, (str, int, float, bool))]


def normalize_inspection_surface(text: str) -> str:
    """Recursive URL-decode, HTML-entity decode, comment strip, NFKC, lowercase."""
    if not text:
        return ""
    current = text
    for _ in range(3):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    current = html.unescape(current)
    current = unicodedata.normalize("NFKC", current)
    current = re.sub(r"/\*.*?\*/", " ", current, flags=re.DOTALL)
    current = re.sub(r"--[^\n]*", " ", current)
    return current.lower()


def _try_parse_special_ip(hostname: str) -> Optional[ipaddress._BaseAddress]:
    """Parse decimal / octal / hex / dotted-weird IPv4 forms that ip_address() may reject."""
    host = hostname.strip().lower()
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    # Pure decimal IPv4 (e.g. 2130706433 -> 127.0.0.1)
    if host.isdigit():
        try:
            return ipaddress.IPv4Address(int(host))
        except Exception:
            return None

    # Hex IPv4 0x7f000001
    if host.startswith("0x"):
        try:
            return ipaddress.IPv4Address(int(host, 16))
        except Exception:
            return None

    # Dotted octal / mixed (e.g. 0177.0.0.1)
    if "." in host and all(p for p in host.split(".")):
        parts = host.split(".")
        if len(parts) == 4:
            try:
                nums = [int(p, 0) for p in parts]
                if all(0 <= n <= 255 for n in nums):
                    return ipaddress.IPv4Address(".".join(str(n) for n in nums))
            except Exception:
                pass
    return None


def _is_restricted_ip(ip_obj: ipaddress._BaseAddress, block_private: bool = True, block_metadata: bool = True) -> bool:
    # Unwrap IPv4-mapped IPv6
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if block_metadata and str(ip_obj) in ("169.254.169.254", "0.0.0.0"):
        return True
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
        return True
    if block_private and ip_obj.is_private:
        return True
    return False


def inspect_ssrf_url(
    candidate_url: str,
    *,
    resolve_dns: bool = True,
    block_private_cidrs: bool = True,
    block_metadata_ip: bool = True,
) -> Optional[str]:
    """
    OWASP API7: Inspects a URL for SSRF. Resolves DNS and rejects private/link-local/metadata IPs.
    """
    raw = unquote((candidate_url or "").strip())
    if not raw:
        return None

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        return f"Forbidden URL scheme '{scheme}://' detected in parameter (SSRF protection)"

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return None

    if hostname in PRIVATE_OR_METADATA_HOSTS or hostname.endswith(".internal") or hostname.endswith(".local"):
        return f"SSRF attempt targeting internal/metadata host '{hostname}' (OWASP API7)"

    if "169.254.169.254" in raw or "127.0.0.1" in raw:
        return "SSRF attempt targeting cloud metadata / loopback address (OWASP API7)"

    ip_obj = _try_parse_special_ip(hostname)
    if ip_obj is not None:
        if _is_restricted_ip(ip_obj, block_private_cidrs, block_metadata_ip):
            return f"SSRF attempt targeting restricted IP range '{ip_obj}' (OWASP API7)"
        return None

    if not resolve_dns:
        return None

    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Unresolvable host — allow (upstream will fail); cannot be SSRF to private IP yet
        return None
    except Exception:
        return None

    for entry in addrinfo:
        try:
            resolved = ipaddress.ip_address(entry[4][0])
        except Exception:
            continue
        if _is_restricted_ip(resolved, block_private_cidrs, block_metadata_ip):
            return (
                f"SSRF attempt: hostname '{hostname}' resolves to restricted IP '{resolved}' "
                f"(DNS-resolved OWASP API7)"
            )
    return None


def egress_trust_keys_for_base_url(base_url: str) -> Set[str]:
    """
    Build trust keys for a configured upstream base_url.

    Keys are host:port only so a local parking API on localhost:8001 is allowed
    for proxy egress without opening every other loopback port (e.g. :6379).
    """
    raw = (base_url or "").strip()
    if not raw:
        return set()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or "").lower().strip()
    if not host:
        return set()
    port = parsed.port
    if port is None:
        port = 443 if (parsed.scheme or "http").lower() == "https" else 80
    return {f"{host}:{port}"}


def _egress_target_keys(url: str) -> Set[str]:
    parsed = urlparse(url if "://" in (url or "") else f"http://{url or ''}")
    host = (parsed.hostname or "").lower().strip()
    if not host:
        return set()
    port = parsed.port
    if port is None:
        port = 443 if (parsed.scheme or "http").lower() == "https" else 80
    return {f"{host}:{port}"}


def inspect_egress_destination(
    url: str,
    allowed_hosts: Optional[Set[str]] = None,
    trusted_hosts: Optional[Set[str]] = None,
) -> Optional[str]:
    """
    OWASP API10 / API7: validate gateway-originated outbound destinations.

    ``trusted_hosts`` are explicit upstream origins (hostname and/or host:port)
    from Inventory base_url. Those destinations are allowed even when they are
    loopback/private — request-body SSRF (?url=, webhook fields) is unchanged.
    """
    raw = (url or "").strip()
    if not raw:
        return None

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        return f"Forbidden URL scheme '{scheme}://' detected in egress destination (OWASP API10 egress)"

    trust = {h.lower() for h in (trusted_hosts or set()) if h}
    target_keys = _egress_target_keys(raw)
    is_trusted_upstream = bool(trust and target_keys.intersection(trust))

    if not is_trusted_upstream:
        err = inspect_ssrf_url(url, resolve_dns=True)
        if err:
            return err.replace("OWASP API7", "OWASP API10 egress")

    if allowed_hosts:
        try:
            host = (parsed.hostname or "").lower()
            if host and host not in {h.lower() for h in allowed_hosts}:
                return f"Egress host '{host}' is not in the configured allowlist (OWASP API10)"
        except Exception:
            pass
    return None


def _find_mass_assignment(data: Any) -> Optional[str]:
    if not isinstance(data, (dict, list)):
        return None
    for path, value in walk_json(data):
        # Key is the last segment of the path (skip root "$")
        if path == "$" or ("." not in path and not path.startswith("$[")):
            continue
        key = path.rsplit(".", 1)[-1] if "." in path else ""
        if not key or "[" in key:
            continue
        key_lower = key.lower()
        if key_lower == "role" and str(value).lower() in ("admin", "root", "superuser", "owner", "staff"):
            return f"Blocked Mass Assignment attempt: client tried to assign '{key}={value}' (OWASP API3)"
        if key_lower in MASS_ASSIGNMENT_FORBIDDEN_FIELDS and value not in (False, None, "", []):
            if key_lower == "role" and str(value).lower() in ("user", "customer", "viewer"):
                continue
            return f"Blocked Mass Assignment of protected property '{key}' (OWASP API3)"
    return None


def _find_ssrf_in_data(
    data: Any,
    *,
    block_private_cidrs: bool = True,
    block_metadata_ip: bool = True,
) -> Optional[str]:
    for path, value in walk_json(data):
        if not isinstance(value, str):
            continue
        key = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if "[" in key:
            key = ""
        if key in URL_LIKE_KEYS or "://" in value or "169.254." in value:
            err = inspect_ssrf_url(
                value,
                block_private_cidrs=block_private_cidrs,
                block_metadata_ip=block_metadata_ip,
            )
            if err:
                return err
    return None


def _find_pagination_abuse(data: Any, max_page_limit: int) -> Optional[str]:
    for path, value in walk_json(data):
        key = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if "[" in key:
            continue
        if key in PAGINATION_KEYS:
            try:
                if int(value) > max_page_limit:
                    return f"Unrestricted pagination parameter '{key}={value}' exceeds gateway cap ({max_page_limit})"
            except (TypeError, ValueError):
                pass
    return None


def _lightweight_schema_check(body_json: Any, schema: Dict[str, Any]) -> Optional[str]:
    """Fallback validator when jsonschema is not installed — covers additionalProperties + required."""
    if not isinstance(schema, dict) or not isinstance(body_json, dict):
        return None
    props = schema.get("properties") or {}
    if schema.get("additionalProperties") is False:
        extras = [k for k in body_json.keys() if k not in props]
        if extras:
            return f"Request schema validation failed (OWASP API3/API8): additional properties not allowed ({extras[0]})"
    for req in schema.get("required") or []:
        if req not in body_json:
            return f"Request schema validation failed (OWASP API3/API8): '{req}' is a required property"
    return None


def validate_request_schema(body_json: Any, schema: Dict[str, Any]) -> Optional[str]:
    """Validate body against OpenAPI/JSON Schema. Rejects additionalProperties and readOnly writes."""
    if not schema:
        return None

    if Draft7Validator is not None:
        try:
            validator = Draft7Validator(schema)
            errors = sorted(validator.iter_errors(body_json), key=lambda e: list(e.path))
            if errors:
                err = errors[0]
                return f"Request schema validation failed (OWASP API3/API8): {err.message}"
        except Exception as exc:
            return f"Request schema validation error: {exc}"
    else:
        light_err = _lightweight_schema_check(body_json, schema)
        if light_err:
            return light_err

    # Explicitly reject writes to readOnly properties (including nested)
    readonly = _collect_readonly_paths(schema)
    if readonly and isinstance(body_json, dict):
        for path, _ in walk_json(body_json):
            # Convert $.a.b -> a.b
            clean = path[2:] if path.startswith("$.") else path.lstrip("$.").lstrip(".")
            if clean in readonly:
                return f"Blocked write to readOnly property '{clean}' (OWASP API3)"
    return None


def _collect_readonly_paths(schema: Dict[str, Any], prefix: str = "") -> Set[str]:
    found: Set[str] = set()
    if not isinstance(schema, dict):
        return found
    props = schema.get("properties") or {}
    for name, sub in props.items():
        path = f"{prefix}.{name}" if prefix else name
        if isinstance(sub, dict):
            if sub.get("readOnly") is True:
                found.add(path)
            found |= _collect_readonly_paths(sub, path)
    return found


def inspect_response_for_unsafe_urls(
    body_text: str,
    *,
    block_private_cidrs: bool = True,
    block_metadata_ip: bool = True,
) -> Optional[Dict[str, Any]]:
    """
    OWASP API10: walk upstream JSON responses for URL-like values pointing at private/metadata targets.
    """
    if not body_text:
        return None
    stripped = body_text.strip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return None
    try:
        data = json.loads(body_text)
    except Exception:
        return None
    err = _find_ssrf_in_data(data, block_private_cidrs=block_private_cidrs, block_metadata_ip=block_metadata_ip)
    if err:
        return {
            "violation": True,
            "http_status": 502,
            "owasp_id": "API10",
            "policy_type": "egress",
            "reason": f"Unsafe third-party / upstream payload URL (OWASP API10): {err}",
            "threat_score": 90,
        }
    return None


def strip_unsafe_urls_from_json(
    data: Any,
    *,
    block_private_cidrs: bool = True,
    block_metadata_ip: bool = True,
) -> Tuple[Any, List[str]]:
    """Replace unsafe URL strings in JSON with a redaction marker. Returns (cleaned, stripped_paths)."""
    stripped: List[str] = []

    def _walk(node: Any, path: str) -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                child_path = f"{path}.{k}" if path else k
                if isinstance(v, str) and (
                    k.lower() in URL_LIKE_KEYS or "://" in v or "169.254." in v
                ):
                    err = inspect_ssrf_url(
                        v,
                        block_private_cidrs=block_private_cidrs,
                        block_metadata_ip=block_metadata_ip,
                    )
                    if err:
                        stripped.append(child_path)
                        out[k] = "[STRIPPED BY GATEWAY API10 POLICY]"
                        continue
                out[k] = _walk(v, child_path)
            return out
        if isinstance(node, list):
            return [_walk(item, f"{path}[{idx}]") for idx, item in enumerate(node)]
        return node

    return _walk(data, "$"), stripped


def inspect_request_payload(
    path: str,
    query_string: str,
    body_text: str,
    max_body_bytes: int = 65536,
    max_page_limit: int = 100,
    request_schema_json: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    block_private_cidrs: bool = True,
    block_metadata_ip: bool = True,
    enable_sqli: bool = True,
    enable_xss: bool = True,
    enable_path_traversal: bool = True,
    enable_cmd_injection: bool = True,
) -> Dict[str, Any]:
    """
    Deep inspection across URL path, query string, headers, and body for:
    - Request size & pagination (OWASP API4)
    - Mass assignment / schema validation (OWASP API3)
    - SSRF URLs including nested JSON + DNS resolve (OWASP API7)
    - SQLi, NoSQLi, XSS, Path Traversal, Command Injection (OWASP API8)
    """
    body_bytes = len(body_text.encode("utf-8")) if body_text else 0
    if body_bytes > max_body_bytes:
        return {
            "violation": True,
            "http_status": 413,
            "owasp_id": "API4",
            "policy_type": "size_limit",
            "reason": f"Request payload size ({body_bytes} bytes) exceeds maximum allowed ({max_body_bytes} bytes)",
            "threat_score": 65,
        }

    parsed_qs = parse_qs(query_string, keep_blank_values=True)
    for k, values in parsed_qs.items():
        k_lower = k.lower()
        for val in values:
            if k_lower in PAGINATION_KEYS:
                try:
                    if int(val) > max_page_limit:
                        return {
                            "violation": True,
                            "http_status": 400,
                            "owasp_id": "API4",
                            "policy_type": "size_limit",
                            "reason": f"Unrestricted pagination parameter '{k}={val}' exceeds gateway cap ({max_page_limit})",
                            "threat_score": 60,
                        }
                except ValueError:
                    pass

            if k_lower in URL_LIKE_KEYS or "://" in val or "169.254." in val:
                ssrf_err = inspect_ssrf_url(
                    val,
                    block_private_cidrs=block_private_cidrs,
                    block_metadata_ip=block_metadata_ip,
                )
                if ssrf_err:
                    return {
                        "violation": True,
                        "http_status": 403,
                        "owasp_id": "API7",
                        "policy_type": "ssrf",
                        "reason": ssrf_err,
                        "threat_score": 95,
                    }

    body_json: Any = None
    if body_text and body_text.strip()[:1] in ("{", "["):
        try:
            body_json = json.loads(body_text)
        except Exception:
            body_json = None

    if body_json is not None:
        page_err = _find_pagination_abuse(body_json, max_page_limit)
        if page_err:
            return {
                "violation": True,
                "http_status": 400,
                "owasp_id": "API4",
                "policy_type": "size_limit",
                "reason": page_err,
                "threat_score": 60,
            }

        mass_err = _find_mass_assignment(body_json)
        if mass_err:
            return {
                "violation": True,
                "http_status": 403,
                "owasp_id": "API3",
                "policy_type": "field_redaction",
                "reason": mass_err,
                "threat_score": 85,
            }

        if request_schema_json:
            try:
                schema = json.loads(request_schema_json) if isinstance(request_schema_json, str) else request_schema_json
                schema_err = validate_request_schema(body_json, schema)
                if schema_err:
                    return {
                        "violation": True,
                        "http_status": 400,
                        "owasp_id": "API3",
                        "policy_type": "field_redaction",
                        "reason": schema_err,
                        "threat_score": 75,
                    }
            except Exception:
                pass

        ssrf_err = _find_ssrf_in_data(
            body_json,
            block_private_cidrs=block_private_cidrs,
            block_metadata_ip=block_metadata_ip,
        )
        if ssrf_err:
            return {
                "violation": True,
                "http_status": 403,
                "owasp_id": "API7",
                "policy_type": "ssrf",
                "reason": ssrf_err,
                "threat_score": 95,
            }

    header_surface = ""
    if headers:
        for hk in ("referer", "cookie", "x-forwarded-for", "x-forwarded-host", "x-original-url"):
            for k, v in headers.items():
                if k.lower() == hk:
                    header_surface += f"\n{k}:{v}"

    nested_strings = ""
    if body_json is not None:
        nested_strings = "\n".join(collect_string_values(body_json))

    combined_raw = f"{path}?{query_string}\n{body_text}\n{header_surface}\n{nested_strings}"
    combined_surface = normalize_inspection_surface(combined_raw)

    enabled_families = []
    if enable_path_traversal:
        enabled_families.append(SIGNATURE_RULES[0])
    if enable_sqli:
        enabled_families.append(SIGNATURE_RULES[1])
        enabled_families.append(SIGNATURE_RULES[2])
    if enable_xss:
        enabled_families.append(SIGNATURE_RULES[3])
    if enable_cmd_injection:
        enabled_families.append(SIGNATURE_RULES[4])

    for patterns, score, reason_fn in enabled_families:
        for pat in patterns:
            if pat.search(combined_surface):
                return {
                    "violation": True,
                    "http_status": 403,
                    "owasp_id": "API8",
                    "policy_type": "signature",
                    "reason": reason_fn(pat),
                    "threat_score": score,
                }

    return {"violation": False, "threat_score": 0}
