import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

# Pre-compiled signature patterns for SQLi, NoSQLi, XSS, Path Traversal, Command Injection
SQLI_PATTERNS = [
    re.compile(r"(?i)(\bunion\b\s+\bselect\b)"),
    re.compile(r"(?i)(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"),
    re.compile(r"(?i)('|\")\s*or\s*('|\")1('|\")\s*=\s*('|\")1"),
    re.compile(r"(?i)(;\s*(drop|alter|truncate|delete|insert|update)\s+)"),
    re.compile(r"(?i)(\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\()"),
    re.compile(r"(?i)(--\s*$|/\*.*\*/)"),
]

NOSQLI_PATTERNS = [
    re.compile(r"(?i)(\$ne|\$gt|\$lt|\$where|\$regex)\b"),
]

XSS_PATTERNS = [
    re.compile(r"(?i)(<\s*script\b[^>]*>|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe\b|<svg\b[^>]*onload)"),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/etc/shadow|c:\\windows\\win\.ini)"),
]

CMD_INJECTION_PATTERNS = [
    re.compile(r"(?i)(;\s*(cat|ls|whoami|id|curl|wget|nc|bash|sh)\b|\|\|\s*(whoami|id|cat)\b|`[^`]+`|\$\([^)]+\))"),
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

MASS_ASSIGNMENT_FORBIDDEN_FIELDS = {
    "is_admin",
    "is_admin_override",
    "password_hash",
    "loyalty_balance",
    "internal_role",
}


def inspect_ssrf_url(candidate_url: str) -> Optional[str]:
    """
    OWASP API7: Inspects a URL string for SSRF targeting localhost, RFC1918 private networks,
    link-local cloud metadata (169.254.169.254), or dangerous schemes (file://, gopher://, dict://).
    """
    raw = unquote(candidate_url.strip())
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

    try:
        ip_obj = ipaddress.ip_address(hostname)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or str(ip_obj) == "169.254.169.254"
        ):
            return f"SSRF attempt targeting restricted IP range '{ip_obj}' (OWASP API7)"
    except ValueError:
        # Hostname is a domain name; check for embedded metadata IPs
        if "169.254.169.254" in raw or "127.0.0.1" in raw:
            return "SSRF attempt targeting cloud metadata / loopback address (OWASP API7)"

    return None


def inspect_request_payload(
    method: str,
    path: str,
    query_string: str,
    headers: Dict[str, str],
    body_text: str,
    max_body_bytes: int = 65536,
    max_page_limit: int = 100,
) -> Dict[str, Any]:
    """
    Performs deep inspection across URL path, query string, headers, and body for:
    - Request size & pagination cap violations (OWASP API4)
    - Mass assignment / forbidden input properties (OWASP API3)
    - SSRF URLs in query/body (OWASP API7)
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

    # Check query parameters for pagination abuse (?limit=50000) and SSRF (?url=...)
    parsed_qs = parse_qs(query_string, keep_blank_values=True)
    for k, values in parsed_qs.items():
        k_lower = k.lower()
        for val in values:
            if k_lower in ("limit", "page_size", "per_page", "count"):
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

            if k_lower in ("url", "uri", "target", "webhook", "callback", "endpoint", "dest", "redirect") or "://" in val or "169.254." in val:
                ssrf_err = inspect_ssrf_url(val)
                if ssrf_err:
                    return {
                        "violation": True,
                        "http_status": 403,
                        "owasp_id": "API7",
                        "policy_type": "ssrf",
                        "reason": ssrf_err,
                        "threat_score": 95,
                    }

    # Inspect JSON body for SSRF fields and API3 Mass Assignment
    if body_text and body_text.strip().startswith("{"):
        try:
            body_json = json.loads(body_text)
            if isinstance(body_json, dict):
                # API3 Mass Assignment check (e.g. registering with role="admin" or setting is_admin_override=True)
                if path.endswith("/register") and body_json.get("role") == "admin":
                    return {
                        "violation": True,
                        "http_status": 403,
                        "owasp_id": "API3",
                        "policy_type": "field_redaction",
                        "reason": "Blocked Mass Assignment attempt: client tried to self-assign 'role=admin' (OWASP API3)",
                        "threat_score": 85,
                    }
                for forbidden_key in MASS_ASSIGNMENT_FORBIDDEN_FIELDS:
                    if forbidden_key in body_json and body_json[forbidden_key] not in (False, None):
                        return {
                            "violation": True,
                            "http_status": 403,
                            "owasp_id": "API3",
                            "policy_type": "field_redaction",
                            "reason": f"Blocked Mass Assignment of protected property '{forbidden_key}' (OWASP API3)",
                            "threat_score": 80,
                        }

                for k, v in body_json.items():
                    if isinstance(v, str) and (
                        k.lower() in ("url", "webhook", "callback", "target", "endpoint") or "://" in v or "169.254." in v
                    ):
                        ssrf_err = inspect_ssrf_url(v)
                        if ssrf_err:
                            return {
                                "violation": True,
                                "http_status": 403,
                                "owasp_id": "API7",
                                "policy_type": "ssrf",
                                "reason": ssrf_err,
                                "threat_score": 95,
                            }
        except Exception:
            pass

    # Combine decoded inspection surface for signature checks
    combined_surface = unquote(f"{path}?{query_string}\n{body_text}")

    for pat in PATH_TRAVERSAL_PATTERNS:
        if pat.search(combined_surface):
            return {
                "violation": True,
                "http_status": 403,
                "owasp_id": "API8",
                "policy_type": "signature",
                "reason": f"Path traversal / sensitive file probe detected matching '{pat.pattern[:32]}'",
                "threat_score": 85,
            }

    for pat in SQLI_PATTERNS:
        if pat.search(combined_surface):
            return {
                "violation": True,
                "http_status": 403,
                "owasp_id": "API8",
                "policy_type": "signature",
                "reason": "SQL Injection (SQLi) payload signature detected in request",
                "threat_score": 90,
            }

    for pat in NOSQLI_PATTERNS:
        if pat.search(combined_surface):
            return {
                "violation": True,
                "http_status": 403,
                "owasp_id": "API8",
                "policy_type": "signature",
                "reason": "NoSQL Injection operator ($ne/$gt/$where) detected in request",
                "threat_score": 85,
            }

    for pat in XSS_PATTERNS:
        if pat.search(combined_surface):
            return {
                "violation": True,
                "http_status": 403,
                "owasp_id": "API8",
                "policy_type": "signature",
                "reason": "Cross-Site Scripting (XSS) payload detected in request",
                "threat_score": 80,
            }

    for pat in CMD_INJECTION_PATTERNS:
        if pat.search(combined_surface):
            return {
                "violation": True,
                "http_status": 403,
                "owasp_id": "API8",
                "policy_type": "signature",
                "reason": "OS Command Injection signature detected in request",
                "threat_score": 92,
            }

    return {"violation": False, "threat_score": 0}
