import json
from typing import Any, Dict, List, Set, Tuple

STRIP_UPSTREAM_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-backend-host",
    "x-runtime",
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Protected-By": "SentinelGW-OWASP-API-Shield",
}


def redact_json_fields(data: Any, fields_to_redact: Set[str], redacted_Accumulator: List[str]) -> Any:
    """Recursively masks sensitive fields in JSON responses (OWASP API3)."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if k in fields_to_redact:
                redacted_Accumulator.append(k)
                cleaned[k] = "[REDACTED BY GATEWAY API3 POLICY]"
            else:
                cleaned[k] = redact_json_fields(v, fields_to_redact, redacted_Accumulator)
        return cleaned
    if isinstance(data, list):
        return [redact_json_fields(item, fields_to_redact, redacted_Accumulator) for item in data]
    return data


def harden_response(
    status_code: int,
    upstream_headers: Dict[str, str],
    body_text: str,
    redact_fields: List[str],
    enable_header_hardening: bool = True,
    enable_field_redaction: bool = True,
) -> Tuple[Dict[str, str], str, List[str]]:
    """
    Applies OWASP API3 (Response Property Redaction) and OWASP API8 (Security Headers,
    Server Banner Stripping, and Verbose Error Sanitization).
    """
    out_headers: Dict[str, str] = {}
    for k, v in upstream_headers.items():
        if enable_header_hardening and k.lower() in STRIP_UPSTREAM_HEADERS:
            continue
        if k.lower() in ("content-length", "transfer-encoding", "content-encoding"):
            continue
        out_headers[k] = v

    if enable_header_hardening:
        out_headers.update(SECURITY_HEADERS)

    redacted_list: List[str] = []
    out_body = body_text

    # Sanitize verbose upstream 500 errors (OWASP API8)
    if enable_header_hardening and status_code >= 500:
        out_body = json.dumps({
            "error": "Upstream Service Error",
            "message": "An internal error occurred. Stack traces and internal details have been sanitized by SentinelGW (OWASP API8).",
        })
        return out_headers, out_body, redacted_list

    # Redact sensitive fields in JSON responses (OWASP API3)
    if enable_field_redaction and redact_fields and body_text:
        stripped = body_text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(body_text)
                cleaned = redact_json_fields(parsed, set(redact_fields), redacted_list)
                if redacted_list:
                    out_body = json.dumps(cleaned)
                    out_headers["X-Gateway-Redacted-Fields"] = ",".join(sorted(set(redacted_list)))
            except Exception:
                pass

    return out_headers, out_body, sorted(set(redacted_list))
