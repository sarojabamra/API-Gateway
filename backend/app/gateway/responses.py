import json
import re
from typing import Any, Dict, List, Set, Tuple

STRIP_UPSTREAM_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-backend-host",
    "x-runtime",
    "x-render-origin-server",
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

# Pattern-based redaction for values that look like SSN or long digit PANs
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def redact_json_fields(data: Any, fields_to_redact: Set[str], redacted_Accumulator: List[str]) -> Any:
    """Recursively masks sensitive fields in JSON responses (OWASP API3)."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if k in fields_to_redact or k.lower() in {f.lower() for f in fields_to_redact}:
                redacted_Accumulator.append(k)
                cleaned[k] = "[REDACTED BY GATEWAY API3 POLICY]"
            else:
                cleaned[k] = redact_json_fields(v, fields_to_redact, redacted_Accumulator)
        return cleaned
    if isinstance(data, list):
        return [redact_json_fields(item, fields_to_redact, redacted_Accumulator) for item in data]
    return data


def redact_pattern_values(data: Any, redacted_Accumulator: List[str]) -> Any:
    """Mask SSN-like and PAN-like string values anywhere in the JSON tree."""
    if isinstance(data, dict):
        return {k: redact_pattern_values(v, redacted_Accumulator) for k, v in data.items()}
    if isinstance(data, list):
        return [redact_pattern_values(item, redacted_Accumulator) for item in data]
    if isinstance(data, str):
        out = data
        if _SSN_RE.search(out):
            out = _SSN_RE.sub("[REDACTED-SSN]", out)
            redacted_Accumulator.append("ssn_pattern")
        # Avoid redacting short numeric IDs; require 13+ digits for PAN
        digits_only = re.sub(r"[^\d]", "", out)
        if len(digits_only) >= 13 and _PAN_RE.search(out):
            out = _PAN_RE.sub("[REDACTED-PAN]", out)
            redacted_Accumulator.append("pan_pattern")
        return out
    return data


def harden_response(
    status_code: int,
    upstream_headers: Dict[str, str],
    body_text: str,
    redact_fields: List[str],
    enable_header_hardening: bool = True,
    enable_field_redaction: bool = True,
    enable_pattern_redaction: bool = True,
    max_response_bytes: int = 0,
) -> Tuple[Dict[str, str], str, List[str]]:
    """
    Applies OWASP API3 (Response Property Redaction) and OWASP API8 (Security Headers,
    Server Banner Stripping, and Verbose Error Sanitization). Also enforces response size caps (API4).
    """
    out_headers: Dict[str, str] = {}
    security_header_keys_lower = {k.lower() for k in SECURITY_HEADERS}
    for k, v in upstream_headers.items():
        kl = k.lower()
        if enable_header_hardening and (kl in STRIP_UPSTREAM_HEADERS or kl in security_header_keys_lower):
            continue
        if kl in ("content-length", "transfer-encoding", "content-encoding", "connection", "keep-alive", "date"):
            continue
        out_headers[k] = v

    if enable_header_hardening:
        out_headers.update(SECURITY_HEADERS)

    redacted_list: List[str] = []
    out_body = body_text

    # Sanitize all 5xx including 502 (OWASP API8) — never leak exception text /
    # upstream stack traces. Preserve gateway-authored JSON that already uses the
    # safe {error, message|detail} shape (e.g. upstream connection hints).
    if enable_header_hardening and status_code >= 500:
        preserve_gateway_error = False
        if body_text and body_text.strip().startswith("{"):
            try:
                parsed_err = json.loads(body_text)
                if (
                    isinstance(parsed_err, dict)
                    and isinstance(parsed_err.get("error"), str)
                    and (
                        isinstance(parsed_err.get("message"), str)
                        or isinstance(parsed_err.get("detail"), str)
                    )
                    and "Traceback" not in body_text
                ):
                    preserve_gateway_error = True
                    out_body = body_text
            except Exception:
                preserve_gateway_error = False
        if not preserve_gateway_error:
            out_body = json.dumps({
                "error": "Upstream Service Error" if status_code != 502 else "Bad Gateway",
                "message": "An internal error occurred. Stack traces and internal details have been sanitized by SentinelGW (OWASP API8).",
            })
        return out_headers, out_body, redacted_list

    if max_response_bytes and body_text and len(body_text.encode("utf-8")) > max_response_bytes:
        out_body = json.dumps({
            "error": "Response Too Large",
            "message": f"Upstream response exceeded gateway cap of {max_response_bytes} bytes (OWASP API4).",
        })
        out_headers["X-Gateway-Decision"] = "response_capped"
        return out_headers, out_body, redacted_list

    # Redact sensitive fields in JSON responses (OWASP API3)
    if enable_field_redaction and body_text:
        stripped = body_text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(body_text)
                cleaned = parsed
                if redact_fields:
                    cleaned = redact_json_fields(parsed, set(redact_fields), redacted_list)
                if enable_pattern_redaction:
                    cleaned = redact_pattern_values(cleaned, redacted_list)
                if redacted_list:
                    out_body = json.dumps(cleaned)
                    out_headers["X-Gateway-Redacted-Fields"] = ",".join(sorted(set(redacted_list)))
            except Exception:
                pass

    return out_headers, out_body, sorted(set(redacted_list))
