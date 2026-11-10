import json
import time
from typing import Any, Dict, List, Optional

from redis.exceptions import RedisError

from app.gateway.redis_client import redis_handle
from app.models import RequestLog


class BehavioralTracker:
    """
    Sliding-window behavioral state tracker for multi-event OWASP correlation rules.
    Windows live in Redis so every gateway worker sees the same client history.
    Process memory is used only when Redis is unavailable.
    """

    def __init__(self):
        self.login_failures: Dict[str, List[float]] = {}
        self.login_usernames: Dict[str, Dict[str, float]] = {}
        self.bola_object_ids: Dict[str, Dict[str, float]] = {}
        self.bfla_probes: Dict[str, List[float]] = {}
        self.rate_limit_hits: Dict[str, List[float]] = {}
        self.sensitive_flow_hits: Dict[str, List[float]] = {}
        self.shadow_scan_hits: Dict[str, List[float]] = {}
        self.revoked_token_hits: Dict[str, List[float]] = {}

    def _prune_ts(self, ts_list: List[float], window_sec: float, now: float) -> List[float]:
        return [t for t in ts_list if now - t <= window_sec]

    def _prune_dict(self, d: Dict[str, float], window_sec: float, now: float) -> Dict[str, float]:
        return {k: t for k, t in d.items() if now - t <= window_sec}

    def _redis_zadd_now(self, key: str, now: float, window_sec: float) -> Optional[int]:
        client = redis_handle.get()
        if client is None:
            return None
        try:
            pipe = client.pipeline()
            pipe.zadd(key, {f"{now:.6f}": now})
            pipe.zremrangebyscore(key, 0, now - window_sec)
            pipe.zcard(key)
            pipe.expire(key, int(window_sec) + 60)
            _, _, count, _ = pipe.execute()
            return int(count)
        except RedisError:
            redis_handle.mark_down()
            return None

    def _redis_zadd_member(self, key: str, member: str, now: float, window_sec: float) -> Optional[int]:
        client = redis_handle.get()
        if client is None:
            return None
        try:
            pipe = client.pipeline()
            pipe.zadd(key, {member: now})
            pipe.zremrangebyscore(key, 0, now - window_sec)
            pipe.zcard(key)
            pipe.expire(key, int(window_sec) + 60)
            _, _, count, _ = pipe.execute()
            return int(count)
        except RedisError:
            redis_handle.mark_down()
            return None

    def _count_event(
        self,
        store: Dict[str, List[float]],
        mem_key: str,
        redis_key: str,
        now: float,
        window_sec: float,
    ) -> int:
        count = self._redis_zadd_now(redis_key, now, window_sec)
        if count is not None:
            return count
        hits = self._prune_ts(store.get(mem_key, []), window_sec, now)
        hits.append(now)
        store[mem_key] = hits
        return len(hits)

    def _count_member(
        self,
        store: Dict[str, Dict[str, float]],
        mem_key: str,
        redis_key: str,
        member: str,
        now: float,
        window_sec: float,
    ) -> int:
        count = self._redis_zadd_member(redis_key, member, now, window_sec)
        if count is not None:
            return count
        mapping = self._prune_dict(store.get(mem_key, {}), window_sec, now)
        mapping[member] = now
        store[mem_key] = mapping
        return len(mapping)

    def evaluate(self, log: RequestLog, anomaly_zscore: float = 0.0) -> List[Dict[str, Any]]:
        now = time.time()
        ip = log.client_ip
        scope_key = f"{log.upstream_id or 1}:{ip}"
        sub = log.user_sub or ip
        path = log.path
        reason = log.block_reason or ""
        triggered: List[Dict[str, Any]] = []

        # 1. JWT Tampering / alg=none / bad signature (API2 - Critical)
        if any(code in reason for code in ("jwt_alg_none", "jwt_bad_signature", "jwt_algorithm_confusion", "jwt_untrusted_kid")):
            triggered.append({
                "type": "jwt_tampering",
                "owasp_id": "API2",
                "severity": "critical",
                "title": f"Cryptographic JWT Tampering / Forgery Detected from {ip}",
                "description": f"Client submitted a forged or tampered JWT on '{log.method} {path}'. Gateway diagnostics: {reason}",
            })

        # 2. Expired or Revoked Token Reuse (API2 - Medium/High)
        if any(code in reason for code in ("jwt_revoked", "jwt_expired")):
            hits = self._count_event(
                self.revoked_token_hits, scope_key, f"sgw:behav:revoked:{scope_key}", now, 300
            )
            triggered.append({
                "type": "token_reuse",
                "owasp_id": "API2",
                "severity": "high" if "jwt_revoked" in reason else "medium",
                "title": f"Compromised / Expired JWT Reuse Attempt ({hits}x)",
                "description": f"Repeated attempts to authenticate with a revoked or expired token from {ip}. Reason: {reason}",
            })

        # 3. Brute Force Login & Credential Stuffing (API2 - High)
        if log.status_code == 401 or path.endswith("/auth/login") or "login" in path.lower():
            if log.status_code == 401 or "invalid" in reason.lower() or "brute" in reason.lower():
                fails = self._count_event(
                    self.login_failures, scope_key, f"sgw:behav:loginfail:{scope_key}", now, 60
                )

                if log.request_body_preview:
                    try:
                        body = json.loads(log.request_body_preview)
                        uname = str(body.get("username") or body.get("email") or body.get("user") or "")
                        if uname:
                            distinct = self._count_member(
                                self.login_usernames,
                                scope_key,
                                f"sgw:behav:loginusers:{scope_key}",
                                uname,
                                now,
                                300,
                            )
                            if distinct >= 5:
                                triggered.append({
                                    "type": "credential_stuffing",
                                    "owasp_id": "API2",
                                    "severity": "high",
                                    "title": f"Credential Stuffing Attack on {path} ({distinct} distinct accounts)",
                                    "description": f"Source IP {ip} attempted authentication against {distinct} distinct usernames within 5 minutes on {path}.",
                                })
                    except Exception:
                        pass

                if fails >= 5:
                    triggered.append({
                        "type": "brute_force_login",
                        "owasp_id": "API2",
                        "severity": "high",
                        "title": f"Brute-Force Authentication Attack on {path} ({fails} failed attempts/min)",
                        "description": f"Source IP {ip} triggered {fails} failed 401 authentication attempts on {log.method} {path} in under 60 seconds.",
                    })

        # 4. BOLA Object ID Enumeration & Ownership Violation (API1 - High)
        segments = [s for s in path.strip("/").split("/") if s]
        numeric_seg = next((s for s in segments if s.isdigit()), None)
        if log.owasp_id == "API1" or numeric_seg is not None:
            obj_id = numeric_seg or (segments[1] if len(segments) >= 2 else "id")
            resource_prefix = segments[0] if segments else "resource"
            key = f"{scope_key}:{resource_prefix}"
            distinct_ids = self._count_member(
                self.bola_object_ids, key, f"sgw:behav:bola:{key}", obj_id, now, 60
            )

            if distinct_ids >= 4 or log.owasp_id == "API1":
                triggered.append({
                    "type": "bola_enumeration",
                    "owasp_id": "API1",
                    "severity": "high",
                    "title": f"BOLA Object ID Enumeration / Unauthorized Access on {path}",
                    "description": f"Principal '{sub}' ({ip}) probed {distinct_ids} distinct object IDs on {path}. {reason}",
                })

        # 5. BFLA Privilege Escalation Probe (API5 - High)
        # Compare roles case-insensitively so JWT claims like "ADMIN" match gateway enforcement.
        caller_role = (log.user_role or "").strip().lower()
        non_admin_on_admin_path = path.startswith("/admin") and caller_role != "admin"
        if log.owasp_id == "API5" or non_admin_on_admin_path:
            probes = self._count_event(
                self.bfla_probes, scope_key, f"sgw:behav:bfla:{scope_key}", now, 300
            )
            triggered.append({
                "type": "bfla_privilege_probe",
                "owasp_id": "API5",
                "severity": "high",
                "title": f"BFLA Privilege Escalation Probe on Admin Endpoint ({path})",
                "description": (
                    f"Non-admin principal '{sub}' (role={log.user_role or 'none'}) "
                    f"attempted to invoke administrative function '{log.method} {path}' ({probes} attempts)."
                ),
            })

        # 6. SSRF Attempt (API7 - Critical)
        if log.owasp_id == "API7":
            triggered.append({
                "type": "ssrf_attempt",
                "owasp_id": "API7",
                "severity": "critical",
                "title": f"Server-Side Request Forgery (SSRF) Targeting Internal/Metadata Host",
                "description": f"Blocked SSRF payload from {ip} on '{log.method} {path}?{log.query_params}'. Details: {reason}",
            })

        # 7. SQLi / XSS / Path Traversal / Command Injection (API8 - High)
        if log.owasp_id == "API8" and any(k in reason for k in ("Injection", "traversal", "Scripting")):
            triggered.append({
                "type": "injection_signature",
                "owasp_id": "API8",
                "severity": "high",
                "title": f"Malicious Payload Signature Blocked ({reason.split('(')[0].strip()})",
                "description": f"Signature inspector blocked malicious payload on '{log.method} {path}' from {ip}. {reason}",
            })

        # 8. API3 Mass Assignment / Sensitive Property Redaction
        if log.owasp_id == "API3" and "Mass Assignment" in reason:
            triggered.append({
                "type": "mass_assignment",
                "owasp_id": "API3",
                "severity": "high",
                "title": f"Broken Object Property Level Authorization (Mass Assignment) Blocked",
                "description": f"Client {ip} attempted to overwrite restricted object properties in request body on '{log.method} {path}'. {reason}",
            })

        # 9. Sensitive Business Flow Abuse (API6 - High)
        if log.owasp_id == "API6":
            hits = self._count_event(
                self.sensitive_flow_hits, scope_key, f"sgw:behav:sensitive:{scope_key}", now, 60
            )
            if hits >= 5 or log.decision == "rate_limited":
                triggered.append({
                    "type": "sensitive_flow_abuse",
                    "owasp_id": "API6",
                    "severity": "high",
                    "title": f"Automated Bot Abuse on Sensitive Business Flow ({path})",
                    "description": f"High-velocity automated requests ({hits} req/min) detected from {ip} against sensitive business flow '{path}'.",
                })

        # 10. Rate Limit Abuse & Resource Exhaustion (API4 - Medium)
        if log.owasp_id == "API4":
            rl_hits = self._count_event(
                self.rate_limit_hits, scope_key, f"sgw:behav:rate:{scope_key}", now, 300
            )
            if rl_hits >= 3 or "pagination" in reason.lower() or "payload size" in reason.lower():
                triggered.append({
                    "type": "resource_exhaustion",
                    "owasp_id": "API4",
                    "severity": "medium",
                    "title": f"Unrestricted Resource Consumption / Rate Abuse ({path})",
                    "description": f"Client {ip} triggered resource consumption policy on '{log.method} {path}' ({rl_hits} events). {reason}",
                })

        # 11. Shadow API Endpoint Probing (API9 - Medium/High)
        if log.owasp_id == "API9":
            sh_hits = self._count_event(
                self.shadow_scan_hits, scope_key, f"sgw:behav:shadow:{scope_key}", now, 300
            )
            triggered.append({
                "type": "shadow_endpoint_scan",
                "owasp_id": "API9",
                "severity": "high" if sh_hits >= 3 else "medium",
                "title": f"Undocumented Shadow API Discovery / Reconnaissance ({path})",
                "description": f"Client {ip} probed undocumented endpoint '{log.method} {path}' ({sh_hits} shadow hits in window).",
            })

        # 12. Behavioral Anomaly Z-Score Spike (API4/API6 - Medium)
        if anomaly_zscore >= 3.5 and not triggered:
            triggered.append({
                "type": "behavioral_anomaly",
                "owasp_id": "API4",
                "severity": "medium",
                "title": f"Behavioral Traffic Velocity Anomaly (Z-Score = {anomaly_zscore})",
                "description": f"Client {ip} traffic rate deviated {anomaly_zscore} standard deviations above rolling historical baseline.",
            })

        return triggered


behavioral_tracker = BehavioralTracker()
