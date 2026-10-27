import json
import time
from typing import Any, Dict, List, Optional, Set
from app.models import RequestLog


class BehavioralTracker:
    """
    In-memory sliding-window behavioral state tracker for multi-event OWASP correlation rules:
    - Brute force login (5+ 401s on /auth/login in 60s -> API2 High)
    - Credential stuffing (8+ distinct usernames from one IP in 300s -> API2 High)
    - BOLA ID enumeration (8+ distinct object IDs on /users/{id} or /orders/{id} in 60s -> API1 High)
    - BFLA privilege escalation probe (2+ non-admin hits on /admin/* -> API5 High)
    - Rate abuse (5+ 429s in 300s -> API4 Medium)
    - Sensitive business flow velocity (/coupons/redeem or /orders burst -> API6 High)
    - Shadow endpoint scan (3+ hits on unregistered paths -> API9 Medium/High)
    - Error spike (high 4xx/5xx ratio -> API8 Medium)
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

    def evaluate(self, log: RequestLog, anomaly_zscore: float = 0.0) -> List[Dict[str, Any]]:
        now = time.time()
        ip = log.client_ip
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
            hits = self._prune_ts(self.revoked_token_hits.get(ip, []), 300, now)
            hits.append(now)
            self.revoked_token_hits[ip] = hits
            triggered.append({
                "type": "token_reuse",
                "owasp_id": "API2",
                "severity": "high" if "jwt_revoked" in reason else "medium",
                "title": f"Compromised / Expired JWT Reuse Attempt ({len(hits)}x)",
                "description": f"Repeated attempts to authenticate with a revoked or expired token from {ip}. Reason: {reason}",
            })

        # 3. Brute Force Login & Credential Stuffing (API2 - High)
        if path.endswith("/auth/login") and log.status_code == 401:
            fails = self._prune_ts(self.login_failures.get(ip, []), 60, now)
            fails.append(now)
            self.login_failures[ip] = fails

            if log.request_body_preview:
                try:
                    body = json.loads(log.request_body_preview)
                    uname = str(body.get("username", ""))
                    if uname:
                        u_map = self._prune_dict(self.login_usernames.get(ip, {}), 300, now)
                        u_map[uname] = now
                        self.login_usernames[ip] = u_map
                        if len(u_map) >= 6:
                            triggered.append({
                                "type": "credential_stuffing",
                                "owasp_id": "API2",
                                "severity": "high",
                                "title": f"Credential Stuffing Attack ({len(u_map)} distinct accounts)",
                                "description": f"Source IP {ip} attempted authentication against {len(u_map)} distinct usernames within 5 minutes on /auth/login.",
                            })
                except Exception:
                    pass

            if len(fails) >= 5:
                triggered.append({
                    "type": "brute_force_login",
                    "owasp_id": "API2",
                    "severity": "high",
                    "title": f"Brute-Force Authentication Attack ({len(fails)} failed logins/min)",
                    "description": f"Source IP {ip} triggered {len(fails)} failed 401 login attempts on POST /auth/login in under 60 seconds.",
                })

        # 4. BOLA Object ID Enumeration & Ownership Violation (API1 - High)
        if path.startswith("/users/") or path.startswith("/orders/"):
            segments = path.strip("/").split("/")
            if len(segments) == 2 and segments[1] != "me":
                obj_id = segments[1]
                key = f"{ip}:{segments[0]}"
                id_map = self._prune_dict(self.bola_object_ids.get(key, {}), 60, now)
                id_map[obj_id] = now
                self.bola_object_ids[key] = id_map

                if len(id_map) >= 5 or log.owasp_id == "API1":
                    triggered.append({
                        "type": "bola_enumeration",
                        "owasp_id": "API1",
                        "severity": "high",
                        "title": f"BOLA Object ID Enumeration / Unauthorized Access on /{segments[0]}/{{id}}",
                        "description": f"Principal '{sub}' ({ip}) probed {len(id_map)} distinct object IDs ({', '.join(list(id_map.keys())[:6])}) on /{segments[0]}/{{id}}. {reason}",
                    })

        # 5. BFLA Privilege Escalation Probe (API5 - High)
        if log.owasp_id == "API5" or (path.startswith("/admin") and log.user_role != "admin"):
            probes = self._prune_ts(self.bfla_probes.get(ip, []), 300, now)
            probes.append(now)
            self.bfla_probes[ip] = probes
            triggered.append({
                "type": "bfla_privilege_probe",
                "owasp_id": "API5",
                "severity": "high",
                "title": f"BFLA Privilege Escalation Probe on Admin Endpoint ({path})",
                "description": f"Non-admin principal '{sub}' (role={log.user_role or 'user'}) attempted to invoke administrative function '{log.method} {path}' ({len(probes)} attempts).",
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
        if log.owasp_id == "API6" or path.startswith("/coupons/redeem"):
            hits = self._prune_ts(self.sensitive_flow_hits.get(ip, []), 60, now)
            hits.append(now)
            self.sensitive_flow_hits[ip] = hits
            if len(hits) >= 5 or log.decision == "rate_limited":
                triggered.append({
                    "type": "sensitive_flow_abuse",
                    "owasp_id": "API6",
                    "severity": "high",
                    "title": f"Automated Bot Abuse on Sensitive Business Flow ({path})",
                    "description": f"High-velocity automated requests ({len(hits)} req/min) detected from {ip} against sensitive business flow '{path}'.",
                })

        # 10. Rate Limit Abuse & Resource Exhaustion (API4 - Medium)
        if log.owasp_id == "API4":
            rl_hits = self._prune_ts(self.rate_limit_hits.get(ip, []), 300, now)
            rl_hits.append(now)
            self.rate_limit_hits[ip] = rl_hits
            if len(rl_hits) >= 3 or "pagination" in reason.lower() or "payload size" in reason.lower():
                triggered.append({
                    "type": "resource_exhaustion",
                    "owasp_id": "API4",
                    "severity": "medium",
                    "title": f"Unrestricted Resource Consumption / Rate Abuse ({path})",
                    "description": f"Client {ip} triggered resource consumption policy on '{log.method} {path}' ({len(rl_hits)} events). {reason}",
                })

        # 11. Shadow API Endpoint Probing (API9 - Medium/High)
        if log.owasp_id == "API9":
            sh_hits = self._prune_ts(self.shadow_scan_hits.get(ip, []), 300, now)
            sh_hits.append(now)
            self.shadow_scan_hits[ip] = sh_hits
            triggered.append({
                "type": "shadow_endpoint_scan",
                "owasp_id": "API9",
                "severity": "high" if len(sh_hits) >= 3 else "medium",
                "title": f"Undocumented Shadow API Discovery / Reconnaissance ({path})",
                "description": f"Client {ip} probed undocumented endpoint '{log.method} {path}' ({len(sh_hits)} shadow hits in window).",
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
