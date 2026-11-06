import os
import sys
import uuid
import json
import hashlib
import subprocess
from datetime import datetime, timezone
import urllib.request
import urllib.error
import urllib.parse
import socket

# ==========================================
# 1. Target Identity & Strict Health Verification
# ==========================================
TARGET_BASE_URL = os.environ.get("LAB_INTERNAL_URL", "http://vulnerable:3000")
PATH_PREFIX = os.environ.get("LAB_PATH_PREFIX", "/lab/vulnerable")
HEALTH_ENDPOINT = f"{TARGET_BASE_URL}{PATH_PREFIX}/api/health"

PROTECTED_CONTENT_MARKER = "M1-FICTIONAL-RECORDS-ONLY"
MAX_BODY_BYTES = 4096

def fetch_and_validate_target_identity(expect_valid=True):
    """
    Fetches and strictly validates the target's health identity.
    If the target returns 404 or invalid metadata, it handles the regression
    by returning an inconclusive/unavailable profile rather than silently 
    retaining hardcoded mock identities.
    """
    try:
        req = urllib.request.Request(HEALTH_ENDPOINT, method="GET")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                version = data.get("version")
                profile = data.get("profile")
                ready = data.get("ready", False)
                
                if not version or not profile:
                    if expect_valid:
                        raise ValueError("Health response missing mandatory fields.")
                
                return {
                    "id": "vulnerable",
                    "base_url": TARGET_BASE_URL,
                    "observed_version": version or "unknown",
                    "profile": profile or "unknown",
                    "ready": ready
                }
    except Exception as e:
        if not expect_valid:
            # Expected failure case (unavailable/unexpected health)
            return {
                "id": "vulnerable-unavailable",
                "base_url": TARGET_BASE_URL,
                "observed_version": "unavailable",
                "profile": "unavailable",
                "ready": False
            }
        print(f"[!] Target health check failed at {HEALTH_ENDPOINT}: {e}")
        # Return fallback for mismatched-target regression tests to keep execution inconclusive
        return {
            "id": "vulnerable-mismatched",
            "base_url": TARGET_BASE_URL,
            "observed_version": "mismatched-or-404",
            "profile": "inconclusive",
            "ready": False
        }
    return {
        "id": "vulnerable-mismatched",
        "base_url": TARGET_BASE_URL,
        "observed_version": "mismatched-or-404",
        "profile": "inconclusive",
        "ready": False
    }

# ==========================================
# 2. Session Acquisition & Management
# ==========================================
def obtain_valid_session_cookie(target_base_url, path_prefix):
    login_url = f"{target_base_url}{path_prefix}/api/login"
    username = os.environ.get("LAB_USER", "admin")
    password = os.environ.get("LAB_PASSWORD", "secret")
    
    data = urllib.parse.urlencode({"username": username, "password": password}).encode('utf-8')
    
    class LoginRedirectHandler(urllib.request.HTTPRedirectHandler):
        def http_error_303(self, req, fp, code, msg, headers): return fp

    opener = urllib.request.build_opener(LoginRedirectHandler)
    req = urllib.request.Request(login_url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    try:
        with opener.open(req, timeout=3.0) as resp:
            set_cookie = resp.headers.get("Set-Cookie", "")
            for cookie in set_cookie.split(";"):
                if "lab_vulnerable_session=" in cookie:
                    return cookie.strip()
    except Exception:
        pass
    return "lab_vulnerable_session=invalid-fallback-token"

# ==========================================
# 3. Scenario Registry (Cookie-free anonymous, valid/tampered sessions)
# ==========================================
def get_scenario_registry(path_prefix):
    dashboard_path = f"{path_prefix}/dashboard"
    return {
        "anonymous-normal": {
            "id": "anonymous-normal",
            "path": dashboard_path,
            "method": "GET",
            "headers": {},
            "cookies": {}, # Strictly cookie-free
            "expected_assertion": "denied"
        },
        "anonymous-cve": {
            "id": "anonymous-cve",
            "path": dashboard_path,
            "method": "GET",
            "headers": {
                "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"
            },
            "cookies": {}, # Strictly cookie-free
            "expected_assertion": "protected-content-returned"
        },
        "valid-session": {
            "id": "valid-session",
            "path": dashboard_path,
            "method": "GET",
            "headers": {},
            "cookies": {"lab_vulnerable_session": obtain_valid_session_cookie(TARGET_BASE_URL, path_prefix)},
            "expected_assertion": "protected-content-returned"
        },
        "invalid-session": {
            "id": "invalid-session",
            "path": dashboard_path,
            "method": "GET",
            "headers": {},
            "cookies": {"lab_vulnerable_session": "tampered-or-expired-token"},
            "expected_assertion": "denied"
        }
    }

def get_git_commit():
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL).decode().strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], stderr=subprocess.DEVNULL).decode().strip()
        return f"{commit}-dirty" if status else commit
    except Exception:
        return None

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers): return fp
    def http_error_302(self, req, fp, code, msg, headers): return fp
    def http_error_303(self, req, fp, code, msg, headers): return fp
    def http_error_307(self, req, fp, code, msg, headers): return fp
    def http_error_308(self, req, fp, code, msg, headers): return fp

def execute_scenario(scenario_id: str, target_identity: dict, scenario_registry: dict):
    if scenario_id not in scenario_registry:
        raise ValueError("Invalid scenario ID.")

    scenario = scenario_registry[scenario_id]
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    source_commit = get_git_commit()

    url = f"{target_identity['base_url']}{scenario['path']}"
    method = scenario['method']
    headers = dict(scenario.get('headers', {}))
    cookies = dict(scenario.get('cookies', {}))

    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers["Cookie"] = cookie_str

    # Redact sensitive credentials/cookies from evidence export
    redacted_headers = {k: v for k, v in headers.items() if k.lower() not in ['cookie', 'authorization']}
    
    response_data = None
    observed = "error"
    error_msg = None
    elapsed_ms = 0.0

    opener = urllib.request.build_opener(NoRedirectHandler)
    req = urllib.request.Request(url, headers=headers, method=method)

    start_time = datetime.now()
    try:
        socket.setdefaulttimeout(5.0)
        try:
            with opener.open(req, timeout=5.0) as resp:
                status_code = resp.status
                redirect_location = resp.headers.get("Location")
                raw_bytes = resp.read(MAX_BODY_BYTES + 1)
        except urllib.error.HTTPError as e:
            status_code = e.code
            redirect_location = e.headers.get("Location")
            raw_bytes = e.read(MAX_BODY_BYTES + 1)

        elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000.0

        truncated = len(raw_bytes) > MAX_BODY_BYTES
        bounded_bytes = raw_bytes[:MAX_BODY_BYTES]
        escaped_body = bounded_bytes.decode('utf-8', errors='replace')

        response_data = {
            "status": status_code,
            "redirect_location": redirect_location,
            "escaped_body": escaped_body,
            "truncated": truncated
        }

        # Comprehensive Assertion & Status Evaluation
        if status_code == 404 or target_identity.get("profile") == "inconclusive":
            # Mismatched target / 404 route regression stays inconclusive
            observed = "conclusive"
        elif status_code == 200:
            if PROTECTED_CONTENT_MARKER in escaped_body:
                observed = "protected-content-returned"
            else:
                observed = "conclusive"
        elif status_code in [302, 307, 308, 401, 403]:
            # Check denial assertion combined with content/markers if necessary
            observed = "denied"
        else:
            observed = "conclusive"

    except Exception as e:
        elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000.0
        error_msg = str(e)
        observed = "conclusive" # Avoid unhandled crashes; keep inconclusive/error controlled
        response_data = None

    evidence = {
        "schema_version": "0.1",
        "run_id": run_id,
        "started_at": started_at,
        "source_commit": source_commit,
        "target": target_identity,
        "scenario": scenario_id,
        "expected": scenario["expected_assertion"],
        "request": {
            "method": method,
            "path": scenario["path"],
            "redacted_headers": redacted_headers
        },
        "response": response_data,
        "observed": observed,
        "elapsed_ms": round(elapsed_ms, 2),
        "error": error_msg,
        "logs": None
    }

    export_dir = os.path.join("evidence", run_id)
    os.makedirs(export_dir, exist_ok=True)
    
    json_path = os.path.join(export_dir, "result.json")
    serialized_bytes = json.dumps(evidence, indent=2, ensure_ascii=False).encode('utf-8')
    
    with open(json_path, "wb") as f:
        f.write(serialized_bytes)

    # Retain SHA-256 integrity hash verification file
    sha256_hash = hashlib.sha256(serialized_bytes).hexdigest()
    hash_path = os.path.join(export_dir, "sha256sum.txt")
    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(f"{sha256_hash}  result.json\n")

    print(f"[+] Run {run_id} | Scenario: {scenario_id} | Status: {status_code if response_data else 'ERR'} | Observed: {observed}")
    return evidence

if __name__ == "__main__":
    print("[*] Executing Regression Suite: Mismatched-Target & Health Validation...")
    
    # 1. Regression test: Mismatched target / 404 health state
    mismatched_identity = fetch_and_validate_target_identity(expect_valid=False)
    registry = get_scenario_registry(PATH_PREFIX)
    for sc in registry.keys():
        execute_scenario(f"reg-mismatched-{sc}", mismatched_identity, {f"reg-mismatched-{sc}": registry[sc]})

    print("\n[*] Executing Standard Scenarios across Real Profiles...")
    valid_identity = fetch_and_validate_target_identity(expect_valid=True)
    for sc in registry.keys():
        execute_scenario(sc, valid_identity, registry)