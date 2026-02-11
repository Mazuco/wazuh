# app.py

from fastapi import FastAPI, Request, HTTPException
import requests
import json
import os
from datetime import datetime

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
# OPA listens on port 8181 by default. Refer to the OPA documentation for more information

app = FastAPI(title="Sample API")

LOG_DIR = "/var/log/sample-app"
LOG_FILE = f"{LOG_DIR}/app.log"

def to_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}

def app_log(message: str) -> None:
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.utcnow().isoformat()}Z {message}\n")
    except Exception:
        pass

def opa_query(policy: str, input_data: dict) -> dict:
    url = f"{OPA_URL}/v1/data/{policy}"
    payload = {"input": input_data}
    r = requests.post(url, json=payload, timeout=3)
    r.raise_for_status()
    return r.json()

def build_input(request: Request) -> dict:
    headers = request.headers

    user_name = headers.get("x-user", "unknown")
    user_role = headers.get("x-user-role", "guest")

    device_trusted = to_bool(headers.get("x-device-trusted", "false"))
    device_mfa = to_bool(headers.get("x-mfa", "false"))

    # Use X-Forwarded-For if present.
    xff = headers.get("x-forwarded-for")
    client_ip = xff.split(",")[0].strip() if xff else request.client.host

    return {
        "user": {"name": user_name, "role": user_role},
        "method": request.method,
        "path": request.url.path,
        "device": {"trusted": device_trusted, "mfa": device_mfa},
        "ip": client_ip
    }

def enforce(policy: str, request: Request) -> None:
    input_data = build_input(request)
    resp = opa_query(policy, input_data)
    decision = resp.get("result", {}).get("decision", {})

    allow = decision.get("allow", False)
    reason = decision.get("reason", "unknown")
    risk = decision.get("risk", "unknown")

    app_log(f"policy={policy} allow={allow} reason={reason} risk={risk} input={json.dumps(input_data)}")

    if not allow:
        raise HTTPException(status_code=403, detail={"reason": reason, "risk": risk})

@app.get("/admin/settings")
async def admin_settings(request: Request):
    enforce("admin_access", request)
    return {"status": "ok", "message": "Admin settings accessed."}

@app.delete("/records/{record_id}")
async def delete_record(record_id: int, request: Request):
    enforce("api_access", request)
    return {"status": "ok", "record_id": record_id, "message": "Record deleted."}

@app.get("/sensitive/records/{record_id}")
async def sensitive_record(record_id: int, request: Request):
    enforce("api_access", request)
    return {"status": "ok", "record_id": record_id, "message": "Sensitive record accessed."}

@app.get("/portal")
async def portal(request: Request):
    enforce("device_access", request)
    return {"status": "ok", "message": "Portal access granted."}

@app.get("/internal")
async def internal(request: Request):
    enforce("ip_allowlist", request)
    return {"status": "ok", "message": "Internal access granted."}
