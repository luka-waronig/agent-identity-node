import json
import os
import urllib.request


BASE_URL = os.environ.get("AGENT_NODE_URL", "http://127.0.0.1:8787")
TOKEN = os.environ["AGENT_NODE_TOKEN"]


def request(path, method="GET", payload=None):
    body = None
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=body,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


print(json.dumps(request("/manifest"), indent=2))

auth_request = request(
    "/auth/request-code",
    "POST",
    {
        "subject": "python-agent",
        "requested_scopes": ["manifest:read", "tool:scan_vault"],
    },
)
grant = request(
    "/auth/grants",
    "POST",
    {
        "request_id": auth_request["request"]["request_id"],
        "subject": "python-agent",
        "scopes": ["manifest:read", "tool:scan_vault"],
        "ttl_seconds": 600,
    },
)

TOKEN = grant["authorization_header"].replace("AIN-Grant ", "")

def grant_request(path, method="GET", payload=None):
    body = None
    headers = {"Authorization": f"AIN-Grant {TOKEN}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=body,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


print(json.dumps(grant_request("/execute", "POST", {"tool_name": "SCAN_VAULT", "payload": ""}), indent=2))
