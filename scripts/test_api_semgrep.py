"""Test API scan with Semgrep engine."""
import time
import requests

url = "http://localhost:8000/api/v1/scan"
payload = {
    "path": "examples/vulnerable_rce.py",
    "config": {
        "enable_ai_verification": False,
        "scan_engine": "semgrep",
    },
}

resp = requests.post(url, json=payload)
data = resp.json()
scan_id = data["scan_id"]
print(f"Scan submitted: ID={scan_id}, status={data['status']}")

# Poll
for _ in range(30):
    time.sleep(1)
    status_resp = requests.get(f"http://localhost:8000/api/v1/scan/{scan_id}/status")
    status_data = status_resp.json()
    print(f"Status: {status_data['status']}")
    if status_data["status"] in ["completed", "failed"]:
        break

if status_data["status"] == "completed":
    results_resp = requests.get(f"http://localhost:8000/api/v1/scan/{scan_id}/results")
    results = results_resp.json()
    findings = results.get("findings", [])
    print(f"\nScan completed with {len(findings)} findings!")
    for f in findings[:5]:
        ev = f.get("evidence", {})
        src = ev.get("source", {}).get("snippet", "")
        sink = ev.get("sink", {}).get("snippet", "")
        steps = ev.get("intermediate_steps", [])
        print(f"  [{f.get('severity')}] {f.get('rule_id')} (status: {f.get('triage_status')})")
        print(f"    Source: {src[:50]}")
        print(f"    Flow steps: {len(steps)}")
        print(f"    Sink: {sink[:50]}")
else:
    print(f"Scan ended with error: {status_data.get('error')}")
