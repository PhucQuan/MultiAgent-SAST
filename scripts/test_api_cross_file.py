"""Test REST API on cross-file RCE project."""
import time
import requests

resp = requests.post(
    "http://localhost:8000/api/v1/scan",
    json={
        "path": "examples/cross_file_rce",
        "config": {
            "enable_ai_verification": False,
            "scan_engine": "semgrep",
        },
    },
)
scan_id = resp.json()["scan_id"]
print("Scan ID:", scan_id)

for _ in range(40):
    time.sleep(1)
    s = requests.get(f"http://localhost:8000/api/v1/scan/{scan_id}/status").json()
    if s["status"] in ["completed", "failed"]:
        break

print("Final status:", s["status"])
if s["status"] == "completed":
    res = requests.get(f"http://localhost:8000/api/v1/scan/{scan_id}/results").json()
    findings = res.get("findings", [])
    print(f"\nAPI returned {len(findings)} findings:")
    for f in findings:
        sev = f.get("severity")
        vtype = f.get("type")
        rule = f.get("rule_id")
        file_ = f.get("file")
        line = f.get("line")
        print(f"  [{sev}] {vtype} ({rule}) in {file_}:{line}")
        print(f"    Msg: {f.get('message')}")
        ev = f.get("evidence", {})
        src = ev.get("source", {})
        sink = ev.get("sink", {})
        steps = ev.get("intermediate_steps", [])
        print(f"    Path ({len(steps) + 2} steps):")
        print(f"      Source: {src.get('file')}:{src.get('line')} -> {src.get('snippet')}")
        for st in steps:
            print(f"      Step:   {st.get('file')}:{st.get('line')} -> {st.get('snippet')}")
        print(f"      Sink:   {sink.get('file')}:{sink.get('line')} -> {sink.get('snippet')}")
else:
    print("Error:", s.get("error"))
