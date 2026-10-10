import json
import urllib.request
import urllib.parse
import sys

BASE_M3 = "http://127.0.0.1:8000"
BASE_M1 = "http://127.0.0.1:8001"

def http_req(url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    req_data = None
    if data is not None:
        req_data = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode("utf-8")
            return response.status, json.loads(res_body) if res_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        print(f"HTTP ERROR {e.code} on {method} {url}: {err_body}")
        raise

def main():
    print("=" * 60)
    print("STARTING COMPLETE E2E WORKFLOW INTEGRATION VERIFICATION")
    print("=" * 60)

    # 1. Login
    print("\n[Step 1] Testing POST /api/auth/login...")
    status, login_res = http_req(f"{BASE_M3}/api/auth/login", "POST", {"username": "rohan", "password": "Password123!"})
    assert status == 200, f"Login failed: {status}"
    token = login_res["token"]
    print(f"-> SUCCESS: Received token: {token[:20]}... for user {login_res['user']['name']}")

    # 2. Auth me
    print("\n[Step 2] Testing GET /api/auth/me with Bearer token...")
    status, me_res = http_req(f"{BASE_M3}/api/auth/me", "GET", headers={"Authorization": f"Bearer {token}"})
    assert status == 200
    print(f"-> SUCCESS: Authenticated user: {me_res.get('name', me_res.get('username'))} ({me_res['role']})")

    # 3. Get cases
    print("\n[Step 3] Testing GET /api/cases...")
    status, cases = http_req(f"{BASE_M3}/api/cases", "GET")
    assert status == 200 and len(cases) > 0, "No cases found"
    active_case = cases[0]
    case_id = active_case["case_id"]
    print(f"-> SUCCESS: Retrieved {len(cases)} case(s). Active case: {case_id} ({active_case['case_name']})")

    # 4. Get evidence
    print(f"\n[Step 4] Testing GET /api/cases/{case_id}/evidence...")
    status, evidence_list = http_req(f"{BASE_M3}/api/cases/{case_id}/evidence", "GET")
    assert status == 200 and len(evidence_list) > 0, "No evidence found"
    active_ev = evidence_list[0]
    ev_id = active_ev["evidence_id"]
    print(f"-> SUCCESS: Retrieved {len(evidence_list)} evidence items. First: {ev_id} ({active_ev['evidence_name']})")

    # 5. Get status of evidence
    print(f"\n[Step 5] Testing GET /api/evidence/{ev_id}/status...")
    status, ev_status = http_req(f"{BASE_M3}/api/evidence/{ev_id}/status", "GET")
    assert status == 200
    print(f"-> SUCCESS: Status={ev_status['status']}, Stage={ev_status['stage']}")

    # 6. Forensic tools status
    print("\n[Step 6] Testing Forensic Tools from M1 and M3...")
    status, m1_tools = http_req(f"{BASE_M1}/tools", "GET")
    assert status == 200
    tools_list = m1_tools.get("tools", [])
    print(f"-> SUCCESS: M1 reports {len(tools_list)} tools: {[t['name'] + ' (v' + str(t.get('version')) + ')' for t in tools_list]}")

    status, m3_tools = http_req(f"{BASE_M3}/api/system/tools", "GET")
    assert status == 200
    print(f"-> SUCCESS: M3 system tools bridge reports {len(m3_tools.get('tools', []))} tools")

    # 7. Get case artifacts
    print(f"\n[Step 7] Testing GET /api/cases/{case_id}/artifacts...")
    status, artifacts = http_req(f"{BASE_M3}/api/cases/{case_id}/artifacts", "GET")
    assert status == 200
    print(f"-> SUCCESS: Retrieved {len(artifacts)} parsed artifacts")

    # 8. Get timeline
    print(f"\n[Step 8] Testing GET /api/cases/{case_id}/timeline...")
    status, timeline = http_req(f"{BASE_M3}/api/cases/{case_id}/timeline", "GET")
    assert status == 200
    print(f"-> SUCCESS: Retrieved {len(timeline)} timeline events")

    # 9. Get findings
    print(f"\n[Step 9] Testing GET /api/cases/{case_id}/findings...")
    status, findings = http_req(f"{BASE_M3}/api/cases/{case_id}/findings", "GET")
    assert status == 200 and len(findings) > 0
    active_finding = findings[0]
    finding_id = active_finding["finding_id"]
    print(f"-> SUCCESS: Retrieved {len(findings)} findings. First: {finding_id} ({active_finding['finding_name']})")

    # 10. Get attack path
    print(f"\n[Step 10] Testing GET /api/cases/{case_id}/attack-path...")
    status, attack_path = http_req(f"{BASE_M3}/api/cases/{case_id}/attack-path", "GET")
    assert status == 200
    print(f"-> SUCCESS: Retrieved {len(attack_path.get('stages', []))} attack path stages")

    # 11. AI Assistant query
    print(f"\n[Step 11] Testing POST /api/cases/{case_id}/assistant/query...")
    status, ai_res = http_req(f"{BASE_M3}/api/cases/{case_id}/assistant/query", "POST", {
        "query": "What evidence indicates data exfiltration in this case?"
    })
    assert status == 200
    print(f"-> SUCCESS: AI response generated ({len(ai_res['answer'])} chars) with {len(ai_res['citations'])} verifiable citations")

    # 12. Validate finding
    print(f"\n[Step 12] Testing PATCH /api/findings/{finding_id}/validate...")
    status, val_res = http_req(f"{BASE_M3}/api/findings/{finding_id}/validate", "PATCH", {
        "status": "Accepted",
        "notes": "Verified by examiner - authoritative match to attacker PowerShell script"
    })
    assert status == 200 and val_res["validation_status"] == "Accepted"
    print(f"-> SUCCESS: Finding updated to {val_res['validation_status']} with notes: {val_res['examiner_notes']}")

    # 13. Generate report
    print(f"\n[Step 13] Testing POST /api/cases/{case_id}/reports/generate...")
    status, rep_res = http_req(f"{BASE_M3}/api/cases/{case_id}/reports/generate", "POST", {
        "report_title": "Forensic Investigation Dossier - E01 Analysis",
        "executive_summary": "Comprehensive investigation into advanced persistent threat activity."
    })
    assert status == 200
    report_id = rep_res["report_id"]
    ex_key = rep_res["examiner_key"]
    sup_key = rep_res["supervisor_key"]
    print(f"-> SUCCESS: Generated Encrypted Report ID: {report_id}")
    print(f"-> SHA256: {rep_res['sha256_hash']}")
    print(f"-> Two-Key Cryptography: Examiner Key={ex_key[:10]}..., Supervisor Key={sup_key[:10]}...")

    # 14. Decrypt report
    print(f"\n[Step 14] Testing GET /api/reports/{report_id}/decrypt...")
    status, dec_res = http_req(f"{BASE_M3}/api/reports/{report_id}/decrypt", "GET", headers={
        "X-Examiner-Key": ex_key,
        "X-Supervisor-Key": sup_key
    })
    assert status == 200 and dec_res["integrity_verified"] is True
    print(f"-> SUCCESS: Decryption verified! Integrity Verified={dec_res['integrity_verified']}")
    print(f"-> Dossier contains {len(dec_res['findings'])} accepted finding(s)")
    print(f"-> Decrypted content sample: {dec_res['decrypted_content'][:150]}...")

    print("\n" + "=" * 60)
    print("ALL 14 E2E WORKFLOW STEPS VERIFIED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == "__main__":
    main()
