"""
SOAR Playbook & Automated Containment Verification Script
Verifies playbook trigger rules, incident case creation, and audit logging.
"""
import urllib.request
import urllib.error
import json

BASE_URL = "http://localhost:8000"

def test_soar_pipeline():
    print("[*] Testing SOAR Playbook Execution Pipeline...")
    
    # Send a Critical simulation alert (IP octet > 160 triggers Critical risk & Wazuh EDR host isolation)
    payload = json.dumps({
        "source_ip": "198.51.100.185",
        "alert_type": "Critical Ransomware Outbreak Test",
        "timestamp": "2026-11-18T22:30:00Z"
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}/alert",
        data=payload,
        headers={"Content-Type": "application/json"}
    )

    try:
        # 1. Obtain Bearer JWT token via /auth/login
        login_payload = json.dumps({"username": "admin", "password": "admin123"}).encode()
        login_req = urllib.request.Request(
            f"{BASE_URL}/auth/login",
            data=login_payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(login_req, timeout=5) as lresp:
            token = json.loads(lresp.read().decode()).get("token")
            print(f"[+] Authenticated successfully as Admin (JWT: {token[:24]}...)")

        # 2. Verify that unauthenticated requests to /timeline are REJECTED
        unauth_req = urllib.request.Request(f"{BASE_URL}/timeline/1")
        try:
            with urllib.request.urlopen(unauth_req, timeout=5) as u_resp:
                print("[FAIL] Unauthenticated access to /timeline allowed!")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print("[PASS] Unauthenticated access to /timeline properly rejected with HTTP 401")

        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            print(f"[+] Alert Processed: Alert #{data.get('alert_id')} for {data.get('source_ip')}")
            print(f"[+] Risk Assessed: {data.get('risk')}")
            print(f"[+] Playbook Actions Executed: {list(data.get('playbook_actions', {}).keys())}")
            
            case_id = data.get("case_id")
            if case_id:
                print(f"[PASS] Automated Incident Case #{case_id} generated successfully.")
                
                # 3. Verify Timeline Audit Trail with valid JWT Bearer token
                tl_req = urllib.request.Request(
                    f"{BASE_URL}/timeline/{case_id}",
                    headers={"Authorization": f"Bearer {token}"}
                )
                with urllib.request.urlopen(tl_req, timeout=5) as tl_resp:
                    tl_data = json.loads(tl_resp.read().decode())
                    events = tl_data.get("timeline", [])
                    print(f"[PASS] Forensic Timeline for Case #{case_id} contains {len(events)} logged events.")
                    for ev in events:
                        print(f"       - [{ev.get('timestamp', 'N/A')}] {ev.get('action')} ({ev.get('performed_by')})")
            else:
                print("[INFO] No incident case generated for this severity level.")
    except Exception as e:
        print(f"[-] SOAR pipeline test failed: {e}")

if __name__ == "__main__":
    test_soar_pipeline()
