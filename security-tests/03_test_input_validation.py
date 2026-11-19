"""
Input Validation & Injection Resistance Audit Script
Verifies that invalid IPs, boundary payloads, and malformed alert data are properly rejected.
"""
import urllib.request
import urllib.error
import json

BASE_URL = "http://localhost:8000"

def test_ip_validation():
    print("[*] Testing IP validation on POST /alert ...")
    test_cases = [
        {"ip": "8.8.8.8", "valid": True, "description": "Standard Valid IPv4"},
        {"ip": "2001:4860:4860::8888", "valid": True, "description": "Standard Valid IPv6"},
        {"ip": "999.999.999.999", "valid": False, "description": "Out-of-range Octets"},
        {"ip": "127.0.0.1; echo injected", "valid": False, "description": "Command Delimiter in IP field"},
        {"ip": "<script>alert(1)</script>", "valid": False, "description": "XSS Script Tag in IP field"},
        {"ip": "../../etc/passwd", "valid": False, "description": "Directory Traversal in IP field"},
        {"ip": "", "valid": False, "description": "Empty IP string"}
    ]

    for tc in test_cases:
        payload = json.dumps({
            "source_ip": tc["ip"],
            "alert_type": "Security Assessment Probe",
            "timestamp": "2026-11-18T22:00:00Z"
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{BASE_URL}/alert",
            data=payload,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
                if tc["valid"]:
                    print(f"[PASS] {tc['description']:<36} -> Accepted (HTTP {status})")
                else:
                    print(f"[FAIL] {tc['description']:<36} -> Accepted invalid IP (HTTP {status})")
        except urllib.error.HTTPError as e:
            if not tc["valid"] and e.code in (400, 422):
                print(f"[PASS] {tc['description']:<36} -> Correctly Rejected (HTTP {e.code})")
            else:
                print(f"[INFO] {tc['description']:<36} -> Returned HTTP {e.code}")
        except Exception as e:
            print(f"[-] Request error for {tc['description']}: {e}")

if __name__ == "__main__":
    test_ip_validation()
