"""
HTTP Security Headers Audit Script
Checks for OWASP-recommended security response headers on web responses.
"""
import urllib.request

BASE_URL = "http://localhost:8000"

RECOMMENDED_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def check_headers():
    print(f"[*] Auditing HTTP Security Headers on {BASE_URL}/ ...")
    try:
        req = urllib.request.Request(BASE_URL, headers={"User-Agent": "SOAR-Header-Auditor/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = dict(resp.headers)
            print("-" * 65)
            print(f"{'Security Header':<28} | {'Status':<10} | {'Value'}")
            print("-" * 65)
            for h in RECOMMENDED_HEADERS:
                val = headers.get(h) or headers.get(h.lower())
                if val:
                    print(f"{h:<28} | PASS       | {val}")
                else:
                    print(f"{h:<28} | MISSING    | -")
            print("-" * 65)
    except Exception as e:
        print(f"[-] Header check failed: {e}")

if __name__ == "__main__":
    check_headers()
