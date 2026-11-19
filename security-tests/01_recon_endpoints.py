"""
Reconnaissance & Route Mapping Script for SOAR Platform
Audits all registered endpoints, HTTP methods, and parameter schemas.
"""
import urllib.request
import json

BASE_URL = "http://localhost:8000"

def run_recon():
    print(f"[*] Probing SOAR OpenAPI documentation at {BASE_URL}/openapi.json ...")
    try:
        req = urllib.request.Request(f"{BASE_URL}/openapi.json", headers={"User-Agent": "SOAR-Security-Auditor/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            spec = json.loads(resp.read().decode())
            print(f"[+] Application Title: {spec.get('info', {}).get('title')}")
            print(f"[+] Version: {spec.get('info', {}).get('version', '1.0.0')}")
            
            paths = spec.get("paths", {})
            print(f"\n[+] Total Endpoints Discovered: {len(paths)}")
            print("-" * 75)
            print(f"{'Method':<8} | {'Route':<32} | {'Tags / Summary'}")
            print("-" * 75)
            for path, methods in sorted(paths.items()):
                for method, details in methods.items():
                    tags = ", ".join(details.get("tags", []))
                    summary = details.get("summary", "")
                    print(f"{method.upper():<8} | {path:<32} | {tags}: {summary}")
            print("-" * 75)
            return True
    except Exception as e:
        print(f"[-] Recon failed: {e}")
        return False

if __name__ == "__main__":
    run_recon()
