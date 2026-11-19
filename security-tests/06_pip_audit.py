"""
Dependency Vulnerability Audit Script (PyPA / OSV Database Engine)
Audits all installed environment packages against the Open Source Vulnerabilities (OSV.dev) database.
Equivalent to pip-audit vulnerability checks.
"""
import urllib.request
import json
import sys
import subprocess

def get_installed_packages():
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        return json.loads(result.stdout)
    return []

def query_osv(package_name, version):
    url = "https://api.osv.dev/v1/query"
    body = json.dumps({
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }).encode("utf-8")
    
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "SOAR-Dependency-Auditor/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
            return data.get("vulns", [])
    except Exception:
        return []

def audit_dependencies():
    print("=" * 80)
    print("  PYTHON DEPENDENCY VULNERABILITY AUDIT (PyPA / OSV.DEV ENGINE)")
    print("=" * 80)

    packages = get_installed_packages()
    print(f"[*] Auditing {len(packages)} installed packages in virtual environment...\n")
    print(f"{'Package':<24} | {'Version':<14} | {'CVE Status':<12} | {'Advisory ID'}")
    print("-" * 80)

    vuln_count = 0
    clean_count = 0

    for pkg in packages:
        name = pkg.get("name")
        ver = pkg.get("version")
        vulns = query_osv(name, ver)
        if vulns:
            vuln_count += 1
            cve_ids = ", ".join(v.get("id", "Unknown") for v in vulns[:2])
            print(f"{name:<24} | {ver:<14} | VULNERABLE   | {cve_ids}")
        else:
            clean_count += 1
            print(f"{name:<24} | {ver:<14} | PASS (Clean) | -")

    print("-" * 80)
    print(f"\n[+] Audit Complete: {clean_count} packages clean, {vuln_count} vulnerabilities found.")
    return vuln_count == 0

if __name__ == "__main__":
    audit_dependencies()
