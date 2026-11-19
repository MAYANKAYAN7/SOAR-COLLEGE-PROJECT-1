"""
Master Security Test Runner for SOAR Incident Containment Platform.
Executes all non-destructive reconnaissance and vulnerability verification modules.
"""
import subprocess
import sys
import os

TESTS = [
    ("01_recon_endpoints.py", "Route & API Surface Reconnaissance"),
    ("02_test_security_headers.py", "OWASP Security Response Headers Audit"),
    ("03_test_input_validation.py", "Injection & Boundary Input Validation"),
    ("04_test_auth_and_hashing.py", "Authentication & Cryptographic Hashing Check"),
    ("05_test_soar_playbooks.py", "SOAR Automated Incident Playbook Pipeline"),
    ("06_pip_audit.py", "Python Dependency Vulnerability Audit (PyPA/OSV)")
]

def main():
    print("=" * 80)
    print("  SOAR PLATFORM LOCAL SECURITY ASSESSMENT SUITE")
    print("=" * 80)
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    passed = 0

    for script_name, description in TESTS:
        script_path = os.path.join(script_dir, script_name)
        print(f"\n[RUNNING] {description} ({script_name})...")
        print("-" * 80)
        res = subprocess.run([sys.executable, script_path])
        if res.returncode == 0:
            passed += 1
            print(f"[OK] {script_name} completed cleanly.")
        else:
            print(f"[FAIL] {script_name} returned exit code {res.returncode}")

    print("\n" + "=" * 80)
    print(f"  SUMMARY: {passed}/{len(TESTS)} Security Audit Modules Executed Successfully")
    print("=" * 80)

if __name__ == "__main__":
    main()
