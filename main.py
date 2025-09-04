from mitre import run_mitre_checks
from iso import run_iso_checks
from password_mfa import run_password_mfa_checks


def run_checks():
    print("Running MITRE ATT&CK checks...")
    run_mitre_checks()

    print("Running ISO 27001/27002 validation...")
    run_iso_checks()

    print("Checking password policies & MFA...")
    run_password_mfa_checks()

    print("All checks complete. Reports saved in ./reports")

if __name__ == "__main__":
    run_checks()