**Access Control Compliance Dashboard**
A Python-powered dashboard to map MITRE ATT&CK techniques to NIST 800-53 and other compliance frameworks for faster audits and better visibility into security posture.

🔍 Why This Project?

Compliance audits are time-consuming and complex. Security teams often struggle to align real-world adversary behaviors (MITRE ATT&CK) with compliance requirements (NIST, ISO).
This tool bridges that gap by automating the mapping and giving security professionals a dashboard to see:

1. Which ATT&CK techniques they detect
2. Which NIST controls those techniques map to
3. Where compliance gaps exist

⚡ Features

✅ Pulls live MITRE ATT&CK framework data

✅ Maps ATT&CK techniques to NIST 800-53 Rev 5 (via official crosswalk)

✅ Exports results to CSV/Excel for audit use

✅ Interactive dashboard for filtering by Technique, Control, or Framework

✅ Modular design to extend mappings (ISO 27001, CIS, etc.)

🚀 Getting Started
1. Pull the repository 
```
git clone https://github.com/Mdot0/access-control-compliance-dashboard.git
cd access-control-compliance-dashboard
```
2. Create Virtual Environment
```
python -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows
```
3. Install Dependencies
```
pip install -r requirements.txt
```
4. Running the Dashboard
```
python main.py
```
