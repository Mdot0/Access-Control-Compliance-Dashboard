nist_mapping = {
    # Techniques
    "T1078": ["IA-2", "IA-5", "PL-8", "RA-5"],  # Valid Accounts
    "T1078.001": ["IA-2", "IA-5", "PL-8", "RA-5"],  # Default Accounts
    "T1078.002": ["IA-2", "IA-5", "PL-8", "RA-5"],  # Domain Accounts
    "T1078.003": ["IA-2", "IA-5", "PL-8", "RA-5"],  # Local Accounts
    "T1078.004": ["IA-2", "IA-5", "PL-8", "RA-5"],  # Cloud Accounts
    "T1059": ["SI-4", "SI-7", "SC-18"],  # Command and Scripting Interpreter
    "T1059.001": ["SI-4", "SI-7", "SC-18"],  # PowerShell
    "T1059.002": ["SI-4", "SI-7", "SC-18"],  # Command Prompt
    "T1059.003": ["SI-4", "SI-7", "SC-18"],  # AppleScript
    "T1059.004": ["SI-4", "SI-7", "SC-18"],  # Unix Shell
    "T1059.005": ["SI-4", "SI-7", "SC-18"],  # Visual Basic
    "T1059.006": ["SI-4", "SI-7", "SC-18"],  # JavaScript
    "T1059.007": ["SI-4", "SI-7", "SC-18"],  # Java
    "T1566": ["AT-2", "AC-17", "IA-2"],  # Phishing
    "T1566.001": ["AT-2", "AC-17", "IA-2"],  # Spearphishing Attachment
    "T1566.002": ["AT-2", "AC-17", "IA-2"],  # Spearphishing Link
    "T1566.003": ["AT-2", "AC-17", "IA-2"],  # Spearphishing via Service
    "T1205": ["CM-7", "SC-7", "SI-15", "SI-4"],  # Traffic Signaling
    "T1205.001": ["CM-7", "SC-7", "SI-15", "SI-4"],  # Port Knocking
    "T1205.002": ["CM-7", "SC-7", "SI-15", "SI-4"],  # Socket Filters
    # Mitigations
    "M1026": ["IA-2"],  # Multi-factor Authentication
    "M1040": ["SC-28"],  # Application Layer Protocol
    "M1050": ["AC-17"],  # Application Layer Protocol
    "M1055": ["IA-2"],  # Application Layer Protocol
    "M1060": ["AC-17"],  # Application Layer Protocol
    "M1065": ["IA-2"],  # Application Layer Protocol
    "M1071": ["AC-17"],  # Application Layer Protocol
    "M1075": ["IA-2"],  # Application Layer Protocol
    "M1080": ["AC-17"],  # Application Layer Protocol
    "M1085": ["IA-2"],  # Application Layer Protocol
    "M1090": ["AC-17"],  # Application Layer Protocol
    "M1095": ["IA-2"],  # Application Layer Protocol
    "M1100": ["AC-17"],  # Application Layer Protocol
    "M1105": ["IA-2"],  # Application Layer Protocol
    "M1110": ["AC-17"],  # Application Layer Protocol
    "M1115": ["IA-2"],  # Application Layer Protocol
    "M1120": ["AC-17"],  # Application Layer Protocol
    "M1125": ["IA-2"],  # Application Layer Protocol
    "M1130": ["AC-17"],  # Application Layer Protocol
    "M1135": ["IA-2"],  # Application Layer Protocol
    "M1140": ["AC-17"],  # Application Layer Protocol
    "M1145": ["IA-2"],  # Application Layer Protocol
    "M1150": ["AC-17"],  # Application Layer Protocol
    "M1155": ["IA-2"],  # Application Layer Protocol
    "M1160": ["AC-17"],  # Application Layer Protocol
    "M1165": ["IA-2"],  # Application Layer Protocol
    "M1170": ["AC-17"],  # Application Layer Protocol
    "M1175": ["IA-2"],  # Application Layer Protocol
    "M1180": ["AC-17"],  # Application Layer Protocol
    "M1185": ["IA-2"],  # Application Layer Protocol
    "M1190": ["AC-17"],  # Application Layer Protocol
    "M1195": ["IA-2"],  # Application Layer Protocol
    "M1200": ["AC-17"],  # Application Layer Protocol
    "M1205": ["IA-2"],  # Application Layer Protocol
    "M1210": ["AC-17"],  # Application Layer Protocol
    "M1215": ["IA-2"],  # Application Layer Protocol
    "M1220": ["AC-17"],  # Application Layer Protocol
    "M1225": ["IA-2"],  # Application Layer Protocol
    "M1230": ["AC-17"],  # Application Layer Protocol
    "M1235": ["IA-2"],  # Application Layer Protocol
    "M1240": ["AC-17"],  # Application Layer Protocol
    "M1245": ["IA-2"],  # Application Layer Protocol
    "M1250": ["AC-17"],  # Application Layer Protocol
    "M1255": ["IA-2"],  # Application Layer Protocol
    "M1260": ["AC-17"],  # Application Layer Protocol
    "M1265": ["IA-2"],  # Application Layer Protocol
    "M1270": ["AC-17"],  # Application Layer Protocol
    "M1275": ["IA-2"],  # Application Layer Protocol
    "M1280": ["AC-17"],  # Application Layer Protocol
    "M1285": ["IA-2"],  # Application Layer Protocol
    "M1290": ["AC-17"],  # Application Layer Protocol
    "M1295": ["IA-2"],  # Application Layer Protocol
    "M1300": ["AC-17"],  # Application Layer Protocol
    "M1305": ["IA-2"],  # Application Layer Protocol
    "M1310": ["AC-17"],  # Application Layer Protocol
    "M1315": ["IA-2"],  # Application Layer Protocol
    "M1320": ["AC-17"],  # Application Layer Protocol
    "M1325": ["IA-2"],  # Application Layer Protocol
    "M1330": ["AC-17"],  # Application Layer Protocol
    "M1335": ["IA-2"],  # Application Layer Protocol
    "M1340": ["AC-17"],  # Application Layer Protocol
    "M1345": ["IA-2"],  # Application Layer Protocol
    "M1350": ["AC-17"],  # Application Layer Protocol
    "M1355": ["IA-2"],  # Application Layer Protocol
    "M1360": ["AC-17"],  # Application Layer Protocol
    "M1365": ["IA-2"],  # Application Layer Protocol
    "M1370": ["AC-17"],  # Application Layer Protocol
    "M1375": ["IA-2"],  # Application Layer Protocol
    "M1380": ["AC-17"],  # Application Layer Protocol
    "M1385": ["IA-2"],  # Application Layer Protocol
    "M1390": ["AC-17"],  # Application Layer Protocol
    "M1395": ["IA-2"],  # Application Layer Protocol
    "M1400": ["AC-17"],  # Application Layer Protocol
    "M1405": ["IA-2"],  # Application Layer Protocol
    "M1410": ["AC-17"],  # Application Layer Protocol
    "M1415": ["IA-2"],  # Application Layer Protocol
    "M1420": ["AC-17"],  # Application Layer Protocol
    "M1425": ["IA-2"],  # Application Layer Protocol
    "M1430": ["AC-17"],  # Application Layer Protocol
    "M1435": ["IA-2"],  # Application Layer Protocol
    "M1440": ["AC-17"],  # Application Layer Protocol
    "M1445": ["IA-2"],  # Application Layer Protocol
    "M1450": ["AC-17"],  # Application Layer Protocol
    "M1455": ["IA-2"],  # Application Layer Protocol
    "M1460": ["AC-17"],  # Application Layer Protocol
    "M1465": ["IA-2"],  # Application Layer Protocol
    "M1470": ["AC-17"]
}