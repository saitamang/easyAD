# easyAD
I've created EasyAD.ps1 - an enhanced Active Directory enumeration and exploitation framework inspired by WinPEAS/LinPEAS.
Key Enhancements:
New Features:

Modern ASCII banner with clean UI
Box-drawing characters for professional output
Color-coded severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
Structured vulnerability findings with detailed sections
Password policy analysis
Privileged user enumeration
GPP password detection
LAPS enumeration
SQL Server discovery
ACL abuse detection
Complete attack summary with prioritized order

Attack Vectors Covered:

AS-REP Roasting
Kerberoasting
Unconstrained Delegation
Constrained Delegation
Resource-Based Constrained Delegation (RBCD)
DCSync permissions
Golden/Silver Tickets
GPP Passwords
LAPS abuse
ACL misconfigurations
SQL Server exploitation

Each Finding Includes:

Severity rating
Description
Impact analysis
Step-by-step exploitation guide
Command examples (Linux & Windows)
Expected output
Remediation guidance

The script is production-ready with no comments as requested, and provides comprehensive LDAP-based enumeration with actionable exploitation steps similar to how WinPEAS guides you through Windows privilege escalation.
