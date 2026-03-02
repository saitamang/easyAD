# 🔐 EasyAD – Active Directory Enumeration & Attack Path Framework

EasyAD.ps1 is an advanced Active Directory enumeration and attack path discovery framework inspired by tools like WinPEAS/LinPEAS.

It is designed to provide structured LDAP-based enumeration, clear vulnerability reporting, and guided exploitation steps for red team, purple team, and lab environments.

## ☕ Support My Work

If you find this project useful, consider supporting:

👉 [https://www.buymeacoffee.com/saitamang](https://buymeacoffee.com/saitamang)

---

## 🚀 How to Run

### Download

Option 1 – Git Clone

```git clone https://github.com/saitamang/easyAD.git```


Option 2 – PowerShell Download

```iwr -uri https://raw.githubusercontent.com/saitamang/easyAD/refs/heads/main/easyAD.ps1
 -outfile easyAD.ps1```


---

### Execute Full Scan

.\easyAD.ps1


### Execute with Exclusions

.\easyAD.ps1 -Exclude ASREP,Kerberoast


---

## ✨ Key Enhancements

- Modern ASCII banner with structured UI
- Clean box-drawing interface
- Color-coded severity levels:
  - 🔴 CRITICAL
  - 🟣 HIGH
  - 🟡 MEDIUM
  - 🟢 LOW
  - 🔵 INFO
- Structured vulnerability findings
- Guided exploitation walkthroughs
- Attack prioritization summary
- Clean terminal output optimized for reporting

---

## 🛠 Core Capabilities

### Active Directory Enumeration
- Domain Information Discovery
- Privileged User Enumeration
- Password Policy Analysis
- Service Principal Discovery
- SQL Server Identification
- ACL Enumeration & Abuse Detection

### Credential Exposure Checks
- GPP Password Discovery
- LAPS Password Enumeration
- Kerberos Pre-Auth Disabled Accounts

### Delegation & Kerberos Attacks
- AS-REP Roasting
- Kerberoasting
- Unconstrained Delegation
- Constrained Delegation
- Resource-Based Constrained Delegation (RBCD)

### Domain Takeover Techniques
- DCSync Permission Detection
- Golden Ticket Abuse
- Silver Ticket Abuse
- ACL Misconfiguration Exploitation

---

## 🎯 Design Philosophy

EasyAD focuses on:

- Clear visibility into attack paths
- Operator education (why it matters)
- Prioritized exploitation order
- Clean reporting output
- Real-world attack simulation logic

The goal is not just enumeration — but structured Active Directory attack path discovery.

---

## ⚠ Disclaimer

This tool is intended for:
- Authorized security assessments
- Red team lab environments
- Blue team detection validation
- Security research and education

Do not use against systems without proper authorization.

---

## 👨‍💻 Author

Developed by Saitamang - and of course with AI as my bestie now ;P

Security Research | Active Directory | Cloud Security | Red Teaming
