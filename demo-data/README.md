# ThreatLens AI — Cyber Threat Intelligence Demo Datasets

This directory contains realistic security event log datasets and entity relational tables designed for **ThreatLens AI** (PSI03 Problem Statement).

---

## 📁 Individual Test Scenario CSV Datasets (Ready for Upload & Testing)

| File Name | Target User | Role | Threat Vector / Scenario | Risk Score | Expected Containment |
|---|---|---|---|---|---|
| `threat_1_account_compromise_rahul.csv` | **Rahul Sharma** (`USR101`) | Cloud DevOps | Credential stuffing, impossible travel IP `185.44.21.8`, Mimikatz, SYSTEM token, DB exfil | **94** (Critical) |  Account Disabled |
| `threat_2_lateral_movement_priya.csv` | **Priya Verma** (`USR205`) | SysAdmin | RDP pivot `SRV003` -> `SRV008` -> `SRV014`, WMI Kerberoasting admin takeover | **91** (Critical) |  Account Disabled |
| `threat_3_data_exfiltration_vikram.csv` | **Vikram Patel** (`USR310`) | Finance Controller | Unrecognized device `DEV088`, 1,400 confidential file reads, tar staging, C2 stream | **88** (High) |  Active Alert |
| `threat_4_ransomware_staging_siddharth.csv` | **Siddharth Rao** (`USR104`) | Lead Architect | Phishing invoice payload, `vssadmin delete shadows`, ransomware file renaming (.locked) | **95** (Critical) |  Account Disabled |
| `threat_5_insider_threat_rohan.csv` | **Rohan Mehta** (`USR105`) | Account Executive | Midnight CRM database dump of 25,000 client contacts, personal cloud exfiltration | **82** (High) |  Active Alert |
| `threat_6_api_token_leak_deepa.csv` | **Deepa Nair** (`USR106`) | Cloud Engineer | Leaked AWS long-term key, foreign IP `194.26.29.112`, rogue admin policy, S3 bucket dump | **90** (Critical) |  Account Disabled |
| `threat_7_brute_force_spray_karan.csv` | **Karan Malhotra** (`USR107`) | Product Manager | Password spray bursts from Tor Exit node `185.220.101.5`, SUID privilege discovery | **85** (High) |  Active Alert |
| `threat_8_supply_chain_poison_neha.csv` | **Neha Gupta** (`USR108`) | Fullstack Dev | Malicious npm postinstall script, reverse bash shell to `45.154.255.89`, CI/CD poisoning | **93** (Critical) |  Account Disabled |
| `threat_9_crypto_mining_arjun.csv` | **Arjun Kapoor** (`USR109`) | AI/ML Engineer | Unauthorized `xmrig` binary execution on GPU node `SRV016`, TCP stratum pool telemetry | **87** (High) |  Active Alert |
| `threat_10_privilege_escalation_meera.csv` | **Meera Joshi** (`USR110`) | Database Admin | Local sudoers vulnerability exploit on `SRV013`, rogue Enterprise Admin group promotion | **92** (Critical) |  Account Disabled |
| `normal_user_ananya.csv` | **Ananya Roy** (`USR001`) | Sales Executive | Normal business hours (09:00 - 17:30), Okta MFA push verified, Salesforce, Google Docs | **12** (Low) |  Clean Baseline |
| `normal_user_aditya.csv` | **Aditya Sen** (`USR002`) | Software Engineer | FIDO2 token authentication, GitHub git pull/commit, staging kubectl logs, Jira updates | **10** (Low) |  Clean Baseline |
| `false_positive_audit_amit.csv` | **Amit Kulkarni** (`USR102`) | IT Systems Engineer | Scheduled finance server audit under Change Ticket `CHG-8821`, MFA approved | **28** (Low) |  Legitimate Pass |
| `multi_user_enterprise_day_shift.csv` | **Multi-User Fleet** | Enterprise Fleet | Blended concurrent shift with normal users, false positive audit, and multiple active attacks | **94** (Critical) |  Multi-Correlation |

---

## 📁 Relational Entity Master Tables

| File | Description | Record Count |
|---|---|---|
| `security_events.csv` | **Full Master Telemetry Stream** (Synthetic enterprise log activity) | ~5,000 Events |
| `users.csv` | Corporate Identity Directory (Users, Roles, Departments, Sensitivity) | 47 Users |
| `devices.csv` | Managed & Unmanaged Endpoint Inventory (`known_device` flags) | 51 Devices |
| `servers.csv` | Infrastructure Host Inventory (`criticality`: Critical, High, Medium, Low) | 20 Servers |
| `ip_addresses.csv` | Internal & External IP Reputation Database | 55 IP Addresses |
| `applications.csv` | Enterprise Application & Service Catalog | 15 Applications |
| `scenarios.json` | JSON scenario definitions with metadata and expected detection outputs | 14 Scenarios |

---

## 🔗 Relational Schema Connections

```
[security_events.csv]
  ├── user_id        ──>  [users.csv] (user_id)
  ├── device_id      ──>  [devices.csv] (device_id)
  ├── server_id      ──>  [servers.csv] (server_id)
  ├── ip_address     ──>  [ip_addresses.csv] (ip_address)
  └── application    ──>  [applications.csv] (application_name)
```

---

## 🛠️ How to Test in ThreatLens AI

1. Open the **"Import CSV"** tab in ThreatLens AI.
2. Either:
   - **Click any of the 1-Click Load Scenario buttons** in the scenario catalog to test immediately.
   - **Download any CSV** and drag & drop it into the upload box.
3. Click **"Analyze Security Events"**.
4. ThreatLens AI will automatically correlate the events, reconstruct the multi-stage attack timeline, render the dynamic attack graph, and provide AI forensic explanation and containment actions.
