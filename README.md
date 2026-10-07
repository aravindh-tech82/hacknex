# ThreatLens AI — Cyber Threat Intelligence Platform (HackNex)

> **"From Security Events to Attack Intelligence"**  
> Problem Statement: **PSI03 — AI-Powered Cyber Threat Intelligence**

ThreatLens AI acts like an AI detective for enterprise Security Operations Centers (SOC). It ingests raw multi-source security event logs, correlates fragmented events across users, endpoints, IPs, and servers, detects multi-stage cyber attacks, reconstructs attack sequence timelines, generates interactive entity relationship graphs, and automates account containment.

---

## 🌟 Key Features

- **Automated CSV Log Ingestion**: Upload any security event stream or choose from 14 pre-built realistic threat attack scenarios.
- **Dynamic Multi-Entity Correlation**: Links `user_id`, `device_id`, `ip_address`, `server_id`, and `application` into unified threat chains.
- **AI Threat Scoring & Severity Calibration**: Dynamically calculates risk scores (0–100) and classifies incidents from Low Risk to Critical Threat.
- **Interactive Multi-Hop Attack Graph**: Visualizes lateral movement and kill-chains using React Flow nodes (Users, Devices, IPs, Servers, and C2 external endpoints).
- **Incident Investigation & Evidence Reconstruction**: Displays correlated evidence items, chronological timeline events, and forensic MITRE ATT&CK mapping.
- **Automated Incident Response & Containment**: Real-time containment toggles allowing SOC analysts to isolate endpoints, block malicious IPs, or disable compromised identities.
- **Threat Detection Test Lab**: Interactive sandbox to simulate attacks, test detection rules, and verify automatic response logic.

---

## 📁 Included Datasets (`/demo-data/` & `/public/demo-data/`)

14 ready-to-test CSV files covering distinct users, roles, and attack vectors:

| File Name | Target User | Role | Threat Vector / Attack Chain | Score |
|---|---|---|---|---|
| `threat_1_account_compromise_rahul.csv` | **Rahul Sharma** (`USR101`) | Cloud DevOps | Credential stuffing, impossible travel (`185.44.21.8`), Mimikatz, DB exfil | **94** |
| `threat_2_lateral_movement_priya.csv` | **Priya Verma** (`USR205`) | SysAdmin | RDP pivot `SRV003` ➔ `SRV008` ➔ `SRV014`, WMI Kerberoasting takeover | **91** |
| `threat_3_data_exfiltration_vikram.csv` | **Vikram Patel** (`USR310`) | Finance Lead | Unrecognized device `DEV088`, 1,400 confidential file reads, tar staging, C2 stream | **88** |
| `threat_4_ransomware_staging_siddharth.csv` | **Siddharth Rao** (`USR104`) | Architect | Phishing payload, `vssadmin delete shadows`, ransomware encryption staging | **95** |
| `threat_5_insider_threat_rohan.csv` | **Rohan Mehta** (`USR105`) | Sales Lead | Midnight CRM database dump of 25,000 client records, cloud upload | **82** |
| `threat_6_api_token_leak_deepa.csv` | **Deepa Nair** (`USR106`) | Cloud Eng | Leaked AWS access key from foreign IP `194.26.29.112`, rogue admin policy, S3 dump | **90** |
| `threat_7_brute_force_spray_karan.csv` | **Karan Malhotra** (`USR107`) | Product Mgr | Password spray bursts from Tor Exit node `185.220.101.5`, SUID discovery | **85** |
| `threat_8_supply_chain_poison_neha.csv` | **Neha Gupta** (`USR108`) | Fullstack Dev | Malicious npm postinstall script, reverse bash shell to `45.154.255.89`, CI/CD poisoning | **93** |
| `threat_9_crypto_mining_arjun.csv` | **Arjun Kapoor** (`USR109`) | AI/ML Eng | Unauthorized `xmrig` binary execution on GPU node `SRV016`, stratum telemetry | **87** |
| `threat_10_privilege_escalation_meera.csv` | **Meera Joshi** (`USR110`) | DBA | Local sudoers exploit on `SRV013`, rogue Enterprise Admin group promotion | **92** |
| `normal_user_ananya.csv` | **Ananya Roy** (`USR001`) | Sales Exec | Daytime employee workflow, Okta MFA push verified (Clean Baseline) | **12** |
| `normal_user_aditya.csv` | **Aditya Sen** (`USR002`) | Software Eng | FIDO2 token hardware MFA, Git push, staging kubectl logs (Clean Baseline) | **10** |
| `false_positive_audit_amit.csv` | **Amit Kulkarni** (`USR102`) | IT Systems Eng | Scheduled finance server audit under Change Ticket `CHG-8821` (Audit Pass) | **28** |
| `multi_user_enterprise_day_shift.csv` | **Multi-User Fleet** | Fleet | Blended concurrent shift with normal users, false positive audit, and multiple active attacks | **94** |

---

## 🛠️ Technology Stack

- **Frontend**: React 19, TypeScript
- **Build System**: Vite 8
- **Graph Visualization**: `@xyflow/react` (React Flow)
- **Styling**: Tailwind CSS + Custom SOC Cyber Theme (Glassmorphism, Neon Indicators)
- **Icons**: Lucide React
- **CSV Engine**: PapaParse

---

## 🚀 Getting Started

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/aravindh-tech82/hacknex.git
cd hacknex
npm install
```

### 2. Run Development Server
```bash
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

### 3. Build for Production
```bash
npm run build
```
