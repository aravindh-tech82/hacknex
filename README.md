# ThreatLens AI — Cyber Threat Intelligence Platform (HackNex)

[![Live Demo](https://img.shields.io/badge/Live_Demo-hacknex--3.onrender.com-6366f1?style=for-the-badge&logo=render&logoColor=white)](https://hacknex-3.onrender.com/)
[![React](https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite_8-646CFF?style=for-the-badge&logo=vite&logoColor=FFD62E)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS_4-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

> **"From Security Events to Attack Intelligence"**  
> Problem Statement: **PSI03 — AI-Powered Cyber Threat Intelligence**

**Live Application URL**: 🌐 **[https://hacknex-3.onrender.com/](https://hacknex-3.onrender.com/)**

ThreatLens AI acts like an AI detective for enterprise Security Operations Centers (SOC). It ingests raw multi-source security event logs, extracts behavioral telemetry, applies unsupervised anomaly detection (Isolation Forest) and supervised threat risk classification (XGBoost), fuses them with a deterministic rule baseline into a transparent threat score, reconstructs multi-hop attack graphs and chronological timelines, and provides an LLM-powered forensic investigator for explainable incident response and controlled containment.

---

## 🏛️ System Architecture & Data Flow

```
           Security Event Telemetry (CSV / Live Stream)
                                │
                                ▼
         [Feature Extraction Engine] (16 Behavioral Dimensions)
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
┌──────────────────────────────┐        ┌──────────────────────────────┐
│   1. Isolation Forest        │        │   2. XGBoost                 │
│   Anomaly Detection          │        │   Threat Classification      │
│   (Unsupervised iTree Forest)│        │   (Supervised GBDT Model)    │
└──────────────┬───────────────┘        └──────────────┬───────────────┘
               │                                       │
               └───────────────────┬───────────────────┘
                                   ▼
                      [Deterministic Rule Engine] (Baseline)
                                   │
                                   ▼
                [Combined Threat Intelligence Score]
          Formula: (Rule × 0.40) + (IF × 0.25) + (XGB × 0.35)
                                   │
                                   ▼
                [Multi-Entity Relational Correlation]
                (Interactive Attack Graph + Kill-Chain)
                                   │
                                   ▼
                [3. LLM AI Forensic Investigator]
          (Evidence Breakdown + Q&A + Playbook Guidance)
                                   │
                                   ▼
                [Controlled Auto-Containment]
       (Score ≥ 91 ➔ Session Revocation & Admin Approval)
```

---

## 🌟 Core Intelligence Layers

### 1. 🌲 Unsupervised Anomaly Detection: Isolation Forest (`src/utils/isolationForest.ts`)
- **Core Question**: *"Is this user's behavioral footprint unusual compared with corporate baselines?"*
- **Algorithmic Engine**:
  - Recursive Isolation Trees ($iTrees$) partitioning multi-dimensional feature space.
  - Path length expectation $E(h(x))$ and harmonic estimation:
    $$c(n) = 2\left(\ln(n - 1) + 0.5772156649\right) - \frac{2(n - 1)}{n}$$
  - Exact anomaly calculation:
    $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
- **Outputs**: Normalized anomaly score (0–100%), classification labels (`ANOMALOUS`, `SUSPICIOUS`, `NORMAL`), and path isolation explanations.

### 2. ⚡ Supervised Threat Classification: XGBoost (`src/utils/xgboostEngine.ts`)
- **Core Question**: *"Given the observed signals, what is the mathematical probability of an active cyber attack?"*
- **Algorithmic Engine**:
  - Boosted decision tree ensemble trained on authentication abuse, unmapped devices, ingress subnets, EDR alerts, and Isolation Forest feedback.
  - Sigmoid link function:
    $$P(\text{attack}) = \frac{1}{1 + e^{-(\sum f_k(x) + b)}}$$
  - Computes SHAP-style feature contributions (e.g. `+1.85 Authentication Failures`, `+2.20 Suspicious Process Execution`).
- **Outputs**: Attack probability %, predicted class (`CRITICAL_THREAT`, `HIGH_RISK`, `SUSPICIOUS`, `LOW_RISK`, `NORMAL`), and top contributing indicators.

### 3. 🔍 Tier-3 SOC LLM Forensic Investigator (`src/services/llmService.ts`)
- **Core Question**: *"What happened, which evidence matters most, and what containment action should the analyst take?"*
- **Features**:
  - **Provider Abstraction**: Supports external API configuration (`VITE_LLM_API_URL` and `VITE_LLM_API_KEY`).
  - **Offline Forensic Reasoning Engine**: Automatically activates when no API key is provided—zero downtime, deterministic, and instant.
  - **Evidence Integrity**: Distinguishes **Observed Evidence**, **Model Inference**, and **SOC Recommendations**. Never hallucinates; states *"Insufficient evidence"* when data is missing.
  - **Interactive Clickable Queries**:
    - *"What happened in this incident?"*
    - *"Why is this account risky?"*
    - *"What evidence supports the threat score?"*
    - *"What was the attack sequence?"*
    - *"Which entity should I investigate first?"*
    - *"Could this be a false positive?"*
    - *"What should the SOC analyst do next?"*

---

## ⚖️ Transparent Combined Threat Score (`src/config/threatScoringConfig.ts`)

| Intelligence Layer | Type | Weight | Contribution Range |
|---|---|:---:|:---:|
| **Deterministic Rule Engine** | Rule Policy Baseline | **40%** (`0.40`) | 0 – 40 pts |
| **Isolation Forest** | Unsupervised Anomaly | **25%** (`0.25`) | 0 – 25 pts |
| **XGBoost Classifier** | Supervised Threat Probability | **35%** (`0.35`) | 0 – 35 pts |
| **Total Combined Score** | **Unified Threat Intelligence** | **100%** | **0 – 100 pts** |

```ts
finalScore = Math.round(
  ruleScore * 0.40 +
  anomalyScorePct * 0.25 +
  xgbProbPct * 0.35
);
```

### 🎯 False Positive Handling
- **Normal Users (`USR001`, `USR002`)**: Clean baseline activity with valid MFA results in low anomaly and low XGBoost probabilities (Score: 10–12).
- **Scheduled Maintenance (`USR102` / Amit Kulkarni)**: Sensitive database access under approved Change Ticket `CHG-8821` with hardware token MFA is verified without alert fatigue (Score: 28 — *Audit Pass*).
- **Explainability Card**: Features a dedicated *"Why was this not classified as a critical threat?"* explanation.

---

## ⏱️ Real-Time Live Security Monitor (`src/components/LiveMonitor.tsx`)

Simulates real-time event ingestion and threat escalation:
- **Controls**: **Start Stream**, **Pause**, **Reset**.
- **Speed Multipliers**: **1x** (1s), **2x** (500ms), **5x** (200ms), **10x** (100ms).
- **Dynamic Progression**: As events arrive, threat scores evolve incrementally (e.g. `20` ➔ `40` ➔ `61` ➔ `78` ➔ `91` ➔ `97`).
- **Real-Time Visuals**: Incoming event highlights, live feature counts, live Isolation Forest & XGBoost cards, and dynamic attack graph node updates.
- **Auto-Containment Trigger**: Alert triggers immediately when the score reaches $\ge 91$.

---

## 🛡️ Controlled Auto-Containment Workflow

When Final Threat Score $\ge 91$:
- **Alert Banner**: `CRITICAL THREAT DETECTED`
- **Simulated Response**:
  - Active user session terminated.
  - EDR network isolation applied to endpoint.
  - Mandatory credential rotation required.
- **Admin Governance**:
  - **`Approve Recovery`**: Verifies credential rotation and restores account status to `ACTIVE`.
  - **`Keep Locked`**: Maintains active quarantine.

---

## 📁 14 Pre-Built Test Datasets (`/demo-data/` & `/public/demo-data/`)

Test individual attack scenarios directly in the **Import CSV** tab with 1-click loading or download:

| File Name | Target User | Role | Attack Vector / Scenario | Score | Status |
|---|---|---|---|:---:|:---:|
| `threat_1_account_compromise_rahul.csv` | **Rahul Sharma** (`USR101`) | Cloud DevOps | Credential stuffing, impossible travel (`185.44.21.8`), Mimikatz, DB exfil | **94** | Contained |
| `threat_2_lateral_movement_priya.csv` | **Priya Verma** (`USR205`) | SysAdmin | RDP pivot `SRV003` ➔ `SRV008` ➔ `SRV014`, WMI Kerberoasting | **91** | Contained |
| `threat_3_data_exfiltration_vikram.csv` | **Vikram Patel** (`USR310`) | Finance Lead | Unrecognized device `DEV088`, 1,400 file reads, tar staging, C2 stream | **88** | Active Alert |
| `threat_4_ransomware_staging_siddharth.csv` | **Siddharth Rao** (`USR104`) | Architect | Phishing invoice, `vssadmin delete shadows`, ransomware encryption staging | **95** | Contained |
| `threat_5_insider_threat_rohan.csv` | **Rohan Mehta** (`USR105`) | Sales Lead | Midnight CRM dump of 25,000 client records from `SRV011`, cloud upload | **82** | Active Alert |
| `threat_6_api_token_leak_deepa.csv` | **Deepa Nair** (`USR106`) | Cloud Eng | Leaked AWS access key from `194.26.29.112`, rogue admin policy, S3 dump | **90** | Contained |
| `threat_7_brute_force_spray_karan.csv` | **Karan Malhotra** (`USR107`) | Product Mgr | Password spray from Tor Exit node `185.220.101.5`, SUID discovery | **85** | Active Alert |
| `threat_8_supply_chain_poison_neha.csv` | **Neha Gupta** (`USR108`) | Fullstack Dev | Poisoned npm script, reverse bash shell to `45.154.255.89`, CI/CD poisoning | **93** | Contained |
| `threat_9_crypto_mining_arjun.csv` | **Arjun Kapoor** (`USR109`) | AI/ML Eng | Unauthorized `xmrig` on GPU node `SRV016`, stratum pool telemetry | **87** | Active Alert |
| `threat_10_privilege_escalation_meera.csv` | **Meera Joshi** (`USR110`) | DBA | Local sudoers exploit on `SRV013`, rogue Enterprise Admin promotion | **92** | Contained |
| `normal_user_ananya.csv` | **Ananya Roy** (`USR001`) | Sales Exec | Daytime employee workflow, Okta MFA push verified (Clean Baseline) | **12** | Clean Pass |
| `normal_user_aditya.csv` | **Aditya Sen** (`USR002`) | Software Eng | FIDO2 token hardware MFA, Git push, staging kubectl logs (Clean Baseline) | **10** | Clean Pass |
| `false_positive_audit_amit.csv` | **Amit Kulkarni** (`USR102`) | IT Systems Eng | Scheduled finance audit under Change Ticket `CHG-8821` (Audit Pass) | **28** | Audit Pass |
| `multi_user_enterprise_day_shift.csv` | **Multi-User Fleet** | Fleet | Blended concurrent shift with normal users, audits, and multiple attacks | **94** | Correlated |

---

## 🛠️ Technology Stack

- **Frontend Core**: React 19, TypeScript
- **Bundler & Tooling**: Vite 8
- **Styling**: Tailwind CSS 4 + Custom Cyber SOC Glassmorphism Design System
- **Graph Visualization**: `@xyflow/react` (React Flow)
- **Telemetry Charts**: Recharts
- **Icons**: Lucide React
- **CSV Engine**: PapaParse
- **Deployment Platform**: Render (`hacknex-3.onrender.com`)

---

## 🚀 Local Development & Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/aravindh-tech82/hacknex.git
cd hacknex
npm install
```

### 2. Run Locally
```bash
npm run dev
# or: npm start
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.

### 3. Build for Production
```bash
npm run build
```

---

## 🌐 Production Deployment (Render)

The application is deployed as a high-performance Single Page Application on Render:
- **Live URL**: [https://hacknex-3.onrender.com/](https://hacknex-3.onrender.com/)
- **Configuration**: [render.yaml](file:///c:/Desktop/HACKNEX/render.yaml) & [public/_redirects](file:///c:/Desktop/HACKNEX/public/_redirects) for client-side routing.
- **Allowed Hosts**: Configured in [vite.config.ts](file:///c:/Desktop/HACKNEX/vite.config.ts) for secure domain binding.

---

## 🏆 Hackathon Demonstration Flow

1. **Command Center**: View real-time AI/ML model statuses, telemetry charts, and transparent score breakdowns.
2. **Live Monitor**: Click **Start Stream** to replay events sequentially; watch the threat score rise in real time (20 ➔ 40 ➔ 61 ➔ 78 ➔ 91 ➔ 97) and see the auto-containment prompt appear.
3. **Investigation**: Inspect correlated evidence, the interactive attack graph, the chronological timeline, and the **AI Investigator Panel**.
4. **Forensic Q&A**: Click any suggested question to receive instant evidence-backed answers from the LLM engine.
5. **Threat Test Lab**: Switch between different user scenarios to evaluate false positive suppression vs. critical containment.
