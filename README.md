# 🛡️ AI-Powered Multi-Cloud Anomaly Detection & Zero Trust Enforcement System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-black?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?logo=scikitlearn&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-ensemble-green)
![Clouds](https://img.shields.io/badge/Clouds-AWS%20%7C%20Azure%20%7C%20GCP-lightgrey)
![Framework](https://img.shields.io/badge/NIST-SP%20800--207-red)

> **Smart India Hackathon (SIH) Submission**
> Problem Statement ID: `<SIH26156>
>` · Team Name: `<TRUSTMATRIX>`

A real-time system that watches **AWS, Azure and GCP** audit logs, scores every event with an **ensemble of three ML models**, computes a **Zero Trust Trust Score**, and enforces a decision: **ALLOW / MFA REQUIRED / BLOCK / CRITICAL BLOCK**. Everything is visible on a live dashboard.

---

## 📌 Problem

Organisations increasingly run workloads across several clouds, each with its own log format and its own security tooling. Suspicious activity such as an IAM user created at 3 AM from an unusual country is easy to miss when logs are siloed and reviewed manually. Static rules generate false positives and cannot adapt to new attack patterns.

## 💡 Our Solution

One unified pipeline that:

1. **Collects** audit logs from AWS CloudTrail, Azure Monitor Activity Log and GCP Cloud Audit Logs
2. **Extracts features** (hour of day, action risk, country, denied/allowed, and more)
3. **Runs 3 ML models** (Random Forest, XGBoost, Isolation Forest) and takes an ensemble vote
4. **Calculates a Trust Score** (0.00 to 1.00) using a research-backed formula
5. **Makes a Zero Trust decision** using research-backed thresholds
6. **Displays everything** on a live dashboard with filters, alerts and charts

---

## 🏗️ Architecture

```
 ┌──────────┐  ┌──────────┐  ┌──────────┐
 │   AWS    │  │  Azure   │  │   GCP    │
 │CloudTrail│  │ Activity │  │  Audit   │
 └────┬─────┘  └────┬─────┘  └────┬─────┘
      └─────────────┼─────────────┘
                    ▼
          Log Collectors (modules/)
                    ▼
            Feature Extraction
                    ▼
     ┌──────────────┴──────────────┐
     ▼                             ▼
 Trust Score (Eq.1)        ML Ensemble (RF + XGB + IF)
     └──────────────┬──────────────┘
                    ▼
        Zero Trust Decision Engine
                    ▼
        Flask Dashboard (live view)
```

---

## 🔍 How the Zero Trust Decision Works

**Example:** `user_admin` creates an IAM user at 3 AM from Russia.

| Stage | Detail |
|-------|--------|
| Feature extraction | `hour=3 → is_odd_hour=1`, `action=CreateUser → action_risk=9`, `country=RU → is_high_risk_country=1`, `is_denied=0` |
| Trust Score | B=0, N=15, D=70, T=50 → `0.4×0 + 0.3×15 + 0.2×70 + 0.1×50 = 23.5` → **0.235** |
| ML ensemble | RF → anomaly · XGBoost → anomaly · Isolation Forest → anomaly (3/3 votes) |
| Decision | `0.235 < 0.30` → 🚨 **CRITICAL BLOCK**: session terminated, admin alerted, IP flagged |

### Trust Score Formula

```
TS = 0.4·B + 0.3·N + 0.2·D + 0.1·T
```

| Factor | Meaning | Weight |
|--------|---------|--------|
| **B** | User Behaviour | 0.4 |
| **N** | Network | 0.3 |
| **D** | Device | 0.2 |
| **T** | Threat History | 0.1 |

### Decision Thresholds

| Trust Score | Decision |
|-------------|----------|
| ≥ 0.80 | ✅ ALLOW |
| 0.60 – 0.79 | 🔐 MFA REQUIRED |
| 0.30 – 0.59 | ⛔ BLOCK |
| < 0.30 | 🚨 CRITICAL BLOCK |

---

## 🤖 ML Models

| Model | Role | Formula |
|-------|------|---------|
| **Random Forest** | Supervised classifier, averages many trees | `F(x) = (1/T) Σ ft(x)` |
| **XGBoost** | Gradient-boosted trees, sums tree outputs | `F(x) = Σ ft(x)` |
| **Isolation Forest** | Unsupervised outlier detection (contamination = 0.02) | `S(x) = c(n)·h(x)/T` |

Models train automatically on collected logs and are saved to `models/`.

---

## ✨ Features

- 🌐 Multi-cloud log ingestion (AWS, Azure, GCP)
- 🧠 3-model ML ensemble with voting
- 📊 Research-backed Trust Score on every event
- 🔒 Four-level Zero Trust decisions aligned with NIST SP 800-207
- 📈 Live dashboard with four views:
  - **Overview**: stat cards, per-cloud counts, decision pie chart, trust-score trend
  - **Event Log**: filters by cloud and decision, trust-score bars, ML vote icons
  - **Alerts**: all BLOCK and CRITICAL BLOCK events with full details
  - **ML Models**: explanation of each model with citations
- 🔑 Login-protected dashboard with hashed passwords (Werkzeug)

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11, Flask 3.1 |
| ML | scikit-learn, XGBoost |
| AWS logs | boto3, CloudTrail |
| Azure logs | azure-identity, azure-mgmt-monitor |
| GCP logs | google-cloud-logging |
| Frontend | HTML5, CSS3, Chart.js |
| Security | Werkzeug password hashing, Flask sessions |

---

## 📁 Project Structure

```
zerotrust-dashboard/
├── app.py                  # Main Flask application (entry point)
├── config.py               # Research-sourced thresholds and weights
├── requirements.txt        # Python dependencies
├── Procfile                # Deployment process definition
├── .ebextensions/          # AWS Elastic Beanstalk configuration
├── modules/
│   ├── aws_collector.py    # AWS CloudTrail collection
│   ├── azure_collector.py  # Azure Monitor Activity Log collection
│   ├── gcp_collector.py    # GCP Cloud Audit Log collection
│   └── ml_engine.py        # RF + XGBoost + Isolation Forest ensemble
├── models/                 # Trained models (auto-created)
└── templates/
    ├── login.html          # Login page
    └── dashboard.html      # Dashboard UI
```

---

## 🚀 Getting Started

### 1. Prerequisites
Python 3.10 or higher:
```bash
python --version
```

### 2. Clone and install
```bash
git clone https://github.com/srushtijain2907-cyber/zerotrust-dashboard.git
cd zerotrust-dashboard
pip install -r requirements.txt
```

### 3. Configure cloud access

**AWS** (required for real CloudTrail logs)
```bash
aws configure
```
Enter your Access Key ID, Secret Access Key, region (e.g. `us-east-1`) and output format (`json`).

**Azure** (optional)
```bash
az login
set AZURE_SUBSCRIPTION_ID=your-subscription-id
```

**GCP** (optional)
```bash
gcloud auth application-default login
set GOOGLE_CLOUD_PROJECT=your-project-id
```

> 🔐 Use **read-only** IAM credentials for this tool, and never commit keys to the repo.

### 4. Set dashboard credentials
Set your own admin credentials through environment variables or your local config before the first run. Do not use default or shared passwords, and do not commit them to GitHub.

### 5. Run
```bash
python app.py
```
Open **http://localhost:5000** in your browser.

---

## ✅ What Works vs. What Needs Setup

| Feature | Status | Requirement |
|---------|--------|-------------|
| AWS CloudTrail logs | Live | `aws configure` |
| Azure Activity logs | Live | `az login` + `AZURE_SUBSCRIPTION_ID` |
| GCP Cloud Audit logs | Live | `gcloud auth` + `GOOGLE_CLOUD_PROJECT` |
| ML ensemble | Live | Trains on collected logs |
| Trust Score | Live | Computed for every event |
| Zero Trust decisions | Live | Thresholds applied per event |
| Dashboard | Live | Flask web app |

---

## ⚠️ Known Limitations

1. Not yet running on a production-grade cloud deployment
2. Lambda invocation requires Docker Desktop
3. Models need retraining as new attack types emerge
4. Device factor (D) uses a fixed baseline of 70, since there is no endpoint agent
5. Only *recommends* MFA and does not send an actual MFA challenge
6. Classifies risky events but does not automatically suspend IAM users

## 🔮 Future Scope

- Production deployment with containerisation (Docker/Kubernetes)
- Real MFA challenge integration (TOTP / push)
- Automated remediation: disable IAM users, revoke sessions, rotate keys
- Endpoint agent for a real Device (D) score
- Online / incremental learning to adapt to new attack patterns
- SIEM integration and email/Slack alerting

---

## 📚 References

1. Jeong, E.; Yang, D. *A Trust Score-Based Access Control Model for Zero Trust Architecture.* Applied Sciences, 2025, 15(17), 9551. DOI: [10.3390/app15179551](https://doi.org/10.3390/app15179551)
2. Al-Shehari, T. et al. *Insider Threat Detection Model Using Anomaly-Based Isolation Forest Algorithm.* IEEE Access, 2023, 11, 118170–118185. DOI: [10.1109/ACCESS.2023.3326750](https://doi.org/10.1109/ACCESS.2023.3326750)
3. Rose, S. et al. *Zero Trust Architecture.* NIST SP 800-207, 2020.

---




---

