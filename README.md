# AI-Powered Multi-Cloud Anomaly Detection & Zero Trust Enforcement System
## GHRCE B.Tech IT Capstone Project 2026
### Team Leader: Srushti Jain (C28) 
# Team Member : Vishwajeet Atal (C49)  Purab Roy (B48)

---

## What This Project Does (Simple Explanation)

This system watches your AWS, Azure, and GCP cloud accounts in real-time.
Every time someone does something in the cloud (creates a user, deletes a bucket,
logs in at 3AM from a foreign country), our AI system:

1. Collects the log from the cloud
2. Extracts features (what time? which action? which country? was it denied?)
3. Runs 3 ML models to check if it looks suspicious
4. Calculates a Trust Score (0.00 to 1.00)
5. Makes a Zero Trust decision: ALLOW / MFA REQUIRED / BLOCK / CRITICAL BLOCK
6. Shows everything on a live dashboard

---

## IEEE Research Paper Sources

### Trust Score Formula & Thresholds
Jeong, E.; Yang, D. "A Trust Score-Based Access Control Model for Zero Trust
Architecture." Applied Sciences, 2025, 15(17), 9551.
DOI: 10.3390/app15179551

- Thresholds: TS≥0.80=ALLOW, 0.60-0.79=MFA, 0.30-0.59=BLOCK (Page 14, §4.1)
- Formula: TS = 0.4·B + 0.3·N + 0.2·D + 0.1·T (Page 10, Eq.1)
- Weights: wB=0.4, wN=0.3, wD=0.2, wT=0.1 (Page 10-11, §3.2.2)
- Off-hours: 02:00-05:00 = very high risk (Page 8, Table 2, Row ③)

### ML Models (Ensemble Architecture)
Al-Shehari, T. et al. "Insider Threat Detection Model Using Anomaly-Based
Isolation Forest Algorithm." IEEE Access, 2023, 11, 118170-118185.
DOI: 10.1109/ACCESS.2023.3326750

- Random Forest formula: F(x) = (1/T)Σft(X) — Eq.3, Page 118176
- XGBoost formula: F(x) = Σft(x) — Eq.2, Page 118175
- Isolation Forest: S(x) = c(n)·h(x)/T — Eq.6, Page 118177
- IF Contamination = 0.02 (best: 98% accuracy, 99% F-score) — Table 6

### Zero Trust Framework
NIST SP 800-207: Rose, S. et al. "Zero Trust Architecture." 2020.
- Score-based Trust Algorithm: §3.3.1, Pages 19-21
- Threshold-based grant/deny/reduce decisions: Page 19-20

---

## Project Structure

```
zerotrust/
├── app.py                    ← Main Flask application (run this)
├── config.py                 ← All IEEE-sourced thresholds and weights
├── requirements.txt          ← Python dependencies
├── modules/
│   ├── aws_collector.py      ← Real AWS CloudTrail log collection
│   ├── azure_collector.py    ← Real Azure Monitor Activity Log collection
│   ├── gcp_collector.py      ← Real GCP Cloud Audit Log collection
│   └── ml_engine.py          ← RF + XGBoost + Isolation Forest ensemble
├── models/                   ← Trained ML models saved here (auto-created)
└── templates/
    ├── login.html            ← Secure login page
    └── dashboard.html        ← Full dashboard UI
```

---

## Step-by-Step Setup (Windows)

### Step 1: Install Python
Make sure Python 3.10+ is installed.
```
python --version
```

### Step 2: Install dependencies
Open Command Prompt in the zerotrust folder:
```
cd "C:\path\to\zerotrust"
pip install -r requirements.txt
```

### Step 3: Configure AWS (Real logs)
You already have AWS CLI configured. Just make sure it points to your account:
```
aws configure
```
Enter your Access Key ID, Secret Access Key, region (us-east-1), output (json).
The system will automatically read CloudTrail logs from your account.

### Step 4: Configure Azure (Real logs) — OPTIONAL
If you want real Azure logs:
1. Install Azure CLI: https://aka.ms/installazurecliwindows
2. Run: az login
3. Set your subscription ID:
   In Command Prompt: set AZURE_SUBSCRIPTION_ID=your-subscription-id
   Find it at: portal.azure.com → Subscriptions

### Step 5: Configure GCP (Real logs) — OPTIONAL
If you want real GCP logs:
1. Install Google Cloud SDK: https://cloud.google.com/sdk/docs/install
2. Run: gcloud auth application-default login
3. Set project: set GOOGLE_CLOUD_PROJECT=your-project-id

### Step 6: Run the project
```
python app.py
```

### Step 7: Open the dashboard
Open your browser and go to:
```
http://localhost:5000
```

Login credentials:
- Username: admin   Password: ZeroTrust@2026
- Username: srushti Password: srushti123
- Username: vishwajeet atal: vishwajeet123

---

## What Is Real vs. What Needs Setup

| Feature | Status | Notes |
|---------|--------|-------|
| AWS CloudTrail logs | REAL | Needs `aws configure` |
| Azure Activity logs | REAL | Needs `az login` + AZURE_SUBSCRIPTION_ID |
| GCP Cloud Audit logs | REAL | Needs `gcloud auth` + GOOGLE_CLOUD_PROJECT |
| ML Models (RF+XGBoost+IF) | REAL | Trains automatically on collected logs |
| Trust Score calculation | REAL | IEEE formula, runs on every event |
| Zero Trust decisions | REAL | IEEE thresholds applied per event |
| Dashboard | REAL | Live Flask web app |

---

## How the Zero Trust Decision Works

```
Cloud Event (e.g. user_admin creates IAM user at 3AM from Russia)
        │
        ▼
Feature Extraction
  - hour=3 → is_odd_hour=1 (Jeong & Yang 2025, Table 2)
  - action=CreateUser → action_risk=9 (high privilege)
  - country=RU → is_high_risk_country=1
  - error_code="" → is_denied=0
        │
        ▼
Trust Score Calculation (IEEE Eq.1)
  B (User Behavior) = 0 (3AM = very high risk)
  N (Network) = 15 (high-risk country)
  D (Device) = 70 (baseline)
  T (Threat History) = 50 (high-risk action)
  TS = 0.4×0 + 0.3×15 + 0.2×70 + 0.1×50 = 23.5 → normalized = 0.235
        │
        ▼
ML Ensemble Vote
  Random Forest  → ANOMALY (1)
  XGBoost        → ANOMALY (1)
  Isolation Forest → ANOMALY (isolated quickly = outlier)
  Ensemble votes = 3/3 → is_anomaly = True → TS adjusted to max 0.55
        │
        ▼
Zero Trust Decision (Jeong & Yang 2025, Page 14)
  TS = 0.235 < 0.30 → CRITICAL BLOCK
  Action: Session terminated. Admin alerted. IP flagged.
```

---

## Dashboard Features

1. Overview — Live stat cards, cloud counts, decision pie chart, trust score trend
2. Event Log — All events with filters (cloud, decision), trust score bars, ML vote icons
3. Alerts — All BLOCK + CRITICAL BLOCK events with full details
4. ML Models — Explanation of each model with IEEE citations

---

## Dashboard Login Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | ZeroTrust@2026 | Security Admin |
| srushti | srushti123 | Analyst |
| vishwajeet | vishwajeet123 | Analyst |

---

## Known Limitations (As Per Project Documentation)

1. Runs on localhost — not deployed on production cloud server
2. Lambda invoke needs Docker Desktop running
3. ML models retrain needed as new attack types appear
4. Device status (D factor) uses baseline 70 — no real endpoint agent
5. No actual MFA challenge sent — only recommends MFA
6. No automatic account suspension — classifies but does not disable IAM users

---

## Technologies Used

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11, Flask 3.1 |
| ML Models | scikit-learn, XGBoost |
| AWS Logs | boto3, AWS CloudTrail |
| Azure Logs | azure-identity, azure-mgmt-monitor |
| GCP Logs | google-cloud-logging |
| Frontend | HTML5, CSS3, Chart.js |
| Security | Werkzeug password hashing, Flask sessions |

---
Built with ❤️ at GHRCE Pune | B.Tech IT 2026
