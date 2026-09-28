**AI-Powered Multi-Cloud Anomaly Detection & Zero Trust Enforcement System
Problem

Modern organizations use AWS, Azure and GCP, generating large volumes of heterogeneous security logs. Different cloud platforms use different log formats and structures, making centralized monitoring, anomaly detection and security response difficult.

Proposed Solution

We propose an AI-powered multi-cloud security framework that collects and standardizes cloud security events from AWS, Azure and GCP and uses machine learning to detect anomalous activities.
Working
AWS / Azure / GCP Logs
          ↓
   Log Collection & Pre-processing
          ↓
     Feature Extraction
          ↓
   AI Anomaly Detection
          ↓
     Risk / Trust Score
          ↓
     Zero Trust Engine
          ↓
 ALLOW / MFA / BLOCK / ALERT

 AI/ML Approach

The system uses an ensemble of:

Random Forest
XGBoost
Isolation Forest

The models analyze factors such as:

User activity
Login time
Source IP/location
Cloud action
Failed/denied operations
Historical behavior
Network/device-related risk

The ensemble result is combined with contextual security factors to generate a trust/risk score and security decision.

Key Features
Multi-cloud monitoring across AWS, Azure and GCP
AI-based anomaly detection
Continuous risk/trust assessment
Zero Trust decision-making
Real-time security dashboard
Event filtering and alert generation
Raw event and security-event analysis
Extensible architecture for additional log sources
Docker/container-ready architecture
Designed for integration with SIEM and future ULPF-based log normalization
Zero Trust Response
Normal Activity       → ALLOW
Suspicious Activity   → MFA REQUIRED
High Risk             → BLOCK
Critical Risk         → BLOCK + ALERT
Technology Stack

Backend: Python, Flask
Cloud: AWS CloudTrail, Azure Monitor, GCP Cloud Audit Logs
ML: Scikit-learn, XGBoost
Frontend: HTML, CSS, Chart.js
Security: IAM, Zero Trust, session-based authentication
Deployment: Docker-ready

Expected Impact

The system provides a unified security layer for multi-cloud environments, reduces dependency on cloud-specific monitoring logic, enables AI-driven anomaly detection, and supports automated Zero Trust security decisions.

Future Scope
Universal Log Pre-processing Framework (ULPF)
Support for firewall, router, IDS/IPS and other perimeter-device logs
Universal event schema
SIEM/Data Lake integration
Real-time distributed log processing
Automated incident response
Air-gapped deployment
