# 🛡️ S3 Security Dashboard

## Overview
The **S3 Security Dashboard** is a Python-based cloud security tool that analyzes and monitors AWS S3 configurations, integrates with CloudTrail for real-time threat detection, and provides a simple FastAPI-powered interface for visualizing audit results and alerts.  
It highlights hands-on expertise in **AWS security monitoring**, **event-driven architecture**, and **cloud threat detection automation** — representing the core skills of a Cloud Security Engineer.

---

## 🎯 Objectives
- Continuously audit AWS S3 buckets for misconfigurations and public access issues.  
- Detect real-time suspicious API activity using AWS CloudTrail, EventBridge, and Lambda.  
- Visualize audit results and threat alerts through a clean, lightweight dashboard.  
- Automate detection and alerting pipelines with minimal manual intervention.

---

## 🧩 Core Features

### 1. S3 Bucket Security Scanning
- Scans all AWS S3 buckets within an account.  
- Identifies:
  - Publicly accessible buckets.  
  - Insecure ACLs or overly permissive bucket policies.  
  - Cross-account access permissions.  
- Assigns risk severity levels to each issue: **Low, Medium, High, Critical.**

### 2. Compliance & Policy Validation
- Maps findings to **AWS CIS Foundations Benchmark** and best security practices.  
- Generates simple compliance reports showing which buckets fail or pass key checks.  
- Enables organizations to track misconfigurations and maintain security hygiene.

### 3. Real-Time CloudTrail Threat Detection
- Integrates **AWS CloudTrail** and **EventBridge** for continuous monitoring of S3 events.  
- Detects and flags abnormal actions such as:
  - Unauthorized `PutBucketPolicy` or `DeleteBucket` calls.  
  - Mass object deletions (`DeleteObject` in short bursts).  
  - Large-scale downloads from unfamiliar IPs or regions.  
- **AWS Lambda** processes these events and triggers alerts.  
- Alerts are pushed instantly through **AWS SNS**, **Slack**, or **Email**.

**Architecture Flow:**
```
CloudTrail → EventBridge → Lambda → SNS/Slack → Dashboard
```

### 4. Alerting & Notifications
- Sends immediate alerts when suspicious activity is detected.  
- Alerts contain:
  - Event name and type.  
  - User identity (ARN).  
  - IP address and region.  
  - Bucket name and timestamp.  
- Supports multiple channels for flexibility (Slack, SNS, or direct email).

### 5. Dashboard & Visualization
- Built using **FastAPI** and **Jinja2 templates**.  
- Displays:
  - Bucket scan results and compliance summary.  
  - Threat alerts with timestamps and metadata.  
  - Summary of overall security posture.  
- Lightweight, fast, and easily deployable on any cloud instance.

### 6. Optional Advanced Enhancements
- **Auto-Remediation Hooks:**
  - Generate Terraform or CloudFormation templates for misconfigurations.  
  - Optionally integrate with AWS Systems Manager for automatic fixes.  
- **Sensitive Data Discovery:**
  - Uses **AWS Macie** or regex-based detection for PII, API keys, or credentials.  
  - Highlights exposed or sensitive data in public buckets.

---

## 🧠 Technical Stack

| Layer | Technology | Purpose |
|-------|-------------|----------|
| **Frontend** | FastAPI + Jinja2 Templates | Simple and fast web UI for results visualization |
| **Backend** | Python (FastAPI) | Core logic for scanning, detection, and AWS integration |
| **AWS SDK** | Boto3 | Communication with AWS S3, CloudTrail, SNS, EventBridge, and Lambda |
| **Event Processing** | AWS Lambda + EventBridge | Handles live event-driven threat detection |
| **Monitoring** | AWS CloudTrail | Captures and forwards all S3 API activity for analysis |
| **Alerting** | AWS SNS / Slack Webhooks | Sends notifications for detected security threats |

---

## 🧰 Prerequisites
- AWS account with permissions for:
  - S3, CloudTrail, Lambda, EventBridge, SNS.  
- AWS CLI configured locally with valid credentials.  
- Python 3.9+ installed on your system.  
- Optional: Slack webhook URL for alert notifications.

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/SanayKrishna/CloudScanner.git
cd CloudScanner
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory:
```bash
AWS_ACCESS_KEY_ID=<your-access-key>
AWS_SECRET_ACCESS_KEY=<your-secret-key>
AWS_DEFAULT_REGION=<your-region>
SLACK_WEBHOOK_URL=<your-slack-webhook-url>
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Deploy AWS Components
- Enable **CloudTrail** to log all S3 events.  
- Create **EventBridge rules** to capture important API calls.  
- Deploy **Lambda functions** for event analysis.  
- Configure **SNS or Slack** for alert delivery.

### 5. Run the Dashboard
```bash
uvicorn main:app --reload
```
Access it locally at **http://localhost:8000**

---

## 🧾 Example Threat Event
Sample CloudTrail event triggering an alert:
```json
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteBucket",
  "userIdentity": { "arn": "arn:aws:iam::123456789012:user/unknown-user" },
  "sourceIPAddress": "45.12.67.89",
  "awsRegion": "us-east-1",
  "eventTime": "2025-11-06T03:41:22Z"
}
```

Alert Example:
```
🚨 [CRITICAL] Suspicious DeleteBucket Activity Detected
User: unknown-user
IP: 45.12.67.89 | Region: us-east-1
Bucket: confidential-data
Time: 2025-11-06T03:41:22Z
```

---

## 📊 Dashboard Metrics
- Total Buckets Scanned  
- Public vs Private Buckets  
- Threat Events by Severity  
- Recent Alerts  
- Compliance Summary  

---

## 🧩 Future Enhancements
- Add **multi-cloud support** for Azure Blob & GCP Cloud Storage.  
- Integrate **AWS GuardDuty** for threat correlation.  
- Enable **AI-driven anomaly detection** for behavioral analysis.  
- Add **RBAC (Role-Based Access Control)** for dashboard access.  
- Implement **automated remediation workflows** via AWS Lambda.

---

## 🏗️ Architecture Diagram
```
                ┌──────────────────────────────┐
                │        CloudTrail            │
                │  (Logs All S3 API Events)    │
                └──────────────┬───────────────┘
                               │
                        ┌──────▼───────┐
                        │ EventBridge  │
                        │ (Filters Key │
                        │  Suspicious  │
                        │   Events)    │
                        └──────┬───────┘
                               │
                     ┌─────────▼─────────┐
                     │ AWS Lambda        │
                     │ (Analyzes Events, │
                     │ Triggers Alerts)  │
                     └─────────┬─────────┘
                               │
                   ┌───────────▼───────────┐
                   │ SNS / Slack / Email   │
                   │ (Real-Time Alerts)    │
                   └───────────┬───────────┘
                               │
                     ┌─────────▼─────────┐
                     │ S3 Security        │
                     │ Dashboard (FastAPI)│
                     │ (Visualizes        │
                     │ Findings & Threats)│
                     └────────────────────┘
```

---

## 🏆 Key Highlights
- 100% **AWS-native**, no external dependencies or databases.  
- Implements **event-driven detection** and **automated alerting** pipelines.  
- Simple yet powerful **FastAPI-based dashboard**.  
- Demonstrates **real-world cloud security engineering** and **SOC-style detection logic**.  
- Focused on **visibility, automation, and hands-on AWS defense.**

---

## 👨‍💻 Author
**Mochi**  
🎓 Student & Aspiring Cloud Security Engineer  
📍 Bangalore, India  
🔗 [LinkedIn](#) | [GitHub](#)

---

## 📜 License
Licensed under the **MIT License**.  
See [LICENSE](LICENSE) for full details.

---

⭐ **If you found this project useful or inspiring, drop a star and share it with fellow cloud security enthusiasts!**
