# 🛡️ S3 Security Dashboard

## Overview
The **S3 Security Dashboard** is a cloud-native security monitoring and compliance tool designed to analyze, detect, and mitigate threats within AWS S3 environments. It provides an enterprise-grade solution that goes beyond static misconfiguration scanning by integrating **real-time threat detection** using AWS CloudTrail and EventBridge.  
This project demonstrates expertise in **cloud security engineering, event-driven automation, and AWS-native service orchestration**—key skills in modern cloud security roles.

---

## 🎯 Objectives
- Continuously monitor AWS S3 buckets for misconfigurations and risks.
- Detect and alert on real-time suspicious API activity via CloudTrail integration.
- Provide compliance posture visualization and detailed reporting.
- Enable automation for detection, response, and compliance workflows.

---

## 🧩 Core Features

### 1. S3 Bucket Security Scanning
- Automatically enumerates all S3 buckets.
- Detects:
  - Publicly accessible buckets.
  - Misconfigured ACLs and bucket policies.
  - Overly permissive IAM roles.
- Classifies issues by severity: **Low, Medium, High, Critical**.

### 2. Compliance & Policy Validation
- Maps findings to **CIS AWS Foundations** and best practices.
- Generates audit-ready compliance reports.
- Monitors historical improvement trends and compliance drift.

### 3. CloudTrail Threat Detection (Enterprise Feature)
- Integrates **AWS CloudTrail** and **EventBridge** for continuous monitoring.
- Detects suspicious actions such as:
  - Unauthorized `PutBucketPolicy` or `DeleteBucket` calls.
  - Bulk object deletions (`DeleteObject` bursts).
  - High-volume downloads or unusual access patterns.
- Uses **AWS Lambda** to process and evaluate event data.
- Sends immediate alerts via **SNS**, **Slack**, or **PagerDuty**.

### 4. Alerting & Notifications
- Delivers real-time alerts when critical events are detected.
- Supports multiple channels: SNS, Slack, Email, PagerDuty.
- Alert payload includes:
  - User identity (ARN)
  - IP and region
  - Event type
  - Resource affected
  - Severity and timestamp

### 5. Security Posture Visualization
- Centralized dashboard displays:
  - Total S3 buckets analyzed.
  - Secure vs. vulnerable resources.
  - Detected threats by severity.
  - Compliance score and trend charts.
- Optional **risk scoring engine** for contextual prioritization.

### 6. Optional Advanced Features
- **Automated Remediation (IaC):**
  - Generates Terraform/CloudFormation templates to fix misconfigurations.
  - Opens automated pull requests for review.
  - Integrates with AWS Systems Manager to apply fixes.
- **Sensitive Data Discovery (DLP):**
  - Uses **AWS Macie** or custom pattern matching to detect sensitive data.
  - Identifies PII, PHI, and API keys.
  - Visualizes sensitive data exposure and risk heatmaps.

---

## 🧠 Technical Stack

| Layer | Technology | Purpose |
|-------|-------------|----------|
| **Frontend** | React / Next.js | Interactive dashboard UI |
| **Backend API** | FastAPI (Python) | RESTful backend and data logic |
| **AWS SDK** | Boto3 | AWS service integration |
| **Database** | PostgreSQL / DynamoDB | Store scan history and alerts |
| **Event Processing** | Lambda + EventBridge | Real-time detection logic |
| **Monitoring** | CloudTrail | Logs all AWS API calls |
| **Alerting** | SNS / Slack Webhooks | Pushes notifications instantly |

---

## 🧰 Prerequisites
- AWS account with:
  - S3, CloudTrail, Lambda, EventBridge, SNS access.
- IAM user/role with administrative privileges for the above services.
- Python 3.9+ and Node.js 18+ installed.
- AWS CLI configured with valid credentials.

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/s3-security-dashboard.git
cd s3-security-dashboard
```

### 2. Environment Configuration
```bash
# Create an .env file with the following variables
AWS_ACCESS_KEY_ID=<your-access-key>
AWS_SECRET_ACCESS_KEY=<your-secret-key>
AWS_DEFAULT_REGION=<your-region>
SLACK_WEBHOOK_URL=<your-slack-webhook-url>
```

### 3. Install Dependencies
```bash
# Backend Dependencies
pip install -r requirements.txt

# Frontend Dependencies
npm install
```

### 4. Deploy AWS Resources
- Enable **CloudTrail** logging for all S3 API calls.
- Create **EventBridge rules** for suspicious API event filtering.
- Deploy **Lambda functions** to handle incoming CloudTrail events.
- Configure **SNS** or **Slack** alert destinations.

### 5. Launch Application
```bash
# Start Backend
uvicorn main:app --reload

# Start Frontend
npm run dev
```
Access dashboard locally at **http://localhost:3000**

---

## 🧾 Example Detection Flow
- **CloudTrail** logs every API call.
- **EventBridge** filters for events such as:
  - `DeleteBucket`
  - `PutBucketPolicy`
  - `DeleteObject`
- **Lambda** processes these logs and evaluates:
  - IP origin
  - User role legitimacy
  - Access frequency
- If suspicious, **SNS/Slack** alert is triggered instantly.

**Architecture Flow:**
```
CloudTrail → EventBridge → Lambda → SNS/Slack → Dashboard
```

**Example Alert Message:**
```
🚨 [CRITICAL] Suspicious S3 Activity Detected!
Event: DeleteBucket
User: arn:aws:iam::123456789012:user/unknown-user
IP: 45.12.67.89 | Region: us-east-1
Bucket: confidential-data
Time: 2025-11-06T03:41:22Z
```

---

## 📊 Dashboard Metrics
- Total Buckets Scanned
- Vulnerable vs. Secure Buckets
- Threat Events by Severity
- Recent Alerts Timeline
- Compliance Score (in %)
- Risk Trend Over Time

---

## 🧩 Future Enhancements
- Extend support to **Azure Blob** and **GCP Cloud Storage**.
- Integrate **AWS GuardDuty** for enriched threat intelligence.
- Implement **AI-based anomaly detection** using ML.
- Add **Role-Based Access Control (RBAC)** for multi-user dashboards.
- Enable **automated incident response playbooks**.

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
                     │ Dashboard UI       │
                     │ (Visualizes        │
                     │ Findings & Threats)│
                     └────────────────────┘
```

---

## 🏆 Key Highlights
- Built **real-time cloud threat detection** using AWS-native components.
- Designed **event-driven Lambda pipelines** for live monitoring.
- Implemented **risk-based prioritization** and compliance mapping.
- Achieved **end-to-end cloud security observability** in a single dashboard.

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

⭐ **If this project helped you, consider giving it a star and sharing it with other cloud security enthusiasts!**
