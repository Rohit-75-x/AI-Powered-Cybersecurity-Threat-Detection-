# 🛡️ AI-Powered Cybersecurity Threat Detection System
### Enterprise SOC Intrusion Detection, Anomaly Scoring & Cyber Warfare Simulation Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![Model Architecture](https://img.shields.io/badge/Architecture-Dual--Engine%20(RF%20%2B%20IsolationForest)-green.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-red.svg)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

---

## 📌 Executive Summary

Modern Security Operations Centers (SOCs) are overwhelmed by thousands of security alerts daily, with up to **80% representing false positives or alert fatigue**. Traditional signature-based Intrusion Detection Systems (like standard Snort or Suricata rulebases) fail when confronted with polymorphic malware, distributed denial-of-service (DDoS) variants, and zero-day data exfiltration tactics.

The **AI-Powered Cybersecurity Threat Detection System** bridges this critical gap. Engineered as a production-ready, industry-oriented platform, it combines:
1. **Supervised Attack Classification (`RandomForestClassifier`)** for high-precision identification of known threat vectors (DoS, Port Scans, SSH/FTP Brute Force, Exfiltration).
2. **Unsupervised Anomaly Outlier Detection (`IsolationForest`)** trained strictly on benign baseline telemetry to surface zero-day attacks and stealth anomalies without relying on prior signatures.
3. **Automated SOC Triage & Risk Scorer (0 - 100)** mapping all alerts to **MITRE ATT&CK Tactics & Techniques**, assigning severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and issuing immediate mitigation playbooks.
4. **Real-Time Flask REST API & Attack Stream Simulator** for streaming telemetry ingestion and incident response automation.

---

## 🏗️ System Architecture

```text
       +------------------------------------------------------------------+
       |               LIVE NETWORK TELEMETRY INGESTION                   |
       |  (Packet Stream / NetFlow / PCAP / Simulated Attack Generators)  |
       +------------------------------------------------------------------+
                                        │
                                        ▼
       +------------------------------------------------------------------+
       |             PREPROCESSING & FEATURE PIPELINE                     |
       |  - Categorical Label Encoding (Protocol, Service, Flag)          |
       |  - StandardScaler Normalization (Bytes, Duration, Window Counts) |
       +------------------------------------------------------------------+
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼                                             ▼
+---------------------------------+           +---------------------------------+
|   SUPERVISED CLASSIFIER         |           |   UNSUPERVISED ANOMALY ENGINE   |
|   (Random Forest Classifier)    |           |   (Isolation Forest Detector)   |
|   - Multi-Class Attack Taxonomy |           |   - Baseline Inlier/Outlier     |
|   - Predicts Specific Attack    |           |   - Zero-Day Anomaly Distance   |
|   - Confidence Score (0-100%)   |           |   - Unsupervised Decision Score |
+---------------------------------+           +---------------------------------+
                 │                                             │
                 └──────────────────────┬──────────────────────┘
                                        ▼
       +------------------------------------------------------------------+
       |                 SOC INCIDENT CORRELATION ENGINE                  |
       |  - Multi-Factor Risk Score Calculation (0 - 100)                 |
       |  - Severity Tiers: CRITICAL / HIGH / MEDIUM / LOW / INFO         |
       |  - MITRE ATT&CK Mapping (T1498, T1046, T1110, T1048, T1204)     |
       |  - Automated Remediation Playbooks (BLOCK_IP, DROP_PORT, etc.)   |
       +------------------------------------------------------------------+
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼                                             ▼
+---------------------------------+           +---------------------------------+
|      REST API MICROSERVICE      |           |     SOC ANALYTICS & AUDIT       |
|      (Flask Server :5000)       |           |     (Visual Dashboards & Logs)  |
|   - POST /api/v1/detect         |           |   - Multi-Class Confusion Matrix|
|   - POST /api/v1/batch-detect   |           |   - Outlier Anomaly Separations |
|   - GET  /api/v1/simulate       |           |   - Audit CSV & JSON Event Logs |
+---------------------------------+           +---------------------------------+
```

---

## 🎯 Threat Detection Taxonomy & MITRE ATT&CK Matrix

| Threat Category | MITRE Tactic | Technique ID | Technique Name | Network Indicators | Automated SOC Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Normal** | N/A | N/A | Benign Enterprise Activity | SF connection flag, normal packet sizes, 0 failed logins | `ALLOW` |
| **DoS** | Impact | `T1498` | Network Denial of Service | S0 flag flood, >250 conns/2s, 0 bytes returned | `BLOCK_IP_RATE_LIMIT` |
| **PortScan** | Discovery | `T1046` | Network Service Discovery | Scanning multiple service ports, high `diff_srv_rate`, REJ flags | `QUARANTINE_PORT_DROP` |
| **BruteForce** | Credential Access | `T1110` | Brute Force Authentication | >3 failed logins, repeated auth hits on SSH/FTP/RDP | `LOCK_ACCOUNT_BLOCK_SRC` |
| **DataExfiltration** | Exfiltration | `T1048` | Exfil Over Alternative Protocol | Outbound payload bytes > 500 KB, elevated duration | `TERMINATE_SESSION_ALERT_SOC` |
| **ZeroDayAnomaly** | Defense Evasion | `T1204` | Statistical Outlier Anomaly | Unsupervised Isolation Forest score < -0.10 | `ISOLATE_HOST_SOC_TRIAGE` |

---

## 📊 Model Performance Benchmarks

Evaluated on holdout test network traffic telemetry ($N = 3,000$ independent connection flows):

| Metric | Random Forest (Supervised) | Isolation Forest (Zero-Day Anomaly) |
| :--- | :--- | :--- |
| **Multi-Class Accuracy** | **100.00%** | N/A (Unsupervised) |
| **Weighted F1-Score** | **100.00%** | N/A |
| **Threat Detection Recall** | **100.00%** | **100.00%** (Attack coverage) |
| **Threat Precision** | **100.00%** | 86.39% |
| **Inference Latency** | **< 1.8 ms / packet** | **< 0.9 ms / packet** |

---

## 📈 Visual Analytics & Proof Assets

The system automatically generates publication-grade analytics under `images/` and `outputs/`:

### 1. Executive SOC Threat Intelligence Dashboard
![SOC Dashboard](images/soc_threat_landscape.png)
*Figure 1: Comprehensive 4-panel dashboard displaying traffic category distribution, per-class model accuracy, risk score distribution, and incident triage by severity tier.*

### 2. Multi-Class Confusion Matrix Heatmap
![Confusion Matrix](images/confusion_matrix.png)
*Figure 2: Confusion matrix showing zero false negatives across Normal, DoS, PortScan, BruteForce, and DataExfiltration.*

### 3. Feature Importance Ranking
![Feature Importance](images/feature_importance.png)
*Figure 3: Top network features identified by Gini importance (serror_rate, count, src_bytes, diff_srv_rate).*

### 4. Unsupervised Anomaly Distribution
![Anomaly Distribution](images/anomaly_distribution.png)
*Figure 4: Clear decision boundary separation between benign network baselines and malicious outliers.*

---

## 📂 Project Structure

```text
AI-Cybersecurity-Threat-Detection/
├── data/
│   ├── raw/                      # Ingested & benchmark traffic CSVs
│   ├── processed/                # Normalized, scaled feature matrices
│   └── test_streams/             # Cyber warfare simulation attack streams
├── docs/
│   ├── MITRE_ATTACK_MAPPING.md   # Threat taxonomy & incident response matrix
│   └── INTERVIEW_PREP.md         # 10+ SOC & ML interview questions with answers
├── images/                       # High-resolution charts for GitHub proof
├── models/                       # Serialized .joblib model artifacts & scalers
├── notebooks/                    # Jupyter notebooks for interactive analysis
├── outputs/                      # Generated evaluation metrics, logs & plots
│   ├── classification_report.txt # Per-class precision, recall, and F1 scores
│   ├── evaluation_metrics.json   # Machine-readable benchmarks
│   ├── soc_alerts.csv            # Structured SOC incident event log
│   └── soc_alerts.json           # JSON lines security audit trail
├── src/
│   ├── __init__.py               # Package marker
│   ├── config.py                 # Hyperparameters, paths & MITRE rules
│   ├── data_loader.py            # Dataset generator & benchmark loader
│   ├── preprocessor.py           # Feature scaling, encoding & pipeline persistence
│   ├── models.py                 # Dual-Engine (Random Forest + Isolation Forest)
│   ├── train.py                  # Training pipeline, cross-validation & metrics
│   ├── alert_system.py           # SOC risk scorer, severity tiers & alert logger
│   ├── simulator.py              # Virtual cyber attack simulation engine
│   └── visualizer.py             # 4 publication-quality visualization generators
├── app.py                        # Production Flask REST API for real-time monitoring
├── run_pipeline.py               # Master single-command autonomous pipeline runner
├── requirements.txt              # Pinned Python package dependencies
├── .env.example                  # Environment variable configuration template
├── .gitignore                    # Git hygiene exclusion rules
└── README.md                     # Comprehensive documentation
```

---

## ⚡ Quickstart Guide

### 1. Clone & Set Up Environment

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/AI-Cybersecurity-Threat-Detection.git
cd AI-Cybersecurity-Threat-Detection

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Mac / Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Autonomous Master Pipeline (One Command)

Executes data generation, preprocessing, model training, evaluation, plot generation, and threat simulation in ~5 seconds:

```bash
python run_pipeline.py
```

Expected Terminal Output:
```text
===========================================================================
      AI-POWERED CYBERSECURITY THREAT DETECTION SYSTEM       
        SOC End-to-End Autonomous Pipeline Execution         
===========================================================================

[STEP 1/3] Running Data Pipeline, Preprocessing & Dual-Engine Training...
[SUCCESS] Trained models serialized to models/
[METRICS] Multi-Class Accuracy:      100.00%
[METRICS] Threat Detection Recall:   100.00%

[STEP 2/3] Generating High-Resolution SOC Analytics & Charts...
[SUCCESS] Dashboard saved to outputs/soc_threat_landscape.png

[STEP 3/3] Launching Real-World Cyber Attack Stream Simulation...
[STREAM EVENT 2/5] Simulating Scenario: SYN Flood DDoS Attack
+------------------------------------------------------------------+
| [!] SOC SECURITY ALERT TRIGGERED - ID: INC-20261016093323-183     |
+------------------------------------------------------------------+
| Severity:       CRITICAL        Risk Score: 100/100              |
| Threat Type:    DoS                  Confidence: 98.3%           |
| Source -> Dest: 45.134.20.12 -> 10.0.0.1                         |
| MITRE ATT&CK:   [T1498] Network Denial of Service                |
| SOC Action:     BLOCK_IP_RATE_LIMIT                              |
+------------------------------------------------------------------+
[PIPELINE COMPLETE] All tasks succeeded in 5.12 seconds!
```

---

## 🌐 Production REST API Usage

Start the REST API microservice:
```bash
python app.py
```
Server starts at `http://127.0.0.1:5000`.

### Real-Time Packet Threat Classification:
**Request:**
```bash
curl -X POST http://127.0.0.1:5000/api/v1/detect \
     -H "Content-Type: application/json" \
     -d '{
       "duration": 0.02,
       "protocol_type": "tcp",
       "service": "http",
       "flag": "S0",
       "count": 450,
       "serror_rate": 0.98,
       "source_ip": "45.134.20.12",
       "dest_ip": "10.0.0.1"
     }'
```

**Response (`HTTP 200 OK`):**
```json
{
  "success": true,
  "threat_detected": true,
  "alert": {
    "incident_id": "INC-20261016093510-183",
    "timestamp": "2026-10-16T09:35:10.124Z",
    "source_ip": "45.134.20.12",
    "destination_ip": "10.0.0.1",
    "threat_classification": "DoS",
    "risk_score": 100,
    "severity": "CRITICAL",
    "model_confidence": 0.9833,
    "is_statistical_anomaly": true,
    "mitre_attack": {
      "tactic": "Impact",
      "technique_id": "T1498",
      "technique_name": "Network Denial of Service"
    },
    "soc_recommended_action": "BLOCK_IP_RATE_LIMIT"
  }
}
```

---

## 🎓 Recruiter & Interview Highlights

- **Dual-Engine Innovation**: Most student projects only do a standard Decision Tree or Logistic Regression. This system pairs **Supervised Multi-Class Classification** with an **Unsupervised Anomaly Detector**, demonstrating practical understanding of handling zero-day exploits.
- **Enterprise SOC Integration**: Implements realistic Risk Scoring (0 - 100), severity escalation, and direct mapping to the **MITRE ATT&CK Framework**.
- **Data Leakage Prevention**: Encoders and standard scalers are fitted strictly on the training partition and persisted via `joblib` for identical runtime inference.
- **Microservice Ready**: Clean REST API with CORS support, batch processing, and health checks ready for containerization in Docker/Kubernetes.

---

## 📜 License & Author

- **Author**: Rohit – Cybersecurity & AI/ML Specialist
- **License**: MIT Open Source License
