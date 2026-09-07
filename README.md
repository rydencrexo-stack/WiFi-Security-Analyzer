# WiFi-Security-Analyzer
Advanced Wi-Fi Security Analyzer for authorized network assessment, featuring security risk scoring, BSSID discovery, channel analysis, baseline monitoring, anomaly detection, scan history, and automated security reports.

## 📌 Project Overview

Wi-Fi Security Analyzer is a defensive cybersecurity tool designed to provide visibility into nearby wireless networks and help identify potentially insecure configurations.

The tool analyzes available Wi-Fi networks, evaluates their security configuration, calculates a risk score, monitors changes against a trusted baseline, and generates security reports.

It is designed for cybersecurity learning, authorized assessments, and controlled lab environments.

## ⚙️ How It Works

```text
Wi-Fi Environment
       ↓
Network Discovery
       ↓
Data Parsing
       ↓
Security Analysis
       ↓
Risk Scoring
       ↓
Baseline Comparison
       ↓
Alerts & Recommendations
       ↓
Security Reports

```

### 3. Risk Levels

```markdown
## 🚦 Risk Levels

| Risk Level | Description |
|---|---|
| 🟢 LOW | Stronger wireless security configuration detected |
| 🟡 MEDIUM | Configuration may require security improvements |
| 🔴 HIGH | Potentially insecure configuration detected |

> Risk scores are security-awareness indicators and should not be considered a replacement for a complete professional security audit.
```

## 📂 Generated Files

The application can generate the following local files:

| File | Purpose |
|---|---|
| `wifi_security.db` | Local scan history database |
| `wifi_baseline.json` | Trusted network baseline |
| `wifi_report.json` | Machine-readable security report |
| `wifi_report.csv` | Spreadsheet-compatible report |
| `wifi_report.html` | Browser-viewable security report |

These generated files are excluded from GitHub using `.gitignore`.

## 🏗️ Security Architecture

```text
┌───────────────────────────────┐
│       Windows Wi-Fi API       │
│            netsh              │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       Network Parser          │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       Security Engine         │
│  Authentication + Encryption  │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│        Risk Engine             │
│       Risk Score 0–100         │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│     Baseline & Monitoring      │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       Reports & History        │
└───────────────────────────────┘
```


### 6. Screenshots

This makes the GitHub page look much better once you have screenshots:

## 🖼️ Screenshots

```markdown


### Wi-Fi Network Scan

_Add screenshot here_
```

## ⚠️ Disclaimer

This project is developed for educational purposes, cybersecurity research, authorized security assessments, and controlled laboratory environments.

Only scan networks that you own or have explicit permission to assess.

The author is not responsible for misuse, unauthorized monitoring, or any activity performed outside the scope of authorization.

