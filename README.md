# CongoComply Agent

**Open source network monitoring agent for Congolese enterprises**

Developed by **SPV DIGITALE LUCEOR** — Thierry LOEMBA  
Ingénieur Civil des Mines de Paris | Cybersecurity Expert | ANSSI & CNPD Auditor

---

## Overview

CongoComply Agent is a lightweight network security agent based on the **Wireshark/libpcap engine**. It captures and analyzes network traffic in real time, detects fraud patterns, and sends certified alerts to the CongoComply cloud platform (Onkɔngɔ).

### Core Features

- **Wireshark Engine** — Real-time packet capture via libpcap/WinPcap
- **SIEM Engine** — Correlation rules for fraud detection
- **SHA-256 Certification** — Every alert is cryptographically signed (admissible as legal evidence under Art. 52, Loi 5-2025)
- **10-year log archiving** — Compliant with Congo's trusted third-party obligations
- **Cloud reporting** — Authenticated batch upload to Onkɔngɔ platform
- **Behavioral profiling** — Anonymized anomaly scoring

### Compliance

- 🇨🇬 Loi 5-2025 (CNPD — Personal Data Protection)
- 🇨🇬 Loi 26-2020 (ANSSI — Cybersecurity)
- 🌍 ITIE Standard 2023 (Mining sector)
- 🏦 COBAC regulations (Banking sector)

---

## Architecture

```
Network Traffic
      │
      ▼
┌─────────────────┐
│ Wireshark Engine│  ← libpcap / WinPcap
│  (Packet Capture)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   SIEM Engine   │  ← Fraud rules, anomaly detection
│  (Correlation)  │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐  ┌──────────────┐
│ Local │  │ Cloud Reporter│  → api.onkongo.cg
│Archive│  │  (HTTPS + JWT)│
│10 yrs │  └──────────────┘
└───────┘
```

---

## Modules

| Module | Description |
|--------|-------------|
| **Core** | Wireshark Engine + SIEM + Fraud Detection + Behavioral Profiling |
| **CC-DLP** | Data Loss Prevention — sensitive document monitoring |
| **CC-NDR** | Network Detection & Response — exfiltration detection |
| **CC-EDR** | Endpoint Detection & Response — workstation protection |
| **CC-IAM** | Identity & Access Management — critical system access control |
| **CC-VULN** | Vulnerability Scanner — exploitable flaw identification |
| **CC-AWARENESS** | Security Awareness — anti-fraud training reports |

---

## Sector-specific Detection Rules

- **Banking** — SWIFT anomaly detection, COBAC compliance
- **Mining** — ITIE data exfiltration detection, Code Minier Art. 78
- **Transport** — Ticketing fraud patterns
- **Healthcare** — Patient data protection (Loi 5-2025 Art. 18)
- **Telecom** — Subscriber data monitoring

---

## Installation

### Prerequisites

**Windows:**
```bash
# Install Npcap (WinPcap-compatible mode)
# https://npcap.com/#download
```

**Linux:**
```bash
sudo apt-get install libpcap-dev
```

### Build from source

```bash
git clone https://github.com/ThierryLoemba/congocomply-agent
cd congocomply-agent
go mod tidy
go build -o congocomply-agent ./cmd/agent
```

### Configuration

```bash
cp congocomply.yaml.example congocomply.yaml
# Edit with your tenant credentials
./congocomply-agent
```

---

## Configuration

```yaml
agent:
  tenant_id: "YOUR-TENANT-ID"
  org_name: "Your Organization"
  sector: "banque"        # banque|minier|transport|sante|telecom
  api_key: "cc_live_xxx"
  cloud_url: "https://api.onkongo.cg/v1"

modules:
  cc_dlp: true
  cc_ndr: true
  cc_edr: false
  cc_iam: false
  cc_vuln: false
  cc_awareness: false

archive:
  local_path: "./logs"
  retention_years: 10
  encrypt: true
```

---

## Legal & Compliance

This agent is designed to comply with:
- Republic of Congo **Loi 5-2025** on personal data protection
- Republic of Congo **Loi 26-2020** on cybersecurity
- All captured data remains on Congolese territory (MTN Data Center, Brazzaville)
- SHA-256 signed logs are admissible as digital evidence under Art. 52

---

## License

Apache License 2.0 — See [LICENSE](LICENSE)

---

## Author

**Thierry LOEMBA**  
Ingénieur Civil des Mines — École des Mines de Paris (2019)  
President, Congo Smart Mining (CSM)  
CEO, SPV DIGITALE LUCEOR  
📧 loemba@novatelcongo.com  
🌐 [congocomply.cg](https://congocomply.cg)
