# Securthy — Healthcare Network Security Platform

> ISO 27001:2022 compliance assessment for Algerian hospital networks

---

## What is Securthy?

Securthy is a modular cybersecurity platform built specifically for Algerian hospitals. It scans hospital networks and employees, scores findings against ISO 27001:2022, encrypts reports, and sends them to the platform. After viewing results, the hospital purchases a remediation pack that automatically applies fixes.

---

## Architecture

Scanner (on-site)          Platform (cloud)
┌─────────────────┐        ┌──────────────────┐
│  securthy (GUI) │        │  FastAPI backend  │
│  scanner_bin    │──SEC──▶│  decrypt + save   │
│  employee_bin   │        │  dashboard        │
└─────────────────┘        └──────────────────┘
↓ (after purchase)
┌─────────────────┐
│  packs_bin      │ ← downloaded separately
│  applies fixes  │
└─────────────────┘  ---

## Modules

### 1. Scanner (free, installed from platform)
- TCP/UDP port scan — 25 healthcare-specific ports
- Protocol probes — DICOM, HL7, FHIR, SMB, RDP, SNMP, Telnet, FTP
- CVE matching — 25+ healthcare CVEs
- Employee scan — phishing, password, WiFi, email, privilege
- ISO 27001 scoring — 5 network domains + 9 human controls
- Encrypted report — AES-256-GCM, sent to platform automatically

### 2. Remediation Packs (purchased on platform)
| Pack | Price (DZD) | Duration | ISO boost |
|------|------------|----------|-----------|
| Essentiel | 150k – 250k | 3-5 days | +27 pts |
| Sécurité | 400k – 600k | 3-4 weeks | +50 pts |
| Conformité | 1M – 1.5M | 2-3 months | +67 pts |

### 3. Hospital Simulator
12-device fake hospital network for demo and testing. Runs on loopback IPs with real protocol handlers — DICOM, HL7, FTP, SMB, RDP, SNMP, FHIR.

---

## Report Files

| File | Audience | Content |
|------|----------|---------|
| `report.txt` | Technician on-site | Teaser — score + 3 sample findings + platform CTA |
| `report.sec` | Platform only | Full encrypted report — AES-256-GCM |
| `report.json` | API/backend | Full machine-readable data |
| `targets.json` | Pack engine | IPs classified for remediation |

---

## Build

```bash
go mod tidy

go build -o scanner_bin       ./cmd/
go build -o employee_bin      ./employee/
go build -o employee_packs_bin ./employee_packs/
go build -o api_bin           ./api/
go build -o securthy          ./gui/

# Pack binary — tier baked in at build time
go build -ldflags "-X main.AllowedTier=essentiel" -o packs_bin ./packs/
```

---

## Run (Demo)

```bash
# Terminal 1 — hospital simulator
sudo /usr/local/go/bin/go run ./simulator

# Terminal 2 — launch GUI
./securthy
# → [3] Full Assessment → enter 127.0.0.0/24
```

---

## Security Model

- Reports encrypted with AES-256-GCM before leaving the machine
- `.sec` file unreadable without platform key
- `packs_bin` has tier + license baked in — cannot run without platform authorization
- No license key needed at runtime — everything compiled in

---

## Stack

- **Scanner:** Go 1.22 — goroutines, no external runtime
- **Encryption:** AES-256-GCM via Go standard library
- **SSH client:** golang.org/x/crypto/ssh
- **Platform:** FastAPI (Python) + PostgreSQL
- **Protocol support:** DICOM, HL7/MLLP, FHIR R4, SMB2, WinRM

---

## ISO 27001 Coverage

**Network:** A.9 · A.10 · A.12 · A.13 · A.14  
**Human:** A.6.3.1 · A.5.17 · A.8.20 · A.8.23 · A.5.15 · A.5.18 · A.8.12

---

*Built for CHU and public hospital networks in Algeria — DEM/FHIR/DICOM/HL7 aware.*
