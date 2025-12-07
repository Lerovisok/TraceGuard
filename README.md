# TraceGuard – Detect C2 Evasion Techniques (DNS Tunneling, Fast Flux, DGA & More)

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green)]

> 🔍 **Detect modern command-and-control (C2) evasion tactics used by malware in 2025**  
> Built for SOC analysts, threat hunters, and network defenders.

**TraceGuard** is an open-source tool that analyzes network logs to detect advanced C2 techniques, including:
- **DNS Tunneling** (data exfiltration over DNS)
- **Fast Flux DNS** (Single & Double Flux)
- **Domain Generation Algorithms (DGAs)**
- **SSL/TLS C2 abuse** (e.g., Let’s Encrypt on malicious domains)
- **Cloud service abuse** (GitHub Pages, Firebase, Azure)

All detections are mapped to **MITRE ATT&CK** and designed for **defensive cybersecurity only**.

> 📚 **Want to understand how these evasion techniques work?**  
> Read our in-depth technical guide:  
> [How Hackers Erase Traces Using DNS Tunneling, SSL/TLS, and Fast Flux (2025)](https://data-encoder.com/hackers-erase-traces-with-dns-tunneling-ssl-tls-fast-flux-etc/)

---

## 🔧 Features

- Parses **Zeek (Bro) `dns.log` and `ssl.log`** files
- Detects 5+ evasion methods with configurable thresholds
- Outputs clean **JSON alerts** (ready for SIEM integration)
- No internet required – runs offline for privacy
- Fully open-source and MIT licensed

---

## 🚀 Quick Start

```bash
git clone https://github.com/yourname/traceguard.git
cd traceguard
pip install -r requirements.txt
python traceguard.py config.yaml
