import yaml
import json
import sys
import os
from collections import defaultdict
from parsers.zeek_parser import parse_zeek_dns, parse_zeek_ssl
from detectors.dns_tunneling import detect_dns_tunneling
from detectors.fast_flux import detect_fast_flux
from detectors.dga import detect_dga
from detectors.tls_c2 import detect_tls_c2
from detectors.cloud_abuse import detect_cloud_abuse

def main():
    if len(sys.argv) != 2:
        print("Usage: python traceguard.py <config.yaml>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        config = yaml.safe_load(f)

    alerts = []

    # Parse DNS logs
    dns_records = parse_zeek_dns("examples/dns.log")
    dns_by_domain = defaultdict(list)
    for rec in dns_records:
        domain = rec.get("query", "")
        dns_by_domain[domain].append(rec)
        # Check DNS tunneling per record
        if detect_dns_tunneling(rec, config):
            alerts.append({
                "type": "DNS_TUNNELING",
                "source_ip": rec.get("id.orig_h"),
                "domain": domain,
                "record_type": rec.get("qtype_name"),
                "mitre": "T1071.004"
            })
        # Check DGA
        if detect_dga(domain.split(".")[0], config):
            alerts.append({
                "type": "SUSPECTED_DGA",
                "domain": domain,
                "mitre": "T1568.002"
            })
        # Check Cloud Abuse
        if detect_cloud_abuse(domain):
            alerts.append({
                "type": "CLOUD_C2_ABUSE",
                "domain": domain,
                "mitre": "T1568.001"
            })

    # Check Fast Flux per domain
    for domain, records in dns_by_domain.items():
        if detect_fast_flux(records, config):
            alerts.append({
                "type": "FAST_FLUX",
                "domain": domain,
                "ip_count": len(set(r.get("id.resp_h") for r in records)),
                "mitre": "T1568"
            })

    # Parse SSL logs
    ssl_records = parse_zeek_ssl("examples/ssl.log")
    for rec in ssl_records:
        if detect_tls_c2(rec, config):
            alerts.append({
                "type": "TLS_C2_SUSPICIOUS",
                "source_ip": rec.get("id.orig_h"),
                "sni": rec.get("server_name"),
                "issuer": rec.get("issuer"),
                "mitre": "T1071.001"
            })

    # Output
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[✓] Detection complete. {len(alerts)} alerts written to alerts.json")

if __name__ == "__main__":
    main()
