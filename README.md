# Akhil Bharani — Incident Response & Threat Hunting

Public cybersecurity portfolio focused on investigation methodology, detection engineering and cloud DFIR.

**Live site:** https://akhil-bharani.github.io/akhil-cybersecurity-portfolio/  
**LinkedIn:** https://www.linkedin.com/in/akhil-bharani-241286190

## Featured case study

**[IR-2026-017: Multi-Stage AWS Identity Intrusion](projects/aws-identity-ir.md)** — synthetic multi-stage CloudTrail investigation, including role assumption, secret retrieval, public ingress, S3 reads, unsuccessful defense evasion, and evidence-based response recommendations.

### Run locally

```bash
python3 scripts/analyze_cloudtrail.py evidence/aws-cloudtrail-synthetic.json
python3 -m unittest discover -s tests -v
```

The lab uses only Python's standard library. Evidence is intentionally synthetic and is **not** derived from Cisco, Dell, or customer incidents. Other project pages are plans, not completed investigations.

### Evidence discipline

The report distinguishes API observations from inferred attacker intent and does **not** claim confirmed exfiltration, persistence or host compromise without supporting telemetry.
