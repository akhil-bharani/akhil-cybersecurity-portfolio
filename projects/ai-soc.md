# CASE AI-SOC-2026-041 — Auditable AI-Ready SOC Investigation Pipeline

> **Synthetic portfolio lab.** No real customer data, live threat-intelligence calls, LLM inference, or autonomous remediation. This is a deterministic **agent-style architecture**, not a claim of deployed AI agents.

## Executive summary
A service identity (`svc-payments`) exhibits a sequence of AWS API actions including successful secret retrieval and security-group modification, plus denied attempts to create an access key and stop logging. The system correlates evidence, distinguishes successful from denied actions, and generates a **human-review-only** response proposal. A benign comparison principal is not flagged.

## Architecture
1. **Normalization agent:** validate event schema, parse timestamps, sort deterministically.
2. **Enrichment agent:** annotate high-risk API actions and documentation-only IPs.
3. **Correlation agent:** group by principal, score suspicious behavior, preserve evidence IDs.
4. **Review agent:** prepare recommendations marked `PENDING_HUMAN_REVIEW`; never run containment.

## Reproduce
```bash
python3 scripts/ai_soc_pipeline.py
python3 -m unittest discover -s tests -p 'test_ai_soc_pipeline.py' -v
```

## Analyst findings
- **Observed:** successful `GetSecretValue`, successful `AuthorizeSecurityGroupIngress`, successful `PutBucketPolicy`, denied `CreateAccessKey` and `StopLogging` in synthetic CloudTrail events.
- **Hypothesis:** possible misuse of a service principal to access secrets and modify cloud resources.
- **Not established:** credential theft, attacker identity, exfiltration, actual business impact, or whether activity was authorized.
- **MITRE ATT&CK:** T1552.004 is included as an *investigative hypothesis*, not a confirmed technique.

## Triage and containment decision
Preserve CloudTrail, IAM, network and resource logs; validate owner and change tickets; investigate sessions, source infrastructure, affected secrets and security groups. Rotate credentials or restrict access **only after human authorization** and operational impact review.

## Why this is AI-ready, not yet AI-driven
The stages expose explicit inputs/outputs and provenance suitable for future LLM enrichment. A future model must be constrained to cited evidence, redact secrets, emit structured JSON, undergo prompt-injection testing, and route all actions through a human approval gate. No model is currently called.

## Engineering notes
- Standard-library Python; no API keys or dependencies.
- Every finding references original event IDs.
- A benign principal is a negative control.
- Scores are heuristic and not validated against real alert outcomes.
- Data is fictional and uses reserved documentation IP ranges.
