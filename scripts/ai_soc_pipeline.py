"""Deterministic, auditable SOC agent-style pipeline. Python standard library only.
This is a simulation, not an LLM or autonomous response system.
"""
import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = BASE / "evidence/ai-soc-2026-041/alerts.json"
DEFAULT_OUTPUT = BASE / "evidence/ai-soc-2026-041/report.json"
SUSPICIOUS_ACTIONS = {"GetSecretValue", "CreateAccessKey", "AuthorizeSecurityGroupIngress",
                      "PutBucketPolicy", "StopLogging"}
HIGH_RISK = {"GetSecretValue", "CreateAccessKey", "StopLogging"}

def validate(events):
    if not isinstance(events, list):
        raise ValueError("Input must be a JSON list")
    required = {"id", "timestamp", "source", "principal", "action", "src_ip", "result"}
    ids = set()
    for event in events:
        if not isinstance(event, dict) or not required.issubset(event):
            raise ValueError("Event missing required fields")
        if event["id"] in ids:
            raise ValueError("Duplicate event ID")
        ids.add(event["id"])
        datetime.fromisoformat(event["timestamp"].replace("Z","+00:00"))
    return events

def normalize_agent(events):
    """Agent 1: canonicalize and sort evidence without modifying originals."""
    return sorted(events, key=lambda e: (e["timestamp"], e["id"]))

def enrichment_agent(events):
    """Agent 2: attach deterministic context; no live threat intel calls."""
    enriched = []
    for e in events:
        row = dict(e)
        row["is_documentation_ip"] = e["src_ip"].startswith(("198.51.100.", "203.0.113.", "192.0.2."))
        row["is_high_risk_action"] = e["action"] in HIGH_RISK
        enriched.append(row)
    return enriched

def correlation_agent(events):
    """Agent 3: correlate risky actions by principal; emit traceable evidence IDs."""
    groups = defaultdict(list)
    for e in events:
        groups[e["principal"]].append(e)
    findings = []
    for principal, rows in sorted(groups.items()):
        suspicious = [e for e in rows if e["action"] in SUSPICIOUS_ACTIONS]
        successes = [e for e in suspicious if e["result"] == "Success"]
        if not suspicious:
            continue
        score = min(100, 15 * len(successes) + 5 * len(suspicious))
        severity = "high" if score >= 60 else "medium" if score >= 30 else "low"
        findings.append({
            "principal": principal, "risk_score": score, "severity": severity,
            "actions": sorted({e["action"] for e in suspicious}),
            "evidence_ids": [e["id"] for e in suspicious],
            "confirmed": "Observed API actions in synthetic telemetry",
            "unknowns": ["Authorization of activity", "Actor identity", "Business impact"],
            "mitre_hypotheses": (["T1552.004"] if "GetSecretValue" in {e["action"] for e in suspicious} else [])
        })
    return findings

def review_agent(findings):
    """Agent 4: create proposed actions; never execute containment."""
    return [{
        "principal": f["principal"], "severity": f["severity"],
        "recommendations": ["Verify identity and authorization",
                            "Preserve CloudTrail and related identity logs",
                            "Review credentials, sessions, and affected resources"],
        "approval_required": True, "status": "PENDING_HUMAN_REVIEW",
        "evidence_ids": f["evidence_ids"]
    } for f in findings]

def run_pipeline(events):
    validated = validate(events)
    normalized = normalize_agent(validated)
    enriched = enrichment_agent(normalized)
    findings = correlation_agent(enriched)
    proposals = review_agent(findings)
    digest = hashlib.sha256(json.dumps(validated, sort_keys=True).encode()).hexdigest()
    return {
        "case_id": "AI-SOC-2026-041",
        "simulation": True,
        "pipeline": ["normalize", "enrich", "correlate", "review"],
        "event_count": len(validated), "input_sha256": digest,
        "findings": findings, "proposed_actions": proposals,
        "limitations": ["Synthetic events", "No live intelligence enrichment",
                        "No LLM inference", "No autonomous response",
                        "Rule-based risk scoring is illustrative, not calibrated"]
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = run_pipeline(json.loads(args.input.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"case_id": result["case_id"], "events": result["event_count"],
                      "findings": len(result["findings"]),
                      "pending_approvals": len(result["proposed_actions"]),
                      "report": str(args.output)}, indent=2))

if __name__ == "__main__":
    main()
