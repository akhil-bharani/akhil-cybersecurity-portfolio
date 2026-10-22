# Case IR-2026-017 — Multi-Stage AWS Identity Intrusion

> **Synthetic forensic exercise.** This is a fictional case constructed for a public portfolio. Account IDs, names, dates, IPs and evidence are simulated. Documentation-range addresses are not real attacker attribution. CloudTrail-style records are illustrative and deliberately omit some AWS service-specific fields. **No real customer data or secrets are included.**

## Executive decision brief

**Assessment:** High-severity suspected credential misuse with demonstrated cloud-control changes and access to a simulated secret and S3 objects. **Confidence:** High that the supplied synthetic records show the listed API activity; low that data was exfiltrated outside AWS because no destination, byte-count or transfer evidence is provided. **Business impact:** Potential unauthorized exposure of analytics data and increased host attack surface. **Recommended posture:** Treat the key and assumed-role session as compromised, contain both, preserve evidence, and investigate downstream access.

**Executive narrative.** A previously trusted deployment principal `deploy-service` made an unusual sequence of API calls from `198.51.100.24`: identity validation, IAM and infrastructure discovery, failed creation of an additional key, successful `AssumeRole` into `AnalyticsReadRole`, retrieval of a database secret, modification of a security group to permit global SSH, and S3 object reads. A failed `StopLogging` call suggests an attempt to reduce visibility, but does not establish successful log tampering. An IR responder subsequently reverted the ingress rule and disabled the original key. The lab includes a benign owner-origin event from a different address to practice attribution boundaries.

## Scope, authority, and preservation

- **Tenant:** fictional account `111122223333`; regions observed: `us-east-1` and `eu-west-1`.
- **Known identities:** IAM user `deploy-service`, STS session `AnalyticsReadRole/lab-session`, IR responder `ir-responder`.
- **Evidence:** `evidence/aws-cloudtrail-synthetic.json`, 17 hand-authored CloudTrail-style records, ordered by UTC event time.
- **Evidence handling:** preserve the original export in read-only storage; calculate SHA-256 at acquisition; record collector, timestamp, source, query window, and any normalization steps. The companion analyzer prints a digest of the supplied file; it is not a chain-of-custody system.
- **Coverage gaps:** no CloudTrail Lake source validation, GuardDuty, IAM policy snapshots, AWS Config history, CloudWatch workload logs, VPC Flow Logs, DNS, S3 server access logs, object sizes, egress records, or evidence of the original credential leak.

## Investigative hypotheses and tests

| Hypothesis | Test | Outcome from provided evidence |
|---|---|---|
| H1: long-lived IAM credentials were misused | Group events by access key, source, user agent, time and baseline | Supported as suspicious sequence; theft mechanism unproven |
| H2: attacker escalated or pivoted via STS | Correlate `AssumeRole` request, role ARN, and assumed-role activity | Role assumption and follow-on session activity shown; actual permission boundary unknown |
| H3: attacker established persistence | Inspect `CreateAccessKey`, role trust changes, login profiles and tokens | `CreateAccessKey` denied; no successful persistence proven |
| H4: actor weakened network controls | Compare ingress rule change against approved baseline and AWS Config | Public SSH ingress change shown; reachability and host exploitation unproven |
| H5: confidential information left the environment | Correlate S3 data events, object metadata, bytes, network egress and destination | Two object reads shown; exfiltration **not** established |
| H6: logging was disabled | Inspect `StopLogging`, trail state, organization trail health | Request denied; no demonstrated outage |

## Reconstructed timeline — UTC

| Time | Identity | API action | Result | Interpretation |
|---|---|---|---|---|
| 08:00 | deploy-service | GetCallerIdentity | Success | Credential validation |
| 08:02 | deploy-service | ListAttachedUserPolicies | Success | Permission discovery |
| 08:04 | deploy-service | ListBuckets | Success | Storage discovery |
| 08:07 | deploy-service | DescribeInstances | Success | Compute discovery |
| 08:09 | deploy-service | CreateAccessKey | **Denied** | Attempted credential persistence |
| 08:12 | deploy-service | AssumeRole | Success | Pivot to AnalyticsReadRole |
| 08:14 | AnalyticsReadRole | ListSecrets | Success | Secret enumeration |
| 08:16 | AnalyticsReadRole | GetSecretValue | Success | Secret value API retrieval; secret content not logged |
| 08:18 | deploy-service | AuthorizeSecurityGroupIngress | Success | TCP/22 permitted from 0.0.0.0/0 |
| 08:22 | AnalyticsReadRole | SendCommand | **Denied** | Failed remote-command attempt |
| 08:27 | AnalyticsReadRole | ListObjectsV2 | Success | Object discovery |
| 08:30 | AnalyticsReadRole | GetObject | Success | Object read; bytes unknown |
| 08:32 | AnalyticsReadRole | GetObject | Success | Second object read |
| 08:35 | deploy-service | StopLogging | **Denied** | Attempted visibility reduction |
| 08:40 | deploy-service | GetAccessKeyLastUsed | Success | Owner-baseline comparison, different IP |
| 08:45 | ir-responder | RevokeSecurityGroupIngress | Success | Reverted exposure |
| 08:47 | ir-responder | UpdateAccessKey | Success | Disabled long-lived key |

## Identity correlation and pivot analysis

The compromised-key hypothesis relies on repeated calls under `AKIAEXAMPLECOMPROMISED` from a documentation IP. The STS role session uses `ASIAEXAMPLESESSION01`; the role session name and temporal adjacency are useful pivots, **but a production investigator should use the actual `AssumeRole` response and CloudTrail `sessionContext` to confirm linkage**, not infer lineage from timestamps alone. Cross-region API events should be checked against service endpoint semantics; a single event region field does not prove the actor physically operated there.

**Privilege boundary questions:** Why could `deploy-service` assume `AnalyticsReadRole`? Did the trust policy constrain principals, session tags, source IPs or external IDs? Was the role over-permissioned to retrieve secrets and read S3 objects? Was permission granted by an identity policy, resource policy, or both? Preserve policies at incident time before modifying them.

## Data-access and exfiltration assessment

A successful `GetSecretValue` indicates an API request returned successfully in this lab; the dataset does not contain the secret itself or evidence of subsequent use. The two `GetObject` records show S3 reads, not the volume transferred, content sensitivity, external destination, or confirmed disclosure. In real AWS environments, S3 object-level CloudTrail **data events must be enabled** for this class of evidence to be present. Obtain object size/version, access logs where configured, workload egress telemetry, and business-owner classification before asserting exfiltration.

## Detection engineering

### Splunk SPL — high-risk IAM sequence

```spl
index=aws sourcetype=aws:cloudtrail
| eval principal=coalesce('userIdentity.arn',userIdentity_arn), key=coalesce('userIdentity.accessKeyId',userIdentity_accessKeyId)
| where eventName IN ("CreateAccessKey","AssumeRole","GetSecretValue","AuthorizeSecurityGroupIngress","StopLogging")
| stats values(eventName) as actions values(errorCode) as errors dc(eventName) as distinct_actions min(_time) as first_seen max(_time) as last_seen by key sourceIPAddress
| where distinct_actions>=3
```

### Splunk SPL — public administrative ingress

```spl
index=aws sourcetype=aws:cloudtrail eventName=AuthorizeSecurityGroupIngress
| spath input=requestParameters path=ipPermissions{} output=permissions
| search requestParameters="*0.0.0.0/0*"
| table _time userIdentity.arn sourceIPAddress awsRegion requestParameters
```

These SPL examples are **starting points**, not validated production detections. Nested JSON paths, extracted field names, service-specific record structure, ingestion source and rule tuning must be verified in the target Splunk deployment. For production use, parse CIDRs and port ranges structurally instead of relying only on string matching.

### Detection design and tuning

- **Signal:** rare principal-source pair + `AssumeRole` + high-risk API calls within 30 minutes; risk score increases with a denied credential-creation or trail-tampering attempt.
- **Benign alternatives:** authorized break-glass operations, CI/CD deploys, new automation rollout, cross-region maintenance, approved security testing.
- **Enrichment:** IAM principal age, expected egress IPs, role trust policy, known change ticket, geolocation reliability, historical API baseline, GuardDuty findings.
- **Tuning:** exclude documented automation identities only when bounded by source, role, time, and change approval; don't suppress all `AssumeRole` events.
- **Metrics:** precision after analyst validation, time-to-triage, false-positive drivers, missed scenario tests, mean time to containment.

## ATT&CK interpretation

| Technique | Evidence status |
|---|---|
| T1078.004 Valid Accounts: Cloud Accounts | Plausible misuse of a valid cloud key; theft source unknown |
| T1580 Cloud Infrastructure Discovery | `DescribeInstances`, `ListBuckets` consistent with discovery |
| T1098.001 Additional Cloud Credentials | `CreateAccessKey` **attempt failed** |
| T1552.004 Private Keys | Not demonstrated; do not claim |
| T1562.007 Disable or Modify Cloud Firewall | Successful public SSH rule change |
| T1530 Data from Cloud Storage | S3 object reads shown; data theft intent unproven |
| T1562.008 Disable or Modify Cloud Logs | `StopLogging` **attempt failed** |

Mapping is analyst interpretation, not independent proof of adversary intent. Verify exact technique versions against the current ATT&CK catalog before publication as a production reference.

## Containment, eradication and recovery

**0–15 minutes:** declare incident, preserve CloudTrail and Config snapshots, confirm business owner, restrict key usage, revoke malicious network exposure, assess role session risk. Disabling a long-lived key **does not automatically invalidate already issued STS credentials**; use the appropriate role/session revocation and permission-deny controls with service-owner coordination.

**15–60 minutes:** enumerate session activity in all relevant accounts and regions; inspect secrets accessed, rotate exposed credentials based on risk; evaluate workloads behind the security group; identify whether object reads were authorized; preserve relevant host/flow evidence before destructive remediation.

**1–24 hours:** validate IAM trust and least privilege, eliminate exposed keys from CI/CD, adopt short-lived workload identities, review SCPs and guardrails, test alerts, restore approved rules, verify service health and monitor for recurrence.

**Communications:** incident commander owns decisions and timeline; cloud engineering validates operational impact; application owners assess secrets and data sensitivity; legal/privacy assesses notification thresholds only after scope and exposure evidence; report clearly separates observed actions from inferred attacker goals.

## Final disposition and unresolved questions

**Confirmed within the synthetic dataset:** role assumption, secret retrieval API call, public SSH ingress rule, two object-read calls, two denied attack-like API calls, and subsequent containment API calls. **Not established:** original credential theft mechanism, persistence, command execution, host access, data volume, external transfer, impact to real customers, or full remediation of active STS sessions.

**Priority follow-ups:** (1) verify role-session lineage; (2) enumerate all session and cross-account actions; (3) confirm secret rotation and any downstream use; (4) investigate host reachability and access; (5) determine S3 object sensitivity and egress; (6) validate session invalidation and recovery.

## Reproduce

```bash
python3 scripts/analyze_cloudtrail.py evidence/aws-cloudtrail-synthetic.json
python3 -m unittest discover -s tests -v
```

The analyzer is offline, standard-library-only, and does not contact AWS. The data is purpose-built for testing investigative logic, not a real CloudTrail export.
