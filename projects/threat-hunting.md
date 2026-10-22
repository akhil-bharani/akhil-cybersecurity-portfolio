# HUNT-2026-031 — Hypothesis-Driven Enterprise Intrusion Hunt

> **Synthetic lab only.** All events, users, hostnames, timestamps and outcomes are invented. No employer/client incident is represented. The analyzer uses synthetic ground-truth labels only for testing, not for detection.

## Executive assessment
A simulated endpoint chain on `WS-FIN-22` starts with Word spawning PowerShell, followed by script-block activity, unusual DNS and proxy traffic, and identity activity against `FILE-07`. A file-read burst, elevated outbound traffic, and scheduled-task creation occur on `FILE-07`. **Suspected intrusion** is the appropriate assessment; the data do not establish who operated the activity, payload contents, or confirmed exfiltration.

## Hunt hypotheses
| ID | Hypothesis | Evidence to validate | Alternative explanation |
|---|---|---|---|
| H1 | Office initiated suspicious PowerShell | Sysmon process parent-child and 4104 | Approved automation or document macro testing |
| H2 | Host contacted an unusual external destination | DNS + proxy joined by host and time | Authorized SaaS / software updater |
| H3 | Credential misuse enabled file-server access | 4648, 4625/4624, source identity and logon type | Legitimate backup operations |
| H4 | File staging preceded outbound transfer | File audit burst + proxy volume | Scheduled reporting or backups |
| H5 | Scheduled task may enable persistence | 4698 task XML, author, action, subsequent runs | Authorized maintenance |

## Scope and data
54 simulated events across Windows Security, Sysmon, PowerShell, DNS, proxy, file-access and EDR streams. Timestamps UTC. Includes benign patching and normal logons to test false-positive handling. Missing: packet capture, actual task XML, EDR process GUIDs, network payloads, full file audit trail and verified asset ownership.

## Reconstructed sequence (UTC, 20 October 2026)
| Time | Evidence | Assessment |
|---|---|---|
| 09:04 | Word spawns encoded PowerShell | Suspicious process ancestry; encoded content not supplied |
| 09:05–09:07 | Script-block event, DNS lookup, proxy POST | Correlated activity; content unknown |
| 09:09–09:10 | `whoami` and `nltest` | Local/domain discovery consistent with post-compromise behavior |
| 09:12–09:14 | Explicit credentials, failed then successful network logon | Possible credential misuse; authorization unresolved |
| 09:17–09:19 | 186 document reads, 18 MB outbound POST | Possible staging and egress; exfiltration **not proven** |
| 09:21 | Scheduled task created | Persistence hypothesis; inspect task action |
| 09:25 | EDR behavioral alert | Independent alerting signal; detection latency needs validation |

## Investigation procedure
1. Preserve original event exports and calculate hashes before processing; normalize UTC timestamps, host identifiers and usernames.
2. Validate Sysmon process lineage using `ProcessGuid` and `ParentProcessGuid` where available; do not infer from executable names alone.
3. Decode and inspect PowerShell script-block content in an isolated analysis environment; compare with approved admin scripts.
4. Correlate DNS, proxy and EDR network events by host/time and destination; request packet or gateway records to determine transferred content.
5. Check 4648/4624/4625 logon types, source hosts, privilege assignments and backup service account ownership.
6. Review task XML, action path, signer and last-run history; verify whether it survived reboot.
7. Scope all peer endpoints and identities for the same process chain and destination, then tune exclusions based on documented legitimate behavior.

## Reproducible detection engineering
- `scripts/hunt_analyzer.py`: two cross-source heuristics, with evidence timestamps and benign-noise control.
- `detections/splunk.spl`: three SPL hunting examples. Field mappings require local adaptation.
- `detections/chronicle_yaral.txt`: illustrative Google SecOps YARA-L 2.0 rule, **not validated in a tenant**.
- `tests/test_hunt.py`: expected signals, benign-only negative control, event-count sanity check.

## Detection validation and limits
The bundled analyzer finds two correlated signals: Office→PowerShell + unusual domain on `WS-FIN-22`, and file-read burst + large outbound transfer on `FILE-07`. It produces zero findings on the bundled benign-only control. These are **fixture-level** results, not a measured enterprise detection rate. Validate against independently labeled data, expected administrative patterns, missing logs, and time-window drift before operational use.

## ATT&CK hypotheses (not automatic attribution)
T1059.001 PowerShell; T1087 Account Discovery; T1018 Remote System Discovery; T1074 Data Staged (hypothesis); T1053.005 Scheduled Task (hypothesis); T1041 Exfiltration Over C2 Channel (unconfirmed). Mapping denotes plausible technique alignment, not proof.

## Response recommendations
Preserve volatile and central evidence, confirm account owner and change tickets, isolate endpoints proportionate to business impact, rotate affected credentials if misuse is validated, investigate task creation and remove unauthorized persistence after evidence capture, and search enterprise-wide for related indicators. Document communications, evidence provenance and confidence for client reporting.

## Run
```bash
python3 scripts/hunt_analyzer.py
python3 -m unittest discover -s tests -p 'test_hunt.py' -v
```
