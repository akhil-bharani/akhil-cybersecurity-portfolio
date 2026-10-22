# CASE WIN-IR-026 — Windows Endpoint Intrusion and Artifact Recovery

> **Synthetic DFIR exercise.** All people, endpoints, logs, paths and timestamps are fictional. The IP `198.51.100.42` is a documentation-only address. KAPE is discussed as an acquisition and processing workflow; no claim is made that it was executed against a real machine. No reverse engineering is performed.

## Executive summary

**Host:** `WS-FIN-07` (Windows workstation) · **Window:** 18 Oct 2026, 08:12–08:40 UTC · **Assessment:** High-priority suspected compromise, subject to validation. A remote-interactive logon was followed by a hidden PowerShell invocation, file enumeration, a newly created scheduled task, archive creation, and apparent log clearing. MFT and USN-derived sample records indicate the archive was subsequently deleted. An orphaned `.lnk` file points to a missing target but is **not** attributable to the intrusion without additional evidence.

**Confirmed within the fictional dataset:** task-creation event 4698, script-block event 4104, archive creation event, Security log clear event 1102, and synthetic deletion indicators. **Not established:** how the credentials were obtained, whether the remote logon was unauthorized, whether the archive left the host, the identity of the operator, or the completeness of the recovered file content.

## 1. Scope, hypotheses and triage priorities

The case is scoped to one endpoint and the supplied evidence. Hypotheses: H1 the remote logon initiated malicious activity; H2 PowerShell executed collection commands; H3 a scheduled task provided persistence; H4 a local archive was staged and deleted; H5 the orphaned shortcut is a benign legacy artifact rather than attacker cleanup. Each hypothesis requires corroboration and alternate-explanation testing.

Priority actions in a real response: preserve volatile state where feasible; record EDR isolation decisions and clock offset; capture host and user context; retain original evidence and hash each collected item; identify affected credentials; check lateral movement and outbound traffic using centrally retained logs.

## 2. KAPE acquisition and processing plan

**KAPE (Kroll Artifact Parser and Extractor)** is used in this proposed workflow to collect targeted Windows forensic artifacts and optionally process them through modules. Obtain it from the authorized vendor distribution; respect its license and do not publish binaries or third-party parsers in this repository.

| Evidence | KAPE target / processing concept | Why it matters |
|---|---|---|
| `$MFT`, `$UsnJrnl:$J` | File-system targets → MFTECmd | Creation, rename, deletion and record reuse; timestamps are not always proof of action order |
| Security / PowerShell / TaskScheduler / Sysmon EVTX | Event-log targets → EvtxECmd | Correlate logon, process, script-block and task activity; check logging coverage |
| `ConsoleHost_history.txt` | User profile / PSReadLine history target | Interactive PowerShell history, when available; not a complete execution log |
| `.lnk` and Jump Lists | Recent-item targets → LECmd / JLECmd | Target paths, volume references, access context and missing target relationships |
| Prefetch | Prefetch targets → PECmd | Support execution hypothesis and last-run context |
| Amcache / Shimcache | Registry/system targets → appropriate parsers | Program presence and possible execution context; avoid overclaiming |
| Scheduled tasks XML and registry hives | Task and registry targets | Persistence configuration, author and command validation |

Collection controls: isolate collection storage from source; log acquisition start/end and time zone; capture tool versions, target/module selections, error output, operator and host identifiers; hash source and output; use write-protected/offline acquisition when possible. KAPE outputs are derivative artifacts, not a replacement for preserving source data. `evidence/windows-dfir/kape-manifest.csv` is a **mock acquisition manifest**, not actual KAPE output.

## 3. Chronological reconstruction

| UTC | Evidence | Interpretation and limits |
|---|---|---|
| 08:12 | Security 4624, type 10 | RDP-style logon; must validate legitimacy and source host |
| 08:14 | Sysmon 1 | Hidden PowerShell from user-writable path; suspicious execution context |
| 08:15 | Sysmon 3 | Outbound TLS connection to synthetic documentation IP; no proof of data transfer |
| 08:16 | Security 4698 | Scheduled task created referencing `sync.ps1`; persistence likely |
| 08:17 | PowerShell 4104 | Enumerated Finance directory; supports discovery/collection hypothesis |
| 08:19–08:20 | Sysmon 1 / 11 | 7-Zip process and archive creation; staging supported |
| 08:22–08:23 | Security 4688 / 1102 | Log-clear command and Security log clearing; anti-forensic behavior suspected |
| 08:28–08:33 | MFT / LNK / USN | Deleted file records and an orphaned shortcut; separate causal attribution required |
| 08:35–08:37 | Prefetch / Amcache | Additional execution and program-presence context |

See the full 18-row synthetic event stream in `evidence/windows-dfir/events.csv`.

## 4. PowerShell history versus execution evidence

The supplied `ConsoleHost_history.txt` contains interactive commands including `whoami`, directory enumeration and task inspection. **PSReadLine history is not a complete audit trail**: it may omit noninteractive commands, can be edited or cleared, may be disabled, and does not reliably provide timestamps. Therefore, the command history must not be used alone to attribute execution to a user or establish exact chronology.

Prefer correlation with PowerShell Operational **4104** script-block events (when enabled), **4103** module logging, Security **4688** with command-line auditing, Sysmon **1** process creation, EDR process telemetry, scheduled-task XML, and file-system metadata. A history line can be a lead even if no corresponding event is available.

## 5. Stale files, deleted records and orphan files

**Stale files** in this lab mean files that appear old, unused or outside the expected retention lifecycle; this is a triage label, **not** a Windows forensic artifact category or proof of compromise. Determine staleness with last-use context, owner, application dependencies, timestamps, backup policy and business purpose. File-system timestamps can be altered and access times may not be reliable.

**Deleted / unallocated file records:** `in_use=false` in the fictional MFT evidence suggests records no longer allocated; USN deletion can corroborate activity. A deleted record does not imply the file's bytes are recoverable. Validate record numbers, sequence numbers, parent paths and possible reuse before linking artifacts.

**Orphan files / orphan references:** this case uses an `.lnk` whose target no longer exists. That is an **orphaned reference**, not necessarily an NTFS orphaned file record. True orphaned file records refer to file-system metadata disconnected from expected parent relationships, and require separate examination. Missing shortcut targets can result from moves, removable media, software changes, user cleanup or malicious deletion. No evidence here ties the orphaned `.lnk` to the suspicious PowerShell activity.

## 6. Findings and confidence

| Finding | Confidence | Why |
|---|---|---|
| Suspicious PowerShell and task creation | High (within synthetic record set) | Process + task creation events |
| Local collection and archive staging | High | Script-block, 7z process, file creation |
| Anti-forensic log clearing | High for clear event, medium for malicious intent | 4688 command and 1102, but authorization unknown |
| Deletion of staged archive | Medium–high | Synthetic MFT and USN agreement; original bytes unavailable |
| Exfiltration | **Unproven** | Network connection metadata alone lacks byte counts and content |
| Credential theft or lateral movement | **Unproven** | No credential-access telemetry or second-host evidence |
| Orphaned shortcut caused by intrusion | **Unproven** | Missing target is nonspecific |

## 7. ATT&CK hypotheses (not proof of full technique execution)

- T1059.001 — PowerShell execution
- T1053.005 — Scheduled Task persistence
- T1005 — Data from Local System (collection hypothesis)
- T1560.001 — Archive via Utility (local archive creation)
- T1070.001 — Clear Windows Event Logs (supported by 1102)

## 8. Recommended response and scoping

Preserve forensic image / triage artifacts and chain of custody. Verify RDP source, MFA, account status and ticketed maintenance. Review task XML, file ACLs, hash and signer information for `sync.ps1`, archive contents if recoverable, EDR telemetry and any endpoint memory evidence. Hunt fleet-wide for task names, path patterns and process ancestry, not only literal hashes. Query proxy, DNS, firewall and DLP telemetry for transferred bytes and destinations. Rotate affected credentials only after evidence and operational impacts are assessed. Restore logging, remove confirmed persistence, reimage if integrity cannot be established, and validate recovery.

## 9. Reproducibility and limitations

Run `python3 scripts/analyze_windows_case.py` from repository root to summarize synthetic evidence. Run `python3 -m unittest discover -s tests -v` for tests. The Python script reads **synthetic CSV**, not raw EVTX/MFT or KAPE outputs. No real endpoint was acquired; no malware sample was analyzed; there is no attribution claim. Findings are illustrative of an investigation method, not verified real-world incident facts.
