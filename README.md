# SOC Detection Engineering & Incident Response Lab

## Status
🔧 Complete.

## Overview
An end-to-end, self-hosted SOC lab simulating realistic attacker behaviors, 
detecting them with a mix of Wazuh's built-in ruleset and custom-authored 
detection rules mapped to MITRE ATT&CK, and following through with full 
investigation, timeline reconstruction, false positive analysis, and 
incident reporting.

Rather than writing detection rules from scratch in isolation, each scenario 
in this lab follows a **gap analysis** methodology: simulate the behavior, 
determine what Wazuh's existing ruleset already catches, identify the 
specific blind spot in that coverage, then build a custom rule to close it. 
In one case, existing coverage was already strong and no gap was found 
that finding is documented too, since knowing when *not* to build something 
is as much a part of detection engineering as building it.

## Safety & Scope
All activity in this project was performed in an isolated VMware lab 
environment (host-only/NAT networking, no internet-facing exposure). 
No real malware was used. All "malicious" behaviors (PowerShell encoding, 
persistence techniques, credential-access patterns, brute-force attempts) 
are simulated using safe, non-destructive methods for the sole purpose of 
testing detection engineering and incident response workflows. No public 
systems, third-party infrastructure, or real credentials were targeted or 
accessed at any point.

## Lab Architecture
- **Wazuh manager/indexer/dashboard**: Ubuntu server (all-in-one install)
- **Windows 10 endpoint**: Sysmon (SwiftOnSecurity config) + Wazuh agent
- **Ubuntu endpoint**: Wazuh agent, native auth.log monitoring
- **Archives enabled**: full event visibility (matched + unmatched) via 
  `wazuh-archives-*`, not just alerted events

See [architecture/data-flow.md](architecture/data-flow.md) for full details.

## Scenarios

| # | Scenario | ATT&CK ID | Built-in Coverage | Custom Rule | Outcome |
|---|----------|-----------|--------------------|-----------|---------|
| 001 | PowerShell Encoded Command | T1059.001 | Partial (PowerShell-parent only) | `100002` | Gap closed |
| 002 | New Local Administrator Account | T1136.001, T1098 | Yes, per-event only | `100010` (correlation) | Gap closed |
| 003 | Suspicious Windows Service Creation | T1543.003 | Yes, generic severity | `100020` | Gap closed |
| 004 | Startup Folder Persistence | T1547.001 | Yes, not location-aware | `100030` (attempted) | Gap identified; tool limitation documented |
| 005 | SSH Brute Force (Linux) | T1110.001 | Strong, one threshold gap | `100040` | Gap closed |

## Notable Findings
- Identified and closed real detection gaps in 4 of 5 scenarios against 
  Wazuh's default ruleset, not just written rules for previously-uncovered behavior
- Discovered a reproducible Wazuh rule-correlation limitation (same-chain 
  rules competing rather than coexisting), observed independently in two 
  separate scenarios — see `lessons-learned.md`
- Investigated and closed out a real, organically-occurring false positive 
  (legitimate Disk Cleanup activity) using the same triage process applied 
  to simulated scenarios — see `threat-hunting/windows-hunting-notes.md`

## Possible Future Enhancements
- Sigma rule equivalents for each custom detection
- Velociraptor integration for endpoint DFIR investigation
- TheHive integration for formal case management
