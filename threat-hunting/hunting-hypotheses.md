# Hunting Hypotheses

This document lists hunting hypotheses considered during this project but not fully simulated, intended as a starting point for future work on this lab rather than completed findings.

## Hypothesis 1: Low-and-Slow SSH Brute Force
Rule 100040 in this lab requires five or more failed logins within a two minute window to fire. An attacker aware of frequency-based detection could space out login attempts well beyond this window, remaining under the threshold indefinitely while still eventually guessing a valid credential. A hunt for this would involve reviewing successful logins over a longer historical window and checking whether the same source IP has any prior failed attempts at all, regardless of how long ago or how sparse.

## Hypothesis 2: Encoded Command Variants Beyond PowerShell
Scenario 1 focused specifically on PowerShell's `-EncodedCommand` flag. Other interpreters and living-off-the-land binaries support similar obfuscation, for example encoded or obfuscated command blocks passed to `cmd.exe`, `mshta.exe`, or `certutil.exe` used for encoding and decoding files. A hunt here would involve searching command line fields across all process creation events for base64-like patterns, not just the specific PowerShell flag syntax tested in this lab.

## Hypothesis 3: Scheduled Task Persistence
This lab covered service creation and Startup folder persistence but did not test scheduled task creation, another extremely common persistence mechanism on Windows. A future scenario could simulate creating a scheduled task via `schtasks.exe` or PowerShell's `Register-ScheduledTask` cmdlet, then check whether Wazuh's built in ruleset has comparable coverage gaps to the ones found in Scenarios 3 and 4.

## Hypothesis 4: Lateral Movement Following Local Admin Creation
Scenario 2 detected local admin account creation and escalation on a single host. A natural extension would be simulating that same newly created account being used to authenticate to a second host on the network shortly afterward, testing whether Wazuh can correlate account creation on one endpoint with authentication activity on another, which would require cross-agent correlation rather than the single-agent correlation used in this lab's rule 100010.

## Hypothesis 5: Wazuh Rule Correlation Limitation, Root Cause
Scenarios 4 and 5 both encountered cases where a custom rule sharing an existing rule chain with a built in rule failed to take precedence or coexist as expected. This was worked around in both cases by chaining off a different rule instead, but the underlying cause was never conclusively identified. A focused investigation, potentially involving Wazuh's own source code or direct engagement with Wazuh's community forums, could confirm whether this is a documented, intended behavior or a genuine bug worth reporting upstream.