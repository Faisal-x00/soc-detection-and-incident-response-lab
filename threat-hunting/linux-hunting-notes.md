# Linux Threat Hunting Notes

This document covers observations from reviewing activity on the Ubuntu endpoint in this lab, beyond the formal detection work covered in Scenario 5.

## Review Method
Authentication activity on the Ubuntu endpoint was reviewed directly via `/var/log/auth.log`, in addition to the Wazuh dashboard, since raw log review is often faster for confirming the exact sequence and wording of sshd and PAM messages than working through the dashboard alone. Both sources agreed exactly in Scenario 5, which is itself a useful confirmation that the Wazuh agent's log forwarding for this endpoint is reliable and not dropping or reordering events.

## Observation: Value of Raw auth.log Alongside Wazuh Alerts
While Wazuh's built in rules correctly correlated the failed-then-successful login pattern in Scenario 5, the raw auth.log excerpt provided additional low level detail not surfaced in the alert itself, specifically the intermediate `pam_unix` authentication failure lines and the exact port numbers used for each connection attempt. In a real investigation, this level of detail can help distinguish between multiple near-simultaneous attack sources or confirm whether attempts came from a single persistent connection versus several short-lived ones.

## Hunting Hypothesis Considered But Not Simulated
Given more time, a natural next hunt on this endpoint would be reviewing successful logins for source IPs that do not correspond to any known administrative workstation, cross-referenced against the times those accounts are normally active, to catch a slow, low-volume credential guessing attempt that would fall below the frequency threshold used in rule 100040 and might not trigger rule 5551 or 40112 either. This kind of low-and-slow brute force is a known real-world evasion technique against frequency-based detections like the ones used in this lab.

## Note on Scope
Formal detection engineering work for this endpoint is fully documented in `scenarios/005-linux-ssh-bruteforce/README.md`. This file exists separately to capture observations and hunting reasoning that fall outside that single scenario's scope.