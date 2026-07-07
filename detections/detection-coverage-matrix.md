# Detection Coverage Matrix

This table summarizes the detection coverage across all five scenarios in this lab, showing what Wazuh's built in ruleset already caught, what gap was identified, and what custom rule was built to address it.

| # | Scenario | MITRE ATT&CK | Built-in Rule(s) | Built-in Coverage | Custom Rule | Custom Rule Status | Final Outcome |
|---|----------|--------------|-------------------|--------------------|--------------|----------------------|----------------|
| 001 | PowerShell Encoded Command | T1059.001 | 92057 | Partial, only matches when parent process is also PowerShell | 100002 | Working | Gap closed, both PowerShell-parent and non-PowerShell-parent execution now detected |
| 002 | New Local Administrator Account | T1136.001, T1098 | 60109, 60154 | Detects each step individually, no correlation between them | 100010 | Working | Gap closed via correlation rule, sequence now escalates above either individual event |
| 003 | Suspicious Windows Service Creation | T1543.003 | 61138 | Detects any service creation at flat low severity, regardless of executable | 100020 | Working | Gap closed, LOLBin executables in service path now escalate severity |
| 004 | Startup Folder Persistence | T1547.001 | 92204 | Detects PowerShell-created files broadly under AppData, not Startup-folder specific, misses non-PowerShell creation methods | 100030 | Attempted, three valid designs tested, none took precedence | Gap identified and documented, underlying Wazuh rule correlation limitation prevented resolution |
| 005 | SSH Brute Force (Linux) | T1110.001 | 5710, 5551, 40112 | Strong layered coverage including a dedicated failures-then-success correlation rule, but no enforced frequency threshold on that rule | 100040 | Working | Gap closed with a complementary high-volume-failure rule, independent of built in 40112 |

## Summary

Across five scenarios, real detection gaps were identified and closed in four cases. In one case (Scenario 5), existing coverage was already strong, and the custom rule built was a genuine but narrower refinement rather than a response to a major blind spot. In one case (Scenario 4), a real gap was identified and a fix was attempted through three separate valid rule designs, but a limitation in Wazuh's rule correlation engine prevented any of them from taking effect, and this is documented as an honest finding rather than a resolved gap.

A recurring theme across Scenarios 1, 4, and 5 was that built in Wazuh rules often scope their detection logic more narrowly than the underlying behavior warrants, whether by requiring a specific parent process, matching a broad file path without distinguishing higher-risk subpaths, or omitting a frequency threshold implied by the rule's own description. Identifying these narrow scoping decisions, rather than only reacting to completely uncovered behaviors, was the primary source of value across this project.