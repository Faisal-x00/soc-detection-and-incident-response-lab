# Scenario 001: Suspicious PowerShell Encoded Command

## MITRE ATT&CK
**T1059.001**  Command and Scripting Interpreter: PowerShell

## Behavior Simulated
A base64-encoded PowerShell command was executed via two different parent 
processes:
1. PowerShell launching PowerShell (`powershell.exe -EncodedCommand ...`)
2. cmd.exe launching PowerShell with the same encoded flag

Both commands decoded to a harmless `Write-Host` string — no real payload 
was executed at any point.

## Why This Matters
Attackers base64-encode PowerShell commands to evade simple string-matching 
defenses and to smuggle multi-line or special-character payloads through a 
single command-line argument. The `-EncodedCommand` flag (and its shorthand 
variants) is rarely used by legitimate administrative scripts, making its 
presence a strong, well-established indicator worth alerting on.

## Detection Gap Identified
Wazuh's built-in rule (`92057`) already detects base64-encoded PowerShell 
commands but only when the **parent process is also PowerShell**. Real 
attackers frequently launch encoded PowerShell from other processes 
(`cmd.exe`, `wscript.exe`, `mshta.exe`, Office applications, etc.), none of 
which would trigger the built-in rule.

## Custom Rule
`100002` extends detection to flag base64-encoded PowerShell execution 
launched from any of several known non-PowerShell parent processes 
(`cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `explorer.exe`, 
`wmiprvse.exe`, `winword.exe`, `excel.exe`).

See `detection-explanation.md` for full rule logic and reasoning.

## Outcome
Both execution paths (PowerShell-parent and cmd.exe-parent) now generate 
alerts — closing the coverage gap in the built-in ruleset.