# Executive Summary

## Project
This project is a self-hosted SOC detection engineering and incident response lab, built to demonstrate the end to end SOC analyst workflow: simulating realistic attacker behavior, evaluating existing detection coverage, building targeted detection rules to close identified gaps, investigating the resulting alerts, and documenting findings in a professional, incident-report style format.

## Environment
The lab consists of three virtual machines, a Wazuh manager, indexer, and dashboard running on Ubuntu, a Windows 10 endpoint instrumented with Sysmon and monitored via a Wazuh agent, and a second Ubuntu endpoint monitored the same way, with all activity contained to an isolated, non-internet-facing network.

## Methodology
Five scenarios were simulated, covering encoded PowerShell execution, local administrator account creation, suspicious Windows service creation, Startup folder persistence, and SSH brute force activity against the Linux endpoint. For each scenario, existing detection coverage in Wazuh's default ruleset was evaluated first, and a custom rule was built only where a genuine gap was identified, rather than writing rules for behaviors that were already well covered.

## Results
Real detection gaps were identified and successfully closed with custom rules in four of five scenarios. In one scenario, a genuine gap was identified but a working fix could not be achieved due to an underlying limitation in Wazuh's rule correlation engine, and this outcome is documented honestly rather than presented as resolved. In a fifth scenario, existing built in coverage was found to already be strong, and the value delivered was a narrower, complementary rule addressing a specific secondary gap rather than a full rebuild.

## Key Findings
A recurring pattern was that Wazuh's built in detection rules frequently scope their logic more narrowly than the underlying attacker behavior warrants, whether by requiring a specific parent process, matching a broad file path without distinguishing higher-risk locations within it, or omitting a frequency threshold implied by the rule's own description. A separate, cross-cutting technical finding was a reproducible case where custom rules sharing an existing correlation chain with a built in rule failed to take precedence or coexist as expected, observed independently in two separate scenarios.

## Recommendation
The custom rules developed in this project, along with the specific tuning recommendations noted in each scenario's documentation, are suitable candidates for review and potential deployment in a production Wazuh environment, alongside the recommendation that the built in rule correlation behavior noted above be further investigated or reported upstream to Wazuh's maintainers.