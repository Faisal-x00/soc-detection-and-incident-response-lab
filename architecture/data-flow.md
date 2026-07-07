# Lab Architecture and Data Flow

This lab consists of three virtual machines running in VMware on a single 
host, connected on a shared internal network.

## Components
The Wazuh server is an Ubuntu machine running the Wazuh manager, indexer, 
and dashboard as an all in one install. The Windows 10 endpoint runs 
Sysmon, configured with the SwiftOnSecurity ruleset, alongside the Wazuh 
agent. The Ubuntu endpoint runs the Wazuh agent with native auth.log 
monitoring for SSH activity.

## Data Flow
On the Windows endpoint, Sysmon captures detailed process, file, and 
registry telemetry and writes it to the Windows Event Log under 
Microsoft-Windows-Sysmon/Operational. The Wazuh agent is configured to 
collect this channel, alongside the standard Application, Security, and 
System event logs, and forwards all of it to the Wazuh manager over an 
encrypted connection. On the Ubuntu endpoint, the Wazuh agent monitors 
/var/log/auth.log directly for SSH authentication activity and forwards 
matching events the same way.

On the Wazuh manager, incoming events are evaluated against the full 
ruleset, both Wazuh's built in rules and the custom rules added to 
local_rules.xml as part of this project. Events that match a rule become 
alerts and are indexed into wazuh-alerts-*. Wazuh's archive feature was 
also enabled during this project, which additionally logs every processed 
event, matched or not, into wazuh-archives-*, giving full visibility into 
raw telemetry rather than only what already triggered an alert. This was 
necessary for debugging custom rules that were not matching as expected, 
and is generally useful for proactive threat hunting.

Both indices are queried through the Wazuh dashboard, where alerts were 
reviewed, investigated, and used to build the evidence and timelines 
documented in each scenario folder.

## Custom Detection Rules
All custom rules built for this project live in 
`/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager, and are also 
copied individually into `detections/wazuh-rules/` in this repository for 
reference alongside each scenario's documentation.