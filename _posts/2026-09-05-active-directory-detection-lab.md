---
tags: Active Directory
---

# Building an Active Directory Detection Lab: Attack Simulation, SIEM Integration, and Threat Detection

## Overview

To build hands-on experience for SOC analyst roles, I built a home lab designed to simulate realistic adversary behavior against an Active Directory environment and validate whether that behavior gets detected. The goal wasn't just to run attacks — it was to close the loop: simulate a technique, confirm the telemetry it generates, and write a detection rule that catches it.

The lab runs entirely on **VirtualBox** on a Windows PC with 32GB of RAM, giving enough headroom to run a domain controller, a client, an attacker box, and a SIEM simultaneously.

## Lab Topology

| Role | Host | IP Address |
|---|---|---|
| SIEM (Splunk) | Ubuntu Server | 192.168.10.10 |
| Domain Controller | Windows Server (ADDC01) | 192.168.10.100 |
| Domain Client | Windows 10 | (internal, joined to domain) |
| Attacker | Kali Linux | 192.168.10.250 |

The core components:

- **Windows Server Domain Controller (ADDC01)** — the Active Directory environment being attacked and monitored.
- **Windows 10 client** — a joined workstation, acting as an additional attack surface and log source.
- **Kali Linux** — the attacker platform used to simulate malicious activity.
- **Ubuntu Server running Splunk** — the SIEM, ingesting logs from the domain to detect the simulated attacks.

## Attack Simulation #1: RDP Brute-Force

The first simulated attack was a brute-force login attempt against RDP, one of the most common real-world initial access vectors against Windows environments.

**What was simulated:** Repeated failed authentication attempts from the Kali box against the domain controller/client over RDP, mapped to:

- **MITRE ATT&CK T1110** — Brute Force
- **MITRE ATT&CK T1110.001** — Password Guessing

**What was detected:** The brute-force activity showed up clearly in the Windows Security event log via:

- **Event ID 4625** — failed logon attempts (the volume/pattern of these is the brute-force signature)
- **Event ID 4624** — successful logon (flags when the brute-force eventually succeeds)
- **Event ID 4776** — credential validation attempts, useful for correlating NTLM-based auth attempts

With these three event IDs ingested into Splunk, a spike of 4625 events from a single source in a short window becomes a reliable, low-noise indicator of brute-force activity — a foundational detection every SOC needs.

## Attack Simulation #2: Atomic Red Team — Multi-Technique Simulation

To go beyond a single technique, I used **Atomic Red Team** to run a broader, MITRE-mapped simulation. Atomic Red Team provides small, scoped "atomic tests" for individual ATT&CK techniques, which makes it easy to simulate one specific behavior and immediately check whether it was caught.

**Key technique simulated:** **T1059.001** — Command and Scripting Interpreter: PowerShell (specifically, a download-and-execute pattern, a very common step in real intrusions once an attacker has initial access).

**Detection:** This technique was caught via **Sysmon**, specifically:

- **Sysmon Event ID 1** — Process Creation (captures the PowerShell process launching with suspicious command-line arguments)
- **Sysmon Event ID 3** — Network Connection (captures the outbound connection made during the download step)

Sysmon's process and network telemetry is what makes PowerShell abuse visible — the built-in Windows Security log alone typically isn't granular enough to catch this kind of behavior.

## SIEM Pipeline: Splunk

Getting the pipeline working end-to-end wasn't frictionless, and documenting the troubleshooting is arguably as valuable as the detections themselves, since this is exactly the kind of debugging a SOC analyst does in production.

**Issues hit and resolved:**

1. **Splunk Universal Forwarder misconfiguration** — the `inputs.conf` file on the forwarder wasn't correctly pointing to the right log sources, so events weren't being shipped to the indexer at all initially.
2. **UFW blocking port 9997** — the Ubuntu firewall (UFW) was blocking the default Splunk forwarder-to-indexer port (9997), silently dropping all forwarded data even after the forwarder config was fixed.
3. **Brute-force telemetry pipeline validation** — after fixing both issues, I had to manually validate that the RDP brute-force events (4625/4624/4776) were actually landing in Splunk and searchable, rather than assuming the pipeline was healthy.

This troubleshooting arc is a good reminder that most of the real work in detection engineering isn't writing the detection logic — it's making sure the data actually gets where it needs to go first.

### A note on Sysmon visibility

Sysmon events don't show up in Splunk automatically just because the forwarder is already running — they live in their own Windows Event Log channel (`Microsoft-Windows-Sysmon/Operational`), separate from the standard Security/Application/System logs, and the forwarder needs an explicit stanza to pick it up:

```
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = your_index_name
sourcetype = XmlWinEventLog
```

Once that's in place, the events are searchable in Splunk with:

```
index=your_index_name sourcetype="XmlWinEventLog" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

filtered further by `EventCode` — e.g. `EventCode=1` for process creation, `EventCode=3` for network connections. It's an easy gap to miss: Security logs flowing can make the pipeline look "done" while Sysmon is silently not being collected at all.

## Cloud Extension: Microsoft Sentinel

To round out the lab with cloud-native SIEM experience, I stood up a parallel **Microsoft Sentinel** environment:

- Integrated **Microsoft Entra ID** sign-in logs via a **Log Analytics Workspace**.
- Wrote **KQL (Kusto Query Language)** detection rules targeting suspicious login patterns and credential access behavior, including:
  - **MITRE ATT&CK T1212** — Exploitation for Credential Access
- Configured **analytic rules** in Azure with automated alert triggers, so matching log patterns generate an actual alert rather than requiring a manual search.

This gave hands-on exposure to a modern, cloud-based SIEM stack (Sentinel + Entra ID + Log Analytics) alongside the on-prem Splunk setup, which reflects how a lot of real-world environments are hybrid.

## What's Next

A few directions this lab is headed:

- **Automated adversary emulation with Caldera** — moving beyond single Atomic Red Team tests toward multi-step, chained operations (recon → credential access → lateral movement) to validate detection coverage across a full attack chain, not just isolated techniques. This also opens the door to a purple-team workflow: run one technique at a time, check Splunk/Sentinel for the expected telemetry, then tune or write a new rule before moving to the next step.
- **Deeper network-layer visibility** — adding Zeek or Suricata to catch things host logs miss, like C2 beaconing patterns.

## Takeaways

Building this lab reinforced a few things that don't come across as clearly from studying alone:

- Mapping every simulated action to a specific MITRE ATT&CK technique makes it possible to reason about detection *coverage* rather than just detection *examples*.
- Running the same class of problem (credential-based attacks) across two different SIEM stacks (Splunk on-prem, Sentinel in the cloud) highlighted how much of the underlying logic — event IDs, log sources, correlation patterns — carries over even when the tooling changes.

---

*This lab is ongoing — future posts will cover the Caldera-driven purple team exercises and much more.*
