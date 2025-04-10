# MITRE ATT&CK Mapping

## Tactic: Initial Access  
**Technique:** [T1078] Valid Accounts  
- A single successful SSH login was recorded on **April 8, 2025**, from remote IP `88.214.57.51`.  
- No prior failed attempts observed. This suggests attacker access using previously compromised credentials.  
- Logon targeted the root account on host `linuxremediation.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`.
- Additional compromised hosts: `linux-vulnscan-allen.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`, `linux-programmatic-fix-wa.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`.

---

## Tactic: Execution  
**Technique:** [T1059.004] Command and Scripting Interpreter: Unix Shell  
- Shells such as `bash`, `dash`, and `sh` were executed immediately following access.  
- Tools like `wget`, `curl`, and `.sh` scripts were leveraged to fetch and execute payloads.  
- Binary `gc_worker` was noted as an initiating process in multiple entries.

**Technique:** [T1059.001] Command and Scripting Interpreter: PowerShell  
- PowerShell use was detected on the host, likely via compatibility layers.  
- `-EncodedCommand` arguments were observed, indicating use of obfuscated commands.

---

## Tactic: Persistence  
**Technique:** [T1037] Boot or Logon Initialization Scripts  
- Files with randomized names (e.g., `ygljglkjgfg0`) were dropped into `/usr/bin/` and launched by `systemd`.  
- These appear configured to reinitialize post-reboot, indicating persistence via init systems.

---

## Tactic: Defense Evasion  
**Technique:** [T1036] Masquerading  
- Malicious binaries were named to resemble legitimate system services (e.g., `svchost.ps1`, `updateservice`).  
- Placed within trusted system folders to avoid detection by file path heuristics.

**Technique:** [T1027] Obfuscated Files or Information  
- PowerShell scripts used base64 encoding and obfuscation tactics.  
- Payloads were embedded within scripts or executed via command-line encoded strings.

---

## Tactic: Discovery  
**Technique:** [T1082] System Information Discovery  
- Commands such as `ifconfig` and environmental probes were executed post-compromise.  
- Indicates early-stage reconnaissance to assess system role or value.

---

## Tactic: Collection  
**Technique:** [T1005] Data from Local System  
- Multiple suspicious files were created under `/usr/bin/` with high entropy names, suggesting staging or dropped payloads.  
- Temporal proximity between file write events and network traffic supports data preparation for exfiltration.

---

## Tactic: Command and Control  
**Technique:** [T1071.001] Application Layer Protocol: Web Protocols  
- Outbound connections to:
  - `185.199.110.133` over port 443
  - `169.254.169.254` over port 80 (AWS metadata query likely for cloud enumeration)
- Initiated via `python3.10`, using modules like `MdeInstallerWrapper.py` and `MdeExtensionHandler.py`.

---

## Tactic: Exfiltration  
**Technique:** [T1041] Exfiltration Over C2 Channel  
- File creation events occurred within two-minute windows of outbound HTTPS connections.  
- Suggests attacker exfiltrated data through an existing encrypted C2 session.

---

## Findings

- **Compromised Host:** `linuxremediation.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`  
- **Source IP:** `88.214.57.51`  
- **Initial Access:** Valid credentials (no brute-force attempts logged)  
- **Execution Stack:** Shell scripting, PowerShell, and Python agents  
- **Persistence Method:** Systemd/init scripts with renamed executables  
- **C2 Infrastructure:** HTTPS sessions to suspicious IPs  
- **Exfiltration Evidence:** Aligned file and network activity  
- **Attacker Behavior:** Highly automated with limited signs of interactive shell use
