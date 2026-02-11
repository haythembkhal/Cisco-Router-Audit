## Cisco ASA Security Audit
What is this?
A simple Python script to check basic security settings on Cisco ASA firewalls.
It connects over SSH, runs a set of show commands, and writes a summary CSV file with key security posture information.

## What it checks

ASA software version
SSH encryption (cipher)
SSH key‑exchange (KEX)
Telnet enabled/disabled
TLS version for ASDM
Logging enabled/disabled
Threat‑Detection enabled/disabled
Weak VPN crypto detection (3DES, MD5, DH2)

These are lightweight but important checks to validate the firewall’s security configuration.

## Requirements

Python 3
Netmiko
EVE‑NG or a real Cisco ASA

Install Netmiko:
ShellAfficher plus de lignes

How to use:
1. Edit the DEVICES list
Add your ASA firewall IPs and usernames.
2. Run the script:
ShellAfficher plus de lignes
3. Enter your SSH and enable passwords when prompted.
4. Check the output file:
asa_security_audit_results.csv


## Example CSV:
Device_IP|Audit_Status|ASA_Version|SSH_Encryption|SSH_KEX|Telnet_Enabled|TLS_Version|Logging_Enabled|Threat_Detection|Weak_VPN_Crypto
192.168.1.10|SUCCESS|9.18|aes256-cbc|dh-group14-sha256|No|tls1.2|Yes|Enabled|No
192.168.1.11|SUCCESS|9.16|3des-cbc|dh-group1-sha1|Yes|tls1.0|No|No|Yes


## Notes

Ensure SSH access is enabled on the ASA.
Your management PC must be allowed via the ASA SSH ACL (ssh x.x.x.x y.y.y.y inside).
The script uses read‑only show commands and does not modify the firewall configuration.
