Cisco IOS Security Audit
What is this?
A simple Python script to check basic security settings on Cisco IOS devices. It connects over SSH, runs a few show commands, and writes a summary to a CSV file.

What it checks

IOS version
Telnet vs SSH status
Minimum password length
NTP sync status


Requirements

Python 3
Netmiko

Install Netmiko:
Shellpip install netmikoAfficher plus de lignes

How to use :

Edit the DEVICES list in the script with your device IPs and usernames.
Run the script:

python cisco.py

Enter your SSH and enable passwords when prompted.

Check the output file:
security_audit_results_summary.csv



Example CSV:
Device_IP,Audit_Status,IOS_Version,Telnet_Status,Min_Pass_Len,NTP_Status

192.168.1.10,SUCCESS,15.2(4)M6,Secure (SSH Enabled),10,Synchronized

192.168.1.11,SUCCESS,15.1(3)T,Insecure (Telnet Enabled),8,Unsynchronized



Make sure SSH and privilege mode are enabled on the devices.

