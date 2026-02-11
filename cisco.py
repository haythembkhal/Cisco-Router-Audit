import csv
from netmiko import ConnectHandler
from getpass import getpass
import sys
import re

# Devices to audit
DEVICES = [
    {'ip': '192.168.1.10', 'username': 'admin'},
    {'ip': '192.168.1.11', 'username': 'admin'},
]

# SECURITY COMMANDS FOR CISCO ASA
SECURITY_AUDIT_COMMANDS = [
    "show running-config ssh",
    "show running-config telnet",
    "show running-config http",
    "show running-config ssl",
    "show running-config logging",
    "show run | include threat-detection",
    "show run | include ikev",
    "show version"
]

def parse_asa_output(output):
    """
    Extract key security posture metrics from Cisco ASA output.
    """

    data = {
        'ASA_Version': 'N/A',
        'SSH_Encryption': 'N/A',
        'SSH_KEX': 'N/A',
        'Telnet_Enabled': 'No',
        'TLS_Version': 'N/A',
        'Logging_Enabled': 'No',
        'Threat_Detection': 'No',
        'Weak_VPN_Crypto': 'No',
    }

    # ASA Version
    ver = re.search(r"Cisco Adaptive Security Appliance Software Version ([\d\.]+)", output)
    if ver:
        data["ASA_Version"] = ver.group(1)

    # SSH encryption ciphers
    ssh_enc = re.search(r"ssh cipher encryption (.+)", output)
    if ssh_enc:
        data["SSH_Encryption"] = ssh_enc.group(1).strip()

    # SSH KEX
    ssh_kex = re.search(r"ssh key-exchange group (.+)", output)
    if ssh_kex:
        data["SSH_KEX"] = ssh_kex.group(1).strip()

    # Telnet detection
    if "telnet " in output:
        data["Telnet_Enabled"] = "Yes"

    # TLS/SSL version
    ssl_ver = re.search(r"ssl server-version (.+)", output)
    if ssl_ver:
        data["TLS_Version"] = ssl_ver.group(1).strip()

    # Logging
    if "logging enable" in output:
        data["Logging_Enabled"] = "Yes"

    # Threat Detection
    if "threat-detection" in output:
        data["Threat_Detection"] = "Enabled"

    # Weak crypto detection (3DES, MD5, DH2)
    if re.search(r"3des|md5|group2", output, re.IGNORECASE):
        data["Weak_VPN_Crypto"] = "Yes"

    return data


def run_compliance_check():
    print("\n--- Enter credentials ---")
    try:
        password = getpass("SSH Password: ")
        enable_secret = getpass("Enable Secret (if needed): ")
    except EOFError:
        print("\nInput error. Exiting.")
        sys.exit(1)

    all_results = []

    for device in DEVICES:
        print(f"\n--- Connecting to ASA {device['ip']} ---")

        asa_conn = {
            "device_type": "cisco_asa",
            "ip": device['ip'],
            "username": device['username'],
            "password": password,
            "secret": enable_secret
        }

        device_data = {"Device_IP": device['ip']}

        try:
            net_connect = ConnectHandler(**asa_conn)
            net_connect.enable()

            # Run all commands in one combined string
            output = net_connect.send_command("\n".join(SECURITY_AUDIT_COMMANDS))
            net_connect.disconnect()

            parsed = parse_asa_output(output)
            device_data.update(parsed)
            device_data["Audit_Status"] = "SUCCESS"
            all_results.append(device_data)

        except Exception as e:
            print(f"FAILED on {device['ip']} → {e}")
            device_data.update({
                "Audit_Status": "FAILED",
                "ASA_Version": "N/A",
                "SSH_Encryption": "N/A",
                "SSH_KEX": "N/A",
                "Telnet_Enabled": "N/A",
                "TLS_Version": "N/A",
                "Logging_Enabled": "N/A",
                "Threat_Detection": "N/A",
                "Weak_VPN_Crypto": "N/A",
            })
            all_results.append(device_data)

    # Write CSV output
    filename = "asa_security_audit_results.csv"
    with open(filename, "w", newline="") as csvfile:
        fieldnames = [
            "Device_IP",
            "Audit_Status",
            "ASA_Version",
            "SSH_Encryption",
            "SSH_KEX",
            "Telnet_Enabled",
            "TLS_Version",
            "Logging_Enabled",
            "Threat_Detection",
            "Weak_VPN_Crypto",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)

    print(f"\n✔ Audit complete. CSV saved as: {filename}")


if __name__ == "__main__":
    run_compliance_check()
