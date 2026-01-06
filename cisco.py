
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

# Commands to run on IOS
SECURITY_AUDIT_COMMANDS = [
    "show version | include Version",
    "show line vty",
    "show ip http server status",
    "show running-config | include security passwords min-length",
    "show running-config | include password encryption",
    "show ntp status",
    "show logging",
    "show running-config | include service pad",
    "show running-config | include username",
]

def parse_ios_output(output):
    """
    Parse raw CLI output into a small summary dictionary.
    Assumes all command outputs are concatenated in one string.
    """
    data = {
        'IOS_Version': 'N/A',
        'Telnet_Status': 'N/A',
        'Min_Pass_Len': 'N/A',
        'NTP_Status': 'N/A'
    }

    # IOS version
    version_match = re.search(r'Version\s+([\d.]+[\w()]+)', output)
    if version_match:
        data['IOS_Version'] = version_match.group(1).strip()

    # VTY / Telnet / SSH status (best effort from mixed output)
    if "Line(s) not in use" in output:
        data['Telnet_Status'] = 'Secure (No Active VTY)'
    vty_config_match = re.search(r'Line\s+\d+\s+Transport\s+input\s+(\w+)', output, re.IGNORECASE)
    if vty_config_match:
        input_type = vty_config_match.group(1).lower()
        if 'telnet' in input_type:
            data['Telnet_Status'] = 'Insecure (Telnet Enabled)'
        elif 'ssh' in input_type or 'all' in input_type:
            data['Telnet_Status'] = 'Secure (SSH Enabled)'

    # Min password length
    min_pass_match = re.search(r'security passwords min-length (\d+)', output)
    if min_pass_match:
        data['Min_Pass_Len'] = min_pass_match.group(1)

    # NTP state
    if "Clock is synchronized" in output:
        data['NTP_Status'] = 'Synchronized'
    elif "Clock is unsynchronized" in output:
        data['NTP_Status'] = 'Unsynchronized'

    return data

def run_compliance_check():
    # Credentials prompt
    print("\n--- Saisie des identifiants ---")
    try:
        password = getpass("Entrez le mot de passe SSH: ")
        secret = getpass("Entrez le mot de passe 'enable' (secret): ")
    except EOFError:
        print("\nErreur de saisie. Arrêt du script.")
        sys.exit(1)

    all_results = []

    for device in DEVICES:
        print(f"\n--- Connexion à {device['ip']} en cours... ---")

        # Netmiko connection args
        ios_conn_details = {
            "device_type": "cisco_ios",
            "ip": device['ip'],
            "username": device['username'],
            "password": password,
            "secret": secret
        }

        device_data = {'Device_IP': device['ip']}

        try:
            # Connect and run all commands as one string (original behavior)
            net_connect = ConnectHandler(**ios_conn_details)
            output = net_connect.send_command("\n".join(SECURITY_AUDIT_COMMANDS))
            net_connect.disconnect()

            # Parse combined output
            parsed_data = parse_ios_output(output)

            device_data.update(parsed_data)
            device_data['Audit_Status'] = 'SUCCESS'
            all_results.append(device_data)

        except Exception as e:
            # Minimal failure record per device
            print(f" ÉCHEC sur {device['ip']}. Erreur: {e}")
            device_data.update({
                'Audit_Status': 'FAILED',
                'IOS_Version': 'N/A',
                'Telnet_Status': 'N/A',
                'Min_Pass_Len': 'N/A',
                'NTP_Status': 'N/A'
            })
            all_results.append(device_data)

    # Generate CSV
    filename = 'security_audit_results_summary.csv'
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Device_IP', 'Audit_Status', 'IOS_Version', 'Telnet_Status', 'Min_Pass_Len', 'NTP_Status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)

    print(f"\n Audit terminé. Rapport synthétique enregistré dans {filename}")

if __name__ == "__main__":
    run_compliance_check()
