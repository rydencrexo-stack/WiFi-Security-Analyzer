import subprocess
import re
import json
import csv
import os
from datetime import datetime
from collections import Counter



# Wi-Fi Security Analyzer
# Windows + Python
# Defensive / Authorized Network Assessment Tool



BASELINE_FILE = "wifi_baseline.json"
JSON_REPORT = "wifi_report.json"
CSV_REPORT = "wifi_report.csv"



# COLORS


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
WHITE = "\033[97m"
RESET = "\033[0m"



# UTILITY FUNCTIONS


def clear_screen():
    os.system("cls")


def print_header():
    print(CYAN + "=" * 75)
    print("                 WI-FI SECURITY ANALYZER")
    print("=" * 75 + RESET)
    print("Defensive Wi-Fi visibility and security assessment tool")
    print()


def get_signal_value(signal):
    """
    Convert signal like '92%' into integer 92.
    """
    if not signal:
        return 0

    match = re.search(r"(\d+)", signal)

    if match:
        return int(match.group(1))

    return 0


def risk_color(risk):
    if risk == "HIGH":
        return RED
    elif risk == "MEDIUM":
        return YELLOW
    else:
        return GREEN



# RUN WINDOWS NETSH


def run_wifi_scan():

    command = [
        "netsh",
        "wlan",
        "show",
        "networks",
        "mode=bssid"
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if result.returncode != 0:
            print(RED + "\n[-] Unable to run netsh." + RESET)
            return []

        return parse_netsh_output(result.stdout)

    except FileNotFoundError:

        print(
            RED +
            "\n[-] netsh was not found."
            "\nThis program requires Windows."
            + RESET
        )

        return []

    except Exception as e:

        print(RED + f"\n[-] Scan error: {e}" + RESET)

        return []



# PARSE NETSH OUTPUT


def parse_netsh_output(output):

    networks = []

    current_network = None
    current_bssid = None

    for raw_line in output.splitlines():

        line = raw_line.strip()

       
        # SSID
       

        if line.startswith("SSID ") and ":" in line:

            # Save previous BSSID
            if current_bssid and current_network:

                current_network["bssids"].append(current_bssid)
                current_bssid = None

            # Save previous network
            if current_network:

                networks.append(current_network)

            ssid = line.split(":", 1)[1].strip()

            current_network = {
                "ssid": ssid,
                "authentication": "Unknown",
                "encryption": "Unknown",
                "signal": "Unknown",
                "channel": "Unknown",
                "radio_type": "Unknown",
                "bssids": []
            }

       
        # Authentication
       

        elif line.startswith("Authentication") and ":" in line:

            if current_network:

                current_network["authentication"] = (
                    line.split(":", 1)[1].strip()
                )

       
        # Encryption
       

        elif line.startswith("Encryption") and ":" in line:

            if current_network:

                current_network["encryption"] = (
                    line.split(":", 1)[1].strip()
                )

       
        # BSSID
       

        elif line.startswith("BSSID") and ":" in line:

            if current_bssid and current_network:

                current_network["bssids"].append(current_bssid)

            bssid = line.split(":", 1)[1].strip()

            current_bssid = {
                "bssid": bssid,
                "signal": "Unknown",
                "channel": "Unknown",
                "radio_type": "Unknown"
            }

       
        # Signal
       

        elif line.startswith("Signal") and ":" in line:

            value = line.split(":", 1)[1].strip()

            if current_bssid:

                current_bssid["signal"] = value

            elif current_network:

                current_network["signal"] = value

       
        # Channel
       

        elif line.startswith("Channel") and ":" in line:

            value = line.split(":", 1)[1].strip()

            if current_bssid:

                current_bssid["channel"] = value

            elif current_network:

                current_network["channel"] = value

       
        # Radio type
       

        elif line.startswith("Radio type") and ":" in line:

            value = line.split(":", 1)[1].strip()

            if current_bssid:

                current_bssid["radio_type"] = value

            elif current_network:

                current_network["radio_type"] = value

    
    # Save final BSSID/network
    

    if current_bssid and current_network:

        current_network["bssids"].append(current_bssid)

    if current_network:

        networks.append(current_network)

    
    # Flatten useful BSSID information
    

    for network in networks:

        if network["bssids"]:

            strongest = max(
                network["bssids"],
                key=lambda x: get_signal_value(x["signal"])
            )

            network["signal"] = strongest["signal"]
            network["channel"] = strongest["channel"]
            network["radio_type"] = strongest["radio_type"]

    return networks



# SECURITY ANALYSIS


def analyze_security(network):

    authentication = network["authentication"].lower()
    encryption = network["encryption"].lower()

    score = 0
    reasons = []
    recommendations = []

    
    # OPEN NETWORK
    

    if authentication in ["open", ""]:
        score += 70

        reasons.append("No Wi-Fi authentication detected.")

        recommendations.append(
            "Use WPA2-Personal or WPA3-Personal instead of an open network."
        )

    
    # WEP
    

    elif "wep" in authentication or "wep" in encryption:

        score += 90

        reasons.append(
            "WEP is obsolete and should not be used."
        )

        recommendations.append(
            "Replace WEP with WPA2 or WPA3."
        )

    
    # WPA
    

    elif authentication == "wpa-personal":

        score += 60

        reasons.append(
            "Legacy WPA authentication detected."
        )

        recommendations.append(
            "Upgrade legacy WPA to WPA2 or WPA3 where possible."
        )

    
    # WPA2
    

    elif "wpa2" in authentication:

        score += 15

        reasons.append(
            "WPA2 authentication detected."
        )

        recommendations.append(
            "Use a strong unique Wi-Fi passphrase."
        )

    
    # WPA3
    

    elif "wpa3" in authentication:

        score += 5

        reasons.append(
            "WPA3 authentication detected."
        )

        recommendations.append(
            "Keep router firmware updated and use a strong passphrase."
        )

    
    # ENTERPRISE
    

    if "enterprise" in authentication:

        recommendations.append(
            "Use certificate-based enterprise authentication where appropriate."
        )

    
    # SIGNAL ANALYSIS
    

    signal = get_signal_value(network["signal"])

    if signal >= 80:

        recommendations.append(
            "Strong nearby signal detected; ensure this is an authorized access point."
        )

    elif signal <= 30 and signal > 0:

        recommendations.append(
            "Weak signal detected; verify AP placement if this is your network."
        )

    
    # FINAL RISK
    

    if score >= 60:

        risk = "HIGH"

    elif score >= 20:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    network["risk_score"] = score
    network["risk"] = risk
    network["risk_reasons"] = reasons
    network["recommendations"] = recommendations

    return network



# ANALYZE ALL NETWORKS


def analyze_networks(networks):

    for network in networks:

        analyze_security(network)

    return networks



# CHANNEL ANALYSIS


def analyze_channels(networks):

    channels = []

    for network in networks:

        channel = network.get("channel", "Unknown")

        if channel != "Unknown":

            try:
                channels.append(int(channel))
            except ValueError:
                pass

    counter = Counter(channels)

    return counter


def print_channel_analysis(networks):

    print("\n" + CYAN + "=" * 75)
    print("CHANNEL ANALYSIS")
    print("=" * 75 + RESET)

    counter = analyze_channels(networks)

    if not counter:

        print("No channel information available.")

        return

    for channel, count in sorted(counter.items()):

        bar = "█" * count

        if count >= 5:

            status = "HIGH CONGESTION"

        elif count >= 3:

            status = "MODERATE"

        else:

            status = "LOW"

        print(
            f"Channel {channel:<4} "
            f"{bar:<15} "
            f"{count} network(s) - {status}"
        )

    least_used = min(counter, key=counter.get)

    print(
        f"\n{GREEN}[+] Least observed channel: "
        f"{least_used} ({counter[least_used]} network(s)){RESET}"
    )



# DISPLAY NETWORKS


def display_networks(networks):

    print("\n" + CYAN + "=" * 75)
    print("DISCOVERED WI-FI NETWORKS")
    print("=" * 75 + RESET)

    if not networks:

        print(RED + "No networks detected." + RESET)

        return

    for index, network in enumerate(networks, 1):

        risk = network["risk"]

        print(
            f"\n[{index}] "
            f"{WHITE}{network['ssid']}{RESET}"
        )

        print(
            f"    Security    : "
            f"{network['authentication']}"
        )

        print(
            f"    Encryption  : "
            f"{network['encryption']}"
        )

        print(
            f"    Signal      : "
            f"{network['signal']}"
        )

        print(
            f"    Channel     : "
            f"{network['channel']}"
        )

        print(
            f"    Radio       : "
            f"{network['radio_type']}"
        )

        print(
            f"    BSSIDs      : "
            f"{len(network['bssids'])}"
        )

        print(
            f"    Risk Score  : "
            f"{network['risk_score']}/100"
        )

        print(
            f"    Risk        : "
            f"{risk_color(risk)}{risk}{RESET}"
        )



# DETAILED NETWORK INFORMATION


def show_network_details(networks):

    if not networks:

        print("No networks available.")

        return

    try:

        choice = int(
            input("\nEnter network number: ")
        )

        if choice < 1 or choice > len(networks):

            print(RED + "Invalid selection." + RESET)

            return

    except ValueError:

        print(RED + "Invalid input." + RESET)

        return

    network = networks[choice - 1]

    print("\n" + CYAN + "=" * 75)
    print("DETAILED SECURITY ASSESSMENT")
    print("=" * 75 + RESET)

    print(f"\nSSID: {network['ssid']}")

    print(
        f"Authentication: "
        f"{network['authentication']}"
    )

    print(
        f"Encryption: "
        f"{network['encryption']}"
    )

    print(
        f"Signal: "
        f"{network['signal']}"
    )

    print(
        f"Channel: "
        f"{network['channel']}"
    )

    print(
        f"Radio Type: "
        f"{network['radio_type']}"
    )

    print(
        f"Risk Score: "
        f"{network['risk_score']}/100"
    )

    print(
        f"Risk Level: "
        f"{risk_color(network['risk'])}"
        f"{network['risk']}"
        f"{RESET}"
    )

    print("\n" + YELLOW + "Risk Reasons:" + RESET)

    for reason in network["risk_reasons"]:

        print(f"  ⚠ {reason}")

    print("\n" + GREEN + "Recommendations:" + RESET)

    for recommendation in network["recommendations"]:

        print(f"  ✓ {recommendation}")

    print("\nBSSIDs:")

    if network["bssids"]:

        for bssid in network["bssids"]:

            print(
                f"  {bssid['bssid']} | "
                f"Signal: {bssid['signal']} | "
                f"Channel: {bssid['channel']} | "
                f"Radio: {bssid['radio_type']}"
            )

    else:

        print("  No BSSID information available.")



# BASELINE


def create_baseline(networks):

    baseline = []

    for network in networks:

        entry = {
            "ssid": network["ssid"],
            "authentication": network["authentication"],
            "encryption": network["encryption"],
            "channel": network["channel"],
            "bssids": [
                b["bssid"]
                for b in network["bssids"]
            ]
        }

        baseline.append(entry)

    with open(
        BASELINE_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            baseline,
            file,
            indent=4
        )

    print(
        GREEN +
        f"\n[+] Baseline saved to {BASELINE_FILE}"
        + RESET
    )



# COMPARE BASELINE


def compare_baseline(networks):

    if not os.path.exists(BASELINE_FILE):

        print(
            YELLOW +
            "\n[!] No baseline exists."
            "\nCreate one first using option 5."
            + RESET
        )

        return

    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        baseline = json.load(file)

    old_ssids = {
        item["ssid"]
        for item in baseline
    }

    current_ssids = {
        item["ssid"]
        for item in networks
    }

    new_networks = current_ssids - old_ssids

    missing_networks = old_ssids - current_ssids

    print("\n" + CYAN + "=" * 75)
    print("BASELINE CHANGE DETECTION")
    print("=" * 75 + RESET)

    if new_networks:

        print(
            YELLOW +
            "\n⚠ NEW NETWORKS DETECTED:"
            + RESET
        )

        for ssid in new_networks:

            print(f"  + {ssid}")

    else:

        print(
            GREEN +
            "\n✓ No new SSIDs detected."
            + RESET
        )

    if missing_networks:

        print(
            YELLOW +
            "\n⚠ NETWORKS NO LONGER VISIBLE:"
            + RESET
        )

        for ssid in missing_networks:

            print(f"  - {ssid}")

    else:

        print(
            GREEN +
            "\n✓ No baseline SSIDs disappeared."
            + RESET
        )



# EXPORT JSON


def export_json(networks):

    report = {

        "tool": "Wi-Fi Security Analyzer",

        "scan_time": datetime.now().isoformat(),

        "network_count": len(networks),

        "networks": networks
    }

    with open(
        JSON_REPORT,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        GREEN +
        f"\n[+] JSON report created: {JSON_REPORT}"
        + RESET
    )



# EXPORT CSV


def export_csv(networks):

    with open(
        CSV_REPORT,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "SSID",
            "Authentication",
            "Encryption",
            "Signal",
            "Channel",
            "Radio Type",
            "BSSID Count",
            "Risk Score",
            "Risk"
        ])

        for network in networks:

            writer.writerow([
                network["ssid"],
                network["authentication"],
                network["encryption"],
                network["signal"],
                network["channel"],
                network["radio_type"],
                len(network["bssids"]),
                network["risk_score"],
                network["risk"]
            ])

    print(
        GREEN +
        f"\n[+] CSV report created: {CSV_REPORT}"
        + RESET
    )



# SECURITY SUMMARY


def security_summary(networks):

    high = 0
    medium = 0
    low = 0
    open_networks = 0

    for network in networks:

        if network["risk"] == "HIGH":
            high += 1

        elif network["risk"] == "MEDIUM":
            medium += 1

        else:
            low += 1

        if network["authentication"].lower() == "open":

            open_networks += 1

    print("\n" + CYAN + "=" * 75)
    print("SECURITY SUMMARY")
    print("=" * 75 + RESET)

    print(
        f"\nTotal Networks : {len(networks)}"
    )

    print(
        f"{RED}High Risk      : {high}{RESET}"
    )

    print(
        f"{YELLOW}Medium Risk    : {medium}{RESET}"
    )

    print(
        f"{GREEN}Low Risk       : {low}{RESET}"
    )

    print(
        f"{RED}Open Networks  : {open_networks}{RESET}"
    )



# FULL SCAN


def perform_scan():

    print(
        CYAN +
        "\n[*] Scanning for nearby Wi-Fi networks..."
        + RESET
    )

    networks = run_wifi_scan()

    networks = analyze_networks(networks)

    return networks



# MAIN MENU


def main():

    networks = []

    while True:

        clear_screen()

        print_header()

        print("1. Scan Wi-Fi Networks")
        print("2. View Networks")
        print("3. Detailed Security Assessment")
        print("4. Channel Analysis")
        print("5. Create Security Baseline")
        print("6. Compare With Baseline")
        print("7. Security Summary")
        print("8. Export JSON Report")
        print("9. Export CSV Report")
        print("0. Exit")

        print()

        choice = input(
            "Select an option: "
        ).strip()

       
        # SCAN
       

        if choice == "1":

            networks = perform_scan()

            display_networks(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # VIEW
       

        elif choice == "2":

            display_networks(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # DETAILS
       

        elif choice == "3":

            show_network_details(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # CHANNEL ANALYSIS
       

        elif choice == "4":

            print_channel_analysis(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # BASELINE
       

        elif choice == "5":

            if not networks:

                networks = perform_scan()

            create_baseline(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # COMPARE
       

        elif choice == "6":

            if not networks:

                networks = perform_scan()

            compare_baseline(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # SUMMARY
       

        elif choice == "7":

            if not networks:

                networks = perform_scan()

            security_summary(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # JSON
       

        elif choice == "8":

            if not networks:

                networks = perform_scan()

            export_json(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # CSV
       

        elif choice == "9":

            if not networks:

                networks = perform_scan()

            export_csv(networks)

            input(
                "\nPress Enter to continue..."
            )

       
        # EXIT
       

        elif choice == "0":

            print(
                GREEN +
                "\n[+] Exiting Wi-Fi Security Analyzer."
                + RESET
            )

            break

        else:

            print(
                RED +
                "\n[-] Invalid option."
                + RESET
            )

            input(
                "\nPress Enter to continue..."
            )



# START PROGRAM


if __name__ == "__main__":

    main()

    # THIS PROJECT IS ONLY MADE FOR ANALYSIS OF NETWORK AND ONLY EDUCATIONAL USE.