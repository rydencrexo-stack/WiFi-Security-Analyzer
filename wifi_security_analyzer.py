import subprocess
import re
import json
import csv
import sqlite3
import os
import time
from datetime import datetime
from collections import Counter


DB_FILE = "wifi_security.db"
BASELINE_FILE = "wifi_baseline.json"
JSON_FILE = "wifi_report.json"
CSV_FILE = "wifi_report.csv"
HTML_FILE = "wifi_report.html"


RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header():
    print(CYAN + "=" * 80)
    print("                 WI-FI SECURITY ANALYZER")
    print("=" * 80 + RESET)


def db_init():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ssid TEXT,
            bssid TEXT,
            authentication TEXT,
            encryption TEXT,
            signal INTEGER,
            channel TEXT,
            radio TEXT,
            risk_score INTEGER,
            risk TEXT
        )
    """)

    conn.commit()
    conn.close()


def signal_value(value):
    match = re.search(r"(\d+)", str(value))

    if match:
        return int(match.group(1))

    return 0


def risk_color(value):
    if value == "HIGH":
        return RED
    if value == "MEDIUM":
        return YELLOW
    return GREEN


def run_netsh():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if result.returncode != 0:
            return ""

        return result.stdout

    except Exception:
        return ""


def parse_wifi(output):
    networks = []
    current = None
    bssid = None

    for raw in output.splitlines():
        line = raw.strip()

        if line.startswith("SSID ") and ":" in line:
            if bssid and current:
                current["bssids"].append(bssid)
                bssid = None

            if current:
                networks.append(current)

            current = {
                "ssid": line.split(":", 1)[1].strip(),
                "authentication": "Unknown",
                "encryption": "Unknown",
                "signal": "Unknown",
                "channel": "Unknown",
                "radio": "Unknown",
                "bssids": []
            }

        elif line.startswith("Authentication") and ":" in line:
            if current:
                current["authentication"] = line.split(":", 1)[1].strip()

        elif line.startswith("Encryption") and ":" in line:
            if current:
                current["encryption"] = line.split(":", 1)[1].strip()

        elif line.startswith("BSSID") and ":" in line:
            if bssid and current:
                current["bssids"].append(bssid)

            bssid = {
                "bssid": line.split(":", 1)[1].strip(),
                "signal": "Unknown",
                "channel": "Unknown",
                "radio": "Unknown"
            }

        elif line.startswith("Signal") and ":" in line:
            value = line.split(":", 1)[1].strip()

            if bssid:
                bssid["signal"] = value
            elif current:
                current["signal"] = value

        elif line.startswith("Channel") and ":" in line:
            value = line.split(":", 1)[1].strip()

            if bssid:
                bssid["channel"] = value
            elif current:
                current["channel"] = value

        elif line.startswith("Radio type") and ":" in line:
            value = line.split(":", 1)[1].strip()

            if bssid:
                bssid["radio"] = value
            elif current:
                current["radio"] = value

    if bssid and current:
        current["bssids"].append(bssid)

    if current:
        networks.append(current)

    for network in networks:
        if network["bssids"]:
            strongest = max(
                network["bssids"],
                key=lambda x: signal_value(x["signal"])
            )

            network["signal"] = strongest["signal"]
            network["channel"] = strongest["channel"]
            network["radio"] = strongest["radio"]

    return networks


def security_analysis(network):
    auth = network["authentication"].lower()
    encryption = network["encryption"].lower()

    score = 0
    reasons = []
    recommendations = []

    if auth in ("open", ""):
        score += 75
        reasons.append("Open or unauthenticated wireless network.")
        recommendations.append("Enable WPA2 or WPA3 security.")

    elif "wep" in auth or "wep" in encryption:
        score += 95
        reasons.append("WEP detected.")
        recommendations.append("Replace WEP immediately with WPA2 or WPA3.")

    elif auth == "wpa-personal":
        score += 60
        reasons.append("Legacy WPA authentication detected.")
        recommendations.append("Upgrade to WPA2 or WPA3.")

    elif "wpa2" in auth:
        score += 15
        reasons.append("WPA2 detected.")
        recommendations.append("Use a long and unique Wi-Fi passphrase.")

    elif "wpa3" in auth:
        score += 5
        reasons.append("WPA3 detected.")
        recommendations.append("Keep AP firmware updated.")

    else:
        score += 30
        reasons.append("Authentication type could not be confidently classified.")
        recommendations.append("Verify the wireless security configuration.")

    signal = signal_value(network["signal"])

    if signal >= 85:
        recommendations.append(
            "Strong nearby signal detected; verify that the AP is authorized."
        )

    if signal <= 25 and signal > 0:
        recommendations.append(
            "Weak signal detected; verify AP placement if this is your network."
        )

    if len(network["bssids"]) > 3:
        recommendations.append(
            "Multiple BSSIDs detected for this SSID; verify expected AP deployment."
        )

    if score >= 60:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    network["risk_score"] = min(score, 100)
    network["risk"] = risk
    network["reasons"] = reasons
    network["recommendations"] = recommendations

    return network


def scan():
    print(CYAN + "\n[*] Scanning wireless networks..." + RESET)

    output = run_netsh()

    if not output:
        print(RED + "[-] Unable to perform Wi-Fi scan." + RESET)
        return []

    networks = parse_wifi(output)

    for network in networks:
        security_analysis(network)

    save_history(networks)

    print(
        GREEN +
        f"[+] {len(networks)} networks discovered."
        + RESET
    )

    return networks


def save_history(networks):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    timestamp = datetime.now().isoformat(timespec="seconds")

    for network in networks:
        for bssid in network["bssids"]:

            cur.execute("""
                INSERT INTO scans (
                    timestamp,
                    ssid,
                    bssid,
                    authentication,
                    encryption,
                    signal,
                    channel,
                    radio,
                    risk_score,
                    risk
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                network["ssid"],
                bssid["bssid"],
                network["authentication"],
                network["encryption"],
                signal_value(bssid["signal"]),
                bssid["channel"],
                bssid["radio"],
                network["risk_score"],
                network["risk"]
            ))

    conn.commit()
    conn.close()


def display_networks(networks):
    if not networks:
        print(YELLOW + "\nNo scan data available." + RESET)
        return

    print("\n" + CYAN + "=" * 100)
    print(
        f"{'#':<4}"
        f"{'SSID':<25}"
        f"{'Security':<20}"
        f"{'Signal':<10}"
        f"{'Channel':<10}"
        f"{'Risk':<12}"
    )
    print("=" * 100 + RESET)

    for i, network in enumerate(networks, 1):

        ssid = network["ssid"][:23]

        print(
            f"{i:<4}"
            f"{ssid:<25}"
            f"{network['authentication'][:18]:<20}"
            f"{network['signal']:<10}"
            f"{network['channel']:<10}"
            f"{risk_color(network['risk'])}"
            f"{network['risk']} "
            f"({network['risk_score']})"
            f"{RESET}"
        )


def details(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    display_networks(networks)

    try:
        number = int(input("\nSelect network: "))

        if number < 1 or number > len(networks):
            print(RED + "Invalid selection." + RESET)
            return

    except ValueError:
        print(RED + "Invalid input." + RESET)
        return

    network = networks[number - 1]

    print("\n" + CYAN + "=" * 80)
    print("SECURITY ASSESSMENT")
    print("=" * 80 + RESET)

    print(f"\nSSID          : {network['ssid']}")
    print(f"Authentication: {network['authentication']}")
    print(f"Encryption    : {network['encryption']}")
    print(f"Signal        : {network['signal']}")
    print(f"Channel       : {network['channel']}")
    print(f"Radio         : {network['radio']}")
    print(f"BSSID Count   : {len(network['bssids'])}")
    print(
        f"Risk Score    : "
        f"{network['risk_score']}/100"
    )
    print(
        f"Risk          : "
        f"{risk_color(network['risk'])}"
        f"{network['risk']}"
        f"{RESET}"
    )

    print("\n" + RED + "Findings" + RESET)

    for reason in network["reasons"]:
        print(f"  ! {reason}")

    print("\n" + GREEN + "Recommendations" + RESET)

    for recommendation in network["recommendations"]:
        print(f"  + {recommendation}")

    print("\n" + BLUE + "BSSIDs" + RESET)

    for item in network["bssids"]:
        print(
            f"  {item['bssid']:<20}"
            f"Signal: {item['signal']:<8}"
            f"Channel: {item['channel']:<8}"
            f"Radio: {item['radio']}"
        )


def channel_analysis(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    counter = Counter()

    for network in networks:
        channel = network["channel"]

        try:
            counter[int(channel)] += 1
        except ValueError:
            pass

    print("\n" + CYAN + "=" * 70)
    print("CHANNEL CONGESTION")
    print("=" * 70 + RESET)

    if not counter:
        print("Channel information unavailable.")
        return

    for channel, count in sorted(counter.items()):

        bar = "█" * min(count, 30)

        if count >= 6:
            status = RED + "HIGH" + RESET
        elif count >= 3:
            status = YELLOW + "MEDIUM" + RESET
        else:
            status = GREEN + "LOW" + RESET

        print(
            f"Channel {channel:<4} "
            f"{bar:<30} "
            f"{count:<3} "
            f"{status}"
        )

    best = min(counter, key=counter.get)

    print(
        f"\n{GREEN}[+] Least observed channel: "
        f"{best}{RESET}"
    )


def summary(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    high = sum(n["risk"] == "HIGH" for n in networks)
    medium = sum(n["risk"] == "MEDIUM" for n in networks)
    low = sum(n["risk"] == "LOW" for n in networks)

    open_count = sum(
        n["authentication"].lower() == "open"
        for n in networks
    )

    wep_count = sum(
        "wep" in n["authentication"].lower()
        for n in networks
    )

    wpa2_count = sum(
        "wpa2" in n["authentication"].lower()
        for n in networks
    )

    wpa3_count = sum(
        "wpa3" in n["authentication"].lower()
        for n in networks
    )

    average_signal = round(
        sum(signal_value(n["signal"]) for n in networks) /
        len(networks)
    )

    print("\n" + CYAN + "=" * 70)
    print("SECURITY SUMMARY")
    print("=" * 70 + RESET)

    print(f"\nNetworks discovered : {len(networks)}")
    print(f"High risk           : {RED}{high}{RESET}")
    print(f"Medium risk         : {YELLOW}{medium}{RESET}")
    print(f"Low risk            : {GREEN}{low}{RESET}")
    print(f"Open networks       : {RED}{open_count}{RESET}")
    print(f"WEP networks        : {RED}{wep_count}{RESET}")
    print(f"WPA2 networks       : {wpa2_count}")
    print(f"WPA3 networks       : {wpa3_count}")
    print(f"Average signal      : {average_signal}%")

    if high > 0:
        print(
            RED +
            "\n[!] High-risk wireless networks detected."
            + RESET
        )

    if open_count > 0:
        print(
            YELLOW +
            "[!] Open wireless networks detected."
            + RESET
        )


def baseline_create(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    baseline = {}

    for network in networks:

        baseline[network["ssid"]] = {
            "authentication": network["authentication"],
            "encryption": network["encryption"],
            "bssids": [
                item["bssid"]
                for item in network["bssids"]
            ]
        }

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


def baseline_compare(networks):
    if not os.path.exists(BASELINE_FILE):
        print(
            YELLOW +
            "No baseline exists. Create one first."
            + RESET
        )
        return

    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        baseline = json.load(file)

    current = {
        n["ssid"]: n
        for n in networks
    }

    baseline_ssids = set(baseline)
    current_ssids = set(current)

    new_ssids = current_ssids - baseline_ssids
    missing_ssids = baseline_ssids - current_ssids

    print("\n" + CYAN + "=" * 70)
    print("BASELINE COMPARISON")
    print("=" * 70 + RESET)

    if new_ssids:
        print("\n" + RED + "NEW NETWORKS" + RESET)

        for ssid in sorted(new_ssids):
            print(f"  + {ssid}")

    else:
        print(
            GREEN +
            "\n✓ No new SSIDs detected."
            + RESET
        )

    if missing_ssids:
        print("\n" + YELLOW + "MISSING NETWORKS" + RESET)

        for ssid in sorted(missing_ssids):
            print(f"  - {ssid}")

    else:
        print(
            GREEN +
            "✓ No baseline SSIDs disappeared."
            + RESET
        )

    changed = []

    for ssid in baseline_ssids & current_ssids:

        old = baseline[ssid]
        new = current[ssid]

        if (
            old["authentication"] !=
            new["authentication"]
            or old["encryption"] !=
            new["encryption"]
        ):
            changed.append(ssid)

    if changed:

        print("\n" + RED + "SECURITY CHANGES" + RESET)

        for ssid in changed:
            print(f"  ! {ssid}")

    else:

        print(
            GREEN +
            "✓ No authentication/encryption changes detected."
            + RESET
        )


def export_json(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    report = {
        "tool": "Wi-Fi Security Analyzer",
        "generated": datetime.now().isoformat(),
        "network_count": len(networks),
        "networks": networks
    }

    with open(
        JSON_FILE,
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
        f"\n[+] Created {JSON_FILE}"
        + RESET
    )


def export_csv(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    with open(
        CSV_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "SSID",
            "BSSID",
            "Authentication",
            "Encryption",
            "Signal",
            "Channel",
            "Radio",
            "Risk Score",
            "Risk"
        ])

        for network in networks:

            if network["bssids"]:

                for item in network["bssids"]:

                    writer.writerow([
                        network["ssid"],
                        item["bssid"],
                        network["authentication"],
                        network["encryption"],
                        signal_value(item["signal"]),
                        item["channel"],
                        item["radio"],
                        network["risk_score"],
                        network["risk"]
                    ])

            else:

                writer.writerow([
                    network["ssid"],
                    "",
                    network["authentication"],
                    network["encryption"],
                    signal_value(network["signal"]),
                    network["channel"],
                    network["radio"],
                    network["risk_score"],
                    network["risk"]
                ])

    print(
        GREEN +
        f"\n[+] Created {CSV_FILE}"
        + RESET
    )


def export_html(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    rows = ""

    for network in networks:

        rows += f"""
        <tr>
            <td>{network['ssid']}</td>
            <td>{network['authentication']}</td>
            <td>{network['encryption']}</td>
            <td>{network['signal']}</td>
            <td>{network['channel']}</td>
            <td>{len(network['bssids'])}</td>
            <td class="{network['risk'].lower()}">
                {network['risk']}
                ({network['risk_score']})
            </td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Wi-Fi Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #10141a;
    color: #ffffff;
    padding: 30px;
}}

h1 {{
    text-align: center;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 30px;
}}

th, td {{
    padding: 12px;
    border: 1px solid #303640;
    text-align: left;
}}

th {{
    background: #202631;
}}

tr:nth-child(even) {{
    background: #171c24;
}}

.high {{
    color: #ff4d4d;
    font-weight: bold;
}}

.medium {{
    color: #ffd24d;
    font-weight: bold;
}}

.low {{
    color: #55e68a;
    font-weight: bold;
}}

.footer {{
    margin-top: 30px;
    text-align: center;
    color: #8c96a5;
}}

</style>
</head>

<body>

<h1>Wi-Fi Security Assessment</h1>

<p>
Generated:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</p>

<p>
Networks discovered:
{len(networks)}
</p>

<table>

<tr>
<th>SSID</th>
<th>Authentication</th>
<th>Encryption</th>
<th>Signal</th>
<th>Channel</th>
<th>BSSIDs</th>
<th>Risk</th>
</tr>

{rows}

</table>

<div class="footer">
Wi-Fi Security Analyzer
</div>

</body>
</html>
"""

    with open(
        HTML_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(html)

    print(
        GREEN +
        f"\n[+] Created {HTML_FILE}"
        + RESET
    )


def history():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT
            timestamp,
            COUNT(DISTINCT ssid),
            AVG(signal),
            MAX(risk_score)
        FROM scans
        GROUP BY timestamp
        ORDER BY timestamp DESC
        LIMIT 20
    """)

    records = cur.fetchall()

    conn.close()

    print("\n" + CYAN + "=" * 80)
    print("SCAN HISTORY")
    print("=" * 80 + RESET)

    if not records:
        print("No history available.")
        return

    for record in records:

        timestamp, count, avg_signal, max_risk = record

        print(
            f"{timestamp} | "
            f"Networks: {count:<3} | "
            f"Avg Signal: {round(avg_signal or 0)}% | "
            f"Max Risk: {max_risk}"
        )


def search_network(networks):
    if not networks:
        print(YELLOW + "Perform a scan first." + RESET)
        return

    query = input(
        "\nEnter SSID search term: "
    ).lower()

    matches = [
        n for n in networks
        if query in n["ssid"].lower()
    ]

    if not matches:
        print(YELLOW + "No matching networks." + RESET)
        return

    display_networks(matches)


def monitor():
    print("\n" + CYAN + "=" * 70)
    print("CONTINUOUS MONITORING")
    print("=" * 70 + RESET)

    try:
        interval = int(
            input("Scan interval in seconds [10]: ") or "10"
        )
    except ValueError:
        interval = 10

    previous = {}

    try:

        while True:

            clear()
            header()

            networks = scan()

            current = {
                n["ssid"]: n
                for n in networks
            }

            if previous:

                new_networks = (
                    set(current) - set(previous)
                )

                removed_networks = (
                    set(previous) - set(current)
                )

                if new_networks:

                    print(
                        "\n" +
                        RED +
                        "ALERT: NEW NETWORK DETECTED"
                        + RESET
                    )

                    for ssid in new_networks:
                        print(f"  + {ssid}")

                if removed_networks:

                    print(
                        "\n" +
                        YELLOW +
                        "NETWORK NO LONGER VISIBLE"
                        + RESET
                    )

                    for ssid in removed_networks:
                        print(f"  - {ssid}")

                for ssid in set(current) & set(previous):

                    old = previous[ssid]
                    new = current[ssid]

                    if (
                        old["authentication"]
                        !=
                        new["authentication"]
                    ):

                        print(
                            RED +
                            f"\nALERT: SECURITY CHANGE - {ssid}"
                            + RESET
                        )

                    if (
                        old["encryption"]
                        !=
                        new["encryption"]
                    ):

                        print(
                            RED +
                            f"ALERT: ENCRYPTION CHANGE - {ssid}"
                            + RESET
                        )

            display_networks(networks)

            previous = current

            print(
                f"\nNext scan in {interval} seconds..."
            )

            time.sleep(interval)

    except KeyboardInterrupt:

        print(
            GREEN +
            "\n\n[+] Monitoring stopped."
            + RESET
        )


def menu():
    db_init()

    networks = []

    while True:

        clear()
        header()

        print("1. Scan Networks")
        print("2. View Networks")
        print("3. Detailed Assessment")
        print("4. Channel Analysis")
        print("5. Security Summary")
        print("6. Create Baseline")
        print("7. Compare Baseline")
        print("8. Continuous Monitoring")
        print("9. Search SSID")
        print("10. Scan History")
        print("11. Export JSON")
        print("12. Export CSV")
        print("13. Export HTML Report")
        print("0. Exit")

        choice = input(
            "\nSelect option: "
        ).strip()

        if choice == "1":
            networks = scan()
            input("\nPress Enter to continue...")

        elif choice == "2":
            display_networks(networks)
            input("\nPress Enter to continue...")

        elif choice == "3":
            details(networks)
            input("\nPress Enter to continue...")

        elif choice == "4":
            channel_analysis(networks)
            input("\nPress Enter to continue...")

        elif choice == "5":
            summary(networks)
            input("\nPress Enter to continue...")

        elif choice == "6":
            if not networks:
                networks = scan()

            baseline_create(networks)
            input("\nPress Enter to continue...")

        elif choice == "7":
            if not networks:
                networks = scan()

            baseline_compare(networks)
            input("\nPress Enter to continue...")

        elif choice == "8":
            monitor()
            input("\nPress Enter to continue...")

        elif choice == "9":
            search_network(networks)
            input("\nPress Enter to continue...")

        elif choice == "10":
            history()
            input("\nPress Enter to continue...")

        elif choice == "11":
            export_json(networks)
            input("\nPress Enter to continue...")

        elif choice == "12":
            export_csv(networks)
            input("\nPress Enter to continue...")

        elif choice == "13":
            export_html(networks)
            input("\nPress Enter to continue...")

        elif choice == "0":
            print(
                GREEN +
                "\nExiting..."
                + RESET
            )
            break

        else:
            print(
                RED +
                "\nInvalid option."
                + RESET
            )
            time.sleep(1)


if __name__ == "__main__":
    menu()