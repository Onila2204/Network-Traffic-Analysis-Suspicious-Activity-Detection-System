
import pyshark
import matplotlib.pyplot as plt

from collections import defaultdict
from datetime import datetime
import os


# ============================================================
# NETSENTRY
# NETWORK TRAFFIC ANALYZER AND SUSPICIOUS ACTIVITY
# DETECTION SYSTEM
# ============================================================


# ============================================================
# FUNCTION 1: GENERATE GRAPHICAL DASHBOARD
# ============================================================

def generate_dashboard(traffic_events, suspicious_report,
                      packet_number, ip_packet_count, folder):

    if not traffic_events:
        print("\nNo IPv4 traffic available for dashboard.")
        return None

    # ---------------- PROCESS TRAFFIC DATA ----------------

    start_time = min(t for t, ip in traffic_events)
    end_time = max(t for t, ip in traffic_events)

    total_traffic = defaultdict(int)
    suspicious_traffic = defaultdict(int)

    flagged_ips = {
        item["src"] for item in suspicious_report
    }

    # Count packets per second

    for timestamp, ip in traffic_events:

        second = int(timestamp - start_time)

        total_traffic[second] += 1

        if ip in flagged_ips:
            suspicious_traffic[second] += 1

    max_second = max(total_traffic.keys())

    seconds = list(range(max_second + 1))

    total_values = [
        total_traffic[s] for s in seconds
    ]

    suspicious_values = [
        suspicious_traffic[s] for s in seconds
    ]

    normal_values = [
        total_traffic[s] - suspicious_traffic[s]
        for s in seconds
    ]

    suspicious_packet_total = sum(suspicious_values)

    capture_duration = end_time - start_time

    # ---------------- DASHBOARD BACKGROUND ----------------

    fig = plt.figure(
        figsize=(16, 10),
        facecolor="#080F1D"
    )

    # Main heading

    fig.text(
        0.05, 0.965,
        "NETSENTRY",
        fontsize=24,
        fontweight="bold",
        color="white"
    )

    fig.text(
        0.05, 0.925,
        "NETWORK TRAFFIC ANALYZER AND SUSPICIOUS ACTIVITY",
        fontsize=11,
        color="#9BAFC8"
    )

    fig.text(
        0.05, 0.900,
        "DETECTION SYSTEM",
        fontsize=11,
        color="#9BAFC8"
    )

    fig.text(
        0.95, 0.955,
        "PCAP ANALYSIS DASHBOARD",
        fontsize=10,
        color="#60A5FA",
        ha="right"
    )

    fig.text(
        0.95, 0.925,
        datetime.now().strftime("%d-%m-%Y %H:%M"),
        fontsize=9,
        color="#9BAFC8",
        ha="right"
    )

    # ========================================================
    # TOP STATISTICS CARDS
    # ========================================================

    ipv4_count = sum(ip_packet_count.values())

    cards = [
        ("TOTAL PACKETS", packet_number, "#3182CE"),
        ("IPv4 PACKETS", ipv4_count, "#22A06B"),
        ("SECURITY ALERTS", len(suspicious_report), "#E05252"),
        ("FLAGGED IPs", len(flagged_ips), "#E9A23B"),
        ("SUSPICIOUS PACKETS", suspicious_packet_total, "#A855F7")
    ]

    positions = [0.05, 0.24, 0.43, 0.62, 0.81]

    for (label, value, color), x in zip(cards, positions):

        ax = fig.add_axes([x, 0.785, 0.17, 0.095])

        ax.set_facecolor("#121F33")

        for spine in ax.spines.values():
            spine.set_color("#263850")

        ax.set_xticks([])
        ax.set_yticks([])

        ax.text(
            0.08, 0.70,
            label,
            transform=ax.transAxes,
            fontsize=8,
            color="#AABBD2"
        )

        ax.text(
            0.08, 0.22,
            f"{value:,}",
            transform=ax.transAxes,
            fontsize=19,
            fontweight="bold",
            color=color
        )

    # ========================================================
    # TRAFFIC OVERVIEW GRAPH
    # ========================================================

    ax1 = fig.add_axes([0.05, 0.405, 0.58, 0.32])

    ax1.set_facecolor("#101B2C")

    # Normal traffic

    ax1.plot(
        seconds,
        normal_values,
        color="#3182F6",
        linewidth=2,
        marker="o",
        markersize=3,
        label="Normal Traffic"
    )

    # Suspicious-source traffic

    ax1.plot(
        seconds,
        suspicious_values,
        color="#F59E0B",
        linewidth=2,
        marker="o",
        markersize=3,
        label="Suspicious Traffic"
    )

    # Highlight seconds containing suspicious-source packets

    for second in seconds:

        if suspicious_traffic[second] > 0:

            ax1.axvspan(
                second - 0.5,
                second + 0.5,
                color="#E05252",
                alpha=0.10
            )

    ax1.set_title(
        "TRAFFIC OVERVIEW",
        color="white",
        fontsize=13,
        fontweight="bold",
        loc="left",
        pad=15
    )

    ax1.set_xlabel(
        "Time (Seconds)",
        color="#AABBD2"
    )

    ax1.set_ylabel(
        "Packets per Second",
        color="#AABBD2"
    )

    ax1.tick_params(colors="#AABBD2")

    ax1.grid(
        color="#29374B",
        alpha=0.5
    )

    ax1.legend(
        facecolor="#17243A",
        labelcolor="white",
        loc="upper left",
        fontsize=9
    )

    for spine in ax1.spines.values():
        spine.set_color("#29374B")

    # ========================================================
    # ATTACK DISTRIBUTION DONUT CHART
    # ========================================================

    ax2 = fig.add_axes([0.68, 0.405, 0.27, 0.32])

    ax2.set_facecolor("#101B2C")

    attack_counts = defaultdict(int)

    for item in suspicious_report:

        attack_counts[item["type"]] += 1

    ax2.set_title(
        "TOP DETECTED ATTACK TYPES",
        color="white",
        fontsize=12,
        fontweight="bold",
        loc="left",
        pad=15
    )

    if attack_counts:

        labels = list(attack_counts.keys())

        values = list(attack_counts.values())

        colors = [
            "#3182F6",
            "#E05252",
            "#F59E0B",
            "#22C55E"
        ]

        wedges, _ = ax2.pie(
            values,
            colors=colors[:len(values)],
            startangle=90,
            wedgeprops={
                "width": 0.38,
                "edgecolor": "#101B2C"
            }
        )

        ax2.text(
            0, 0,
            f"{sum(values)}\nAlerts",
            ha="center",
            va="center",
            fontsize=15,
            fontweight="bold",
            color="white"
        )

        ax2.legend(
            wedges,
            labels,
            loc="center left",
            bbox_to_anchor=(0.95, 0.5),
            facecolor="#101B2C",
            labelcolor="white",
            fontsize=8
        )

    else:

        ax2.text(
            0, 0,
            "No Alerts",
            ha="center",
            va="center",
            color="white",
            fontsize=14
        )

    # ========================================================
    # RECENT SECURITY ALERTS TABLE
    # ========================================================

    ax3 = fig.add_axes([0.05, 0.075, 0.58, 0.255])

    ax3.set_facecolor("#101B2C")

    ax3.axis("off")

    ax3.set_title(
        "RECENT SECURITY ALERTS",
        color="white",
        fontsize=13,
        fontweight="bold",
        loc="left",
        pad=12
    )

    table_rows = []

    for item in suspicious_report[:6]:

        table_rows.append([
            item["type"],
            item["src"],
            item["details"][:35],
            item["attack"]
        ])

    if table_rows:

        table = ax3.table(
            cellText=table_rows,
            colLabels=[
                "ACTIVITY",
                "SOURCE IP",
                "DETAILS",
                "POSSIBLE ATTACK"
            ],
            cellLoc="center",
            loc="center",
            colWidths=[0.20, 0.19, 0.27, 0.34]
        )

        table.auto_set_font_size(False)

        table.set_fontsize(8)

        table.scale(1, 2.0)

        for (row, col), cell in table.get_celld().items():

            cell.set_edgecolor("#29374B")

            if row == 0:

                cell.set_facecolor("#263850")

                cell.set_text_props(
                    color="white",
                    weight="bold"
                )

            else:

                cell.set_facecolor("#142238")

                cell.set_text_props(
                    color="#D6E1EF"
                )

    else:

        ax3.text(
            0.5, 0.5,
            "No suspicious activities detected",
            color="#22C55E",
            ha="center",
            va="center",
            fontsize=12
        )

    # ========================================================
    # SECURITY STATUS PANEL
    # ========================================================

    ax4 = fig.add_axes([0.68, 0.075, 0.27, 0.255])

    ax4.set_facecolor("#101B2C")

    ax4.axis("off")

    ax4.set_title(
        "SYSTEM SECURITY STATUS",
        color="white",
        fontsize=12,
        fontweight="bold",
        loc="left",
        pad=12
    )

    status = (
        "SUSPICIOUS TRAFFIC DETECTED"
        if suspicious_report
        else "NO SUSPICIOUS PATTERNS DETECTED"
    )

    status_color = (
        "#E05252"
        if suspicious_report
        else "#22C55E"
    )

    summary = [
        ("Security Assessment", status),
        ("Total Packets", str(packet_number)),
        ("IPv4 Source IPs", str(len(ip_packet_count))),
        ("Flagged IPs", str(len(flagged_ips))),
        ("Detected Alerts", str(len(suspicious_report))),
        ("Capture Duration", f"{capture_duration:.2f} sec")
    ]

    for i, (label, value) in enumerate(summary):

        y = 0.83 - i * 0.15

        ax4.text(
            0.03,
            y,
            label,
            transform=ax4.transAxes,
            color="#AABBD2",
            fontsize=8
        )

        ax4.text(
            0.98,
            y,
            value,
            transform=ax4.transAxes,
            color=status_color if i == 0 else "white",
            fontsize=8,
            ha="right",
            fontweight="bold"
        )

    # ---------------- SAVE DASHBOARD ----------------

    dashboard_path = os.path.join(
        folder,
        "NetSentry_Dashboard.png"
    )

    fig.savefig(
        dashboard_path,
        dpi=250,
        facecolor=fig.get_facecolor(),
        bbox_inches="tight"
    )

    plt.close(fig)

    print("\nDashboard generated successfully!")

    print("Dashboard saved at:", dashboard_path)

    return dashboard_path


# ============================================================
# FUNCTION 2: ANALYZE PCAP FILE
# ============================================================

def analyze_pcap(file_path):

    file_path = file_path.strip().strip('"')

    # Check file existence

    if not os.path.isfile(file_path):

        print("\nFile not found. Please check the path.")

        return

    # Check file extension

    if not file_path.lower().endswith(
        (".pcap", ".pcapng")
    ):

        print("\nPlease provide a PCAP or PCAPNG file.")

        return

    folder = os.path.dirname(
        os.path.abspath(__file__)
    )

    # ---------------- INITIALIZE VARIABLES ----------------

    ip_packet_count = defaultdict(int)

    ip_ports = defaultdict(set)

    syn_count = defaultdict(int)

    icmp_count = defaultdict(int)

    suspicious_report = []

    traffic_events = []

    packet_number = 0

    print("\nAnalyzing network traffic... Please wait...\n")

    # ========================================================
    # PACKET CAPTURE AND ANALYSIS
    # ========================================================

    try:

        cap = pyshark.FileCapture(
            file_path,
            keep_packets=False
        )

        try:

            for packet in cap:

                packet_number += 1

                try:

                    # Analyze IPv4 packets

                    if not hasattr(packet, "ip"):

                        continue

                    src_ip = packet.ip.src

                    timestamp = float(
                        packet.sniff_timestamp
                    )

                    # Store packet timestamp and source IP

                    traffic_events.append(
                        (timestamp, src_ip)
                    )

                    ip_packet_count[src_ip] += 1

                    # ---------------- TCP ANALYSIS ----------------

                    if hasattr(packet, "tcp"):

                        dst_port = int(
                            packet.tcp.dstport
                        )

                        ip_ports[src_ip].add(dst_port)

                        # SYN flag without ACK

                        flags = int(
                            packet.tcp.flags,
                            16
                        )

                        if (
                            flags & 0x02
                        ) and not (
                            flags & 0x10
                        ):

                            syn_count[src_ip] += 1

                    # ---------------- ICMP ANALYSIS ----------------

                    if hasattr(packet, "icmp"):

                        icmp_count[src_ip] += 1

                except (
                    AttributeError,
                    ValueError,
                    TypeError
                ):

                    continue

        finally:

            cap.close()

    except Exception as e:

        print("\nError while reading PCAP file:", e)

        print(
            "\nCheck that Wireshark and TShark are installed correctly."
        )

        return

    print("Total packets analyzed:", packet_number)

    print(
        "IPv4 packets analyzed:",
        sum(ip_packet_count.values())
    )

    # ========================================================
    # SUSPICIOUS ACTIVITY DETECTION
    # ========================================================

    for ip in ip_packet_count:

        # ---------------- 1. HIGH TRAFFIC VOLUME ----------------

        if ip_packet_count[ip] > 200:

            suspicious_report.append({

                "type": "High Traffic Volume",

                "src": ip,

                "details": (
                    f"{ip} sent {ip_packet_count[ip]} packets"
                ),

                "reason": (
                    "Unusually high number of packets "
                    "from a single source"
                ),

                "attack": "Possible DoS/DDoS Attack",

                "filter": f"ip.src == {ip}",

                "filter_result": (
                    "Shows all traffic originating from this IP"
                )

            })

        # ---------------- 2. PORT SCANNING ----------------

        if len(ip_ports[ip]) > 25:

            suspicious_report.append({

                "type": "Port Scanning",

                "src": ip,

                "details": (
                    f"{len(ip_ports[ip])} different TCP "
                    "destination ports accessed"
                ),

                "reason": (
                    "Accessing many destination ports"
                ),

                "attack": "Port Scanning (Reconnaissance)",

                "filter": (
                    f"ip.src == {ip} && "
                    "tcp.flags.syn == 1 && "
                    "tcp.flags.ack == 0"
                ),

                "filter_result": (
                    "Shows TCP SYN connection attempts "
                    "from this IP"
                )

            })

        # ---------------- 3. SYN FLOOD ----------------

        if syn_count[ip] > 100:

            suspicious_report.append({

                "type": "SYN Flood",

                "src": ip,

                "details": (
                    f"{ip} sent {syn_count[ip]} SYN packets"
                ),

                "reason": (
                    "Large number of TCP SYN packets detected"
                ),

                "attack": "Possible SYN Flood Attack",

                "filter": (
                    f"ip.src == {ip} && "
                    "tcp.flags.syn == 1 && "
                    "tcp.flags.ack == 0"
                ),

                "filter_result": (
                    "Displays TCP SYN packets without ACK "
                    "from this IP"
                )

            })

        # ---------------- 4. ICMP FLOOD ----------------

        if icmp_count[ip] > 50:

            suspicious_report.append({

                "type": "ICMP Flood",

                "src": ip,

                "details": (
                    f"{ip} sent {icmp_count[ip]} ICMP packets"
                ),

                "reason": (
                    "Excessive ICMP traffic detected"
                ),

                "attack": "Possible ICMP Flood / Ping Flood",

                "filter": f"ip.src == {ip} && icmp",

                "filter_result": (
                    "Shows ICMP packets originating from this IP"
                )

            })

    # ========================================================
    # OPTIONAL WIRESHARK FILTERS
    # ========================================================

    show_filters = False

    if suspicious_report:

        print("\nSuspicious traffic detected!")

        choice = input(
            "\nDo you want Wireshark filters and explanations "
            "in the report? (yes/no): "
        ).strip().lower()

        show_filters = choice in ("yes", "y")

    else:

        print(
            "\nNo configured suspicious activity thresholds "
            "were exceeded."
        )

    # ========================================================
    # GENERATE GRAPHICAL DASHBOARD
    # ========================================================

    dashboard_path = generate_dashboard(
        traffic_events,
        suspicious_report,
        packet_number,
        ip_packet_count,
        folder
    )

    # ========================================================
    # GENERATE TEXT REPORT
    # ========================================================

    report = []

    report.append("=" * 75)

    report.append(
        "NETSENTRY - NETWORK TRAFFIC ANALYZER"
    )

    report.append(
        "AND SUSPICIOUS ACTIVITY DETECTION SYSTEM"
    )

    report.append("=" * 75)

    report.append(
        f"\nReport Date : {datetime.now().strftime('%d-%m-%Y')}"
    )

    report.append(
        f"Report Time : {datetime.now().strftime('%H:%M:%S')}"
    )

    report.append(
        f"PCAP File   : {os.path.basename(file_path)}"
    )

    report.append(
        f"Total Packets Analyzed : {packet_number}"
    )

    report.append(
        f"IPv4 Packets Analyzed  : {sum(ip_packet_count.values())}"
    )

    report.append(
        f"Unique Source IPs      : {len(ip_packet_count)}"
    )

    if traffic_events:

        duration = (
            max(t for t, ip in traffic_events)
            - min(t for t, ip in traffic_events)
        )

        report.append(
            f"Capture Duration       : {duration:.2f} seconds"
        )

    if dashboard_path:

        report.append(
            f"Dashboard File         : "
            f"{os.path.basename(dashboard_path)}"
        )

    report.append("\n" + "=" * 75)

    report.append("TRAFFIC ANALYSIS SUMMARY")

    report.append("=" * 75)

    flagged_ips = {
        item["src"] for item in suspicious_report
    }

    report.append(
        f"\nTotal Suspicious Activities : {len(suspicious_report)}"
    )

    report.append(
        f"Flagged IP Addresses        : {len(flagged_ips)}"
    )

    # ---------------- SUSPICIOUS ACTIVITY DETAILS ----------------

    if suspicious_report:

        report.append(
            "\nSECURITY STATUS: SUSPICIOUS TRAFFIC DETECTED"
        )

        report.append("\n" + "=" * 75)

        report.append("SUSPICIOUS ACTIVITY DETAILS")

        report.append("=" * 75)

        for i, item in enumerate(suspicious_report, 1):

            report.append(f"\nISSUE #{i}")

            report.append("-" * 75)

            report.append(
                f"Activity Type    : {item['type']}"
            )

            report.append(
                f"Source IP        : {item['src']}"
            )

            report.append(
                f"Details          : {item['details']}"
            )

            report.append(
                f"Reason           : {item['reason']}"
            )

            report.append(
                f"Possible Attack  : {item['attack']}"
            )

            # Optional Wireshark information

            if show_filters:

                report.append(
                    f"Wireshark Filter : {item['filter']}"
                )

                report.append(
                    f"What it Shows    : {item['filter_result']}"
                )

    else:

        report.append(
            "\nSECURITY STATUS: "
            "NO CONFIGURED SUSPICIOUS PATTERNS DETECTED"
        )

        report.append(
            "\nNo detection thresholds were exceeded."
        )

    report.append("\n" + "=" * 75)

    report.append("END OF NETSENTRY REPORT")

    report.append("=" * 75)

    # ========================================================
    # SAVE REPORT
    # ========================================================

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    report_name = (
        f"NetSentry_Report_{timestamp}.txt"
    )

    report_path = os.path.join(
        folder,
        report_name
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write("\n".join(report))

    # ========================================================
    # DISPLAY FINAL REPORT
    # ========================================================

    print("\n" + "\n".join(report))

    print("\n" + "=" * 65)

    print("NETSENTRY ANALYSIS COMPLETED")

    print("=" * 65)

    print("\nReport saved at:")

    print(report_path)

    if dashboard_path:

        print("\nDashboard saved at:")

        print(dashboard_path)


# ============================================================
# MAIN PROGRAM EXECUTION
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 75)

    print("NETSENTRY")

    print(
        "NETWORK TRAFFIC ANALYZER AND SUSPICIOUS ACTIVITY "
        "DETECTION SYSTEM"
    )

    print("=" * 75)

    file_path = input(
        "\nEnter PCAP/PCAPNG file path: "
    )

    analyze_pcap(file_path)
