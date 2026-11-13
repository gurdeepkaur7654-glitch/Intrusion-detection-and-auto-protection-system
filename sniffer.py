from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from collections import defaultdict
from datetime import datetime
import geoip2.database
import threading
import time

reader = geoip2.database.Reader("GeoLite2-City.mmdb")
running = False
current_interface = None
live_packets = []
alerts = []
attack_timeline = []

attacker_ips = defaultdict(int)
packet_rate = 0
packet_count = 0
packets_per_second = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
port_scan_count = 0
udp_attack_count = 0
icmp_attack_count = 0
syn_flood_count = 0


port_scan_tracker = defaultdict(set)
udp_tracker = defaultdict(set)
icmp_tracker = defaultdict(int)
syn_tracker = defaultdict(int)


def get_location(ip):
    try:
        response = reader.city(ip)

        city = response.city.name or "Unknown City"
        country = response.country.name or "Unknown Country"

        return f"{city}, {country}"

    except Exception:
        return "Private/Local IP"


def update_packet_rate():
    global packet_rate
    global packets_per_second

    while running:
        time.sleep(1)
        packets_per_second = packet_rate
        packet_rate = 0


def process_packet(packet):

    global packet_rate
    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global port_scan_count
    global udp_attack_count
    global icmp_attack_count
    global syn_flood_count

    if IP not in packet:
        return

    packet_count += 1
    packet_rate += 1

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if (
        src_ip.startswith("224.")
        or dst_ip.startswith("224.")
        or dst_ip == "255.255.255.255"
    ):
        return

    time_now = datetime.now().strftime("%H:%M:%S")

    protocol = ""
    src_port = "-"
    dst_port = "-"

    if TCP in packet:

        tcp_count += 1
        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) == 20:

            port_scan_count += 1
            attacker_ips[src_ip] += 1

            location = get_location(src_ip)

            alert = (
                f"[{time_now}] " f"Port Scan detected from " f"{src_ip} ({location})"
            )

            alerts.append(alert)
            attack_timeline.append(alert)

        if packet[TCP].flags & 0x02:

            syn_tracker[src_ip] += 1

            if syn_tracker[src_ip] == 50:

                syn_flood_count += 1
                attacker_ips[src_ip] += 1

                location = get_location(src_ip)

                alert = (
                    f"[{time_now}] "
                    f"SYN Flood detected from "
                    f"{src_ip} ({location})"
                )

                alerts.append(alert)
                attack_timeline.append(alert)

    elif UDP in packet:

        udp_count += 1
        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        udp_tracker[src_ip].add(dst_port)

        if len(udp_tracker[src_ip]) == 50:

            udp_attack_count += 1
            attacker_ips[src_ip] += 1

            location = get_location(src_ip)

            alert = (
                f"[{time_now}] " f"UDP Flood detected from " f"{src_ip} ({location})"
            )

            alerts.append(alert)

            attack_timeline.append(alert)

    elif ICMP in packet:

        icmp_count += 1
        protocol = "ICMP"

        icmp_tracker[src_ip] += 1

        if icmp_tracker[src_ip] == 50:

            icmp_attack_count += 1
            attacker_ips[src_ip] += 1

            location = get_location(src_ip)

            alert = (
                f"[{time_now}] " f"ICMP Flood detected from " f"{src_ip} ({location})"
            )

            alerts.append(alert)
            attack_timeline.append(alert)

    location = get_location(src_ip)

    live_packets.append(
        (
            packet_count,
            time_now,
            src_ip,
            location,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            len(packet),
        )
    )

    # Keep only last 300 packets
    if len(live_packets) > 300:
        live_packets.pop(0)


from scapy.all import conf

def resolve_interface(iface):
    if iface is None or iface == "Any":
        return None

    # If the combobox value is like:
    # "VirtualBox Host-Only Ethernet Adapter #2 (VirtualBox Host-Only Ethernet Adapter)"
    if "(" in iface:
        iface = iface.split("(")[0].strip()

    for name, scapy_iface in conf.ifaces.items():

        desc = (scapy_iface.description or "").strip()

        print(f"{name} --> {desc}")

        if iface.lower() == desc.lower():
            print("Matched:", name)
            return name

    print("No interface matched!")
    return None


def start_sniffer(interface=None):
    global running, current_interface

    running = True

    resolved = resolve_interface(interface)
    current_interface = resolved

    print("Selected:", interface)
    print("Resolved:", resolved)

    threading.Thread(target=update_packet_rate, daemon=True).start()

    while running:
        sniff(
            iface=resolved,
            filter="tcp or udp or icmp",
            prn=process_packet,
            store=False,
            timeout=1,
        )

def stop_sniffer():
    global running
    running = False
