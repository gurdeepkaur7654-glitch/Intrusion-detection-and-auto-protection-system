import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from tkinter import ttk
from tkinter import filedialog
from matplotlib.ticker import MaxNLocator
from PIL import ImageGrab
import sniffer
import threading
import psutil
from datetime import datetime
import time
import socket
from tkinter import messagebox
import numpy as np

sniffer_thread = None
start_time = None
ids_running = False
elapsed_time = 0
fill = None

packet_count = 0
alert_count = 0

total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0
alert_count = 0
last_alert = ""


def update_graph():

    global traffic_data

    if ids_running:
        traffic_data.pop(0)
        traffic_data.append(sniffer.packets_per_second)

    line.set_ydata(traffic_data)

    while ax.collections:
        ax.collections[0].remove()

    line.set_data(range(len(traffic_data)), traffic_data)

    ax.set_ylim(0, max(max(traffic_data) + 2, 10))

    ax.fill_between(
        range(len(traffic_data)),
        traffic_data,
        color="#00FF66",
        alpha=0.18,
    )

    canvas.draw_idle()

    root.after(1000, update_graph)


def update_threat_level():

    total_attacks = (
        sniffer.port_scan_count
        + sniffer.syn_flood_count
        + sniffer.udp_attack_count
        + sniffer.icmp_attack_count
    )

    if total_attacks == 0:
        threat = "SAFE"
        color = "#22c55e"

    elif total_attacks < 10:
        threat = "LOW"
        color = "#22c55e"

    elif total_attacks < 30:
        threat = "MEDIUM"
        color = "#facc15"

    elif total_attacks < 60:
        threat = "HIGH"
        color = "#f97316"

    else:
        threat = "CRITICAL"
        color = "#ef4444"

    threat_card.configure(text=threat, text_color=color)

    score = min(total_attacks * 5, 100)

    score_text.set_text(f"{score}/100")

    angle = np.pi * (1 - score / 100)

    needle_length = 0.82

    x = needle_length * np.cos(angle)
    y = needle_length * np.sin(angle)

    needle.set_data([0, x], [0, y])

    needle.set_color("white")

    gauge_canvas.draw_idle()

    root.after(1000, update_threat_level)


def update_protocol_chart():

    pie_ax.clear()

    data = [
        sniffer.tcp_count,
        sniffer.udp_count,
        sniffer.icmp_count,
    ]

    if sum(data) == 0:

        pie_ax.text(
            0.5,
            0.5,
            "No Network Traffic",
            ha="center",
            va="center",
            color="white",
            fontsize=14,
            weight="bold",
        )

        pie_ax.set_facecolor("#111827")
        pie_ax.axis("off")

    else:

        labels = ["TCP", "UDP", "ICMP"]

        colors = [
            "#38BDF8",
            "#F59E0B",
            "#22C55E",
        ]

        pie_ax.pie(
            data,
            colors=colors,
            autopct="%1.0f%%",
            startangle=90,
            wedgeprops=dict(width=0.45, edgecolor="#111827"),
            textprops={"color": "white"},
        )

        pie_ax.legend(
            labels,
            loc="center left",
            bbox_to_anchor=(1.0, 0.5),
            frameon=False,
            labelcolor="white",
        )

        pie_ax.set_aspect("equal")
        pie_ax.set_facecolor("#111827")

    pie_canvas.draw_idle()

    root.after(1000, update_protocol_chart)


def update_system():

    cpu = psutil.cpu_percent()

    ram = psutil.virtual_memory().percent

    cpu_label.configure(text=f"{cpu}%")

    ram_label.configure(text=f"{ram}%")

    root.after(1000, update_system)


def update_attack_chart():

    bar_ax.clear()

    names = [
        "Port Scan",
        "UDP Flood",
        "ICMP Flood",
        "SYN Flood",
    ]

    values = [
        sniffer.port_scan_count,
        sniffer.udp_attack_count,
        sniffer.icmp_attack_count,
        sniffer.syn_flood_count,
    ]

    colors = [
        "#ef4444",
        "#f59e0b",
        "#3b82f6",
        "#8b5cf6",
    ]

    bars = bar_ax.barh(
        names,
        values,
        color=colors,
        height=0.65,
        edgecolor="white",
        linewidth=1.5,
    )

    bar_ax.set_facecolor("#111827")

    bar_ax.grid(
        axis="x",
        color="#334155",
        linestyle="--",
        alpha=0.4,
    )

    bar_ax.tick_params(colors="white", labelsize=10)

    for spine in bar_ax.spines.values():
        spine.set_color("#64748B")

    for bar in bars:
        width = bar.get_width()

        bar_ax.text(
            width + 0.2,
            bar.get_y() + bar.get_height() / 2,
            str(int(width)),
            color="white",
            fontsize=10,
            fontweight="bold",
            va="center",
        )

    bar_ax.set_xlim(0, max(max(values) + 2, 5))

    bar_canvas.draw()

    root.after(1000, update_attack_chart)


previous_attackers = ""


def update_attackers():
    global previous_attackers

    text = ""

    top = sorted(sniffer.attacker_ips.items(), key=lambda x: x[1], reverse=True)[:5]

    if not top:
        text = "No attackers detected."

    else:
        for ip, count in top:
            text += (
                f"IP : {ip}\n"
                f"Location : {sniffer.get_location(ip)}\n"
                f"Attacks : {count}\n"
                "-----------------------------\n"
            )

    if text != previous_attackers:
        attacker_box.delete("1.0", "end")
        attacker_box.insert("end", text)
        previous_attackers = text

    root.after(1000, update_attackers)


def start_ids():

    global sniffer_thread
    global start_time
    global ids_running
    global elapsed_time

    if sniffer_thread is not None and sniffer_thread.is_alive():
        return

    start_time = time.time()
    ids_running = True

    adapter = None if adapter_var.get() == "Any" else adapter_var.get()
    sniffer_thread = threading.Thread(target=sniffer.start_sniffer, args=(adapter,), daemon=True)

    sniffer_thread.start()

    system_status.configure(state="normal")
    system_status.insert("end", "\n🟢 IDS Started")
    system_status.see("end")
    system_status.configure(state="disabled")

    status_bar.configure(
        text="🟢 Status: Monitoring | IDS Running", text_color="#00FF00"
    )
    start_btn.configure(state="disabled")
    stop_btn.configure(state="normal")


def stop_ids():

    global ids_running
    global sniffer_thread

    sniffer.stop_sniffer()
    ids_running = False

    sniffer_thread = None

    system_status.configure(state="normal")
    system_status.insert("end", "\n🔴 IDS Stopped")
    system_status.see("end")
    system_status.configure(state="disabled")

    status_bar.configure(
        text="🔴 Status: Stopped | IDS Not Running", text_color="#ff4444"
    )
    start_btn.configure(state="normal")
    stop_btn.configure(state="disabled")


def export_logs():

    filename = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        title="Save IDS Report",
    )

    if not filename:
        return

    with open(filename, "w") as file:

        file.write("=" * 60 + "\n")
        file.write("      INTRUSION DETECTION SYSTEM REPORT\n")
        file.write("=" * 60 + "\n\n")

        file.write(
            f"Report Generated : {datetime.now().strftime('%d-%b-%Y %I:%M:%S %p')}\n\n"
        )

        file.write("NETWORK SUMMARY\n")
        file.write("-" * 60 + "\n")
        file.write(f"Total Packets : {sniffer.packet_count}\n")
        file.write(f"TCP Packets   : {sniffer.tcp_count}\n")
        file.write(f"UDP Packets   : {sniffer.udp_count}\n")
        file.write(f"ICMP Packets  : {sniffer.icmp_count}\n\n")

        file.write("ATTACK SUMMARY\n")
        file.write("-" * 60 + "\n")
        file.write(f"Port Scan Attacks : {sniffer.port_scan_count}\n")
        file.write(f"UDP Flood Attacks : {sniffer.udp_attack_count}\n")
        file.write(f"ICMP Flood Attacks: {sniffer.icmp_attack_count}\n")
        file.write(f"SYN Attacks       : {sniffer.syn_flood_count}\n\n")

        file.write("TOP ATTACKERS\n")
        file.write("-" * 60 + "\n")

        if sniffer.attacker_ips:
            for ip, count in sorted(
                sniffer.attacker_ips.items(), key=lambda x: x[1], reverse=True
            ):
                file.write(f"{ip}  --->  {count} attacks\n")
        else:
            file.write("No attackers detected.\n")

        file.write("\n")

        file.write("ALERT LOGS\n")
        file.write("-" * 60 + "\n")

        if sniffer.alerts:
            for alert in sniffer.alerts:
                file.write(alert + "\n")
        else:
            file.write("No alerts detected.\n")

        file.write("\n")
        file.write("=" * 60 + "\n")
        file.write("End of IDS Report\n")
        file.write("=" * 60 + "\n")

    system_status.configure(state="normal")
    system_status.insert("end", "\n📄 IDS Report Exported Successfully")
    system_status.see("end")
    system_status.configure(state="disabled")


def take_screenshot():

    filename = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Image", "*.png")],
        title="Save Dashboard Screenshot",
    )

    if not filename:
        return

    root.update()

    x = root.winfo_rootx()
    y = root.winfo_rooty()
    w = x + root.winfo_width()
    h = y + root.winfo_height()

    img = ImageGrab.grab(bbox=(x, y, w, h))
    img.save(filename)

    system_status.configure(state="normal")
    system_status.insert("end", "\n📷 Dashboard Screenshot Saved")
    system_status.see("end")
    system_status.configure(state="disabled")


def clear_dashboard():

    sniffer.port_scan_tracker.clear()
    sniffer.syn_tracker.clear()
    sniffer.udp_tracker.clear()
    sniffer.icmp_tracker.clear()

    sniffer.alerts.clear()
    sniffer.attack_timeline.clear()
    sniffer.live_packets.clear()
    sniffer.attacker_ips.clear()

    sniffer.port_scan_count = 0
    sniffer.udp_attack_count = 0
    sniffer.icmp_attack_count = 0
    sniffer.syn_flood_count = 0

    sniffer.packet_count = 0
    sniffer.tcp_count = 0
    sniffer.udp_count = 0
    sniffer.icmp_count = 0

    recent_alerts.delete("1.0", "end")

    attack_timeline.delete("1.0", "end")

    attacker_box.delete("1.0", "end")

    for item in traffic_table.get_children():
        traffic_table.delete(item)

    packet_label.configure(text="0")
    tcp_label.configure(text="0")
    udp_label.configure(text="0")
    icmp_label.configure(text="0")
    alert_label.configure(text="0")

    threat_card.configure(text="SAFE", text_color="#22c55e")

    score_text.set_text("0/100")
    gauge_canvas.draw_idle()

    system_status.configure(state="normal")
    system_status.insert("end", "\n🧹 Dashboard Cleared Successfully")
    system_status.see("end")
    system_status.configure(state="disabled")


def get_adapter_descriptions():
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetAdapter | Select-Object Name, InterfaceDescription | ConvertTo-Json"],
            capture_output=True, text=True, timeout=5
        )
        import json
        data = json.loads(result.stdout)
        mapping = {}
        if isinstance(data, dict):
            mapping[data["Name"]] = data["InterfaceDescription"]
        else:
            for item in data:
                mapping[item["Name"]] = item["InterfaceDescription"]
        return mapping
    except:
        return {}


def get_available_adapters():
    adapters = list(psutil.net_if_addrs().keys())
    desc_map = get_adapter_descriptions()
    names = []
    for a in adapters:
        desc = desc_map.get(a)
        names.append(f"{desc} ({a})" if desc else a)
    return names if names else ["Any"]


def apply_adapter(choice):
    if choice == "Any":
        sniffer.current_interface = None
    else:
        if "(" in choice and choice.endswith(")"):
            sniffer.current_interface = choice.split("(")[-1].rstrip(")")
        else:
            sniffer.current_interface = choice


def update_network_info():

    hostname = socket.gethostname()

    try:
        ip = socket.gethostbyname(hostname)

        if ip.startswith("127."):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()

    except Exception:
        ip = "Not Connected"

    hostname_label.configure(text=f"💻 Host: {hostname}")
    ip_label.configure(text=f"🌐 IP: {ip}")

    interfaces = psutil.net_if_addrs()

    interface = "Unknown"

    for name, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                interface = name
            break
        if interface != "Unknown":
            break

    interface_label.configure(text=f"📡 Interface: {interface}")

    available = get_available_adapters()
    if adapter_combo.cget("values") != available:
        adapter_combo.configure(values=available)

    root.after(5000, update_network_info)


def check_new_alert():
    global last_alert

    if sniffer.alerts:
        latest = sniffer.alerts[-1]

        if latest != last_alert:
            last_alert = latest

            messagebox.showwarning("⚠ Intrusion Detected", latest)

    root.after(1000, check_new_alert)


def update_cards():

    packet_label.configure(text=str(sniffer.packet_count))
    tcp_label.configure(text=str(sniffer.tcp_count))
    udp_label.configure(text=str(sniffer.udp_count))
    icmp_label.configure(text=str(sniffer.icmp_count))

    alert_label.configure(
        text=str(
            sniffer.port_scan_count
            + sniffer.udp_attack_count
            + sniffer.icmp_attack_count
            + sniffer.syn_flood_count
        )
    )

    root.after(1000, update_cards)


def update_table():

    keep_bottom = traffic_table.yview()[1] == 1.0

    while sniffer.live_packets:
        p = sniffer.live_packets.pop(0)
        traffic_table.insert("", "end", values=p)

        if len(traffic_table.get_children()) > 300:
            traffic_table.delete(traffic_table.get_children()[0])

    if keep_bottom:
        children = traffic_table.get_children()
        if children:
            traffic_table.see(children[-1])

    root.after(500, update_table)


alert_last = 0


def update_alerts():
    global alert_last

    while alert_last < len(sniffer.alerts):
        recent_alerts.insert("end", sniffer.alerts[alert_last] + "\n")
        alert_last += 1

    root.after(1000, update_alerts)


timeline_last = 0


def update_timeline():
    global timeline_last

    while timeline_last < len(sniffer.attack_timeline):
        attack_timeline.insert("end", sniffer.attack_timeline[timeline_last] + "\n")
        timeline_last += 1

    root.after(1000, update_timeline)


def update_clock():

    global elapsed_time
    now = datetime.now().strftime("%d-%b-%Y %I:%M:%S %p")
    time_label.configure(text=f"🕒 {now}")

    if ids_running and start_time is not None:
        elapsed_time = int(time.time() - start_time)

    hrs = elapsed_time // 3600
    mins = (elapsed_time % 3600) // 60
    secs = elapsed_time % 60

    uptime_label.configure(text=f"⏱ Uptime: {hrs:02}:{mins:02}:{secs:02}")
    root.after(1000, update_clock)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("IDS Dashboard - Intrusion Detection System")
root.state("zoomed")

root.grid_rowconfigure(0, minsize=90)
root.configure(fg_color="#020817")

root.grid_rowconfigure(0, weight=0)  # Header
root.grid_rowconfigure(1, weight=0)  # Cards
root.grid_rowconfigure(2, weight=4)  # Graphs
root.grid_rowconfigure(3, weight=3)  # Status
root.grid_rowconfigure(4, weight=5)  # Tables
root.grid_rowconfigure(5, weight=0)  # Buttons
root.grid_rowconfigure(6, weight=0)  # Footer

for i in range(8):
    root.grid_columnconfigure(i, weight=1, uniform="cols")

title = ctk.CTkLabel(
    root,
    text="🛡 INTRUSION DETECTION SYSTEM",
    font=("Segoe UI", 24, "bold"),
    text_color="#00FF00",
)
title.grid(row=0, column=0, columnspan=8, pady=(15, 8))

info_frame = ctk.CTkFrame(
    root,
    fg_color="#0B1323",
    corner_radius=10,
    border_width=1,
    border_color="#2A3345",
)

info_frame.grid(row=0, column=6, columnspan=2, padx=10, pady=10, sticky="e")
time_label = ctk.CTkLabel(info_frame, text="🕒 Time", font=("Segoe UI", 13, "bold"))
time_label.pack(anchor="e", padx=10, pady=(5, 2))
uptime_label = ctk.CTkLabel(
    info_frame, text="⏱ Uptime: 00:00:00", font=("Segoe UI", 13)
)
uptime_label.pack(anchor="e", padx=10, pady=(0, 5))


def create_card(title, value, color):

    card = ctk.CTkFrame(
        root,
        width=170,
        height=82,
        corner_radius=15,
        border_width=2,
        border_color="#334155",
        fg_color="#0F172A",
    )
    card.pack_propagate(False)
    top_bar = ctk.CTkFrame(
        card,
        height=4,
        fg_color=color,
        corner_radius=18,
    )

    top_bar.pack(fill="x", side="top")

    label1 = ctk.CTkLabel(
        card,
        text=title,
        font=("Segoe UI", 13, "bold"),
    )
    label1.pack(pady=(8, 2))

    label2 = ctk.CTkLabel(
        card,
        text=value,
        font=("Segoe UI", 26, "bold"),
        text_color=color,
    )
    label2.pack(pady=(0, 6))

    return card, label2


cards = [
    ("📦 Total Packets", "0", "#00ff00"),
    ("🌐 TCP", "0", "#00ccff"),
    ("📡 UDP", "0", "#FFD700"),
    ("📶 ICMP", "0", "#FF9900"),
    ("🚨 Alerts", "0", "#FF3333"),
    ("🛡 Threat", "LOW", "#00FF00"),
    ("💻 CPU", "0%", "#00FF00"),
    ("🧠 RAM", "0%", "#00FF00"),
]

card_widgets = []

for col, (name, val, color) in enumerate(cards):
    c, lbl = create_card(name, val, color)
    c.grid(row=1, column=col, padx=6, pady=(2, 4), sticky="nsew")
    card_widgets.append(lbl)

    packet_label = card_widgets[0]
tcp_label = card_widgets[1]
udp_label = card_widgets[2]
icmp_label = card_widgets[3]
alert_label = card_widgets[4]
threat_card = card_widgets[5]
cpu_label = card_widgets[6]
ram_label = card_widgets[7]

traffic_frame = ctk.CTkFrame(
    root,
    corner_radius=15,
    border_width=1,
    border_color="#333333",
    fg_color="#111827",
)


traffic_frame.grid(
    row=2, column=0, columnspan=4, padx=(12, 6), pady=(5, 4), sticky="nsew"
)

traffic_title = ctk.CTkLabel(
    traffic_frame,
    text="📈 LIVE TRAFFIC",
    font=("Segoe UI", 17, "bold"),
    text_color="#E2E8F0",
)
traffic_title.pack(pady=(2, 0))

fig = Figure(figsize=(7, 3.8), dpi=100, facecolor="#111827")

ax = fig.add_subplot(111)

fig.subplots_adjust(
    left=0.08,
    right=0.98,
    top=0.95,
    bottom=0.22,
)

ax.set_facecolor("#111827")

ax.set_xlabel("Time", color="white")
ax.set_ylabel("Packets", color="white")

ax.grid(
    True,
    color="#334155",
    linestyle="--",
    alpha=0.5,
)

traffic_data = [0] * 30

ax.plot(
    traffic_data,
    color="#00FF66",
    linewidth=8,
    alpha=0.10,
)

ax.plot(
    traffic_data,
    color="#00FF66",
    linewidth=5,
    alpha=0.20,
)

(line,) = ax.plot(
    traffic_data,
    color="#00FF66",
    linewidth=2.2,
    marker="o",
    markersize=3,
    markerfacecolor="#00FF66",
    markeredgecolor="white",
)
ax.fill_between(
    range(len(traffic_data)),
    traffic_data,
    color="#00FF66",
    alpha=0.10,
)

ax.set_xlim(0, len(traffic_data) - 1)
ax.set_ylim(0, 10)

ax.tick_params(
    colors="white",
    labelsize=9,
)

for spine in ax.spines.values():
    spine.set_color("#64748B")
    spine.set_linewidth(1)

canvas = FigureCanvasTkAgg(fig, master=traffic_frame)
canvas.get_tk_widget().configure(
    highlightthickness=0,
    bd=0,
)
canvas.draw()
canvas.get_tk_widget()["bg"] = "#111827"
canvas.get_tk_widget().pack(
    fill="both",
    expand=True,
    padx=5,
    pady=(0, 2),
)

protocol_frame = ctk.CTkFrame(
    root, corner_radius=15, border_width=1, border_color="#333333", fg_color="#111827"
)

protocol_frame.grid(row=2, column=4, columnspan=2, padx=6, pady=(5, 4), sticky="nsew")

protocol_title = ctk.CTkLabel(
    protocol_frame,
    text="🥧 PROTOCOL DISTRIBUTION",
    font=("Segoe UI", 17, "bold"),
    text_color="#E2E8F0",
)
protocol_title.pack(pady=5)

pie_fig = Figure(figsize=(5, 3.4), dpi=100, facecolor="#111827")

pie_ax = pie_fig.add_subplot(111)
pie_ax.set_facecolor("#111827")
protocol_data = [sniffer.tcp_count, sniffer.udp_count, sniffer.icmp_count]

if sum(protocol_data) == 0:
    protocol_data = [1, 1, 1]

protocol_names = ["TCP", "UDP", "ICMP"]

colors = [
    "#38BDF8",
    "#22C55E",
    "#F59E0B",
]

explode = (0.05, 0.05, 0.05)

pie_ax.pie(
    protocol_data,
    labels=protocol_names,
    colors=colors,
    explode=explode,
    startangle=90,
    autopct=None,
    pctdistance=0.75,
    wedgeprops={"edgecolor": "#111827", "linewidth": 2},
    textprops={"color": "white", "fontsize": 11, "weight": "bold"},
)

pie_ax.set_facecolor("#111827")
pie_canvas = FigureCanvasTkAgg(pie_fig, master=protocol_frame)
pie_canvas.draw()

pie_canvas.get_tk_widget().pack(
    fill="both",
    expand=True,
    padx=5,
    pady=2,
)

attack_frame = ctk.CTkFrame(
    root, corner_radius=15, border_width=1, border_color="#333333", fg_color="#111827"
)

attack_frame.grid(
    row=2, column=6, columnspan=2, padx=(6, 12), pady=(5, 4), sticky="nsew"
)

attack_title = ctk.CTkLabel(
    attack_frame,
    text="📊 ATTACK STATISTICS",
    font=("Segoe UI", 17, "bold"),
    text_color="#E2E8F0",
)
attack_title.pack(pady=5)

bar_fig = Figure(figsize=(4.3, 3.2), dpi=100, facecolor="#111827")
bar_fig.subplots_adjust(left=0.28, right=0.97, top=0.92, bottom=0.18)
bar_ax = bar_fig.add_subplot(111)
bar_ax.set_facecolor("#111827")

attacks = ["Port Scan", "UDP Flood", "ICMP Flood", "SYN Flood"]

values = [
    sniffer.port_scan_count,
    sniffer.udp_attack_count,
    sniffer.icmp_attack_count,
    sniffer.syn_flood_count,
]

bars = bar_ax.barh(attacks, values)
bar_ax.tick_params(colors="white")
bar_canvas = FigureCanvasTkAgg(bar_fig, master=attack_frame)
bar_canvas.draw()
bar_canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=2)

status_frame = ctk.CTkFrame(
    root,
    corner_radius=15,
    border_width=1,
    border_color="#333333",
    fg_color="#111827",
)

status_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=(4, 4), sticky="new")

ctk.CTkLabel(status_frame, text="🖥 SYSTEM STATUS", font=("Arial", 18, "bold")).pack(
    pady=(5, 2)
)
system_status = ctk.CTkTextbox(
    status_frame, fg_color="#111827", border_width=0, font=("Arial", 14), height=110
)

system_status.pack(fill="both", expand=True, padx=10, pady=(5, 8))

system_status.insert(
    "end",
    "🟢 System Started\n"
    "🟢 Sniffer Running\n"
    "🟢 Network Monitoring\n"
    "🟢 Log System Active\n"
    "🟢 Database Connected\n\n"
    "Status: All Systems Operational",
)

system_status.configure(state="disabled")

timeline_frame = ctk.CTkFrame(
    root,
    corner_radius=15,
    border_width=1,
    border_color="#333333",
    fg_color="#111827",
)

timeline_frame.grid(row=3, column=2, columnspan=2, padx=10, pady=(4, 4), sticky="new")

ctk.CTkLabel(
    timeline_frame, text="🕒 ATTACK TIMELINE", font=("Arial", 18, "bold")
).pack(pady=(5, 2))
attack_timeline = ctk.CTkTextbox(
    timeline_frame, fg_color="#111827", border_width=0, font=("Arial", 14)
)

attack_timeline.pack(fill="both", expand=True, padx=10, pady=(5, 8))

attacker_frame = ctk.CTkFrame(
    root,
    corner_radius=15,
    border_width=1,
    border_color="#333333",
    fg_color="#111827",
)

attacker_frame.grid(row=3, column=4, columnspan=2, padx=10, pady=(4, 4), sticky="new")

ctk.CTkLabel(
    attacker_frame, text="👤 TOP ATTACKER IPS", font=("Arial", 18, "bold")
).pack(pady=(5, 2))
attacker_box = ctk.CTkTextbox(
    attacker_frame, fg_color="#111827", border_width=0, font=("Arial", 14)
)

attacker_box.pack(fill="both", expand=True, padx=10, pady=(5, 8))

threat_frame = ctk.CTkFrame(
    root,
    corner_radius=15,
    border_width=1,
    border_color="#333333",
    fg_color="#111827",
)

threat_frame.grid(
    row=3,
    column=6,
    columnspan=2,
    padx=10,
    pady=(4, 4),
    sticky="nsew",
)

ctk.CTkLabel(
    threat_frame,
    text="🎯 THREAT LEVEL",
    font=("Segoe UI", 18, "bold"),
).pack(pady=(5, 0))

gauge_fig = Figure(figsize=(3.8, 1.55), dpi=100, facecolor="#111827")
gauge_ax = gauge_fig.add_subplot(111)

gauge_ax.set_facecolor("#111827")
gauge_ax.axis("off")

theta = np.linspace(np.pi, np.pi * 0.65, 80)
gauge_ax.plot(
    np.cos(theta),
    np.sin(theta),
    color="#22c55e",
    linewidth=14,
)

theta = np.linspace(np.pi * 0.65, np.pi * 0.40, 80)
gauge_ax.plot(
    np.cos(theta),
    np.sin(theta),
    color="#facc15",
    linewidth=14,
)

theta = np.linspace(np.pi * 0.40, np.pi * 0.20, 60)
gauge_ax.plot(
    np.cos(theta),
    np.sin(theta),
    color="#f97316",
    linewidth=14,
)

theta = np.linspace(np.pi * 0.20, 0, 80)
gauge_ax.plot(
    np.cos(theta),
    np.sin(theta),
    color="#ef4444",
    linewidth=14,
)

(needle,) = gauge_ax.plot(
    [0, -0.85],
    [0, 0],
    color="white",
    linewidth=5,
    solid_capstyle="round",
)

gauge_ax.scatter(
    0,
    0,
    s=90,
    color="white",
    edgecolors="#222",
    linewidths=2,
    zorder=10,
)
score_text = gauge_ax.text(
    0,
    -0.35,
    "0/100",
    ha="center",
    va="center",
    color="white",
    fontsize=15,
    fontweight="bold",
)

gauge_ax.set_xlim(-1.2, 1.2)
gauge_ax.set_ylim(-0.25, 1.2)

gauge_fig.subplots_adjust(top=0.95, bottom=0.18)

gauge_canvas = FigureCanvasTkAgg(
    gauge_fig,
    master=threat_frame,
)

gauge_canvas.draw()
gauge_canvas.get_tk_widget().pack(pady=(0, 5))

network_frame = ctk.CTkFrame(
    root, corner_radius=15, border_width=1, border_color="#333333", fg_color="#111827"
)
network_frame.grid(row=4, column=0, columnspan=5, padx=10, pady=5, sticky="nsew")

ctk.CTkLabel(
    network_frame, text="🌐 LIVE NETWORK TRAFFIC", font=("Arial", 18, "bold")
).pack(pady=10)

columns = (
    "No",
    "Time",
    "Source IP",
    "Location",
    "Destination IP",
    "Protocol",
    "Src Port",
    "Dst Port",
    "Length",
)

traffic_table = ttk.Treeview(network_frame, columns=columns, show="headings", height=12)

for col in columns:
    traffic_table.heading(col, text=col)

    if col == "Location":
        traffic_table.column(col, width=220)
    elif col in ("Source IP", "Destination IP"):
        traffic_table.column(col, width=140)
    else:
        traffic_table.column(col, width=90)

scrollbar = ttk.Scrollbar(network_frame, orient="vertical")
scrollbar.pack(side="right", fill="y")

traffic_table.configure(yscrollcommand=scrollbar.set)
scrollbar.config(command=traffic_table.yview)

traffic_table.pack(fill="both", expand=True, side="left", padx=10, pady=10)

style = ttk.Style()
style.theme_use("clam")
style.configure(
    "Treeview",
    background="#111827",
    foreground="white",
    fieldbackground="#111827",
    rowheight=25,
)

style.configure("Treeview.Heading", background="#1E293B", foreground="white")

recent_alerts_frame = ctk.CTkFrame(
    root, corner_radius=15, border_width=1, border_color="#333333", fg_color="#111827"
)

recent_alerts_frame.grid(row=4, column=5, columnspan=3, padx=10, pady=5, sticky="nsew")

ctk.CTkLabel(
    recent_alerts_frame, text="🚨 RECENT ALERTS", font=("Arial", 18, "bold")
).pack(pady=10)

recent_alerts = ctk.CTkTextbox(
    recent_alerts_frame, fg_color="#111827", border_width=0, font=("Arial", 14)
)

recent_alerts.pack(fill="both", expand=True, padx=10, pady=10)
recent_alerts.delete("1.0", "end")

network_info_frame = ctk.CTkFrame(
    root,
    fg_color="#111827",
    border_width=1,
    border_color="#333333",
    corner_radius=12,
)
network_info_frame.grid(
    row=6,
    column=0,
    columnspan=8,
    padx=12,
    pady=5,
    sticky="ew",
)
hostname_label = ctk.CTkLabel(
    network_info_frame,
    text="💻 Host: -",
    font=("Segoe UI", 14, "bold"),
)
hostname_label.pack(side="left", padx=20, pady=8)

ip_label = ctk.CTkLabel(
    network_info_frame,
    text="🌐 IP: -",
    font=("Segoe UI", 14),
)
ip_label.pack(side="left", padx=20)

interface_label = ctk.CTkLabel(
    network_info_frame,
    text="📡 Interface: -",
    font=("Segoe UI", 14),
)
interface_label.pack(side="left", padx=20)

adapter_var = ctk.StringVar(value="Any")
adapter_combo = ctk.CTkComboBox(
    network_info_frame,
    variable=adapter_var,
    values=get_available_adapters() or ["Any"],
    command=apply_adapter,
    width=200,
    height=30,
    font=("Segoe UI", 13),
    dropdown_font=("Segoe UI", 13),
    state="readonly",
)
adapter_combo.pack(side="left", padx=10)

control_frame = ctk.CTkFrame(
    root,
    fg_color="#0B1323",
    border_width=1,
    border_color="#2A3345",
    corner_radius=12,
    height=75,
)

control_frame.grid(row=5, column=0, columnspan=8, padx=12, pady=8, sticky="ew")

control_frame.grid_columnconfigure(0, weight=1)
control_frame.grid_columnconfigure(1, weight=0)

button_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
button_frame.grid(row=0, column=0, sticky="w", padx=10, pady=10)

BUTTON_WIDTH = 175
BUTTON_HEIGHT = 42

btn_font = ("Segoe UI", 15, "bold")

start_btn = ctk.CTkButton(
    button_frame,
    text="▶️ Start Monitoring",
    command=start_ids,
    width=BUTTON_WIDTH,
    height=BUTTON_HEIGHT,
    fg_color="#16a34a",
    hover_color="#15803d",
    corner_radius=14,
    border_width=1,
    border_color="#22c55e",
    font=("Segoe UI", 14, "bold"),
)
stop_btn = ctk.CTkButton(
    button_frame,
    text="■ Stop Monitoring",
    command=stop_ids,
    width=BUTTON_WIDTH,
    height=BUTTON_HEIGHT,
    fg_color="#b91c1c",
    hover_color="#991b1b",
    corner_radius=14,
    border_width=1,
    border_color="#ef4444",
    font=("Segoe UI", 14, "bold"),
)
stop_btn.configure(state="disabled")
export_btn = ctk.CTkButton(
    button_frame,
    text="📄 Export Logs",
    command=export_logs,
    width=BUTTON_WIDTH,
    height=BUTTON_HEIGHT,
    fg_color="#2563eb",
    hover_color="#1d4ed8",
    corner_radius=14,
    border_width=1,
    border_color="#60a5fa",
    font=("Segoe UI", 14, "bold"),
)
shot_btn = ctk.CTkButton(
    button_frame,
    text="📷 Screenshot",
    command=take_screenshot,
    width=BUTTON_WIDTH,
    height=BUTTON_HEIGHT,
    fg_color="#7c3aed",
    hover_color="#6d28d9",
    corner_radius=14,
    border_width=1,
    border_color="#a855f7",
    font=("Segoe UI", 14, "bold"),
)
clear_btn = ctk.CTkButton(
    button_frame,
    text="🗑 Clear Dashboard",
    command=clear_dashboard,
    width=BUTTON_WIDTH,
    height=BUTTON_HEIGHT,
    fg_color="#d97706",
    hover_color="#b45309",
    corner_radius=14,
    border_width=1,
    border_color="#fbbf24",
    font=("Segoe UI", 14, "bold"),
)

start_btn.pack(side="left", padx=4)
stop_btn.pack(side="left", padx=4)
export_btn.pack(side="left", padx=4)
shot_btn.pack(side="left", padx=4)
clear_btn.pack(side="left", padx=4)

status_bar = ctk.CTkLabel(
    control_frame,
    text="🔴 Status: Stopped | IDS Not Running",
    text_color="#ef4444",
    font=("Segoe UI", 15, "bold"),
)

status_bar.grid(row=0, column=1, padx=(30, 15), sticky="e")

update_graph()
update_protocol_chart()
update_attack_chart()
update_threat_level()
update_cards()
update_table()
update_alerts()
update_attackers()
check_new_alert()
update_timeline()
update_system()
update_clock()
update_network_info()

root.mainloop()
