from scapy.all import conf, sniff

print("=" * 60)
print("Available Scapy Interfaces")
print("=" * 60)

for name, iface in conf.ifaces.items():
    print(f"Name        : {name}")
    print(f"Description : {iface.description}")
    print("-" * 60)

interface = input("\nEnter interface name to test (or press Enter for default): ")

print("\nStarting packet capture...")

sniff(
    iface=interface if interface else None,
    filter="icmp or tcp or udp",
    prn=lambda pkt: print(pkt.summary()),
    store=False,
)