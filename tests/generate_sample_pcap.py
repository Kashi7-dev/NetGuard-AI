from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap

OUTPUT = Path(__file__).resolve().parents[1] / "data" / "sample.pcap"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

packets = [
    Ether() / IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=50001, dport=443, flags="S"),

    Ether() / IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=50001, dport=443, flags="A"),

    Ether() / IP(src="192.168.1.11", dst="192.168.1.30")
    / UDP(sport=53000, dport=53),

    Ether() / IP(src="192.168.1.12", dst="192.168.1.1")
    / ICMP(type=8),
]

# Assign deterministic timestamps, one second apart.
for index, packet in enumerate(packets):
    packet.time = 1700000000 + index

wrpcap(str(OUTPUT), packets)
print(f"Created {OUTPUT} with {len(packets)} packets")
