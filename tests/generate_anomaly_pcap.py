
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "anomaly_sample.pcap"

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

packets = []

for index in range(30):
    packet = (
        Ether()
        / IP(
            src="192.168.1.50",
            dst="192.168.1.100",
        )
        / TCP(
            sport=40000 + index,
            dport=1000 + index,
            flags="S",
        )
    )

    packet.time = 1700000000 + index * 0.01
    packets.append(packet)

wrpcap(str(OUTPUT), packets)

print(f"Created {OUTPUT}")
print(f"Total packets: {len(packets)}")
