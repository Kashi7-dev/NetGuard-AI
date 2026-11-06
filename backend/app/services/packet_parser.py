#đọc packet và chuyển thành dữ liệu python có cấu trúc

from pathlib import Path
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP


def parse_pcap(file_path: str) -> list[dict]:
    """Extract packet metadata from a PCAP file."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    packets = []

    with PcapReader(str(path)) as reader:
        for packet in reader:
            if IP in packet:
                ip_layer = packet[IP]
            elif IPv6 in packet:
                ip_layer = packet[IPv6]
            else:
                continue

            protocol = "OTHER"
            source_port = None
            destination_port = None
            tcp_syn_attempt = False

            if TCP in packet:
                tcp = packet[TCP]
                protocol = "TCP"
                source_port = int(tcp.sport)
                destination_port = int(tcp.dport)

                # SYN set, ACK not set
                tcp_syn_attempt = bool(
                    tcp.flags & 0x02 and not tcp.flags & 0x10
                )

            elif UDP in packet:
                udp = packet[UDP]
                protocol = "UDP"
                source_port = int(udp.sport)
                destination_port = int(udp.dport)

            elif ICMP in packet:
                protocol = "ICMP"

            elif IPv6 in packet and int(ip_layer.nh) == 58:
                protocol = "ICMPv6"

            packets.append({
                "timestamp": float(packet.time),
                "source_ip": ip_layer.src,
                "destination_ip": ip_layer.dst,
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": protocol,
                "packet_size": len(packet),
                "tcp_syn_attempt": tcp_syn_attempt,
            })

    return packets
