#Tính toán thống kê từ những packet đã đọc
from collections import Counter, defaultdict
from datetime import datetime, timezone


def analyze_traffic(packets: list[dict]) -> dict:
    if not packets:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "unique_source_ips": 0,
            "protocol_distribution": {},
            "flow_count": 0,
            "flows": [],
            "traffic_timeseries": [],
            "connection_attempts_by_port": {},
        }

    protocol_counts = Counter()
    source_ips = set()
    flows = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
    })
    time_buckets = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
    })
    attempts_by_port = Counter()

    for packet in packets:
        protocol_counts[packet["protocol"]] += 1
        source_ips.add(packet["source_ip"])

        flow_key = (
            packet["source_ip"],
            packet["destination_ip"],
            packet["source_port"],
            packet["destination_port"],
            packet["protocol"],
        )

        flows[flow_key]["packets"] += 1
        flows[flow_key]["bytes"] += packet["packet_size"]

        # One-second time window.
        second = int(packet["timestamp"])
        time_buckets[second]["packets"] += 1
        time_buckets[second]["bytes"] += packet["packet_size"]

        if (
            packet["tcp_syn_attempt"]
            and packet["destination_port"] is not None
        ):
            attempts_by_port[packet["destination_port"]] += 1

    flow_results = []

    for key, values in flows.items():
        src, dst, sport, dport, protocol = key

        flow_results.append({
            "source_ip": src,
            "destination_ip": dst,
            "source_port": sport,
            "destination_port": dport,
            "protocol": protocol,
            **values,
        })

    timeseries = []

    for second in sorted(time_buckets):
        values = time_buckets[second]

        timeseries.append({
            "timestamp": datetime.fromtimestamp(
                second, tz=timezone.utc
            ).isoformat(),
            "pps": values["packets"],
            "bps": values["bytes"],
        })

    return {
        "total_packets": len(packets),
        "total_bytes": sum(
            p["packet_size"] for p in packets
        ),
        "unique_source_ips": len(source_ips),
        "protocol_distribution": dict(protocol_counts),
        "flow_count": len(flows),
        "flows": flow_results,
        "traffic_timeseries": timeseries,
        "connection_attempts_by_port": {
            str(port): count
            for port, count in attempts_by_port.items()
        },
    }
