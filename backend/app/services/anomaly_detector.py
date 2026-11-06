
from collections import defaultdict


DEFAULT_THRESHOLDS = {
    "max_pps": 100,
    "max_bytes_per_second": 100_000,
    "max_unique_ports": 10,
    "max_syn_attempts": 20,
}


def detect_anomalies(
    packets: list[dict],
    traffic_result: dict,
    thresholds: dict | None = None,
) -> list[dict]:
    """Detect suspicious traffic using statistical rules."""

    config = DEFAULT_THRESHOLDS.copy()

    if thresholds:
        config.update(thresholds)

    alerts = []

    # Rule 1: High packets per second
    for metric in traffic_result["traffic_timeseries"]:
        if metric["pps"] > config["max_pps"]:
            alerts.append({
                "alert_type": "TRAFFIC_SPIKE",
                "severity": "HIGH",
                "source_ip": None,
                "description": (
                    f"High packet rate: {metric['pps']} PPS"
                ),
                "detected_at": metric["timestamp"],
            })

        # Rule 2: High bytes per second
        if metric["bps"] > config["max_bytes_per_second"]:
            alerts.append({
                "alert_type": "HIGH_BANDWIDTH",
                "severity": "MEDIUM",
                "source_ip": None,
                "description": (
                    f"High traffic volume: {metric['bps']} bytes/s"
                ),
                "detected_at": metric["timestamp"],
            })

    # Group TCP SYN attempts by source IP.
    syn_ports = defaultdict(set)
    syn_counts = defaultdict(int)

    for packet in packets:
        if not packet.get("tcp_syn_attempt", False):
            continue

        source_ip = packet["source_ip"]
        destination_port = packet["destination_port"]

        syn_counts[source_ip] += 1

        if destination_port is not None:
            syn_ports[source_ip].add(destination_port)

    # Rule 3: Possible port scanning
    for source_ip, ports in syn_ports.items():
        if len(ports) > config["max_unique_ports"]:
            alerts.append({
                "alert_type": "POSSIBLE_PORT_SCAN",
                "severity": "HIGH",
                "source_ip": source_ip,
                "description": (
                    f"Source contacted {len(ports)} "
                    "distinct destination ports"
                ),
                "detected_at": None,
            })

    # Rule 4: High SYN activity
    for source_ip, count in syn_counts.items():
        if count > config["max_syn_attempts"]:
            alerts.append({
                "alert_type": "HIGH_SYN_ACTIVITY",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "description": (
                    f"Source generated {count} TCP SYN attempts"
                ),
                "detected_at": None,
            })

    return alerts
