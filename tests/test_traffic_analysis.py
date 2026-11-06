
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.packet_parser import parse_pcap
from app.services.traffic_analyzer import analyze_traffic


def test_sample_pcap_analysis():
    path = ROOT / "data" / "sample.pcap"

    packets = parse_pcap(str(path))
    result = analyze_traffic(packets)

    assert result["total_packets"] == 4
    assert result["unique_source_ips"] == 3
    assert result["flow_count"] == 3
    assert result["protocol_distribution"]["TCP"] == 2
    assert result["connection_attempts_by_port"]["443"] == 1


def test_empty_traffic():
    result = analyze_traffic([])

    assert result["total_packets"] == 0
    assert result["total_bytes"] == 0
    assert result["flow_count"] == 0
