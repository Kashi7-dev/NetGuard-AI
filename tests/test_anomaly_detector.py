
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.anomaly_detector import detect_anomalies


def test_normal_traffic():
    packets = [
        {
            "source_ip": "192.168.1.10",
            "destination_port": 443,
            "tcp_syn_attempt": True,
        }
    ]

    traffic_result = {
        "traffic_timeseries": [
            {
                "timestamp": "2026-11-06T10:00:00+00:00",
                "pps": 5,
                "bps": 500,
            }
        ]
    }

    alerts = detect_anomalies(packets, traffic_result)

    assert len(alerts) == 0


def test_traffic_spike():
    traffic_result = {
        "traffic_timeseries": [
            {
                "timestamp": "2026-11-06T10:00:00+00:00",
                "pps": 150,
                "bps": 1000,
            }
        ]
    }

    alerts = detect_anomalies([], traffic_result)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "TRAFFIC_SPIKE"
    assert alerts[0]["severity"] == "HIGH"


def test_port_scan_and_syn_activity():
    packets = [
        {
            "source_ip": "192.168.1.50",
            "destination_port": 1000 + i,
            "tcp_syn_attempt": True,
        }
        for i in range(30)
    ]

    traffic_result = {
        "traffic_timeseries": []
    }

    alerts = detect_anomalies(packets, traffic_result)

    alert_types = {
        alert["alert_type"]
        for alert in alerts
    }

    assert "POSSIBLE_PORT_SCAN" in alert_types
    assert "HIGH_SYN_ACTIVITY" in alert_types
    assert len(alerts) == 2
