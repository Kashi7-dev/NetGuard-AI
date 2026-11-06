
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.database.connection import Base
from app.database import models
from app.services.analysis_repository import (
    save_analysis,
    get_analysis,
    list_analyses,
)


def test_save_and_retrieve_analysis():
    # Isolated in-memory database for this test.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    result = {
        "total_packets": 2,
        "total_bytes": 200,
        "unique_source_ips": 1,
        "flows": [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
                "source_port": 50000,
                "destination_port": 443,
                "protocol": "TCP",
                "packets": 2,
                "bytes": 200,
            }
        ],
        "traffic_timeseries": [
            {
                "timestamp": "2026-11-06T10:00:00+00:00",
                "pps": 2,
                "bps": 200,
            }
        ],
    }

    try:
        with Session(engine) as db:
            saved = save_analysis(
                db,
                filename="test.pcap",
                result=result,
            )

            assert saved.id is not None

            found = get_analysis(db, saved.id)

            assert found is not None
            assert found.filename == "test.pcap"
            assert found.total_packets == 2
            assert len(found.flows) == 1
            assert len(found.metrics) == 1

            assert len(list_analyses(db)) == 1
            assert get_analysis(db, 999999) is None

    finally:
        engine.dispose()
