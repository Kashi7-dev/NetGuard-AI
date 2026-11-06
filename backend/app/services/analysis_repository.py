
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database.models import (
    Analysis,
    Flow,
    TrafficMetric,
    SecurityAlert,
)


def save_analysis(
    db: Session,
    filename: str,
    result: dict,
    alerts: list[dict] | None = None,
) -> Analysis:
    analysis = Analysis(
        filename=filename,
        total_packets=result["total_packets"],
        total_bytes=result["total_bytes"],
        unique_source_ips=result["unique_source_ips"],
    )

    for flow in result["flows"]:
        analysis.flows.append(
            Flow(
                source_ip=flow["source_ip"],
                destination_ip=flow["destination_ip"],
                source_port=flow["source_port"],
                destination_port=flow["destination_port"],
                protocol=flow["protocol"],
                packets=flow["packets"],
                bytes=flow["bytes"],
            )
        )

    for metric in result["traffic_timeseries"]:
        timestamp = datetime.fromisoformat(
            metric["timestamp"]
        ).replace(tzinfo=None)

        analysis.metrics.append(
            TrafficMetric(
                timestamp=timestamp,
                pps=metric["pps"],
                bytes_per_second=metric["bps"],
            )
        )

    for alert in alerts or []:
        detected_at = alert.get("detected_at")

        if detected_at is not None:
            detected_at = datetime.fromisoformat(
                detected_at
            ).replace(tzinfo=None)

        analysis.alerts.append(
            SecurityAlert(
                alert_type=alert["alert_type"],
                severity=alert["severity"],
                source_ip=alert["source_ip"],
                description=alert["description"],
                detected_at=detected_at,
            )
        )

    try:
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
    except Exception:
        db.rollback()
        raise

    return analysis


def list_analyses(db: Session) -> list[Analysis]:
    statement = (
        select(Analysis)
        .order_by(Analysis.id.desc())
        .limit(100)
    )
    return list(db.scalars(statement).all())


def get_analysis(
    db: Session,
    analysis_id: int,
) -> Analysis | None:
    statement = (
        select(Analysis)
        .options(
            selectinload(Analysis.flows),
            selectinload(Analysis.metrics),
            selectinload(Analysis.alerts),
        )
        .where(Analysis.id == analysis_id)
    )

    return db.scalar(statement)
