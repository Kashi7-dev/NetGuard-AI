
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.connection import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)

    filename: Mapped[str] = mapped_column(String(255))

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    total_packets: Mapped[int] = mapped_column(Integer)
    total_bytes: Mapped[int] = mapped_column(Integer)
    unique_source_ips: Mapped[int] = mapped_column(Integer)

    flows: Mapped[list["Flow"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )

    metrics: Mapped[list["TrafficMetric"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
    alerts: Mapped[list["SecurityAlert"]] = relationship(
    back_populates="analysis",
    cascade="all, delete-orphan",
)


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(primary_key=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        index=True,
    )

    source_ip: Mapped[str] = mapped_column(String(45))
    destination_ip: Mapped[str] = mapped_column(String(45))

    source_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    destination_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    protocol: Mapped[str] = mapped_column(String(20))
    packets: Mapped[int] = mapped_column(Integer)
    bytes: Mapped[int] = mapped_column(Integer)

    analysis: Mapped["Analysis"] = relationship(
        back_populates="flows"
    )


class TrafficMetric(Base):
    __tablename__ = "traffic_metrics"

    id: Mapped[int] = mapped_column(primary_key=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(DateTime)
    pps: Mapped[int] = mapped_column(Integer)
    bytes_per_second: Mapped[int] = mapped_column(Integer)

    analysis: Mapped["Analysis"] = relationship(
        back_populates="metrics"
    )

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        index=True,
    )

    alert_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    description: Mapped[str] = mapped_column(String(500))

    detected_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    analysis: Mapped["Analysis"] = relationship(
        back_populates="alerts",
    )
