
import tempfile
from pathlib import Path
from app.services.anomaly_detector import detect_anomalies
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
)
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.packet_parser import parse_pcap
from app.services.traffic_analyzer import analyze_traffic
from app.services.analysis_repository import (
    save_analysis,
    list_analyses,
    get_analysis,
)


router = APIRouter()

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


# ============================================
# 1. HEALTH CHECK
# ============================================

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Network Traffic Monitor API",
    }


# ============================================
# 2. PROJECT INFORMATION
# ============================================

@router.get("/info")
def project_info():
    return {
        "project_name": (
            "Network Traffic Monitor and Anomaly Detection"
        ),
        "version": "1.0.0",
        "description": (
            "A system for analyzing network traffic "
            "and detecting anomalies"
        ),
        "features": [
            "Network Traffic Analysis",
            "Anomaly Detection",
            "Traffic Visualization",
            "Database Integration",
        ],
    }


# ============================================
# 3. UPLOAD, ANALYZE AND SAVE PCAP
# ============================================

@router.post("/traffic/analyze")
async def analyze_uploaded_traffic(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    filename = Path(file.filename or "capture.pcap").name
    extension = Path(filename).suffix.lower()

    # Step 1: Validate file extension
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Only PCAP and PCAPNG files are supported",
        )

    temp_path = None

    try:
        # Step 2: Read uploaded file
        content = await file.read(MAX_FILE_SIZE + 1)

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File exceeds 10 MiB limit",
            )

        # Step 3: Save to temporary file
        with tempfile.NamedTemporaryFile(
            suffix=extension,
            delete=False,
        ) as temp_file:
            temp_file.write(content)
            temp_path = Path(temp_file.name)

        # Step 4: Parse packets
        packets = parse_pcap(str(temp_path))

        # Step 5: Analyze traffic
        result = analyze_traffic(packets)
        alerts = detect_anomalies(packets, result)
    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse the uploaded capture",
        ) from exc

    finally:
        await file.close()

        # Remove temporary file
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    # Step 6: Save analysis to database
    try:
        analysis = save_analysis(
            db=db,
            filename=filename,
            result=result,
            alerts=alerts,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to save analysis to database",
        ) from exc

    # Step 7: Return result
    return {
        "analysis_id": analysis.id,
        "filename": analysis.filename,
        **result,
        "alert_count": len(alerts),
        "alerts": alerts,
    }


# ============================================
# 4. GET ANALYSIS HISTORY
# ============================================

@router.get("/analyses")
def get_analyses(
    db: Session = Depends(get_db),
):
    analyses = list_analyses(db)

    return [
        {
            "id": item.id,
            "filename": item.filename,
            "created_at": item.created_at.isoformat(),
            "total_packets": item.total_packets,
            "total_bytes": item.total_bytes,
            "unique_source_ips": item.unique_source_ips,
        }
        for item in analyses
    ]


# ============================================
# 5. GET ANALYSIS DETAILS
# ============================================

@router.get("/analyses/{analysis_id}")
def get_analysis_detail(
    analysis_id: int,
    db: Session = Depends(get_db),
):
    analysis = get_analysis(db, analysis_id)

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found",
        )

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "created_at": analysis.created_at.isoformat(),
        "total_packets": analysis.total_packets,
        "total_bytes": analysis.total_bytes,
        "unique_source_ips": analysis.unique_source_ips,

        "flows": [
            {
                "source_ip": flow.source_ip,
                "destination_ip": flow.destination_ip,
                "source_port": flow.source_port,
                "destination_port": flow.destination_port,
                "protocol": flow.protocol,
                "packets": flow.packets,
                "bytes": flow.bytes,
            }
            for flow in analysis.flows
        ],

        "traffic_timeseries": [
            {
                "timestamp": (
                    metric.timestamp.isoformat() + "Z"
                ),
                "pps": metric.pps,
                "bps": metric.bytes_per_second,
            }
            for metric in sorted(
                analysis.metrics,
                key=lambda m: m.timestamp,
            )
        ],
        
        "alert_count": len(analysis.alerts),

        "alerts": [
            {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "description": alert.description,
                "detected_at": (
                    alert.detected_at.isoformat() + "Z"
                    if alert.detected_at is not None
                    else None
                ),
            }
            for alert in analysis.alerts
        ],

    }
