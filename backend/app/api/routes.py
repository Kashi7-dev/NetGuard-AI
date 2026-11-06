from fastapi import APIRouter
import tempfile
from pathlib import Path

from fastapi import File, HTTPException, UploadFile

from app.services.packet_parser import parse_pcap
from app.services.traffic_analyzer import analyze_traffic
router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Network Traffic Monitor API"
    }


@router.get("/info")
def project_info():
    return {
        "project_name": "Network Traffic Monitor and Anomaly Detection",
        "version": "1.0.0",
        "description": "A system for analyzing network traffic and detecting anomalies",
        "features": [
            "Network Traffic Analysis",
            "Anomaly Detection",
            "Traffic Visualization"
        ]
    }

@router.post("/traffic/analyze")
async def analyze_uploaded_traffic(
    file: UploadFile = File(...)
):
    allowed_extensions = {".pcap", ".pcapng"}
    extension = Path(file.filename or "").suffix.lower()

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail="Only PCAP and PCAPNG files are supported",
        )

    max_size = 10 * 1024 * 1024  # 10 MiB for MVP
    temp_path = None

    try:
        # Read one extra byte to detect oversized uploads.
        content = await file.read(max_size + 1)

        if len(content) > max_size:
            raise HTTPException(
                status_code=413,
                detail="File exceeds 10 MiB limit",
            )

        with tempfile.NamedTemporaryFile(
            suffix=extension,
            delete=False,
        ) as temp_file:
            temp_file.write(content)
            temp_path = Path(temp_file.name)

        packets = parse_pcap(str(temp_path))
        return analyze_traffic(packets)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse the uploaded capture",
        ) from exc

    finally:
        await file.close()
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
