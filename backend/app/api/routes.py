from fastapi import APIRouter

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
