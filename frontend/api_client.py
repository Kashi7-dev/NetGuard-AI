
import os
import requests


API_BASE_URL = os.getenv(
    "API_BASE_URL",
    "http://127.0.0.1:8000/api",
)


def upload_pcap(uploaded_file):
    """Upload PCAP to FastAPI and return analysis result."""
    files = {
        "file": (
            uploaded_file.name,
            uploaded_file.getvalue(),
            "application/octet-stream",
        )
    }

    response = requests.post(
        f"{API_BASE_URL}/traffic/analyze",
        files=files,
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def get_analyses():
    """Fetch analysis history."""
    response = requests.get(
        f"{API_BASE_URL}/analyses",
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def get_analysis_detail(analysis_id: int):
    """Fetch a stored analysis by ID."""
    response = requests.get(
        f"{API_BASE_URL}/analyses/{analysis_id}",
        timeout=10,
    )
    response.raise_for_status()
    return response.json()
