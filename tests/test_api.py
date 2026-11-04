import sys
from pathlib import Path

from fastapi.testclient import TestClient

# Add backend directory to Python import path
backend_dir = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_dir))

from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_project_info():
    response = client.get("/api/info")

    assert response.status_code == 200
    assert "project_name" in response.json()
