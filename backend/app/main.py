from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(
    title="Network Traffic Monitor API",
    description="Backend API for network traffic monitoring and anomaly detection",
    version="1.0.0"
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {
        "message": "Welcome to Network Traffic Monitor API"
    }
