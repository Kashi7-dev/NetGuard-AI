
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.database.connection import Base, engine
from app.database import models  # Register ORM models


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Network Traffic Monitor API",
    description="Network traffic monitoring and anomaly detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {
        "message": "Welcome to Network Traffic Monitor API"
    }
