from fastapi import FastAPI

from .config import settings


def add_health_endpoint(app: FastAPI) -> None:
    """Endpoint de salud sin autenticación, solo para el healthcheck del orquestador."""

    @app.get("/health", include_in_schema=False)
    def health() -> dict:
        return {"status": "ok", "service": settings.service_name}
