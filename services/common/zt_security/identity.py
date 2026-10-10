"""Identidad M2M del propio servicio (OAuth 2.0 client_credentials frente a Keycloak)."""

import time
from threading import Lock

from workload_identity import http_client

from .config import settings

_token_lock = Lock()
_cached_token: str | None = None
_cached_token_expiry = 0.0


def service_token(span=None) -> str:
    """Devuelve el token M2M del servicio, cacheado hasta 30 s antes de expirar.

    Si se indica un span, deja constancia en la traza de si se reutilizó el token
    o hubo que solicitarlo a Keycloak.
    """
    global _cached_token, _cached_token_expiry
    if not settings.client_id or not settings.client_secret or not settings.token_url:
        raise RuntimeError("Servicio sin credenciales M2M (SERVICE_CLIENT_ID/SECRET, OIDC_TOKEN_URL)")
    with _token_lock:
        if _cached_token and time.time() < _cached_token_expiry - 30:
            if span is not None:
                span.event("m2m_token", cached=True, client_id=settings.client_id)
            return _cached_token
        started = time.perf_counter()
        response = http_client().post(
            settings.token_url,
            data={"grant_type": "client_credentials"},
            auth=(settings.client_id, settings.client_secret),
        )
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        if span is not None:
            span.event("m2m_token", cached=False, client_id=settings.client_id,
                       status=response.status_code, ms=elapsed)
        response.raise_for_status()
        body = response.json()
        _cached_token = body["access_token"]
        _cached_token_expiry = time.time() + int(body.get("expires_in", 60))
        return _cached_token


def invalidate_service_token() -> None:
    """Descarta el token M2M cacheado (p. ej. si el receptor lo rechaza porque la clave
    con la que se firmó se retiró del JWKS o la sesión del cliente se revocó)."""
    global _cached_token, _cached_token_expiry
    with _token_lock:
        _cached_token, _cached_token_expiry = None, 0.0
