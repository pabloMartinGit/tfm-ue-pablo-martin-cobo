"""Configuración de seguridad de cada microservicio, leída de variables de entorno."""

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(f"Variable de entorno obligatoria no definida: {name}")
    return value


@dataclass(frozen=True)
class Settings:
    service_name: str
    # Validación de tokens (Resource Server)
    issuer: str
    audience: str
    jwks_url: str
    allowed_algorithms: tuple[str, ...]
    # Identidad propia del servicio para llamadas M2M (client_credentials).
    # Opcional: un servicio que no invoca a otros (p. ej. el colector) no la necesita.
    token_url: str
    client_id: str
    client_secret: str
    # Punto de decisión de políticas (PDP)
    opa_decision_url: str
    expose_deny_reasons: bool
    http_timeout: float
    # Colector de trazas (vacío = no se exportan spans)
    trace_collector_url: str
    # Introspección RFC 7662 (vacío = deshabilitada; revocación en tiempo real)
    introspection_url: str
    introspection_cache_ttl: float


def load_settings() -> Settings:
    return Settings(
        service_name=_env("SERVICE_NAME"),
        issuer=_env("OIDC_ISSUER"),
        audience=_env("OIDC_AUDIENCE", "microservices-backend-api"),
        jwks_url=_env("OIDC_JWKS_URL"),
        allowed_algorithms=tuple(_env("OIDC_ALLOWED_ALGS", "RS256").split(",")),
        token_url=os.getenv("OIDC_TOKEN_URL", ""),
        client_id=os.getenv("SERVICE_CLIENT_ID", ""),
        client_secret=os.getenv("SERVICE_CLIENT_SECRET", ""),
        opa_decision_url=_env("OPA_DECISION_URL"),
        expose_deny_reasons=os.getenv("EXPOSE_DENY_REASONS", "false").lower() == "true",
        http_timeout=float(os.getenv("HTTP_TIMEOUT_SECONDS", "3")),
        trace_collector_url=os.getenv("TRACE_COLLECTOR_URL", ""),
        introspection_url=os.getenv("OIDC_INTROSPECTION_URL", ""),
        # 0 = sin caché: la revocación es inmediata a costa de una introspección por
        # operación crítica. Un valor >0 amortigua ráfagas retrasando la revocación.
        introspection_cache_ttl=float(os.getenv("INTROSPECTION_CACHE_TTL_SECONDS", "0")),
    )


settings = load_settings()
