"""Introspección de tokens RFC 7662 (revocación en tiempo real).

La validación local del JWT (firma + exp) es rápida pero *stateless*: un token
exfiltrado sigue siendo válido hasta su expiración natural. Para las operaciones
críticas (p. ej. `payments:execute`, memoria 4.2.2.3) el microservicio "pivota a
un modelo con estado" y pregunta al IdP si el token sigue activo. Keycloak
devuelve `active:false` en cuanto la sesión se cierra o el token se revoca
(RP-initiated logout, revocación del refresh token o cuenta deshabilitada),
logrando así la revocación inmediata que el modelo stateless no permite.

El coste es una llamada síncrona al IdP en la ruta crítica; se acota con una
caché de muy corta vida por `jti` para no repetir la introspección en ráfagas,
sin comprometer sensiblemente la inmediatez de la revocación.
"""

import time
from threading import Lock

import httpx
from fastapi import HTTPException, status

from workload_identity import http_client

from .audit import audit_log
from .auth import SecurityContext
from .config import settings

# Caché por jti: jti -> (active: bool, expiry_epoch). TTL corto (revocación ~inmediata).
_cache: dict[str, tuple[bool, float]] = {}
_cache_lock = Lock()


class IntrospectionUnavailable(RuntimeError):
    """El IdP no respondió a la introspección: la operación crítica debe fallar cerrada."""


def _cache_get(jti: str) -> bool | None:
    if settings.introspection_cache_ttl <= 0:
        return None
    with _cache_lock:
        entry = _cache.get(jti)
        if entry and time.time() < entry[1]:
            return entry[0]
        if entry:
            del _cache[jti]
    return None


def _cache_put(jti: str, active: bool) -> None:
    if settings.introspection_cache_ttl <= 0:
        return
    with _cache_lock:
        _cache[jti] = (active, time.time() + settings.introspection_cache_ttl)
        if len(_cache) > 4096:  # cota de memoria en el PoC
            now = time.time()
            for key in [k for k, v in _cache.items() if v[1] < now]:
                _cache.pop(key, None)


def is_token_active(token: str, claims: dict, span=None) -> bool:
    """Devuelve True si el IdP considera el token activo (no revocado/expirado).

    Fail-closed: si la introspección no está configurada o el IdP no responde,
    se lanza IntrospectionUnavailable (la operación crítica se rechaza).
    """
    if not settings.introspection_url:
        raise IntrospectionUnavailable("introspection_not_configured")
    if not settings.client_id or not settings.client_secret:
        raise IntrospectionUnavailable("no_client_credentials")

    jti = claims.get("jti", "")
    cached = _cache_get(jti) if jti else None
    if cached is not None:
        if span is not None:
            span.event("introspection", active=cached, cached=True)
        return cached

    started = time.perf_counter()
    try:
        response = http_client().post(
            settings.introspection_url,
            data={"token": token, "token_type_hint": "access_token"},
            auth=(settings.client_id, settings.client_secret),
        )
        response.raise_for_status()
        active = bool(response.json().get("active", False))
    except (httpx.HTTPError, ValueError) as exc:
        if span is not None:
            span.event("introspection", active=None, error=str(exc))
        raise IntrospectionUnavailable(str(exc)) from exc

    elapsed = round((time.perf_counter() - started) * 1000, 2)
    if jti:
        _cache_put(jti, active)
    if span is not None:
        span.event("introspection", active=active, cached=False, ms=elapsed)
    return active


def enforce_active(ctx: SecurityContext) -> None:
    """Guarda para operaciones críticas: rechaza (401) si el IdP revocó el token.

    Se comprueba el token delegado del usuario (misma sesión `sid` que el token
    original): lo que interesa revocar es la sesión del usuario.
    """
    try:
        active = is_token_active(ctx.token, ctx.claims, ctx.span)
    except IntrospectionUnavailable as exc:
        audit_log("introspection_unavailable", error=str(exc), request_id=ctx.request_id)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {"error": "introspection_unavailable"}) from exc
    if not active:
        audit_log("token_revoked", sub=ctx.claims.get("sub"), jti=ctx.claims.get("jti"),
                  request_id=ctx.request_id)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            {"error": "token_revoked", "request_id": ctx.request_id},
            headers={"WWW-Authenticate": 'Bearer realm="tfm", error="invalid_token"'},
        )
