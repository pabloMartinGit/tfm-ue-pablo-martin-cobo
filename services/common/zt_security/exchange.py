"""Token Exchange (RFC 8693): delegación con audiencia reducida en cada salto.

En lugar de reenviar el token del usuario tal cual (Token Relay), el servicio
llamante lo canjea en Keycloak (STS) por un token nuevo que:

- conserva al usuario (`sub`, `tenant_id`, atributos ABAC y la sesión `sid`),
- tiene como audiencia **solo** el servicio destino (`aud`),
- lleva como `azp` al servicio que lo pidió (delegación verificable), y
- contiene únicamente los roles de ese destino.

Así, un token capturado en un salto no sirve contra otro servicio (memoria,
Tabla 8: aislamiento "Muy alto"). El precio es una llamada síncrona al IdP por
salto; se memoriza por petición (varias llamadas al mismo destino reutilizan el
token) y queda medida en la traza. Como el canje exige que la sesión del usuario
siga viva, cada salto es además un punto de revocación.
"""

import time

import httpx
from fastapi import HTTPException, status

from workload_identity import http_client

from .audit import audit_log
from .auth import SecurityContext
from .config import settings

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def delegated_token(ctx: SecurityContext, audience: str) -> str:
    """Devuelve un token del usuario de ctx con audiencia = `audience` (memorizado por petición)."""
    cached = ctx.delegations.get(audience)
    if cached is not None:
        if ctx.span is not None:
            ctx.span.event("token_exchange", audience=audience, cached=True)
        return cached
    if not settings.client_id or not settings.client_secret or not settings.token_url:
        raise RuntimeError("Token Exchange sin credenciales (SERVICE_CLIENT_ID/SECRET, OIDC_TOKEN_URL)")

    started = time.perf_counter()
    try:
        response = http_client().post(
            settings.token_url,
            data={
                "grant_type": GRANT_TYPE,
                "subject_token": ctx.token,
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "requested_token_type": ACCESS_TOKEN_TYPE,
                "audience": audience,
            },
            auth=(settings.client_id, settings.client_secret),
        )
    except httpx.HTTPError as exc:
        audit_log("sts_unavailable", audience=audience, error=str(exc), request_id=ctx.request_id)
        if ctx.span is not None:
            ctx.span.event("token_exchange", audience=audience, ok=False, error="sts_unavailable")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {"error": "sts_unavailable"}) from exc
    elapsed = round((time.perf_counter() - started) * 1000, 2)

    if response.status_code != 200:
        try:
            error = response.json()
        except ValueError:
            error = {}
        audit_log("delegation_denied", audience=audience, sub=ctx.claims.get("sub"),
                  status=response.status_code, error=error.get("error"),
                  error_description=error.get("error_description"), request_id=ctx.request_id)
        if ctx.span is not None:
            ctx.span.event("token_exchange", audience=audience, ok=False, status=response.status_code,
                           error=error.get("error_description") or error.get("error"), ms=elapsed)
        if error.get("error_description") == "Invalid token":
            # El STS no acepta el token del usuario: la sesión se cerró o se revocó.
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                {"error": "token_revoked", "request_id": ctx.request_id},
                headers={"WWW-Authenticate": 'Bearer realm="tfm", error="invalid_token"'},
            )
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"error": "delegation_denied", "request_id": ctx.request_id})

    token = response.json()["access_token"]
    ctx.delegations[audience] = token
    if ctx.span is not None:
        ctx.span.event("token_exchange", audience=audience, ok=True, cached=False, ms=elapsed)
    return token
