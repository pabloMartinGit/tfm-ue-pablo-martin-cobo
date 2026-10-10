"""Llamadas servicio a servicio (M2M) con doble identidad (memoria 4.1.3.2):

1. Contexto de usuario  -> Token Exchange (RFC 8693): se envía un token del
   usuario canjeado para el servicio destino (aud = destino, azp = llamante),
   nunca el token original (evolución del Token Relay, Tabla 8).
2. Contexto de servicio -> mTLS: el SVID del servicio llamante autentica la
   conexión; el receptor comprueba que coincide con el `azp` del token delegado.

El transporte es HTTP/2 sobre TLS 1.3 con conexiones reutilizadas. Además se
propaga el contexto de traza W3C (`traceparent`): cada llamada saliente es un
span cliente cuyo id pasa a ser el padre del span del servicio destino.
"""

import secrets
import time
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status

from workload_identity import http_client

from .audit import audit_log
from .auth import REQUEST_ID_HEADER, SecurityContext
from .exchange import delegated_token


def relay(ctx: SecurityContext, method: str, url: str, json: dict | None = None, *,
          audience: str) -> httpx.Response:
    """Invoca `url` en nombre del usuario de ctx con un token delegado para `audience`."""
    span = ctx.span
    token = delegated_token(ctx, audience)
    client_span_id = secrets.token_hex(8)
    target = urlparse(url)
    started = time.perf_counter()
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            REQUEST_ID_HEADER: ctx.request_id,
            "traceparent": f"00-{ctx.request_id}-{client_span_id}-01",
        }
        response = http_client().request(method, url, json=json, headers=headers)
    except httpx.HTTPError as exc:
        audit_log("downstream_unavailable", url=url, error=str(exc), request_id=ctx.request_id)
        if span is not None:
            span.event("call", span_id=client_span_id, host=target.hostname, method=method,
                       path=target.path, status=None, error="unavailable", audience=audience,
                       ms=round((time.perf_counter() - started) * 1000, 2))
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, {"error": "downstream_unavailable"}) from exc

    if span is not None:
        span.event("call", span_id=client_span_id, host=target.hostname, method=method,
                   path=target.path, status=response.status_code, audience=audience,
                   protocol=response.http_version, ms=round((time.perf_counter() - started) * 1000, 2))
    return response


def raise_for_downstream(response: httpx.Response) -> dict:
    """Propaga 401/403/404/409 del servicio destino; cualquier otro error se traduce en 502."""
    if response.is_success:
        return response.json()
    if response.status_code in (401, 403, 404, 409):
        try:
            detail = response.json().get("detail", {})
        except ValueError:
            detail = {}
        raise HTTPException(response.status_code, detail)
    raise HTTPException(status.HTTP_502_BAD_GATEWAY, {"error": "downstream_error"})
