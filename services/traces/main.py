"""Trace Service - colector de trazas distribuidas (observabilidad, RU-06).

- POST /internal/v1/spans (solo M2M): los microservicios envían sus spans por
  mTLS y con su token client_credentials. El PDP decide qué servicios pueden
  publicar trazas (`traces:ingest`) y exige que el SPIFFE ID de la conexión
  coincida con el `azp` del token; el colector sella cada span con esa identidad
  autenticada, de modo que un servicio no puede suplantar a otro.
- GET /api/v1/traces/{trace_id} (vía gateway): devuelve la traza completa. El
  PDP aplica ABAC (`traces:read`): cada usuario ve las trazas de sus propias
  peticiones; auditores y administradores, todas las de su tenant.

Almacenamiento en memoria y acotado (PoC): las trazas más antiguas se descartan.
"""

import re
from collections import OrderedDict
from threading import Lock

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from zt_security import SecurityContext, add_health_endpoint, authorize, require_service, require_user

MAX_TRACES = 1000
MAX_SPANS_PER_TRACE = 200

app = FastAPI(title="Trace Service", version="0.1.0")
add_health_endpoint(app)

_traces: "OrderedDict[str, list[dict]]" = OrderedDict()
_lock = Lock()


class SpanIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    span_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    parent_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    name: str = Field(max_length=200)
    start: float
    end: float | None = None
    status: int | None = None
    attrs: dict = Field(default_factory=dict)
    events: list[dict] = Field(default_factory=list, max_length=100)


class SpanBatch(BaseModel):
    spans: list[SpanIn] = Field(max_length=500)


@app.post("/internal/v1/spans", status_code=202)
def ingest(batch: SpanBatch, ctx: SecurityContext = Depends(require_service)) -> dict:
    authorize(ctx, "traces:ingest", {"type": "spans"})
    with _lock:
        for span in batch.spans:
            record = span.model_dump()
            record["service"] = ctx.caller_service  # identidad mTLS verificada, no la declarada
            spans = _traces.setdefault(span.trace_id, [])
            _traces.move_to_end(span.trace_id)
            if len(spans) < MAX_SPANS_PER_TRACE:
                spans.append(record)
        while len(_traces) > MAX_TRACES:
            _traces.popitem(last=False)
    return {"accepted": len(batch.spans)}


def _trace_owner(spans: list[dict]) -> dict:
    """Sujeto que originó la traza: primer usuario autenticado registrado en ella (con su
    token de borde o con un token delegado en su nombre: ambos identifican al usuario)."""
    for span in sorted(spans, key=lambda s: s["start"]):
        for event in span["events"]:
            if (event.get("type") == "authn" and event.get("kind") in ("user", "delegated")
                    and event.get("ok")):
                return {"sub": event.get("sub"), "tenant_id": event.get("tenant_id")}
    return {}


@app.get("/api/v1/traces/{trace_id}")
def get_trace(trace_id: str, ctx: SecurityContext = Depends(require_user)) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", trace_id):
        raise HTTPException(404, {"error": "trace_not_found"})
    with _lock:
        spans = [dict(s) for s in _traces.get(trace_id, [])]
    if not spans:
        raise HTTPException(404, {"error": "trace_not_found"})
    owner = _trace_owner(spans)
    authorize(ctx, "traces:read",
              {"type": "trace", "id": trace_id, "owner_id": owner.get("sub"), "tenant_id": owner.get("tenant_id")})
    return {"trace_id": trace_id, "owner": owner, "spans": sorted(spans, key=lambda s: s["start"])}
