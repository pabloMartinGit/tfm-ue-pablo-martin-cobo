"""Trazas distribuidas ligeras compatibles con W3C Trace Context (RU-06).

Cada petición que llega a un microservicio abre un *span* con el contexto
recibido en la cabecera `traceparent` (trace-id = X-Request-ID generado por el
gateway). La librería añade eventos automáticamente (autenticación, decisiones
del PDP, token M2M, canjes de token, llamadas salientes) y el transporte de la
petición (HTTP/2, TLS 1.3 y SPIFFE ID del llamante). Al terminar la petición, el
span se envía en segundo plano al colector (trace-service) por mTLS y con la
identidad M2M del servicio. El envío nunca bloquea ni hace fallar la petición.
"""

import logging
import queue
import re
import secrets
import threading
import time
import uuid

import httpx

from workload_identity import http_client, peer_identity

from .config import settings

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_MAX_EVENTS = 60
_log = logging.getLogger("zt_security.tracing")


def now_ms() -> float:
    return time.time() * 1000


class Span:
    def __init__(self, trace_id: str, parent_id: str | None, name: str):
        self.trace_id = trace_id
        self.span_id = secrets.token_hex(8)
        self.parent_id = parent_id
        self.name = name
        self.start = now_ms()
        self.end: float | None = None
        self.status: int | None = None
        self.attrs: dict = {}
        self.events: list[dict] = []

    def event(self, event_type: str, **fields) -> None:
        if len(self.events) < _MAX_EVENTS:
            self.events.append({"t": round(now_ms(), 3), "type": event_type, **fields})

    def finish(self, status: int) -> None:
        self.status = status
        self.end = now_ms()

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "service": settings.service_name,
            "name": self.name,
            "start": round(self.start, 3),
            "end": round(self.end, 3) if self.end else None,
            "status": self.status,
            "attrs": self.attrs,
            "events": self.events,
        }


def _parse_edge(value: str) -> dict:
    """'verified;alg=RS256;kid=...;ms=1' -> {'result': 'verified', 'alg': 'RS256', ...}"""
    parts = value.split(";")
    edge = {"result": parts[0]}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        if key:
            edge[key] = val
    return edge


def new_trace_context(headers: dict[str, str]) -> tuple[str, str | None]:
    match = _TRACEPARENT.match(headers.get("traceparent", ""))
    if match:
        return match.group(1), match.group(2)
    request_id = headers.get("x-request-id", "")
    trace_id = request_id if re.fullmatch(r"[0-9a-f]{32}", request_id) else uuid.uuid4().hex
    return trace_id, None


class TracingMiddleware:
    """Middleware ASGI: abre un span por petición y lo exporta al terminar."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/health":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        trace_id, parent_id = new_trace_context(headers)
        span = Span(trace_id, parent_id, f'{scope["method"]} {scope["path"]}')
        if headers.get("x-edge-auth"):
            # Petición que atravesó el PEP de borde: se conserva su veredicto.
            span.attrs["via"] = "api-gateway"
            span.attrs["edge"] = _parse_edge(headers["x-edge-auth"])
            try:
                span.attrs["edge_elapsed_ms"] = round(float(headers.get("x-edge-elapsed", "0")) * 1000, 3)
            except ValueError:
                pass
        else:
            span.attrs["via"] = "direct"
        # Transporte: identidad mTLS del llamante (SPIFFE) y versión de HTTP negociada.
        peer = peer_identity(scope)
        span.attrs["transport"] = {
            "protocol": f'HTTP/{scope.get("http_version", "1.1")}',
            "tls": peer["tls_version"] if peer else None,
            "peer": peer["spiffe_id"] if peer else None,
        }
        scope.setdefault("state", {})["span"] = span

        status = {"code": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            span.finish(status["code"])
            export(span)


def add_tracing(app) -> None:
    app.add_middleware(TracingMiddleware)


def note(ctx, message: str, **fields) -> None:
    """Evento de negocio legible en la traza (p. ej. una compensación)."""
    span = getattr(ctx, "span", None)
    if span is not None:
        span.event("note", message=message, **fields)


# --------------------------------------------------------------------------
# Exportación asíncrona al colector
# --------------------------------------------------------------------------
_queue: "queue.Queue[dict]" = queue.Queue(maxsize=2000)
_worker_lock = threading.Lock()
_worker: threading.Thread | None = None


def export(span: Span) -> None:
    if not settings.trace_collector_url:
        return
    _ensure_worker()
    try:
        _queue.put_nowait(span.to_dict())
    except queue.Full:
        pass


def _ensure_worker() -> None:
    global _worker
    with _worker_lock:
        if _worker is None:
            _worker = threading.Thread(target=_export_loop, name="trace-exporter", daemon=True)
            _worker.start()


def _post_batch(batch: list[dict]) -> int:
    """Envía un lote de spans al colector. Reintenta, una vez por causa, si la conexión
    reutilizada del pool estaba rota (p. ej. el colector se reinició) y si el colector
    rechaza el token M2M (p. ej. firmado con una clave ya retirada tras una rotación):
    en ese caso lo descarta y pide uno nuevo."""
    from .identity import invalidate_service_token, service_token  # evita importación circular

    reconnected = token_renewed = False
    while True:
        try:
            response = http_client().post(
                settings.trace_collector_url,
                json={"spans": batch},
                headers={"Authorization": f"Bearer {service_token()}"},
            )
        except httpx.TransportError:
            if reconnected:
                raise
            reconnected = True  # el pool descarta la conexión rota; se abre otra
            continue
        if response.status_code == 401 and not token_renewed:
            invalidate_service_token()
            token_renewed = True
            continue
        return response.status_code


def _export_loop() -> None:
    while True:
        batch = [_queue.get()]
        while len(batch) < 100:
            try:
                batch.append(_queue.get_nowait())
            except queue.Empty:
                break
        try:
            status = _post_batch(batch)
            if status >= 300:
                _log.warning("trace export rejected: %s", status)
        except Exception as exc:  # la observabilidad nunca debe tumbar el servicio
            _log.warning("trace export failed: %s", exc)
