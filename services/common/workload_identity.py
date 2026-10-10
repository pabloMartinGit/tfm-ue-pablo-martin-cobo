"""Identidad de carga de trabajo (SVID X.509 con ID SPIFFE) y transporte mTLS + HTTP/2.

Módulo autónomo (no depende de zt_security) que usan todos los servicios, BFF incluido:

- ``python -m workload_identity main:app`` arranca la app ASGI con Hypercorn sobre
  TLS 1.3 con autenticación mutua obligatoria y ALPN h2/http1.1. Sin un SVID
  firmado por la CA del dominio de confianza no se completa el handshake: un
  contenedor comprometido sin identidad no puede ni abrir la conexión.
  Además escucha en 127.0.0.1 sin TLS, solo para el healthcheck del contenedor.
- ``peer_identity(scope)`` devuelve el SPIFFE ID del extremo mTLS. Hypercorn no
  implementa la extensión ASGI "tls", así que el servidor la añade al scope.
- ``http_client()`` es el cliente saliente compartido: HTTP/2, mTLS con el SVID
  propio y pool de conexiones (amortiza el coste del handshake entre peticiones).

Los certificados los emite scripts/gen-internal-pki.sh (formato SPIFFE); con
SPIRE solo cambiaría quién los emite y los rota.
"""

import os
import ssl
import sys
from functools import lru_cache
from threading import Lock

import httpx
from cryptography import x509

CERT_FILE = os.getenv("TLS_CERT_FILE", "/run/svid/svid.pem")
KEY_FILE = os.getenv("TLS_KEY_FILE", "/run/svid/svid.key")
CA_FILE = os.getenv("TLS_CA_FILE", "/run/svid/bundle.pem")
TRUST_DOMAIN = os.getenv("SPIFFE_TRUST_DOMAIN", "tfm.local")
TLS_PORT = int(os.getenv("TLS_PORT", "8443"))
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8000"))

_TLS_VERSIONS = {"TLSv1.3": 0x0304, "TLSv1.2": 0x0303}


# --------------------------------------------------------------------------
# Identidad del extremo (servidor)
# --------------------------------------------------------------------------
@lru_cache(maxsize=256)
def _spiffe_id(pem: str) -> str | None:
    cert = x509.load_pem_x509_certificate(pem.encode())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    prefix = f"spiffe://{TRUST_DOMAIN}/"
    return next((uri for uri in san.get_values_for_type(x509.UniformResourceIdentifier)
                 if uri.startswith(prefix)), None)


def peer_identity(scope: dict) -> dict | None:
    """SPIFFE ID y nombre de servicio del cliente mTLS, o None si la conexión no es mTLS."""
    tls = (scope.get("extensions") or {}).get("tls") or {}
    chain = tls.get("client_cert_chain") or []
    spiffe_id = _spiffe_id(chain[0]) if chain else None
    if spiffe_id is None:
        return None
    return {"spiffe_id": spiffe_id, "service": spiffe_id.rsplit("/", 1)[-1],
            "tls_version": {v: k for k, v in _TLS_VERSIONS.items()}.get(tls.get("tls_version"))}


# --------------------------------------------------------------------------
# Cliente saliente (mTLS + HTTP/2)
# --------------------------------------------------------------------------
def client_ssl_context() -> ssl.SSLContext:
    """Contexto TLS de cliente: solo confía en la CA interna y presenta el SVID propio."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    return context


_client: httpx.Client | None = None
_client_lock = Lock()


def http_client() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None:
            _client = httpx.Client(
                http2=True,
                verify=client_ssl_context(),
                timeout=float(os.getenv("HTTP_TIMEOUT_SECONDS", "3")),
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=20, keepalive_expiry=30),
            )
        return _client


# --------------------------------------------------------------------------
# Servidor (Hypercorn con mTLS obligatorio)
# --------------------------------------------------------------------------
def _tls_extension(ssl_object: ssl.SSLObject) -> dict:
    """Extensión ASGI "tls" (https://asgi.readthedocs.io/en/latest/specs/tls.html)."""
    der = ssl_object.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der) if der else None
    return {
        "server_cert": None,
        "client_cert_chain": [ssl.DER_cert_to_PEM_cert(der)] if der else [],
        "client_cert_name": cert.subject.rfc4514_string() if cert else None,
        "client_cert_error": None,
        "tls_version": _TLS_VERSIONS.get(ssl_object.version()),
        "cipher_suite": None,
    }


class _WithTLSExtension:
    def __init__(self, app, tls: dict):
        self.app, self.tls = app, tls

    async def __call__(self, scope, receive, send, sync_spawn, call_soon):
        if scope["type"] in ("http", "websocket"):
            scope.setdefault("extensions", {})["tls"] = self.tls
        await self.app(scope, receive, send, sync_spawn, call_soon)


def serve(app_path: str) -> None:
    import asyncio
    import importlib

    import hypercorn.asyncio.run as hypercorn_run
    from hypercorn.asyncio import serve as hypercorn_serve
    from hypercorn.asyncio.tcp_server import TCPServer
    from hypercorn.config import Config

    class TLSAwareTCPServer(TCPServer):
        async def run(self) -> None:
            ssl_object = self.writer.get_extra_info("ssl_object")
            if ssl_object is not None:  # el handshake mTLS ya se ha completado aquí
                self.app = _WithTLSExtension(self.app, _tls_extension(ssl_object))
            try:
                await super().run()
            except ssl.SSLError:
                pass  # cierre TLS abrupto del cliente al terminar la conexión: sin efecto

    class MutualTLSConfig(Config):
        def create_ssl_context(self) -> ssl.SSLContext | None:
            context = super().create_ssl_context()
            if context is not None:
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            return context

    hypercorn_run.TCPServer = TLSAwareTCPServer

    config = MutualTLSConfig()
    config.bind = [f"0.0.0.0:{TLS_PORT}"]
    config.insecure_bind = [f"127.0.0.1:{HEALTH_PORT}"]  # solo healthcheck local
    config.certfile, config.keyfile, config.ca_certs = CERT_FILE, KEY_FILE, CA_FILE
    config.verify_mode = ssl.CERT_REQUIRED
    config.alpn_protocols = ["h2", "http/1.1"]
    # El servidor debe mantener las conexiones ociosas más tiempo que sus clientes
    # (httpx 30 s, nginx 60 s): si cerrase antes, el cliente podría reutilizar una
    # conexión ya cerrada ("Server disconnected").
    config.keep_alive_timeout = 75
    config.accesslog = None
    config.errorlog = "-"
    config.loglevel = os.getenv("LOG_LEVEL", "WARNING")
    config.include_server_header = False

    module_name, _, attr = app_path.partition(":")
    app = getattr(importlib.import_module(module_name), attr or "app")
    asyncio.run(hypercorn_serve(app, config))


if __name__ == "__main__":
    serve(sys.argv[1] if len(sys.argv) > 1 else "main:app")
