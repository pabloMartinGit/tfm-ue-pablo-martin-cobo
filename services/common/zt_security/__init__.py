"""Librería común de seguridad Zero Trust (PEP) para los microservicios del PoC.

Encapsula la validación de tokens, la consulta al PDP, la propagación de
identidad (Token Exchange + mTLS) y la trazabilidad distribuida, de modo que la
lógica de negocio no implemente rutinas de seguridad propias (requisito RU-03).
"""

from .audit import audit_log
from .auth import SecurityContext, require_delegated, require_service, require_user
from .config import settings
from .exchange import delegated_token
from .health import add_health_endpoint
from .introspection import enforce_active, is_token_active
from .pdp import authorize, evaluate
from .relay import raise_for_downstream, relay
from .tracing import add_tracing, note

__all__ = [
    "SecurityContext",
    "add_health_endpoint",
    "add_tracing",
    "audit_log",
    "authorize",
    "delegated_token",
    "enforce_active",
    "evaluate",
    "is_token_active",
    "note",
    "raise_for_downstream",
    "relay",
    "require_delegated",
    "require_service",
    "require_user",
    "settings",
]
