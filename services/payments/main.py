"""Microservicio B - Pagos (recurso crítico, solo accesible M2M desde la red interna).

Solo acepta tokens delegados (Token Exchange) cuya audiencia es payments-service,
presentados por la carga de trabajo que los obtuvo (mTLS). Ni el token de borde
del usuario ni un token canjeado para otro servicio sirven aquí.
"""

import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Literal

from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict, Field

from zt_security import (
    SecurityContext,
    add_health_endpoint,
    add_tracing,
    authorize,
    enforce_active,
    note,
    require_delegated,
)

app = FastAPI(title="Payments Service", version="0.1.0")
add_health_endpoint(app)
add_tracing(app)

_payments: dict[str, dict] = {}
_lock = Lock()


class PaymentRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    order_id: str = Field(max_length=64)
    amount: float = Field(gt=0)
    currency: Literal["EUR"] = "EUR"


@app.post("/internal/v1/payments", status_code=201)
def execute_payment(body: PaymentRequest, ctx: SecurityContext = Depends(require_delegated)) -> dict:
    # ABAC: el PDP compara el importe con el atributo max_transaction_limit del usuario
    # y exige que el token lo haya delegado el servicio de pedidos (azp) y que la
    # conexión mTLS provenga de ese mismo servicio (SPIFFE ID).
    authorize(
        ctx,
        "payments:execute",
        {"type": "payment", "tenant_id": ctx.tenant_id, "owner_id": ctx.subject},
        {"amount": body.amount, "currency": body.currency},
    )
    # Revocación en tiempo real (RFC 7662): tras autorizar, se pivota a un modelo con
    # estado y se pregunta al IdP si el token sigue activo. Un token de una sesión
    # cerrada (logout) o revocada se rechaza aunque no haya expirado. Keycloak solo deja
    # introspeccionar tokens cuya audiencia incluye al cliente que pregunta: el token
    # delegado (aud = payments-service) lo cumple siempre.
    enforce_active(ctx)
    payment = {
        "payment_id": str(uuid.uuid4()),
        "order_id": body.order_id,
        "owner_id": ctx.subject,
        "tenant_id": ctx.tenant_id,
        "amount": body.amount,
        "currency": body.currency,
        "status": "captured",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        _payments[payment["payment_id"]] = payment
    note(ctx, "Cobro capturado", payment_id=payment["payment_id"], amount=body.amount)
    return payment
