"""Microservicio A - Pedidos (único servicio de negocio expuesto a través del gateway).

Orquesta el flujo de la Ilustración 12 de la memoria:
  1. Autoriza orders:create en el PDP.
  2. Reserva stock en Inventario (token delegado aud=inventory-service + mTLS).
  3. Ejecuta el cobro en Pagos (token delegado aud=payments-service + mTLS).
  4. Confirma la reserva en Inventario.
  5. Devuelve 201 Created con el identificador del pedido.

El token del usuario nunca sale de este servicio: para cada destino se canjea
(Token Exchange, RFC 8693) por uno cuya audiencia es solo ese destino.
"""

import os
import uuid
from datetime import datetime, timezone
from threading import Lock

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from zt_security import (
    SecurityContext,
    add_health_endpoint,
    add_tracing,
    audit_log,
    authorize,
    evaluate,
    note,
    raise_for_downstream,
    relay,
    require_user,
)

INVENTORY_URL = os.environ["INVENTORY_SERVICE_URL"]
PAYMENTS_URL = os.environ["PAYMENTS_SERVICE_URL"]
# Audiencias de los tokens delegados (client_id de cada servicio destino en Keycloak)
INVENTORY_AUDIENCE = "inventory-service"
PAYMENTS_AUDIENCE = "payments-service"

app = FastAPI(title="Orders Service", version="0.1.0")
add_health_endpoint(app)
add_tracing(app)

_orders: dict[str, dict] = {}
_lock = Lock()


class OrderCreate(BaseModel):
    # API3:2023 (Broken Object Property Level Authorization): los campos no
    # declarados (owner_id, tenant_id, status, role...) se descartan; la identidad
    # y el tenant proceden exclusivamente del JWT firmado por Keycloak.
    model_config = ConfigDict(extra="ignore")
    sku: str = Field(pattern=r"^[A-Z0-9-]{3,32}$")
    quantity: int = Field(gt=0, le=100)


def _as_resource(order: dict) -> dict:
    return {"type": "order", "id": order["order_id"], "tenant_id": order["tenant_id"], "owner_id": order["owner_id"]}


def _load_order(order_id: str) -> dict:
    order = _orders.get(order_id)
    if order is None:
        raise HTTPException(404, {"error": "order_not_found"})
    return order


@app.post("/api/v1/orders", status_code=201)
def create_order(body: OrderCreate, ctx: SecurityContext = Depends(require_user)) -> dict:
    authorize(ctx, "orders:create", {"type": "order", "tenant_id": ctx.tenant_id, "owner_id": ctx.subject})
    order_id = str(uuid.uuid4())

    reservation = raise_for_downstream(
        relay(ctx, "POST", f"{INVENTORY_URL}/internal/v1/inventory/reserve",
              {"order_id": order_id, "sku": body.sku, "quantity": body.quantity}, audience=INVENTORY_AUDIENCE)
    )

    payment_response = relay(ctx, "POST", f"{PAYMENTS_URL}/internal/v1/payments",
                             {"order_id": order_id, "amount": reservation["amount"], "currency": "EUR"},
                             audience=PAYMENTS_AUDIENCE)
    if not payment_response.is_success:
        # Compensación: se libera el stock reservado si el pago es rechazado.
        note(ctx, "Pago rechazado: compensación, se libera la reserva de stock",
             reservation_id=reservation["reservation_id"])
        relay(ctx, "POST", f"{INVENTORY_URL}/internal/v1/inventory/release",
              {"reservation_id": reservation["reservation_id"]}, audience=INVENTORY_AUDIENCE)
        audit_log("order_rejected", order_id=order_id, payment_status=payment_response.status_code,
                  request_id=ctx.request_id)
    payment = raise_for_downstream(payment_response)

    raise_for_downstream(
        relay(ctx, "POST", f"{INVENTORY_URL}/internal/v1/inventory/commit",
              {"reservation_id": reservation["reservation_id"]}, audience=INVENTORY_AUDIENCE)
    )

    order = {
        "order_id": order_id,
        "owner_id": ctx.subject,
        "tenant_id": ctx.tenant_id,
        "sku": body.sku,
        "quantity": body.quantity,
        "amount": reservation["amount"],
        "currency": "EUR",
        "payment_id": payment["payment_id"],
        "status": "confirmed",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        _orders[order_id] = order
    note(ctx, "Pedido confirmado", order_id=order_id, amount=order["amount"])
    return order


@app.get("/api/v1/orders")
def list_orders(ctx: SecurityContext = Depends(require_user)) -> dict:
    # Filtrado de datos delegado al PDP: solo se devuelven los pedidos que la
    # política permite leer al sujeto (propios, o todos los del tenant si es auditor/admin).
    visible = [
        order for order in list(_orders.values())
        if order["tenant_id"] == ctx.tenant_id and evaluate(ctx, "orders:read", _as_resource(order))[0]
    ]
    return {"items": visible, "count": len(visible)}


@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, ctx: SecurityContext = Depends(require_user)) -> dict:
    order = _load_order(order_id)
    # API1:2023 (BOLA): la propiedad del objeto se comprueba en el PDP, no en el código.
    authorize(ctx, "orders:read", _as_resource(order))
    return order


@app.post("/api/v1/orders/{order_id}/cancel")
def cancel_order(order_id: str, ctx: SecurityContext = Depends(require_user)) -> dict:
    order = _load_order(order_id)
    authorize(ctx, "orders:cancel", _as_resource(order))
    with _lock:
        if order["status"] != "confirmed":
            raise HTTPException(409, {"error": f"order_{order['status']}"})
        order["status"] = "cancelled"
    return order


@app.delete("/api/v1/admin/purge")
def purge_orders(ctx: SecurityContext = Depends(require_user)) -> dict:
    # API5:2023 (BFLA): función administrativa protegida por rol + clearance + step-up
    # MFA reciente (acr=aal2 / amr otp, emitidos por Keycloak en el flujo interactivo).
    authorize(ctx, "admin:purge", {"type": "orders", "tenant_id": ctx.tenant_id})
    with _lock:
        doomed = [oid for oid, order in _orders.items() if order["tenant_id"] == ctx.tenant_id]
        for oid in doomed:
            del _orders[oid]
    audit_log("orders_purged", tenant_id=ctx.tenant_id, count=len(doomed), sub=ctx.subject,
              request_id=ctx.request_id)
    return {"purged": len(doomed), "tenant_id": ctx.tenant_id}
