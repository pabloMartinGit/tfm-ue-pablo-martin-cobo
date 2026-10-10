"""Microservicio C - Inventario (Resource Server + PEP).

Expone el catálogo del tenant a través del gateway (token de usuario de borde) y,
en la red interna, las operaciones de reserva/confirmación/liberación de stock que
invoca el servicio de pedidos con un token delegado (aud = inventory-service).
"""

import uuid
from copy import deepcopy
from threading import Lock

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from zt_security import (
    SecurityContext,
    add_health_endpoint,
    add_tracing,
    authorize,
    note,
    require_delegated,
    require_user,
)

app = FastAPI(title="Inventory Service", version="0.1.0")
add_health_endpoint(app)
add_tracing(app)

# Datos de ejemplo del PoC, aislados por tenant (multitenencia lógica).
_CATALOG = {
    "tenant-corp-alpha": {
        "SKU-001": {"name": "Portátil", "unit_price": 1200, "stock": 500},
        "SKU-002": {"name": "Monitor", "unit_price": 300, "stock": 1000},
        "SKU-003": {"name": "Servidor", "unit_price": 9000, "stock": 50},
    },
    "tenant-corp-beta": {
        "SKU-001": {"name": "Portátil", "unit_price": 1150, "stock": 200},
        "SKU-004": {"name": "Router", "unit_price": 450, "stock": 300},
    },
}
_stock = deepcopy(_CATALOG)
_reservations: dict[str, dict] = {}
_lock = Lock()


class ReserveRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    order_id: str = Field(max_length=64)
    sku: str = Field(pattern=r"^[A-Z0-9-]{3,32}$")
    quantity: int = Field(gt=0, le=100)


class ReservationRef(BaseModel):
    model_config = ConfigDict(extra="ignore")
    reservation_id: str = Field(max_length=64)


@app.get("/api/v1/inventory")
def list_inventory(ctx: SecurityContext = Depends(require_user)) -> dict:
    authorize(ctx, "inventory:read", {"type": "catalog", "tenant_id": ctx.tenant_id})
    return {"tenant_id": ctx.tenant_id, "items": _stock.get(ctx.tenant_id, {})}


@app.post("/internal/v1/inventory/reserve", status_code=201)
def reserve(body: ReserveRequest, ctx: SecurityContext = Depends(require_delegated)) -> dict:
    # El tenant y el propietario se derivan del token, nunca del cuerpo de la petición.
    authorize(
        ctx,
        "inventory:reserve",
        {"type": "reservation", "tenant_id": ctx.tenant_id, "owner_id": ctx.subject},
    )
    with _lock:
        item = _stock.get(ctx.tenant_id, {}).get(body.sku)
        if item is None:
            raise HTTPException(404, {"error": "sku_not_found"})
        if item["stock"] < body.quantity:
            raise HTTPException(409, {"error": "insufficient_stock"})
        item["stock"] -= body.quantity
        reservation = {
            "reservation_id": str(uuid.uuid4()),
            "order_id": body.order_id,
            "owner_id": ctx.subject,
            "tenant_id": ctx.tenant_id,
            "sku": body.sku,
            "quantity": body.quantity,
            "unit_price": item["unit_price"],
            "amount": item["unit_price"] * body.quantity,
            "status": "reserved",
        }
        _reservations[reservation["reservation_id"]] = reservation
    note(ctx, f"Stock reservado: {body.quantity} x {body.sku} (quedan {item['stock']})",
         reservation_id=reservation["reservation_id"])
    return reservation


def _load_reservation(reservation_id: str) -> dict:
    reservation = _reservations.get(reservation_id)
    if reservation is None:
        raise HTTPException(404, {"error": "reservation_not_found"})
    return reservation


def _as_resource(reservation: dict) -> dict:
    return {"type": "reservation", "tenant_id": reservation["tenant_id"], "owner_id": reservation["owner_id"]}


@app.post("/internal/v1/inventory/commit")
def commit(body: ReservationRef, ctx: SecurityContext = Depends(require_delegated)) -> dict:
    reservation = _load_reservation(body.reservation_id)
    authorize(ctx, "inventory:commit", _as_resource(reservation))
    with _lock:
        if reservation["status"] != "reserved":
            raise HTTPException(409, {"error": f"reservation_{reservation['status']}"})
        reservation["status"] = "committed"
    return reservation


@app.post("/internal/v1/inventory/release")
def release(body: ReservationRef, ctx: SecurityContext = Depends(require_delegated)) -> dict:
    reservation = _load_reservation(body.reservation_id)
    authorize(ctx, "inventory:release", _as_resource(reservation))
    with _lock:
        if reservation["status"] != "reserved":
            raise HTTPException(409, {"error": f"reservation_{reservation['status']}"})
        _stock[reservation["tenant_id"]][reservation["sku"]]["stock"] += reservation["quantity"]
        reservation["status"] = "released"
    note(ctx, f"Reserva liberada: se devuelven {reservation['quantity']} x {reservation['sku']}")
    return reservation
