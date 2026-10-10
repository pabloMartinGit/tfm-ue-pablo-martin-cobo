"""Trazabilidad distribuida (RU-06): contexto W3C propagado por todos los saltos,
traza consultable con control de acceso ABAC y no manipulable desde el exterior."""

from conftest import wait_trace


def test_st33_trace_covers_every_hop_and_is_access_controlled(api, token):
    """ST-33: la traza de un pedido recorre gateway, Pedidos, Inventario y Pagos con sus
    decisiones del PDP; solo la ve su autor o un auditor del mismo tenant."""
    created = api("POST", "/api/v1/orders", token("alice"), json={"sku": "SKU-002", "quantity": 1})
    assert created.status_code == 201
    trace_id = created.headers["X-Request-ID"]

    trace = wait_trace(api, trace_id, token("alice"))
    spans = trace["spans"]
    assert all(span["trace_id"] == trace_id for span in spans)
    assert {"orders-service", "inventory-service", "payments-service"} <= {s["service"] for s in spans}

    root = next(s for s in spans if s["attrs"].get("via") == "api-gateway")
    assert root["service"] == "orders-service"
    assert root["attrs"]["edge"]["result"] == "verified"
    assert root["parent_id"] == trace_id[:16]  # span del gateway derivado del trace-id

    decisions = {e["action"]: e["decision"] for s in spans for e in s["events"] if e["type"] == "pdp"}
    assert decisions == {"orders:create": "allow", "inventory:reserve": "allow",
                         "payments:execute": "allow", "inventory:commit": "allow"}
    # Cada llamada saliente enlaza exactamente con el span del servicio destino.
    call_ids = {e["span_id"] for s in spans for e in s["events"] if e["type"] == "call"}
    assert {s["parent_id"] for s in spans if s is not root} <= call_ids

    other = api("GET", f"/api/v1/traces/{trace_id}", token("bob"))
    assert other.status_code == 403
    assert "not_resource_owner" in other.json()["detail"]["reasons"]
    assert api("GET", f"/api/v1/traces/{trace_id}", token("dave")).status_code == 200
    cross_tenant = api("GET", f"/api/v1/traces/{trace_id}", token("carol"))
    assert cross_tenant.status_code == 403
    assert "tenant_mismatch" in cross_tenant.json()["detail"]["reasons"]


def test_st36_client_cannot_inject_trace_context(api, token):
    """ST-36: el gateway descarta el `traceparent` del cliente y abre una traza nueva,
    de modo que nadie puede colar spans en la traza de otra petición."""
    injected = "f" * 32
    response = api("GET", "/api/v1/inventory", token("alice"),
                   headers={"traceparent": f"00-{injected}-{'f' * 16}-01", "X-Edge-Auth": "verified;forged"})
    assert response.status_code == 200
    trace_id = response.headers["X-Request-ID"]
    assert trace_id != injected

    trace = wait_trace(api, trace_id, token("alice"))
    assert trace["spans"][0]["attrs"]["edge"]["result"] == "verified"
    assert trace["spans"][0]["attrs"]["edge"].get("alg") == "RS256"
    assert api("GET", f"/api/v1/traces/{injected}", token("alice")).status_code == 404
