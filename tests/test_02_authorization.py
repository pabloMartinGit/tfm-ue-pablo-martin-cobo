"""Autorización desacoplada (RBAC + ABAC en OPA) frente a OWASP API Security Top 10 2023."""


def _stock(api, token, sku):
    return api("GET", "/api/v1/inventory", token).json()["items"][sku]["stock"]


def test_st09_happy_path_order_flow(api, token):
    """ST-09: flujo completo Pedidos -> Inventario -> Pagos -> Inventario con token relay -> 201."""
    before = _stock(api, token("alice"), "SKU-001")
    response = api("POST", "/api/v1/orders", token("alice"), json={"sku": "SKU-001", "quantity": 2})
    assert response.status_code == 201, response.text
    order = response.json()
    assert order["status"] == "confirmed"
    assert order["amount"] == 2400
    assert order["payment_id"]
    assert _stock(api, token("alice"), "SKU-001") == before - 2


def test_st10_bola_other_user_cannot_read_order(api, token, alice_order):
    """ST-10 (API1:2023 BOLA): bob, mismo tenant y mismo rol, no puede leer el pedido de alice."""
    path = f"/api/v1/orders/{alice_order['order_id']}"
    assert api("GET", path, token("alice")).status_code == 200
    response = api("GET", path, token("bob"))
    assert response.status_code == 403
    assert "not_resource_owner" in response.json()["detail"]["reasons"]


def test_st11_bola_other_user_cannot_cancel_order(api, token, alice_order):
    """ST-11 (API1:2023 BOLA en escritura): bob no puede cancelar el pedido de alice; alice sí."""
    path = f"/api/v1/orders/{alice_order['order_id']}/cancel"
    assert api("POST", path, token("bob")).status_code == 403
    response = api("POST", path, token("alice"))
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"


def test_st12_cross_tenant_access_is_denied(api, token, alice_order):
    """ST-12 (multitenencia): carol (tenant beta) no accede a recursos del tenant alpha."""
    response = api("GET", f"/api/v1/orders/{alice_order['order_id']}", token("carol"))
    assert response.status_code == 403
    assert "tenant_mismatch" in response.json()["detail"]["reasons"]
    catalog = api("GET", "/api/v1/inventory", token("carol")).json()
    assert catalog["tenant_id"] == "tenant-corp-beta"
    assert "SKU-003" not in catalog["items"]


def test_st13_mass_assignment_is_ignored(api, token):
    """ST-13 (API3:2023 BOPLA): propiedades privilegiadas inyectadas en el body se ignoran."""
    response = api("POST", "/api/v1/orders", token("alice"), json={
        "sku": "SKU-002", "quantity": 1,
        "owner_id": "attacker", "tenant_id": "tenant-corp-beta",
        "status": "paid", "amount": 0.01, "role": "admin",
    })
    assert response.status_code == 201
    order = response.json()
    alice_sub = api("GET", f"/api/v1/orders/{order['order_id']}", token("alice")).json()["owner_id"]
    assert order["owner_id"] == alice_sub != "attacker"
    assert order["tenant_id"] == "tenant-corp-alpha"
    assert order["amount"] == 300
    assert order["status"] == "confirmed"


def test_st14_auditor_is_read_only(api, token, alice_order):
    """ST-14 (RBAC): el auditor lee cualquier pedido de su tenant pero no puede crear ni cancelar."""
    path = f"/api/v1/orders/{alice_order['order_id']}"
    assert api("GET", path, token("dave")).status_code == 200
    listed = api("GET", "/api/v1/orders", token("dave")).json()
    assert any(o["order_id"] == alice_order["order_id"] for o in listed["items"])

    response = api("POST", "/api/v1/orders", token("dave"), json={"sku": "SKU-001", "quantity": 1})
    assert response.status_code == 403
    assert "missing_role" in response.json()["detail"]["reasons"]
    assert api("POST", f"{path}/cancel", token("dave")).status_code == 403


def test_st15_list_only_returns_own_orders(api, token, alice_order):
    """ST-15 (filtrado de datos vía PDP): bob no ve los pedidos de alice en el listado."""
    listed = api("GET", "/api/v1/orders", token("bob")).json()
    assert all(o["order_id"] != alice_order["order_id"] for o in listed["items"])


def test_st16_abac_transaction_limit(api, token):
    """ST-16 (ABAC): importe > max_transaction_limit del usuario -> pago denegado y stock liberado."""
    before = _stock(api, token("alice"), "SKU-003")
    response = api("POST", "/api/v1/orders", token("alice"), json={"sku": "SKU-003", "quantity": 1})
    assert response.status_code == 403
    assert "amount_exceeds_limit" in response.json()["detail"]["reasons"]
    assert _stock(api, token("alice"), "SKU-003") == before


def test_st17_bfla_admin_endpoint_requires_role_clearance_and_mfa(api, token, stepup_token, alice_order):
    """ST-17 (API5:2023 BFLA): purge exige rol admin + clearance >= 5 + step-up MFA
    (acr=aal2 del flujo interactivo; el grant de contraseña nunca lo acredita)."""
    response = api("DELETE", "/api/v1/admin/purge", token("alice"))
    assert response.status_code == 403
    assert "missing_role" in response.json()["detail"]["reasons"]

    response = api("DELETE", "/api/v1/admin/purge", token("frank"))  # admin sin MFA
    assert response.status_code == 403
    assert "mfa_required" in response.json()["detail"]["reasons"]

    # erin con step-up (contraseña + OTP, acr=aal2) y clearance 5
    response = api("DELETE", "/api/v1/admin/purge", stepup_token("erin"))
    assert response.status_code == 200
    assert response.json()["purged"] >= 1
