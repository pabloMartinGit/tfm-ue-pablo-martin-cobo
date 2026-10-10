"""Permisos variados entre usuarios (RBAC de grano fino, RBAC jerárquico, ABAC)
y gestión centralizada de identidades en el IdP (RU-05)."""

from conftest import TOKEN_URL, DEMO_PASSWORD, decode_segment, stock


def test_st28_authorization_is_enforced_at_every_hop(api, token):
    """ST-28 (defensa en profundidad): gina puede crear pedidos (Pedidos e Inventario lo
    permiten) pero no tiene `payments:execute`: el servicio de Pagos deniega y se compensa."""
    before = stock(api, token("gina"), "SKU-002")
    response = api("POST", "/api/v1/orders", token("gina"), json={"sku": "SKU-002", "quantity": 1})
    assert response.status_code == 403
    assert "missing_role" in response.json()["detail"]["reasons"]
    assert stock(api, token("gina"), "SKU-002") == before


def test_st29_supervisor_role_hierarchy(api, token, alice_order):
    """ST-29 (RBAC jerárquico, RBAC1): `supervisor` es un rol compuesto que incluye `operator`;
    hector puede leer y cancelar pedidos ajenos de su tenant."""
    roles = set(decode_segment(token("hector").split(".")[1])["realm_access"]["roles"])
    assert {"supervisor", "operator"} <= roles

    path = f"/api/v1/orders/{alice_order['order_id']}"
    assert api("GET", path, token("hector")).status_code == 200
    response = api("POST", f"{path}/cancel", token("hector"))
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"


def test_st30_junior_operator_cannot_cancel_own_order(api, token):
    """ST-30 (RBAC de grano fino): bob crea pedidos pero no tiene `orders:cancel`,
    ni siquiera sobre sus propios pedidos."""
    created = api("POST", "/api/v1/orders", token("bob"), json={"sku": "SKU-002", "quantity": 1})
    assert created.status_code == 201
    response = api("POST", f"/api/v1/orders/{created.json()['order_id']}/cancel", token("bob"))
    assert response.status_code == 403
    assert "missing_role" in response.json()["detail"]["reasons"]


def test_st31_same_role_different_attributes(api, token):
    """ST-31 (ABAC): alice y bob tienen el mismo rol; el importe (1.200 €) supera el
    `max_transaction_limit` de bob (1.000 €) pero no el de alice (5.000 €)."""
    as_bob = api("POST", "/api/v1/orders", token("bob"), json={"sku": "SKU-001", "quantity": 1})
    assert as_bob.status_code == 403
    assert "amount_exceeds_limit" in as_bob.json()["detail"]["reasons"]
    as_alice = api("POST", "/api/v1/orders", token("alice"), json={"sku": "SKU-001", "quantity": 1})
    assert as_alice.status_code == 201


def test_st32_suspended_account_cannot_authenticate(http):
    """ST-32 (RU-05): una cuenta deshabilitada en Keycloak no obtiene ningún token."""
    response = http.post(TOKEN_URL, data={
        "grant_type": "password", "client_id": "tfm-web",
        "username": "ivan", "password": DEMO_PASSWORD,
    })
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert "disabled" in response.json()["error_description"].lower()
