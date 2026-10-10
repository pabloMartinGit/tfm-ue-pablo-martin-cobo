"""Seguridad M2M y movimiento lateral.

Estas pruebas simulan un atacante dentro de la red backend. Como todo el tráfico
interno exige mTLS, el contenedor de pruebas usa dos identidades:
  - su propio SVID (identidad válida de la CA interna, sin ningún permiso), y
  - una copia del SVID de orders-service, que simula que ese servicio ha sido
    comprometido (clave privada y secreto de cliente robados).
Se omiten automáticamente si se ejecutan desde fuera de esa red.
"""

import os
import secrets
import time

import pytest
import requests

from conftest import (
    INTERNAL_CA,
    INVENTORY_URL,
    OPA_URL,
    ORDERS_SVID,
    OWN_SVID,
    PAYMENTS_URL,
    TRACES_URL,
    b64url_json,
    claims_of,
    decode_segment,
    delegated,
    internal,
)


def _reachable(url: str) -> bool:
    try:
        internal("GET", f"{url}/health", timeout=2)
        return True
    except (requests.RequestException, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not (os.path.exists(INTERNAL_CA) and _reachable(PAYMENTS_URL) and _reachable(INVENTORY_URL)
         and _reachable(TRACES_URL)),
    reason="Servicios internos no alcanzables: ejecutar dentro de la red backend (make test)",
)


def _pay(token: str | None, amount: float = 100, cert=ORDERS_SVID) -> requests.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return internal("POST", f"{PAYMENTS_URL}/internal/v1/payments", cert=cert, headers=headers,
                    json={"order_id": "lateral-test", "amount": amount, "currency": "EUR"})


def test_st18_internal_service_revalidates_tokens(token):
    """ST-18: la red interna no es confiable; el servicio vuelve a validar el JWT aunque
    la petición llegue por mTLS desde un servicio legítimo (sin token o con claims
    manipulados -> 401)."""
    assert _pay(None).status_code == 401

    header, payload, signature = delegated(token("alice"), "payments-service").split(".")
    claims = decode_segment(payload)
    claims["max_transaction_limit"] = 10_000_000
    tampered = f"{header}.{b64url_json(claims)}.{signature}"
    assert _pay(tampered).status_code == 401


def test_st19_edge_token_relayed_to_internal_service_is_rejected(token):
    """ST-19 (Token Relay, Tabla 8): el token de borde del usuario, reenviado tal cual a
    Pagos, no sirve: su audiencia no incluye payments-service -> 401. Solo un token
    delegado para Pagos se acepta."""
    edge_claims = claims_of(token("alice"))
    assert "payments-service" not in edge_claims["aud"]
    assert "payments-service" not in edge_claims.get("resource_access", {})
    assert _pay(token("alice")).status_code == 401


def test_st20_token_exchanged_for_one_hop_is_useless_on_another(token):
    """ST-20 (aislamiento por salto): un token intercambiado para Inventario, capturado
    en ese salto, no sirve contra Pagos (aud = inventory-service) -> 401."""
    for_inventory = delegated(token("alice"), "inventory-service")
    assert claims_of(for_inventory)["aud"] == "inventory-service"
    assert _pay(for_inventory).status_code == 401


def test_st21_forged_delegated_token_is_rejected(token):
    """ST-21: token delegado falsificado (alg none) con las claims de uno legítimo -> 401."""
    claims = claims_of(delegated(token("alice"), "payments-service"))
    forged = f"{b64url_json({'alg': 'none', 'typ': 'JWT'})}.{b64url_json(claims)}."
    assert _pay(forged).status_code == 401


def test_st22_confused_deputy_cannot_act_on_foreign_resources(token):
    """ST-22 (diputado confuso): aun con la identidad de orders-service comprometida,
    el servicio no puede confirmar la reserva de alice usando la identidad de bob."""
    reserve = internal("POST", f"{INVENTORY_URL}/internal/v1/inventory/reserve",
                       headers={"Authorization": f"Bearer {delegated(token('alice'), 'inventory-service')}"},
                       json={"order_id": "deputy-test", "sku": "SKU-002", "quantity": 1})
    assert reserve.status_code == 201, reserve.text
    reservation_id = reserve.json()["reservation_id"]

    as_bob = internal("POST", f"{INVENTORY_URL}/internal/v1/inventory/commit",
                      headers={"Authorization": f"Bearer {delegated(token('bob'), 'inventory-service')}"},
                      json={"reservation_id": reservation_id})
    assert as_bob.status_code == 403
    assert "not_resource_owner" in as_bob.json()["detail"]["reasons"]

    release = internal("POST", f"{INVENTORY_URL}/internal/v1/inventory/release",
                       headers={"Authorization": f"Bearer {delegated(token('alice'), 'inventory-service')}"},
                       json={"reservation_id": reservation_id})
    assert release.status_code == 200


def test_st23_pdp_is_only_reachable_by_peps_and_management_api_is_locked():
    """ST-23: el PDP exige mTLS y solo atiende a los PEP. Un contenedor con identidad
    válida pero ajena no puede ni consultar decisiones; ni siquiera un PEP (orders
    comprometido) puede sustituir políticas o leer datos por la API."""
    with pytest.raises(requests.exceptions.ConnectionError):
        internal("GET", f"{OPA_URL}/health", cert=None)

    decision_url = f"{OPA_URL}/v1/data/tfm/authz/decision"
    as_foreign = internal("POST", decision_url, cert=OWN_SVID, json={"input": {}})
    assert as_foreign.status_code == 401

    malicious = "package tfm.authz\n\nallow := true\n"
    assert internal("PUT", f"{OPA_URL}/v1/policies/tfm/authz", data=malicious).status_code == 401
    assert internal("GET", f"{OPA_URL}/v1/data").status_code == 401
    assert internal("GET", f"{OPA_URL}/v1/policies").status_code == 401
    decision = internal("POST", decision_url, json={"input": {}})
    assert decision.status_code == 200
    assert decision.json()["result"]["allow"] is False


def _fake_span(trace_id: str, sub: str, claimed_service: str) -> dict:
    now = time.time() * 1000
    return {
        "trace_id": trace_id, "span_id": secrets.token_hex(8), "parent_id": None,
        "service": claimed_service, "name": "POST /fake", "start": now, "end": now + 1, "status": 200,
        "attrs": {}, "events": [{"t": now, "type": "authn", "kind": "user", "ok": True,
                                 "sub": sub, "tenant_id": "tenant-corp-alpha"}],
    }


def test_st34_trace_ingestion_is_m2m_only(token, service_token):
    """ST-34: solo los microservicios autorizados publican spans; un usuario no puede
    inyectar trazas aunque tenga un token válido."""
    batch = {"spans": [_fake_span(secrets.token_hex(16), "x", "orders-service")]}
    url = f"{TRACES_URL}/internal/v1/spans"
    assert internal("POST", url, json=batch).status_code == 401
    as_user = internal("POST", url, json=batch, headers={"Authorization": f"Bearer {token('alice')}"})
    assert as_user.status_code == 403
    assert "service_not_authorized" in as_user.json()["detail"]["reasons"]
    as_service = internal("POST", url, json=batch, headers={"Authorization": f"Bearer {service_token}"})
    assert as_service.status_code == 202


def test_st35_collector_stamps_authenticated_service_identity(api, token, service_token):
    """ST-35: el colector sella cada span con la identidad mTLS verificada: orders-service
    no puede publicar spans haciéndose pasar por payments-service."""
    trace_id = secrets.token_hex(16)
    alice_sub = claims_of(token("alice"))["sub"]
    response = internal("POST", f"{TRACES_URL}/internal/v1/spans",
                        json={"spans": [_fake_span(trace_id, alice_sub, "payments-service")]},
                        headers={"Authorization": f"Bearer {service_token}"})
    assert response.status_code == 202
    trace = api("GET", f"/api/v1/traces/{trace_id}", token("alice"))
    assert trace.status_code == 200
    assert [s["service"] for s in trace.json()["spans"]] == ["orders-service"]
