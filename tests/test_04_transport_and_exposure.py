"""Seguridad de transporte y superficie expuesta por el gateway."""

import requests

from conftest import GATEWAY_HTTP_URL, wait_trace


def test_st24_http_redirects_to_https():
    """ST-24: todo acceso HTTP se redirige a HTTPS."""
    response = requests.get(f"{GATEWAY_HTTP_URL}/api/v1/orders", allow_redirects=False, timeout=5)
    assert response.status_code == 301
    assert response.headers["Location"].startswith("https://")


def test_st25_security_headers_present(api, token):
    """ST-25: cabeceras de seguridad perimetral y ocultación de versión del servidor."""
    response = api("GET", "/api/v1/inventory", token("alice"))
    assert "max-age" in response.headers.get("Strict-Transport-Security", "")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Request-ID")
    assert response.headers.get("Server", "") in ("nginx", "")


def test_st26_internal_routes_not_published(api, token):
    """ST-26: Pagos y las rutas /internal/* no se publican en el gateway (404)."""
    assert api("POST", "/api/v1/payments", token("alice"), json={}).status_code == 404
    assert api("POST", "/internal/v1/payments", token("alice"), json={}).status_code == 404
    assert api("POST", "/internal/v1/inventory/reserve", token("alice"), json={}).status_code == 404


def test_st27_identity_headers_cannot_be_spoofed(api, token):
    """ST-27 (header spoofing, Tabla 8): la identidad de la carga de trabajo llamante no
    viaja en cabeceras sino en el handshake mTLS. Un cliente externo que inyecta
    cabeceras de identidad (certificado reenviado, SPIFFE ID, token de servicio) no
    altera nada: el servicio sigue viendo al gateway como llamante."""
    forged = {
        "X-Forwarded-Client-Cert": "URI=spiffe://tfm.local/ns/poc/sa/orders-service",
        "X-SPIFFE-ID": "spiffe://tfm.local/ns/poc/sa/orders-service",
        "X-Service-Token": "forged.service.token",
    }
    response = api("POST", "/api/v1/orders", token("alice"), headers=forged,
                   json={"sku": "SKU-002", "quantity": 1})
    assert response.status_code == 201
    trace = wait_trace(api, response.headers["X-Request-ID"], token("alice"))
    root = next(s for s in trace["spans"] if s["attrs"].get("via") == "api-gateway")
    assert root["attrs"]["transport"]["peer"] == "spiffe://tfm.local/ns/poc/sa/api-gateway"
