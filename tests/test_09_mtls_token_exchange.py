"""mTLS interno (SVID X.509 con ID SPIFFE), HTTP/2 y Token Exchange (RFC 8693).

Comprueba que el tráfico este-oeste exige identidad de carga de trabajo, que la
identidad del transporte se vincula al token (un token robado no sirve desde otra
carga de trabajo) y que cada salto usa un token con la audiencia reducida al
servicio destino.
"""

import datetime
import os
import socket
import ssl
from urllib.parse import urlparse

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from conftest import (
    INTERNAL_CA,
    INVENTORY_URL,
    KEYCLOAK_URL,
    OPA_URL,
    ORDERS_SVID,
    ORDERS_URL,
    OWN_SVID,
    PAYMENTS_URL,
    TOKEN_URL,
    claims_of,
    delegated,
    exchange,
    internal,
    wait_trace,
)

INTERNAL_ENDPOINTS = [f"{ORDERS_URL}/health", f"{PAYMENTS_URL}/health", f"{INVENTORY_URL}/health",
                      f"{OPA_URL}/health", f"{KEYCLOAK_URL}/realms/tfm/protocol/openid-connect/certs"]


def _in_backend_network() -> bool:
    try:
        return os.path.exists(INTERNAL_CA) and internal("GET", f"{PAYMENTS_URL}/health", timeout=2).ok
    except (requests.RequestException, OSError):
        return False


backend_only = pytest.mark.skipif(not _in_backend_network(),
                                  reason="Red interna no alcanzable: ejecutar dentro de la red backend (make test)")


@pytest.fixture(scope="module")
def rogue_svid(tmp_path_factory):
    """SVID autoemitido por una CA ajena con el SPIFFE ID de orders-service (suplantación)."""
    directory = tmp_path_factory.mktemp("rogue")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "orders-service")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("spiffe://tfm.local/ns/poc/sa/orders-service"),
                x509.DNSName("orders-service")]), critical=False)
            .sign(key, hashes.SHA256()))
    (directory / "svid.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "svid.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(directory / "svid.pem"), str(directory / "svid.key")


@backend_only
def test_st47_east_west_traffic_requires_a_valid_svid(rogue_svid):
    """ST-47: sin certificado de cliente, o con uno emitido por una CA ajena (aunque
    declare el SPIFFE ID de orders-service), ningún servicio interno, ni el PDP ni el
    IdP completan el handshake TLS (el servidor responde con la alerta "certificate
    required"/"unknown ca" y corta). Con un SVID de la CA interna, sí."""
    for url in INTERNAL_ENDPOINTS:
        with pytest.raises(requests.exceptions.ConnectionError):
            internal("GET", url, cert=None)
        with pytest.raises(requests.exceptions.ConnectionError):
            internal("GET", url, cert=rogue_svid)
        assert internal("GET", url, cert=OWN_SVID).status_code == 200, url


@backend_only
def test_st48_internal_tls_is_tls13_and_verifies_server_identity():
    """ST-48: el transporte interno es TLS 1.3 y el cliente autentica al servidor: el
    certificado de payments-service no es válido para otro nombre (anti-MitM)."""
    context = ssl.create_default_context(cafile=INTERNAL_CA)
    context.load_cert_chain(*OWN_SVID)
    target = urlparse(PAYMENTS_URL)
    with socket.create_connection((target.hostname, target.port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="payments-service") as tls:
            assert tls.version() == "TLSv1.3"
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection((target.hostname, target.port), timeout=5) as raw:
            context.wrap_socket(raw, server_hostname="orders-service")


@backend_only
def test_st49_stolen_delegated_token_is_useless_from_another_workload(token):
    """ST-49 (vínculo token <-> mTLS): con el secreto de orders-service robado se obtiene
    un token delegado para Pagos legítimo, pero presentado desde otra carga de trabajo
    (SVID propio del atacante) Pagos lo rechaza: el SPIFFE ID no coincide con el azp."""
    stolen = delegated(token("alice"), "payments-service")
    assert claims_of(stolen)["azp"] == "orders-service"
    response = internal("POST", f"{PAYMENTS_URL}/internal/v1/payments", cert=OWN_SVID,
                        headers={"Authorization": f"Bearer {stolen}"},
                        json={"order_id": "stolen", "amount": 100, "currency": "EUR"})
    assert response.status_code == 403
    assert response.json()["detail"]["reasons"] == ["peer_identity_mismatch"]


@backend_only
def test_st50_edge_actions_cannot_bypass_the_gateway(token):
    """ST-50: aun con un token de usuario válido y un SVID legítimo (el propio o el de otro
    servicio interno), invocar Pedidos directamente por la red interna saltándose el PEP
    de borde se deniega: las acciones de usuario solo se aceptan desde el gateway."""
    for cert in (OWN_SVID, ORDERS_SVID):
        response = internal("POST", f"{ORDERS_URL}/api/v1/orders", cert=cert,
                            headers={"Authorization": f"Bearer {token('alice')}"},
                            json={"sku": "SKU-002", "quantity": 1})
        assert response.status_code == 403
        assert "edge_bypass" in response.json()["detail"]["reasons"]


def test_st51_token_exchange_reduces_audience_on_every_hop(api, token):
    """ST-51 (Token Exchange, Tabla 8): el token de borde solo vale para la API de borde y
    Pedidos; en cada salto Pedidos lo canjea por uno cuya audiencia es solo el destino,
    delegado por orders-service (azp) y con los roles de ese destino. La traza lo muestra."""
    edge = claims_of(token("alice"))
    assert set(edge["aud"]) == {"microservices-backend-api", "orders-service"}
    assert set(edge.get("resource_access", {})) == {"orders-service"}

    created = api("POST", "/api/v1/orders", token("alice"), json={"sku": "SKU-002", "quantity": 1})
    assert created.status_code == 201, created.text
    spans = wait_trace(api, created.headers["X-Request-ID"], token("alice"))["spans"]

    exchanges = [e for s in spans if s["service"] == "orders-service" for e in s["events"]
                 if e["type"] == "token_exchange"]
    assert {e["audience"] for e in exchanges if e.get("ok")} == {"inventory-service", "payments-service"}
    # inventario se invoca dos veces (reserva y confirmación) con el mismo token delegado
    assert any(e.get("cached") for e in exchanges if e["audience"] == "inventory-service")

    for service in ("inventory-service", "payments-service"):
        authn = [e for s in spans if s["service"] == service for e in s["events"]
                 if e["type"] == "authn" and e.get("ok")]
        assert authn and all(e["kind"] == "delegated" and e["aud"] == service and e["azp"] == "orders-service"
                             for e in authn), authn


def test_st52_sts_enforces_who_may_exchange(http, token):
    """ST-52: el STS solo permite el canje al cliente habilitado (orders-service). Ni
    inventory-service —aunque se conozca su secreto— ni el cliente público tfm-web
    pueden obtener un token de Pagos a partir del de alice."""
    exchange_grant = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                      "subject_token": token("alice"),
                      "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                      "audience": "payments-service"}
    attempts = [
        http.post(TOKEN_URL, data=exchange_grant,
                  auth=("inventory-service", os.environ["INVENTORY_CLIENT_SECRET"])),
        http.post(TOKEN_URL, data={**exchange_grant, "client_id": "tfm-web"}),
    ]
    for response in attempts:
        assert response.status_code == 400, response.text
        assert "token exchange is not enabled" in response.json()["error_description"].lower()
    assert exchange(token("alice"), "payments-service").status_code == 200


def test_st53_internal_hops_use_http2_over_mtls(api, token):
    """ST-53: todos los saltos internos (gateway -> Pedidos, Pedidos -> Inventario/Pagos)
    negocian HTTP/2 sobre TLS 1.3 y registran la identidad SPIFFE del llamante."""
    created = api("POST", "/api/v1/orders", token("alice"), json={"sku": "SKU-002", "quantity": 1})
    assert created.status_code == 201, created.text
    spans = wait_trace(api, created.headers["X-Request-ID"], token("alice"))["spans"]
    expected_peer = {"orders-service": "api-gateway", "inventory-service": "orders-service",
                     "payments-service": "orders-service"}
    for span in spans:
        transport = span["attrs"]["transport"]
        assert transport["protocol"] == "HTTP/2", span["name"]
        assert transport["tls"] == "TLSv1.3"
        assert transport["peer"] == f"spiffe://tfm.local/ns/poc/sa/{expected_peer[span['service']]}"
    calls = [e for s in spans for e in s["events"] if e["type"] == "call"]
    assert calls and all(e["protocol"] == "HTTP/2" for e in calls)
