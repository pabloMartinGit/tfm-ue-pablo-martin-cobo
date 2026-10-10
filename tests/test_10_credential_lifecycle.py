"""Ciclo de vida de las credenciales y abuso de los endpoints (O5): token expirado,
rotación de las claves de firma (JWKS), rate limiting en el borde y bloqueo por
fuerza bruta en el IdP.

Las pruebas de rotación y de fuerza bruta usan la API de administración de
Keycloak desde la red interna (mTLS) y crean y retiran sus propios recursos
temporales (una clave de firma y un usuario), de modo que no alteran el realm.
Las de rate limiting van al final: agotan el cupo de la IP de pruebas y esperan
a que se recupere antes de terminar.
"""

import concurrent.futures
import os
import secrets
import threading
import time

import pytest
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from conftest import (
    CA_BUNDLE,
    DEMO_PASSWORD,
    GATEWAY_URL,
    INTERNAL_CA,
    INVENTORY_URL,
    JWKS_URL,
    KEYCLOAK_URL,
    OWN_SVID,
    TOKEN_URL,
    _password_grant,
    b64url,
    b64url_json,
    claims_of,
    decode_segment,
    internal,
    wait_trace,
)

# Tolerancia de desfase de reloj del gateway (njs) y de los servicios (zt_security).
CLOCK_LEEWAY = 10


def _in_backend_network() -> bool:
    try:
        return os.path.exists(INTERNAL_CA) and internal(
            "GET", f"{KEYCLOAK_URL}/realms/tfm", cert=OWN_SVID, timeout=2).ok
    except (requests.RequestException, OSError):
        return False


IN_BACKEND = _in_backend_network()
backend_admin = pytest.mark.skipif(
    not (IN_BACKEND and os.getenv("KC_ADMIN_PASSWORD")),
    reason="Requiere la red interna y KC_ADMIN_PASSWORD (make test)")


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _kid(token: str) -> str:
    return decode_segment(token.split(".")[0])["kid"]


@pytest.fixture
def kc_admin() -> requests.Session:
    """Sesión de administración de Keycloak por la red interna (mTLS con el SVID propio)."""
    session = requests.Session()
    session.cert, session.verify = OWN_SVID, INTERNAL_CA
    response = session.post(f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token", timeout=10, data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": os.environ["KC_ADMIN_PASSWORD"]})
    assert response.status_code == 200, response.text
    session.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
    session.realm_url = f"{KEYCLOAK_URL}/admin/realms/tfm"
    return session


# -----------------------------------------------------------------------------
# Token expirado
# -----------------------------------------------------------------------------
def test_st54_expired_token_is_rejected_at_edge_and_services(api):
    """ST-54: un access token de vida corta (5 s, cliente de pruebas `tfm-short-lived`) es
    criptográficamente válido mientras no caduca: el borde lo deja pasar y es el PDP quien
    lo deniega, porque ese cliente no autoriza nada. Pasados exp + 10 s de tolerancia de
    reloj, el gateway lo rechaza con 401 `expired` y el servicio, invocado directamente,
    también: no confía solo en el borde."""
    response = requests.post(TOKEN_URL, verify=CA_BUNDLE, timeout=5, data={
        "grant_type": "password", "client_id": "tfm-short-lived",
        "username": "alice", "password": DEMO_PASSWORD})
    assert response.status_code == 200, response.text
    short = response.json()["access_token"]
    claims = claims_of(short)
    assert claims["exp"] - claims["iat"] == 5

    fresh = api("GET", "/api/v1/inventory", short)
    assert fresh.status_code == 403  # superó la validación del borde
    assert "not_a_user_token" in fresh.json()["detail"]["reasons"]
    direct = f"{INVENTORY_URL}/api/v1/inventory"
    if IN_BACKEND:
        assert internal("GET", direct, cert=OWN_SVID, headers=_bearer(short)).status_code == 403

    time.sleep(max(0.0, claims["exp"] + CLOCK_LEEWAY + 1.5 - time.time()))

    expired = api("GET", "/api/v1/inventory", short)
    assert expired.status_code == 401
    assert expired.json()["edge_reason"] == "expired"
    if IN_BACKEND:
        assert internal("GET", direct, cert=OWN_SVID, headers=_bearer(short)).status_code == 401


# -----------------------------------------------------------------------------
# Rotación de claves de firma (JWKS)
# -----------------------------------------------------------------------------
@backend_admin
def test_st55_signing_key_rotation_without_downtime(api, http, token, kc_admin):
    """ST-55 (rotación de claves): el IdP pasa a firmar con una clave RSA nueva. Los tokens
    con el kid nuevo se aceptan en el acto —el gateway recarga el JWKS al ver un kid
    desconocido y los servicios también, incluidos los tokens delegados— y los emitidos
    con la clave anterior siguen siendo válidos mientras esta se publique. Sin cortes."""
    old_token = token("alice")
    old_kid = _kid(old_token)
    realm_id = kc_admin.get(kc_admin.realm_url, timeout=10).json()["id"]
    created = kc_admin.post(f"{kc_admin.realm_url}/components", timeout=10, json={
        "name": f"rsa-rotated-{secrets.token_hex(3)}", "providerId": "rsa-generated",
        "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm_id,
        "config": {"priority": ["1000"], "keySize": ["2048"], "algorithm": ["RS256"],
                   "active": ["true"], "enabled": ["true"]}})
    assert created.status_code == 201, created.text
    component_id = created.headers["Location"].rsplit("/", 1)[-1]
    try:
        new_token = _password_grant(http, "alice")["access_token"]
        new_kid = _kid(new_token)
        assert new_kid != old_kid
        assert {old_kid, new_kid} <= {k["kid"] for k in http.get(JWKS_URL).json()["keys"]}

        first = api("GET", "/api/v1/inventory", new_token)
        assert first.status_code == 200, first.text
        spans = wait_trace(api, first.headers["X-Request-ID"], new_token)["spans"]
        edge = next(s for s in spans if s["attrs"].get("via") == "api-gateway")["attrs"]["edge"]
        assert edge["kid"] == new_kid and edge["jwks"] == "refreshed", edge

        # Pedidos, Inventario y Pagos validan tokens (de borde y delegados) con la clave nueva.
        order = api("POST", "/api/v1/orders", new_token, json={"sku": "SKU-002", "quantity": 1})
        assert order.status_code == 201, order.text
        assert api("GET", "/api/v1/inventory", old_token).status_code == 200
    finally:
        kc_admin.delete(f"{kc_admin.realm_url}/components/{component_id}", timeout=10)
    assert _kid(_password_grant(http, "alice")["access_token"]) == old_kid


def test_st56_foreign_signing_key_and_jku_are_rejected(api, token):
    """ST-56 (sustitución de clave): un token firmado con una clave del atacante, con un kid
    que el IdP no publica y una cabecera `jku` que apunta a su propio JWKS, se rechaza
    (401 unknown_kid). El borde solo confía en el JWKS de Keycloak, nunca sigue jku/x5u y
    limita las recargas forzadas por kid desconocido (no amplifica ataques contra el IdP)."""
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = claims_of(token("alice"))
    for _ in range(3):
        header = {"alg": "RS256", "typ": "JWT", "kid": f"attacker-{secrets.token_hex(4)}",
                  "jku": "https://attacker.example/.well-known/jwks.json"}
        signing_input = f"{b64url_json(header)}.{b64url_json(claims)}"
        signature = attacker_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        response = api("GET", "/api/v1/inventory", f"{signing_input}.{b64url(signature)}")
        assert response.status_code == 401
        assert response.json()["edge_reason"] == "unknown_kid"


# -----------------------------------------------------------------------------
# Bloqueo por fuerza bruta en el IdP
# -----------------------------------------------------------------------------
@backend_admin
def test_st57_brute_force_locks_the_account(kc_admin):
    """ST-57 (fuerza bruta contra una cuenta): tras `failureFactor` contraseñas erróneas
    Keycloak bloquea temporalmente la cuenta; la contraseña correcta deja de funcionar y la
    respuesta es idéntica a la de una contraseña errónea (no revela el bloqueo). Se ataca el
    IdP directamente, esquivando el límite del borde (ST-58): es una barrera independiente.
    Un administrador puede levantar el bloqueo."""
    username = f"bf-{secrets.token_hex(4)}"
    password = f"Bf-{secrets.token_hex(6)}-Aa1!"
    created = kc_admin.post(f"{kc_admin.realm_url}/users", timeout=10, json={
        "username": username, "enabled": True, "email": f"{username}@example.test",
        "emailVerified": True, "firstName": "Brute", "lastName": "Force",
        "credentials": [{"type": "password", "value": password, "temporary": False}]})
    assert created.status_code == 201, created.text
    user_id = created.headers["Location"].rsplit("/", 1)[-1]
    token_url = f"{KEYCLOAK_URL}/realms/tfm/protocol/openid-connect/token"

    def login(candidate: str) -> requests.Response:
        return internal("POST", token_url, cert=OWN_SVID, timeout=10, data={
            "grant_type": "password", "client_id": "tfm-web", "username": username, "password": candidate})

    status_url = f"{kc_admin.realm_url}/attack-detection/brute-force/users/{user_id}"

    def lockout_status() -> dict:
        deadline = time.time() + 5
        while not (status := kc_admin.get(status_url, timeout=10).json()).get("disabled") and time.time() < deadline:
            time.sleep(0.3)
        return status

    try:
        # Sin login correcto previo: un éxito pone a cero el contador de fallos y, si esa
        # puesta a cero se aplica tras el primer fallo, Keycloak lo pierde.
        failure_factor = kc_admin.get(kc_admin.realm_url, timeout=10).json()["failureFactor"]
        wrong = [login(f"Wrong-{secrets.token_hex(4)}") for _ in range(failure_factor)]
        assert all(r.status_code in (400, 401) for r in wrong)
        status = lockout_status()
        for _ in range(2):  # margen por si el IdP no contabilizó algún intento
            if status.get("disabled"):
                break
            wrong.append(login(f"Wrong-{secrets.token_hex(4)}"))
            status = lockout_status()
        assert status["disabled"] is True and status["numFailures"] >= failure_factor - 2, status

        locked = login(password)
        assert locked.status_code == wrong[-1].status_code
        assert locked.json() == wrong[-1].json()  # indistinguible de una contraseña errónea

        assert kc_admin.delete(status_url, timeout=10).status_code == 204
        assert login(password).status_code == 200
    finally:
        kc_admin.delete(f"{kc_admin.realm_url}/users/{user_id}", timeout=10)


# -----------------------------------------------------------------------------
# Rate limiting en el borde
# -----------------------------------------------------------------------------
def _burst(method: str, url: str, count: int, workers: int = 16, **kwargs) -> list[int]:
    """Lanza `count` peticiones concurrentes y devuelve sus códigos de estado."""
    local = threading.local()

    def one(_: int) -> int:
        if not hasattr(local, "session"):
            local.session = requests.Session()
            local.session.verify = CA_BUNDLE
        return local.session.request(method, url, timeout=10, **kwargs).status_code

    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        return list(pool.map(one, range(count)))


def test_st58_credential_endpoint_is_rate_limited():
    """ST-58 (fuerza bruta en el borde): una ráfaga contra el endpoint de credenciales supera
    el límite del gateway (10 r/s por IP, ráfaga de 20) y el exceso recibe 429 sin llegar a
    Keycloak; lo permitido sí llega al IdP (aquí 401 por un cliente inexistente)."""
    statuses = _burst("POST", TOKEN_URL, 60, data={
        "grant_type": "password", "client_id": "rate-limit-probe", "username": "x", "password": "y"})
    try:
        assert statuses.count(429) >= 20, statuses
        assert 0 < len([s for s in statuses if s in (400, 401)]), statuses
        assert set(statuses) <= {400, 401, 429}, statuses
    finally:
        time.sleep(3)  # el cupo (10 r/s) se recupera antes de las pruebas siguientes


def test_st59_api_is_rate_limited():
    """ST-59 (API4:2023, consumo de recursos sin límite): una ráfaga contra la API supera el
    límite del gateway (50 r/s por IP, ráfaga de 100); el exceso recibe 429 antes incluso
    de validar el token, de modo que no consume ni la validación JWT ni los servicios."""
    statuses = _burst("GET", f"{GATEWAY_URL}/api/v1/orders", 300, workers=32)
    try:
        assert statuses.count(429) >= 50, statuses
        assert statuses.count(401) >= 50, statuses  # lo permitido llega al PEP de borde (sin token)
        assert set(statuses) <= {401, 429}, statuses
    finally:
        time.sleep(3)
