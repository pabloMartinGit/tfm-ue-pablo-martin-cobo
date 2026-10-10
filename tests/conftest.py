"""Fixtures comunes de la batería de pruebas de seguridad IAM (objetivo O5)."""

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import socket
import struct
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost:8443")
GATEWAY_HTTP_URL = os.getenv("GATEWAY_HTTP_URL", "http://localhost:8080")
CA_BUNDLE = os.getenv("CA_BUNDLE", "certs/gateway.crt")
TOKEN_URL = f"{GATEWAY_URL}/auth/realms/tfm/protocol/openid-connect/token"
AUTH_URL = f"{GATEWAY_URL}/auth/realms/tfm/protocol/openid-connect/auth"
JWKS_URL = f"{GATEWAY_URL}/auth/realms/tfm/protocol/openid-connect/certs"
DEMO_PASSWORD = os.environ["TFM_DEMO_PASSWORD"]
LOGOUT_URL = f"{GATEWAY_URL}/auth/realms/tfm/protocol/openid-connect/logout"

# MFA: usuarios con OTP obligatorio y semilla TOTP compartida del PoC.
MFA_USERS = {"erin", "hector"}
MFA_SECRET = os.getenv("TFM_MFA_SECRET", "TfmMfaSharedSeed2026x")


# -----------------------------------------------------------------------------
# Origen público dentro del contenedor de pruebas
# -----------------------------------------------------------------------------
def _start_public_origin_forwarder(upstream: str) -> None:
    """Hace alcanzable https://localhost:8443 (issuer y redirect_uri del BFF) desde el
    contenedor de pruebas reenviando el puerto local al gateway. Así las redirecciones
    de Keycloak y del BFF funcionan igual que desde el navegador del anfitrión."""
    local_port = urlparse(GATEWAY_URL).port or 443
    host, _, port = upstream.rpartition(":")
    listener = socket.create_server(("127.0.0.1", local_port))

    def pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (src, dst):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def accept_loop() -> None:
        while True:
            client, _ = listener.accept()
            try:
                remote = socket.create_connection((host, int(port)), timeout=5)
                remote.settimeout(None)
            except OSError:
                client.close()
                continue
            threading.Thread(target=pipe, args=(client, remote), daemon=True).start()
            threading.Thread(target=pipe, args=(remote, client), daemon=True).start()

    threading.Thread(target=accept_loop, name="public-origin-forwarder", daemon=True).start()


if os.getenv("GATEWAY_UPSTREAM"):
    _start_public_origin_forwarder(os.environ["GATEWAY_UPSTREAM"])


# -----------------------------------------------------------------------------
# TOTP (2.º factor de erin y hector)
# -----------------------------------------------------------------------------
def totp_now(raw_secret: str = MFA_SECRET, when: float | None = None) -> str:
    """Código TOTP (RFC 6238, HMAC-SHA1, 6 dígitos, 30 s) a partir del secreto en claro."""
    counter = int((when if when is not None else time.time()) // 30)
    digest = hmac.new(raw_secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


# Keycloak rechaza reutilizar un código TOTP dentro de su ventana. Como erin y hector
# comparten la semilla, se garantiza una ventana nueva por usuario en cada login OTP.
_otp_used: dict[str, int] = {}


def fresh_otp(username: str) -> str:
    """Devuelve un código OTP de una ventana no usada aún por este usuario (esperando si hace falta)."""
    while True:
        window = int(time.time() // 30)
        if _otp_used.get(username) != window:
            _otp_used[username] = window
            return totp_now()
        time.sleep(31 - (time.time() % 30))


# -----------------------------------------------------------------------------
# Red interna: endpoints y SVID (solo desde el contenedor de pruebas)
# -----------------------------------------------------------------------------
# Solo alcanzables desde la red backend y únicamente por mTLS.
PAYMENTS_URL = os.getenv("PAYMENTS_URL", "https://payments-service:8443")
INVENTORY_URL = os.getenv("INVENTORY_URL", "https://inventory-service:8443")
TRACES_URL = os.getenv("TRACES_URL", "https://trace-service:8443")
ORDERS_URL = os.getenv("ORDERS_URL", "https://orders-service:8443")
OPA_URL = os.getenv("OPA_URL", "https://opa:8181")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "https://keycloak:8443/auth")

# SVID propio del contenedor de pruebas: identidad válida de la CA interna, pero
# sin ningún permiso (un contenedor ajeno dentro de la red).
SVID_DIR = os.getenv("SVID_DIR", "/run/svid")
# Copia del SVID de orders-service: simula que ese servicio ha sido comprometido.
COMPROMISED_SVID_DIR = os.getenv("COMPROMISED_SVID_DIR", "/run/svid-orders")
INTERNAL_CA = os.path.join(SVID_DIR, "bundle.pem")


def svid(directory: str) -> tuple[str, str]:
    return os.path.join(directory, "svid.pem"), os.path.join(directory, "svid.key")


OWN_SVID = svid(SVID_DIR)
ORDERS_SVID = svid(COMPROMISED_SVID_DIR)


def internal(method: str, url: str, cert: tuple[str, str] | None = ORDERS_SVID, **kwargs) -> requests.Response:
    """Llamada directa a un servicio interno por mTLS (por defecto, como orders-service comprometido)."""
    kwargs.setdefault("timeout", 5)
    return requests.request(method, url, cert=cert, verify=INTERNAL_CA, **kwargs)


def exchange(subject_token: str, audience: str) -> requests.Response:
    """Token Exchange (RFC 8693) con las credenciales de orders-service (secreto robado)."""
    return requests.post(TOKEN_URL, verify=CA_BUNDLE, timeout=5,
                         auth=("orders-service", os.environ["ORDERS_CLIENT_SECRET"]),
                         data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                               "subject_token": subject_token,
                               "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                               "audience": audience})


def delegated(subject_token: str, audience: str) -> str:
    response = exchange(subject_token, audience)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_json(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode())


def decode_segment(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def claims_of(token: str) -> dict:
    return decode_segment(token.split(".")[1])


@pytest.fixture(scope="session")
def http() -> requests.Session:
    session = requests.Session()
    session.verify = CA_BUNDLE
    return session


def _password_grant(http: requests.Session, username: str) -> dict:
    data = {
        "grant_type": "password",
        "client_id": "tfm-web",
        "username": username,
        "password": DEMO_PASSWORD,
        "scope": "openid",
    }
    attempts = 3 if username in MFA_USERS else 1
    for attempt in range(attempts):
        if username in MFA_USERS:
            # Segundo factor real: Keycloak exige el OTP. Ventana nueva por intento para
            # evitar el rechazo por reutilización y tolerar el borde de ventana de 30 s.
            code = fresh_otp(username)
            data["otp"] = data["totp"] = code
        response = http.post(TOKEN_URL, data=data)
        if response.status_code == 200 or attempt == attempts - 1:
            break
    assert response.status_code == 200, response.text
    return response.json()


def end_session(http: requests.Session, refresh_token: str) -> None:
    """RP-initiated logout: cierra la sesión en Keycloak (revoca los tokens)."""
    response = http.post(LOGOUT_URL, data={"client_id": "tfm-web", "refresh_token": refresh_token})
    assert response.status_code in (200, 204), response.text


def new_session() -> requests.Session:
    session = requests.Session()
    session.verify = CA_BUNDLE
    return session


# -----------------------------------------------------------------------------
# Flujo interactivo de Keycloak (lo que haría el navegador)
# -----------------------------------------------------------------------------
_FORM_ACTION_RE = re.compile(r'<form[^>]*\baction="([^"]*login-actions/[^"]*)"', re.IGNORECASE)


def _form_action(page_html: str) -> str:
    match = _FORM_ACTION_RE.search(page_html)
    assert match, "no se encontró el formulario de login de Keycloak"
    return html.unescape(match.group(1))


def keycloak_forms(session: requests.Session, response: requests.Response, username: str,
                   password: str = DEMO_PASSWORD, stop_at: str | None = None) -> tuple[requests.Response, list[str]]:
    """Completa los formularios que Keycloak presente (usuario/contraseña y OTP) hasta
    salir del IdP. Devuelve la respuesta final y los pasos realizados; con Keycloak
    pidiendo algo inesperado (p. ej. enrolar un OTP) se detiene y lo indica."""
    steps: list[str] = []
    for _ in range(4):
        page = response.text
        if response.status_code != 200 or not urlparse(response.url).path.startswith("/auth/"):
            break  # ya fuera del IdP (vuelta a la SPA/BFF) o error
        if 'name="password"' in page:
            steps.append("password")
            data = {"password": password}
            if 'name="username"' in page:
                data["username"] = username
            response = session.post(_form_action(page), data=data)
        elif 'name="otp"' in page and "totpSecret" not in page:
            steps.append("otp")
            response = session.post(_form_action(page), data={"otp": fresh_otp(username)})
        else:
            steps.append("otp_enrollment" if "totpSecret" in page else "unexpected_page")
            break
    return response, steps


def browser_login(session: requests.Session, username: str, acr: str | None = None) -> list[str]:
    """Flujo completo Authorization Code + PKCE a través del BFF (patrón navegador).

    Deja la sesión con la cookie __Host-tfm_session establecida. Con acr="aal2" pide
    step-up: si ya hay sesión SSO, Keycloak solo exige el OTP. Devuelve los pasos.
    """
    params = {"return_to": "/app/", **({"acr": acr} if acr else {})}
    started = session.get(f"{GATEWAY_URL}/bff/login", params=params)
    _, steps = keycloak_forms(session, started, username)
    return steps


def interactive_tokens(username: str, acr: str | None = None,
                       session: requests.Session | None = None) -> tuple[dict | None, list[str]]:
    """Authorization Code + PKCE con el cliente público tfm-web (sin BFF), opcionalmente
    con step-up (acr_values). Devuelve (tokens | None, pasos del login)."""
    session = session or new_session()
    verifier = secrets.token_urlsafe(48)
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    redirect_uri = f"{GATEWAY_URL}/app/"
    params = {"client_id": "tfm-web", "response_type": "code", "scope": "openid",
              "redirect_uri": redirect_uri, "state": secrets.token_urlsafe(8),
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if acr:
        params["acr_values"] = acr
    response = session.get(AUTH_URL, params=params)
    response, steps = keycloak_forms(session, response, username)
    # Keycloak redirige a la SPA con ?code=... (la respuesta final es la propia SPA).
    code = parse_qs(urlparse(response.url).query).get("code")
    if not code:
        return None, steps
    tokens = session.post(TOKEN_URL, data={"grant_type": "authorization_code", "client_id": "tfm-web",
                                           "code": code[0], "redirect_uri": redirect_uri,
                                           "code_verifier": verifier})
    assert tokens.status_code == 200, tokens.text
    return tokens.json(), steps


@pytest.fixture(scope="session")
def tokens(http):
    """Tokens (access + id) por usuario del realm, obtenidos una sola vez por sesión."""
    cache: dict[str, dict] = {}

    def get(username: str) -> dict:
        if username not in cache:
            cache[username] = _password_grant(http, username)
        return cache[username]

    return get


@pytest.fixture(scope="session")
def token(tokens):
    return lambda username: tokens(username)["access_token"]


@pytest.fixture(scope="session")
def stepup_token():
    """Access token con step-up (acr=aal2) del flujo interactivo, uno por usuario."""
    cache: dict[str, str] = {}

    def get(username: str) -> str:
        if username not in cache:
            tokens, steps = interactive_tokens(username, acr="aal2")
            assert tokens, f"{username} no completó el step-up: {steps}"
            cache[username] = tokens["access_token"]
        return cache[username]

    return get


@pytest.fixture(scope="session")
def api(http):
    """Cliente del gateway: api(method, path, token=None, **kwargs)."""

    def call(method: str, path: str, token: str | None = None, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return http.request(method, f"{GATEWAY_URL}{path}", headers=headers, **kwargs)

    return call


@pytest.fixture(scope="session")
def service_token(http) -> str:
    """Token M2M legítimo del servicio de pedidos (client_credentials)."""
    response = http.post(TOKEN_URL, data={"grant_type": "client_credentials"},
                         auth=("orders-service", os.environ["ORDERS_CLIENT_SECRET"]))
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
def alice_order(api, token) -> dict:
    response = api("POST", "/api/v1/orders", token("alice"), json={"sku": "SKU-002", "quantity": 1})
    assert response.status_code == 201, response.text
    return response.json()


def stock(api, token: str, sku: str) -> int:
    return api("GET", "/api/v1/inventory", token).json()["items"][sku]["stock"]


def trace_complete(spans: list[dict]) -> bool:
    """Traza completa: está el span raíz (llegado por el gateway) y cada llamada saliente
    que obtuvo respuesta tiene ya el span del servicio destino. Cada servicio exporta sus
    spans por su cuenta, así que el raíz puede llegar antes que los de sus destinos."""
    if not any(s["attrs"].get("via") == "api-gateway" for s in spans):
        return False
    calls = {e["span_id"] for s in spans for e in s["events"]
             if e["type"] == "call" and e.get("status") is not None}
    return calls <= {s["parent_id"] for s in spans}


def wait_trace(api, trace_id: str, token: str, timeout: float = 8.0) -> dict:
    """Espera a que el colector tenga la traza completa."""
    deadline = time.time() + timeout
    while True:
        response = api("GET", f"/api/v1/traces/{trace_id}", token)
        if response.status_code == 200 and trace_complete(response.json()["spans"]):
            return response.json()
        if response.status_code not in (200, 404) or time.time() > deadline:
            raise AssertionError(f"traza {trace_id} no disponible: {response.status_code} {response.text}")
        time.sleep(0.2)
