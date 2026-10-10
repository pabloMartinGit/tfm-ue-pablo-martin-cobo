"""BFF / Token Handler (Authorization Code + PKCE, cookie de sesión) y revocación
en tiempo real por introspección RFC 7662."""

from conftest import GATEWAY_URL, _password_grant, browser_login, end_session, new_session


# -----------------------------------------------------------------------------
# Revocación (RFC 7662): la introspección corta un token no expirado pero revocado
# -----------------------------------------------------------------------------
def test_st40_logout_revokes_token_at_payments(api, http):
    """ST-40: tras el logout, el mismo access token (aún dentro de su ventana de
    validez) es rechazado en la operación crítica gracias a la introspección."""
    session = _password_grant(http, "alice")  # login dedicado (no contamina el caché)
    access, refresh = session["access_token"], session["refresh_token"]

    ok = api("POST", "/api/v1/orders", access, json={"sku": "SKU-002", "quantity": 1})
    assert ok.status_code == 201, ok.text

    end_session(http, refresh)

    revoked = api("POST", "/api/v1/orders", access, json={"sku": "SKU-002", "quantity": 1})
    assert revoked.status_code == 401, revoked.text
    assert revoked.json()["detail"]["error"] == "token_revoked"


# -----------------------------------------------------------------------------
# BFF / Token Handler
# -----------------------------------------------------------------------------
def test_st41_bff_login_starts_authorization_code_pkce():
    """ST-41: /bff/login inicia el flujo con PKCE (S256) y fija una cookie de login
    endurecida; el navegador no recibe ningún token todavía."""
    session = new_session()
    resp = session.get(f"{GATEWAY_URL}/bff/login", params={"return_to": "/app/"}, allow_redirects=False)
    assert resp.status_code == 303
    location = resp.headers["Location"]
    assert "/auth/realms/tfm/protocol/openid-connect/auth" in location
    assert "client_id=tfm-bff" in location
    assert "code_challenge_method=S256" in location
    assert "code_challenge=" in location
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "tfm_login=" in set_cookie and "HttpOnly" in set_cookie and "Secure" in set_cookie


def test_st42_bff_token_endpoint_is_not_public():
    """ST-42: el endpoint interno cookie->token no está publicado en el gateway."""
    assert new_session().get(f"{GATEWAY_URL}/bff/token").status_code == 404


def test_st43_bff_session_authorizes_api_via_cookie_only():
    """ST-43: tras el login, el navegador solo tiene la cookie de sesión (ningún
    token en JS) y con ella autoriza la API; el borde traduce cookie -> Bearer."""
    session = new_session()
    browser_login(session, "alice")

    info = session.get(f"{GATEWAY_URL}/bff/userinfo")
    assert info.status_code == 200 and info.json()["authenticated"] is True
    assert info.json()["username"] == "alice"

    # La cookie de sesión es HttpOnly y con prefijo __Host- (o tfm_session sin TLS).
    session_cookies = [c for c in session.cookies if c.name.endswith("tfm_session")]
    assert session_cookies, "no se estableció la cookie de sesión"

    # Sin cabecera Authorization: la cookie basta (cookie -> token en el borde).
    assert session.get(f"{GATEWAY_URL}/api/v1/inventory").status_code == 200
    order = session.post(f"{GATEWAY_URL}/api/v1/orders", json={"sku": "SKU-002", "quantity": 1})
    assert order.status_code == 201, order.text


def test_st44_bff_logout_ends_session():
    """ST-44: el logout del BFF revoca la sesión; la cookie deja de autorizar."""
    session = new_session()
    browser_login(session, "alice")
    assert session.get(f"{GATEWAY_URL}/api/v1/inventory").status_code == 200

    assert session.post(f"{GATEWAY_URL}/bff/logout").status_code == 200
    assert session.get(f"{GATEWAY_URL}/bff/userinfo").status_code == 401
    assert session.get(f"{GATEWAY_URL}/api/v1/inventory").status_code == 401


def test_st45_bff_step_up_on_demand():
    """ST-45 (step-up en el BFF): erin entra por el BFF solo con contraseña (aal1) y la
    purga se deniega por falta de MFA. Al elevar la sesión (/bff/login?acr=aal2),
    Keycloak solo pide el OTP, el BFF sustituye la sesión por una de nivel aal2 y la
    misma cookie ya autoriza la purga. El token nunca pasa por el navegador."""
    session = new_session()
    assert browser_login(session, "erin") == ["password"]
    info = session.get(f"{GATEWAY_URL}/bff/userinfo").json()
    assert info["acr"] == "aal1" and info["amr"] == ["pwd"]
    old_cookie = session.cookies.get("__Host-tfm_session")

    denied = session.delete(f"{GATEWAY_URL}/api/v1/admin/purge")
    assert denied.status_code == 403
    assert "mfa_required" in denied.json()["detail"]["reasons"]

    assert browser_login(session, "erin", acr="aal2") == ["otp"]
    info = session.get(f"{GATEWAY_URL}/bff/userinfo").json()
    assert info["acr"] == "aal2" and set(info["amr"]) == {"pwd", "otp"}
    assert session.cookies.get("__Host-tfm_session") != old_cookie  # sesión renovada
    assert session.delete(f"{GATEWAY_URL}/api/v1/admin/purge").status_code == 200
