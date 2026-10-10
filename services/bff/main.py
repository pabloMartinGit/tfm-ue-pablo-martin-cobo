"""BFF / Token Handler (patrón de la memoria 7.1.2.1).

Realiza el flujo OAuth 2.0 Authorization Code + PKCE contra Keycloak y guarda los
tokens SOLO en el servidor. El navegador nunca ve el access token ni el refresh
token: únicamente recibe una cookie de sesión opaca `__Host-tfm_session` con los
atributos `HttpOnly`, `Secure`, `SameSite=Strict` y `Path=/`. Esto neutraliza la
exfiltración de tokens por XSS (no hay token en JS) y, con SameSite=Strict, el
CSRF (todo el ecosistema es del mismo origen tras el gateway).

Endpoints públicos (vía gateway, prefijo /bff/):
  GET  /bff/login       inicia el flujo (PKCE) y redirige a Keycloak. Con
                        ?acr=aal2 pide *step-up*: Keycloak solo exige el OTP si ya
                        hay sesión SSO y emite un token con acr=aal2 / amr=[pwd,otp].
  GET  /bff/callback    canjea el código por tokens y crea la sesión (cookie).
  GET  /bff/userinfo    claims seguros de la sesión (nunca el token).
  POST /bff/logout      revoca la sesión en Keycloak (RFC 7009) y borra la cookie.

Endpoint interno (solo backend-net, no publicado en el gateway):
  GET  /bff/token       devuelve un access token válido (refrescándolo) a partir
                        de la cookie de sesión. Lo consume el njs del gateway para
                        traducir cookie -> Authorization: Bearer (el navegador no
                        maneja el token).

Transporte: el BFF solo acepta conexiones mTLS (del gateway) y habla con Keycloak
por mTLS con su propio SVID (workload_identity).
"""

import base64
import hashlib
import json
import os
import secrets
import time
from threading import Lock
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import Cookie, FastAPI, Query, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

from workload_identity import client_ssl_context, http_client

# --- Configuración ----------------------------------------------------------
ISSUER = os.environ["OIDC_ISSUER"]  # público, cara al navegador (redirecciones)
AUTH_URL = os.getenv("OIDC_AUTH_URL") or f"{ISSUER}/protocol/openid-connect/auth"
LOGOUT_URL = os.getenv("OIDC_LOGOUT_URL") or f"{ISSUER}/protocol/openid-connect/logout"
# back-channel (BFF -> Keycloak por la red interna)
TOKEN_URL = os.environ["OIDC_TOKEN_URL"]
REVOKE_URL = os.getenv("OIDC_REVOKE_URL") or TOKEN_URL.replace("/token", "/revoke")
JWKS_URL = os.environ["OIDC_JWKS_URL"]
CLIENT_ID = os.environ["BFF_CLIENT_ID"]
CLIENT_SECRET = os.environ["BFF_CLIENT_SECRET"]
REDIRECT_URI = os.environ["BFF_REDIRECT_URI"]
BASE_PATH = os.getenv("BFF_BASE_PATH", "/bff")
APP_HOME = os.getenv("BFF_APP_HOME", "/app/")
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "3"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"
SESSION_COOKIE = "__Host-tfm_session" if COOKIE_SECURE else "tfm_session"
LOGIN_COOKIE = "__Host-tfm_login" if COOKIE_SECURE else "tfm_login"
LOGIN_TTL = 300
REFRESH_SKEW = 20  # renovar el access token si le quedan < 20 s
# Niveles de autenticación que la SPA puede pedir (acr.loa.map del realm).
ACR_VALUES = {"aal1", "aal2"}

app = FastAPI(title="BFF / Token Handler", version="0.1.0")

_jwks = jwt.PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=300, timeout=HTTP_TIMEOUT,
                        ssl_context=client_ssl_context(), cooldown_duration=0)
_pending: dict[str, dict] = {}   # login_id -> {verifier, state, nonce, return_to, created}
_sessions: dict[str, dict] = {}  # session_id -> {tokens, claims, access_exp, ...}
_lock = Lock()


# --- Utilidades -------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _safe_return_to(value: str | None) -> str:
    # Evita open redirect: solo rutas locales absolutas (no "//host").
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return APP_HOME


def _set_cookie(resp: Response, name: str, value: str, max_age: int, samesite: str = "strict") -> None:
    resp.set_cookie(
        key=name, value=value, max_age=max_age, path="/",
        httponly=True, secure=COOKIE_SECURE, samesite=samesite,
    )


def _clear_cookie(resp: Response, name: str) -> None:
    resp.delete_cookie(key=name, path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")


def _gc() -> None:
    now = time.time()
    for lid in [k for k, v in _pending.items() if now - v["created"] > LOGIN_TTL]:
        _pending.pop(lid, None)


@app.get("/health", include_in_schema=False)
def health() -> dict:
    return {"status": "ok", "service": "bff"}


# --- 1. Inicio del flujo (PKCE) --------------------------------------------
@app.get(f"{BASE_PATH}/login")
def login(return_to: str = Query(default=None), acr: str = Query(default=None)) -> Response:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    state = _b64url(secrets.token_bytes(16))
    nonce = _b64url(secrets.token_bytes(16))
    login_id = _b64url(secrets.token_bytes(16))
    with _lock:
        _gc()
        _pending[login_id] = {
            "verifier": verifier, "state": state, "nonce": nonce,
            "return_to": _safe_return_to(return_to), "created": time.time(),
            "acr": acr if acr in ACR_VALUES else None,
        }
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if acr in ACR_VALUES:
        # Step-up (OIDC acr_values): con sesión SSO previa, Keycloak solo ejecuta los
        # pasos del nivel que falta (el OTP del nivel 2, flujo "tfm browser step-up").
        params["acr_values"] = acr
    resp = RedirectResponse(f"{AUTH_URL}?{urlencode(params)}", status_code=status.HTTP_303_SEE_OTHER)
    # SameSite=Lax en la cookie temporal: el retorno desde la página de login de
    # Keycloak es una navegación de nivel superior (aunque aquí sea el mismo origen).
    _set_cookie(resp, LOGIN_COOKIE, login_id, LOGIN_TTL, samesite="lax")
    return resp


# --- 2. Callback: canje del código y creación de la sesión ------------------
@app.get(f"{BASE_PATH}/callback")
def callback(
    request: Request,
    code: str = Query(default=None),
    state: str = Query(default=None),
    error: str = Query(default=None),
) -> Response:
    login_id = request.cookies.get(LOGIN_COOKIE)
    with _lock:
        pending = _pending.pop(login_id, None) if login_id else None
    if error:
        return _fail("authorization_error", detail=error)
    if not pending or not code or not state or not secrets.compare_digest(state, pending["state"]):
        return _fail("invalid_login_state")

    try:
        token_resp = http_client().post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": pending["verifier"],
            },
            auth=(CLIENT_ID, CLIENT_SECRET),
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except httpx.HTTPError as exc:
        return _fail("token_exchange_failed", detail=str(exc))

    try:
        id_claims = _verify_id_token(tokens["id_token"], pending["nonce"])
    except (jwt.PyJWTError, KeyError) as exc:
        return _fail("invalid_id_token", detail=str(exc))
    if pending["acr"] and id_claims.get("acr") != pending["acr"]:
        # Se pidió step-up y el IdP no lo acreditó: no se degrada la sesión en silencio.
        return _fail("step_up_failed", detail=str(id_claims.get("acr")))

    session_id = _b64url(secrets.token_bytes(32))
    previous = request.cookies.get(SESSION_COOKIE)
    with _lock:
        # Step-up o cambio de usuario: la sesión anterior se sustituye (nuevo id de
        # sesión, que además evita la fijación de sesión).
        if previous:
            _sessions.pop(previous, None)
        _sessions[session_id] = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "access_exp": time.time() + int(tokens.get("expires_in", 60)),
            "claims": _access_claims(tokens["access_token"]),
            "id_claims": id_claims,
            "created": time.time(),
        }
    resp = RedirectResponse(pending["return_to"], status_code=status.HTTP_303_SEE_OTHER)
    # Cookie de sesión del navegador (sin Max-Age): se borra al cerrar el navegador;
    # la sesión del lado servidor y del SSO acota su validez real.
    resp.set_cookie(SESSION_COOKIE, session_id, path="/", httponly=True,
                    secure=COOKIE_SECURE, samesite="strict")
    _clear_cookie(resp, LOGIN_COOKIE)
    return resp


def _fail(reason: str, detail: str = "") -> Response:
    # Redirige a la app con un parámetro de error (sin exponer detalles sensibles).
    resp = RedirectResponse(f"{APP_HOME}?bff_error={reason}", status_code=status.HTTP_303_SEE_OTHER)
    _clear_cookie(resp, LOGIN_COOKIE)
    return resp


def _verify_id_token(id_token: str, nonce: str) -> dict:
    key = _jwks.get_signing_key_from_jwt(id_token).key
    claims = jwt.decode(
        id_token, key, algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    if claims.get("nonce") != nonce:
        raise jwt.InvalidTokenError("nonce_mismatch")
    return claims


def _access_claims(access_token: str) -> dict:
    # Decodifica sin verificar firma (ya validada por Keycloak al emitirlo): solo
    # para exponer atributos seguros a la SPA vía /bff/userinfo.
    payload = access_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# --- 3. userinfo (claims seguros, nunca el token) ---------------------------
def _session(session_id: str | None) -> dict | None:
    if not session_id:
        return None
    with _lock:
        return _sessions.get(session_id)


@app.get(f"{BASE_PATH}/userinfo")
def userinfo(session: str = Cookie(default=None, alias=SESSION_COOKIE)) -> Response:
    sess = _session(session)
    if sess is None:
        return JSONResponse({"authenticated": False}, status_code=status.HTTP_401_UNAUTHORIZED)
    c = sess["claims"]
    realm_roles = [r for r in c.get("realm_access", {}).get("roles", [])
                   if not r.startswith("default-roles") and r not in ("offline_access", "uma_authorization")]
    return JSONResponse({
        "authenticated": True,
        "flow": "bff",
        "username": c.get("preferred_username"),
        "sub": c.get("sub"),
        "tenant_id": c.get("tenant_id"),
        "department": c.get("department"),
        "clearance_level": c.get("clearance_level"),
        "max_transaction_limit": c.get("max_transaction_limit"),
        "acr": c.get("acr"),
        "amr": c.get("amr"),
        "realm_roles": realm_roles,
        "resource_access": c.get("resource_access", {}),
        "access_exp": int(sess["access_exp"]),
    })


# --- 4. logout: revocación en Keycloak (RFC 7009) + borrado de sesión -------
@app.post(f"{BASE_PATH}/logout")
def logout(session: str = Cookie(default=None, alias=SESSION_COOKIE)) -> Response:
    with _lock:
        sess = _sessions.pop(session, None) if session else None
    if sess and sess.get("refresh_token"):
        try:
            # Revocar el refresh token cierra la sesión: la introspección del access
            # token pasa a devolver active:false (revocación inmediata, memoria 4.2.2.3).
            http_client().post(REVOKE_URL,
                               data={"token": sess["refresh_token"], "token_type_hint": "refresh_token"},
                               auth=(CLIENT_ID, CLIENT_SECRET))
        except httpx.HTTPError:
            pass
    resp = JSONResponse({"logged_out": True, "logout_url": f"{LOGOUT_URL}?client_id={CLIENT_ID}"})
    _clear_cookie(resp, SESSION_COOKIE)
    return resp


# --- 5. Endpoint interno: cookie -> access token (lo usa el njs del gateway) -
@app.get(f"{BASE_PATH}/token")
def resolve_token(session: str = Cookie(default=None, alias=SESSION_COOKIE)) -> Response:
    sess = _session(session)
    if sess is None:
        return PlainTextResponse("no_session", status_code=status.HTTP_401_UNAUTHORIZED)
    if sess["access_exp"] - time.time() < REFRESH_SKEW:
        if not _refresh(session, sess):
            return PlainTextResponse("refresh_failed", status_code=status.HTTP_401_UNAUTHORIZED)
        sess = _session(session)
    return PlainTextResponse(sess["access_token"])


def _refresh(session_id: str, sess: dict) -> bool:
    refresh_token = sess.get("refresh_token")
    if not refresh_token:
        return False
    try:
        resp = http_client().post(TOKEN_URL,
                                  data={"grant_type": "refresh_token", "refresh_token": refresh_token},
                                  auth=(CLIENT_ID, CLIENT_SECRET))
        if resp.status_code != 200:
            # refresh revocado/expirado -> sesión inservible
            with _lock:
                _sessions.pop(session_id, None)
            return False
        tokens = resp.json()
    except httpx.HTTPError:
        return False
    with _lock:
        current = _sessions.get(session_id)
        if current is None:
            return False
        current["access_token"] = tokens["access_token"]
        current["refresh_token"] = tokens.get("refresh_token", refresh_token)
        current["access_exp"] = time.time() + int(tokens.get("expires_in", 60))
        current["claims"] = _access_claims(tokens["access_token"])
    return True
