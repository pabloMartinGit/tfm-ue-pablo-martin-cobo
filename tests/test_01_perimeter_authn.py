"""Autenticación perimetral en el API Gateway y ataques sobre JWT.

Cada prueba lleva un identificador ST-xx para referenciarla en el capítulo 8
(Pruebas y validación) de la memoria.
"""

import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from conftest import JWKS_URL, b64url, b64url_json, decode_segment


def _int(b64: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)), "big")


def test_st01_request_without_token_is_rejected(api):
    """ST-01: petición sin token -> 401 en el borde (no llega a la red interna)."""
    response = api("GET", "/api/v1/orders")
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate", "").startswith("Bearer")
    assert response.json()["edge_reason"] == "missing_token"


def test_st02_malformed_token_is_rejected(api):
    """ST-02: token con formato inválido -> 401."""
    for bad in ("not.a.jwt!", "abc"):
        response = api("GET", "/api/v1/orders", bad)
        assert response.status_code == 401
        assert response.json()["edge_reason"] == "malformed_token"


def test_st03_tampered_payload_is_rejected(api, token):
    """ST-03: escalada modificando claims (tenant/roles) sin re-firmar -> firma inválida -> 401."""
    header, payload, signature = token("alice").split(".")
    claims = decode_segment(payload)
    claims["tenant_id"] = "tenant-corp-beta"
    claims["realm_access"] = {"roles": ["admin"]}
    forged = f"{header}.{b64url_json(claims)}.{signature}"
    response = api("GET", "/api/v1/orders", forged)
    assert response.status_code == 401
    assert response.json()["edge_reason"] == "bad_signature"


def test_st04_alg_none_is_rejected(api, token):
    """ST-04: ataque 'alg: none' (token sin firma) -> 401."""
    claims = decode_segment(token("alice").split(".")[1])
    forged = f"{b64url_json({'alg': 'none', 'typ': 'JWT'})}.{b64url_json(claims)}."
    for candidate in (forged, forged.rstrip(".") + ".e30"):
        response = api("GET", "/api/v1/orders", candidate)
        assert response.status_code == 401
        assert response.json()["edge_reason"] == "alg_not_allowed:none"


def test_st05_key_confusion_hs256_is_rejected(api, http, token):
    """ST-05: confusión de claves RS256 -> HS256 firmando con la clave pública como secreto HMAC -> 401."""
    header = decode_segment(token("alice").split(".")[0])
    jwk = next(k for k in http.get(JWKS_URL).json()["keys"] if k["kid"] == header["kid"])
    public_pem = RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    claims = decode_segment(token("alice").split(".")[1])
    signing_input = f"{b64url_json({'alg': 'HS256', 'typ': 'JWT', 'kid': header['kid']})}.{b64url_json(claims)}"
    signature = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    response = api("GET", "/api/v1/orders", f"{signing_input}.{b64url(signature)}")
    assert response.status_code == 401
    assert response.json()["edge_reason"] == "alg_not_allowed:HS256"


def test_st06_id_token_cannot_be_used_as_access_token(api, tokens):
    """ST-06: un ID Token (audiencia = cliente, typ = ID) no autoriza llamadas a la API -> 401."""
    response = api("GET", "/api/v1/orders", tokens("alice")["id_token"])
    assert response.status_code == 401
    assert response.json()["edge_reason"] == "bad_audience"


def test_st07_service_account_token_is_not_a_user_identity(api, service_token):
    """ST-07: un token M2M (client_credentials) no sirve como identidad de usuario final.

    Supera la validación criptográfica del borde, pero el PDP no lo reconoce como
    usuario: el listado filtrado no devuelve datos y la creación se deniega (403).
    """
    response = api("GET", "/api/v1/orders", service_token)
    assert response.status_code == 200
    assert response.json()["count"] == 0
    response = api("POST", "/api/v1/orders", service_token, json={"sku": "SKU-001", "quantity": 1})
    assert response.status_code == 403
    assert "not_a_user_token" in response.json()["detail"]["reasons"]


def test_st08_valid_token_is_accepted(api, token):
    """ST-08: control positivo -> un access token legítimo es aceptado."""
    response = api("GET", "/api/v1/inventory", token("alice"))
    assert response.status_code == 200
    assert response.json()["tenant_id"] == "tenant-corp-alpha"
