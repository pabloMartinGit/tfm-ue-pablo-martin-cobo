"""MFA real con step-up: OTP en Keycloak y autorización basada en acr/amr.

El flujo interactivo del realm ("tfm browser step-up") tiene dos niveles (LoA):
nivel 1 = contraseña (acr=aal1, amr=[pwd]); nivel 2 = OTP (acr=aal2, amr=[pwd, otp]).
El segundo nivel solo se exige cuando el cliente lo pide (acr_values=aal2), y la
política exige esas señales para las acciones críticas. No queda ninguna señal
estática (el antiguo atributo mfa_verified desapareció del realm y de la política).
"""

from conftest import DEMO_PASSWORD, TOKEN_URL, claims_of, fresh_otp, interactive_tokens, new_session


def _grant(http, username, otp=None):
    data = {"grant_type": "password", "client_id": "tfm-web",
            "username": username, "password": DEMO_PASSWORD, "scope": "openid"}
    if otp is not None:
        data["otp"] = otp
        data["totp"] = otp
    return http.post(TOKEN_URL, data=data)


def test_st37_mfa_is_enforced_for_configured_users(http):
    """ST-37: erin tiene OTP obligatorio en Keycloak; sin OTP (o con OTP inválido) no
    obtiene token — MFA real, no un simple atributo."""
    assert _grant(http, "erin").status_code in (400, 401)
    assert _grant(http, "erin", otp="000000").status_code in (400, 401)
    assert _grant(http, "erin", otp=fresh_otp("erin")).status_code == 200
    assert "mfa_verified" not in claims_of(_grant(http, "alice").json()["access_token"])


def test_st38_step_up_emits_acr_and_amr():
    """ST-38: el login interactivo normal es de nivel 1 (acr=aal1, amr=[pwd]); al pedir
    step-up sobre la misma sesión SSO, Keycloak solo exige el OTP y el nuevo token
    acredita el segundo factor (acr=aal2, amr=[pwd, otp])."""
    session = new_session()
    normal, steps = interactive_tokens("erin", session=session)
    assert steps == ["password"]
    claims = claims_of(normal["access_token"])
    assert claims["acr"] == "aal1" and claims["amr"] == ["pwd"]

    stepped_up, steps = interactive_tokens("erin", acr="aal2", session=session)
    assert steps == ["otp"], steps  # la contraseña ya estaba acreditada (LoA 1 vigente)
    claims = claims_of(stepped_up["access_token"])
    assert claims["acr"] == "aal2"
    assert set(claims["amr"]) == {"pwd", "otp"}


def test_st39_purge_requires_step_up(api, token, stepup_token):
    """ST-39 (BFLA con step-up): el token del grant de contraseña de erin no acredita MFA
    (aunque Keycloak le exigió el OTP) y la purga se deniega; con step-up interactivo
    (acr=aal2) se permite. frank (admin sin OTP) no puede elevar: Keycloak le obliga a
    enrolar un segundo factor antes de emitir un token de nivel 2."""
    ropc = claims_of(token("erin"))
    assert ropc["acr"] == "aal1" and "otp" not in (ropc.get("amr") or [])
    denied = api("DELETE", "/api/v1/admin/purge", token("erin"))
    assert denied.status_code == 403
    assert "mfa_required" in denied.json()["detail"]["reasons"]

    assert api("DELETE", "/api/v1/admin/purge", stepup_token("erin")).status_code == 200

    tokens, steps = interactive_tokens("frank", acr="aal2")
    assert tokens is None and steps == ["password", "otp_enrollment"], steps
