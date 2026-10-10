"""Validación de identidades (usuario y servicio) en cada microservicio.

Zero Trust: aunque el API Gateway ya valida el token en el perímetro, cada
servicio vuelve a verificar firma, emisor, audiencia y vigencia, porque la red
interna no se considera confiable (un atacante con acceso a la red interna
podría invocar el servicio directamente).

Cada petición combina dos identidades independientes:
- la del **usuario**, en el JWT (Authorization: Bearer), y
- la de la **carga de trabajo llamante**, que no viaja en ninguna cabecera: la
  aporta el handshake mTLS (SPIFFE ID del certificado del cliente). Así no hay
  cabeceras de identidad que un atacante pueda falsificar o reutilizar.

Tipos de token según el endpoint:
- ``require_user``      token de usuario de borde (aud = API de borde), llega vía gateway.
- ``require_delegated`` token delegado por Token Exchange (RFC 8693): aud = este
                        servicio y azp = el servicio que lo obtuvo en nombre del usuario.
- ``require_service``   token M2M (client_credentials) del propio servicio llamante.
"""

import uuid
from dataclasses import dataclass, field
from threading import Lock

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from workload_identity import client_ssl_context, peer_identity

from .audit import audit_log
from .config import settings

REQUEST_ID_HEADER = "X-Request-ID"

_bearer = HTTPBearer(auto_error=False)
_jwks_client: jwt.PyJWKClient | None = None
_jwks_lock = Lock()


@dataclass(frozen=True)
class SecurityContext:
    token: str
    claims: dict
    # Servicio del extremo mTLS (SPIFFE ID verificado en el handshake), no una cabecera.
    caller_service: str | None
    request_id: str
    span: object | None = None
    peer_id: str | None = None
    # Tokens delegados obtenidos durante la petición (audiencia -> token).
    delegations: dict = field(default_factory=dict, compare=False, repr=False)

    @property
    def subject(self) -> str:
        return self.claims["sub"]

    @property
    def tenant_id(self) -> str | None:
        return self.claims.get("tenant_id")


def _jwks() -> jwt.PyJWKClient:
    global _jwks_client
    with _jwks_lock:
        if _jwks_client is None:
            # El JWKS se descarga de Keycloak por mTLS (el IdP exige certificado de cliente).
            # Sin enfriamiento entre recargas: por defecto PyJWT no vuelve a descargar el
            # JWKS durante 30 s tras cualquier descarga, así que una clave recién rotada
            # se rechazaría. Aquí no hay riesgo de amplificación: los kid desconocidos
            # los filtra el gateway (con su propio enfriamiento) y sin SVID no se llega.
            _jwks_client = jwt.PyJWKClient(
                settings.jwks_url, cache_jwk_set=True, lifespan=300, timeout=settings.http_timeout,
                ssl_context=client_ssl_context(), cooldown_duration=0,
            )
        return _jwks_client


def _unauthorized(reason: str, request_id: str, span=None, kind: str = "user") -> HTTPException:
    audit_log("authn_failure", reason=reason, token_kind=kind, request_id=request_id)
    if span is not None:
        span.event("authn", kind=kind, ok=False, reason=reason.split(":")[0])
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "unauthorized", "request_id": request_id},
        headers={"WWW-Authenticate": 'Bearer realm="tfm"'},
    )


def verify_token(raw_token: str, request_id: str, span=None, kind: str = "user",
                 audience: str | None = None) -> dict:
    """Verifica un access token emitido por Keycloak y devuelve sus claims."""
    try:
        signing_key = _jwks().get_signing_key_from_jwt(raw_token)
    except jwt.PyJWKClientConnectionError as exc:
        audit_log("jwks_unavailable", error=str(exc), request_id=request_id)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {"error": "idp_unavailable"}) from exc
    except jwt.PyJWTError as exc:
        raise _unauthorized(f"signing_key: {exc}", request_id, span, kind) from exc

    try:
        # La lista blanca de algoritmos neutraliza "alg: none" y la confusión RS256/HS256.
        claims = jwt.decode(
            raw_token,
            signing_key.key,
            algorithms=list(settings.allowed_algorithms),
            audience=audience or settings.audience,
            issuer=settings.issuer,
            leeway=10,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise _unauthorized(f"invalid_token: {exc}", request_id, span, kind) from exc

    # Keycloak marca los access tokens con typ=Bearer; un ID token (typ=ID) no autoriza APIs.
    if claims.get("typ") != "Bearer":
        raise _unauthorized("not_an_access_token", request_id, span, kind)
    return claims


def _request_context(request: Request) -> tuple[str, object | None, dict | None]:
    span = getattr(request.state, "span", None)
    request_id = span.trace_id if span is not None else (
        request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex)
    return request_id, span, peer_identity(request.scope)


def _context(request: Request, credentials: HTTPAuthorizationCredentials | None,
             kind: str, audience: str | None) -> SecurityContext:
    request_id, span, peer = _request_context(request)
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized("missing_bearer_token", request_id, span, kind)
    claims = verify_token(credentials.credentials, request_id, span, kind, audience)
    if span is not None:
        span.event("authn", kind=kind, ok=True, sub=claims.get("sub"),
                   username=claims.get("preferred_username"), tenant_id=claims.get("tenant_id"),
                   azp=claims.get("azp"), aud=claims.get("aud"))
    return SecurityContext(
        token=credentials.credentials,
        claims=claims,
        caller_service=peer["service"] if peer else None,
        request_id=request_id,
        span=span,
        peer_id=peer["spiffe_id"] if peer else None,
    )


def require_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> SecurityContext:
    """Endpoints de borde: token de usuario cuya audiencia es la API publicada en el gateway."""
    return _context(request, credentials, "user", settings.audience)


def require_delegated(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> SecurityContext:
    """Endpoints internos: solo tokens intercambiados cuya audiencia es ESTE servicio.

    Un token de usuario de borde (Token Relay) o uno intercambiado para otro
    servicio se rechaza con 401 por audiencia: un token capturado en un salto no
    sirve en otro (Tabla 8, aislamiento de privilegios).
    """
    if not settings.client_id:
        raise RuntimeError("require_delegated exige SERVICE_CLIENT_ID (audiencia propia)")
    return _context(request, credentials, "delegated", settings.client_id)


def require_service(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> SecurityContext:
    """Endpoints exclusivamente M2M: el sujeto es la cuenta de servicio llamante."""
    return _context(request, credentials, "service", settings.audience)
