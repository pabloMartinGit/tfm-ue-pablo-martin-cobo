"""Cliente del PDP (Open Policy Agent). El microservicio actúa como PEP."""

import time
from datetime import datetime, timezone

import httpx
from fastapi import HTTPException, status

from workload_identity import http_client

from .audit import audit_log
from .auth import SecurityContext
from .config import settings


def evaluate(
    ctx: SecurityContext, action: str, resource: dict, action_attrs: dict | None = None
) -> tuple[bool, list[str]]:
    """Consulta el PDP y registra la decisión. Fail-closed: si OPA no responde se deniega (503)."""
    opa_input = {
        "jwt_claims": ctx.claims,
        "resource": {"service": settings.service_name, **resource},
        "action": {"name": action, **(action_attrs or {})},
        "environment": {
            "time": datetime.now(timezone.utc).isoformat(),
            # Identidad de la carga de trabajo llamante, verificada por mTLS (SPIFFE).
            "caller_service": ctx.caller_service,
            "peer_id": ctx.peer_id,
            "request_id": ctx.request_id,
        },
    }
    started = time.perf_counter()
    try:
        # OPA solo atiende por mTLS a los PEP (--authentication=tls, opa/system/system.rego).
        response = http_client().post(settings.opa_decision_url, json={"input": opa_input})
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        audit_log("pdp_unavailable", action=action, error=str(exc), request_id=ctx.request_id)
        if ctx.span is not None:
            ctx.span.event("pdp", action=action, decision="error", reasons=["pdp_unavailable"])
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {"error": "pdp_unavailable"}) from exc
    elapsed = round((time.perf_counter() - started) * 1000, 2)

    decision = body.get("result") or {}
    allowed = decision.get("allow") is True
    reasons = decision.get("reasons", [])
    audit_log(
        "authz_decision",
        decision="allow" if allowed else "deny",
        action=action,
        sub=ctx.claims.get("sub"),
        tenant_id=ctx.tenant_id,
        caller_service=ctx.caller_service,
        resource=resource,
        reasons=reasons,
        request_id=ctx.request_id,
        decision_id=body.get("decision_id"),
    )
    if ctx.span is not None:
        ctx.span.event("pdp", action=action, decision="allow" if allowed else "deny",
                       reasons=reasons, ms=elapsed, decision_id=body.get("decision_id"),
                       resource={k: v for k, v in resource.items() if k in ("type", "id", "owner_id", "tenant_id")},
                       attrs=action_attrs or {})
    return allowed, reasons


def authorize(ctx: SecurityContext, action: str, resource: dict, action_attrs: dict | None = None) -> None:
    """Aplica la decisión del PDP: lanza 403 si deniega."""
    allowed, reasons = evaluate(ctx, action, resource, action_attrs)
    if allowed:
        return
    detail = {"error": "forbidden", "request_id": ctx.request_id}
    # Solo en el PoC: exponer los motivos facilita las pruebas; en producción se omiten.
    if settings.expose_deny_reasons:
        detail["reasons"] = reasons
    raise HTTPException(status.HTTP_403_FORBIDDEN, detail)
