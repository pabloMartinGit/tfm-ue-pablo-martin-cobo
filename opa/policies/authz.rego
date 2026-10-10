# =============================================================================
# PDP (Policy Decision Point) - Política de autorización del PoC Zero Trust
# -----------------------------------------------------------------------------
# Punto de consulta:  POST /v1/data/tfm/authz/decision
#
# Contrato de entrada (vector ABAC, memoria 7.1.3.3: Decisión = f(S, R, A, E)):
#   input.jwt_claims  -> Sujeto (S): claims del access token ya verificado por el PEP
#   input.resource    -> Recurso (R): service, type, owner_id, tenant_id, ...
#   input.action      -> Acción (A): name ("orders:create", ...), amount, method, path
#   input.environment -> Entorno (E): time, request_id y caller_service/peer_id:
#                        identidad de la carga de trabajo llamante verificada por
#                        mTLS (SPIFFE ID del certificado cliente), nunca una cabecera
#
# Salida: {"allow": bool, "reasons": [motivos de denegación]}
#
# Principio "Denegación por defecto": toda acción no contemplada explícitamente
# se deniega. Los motivos (reasons) son solo explicativos para auditoría; la
# decisión se basa exclusivamente en reglas "allow" explícitas.
# =============================================================================
package tfm.authz

# -----------------------------------------------------------------------------
# Configuración del dominio
# -----------------------------------------------------------------------------

# Clientes OIDC desde los que se aceptan tokens de usuario final:
#   tfm-web  -> SPA (Authorization Code + PKCE, o el grant de contraseña de pruebas),
#   tfm-bff  -> Backend for Frontend (el token vive en el servidor; el navegador
#               solo tiene una cookie de sesión).
user_clients := {"tfm-web", "tfm-bff"}

# Cargas de trabajo (SPIFFE) por las que deben llegar las acciones de usuario: el
# PEP de borde. Una acción de borde invocada desde otra carga de trabajo interna
# (saltándose el gateway) se deniega.
edge_workloads := {"api-gateway"}

# Rol de cliente (resource_access) exigido por acción (RBAC de grano fino).
required_client_role := {
	"orders:create": ["orders-service", "orders:create"],
	"orders:read": ["orders-service", "orders:read"],
	"orders:cancel": ["orders-service", "orders:cancel"],
	"inventory:reserve": ["inventory-service", "inventory:reserve"],
	"inventory:commit": ["inventory-service", "inventory:commit"],
	"inventory:release": ["inventory-service", "inventory:commit"],
	"payments:execute": ["payments-service", "payments:execute"],
}

# Rol global (realm_access) alternativo exigido por acción (RBAC de grano grueso).
# "supervisor" es un rol compuesto de Keycloak que incluye "operator" (RBAC jerárquico).
required_realm_roles := {
	"inventory:read": {"operator", "supervisor", "auditor", "admin"},
	"admin:purge": {"admin"},
	"traces:read": {"operator", "supervisor", "auditor", "admin"},
}

# Acciones internas (M2M): solo con un token DELEGADO (Token Exchange, RFC 8693)
# que haya obtenido uno de los servicios indicados (azp del token) en nombre del
# usuario, presentado por ese mismo servicio (identidad mTLS).
allowed_callers := {
	"inventory:reserve": {"orders-service"},
	"inventory:commit": {"orders-service"},
	"inventory:release": {"orders-service"},
	"payments:execute": {"orders-service"},
}

# Acciones exclusivamente M2M (sin usuario final): el sujeto es la cuenta de
# servicio y solo los servicios indicados pueden ejecutarlas.
service_actions := {"traces:ingest": {"orders-service", "payments-service", "inventory-service"}}

# Acciones cuyo recurso tiene propietario: solo el propietario (o un rol
# privilegiado de lectura/gestión) puede operar sobre él (mitigación BOLA).
owner_bound_actions := {"orders:read", "orders:cancel", "inventory:commit", "inventory:release", "traces:read"}

# Roles que pueden operar sobre recursos ajenos dentro de su propio tenant.
privileged_roles := {
	"orders:read": {"admin", "auditor", "supervisor"},
	"orders:cancel": {"admin", "supervisor"},
	"traces:read": {"admin", "auditor"},
}

# Requisitos de la acción administrativa (mitigación BFLA, memoria 7.1.4).
admin_min_clearance := 5

# Autenticación fuerte (MFA / step-up). El token debe acreditar un segundo factor
# real y reciente, emitido por Keycloak en el flujo interactivo con niveles (LoA):
#   - `acr` (Authentication Context Class Reference) = aal2, que Keycloak solo emite
#     tras superar el OTP del nivel 2 (acr.loa.map del realm; caduca a los 5 min), o
#   - `amr` (Authentication Method Reference, RFC 8176) que incluya el OTP.
# El grant de contraseña (ROPC) nunca emite estas señales: no sirve para acciones
# que exigen MFA.
strong_acr_values := {"aal2"}

mfa_amr_methods := {"otp", "mfa", "hwk", "sc", "totp"}

# -----------------------------------------------------------------------------
# Atajos sobre la entrada
# -----------------------------------------------------------------------------
claims := input.jwt_claims

action := input.action.name

realm_roles contains role if some role in claims.realm_access.roles

known_action if required_client_role[action]

known_action if required_realm_roles[action]

known_action if service_actions[action]

user_action if not service_actions[action]

# Acción interna (salto entre servicios) frente a acción de borde (vía gateway).
internal_action if allowed_callers[action]

edge_action if {
	known_action
	user_action
	not internal_action
}

# Carga de trabajo llamante autenticada por mTLS (nombre de servicio del SPIFFE ID).
# Vacío si la petición no llegó por mTLS (nunca coincide con ninguna identidad).
default peer := ""

peer := input.environment.caller_service if is_string(input.environment.caller_service)

# El tipo de token es el adecuado para la acción:
#   - de borde: token de usuario emitido a un cliente de usuario;
#   - interna:  token delegado que obtuvo un servicio autorizado (azp).
token_ok if {
	edge_action
	claims.azp in user_clients
}

token_ok if {
	internal_action
	claims.azp in allowed_callers[action]
}

# Vinculación token <-> transporte (mTLS):
#   - de borde: la petición llega a través del gateway;
#   - interna / M2M: quien presenta el token es quien lo obtuvo (SPIFFE ID = azp),
#     de modo que un token robado no sirve desde otra carga de trabajo.
transport_ok if {
	edge_action
	peer in edge_workloads
}

transport_ok if {
	not edge_action
	peer != ""
	peer == claims.azp
}

tenant_present if {
	is_string(claims.tenant_id)
	claims.tenant_id != ""
}

same_tenant if {
	tenant_present
	claims.tenant_id == input.resource.tenant_id
}

is_owner if {
	is_string(claims.sub)
	claims.sub == input.resource.owner_id
}

# Referencias de método de autenticación presentes en el token (si las hay).
token_amr contains method if some method in claims.amr

# El sujeto ha superado un segundo factor (step-up en el flujo interactivo/BFF).
mfa_satisfied if claims.acr in strong_acr_values

mfa_satisfied if {
	some method in mfa_amr_methods
	method in token_amr
}

# -----------------------------------------------------------------------------
# Bloques de evaluación
# -----------------------------------------------------------------------------

has_required_role if {
	[client, role] := required_client_role[action]
	role in claims.resource_access[client].roles
}

has_required_role if {
	some role in required_realm_roles[action]
	role in realm_roles
}

ownership_ok if not action in owner_bound_actions

ownership_ok if is_owner

ownership_ok if {
	some role in privileged_roles[action]
	role in realm_roles
}

# Restricciones ABAC específicas de cada acción.
constraints_ok if not action in {"payments:execute", "admin:purge"}

constraints_ok if {
	action == "payments:execute"
	amount_within_limit
}

constraints_ok if {
	action == "admin:purge"
	claims.clearance_level >= admin_min_clearance
	mfa_satisfied
}

amount_within_limit if {
	is_number(input.action.amount)
	input.action.amount > 0
	is_number(claims.max_transaction_limit)
	input.action.amount <= claims.max_transaction_limit
}

# -----------------------------------------------------------------------------
# Decisión
# -----------------------------------------------------------------------------
default allow := false

# Acciones de usuario final (de borde o delegadas): RBAC + ABAC completos.
allow if {
	known_action
	user_action
	token_ok
	transport_ok
	has_required_role
	same_tenant
	ownership_ok
	constraints_ok
}

# Acciones M2M: la cuenta de servicio autenticada está autorizada y la presenta
# su propia carga de trabajo (mTLS).
allow if {
	callers := service_actions[action]
	claims.azp in callers
	transport_ok
}

# Motivos de denegación (explicativos, para trazabilidad y auditoría RU-06).
reasons contains "unknown_action" if not known_action

reasons contains "not_a_user_token" if {
	edge_action
	not claims.azp in user_clients
}

reasons contains "service_not_authorized" if {
	callers := service_actions[action]
	not claims.azp in callers
}

# Acción interna con un token que no delegó un servicio autorizado (p. ej. el token
# de borde reutilizado directamente: Token Relay).
reasons contains "caller_service_not_authorized" if {
	internal_action
	not claims.azp in allowed_callers[action]
}

reasons contains "edge_bypass" if {
	edge_action
	not peer in edge_workloads
}

reasons contains "peer_identity_mismatch" if {
	not edge_action
	known_action
	not peer == claims.azp
}

reasons contains "missing_role" if {
	known_action
	user_action
	not has_required_role
}

reasons contains "missing_tenant" if {
	user_action
	not tenant_present
}

reasons contains "tenant_mismatch" if {
	user_action
	tenant_present
	not same_tenant
}

reasons contains "not_resource_owner" if not ownership_ok

reasons contains "amount_exceeds_limit" if {
	action == "payments:execute"
	not amount_within_limit
}

reasons contains "insufficient_clearance" if {
	action == "admin:purge"
	not claims.clearance_level >= admin_min_clearance
}

reasons contains "mfa_required" if {
	action == "admin:purge"
	not mfa_satisfied
}

decision := {
	"allow": allow,
	"reasons": reasons,
}
