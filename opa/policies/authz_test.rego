# Pruebas unitarias de la política de autorización (opa test opa/ -v)
package tfm.authz_test

import data.tfm.authz

# -----------------------------------------------------------------------------
# Identidades de ejemplo (equivalentes a los usuarios del realm de Keycloak)
# -----------------------------------------------------------------------------

# Tokens de borde (tfm-web / tfm-bff): roles de realm y de Pedidos; los de
# Inventario y Pagos solo existen en los tokens delegados (Token Exchange).
operator_claims := {
	"sub": "alice-id",
	"azp": "tfm-web",
	"aud": ["microservices-backend-api", "orders-service"],
	"tenant_id": "tenant-corp-alpha",
	"clearance_level": 3,
	"max_transaction_limit": 5000,
	"acr": "aal1",
	"amr": ["pwd"],
	"realm_access": {"roles": ["operator"]},
	"resource_access": {"orders-service": {"roles": ["orders:read", "orders:create", "orders:cancel"]}},
}

auditor_claims := {
	"sub": "dave-id",
	"azp": "tfm-web",
	"tenant_id": "tenant-corp-alpha",
	"clearance_level": 2,
	"realm_access": {"roles": ["auditor"]},
	"resource_access": {"orders-service": {"roles": ["orders:read"]}},
}

admin_claims := {
	"sub": "erin-id",
	"azp": "tfm-bff",
	"tenant_id": "tenant-corp-alpha",
	"clearance_level": 5,
	# Step-up real: Keycloak emite acr=aal2 y amr con otp tras superar el OTP (nivel 2).
	"acr": "aal2",
	"amr": ["pwd", "otp"],
	"realm_access": {"roles": ["admin"]},
	"resource_access": {"orders-service": {"roles": ["orders:read", "orders:create", "orders:cancel"]}},
}

# Token delegado (RFC 8693) que orders-service obtiene para un destino: mismo usuario,
# aud = destino, azp = orders-service y solo los roles de ese destino.
delegated(user, target, roles) := {
	"sub": user.sub,
	"azp": "orders-service",
	"aud": target,
	"tenant_id": user.tenant_id,
	"max_transaction_limit": user.max_transaction_limit,
	"resource_access": {target: {"roles": roles}},
}

alice_order := {"service": "orders-service", "type": "order", "owner_id": "alice-id", "tenant_id": "tenant-corp-alpha"}

# Petición de borde: llega por el gateway (identidad mTLS api-gateway).
req(c, a, r) := {"jwt_claims": c, "action": a, "resource": r, "environment": {"caller_service": "api-gateway"}}

# Petición desde una carga de trabajo concreta (identidad mTLS = peer).
from_peer(c, a, r, peer) := {"jwt_claims": c, "action": a, "resource": r, "environment": {"caller_service": peer}}

# -----------------------------------------------------------------------------
# Pedidos
# -----------------------------------------------------------------------------
test_operator_can_create_order if {
	authz.allow with input as req(operator_claims, {"name": "orders:create"}, {"tenant_id": "tenant-corp-alpha", "owner_id": "alice-id"})
}

test_auditor_cannot_create_order if {
	not authz.allow with input as req(auditor_claims, {"name": "orders:create"}, {"tenant_id": "tenant-corp-alpha", "owner_id": "dave-id"})
	"missing_role" in authz.reasons with input as req(auditor_claims, {"name": "orders:create"}, {"tenant_id": "tenant-corp-alpha", "owner_id": "dave-id"})
}

test_owner_can_read_own_order if {
	authz.allow with input as req(operator_claims, {"name": "orders:read"}, alice_order)
}

test_bola_other_user_same_tenant_denied if {
	bob := object.union(operator_claims, {"sub": "bob-id"})
	not authz.allow with input as req(bob, {"name": "orders:read"}, alice_order)
	"not_resource_owner" in authz.reasons with input as req(bob, {"name": "orders:read"}, alice_order)
}

test_cross_tenant_denied if {
	carol := object.union(operator_claims, {"sub": "carol-id", "tenant_id": "tenant-corp-beta"})
	not authz.allow with input as req(carol, {"name": "orders:read"}, alice_order)
	"tenant_mismatch" in authz.reasons with input as req(carol, {"name": "orders:read"}, alice_order)
}

test_auditor_can_read_any_order_in_tenant if {
	authz.allow with input as req(auditor_claims, {"name": "orders:read"}, alice_order)
}

test_auditor_cannot_cancel_foreign_order if {
	not authz.allow with input as req(auditor_claims, {"name": "orders:cancel"}, alice_order)
}

test_admin_can_cancel_foreign_order if {
	authz.allow with input as req(admin_claims, {"name": "orders:cancel"}, alice_order)
}

test_missing_tenant_claim_denied if {
	no_tenant := object.remove(operator_claims, ["tenant_id"])
	not authz.allow with input as req(no_tenant, {"name": "orders:create"}, {"owner_id": "alice-id"})
	"missing_tenant" in authz.reasons with input as req(no_tenant, {"name": "orders:create"}, {"owner_id": "alice-id"})
}

# -----------------------------------------------------------------------------
# Tokens que no son de usuario final / acciones desconocidas
# -----------------------------------------------------------------------------
test_service_account_token_not_accepted_as_user if {
	svc := object.union(operator_claims, {"azp": "orders-service"})
	not authz.allow with input as req(svc, {"name": "orders:create"}, {"tenant_id": "tenant-corp-alpha"})
	"not_a_user_token" in authz.reasons with input as req(svc, {"name": "orders:create"}, {"tenant_id": "tenant-corp-alpha"})
}

test_unknown_action_denied if {
	not authz.allow with input as req(admin_claims, {"name": "orders:delete_all"}, {"tenant_id": "tenant-corp-alpha"})
	"unknown_action" in authz.reasons with input as req(admin_claims, {"name": "orders:delete_all"}, {"tenant_id": "tenant-corp-alpha"})
}

test_empty_input_denied if {
	not authz.allow with input as {}
}

# Las acciones de borde solo se aceptan si llegan a través del gateway (identidad
# mTLS api-gateway): una carga de trabajo interna no puede saltarse el PEP de borde.
test_edge_action_must_come_through_gateway if {
	create := {"name": "orders:create"}
	resource := {"tenant_id": "tenant-corp-alpha", "owner_id": "alice-id"}
	not authz.allow with input as from_peer(operator_claims, create, resource, "inventory-service")
	"edge_bypass" in authz.reasons with input as from_peer(operator_claims, create, resource, "inventory-service")
	no_peer := {"jwt_claims": operator_claims, "action": create, "resource": resource, "environment": {}}
	not authz.allow with input as no_peer
	"edge_bypass" in authz.reasons with input as no_peer
}

# -----------------------------------------------------------------------------
# Saltos internos: token delegado (RFC 8693) + vínculo con la identidad mTLS
# -----------------------------------------------------------------------------
payment(amount) := {"name": "payments:execute", "amount": amount}

payment_resource := {"type": "payment", "tenant_id": "tenant-corp-alpha", "owner_id": "alice-id"}

alice_for_payments := delegated(operator_claims, "payments-service", ["payments:execute"])

test_payment_with_delegated_token_from_orders_allowed if {
	authz.allow with input as from_peer(alice_for_payments, payment(1200), payment_resource, "orders-service")
}

# Token Relay: el token de borde del usuario reutilizado en Pagos no es un token delegado.
test_edge_token_relayed_to_payments_denied if {
	with_role := object.union(operator_claims, {"resource_access": {"payments-service": {"roles": ["payments:execute"]}}})
	d := authz.decision with input as from_peer(with_role, payment(1200), payment_resource, "orders-service")
	d.allow == false
	"caller_service_not_authorized" in d.reasons
}

# Token delegado robado y presentado desde otra carga de trabajo (su SVID no es el de
# orders-service): el vínculo token <-> mTLS lo invalida.
test_delegated_token_presented_by_other_workload_denied if {
	d := authz.decision with input as from_peer(alice_for_payments, payment(1200), payment_resource, "security-tests")
	d.allow == false
	d.reasons == {"peer_identity_mismatch"}
}

test_payment_delegated_by_other_service_denied if {
	by_inventory := object.union(alice_for_payments, {"azp": "inventory-service"})
	not authz.allow with input as from_peer(by_inventory, payment(1200), payment_resource, "inventory-service")
	"caller_service_not_authorized" in authz.reasons with input as from_peer(by_inventory, payment(1200), payment_resource, "inventory-service")
}

test_payment_above_limit_denied if {
	not authz.allow with input as from_peer(alice_for_payments, payment(9000), payment_resource, "orders-service")
	"amount_exceeds_limit" in authz.reasons with input as from_peer(alice_for_payments, payment(9000), payment_resource, "orders-service")
}

test_payment_non_positive_amount_denied if {
	not authz.allow with input as from_peer(alice_for_payments, payment(0), payment_resource, "orders-service")
}

test_inventory_commit_requires_reservation_owner if {
	reservation := {"type": "reservation", "tenant_id": "tenant-corp-alpha", "owner_id": "alice-id"}
	alice := delegated(operator_claims, "inventory-service", ["inventory:reserve", "inventory:commit"])
	bob := object.union(alice, {"sub": "bob-id"})
	authz.allow with input as from_peer(alice, {"name": "inventory:commit"}, reservation, "orders-service")
	not authz.allow with input as from_peer(bob, {"name": "inventory:commit"}, reservation, "orders-service")
}

# La cuenta de servicio de orders-service (client_credentials) no actúa en nombre de nadie.
test_service_account_token_cannot_act_as_delegated if {
	d := authz.decision with input as from_peer({"sub": "sa-orders", "azp": "orders-service"}, payment(100), payment_resource, "orders-service")
	d.allow == false
	"missing_role" in d.reasons
	"missing_tenant" in d.reasons
}

# -----------------------------------------------------------------------------
# Acción administrativa (BFLA): admin + clearance >= 5 + step-up MFA (acr/amr)
# -----------------------------------------------------------------------------
purge := {"name": "admin:purge"}

tenant_resource := {"type": "orders", "tenant_id": "tenant-corp-alpha"}

test_admin_with_strong_acr_can_purge if {
	authz.allow with input as req(admin_claims, purge, tenant_resource)
}

test_operator_cannot_purge if {
	not authz.allow with input as req(operator_claims, purge, tenant_resource)
}

# El segundo factor puede acreditarse por amr (RFC 8176) aunque el acr sea bajo.
test_admin_with_otp_amr_can_purge if {
	via_amr := object.union(admin_claims, {"acr": "aal1", "amr": ["pwd", "otp"]})
	authz.allow with input as req(via_amr, purge, tenant_resource)
}

# Login interactivo sin step-up (solo contraseña): acr=aal1, amr=[pwd].
test_admin_without_step_up_cannot_purge if {
	aal1 := object.union(admin_claims, {"acr": "aal1", "amr": ["pwd"]})
	not authz.allow with input as req(aal1, purge, tenant_resource)
	"mfa_required" in authz.reasons with input as req(aal1, purge, tenant_resource)
}

# Grant de contraseña (ROPC): Keycloak no emite señales de step-up aunque el usuario
# haya superado el OTP, así que no sirve para acciones que exigen MFA.
test_admin_password_grant_token_cannot_purge if {
	ropc := object.union(admin_claims, {"azp": "tfm-web", "acr": "aal1", "amr": []})
	not authz.allow with input as req(ropc, purge, tenant_resource)
	"mfa_required" in authz.reasons with input as req(ropc, purge, tenant_resource)
}

# La antigua señal estática ya no concede nada.
test_static_mfa_attribute_is_ignored if {
	static := json.remove(object.union(admin_claims, {"acr": "aal1", "mfa_verified": true}), ["amr"])
	not authz.allow with input as req(static, purge, tenant_resource)
	"mfa_required" in authz.reasons with input as req(static, purge, tenant_resource)
}

test_admin_low_clearance_cannot_purge if {
	low := object.union(admin_claims, {"clearance_level": 4})
	not authz.allow with input as req(low, purge, tenant_resource)
	"insufficient_clearance" in authz.reasons with input as req(low, purge, tenant_resource)
}

test_decision_document_shape if {
	d := authz.decision with input as req(operator_claims, {"name": "orders:create"}, {"tenant_id": "tenant-corp-alpha"})
	d.allow == true
	count(d.reasons) == 0
}

# -----------------------------------------------------------------------------
# Permisos variados: supervisor (RBAC jerárquico), junior y solicitante
# -----------------------------------------------------------------------------
supervisor_claims := {
	"sub": "hector-id",
	"azp": "tfm-web",
	"tenant_id": "tenant-corp-alpha",
	"clearance_level": 4,
	"acr": "aal2",
	"realm_access": {"roles": ["supervisor", "operator"]},
	"resource_access": {"orders-service": {"roles": ["orders:read", "orders:create", "orders:cancel"]}},
}

test_supervisor_can_read_and_cancel_foreign_order if {
	authz.allow with input as req(supervisor_claims, {"name": "orders:read"}, alice_order)
	authz.allow with input as req(supervisor_claims, {"name": "orders:cancel"}, alice_order)
}

test_supervisor_cannot_act_in_other_tenant if {
	beta_order := object.union(alice_order, {"tenant_id": "tenant-corp-beta"})
	not authz.allow with input as req(supervisor_claims, {"name": "orders:cancel"}, beta_order)
}

test_supervisor_cannot_purge if {
	d := authz.decision with input as req(supervisor_claims, purge, tenant_resource)
	d.allow == false
	"missing_role" in d.reasons
	"insufficient_clearance" in d.reasons
}

test_junior_without_cancel_role_cannot_cancel_own_order if {
	junior := object.union(operator_claims, {
		"sub": "bob-id",
		"resource_access": {"orders-service": {"roles": ["orders:read", "orders:create"]}},
	})
	own := object.union(alice_order, {"owner_id": "bob-id"})
	not authz.allow with input as req(junior, {"name": "orders:cancel"}, own)
	"missing_role" in authz.reasons with input as req(junior, {"name": "orders:cancel"}, own)
}

# gina crea pedidos, pero su token delegado para Pagos no lleva el rol: Keycloak
# delega (el STS no decide) y el PDP de Pagos deniega.
test_requester_without_payment_role_is_denied_at_payments if {
	gina := object.union(operator_claims, {"sub": "gina-id"})
	authz.allow with input as req(gina, {"name": "orders:create"}, {"tenant_id": "tenant-corp-alpha"})
	gina_for_payments := delegated(gina, "payments-service", [])
	not authz.allow with input as from_peer(gina_for_payments, payment(300), payment_resource, "orders-service")
	"missing_role" in authz.reasons with input as from_peer(gina_for_payments, payment(300), payment_resource, "orders-service")
}

# -----------------------------------------------------------------------------
# Trazas: lectura con ABAC e ingesta exclusivamente M2M
# -----------------------------------------------------------------------------
alice_trace := {"type": "trace", "owner_id": "alice-id", "tenant_id": "tenant-corp-alpha"}

test_user_can_read_own_trace if {
	authz.allow with input as req(operator_claims, {"name": "traces:read"}, alice_trace)
}

test_user_cannot_read_foreign_trace if {
	bob := object.union(operator_claims, {"sub": "bob-id"})
	not authz.allow with input as req(bob, {"name": "traces:read"}, alice_trace)
	"not_resource_owner" in authz.reasons with input as req(bob, {"name": "traces:read"}, alice_trace)
}

test_auditor_can_read_any_trace_of_tenant if {
	authz.allow with input as req(auditor_claims, {"name": "traces:read"}, alice_trace)
}

test_auditor_cannot_read_trace_of_other_tenant if {
	beta_trace := object.union(alice_trace, {"tenant_id": "tenant-corp-beta"})
	not authz.allow with input as req(auditor_claims, {"name": "traces:read"}, beta_trace)
}

service_claims(client) := {"sub": concat("-", ["sa", client]), "azp": client}

ingest(client, peer) := from_peer(service_claims(client), {"name": "traces:ingest"}, {"type": "spans"}, peer)

test_services_can_ingest_traces if {
	authz.allow with input as ingest("orders-service", "orders-service")
	authz.allow with input as ingest("payments-service", "payments-service")
}

test_user_token_cannot_ingest_traces if {
	d := authz.decision with input as from_peer(operator_claims, {"name": "traces:ingest"}, {"type": "spans"}, "orders-service")
	d.allow == false
	"service_not_authorized" in d.reasons
}

test_unknown_service_cannot_ingest_traces if {
	not authz.allow with input as ingest("rogue-service", "rogue-service")
}

# El colector sella los spans con la identidad mTLS: un servicio no puede publicar
# con el token de otro.
test_service_cannot_ingest_as_another_workload if {
	d := authz.decision with input as ingest("orders-service", "payments-service")
	d.allow == false
	d.reasons == {"peer_identity_mismatch"}
}
