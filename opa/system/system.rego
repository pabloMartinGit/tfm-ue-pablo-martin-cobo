# =============================================================================
# Hardening del propio PDP (amenaza "alteración maliciosa de las reglas". OPA se arranca con:
#   --authentication=tls  -> solo acepta conexiones mTLS con un SVID de la CA
#                            interna; sin certificado no hay ni handshake.
#   --authorization=basic -> cada petición a su API REST se evalúa contra
#                            data.system.authz.allow.
# Solo los PEP (microservicios) pueden pedir decisiones; cualquier intento de
# subir, modificar o borrar políticas/datos vía API (PUT/PATCH/DELETE) se
# rechaza con 401. Las políticas únicamente cambian a través del repositorio
# Git (PAP) y el volumen de solo lectura.
# =============================================================================
package system.authz

trust_domain_prefix := "spiffe://tfm.local/ns/poc/sa/"

# Cargas de trabajo que actúan como PEP y pueden consultar al PDP.
pep_workloads := {"orders-service", "payments-service", "inventory-service", "trace-service"}

# SPIFFE ID del certificado cliente verificado en el handshake (SAN URI).
spiffe_ids contains sprintf("%s://%s%s", [uri.Scheme, uri.Host, uri.Path]) if {
	some uri in input.client_certificates[0].URIs
}

caller_workload := trim_prefix(id, trust_domain_prefix) if {
	some id in spiffe_ids
	startswith(id, trust_domain_prefix)
}

default allow := false

allow if {
	input.method == "POST"
	input.path == ["v1", "data", "tfm", "authz", "decision"]
	caller_workload in pep_workloads
}

allow if {
	input.method == "GET"
	input.path == ["health"]
}
