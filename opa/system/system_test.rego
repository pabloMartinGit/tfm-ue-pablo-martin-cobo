# Pruebas de la autorización de la API del PDP (opa test opa/ -v)
package system.authz_test

import data.system.authz

cert_of(name) := [{"URIs": [{"Scheme": "spiffe", "Host": "tfm.local", "Path": concat("", ["/ns/poc/sa/", name])}]}]

decision_req(certs) := {"method": "POST", "path": ["v1", "data", "tfm", "authz", "decision"], "client_certificates": certs}

test_pep_workload_can_query_decisions if {
	authz.allow with input as decision_req(cert_of("orders-service"))
	authz.allow with input as decision_req(cert_of("payments-service"))
}

# Identidad válida de la CA interna, pero no es un PEP (p. ej. un contenedor ajeno).
test_non_pep_workload_cannot_query_decisions if {
	not authz.allow with input as decision_req(cert_of("security-tests"))
	not authz.allow with input as decision_req(cert_of("api-gateway"))
}

test_foreign_trust_domain_is_rejected if {
	foreign := [{"URIs": [{"Scheme": "spiffe", "Host": "evil.example", "Path": "/ns/poc/sa/orders-service"}]}]
	not authz.allow with input as decision_req(foreign)
}

test_policy_management_api_is_locked_even_for_peps if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "tfm", "authz"], "client_certificates": cert_of("orders-service")}
	not authz.allow with input as {"method": "GET", "path": ["v1", "data"], "client_certificates": cert_of("orders-service")}
}

test_health_is_open_to_authenticated_workloads if {
	authz.allow with input as {"method": "GET", "path": ["health"], "client_certificates": cert_of("security-tests")}
}
