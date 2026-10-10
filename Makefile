# PoC Zero Trust IAM en microservicios - atajos de operación
# Si tu usuario no pertenece al grupo docker: make <objetivo> DOCKER="sudo docker"
DOCKER  ?= docker
COMPOSE  = $(DOCKER) compose
OPA_IMG  = openpolicyagent/opa:1.21.0-static
GATEWAY  = https://localhost:8443
DEMO_USER ?= alice

.PHONY: help init certs pki up down clean ps logs audit opa-test opa-fmt test token

help: ## Muestra esta ayuda
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

init: ## Genera .env con secretos aleatorios (si no existe)
	@./scripts/init-env.sh

certs: ## Regenera el certificado TLS autofirmado del gateway
	@./scripts/gen-certs.sh

pki: ## Emite/renueva la CA interna y los SVID mTLS (SPIFFE) de cada carga de trabajo
	@./scripts/gen-internal-pki.sh

up: init pki ## Construye y levanta todo el entorno
	$(COMPOSE) up -d --build
	@echo "Gateway: $(GATEWAY)  |  Consola Keycloak: $(GATEWAY)/auth/admin"

down: ## Detiene el entorno (conserva datos)
	$(COMPOSE) down

clean: ## Detiene el entorno y borra volúmenes (reimporta el realm en el siguiente up)
	$(COMPOSE) --profile tests down -v --remove-orphans

ps: ## Estado de los contenedores
	$(COMPOSE) ps

logs: ## Logs de todos los servicios
	$(COMPOSE) logs -f --tail=100

audit: ## Traza de auditoría: decisiones allow/deny de los PEP (JSON)
	$(COMPOSE) logs --no-log-prefix orders-service payments-service inventory-service trace-service | grep '"authz_decision"'

opa-test: ## Pruebas unitarias de las políticas Rego
	$(DOCKER) run --rm -v "$(CURDIR)/opa:/rego:ro" $(OPA_IMG) test /rego -v

opa-fmt: ## Comprueba formato y sintaxis estricta de las políticas
	$(DOCKER) run --rm -v "$(CURDIR)/opa:/rego:ro" $(OPA_IMG) check --strict /rego
	$(DOCKER) run --rm -v "$(CURDIR)/opa:/rego:ro" $(OPA_IMG) fmt --fail --list /rego

test: opa-test ## Pruebas unitarias OPA + batería de seguridad de extremo a extremo (O5)
	@mkdir -p reports
	$(COMPOSE) --profile tests run --rm --build security-tests | tee reports/security-tests.log

token: ## Obtiene un access token de demo: make token DEMO_USER=bob
	@. ./.env && curl -s --cacert certs/gateway.crt $(GATEWAY)/auth/realms/tfm/protocol/openid-connect/token \
	  -d grant_type=password -d client_id=tfm-web -d username=$(DEMO_USER) -d "password=$$TFM_DEMO_PASSWORD" \
	  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
