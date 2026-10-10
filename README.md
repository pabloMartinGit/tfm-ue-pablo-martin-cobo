# Desarrollo seguro en microservicios: patrones y herramientas

Prueba de concepto (PoC) del TFM *MUSTIC 25/26* (Universidad Europea) — Pablo Martín Cobo.
Tutor: José Cándido Carballido López.

Marco de trabajo IAM para microservicios bajo el paradigma **Zero Trust**: la identidad es
el perímetro, cada petición se autentica en el borde y se vuelve a verificar y autorizar en
cada salto interno, y la lógica de autorización vive fuera del código de negocio (*Policy as Code*).

> Estado: **MVP funcional** (base para la fase de desarrollo, apartado 7.2 de la memoria).
> Ver [docs/trazabilidad-tfm.md](docs/trazabilidad-tfm.md) para la correspondencia
> memoria ↔ código, las decisiones tomadas y el backlog de siguientes iteraciones.

## Arquitectura

```
                          Cliente (navegador / curl)
                                    │  HTTPS :8443 (TLS autofirmado)
┌─ frontend-net ────────────────────┼──────────────────────────────────────────────┐
│                     ┌─────────────▼─────────────┐                                │
│                     │ API Gateway (Nginx + njs) │  PEP perimetral: valida firma  │
│                     │  /auth/*  /api/v1/*  /bff │  RS256 (JWKS), iss, aud, exp   │
│                     └─────┬───────────────┬─────┘                                │
└───────────────────────────┼───────────────┼──────────────────────────────────────┘
┌─ backend-net (interna) ═══╪═══════════════╪══ mTLS (TLS 1.3, SVID SPIFFE) + HTTP/2 ┐
│                           │ token de borde│ /auth/*                              │
│   ┌───────────────────────▼──┐        ┌───▼──────────┐       ┌────────────────┐  │
│   │ A · Pedidos (PEP)        │ canje  │  Keycloak    │       │  OPA (PDP)     │  │
│   │ orders-service           │◀──────▶│  IdP / STS   │       │  Rego + logs   │  │
│   └──┬──────────────────┬────┘RFC 8693└──────────────┘       └───────▲────────┘  │
│      │ token delegado   │ token delegado                             │ decisión   │
│      │ aud=inventory    │ aud=payments                               │ por salto  │
│   ┌──▼─────────────┐ ┌──▼─────────────┐                (todos los servicios)     │
│   │ C · Inventario │ │ B · Pagos      │                                          │
│   └────────────────┘ └────────────────┘                                          │
│   todos los PEP ── spans W3C ──▶ trace-service (colector)                        │
└══════════════════════════════════════════════════════════════════════════════════┘
┌─ auth-net (interna) ─────────────────────────────────────────┐
│                               Keycloak ────── PostgreSQL      │
└───────────────────────────────────────────────────────────────┘
```

| Componente | Imagen | Rol Zero Trust (NIST SP 800-207) |
|---|---|---|
| API Gateway | `nginxinc/nginx-unprivileged:1.30-alpine` + njs | PEP perimetral |
| Keycloak | `quay.io/keycloak/keycloak:26.7.4` | Policy Administrator / IdP (OAuth 2.0 + OIDC) y STS (Token Exchange) |
| PostgreSQL | `postgres:16-alpine` | Persistencia del IdP |
| Open Policy Agent | `openpolicyagent/opa:1.21.0-static` | PDP / Policy Engine (Rego) |
| Pedidos (A) | `services/` (FastAPI + Hypercorn, Python 3.13) | Resource Server + PEP, orquesta el flujo y canjea tokens por salto |
| Pagos (B) | `services/` | Resource Server + PEP, solo M2M, introspección (RFC 7662) |
| Inventario (C) | `services/` | Resource Server + PEP |
| BFF | `services/` (`bff`) | Token Handler: Authorization Code + PKCE, cookie de sesión |
| Trazas | `services/` (`traces`) | Colector de trazas distribuidas (observabilidad, RU-06) |

### Flujo de un pedido (Ilustración 12 de la memoria)

1. El cliente obtiene un access token de Keycloak (RS256, 5 min) con `sub`, `tenant_id`,
   `clearance_level`, `max_transaction_limit`, `acr`/`amr` y roles. Su audiencia es solo la API
   de borde y Pedidos: no incluye Inventario ni Pagos.
2. El gateway valida firma, `iss`, `aud`, `exp` y `typ` y reenvía la petición a Pedidos por
   **mTLS** (se autentica con su SVID `spiffe://tfm.local/ns/poc/sa/api-gateway`) y **HTTP/2**.
3. **Pedidos** vuelve a validar el JWT y pregunta a OPA por `orders:create`.
4. Pedidos llama a **Inventario** (`reserve`) → **Pagos** (`execute`) → **Inventario** (`commit`).
   En cada salto viajan **dos identidades**: la del usuario, en un **token delegado** que Pedidos
   obtiene de Keycloak por *Token Exchange* (RFC 8693) con audiencia = servicio destino, y la del
   servicio llamante, que aporta el **handshake mTLS** (SPIFFE ID de su certificado).
5. Cada servicio receptor exige que el token delegado sea para él (`aud`), que lo haya delegado un
   servicio autorizado (`azp`) y que coincida con la identidad mTLS del llamante, y consulta a OPA;
   si el pago se deniega, se libera la reserva (compensación).
6. Todo el recorrido queda en una **traza distribuida** (W3C Trace Context): el gateway abre la
   traza (`traceparent`, trace-id = `X-Request-ID`) y cada servicio registra autenticación,
   transporte (HTTP/2, TLS 1.3, SPIFFE ID del llamante), canjes de token, decisiones del PDP y
   llamadas salientes, que envía al colector con su identidad M2M.

## Puesta en marcha

Requisitos: Linux, Docker Engine + Docker Compose v2, `openssl`. `make` es opcional.

```bash
make up            # genera .env y la PKI interna (SVID mTLS), construye y arranca
make ps            # esperar a que todo esté "healthy" (Keycloak tarda ~30-60 s)
make test          # pruebas unitarias OPA + batería de seguridad E2E
```

Sin `make`:

```bash
./scripts/init-env.sh
./scripts/gen-internal-pki.sh   # CA interna + un SVID por carga de trabajo en certs/internal/
docker compose up -d --build
docker run --rm -v "$PWD/opa:/rego:ro" openpolicyagent/opa:1.21.0-static test /rego -v
docker compose --profile tests run --rm --build security-tests
```

> Si tu usuario no pertenece al grupo `docker`: `sudo usermod -aG docker $USER` (y volver a
> iniciar sesión), o bien `make up DOCKER="sudo docker"`.

El realm `tfm` se importa solo en el primer arranque. Tras modificar
`keycloak/realm-tfm.json` (p. ej. al actualizar el repositorio con usuarios nuevos) hay que
ejecutar `make clean && make up`: borra el volumen de Keycloak y lo reimporta.

> **Al actualizar un despliegue anterior**: el realm cambió (flujo de step-up, Token Exchange,
> audiencias) y el tráfico interno exige los certificados de `certs/internal/`. `make up` los genera
> (`make pki`); después reimporta el realm con `make clean && make up`. No hay secretos nuevos en
> `.env` respecto a la versión con BFF (`BFF_CLIENT_SECRET`, `TFM_MFA_SECRET`).
>
> `make pki` es idempotente: solo emite lo que falta o caduca en menos de 7 días (SVID de 30 días,
> CA de 1 año). Keycloak y OPA recargan sus certificados solos; los servicios Python y el gateway
> los leen al arrancar (`make up` tras renovar).

### Accesos

| Recurso | URL |
|---|---|
| **Consola de demostración** | `https://localhost:8443/` |
| API | `https://localhost:8443/api/v1/...` |
| Consola de Keycloak | `https://localhost:8443/auth/admin` (usuario `admin`, contraseña `KC_ADMIN_PASSWORD` de `.env`) |
| Discovery OIDC | `https://localhost:8443/auth/realms/tfm/.well-known/openid-configuration` |

### Consola web

En `https://localhost:8443/` hay una consola (SPA) para recorrer los casos de uso sin usar
la terminal. Servida por el propio gateway (mismo origen que la API y Keycloak, sin CORS):

- Iniciar sesión como cualquiera de los nueve usuarios demo (introduce una vez la contraseña
  `TFM_DEMO_PASSWORD`) y ver su JWT decodificado (roles y vector de atributos ABAC).
- Lanzar cada operación (catálogo, crear/leer/cancelar pedido, purga admin) *actuando como*
  cualquier usuario (tarjetas y selector están sincronizados), con el código de respuesta y los
  motivos de denegación del PDP.
- **24 escenarios guiados** agrupados por componente (borde, PDP, IdP, trazabilidad, propagación
  con Token Exchange y mTLS, ciclo de vida de credenciales —token expirado, clave de firma ajena,
  rate limiting—, MFA y revocación), uno a uno o con «Ejecutar todos»: la consola
  inicia sesión con los usuarios necesarios y verifica el resultado esperado (PASS/FALLO),
  incluidos ataques al borde forjados en el navegador. El escenario de step-up (ST-46) ejecuta el
  flujo interactivo real de Keycloak (contraseña + OTP) desde la propia consola.
- **Login BFF** (Authorization Code + PKCE): el botón «Entrar con Keycloak (BFF)» redirige a la
  página de login real; al volver, el navegador solo tiene una cookie de sesión y opera la API
  sin ver ningún token (el inspector lo indica). La sesión es de nivel `aal1`; el botón
  **«elevar a aal2 (OTP)»** hace el *step-up* (Keycloak solo pide el OTP; para erin y hector la
  tarjeta muestra el código demo vigente).
- **Registro de actividad clicable**: cada llamada (a la API o a Keycloak) abre su **traza**:
  cascada temporal por componente (gateway, servicios, consultas a OPA y canjes en Keycloak) y el
  recorrido paso a paso: veredicto del borde, transporte de cada salto (mTLS TLS 1.3, HTTP/2 y
  SPIFFE ID del llamante), token de usuario o delegado verificado (con su `aud` y `azp`), canjes
  RFC 8693, decisión del PDP con sus motivos, introspección, compensaciones y código devuelto. Las
  peticiones rechazadas en el borde muestran el motivo exacto (`alg_not_allowed:none`, …).

Los access token viven solo en memoria de la pestaña. La consola usa el *grant* de contraseña
del cliente público `tfm-web` (habilitado para las pruebas del PoC) para poder manejar varias
identidades a la vez; ese atajo nunca acredita *step-up* (`acr=aal1`). En producción el navegador
no vería tokens (patrón BFF). Keycloak mantiene **una sesión SSO por navegador**: si la sesión BFF
de otro usuario está abierta, el escenario de step-up pide cerrarla antes.

### Usuarios de demostración

Todos usan la contraseña `TFM_DEMO_PASSWORD` de `.env`.

| Usuario | Grupo / rol | Permisos de cliente destacados | Tenant | clearance | Límite (€) | OTP | Para probar |
|---|---|---|---|---|---|---|---|
| `alice` | operators / `operator` | pedidos (leer, crear, cancelar), pagos, inventario | alpha | 3 | 5.000 | no | flujo normal, límite ABAC |
| `bob` | junior-operators / `operator` | como alice **sin** `orders:cancel` | alpha | 2 | 1.000 | no | BOLA, mismo rol con otro límite, no cancela |
| `carol` | operators / `operator` | como alice | beta | 3 | 20.000 | no | aislamiento entre tenants |
| `dave` | auditors / `auditor` | solo `orders:read` | alpha | 2 | 0 | no | lectura de todo el tenant (pedidos y trazas) |
| `erin` | admins / `admin` | todos | alpha | 5 | 50.000 | sí | endpoint administrativo tras *step-up* (`acr=aal2`) |
| `frank` | admins / `admin` | todos | alpha | 5 | 50.000 | no | BFLA: admin sin 2.º factor (no puede elevar sin enrolar OTP) |
| `gina` | requesters / `operator` | pedidos e inventario, **sin** `payments:execute` | alpha | 2 | 5.000 | no | autorización en cada salto (lo deniega Pagos) |
| `hector` | supervisors / `supervisor` ⊃ `operator` | todos los de operador | alpha | 4 | 20.000 | sí | RBAC jerárquico: gestiona pedidos ajenos; no puede purgar |
| `ivan` | operators, **deshabilitado** | — | beta | 3 | 5.000 | no | cuenta suspendida en el IdP (RU-05) |

`supervisor` es un rol compuesto de Keycloak: el token de hector incluye `supervisor` y el
`operator` heredado (RBAC jerárquico, apartado 4.3.1.1 de la memoria).

Los roles de Inventario y Pagos siguen asignados a los usuarios en Keycloak, pero **no viajan en
el token del navegador**: los clientes de usuario (`tfm-web`, `tfm-bff`) solo pueden emitir roles
de realm y de Pedidos. Esos roles aparecen únicamente en los tokens delegados que Pedidos obtiene
para cada destino (el alcance de `orders-service` define qué puede delegar).

### Ejemplo rápido

```bash
TOKEN=$(make -s token DEMO_USER=alice)
curl --cacert certs/gateway.crt -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/v1/inventory
curl --cacert certs/gateway.crt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"sku":"SKU-001","quantity":2}' https://localhost:8443/api/v1/orders            # 201
curl --cacert certs/gateway.crt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"sku":"SKU-003","quantity":1}' https://localhost:8443/api/v1/orders            # 403 amount_exceeds_limit
```

## API expuesta por el gateway

| Método y ruta | Acción OPA | Servicio |
|---|---|---|
| `GET /api/v1/inventory` | `inventory:read` | Inventario |
| `POST /api/v1/orders` | `orders:create` (+ reserve, payments:execute, commit) | Pedidos |
| `GET /api/v1/orders` | `orders:read` (filtrado por objeto) | Pedidos |
| `GET /api/v1/orders/{id}` | `orders:read` | Pedidos |
| `POST /api/v1/orders/{id}/cancel` | `orders:cancel` | Pedidos |
| `DELETE /api/v1/admin/purge` | `admin:purge` | Pedidos |
| `GET /api/v1/traces/{trace_id}` | `traces:read` (autor de la petición, o auditor/admin del tenant) | Trazas |

Las rutas `/internal/v1/*` **no se publican**: solo son alcanzables dentro de `backend-net` y por
mTLS. Las de Pagos e Inventario exigen un token delegado para ese servicio (`aud`), obtenido por
el servicio de pedidos (`azp`) y presentado por él mismo (SPIFFE ID de la conexión); la ingesta de
spans del colector (`traces:ingest`) solo admite cuentas de servicio de los microservicios,
también vinculadas a su identidad mTLS. Las acciones de usuario solo se aceptan si llegan a través
del gateway (identidad mTLS `api-gateway`).

## Pruebas de seguridad (objetivo O5)

- `opa/`: 47 pruebas unitarias (42 de la política de autorización y 5 de la API del PDP).
- `tests/`: 58 pruebas de extremo a extremo (ST-01 … ST-59) que se ejecutan desde un
  contenedor conectado a la red externa **y** a la interna, simulando tanto un cliente
  externo como un contenedor comprometido (movimiento lateral). El contenedor tiene su propio
  SVID (identidad válida sin permisos) y una copia del de `orders-service` para simular que ese
  servicio ha sido comprometido.

| Bloque | Pruebas | Ataques cubiertos |
|---|---|---|
| `test_01_perimeter_authn.py` | ST-01…08 | sin token, token malformado, claims manipulados, `alg: none`, confusión RS256→HS256, ID token como access token, token M2M como usuario (comprobando el motivo exacto del rechazo en el borde) |
| `test_02_authorization.py` | ST-09…17 | BOLA (API1), BOPLA/asignación masiva (API3), BFLA con step-up (API5), multitenencia, RBAC auditor, ABAC límite de importe |
| `test_03_lateral_movement.py` | ST-18…23, 34, 35 | revalidación interna, reenvío del token de borde (*Token Relay*) a Pagos, reutilización de un token delegado en otro salto, token delegado forjado, diputado confuso, PDP solo accesible a los PEP, inyección de spans y suplantación en el colector |
| `test_04_transport_and_exposure.py` | ST-24…27 | redirección HTTPS, cabeceras de seguridad, rutas internas no publicadas, cabeceras de identidad falsificadas (*header spoofing*) |
| `test_05_roles_and_identity.py` | ST-28…32 | autorización en cada salto, RBAC jerárquico, RBAC de grano fino, mismo rol con distintos atributos, cuenta suspendida |
| `test_06_tracing.py` | ST-33, 36 | traza completa con control de acceso ABAC, inyección de contexto de traza desde el cliente |
| `test_07_mfa.py` | ST-37…39 | OTP obligatorio en Keycloak, step-up que emite `acr=aal2`/`amr=[pwd,otp]`, purga solo con step-up, admin sin OTP no puede elevar |
| `test_08_bff_revocation.py` | ST-40…45 | revocación inmediata (canje e introspección), PKCE en el borde, cookie→token, `/bff/token` no público, logout, step-up bajo demanda en el BFF |
| `test_09_mtls_token_exchange.py` | ST-47…53 | tráfico interno sin SVID o con CA ajena, TLS 1.3 y verificación del servidor, token delegado robado usado desde otra carga de trabajo, acciones de usuario que evitan el gateway, audiencia reducida por salto, reglas del STS, HTTP/2 interno |
| `test_10_credential_lifecycle.py` | ST-54…59 | token expirado en el borde y en el servicio (cliente de pruebas con tokens de 5 s), rotación de la clave de firma sin cortes, clave ajena con `kid`/`jku` propios, bloqueo por fuerza bruta en Keycloak (respuesta indistinguible y desbloqueo), rate limiting del login y de la API (API4:2023) |

El resultado queda en `reports/security-tests.log`.

Las pruebas de rotación de claves y de fuerza bruta usan la API de administración de Keycloak
desde la red interna (el contenedor de pruebas recibe `KC_ADMIN_PASSWORD`) y crean y retiran sus
propios recursos temporales: una clave RSA de prioridad alta y un usuario desechable. La de token
expirado usa `tfm-short-lived`, un cliente del realm solo para pruebas que emite tokens de 5 s y
que la política no reconoce como cliente de usuario (no autoriza nada). Las de rate limiting van
al final y esperan a que se recupere el cupo de la IP de pruebas.

## Identidad avanzada

Mecanismos que refuerzan la gestión de identidad más allá del token stateless:

- **BFF / Token Handler** (patrón 7.1.2.1). El servicio `bff` realiza el flujo *Authorization
  Code + PKCE* contra Keycloak (cliente confidencial `tfm-bff`) y guarda los tokens **en el
  servidor**. El navegador solo recibe la cookie `__Host-tfm_session` (`HttpOnly · Secure ·
  SameSite=Strict`), lo que neutraliza la exfiltración de tokens por XSS. Para las llamadas a la
  API, el gateway (njs) traduce la cookie a `Authorization: Bearer` consultando un endpoint
  interno del BFF (`/bff/token`, no publicado); la validación criptográfica del JWT en el borde
  se mantiene. Rutas: `GET /bff/login[?acr=aal2]`, `GET /bff/callback`, `GET /bff/userinfo`,
  `POST /bff/logout`. La consola ofrece ambos modos (BFF y el grant de contraseña de pruebas).
- **MFA real con step-up (`acr`/`amr`)**. El flujo de login del realm («tfm browser step-up») tiene
  dos niveles (LoA): nivel 1 = contraseña (`acr=aal1`, `amr=[pwd]`); nivel 2 = OTP (`acr=aal2`,
  `amr=[pwd, otp]`, válido 5 min). El segundo nivel se pide **bajo demanda** con
  `acr_values=aal2`: si ya hay sesión, Keycloak solo exige el OTP. `admin:purge` exige `acr=aal2`
  (o `amr` con OTP); ya no existe el atributo estático `mfa_verified`. Un usuario sin OTP
  (`frank`) no puede elevar: Keycloak le obliga a enrolar un segundo factor. El *grant* de
  contraseña sigue exigiendo el OTP a erin/hector, pero nunca acredita el nivel 2.
- **Revocación en tiempo real (introspección RFC 7662)**. La operación crítica `payments:execute`
  «pivota a un modelo con estado»: tras autorizar, pregunta a Keycloak si el token sigue activo.
  Un token de una sesión cerrada (logout) o revocada se rechaza (`401 token_revoked`) aunque no
  haya expirado, resolviendo la principal limitación del modelo stateless (memoria 4.2.2.3). Con
  Token Exchange, cada canje es además un punto de revocación: el STS no canjea tokens de
  sesiones cerradas.
- **Token Exchange (RFC 8693), audiencia reducida en cada salto** (Tabla 8). El token del
  navegador solo sirve para la API de borde y Pedidos. Para cada llamada interna, Pedidos lo
  canjea en Keycloak (*Standard Token Exchange*) por un token con `aud` = servicio destino,
  `azp` = `orders-service` y solo los roles de ese destino. Un token capturado en un salto no
  sirve en otro, y el token de borde reenviado tal cual (*Token Relay*) se rechaza. El coste
  (~15-30 ms por canje en local) se memoriza por petición y aparece en la traza.
- **mTLS interno con identidades SPIFFE y HTTP/2** (memoria 5.3, O4). `make pki` emite una CA
  propia y un SVID X.509 por carga de trabajo (`spiffe://tfm.local/ns/poc/sa/<nombre>`); cada
  contenedor monta solo el suyo. Todo el tráfico de `backend-net` (gateway, servicios, BFF,
  colector, OPA y Keycloak) exige TLS 1.3 con certificado de cliente de esa CA: sin él no hay
  ni handshake. La identidad del llamante ya no viaja en cabeceras (desaparece `X-Service-Token`):
  la política exige que el SPIFFE ID de la conexión coincida con el `azp` del token delegado, que
  las acciones de usuario lleguen por el gateway, y OPA solo atiende a los PEP. Los saltos
  gateway→servicio y servicio→servicio negocian HTTP/2 (ALPN) con conexiones persistentes.

## Auditoría y trazabilidad (RU-06)

- **Trazas distribuidas (W3C Trace Context)**: el gateway abre la traza y propaga
  `traceparent` (trace-id = `X-Request-ID`) junto con su veredicto (`X-Edge-Auth`). La librería
  `zt_security` crea un span por petición en cada servicio, con un span cliente por llamada
  saliente, y registra la autenticación, las decisiones del PDP (con su `decision_id`, que
  enlaza con el *decision log* de OPA), el transporte (HTTP/2, TLS 1.3 y SPIFFE ID del llamante),
  los canjes de token y los eventos de negocio. Los spans se envían en segundo plano (por mTLS)
  al **trace-service**, que los sella con la identidad mTLS verificada del servicio y aplica ABAC
  en la lectura. El gateway sobrescribe siempre `traceparent`, de modo
  que un cliente no puede inyectar ni reutilizar trazas.
- **Gateway**: access log JSON con `request_id`, ruta, estado, `sub` y veredicto del borde
  (`edge`). En modo PoC (`EXPOSE_DENY_REASONS=true`) el 401 incluye `edge_reason`; en
  producción el motivo solo queda en el log.
- **Microservicios**: evento `authz_decision` (JSON) por cada decisión, con `sub`, `tenant_id`,
  acción, recurso, servicio llamante y motivos de denegación: `make audit`.
- **OPA**: *decision logs* completos en consola, con el email enmascarado.
- **Keycloak**: eventos de login y de administración (`jboss-logging`, formato JSON).
- El `X-Request-ID` generado en el borde se propaga por toda la cadena.

## Políticas en caliente (RU-04)

OPA se arranca con `--watch`: al editar `opa/policies/*.rego` la política se recarga sin
reiniciar ni redesplegar ningún servicio. Su API de gestión está bloqueada
(`opa/system/system.rego`), así que las políticas solo cambian a través del repositorio (PAP).

## Estructura

```
.
├── docker-compose.yml          # Orquestación, redes y hardening de contenedores
├── .env.example                # Plantilla de secretos (make init genera .env)
├── Makefile
├── certs/                      # Certificado TLS del gateway; internal/ = CA y SVID (make pki)
├── gateway/
│   ├── nginx.conf              # PEP perimetral, TLS, rate limiting, logs JSON, upstreams mTLS
│   ├── upstream-tls.inc        # mTLS + HTTP/2 hacia los upstreams internos (SVID del gateway)
│   ├── proxy-common.inc        # Cabeceras hacia los servicios (trazas, cookie BFF)
│   ├── keycloak-proxy.inc      # Proxy hacia Keycloak (cabeceras de seguridad por ruta)
│   └── njs/jwt.js              # Validación RS256 + JWKS con caché y rotación de kid
├── frontend/                   # Consola web (SPA sin dependencias): index.html, styles.css, app.js
├── keycloak/realm-tfm.json     # Realm: clientes, roles, grupos, usuarios, mappers ABAC, flujo step-up, Token Exchange
├── opa/
│   ├── policies/authz.rego     # Política RBAC + ABAC (PDP)
│   ├── policies/authz_test.rego
│   └── system/                 # API de OPA solo para los PEP (mTLS), enmascarado de logs y sus pruebas
├── services/
│   ├── Dockerfile              # Imagen común (no root, rootfs de solo lectura)
│   ├── common/workload_identity.py  # SVID/SPIFFE: servidor mTLS + HTTP/2 (Hypercorn) y cliente mTLS
│   ├── common/zt_security/     # Librería PEP: JWT, PDP, Token Exchange, trazas, introspección, auditoría
│   ├── orders/main.py          # A · Pedidos
│   ├── payments/main.py        # B · Pagos (introspección RFC 7662)
│   ├── inventory/main.py       # C · Inventario
│   ├── traces/main.py          # Colector de trazas (spans M2M, lectura con ABAC)
│   └── bff/main.py             # BFF / Token Handler (Authorization Code + PKCE, cookie)
├── tests/                      # Batería de seguridad E2E (pytest)
├── scripts/                    # init-env.sh, gen-certs.sh, gen-internal-pki.sh
└── docs/trazabilidad-tfm.md    # Memoria ↔ implementación, decisiones y backlog
```

## Limitaciones conocidas del MVP

- Los datos de negocio y las trazas se guardan en memoria (se pierden al reiniciar).
- Keycloak y OPA no están instrumentados con trazas: el login se representa con los datos de
  la respuesta del IdP y cada decisión de OPA aparece como evento del servicio que la consulta.
- *Step-up*: el nivel `aal2` caduca a los 5 min para nuevos logins, pero un token ya emitido (o
  refrescado por el BFF) conserva `acr=aal2` hasta que expira (5 min); exigir además `auth_time`
  reciente en la política acotaría más la ventana.
- El *grant* de contraseña (ROPC) sigue habilitado en `tfm-web` para automatizar pruebas; nunca
  acredita el nivel `aal2`. El modo recomendado es el BFF (Authorization Code + PKCE).
- PKI interna: los SVID son estáticos (30 días) y se renuevan con `make pki`/`make up`, sin rotación
  en caliente en los servicios Python ni en Nginx; SPIRE aportaría emisión y rotación automáticas
  (atestación de cargas de trabajo) sin cambiar el modelo de identidad. Los servicios se siguen
  autenticando ante Keycloak con `client_secret`; usar el propio SVID (RFC 8705,
  `tls_client_auth`) eliminaría esos secretos.
- OPA solo negocia HTTP/1.1 sobre TLS (su servidor no anuncia `h2` por ALPN); el resto de saltos
  internos usa HTTP/2.
- Claves de firma: el gateway y los servicios guardan el JWKS hasta 300 s. Una clave nueva se
  acepta al instante (recarga por `kid` desconocido), pero una clave **retirada** (p. ej. por
  compromiso) puede seguir aceptándose hasta que caduca esa caché; acortarla o invalidarla
  activamente acotaría esa ventana.
- La revocación inmediata (introspección RFC 7662) se aplica a la operación crítica
  `payments:execute` (y, de hecho, a cada canje de token); extenderla a más rutas o añadir una
  *denylist* por `jti` queda como mejora.
