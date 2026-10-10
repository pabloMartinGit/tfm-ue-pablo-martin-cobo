#!/usr/bin/env bash
# =============================================================================
# PKI interna del plano de datos (mTLS este-oeste, memoria 5.3 y O4).
#
# Emite una CA propia del dominio de confianza y un SVID X.509 por carga de
# trabajo con el formato de SPIFFE (URI SAN spiffe://<dominio>/ns/<ns>/sa/<nombre>),
# de modo que migrar a SPIRE solo cambiaría el emisor, no el modelo de identidad.
#
# Idempotente: solo (re)emite lo que falta, lo que caduca en menos de
# RENEW_BEFORE_DAYS o lo que ya no firma la CA vigente. `make up` lo ejecuta en
# cada arranque, que hace las veces de rotación (SPIRE rotaría en caliente).
#
# Salida (certs/internal/, no versionada):
#   ca/ca.pem, ca/ca.key         CA del dominio (la clave nunca se monta)
#   <carga>/svid.pem, svid.key   certificado y clave de la carga de trabajo
#   <carga>/bundle.pem           CA de confianza (trust bundle)
# Cada contenedor monta SOLO su directorio: ninguno ve la clave de otro.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${PKI_DIR:-certs/internal}
TRUST_DOMAIN=${SPIFFE_TRUST_DOMAIN:-tfm.local}
NAMESPACE=${SPIFFE_NAMESPACE:-poc}
CA_DAYS=${CA_DAYS:-365}
SVID_DAYS=${SVID_DAYS:-30}
RENEW_BEFORE_DAYS=${RENEW_BEFORE_DAYS:-7}
# SAN adicionales para todas las cargas (solo para arneses locales, p. ej. IP:127.0.0.1)
EXTRA_SAN=${SVID_EXTRA_SAN:-}
# security-tests representa un contenedor ajeno con identidad válida pero sin
# permisos (pruebas de movimiento lateral).
WORKLOADS=${WORKLOADS:-"api-gateway orders-service payments-service inventory-service trace-service bff opa keycloak security-tests"}

renew_window=$((RENEW_BEFORE_DAYS * 86400))
umask 022
mkdir -p "$OUT/ca"

# --- CA del dominio de confianza --------------------------------------------
ca_changed=0
if [ ! -s "$OUT/ca/ca.pem" ] || ! openssl x509 -in "$OUT/ca/ca.pem" -noout -checkend $((30 * 86400)) >/dev/null; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/ca/ca.key" 2>/dev/null
  chmod 600 "$OUT/ca/ca.key"
  openssl req -x509 -new -key "$OUT/ca/ca.key" -sha256 -days "$CA_DAYS" -out "$OUT/ca/ca.pem" \
    -subj "/O=TFM Zero Trust/CN=TFM Workload CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectAltName=URI:spiffe://${TRUST_DOMAIN}"
  ca_changed=1
  echo "CA emitida: spiffe://${TRUST_DOMAIN} (válida ${CA_DAYS} días)"
fi

# --- SVID por carga de trabajo ------------------------------------------------
issue() {
  local name=$1 dir="$OUT/$1"
  local spiffe_id="spiffe://${TRUST_DOMAIN}/ns/${NAMESPACE}/sa/${name}"
  local san="URI:${spiffe_id},DNS:${name}${EXTRA_SAN:+,${EXTRA_SAN}}"
  local ext
  ext=$(mktemp)
  mkdir -p "$dir"
  cat > "$ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyAgreement
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${san}
EOF
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/svid.key" 2>/dev/null
  openssl req -new -key "$dir/svid.key" -subj "/O=TFM Zero Trust/OU=workload/CN=${name}" -out "$dir/svid.csr"
  openssl x509 -req -in "$dir/svid.csr" -CA "$OUT/ca/ca.pem" -CAkey "$OUT/ca/ca.key" \
    -CAcreateserial -sha256 -days "$SVID_DAYS" -extfile "$ext" -out "$dir/svid.pem" 2>/dev/null
  rm -f "$dir/svid.csr" "$ext"
  cp "$OUT/ca/ca.pem" "$dir/bundle.pem"
  # Los procesos de los contenedores no se ejecutan con el uid del anfitrión: la
  # clave debe ser legible por ellos. El aislamiento lo da el montaje por carga
  # (cada contenedor solo ve su propio directorio, en solo lectura).
  chmod 644 "$dir/svid.pem" "$dir/svid.key" "$dir/bundle.pem"
  echo "SVID emitido: ${spiffe_id} (válido ${SVID_DAYS} días)"
}

for name in $WORKLOADS; do
  dir="$OUT/$name"
  if [ "$ca_changed" = 1 ] || [ ! -s "$dir/svid.pem" ] || [ ! -s "$dir/svid.key" ] \
     || ! openssl x509 -in "$dir/svid.pem" -noout -checkend "$renew_window" >/dev/null \
     || ! openssl verify -CAfile "$OUT/ca/ca.pem" "$dir/svid.pem" >/dev/null 2>&1; then
    issue "$name"
  fi
done
rm -f "$OUT/ca/ca.srl"
