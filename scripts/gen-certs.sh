#!/usr/bin/env bash
# Regenera el certificado autofirmado del API Gateway (TLS perimetral).
# El SAN incluye los nombres por los que se accede al gateway desde el host
# (localhost / 127.0.0.1) y desde la red Docker (api-gateway).
set -euo pipefail
cd "$(dirname "$0")/../certs"

openssl req -x509 -nodes -newkey rsa:3072 -days 365 \
  -keyout gateway.key -out gateway.crt \
  -subj "/CN=localhost/O=TFM-ZeroTrust/OU=DevSecOps" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:api-gateway" \
  -addext "basicConstraints=critical,CA:TRUE"

# El proceso nginx del contenedor (uid 101) necesita leer la clave.
chmod 644 gateway.crt gateway.key
openssl x509 -in gateway.crt -noout -subject -enddate -ext subjectAltName
