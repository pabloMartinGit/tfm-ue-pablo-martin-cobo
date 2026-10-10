#!/usr/bin/env bash
# Genera .env a partir de .env.example con secretos aleatorios (no sobrescribe uno existente).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo ".env ya existe; no se modifica."
  exit 0
fi

secret() { openssl rand -hex 24; }

sed -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(secret)/" \
    -e "s/^KC_ADMIN_PASSWORD=.*/KC_ADMIN_PASSWORD=$(secret)/" \
    -e "s/^TFM_DEMO_PASSWORD=.*/TFM_DEMO_PASSWORD=Tfm-$(openssl rand -hex 6)-Demo2026!/" \
    -e "s/^ORDERS_CLIENT_SECRET=.*/ORDERS_CLIENT_SECRET=$(secret)/" \
    -e "s/^PAYMENTS_CLIENT_SECRET=.*/PAYMENTS_CLIENT_SECRET=$(secret)/" \
    -e "s/^INVENTORY_CLIENT_SECRET=.*/INVENTORY_CLIENT_SECRET=$(secret)/" \
    -e "s/^BFF_CLIENT_SECRET=.*/BFF_CLIENT_SECRET=$(secret)/" \
    .env.example > .env
# TFM_MFA_SECRET se mantiene fijo (Base32 válido) para poder calcular el OTP en las pruebas.
chmod 600 .env
echo ".env generado. Contraseña de los usuarios demo: $(grep ^TFM_DEMO_PASSWORD .env | cut -d= -f2)"
