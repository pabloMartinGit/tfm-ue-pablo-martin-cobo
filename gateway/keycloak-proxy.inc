# Proxy hacia Keycloak (servido bajo /auth tanto interna como externamente).
# El IdP exige mTLS (KC_HTTPS_CLIENT_AUTH=required): el gateway presenta su SVID.
proxy_pass https://keycloak;
include upstream-tls.inc;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port 8443;
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;
# Keycloak envía sus propias cabeceras de seguridad (HSTS, X-Frame-Options
# SAMEORIGIN, CSP frame-ancestors) y su consola usa iframes del mismo origen
# (comprobación de cookies y estado de sesión). Declarar add_header aquí evita
# heredar el "X-Frame-Options: DENY" del servidor, que rompería el login.
add_header X-Request-ID $request_id always;
