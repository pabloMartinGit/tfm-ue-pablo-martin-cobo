# mTLS + HTTP/2 hacia los upstreams internos (memoria 5.3, O4): el gateway se
# autentica con su SVID (spiffe://tfm.local/ns/poc/sa/api-gateway), solo confía
# en la CA interna y verifica que el certificado del destino corresponde al
# nombre del upstream (proxy_ssl_name = $proxy_host, SAN DNS del SVID).
proxy_ssl_certificate         /etc/nginx/svid/svid.pem;
proxy_ssl_certificate_key     /etc/nginx/svid/svid.key;
proxy_ssl_trusted_certificate /etc/nginx/svid/bundle.pem;
proxy_ssl_verify              on;
proxy_ssl_verify_depth        2;
proxy_ssl_protocols           TLSv1.3;
proxy_ssl_server_name         on;
proxy_ssl_session_reuse       on;
proxy_http_version            2;
