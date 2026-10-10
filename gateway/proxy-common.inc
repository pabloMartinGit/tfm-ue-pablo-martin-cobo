# Cabeceras comunes hacia los microservicios internos (mTLS + HTTP/2)
include upstream-tls.inc;
proxy_set_header Host $host;
# Flujo BFF: el njs resuelve la cookie a un token y lo inyecta ($final_auth);
# flujo directo: se reenvía el Bearer del cliente.
proxy_set_header Authorization $final_auth;
proxy_set_header X-Request-ID $request_id;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto https;
# La identidad del gateway ante los servicios la aporta el handshake mTLS, no una
# cabecera: no hay cabeceras de identidad interna que un cliente pueda inyectar.
# La cookie de sesión BFF se consume en el borde: no se propaga a los servicios.
proxy_set_header Cookie "";
# Trazabilidad: contexto W3C (trace-id = X-Request-ID) y veredicto del PEP de borde.
# Se sobrescriben siempre: un cliente externo no puede inyectar ni reutilizar trazas.
proxy_set_header traceparent "00-$request_id-$gateway_span_id-01";
proxy_set_header tracestate "";
proxy_set_header X-Edge-Auth $edge_auth;
proxy_set_header X-Edge-Elapsed $request_time;
