// =============================================================================
// Validación perimetral en el API Gateway (PEP de borde). Se invoca por
// auth_request y devuelve 204 (permite) o 401 (deniega). Soporta dos flujos:
//
//   1. Bearer directo   -> el cliente envía "Authorization: Bearer <JWT>".
//   2. Sesión BFF        -> el navegador solo tiene la cookie __Host-tfm_session;
//      el njs pide el access token al BFF (cookie -> token) y, tras validarlo,
//      lo inyecta hacia el upstream (X-Resolved-Auth). El navegador nunca ve el
//      token (patrón Token Handler, memoria 7.1.2.1).
//
// En ambos casos se realiza la MISMA validación criptográfica (firma RS256 con
// la clave del JWKS, iss, aud, exp, nbf, typ), preservando el PEP de borde.
//
// El JWKS y el endpoint cookie -> token se consultan a través del servidor
// interno del propio gateway (127.0.0.1:8081), que los reenvía por mTLS: el IdP
// y el BFF solo aceptan conexiones con un SVID y ngx.fetch no puede presentarlo.
// =============================================================================

const JWKS_URL = process.env.OIDC_JWKS_URL;
const ISSUER = process.env.OIDC_ISSUER;
const AUDIENCE = process.env.OIDC_AUDIENCE;
const BFF_TOKEN_URL = process.env.BFF_TOKEN_URL || '';
const ALLOWED_ALGS = ['RS256'];
// Tolerancia de desfase de reloj, igual que en los servicios (zt_security): 10 s.
const LEEWAY_SECONDS = 10;
// Recarga forzada del JWKS por kid desconocido: como mucho una cada 10 s, para que
// tokens con kid inventados no conviertan el gateway en un amplificador contra el IdP.
const FORCED_REFRESH_COOLDOWN_MS = 10000;
const EXPOSE_REASONS = process.env.EXPOSE_DENY_REASONS === 'true';

function b64urlDecode(segment) {
    return Buffer.from(segment, 'base64url');
}

async function loadJwks(forceRefresh) {
    const cache = ngx.shared.jwks;
    let raw = forceRefresh ? undefined : cache.get('jwks');
    if (!raw) {
        const response = await ngx.fetch(JWKS_URL);
        if (!response.ok) {
            throw new Error('jwks_fetch_failed status=' + response.status);
        }
        raw = await response.text();
        cache.set('jwks', raw);
    }
    return JSON.parse(raw);
}

// Devuelve {key, source}: source indica de dónde salió el JWKS usado:
//   cache     -> caché compartida (hasta 300 s)
//   fetched   -> descargado porque la caché estaba vacía o había caducado
//   refreshed -> recargado a la fuerza por un kid desconocido (rotación de claves)
//   cooldown  -> kid desconocido, pero la última recarga forzada es demasiado reciente
async function findKey(kid) {
    const match = (jwks) => jwks.keys.find((k) =>
        k.kid === kid && k.kty === 'RSA' && (k.use === undefined || k.use === 'sig'));
    const cache = ngx.shared.jwks;
    const source = cache.get('jwks') ? 'cache' : 'fetched';
    let key = match(await loadJwks(false));
    if (key) {
        return { key, source };
    }
    // kid desconocido: posible rotación de claves en el IdP -> refrescar una vez.
    const now = Date.now();
    const last = Number(cache.get('jwks_forced_at') || 0);
    if (now - last < FORCED_REFRESH_COOLDOWN_MS) {
        return { key: undefined, source: 'cooldown' };
    }
    cache.set('jwks_forced_at', String(now));
    key = match(await loadJwks(true));
    return { key, source: 'refreshed' };
}

function audienceMatches(aud) {
    return Array.isArray(aud) ? aud.indexOf(AUDIENCE) !== -1 : aud === AUDIENCE;
}

// Núcleo de validación (sin acoplar a la petición): devuelve {ok, reason|jose,claims,jwks}.
async function verifyToken(token) {
    // La firma puede venir vacía (p. ej. alg:none): se admite en el parseo para
    // registrar el motivo exacto; la lista blanca de algoritmos lo rechaza después.
    const parts = String(token).match(/^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/);
    if (!parts) {
        return { ok: false, reason: 'malformed_token' };
    }
    let jose;
    try { jose = JSON.parse(b64urlDecode(parts[1]).toString()); } catch (e) { return { ok: false, reason: 'malformed_token' }; }
    if (ALLOWED_ALGS.indexOf(jose.alg) === -1) {
        return { ok: false, reason: 'alg_not_allowed:' + jose.alg };
    }
    if (!jose.kid) {
        return { ok: false, reason: 'missing_kid' };
    }
    const found = await findKey(jose.kid);
    const jwk = found.key;
    if (!jwk) {
        return { ok: false, reason: 'unknown_kid' };
    }
    const key = await crypto.subtle.importKey(
        'jwk', { kty: 'RSA', n: jwk.n, e: jwk.e },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const signatureOk = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' }, key,
        b64urlDecode(parts[3]), Buffer.from(parts[1] + '.' + parts[2]));
    if (!signatureOk) {
        return { ok: false, reason: 'bad_signature' };
    }
    let claims;
    try { claims = JSON.parse(b64urlDecode(parts[2]).toString()); } catch (e) { return { ok: false, reason: 'malformed_token' }; }
    const now = Math.floor(Date.now() / 1000);
    if (claims.iss !== ISSUER) {
        return { ok: false, reason: 'bad_issuer' };
    }
    if (!audienceMatches(claims.aud)) {
        return { ok: false, reason: 'bad_audience' };
    }
    if (typeof claims.exp !== 'number' || claims.exp < now - LEEWAY_SECONDS) {
        return { ok: false, reason: 'expired' };
    }
    if (typeof claims.nbf === 'number' && claims.nbf > now + LEEWAY_SECONDS) {
        return { ok: false, reason: 'not_yet_valid' };
    }
    if (claims.typ !== 'Bearer') {
        return { ok: false, reason: 'not_an_access_token' };
    }
    return { ok: true, jose, claims, jwks: found.source };
}

function finishReject(r, t0, reason) {
    r.headersOut['X-Edge-Auth'] = 'rejected;reason=' + reason + ';ms=' + (Date.now() - t0);
    r.warn('jwt_rejected reason=' + reason + ' request_id=' + r.variables.request_id);
    r.return(401);
}

function finishAllow(r, t0, res, via, token, inject) {
    r.headersOut['X-Edge-Auth'] = 'verified;via=' + via + ';alg=' + res.jose.alg +
        ';kid=' + res.jose.kid + ';jwks=' + res.jwks + ';ms=' + (Date.now() - t0);
    if (inject) {
        r.headersOut['X-Resolved-Auth'] = 'Bearer ' + token;
    }
    r.return(204);
}

const SESSION_COOKIE_RE = /(?:^|;\s*)(?:__Host-)?tfm_session=/;

// Punto de entrada de las rutas /api: acepta Bearer directo o sesión BFF (cookie).
async function apiAuth(r) {
    const t0 = Date.now();
    try {
        const auth = r.headersIn['Authorization'] || '';
        const bearer = auth.match(/^Bearer (.+)$/);
        if (bearer) {
            const res = await verifyToken(bearer[1]);
            return res.ok ? finishAllow(r, t0, res, 'bearer', bearer[1], false) : finishReject(r, t0, res.reason);
        }
        const cookie = r.headersIn['Cookie'] || '';
        if (BFF_TOKEN_URL && SESSION_COOKIE_RE.test(cookie)) {
            let resp;
            try {
                resp = await ngx.fetch(BFF_TOKEN_URL, { headers: { Cookie: cookie } });
            } catch (e) {
                return finishReject(r, t0, 'bff_unreachable');
            }
            if (!resp.ok) {
                return finishReject(r, t0, 'bff_session_invalid');
            }
            const token = (await resp.text()).trim();
            const res = await verifyToken(token);
            return res.ok ? finishAllow(r, t0, res, 'bff', token, true) : finishReject(r, t0, res.reason);
        }
        return finishReject(r, t0, auth ? 'malformed_token' : 'missing_token');
    } catch (e) {
        r.error('jwt_validation_error ' + e.message + ' request_id=' + r.variables.request_id);
        r.headersOut['X-Edge-Auth'] = 'rejected;reason=validation_error;ms=' + (Date.now() - t0);
        r.return(401);
    }
}

// Respuesta 401 del borde. Con EXPOSE_DENY_REASONS=true (solo PoC) incluye el motivo.
function unauthorized(r) {
    const body = { error: 'unauthorized', request_id: r.variables.request_id };
    const edge = r.variables.edge_auth || '';
    const m = edge.match(/reason=([^;]+)/);
    if (EXPOSE_REASONS && m) {
        body.edge_reason = m[1];
    }
    r.headersOut['Content-Type'] = 'application/json';
    r.headersOut['WWW-Authenticate'] = 'Bearer realm="tfm"';
    r.return(401, JSON.stringify(body));
}

// Sujeto declarado en el token (sin verificar) para enriquecer el access log.
function claimedSubject(r) {
    try {
        const header = r.headersIn['Authorization'] || '';
        const parts = header.split(' ')[1].split('.');
        return JSON.parse(b64urlDecode(parts[1]).toString()).sub || '-';
    } catch (e) {
        return '-';
    }
}

export default { apiAuth, unauthorized, claimedSubject };
