/* =============================================================================
 * Consola de demostración Zero Trust IAM.
 * Todo a mismo origen que la API y Keycloak (sin CORS). Los access tokens se
 * guardan solo en memoria; la contraseña demo, en sessionStorage.
 *
 * Para recrear con comodidad casos con varios usuarios a la vez (p. ej. BOLA:
 * alice crea, bob intenta leer) la consola usa el flujo de contraseña (ROPC) del
 * cliente público `tfm-web`, habilitado en el realm para las pruebas del PoC.
 * Ese atajo nunca acredita step-up (acr=aal1): para las acciones que exigen MFA
 * la consola ejecuta el flujo interactivo real (Authorization Code + PKCE con
 * acr_values=aal2) contra las páginas de Keycloak del mismo origen.
 * En producción el navegador no manejaría tokens (patrón BFF).
 * ========================================================================== */
(() => {
  "use strict";

  const TOKEN_PATH = "/auth/realms/tfm/protocol/openid-connect/token";
  const AUTHORIZE_PATH = "/auth/realms/tfm/protocol/openid-connect/auth";
  const LOGOUT_PATH = "/auth/realms/tfm/protocol/openid-connect/logout";
  const API = "/api/v1";
  const CLIENT_ID = "tfm-web";
  // Cliente de pruebas del realm con tokens de 5 s (no autoriza nada en la política).
  const SHORT_LIVED_CLIENT = "tfm-short-lived";
  const CLOCK_LEEWAY_S = 10;  // tolerancia de reloj del borde y de los servicios
  const BFF_ACTOR = "__bff__";

  // MFA real: usuarios con OTP obligatorio y semilla TOTP compartida del PoC. La
  // consola calcula el OTP (WebCrypto) para el grant de contraseña y el step-up
  // automático; en el flujo BFF el OTP lo introduce el usuario en Keycloak.
  const MFA_USERS = new Set(["erin", "hector"]);
  const MFA_SECRET = "TfmMfaSharedSeed2026x";
  const STRONG_ACR = new Set(["aal2"]);
  const MFA_AMR = new Set(["otp", "mfa", "totp", "hwk", "sc"]);
  // Señal de 2.º factor que acepta la política: step-up (acr=aal2) o amr con OTP.
  const isStrongAuth = (c) => STRONG_ACR.has(c.acr) || (c.amr || []).some((m) => MFA_AMR.has(m));

  // Metadatos de los usuarios del realm (solo para la interfaz; la verdad está en el token).
  const USERS = [
    { u: "alice", role: "operadora", tenant: "alpha", clearance: 3, limit: 5000, mfa: false, note: "Flujo completo · límite 5.000 €" },
    { u: "bob", role: "operador junior", tenant: "alpha", clearance: 2, limit: 1000, mfa: false, note: "No puede cancelar · límite 1.000 €" },
    { u: "carol", role: "operadora", tenant: "beta", clearance: 3, limit: 20000, mfa: false, note: "Otro tenant · límite 20.000 €" },
    { u: "dave", role: "auditor", tenant: "alpha", clearance: 2, limit: 0, mfa: false, note: "Solo lectura de todo su tenant" },
    { u: "erin", role: "admin", tenant: "alpha", clearance: 5, limit: 50000, mfa: true, note: "Admin con OTP: purga tras step-up (aal2)" },
    { u: "frank", role: "admin", tenant: "alpha", clearance: 5, limit: 50000, mfa: false, note: "Admin sin OTP: no puede elevar a aal2" },
    { u: "gina", role: "solicitante", tenant: "alpha", clearance: 2, limit: 5000, mfa: false, note: "Crea pedidos, sin rol de pagos" },
    { u: "hector", role: "supervisor", tenant: "alpha", clearance: 4, limit: 20000, mfa: true, note: "Rol compuesto: gestiona pedidos ajenos" },
    { u: "ivan", role: "suspendido", tenant: "beta", clearance: 3, limit: 5000, mfa: false, note: "Cuenta deshabilitada en el IdP", disabled: true },
  ];

  const SERVICE_COLORS = {
    "browser": "#94a3b8",
    "bff": "#f472b6",
    "api-gateway": "#818cf8",
    "orders-service": "#38bdf8",
    "inventory-service": "#34d399",
    "payments-service": "#fbbf24",
    "opa": "#a78bfa",
    "keycloak": "#fb7185",
  };

  const EDGE_REASONS = {
    missing_token: "la petición no incluye credenciales",
    malformed_token: "el token no tiene formato JWS compacto",
    missing_kid: "la cabecera del JWT no indica kid",
    unknown_kid: "el kid no existe en el JWKS de Keycloak",
    bad_signature: "la firma RS256 no es válida (claims manipulados o firmado con otra clave)",
    bad_issuer: "el emisor (iss) no es el IdP autorizado",
    bad_audience: "la audiencia (aud) no es la API (p. ej. un ID token)",
    expired: "el token ha expirado",
    not_yet_valid: "el token aún no es válido (nbf)",
    not_an_access_token: "no es un access token (typ ≠ Bearer)",
    validation_error: "error al validar el token",
  };

  const state = {
    identities: {},   // username -> { access_token, claims, exp }
    current: null,
    catalogTenant: null,
    log: [],
    seq: 0,
    lastResponseEntry: null,
    bff: null,        // userinfo de la sesión BFF (claims seguros; nunca el token)
  };

  /* ------------------------------ Utilidades ------------------------------ */
  const $ = (sel) => document.querySelector(sel);
  const el = (tag, cls, html) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const delay = (ms) => new Promise((res) => setTimeout(res, ms));
  const fmtMs = (ms) => (ms == null ? "—" : ms < 1 ? "<1 ms" : (ms < 10 ? Number(ms).toFixed(1) : Math.round(ms)) + " ms");
  const shortId = (id) => (id ? String(id).slice(0, 8) + "…" : "—");

  function b64urlEncode(str) {
    return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64urlDecode(seg) {
    seg = seg.replace(/-/g, "+").replace(/_/g, "/");
    while (seg.length % 4) seg += "=";
    return decodeURIComponent(escape(atob(seg)));
  }
  function b64urlBytes(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function decodePart(token, i) {
    try { return JSON.parse(b64urlDecode(token.split(".")[i])); } catch (e) { return {}; }
  }
  const passwordValue = () => $("#demo-password").value.trim();

  // TOTP (RFC 6238, HMAC-SHA1, 6 dígitos, 30 s) sobre el secreto en claro del PoC.
  async function totpNow(rawSecret, counter) {
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(rawSecret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    if (counter == null) counter = Math.floor(Date.now() / 1000 / 30);
    const msg = new DataView(new ArrayBuffer(8));
    msg.setUint32(4, counter);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg.buffer));
    const offset = sig[sig.length - 1] & 0x0f;
    const bin = ((sig[offset] & 0x7f) << 24) | (sig[offset + 1] << 16) | (sig[offset + 2] << 8) | sig[offset + 3];
    return String(bin % 1000000).padStart(6, "0");
  }

  // Keycloak rechaza reutilizar un código OTP dentro de su ventana: cada login con
  // OTP de un usuario usa una ventana de 30 s nueva (espera si hace falta).
  const otpWindowUsed = {};
  async function freshOtp(username) {
    let win = Math.floor(Date.now() / 1000 / 30);
    if (otpWindowUsed[username] === win) {
      await delay((30 - (Date.now() / 1000) % 30) * 1000 + 300);
      win = Math.floor(Date.now() / 1000 / 30);
    }
    otpWindowUsed[username] = win;
    return totpNow(MFA_SECRET, win);
  }

  /* ------------------------------ Autenticación --------------------------- */
  async function login(username) {
    const pw = passwordValue();
    if (!pw) {
      flashPassword();
      throw new Error("Introduce la contraseña de los usuarios demo.");
    }
    sessionStorage.setItem("tfm_demo_pw", pw);
    const form = { grant_type: "password", client_id: CLIENT_ID, username, password: pw, scope: "openid" };
    const started = performance.now();
    let r;
    // Segundo factor real: Keycloak exige el OTP a estos usuarios (aunque el grant de
    // contraseña no lo refleje en acr/amr). Si el código de esta ventana ya se usó
    // fuera de la consola (p. ej. en la página de Keycloak), se reintenta con el siguiente.
    for (let attempt = 0; attempt < (MFA_USERS.has(username) ? 2 : 1); attempt++) {
      if (MFA_USERS.has(username)) form.otp = form.totp = await freshOtp(username);
      r = await fetch(TOKEN_PATH, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(form),
      });
      if (r.ok || (r.status !== 400 && r.status !== 401)) break;  // OTP rechazado: 400 invalid_grant
    }
    const text = await r.text();
    let data;
    try { data = JSON.parse(text); } catch (e) { data = { error: "http_" + r.status }; }

    const entry = {
      kind: "auth", method: "POST", path: TOKEN_PATH, status: r.status, actor: username,
      rid: r.headers.get("X-Request-ID") || "", ms: Math.round(performance.now() - started),
    };
    if (r.ok) {
      const claims = decodePart(data.access_token, 1);
      const header = decodePart(data.access_token, 0);
      state.identities[username] = { access_token: data.access_token, claims, exp: (claims.exp || 0) * 1000 };
      entry.json = {
        token_type: data.token_type, expires_in: data.expires_in, alg: header.alg, kid: header.kid,
        sub: claims.sub, tenant_id: claims.tenant_id, roles: (claims.realm_access || {}).roles || [],
      };
    } else {
      entry.json = data;
    }
    addLog(entry);
    if (!r.ok) throw new Error(data.error_description || data.error || "HTTP " + r.status);
    return username;
  }

  // Devuelve un token válido para el usuario, renovándolo si está a punto de expirar.
  async function ensureToken(username) {
    const id = state.identities[username];
    if (id && id.exp - Date.now() > 20000) return id.access_token;
    await login(username);
    return state.identities[username].access_token;
  }

  /* ------------- Flujo interactivo con step-up (Authorization Code + PKCE) ----- */
  // Reproduce lo que hace el navegador en las páginas de login de Keycloak (mismo
  // origen): pide el nivel `acr` (acr_values), rellena usuario/contraseña y, si
  // Keycloak lo pide, el OTP; después canjea el código con PKCE (cliente público
  // tfm-web). prompt=login fuerza la reautenticación. Keycloak mantiene una sola
  // sesión SSO por navegador: si hay otra abierta (p. ej. la del BFF), se avisa.
  async function interactiveLogin(username, acr) {
    const pw = passwordValue();
    if (!pw) { flashPassword(); throw new Error("Introduce la contraseña de los usuarios demo."); }
    const verifier = b64urlBytes(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = b64urlBytes(new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    const redirectUri = location.origin + "/app/";
    const params = new URLSearchParams({
      client_id: CLIENT_ID, response_type: "code", scope: "openid", redirect_uri: redirectUri,
      state: b64urlBytes(crypto.getRandomValues(new Uint8Array(8))),
      code_challenge: challenge, code_challenge_method: "S256", prompt: "login" });
    if (acr) params.set("acr_values", acr);

    const started = performance.now();
    const steps = [];
    let r = await fetch(AUTHORIZE_PATH + "?" + params);
    for (let i = 0; i < 5 && r.ok && new URL(r.url).pathname.indexOf("/auth/") === 0; i++) {
      const doc = new DOMParser().parseFromString(await r.text(), "text/html");
      const form = doc.querySelector("form[action*='login-actions/']");
      if (!form) break;
      const action = form.getAttribute("action");
      if (doc.querySelector("input[name=password]")) {
        const shown = doc.querySelector("#kc-attempted-username");
        if (!doc.querySelector("input[name=username]") && shown && shown.textContent.trim() !== username) {
          throw new Error(`Hay una sesión SSO de «${shown.textContent.trim()}» abierta en este navegador ` +
            `(p. ej. la del BFF): ciérrala para autenticar a ${username}.`);
        }
        steps.push("contraseña");
        r = await fetch(action, { method: "POST", body: new URLSearchParams({ username, password: pw }) });
      } else if (doc.querySelector("input[name=otp]") && MFA_USERS.has(username)) {
        // Un código ya usado en su ventana se rechaza y Keycloak vuelve a pedirlo:
        // el siguiente intento usa la ventana siguiente.
        if (steps[steps.length - 1] !== "OTP") steps.push("OTP");
        r = await fetch(action, { method: "POST", body: new URLSearchParams({ otp: await freshOtp(username) }) });
      } else {
        steps.push(doc.querySelector("input[name=totpSecret]") ? "enrolar OTP" : "página inesperada");
        break;
      }
    }

    const code = new URL(r.url).searchParams.get("code");
    const entry = { kind: "auth", flow: "interactive", method: "GET", path: AUTHORIZE_PATH, actor: username,
      acr, steps, rid: "", status: code ? 200 : 401 };
    if (!code) {
      entry.ms = Math.round(performance.now() - started);
      entry.json = { error: steps.indexOf("enrolar OTP") >= 0 ? "otp_enrollment_required" : "login_incomplete", steps };
      addLog(entry);
      return { tokens: null, claims: {}, steps };
    }
    const t = await fetch(TOKEN_PATH, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: CLIENT_ID, code,
        redirect_uri: redirectUri, code_verifier: verifier }) });
    const tokens = await t.json().catch(() => ({}));
    entry.ms = Math.round(performance.now() - started);
    entry.status = t.status;
    const claims = t.ok ? decodePart(tokens.access_token, 1) : {};
    entry.json = t.ok ? { acr: claims.acr, amr: claims.amr, sub: claims.sub, tenant_id: claims.tenant_id, steps } : tokens;
    addLog(entry);
    if (!t.ok) throw new Error(tokens.error_description || tokens.error || "HTTP " + t.status);
    if (claims.preferred_username !== username) {
      throw new Error(`Keycloak autenticó a ${claims.preferred_username} (sesión SSO previa), no a ${username}.`);
    }
    return { tokens, claims, steps };
  }

  /* ---------------------------- Sesión BFF (cookie) ----------------------- */
  async function loadBffSession() {
    try {
      const r = await fetch("/bff/userinfo", { headers: { Accept: "application/json" } });
      state.bff = r.ok ? await r.json() : null;
    } catch (e) {
      state.bff = null;
    }
    renderBff();
    renderActorSelect();
    if (state.current === BFF_ACTOR && !state.bff) setCurrent(null);
  }

  function bffLogin(acr) {
    // Navegación de nivel superior: /bff/login fija la cookie y redirige a Keycloak.
    // Con acr=aal2 pide step-up: con la sesión SSO ya abierta, Keycloak solo pide el OTP.
    window.location.assign("/bff/login?return_to=/app/" + (acr ? "&acr=" + acr : ""));
  }

  async function bffLogout() {
    try {
      await fetch("/bff/logout", { method: "POST" });
    } catch (e) { /* la cookie se invalida igualmente */ }
    state.bff = null;
    if (state.current === BFF_ACTOR) state.current = null;
    renderBff();
    renderActorSelect();
    renderToken();
    addLog({ kind: "auth", method: "POST", path: "/bff/logout", status: 200, actor: "bff",
             rid: "", ms: 0, json: { logged_out: true } });
  }

  /* --------------------------------- API ---------------------------------- */
  // El token es SIEMPRE explícito: sin token no se envía cabecera Authorization.
  async function apiCall(method, path, { token = null, actor = null, tokenLabel = null, body = null } = {}) {
    const headers = {};
    if (token) headers.Authorization = "Bearer " + token;
    if (body) headers["Content-Type"] = "application/json";
    const started = performance.now();
    const r = await fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const text = await r.text();
    let json;
    try { json = text ? JSON.parse(text) : null; } catch (e) { json = text; }
    const entry = {
      kind: "api", method, path: API + path, status: r.status,
      actor: actor || "anónimo",
      tokenLabel: tokenLabel || (token ? "Bearer (access token de " + actor + ")" : "sin cabecera Authorization"),
      rid: r.headers.get("X-Request-ID") || "", ms: Math.round(performance.now() - started),
      json, requestBody: body,
    };
    addLog(entry);
    return { status: r.status, ok: r.ok, json, rid: entry.rid, entry };
  }

  const reasonsOf = (res) => (res && res.json && res.json.detail && res.json.detail.reasons) || [];
  const hasReason = (res, reason) => reasonsOf(res).indexOf(reason) >= 0;
  const edgeReason = (res) => res && res.json && res.json.edge_reason;

  /* ------------------------------ Identidades ----------------------------- */
  function renderIdentities() {
    const grid = $("#identities");
    grid.innerHTML = "";
    USERS.forEach((m) => {
      const logged = !!state.identities[m.u];
      const active = state.current === m.u;
      const card = el("div", "identity" + (active ? " active" : "") + (logged ? " logged" : "") + (m.disabled ? " disabled" : ""));
      card.innerHTML = `
        <div class="who"><span class="avatar">${m.u.slice(0, 2).toUpperCase()}</span>
          <div><div class="name">${m.u}</div><div class="role">${esc(m.role)}</div></div></div>
        <div class="chips">
          <span class="chip chip-${m.tenant}">${m.tenant}</span>
          <span class="chip">clr ${m.clearance}</span>
          <span class="chip">${m.limit ? m.limit.toLocaleString("es-ES") + " €" : "sin compras"}</span>
          <span class="chip ${m.mfa ? "chip-mfa" : "chip-nomfa"}">${m.mfa ? "MFA" : "sin MFA"}</span>
        </div>
        <div class="identity-note">${esc(m.note)}</div>
        <button class="btn btn-login">${logged ? (active ? "activo" : "usar") : "entrar"}</button>`;
      card.querySelector(".btn-login").addEventListener("click", (ev) => { ev.stopPropagation(); activate(m.u); });
      card.addEventListener("click", () => activate(m.u));
      grid.appendChild(card);
    });
  }

  async function activate(username) {
    try {
      if (!state.identities[username]) await login(username);
      setCurrent(username);
    } catch (e) {
      showError(e.message, state.log[state.log.length - 1]);
    }
  }

  // Única fuente de verdad del actor: state.current (tarjetas y selector lo cambian).
  function setCurrent(username) {
    state.current = username;
    const ident = state.identities[username];
    const tenant = username === BFF_ACTOR && state.bff ? state.bff.tenant_id
      : (ident && ident.claims ? ident.claims.tenant_id : null);
    if (state.catalogTenant && tenant !== state.catalogTenant) {
      $("#order-sku").innerHTML = '<option value="">SKU… (pulsa GET catálogo)</option>';
      state.catalogTenant = null;
    }
    renderIdentities();
    renderActorSelect();
    renderToken();
  }

  function renderActorSelect() {
    const sel = $("#actor-select");
    const logged = Object.keys(state.identities);
    const hasAny = logged.length || state.bff;
    sel.innerHTML = hasAny ? "" : '<option value="">—</option>';
    logged.forEach((u) => {
      const o = el("option");
      o.value = u;
      o.textContent = u;
      sel.appendChild(o);
    });
    if (state.bff) {
      const o = el("option");
      o.value = BFF_ACTOR;
      o.textContent = `BFF · ${state.bff.username} (cookie)`;
      sel.appendChild(o);
    }
    if (state.current) sel.value = state.current;
  }

  const claimRow = (k, v, full) => `<div class="claim${full ? " full" : ""}"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  const rolesHtml = (arr) => `<div class="roles">${arr.map((r) => `<span class="role-chip">${esc(r)}</span>`).join("") || '<span class="hint">—</span>'}</div>`;
  const cleanRealmRoles = (roles) => (roles || []).filter((r) =>
    r.indexOf("default-roles") !== 0 && ["offline_access", "uma_authorization"].indexOf(r) < 0);
  const flatResourceRoles = (ra) => { const out = []; Object.keys(ra || {}).forEach((svc) => (ra[svc].roles || []).forEach((r) => out.push(r))); return out; };

  function mfaClaimRow(c) {
    const strong = isStrongAuth(c);
    const detail = `acr <code>${esc(c.acr || "—")}</code> · amr [${esc((c.amr || []).join(", ") || "—")}]`;
    return claimRow("2.º factor (step-up)",
      `<span class="${strong ? "dec-allow" : "dec-deny"}">${strong ? "✔ acreditado" : "✘ no"}</span> <span class="muted">${detail}</span>`, true);
  }

  function renderToken() {
    const box = $("#token-inspector");
    if (state.current === BFF_ACTOR && state.bff) {
      const b = state.bff;
      box.className = "";
      box.innerHTML = `<div class="bff-token-note">🔒 En el flujo BFF el navegador <b>no</b> recibe el token: vive en el servidor.
        Estos son los claims seguros que expone <code>/bff/userinfo</code>.</div>
        <div class="claims">
        ${claimRow("usuario", esc(b.username || "—"))}
        ${claimRow("tenant_id", esc(b.tenant_id || "—"))}
        ${claimRow("clearance_level", b.clearance_level != null ? b.clearance_level : "—")}
        ${claimRow("max_transaction_limit", b.max_transaction_limit != null ? b.max_transaction_limit + " €" : "—")}
        ${mfaClaimRow(b)}
        ${claimRow("realm_access.roles", rolesHtml(cleanRealmRoles(b.realm_roles)), true)}
        ${claimRow("resource_access", rolesHtml(flatResourceRoles(b.resource_access)), true)}
        ${claimRow("sub", `<span class="mono-sm">${esc(b.sub || "—")}</span>`, true)}
      </div>`;
      return;
    }
    const id = state.current && state.identities[state.current];
    if (!id) {
      box.className = "token-empty";
      box.textContent = "Entra con un usuario para inspeccionar su JWT.";
      return;
    }
    box.className = "";
    const c = id.claims;
    box.innerHTML = `<div class="claims">
      ${claimRow("usuario", esc(c.preferred_username || "—"))}
      ${claimRow("tenant_id", esc(c.tenant_id || "—"))}
      ${claimRow("clearance_level", c.clearance_level != null ? c.clearance_level : "—")}
      ${claimRow("max_transaction_limit", c.max_transaction_limit != null ? c.max_transaction_limit + " €" : "—")}
      ${mfaClaimRow(c)}
      ${claimRow("department", esc(c.department || "—"))}
      ${claimRow("aud", esc([].concat(c.aud || []).join(", ") || "—"))}
      ${claimRow("realm_access.roles", rolesHtml(cleanRealmRoles((c.realm_access || {}).roles)), true)}
      ${claimRow("resource_access", rolesHtml(flatResourceRoles(c.resource_access)), true)}
      ${claimRow("sub", `<span class="mono-sm">${esc(c.sub || "—")}</span>`, true)}
    </div>`;
  }

  function tickExp() {
    const id = state.current && state.identities[state.current];
    const span = $("#token-exp");
    if (!id) { span.textContent = ""; return; }
    const left = Math.max(0, Math.round((id.exp - Date.now()) / 1000));
    span.textContent = left > 0 ? "expira en " + left + " s" : "expirado (se renueva al usarlo)";
  }

  /* ------------------------- Panel de respuesta --------------------------- */
  const statusClass = (code) => (code >= 200 && code < 300 ? "pill-ok" : code >= 400 && code < 500 ? "pill-warn" : "pill-danger");

  function showResponse(res) {
    const pill = $("#response-status");
    pill.className = "pill " + statusClass(res.status);
    pill.textContent = res.status;
    $("#response-body").textContent = typeof res.json === "string" ? res.json : JSON.stringify(res.json, null, 2);
    renderReasons(reasonsOf(res).concat(edgeReason(res) ? ["borde: " + edgeReason(res)] : []));
    state.lastResponseEntry = res.entry;
    $("#response-trace").hidden = !res.entry;
  }
  function showError(message, entry) {
    const pill = $("#response-status");
    pill.className = "pill pill-danger";
    pill.textContent = entry && entry.status ? entry.status : "error";
    $("#response-body").textContent = JSON.stringify({ error: message }, null, 2);
    renderReasons([]);
    state.lastResponseEntry = entry || null;
    $("#response-trace").hidden = !entry;
  }
  function renderReasons(reasons) {
    const old = document.querySelector(".response .reasons");
    if (old) old.remove();
    if (!reasons.length) return;
    const box = el("div", "reasons");
    reasons.forEach((r) => box.appendChild(el("span", "reason-chip", esc(r))));
    $("#response-body").parentNode.appendChild(box);
  }

  /* ------------------------------ Operaciones ----------------------------- */
  async function run(method, path, body) {
    const actor = state.current;
    if (!actor) { showError("Entra con un usuario primero."); return null; }
    try {
      if (actor === BFF_ACTOR) {
        // Flujo BFF: sin token en el navegador; la cookie de sesión (mismo origen)
        // viaja sola y el borde la traduce a Bearer. No se envía Authorization.
        const res = await apiCall(method, path, {
          actor: "bff", tokenLabel: "cookie de sesión BFF (el token vive en el servidor)", body });
        showResponse(res);
        return res;
      }
      const token = await ensureToken(actor);
      const res = await apiCall(method, path, { token, actor, body });
      showResponse(res);
      return res;
    } catch (e) {
      showError(e.message);
      return null;
    }
  }

  const OPS = {
    "inventory": async () => {
      const res = await run("GET", "/inventory");
      if (res && res.ok && res.json.items) {
        const sel = $("#order-sku");
        sel.innerHTML = "";
        Object.keys(res.json.items).forEach((sku) => {
          const it = res.json.items[sku];
          const o = el("option");
          o.value = sku;
          o.textContent = `${sku} · ${it.name} · ${it.unit_price} € (stock ${it.stock})`;
          sel.appendChild(o);
        });
        state.catalogTenant = res.json.tenant_id;
      }
    },
    "create-order": async () => {
      const sku = $("#order-sku").value;
      const quantity = parseInt($("#order-qty").value, 10) || 1;
      if (!sku) { showError("Pulsa «GET catálogo» y elige un SKU."); return; }
      const res = await run("POST", "/orders", { sku, quantity });
      if (res && res.ok && res.json.order_id) {
        $("#order-id").value = res.json.order_id;
        $("#cancel-id").value = res.json.order_id;
      }
    },
    "list-orders": () => run("GET", "/orders"),
    "get-order": () => {
      const id = $("#order-id").value.trim();
      if (!id) return showError("Indica un order_id.");
      return run("GET", "/orders/" + encodeURIComponent(id));
    },
    "cancel-order": () => {
      const id = $("#cancel-id").value.trim();
      if (!id) return showError("Indica un order_id.");
      return run("POST", "/orders/" + encodeURIComponent(id) + "/cancel");
    },
    "purge": () => run("DELETE", "/admin/purge"),
  };

  /* ------------------------------ Escenarios ------------------------------ */
  const step = (label, ok, extra) => ({ label, ok: !!ok, extra: extra || "" });
  const as = async (user) => ({ token: await ensureToken(user), actor: user });

  // Login dedicado (con OTP si procede) que devuelve access + refresh, sin tocar el
  // caché de identidades: necesario para la demo de revocación.
  async function rawGrant(username) {
    const form = { grant_type: "password", client_id: CLIENT_ID, username, password: passwordValue(), scope: "openid" };
    let r;
    for (let attempt = 0; attempt < (MFA_USERS.has(username) ? 2 : 1); attempt++) {
      if (MFA_USERS.has(username)) form.otp = form.totp = await freshOtp(username);
      r = await fetch(TOKEN_PATH, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(form) });
      if (r.ok || (r.status !== 400 && r.status !== 401)) break;  // OTP rechazado: 400 invalid_grant
    }
    if (!r.ok) throw new Error("no se pudo autenticar a " + username);
    return r.json();
  }
  async function keycloakLogout(refreshToken) {
    await fetch(LOGOUT_PATH, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: CLIENT_ID, refresh_token: refreshToken }) });
  }

  function forgeAlgNone(token) {
    return b64urlEncode(JSON.stringify({ alg: "none", typ: "JWT" })) + "." +
      b64urlEncode(JSON.stringify(decodePart(token, 1))) + ".";
  }
  function forgeTampered(token) {
    const p = token.split(".");
    const claims = decodePart(token, 1);
    claims.tenant_id = "tenant-corp-beta";
    claims.realm_access = { roles: ["admin"] };
    claims.clearance_level = 5;
    return p[0] + "." + b64urlEncode(JSON.stringify(claims)) + "." + p[2];
  }
  async function newOrder(user, sku, quantity) {
    return apiCall("POST", "/orders", { ...(await as(user)), body: { sku, quantity: quantity || 1 } });
  }
  // Traza completa: está el span raíz y cada llamada saliente con respuesta tiene ya el
  // span del destino (cada servicio exporta sus spans por su cuenta, sin orden garantizado).
  const traceComplete = (data) => {
    const spans = (data && data.spans) || [];
    if (!spans.some((s) => s.attrs && s.attrs.via === "api-gateway")) return false;
    const parents = new Set(spans.map((s) => s.parent_id));
    return spans.every((s) => s.events.every((e) => e.type !== "call" || e.status == null || parents.has(e.span_id)));
  };

  // Los spans llegan al colector de forma asíncrona: se reintenta hasta que la traza
  // está completa. Devuelve {status, data}.
  // token = null -> se lee con la cookie de sesión BFF (el borde la traduce a Bearer).
  async function fetchTraceComplete(rid, token, attempts) {
    let status = 404;
    let data = null;
    for (let i = 0; i < (attempts || 24); i++) {
      const r = await fetch(API + "/traces/" + rid, { headers: token ? { Authorization: "Bearer " + token } : {} });
      status = r.status;
      data = await r.json().catch(() => null);
      if (status !== 404 && !(status === 200 && !traceComplete(data))) break;
      await delay(250);
    }
    return { status, data };
  }

  async function readTrace(rid, user, attempts) {
    for (let i = 0; i < (attempts || 1); i++) {
      const res = await apiCall("GET", "/traces/" + rid, await as(user));
      if (res.status !== 404) return res;
      await delay(300);
    }
    return { status: 404, json: null };
  }

  const SCENARIOS = [
    {
      group: "Borde · PEP perimetral (API Gateway)", id: "ST-01", title: "Petición sin token",
      desc: "Llamada sin cabecera Authorization (aunque haya un usuario activo).",
      run: async () => {
        const r = await apiCall("GET", "/orders", { actor: "anónimo" });
        return [step("el gateway responde 401", r.status === 401, "HTTP " + r.status),
          step("motivo en el borde: missing_token", edgeReason(r) === "missing_token")];
      },
    },
    {
      group: "Borde · PEP perimetral (API Gateway)", id: "ST-03", title: "Escalada por manipulación",
      desc: "Se altera el payload (tenant, roles, clearance) sin volver a firmar.",
      run: async () => {
        const { token } = await as("alice");
        const r = await apiCall("GET", "/orders", { token: forgeTampered(token), actor: "forjado", tokenLabel: "token de alice con claims manipulados" });
        return [step("el gateway responde 401", r.status === 401, "HTTP " + r.status),
          step("motivo: bad_signature", edgeReason(r) === "bad_signature")];
      },
    },
    {
      group: "Borde · PEP perimetral (API Gateway)", id: "ST-04", title: "Ataque alg:none",
      desc: "Token sin firma (alg:none) con los claims de alice.",
      run: async () => {
        const { token } = await as("alice");
        const r = await apiCall("GET", "/orders", { token: forgeAlgNone(token), actor: "forjado", tokenLabel: "token forjado con alg:none" });
        return [step("el gateway responde 401", r.status === 401, "HTTP " + r.status),
          step("motivo: alg_not_allowed:none", edgeReason(r) === "alg_not_allowed:none")];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-09", title: "Flujo de pedido correcto",
      desc: "alice compra 1×SKU-001: pedido → reserva → pago → confirmación.",
      run: async () => {
        const r = await newOrder("alice", "SKU-001");
        return [step("POST /orders devuelve 201", r.status === 201, "HTTP " + r.status),
          step("estado = confirmed", r.json && r.json.status === "confirmed")];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-16", title: "Límite de importe (ABAC)",
      desc: "alice intenta comprar SKU-003 (9.000 € > su límite de 5.000 €).",
      run: async () => {
        const r = await newOrder("alice", "SKU-003");
        return [step("se deniega con 403", r.status === 403, "HTTP " + r.status),
          step("motivo: amount_exceeds_limit", hasReason(r, "amount_exceeds_limit"))];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-31", title: "Mismo rol, distinto atributo",
      desc: "alice y bob son operadores; un portátil (1.200 €) supera el límite de bob (1.000 €).",
      run: async () => {
        const rb = await newOrder("bob", "SKU-001");
        const ra = await newOrder("alice", "SKU-001");
        return [step("bob: 403 amount_exceeds_limit", rb.status === 403 && hasReason(rb, "amount_exceeds_limit"), "HTTP " + rb.status),
          step("alice: 201", ra.status === 201, "HTTP " + ra.status)];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-10", title: "Objeto ajeno (BOLA)",
      desc: "alice crea un pedido; bob (mismo tenant) intenta leerlo.",
      run: async () => {
        const o = await newOrder("alice", "SKU-002");
        const r = await apiCall("GET", "/orders/" + (o.json && o.json.order_id), await as("bob"));
        return [step("bob recibe 403", r.status === 403, "HTTP " + r.status),
          step("motivo: not_resource_owner", hasReason(r, "not_resource_owner"))];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-12", title: "Aislamiento entre tenants",
      desc: "carol (tenant beta) intenta leer un pedido de alice (tenant alpha).",
      run: async () => {
        const o = await newOrder("alice", "SKU-002");
        const r = await apiCall("GET", "/orders/" + (o.json && o.json.order_id), await as("carol"));
        return [step("carol recibe 403", r.status === 403, "HTTP " + r.status),
          step("motivo: tenant_mismatch", hasReason(r, "tenant_mismatch"))];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-13", title: "Asignación masiva ignorada",
      desc: "alice inyecta owner_id, status y amount en el cuerpo del pedido.",
      run: async () => {
        const r = await apiCall("POST", "/orders", {
          ...(await as("alice")),
          body: { sku: "SKU-002", quantity: 1, owner_id: "attacker", tenant_id: "tenant-corp-beta", status: "paid", amount: 0.01 },
        });
        const ok = r.status === 201 && r.json;
        return [step("se crea (201) ignorando los campos", r.status === 201, "HTTP " + r.status),
          step("owner_id ≠ attacker", ok && r.json.owner_id !== "attacker"),
          step("importe real, no 0,01 €", ok && r.json.amount !== 0.01, ok ? r.json.amount + " €" : "")];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-14", title: "Auditor de solo lectura",
      desc: "dave (auditor) puede listar pedidos del tenant pero no crear.",
      run: async () => {
        const rl = await apiCall("GET", "/orders", await as("dave"));
        const rc = await newOrder("dave", "SKU-001");
        return [step("GET /orders permitido (200)", rl.status === 200, "HTTP " + rl.status),
          step("POST /orders denegado: missing_role", rc.status === 403 && hasReason(rc, "missing_role"), "HTTP " + rc.status)];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-17", title: "Función admin (BFLA)",
      desc: "Purga con el grant de contraseña: frank (admin sin OTP), hector (supervisor, clearance 4) y erin (admin con OTP, pero sin step-up).",
      run: async () => {
        const rf = await apiCall("DELETE", "/admin/purge", await as("frank"));
        const rh = await apiCall("DELETE", "/admin/purge", await as("hector"));
        const re = await apiCall("DELETE", "/admin/purge", await as("erin"));
        return [step("frank → 403 mfa_required", rf.status === 403 && hasReason(rf, "mfa_required"), "HTTP " + rf.status),
          step("hector → 403 missing_role + insufficient_clearance",
            rh.status === 403 && hasReason(rh, "missing_role") && hasReason(rh, "insufficient_clearance"), "HTTP " + rh.status),
          step("erin → 403 mfa_required: su token ROPC es aal1 (ver ST-46)", re.status === 403 && hasReason(re, "mfa_required"), "HTTP " + re.status)];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-28", title: "Autorización en cada salto",
      desc: "gina puede crear pedidos pero no tiene rol de pagos: lo deniega el servicio de Pagos.",
      run: async () => {
        const r = await newOrder("gina", "SKU-002");
        return [step("el pedido se deniega (403)", r.status === 403, "HTTP " + r.status),
          step("motivo: missing_role (en Pagos)", hasReason(r, "missing_role")),
          step("ver la traza: permitido en Pedidos e Inventario, denegado en Pagos", true, "pincha en la llamada")];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-29", title: "Supervisor (RBAC jerárquico)",
      desc: "hector (supervisor ⊃ operator) lee y cancela un pedido de alice.",
      run: async () => {
        const o = await newOrder("alice", "SKU-002");
        const id = o.json && o.json.order_id;
        const rr = await apiCall("GET", "/orders/" + id, await as("hector"));
        const rc = await apiCall("POST", "/orders/" + id + "/cancel", await as("hector"));
        const hc = (state.identities.hector || {}).claims || {};
        const roles = (hc.realm_access || {}).roles || [];
        return [step("token con supervisor + operator heredado", roles.indexOf("supervisor") >= 0 && roles.indexOf("operator") >= 0),
          step("lee el pedido ajeno (200)", rr.status === 200, "HTTP " + rr.status),
          step("lo cancela (200)", rc.status === 200 && rc.json && rc.json.status === "cancelled", "HTTP " + rc.status)];
      },
    },
    {
      group: "Autorización · PDP (OPA)", id: "ST-30", title: "Junior sin permiso de cancelación",
      desc: "bob crea su propio pedido pero no tiene el rol orders:cancel.",
      run: async () => {
        const o = await newOrder("bob", "SKU-002");
        const rc = await apiCall("POST", "/orders/" + (o.json && o.json.order_id) + "/cancel", await as("bob"));
        return [step("bob crea su pedido (201)", o.status === 201, "HTTP " + o.status),
          step("cancelar → 403 missing_role", rc.status === 403 && hasReason(rc, "missing_role"), "HTTP " + rc.status)];
      },
    },
    {
      group: "Identidad · IdP (Keycloak)", id: "ST-32", title: "Cuenta suspendida (RU-05)",
      desc: "ivan está deshabilitado en Keycloak: no puede obtener ningún token.",
      run: async () => {
        try {
          await login("ivan");
          return [step("Keycloak no emite token", false, "se emitió un token")];
        } catch (e) {
          const last = state.log.filter((x) => x.kind === "auth" && x.actor === "ivan").pop() || {};
          return [step("Keycloak rechaza la autenticación (400)", last.status === 400, "HTTP " + last.status),
            step("motivo: Account disabled", /disabled/i.test(e.message), e.message)];
        }
      },
    },
    {
      group: "Trazabilidad · RU-06", id: "ST-33", title: "Trazas con control de acceso",
      desc: "alice ve la traza de su pedido; bob no puede; el auditor dave sí.",
      run: async () => {
        const o = await newOrder("alice", "SKU-002");
        await fetchTraceComplete(o.rid, (await as("alice")).token);
        const mine = await readTrace(o.rid, "alice", 1);
        const services = new Set(((mine.json && mine.json.spans) || []).map((s) => s.service));
        const other = await readTrace(o.rid, "bob", 1);
        const audit = await readTrace(o.rid, "dave", 1);
        return [step("alice lee su traza (200)", mine.status === 200, "HTTP " + mine.status),
          step("recorre pedidos, inventario y pagos",
            services.has("orders-service") && services.has("inventory-service") && services.has("payments-service"),
            Array.from(services).join(", ")),
          step("bob: 403 not_resource_owner", other.status === 403 && hasReason(other, "not_resource_owner"), "HTTP " + other.status),
          step("dave (auditor): 200", audit.status === 200, "HTTP " + audit.status)];
      },
    },
    {
      group: "Propagación · Token Exchange y mTLS", id: "ST-51", title: "Audiencia reducida en cada salto",
      desc: "El token de alice solo vale para la API de borde y Pedidos; Pedidos lo canjea (RFC 8693) por uno por destino.",
      run: async () => {
        const { token } = await as("alice");
        const edgeAud = [].concat(decodePart(token, 1).aud || []);
        const o = await newOrder("alice", "SKU-002");
        const { data } = await fetchTraceComplete(o.rid, token);
        const spans = (data && data.spans) || [];
        const exchanged = new Set();
        spans.forEach((s) => s.events.forEach((e) => { if (e.type === "token_exchange" && e.ok) exchanged.add(e.audience); }));
        const delegatedOk = spans.filter((s) => s.service !== "orders-service").every((s) =>
          s.events.filter((e) => e.type === "authn" && e.ok).every((e) => e.kind === "delegated" && e.aud === s.service && e.azp === "orders-service"));
        return [step("pedido creado (201)", o.status === 201, "HTTP " + o.status),
          step("token de borde sin audiencias internas", edgeAud.indexOf("payments-service") < 0 && edgeAud.indexOf("inventory-service") < 0, edgeAud.join(", ")),
          step("Pedidos canjea un token por destino", exchanged.has("inventory-service") && exchanged.has("payments-service"), Array.from(exchanged).join(", ")),
          step("cada servicio recibe aud = él mismo, azp = orders-service", spans.length > 1 && delegatedOk)];
      },
    },
    {
      group: "Propagación · Token Exchange y mTLS", id: "ST-53", title: "mTLS + HTTP/2 interno",
      desc: "Cada salto (gateway → Pedidos → Inventario/Pagos) va por TLS 1.3 con autenticación mutua (SVID SPIFFE) y HTTP/2.",
      run: async () => {
        const o = await newOrder("alice", "SKU-002");
        const { data } = await fetchTraceComplete(o.rid, (await as("alice")).token);
        const spans = (data && data.spans) || [];
        const expected = { "orders-service": "api-gateway", "inventory-service": "orders-service", "payments-service": "orders-service" };
        const tr = (s) => (s.attrs && s.attrs.transport) || {};
        return [step("pedido creado (201)", o.status === 201, "HTTP " + o.status),
          step("todos los saltos en HTTP/2", spans.length > 1 && spans.every((s) => tr(s).protocol === "HTTP/2"), spans.map((s) => tr(s).protocol).join(", ")),
          step("todos por TLS 1.3", spans.length > 1 && spans.every((s) => tr(s).tls === "TLSv1.3")),
          step("llamante autenticado por su SVID (SPIFFE ID)", spans.length > 1 && spans.every((s) =>
            tr(s).peer === "spiffe://tfm.local/ns/poc/sa/" + expected[s.service]), "ver la traza")];
      },
    },
    {
      group: "Propagación · Token Exchange y mTLS", id: "ST-27", title: "Cabeceras de identidad falsas",
      desc: "alice inyecta X-Forwarded-Client-Cert / X-SPIFFE-ID de orders-service: la identidad viene del handshake mTLS, no de cabeceras.",
      run: async () => {
        const { token } = await as("alice");
        const r = await fetch(API + "/orders", { method: "POST", headers: {
          Authorization: "Bearer " + token, "Content-Type": "application/json",
          "X-Forwarded-Client-Cert": "URI=spiffe://tfm.local/ns/poc/sa/orders-service",
          "X-SPIFFE-ID": "spiffe://tfm.local/ns/poc/sa/orders-service" },
          body: JSON.stringify({ sku: "SKU-002", quantity: 1 }) });
        const rid = r.headers.get("X-Request-ID") || "";
        addLog({ kind: "api", method: "POST", path: API + "/orders", status: r.status, actor: "alice",
          tokenLabel: "Bearer de alice + cabeceras de identidad falsas", rid, ms: 0, json: await r.json().catch(() => null) });
        const { data } = await fetchTraceComplete(rid, token);
        const root = ((data && data.spans) || []).find((s) => s.attrs && s.attrs.via === "api-gateway");
        const peer = root && root.attrs.transport ? root.attrs.transport.peer : null;
        return [step("la petición se procesa normal (201)", r.status === 201, "HTTP " + r.status),
          step("el servicio ve al gateway como llamante (mTLS)", peer === "spiffe://tfm.local/ns/poc/sa/api-gateway", peer || "—")];
      },
    },
    {
      group: "Ciclo de vida · expiración, claves y abuso", id: "ST-54", title: "Token expirado",
      desc: "Token de 5 s (cliente de pruebas tfm-short-lived): supera el borde mientras vale y, al caducar (+10 s de tolerancia de reloj), el gateway lo rechaza. Tarda ~16 s.",
      run: async () => {
        const r = await fetch(TOKEN_PATH, {
          method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ grant_type: "password", client_id: SHORT_LIVED_CLIENT, username: "alice", password: passwordValue() }) });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.error_description || data.error || "HTTP " + r.status);
        const c = decodePart(data.access_token, 1);
        const fresh = await apiCall("GET", "/inventory", { token: data.access_token, actor: "alice (5 s)", tokenLabel: "Bearer de vida corta (tfm-short-lived)" });
        await delay(Math.max(0, (c.exp + CLOCK_LEEWAY_S + 1.5) * 1000 - Date.now()));
        const expired = await apiCall("GET", "/inventory", { token: data.access_token, actor: "alice (caducado)", tokenLabel: "el mismo Bearer, ya caducado" });
        return [step("token de vida corta (exp − iat = 5 s)", c.exp - c.iat === 5, (c.exp - c.iat) + " s"),
          step("mientras vale supera el borde; lo deniega el PDP (cliente sin permisos)", fresh.status === 403 && hasReason(fresh, "not_a_user_token"), "HTTP " + fresh.status),
          step("caducado: 401 en el borde (expired)", expired.status === 401 && edgeReason(expired) === "expired", "HTTP " + expired.status)];
      },
    },
    {
      group: "Ciclo de vida · expiración, claves y abuso", id: "ST-56", title: "Clave de firma ajena (kid / jku)",
      desc: "Token firmado con una clave RSA generada en el navegador, con un kid que Keycloak no publica y una cabecera jku hacia un JWKS del atacante.",
      run: async () => {
        const { token } = await as("alice");
        const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, false, ["sign", "verify"]);
        const header = { alg: "RS256", typ: "JWT", kid: "attacker-" + b64urlBytes(crypto.getRandomValues(new Uint8Array(4))),
          jku: "https://attacker.example/.well-known/jwks.json" };
        const input = b64urlEncode(JSON.stringify(header)) + "." + b64urlEncode(JSON.stringify(decodePart(token, 1)));
        const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input)));
        const r = await apiCall("GET", "/inventory", { token: input + "." + b64urlBytes(sig), actor: "forjado",
          tokenLabel: "token firmado con una clave del atacante (kid y jku propios)" });
        return [step("el gateway responde 401", r.status === 401, "HTTP " + r.status),
          step("motivo: unknown_kid (solo confía en el JWKS de Keycloak; no sigue jku)", edgeReason(r) === "unknown_kid", edgeReason(r) || "—")];
      },
    },
    {
      group: "Ciclo de vida · expiración, claves y abuso", id: "ST-58", title: "Rate limiting en el login",
      desc: "40 peticiones simultáneas al endpoint de credenciales: el gateway (10 r/s por IP, ráfaga 20) corta el exceso con 429 antes de llegar a Keycloak.",
      run: async () => {
        const started = performance.now();
        const statuses = await Promise.all(Array.from({ length: 40 }, () => fetch(TOKEN_PATH, {
          method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ grant_type: "password", client_id: "rate-limit-probe", username: "x", password: "y" }),
        }).then((x) => x.status).catch(() => 0)));
        const limited = statuses.filter((x) => x === 429).length;
        const reached = statuses.filter((x) => x === 400 || x === 401).length;
        addLog({ kind: "auth", flow: "burst", method: "POST", path: TOKEN_PATH, status: 429, actor: "ráfaga ×40",
          rid: "", ms: Math.round(performance.now() - started), json: { burst: 40, rate_limited: limited, reached_idp: reached } });
        await delay(3000);  // el cupo se recupera antes de seguir con otros escenarios
        return [step("el exceso recibe 429 en el borde", limited >= 10, limited + " de 40"),
          step("lo permitido llega a Keycloak (cliente inexistente)", reached > 0, reached + " de 40")];
      },
    },
    {
      group: "Sesión · MFA y revocación", id: "ST-46", title: "Step-up MFA (acr=aal2)",
      desc: "erin eleva su autenticación en el flujo interactivo (contraseña + OTP) y entonces sí puede purgar; frank no puede elevar sin enrolar un OTP.",
      run: async () => {
        const ropc = await apiCall("DELETE", "/admin/purge", await as("erin"));
        const up = await interactiveLogin("erin", "aal2");
        const c = up.claims;
        const rp = up.tokens
          ? await apiCall("DELETE", "/admin/purge", { token: up.tokens.access_token, actor: "erin (aal2)", tokenLabel: "Bearer (token step-up aal2 de erin)" })
          : { status: "—" };
        // No dejar abierta la sesión SSO del navegador (evita conflictos con el BFF).
        if (up.tokens) await keycloakLogout(up.tokens.refresh_token);
        const fr = await interactiveLogin("frank", "aal2");
        if (fr.tokens) await keycloakLogout(fr.tokens.refresh_token);
        return [step("erin con el grant de contraseña (aal1) → 403 mfa_required", ropc.status === 403 && hasReason(ropc, "mfa_required"), "HTTP " + ropc.status),
          step("step-up: Keycloak pide contraseña + OTP", up.steps.join(" + ") === "contraseña + OTP", up.steps.join(" + ")),
          step("token con acr=aal2 y amr con otp", c.acr === "aal2" && (c.amr || []).indexOf("otp") >= 0, "acr=" + (c.acr || "—") + " amr=[" + (c.amr || []).join(",") + "]"),
          step("erin (aal2) purga (200)", rp.status === 200, "HTTP " + rp.status),
          step("frank: Keycloak exige enrolar un OTP, sin token aal2", !fr.tokens && fr.steps.indexOf("enrolar OTP") >= 0, fr.steps.join(" + "))];
      },
    },
    {
      group: "Sesión · MFA y revocación", id: "ST-40", title: "Revocación inmediata (RFC 7662)",
      desc: "alice paga; tras cerrar su sesión, el mismo token (aún no expirado) ya no se puede canjear ni usar en Pagos.",
      run: async () => {
        const session = await rawGrant("alice");
        const before = await apiCall("POST", "/orders", {
          token: session.access_token, actor: "alice", body: { sku: "SKU-002", quantity: 1 } });
        await keycloakLogout(session.refresh_token);
        const after = await apiCall("POST", "/orders", {
          token: session.access_token, actor: "alice (revocado)", body: { sku: "SKU-002", quantity: 1 } });
        return [step("el pago inicial funciona (201)", before.status === 201, "HTTP " + before.status),
          step("tras el logout: 401 token_revoked",
            after.status === 401 && (after.json && after.json.detail || {}).error === "token_revoked", "HTTP " + after.status),
          step("el canje (Token Exchange) y la introspección cortan un token no expirado pero revocado", after.status === 401)];
      },
    },
  ];

  function renderScenarios() {
    const root = $("#scenarios");
    root.innerHTML = "";
    let grid = null;
    let group = null;
    SCENARIOS.forEach((sc) => {
      if (sc.group !== group) {
        group = sc.group;
        root.appendChild(el("div", "scenario-group", esc(group)));
        grid = el("div", "scenario-grid");
        root.appendChild(grid);
      }
      const btn = el("button", "scenario");
      btn.innerHTML = `
        <div class="st-head"><span class="st-title">${esc(sc.title)}</span>
          <span class="badge badge-run" hidden>…</span></div>
        <div class="st-id">${sc.id}</div>
        <div class="st-desc">${esc(sc.desc)}</div>
        <div class="st-result"><div class="st-steps"></div></div>`;
      btn.addEventListener("click", () => runScenario(sc, btn));
      sc.button = btn;
      grid.appendChild(btn);
    });
  }

  async function runScenario(sc, btn) {
    if (!passwordValue()) { flashPassword(); return false; }
    btn.disabled = true;
    btn.classList.add("done");
    const badge = btn.querySelector(".badge");
    badge.hidden = false;
    badge.className = "badge badge-run";
    badge.textContent = "ejecutando…";
    const stepsBox = btn.querySelector(".st-steps");
    stepsBox.innerHTML = "";
    let allOk = false;
    try {
      const steps = await sc.run();
      allOk = steps.every((s) => s.ok);
      steps.forEach((s) => {
        stepsBox.appendChild(el("div", "st-step " + (s.ok ? "step-ok" : "step-fail"),
          `<span class="mark">${s.ok ? "✔" : "✘"}</span><span>${esc(s.label)}${s.extra ? ` <span class="st-extra">(${esc(s.extra)})</span>` : ""}</span>`));
      });
      badge.className = "badge " + (allOk ? "badge-pass" : "badge-fail");
      badge.textContent = allOk ? "PASS" : "FALLO";
    } catch (e) {
      badge.className = "badge badge-fail";
      badge.textContent = "ERROR";
      stepsBox.appendChild(el("div", "st-step step-fail", `<span class="mark">✘</span><span>${esc(e.message)}</span>`));
    }
    btn.disabled = false;
    renderIdentities();
    renderActorSelect();
    return allOk;
  }

  async function runAll() {
    if (!passwordValue()) { flashPassword(); return; }
    const button = $("#run-all");
    const summary = $("#scenario-summary");
    button.disabled = true;
    let passed = 0;
    for (const sc of SCENARIOS) {
      summary.hidden = false;
      summary.className = "pill pill-muted";
      summary.textContent = `${sc.id}…`;
      if (await runScenario(sc, sc.button)) passed++;
    }
    summary.className = "pill " + (passed === SCENARIOS.length ? "pill-ok" : "pill-warn");
    summary.textContent = `${passed}/${SCENARIOS.length} PASS`;
    button.disabled = false;
  }

  /* ------------------------------- Registro ------------------------------- */
  function addLog(entry) {
    entry.id = ++state.seq;
    state.log.push(entry);
    const log = $("#log");
    const empty = log.querySelector(".log-empty");
    if (empty) empty.remove();
    const cls = entry.status >= 500 ? "c5" : entry.status >= 400 ? "c4" : "c2";
    const row = el("div", "log-row");
    row.title = "Ver la traza de esta llamada";
    row.innerHTML = `
      <span class="kind kind-${entry.kind}">${entry.kind === "auth" ? "IdP" : "API"}</span>
      <span class="method">${entry.method}</span>
      <span class="code ${cls}">${entry.status}</span>
      <span class="path">${esc(entry.path)}</span>
      <span class="who">${esc(entry.actor || "—")}</span>
      <span class="rid">${esc(shortId(entry.rid))}</span>
      <span class="go">traza ›</span>`;
    row.addEventListener("click", () => openTrace(entry));
    log.insertBefore(row, log.firstChild);
  }

  /* ------------------------------ Panel de traza -------------------------- */
  function openDrawer() {
    $("#trace-drawer").classList.add("open");
    $("#trace-drawer").setAttribute("aria-hidden", "false");
    $("#drawer-backdrop").classList.add("open");
  }
  function closeDrawer() {
    $("#trace-drawer").classList.remove("open");
    $("#trace-drawer").setAttribute("aria-hidden", "true");
    $("#drawer-backdrop").classList.remove("open");
  }

  const svcChip = (name) => `<span class="svc-chip" style="--svc:${SERVICE_COLORS[name] || "#94a3b8"}">${esc(name)}</span>`;
  const pill = (status) => `<span class="pill ${statusClass(status)}">${status}</span>`;

  function renderSummary(entry, extra) {
    $("#drawer-summary").innerHTML = `
      <div class="ds-line"><span class="method">${entry.method}</span> <code>${esc(entry.path)}</code> ${pill(entry.status)}</div>
      <div class="ds-meta">
        <span>actor: <b>${esc(entry.actor || "—")}</b></span>
        <span>extremo a extremo: <b>${fmtMs(entry.ms)}</b></span>
        <span title="${esc(entry.rid)}">trace-id: <code>${esc(entry.rid || "—")}</code></span>
        ${extra || ""}
      </div>`;
  }

  function isEdgeRejection(entry) {
    const j = entry.json;
    return (entry.status === 401 && j && typeof j === "object" && j.error === "unauthorized" && !j.detail) ||
      entry.status === 429;
  }

  async function openTrace(entry) {
    renderSummary(entry);
    $("#drawer-body").innerHTML = '<div class="t-loading">Consultando la traza…</div>';
    openDrawer();
    if (entry.path && entry.path.indexOf("/bff") === 0) {
      $("#drawer-body").innerHTML = `${hop("browser", "api-gateway", entry.method + " " + entry.path, "cookie de sesión")}
        ${hop("api-gateway", "bff", "proxy")}
        <div class="t-info">El BFF gestiona la sesión (Authorization Code + PKCE). Los tokens viven en el
        servidor; el navegador solo maneja la cookie <code>__Host-tfm_session</code>. Resultado: ${pill(entry.status)}
        ${entry.json && entry.json.error ? " · " + esc(entry.json.error) : ""}</div>`;
      return;
    }
    if (entry.kind === "auth") return renderAuthTrace(entry);
    if (isEdgeRejection(entry)) return renderEdgeTrace(entry);
    if (entry.path.indexOf(API + "/traces/") === 0) {
      $("#drawer-body").innerHTML = `${hop("browser", "api-gateway", entry.method + " " + entry.path, entry.tokenLabel)}
        <div class="t-info">Las consultas al colector de trazas no se instrumentan (el colector no genera spans de sí mismo).
        Resultado: ${pill(entry.status)} ${entry.json && entry.json.detail && entry.json.detail.reasons ? "motivos: " + entry.json.detail.reasons.map(esc).join(", ") : ""}</div>`;
      return;
    }
    const viaBff = entry.actor === "bff" || (!state.identities[entry.actor] && state.current === BFF_ACTOR && state.bff);
    const reader = viaBff ? "bff" : (state.identities[entry.actor] ? entry.actor : state.current);
    if (!reader) {
      $("#drawer-body").innerHTML = '<div class="t-info">Inicia sesión con algún usuario para consultar trazas.</div>';
      return;
    }
    try {
      const token = viaBff ? null : await ensureToken(reader);
      const { status, data: raw } = await fetchTraceComplete(entry.rid, token);
      const data = raw || {};
      if (status === 200) return renderTrace(entry, data);
      if (status === 403) {
        $("#drawer-body").innerHTML = `<div class="t-info">El PDP deniega a <b>${esc(reader)}</b> la lectura de esta traza
          (<code>traces:read</code>): ${((data.detail || {}).reasons || []).map((x) => `<span class="reason-chip">${esc(x)}</span>`).join(" ")}</div>`;
        return;
      }
      $("#drawer-body").innerHTML = `<div class="t-info">No hay spans registrados para esta petición (HTTP ${status}).</div>`;
    } catch (e) {
      $("#drawer-body").innerHTML = `<div class="t-info">No se pudo consultar la traza: ${esc(e.message)}</div>`;
    }
  }

  function hop(from, to, what, detail) {
    return `<div class="t-hop">${svcChip(from)}<span class="arrow">→</span>${svcChip(to)}
      <span class="t-hop-what"><code>${esc(what)}</code>${detail ? `<span class="t-hop-detail">${esc(detail)}</span>` : ""}</span></div>`;
  }
  const back = (status, text) => `<div class="t-back"><span class="arrow">◀</span> ${pill(status)} ${text}</div>`;

  function renderInteractiveTrace(entry) {
    const j = entry.json || {};
    let body = hop("browser", "api-gateway", "GET " + entry.path,
      `Authorization Code + PKCE (S256) · client_id=tfm-web · prompt=login${entry.acr ? " · acr_values=" + entry.acr : ""}`);
    body += hop("api-gateway", "keycloak", "flujo «tfm browser step-up» (niveles LoA)", "mTLS · SVID del gateway");
    body += `<div class="t-node kc"><div class="t-node-head">${svcChip("keycloak")} Formularios del IdP</div>
      ${(entry.steps || []).map((x) => `<div class="t-ev"><span class="ico ${x === "enrolar OTP" ? "bad" : "ok"}">${x === "enrolar OTP" ? "✘" : "✔"}</span>${
        x === "contraseña" ? "Nivel 1 (aal1): usuario y contraseña" : x === "OTP" ? "Nivel 2 (aal2): código OTP (TOTP)"
          : x === "enrolar OTP" ? "Keycloak exige enrolar un 2.º factor: sin él no hay nivel aal2" : esc(x)}</div>`).join("")}
    </div>`;
    if (entry.status === 200) {
      body += `<div class="t-node kc"><div class="t-node-head">${svcChip("keycloak")} Canje del código (PKCE)</div>
        <div class="t-ev"><span class="ico ok">✔</span>acr <code>${esc(j.acr)}</code> · amr [${esc((j.amr || []).join(", "))}] · tenant ${esc(j.tenant_id || "")}</div></div>`;
      body += back(200, "Token de nivel " + esc(j.acr) + " (solo en memoria; se cierra la sesión SSO al terminar el escenario)");
    } else {
      body += back(entry.status, esc(j.error || "sin token"));
    }
    $("#drawer-body").innerHTML = body;
  }

  function renderBurstTrace(entry) {
    const j = entry.json || {};
    $("#drawer-body").innerHTML = `${hop("browser", "api-gateway", j.burst + " × POST " + entry.path, "client_id=rate-limit-probe · simultáneas")}
      <div class="t-node gw"><div class="t-node-head">${svcChip("api-gateway")} Rate limiting del endpoint de credenciales · 10 r/s por IP, ráfaga 20</div>
        <div class="t-ev"><span class="ico bad">✘</span><b>${esc(j.rate_limited)}</b> peticiones cortadas con 429: no llegan a Keycloak</div>
        <div class="t-ev"><span class="ico ok">✔</span><b>${esc(j.reached_idp)}</b> dentro del cupo, reenviadas a Keycloak (que las rechaza: cliente inexistente)</div></div>
      <div class="t-foot">Complementa el bloqueo por fuerza bruta de Keycloak (cuenta a cuenta), que la batería pytest comprueba (ST-57).</div>`;
  }

  function renderAuthTrace(entry) {
    if (entry.flow === "interactive") return renderInteractiveTrace(entry);
    if (entry.flow === "burst") return renderBurstTrace(entry);
    const j = entry.json || {};
    let body = hop("browser", "api-gateway", "POST " + entry.path,
      "grant_type=password · client_id=tfm-web · username=" + entry.actor);
    if (entry.status === 429) {
      body += `<div class="t-node gw"><div class="t-node-head">${svcChip("api-gateway")} Endpoint de credenciales con rate limiting</div>
        <div class="t-ev"><span class="ico bad">✘</span>Límite de peticiones superado (anti fuerza bruta): la petición no llega a Keycloak.</div></div>`;
      $("#drawer-body").innerHTML = body + back(entry.status, "Too Many Requests");
      return;
    }
    body += `<div class="t-node gw"><div class="t-node-head">${svcChip("api-gateway")} Endpoint de credenciales · límite 10 r/s</div>
      <div class="t-ev"><span class="ico">⇢</span>Proxy hacia Keycloak (<code>/auth</code>), sin validar JWT: aquí se emite.</div></div>`;
    body += hop("api-gateway", "keycloak", "realm tfm · cliente público tfm-web");
    if (entry.status === 200) {
      body += `<div class="t-node kc"><div class="t-node-head">${svcChip("keycloak")} Autenticación correcta</div>
        <div class="t-ev"><span class="ico ok">✔</span>Access token firmado ${esc(j.alg || "")} · kid <code>${esc(shortId(j.kid))}</code> · expira en ${esc(j.expires_in)} s</div>
        <div class="t-ev"><span class="ico">🪪</span>sub <code>${esc(shortId(j.sub))}</code> · tenant ${esc(j.tenant_id)} · roles ${(j.roles || []).map((r) => `<span class="role-chip">${esc(r)}</span>`).join(" ")}</div></div>`;
      body += back(200, "Token entregado al navegador (se guarda solo en memoria)");
    } else {
      body += `<div class="t-node kc"><div class="t-node-head">${svcChip("keycloak")} Autenticación rechazada</div>
        <div class="t-ev"><span class="ico bad">✘</span><code>${esc(j.error || "")}</code> · ${esc(j.error_description || "")}</div></div>`;
      body += back(entry.status, "Sin token: la identidad no puede usarse en ningún servicio");
    }
    body += '<div class="t-foot">Keycloak no está instrumentado con trazas: los datos proceden de la respuesta del IdP.</div>';
    $("#drawer-body").innerHTML = body;
  }

  function renderEdgeTrace(entry) {
    const reason = entry.json && entry.json.edge_reason;
    let body = hop("browser", "api-gateway", entry.method + " " + entry.path, "Authorization: " + (entry.tokenLabel || "—"));
    if (entry.status === 429) {
      body += `<div class="t-node gw"><div class="t-node-head">${svcChip("api-gateway")} Rate limiting</div>
        <div class="t-ev"><span class="ico bad">✘</span>Límite de peticiones superado.</div></div>`;
    } else {
      body += `<div class="t-node gw"><div class="t-node-head">${svcChip("api-gateway")} PEP de borde · validación del JWT (njs)</div>
        <div class="t-ev"><span class="ico bad">✘</span>JWT rechazado${reason ? `: <code>${esc(reason)}</code>` : ""}</div>
        ${reason ? `<div class="t-ev"><span class="ico">ℹ</span>${esc(EDGE_REASONS[reason] || (reason.indexOf("alg_not_allowed") === 0 ? "algoritmo no permitido (lista blanca: RS256)" : reason))}</div>` : ""}
      </div>`;
    }
    body += back(entry.status, "La petición no llega a ningún microservicio (0 spans internos).");
    $("#drawer-body").innerHTML = body;
  }

  function describeEvent(ev) {
    switch (ev.type) {
      case "authn": {
        const kind = { service: "de servicio", delegated: "delegado" }[ev.kind] || "de usuario";
        if (!ev.ok) return ["bad", `Token ${kind} rechazado: <code>${esc(ev.reason)}</code>`];
        if (ev.kind === "service") return ["ok", `Token M2M de <b>${esc(ev.azp)}</b> verificado <span class="muted">(client_credentials)</span>`];
        if (ev.kind === "delegated") {
          return ["ok", `Token delegado verificado: <b>${esc(ev.username)}</b> · aud <code>${esc(ev.aud)}</code> · delegado por <b>${esc(ev.azp)}</b> <span class="muted">(RFC 8693)</span>`];
        }
        return ["ok", `Token de usuario verificado: <b>${esc(ev.username)}</b> · ${esc(ev.tenant_id || "sin tenant")} · aud <code>${esc([].concat(ev.aud || []).join(", "))}</code> <span class="muted">(firma RS256, iss, exp)</span>`];
      }
      case "token_exchange":
        if (ev.ok === false) {
          return ["bad", `${svcChip("keycloak")} Token Exchange para <code>${esc(ev.audience)}</code> rechazado: ${esc(ev.error || ev.status || "")}`];
        }
        return ev.cached
          ? ["key", `Token delegado para <code>${esc(ev.audience)}</code> reutilizado (misma petición)`]
          : ["key", `${svcChip("keycloak")} Token Exchange (RFC 8693) → aud <code>${esc(ev.audience)}</code> <span class="muted">${fmtMs(ev.ms)}</span>`];
      case "pdp": {
        const amount = ev.attrs && ev.attrs.amount != null ? ` · ${ev.attrs.amount} ${esc(ev.attrs.currency || "")}` : "";
        const reasons = (ev.reasons || []).map((r) => `<span class="reason-chip">${esc(r)}</span>`).join(" ");
        return [ev.decision === "allow" ? "ok" : "bad",
          `${svcChip("opa")} <code>${esc(ev.action)}</code>${amount} → <span class="${ev.decision === "allow" ? "dec-allow" : "dec-deny"}">${esc(String(ev.decision).toUpperCase())}</span>
           <span class="muted">${fmtMs(ev.ms)}</span> ${reasons}`];
      }
      case "m2m_token":
        return ev.cached
          ? ["key", `Token M2M de <b>${esc(ev.client_id)}</b> reutilizado de caché`]
          : ["key", `${svcChip("keycloak")} token M2M <code>client_credentials</code> para <b>${esc(ev.client_id)}</b> <span class="muted">${fmtMs(ev.ms)}</span>`];
      case "introspection":
        if (ev.active == null) return ["bad", `${svcChip("keycloak")} Introspección (RFC 7662) no disponible: se deniega (fail-closed)`];
        return [ev.active ? "ok" : "bad", `${svcChip("keycloak")} Introspección (RFC 7662): token ${ev.active
          ? "activo" : "<b>revocado</b>"}${ev.cached ? " (caché)" : ""} <span class="muted">${fmtMs(ev.ms)}</span>`];
      case "note":
        return ["note", esc(ev.message)];
      default:
        return ["", esc(ev.type)];
    }
  }

  const transportLabel = (span) => {
    const t = (span && span.attrs && span.attrs.transport) || {};
    return t.peer ? `mTLS ${t.tls || ""} · ${t.protocol || ""} · SVID del gateway` : "";
  };

  function renderTrace(entry, data) {
    const spans = data.spans || [];
    const callIds = new Set();
    spans.forEach((s) => s.events.forEach((e) => { if (e.type === "call") callIds.add(e.span_id); }));
    const childOf = {};
    spans.forEach((s) => { childOf[s.parent_id] = s; });
    const roots = spans.filter((s) => !callIds.has(s.parent_id));
    const root = roots[0];

    // --- Cascada temporal (waterfall)
    const edgeMs = root && root.attrs.edge_elapsed_ms ? root.attrs.edge_elapsed_ms : 0;
    const t0 = Math.min(...spans.map((s) => s.start)) - edgeMs;
    const t1 = Math.max(...spans.map((s) => s.end || s.start));
    const total = Math.max(1, t1 - t0);
    const rows = [];
    if (root && root.attrs.via === "api-gateway") {
      rows.push({ label: "api-gateway", name: "PEP de borde", start: t0, end: t1, depth: 0, status: entry.status, subs: [] });
    }
    const walk = (s, depth) => {
      const subs = s.events.filter((e) => (e.type === "pdp" || ((e.type === "m2m_token" || e.type === "token_exchange") && !e.cached)) && e.ms)
        .map((e) => ({ start: e.t - e.ms, end: e.t, color: SERVICE_COLORS[e.type === "pdp" ? "opa" : "keycloak"] }));
      rows.push({ label: s.service, name: s.name, start: s.start, end: s.end || s.start, depth, status: s.status, subs });
      s.events.forEach((e) => { if (e.type === "call" && childOf[e.span_id]) walk(childOf[e.span_id], depth + 1); });
    };
    roots.forEach((r) => walk(r, rows.length && rows[0].label === "api-gateway" ? 1 : 0));

    const pct = (v) => ((v - t0) / total) * 100;
    let wf = '<div class="wf">';
    rows.forEach((r) => {
      const color = SERVICE_COLORS[r.label] || "#94a3b8";
      wf += `<div class="wf-row">
        <div class="wf-label" style="padding-left:${r.depth * 12}px" title="${esc(r.name)}"><span class="dot" style="background:${color}"></span>${esc(r.label)}</div>
        <div class="wf-track"><div class="wf-bar" style="left:${pct(r.start)}%;width:${Math.max(0.8, pct(r.end) - pct(r.start))}%;background:${color}"></div>
          ${r.subs.map((x) => `<div class="wf-sub" style="left:${pct(x.start)}%;width:${Math.max(0.6, pct(x.end) - pct(x.start))}%;background:${x.color}"></div>`).join("")}</div>
        <div class="wf-dur">${fmtMs(r.end - r.start)} ${r.status ? `<span class="code ${r.status >= 400 ? "c4" : "c2"}">${r.status}</span>` : ""}</div>
      </div>`;
    });
    wf += `</div><div class="wf-legend">${["api-gateway", "orders-service", "inventory-service", "payments-service", "opa", "keycloak"]
      .map((n) => `<span><span class="dot" style="background:${SERVICE_COLORS[n]}"></span>${n === "opa" ? "OPA (PDP)" : n === "keycloak" ? "Keycloak (Token Exchange)" : n}</span>`).join("")}</div>`;

    // --- Recorrido paso a paso
    let steps = hop("browser", "api-gateway", entry.method + " " + entry.path, "Authorization: " + (entry.tokenLabel || "—"));
    if (root && root.attrs.edge) {
      const e = root.attrs.edge;
      steps += `<div class="t-node gw"><div class="t-node-head">${svcChip("api-gateway")} PEP de borde · validación del JWT (njs)</div>
        <div class="t-ev"><span class="ico ok">✔</span>JWT verificado: ${esc(e.alg || "")} · kid <code>${esc(shortId(e.kid))}</code> · JWKS ${e.jwks === "cache" ? "en caché" : "descargado de Keycloak"} · ${esc(e.ms)} ms</div>
        <div class="t-ev"><span class="ico">⇢</span>Reenvía el token de usuario y <code>traceparent 00-${esc(shortId(data.trace_id))}-…-01</code> · ${fmtMs(root.attrs.edge_elapsed_ms)} en el borde</div></div>`;
      steps += hop("api-gateway", root.service, root.name, transportLabel(root));
    }
    const renderSpan = (s) => {
      const t = s.attrs.transport || {};
      let html = `<div class="t-node" style="--svc:${SERVICE_COLORS[s.service] || "#94a3b8"}">
        <div class="t-node-head">${svcChip(s.service)} <code>${esc(s.name)}</code> ${s.status ? pill(s.status) : ""} <span class="muted">${fmtMs((s.end || s.start) - s.start)}</span></div>`;
      if (t.peer) {
        html += `<div class="t-ev"><span class="ico ok">🔐</span><span>mTLS ${esc(t.tls || "")} · ${esc(t.protocol || "")} · llamante <code>${esc(t.peer)}</code></span></div>`;
      }
      s.events.forEach((ev) => {
        if (ev.type === "call") {
          const child = childOf[ev.span_id];
          html += `<div class="t-call">${hop(s.service, child ? child.service : ev.host, ev.method + " " + ev.path,
            `token delegado (aud=${ev.audience || "—"}) · mTLS · ${ev.protocol || "HTTP"} · traceparent`)}
            ${child ? renderSpan(child) : `<div class="t-ev"><span class="ico bad">✘</span>Sin span del destino ${ev.error ? "(" + esc(ev.error) + ")" : ""}</div>`}
            <div class="t-back small"><span class="arrow">◀</span> ${ev.status ? pill(ev.status) : "—"} <span class="muted">${fmtMs(ev.ms)}</span></div></div>`;
          return;
        }
        const [icon, text] = describeEvent(ev);
        const ico = { ok: "✔", bad: "✘", key: "🔑", note: "•" }[icon] || "·";
        html += `<div class="t-ev"><span class="ico ${icon}">${ico}</span><span>${text}</span></div>`;
      });
      return html + "</div>";
    };
    roots.forEach((r) => { steps += renderSpan(r); });
    steps += back(entry.status, "Respuesta devuelta al navegador");

    renderSummary(entry, `<span>spans: <b>${spans.length}</b></span>`);
    $("#drawer-body").innerHTML = `<h3 class="t-section">Cascada temporal</h3>${wf}<h3 class="t-section">Recorrido de la llamada</h3>${steps}`;
  }

  /* -------------------------------- Salud --------------------------------- */
  async function checkHealth() {
    const pillEl = $("#health-pill");
    try {
      // Sin token el borde debe responder 401: significa que el gateway está vivo.
      const r = await fetch(API + "/orders");
      pillEl.className = "pill " + (r.status === 401 || r.ok ? "pill-ok" : "pill-warn");
      pillEl.textContent = r.status === 401 || r.ok ? "gateway activo" : "gateway HTTP " + r.status;
    } catch (e) {
      pillEl.className = "pill pill-danger";
      pillEl.textContent = "sin conexión";
    }
  }

  function flashPassword() {
    const input = $("#demo-password");
    input.focus();
    input.classList.add("invalid");
    setTimeout(() => input.classList.remove("invalid"), 1200);
  }

  /* --------------------------------- BFF UI ------------------------------- */
  function renderBff() {
    const box = $("#bff-status");
    if (!box) return;
    if (state.bff && state.bff.authenticated) {
      const b = state.bff;
      const strong = isStrongAuth(b);
      box.innerHTML = `
        <div class="bff-session">
          <div class="bff-line"><span class="avatar">${(b.username || "?").slice(0, 2).toUpperCase()}</span>
            <div><div class="name">${esc(b.username)}</div>
              <div class="role">${esc((b.realm_roles || []).join(", ") || "—")}</div></div>
            <span class="chip ${strong ? "chip-mfa" : "chip-nomfa"}">${esc(b.acr || "—")}${strong ? " · 2FA ✔" : ""}</span></div>
          <div class="bff-actions">
            <button class="btn btn-sm" id="bff-use">operar con esta sesión</button>
            ${strong ? "" : '<button class="btn btn-sm" id="bff-stepup" title="acr_values=aal2: Keycloak solo pedirá el OTP">elevar a aal2 (OTP)</button>'}
            <button class="btn btn-ghost btn-sm" id="bff-logout">cerrar sesión</button>
          </div>
          ${strong ? "" : `<div class="bff-otp" id="bff-otp">${MFA_USERS.has(b.username)
            ? "Código OTP demo para el step-up: <code>…</code>"
            : "Este usuario no tiene OTP: Keycloak le pedirá enrolar uno para llegar a aal2."}</div>`}
        </div>`;
      $("#bff-use").addEventListener("click", () => setCurrent(BFF_ACTOR));
      $("#bff-logout").addEventListener("click", bffLogout);
      if (!strong) $("#bff-stepup").addEventListener("click", () => bffLogin("aal2"));
      if (!strong && MFA_USERS.has(b.username)) refreshOtpHint();
    } else {
      box.innerHTML = `
        <p class="bff-intro">Inicia sesión con el flujo <b>Authorization Code + PKCE</b>. El token se
          guarda en el servidor; el navegador solo recibe una cookie <code>HttpOnly · Secure ·
          SameSite=Strict</code>. Ideal frente a XSS (no hay token en JS). El login es de nivel
          <code>aal1</code>; las acciones críticas piden elevar a <code>aal2</code> (step-up con OTP).</p>
        <button class="btn" id="bff-login">Entrar con Keycloak (BFF)</button>`;
      $("#bff-login").addEventListener("click", () => bffLogin());
    }
  }

  // Ayuda para la demo manual del step-up en el BFF: el código OTP vigente (semilla
  // compartida del PoC; en un entorno real saldría de la app de autenticación).
  async function refreshOtpHint() {
    const box = document.getElementById("bff-otp");
    if (!box || !state.bff || !MFA_USERS.has(state.bff.username)) return;
    const left = 30 - Math.floor(Date.now() / 1000) % 30;
    box.innerHTML = `Código OTP demo para el step-up: <code>${await totpNow(MFA_SECRET)}</code> <span class="muted">(${left} s)</span>`;
  }

  function showBffError(code) {
    const messages = {
      step_up_failed: "Keycloak no acreditó el nivel aal2 pedido (step-up no completado)",
      invalid_login_state: "el estado de login no coincide (posible CSRF o cookie caducada)",
      token_exchange_failed: "no se pudo canjear el código en Keycloak",
      invalid_id_token: "el ID token no superó la validación",
      authorization_error: "Keycloak devolvió un error de autorización",
    };
    addLog({ kind: "auth", method: "GET", path: "/bff/callback", status: 400, actor: "bff",
             rid: "", ms: 0, json: { error: code, detail: messages[code] || code } });
  }

  /* ------------------------------- Arranque ------------------------------- */
  function init() {
    const saved = sessionStorage.getItem("tfm_demo_pw");
    if (saved) $("#demo-password").value = saved;
    $("#demo-password").addEventListener("change", (ev) => sessionStorage.setItem("tfm_demo_pw", ev.target.value.trim()));
    $("#actor-select").addEventListener("change", (ev) => {
      const v = ev.target.value;
      if (v === BFF_ACTOR ? state.bff : state.identities[v]) setCurrent(v);
    });

    // Retorno del BFF: limpiar el parámetro de error/estado de la URL.
    const params = new URLSearchParams(window.location.search);
    if (params.get("bff_error")) showBffError(params.get("bff_error"));
    if (params.has("bff_error")) history.replaceState(null, "", "/app/");
    document.querySelectorAll("[data-op]").forEach((b) =>
      b.addEventListener("click", () => { const fn = OPS[b.getAttribute("data-op")]; if (fn) fn(); }));
    $("#response-trace").addEventListener("click", () => { if (state.lastResponseEntry) openTrace(state.lastResponseEntry); });
    $("#run-all").addEventListener("click", runAll);
    $("#clear-log").addEventListener("click", () => {
      state.log = [];
      $("#log").innerHTML = '<div class="log-empty">Sin actividad.</div>';
    });
    $("#drawer-close").addEventListener("click", closeDrawer);
    $("#drawer-backdrop").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeDrawer(); });
    $("#log").innerHTML = '<div class="log-empty">Sin actividad.</div>';

    renderIdentities();
    renderScenarios();
    renderActorSelect();
    renderBff();
    loadBffSession();
    checkHealth();
    setInterval(tickExp, 1000);
    setInterval(refreshOtpHint, 1000);
    setInterval(checkHealth, 15000);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
