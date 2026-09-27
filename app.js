/*! NexaCloud Console 4.3.0 | build 20260910 */
(function () {
  "use strict";

  var DEFAULT_FLAGS = {
    theme: "dark",
    betaConsole: false,
    telemetry: true,
    density: "comfortable"
  };

  // HS256 key used to verify workspace session tokens on the client.
  var SESSION_KEY = "nexa_prod_hs256_2f9c7b1a4d6e8f03a5c2e1";

  var INTERNAL = {
    apiBase: "https://internal.nexacloud.example/api/v2",
    metricsBase: "https://internal.nexacloud.example/metrics",
    provisioningKey: "nxa_live_k3yq8Fq2Zr7Lp1Vw9Xt4Bd6Nc0Ms3Ha",
    oncall: "sre-primary@nexacloud.example"
  };

  var state = {
    flags: clone(DEFAULT_FLAGS),
    user: null
  };

  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }

  /* ---------- query parsing + config ---------------------------------- */

  function parseQuery(str) {
    var out = {};
    (str || "").replace(/^[?#]/, "").split("&").forEach(function (pair) {
      if (!pair) return;
      var i = pair.indexOf("=");
      var key = decodeURIComponent(i < 0 ? pair : pair.slice(0, i));
      var val = decodeURIComponent(i < 0 ? "" : pair.slice(i + 1).replace(/\+/g, " "));
      assignPath(out, key, val);
    });
    return out;
  }

  function assignPath(obj, key, value) {
    var path = key.replace(/\]/g, "").split("[");
    var cur = obj;
    for (var i = 0; i < path.length - 1; i++) {
      var k = path[i];
      if (typeof cur[k] !== "object" || cur[k] === null) cur[k] = {};
      cur = cur[k];
    }
    cur[path[path.length - 1]] = value;
  }

  function merge(target, src) {
    for (var k in src) {
      var v = src[k];
      if (v && typeof v === "object") {
        if (typeof target[k] !== "object" || target[k] === null) target[k] = {};
        merge(target[k], v);
      } else {
        target[k] = v;
      }
    }
    return target;
  }

  function loadConfig() {
    var overrides = parseQuery(location.search);
    if (overrides.flags) merge(state.flags, overrides.flags);
    return overrides;
  }

  /* ---------- session tokens (JWT / HS256) ---------------------------- */

  function b64urlFromBytes(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64urlFromString(str) { return b64urlFromBytes(enc.encode(str)); }
  function b64urlToBytes(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    var bin = atob(str), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // SHA-256 over a byte array -> 32-byte digest.
  function sha256Bytes(bytes) {
    var K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var l = bytes.length, bitLen = l * 8;
    var total = (((l + 8) >> 6) + 1) * 64;
    var m = new Uint8Array(total);
    m.set(bytes);
    m[l] = 0x80;
    var hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
    m[total - 8] = (hi >>> 24) & 0xff; m[total - 7] = (hi >>> 16) & 0xff;
    m[total - 6] = (hi >>> 8) & 0xff;  m[total - 5] = hi & 0xff;
    m[total - 4] = (lo >>> 24) & 0xff; m[total - 3] = (lo >>> 16) & 0xff;
    m[total - 2] = (lo >>> 8) & 0xff;  m[total - 1] = lo & 0xff;
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    var w = new Array(64);
    for (var i = 0; i < total; i += 64) {
      for (var t = 0; t < 16; t++) {
        w[t] = ((m[i+t*4] << 24) | (m[i+t*4+1] << 16) | (m[i+t*4+2] << 8) | m[i+t*4+3]) >>> 0;
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t-15],7) ^ rotr(w[t-15],18) ^ (w[t-15] >>> 3);
        var s1 = rotr(w[t-2],17) ^ rotr(w[t-2],19) ^ (w[t-2] >>> 10);
        w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
        var S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    var out = new Uint8Array(32);
    for (var j = 0; j < 8; j++) {
      out[j*4] = (H[j] >>> 24) & 0xff; out[j*4+1] = (H[j] >>> 16) & 0xff;
      out[j*4+2] = (H[j] >>> 8) & 0xff; out[j*4+3] = H[j] & 0xff;
    }
    return out;
  }

  function hmacSha256Bytes(keyBytes, msgBytes) {
    var B = 64;
    var key = keyBytes.length > B ? sha256Bytes(keyBytes) : keyBytes;
    var pad = new Uint8Array(B); pad.set(key);
    var iKey = new Uint8Array(B), oKey = new Uint8Array(B);
    for (var i = 0; i < B; i++) { iKey[i] = pad[i] ^ 0x36; oKey[i] = pad[i] ^ 0x5c; }
    var inner = new Uint8Array(B + msgBytes.length);
    inner.set(iKey, 0); inner.set(msgBytes, B);
    var ih = sha256Bytes(inner);
    var outer = new Uint8Array(B + 32);
    outer.set(oKey, 0); outer.set(ih, B);
    return sha256Bytes(outer);
  }

  // HMAC-SHA256 of a string. Uses WebCrypto when the origin is a secure
  // context; otherwise falls back to the in-page implementation so the
  // console still works when served over plain HTTP.
  function hmacSign(dataStr) {
    var msg = enc.encode(dataStr);
    if (window.crypto && window.crypto.subtle) {
      return crypto.subtle.importKey("raw", enc.encode(SESSION_KEY),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
        .then(function (key) { return crypto.subtle.sign("HMAC", key, msg); })
        .then(function (sig) { return new Uint8Array(sig); });
    }
    return Promise.resolve(hmacSha256Bytes(enc.encode(SESSION_KEY), msg));
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function signToken(payload) {
    var header = { alg: "HS256", typ: "JWT" };
    var data = b64urlFromString(JSON.stringify(header)) + "." + b64urlFromString(JSON.stringify(payload));
    return hmacSign(data).then(function (sig) {
      return data + "." + b64urlFromBytes(sig);
    });
  }

  function verifyToken(token) {
    var parts = (token || "").split(".");
    if (parts.length !== 3) return Promise.resolve(null);
    var data = parts[0] + "." + parts[1];
    var provided = b64urlToBytes(parts[2]);
    return hmacSign(data).then(function (expected) {
      if (!bytesEqual(provided, expected)) return null;
      try { return JSON.parse(dec.decode(b64urlToBytes(parts[1]))); }
      catch (e) { return null; }
    });
  }

  function restoreSession() {
    var token = null;
    try { token = localStorage.getItem("nexa.session"); } catch (e) {}
    if (!token) return Promise.resolve();
    return verifyToken(token).then(function (claims) {
      if (claims) {
        state.user = { email: claims.sub, role: claims.role };
        paintSessionChip();
      }
    });
  }

  function paintSessionChip() {
    var chip = $("session-chip");
    if (!chip) return;
    if (state.user) {
      chip.textContent = state.user.email + " · " + state.user.role;
      chip.classList.remove("hidden");
    } else {
      chip.classList.add("hidden");
    }
  }

  function isAdmin() {
    if (state.user && state.user.role === "admin") return true;
    return !!state.flags.isAdmin;
  }

  /* ---------- redirect handling -------------------------------------- */

  function handleReturnParam(overrides) {
    var dest = overrides.next || overrides.redirect;
    if (dest) safeNavigate(dest);
  }

  function safeNavigate(dest) {
    var allow = ["https://app.nexacloud.example", "https://nexacloud.example"];
    var ok = allow.some(function (a) { return dest.indexOf(a) === 0; });
    if (!ok && dest.charAt(0) === "/") ok = true;
    if (ok) location.href = dest;
  }

  /* ---------- branding ------------------------------------------------ */

  function applyBranding() {
    if (!state.flags.logoUrl) return;
    var brand = $("brand");
    if (brand) brand.innerHTML = '<img class="logo-img" src="' + state.flags.logoUrl + '" alt="logo">';
  }

  /* ---------- views --------------------------------------------------- */

  var SEARCH_INDEX = [
    { title: "Provisioning API reference", url: "#/docs" },
    { title: "Cluster autoscaling guide", url: "#/docs" },
    { title: "Incident response runbook", url: "#/status" },
    { title: "Billing & usage exports", url: "#/docs" },
    { title: "Access tokens and scopes", url: "#/docs" }
  ];

  function renderHome() {
    var view = $("view");
    view.innerHTML = "";
    var hero = el("section", "hero");

    var left = el("div", "hero-content");
    left.appendChild(el("div", "badge", "Now in GA — v4.3.0"));
    left.appendChild(el("h1", null, "Your infrastructure,<br><em>unified.</em>"));
    left.appendChild(el("p", "subtitle",
      "NexaCloud brings compute, storage, and observability into a single control plane. Built for platform teams."));

    var card = el("div", "panel login-card");
    card.innerHTML =
      '<h2>Sign in to your workspace</h2>' +
      '<p class="muted" style="margin-bottom:18px">Enter your credentials below</p>' +
      '<form id="login-form">' +
      '  <div class="field"><label for="email">Work email</label>' +
      '    <input type="email" id="email" name="email" placeholder="you@company.com" autocomplete="email"></div>' +
      '  <div class="field"><label for="password">Password</label>' +
      '    <input type="password" id="password" name="password" placeholder="••••••••" autocomplete="on"></div>' +
      '  <div class="field-row">' +
      '    <label class="checkbox-label"><input type="checkbox" name="remember"> Remember me</label>' +
      '    <a class="forgot" href="#/reset">Forgot password?</a></div>' +
      '  <button type="submit" class="btn-primary">Sign in</button>' +
      '</form>' +
      '<div class="divider"><span>or continue with</span></div>' +
      '<div class="sso-buttons">' +
      '  <button class="btn-sso" type="button">Google</button>' +
      '  <button class="btn-sso" type="button">GitHub</button>' +
      '</div>';
    left.appendChild(card);

    var right = el("div", "hero-visual");
    right.appendChild(el("div", "terminal",
      '<div class="term-bar"><span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span><span class="term-title">nexacloud — bash</span></div>' +
      '<div class="term-body">' +
      '<div class="term-line"><span class="prompt">$</span> nexactl cluster list</div>' +
      '<div class="term-line out">NAME          REGION       STATUS</div>' +
      '<div class="term-line out">prod-us-east  us-east-1    <span class="ok">●</span> Running</div>' +
      '<div class="term-line out">prod-eu-west  eu-west-1    <span class="ok">●</span> Running</div>' +
      '<div class="term-line out">staging       us-west-2    <span class="warn">●</span> Degraded</div>' +
      '<div class="term-line"><span class="prompt">$</span> <span class="cursor">_</span></div>' +
      '</div>'));

    hero.appendChild(left);
    hero.appendChild(right);
    view.appendChild(hero);

    var form = $("login-form");
    if (form) form.addEventListener("submit", onLogin);
  }

  function onLogin(e) {
    e.preventDefault();
    var email = ($("email").value || "guest@nexacloud.example").trim();
    signToken({ sub: email, role: "user", iat: Math.floor(Date.now() / 1000) }).then(function (token) {
      try { localStorage.setItem("nexa.session", token); } catch (err) {}
      state.user = { email: email, role: "user" };
      paintSessionChip();
      showToast("Signed in as <b>" + email + "</b>");
      location.hash = "#/status";
    });
  }

  function renderSearch(q) {
    var view = $("view");
    var needle = String(q).toLowerCase();
    var matches = SEARCH_INDEX.filter(function (r) {
      return r.title.toLowerCase().indexOf(needle) >= 0;
    });
    var rows = matches.map(function (r) {
      return '<tr><td><a href="' + r.url + '">' + r.title + "</a></td></tr>";
    }).join("");
    view.innerHTML =
      '<section class="panel">' +
      '<h2>Search</h2>' +
      '<p class="muted">Showing results for “' + q + '”</p>' +
      '<table class="tbl"><thead><tr><th>Document</th></tr></thead><tbody>' +
      (rows || '<tr><td class="muted">No documents matched.</td></tr>') +
      '</tbody></table>' +
      '<form id="search-form" style="margin-top:16px"><div class="field">' +
      '<input type="text" id="search-input" placeholder="Search documentation…" value=""></div></form>' +
      '</section>';
    var sf = $("search-form");
    if (sf) sf.addEventListener("submit", function (ev) {
      ev.preventDefault();
      location.hash = "#/search?q=" + encodeURIComponent($("search-input").value);
    });
  }

  function renderStatus() {
    var view = $("view");
    view.innerHTML =
      '<section class="panel">' +
      '<h2>Platform status</h2>' +
      '<p class="muted">Live health of NexaCloud regions.</p>' +
      '<table class="tbl"><thead><tr><th>Cluster</th><th>Region</th><th>Status</th></tr></thead><tbody>' +
      '<tr><td>prod-us-east</td><td>us-east-1</td><td><span class="pill ok">Operational</span></td></tr>' +
      '<tr><td>prod-eu-west</td><td>eu-west-1</td><td><span class="pill ok">Operational</span></td></tr>' +
      '<tr><td>staging</td><td>us-west-2</td><td><span class="pill warn">Degraded</span></td></tr>' +
      '</tbody></table></section>';
  }

  function renderDocs() {
    var view = $("view");
    view.innerHTML =
      '<section class="panel"><h2>Documentation</h2>' +
      '<p class="muted">Guides for the NexaCloud control plane.</p>' +
      '<h3>Getting started</h3>' +
      '<div class="kv">' +
      '<div>Install CLI: <b>curl -fsSL https://get.nexacloud.example | sh</b></div>' +
      '<div>Authenticate: <b>nexactl auth login</b></div>' +
      '<div>List clusters: <b>nexactl cluster list</b></div>' +
      '</div></section>';
  }

  function renderReset() {
    var view = $("view");
    view.innerHTML =
      '<section class="panel login-card"><h2>Reset password</h2>' +
      '<p class="muted" style="margin-bottom:18px">We will send a reset link to your inbox.</p>' +
      '<form id="reset-form"><div class="field"><label for="r-email">Work email</label>' +
      '<input type="email" id="r-email" placeholder="you@company.com"></div>' +
      '<button class="btn-primary" type="submit">Send reset link</button></form></section>';
    var rf = $("reset-form");
    if (rf) rf.addEventListener("submit", function (ev) {
      ev.preventDefault();
      showToast("If that account exists, a reset link is on its way.");
    });
  }

  function renderAdmin() {
    var view = $("view");
    if (!isAdmin()) {
      view.innerHTML =
        '<section class="panel"><h2>Admin console</h2>' +
        '<p class="muted">You do not have permission to view this area. ' +
        'Sign in with an administrator workspace token.</p></section>';
      return;
    }
    view.innerHTML =
      '<section class="panel"><h2>Admin console</h2>' +
      '<p class="muted">Internal operations — restricted.</p>' +
      '<h3>Provisioning service</h3>' +
      '<div class="kv">' +
      '<div>API base: <b>' + INTERNAL.apiBase + '</b></div>' +
      '<div>Metrics: <b>' + INTERNAL.metricsBase + '</b></div>' +
      '<div>Provisioning key: <b>' + INTERNAL.provisioningKey + '</b></div>' +
      '<div>On-call: <b>' + INTERNAL.oncall + '</b></div>' +
      '</div>' +
      '<h3>Danger zone</h3>' +
      '<div class="kv"><div>Rotate provisioning key · Purge region cache · Force failover</div></div>' +
      '</section>';
  }

  /* ---------- router -------------------------------------------------- */

  function router() {
    var raw = location.hash.slice(1) || "/";
    var qi = raw.indexOf("?");
    var path = qi < 0 ? raw : raw.slice(0, qi);
    var query = qi < 0 ? {} : parseQuery(raw.slice(qi));
    switch (path) {
      case "/":       renderHome(); break;
      case "/search": renderSearch(query.q || ""); break;
      case "/status": renderStatus(); break;
      case "/docs":   renderDocs(); break;
      case "/reset":  renderReset(); break;
      case "/admin":  renderAdmin(); break;
      default:        renderHome();
    }
  }

  /* ---------- messaging ----------------------------------------------- */

  function showToast(html) {
    var t = $("toast");
    if (!t) return;
    t.innerHTML = html;
    t.classList.add("show");
    clearTimeout(showToast._t);
    showToast._t = setTimeout(function () { t.classList.remove("show"); }, 4000);
  }

  function onMessage(e) {
    var msg = e.data;
    if (!msg || typeof msg !== "object") return;
    if (msg.type === "nexa:toast") {
      showToast(msg.body);
    } else if (msg.type === "nexa:route") {
      location.hash = msg.to;
    } else if (msg.type === "nexa:theme") {
      document.body.setAttribute("data-theme", msg.theme);
    }
  }

  /* ---------- boot ---------------------------------------------------- */

  function boot() {
    var overrides = loadConfig();
    applyBranding();
    window.addEventListener("hashchange", router);
    window.addEventListener("message", onMessage);
    restoreSession().then(function () {
      handleReturnParam(overrides);
      router();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  window.NexaCloud = { version: "4.3.0", state: state };
})();
//# sourceMappingURL=app.js.map
