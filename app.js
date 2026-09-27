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

  function importKey(usage) {
    return crypto.subtle.importKey(
      "raw", enc.encode(SESSION_KEY),
      { name: "HMAC", hash: "SHA-256" }, false, usage
    );
  }

  function signToken(payload) {
    var header = { alg: "HS256", typ: "JWT" };
    var data = b64urlFromString(JSON.stringify(header)) + "." + b64urlFromString(JSON.stringify(payload));
    return importKey(["sign"]).then(function (key) {
      return crypto.subtle.sign("HMAC", key, enc.encode(data));
    }).then(function (sig) {
      return data + "." + b64urlFromBytes(new Uint8Array(sig));
    });
  }

  function verifyToken(token) {
    var parts = (token || "").split(".");
    if (parts.length !== 3) return Promise.resolve(null);
    var data = parts[0] + "." + parts[1];
    return importKey(["verify"]).then(function (key) {
      return crypto.subtle.verify("HMAC", key, b64urlToBytes(parts[2]), enc.encode(data));
    }).then(function (ok) {
      if (!ok) return null;
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
