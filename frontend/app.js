"use strict";
/* SOC Incident Analyzer – frontend sin dependencias. Todo dato de los logs se escapa antes de insertarse. */

const SEV = ["Crítico", "Alto", "Medio", "Bajo"];
const SEV_COLOR = { "Crítico": "#b3261e", "Alto": "#e07b00", "Medio": "#d4b100", "Bajo": "#3f8f68" };
const S = { needAuth: false, sid: null, filename: "", client: "", analyst: "", a: null, ai: null, aiConfigured: false, aiKeys: {}, intel: null, intelConfirm: false, intelReserved: false,
            findingFilter: "Todos", findingCat: "", findingQ: "", logs: { page: 1, q: "", severity: "", flagged: "", host: "", user: "", event_id: "", finding: "" } };

const $ = (s, r = document) => r.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const plural = (n, one, many) => `${num(n)} ${n === 1 ? one : many}`;
const sevPill = (s, label) => `<span class="sev ${esc(s)}">${esc(label ?? s)}</span>`;
const num = (n) => Number(n).toLocaleString("es-AR");
const hhmm = (t) => (t || "").slice(11, 16);
const hhmmss = (t) => (t || "").slice(11, 19);
const ts = (t) => new Date(String(t).replace(" ", "T")).getTime();
const pref = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
               set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* sin almacenamiento */ } } };
const store = { get: (k) => { try { return sessionStorage.getItem(k); } catch { return null; } },
                set: (k, v) => { try { sessionStorage.setItem(k, v); } catch { /* sin almacenamiento */ } } };

/* Optional access token (server option APP_ACCESS_TOKEN). Kept in sessionStorage: it dies with the tab. */
const auth = { get: () => store.get("token") || "", set: (v) => store.set("token", v) };
const authHeaders = () => (auth.get() ? { Authorization: `Bearer ${auth.get()}` } : {});

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("show"), 3800);
}
function busy(on, text) { $("#busy").hidden = !on; if (text) $("#busyText").textContent = text; }

/* ---------- captcha local (solo si el servidor lo activa con CAPTCHA=on) ----------
   El servidor responde 403 + X-Captcha-Required a una subida sin pase: se abre el desafío y se repite la petición. */
const CAP = { pass: "" };
function captchaModal() {
  return new Promise((resolve, reject) => {
    const prev = document.activeElement, wasBusy = !$("#busy").hidden;
    busy(false);
    const box = document.createElement("div");
    box.className = "cap"; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "capT");
    box.innerHTML = `<div class="cap-box">
      <h2 id="capT">Verificación rápida</h2>
      <p id="capP" class="muted">Cargando desafío…</p>
      <div class="cap-grid" id="capG" role="group" aria-label="Imágenes del desafío"></div>
      <p class="cap-err" id="capE" role="alert" hidden></p>
      <div class="cap-act"><button class="btn ghost" id="capN" type="button">Otro desafío</button><span class="sp"></span>
        <button class="btn" id="capX" type="button">Cancelar</button><button class="btn primary" id="capV" type="button" disabled>Verificar</button></div>
    </div>`;
    document.body.appendChild(box);
    const picks = new Set(); let token = "", mode = "images", ro = null, trk = [], x = 0;
    const g = $("#capG", box), err = $("#capE", box), ok = $("#capV", box);
    const close = (fn) => { document.removeEventListener("keydown", onKey, true); if (ro) ro.disconnect(); box.remove(); if (wasBusy) busy(true); if (prev && prev.focus) prev.focus(); fn(); };
    const onKey = (e) => { if (e.key === "Escape") { e.stopPropagation(); close(() => reject(new Error("Verificación cancelada."))); } };
    document.addEventListener("keydown", onKey, true);
    const sync = () => { if (mode === "puzzle") return; ok.disabled = picks.size !== 3; $("#capP", box).textContent = `Marca las 3 imágenes que muestran la misma figura (pueden estar giradas o de otro color). Elegidas: ${picks.size} de 3.`; };
    const say = (m) => { err.textContent = m || ""; err.hidden = !m; };
    /* Rompecabezas: se arrastra la pieza (ratón, dedo o flechas del teclado) hasta el hueco. El servidor decide si encaja. */
    function drawPuzzle(c) {
      if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(c.background) || !/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(c.piece)) throw new Error("Desafío no válido.");
      mode = "puzzle"; trk = []; x = 0; picks.clear(); ok.disabled = true;
      g.className = "cap-puz"; g.removeAttribute("role"); g.replaceChildren();
      const scene = document.createElement("div"); scene.className = "cap-scene"; scene.style.aspectRatio = `${c.width} / ${c.height}`;
      const bg = document.createElement("img"); bg.className = "cap-bg"; bg.alt = "Imagen con un hueco en forma de pieza de rompecabezas"; bg.src = c.background; bg.draggable = false;
      const piece = document.createElement("img"); piece.className = "cap-piece"; piece.alt = ""; piece.src = c.piece; piece.draggable = false;
      scene.append(bg, piece);
      const rail = document.createElement("div"); rail.className = "cap-rail";
      const handle = document.createElement("div"); handle.className = "cap-handle"; handle.tabIndex = 0; handle.setAttribute("role", "slider");
      handle.setAttribute("aria-label", "Pieza del rompecabezas: desliza hasta el hueco (flechas izquierda y derecha)");
      const maxX = c.width - c.piece_size;
      handle.setAttribute("aria-valuemin", "0"); handle.setAttribute("aria-valuemax", String(maxX)); handle.setAttribute("aria-valuenow", "0");
      handle.textContent = "›››"; rail.appendChild(handle);
      const hint = document.createElement("span"); hint.className = "cap-hint"; hint.textContent = "Desliza hacia la derecha"; rail.appendChild(hint);
      g.append(scene, rail);
      const railMax = () => Math.max(1, rail.clientWidth - handle.offsetWidth - 4);
      let tStart = 0, dragging = false;
      const place = (xi) => {
        const nx = Math.max(0, Math.min(maxX, Math.round(xi)));
        if (nx !== x || !trk.length) {
          x = nx;
          if (!trk.length) tStart = performance.now();
          trk.push([Math.round(performance.now() - tStart), x]);
          if (trk.length >= 380) trk = trk.filter((_, i) => i % 2 === 0 || i === trk.length - 1);
        }
        const sc = scene.clientWidth / c.width;
        piece.style.left = `${x * sc}px`; piece.style.top = `${c.piece_y * sc}px`; piece.style.width = `${c.piece_size * sc}px`;
        handle.style.left = `${2 + (x / maxX) * railMax()}px`;
        handle.setAttribute("aria-valuenow", String(x)); handle.setAttribute("aria-valuetext", `posición ${x} de ${maxX}`);
        ok.disabled = x < 4; hint.hidden = x > 0;
        if (x > 0 && !err.hidden) say("");
      };
      const layout = () => { const sc = scene.clientWidth / c.width; piece.style.left = `${x * sc}px`; piece.style.top = `${c.piece_y * sc}px`; piece.style.width = `${c.piece_size * sc}px`; handle.style.left = `${2 + (x / maxX) * railMax()}px`; };
      layout();
      handle.onpointerdown = (e) => { dragging = true; handle.setPointerCapture(e.pointerId); handle.classList.add("on"); e.preventDefault(); };
      handle.onpointermove = (e) => { if (!dragging) return; const r = rail.getBoundingClientRect(); place(((e.clientX - r.left - handle.offsetWidth / 2 - 2) / railMax()) * maxX); };
      const stop = () => { dragging = false; handle.classList.remove("on"); };
      handle.onpointerup = stop; handle.onpointercancel = stop;
      handle.onkeydown = (e) => {
        const step = e.shiftKey ? 12 : 4;
        if (e.key === "ArrowRight") { place(x + step); e.preventDefault(); }
        else if (e.key === "ArrowLeft") { place(x - step); e.preventDefault(); }
        else if (e.key === "Enter" && !ok.disabled) { ok.click(); e.preventDefault(); }
      };
      ro = new ResizeObserver(layout); ro.observe(scene);
      $("#capP", box).textContent = c.prompt || "Desliza la pieza hasta que encaje en el hueco de la imagen.";
      handle.focus();
    }
    async function load() {
      if (ro) { ro.disconnect(); ro = null; }
      mode = "images"; g.className = "cap-grid"; g.setAttribute("role", "group");
      picks.clear(); say(""); g.replaceChildren(); ok.disabled = true; $("#capP", box).textContent = "Cargando desafío…";
      try {
        const c = await api("/api/captcha/challenge", { method: "POST" });
        token = c.token;
        if (c.type === "puzzle") { drawPuzzle(c); return; }
        c.images.forEach((src, i) => {
          if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(src)) return;
          const b = document.createElement("button"); b.type = "button"; b.className = "cap-tile";
          b.setAttribute("aria-pressed", "false"); b.setAttribute("aria-label", `Imagen ${i + 1} de ${c.images.length}`);
          const im = document.createElement("img"); im.alt = ""; im.src = src; im.draggable = false; b.appendChild(im);
          b.onclick = () => {
            if (picks.has(i)) { picks.delete(i); b.setAttribute("aria-pressed", "false"); }
            else if (picks.size < 3) { picks.add(i); b.setAttribute("aria-pressed", "true"); }
            else say("Ya elegiste 3. Desmarca una para cambiarla.");
            if (picks.size < 3 && err.textContent.startsWith("Ya elegiste")) say("");
            sync();
          };
          g.appendChild(b);
        });
        sync(); const first = g.querySelector("button"); if (first) first.focus();
      } catch (e) { say(e.message); $("#capP", box).textContent = "No se pudo cargar el desafío."; }
    }
    ok.onclick = async () => {
      ok.disabled = true;
      try {
        const r = await api("/api/captcha/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(mode === "puzzle" ? { token, x, track: trk } : { token, selected: [...picks] }) });
        CAP.pass = r.pass; close(resolve);
      } catch (e) { await load(); say(e.message); }
    };
    $("#capN", box).onclick = load;
    $("#capX", box).onclick = () => close(() => reject(new Error("Verificación cancelada.")));
    load();
  });
}

async function api(path, opts = {}, retried = false) {
  const extra = CAP.pass ? { "X-Captcha-Pass": CAP.pass } : {};
  const r = await fetch(path, { ...opts, headers: { ...(opts.headers || {}), ...authHeaders(), ...extra } });
  if (r.status === 403 && r.headers.get("X-Captcha-Required") && !retried) {
    CAP.pass = ""; await captchaModal();
    try { return await api(path, opts, true); } finally { CAP.pass = ""; }      // el pase es de un solo uso
  }
  if (r.status === 401 && path !== "/api/auth/check") { auth.set(""); S.needAuth = true; render(); }
  if (!r.ok) {
    let d = r.statusText;
    try { const j = await r.json(); d = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* sin cuerpo */ }
    throw new Error(d);
  }
  return r.json();
}

/* ---------- proveedores de IA (Claude, OpenAI, Gemini, Ollama) ---------- */
/* La clave se envía solo por cabecera y se usa en esa consulta; el servidor no la guarda. Las direcciones de los servicios están fijas en el servidor. */
const CLOUD = { openai: { name: "OpenAI", ph: "sk-…", models: ["gpt-5.4-mini", "gpt-5"] },
                gemini: { name: "Gemini (Google)", ph: "AIza…", models: ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-4-argon"] } };
const AI_LABEL = { anthropic: "IA (", openai: "IA · OpenAI (", gemini: "IA · Gemini (", ollama: "IA local · Ollama (" };
const aiBadge = (A) => (AI_LABEL[A.provider] || "IA (") + esc(A.model) + ")";
const PROV_OPTIONS = '<option value="anthropic">Claude (Anthropic, requiere clave)</option><option value="openai">OpenAI (requiere clave)</option>'
  + '<option value="gemini">Gemini · Google (requiere clave)</option><option value="ollama">IA local (Ollama, sin enviar datos a terceros)</option>';
const cloudFields = (id) => Object.entries(CLOUD).map(([p, c]) => `<div id="${id}-${p}" hidden>
  <label class="f" ${S.aiKeys[p] ? "hidden" : ""}>Clave de ${esc(c.name)} (solo esta sesión)<input type="password" data-pk="${p}" placeholder="${esc(c.ph)}" autocomplete="off"></label>
  <label class="f">Modelo (puedes escribir otro)<input type="text" data-pm="${p}" list="${id}-${p}-dl" placeholder="${esc(c.models[0])}" maxlength="80" autocomplete="off"></label>
  <datalist id="${id}-${p}-dl">${c.models.map((m) => `<option value="${esc(m)}">`).join("")}</datalist>
  <p class="muted">Los datos del análisis se envían a ${esc(c.name)} para redactar. La severidad la sigue fijando el motor.</p></div>`).join("");
/* cabeceras y query de la solicitud según el proveedor elegido; root = contenedor del panel */
function aiRequest(root, prov, anthKey, ollamaModel) {
  const h = {}; let q = "";
  if (prov === "anthropic") { if (anthKey && anthKey.value.trim()) h["X-Anthropic-Key"] = anthKey.value.trim(); }
  else if (prov === "ollama") q = `?provider=ollama&model=${encodeURIComponent(ollamaModel || "")}`;
  else {
    const k = root.querySelector(`[data-pk="${prov}"]`), m = root.querySelector(`[data-pm="${prov}"]`);
    if (k && k.value.trim()) h["X-Provider-Key"] = k.value.trim();
    q = `?provider=${prov}` + (m && m.value.trim() ? `&model=${encodeURIComponent(m.value.trim())}` : "");
  }
  return { h, q };
}
function showCloud(root, id, prov) { Object.keys(CLOUD).forEach((p) => { const el = root.querySelector(`#${id}-${p}`); if (el) el.hidden = p !== prov; }); }

/* ---------- carga ---------- */
function adopt(res) {
  S.sid = res.session_id; S.filename = res.filename; S.client = res.client || ""; S.analyst = res.analyst || "";
  S.a = res.analysis; S.ai = res.ai; if (res.ai_configured !== undefined) S.aiConfigured = res.ai_configured; if (res.ai_keys) S.aiKeys = res.ai_keys;
  S.logs = { page: 1, q: "", severity: "", flagged: "", host: "", user: "", event_id: "", finding: "" };
  S.findingFilter = "Todos"; S.findingCat = ""; S.findingQ = "";
  S.triage = null; S.intel = null; S.intelConfirm = false; S.intelReserved = false; clearInterval(S.intelTimer);   // S.ph (correos) es un análisis aparte: no se mezcla con el de logs
  store.set("sid", S.sid);
}
async function upload(file, client, analyst) {
  busy(true, "Analizando eventos…");
  try {
    const fd = new FormData(); fd.append("client", client); fd.append("analyst", analyst);
    fd.append("file", file);
    const res = await api("/api/upload", { method: "POST", body: fd });
    adopt(res); location.hash = "#/dashboard"; render();
  } catch (e) { showLandingError(e.message); }
  finally { busy(false); }
}
async function useSample(client, analyst) {
  busy(true, "Analizando el ejemplo…");
  try {
    const fd = new FormData(); fd.append("client", client); fd.append("analyst", analyst);
    const res = await api("/api/sample", { method: "POST", body: fd });
    adopt(res); location.hash = "#/dashboard"; render();
  } catch (e) { showLandingError(e.message); }
  finally { busy(false); }
}
function showLandingError(m) { const b = $("#lerr"); if (b) { b.textContent = m; b.hidden = false; } else toast(m); }

/* ---------- navegación ---------- */
const ROUTES = [["dashboard", "Panel"], ["incidents", "Incidentes"], ["findings", "Hallazgos"], ["attack", "ATT&CK"], ["logs", "Eventos"], ["iocs", "Indicadores (IoC)"], ["report", "Informe"]];
const inPh = (r) => r === "phishing" || r.startsWith("phishing/");
function route() { return (location.hash.replace(/^#\/?/, "") || "").split("?")[0]; }

function renderRail() {
  const nav = $("#nav"), foot = $("#railFoot");
  if (!S.a) {   // sin análisis de logs abierto: dos entradas, logs y phishing (son análisis independientes)
    nav.innerHTML = [["", "Análisis de logs"], ["phishing", "Phishing"]].map(([k, l]) => `<a href="#/${k}" ${(k === "phishing" ? inPh(route()) : route() === k) ? 'aria-current="page"' : ""}><span>${l}</span></a>`).join("");
    foot.innerHTML = ""; return;
  }
  const cnt = { incidents: S.a.incidents.length, findings: S.a.findings.length, iocs: S.a.iocs.length, logs: S.a.profile.rows };
  nav.innerHTML = ROUTES.map(([k, l], i) =>
    `<a href="#/${k}" ${route() === k ? 'aria-current="page"' : ""}><span class="n">${i + 1}</span><span>${l}</span>${cnt[k] !== undefined ? `<span class="count">${num(cnt[k])}</span>` : ""}</a>`).join("");
  const cur = nav.querySelector("[aria-current=page]"); if (cur) nav.scrollLeft = Math.max(0, cur.offsetLeft - 24);   // narrow screens: keep the open section visible
  foot.innerHTML = `<span>Archivo</span><b title="${esc(S.filename)}">${esc(S.filename)}</b><button class="btn ghost" id="newBtn">Cargar otro</button>`;
  $("#newBtn").onclick = () => { S.a = null; S.sid = null; store.set("sid", ""); location.hash = "#/"; render(); };
}

function accessView() {
  return `<section class="landing">
    <h1>Acceso protegido</h1>
    <p class="lead">Esta instancia requiere una clave de acceso. Pídesela a quien administra la aplicación.</p>
    <form id="accessForm" class="fields" autocomplete="off">
      <label class="f" style="max-width:420px">Clave de acceso<input type="password" id="accessKey" autocomplete="current-password" required></label>
      <button class="btn primary" type="submit">Entrar</button>
    </form>
    <p id="accessErr" role="alert" style="color:var(--danger,#b3261e);min-height:1.4em"></p>
  </section>`;
}
function bindAccess() {
  $("#accessKey").focus();
  $("#accessForm").onsubmit = async (e) => {
    e.preventDefault();
    const k = $("#accessKey").value.trim(); if (!k) return;
    auth.set(k);
    try { await api("/api/auth/check"); S.needAuth = false; await start(); }
    catch (err) { auth.set(""); $("#accessErr").textContent = err.message; }
  };
}

function render() {
  hideTip();
  stopLoops();
  const main = $("#main");
  const r = route();
  if (S.needAuth) { $("#nav").innerHTML = ""; $("#railFoot").innerHTML = ""; main.innerHTML = `<div class="view">${accessView()}</div>`; bindAccess(); return; }
  if (inPh(r) && S.a) { location.replace("#/dashboard"); return; }   // con un análisis de logs abierto no hay pestaña Phishing
  if (inPh(r)) {
    renderRail();
    const v = { "phishing/dominio": [domainView, bindDomain], "phishing/parecidos": [lookView, bindLook] }[r] || [phishingView, bindPhishing];
    main.innerHTML = `<div class="view glassv">${AURORA_HTML}${phTabs(r)}${v[0]()}</div>`; v[1](); viewFx(main.firstElementChild, `ph:${r}:${S.ph ? "res" : "up"}`, true); if (!S.keepScroll) window.scrollTo(0, 0); S.keepScroll = false; return;
  }
  if (!S.a) { renderRail(); main.innerHTML = `<div class="view glassv">${landing()}</div>`; bindLanding(); bindHero(); viewFx(main.firstElementChild, "landing", false); return; }
  renderRail();
  const views = { dashboard, incidents, findings, attack, logs, iocs, report };
  const v = views[r] || dashboard;
  main.innerHTML = `<div class="view">${v()}</div>`; bindHero(); countUp();
  const bind = { dashboard: bindDashboard, incidents: bindIncidents, findings: bindFindings, attack: bindAttack, logs: bindLogs, iocs: bindIocs, report: bindReport }[views[r] ? r : "dashboard"];
  bind();
  if (!S.keepScroll) window.scrollTo(0, 0);
  S.keepScroll = false;
}
window.addEventListener("hashchange", render);

/* ---------- landing ---------- */
function landing() {
  return `<section class="landing">
    <h1>Del export del SIEM al informe de incidentes</h1>
    <p class="lead">Detecta indicadores de compromiso, los agrupa en incidentes y prepara el informe técnico en PDF.</p>
    <div class="drop" id="drop" tabindex="0" role="button" aria-label="Seleccionar archivo de eventos">
      <strong id="dropTitle">Arrastra el archivo aquí o haz clic para elegirlo</strong>
      <span>Excel, CSV/TSV, JSON/NDJSON o auth.log de Linux · hasta 25 MB</span>
      <input type="file" id="file" accept=".xlsx,.xlsm,.csv,.tsv,.txt,.log,.json,.jsonl,.ndjson" hidden>
    </div>
    <button class="linkbtn" id="fmtHelp" type="button">¿Qué formato y columnas necesita?</button>
    <div class="fields">
      <label class="f">Cliente<input type="text" id="client" placeholder="Nombre del cliente" autocomplete="off"></label>
      <label class="f">Analista<input type="text" id="analyst" placeholder="Tu nombre" autocomplete="off"></label>
    </div>
    <div class="row">
      <button class="btn primary" id="go" disabled>Analizar archivo</button>
      <button class="btn" id="sample" type="button">Probar con datos de ejemplo</button>
    </div>
    <div class="err" id="lerr" role="alert" hidden></div>
    <ul class="checks">
      <li>Fuerza bruta y password spraying</li><li>Inicios de sesión externos y fuera de patrón</li>
      <li>Escalamiento de privilegios</li><li>Comandos y procesos sospechosos</li>
      <li>Movimiento lateral</li><li>Exfiltración, persistencia y ataques web</li>
    </ul>
  </section>`;
}
function bindLanding() {
  let file = null;
  const drop = $("#drop"), inp = $("#file"), go = $("#go");
  const pick = (f) => { if (!f) return; file = f; $("#dropTitle").textContent = f.name; go.disabled = false; $("#lerr").hidden = true; };
  drop.onclick = () => inp.click();
  drop.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); inp.click(); } };
  inp.onchange = () => pick(inp.files[0]);
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => pick(e.dataTransfer.files[0]));
  go.onclick = () => upload(file, $("#client").value, $("#analyst").value);
  $("#fmtHelp").onclick = showHow;
  $("#sample").onclick = () => useSample($("#client").value, $("#analyst").value);
}

/* ---------- gráficos ---------- */
function showTip(html, e) {
  let t = $(".tip"); if (!t) { t = document.createElement("div"); t.className = "tip"; document.body.appendChild(t); }
  t.innerHTML = html; t.style.left = Math.min(e.clientX + 14, innerWidth - 340) + "px"; t.style.top = e.clientY + 14 + "px";
}
function hideTip() { const t = $(".tip"); if (t) t.remove(); }

/* Línea de tiempo de casos: un carril por incidente, un segmento por hallazgo. */
const SW = { W: 1000, L: 210, R: 16 };
function swimlane() {
  const incs = S.a.incidents; if (!incs.length) return "<p class='muted'>No se detectaron incidentes.</p>";
  const { W, L, R } = SW, laneH = 38, top = 26, H = top + incs.length * laneH + 8;
  const t0 = ts(S.a.profile.time_start), t1 = ts(S.a.profile.time_end), span = Math.max(t1 - t0, 1);
  const x = (t) => L + ((ts(t) - t0) / span) * (W - L - R);
  let g = "";
  const ticks = 6;
  for (let i = 0; i <= ticks; i++) {
    const tx = L + (i / ticks) * (W - L - R), d = new Date(t0 + (i / ticks) * span);
    g += `<line x1="${tx}" x2="${tx}" y1="${top - 6}" y2="${H - 8}" class="grid-line"/><text x="${tx}" y="14" text-anchor="middle">${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}</text>`;
  }
  incs.forEach((inc, i) => {
    const y = top + i * laneH;
    g += `<g class="lane" data-inc="${esc(inc.id)}"><text class="lane-label" x="0" y="${y + 15}">${esc(inc.id)}</text><text x="0" y="${y + 29}">${esc(inc.title.length > 34 ? inc.title.slice(0, 33) + "…" : inc.title)}</text>`;
    g += `<rect class="lane-bg" x="${L}" y="${y + 4}" width="${W - L - R}" height="${laneH - 12}" rx="4"/>`;
    S.a.findings.filter((f) => f.incident_id === inc.id).forEach((f) => {
      const a = x(f.time_start), w = Math.max(x(f.time_end) - a, 7);
      g += `<rect class="seg" data-f="${esc(f.id)}" x="${a}" y="${y + 6}" width="${w}" height="${laneH - 16}" rx="3" fill="${SEV_COLOR[f.severity]}" opacity=".92" tabindex="0" role="button" aria-label="${esc(f.id + " " + f.title)}"/>`;
    });
    g += "</g>";
  });
  return `<div class="chart swim"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Línea de tiempo de incidentes">${g}</svg>
    <div class="legend">${SEV.map((s) => `<span><i style="background:${SEV_COLOR[s]}"></i>${s}</span>`).join("")}<span>Cada barra es un hallazgo; haz clic para abrirlo.</span></div></div>`;
}

/* Actividad: eventos por intervalo de 10 min, apilados por severidad del hallazgo asociado. */
function activityChart() {
  const tl = S.a.stats.timeline; if (!tl.length) return "";
  const W = 640, H = 200, L = 34, B = 24, T = 8, bw = (W - L) / tl.length;
  const max = Math.max(...tl.map((d) => d.total), 1);
  const y = (v) => T + (H - B - T) * (1 - v / max);
  let g = [0, 0.5, 1].map((f) => { const v = Math.round(max * f); return `<line x1="${L}" x2="${W}" y1="${y(v)}" y2="${y(v)}" class="grid-line"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`; }).join("");
  tl.forEach((d, i) => {
    let acc = 0; const x0 = L + i * bw + 2, w = Math.max(bw - 4, 2);
    const parts = [["normal", "#8a99b0"], ...SEV.slice().reverse().map((s) => [s, SEV_COLOR[s]])];
    let seg = "";
    parts.forEach(([k, c]) => { const v = d[k] || 0; if (!v) return; const y1 = y(acc + v), y0 = y(acc); seg += `<rect x="${x0}" y="${y1}" width="${w}" height="${y0 - y1}" fill="${c}"/>`; acc += v; });
    g += `<g data-i="${i}">${seg}<rect x="${x0}" y="${T}" width="${w}" height="${H - B - T}" fill="transparent"/></g>`;
    if (i % 3 === 0) g += `<text x="${x0 + w / 2}" y="${H - 6}" text-anchor="middle">${esc(d.t)}</text>`;
  });
  return `<div class="chart act"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Eventos por intervalo de 10 minutos">${g}</svg>
    <div class="legend"><span><i style="background:#8a99b0"></i>Sin hallazgo</span>${SEV.map((s) => `<span><i style="background:${SEV_COLOR[s]}"></i>${s}</span>`).join("")}</div></div>`;
}

/* Dona de criticidad: cada color filtra el panel; los números y las barras se animan al entrar. */
function donut() {
  const fs = S.a.stats.findings_by_severity, tot = Math.max(S.a.stats.findings_total, 1), C = 2 * Math.PI * 54;
  let cum = 0;
  const segs = SEV.filter((s) => fs[s]).map((s) => {
    const l = C * fs[s] / tot, d = `${l.toFixed(2)} ${(C - l).toFixed(2)}`;
    const h = `<circle class="seg" data-s="${s}" style="--c:${SEV_COLOR[s]}" cx="80" cy="80" r="54" data-dash="${d}" stroke-dasharray="${d}" stroke-dashoffset="${(-cum).toFixed(2)}" tabindex="0" role="button" aria-label="${s}: ${plural(fs[s], "hallazgo", "hallazgos")}"/>`;
    cum += l; return h;
  }).join("");
  return `<div class="donutbox"><svg class="donut" id="donut" viewBox="0 0 160 160" role="img" aria-label="Hallazgos por criticidad"><circle class="track" cx="80" cy="80" r="54"/><g transform="rotate(-90 80 80)">${segs}</g><text class="big" id="dTot" x="80" y="82" text-anchor="middle">${S.a.stats.findings_total}</text><text id="dLab" x="80" y="100" text-anchor="middle">hallazgos</text></svg>
    <div class="chips">${SEV.map((s) => `<button class="sevchip" data-s="${s}" style="--c:${SEV_COLOR[s]}" type="button" aria-pressed="false"><i></i>${s}<b>${fs[s] || 0}</b></button>`).join("")}
      <button class="btn" id="sevGo" type="button" hidden></button></div></div>`;
}
function catBars() {
  const c = S.a.stats.findings_by_category, max = Math.max(...Object.values(c), 1);
  return Object.entries(c).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="bar-row" style="cursor:default"><span>${esc(k)}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${v / max * 100}%;background:var(--muted)"></span></span><span class="n">${v}</span></div>`).join("");
}
function ipBars() {
  const rows = S.a.stats.top_ips.slice(0, 8), max = Math.max(...rows.map((r) => r.events), 1);
  return rows.map((r) => `<button class="bar-row" data-ip="${esc(r.ip)}" style="grid-template-columns:150px 1fr 38px" aria-label="Buscar eventos de ${esc(r.ip)}"><span class="mono"><i class="dot" style="background:${r.external ? "#e07b00" : "#8794a6"}"></i>${esc(r.ip)}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${r.events / max * 100}%;background:${r.external ? "#e07b00" : "#8794a6"}"></span></span><span class="n">${r.events}</span></button>`).join("")
    + `<div class="legend"><span><i style="background:#e07b00"></i>IP externa</span><span><i style="background:#8794a6"></i>IP interna</span></div>`;
}

/* ---------- panel ---------- */
function dashboard() {
  const st = S.a.stats, p = S.a.profile, fs = st.findings_by_severity, total = Math.max(st.findings_total, 1);
  const crit = st.incidents_by_severity["Crítico"] || 0;
  const RC = 2 * Math.PI * 22;
  const ring = (frac, color) => { const d = `${(RC * Math.min(Math.max(frac, 0), 1)).toFixed(2)} ${RC.toFixed(2)}`; return `<svg class="ring" width="54" height="54" viewBox="0 0 54 54" aria-hidden="true"><circle cx="27" cy="27" r="22" fill="none" class="rtrack" stroke-width="6"/><circle class="rfg" cx="27" cy="27" r="22" fill="none" stroke="${color}" stroke-width="6" stroke-linecap="round" transform="rotate(-90 27 27)" data-dash="${d}" stroke-dasharray="${d}"/></svg>`; };
  const k = (n, label, extra = "") => `<div class="panel kpi"><b data-count="${n}">${num(n)}</b><span>${label}</span>${extra}</div>`;
  const rows = Math.max(p.rows, 1);
  return `<div class="dash"><div class="aurora" aria-hidden="true"><i></i><i></i><i></i></div>
    <section class="panel hero"><i class="scan" aria-hidden="true"></i>
      <div class="page-head" style="margin:0">
        <div><h1>${S.client ? esc(S.client) : "Resultado del análisis"}</h1>
        <p>${esc(p.time_start)} a ${esc(p.time_end)} (${esc(p.duration)}) · ${plural(p.rows, "evento", "eventos")} · ${plural(p.hosts, "equipo", "equipos")} · ${plural(p.users, "cuenta", "cuentas")}</p></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn" href="#/findings">Ver hallazgos</a><a class="btn primary" href="#/report">Ir al informe</a></div>
      </div></section>
    <div class="grid g4" style="margin-top:16px">
      ${k(st.incidents_total, `Incidentes distintos${crit ? ` (${crit} críticos)` : ""}`, ring(crit / Math.max(st.incidents_total, 1), SEV_COLOR["Crítico"]))}
      ${k(st.findings_total, "Hallazgos con evidencia", `<div class="sevbar">${SEV.map((s) => `<span style="width:${(fs[s] || 0) / total * 100}%;background:${SEV_COLOR[s]}" title="${s}: ${fs[s] || 0}"></span>`).join("")}</div>`)}
      ${k(st.flagged_events, `Eventos ligados a incidentes (${Math.round(st.flagged_events / rows * 100)} % del total)`, ring(st.flagged_events / rows, "var(--accent)"))}
      ${k(S.a.iocs.length, "Indicadores de compromiso")}
    </div>
    <div class="inc-cards">${S.a.incidents.map((i) => `<button class="inc-card ${esc(i.severity)}" data-card="${esc(i.id)}" aria-expanded="false" aria-controls="drawer">
        <span class="top2"><span class="mono muted">${esc(i.id)}</span>${i.severity === "Crítico" ? `<span class="pulse">${sevPill(i.severity)}</span>` : sevPill(i.severity)}</span>
        <b>${esc((S.ai.incidents[i.id] || {}).title || i.title)}</b>
        <small>${hhmm(i.time_start)}–${hhmm(i.time_end)} · ${plural(i.finding_ids.length, "hallazgo", "hallazgos")} · ${plural(i.evidence_count, "evento", "eventos")}</small></button>`).join("")}</div>
    <div class="drawer" id="drawer" aria-live="polite"><div class="panel dr-in" id="drawerIn"></div></div>
    <div class="panel" style="margin-top:16px"><h3>Línea de tiempo de incidentes <small>pasa el mouse para ver la hora; haz clic en una fila para ver el caso</small></h3>${swimlane()}</div>
    <div class="grid g-wide" style="margin-top:16px">
      <div class="panel"><h3>Actividad de la ventana analizada</h3>${activityChart()}</div>
      <div class="panel"><h3>Hallazgos por criticidad <small>haz clic en un color para filtrar</small></h3>${donut()}<h3 style="margin-top:18px">Por categoría</h3>${catBars()}</div>
    </div>
    <div class="panel" style="margin-top:16px"><h3>Direcciones IP con más actividad</h3>${ipBars()}</div>
    ${S.a.limitations.length ? `<div class="panel" style="margin-top:16px"><h3>Límites del análisis</h3><ul>${S.a.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>` : ""}</div>`;
}
function bindDashboard() {
  const dash = $(".dash"); if (!dash) return;
  const svg = $(".swim svg"), drawer = $("#drawer"), drawerIn = $("#drawerIn");
  const fs = S.a.stats.findings_by_severity, ftot = S.a.stats.findings_total;
  let filter = null, selected = null, hovered = null;
  const lanesOn = (id) => {
    if (!svg) return;
    svg.classList.toggle("dim", !!id);
    svg.querySelectorAll(".lane").forEach((l) => l.classList.toggle("on", !!id && l.dataset.inc === id));
  };
  const apply = () => {
    document.querySelectorAll("[data-card]").forEach((c) => {
      const id = c.dataset.card, has = !filter || S.a.findings.some((f) => f.incident_id === id && f.severity === filter);
      c.classList.toggle("off", !has); c.classList.toggle("sel", selected === id); c.setAttribute("aria-expanded", String(selected === id));
    });
    document.querySelectorAll(".sevchip[data-s]").forEach((c) => { const on = c.dataset.s === filter; c.classList.toggle("on", on); c.setAttribute("aria-pressed", String(on)); });
    document.querySelectorAll("#donut .seg").forEach((c) => c.classList.toggle("hot", c.dataset.s === filter));
    $("#donut").classList.toggle("dim", !!filter);
    $("#dTot").textContent = filter ? fs[filter] || 0 : ftot; $("#dLab").textContent = filter ? filter.toLowerCase() : "hallazgos";
    document.querySelectorAll(".swim .seg").forEach((r) => {
      const f = S.a.findings.find((x) => x.id === r.dataset.f);
      r.style.opacity = filter && f && f.severity !== filter ? ".2" : "";
    });
    const go = $("#sevGo"); go.hidden = !filter;
    if (filter) go.textContent = `Ver ${plural(fs[filter] || 0, "hallazgo", "hallazgos")} ${filter.toLowerCase()} →`;
    lanesOn(hovered || selected);
    drawerIn.querySelectorAll(".fnd").forEach((r) => { r.style.opacity = filter && r.dataset.sev !== filter ? ".35" : ""; });
  };
  const setFilter = (s) => { filter = filter === s ? null : s; apply(); };
  document.querySelectorAll("#donut .seg").forEach((c) => {
    c.onclick = () => setFilter(c.dataset.s); c.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setFilter(c.dataset.s); } };
    c.onmousemove = (e) => showTip(`<b>${esc(c.dataset.s)}</b>: ${plural(fs[c.dataset.s], "hallazgo", "hallazgos")}`, e); c.onmouseleave = hideTip;
  });
  document.querySelectorAll(".sevchip[data-s]").forEach((c) => c.onclick = () => setFilter(c.dataset.s));
  $("#sevGo").onclick = () => { S.findingFilter = filter; location.hash = "#/findings"; };

  /* detalle del caso: se despliega debajo de las tarjetas sin salir del panel */
  const fx = () => typeof anime === "function" && !reducedMotion();
  const drawerHtml = (inc) => {
    const g = (S.ai.incidents || {})[inc.id] || {}, fl = S.a.findings.filter((f) => f.incident_id === inc.id);
    const meta = [`${hhmmss(inc.time_start)} a ${hhmmss(inc.time_end)}`, inc.hosts.length ? `Equipos: ${inc.hosts.join(", ")}` : "", inc.external_ips.length ? `IP externas: ${inc.external_ips.join(", ")}` : "", inc.actor_users.length ? `Cuentas: ${inc.actor_users.join(", ")}` : ""].filter(Boolean).map(esc).join(" · ");
    return `<h3 style="margin:0 0 6px"><span class="mono muted">${esc(inc.id)}</span> ${esc(g.title || inc.title)} ${sevPill(inc.severity)}</h3><p class="muted" style="margin:0 0 8px;font-size:13.5px">${meta}</p>`
      + fl.map((f) => `<div class="fnd" data-sev="${esc(f.severity)}">${sevPill(f.severity)}<span class="mono muted">${esc(f.id)}</span><span>${esc(f.title)}</span></div>`).join("")
      + `<div style="margin-top:10px"><button class="btn primary" id="drGo" type="button">Abrir en Incidentes →</button></div>`;
  };
  const openInc = (id) => {
    const first = selected !== id; selected = first ? id : null; apply();
    if (!first) {
      if (fx()) anime({ targets: drawer, height: 0, opacity: 0, duration: 260, easing: "easeInOutQuad", complete: () => drawer.classList.remove("open") });
      else { drawer.classList.remove("open"); drawer.style.height = "0"; }
      return;
    }
    const inc = S.a.incidents.find((x) => x.id === id); if (!inc) return;
    drawerIn.innerHTML = drawerHtml(inc); apply();
    $("#drGo").onclick = () => { S.openInc = id; location.hash = "#/incidents"; };
    drawer.classList.add("open");
    if (fx()) {
      anime.remove(drawer); drawer.style.height = "0"; drawer.style.opacity = "0";
      anime({ targets: drawer, height: [0, drawer.scrollHeight], opacity: [0, 1], duration: 380, easing: "easeOutCubic", complete: () => { drawer.style.height = "auto"; } });
      anime({ targets: drawer.querySelectorAll(".fnd"), opacity: [0, 1], translateX: [-14, 0], delay: anime.stagger(55, { start: 150 }), duration: 380, easing: "easeOutQuad", complete: () => apply() });
    } else { drawer.style.height = "auto"; drawer.style.opacity = "1"; }
    drawer.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "nearest" });
  };
  document.querySelectorAll("[data-card]").forEach((c) => {
    const id = c.dataset.card;
    c.onclick = () => openInc(id);
    c.onmouseenter = c.onfocus = () => { hovered = id; lanesOn(id); };
    c.onmouseleave = c.onblur = () => { hovered = null; lanesOn(selected); };
    c.onpointermove = (e) => { const r = c.getBoundingClientRect(); c.style.setProperty("--mx", e.clientX - r.left + "px"); c.style.setProperty("--my", e.clientY - r.top + "px"); };
  });
  document.querySelectorAll(".swim .lane").forEach((l) => {
    l.onclick = (e) => { if (!e.target.classList.contains("seg")) openInc(l.dataset.inc); };
  });
  document.querySelectorAll(".lane-label").forEach((t) => { t.style.cursor = "pointer"; });
  document.querySelectorAll(".swim .seg").forEach((el) => {
    const f = S.a.findings.find((x) => x.id === el.dataset.f); if (!f) return;
    const go = () => { S.findingFilter = "Todos"; S.openFinding = f.id; location.hash = "#/findings"; };
    el.onclick = go; el.onkeydown = (e) => { if (e.key === "Enter") go(); };
    el.onmousemove = (e) => showTip(`<b>${esc(f.id)} · ${esc(f.title)}</b><br>${sevPill(f.severity)} <span class="mono">${hhmmss(f.time_start)}–${hhmmss(f.time_end)}</span>`, e);
    el.onmouseleave = hideTip;
  });
  /* cursor de hora sobre la línea de tiempo */
  const sw = $(".swim");
  if (sw && svg) {
    const cur = document.createElement("div"); cur.className = "cursor"; cur.setAttribute("aria-hidden", "true"); cur.appendChild(document.createElement("span")); sw.appendChild(cur);
    const t0 = ts(S.a.profile.time_start), span = Math.max(ts(S.a.profile.time_end) - t0, 1);
    svg.addEventListener("mousemove", (e) => {
      const r = svg.getBoundingClientRect(), sr = sw.getBoundingClientRect(), vx = (e.clientX - r.left) / r.width * SW.W;
      if (vx < SW.L || vx > SW.W - SW.R) { cur.style.opacity = "0"; return; }
      const d = new Date(t0 + (vx - SW.L) / (SW.W - SW.L - SW.R) * span);
      cur.style.left = e.clientX - sr.left + "px"; cur.style.top = r.top - sr.top + 22 + "px"; cur.style.height = Math.max(r.height - 22, 0) + "px"; cur.style.opacity = "1";
      cur.firstElementChild.textContent = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    });
    svg.addEventListener("mouseleave", () => { cur.style.opacity = "0"; });
  }
  document.querySelectorAll("[data-ip]").forEach((b) => b.onclick = () => { S.logs = { ...S.logs, q: b.dataset.ip, page: 1 }; location.hash = "#/logs"; });
  document.querySelectorAll(".act g[data-i]").forEach((g) => {
    const d = S.a.stats.timeline[+g.dataset.i];
    g.onmousemove = (e) => showTip(`<b>${esc(d.t)}</b> · ${d.total} eventos<br>${SEV.filter((s) => d[s]).map((s) => `${s}: ${d[s]}`).join(" · ") || "Sin hallazgos asociados"}`, e);
    g.onmouseleave = hideTip;
  });
  apply();
  dashFx(dash);
}

/* Animaciones de entrada del Panel (anime.js). Son opcionales: sin la librería o con «reducir movimiento»
   todo queda directamente en su estado final, y las animaciones solo tocan atributos y estilos por JavaScript (compatible con la CSP). */
const AURORA_HTML = '<div class="aurora" aria-hidden="true"><i></i><i></i><i></i></div>';
let AURORA = [];
function stopLoops() {
  AURORA.forEach((a) => a.pause()); AURORA = [];
  if (typeof anime === "function") anime.running.slice().forEach((a) => a.pause());          // sin animaciones en bucle de paneles anteriores
}
/* Aurora de fondo: tres manchas que derivan despacio; se detienen con la pestaña oculta para no gastar equipo. */
function auroraFx(root) {
  if (typeof anime !== "function" || reducedMotion()) return;
  [[1, 90, 60, 14000], [2, -80, -50, 17000], [3, 70, -40, 20000]].forEach(([n, x, y, d]) => {
    const el = root.querySelector(`.aurora i:nth-child(${n})`);
    if (el) AURORA.push(anime({ targets: el, translateX: [0, x], translateY: [0, y], duration: d, direction: "alternate", loop: true, easing: "easeInOutSine" }));
  });
}
document.addEventListener("visibilitychange", () => AURORA.forEach((a) => (document.hidden ? a.pause() : a.play())));
/* Entrada escalonada de las vistas de inicio y phishing; solo cuando cambia de pantalla (no en cada redibujado). */
function viewFx(root, key, withAurora) {
  if (!root) return;
  if (withAurora) auroraFx(root);
  const first = S.fxKey !== key; S.fxKey = key;
  if (!first || typeof anime !== "function" || reducedMotion()) return;
  const host = root.querySelector(":scope > .landing");
  const kids = [...(host || root).querySelectorAll(":scope > *:not(.aurora)")];
  anime.set(kids, { opacity: 0 });
  anime({ targets: kids, opacity: [0, 1], translateY: [18, 0], delay: anime.stagger(70), duration: 550, easing: "easeOutCubic",
    complete: () => kids.forEach((e) => { e.style.opacity = ""; e.style.transform = ""; }) });
}

function dashFx(dash) {
  if (typeof anime !== "function" || reducedMotion()) return;
  stopLoops();
  const q = (s) => [...dash.querySelectorAll(s)];
  const clear = (els, props) => () => els.forEach((e) => props.forEach((p) => { e.style[p] = ""; }));
  dash.classList.add("fx-run");
  const cards = q("[data-card]"), lanes = q(".swim .lane"), kpis = q(".kpi");
  anime.set([...cards, ...kpis, ...lanes, ...q(".hero")], { opacity: 0 });
  anime({ targets: ".dash .hero", opacity: [0, 1], translateY: [16, 0], duration: 600, easing: "easeOutCubic", complete: clear(q(".hero"), ["transform", "opacity"]) });
  anime({ targets: ".dash .hero .scan", translateX: ["-120%", "120%"], duration: 1400, delay: 350, easing: "easeInOutSine" });
  anime({ targets: kpis, opacity: [0, 1], translateY: [20, 0], delay: anime.stagger(90, { start: 150 }), duration: 600, easing: "easeOutCubic", complete: clear(kpis, ["transform", "opacity"]) });
  q(".rfg").forEach((c, i) => anime({ targets: c, "stroke-dasharray": ["0 139", c.dataset.dash], duration: 1100, delay: 400 + i * 100, easing: "easeOutCubic" }));
  q(".donut .seg").forEach((c, i) => anime({ targets: c, "stroke-dasharray": ["0 339", c.dataset.dash], duration: 900, delay: 350 + i * 160, easing: "easeOutCubic" }));
  anime({ targets: ".dash .sevchip", opacity: [0, 1], translateX: [16, 0], delay: anime.stagger(80, { start: 500 }), duration: 500, easing: "easeOutQuad", complete: clear(q(".sevchip"), ["transform", "opacity"]) });
  anime({ targets: "#dTot", opacity: [0, 1], duration: 600, delay: 500, easing: "easeOutQuad" });
  anime({ targets: ".dash .sevbar span", scaleX: [0, 1], delay: anime.stagger(110, { start: 500 }), duration: 700, easing: "easeOutCubic" });
  q(".bar-fill").forEach((e, i) => anime({ targets: e, scaleX: [0, 1], duration: 800, delay: 500 + i * 70, easing: "easeOutCubic" }));
  anime({ targets: cards, opacity: [0, 1], translateY: [26, 0], delay: anime.stagger(110, { start: 700 }), duration: 650, easing: "easeOutCubic", complete: () => { clear(cards, ["transform", "opacity"])(); } });
  anime({ targets: lanes, opacity: [0, 1], delay: anime.stagger(70, { start: 900 }), duration: 400, easing: "linear", complete: clear(lanes, ["opacity"]) });
  q(".swim rect.seg").forEach((r, i) => { const w = +r.getAttribute("width"); anime({ targets: r, width: [0, w], delay: 1000 + i * 40, duration: 600, easing: "easeOutQuad" }); });
  q(".act g[data-i] rect").forEach((r, i) => {
    const h = +r.getAttribute("height"), y = +r.getAttribute("y"); if (!h || r.getAttribute("fill") === "transparent") return;
    anime({ targets: r, height: [0, h], y: [y + h, y], delay: 1100 + i * 8, duration: 600, easing: "easeOutQuad" });
  });
  auroraFx(dash);
  setTimeout(() => dash.classList.remove("fx-run"), 2600);
}

/* ---------- incidentes ---------- */
function evLinks(ids) {
  return (ids || []).map((i) => `<button class="ev-link" data-ev="${esc(i)}">${esc(i)}</button>`).join("");
}
function incidents() {
  const A = S.ai, G = A.incidents || {};
  const cards = S.a.incidents.map((inc) => {
    const g = G[inc.id] || {}, fs = S.a.findings.filter((f) => f.incident_id === inc.id);
    return `<article class="panel inc ${esc(inc.severity)}" id="${esc(inc.id)}">
      <div class="inc-head"><div><span class="id">${esc(inc.id)}</span><h2>${esc(g.title || inc.title)}</h2></div>${sevPill(inc.severity)}</div>
      <div class="meta-line"><span>${hhmmss(inc.time_start)}–${hhmmss(inc.time_end)}</span><span>${plural(inc.evidence_count, "evento", "eventos")} de evidencia</span>
        ${g.confidence ? `<span>Confianza de la correlación: ${esc(g.confidence)}</span>` : ""}</div>
      <p>${esc(g.narrative || "")}</p>
      ${g.confidence_reason ? `<p class="muted">${esc(g.confidence_reason)}</p>` : ""}
      <div>${inc.external_ips.map((i) => `<span class="tag">${esc(i)}</span>`).join("")}${inc.actor_users.map((u) => `<span class="tag">${esc(u)}</span>`).join("")}${inc.hosts.map((h) => `<span class="tag">${esc(h)}</span>`).join("")}</div>
      ${(g.kill_chain || []).length ? `<h4 style="margin-top:12px">Secuencia de eventos</h4><ol class="kc" style="list-style:none">${g.kill_chain.map((s) => `<li><span class="t">${esc(hhmmss(s.time) || s.time)}</span>${esc(s.step)} ${evLinks(s.evidence_ids)}</li>`).join("")}</ol>` : ""}
      <h4 style="margin-top:12px">Hallazgos</h4>
      ${fs.map((f) => `<div class="finding-row">${sevPill(f.severity)}<button class="title" data-open="${esc(f.id)}">${esc(f.id)} · ${esc(f.title)}</button><span class="muted mono">${hhmm(f.time_start)}</span></div>`).join("")}
      ${triageBox(inc.id)}
    </article>`;
  }).join("");
  const hyp = S.a.hypotheses.length ? `<div class="panel"><h3>Posibles relaciones sin evidencia directa</h3><p class="muted">No se fusionan incidentes por compartir recursos u hosts. Estas relaciones quedan como hipótesis de confianza baja para validar.</p><ul>${S.a.hypotheses.map((h) => `<li><b>${esc(h.id)}</b> ${esc(h.statement)} <span class="muted">${esc(h.basis)}</span></li>`).join("")}</ul></div>` : "";
  return `<div class="page-head"><div><h1>Incidentes</h1><p>${esc(A.cross_incident_assessment || "")}</p></div></div>${triagePanel()}${cards}${hyp}`;
}

/* ---------- triaje asistido por IA: la IA recomienda, el analista decide, la severidad es del motor ---------- */
const DECISIONS = ["Escalado", "Descartado", "En investigación"];
function triagePanel() {
  const T = S.triage;
  if (!T) return `<div class="panel"><h3>Triaje</h3><p class="muted">Cargando recomendaciones…</p></div>`;
  const isAI = T.mode === "ia", v = T.validation || {}, r = T.resumen || {};
  return `<div class="panel" id="triPanel"><h3>Triaje asistido por IA</h3>
    <p class="muted">Cada incidente tiene una recomendación (Escalar, Probable falso positivo o Falta información) con sus motivos y qué dato la cambiaría. La severidad la fija siempre el motor: la IA no la modifica y, si propone ser menos exigente en un incidente Crítico o Alto, se conserva la del motor y se marca el conflicto. La decisión final es tuya.</p>
    <p>Recomendaciones: <span class="mode-badge ${isAI ? "ia" : "determinista"}">${isAI ? aiBadge(T) : "Reglas del motor"}</span>
      · Decididos: <b>${r.decididos ?? 0}</b> de ${r.total ?? 0}</p>
    ${isAI ? `<div class="stat-line"><span>Con IA: <b>${v.con_ia ?? 0}</b></span><span>Respaldo del motor: <b>${v.respaldo_motor ?? 0}</b></span><span>Conflictos con el motor: <b>${v.conflictos ?? 0}</b></span><span>Difieren del motor: <b>${v.difieren ?? 0}</b></span><span>Citas descartadas: <b>${v.citas_descartadas ?? 0}</b></span><span>IPs descartadas: <b>${v.ips_descartadas ?? 0}</b></span></div>` : ""}
    ${(T.errors || []).length ? `<div class="notice" style="margin-top:10px">${T.errors.map(esc).join("<br>")}</div>` : ""}
    <div class="fields" style="margin-top:10px">
      <label class="f">Proveedor<select id="triProv">${PROV_OPTIONS}</select></label>
      <label class="f" id="triKeyBox" ${S.aiConfigured ? "hidden" : ""}>API key de Anthropic (solo esta sesión)<input type="password" id="triKey" placeholder="sk-ant-…" autocomplete="off"></label>
      <label class="f" id="triModelBox" hidden>Modelo de Ollama<select id="triModel"></select></label>${cloudFields("triCl")}</div>
    <div class="notice" id="triOlHint" style="margin-top:10px" hidden>Recomendación: un modelo local pequeño (como llama3.1:8b) sirve como apoyo y para practicar, pero puede equivocarse al redactar y al recomendar. Para el informe formal y el triaje, usa un modelo de mayor calidad, como Claude.</div>
    <div style="margin-top:10px"><button class="btn dark" id="triRun">${isAI ? "Volver a generar con IA" : "Generar recomendaciones con IA"}</button></div></div>`;
}
function triageBox(id) {
  const t = S.triage && (S.triage.items || []).find((x) => x.incident_id === id);
  if (!t) return "";
  const d = t.decision, sug = t.ia_sugirio;
  return `<div class="tri" data-tri="${esc(id)}"><h4>Triaje</h4>
    <div class="tri-head"><span class="tri-chip ${esc(t.recommendation.replace(/\s+/g, "-"))}">${esc(t.recommendation)}</span>
      <span class="muted">Confianza: ${esc(t.confidence)} · ${t.source === "ia" ? "propuesta por la IA" : "propuesta por el motor"}${t.difiere ? " · difiere del motor" : ""}</span></div>
    ${t.conflicto && sug ? `<div class="notice" style="margin:8px 0">Conflicto: la IA sugirió «${esc(sug.recommendation)}», pero el incidente es grave para el motor y se mantiene su recomendación. Revísalo antes de descartar.</div>` : ""}
    <ul class="tri-reasons">${t.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
    ${(t.evidence_ids || []).length ? `<div>${evLinks(t.evidence_ids)}</div>` : ""}
    <p class="muted"><b>Cambiaría de opinión si:</b> ${esc(t.would_change_if)}</p>
    <div class="tri-dec"><textarea maxlength="500" rows="2" placeholder="Nota del analista (opcional)" aria-label="Nota del analista para ${esc(id)}">${esc(d ? d.note : "")}</textarea>
      <div>${DECISIONS.map((x) => `<button class="btn ${d && d.decision === x ? "dark" : ""}" data-dec="${esc(x)}">${esc(x)}</button>`).join(" ")}</div></div>
    ${d ? `<p class="muted">Decisión: <b>${esc(d.decision)}</b>${d.by ? " · " + esc(d.by) : ""} · ${esc(d.at)}</p>` : ""}</div>`;
}
async function loadTriage() {
  try { S.triage = await api(`/api/sessions/${S.sid}/triage`); } catch { S.triage = { mode: "motor", items: [], resumen: {}, validation: {}, errors: [] }; }
  S.keepScroll = true; if (route() === "incidents") render();
}
function bindTriage() {
  if (S.triage === null) { S.triage = false; loadTriage(); return; }
  document.querySelectorAll("[data-dec]").forEach((b) => b.onclick = async () => {
    const box = b.closest(".tri"), fd = new FormData();
    fd.append("decision", b.dataset.dec); fd.append("tz", String(new Date().getTimezoneOffset())); fd.append("note", box.querySelector("textarea").value);
    try { S.triage = { ...S.triage, ...(await api(`/api/sessions/${S.sid}/triage/${encodeURIComponent(box.dataset.tri)}/decision`, { method: "POST", body: fd })) }; S.keepScroll = true; render(); toast("Decisión registrada"); }
    catch (e) { toast(e.message); }
  });
  const prov = $("#triProv"); if (!prov) return;
  let ol = null;
  const sync = () => {
    const isOl = prov.value === "ollama";
    $("#triKeyBox").hidden = prov.value !== "anthropic" || S.aiConfigured; $("#triModelBox").hidden = !isOl; $("#triOlHint").hidden = !isOl;
    showCloud(document, "triCl", prov.value);
    if (isOl && !ol) api("/api/ai/providers").then((p) => { ol = p.ollama; fill(); }).catch(() => { ol = { models: [] }; fill(); });
    else if (isOl) fill();
  };
  const fill = () => { const sel = $("#triModel"); sel.replaceChildren(...((ol && ol.models) || []).map((m) => { const o = document.createElement("option"); o.value = m; o.textContent = m; return o; })); };
  prov.onchange = sync;
  $("#triRun").onclick = async () => {
    busy(true, "La IA está evaluando cada incidente. Un modelo local puede tardar varios minutos…");
    try {
      const { h, q } = aiRequest(document, prov.value, $("#triKey"), $("#triModel").value);
      S.triage = await api(`/api/sessions/${S.sid}/triage/ai${q}`, { method: "POST", headers: h });
      toast("Recomendaciones generadas"); S.keepScroll = true; render();
    } catch (e) { toast(e.message); } finally { busy(false); }
  };
}
function bindIncidents() {
  if (S.openInc) { const el = document.getElementById(S.openInc); S.openInc = null; if (el) { el.scrollIntoView({ block: "start" }); el.classList.add("pulse"); } }
  bindEvidence(); bindTriage(); document.querySelectorAll("[data-open]").forEach((b) => b.onclick = () => { S.openFinding = b.dataset.open; S.findingFilter = "Todos"; location.hash = "#/findings"; }); }

/* ---------- MITRE ATT&CK ---------- */
const MITRE_URL = /^https:\/\/attack\.mitre\.org\/techniques\/T\d{4}(\/\d{3})?\/$/;
function techTag(id, extra) {   // extra: técnicas de otra fuente (correos), por si no hay análisis de logs abierto
  const t = (((S.a && S.a.attack) || {}).techniques || {})[id] || (extra || {})[id];
  if (!t || !MITRE_URL.test(t.url)) return `<span class="tag">${esc(id)}</span>`;
  return `<a class="tag tag-link" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer" title="Ver ${esc(id)} en attack.mitre.org">${esc(id)} ${esc(t.name)}</a>`;
}
function attack() {
  const A = S.a.attack, head = `<div class="page-head"><div><h1>Matriz MITRE ATT&amp;CK</h1><p>Técnicas que los hallazgos sugieren, agrupadas por táctica (ATT&amp;CK Enterprise v${esc(A.version)}).</p></div></div>`;
  if (!A.tactics.length) return head + `<div class="panel"><p class="muted">Ningún hallazgo de este archivo tiene técnicas ATT&amp;CK asociadas.</p></div>`;
  const cols = A.tactics.map((t) => `<section class="mx-col" aria-label="${esc(t.name_es)}">
      <h3>${esc(t.name_es)}<small>${esc(t.id)} · ${esc(t.name)}</small></h3>
      ${t.techniques.map((c) => `<article class="mx-cell ${esc(c.severity)}">
        ${MITRE_URL.test(c.url) ? `<a href="${esc(c.url)}" target="_blank" rel="noopener noreferrer"><span class="mono">${esc(c.id)}</span> ${esc(c.name)}</a>` : `<span class="mono">${esc(c.id)}</span> ${esc(c.name)}`}
        <div class="mx-meta">${sevPill(c.severity)}<span class="muted">${plural(c.count, "hallazgo", "hallazgos")}</span></div>
        <div>${c.finding_ids.map((f) => `<button class="tag tag-btn" data-mxf="${esc(c.id)}" title="Ver hallazgos con ${esc(c.id)}">${esc(f)}</button>`).join("")}</div>
      </article>`).join("")}</section>`).join("");
  return `${head}
    <div class="notice">La asignación es <b>orientativa</b>: indica técnicas consistentes con la evidencia, no prueba que el atacante las haya usado, y no cambia la criticidad. Una técnica que pertenece a varias tácticas aparece en cada una.</div>
    <div class="panel" style="margin-top:16px"><h3>Exportar</h3>
      <p class="muted">Descarga una capa para <b>ATT&amp;CK Navigator</b> (el color indica la criticidad máxima). En Navigator: <i>Open Existing Layer</i> → <i>Upload from local</i>. El archivo se genera aquí; no se envía a ningún servicio.</p>
      <button class="btn primary" id="navLayer">Descargar capa para Navigator (.json)</button></div>
    <div class="mx" role="region" aria-label="Matriz ATT&amp;CK">${cols}</div>
    <p class="muted">${A.techniques_total} ${A.techniques_total === 1 ? "técnica" : "técnicas"} en ${A.tactics.length} ${A.tactics.length === 1 ? "táctica" : "tácticas"}.${A.findings_without_mapping ? ` ${plural(A.findings_without_mapping, "hallazgo sin técnica asociada", "hallazgos sin técnica asociada")} (por ejemplo, calidad de datos).` : ""}</p>`;
}
function bindAttack() {
  document.querySelectorAll("[data-mxf]").forEach((b) => b.onclick = () => { S.findingQ = b.dataset.mxf; S.findingFilter = "Todos"; S.findingCat = ""; location.hash = "#/findings"; });
  const btn = $("#navLayer"); if (!btn) return;
  btn.onclick = async () => {
    try {
      const r = await fetch(`/api/sessions/${S.sid}/attack-layer.json`, { headers: authHeaders() });
      if (!r.ok) throw new Error("No se pudo generar la capa de Navigator.");
      const url = URL.createObjectURL(await r.blob()), a = document.createElement("a");
      a.href = url; a.download = "attack_navigator_layer.json"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast("Capa descargada");
    } catch (e) { toast(e.message); }
  };
}

/* ---------- hallazgos ---------- */
function findings() {
  const flt = S.findingFilter, q = S.findingQ.trim().toLowerCase();
  const list = S.a.findings.filter((f) => (flt === "Todos" || f.severity === flt) && (!S.findingCat || f.category === S.findingCat)
    && (!q || (f.id + " " + f.title + " " + f.category + " " + f.tactic + " " + (f.mitre || []).join(" ")).toLowerCase().includes(q)));
  const cats = Object.keys(S.a.stats.findings_by_category);
  const AI = S.ai.findings || {};
  const chips = ["Todos", ...SEV].map((s) => `<button class="chip" data-chip="${s}" aria-pressed="${s === flt}">${s}${s === "Todos" ? "" : ` (${S.a.stats.findings_by_severity[s] || 0})`}</button>`).join("");
  const li = (a) => (a || []).map((x) => `<li>${esc(x)}</li>`).join("");
  const items = list.map((f) => {
    const a = AI[f.id] || {}, ap = a.action_plan || {};
    return `<details class="finding" id="${esc(f.id)}" ${S.openFinding === f.id ? "open" : ""}>
      <summary>${sevPill(f.severity)}<span class="mono muted">${esc(f.id)}</span><b>${esc(f.title)}</b><span class="muted mono">${hhmm(f.time_start)}</span></summary>
      <div class="f-body">
        <div style="margin-top:12px"><span class="tag">${esc(f.category)}</span><span class="tag">${esc(f.tactic)}</span>${(f.mitre || []).map(techTag).join("")}${f.incident_id ? `<span class="tag">${esc(f.incident_id)}</span>` : '<span class="tag">Observación (fuera de incidentes)</span>'}</div>
        <h4>Explicación técnica</h4><p>${esc(a.technical_explanation || f.explanation)}</p>
        <h4>Criticidad: ${esc(f.severity)}</h4><p>${esc(a.severity_justification || "")}</p><ul>${li(f.reasons)}</ul>
        <h4>Impacto en la organización</h4><p>${esc(a.impact || "")}</p>
        <h4>Evidencia (${plural(f.evidence_ids.length, "evento", "eventos")})</h4>
        <div class="evbox" data-fid="${esc(f.id)}"><button class="btn" data-loadev="${esc(f.id)}">Ver eventos de log</button></div>
        ${(S.a.siem_rules || []).includes(f.rule) ? `<h4>Buscar en tu SIEM</h4><div class="siembox"><button class="btn" data-siem="${esc(f.id)}">Ver consultas (Splunk, KQL, Sigma)</button></div>` : ""}
        <h4>Plan de acción</h4>
        <div class="plan"><div><h4>Investigar</h4><ul>${li(ap.investigate)}</ul></div><div><h4>Contener</h4><ul>${li(ap.contain)}</ul></div><div><h4>Remediar</h4><ul>${li(ap.remediate)}</ul></div></div>
      </div></details>`;
  }).join("");
  return `<div class="page-head"><div><h1>Hallazgos</h1><p>Cada hallazgo cita los Log_ID del archivo que lo sustentan.</p></div>${(S.a.siem_rules || []).some((k) => S.a.findings.some((f) => f.rule === k)) ? '<button class="btn" id="sigmaAll">Descargar reglas Sigma (.yml)</button>' : ""}</div>
    <div class="filters"><input type="search" id="fq" placeholder="Buscar por nombre, técnica (T1110) o táctica" value="${esc(S.findingQ)}" aria-label="Buscar hallazgos">
      <select id="fcat" aria-label="Categoría"><option value="">Todas las categorías</option>${cats.map((c) => `<option ${c === S.findingCat ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>
      <span class="muted">${list.length} de ${plural(S.a.findings.length, "hallazgo", "hallazgos")}</span></div>
    <div class="chip-row">${chips}</div>${items || "<p class='muted'>No hay hallazgos con ese filtro.</p>"}`;
}
function siemView(r) {
  const block = (label, txt) => txt ? `<div class="qblock"><div class="qhead"><b>${label}</b><button class="btn" data-copyq>Copiar</button></div><pre class="mono">${esc(txt)}</pre></div>` : "";
  return `<p class="muted">Revisa el índice, el sourcetype y los nombres de campo: cada SIEM los nombra distinto. Cubren la ventana del hallazgo ±30 min.</p>${block("Splunk (SPL)", r.splunk)}${block("Microsoft Sentinel / Defender (KQL)", r.kql)}${block("Sigma (YAML)", r.sigma)}`;
}
function bindSiemCopy() {
  document.querySelectorAll("[data-copyq]").forEach((b) => b.onclick = async () => {
    const txt = b.closest(".qblock").querySelector("pre").textContent;
    try { await navigator.clipboard.writeText(txt); toast("Copiado"); } catch { toast("No se pudo copiar; selecciona el texto manualmente."); }
  });
}
function evTable(rows) {
  return `<div class="tbl-wrap"><table class="ev-table"><thead><tr><th>Log_ID</th><th>Hora</th><th>Equipo</th><th>Evento</th><th>Usuario</th><th>IP origen</th><th>Destino</th><th>Detalle</th><th>Resultado</th></tr></thead><tbody>${rows.map((r) =>
    `<tr><td class="mono">${esc(r.Log_ID)}</td><td class="mono">${esc(hhmmss(r.Timestamp))}</td><td>${esc(r.Hostname)}</td><td class="mono">${esc(r.Event_ID)}</td><td>${esc(r.User)}</td><td class="mono">${esc(r.Source_IP)}</td><td>${esc(r.Destination)}</td><td class="cmd">${esc(r.Process_CommandLine || r.Event_Description)}</td><td>${esc(r.Result)}</td></tr>`).join("")}</tbody></table></div>`;
}
function bindFindings() {
  let t; $("#fq").oninput = (e) => { clearTimeout(t); t = setTimeout(() => { S.findingQ = e.target.value; S.keepScroll = true; render(); const q = $("#fq"); q.focus(); q.setSelectionRange(q.value.length, q.value.length); }, 220); };
  $("#fcat").onchange = (e) => { S.findingCat = e.target.value; S.keepScroll = true; render(); };
  document.querySelectorAll("[data-chip]").forEach((b) => b.onclick = () => { S.findingFilter = b.dataset.chip; S.openFinding = null; render(); });
  document.querySelectorAll("[data-loadev]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    try { const r = await api(`/api/sessions/${S.sid}/findings/${b.dataset.loadev}/evidence`); b.closest(".evbox").innerHTML = evTable(r.rows); }
    catch (e) { toast(e.message); b.disabled = false; }
  });
  document.querySelectorAll("[data-siem]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    try { const r = await api(`/api/sessions/${S.sid}/findings/${b.dataset.siem}/queries`); b.closest(".siembox").innerHTML = siemView(r); bindSiemCopy(); }
    catch (e) { toast(e.message); b.disabled = false; }
  });
  const sg = $("#sigmaAll");
  if (sg) sg.onclick = async () => {
    try {
      const r = await fetch(`/api/sessions/${S.sid}/sigma.yml`, { headers: authHeaders() });
      if (!r.ok) throw new Error("No hay reglas Sigma para los hallazgos de esta sesión.");
      const url = URL.createObjectURL(await r.blob()), a = document.createElement("a");
      a.href = url; a.download = "reglas_sigma.yml"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast("Reglas Sigma descargadas");
    } catch (e) { toast(e.message); }
  };
  const open = S.openFinding && document.getElementById(S.openFinding);
  if (open) { open.scrollIntoView({ block: "start" }); const b = open.querySelector("[data-loadev]"); if (b) b.click(); }
  S.openFinding = null;
}

/* modal de evidencia por Log_ID */
function bindEvidence() {
  document.querySelectorAll("[data-ev]").forEach((b) => b.onclick = async () => {
    try {
      S.logs = { page: 1, q: b.dataset.ev, severity: "", flagged: "", host: "", user: "", event_id: "", finding: "" };
      const r = await api(`/api/sessions/${S.sid}/events?page_size=10&q=${encodeURIComponent(b.dataset.ev)}`);
      openDialog(b.dataset.ev, evTable(r.rows));
    } catch (e) { toast(e.message); }
  });
}
function openDialog(title, body) {
  let d = $("#dlg"); if (d) d.remove();
  d = document.createElement("dialog"); d.id = "dlg";
  d.innerHTML = `<div class="dh"><h3>${esc(title)}</h3><button class="btn" id="dclose">Cerrar</button></div><div class="db">${body}</div>`;
  document.body.appendChild(d); d.showModal();
  $("#dclose").onclick = () => d.close(); d.onclick = (e) => { if (e.target === d) d.close(); };
}

/* ---------- eventos ---------- */
let logsData = null;
function logs() {
  return `<div class="page-head"><div><h1>Eventos</h1><p>Todos los registros del archivo. Los eventos que forman parte de un incidente llevan una marca de color.</p></div></div>
    <div class="filters">
      <input type="search" id="q" placeholder="Buscar por Log_ID, usuario, IP, comando…" value="${esc(S.logs.q)}" aria-label="Buscar eventos">
      <select id="fHost" aria-label="Equipo"><option value="">Todos los equipos</option></select>
      <select id="fUser" aria-label="Usuario"><option value="">Todos los usuarios</option></select>
      <select id="fEid" aria-label="Event ID"><option value="">Todos los Event ID</option></select>
      <select id="fSev" aria-label="Severidad del SIEM"><option value="">Severidad SIEM</option></select>
      <label><input type="checkbox" id="fFlag" ${S.logs.flagged ? "checked" : ""}> Solo ligados a incidentes</label>
    </div>
    <div id="logsOut"><p class="muted">Cargando…</p></div>`;
}
async function loadLogs() {
  const L = S.logs, qs = new URLSearchParams({ page: L.page, page_size: 50, q: L.q, severity: L.severity, flagged: L.flagged, host: L.host, user: L.user, event_id: L.event_id, finding: L.finding });
  try {
    const r = await api(`/api/sessions/${S.sid}/events?${qs}`);
    const fill = (id, arr, cur) => { const el = $(id); if (el.options.length > 1) return; arr.forEach((v) => el.add(new Option(v, v))); el.value = cur; };
    fill("#fHost", r.options.hosts, L.host); fill("#fUser", r.options.users, L.user); fill("#fEid", r.options.event_ids, L.event_id); fill("#fSev", r.options.severities, L.severity);
    $("#logsOut").innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Log_ID</th><th>Hora</th><th>Equipo</th><th>Event ID</th><th>Usuario</th><th>IP origen</th><th>Destino</th><th>Descripción / comando</th><th>Resultado</th><th>SIEM</th><th>Hallazgo</th></tr></thead><tbody>${r.rows.map((x) =>
      `<tr class="${x.flag_severity ? "flag s-" + esc(x.flag_severity) : ""}"><td class="mono">${esc(x.Log_ID)}</td><td class="mono">${esc(hhmmss(x.Timestamp))}</td><td>${esc(x.Hostname)}</td><td class="mono">${esc(x.Event_ID)}</td><td>${esc(x.User)}</td><td class="mono">${esc(x.Source_IP)}</td><td>${esc(x.Destination)}</td><td class="cmd">${esc(x.Process_CommandLine || x.Event_Description)}</td><td>${esc(x.Result)}</td><td>${esc(x.Severity)}</td><td>${(x.findings || []).map((f) => `<span class="tag">${esc(f)}</span>`).join("")}</td></tr>`).join("") || `<tr><td colspan="11" class="muted">Ningún evento coincide con los filtros.</td></tr>`}</tbody></table></div>
      <div class="pager"><span>${num(r.total)} eventos · página ${r.page} de ${r.pages}</span><button class="btn" id="prev" ${r.page <= 1 ? "disabled" : ""}>Anterior</button><button class="btn" id="next" ${r.page >= r.pages ? "disabled" : ""}>Siguiente</button></div>`;
    $("#prev").onclick = () => { L.page = r.page - 1; loadLogs(); };
    $("#next").onclick = () => { L.page = r.page + 1; loadLogs(); };
  } catch (e) { $("#logsOut").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
function bindLogs() {
  const L = S.logs; let t;
  $("#q").oninput = (e) => { clearTimeout(t); t = setTimeout(() => { L.q = e.target.value; L.page = 1; loadLogs(); }, 250); };
  const sel = [["#fHost", "host"], ["#fUser", "user"], ["#fEid", "event_id"], ["#fSev", "severity"]];
  sel.forEach(([id, k]) => $(id).onchange = (e) => { L[k] = e.target.value; L.page = 1; loadLogs(); });
  $("#fFlag").onchange = (e) => { L.flagged = e.target.checked ? "1" : ""; L.page = 1; loadLogs(); };
  loadLogs();
}

/* ---------- IoC ---------- */
const ipOf = (v) => { const m = String(v || "").match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/); return m ? m[1] : ""; };
function repKey(i) {
  if (i.type === "IP") return ipOf(i.value) || i.value;
  if (i.type === "URL/URI" && /^https?:\/\//i.test(i.value)) { try { return new URL(i.value).hostname.toLowerCase(); } catch { return ""; } }
  return "";
}
function repCell(r) {
  if (!r) return `<span class="muted">—</span>`;
  const vt = r.vt && r.vt.status === "ok" ? `VT ${r.vt.malicious}/${r.vt.total}` : r.vt ? "VT sin datos" : "";
  const ab = r.abuse && r.abuse.status === "ok" ? `Abuse ${r.abuse.score} %` : r.abuse ? "Abuse sin datos" : "";
  const links = [r.vt && r.vt.link ? `<a href="${esc(r.vt.link)}" target="_blank" rel="noopener noreferrer">VirusTotal</a>` : "",
                 r.abuse && r.abuse.link ? `<a href="${esc(r.abuse.link)}" target="_blank" rel="noopener noreferrer">AbuseIPDB</a>` : ""].filter(Boolean).join(" · ");
  const who = [r.abuse && r.abuse.country, (r.abuse && r.abuse.isp) || (r.vt && (r.vt.owner || r.vt.registrar))].filter(Boolean).join(" · ");
  return `<span class="rep ${esc(String(r.verdict).replace(/\s+/g, "-"))}">${esc(r.verdict)}</span>${r.reserved ? ` <span class="muted">(prueba)</span>` : ""}
    <div class="muted" style="font-size:12px;margin-top:3px">${esc([vt, ab].filter(Boolean).join(" · "))}${who ? `<br>${esc(who)}` : ""}${links ? `<br>${links}` : ""}</div>`;
}
function intelPanel(c = S) {
  const I = c.intel, job = I && I.job, plan = I && I.plan;
  const head = `<h3>Reputación de indicadores externos <span class="muted" style="font-weight:400">(VirusTotal y AbuseIPDB, opcional)</span></h3>`;
  if (!I) return `<div class="panel">${head}<p class="muted">Cargando…</p></div>`;
  if (job && job.status === "running") {
    const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
    return `<div class="panel">${head}<p>Consultando indicadores… <b>${job.done}</b> de <b>${job.total}</b>. Con el plan gratuito de VirusTotal son 4 consultas por minuto, así que puede tardar unos minutos.</p>
      <div class="meter" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><span style="width:${pct}%"></span></div></div>`;
  }
  const notices = job && (job.notices || []).length ? `<div class="notice" style="margin-top:12px">${job.notices.map(esc).join("<br>")}</div>` : "";
  if (c.intelConfirm) {
    const q = plan.queries, prov = I.configured;
    const need = [!prov.virustotal ? `<label class="f" style="max-width:420px">API key de VirusTotal (solo se usa en esta consulta)<input type="password" id="vtKey" autocomplete="off"></label>` : "",
                  !prov.abuseipdb ? `<label class="f" style="max-width:420px">API key de AbuseIPDB (solo se usa en esta consulta)<input type="password" id="abKey" autocomplete="off"></label>` : ""].join("");
    const skipped = plan.skipped.length ? `<details style="margin-top:8px"><summary class="muted">${plan.skipped.length} indicadores no se enviarán</summary><ul>${plan.skipped.map((x) => `<li><span class="mono">${esc(x.value)}</span> — ${esc(x.reason)}</li>`).join("")}</ul></details>` : "";
    const resv = plan.reserved_available ? `<label style="display:flex;gap:8px;align-items:center;margin-top:10px"><input type="checkbox" id="resv" ${c.intelReserved ? "checked" : ""}> Incluir ${plan.reserved_available} IP de documentación (solo para probar la conexión; no tienen reputación real)</label>` : "";
    const none = !q.length ? `<div class="notice" style="margin-top:10px">No hay indicadores públicos para consultar.</div>` : "";
    return `<div class="panel">${head}
      <p><b>Se enviarán ${q.length} indicadores públicos</b> a VirusTotal y AbuseIPDB (solo IP y dominios). No se envían cuentas, equipos, comandos ni contenido de los logs. Cada servicio recibe esos indicadores y puede registrarlos.</p>
      <div>${q.map((x) => `<span class="tag mono">${esc(x.value)}</span>`).join(" ")}</div>
      ${plan.truncated ? `<p class="muted">Se consultarán los primeros ${plan.max_indicators}; ${plan.truncated} quedan fuera por el tope por consulta.</p>` : ""}
      ${skipped}${resv}${none}
      ${need ? `<div style="margin-top:12px;display:flex;gap:12px;flex-wrap:wrap">${need}</div>` : ""}
      <div style="margin-top:14px;display:flex;gap:10px"><button class="btn primary" id="intelGo" ${q.length ? "" : "disabled"}>Confirmar y consultar</button><button class="btn ghost" id="intelCancel">Cancelar</button></div></div>`;
  }
  const done = job && job.status === "done";
  return `<div class="panel">${head}
    <p class="muted">Añade contexto a los indicadores externos: cuántos motores los marcan como maliciosos y cuántos reportes de abuso tienen. No cambia la criticidad de los hallazgos. Solo se envían IP y dominios públicos, y solo cuando tú lo confirmas.</p>
    ${done ? `<div class="stat-line"><span>Consultados: <b>${job.results.length}</b></span><span>Maliciosos: <b>${job.results.filter((r) => r.verdict === "Malicioso").length}</b></span><span>Sospechosos: <b>${job.results.filter((r) => r.verdict === "Sospechoso").length}</b></span><span>${esc(job.queried_at || "")}</span></div>` : ""}
    ${job && job.status === "error" ? `<div class="notice">No se pudo completar la consulta.</div>` : ""}${notices}
    <div style="margin-top:12px"><button class="btn dark" id="intelOpen">${done ? "Volver a consultar" : "Consultar reputación…"}</button></div></div>`;
}
function iocs() {
  const res = {}; ((S.intel && S.intel.job && S.intel.job.results) || []).forEach((r) => { res[r.indicator] = r; });
  const hasRep = Object.keys(res).length > 0;
  return `<div class="page-head"><div><h1>Indicadores de compromiso</h1><p>Solo se listan valores presentes en los hallazgos con evidencia.</p></div></div>
    ${intelPanel()}
    <div class="tbl-wrap" style="margin-top:16px"><table><thead><tr><th>Tipo</th><th>Valor</th><th>Criticidad</th>${hasRep ? "<th>Reputación</th>" : ""}<th>Notas</th><th>Primera vez</th><th>Última vez</th><th>Hallazgos</th></tr></thead><tbody>${S.a.iocs.map((i) =>
      `<tr><td>${esc(i.type)}</td><td class="mono" style="word-break:break-all">${esc(i.value)}</td><td>${sevPill(i.severity)}</td>${hasRep ? `<td>${repCell(res[repKey(i)])}</td>` : ""}<td>${(i.notes || []).map(esc).join("<br>")}</td><td class="mono">${esc(hhmmss(i.first_seen))}</td><td class="mono">${esc(hhmmss(i.last_seen))}</td><td>${(i.finding_ids || []).map((f) => `<span class="tag">${esc(f)}</span>`).join("")}</td></tr>`).join("")}</tbody></table></div>`;
}
/* c = S (indicadores de los logs) o S.ph (correos); base = ruta de la API; where = sección que se repinta */
const intelUrl = (c, base) => `${base}/intel?include_reserved=${c.intelReserved ? "true" : "false"}`;
async function loadIntel(c = S, base = `/api/sessions/${S.sid}`, where = "iocs") {
  try {
    c.intel = await api(intelUrl(c, base));
    if (c.intel.job && c.intel.job.status === "running") pollIntel(c, base, where);
  } catch (e) { toast(e.message); }
  if (route() === where) { S.keepScroll = true; render(); }
}
function pollIntel(c = S, base = `/api/sessions/${S.sid}`, where = "iocs") {
  clearInterval(c.intelTimer);
  c.intelTimer = setInterval(async () => {
    try {
      c.intel = await api(intelUrl(c, base));
      const running = c.intel.job && c.intel.job.status === "running";
      if (!running) { clearInterval(c.intelTimer); toast("Consulta de reputación terminada"); }
      if (route() === where) { S.keepScroll = true; render(); }
    } catch { clearInterval(c.intelTimer); }
  }, 2500);
}
function bindIntel(c, base, where) {
  const open = $("#intelOpen"), cancel = $("#intelCancel"), go = $("#intelGo"), resv = $("#resv");
  if (open) open.onclick = () => { c.intelConfirm = true; S.keepScroll = true; render(); };
  if (cancel) cancel.onclick = () => { c.intelConfirm = false; S.keepScroll = true; render(); };
  if (resv) resv.onchange = async () => { c.intelReserved = resv.checked; S.keepScroll = true; await loadIntel(c, base, where); };
  if (go) go.onclick = async () => {
    const h = {}; const v = $("#vtKey"), a = $("#abKey");
    if (v && v.value.trim()) h["X-VT-Key"] = v.value.trim();
    if (a && a.value.trim()) h["X-AbuseIPDB-Key"] = a.value.trim();
    try {
      const r = await api(intelUrl(c, base), { method: "POST", headers: h });
      c.intel.job = r.job; c.intelConfirm = false; S.keepScroll = true; render(); pollIntel(c, base, where);
    } catch (e) { toast(e.message); }
  };
}
function bindIocs() {
  const base = `/api/sessions/${S.sid}`;
  if (!S.intel) loadIntel(S, base, "iocs");
  bindIntel(S, base, "iocs");
}

/* ---------- informe ---------- */
function report() {
  const A = S.ai, v = A.validation || {}, isAI = A.mode === "ia";
  return `<div class="page-head"><div><h1>Informe técnico</h1><p>El PDF incluye resumen ejecutivo, hallazgos con evidencia, criticidad, impacto, plan de acción y recomendaciones.</p></div></div>
    <div class="panel"><h3>Datos de portada</h3>
      <div class="fields"><label class="f">Cliente<input type="text" id="rClient" value="${esc(S.client)}"></label><label class="f">Analista<input type="text" id="rAnalyst" value="${esc(S.analyst)}"></label></div>
      <div class="row" style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn primary" id="pdf">Descargar informe en PDF</button><button class="btn" id="htmlrep">Descargar informe HTML</button></div>
      <p class="muted">El informe HTML es un solo archivo que se abre sin conexión en cualquier navegador: gráficos interactivos, modo claro y oscuro, y versión imprimible.</p></div>
    <div class="panel"><h3>Redacción con IA</h3>
      <p>Modo actual: <span class="mode-badge ${isAI ? "ia" : "determinista"}">${isAI ? aiBadge(A) : "Reglas deterministas"}</span></p>
      <p class="muted">La IA redacta el análisis de cada incidente a partir de los hallazgos ya detectados. No puede cambiar la criticidad ni agregar eventos: toda cita a un Log_ID o IP que no exista en el archivo se descarta y se informa abajo.</p>
      <label class="f" style="max-width:480px">Proveedor de IA
        <select id="prov">${PROV_OPTIONS}</select></label>
      <div id="keyBox">${S.aiConfigured ? "" : `<label class="f" style="max-width:480px">API key de Anthropic (solo se usa en esta sesión)<input type="password" id="key" placeholder="sk-ant-…" autocomplete="off"></label>`}</div>
      ${cloudFields("repCl")}
      <div id="olBox" hidden>
        <label class="f" style="max-width:480px">Modelo instalado en Ollama<select id="omodel"></select></label>
        <p class="muted" id="olInfo"></p>
        <div class="notice" id="olHint">Recomendación: un modelo local pequeño (como llama3.1:8b) sirve como apoyo y para practicar, pero puede equivocarse al redactar y al recomendar. Para el informe formal y el triaje, usa un modelo de mayor calidad, como Claude.</div></div>
      <div style="margin-top:12px"><button class="btn dark" id="runAi">${isAI ? "Volver a generar con IA" : "Generar análisis con IA"}</button></div>
      ${isAI ? `<div class="stat-line"><span>Citas verificadas: <b>${v.citas_verificadas ?? 0}</b></span><span>Citas descartadas: <b>${v.citas_descartadas ?? 0}</b></span><span>IPs descartadas: <b>${v.ips_descartadas ?? 0}</b></span><span>Hallazgos redactados por IA: <b>${v.hallazgos_con_ia ?? 0}</b> de ${v.hallazgos_total ?? S.a.findings.length}</span></div>` : ""}
      ${(A.errors || []).length ? `<div class="notice" style="margin-top:12px">${A.errors.map(esc).join("<br>")}</div>` : ""}
    </div>
    <div class="panel"><h3>Resumen ejecutivo</h3><p style="white-space:pre-line">${esc(A.executive_summary)}</p></div>
    <div class="panel"><h3>Acciones priorizadas</h3><ul class="actions">${(A.prioritized_actions || []).map((a) => `<li><span class="prio">${esc(a.priority)}</span>${esc(a.action)}</li>`).join("")}</ul></div>
    <div class="panel"><h3>Recomendaciones generales</h3><ul>${(A.general_recommendations || []).map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>`;
}
function bindReport() {
  const meta = () => { S.client = $("#rClient").value.trim(); S.analyst = $("#rAnalyst").value.trim(); return { client: S.client, analyst: S.analyst }; };
  const download = (btnId, ext, mime, label) => async () => {
    const m = meta(); busy(true, `Generando ${label}…`);
    try {
      const fd = new FormData(); fd.append("client", m.client); fd.append("analyst", m.analyst);      // POST: names stay out of the URL and the access logs
      const r = await fetch(`/api/sessions/${S.sid}/report.${ext}`, { method: "POST", body: fd, headers: authHeaders() });
      if (!r.ok) throw new Error(`No se pudo generar el ${label}.`);
      const url = URL.createObjectURL(new Blob([await r.arrayBuffer()], { type: mime })), a = document.createElement("a");
      a.href = url; a.download = `informe_incidentes_seguridad.${ext}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast(`${label} descargado`);
    } catch (e) { toast(e.message); } finally { busy(false); }
  };
  $("#pdf").onclick = download("pdf", "pdf", "application/pdf", "PDF");
  $("#htmlrep").onclick = download("htmlrep", "html", "text/html", "informe HTML");
  let ol = null;
  const syncProv = () => {
    const isOl = $("#prov").value === "ollama";
    $("#keyBox").hidden = $("#prov").value !== "anthropic"; $("#olBox").hidden = !isOl; showCloud(document, "repCl", $("#prov").value);
    if (isOl && !ol) { $("#olInfo").textContent = "Buscando Ollama…"; api("/api/ai/providers").then((p) => { ol = p.ollama; fillOl(); }).catch(() => { ol = { available: false, models: [], error: "No se pudo consultar Ollama." }; fillOl(); }); }
    else if (isOl) fillOl();
  };
  const fillOl = () => {
    const sel = $("#omodel"); if (!sel) return;
    sel.replaceChildren(...(ol.models || []).map((m) => { const o = document.createElement("option"); o.value = m; o.textContent = m; return o; }));
    $("#olInfo").textContent = !ol.available || !(ol.models || []).length ? (ol.error || "Ollama no está disponible.")
      : ol.local ? "Ollama corre en este equipo: los datos del análisis no salen de él." : `Ollama está en ${ol.host}: los datos del análisis se envían a ese equipo.`;
  };
  $("#prov").onchange = syncProv;
  $("#runAi").onclick = async () => {
    meta(); busy(true, "La IA está analizando los incidentes. Un modelo local puede tardar varios minutos…");
    try {
      const { h, q } = aiRequest(document, $("#prov").value, $("#key"), $("#omodel").value);
      const r = await api(`/api/sessions/${S.sid}/ai${q}`, { method: "POST", headers: h });
      S.ai = r.ai; toast("Análisis con IA aplicado"); render();
    } catch (e) { toast(e.message); } finally { busy(false); }
  };
}

/* ---------- phishing (.eml) ---------- */
/* Todo lo que viene del correo (asunto, remitente, URL, nombres de adjuntos) se escapa; las URL se muestran «defangeadas» y nunca como enlaces. */
const AUTH_SEV = { pass: "Bajo", fail: "Alto", permerror: "Alto", softfail: "Medio", none: "Medio", neutral: "Medio", temperror: "Medio" };
const authChip = (label, v) => `<span class="sev ${v ? (AUTH_SEV[v] || "Medio") : "Bajo"}" title="${esc(label)}">${esc(label)}: ${esc(v || "sin dato")}</span>`;
function phishingUpload() {
  return `<section class="landing">
    <h1>Análisis de correos sospechosos</h1>
    <p class="lead">Sube un correo reportado como phishing (.eml) y obtén sus encabezados, SPF/DKIM/DMARC, enlaces y adjuntos analizados, con un veredicto y qué verificar.</p>
    <div class="drop" id="pdrop" tabindex="0" role="button" aria-label="Seleccionar archivos .eml">
      <strong id="pdropTitle">Arrastra los .eml aquí o haz clic para elegirlos</strong>
      <span>Hasta 5 archivos · 5 MB cada uno · se leen como texto: no se abre ningún enlace ni se ejecuta ningún adjunto</span>
      <input type="file" id="pfile" accept=".eml" multiple hidden>
    </div>
    <details class="paste" id="pdet"><summary><b>¿No tienes el .eml? Pega las cabeceras</b></summary>
      <p class="muted">Copia el origen del mensaje («Mostrar original» en Gmail, «Ver código fuente del mensaje» en Outlook o Thunderbird) y pégalo aquí. Con solo las cabeceras se analizan remitente, autenticación y recorrido; sin el cuerpo no se ven enlaces ni adjuntos.</p>
      <textarea id="phdr" rows="7" maxlength="512000" spellcheck="false" autocomplete="off" aria-label="Cabeceras del correo" placeholder="Received: from …&#10;From: …&#10;Subject: …"></textarea></details>
    <label class="f" style="max-width:640px;margin:14px 0"><span><b>Remitente esperado</b> (opcional)</span>
      <input id="pexp" type="text" maxlength="200" autocomplete="off" spellcheck="false">
      <span style="font-weight:400">Si lo escribes, la app compara carácter por carácter la dirección del correo con la tuya y señala qué letra cambió (por ejemplo una «I» mayúscula por una «l»).</span></label>
    <div class="row">
      <button class="btn primary" id="pgo" disabled>Analizar correos</button>
      <button class="btn" id="psample" type="button">Probar con correos de ejemplo</button>
    </div>
    <div class="err" id="perr" role="alert" hidden></div>
    <ul class="checks"><li>Remitente, Reply-To y suplantación</li><li>Homógrafos: letras que se ven iguales y no lo son</li><li>SPF, DKIM y DMARC</li><li>Enlaces engañosos y dominios parecidos</li><li>Adjuntos peligrosos, macros y hash</li><li>Recorrido del correo y puntaje explicado</li></ul>
  </section>`;
}

/* ---------- herramientas de dominio (DNS público: solo se consulta lo que el analista pide) ---------- */
function phTabs(cur) {
  const t = [["phishing", "Correos"], ["phishing/dominio", "Evaluar dominio"], ["phishing/parecidos", "Dominios parecidos"]];
  return `<nav class="ph-tabs" aria-label="Herramientas de phishing">${t.map(([k, l]) => `<a href="#/${k}" ${k === cur ? 'aria-current="page"' : ""}>${l}</a>`).join("")}</nav>`;
}
const senderDomain = (m) => { const a = (m.headers.from_addr || "").split("@"); return a.length > 1 ? a.pop().trim() : ""; };
const CHK = { ok: ["Bajo", "Bien"], warn: ["Medio", "Atención"], fail: ["Alto", "Falla"], info: ["Bajo", "Dato"] };
const GRADE_CLS = { A: "Bajo", B: "Bajo", C: "Medio", D: "Alto", F: "Crítico" };
function domainView() {
  const D = S.dom || (S.dom = { q: "", res: null, err: "" });
  const r = D.res;
  const out = !r ? "" : `<div class="panel"><div class="grade-row"><div class="grade ${GRADE_CLS[r.grade]}" aria-label="Nota ${esc(r.grade)}">${esc(r.grade)}</div>
      <div><h3 style="margin:0">${esc(r.domain)} · ${esc(r.score)}/100</h3><p class="muted" style="margin:4px 0 0">Consultado ${esc(r.checked_at)} vía ${esc(r.provider)}. Escala: ${r.scale.map((x) => `${esc(x.grade)} ≥ ${esc(x.from)}`).join(" · ")}.</p></div></div>
      <p style="margin-top:10px">${authChip("SPF", r.spf.all || (r.spf.record ? "sin all" : "ausente"))} ${authChip("DMARC", r.dmarc.policy || (r.dmarc.record ? "inválida" : "ausente"))} ${authChip("DKIM", r.dkim.found.length ? "clave encontrada" : "no encontrada")}</p></div>
    <div class="panel"><h3>Comprobaciones (cada una resta puntos visibles)</h3><div class="tbl-wrap"><table><thead><tr><th>Estado</th><th>Comprobación</th><th>Resta</th><th>Detalle y cómo corregirlo</th></tr></thead><tbody>${r.checks.map((c) =>
      `<tr><td>${sevPill(CHK[c.status][0], CHK[c.status][1])}</td><td><b>${esc(c.title)}</b></td><td class="mono">${c.points ? "−" + esc(c.points) : "0"}</td><td>${esc(c.detail)}${c.fix ? `<div class="muted" style="margin-top:4px"><b>Corrección:</b> ${esc(c.fix)}</div>` : ""}</td></tr>`).join("")}</tbody></table></div></div>
    ${r.recommendations.length ? `<div class="panel"><h3>Recomendaciones (de mayor a menor impacto)</h3><ol>${r.recommendations.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></div>` : ""}
    <details class="panel"><summary><b>Registros leídos</b></summary><dl class="recs">
      <dt>SPF</dt><dd class="mono">${esc(r.spf.record || "—")}</dd><dt>DMARC</dt><dd class="mono">${esc(r.dmarc.record || "—")}${r.dmarc.inherited_from ? ` (heredado de ${esc(r.dmarc.inherited_from)})` : ""}</dd>
      <dt>MX</dt><dd class="mono">${r.mx.records.length ? r.mx.records.map(esc).join("<br>") : "—"}</dd>
      <dt>DKIM</dt><dd>${r.dkim.found.length ? r.dkim.found.map((f) => `${esc(f.selector)}: ${f.revoked ? "revocada" : esc(f.algorithm) + (f.bits ? " ~" + esc(f.bits) + " bits" : "")}`).join("<br>") : `Sin claves en los selectores comunes (${esc(r.dkim.tried.join(", "))})`}</dd></dl></details>
    <p class="muted">${r.limitations.map(esc).join(" ")}</p>`;
  return `<section class="landing"><h1>Evaluar la protección de un dominio</h1>
    <p class="lead">Lee los registros públicos SPF, DKIM y DMARC de un dominio y los califica de A a F, con lo que resta cada falla y cómo corregirla. Sirve para saber si un dominio se puede suplantar fácilmente.</p>
    <form id="dform" class="row" style="gap:10px;flex-wrap:wrap;align-items:flex-end"><label class="f" style="flex:1;min-width:260px"><span><b>Dominio</b></span><input id="dq" type="text" maxlength="253" autocomplete="off" spellcheck="false" value="${esc(D.q)}"></label>
      <button class="btn primary" id="dgo" type="submit">Evaluar</button></form>
    <p class="muted">Privacidad: solo sale el nombre del dominio, mediante DNS sobre HTTPS a Cloudflare (o Google si falla). No se envía ningún correo ni contenido. El administrador puede desactivarlo con <span class="mono">DNS_LOOKUPS=off</span>.</p>
    <div class="err" id="derr" role="alert" ${D.err ? "" : "hidden"}>${esc(D.err)}</div></section>${out}`;
}
function bindDomain() {
  const D = S.dom;
  $("#dform").onsubmit = async (e) => {
    e.preventDefault(); D.q = $("#dq").value.trim(); if (!D.q) return;
    busy(true, "Consultando el DNS…");
    try { const fd = new FormData(); fd.append("domain", D.q); D.res = await api("/api/domain/grade", { method: "POST", body: fd }); D.err = ""; }
    catch (err) { D.res = null; D.err = err.message; } finally { busy(false); }
    S.keepScroll = true; render();
  };
}
function lookView() {
  const L = S.look || (S.look = { q: "", check: false, res: null, err: "" });
  const r = L.res;
  const stCls = { registrado: "Alto", libre: "Bajo", sin_datos: "Medio", error: "Medio" };
  const out = !r ? "" : `<div class="panel"><h3>${esc(num(r.total))} variantes de ${esc(r.domain)}${r.checked ? ` · ${esc(num(r.checked))} comprobadas en el DNS` : ""}</h3>
      <div class="row" style="gap:8px;flex-wrap:wrap;margin-bottom:10px"><button class="btn" id="ldltxt" type="button">Descargar lista (.txt)</button><button class="btn" id="ldlcsv" type="button">Descargar tabla (.csv)</button></div>
      <div class="tbl-wrap"><table><thead><tr><th>Tipo</th><th>Dominio</th><th>Qué cambia</th>${r.checked ? "<th>Estado</th>" : ""}</tr></thead><tbody>${r.variants.map((v) =>
        `<tr><td>${esc(v.kind_label)}</td><td class="mono" style="word-break:break-all">${esc(v.domain)}${v.unicode ? `<div class="muted" style="font-size:12px">se ve como ${esc(v.unicode)}</div>` : ""}</td><td>${esc(v.note)}</td>${r.checked ? `<td>${v.state ? sevPill(stCls[v.state], v.state_label) : '<span class="muted">sin comprobar</span>'}</td>` : ""}</tr>`).join("")}</tbody></table></div></div>
    <p class="muted">${r.limitations.map(esc).join(" ")}</p>`;
  return `<section class="landing"><h1>Dominios parecidos a una marca</h1>
    <p class="lead">Genera las variantes que un atacante podría registrar para imitar un dominio (letras parecidas, homógrafos, teclas vecinas, otras terminaciones…). Úsalas para vigilar o bloquear en el proxy y el DNS.</p>
    <form id="lform" class="row" style="gap:10px;flex-wrap:wrap;align-items:flex-end"><label class="f" style="flex:1;min-width:260px"><span><b>Dominio de la marca</b></span><input id="lq" type="text" maxlength="253" autocomplete="off" spellcheck="false" value="${esc(L.q)}"></label>
      <button class="btn primary" type="submit">Generar variantes</button></form>
    <label class="chk"><input type="checkbox" id="lchk" ${L.check ? "checked" : ""}> Comprobar cuáles están registradas (consulta el DNS público de los primeros ${esc(r ? r.check_limit : 60)})</label>
    <p class="muted">Generar la lista es local y no abre ninguna conexión. Si marcas la comprobación, solo se envían los nombres de dominio de la lista, por DNS sobre HTTPS a Cloudflare (o Google). Puede desactivarse con <span class="mono">DNS_LOOKUPS=off</span>.</p>
    <div class="err" id="lerr2" role="alert" ${L.err ? "" : "hidden"}>${esc(L.err)}</div></section>${out}`;
}
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type })), a = document.createElement("a");
  a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
}
function bindLook() {
  const L = S.look;
  $("#lform").onsubmit = async (e) => {
    e.preventDefault(); L.q = $("#lq").value.trim(); L.check = $("#lchk").checked; if (!L.q) return;
    busy(true, L.check ? "Consultando el DNS…" : "Generando variantes…");
    try { const fd = new FormData(); fd.append("domain", L.q); fd.append("check", String(L.check)); L.res = await api("/api/domain/lookalikes", { method: "POST", body: fd }); L.err = ""; }
    catch (err) { L.res = null; L.err = err.message; } finally { busy(false); }
    S.keepScroll = true; render();
  };
  if (!L.res) return;
  const csvCell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  $("#ldltxt").onclick = () => download(`parecidos_${L.res.domain}.txt`, L.res.variants.map((v) => v.domain).join("\n") + "\n", "text/plain");
  $("#ldlcsv").onclick = () => download(`parecidos_${L.res.domain}.csv`, "dominio,se_ve_como,tipo,detalle,estado\n" + L.res.variants.map((v) => [v.domain, v.unicode, v.kind_label, v.note, v.state_label].map(csvCell).join(",")).join("\n") + "\n", "text/csv");
}
function mailRow(m, sel) {
  const h = m.headers;
  return `<tr class="${sel ? "sel" : ""}" data-mail="${esc(m.id)}" tabindex="0" style="cursor:pointer"><td><b>${esc(m.id)}</b></td><td>${sevPill(m.severity)}</td><td>${esc(h.subject || "(sin asunto)")}</td>
    <td class="mono" style="word-break:break-all">${esc(h.from_addr || h.from)}</td><td>${esc(m.verdict)}</td><td class="mono">${esc(m.score)}</td></tr>`;
}
/* Desglose carácter por carácter: lo que el ojo no distingue (I/l, a latina/cirílica) se ve con su código y alfabeto. */
function hgTable(cells, truncated) {
  const row = (fn) => cells.map(fn).join("");
  return `<div class="hg-wrap"><table class="hg-tbl" aria-label="Desglose carácter por carácter"><tbody>
    <tr><th scope="row">Carácter</th>${row((c) => `<td class="hg ${c.flag ? "bad" : ""}" title="${esc(c.code + " · " + c.name + " · " + c.script)}"><span class="hg-ch">${esc(c.ch)}</span></td>`)}</tr>
    <tr><th scope="row">Código</th>${row((c) => `<td class="hg ${c.flag ? "bad" : ""}"><span class="hg-cd">${esc(c.code.slice(2))}</span></td>`)}</tr>
    <tr><th scope="row">Alfabeto</th>${row((c) => `<td class="hg ${c.flag ? "bad" : ""}"><span class="hg-sc">${esc(c.script.slice(0, 4))}</span></td>`)}</tr>
    <tr><th scope="row">Aviso</th>${row((c) => `<td class="hg ${c.flag ? "bad" : ""}">${c.flag ? `<span class="hg-warn" aria-label="sospechoso">▲</span>` : ""}</td>`)}</tr>
  </tbody></table></div>${truncated ? `<p class="muted">Se muestran los primeros ${cells.length} caracteres.</p>` : ""}`;
}
function hgPanel(m) {
  const g = m.homograph;
  if (!g || !g.entries.length) return "";
  const cmpText = (d) => `posición ${d.pos}: tiene ${d.found_detail.map((c) => `«${esc(c.ch)}» (${esc(c.code)} ${esc(c.name)})`).join(", ") || "nada"}, debía ser ${d.expected_detail.map((c) => `«${esc(c.ch)}» (${esc(c.code)} ${esc(c.name)})`).join(", ") || "nada"}`;
  const exp = g.expected ? `<div class="hg-exp ${g.expected.kind === "igual" ? "ok" : "bad"}"><b>Comparación con la dirección esperada</b> (<span class="mono">${esc(g.expected.expected)}</span>): ${
      g.expected.kind === "igual" ? "coincide carácter por carácter." :
      `<b>${esc({ parecida: "se ve igual pero NO es la misma", casi: "es casi idéntica", distinta: "es distinta" }[g.expected.kind])}</b>.${g.expected.diffs.length ? `<ul>${g.expected.diffs.map((d) => `<li>${cmpText(d)}</li>`).join("")}</ul>` : ""}`}</div>` : "";
  const cmp = g.comparisons.length ? `<ul>${g.comparisons.map((c) => `<li><b>${esc(c.between[0])}</b> y <b>${esc(c.between[1])}</b> se ven iguales pero no lo son: <span class="mono">${esc(c.a)}</span> / <span class="mono">${esc(c.b)}</span>${c.diffs.length ? ` (${c.diffs.slice(0, 2).map(cmpText).join("; ")})` : ""}</li>`).join("")}</ul>` : "";
  return `<div class="panel"><h3>Verificación de caracteres ${g.suspicious ? sevPill("Alto") : ""}</h3>
    <p class="muted">Cada carácter por separado, con su código Unicode y su alfabeto. Una «I» mayúscula y una «l» minúscula, o la «a» latina (U+0061) y la «а» cirílica (U+0430), se ven iguales pero tienen códigos distintos. Compáralo con la dirección del contacto real.</p>
    ${exp}${cmp}
    ${g.entries.map((e) => `<div class="hg-entry ${e.suspicious ? "bad" : ""}"><h4>${esc(e.label)}${e.suspicious ? " · sospechoso" : ""}</h4>
      <p class="mono hg-val">${esc(e.value)}</p>
      <p class="mono hg-spell">${esc(e.spelled)}</p>
      ${e.notes.length ? `<ul>${e.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : `<p class="muted">Sin caracteres sospechosos (alfabetos: ${esc(e.scripts.join(", ") || "—")}).</p>`}
      ${hgTable(e.chars, e.truncated)}</div>`).join("")}</div>`;
}
function mailDetail(m) {
  const h = m.headers, a = m.auth;
  const facts = [["De", h.from], ["Reply-To", h.reply_to || "—"], ["Return-Path", h.return_path || "—"], ["Para", h.to || "—"], ["Fecha", h.date || "—"],
                 ["Message-ID", h.message_id || "—"], ["Origen probable (IP)", m.origin_ip || "no determinado"]];
  const sig = m.signals.length ? `<div class="tbl-wrap"><table><thead><tr><th>Categoría</th><th>Criticidad</th><th>Señal</th><th>Detalle</th></tr></thead><tbody>${m.signals.map((x) =>
    `<tr><td>${esc(x.category)}</td><td>${sevPill(x.severity)}</td><td><b>${esc(x.title)}</b></td><td>${esc(x.detail)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">No se detectaron señales de phishing.</p>`;
  const urls = m.urls.length ? `<div class="tbl-wrap"><table><thead><tr><th>URL (defangeada: no es un enlace)</th><th>Dónde</th><th>Texto visible</th><th>Señales</th></tr></thead><tbody>${m.urls.map((u) =>
    `<tr><td class="mono" style="word-break:break-all">${esc(u.defanged)}${u.normalized ? `<div class="muted" style="font-size:12px">Interpretada como: ${esc(u.normalized)}</div>` : ""}${u.host_unicode || u.host_ascii ? `<div class="muted" style="font-size:12px">${u.host_unicode ? `Dominio (Unicode): ${esc(u.host_unicode)} ` : ""}${u.host_ascii ? `· forma técnica: ${esc(u.host_ascii)}` : ""}</div>` : ""}${u.host_chars ? `<details><summary class="muted">Desglose del dominio</summary>${hgTable(u.host_chars, false)}</details>` : ""}</td><td>${esc(u.location)}</td><td>${esc(u.text || "—")}</td><td>${u.flags.length ? u.flags.map((f) => `<span class="tag">${esc(f)}</span>`).join(" ") : `<span class="muted">—</span>`}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">El correo no contiene enlaces.</p>`;
  const att = m.attachments.length ? `<div class="tbl-wrap"><table><thead><tr><th>Archivo</th><th>Riesgo</th><th>Tamaño</th><th>SHA-256</th><th>Notas</th></tr></thead><tbody>${m.attachments.map((x) =>
    `<tr><td><b>${esc(x.filename)}</b><div class="muted" style="font-size:12px">${esc(x.content_type)}</div></td><td>${sevPill(x.risk)}</td><td class="mono">${num(x.size)} B</td><td class="mono" style="word-break:break-all;font-size:11px">${esc(x.sha256)}</td><td>${x.notes.length ? x.notes.map(esc).join("<br>") : `<span class="muted">—</span>`}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">Sin adjuntos.</p>`;
  const dly = (x) => { if (x.delay_s === null || x.delay_s === undefined) return "—"; const a = Math.abs(x.delay_s); return (x.delay_s < 0 ? "−" : "+") + (a >= 3600 ? `${Math.floor(a / 3600)} h ${Math.floor(a % 3600 / 60)} min` : a >= 60 ? `${Math.floor(a / 60)} min ${a % 60} s` : `${a} s`); };
  const FL = { hora_anterior: "hora anterior al salto previo", retraso_largo: "retraso largo", sin_fecha: "sin fecha" };
  const rt = m.route || { count: 0 };
  const hops = m.hops.length ? `<div class="panel"><h3>Recorrido del correo (del origen al destino)</h3>
      <p class="muted">${esc(rt.count)} saltos${rt.span_text ? ` · ${esc(rt.span_text)} de principio a fin` : ""} · ${esc(rt.with_tls)} con TLS${rt.backwards ? ` · <b>${esc(rt.backwards)} con hora fuera de orden</b>` : ""}${rt.long_delays ? ` · <b>${esc(rt.long_delays)} con retraso largo</b>` : ""}${rt.undated ? ` · ${esc(rt.undated)} sin fecha` : ""}. Horas en UTC. Los Received que añadió el servidor del atacante se pueden inventar; solo los de tu propia infraestructura son fiables.</p>
      <div class="tbl-wrap"><table><thead><tr><th>#</th><th>Desde</th><th>Hacia</th><th>IP</th><th>Protocolo</th><th>Hora (UTC)</th><th>Retraso</th><th>Aviso</th></tr></thead><tbody>${m.hops.map((x) =>
      `<tr class="${x.flags.some((f) => f !== "sin_fecha") ? "sel" : ""}"><td>${esc(x.n)}</td><td class="mono" style="word-break:break-all">${esc(x.from || "?")}</td><td class="mono" style="word-break:break-all">${esc(x.by || "?")}</td><td class="mono">${x.ip ? esc(x.ip) + (x.public ? "" : " (interna)") : "—"}</td><td>${esc(x.protocol || "—")}${x.tls ? " · TLS" : ""}</td><td class="mono">${esc(x.ts || "—")}</td><td class="mono">${dly(x)}</td><td>${x.flags.length ? x.flags.map((f) => `<span class="tag">${esc(FL[f] || f)}</span>`).join(" ") : ""}</td></tr>`).join("")}</tbody></table></div></div>` : "";
  const bd = m.score_breakdown;
  const why = bd ? `<details class="panel" id="why"><summary><b>¿Cómo se calculó el puntaje?</b> ${esc(bd.total)} puntos → ${sevPill(bd.severity)}</summary>
      <p>${esc(bd.why)}</p>
      <div class="tbl-wrap"><table><thead><tr><th>Categoría</th><th>Señal</th><th>Criticidad</th><th>Puntos</th><th>Contó</th></tr></thead><tbody>${bd.categories.map((c) => c.signals.map((x, i) =>
        `<tr>${i === 0 ? `<td rowspan="${c.signals.length}"><b>${esc(c.category)}</b><div class="muted" style="font-size:12px">tope ${esc(c.cap)}${c.capped ? ` · se aplicó el tope (${esc(c.raw)} → ${esc(c.applied)})` : ""}</div></td>` : ""}<td>${esc(x.title)}</td><td>${sevPill(x.severity)}</td><td class="mono">+${esc(x.points)}</td><td class="mono">${esc(x.applied)}</td></tr>`).join("")).join("") || `<tr><td colspan="5" class="muted">Ninguna señal sumó puntos.</td></tr>`}</tbody></table></div>
      <p class="muted" style="margin-top:8px"><b>Cómo se decide la criticidad:</b> ${bd.thresholds.map((t) => `${esc(t.severity)}: ${esc(t.rule)}`).join(" · ")}.</p></details>` : "";
  const dom = senderDomain(m);
  const dr = m.dns_review;
  const idx = S.ph.items.indexOf(m);
  const dnsPanel = !dom ? "" : dr ? `<div class="panel"><h3>Verificación en DNS de ${esc(dr.domain)} · nota ${esc(dr.grade)} (${esc(dr.score)}/100)</h3>
      <p class="muted">Compara lo que dicen las cabeceras del correo (SPF=${esc(dr.claimed.spf || "?")}, DKIM=${esc(dr.claimed.dkim || "?")}, DMARC=${esc(dr.claimed.dmarc || "?")}) con lo que el DNS publica hoy. Consultado el ${esc(dr.checked_at)}.</p>
      <div class="tbl-wrap"><table><thead><tr><th>Resultado</th><th>Comprobación</th><th>Detalle</th></tr></thead><tbody>${dr.checks.map((c) =>
        `<tr><td>${sevPill({ ok: "Bajo", info: "Bajo", warn: "Medio", fail: "Alto" }[c.status] || "Bajo", { ok: "OK", info: "Info", warn: "Revisar", fail: "Diferencia" }[c.status])}</td><td><b>${esc(c.title)}</b></td><td>${esc(c.detail)}${c.fix ? `<div class="muted">${esc(c.fix)}</div>` : ""}</td></tr>`).join("")}</tbody></table></div>
      <p class="muted" style="margin-top:8px">${dr.limitations.map(esc).join(" ")}</p></div>`
    : `<div class="panel"><h3>Verificar el remitente en DNS</h3>
      <p class="muted">Comprueba si ${esc(dom)} autoriza hoy la IP de origen del correo (SPF), si existe la clave de su firma DKIM y qué política DMARC tiene, y lo compara con lo que dicen las cabeceras. Solo salen nombres de dominio por DNS sobre HTTPS (Cloudflare o Google); la IP y el contenido no se envían. El dominio puede recibir una consulta desde el resolvedor público, no desde tu red.</p>
      <p><button class="btn" data-dnsrev="${idx}" type="button">Verificar en DNS</button></p><div class="err" id="dnserr" role="alert" hidden></div></div>`;
  const domBtns = dom ? `<p style="margin-top:10px"><button class="btn" data-dom="phishing/dominio" data-v="${esc(dom)}" type="button">Evaluar SPF/DKIM/DMARC de ${esc(dom)}</button> <button class="btn" data-dom="phishing/parecidos" data-v="${esc(dom)}" type="button">Dominios parecidos a ${esc(dom)}</button></p>` : "";
  return `<div class="panel"><h3>${esc(m.id)} · ${esc(h.subject || "(sin asunto)")} ${sevPill(m.severity)}</h3>
      <p><b>${esc(m.verdict)}</b> · puntaje ${esc(m.score)} · ${m.source ? `origen <b>${esc(m.source)}</b>` : `archivo <span class="mono">${esc(m.filename)}</span>`}</p>${m.headers_only ? `<div class="notice">Solo se analizaron las cabeceras: sin el cuerpo no se evaluaron enlaces ni adjuntos.</div>` : ""}
      <div class="tbl-wrap"><table><tbody>${facts.map(([k, v]) => `<tr><th style="width:190px;text-align:left">${esc(k)}</th><td class="mono" style="word-break:break-all">${esc(v)}</td></tr>`).join("")}</tbody></table></div>
      <p style="margin-top:10px">${authChip("SPF", a.spf)} ${authChip("DKIM", a.dkim)} ${authChip("DMARC", a.dmarc)} ${m.favorable.length ? `<span class="muted">A favor: ${m.favorable.map(esc).join(", ")}</span>` : ""}</p>${domBtns}</div>
    ${dnsPanel}
    ${hops}
    <div class="panel"><h3>Señales detectadas</h3>${sig}</div>${why}
    ${hgPanel(m)}
    <div class="panel"><h3>Enlaces</h3>${urls}</div>
    <div class="panel"><h3>Adjuntos</h3>${att}<p class="muted" style="margin-top:8px">No se abrió ni ejecutó nada. Para saber si un hash es conocido, usa la reputación de abajo.</p></div>
    <div class="grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin-top:16px">
      <div class="panel" style="margin-top:0"><h3>Qué verificar</h3><ul>${m.verify.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
      <div class="panel" style="margin-top:0"><h3>Acciones sugeridas</h3><ul>${m.actions.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
        ${m.mitre.length ? `<p class="muted" style="margin-top:10px">MITRE ATT&amp;CK (orientativo): ${m.mitre.map((t) => techTag(t, m.mitre_info)).join(" ")}</p>` : ""}</div></div>
    <p class="muted" style="margin-top:10px">${m.limitations.map(esc).join(" ")}</p>`;
}
function phishingResults() {
  const P = S.ph, sel = P.items.find((x) => x.id === P.sel) || P.items[0];
  const sev = (k) => P.items.filter((x) => x.severity === k).length;
  const res = {}; ((P.intel && P.intel.job && P.intel.job.results) || []).forEach((r) => { res[r.indicator] = r; });
  const repRows = Object.values(res);
  return `<div class="page-head"><div><h1>Correos sospechosos</h1><p>Análisis estático: no se abrió ningún enlace ni se ejecutó ningún adjunto. La criticidad sale de reglas con pesos fijos y sirve para el triage.</p></div>
      <div style="display:flex;gap:8px"><button class="btn ghost" id="pagain">Analizar otros correos</button></div></div>
    <div class="stat-line"><span>Correos: <b>${P.items.length}</b></span><span>Críticos: <b>${sev("Crítico")}</b></span><span>Altos: <b>${sev("Alto")}</b></span><span>Medios: <b>${sev("Medio")}</b></span><span>Sin señales: <b>${sev("Bajo")}</b></span></div>
    ${P.errors.length ? `<div class="notice" style="margin:12px 0">${P.errors.map((e) => `${esc(e.filename)}: ${esc(e.error)}`).join("<br>")}</div>` : ""}
    <div class="tbl-wrap" style="margin-top:12px"><table><thead><tr><th>ID</th><th>Criticidad</th><th>Asunto</th><th>Remitente</th><th>Veredicto</th><th>Puntaje</th></tr></thead><tbody>${P.items.map((m) => mailRow(m, m.id === sel.id)).join("")}</tbody></table></div>
    <p class="muted" style="margin:6px 0 16px">Haz clic en una fila para ver su detalle.</p>
    ${mailDetail(sel)}
    <div style="margin-top:16px">${intelPanel(P)}</div>
    ${repRows.length ? `<div class="tbl-wrap" style="margin-top:12px"><table><thead><tr><th>Indicador consultado</th><th>Tipo</th><th>Reputación</th></tr></thead><tbody>${repRows.map((r) =>
      `<tr><td class="mono" style="word-break:break-all">${esc(r.indicator)}</td><td>${esc(r.kind === "hash" ? "SHA-256" : r.kind === "ip" ? "IP" : "Dominio")}</td><td>${repCell(r)}</td></tr>`).join("")}</tbody></table></div>` : ""}
    <div class="panel" style="margin-top:16px"><h3>Informe en PDF</h3>
      <div class="fields"><label class="f">Cliente<input type="text" id="pClient" value="${esc(S.client)}"></label><label class="f">Analista<input type="text" id="pAnalyst" value="${esc(S.analyst)}"></label></div>
      <div class="row" style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn primary" id="ppdf">Descargar informe de phishing</button></div>
</div>`;
}
function phishingView() { return S.ph ? phishingResults() : phishingUpload(); }
function adoptPhishing(res) {
  clearInterval(S.ph && S.ph.intelTimer);
  S.ph = { pid: res.phishing_id, items: res.items, errors: res.errors, sel: res.items[0] && res.items[0].id, intel: null, intelConfirm: false, intelReserved: false };
}
async function sendEml(files, sample) {
  busy(true, "Analizando correos…");
  try {
    const fd = new FormData();
    if (!sample) { files.forEach((f) => fd.append("files", f)); fd.append("expected", ($("#pexp") || {}).value || ""); fd.append("headers_text", ($("#phdr") || {}).value || ""); }
    adoptPhishing(await api(sample ? "/api/phishing/sample" : "/api/phishing", { method: "POST", body: fd }));
    render();
  } catch (e) { const b = $("#perr"); if (b) { b.textContent = e.message; b.hidden = false; } else toast(e.message); }
  finally { busy(false); }
}
function bindPhishing() {
  if (!S.ph) {
    let files = [];
    const drop = $("#pdrop"), inp = $("#pfile"), go = $("#pgo");
    const sync = () => { go.disabled = !files.length && !$("#phdr").value.trim(); };
    const pick = (list) => { files = [...list].slice(0, 5); if (!files.length) return; $("#pdropTitle").textContent = files.map((f) => f.name).join(", "); sync(); $("#perr").hidden = true; };
    $("#phdr").oninput = sync;
    drop.onclick = () => inp.click();
    drop.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); inp.click(); } };
    inp.onchange = () => pick(inp.files);
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", (e) => pick(e.dataTransfer.files));
    go.onclick = () => sendEml(files, false);
    $("#psample").onclick = () => sendEml([], true);
    return;
  }
  const P = S.ph, base = `/api/phishing/${P.pid}`;
  document.querySelectorAll("[data-dom]").forEach((b) => { b.onclick = () => { b.dataset.dom === "phishing/dominio" ? (S.dom = { q: b.dataset.v, res: null, err: "" }) : (S.look = { q: b.dataset.v, check: false, res: null, err: "" }); location.hash = "#/" + b.dataset.dom; }; });
  $("#pagain").onclick = () => { clearInterval(P.intelTimer); S.ph = null; render(); };
  document.querySelectorAll("[data-dnsrev]").forEach((b) => b.onclick = async () => {
    busy(true, "Consultando el DNS…");
    try { const r = await api(`${base}/items/${b.dataset.dnsrev}/dns`, { method: "POST" }); P.items[+b.dataset.dnsrev].dns_review = r; S.keepScroll = true; render(); }
    catch (e) { const el = $("#dnserr"); if (el) { el.textContent = e.message; el.hidden = false; } else toast(e.message); }
    finally { busy(false); }
  });
  document.querySelectorAll("[data-mail]").forEach((tr) => {
    const open = () => { P.sel = tr.dataset.mail; S.keepScroll = true; render(); };
    tr.onclick = open; tr.onkeydown = (e) => { if (e.key === "Enter") open(); };
  });
  if (!P.intel) loadIntel(P, base, "phishing");
  bindIntel(P, base, "phishing");
  $("#ppdf").onclick = async () => {
    busy(true, "Generando PDF…");
    try {
      const fd = new FormData(); fd.append("client", $("#pClient").value.trim()); fd.append("analyst", $("#pAnalyst").value.trim());
      const r = await fetch(`${base}/report.pdf`, { method: "POST", body: fd, headers: authHeaders() });
      if (!r.ok) throw new Error("No se pudo generar el PDF.");
      const url = URL.createObjectURL(await r.blob()), a = document.createElement("a");
      a.href = url; a.download = "informe_phishing.pdf"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast("PDF descargado");
    } catch (e) { toast(e.message); } finally { busy(false); }
  };
}

/* ---------- efectos ---------- */
const reducedMotion = () => document.documentElement.getAttribute("data-motion") === "reduced" || matchMedia("(prefers-reduced-motion: reduce)").matches;
function countUp() {
  document.querySelectorAll("[data-count]").forEach((el) => {
    const to = +el.dataset.count; if (reducedMotion() || to < 2) return;
    const t0 = performance.now(), dur = 700;
    const step = (now) => { const p = Math.min(1, (now - t0) / dur); el.textContent = num(Math.round(to * (1 - Math.pow(1 - p, 3)))); if (p < 1) requestAnimationFrame(step); };
    el.textContent = "0"; requestAnimationFrame(step);
  });
}
function bindHero() {
  document.querySelectorAll(".hero").forEach((h) => h.addEventListener("pointermove", (e) => {
    const r = h.getBoundingClientRect(); h.style.setProperty("--gx", e.clientX - r.left + "px"); h.style.setProperty("--gy", e.clientY - r.top + "px");
  }));
}

/* ---------- tema, movimiento, ayuda y búsqueda ---------- */
const THEMES = { auto: "Tema: automático", light: "Tema: claro", dark: "Tema: oscuro" };
function applyTheme(t) {
  const root = document.documentElement;
  if (t === "light" || t === "dark") root.setAttribute("data-theme", t); else root.removeAttribute("data-theme");
  $("#themeBtn").textContent = THEMES[t];
  $("#themeBtn").title = THEMES[t];
}
function applyMotion(m) {
  const root = document.documentElement;
  if (m === "reduced") root.setAttribute("data-motion", "reduced"); else root.removeAttribute("data-motion");
  $("#motionBtn").textContent = "✦ Movimiento: " + (m === "reduced" ? "reducido" : "completo");
}
const showHow = () => {
  const inPhishing = inPh(route());
  openDialog("¿Cómo funciona?", `<div class="how">
    <div class="row" role="tablist" style="margin-bottom:12px">
      <button class="btn" id="hwLogs" role="tab" type="button">Análisis de logs</button>
      <button class="btn" id="hwPhish" role="tab" type="button">Phishing (.eml)</button>
    </div>
    <div id="hwLogsP"><ol>
    <li><b>Carga</b> el export del SIEM en Excel (.xlsx), CSV/TSV o JSON/NDJSON, de hasta 25 MB. Se detectan el formato y las columnas aunque cambien de nombre (ver «Columnas esperadas» más abajo).</li>
    <li><b>Reglas deterministas</b> buscan fuerza bruta, inicios de sesión externos, escalamiento, comandos sospechosos, movimiento lateral, exfiltración, persistencia y ataques web. Cada hallazgo cita los Log_ID que lo prueban.</li>
    <li><b>Correlación</b>: los hallazgos se agrupan en incidentes solo si comparten IP externa o cuenta. Compartir un host o recurso queda como hipótesis de confianza baja.</li>
    <li><b>IA</b> redacta explicaciones, impacto y plan de acción. No cambia la criticidad y se descarta cualquier Log_ID o IP que no esté en el archivo.</li>
    <li><b>Informe PDF</b> con resumen ejecutivo, hallazgos, evidencia, criticidad, impacto, plan de acción y recomendaciones.</li></ol>
    <h4>Columnas esperadas</h4><p>Solo son indispensables <span class="mono">Timestamp</span> y <span class="mono">Event_ID</span>. Se aprovechan también <span class="mono">Log_ID</span>, <span class="mono">Hostname</span>, <span class="mono">User</span>, <span class="mono">Source_IP</span>, <span class="mono">Destination</span>, <span class="mono">Process_CommandLine</span> y similares, con otros idiomas o mayúsculas, y los campos de Elastic ECS (<span class="mono">@timestamp</span>, <span class="mono">host.name</span>, <span class="mono">source.ip</span>…). Lo que falte queda vacío y se informa.</p>
    <p class="muted">Cada conclusión cita los Log_ID que la respaldan. Atajos: Ctrl+K o / para buscar.</p></div>
    <div id="hwPhishP" hidden>
      <ol>
        <li><b>Obtén el correo como .eml.</b> En Outlook, Thunderbird o Gmail, abre el correo y guárdalo como .eml («Guardar como», «Descargar mensaje» u «Origen del mensaje»). Los archivos .msg no se admiten.</li>
        <li><b>Cárgalo</b> (hasta 5 archivos de 5 MB). Se leen como texto: no se abre ningún enlace ni se ejecuta ningún adjunto.</li>
        <li><b>Remitente esperado</b> (opcional): si escribes la dirección legítima, la app la compara carácter por carácter con la del correo y señala qué letra cambió.</li>
        <li><b>Análisis</b>: remitente, Reply-To y suplantación, homógrafos, SPF/DKIM/DMARC, enlaces engañosos y dominios parecidos, adjuntos peligrosos y macros.</li>
        <li><b>Sin el .eml</b>: abre «¿No tienes el .eml?» y pega las cabeceras o el origen del mensaje. Se analizan remitente, autenticación y recorrido (sin cuerpo no hay enlaces ni adjuntos).</li>
        <li><b>Recorrido</b>: los saltos Received se ordenan del origen al destino, con hora UTC y retraso entre servidores; se marcan horas fuera de orden y retrasos largos. Son pistas de bajo peso: el atacante puede inventar los Received que añade.</li>
        <li><b>Puntaje explicado</b>: «¿Cómo se calculó el puntaje?» muestra qué sumó cada señal, los topes por categoría y los umbrales de criticidad.</li>
        <li><b>Verificar en DNS</b> (opcional, en cada correo): usa el selector de la firma DKIM del correo y la IP que registró tu servidor receptor para comprobar si el dominio autoriza esa IP en SPF y si existe la clave de la firma, y lo compara con lo que dicen las cabeceras. Solo salen nombres de dominio.</li>
        <li><b>Comandos en el cuerpo</b>: un <span class="mono">powershell -enc …</span> en el texto del correo se decodifica y se muestra qué hace; pedir pegar un comando así es la técnica «ClickFix».</li>
        <li><b>Resultado</b>: un veredicto con las señales que lo respaldan, qué verificar y un informe PDF. El análisis de correos es independiente del de logs.</li></ol>
      <h4>Herramientas de dominio</h4>
      <p><b>Evaluar dominio</b> lee los registros SPF, DKIM y DMARC y da una nota de A a F con lo que resta cada falla. <b>Dominios parecidos</b> genera variantes de typosquatting para vigilar o bloquear; la comprobación de cuáles están registradas es opcional. Ambas consultan el DNS público solo cuando tú lo pides, y únicamente envían nombres de dominio.</p>
    </div></div>`);
  const tab = (w) => {
    $("#hwLogsP").hidden = w !== "logs"; $("#hwPhishP").hidden = w !== "phish";
    $("#hwLogs").setAttribute("aria-selected", String(w === "logs")); $("#hwPhish").setAttribute("aria-selected", String(w === "phish"));
    $("#hwLogs").classList.toggle("primary", w === "logs"); $("#hwPhish").classList.toggle("primary", w === "phish");
  };
  $("#hwLogs").onclick = () => tab("logs"); $("#hwPhish").onclick = () => tab("phish");
  tab(inPhishing ? "phish" : "logs");
};
function initChrome() {
  let theme = pref.get("theme") || "auto", motion = pref.get("motion") || "full";
  applyTheme(theme); applyMotion(motion);
  const sBtn = $("#settingsBtn"), sMenu = $("#settingsMenu");
  const closeMenu = (focus) => { sMenu.hidden = true; sBtn.setAttribute("aria-expanded", "false"); if (focus) sBtn.focus(); };
  sBtn.onclick = () => { const open = sMenu.hidden; sMenu.hidden = !open; sBtn.setAttribute("aria-expanded", String(open)); if (open) sMenu.querySelector("button").focus(); };
  document.addEventListener("click", (e) => { if (!sMenu.hidden && !e.target.closest(".menu-wrap")) closeMenu(false); });
  sMenu.addEventListener("keydown", (e) => {
    const items = [...sMenu.querySelectorAll("button")], i = items.indexOf(document.activeElement);
    if (e.key === "Escape") { e.preventDefault(); closeMenu(true); }
    else if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
  });
  $("#themeBtn").onclick = () => { theme = { auto: "light", light: "dark", dark: "auto" }[theme]; pref.set("theme", theme); applyTheme(theme); };
  $("#motionBtn").onclick = () => { motion = motion === "full" ? "reduced" : "full"; pref.set("motion", motion); applyMotion(motion); };
  $("#helpBtn").onclick = showHow;
  $("#searchBtn").onclick = openPalette;
  addEventListener("keydown", (e) => {
    const typing = /INPUT|SELECT|TEXTAREA/.test(document.activeElement?.tagName || "");
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    else if (e.key === "/" && !typing) { e.preventDefault(); openPalette(); }
  });
}
function paletteItems() {
  const items = [["Ir a", "Panel", "#/dashboard"], ["Ir a", "Incidentes", "#/incidents"], ["Ir a", "Hallazgos", "#/findings"], ["Ir a", "Matriz ATT&CK", "#/attack"], ["Ir a", "Eventos", "#/logs"], ["Ir a", "Indicadores (IoC)", "#/iocs"], ["Ir a", "Informe y PDF", "#/report"]];
  if (!S.a) return [["Ir a", "Cargar archivo", "#/"]];
  const nav = (h) => { if (location.hash === h) render(); else location.hash = h; };
  const act = [];
  S.a.incidents.forEach((i) => act.push(["Incidente", `${i.id} · ${(S.ai.incidents[i.id] || {}).title || i.title}`, () => { S.openInc = i.id; nav("#/incidents"); }, i.severity]));
  S.a.findings.forEach((f) => act.push(["Hallazgo", `${f.id} · ${f.title}`, () => { S.openFinding = f.id; S.findingFilter = "Todos"; S.findingCat = ""; S.findingQ = ""; nav("#/findings"); }, f.severity]));
  S.a.iocs.forEach((i) => act.push([i.type, i.value, () => { S.logs = { ...S.logs, q: i.value, page: 1 }; nav("#/logs"); }, i.severity]));
  return [...items, ...act];
}
function openPalette() {
  let d = $("#dlg"); if (d) d.remove();
  d = document.createElement("dialog"); d.id = "dlg"; d.className = "pal";
  d.innerHTML = `<input type="search" id="pq" placeholder="Buscar incidente, hallazgo, IP, cuenta o sección…" aria-label="Buscar" autocomplete="off"><ul class="pal-list" id="pl" role="listbox"></ul>`;
  document.body.appendChild(d); d.showModal();
  const all = paletteItems(); let shown = [], sel = 0;
  const go = (it) => { d.close(); if (typeof it[2] === "function") it[2](); else { if (location.hash === it[2]) render(); else location.hash = it[2]; } };
  const draw = () => {
    const q = $("#pq").value.trim().toLowerCase();
    shown = all.filter((it) => !q || (it[0] + " " + it[1]).toLowerCase().includes(q)).slice(0, 30); sel = Math.min(sel, Math.max(shown.length - 1, 0));
    $("#pl").innerHTML = shown.length ? shown.map((it, i) => `<li role="option" data-i="${i}" aria-selected="${i === sel}"><span class="kind">${esc(it[0])}</span><span class="t">${esc(it[1])}</span>${it[3] ? sevPill(it[3]) : ""}</li>`).join("") : `<li class="pal-empty">Sin resultados para esa búsqueda.</li>`;
    $("#pl").querySelectorAll("li[data-i]").forEach((li) => { li.onclick = () => go(shown[+li.dataset.i]); li.onmousemove = () => { sel = +li.dataset.i; $("#pl").querySelectorAll("li").forEach((x) => x.setAttribute("aria-selected", x === li)); }; });
  };
  $("#pq").oninput = () => { sel = 0; draw(); };
  $("#pq").onkeydown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(sel + 1, shown.length - 1); draw(); $("#pl").querySelector("[aria-selected=true]")?.scrollIntoView({ block: "nearest" }); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(sel - 1, 0); draw(); $("#pl").querySelector("[aria-selected=true]")?.scrollIntoView({ block: "nearest" }); }
    else if (e.key === "Enter" && shown[sel]) go(shown[sel]);
  };
  d.onclick = (e) => { if (e.target === d) d.close(); };
  draw(); $("#pq").focus();
}

/* ---------- arranque ---------- */
async function start() {
  try { const h = await api("/api/health"); S.aiConfigured = h.ai_configured; S.aiKeys = h.ai_keys || {}; } catch { /* servidor sin health */ }
  const sid = store.get("sid");
  if (sid) {
    try { const r = await api(`/api/sessions/${sid}`); adopt(r); if (!route()) location.hash = "#/dashboard"; } catch { store.set("sid", ""); }
  }
  render();
}
(async function init() {
  initChrome();
  try {
    const st = await api("/api/auth/status");
    if (st.required) {
      let ok = false;
      if (auth.get()) { try { await api("/api/auth/check"); ok = true; } catch { auth.set(""); } }
      if (!ok) { S.needAuth = true; render(); return; }
    }
  } catch { /* servidor sin auth/status: se asume acceso abierto */ }
  await start();
})();
