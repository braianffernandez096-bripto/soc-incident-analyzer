"use strict";
/* SOC Incident Analyzer – frontend sin dependencias. Todo dato de los logs se escapa antes de insertarse. */

const SEV = ["Crítico", "Alto", "Medio", "Bajo"];
const SEV_COLOR = { "Crítico": "#b3261e", "Alto": "#e07b00", "Medio": "#d4b100", "Bajo": "#3f8f68" };
const S = { sid: null, filename: "", client: "", analyst: "", a: null, ai: null, aiConfigured: false, intel: null, intelConfirm: false, intelReserved: false,
            findingFilter: "Todos", findingCat: "", findingQ: "", logs: { page: 1, q: "", severity: "", flagged: "", host: "", user: "", event_id: "", finding: "" } };

const $ = (s, r = document) => r.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sevPill = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const num = (n) => Number(n).toLocaleString("es-AR");
const hhmm = (t) => (t || "").slice(11, 16);
const hhmmss = (t) => (t || "").slice(11, 19);
const ts = (t) => new Date(String(t).replace(" ", "T")).getTime();
const pref = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
               set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* sin almacenamiento */ } } };
const store = { get: (k) => { try { return sessionStorage.getItem(k); } catch { return null; } },
                set: (k, v) => { try { sessionStorage.setItem(k, v); } catch { /* sin almacenamiento */ } } };

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("show"), 3800);
}
function busy(on, text) { $("#busy").hidden = !on; if (text) $("#busyText").textContent = text; }

async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let d = r.statusText;
    try { const j = await r.json(); d = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* sin cuerpo */ }
    throw new Error(d);
  }
  return r.json();
}

/* ---------- carga ---------- */
function adopt(res) {
  S.sid = res.session_id; S.filename = res.filename; S.client = res.client || ""; S.analyst = res.analyst || "";
  S.a = res.analysis; S.ai = res.ai; if (res.ai_configured !== undefined) S.aiConfigured = res.ai_configured;
  S.logs = { page: 1, q: "", severity: "", flagged: "", host: "", user: "", event_id: "", finding: "" };
  S.findingFilter = "Todos"; S.findingCat = ""; S.findingQ = "";
  S.intel = null; S.intelConfirm = false; S.intelReserved = false; clearInterval(S.intelTimer);
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
function showLandingError(m) { const b = $("#lerr"); if (b) { b.textContent = m; b.hidden = false; } else toast(m); }

/* ---------- navegación ---------- */
const ROUTES = [["dashboard", "Panel"], ["incidents", "Incidentes"], ["findings", "Hallazgos"], ["logs", "Eventos"], ["iocs", "Indicadores (IoC)"], ["report", "Informe"]];
function route() { return (location.hash.replace(/^#\/?/, "") || "").split("?")[0]; }

function renderRail() {
  const nav = $("#nav"), foot = $("#railFoot");
  if (!S.a) { nav.innerHTML = ""; foot.innerHTML = ""; return; }
  const cnt = { incidents: S.a.incidents.length, findings: S.a.findings.length, iocs: S.a.iocs.length, logs: S.a.profile.rows };
  nav.innerHTML = ROUTES.map(([k, l], i) =>
    `<a href="#/${k}" ${route() === k ? 'aria-current="page"' : ""}><span class="n">${i + 1}</span><span>${l}</span>${cnt[k] !== undefined ? `<span class="count">${num(cnt[k])}</span>` : ""}</a>`).join("");
  foot.innerHTML = `<span>Archivo</span><b title="${esc(S.filename)}">${esc(S.filename)}</b><button class="btn ghost" id="newBtn">Cargar otro</button>`;
  $("#newBtn").onclick = () => { S.a = null; S.sid = null; store.set("sid", ""); location.hash = "#/"; render(); };
}

function render() {
  hideTip();
  const main = $("#main");
  const r = route();
  if (!S.a) { renderRail(); main.innerHTML = `<div class="view">${landing()}</div>`; bindLanding(); bindHero(); return; }
  renderRail();
  const views = { dashboard, incidents, findings, logs, iocs, report };
  const v = views[r] || dashboard;
  main.innerHTML = `<div class="view">${v()}</div>`; bindHero(); countUp();
  const bind = { dashboard: bindDashboard, incidents: bindIncidents, findings: bindFindings, logs: bindLogs, iocs: bindIocs, report: bindReport }[views[r] ? r : "dashboard"];
  bind();
  if (!S.keepScroll) window.scrollTo(0, 0);
  S.keepScroll = false;
}
window.addEventListener("hashchange", render);

/* ---------- landing ---------- */
function landing() {
  return `<section class="landing">
    <h1>Del export del SIEM al informe de incidentes</h1>
    <p class="lead">Carga el export de tu SIEM (Excel, CSV o JSON). La aplicación detecta indicadores de compromiso, correlaciona los eventos en incidentes y prepara el informe técnico en PDF. Cada conclusión cita los Log_ID que la respaldan.</p>
    <div class="drop" id="drop" tabindex="0" role="button" aria-label="Seleccionar archivo de eventos">
      <strong id="dropTitle">Arrastra el archivo aquí o haz clic para elegirlo</strong>
      <span>Excel (.xlsx), CSV/TSV o JSON/NDJSON, hasta 25 MB. Columnas esperadas: Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP y similares (también campos tipo Elastic ECS).</span>
      <input type="file" id="file" accept=".xlsx,.xlsm,.csv,.tsv,.txt,.log,.json,.jsonl,.ndjson" hidden>
    </div>
    <div class="fields">
      <label class="f">Cliente<input type="text" id="client" placeholder="Nombre del cliente" autocomplete="off"></label>
      <label class="f">Analista<input type="text" id="analyst" placeholder="Tu nombre" autocomplete="off"></label>
    </div>
    <div class="row">
      <button class="btn primary" id="go" disabled>Analizar archivo</button>
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
}

/* ---------- gráficos ---------- */
function showTip(html, e) {
  let t = $(".tip"); if (!t) { t = document.createElement("div"); t.className = "tip"; document.body.appendChild(t); }
  t.innerHTML = html; t.style.left = Math.min(e.clientX + 14, innerWidth - 340) + "px"; t.style.top = e.clientY + 14 + "px";
}
function hideTip() { const t = $(".tip"); if (t) t.remove(); }

/* Línea de tiempo de casos: un carril por incidente, un segmento por hallazgo. */
function swimlane() {
  const incs = S.a.incidents; if (!incs.length) return "<p class='muted'>No se detectaron incidentes.</p>";
  const W = 1000, L = 210, R = 16, laneH = 38, top = 26, H = top + incs.length * laneH + 8;
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

function sevBars() {
  const c = S.a.stats.findings_by_severity, max = Math.max(...Object.values(c), 1);
  return SEV.map((s) => `<button class="bar-row" data-sev="${s}" aria-label="Ver hallazgos ${s}"><span>${sevPill(s)}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${(c[s] || 0) / max * 100}%;background:${SEV_COLOR[s]}"></span></span><span class="n">${c[s] || 0}</span></button>`).join("");
}
function catBars() {
  const c = S.a.stats.findings_by_category, max = Math.max(...Object.values(c), 1);
  return Object.entries(c).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="bar-row" style="cursor:default"><span>${esc(k)}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${v / max * 100}%;background:var(--muted)"></span></span><span class="n">${v}</span></div>`).join("");
}
function ipBars() {
  const rows = S.a.stats.top_ips.slice(0, 8), max = Math.max(...rows.map((r) => r.events), 1);
  return rows.map((r) => `<button class="bar-row" data-ip="${esc(r.ip)}" style="grid-template-columns:150px 1fr 38px" aria-label="Buscar eventos de ${esc(r.ip)}"><span class="mono">${esc(r.ip)}${r.external ? "" : ""}</span><span class="bar-track"><span class="bar-fill" style="display:block;width:${r.events / max * 100}%;background:${r.external ? "#e07b00" : "#8794a6"}"></span></span><span class="n">${r.events}</span></button>`).join("")
    + `<div class="legend"><span><i style="background:#e07b00"></i>IP externa</span><span><i style="background:#8794a6"></i>IP interna</span></div>`;
}

/* ---------- panel ---------- */
function dashboard() {
  const st = S.a.stats, p = S.a.profile, fs = st.findings_by_severity, total = Math.max(st.findings_total, 1);
  const crit = st.incidents_by_severity["Crítico"] || 0;
  const k = (n, label, extra = "") => `<div class="panel kpi"><b data-count="${n}">${num(n)}</b><span>${label}</span>${extra}</div>`;
  return `<section class="panel hero">
      <div class="page-head" style="margin:0">
        <div><h1>${S.client ? esc(S.client) : "Resultado del análisis"}</h1>
        <p>${esc(p.time_start)} a ${esc(p.time_end)} (${esc(p.duration)}) · ${num(p.rows)} eventos · ${p.hosts} equipos · ${p.users} cuentas</p></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn" href="#/findings">Ver hallazgos</a><a class="btn primary" href="#/report">Ir al informe</a></div>
      </div></section>
    <div class="grid g4" style="margin-top:16px">
      ${k(st.incidents_total, `Incidentes distintos${crit ? ` (${crit} críticos)` : ""}`)}
      ${k(st.findings_total, "Hallazgos con evidencia", `<div class="sevbar">${SEV.map((s) => `<span style="width:${(fs[s] || 0) / total * 100}%;background:${SEV_COLOR[s]}" title="${s}: ${fs[s] || 0}"></span>`).join("")}</div>`)}
      ${k(st.flagged_events, "Eventos ligados a incidentes")}
      ${k(S.a.iocs.length, "Indicadores de compromiso")}
    </div>
    <div class="inc-cards">${S.a.incidents.map((i) => `<button class="inc-card ${esc(i.severity)}" data-card="${esc(i.id)}">
        <span class="top2"><span class="mono muted">${esc(i.id)}</span>${sevPill(i.severity)}</span>
        <b>${esc((S.ai.incidents[i.id] || {}).title || i.title)}</b>
        <small>${hhmm(i.time_start)}–${hhmm(i.time_end)} · ${i.finding_ids.length} hallazgos · ${i.evidence_count} eventos</small></button>`).join("")}</div>
    <div class="panel" style="margin-top:16px"><h3>Línea de tiempo de incidentes</h3>${swimlane()}</div>
    <div class="grid g-wide" style="margin-top:16px">
      <div class="panel"><h3>Actividad de la ventana analizada</h3>${activityChart()}</div>
      <div class="panel"><h3>Hallazgos por criticidad</h3>${sevBars()}<h3 style="margin-top:18px">Por categoría</h3>${catBars()}</div>
    </div>
    <div class="panel" style="margin-top:16px"><h3>Direcciones IP con más actividad</h3>${ipBars()}</div>
    ${S.a.limitations.length ? `<div class="panel" style="margin-top:16px"><h3>Límites del análisis</h3><ul>${S.a.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>` : ""}`;
}
function bindDashboard() {
  document.querySelectorAll("[data-card]").forEach((c) => {
    const id = c.dataset.card, svg = $(".swim svg");
    c.onclick = () => { S.openInc = id; location.hash = "#/incidents"; };
    const on = () => { if (!svg) return; svg.classList.add("dim"); svg.querySelector(`.lane[data-inc="${id}"]`)?.classList.add("on"); };
    const off = () => { if (!svg) return; svg.classList.remove("dim"); svg.querySelectorAll(".lane.on").forEach((l) => l.classList.remove("on")); };
    c.onmouseenter = on; c.onmouseleave = off; c.onfocus = on; c.onblur = off;
  });
  document.querySelectorAll(".lane-label").forEach((t) => { t.style.cursor = "pointer"; t.onclick = () => { S.openInc = t.parentNode.dataset.inc; location.hash = "#/incidents"; }; });
  document.querySelectorAll(".seg").forEach((el) => {
    const f = S.a.findings.find((x) => x.id === el.dataset.f);
    const go = () => { S.findingFilter = "Todos"; S.openFinding = f.id; location.hash = "#/findings"; };
    el.onclick = go; el.onkeydown = (e) => { if (e.key === "Enter") go(); };
    el.onmousemove = (e) => showTip(`<b>${esc(f.id)} · ${esc(f.title)}</b><br>${sevPill(f.severity)} <span class="mono">${hhmmss(f.time_start)}–${hhmmss(f.time_end)}</span>`, e);
    el.onmouseleave = hideTip;
  });
  document.querySelectorAll("[data-sev]").forEach((b) => b.onclick = () => { S.findingFilter = b.dataset.sev; location.hash = "#/findings"; });
  document.querySelectorAll("[data-ip]").forEach((b) => b.onclick = () => { S.logs = { ...S.logs, q: b.dataset.ip, page: 1 }; location.hash = "#/logs"; });
  document.querySelectorAll(".act g[data-i]").forEach((g) => {
    const d = S.a.stats.timeline[+g.dataset.i];
    g.onmousemove = (e) => showTip(`<b>${esc(d.t)}</b> · ${d.total} eventos<br>${SEV.filter((s) => d[s]).map((s) => `${s}: ${d[s]}`).join(" · ") || "Sin hallazgos asociados"}`, e);
    g.onmouseleave = hideTip;
  });
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
      <div class="meta-line"><span>${hhmmss(inc.time_start)}–${hhmmss(inc.time_end)}</span><span>${inc.evidence_count} eventos de evidencia</span>
        ${g.confidence ? `<span>Confianza de la correlación: ${esc(g.confidence)}</span>` : ""}</div>
      <p>${esc(g.narrative || "")}</p>
      ${g.confidence_reason ? `<p class="muted">${esc(g.confidence_reason)}</p>` : ""}
      <div>${inc.external_ips.map((i) => `<span class="tag">${esc(i)}</span>`).join("")}${inc.actor_users.map((u) => `<span class="tag">${esc(u)}</span>`).join("")}${inc.hosts.map((h) => `<span class="tag">${esc(h)}</span>`).join("")}</div>
      ${(g.kill_chain || []).length ? `<h4 style="margin-top:12px">Secuencia de eventos</h4><ol class="kc" style="list-style:none">${g.kill_chain.map((s) => `<li><span class="t">${esc(hhmmss(s.time) || s.time)}</span>${esc(s.step)} ${evLinks(s.evidence_ids)}</li>`).join("")}</ol>` : ""}
      <h4 style="margin-top:12px">Hallazgos</h4>
      ${fs.map((f) => `<div class="finding-row">${sevPill(f.severity)}<button class="title" data-open="${esc(f.id)}">${esc(f.id)} · ${esc(f.title)}</button><span class="muted mono">${hhmm(f.time_start)}</span></div>`).join("")}
    </article>`;
  }).join("");
  const hyp = S.a.hypotheses.length ? `<div class="panel"><h3>Posibles relaciones sin evidencia directa</h3><p class="muted">No se fusionan incidentes por compartir recursos u hosts. Estas relaciones quedan como hipótesis de confianza baja para validar.</p><ul>${S.a.hypotheses.map((h) => `<li><b>${esc(h.id)}</b> ${esc(h.statement)} <span class="muted">${esc(h.basis)}</span></li>`).join("")}</ul></div>` : "";
  return `<div class="page-head"><div><h1>¿Uno o varios incidentes?</h1><p>${esc(A.cross_incident_assessment || "")}</p></div></div>${cards}${hyp}`;
}
function bindIncidents() {
  if (S.openInc) { const el = document.getElementById(S.openInc); S.openInc = null; if (el) { el.scrollIntoView({ block: "start" }); el.classList.add("pulse"); } }
  bindEvidence(); document.querySelectorAll("[data-open]").forEach((b) => b.onclick = () => { S.openFinding = b.dataset.open; S.findingFilter = "Todos"; location.hash = "#/findings"; }); }

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
        <div style="margin-top:12px"><span class="tag">${esc(f.category)}</span><span class="tag">${esc(f.tactic)}</span>${(f.mitre || []).map((m) => `<span class="tag">${esc(m)}</span>`).join("")}${f.incident_id ? `<span class="tag">${esc(f.incident_id)}</span>` : '<span class="tag">Observación (fuera de incidentes)</span>'}</div>
        <h4>Explicación técnica</h4><p>${esc(a.technical_explanation || f.explanation)}</p>
        <h4>Criticidad: ${esc(f.severity)}</h4><p>${esc(a.severity_justification || "")}</p><ul>${li(f.reasons)}</ul>
        <h4>Impacto en la organización</h4><p>${esc(a.impact || "")}</p>
        <h4>Evidencia (${f.evidence_ids.length} eventos)</h4>
        <div class="evbox" data-fid="${esc(f.id)}"><button class="btn" data-loadev="${esc(f.id)}">Ver eventos de log</button></div>
        <h4>Plan de acción</h4>
        <div class="plan"><div><h4>Investigar</h4><ul>${li(ap.investigate)}</ul></div><div><h4>Contener</h4><ul>${li(ap.contain)}</ul></div><div><h4>Remediar</h4><ul>${li(ap.remediate)}</ul></div></div>
      </div></details>`;
  }).join("");
  return `<div class="page-head"><div><h1>Hallazgos</h1><p>Cada hallazgo cita los Log_ID del archivo que lo sustentan.</p></div></div>
    <div class="filters"><input type="search" id="fq" placeholder="Buscar por nombre, técnica (T1110) o táctica" value="${esc(S.findingQ)}" aria-label="Buscar hallazgos">
      <select id="fcat" aria-label="Categoría"><option value="">Todas las categorías</option>${cats.map((c) => `<option ${c === S.findingCat ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>
      <span class="muted">${list.length} de ${S.a.findings.length} hallazgos</span></div>
    <div class="chip-row">${chips}</div>${items || "<p class='muted'>No hay hallazgos con ese filtro.</p>"}`;
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
function intelPanel() {
  const I = S.intel, job = I && I.job, plan = I && I.plan;
  const head = `<h3>Reputación de indicadores externos <span class="muted" style="font-weight:400">(VirusTotal y AbuseIPDB, opcional)</span></h3>`;
  if (!I) return `<div class="panel">${head}<p class="muted">Cargando…</p></div>`;
  if (job && job.status === "running") {
    const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
    return `<div class="panel">${head}<p>Consultando indicadores… <b>${job.done}</b> de <b>${job.total}</b>. Con el plan gratuito de VirusTotal son 4 consultas por minuto, así que puede tardar unos minutos.</p>
      <div class="meter" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><span style="width:${pct}%"></span></div></div>`;
  }
  const notices = job && (job.notices || []).length ? `<div class="notice" style="margin-top:12px">${job.notices.map(esc).join("<br>")}</div>` : "";
  if (S.intelConfirm) {
    const q = plan.queries, prov = I.configured;
    const need = [!prov.virustotal ? `<label class="f" style="max-width:420px">API key de VirusTotal (solo se usa en esta consulta)<input type="password" id="vtKey" autocomplete="off"></label>` : "",
                  !prov.abuseipdb ? `<label class="f" style="max-width:420px">API key de AbuseIPDB (solo se usa en esta consulta)<input type="password" id="abKey" autocomplete="off"></label>` : ""].join("");
    const skipped = plan.skipped.length ? `<details style="margin-top:8px"><summary class="muted">${plan.skipped.length} indicadores no se enviarán</summary><ul>${plan.skipped.map((x) => `<li><span class="mono">${esc(x.value)}</span> — ${esc(x.reason)}</li>`).join("")}</ul></details>` : "";
    const resv = plan.reserved_available ? `<label style="display:flex;gap:8px;align-items:center;margin-top:10px"><input type="checkbox" id="resv" ${S.intelReserved ? "checked" : ""}> Incluir ${plan.reserved_available} IP de documentación (solo para probar la conexión; no tienen reputación real)</label>` : "";
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
async function loadIntel() {
  try {
    S.intel = await api(`/api/sessions/${S.sid}/intel?include_reserved=${S.intelReserved ? "true" : "false"}`);
    if (S.intel.job && S.intel.job.status === "running") pollIntel();
  } catch (e) { toast(e.message); }
  if (route() === "iocs") { S.keepScroll = true; render(); }
}
function pollIntel() {
  clearInterval(S.intelTimer);
  S.intelTimer = setInterval(async () => {
    try {
      S.intel = await api(`/api/sessions/${S.sid}/intel?include_reserved=${S.intelReserved ? "true" : "false"}`);
      const running = S.intel.job && S.intel.job.status === "running";
      if (!running) { clearInterval(S.intelTimer); toast("Consulta de reputación terminada"); }
      if (route() === "iocs") { S.keepScroll = true; render(); }
    } catch { clearInterval(S.intelTimer); }
  }, 2500);
}
function bindIocs() {
  if (!S.intel) loadIntel();
  const open = $("#intelOpen"), cancel = $("#intelCancel"), go = $("#intelGo"), resv = $("#resv");
  if (open) open.onclick = () => { S.intelConfirm = true; S.keepScroll = true; render(); };
  if (cancel) cancel.onclick = () => { S.intelConfirm = false; S.keepScroll = true; render(); };
  if (resv) resv.onchange = async () => { S.intelReserved = resv.checked; S.keepScroll = true; await loadIntel(); };
  if (go) go.onclick = async () => {
    const h = {}; const v = $("#vtKey"), a = $("#abKey");
    if (v && v.value.trim()) h["X-VT-Key"] = v.value.trim();
    if (a && a.value.trim()) h["X-AbuseIPDB-Key"] = a.value.trim();
    try {
      const r = await api(`/api/sessions/${S.sid}/intel?include_reserved=${S.intelReserved ? "true" : "false"}`, { method: "POST", headers: h });
      S.intel.job = r.job; S.intelConfirm = false; S.keepScroll = true; render(); pollIntel();
    } catch (e) { toast(e.message); }
  };
}

/* ---------- informe ---------- */
function report() {
  const A = S.ai, v = A.validation || {}, isAI = A.mode === "ia";
  return `<div class="page-head"><div><h1>Informe técnico</h1><p>El PDF incluye resumen ejecutivo, hallazgos con evidencia, criticidad, impacto, plan de acción y recomendaciones.</p></div></div>
    <div class="panel"><h3>Datos de portada</h3>
      <div class="fields"><label class="f">Cliente<input type="text" id="rClient" value="${esc(S.client)}"></label><label class="f">Analista<input type="text" id="rAnalyst" value="${esc(S.analyst)}"></label></div>
      <div class="row" style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn primary" id="pdf">Descargar informe en PDF</button></div></div>
    <div class="panel"><h3>Redacción con IA</h3>
      <p>Modo actual: <span class="mode-badge ${isAI ? "ia" : "determinista"}">${isAI ? "IA (" + esc(A.model) + ")" : "Reglas deterministas"}</span></p>
      <p class="muted">La IA redacta el análisis de cada incidente a partir de los hallazgos ya detectados. No puede cambiar la criticidad ni agregar eventos: toda cita a un Log_ID o IP que no exista en el archivo se descarta y se informa abajo.</p>
      ${S.aiConfigured ? "" : `<label class="f" style="max-width:480px">API key de Anthropic (solo se usa en esta sesión)<input type="password" id="key" placeholder="sk-ant-…" autocomplete="off"></label>`}
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
  $("#pdf").onclick = async () => {
    const m = meta(); busy(true, "Generando PDF…");
    try {
      const r = await fetch(`/api/sessions/${S.sid}/report.pdf?client=${encodeURIComponent(m.client)}&analyst=${encodeURIComponent(m.analyst)}`);
      if (!r.ok) throw new Error("No se pudo generar el PDF.");
      const url = URL.createObjectURL(await r.blob()), a = document.createElement("a");
      a.href = url; a.download = "informe_incidentes_seguridad.pdf"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast("PDF descargado");
    } catch (e) { toast(e.message); } finally { busy(false); }
  };
  $("#runAi").onclick = async () => {
    meta(); busy(true, "La IA está analizando los incidentes. Puede tardar un minuto…");
    try {
      const h = {}; const k = $("#key"); if (k && k.value.trim()) h["X-Anthropic-Key"] = k.value.trim();
      const r = await api(`/api/sessions/${S.sid}/ai`, { method: "POST", headers: h });
      S.ai = r.ai; toast("Análisis con IA aplicado"); render();
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
function initChrome() {
  let theme = pref.get("theme") || "auto", motion = pref.get("motion") || "full";
  applyTheme(theme); applyMotion(motion);
  $("#themeBtn").onclick = () => { theme = { auto: "light", light: "dark", dark: "auto" }[theme]; pref.set("theme", theme); applyTheme(theme); };
  $("#motionBtn").onclick = () => { motion = motion === "full" ? "reduced" : "full"; pref.set("motion", motion); applyMotion(motion); };
  $("#helpBtn").onclick = () => openDialog("¿Cómo funciona?", `<div class="how"><ol>
    <li><b>Carga</b> el export del SIEM en Excel, CSV o JSON. Se detectan el formato y las columnas aunque cambien de nombre.</li>
    <li><b>Reglas deterministas</b> buscan fuerza bruta, inicios de sesión externos, escalamiento, comandos sospechosos, movimiento lateral, exfiltración, persistencia y ataques web. Cada hallazgo cita los Log_ID que lo prueban.</li>
    <li><b>Correlación</b>: los hallazgos se agrupan en incidentes solo si comparten IP externa o cuenta. Compartir un host o recurso queda como hipótesis de confianza baja.</li>
    <li><b>IA</b> redacta explicaciones, impacto y plan de acción. No cambia la criticidad y se descarta cualquier Log_ID o IP que no esté en el archivo.</li>
    <li><b>Informe PDF</b> con resumen ejecutivo, hallazgos, evidencia, criticidad, impacto, plan de acción y recomendaciones.</li></ol>
    <p class="muted">Atajos: Ctrl+K o / para buscar.</p></div>`);
  $("#searchBtn").onclick = openPalette;
  addEventListener("keydown", (e) => {
    const typing = /INPUT|SELECT|TEXTAREA/.test(document.activeElement?.tagName || "");
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    else if (e.key === "/" && !typing) { e.preventDefault(); openPalette(); }
  });
}
function paletteItems() {
  const items = [["Ir a", "Panel", "#/dashboard"], ["Ir a", "Incidentes", "#/incidents"], ["Ir a", "Hallazgos", "#/findings"], ["Ir a", "Eventos", "#/logs"], ["Ir a", "Indicadores (IoC)", "#/iocs"], ["Ir a", "Informe y PDF", "#/report"]];
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
(async function init() {
  initChrome();
  try { const h = await api("/api/health"); S.aiConfigured = h.ai_configured; } catch { /* servidor sin health */ }
  const sid = store.get("sid");
  if (sid) {
    try { const r = await api(`/api/sessions/${sid}`); adopt(r); if (!route()) location.hash = "#/dashboard"; } catch { store.set("sid", ""); }
  }
  render();
})();
