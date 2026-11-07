(function () {
  "use strict";
  var root = document.documentElement;
  var reduce = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  var canAnimate = typeof anime === "function" && !reduce;
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* tema: respeta el del sistema y se puede cambiar; si el navegador no deja guardar, sigue funcionando */
  var tbtn = document.getElementById("theme");
  try { var saved = localStorage.getItem("soc-report-theme"); if (saved === "dark" || saved === "light") root.setAttribute("data-theme", saved); } catch (e) { /* sin almacenamiento */ }
  if (tbtn) tbtn.addEventListener("click", function () {
    var dark = root.getAttribute("data-theme") === "dark" || (!root.getAttribute("data-theme") && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    var next = dark ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("soc-report-theme", next); } catch (e) { /* sin almacenamiento */ }
  });

  /* filtros de la tabla de IoC */
  var q = document.getElementById("ioc-q"), sv = document.getElementById("ioc-sev");
  function applyIoc() {
    var text = q ? q.value.trim().toLowerCase() : "", sev = sv ? sv.value : "";
    var rows = $$("#ioc-body tr"), shown = 0;
    rows.forEach(function (r) {
      var ok = (!text || (r.getAttribute("data-t") || "").indexOf(text) !== -1) && (!sev || r.getAttribute("data-s") === sev);
      r.classList.toggle("hidden-row", !ok);
      if (ok) shown++;
    });
    var c = document.getElementById("ioc-count");
    if (c) c.textContent = shown + " de " + rows.length + " indicadores";
  }
  if (q) q.addEventListener("input", applyIoc);
  if (sv) sv.addEventListener("change", applyIoc);

  /* expandir / contraer incidentes */
  function setAll(open) { $$("details.inc,details.fnd").forEach(function (d) { d.open = open; }); }
  var ex = document.getElementById("expand"), co = document.getElementById("collapse");
  if (ex) ex.addEventListener("click", function () { setAll(true); });
  if (co) co.addEventListener("click", function () { setAll(false); });

  /* impresión: todo abierto y visible */
  var openBefore = [];
  window.addEventListener("beforeprint", function () {
    openBefore = $$("details").map(function (d) { return d.open; });
    $$("details").forEach(function (d) { d.open = true; });
    $$(".reveal").forEach(function (e) { e.style.opacity = "1"; e.style.transform = "none"; });
  });
  window.addEventListener("afterprint", function () { $$("details").forEach(function (d, i) { d.open = openBefore[i]; }); });
  var pbtn = document.getElementById("print");
  if (pbtn) pbtn.addEventListener("click", function () { window.print(); });

  /* animaciones (solo si hay anime.js y el usuario no pidió menos movimiento): el contenido ya está completo sin ellas */
  if (!canAnimate) return;
  root.classList.add("anim");

  $$(".kpi .n").forEach(function (el) {
    var fin = el.textContent, v = parseInt(fin.replace(/\D/g, ""), 10);
    if (isNaN(v)) return;
    var o = { n: 0 };
    anime({ targets: o, n: v, round: 1, duration: 1100, easing: "easeOutExpo", update: function () { el.textContent = o.n.toLocaleString("es-AR"); }, complete: function () { el.textContent = fin; } });
  });
  $$("circle.seg").forEach(function (c, i) {
    var fin = c.getAttribute("data-dash"), full = c.getAttribute("data-c");
    c.setAttribute("stroke-dasharray", "0 " + full);
    anime({ targets: c, "stroke-dasharray": [("0 " + full), fin], duration: 900, delay: 150 + i * 140, easing: "easeOutCubic" });
  });
  var bars = $$("rect.bar");
  bars.forEach(function (r) { r.setAttribute("data-h", r.getAttribute("height")); r.setAttribute("data-y", r.getAttribute("y")); r.setAttribute("height", "0"); r.setAttribute("y", r.getAttribute("data-base")); });
  var bt = document.getElementById("timeline");
  function growBars() {
    if (!bars.length) return;
    anime({ targets: bars, height: function (r) { return Number(r.getAttribute("data-h")); }, y: function (r) { return Number(r.getAttribute("data-y")); },
            duration: 700, delay: anime.stagger(12), easing: "easeOutQuad" });
  }
  /* estado final de gráficos (impresión o red de seguridad) */
  function finishCharts() {
    bars.forEach(function (r) { r.setAttribute("height", r.getAttribute("data-h")); r.setAttribute("y", r.getAttribute("data-y")); });
    $$("circle.seg").forEach(function (c) { c.setAttribute("stroke-dasharray", c.getAttribute("data-dash")); });
  }
  window.addEventListener("beforeprint", function () { if (typeof anime.remove === "function") anime.remove(bars); finishCharts(); });
  var revealed = false;
  function revealAll() {
    if (revealed) return; revealed = true;
    $$(".reveal").forEach(function (e) { e.style.opacity = "1"; e.style.transform = "none"; });
  }
  if ("IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        io.unobserve(en.target);
        if (en.target === bt) growBars();
        if (en.target.classList.contains("reveal")) {
          anime({ targets: en.target, opacity: [0, 1], translateY: [16, 0], duration: 600, easing: "easeOutCubic" });
          var items = $$(".kc li", en.target);
          if (items.length) anime({ targets: items, opacity: [0, 1], translateX: [-10, 0], delay: anime.stagger(60, { start: 200 }), duration: 450, easing: "easeOutQuad" });
        }
      });
    }, { threshold: 0.08 });
    $$(".reveal").forEach(function (e) { io.observe(e); });
    if (bt) io.observe(bt);
    setTimeout(function () { revealAll(); growBars(); }, 4000);   /* red de seguridad: nada queda oculto */
  } else { revealAll(); growBars(); }
  /* al abrir un incidente se anima su cronología */
  $$("details.inc").forEach(function (d) {
    d.addEventListener("toggle", function () {
      if (!d.open) return;
      var items = $$(".kc li", d);
      if (items.length) anime({ targets: items, opacity: [0, 1], translateX: [-10, 0], delay: anime.stagger(50), duration: 400, easing: "easeOutQuad" });
    });
  });
})();
