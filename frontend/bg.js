/* Landing background: a soft radar sweep, expanding rings and a drifting node network on a <canvas>.
   Only runs while the landing screen is on; honours the motion setting and prefers-reduced-motion.
   Standalone on purpose: it watches #main for the landing section, so app.js needs no changes. */
(function () {
  "use strict";
  var root = document.documentElement, main = document.getElementById("main");
  if (!main || !window.requestAnimationFrame) return;

  var canvas = document.createElement("canvas");
  canvas.id = "bgCanvas"; canvas.setAttribute("aria-hidden", "true");
  document.body.insertBefore(canvas, document.body.firstChild);
  var ctx = canvas.getContext("2d");
  if (!ctx) { canvas.remove(); return; }

  var W = 0, H = 0, nodes = [], packets = [], raf = 0, last = 0, clock = 0, nextPacket = 0;
  var mouse = { x: -9999, y: -9999 };
  var ink = [147, 163, 187], accent = [255, 106, 43], dark = true;

  function hexToRgb(v, fallback) {
    var m = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.exec((v || "").trim());
    if (!m) return fallback;
    var h = m[1].length === 3 ? m[1].replace(/./g, "$&$&") : m[1];
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
  }
  function readColors() {
    var cs = getComputedStyle(root);
    accent = hexToRgb(cs.getPropertyValue("--accent"), accent);
    ink = hexToRgb(cs.getPropertyValue("--muted"), ink);
    var bg = hexToRgb(cs.getPropertyValue("--bg"), [7, 13, 26]);
    dark = (bg[0] + bg[1] + bg[2]) / 3 < 128;
  }
  var rgba = function (c, a) { return "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + a.toFixed(3) + ")"; };

  function reduced() {
    return root.getAttribute("data-motion") === "reduced" || matchMedia("(prefers-reduced-motion: reduce)").matches;
  }
  function onLanding() { return !!main.querySelector(".landing"); }

  function resize() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var n = Math.min(70, Math.floor((W * H) / 20000)); if (W < 700) n = Math.min(n, 28);
    nodes = [];
    for (var i = 0; i < n; i++) {
      nodes.push({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * 14, vy: (Math.random() - .5) * 14,
        r: Math.random() * 1.2 + .5, ph: Math.random() * 6.28, hub: Math.random() < .09 });
    }
    packets = [];
    draw();
  }

  /* One frame at time t (seconds). Alphas are kept low so the text on top stays readable. */
  function draw() {
    ctx.clearRect(0, 0, W, H);
    var k = dark ? 1 : .8, cx = W * .5, cy = H * .42, maxR = Math.max(W, H) * .7, t = clock;

    for (var i = 0; i < 4; i++) {                               // expanding rings
      var ph = (t * .09 + i * .25) % 1;
      ctx.strokeStyle = rgba(accent, (1 - ph) * .11 * k); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(cx, cy, ph * maxR, 0, 6.2832); ctx.stroke();
    }

    var ang = t * .45, wedge = Math.PI / 5;                      // sweep wedge
    var g = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
    g.addColorStop(0, rgba(accent, .13 * k)); g.addColorStop(.55, rgba(accent, .05 * k)); g.addColorStop(1, rgba(accent, 0));
    ctx.fillStyle = g; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, maxR, ang - wedge, ang); ctx.closePath(); ctx.fill();
    ctx.strokeStyle = rgba(accent, .28 * k); ctx.lineWidth = 1.2;  // leading edge
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(ang) * maxR, cy + Math.sin(ang) * maxR); ctx.stroke();

    var D = 150;                                                 // network links
    ctx.lineWidth = .7;
    for (var a = 0; a < nodes.length; a++) for (var b = a + 1; b < nodes.length; b++) {
      var dx = nodes[a].x - nodes[b].x, dy = nodes[a].y - nodes[b].y, d = Math.sqrt(dx * dx + dy * dy);
      if (d < D) { ctx.strokeStyle = rgba(ink, (1 - d / D) * .2 * k); ctx.beginPath(); ctx.moveTo(nodes[a].x, nodes[a].y); ctx.lineTo(nodes[b].x, nodes[b].y); ctx.stroke(); }
    }
    nodes.forEach(function (n) {                                 // nodes: those the sweep just crossed glow orange
      var diff = (((ang - Math.atan2(n.y - cy, n.x - cx)) % 6.2832) + 6.2832) % 6.2832;
      var lit = diff < wedge ? 1 - diff / wedge : 0, r = n.r + Math.sin(n.ph + t * 1.5) * .25;
      if (n.hub || lit > .02) {
        var gr = r * (n.hub ? 9 : 6), gg = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, gr), c = lit > .02 ? accent : ink;
        gg.addColorStop(0, rgba(c, (n.hub ? .22 : .5 * lit) * k)); gg.addColorStop(1, rgba(c, 0));
        ctx.fillStyle = gg; ctx.beginPath(); ctx.arc(n.x, n.y, gr, 0, 6.2832); ctx.fill();
      }
      ctx.fillStyle = rgba(lit > .02 ? accent : ink, (.35 + .4 * lit) * k); ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 6.2832); ctx.fill();
    });
    packets.forEach(function (p) {                               // data packets travelling between close nodes
      var u = (t - p.t0) / p.dur, x = p.a.x + (p.b.x - p.a.x) * u, y = p.a.y + (p.b.y - p.a.y) * u;
      var h = ctx.createRadialGradient(x, y, 0, x, y, 8);
      h.addColorStop(0, rgba(accent, .6 * k)); h.addColorStop(1, rgba(accent, 0));
      ctx.fillStyle = h; ctx.beginPath(); ctx.arc(x, y, 8, 0, 6.2832); ctx.fill();
      ctx.fillStyle = rgba(accent, .9 * k); ctx.beginPath(); ctx.arc(x, y, 1.8, 0, 6.2832); ctx.fill();
    });
  }

  function step(dt) {
    clock += dt;
    nodes.forEach(function (n) {
      n.x += n.vx * dt; n.y += n.vy * dt;
      if (n.x < 0 || n.x > W) n.vx *= -1; if (n.y < 0 || n.y > H) n.vy *= -1;
      var dx = n.x - mouse.x, dy = n.y - mouse.y, d = Math.sqrt(dx * dx + dy * dy);
      if (d < 130 && d > 1) { var f = (130 - d) / 130 * 40 * dt; n.x += dx / d * f; n.y += dy / d * f; }
    });
    packets = packets.filter(function (p) { return clock - p.t0 < p.dur; });
    if (clock > nextPacket && nodes.length > 1) {
      nextPacket = clock + .35;
      var a = nodes[Math.floor(Math.random() * nodes.length)], best = null, bd = 1e9;
      nodes.forEach(function (c) { var d = Math.hypot(c.x - a.x, c.y - a.y); if (c !== a && d < 170 && d < bd && Math.random() < .5) { best = c; bd = d; } });
      if (best) packets.push({ a: a, b: best, t0: clock, dur: 1.4 + Math.random() * 1.2 });
    }
  }

  function frame(now) {
    raf = 0;
    var dt = Math.min(.05, (now - (last || now)) / 1000); last = now;
    step(dt); draw(); raf = requestAnimationFrame(frame);
  }

  /* Decide what to do: animate, show one still frame, or hide. */
  function sync() {
    var show = onLanding();
    canvas.style.display = show ? "block" : "none";
    if (raf) { cancelAnimationFrame(raf); raf = 0; }
    if (!show) return;
    readColors();
    if (!W) resize();
    if (reduced()) { clock = 4; draw(); return; }
    if (!document.hidden) { last = 0; raf = requestAnimationFrame(frame); }
  }

  new MutationObserver(sync).observe(main, { childList: true });
  new MutationObserver(sync).observe(root, { attributes: true, attributeFilter: ["data-theme", "data-motion"] });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", sync);
  matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", sync);
  document.addEventListener("visibilitychange", sync);
  window.addEventListener("resize", function () { if (onLanding()) { resize(); sync(); } });
  window.addEventListener("mousemove", function (e) { mouse.x = e.clientX; mouse.y = e.clientY; }, { passive: true });
  window.addEventListener("mouseout", function (e) { if (!e.relatedTarget) { mouse.x = mouse.y = -9999; } });
  sync();
})();
