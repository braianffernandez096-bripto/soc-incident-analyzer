/* Aplica tema y movimiento antes de pintar para evitar parpadeos. */
(function () {
  try {
    var t = localStorage.getItem("theme"), m = localStorage.getItem("motion");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
    if (m === "reduced") document.documentElement.setAttribute("data-motion", "reduced");
  } catch (e) { /* sin almacenamiento */ }
})();
