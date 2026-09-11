/* bluesky Web Dashboard — cliente minimalista (sin dependencias).
   Regla anti-XSS: NUNCA se usa innerHTML con datos; todo se renderiza
   con createElement + textContent. */

(function () {
  "use strict";

  // ── Utilidades ──────────────────────────────────────────────────────

  function $(sel, root) { return (root || document).querySelector(sel); }

  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function toast(msg) {
    var t = $("#toast");
    if (!t) return;
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(t._timer);
    t._timer = setTimeout(function () { t.classList.remove("show"); }, 2600);
  }

  // ── Estado global (todas las páginas: pill de la topbar) ───────────

  function refreshStatusPill() {
    fetch("/api/scan/status")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        var dot = $("[data-status-dot]");
        var txt = $("[data-status-text]");
        if (!dot || !txt) return;
        if (d.in_progress) {
          dot.className = "dot busy";
          txt.textContent = "operación en curso";
        } else {
          dot.className = "dot live";
          txt.textContent = "listo";
        }
        var pill = $("#scan-pill");
        if (pill) {
          var pd = pill.querySelector(".dot");
          var pt = pill.lastChild;
          if (pd) pd.className = "dot " + (d.in_progress ? "busy" : "live");
        }
        if (window.__onScanStatus) window.__onScanStatus(d);
      })
      .catch(function () {});
  }
  refreshStatusPill();
  setInterval(refreshStatusPill, 4000);

  // ── Página de escaneo ───────────────────────────────────────────────

  var scanBtn = $("#scan-btn");
  if (scanBtn) {
    scanBtn.addEventListener("click", function () {
      var type = ($("#scan-type") || {}).value || "device";
      var target = ($("#scan-target") || {}).value || "";
      scanBtn.disabled = true;
      scanBtn.textContent = "Iniciando…";
      fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanner: type, target: target })
      })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (res.ok) {
            toast("Escaneo iniciado");
            window.__onScanStatus = pollScanResults;
          } else {
            toast(res.j && res.j.message ? res.j.message : "No se pudo iniciar");
          }
        })
        .catch(function () { toast("Error de red"); })
        .finally(function () {
          scanBtn.disabled = false;
          scanBtn.textContent = "Iniciar escaneo";
        });
    });
  }

  function pollScanStatus() {}

  function pollScanResults() {
    fetch("/api/scan/status")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.recent_results) return;
        renderScanResults(d.recent_results.slice().reverse());
      })
      .catch(function () {});
  }

  function renderScanResults(results) {
    var tbody = $("#scan-results");
    if (!tbody) return;
    var empty = $("#scan-empty");
    var table = $("#scan-table");
    if (empty && results.length) { empty.style.display = "none"; }
    if (table) { table.style.display = results.length ? "" : "none"; }

    tbody.textContent = "";
    results.forEach(function (r) {
      var tr = el("tr");

      var tdTime = el("td", "mono", r.time || "");
      var tdMod = el("td", null, r.module || "");
      var tdTarget = el("td", "mono", r.target || "broadcast");

      var tdState = el("td");
      var badge = el("span", "badge " + (r.success ? "ok" : "danger"),
                     r.success ? "OK" : "Fallo");
      tdState.appendChild(badge);

      var detail = "completado";
      if (r.result && typeof r.result === "object" && r.result.error) {
        detail = r.result.error;
      }
      var tdDetail = el("td", "muted", detail);

      tr.appendChild(tdTime);
      tr.appendChild(tdMod);
      tr.appendChild(tdTarget);
      tr.appendChild(tdState);
      tr.appendChild(tdDetail);
      tbody.appendChild(tr);
    });
  }

  // ── Página de reportes (visor) ──────────────────────────────────────

  document.querySelectorAll("[data-report]").forEach(function (link) {
    link.addEventListener("click", function (ev) {
      ev.preventDefault();
      var name = link.getAttribute("data-report");
      var viewer = $("#report-viewer");
      fetch("/api/reports/" + encodeURIComponent(name))
        .then(function (r) {
          if (!r.ok) throw new Error("no disponible");
          return r.json();
        })
        .then(function (d) {
          $("#report-viewer-name").textContent = d.name || name;
          $("#report-viewer-body").textContent = (d.content || "").slice(0, 20000);
          viewer.style.display = "";
          viewer.scrollIntoView({ behavior: "smooth", block: "nearest" });
        })
        .catch(function () { toast("Reporte no disponible"); });
    });
  });

  var reportClose = $("#report-close");
  if (reportClose) {
    reportClose.addEventListener("click", function () {
      $("#report-viewer").style.display = "none";
    });
  }

  // ── Página de logs (auto-refresh) ───────────────────────────────────

  var logBody = $("#log-body");
  if (logBody) {
    setInterval(function () {
      fetch("/api/logs")
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d || !d.entries) return;
          var pill = $("#log-pill .dot");
          if (pill) pill.className = "dot live";
          logBody.textContent = "";
          d.entries.slice().reverse().forEach(function (e) {
            var tr = el("tr");
            tr.appendChild(el("td", "mono faint", e.time || ""));
            var lvl = el("td", "log-level " + (e.level || "info"), e.level || "info");
            tr.appendChild(lvl);
            tr.appendChild(el("td", null, e.message || ""));
            logBody.appendChild(tr);
          });
        })
        .catch(function () {
          var pill = $("#log-pill .dot");
          if (pill) pill.className = "dot";
        });
    }, 4000);
  }
})();
