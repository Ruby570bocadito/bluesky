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
    // Mostrar/ocultar modo y timeout según el escáner elegido
    var scanTypeSel = $("#scan-type");
    function syncScanFields() {
      var isDevice = !scanTypeSel || scanTypeSel.value === "device";
      var modeField = $("#scan-mode-field");
      var timeoutField = $("#scan-timeout-field");
      if (modeField) modeField.style.display = isDevice ? "" : "none";
      if (timeoutField) timeoutField.style.display = isDevice ? "" : "none";
    }
    if (scanTypeSel) {
      scanTypeSel.addEventListener("change", syncScanFields);
      syncScanFields();
    }

    scanBtn.addEventListener("click", function () {
      var type = ($("#scan-type") || {}).value || "device";
      var target = ($("#scan-target") || {}).value || "";
      var body = { scanner: type, target: target.trim() };
      if (type === "device") {
        body.type = ($("#scan-mode") || {}).value || "all";
        var t = parseInt(($("#scan-timeout") || {}).value || "", 10);
        if (!isNaN(t)) body.timeout = t;
      }
      scanBtn.disabled = true;
      scanBtn.textContent = "Iniciando…";
      fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
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

  // Descarga del CSV con los dispositivos del último escaneo
  var exportBtn = $("#scan-export");
  if (exportBtn) {
    exportBtn.addEventListener("click", function () {
      fetch("/api/scan/export")
        .then(function (r) {
          if (!r.ok) throw new Error("no disponible");
          return r.blob();
        })
        .then(function (blob) {
          var a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "bluesky_devices.csv";
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(a.href);
          toast("CSV exportado");
        })
        .catch(function () { toast("No hay dispositivos para exportar"); });
    });
  }

  function pollScanStatus() {}

  function pollScanResults(opts) {
    fetch("/api/scan/status")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.recent_results) return;
        if (!opts || opts.runs !== false) {
          renderScanResults(d.recent_results.slice().reverse());
        }
        renderDevicesFromResults(d.recent_results);
      })
      .catch(function () {});
  }

  // Extrae los dispositivos del resultado de escaneo más reciente que los tenga
  function renderDevicesFromResults(results) {
    for (var i = results.length - 1; i >= 0; i--) {
      var r = results[i];
      if (!r || !r.result || typeof r.result !== "object") continue;
      var data = r.result.data;
      if (!data || typeof data !== "object" || !Array.isArray(data.devices)) continue;
      renderDevices(data.devices);
      return;
    }
  }

  function renderDevices(devices) {
    var tbody = $("#devices-body");
    var empty = $("#devices-empty");
    var table = $("#devices-table");
    var exportBtn = $("#scan-export");
    if (!tbody || !table) return;
    if (empty) empty.style.display = devices.length ? "none" : "";
    table.style.display = devices.length ? "" : "none";
    if (exportBtn) exportBtn.disabled = !devices.length;

    tbody.textContent = "";
    devices.forEach(function (d) {
      if (!d || typeof d !== "object") return;
      var tr = el("tr");
      tr.appendChild(el("td", "mono", d.mac || ""));
      tr.appendChild(el("td", null, d.name || "Unknown"));
      tr.appendChild(el("td", null, (d.type || "?").toUpperCase()));
      tr.appendChild(el("td", null, d.vendor || "—"));
      tr.appendChild(el("td", "mono", d.rssi ? String(d.rssi) : ""));
      tbody.appendChild(tr);
    });
  }

  // Carga inicial: solo dispositivos (la tabla de runs ya está server-rendered)
  if ($("#devices-body")) {
    window.__onScanStatus = function () { pollScanResults(); };
    pollScanResults({ runs: false });
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
