/* Forensics triage dashboard (case-file edition). Vanilla JS, no dependencies, no HTML string injection: every value is
   inserted with textContent, because evidence contains attacker-controlled strings (file names, URLs, <script> ...). */
(function () {
  "use strict";

  var SEV = ["critical", "high", "medium", "low"];
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  var SEV_COLOR = { critical: "#a8281f", high: "#bf5509", medium: "#8f6a00", low: "#25507a" };
  var SRC_COLOR = { "FILESYSTEM": "#25507a", "NTFS $FN": "#6a4a9a", "BROWSER": "#b0800b", "PREFETCH": "#2c7a3c",
                    "REGISTRY": "#a8346a", "MFT": "#bf5509", "DOCUMENT": "#15788a", "RECYCLE BIN": "#6b6354" };
  var INK = "#2a2118", INK2 = "#5d4e3a", GRID = "#dccfae";
  var TABS = ["case", "timeline", "findings", "files", "clues", "recovered", "custody", "traces", "attack"];
  var tab = "case";
  var FLAG_SEV = { known_bad: "critical", timestomp_likely: "high", signature_mismatch: "medium", staging_dir: "medium",
                   timestamp_weak: "low", known_good: "ok", recycle_bin: "", browser_history: "" };
  var FLAGGED = ["known_bad", "signature_mismatch", "timestomp_likely", "timestamp_weak", "staging_dir", "recycle_bin"];   // same set the engine counts as "flagged"
  var DEFAULT_URL = "data/case.json";
  var PAGE = 150;

  var data = null, state = null, lastFocus = null;
  var bins = [], hoverBin = -1, tlEvents = [], tlShown = PAGE;
  var chainEntries = null, tamperedSeq = 0;

  function freshState() {
    return {
      f: { sev: {}, q: "", cat: "", technique: "", file: "", sort: "severity", dir: -1 },
      fl: { q: "", flag: "", only: false, sort: "flags", dir: -1 },
      tl: { mode: "window", off: {}, q: "", range: null },
      ioc: { type: "", scope: "", q: "" }
    };
  }

  // ------------------------------------------------------------------ tabs (manila folder tabs on the left spine)
  function goTab(name, noScroll) {
    if (TABS.indexOf(name) < 0) name = "case";
    tab = name;
    TABS.forEach(function (t) {
      var on = t === name, btn = $("tab-" + t), pg = $("page-" + t);
      btn.setAttribute("aria-selected", on ? "true" : "false"); btn.tabIndex = on ? 0 : -1; pg.hidden = !on;
    });
    if (name === "timeline" && data) drawChart();           // the canvas has no size while its page is hidden
    if (!noScroll) { var top = $("sheet").getBoundingClientRect().top + window.pageYOffset - 10; if (window.pageYOffset > top) window.scrollTo(0, Math.max(0, top)); }
  }
  function wireTabs() {
    var btns = $("tabs").querySelectorAll("button.tab");
    for (var i = 0; i < btns.length; i++) (function (b, idx) {
      b.addEventListener("click", function () { goTab(b.getAttribute("data-tab")); });
      b.addEventListener("keydown", function (e) {
        var d = (e.key === "ArrowDown" || e.key === "ArrowRight") ? 1 : (e.key === "ArrowUp" || e.key === "ArrowLeft") ? -1 : e.key === "Home" ? -99 : e.key === "End" ? 99 : 0;
        if (!d) return; e.preventDefault();
        var n = Math.abs(d) === 99 ? (d < 0 ? 0 : btns.length - 1) : (idx + d + btns.length) % btns.length;
        btns[n].focus(); goTab(btns[n].getAttribute("data-tab"), true);
      });
    })(btns[i], i);
  }

  // ------------------------------------------------------------------ DOM helpers
  function $(id) { return document.getElementById(id); }
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    (kids || []).forEach(function (c) {
      if (c === null || c === undefined) return;
      el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function sevBadge(sev) { return h("span", { class: "sev-badge sev-" + sev, text: sev }); }
  function td(content, cls) { return h("td", cls ? { class: cls } : null, [content]); }
  function srcTag(s) { var e = h("span", { class: "src", text: s }); e.style.setProperty("--c", SRC_COLOR[s] || "#7a6e5a"); return e; }
  function flagTag(f) { return h("span", { class: "flag" + (FLAG_SEV[f] ? " f-" + FLAG_SEV[f] : ""), text: f }); }
  function num(n) { return Number(n).toLocaleString("en-US"); }
  function bytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  }
  function short(s, n) { return s && s.length > n ? s.slice(0, n) + "…" : s; }
  function pad(n) { return n < 10 ? "0" + n : "" + n; }
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function utc(ms) {
    var d = new Date(ms);
    return d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " + pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds());
  }
  function axisLabel(ms, withTime) {
    var d = new Date(ms);
    return MONTHS[d.getUTCMonth()] + " " + d.getUTCDate() + (withTime ? " " + pad(d.getUTCHours()) + ":00" : "");
  }
  function parseNaive(s) {                    // "YYYY-MM-DD HH:MM:SS[.fff]" (UTC) -> ms, or NaN
    var m = /^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)/.exec(s || "");
    return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : NaN;
  }
  function dirOf(p) { var i = p.lastIndexOf("/"); return i < 0 ? "" : p.slice(0, i + 1); }
  function nameOf(p) { var i = p.lastIndexOf("/"); return i < 0 ? p : p.slice(i + 1); }
  function pathCell(p) { return h("span", { class: "path" }, [h("span", { class: "nm", text: nameOf(p) }), h("span", { class: "dir", text: dirOf(p) })]); }
  function lc(s) { return String(s === undefined || s === null ? "" : s).toLowerCase(); }

  // ------------------------------------------------------------------ loading
  function load(url) {
    fetch(url, { cache: "no-cache" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }).then(init).catch(function (err) {
      showError("Could not load " + url + " (" + err.message + "). If you opened index.html directly from disk, browsers block fetch() on file:// URLs: " +
        "run `python -m http.server` in this folder, or use \"Open your own case_report.json\" on the left.");
      $("dataset-meta").textContent = "Folder is empty";
    });
  }
  function showError(msg) { var e = $("error"); e.textContent = msg; e.hidden = false; }
  function validate(d) {
    if (!d || typeof d !== "object" || Array.isArray(d)) throw new Error("not a JSON object");
    ["meta", "summary", "integrity", "window"].forEach(function (k) { if (!d[k] || typeof d[k] !== "object") throw new Error("missing '" + k + "': is this a forensictriage case_report.json?"); });
    ["findings", "files", "timeline", "iocs", "mitre", "rules", "narrative"].forEach(function (k) {
      if (d[k] === undefined) d[k] = [];
      if (!Array.isArray(d[k])) throw new Error("'" + k + "' must be a list");
    });
    d.carved = d.carved || {}; d.carved.files = d.carved.files || []; d.carved.stats = d.carved.stats || [];
    d.deleted = d.deleted || {}; d.deleted.recycle_bin = d.deleted.recycle_bin || []; d.deleted.mft_entries = d.deleted.mft_entries || [];
    d.browser = d.browser || {}; ["flagged_visits", "flagged_searches", "downloads"].forEach(function (k) { d.browser[k] = d.browser[k] || []; });
    d.artifacts = d.artifacts || {}; ["prefetch", "usb_devices", "recent_docs"].forEach(function (k) { d.artifacts[k] = d.artifacts[k] || []; });
    d.integrity.custody = d.integrity.custody || []; d.integrity.differences = d.integrity.differences || [];
    d.integrity.before = d.integrity.before || {}; d.integrity.after = d.integrity.after || {};
    d.findings.forEach(function (f) {
      if (!SEV_RANK[f.severity]) throw new Error("finding " + f.id + " has unknown severity " + f.severity);
      ["files", "evidence", "mitre", "response"].forEach(function (k) { f[k] = f[k] || []; });
    });
    d.files.forEach(function (f) { f.flags = f.flags || []; f.times = f.times || {}; f.timestomp = f.timestomp || { score: 0, verdict: "none", indicators: [] }; f.embedded = f.embedded || {}; });
    return d;
  }

  function init(d) {
    try { data = validate(d); } catch (e) { showError("Invalid report file: " + e.message); return; }
    $("error").hidden = true;
    state = freshState();
    hideDrawer(true);
    chainEntries = JSON.parse(JSON.stringify(data.integrity.custody)); tamperedSeq = 0;
    buildBanner(); buildKpis(); buildCase(); buildStory(); buildTimelineControls(); buildFindingFilters(); buildFileFilters(); buildIocFilters();
    buildCarved(); buildIntegrity(); buildArtifacts(); buildMitre(); buildRules();
    renderAll();
    var m = /finding=([A-Za-z0-9-]+)/.exec(location.hash);
    if (m) { var f = findingById(m[1]); if (f) { goTab("findings", true); openFinding(f); } }
  }
  function findingById(id) { for (var i = 0; i < data.findings.length; i++) if (data.findings[i].id === id) return data.findings[i]; return null; }
  function fileByPath(p) { for (var i = 0; i < data.files.length; i++) if (data.files[i].path === p) return data.files[i]; return null; }
  function renderAll() { renderFindings(); renderFiles(); renderTimeline(); renderIocs(); if (tab === "timeline") drawChart(); }

  // ------------------------------------------------------------------ static sections
  function buildBanner() {
    var b = $("banner"), meta = data.meta;
    if (meta.synthetic) {
      b.className = "banner synthetic";
      var note = (meta.notice || "This report is labelled synthetic.").replace(/^SYNTHETIC DATA\.?\s*/, "");
      b.firstElementChild.textContent = "SYNTHETIC DATA.";
      $("banner-text").textContent = " " + note.charAt(0).toUpperCase() + note.slice(1);
    } else {
      b.className = "banner real";
      b.firstElementChild.textContent = "YOUR DATA.";
      $("banner-text").textContent = " This report came from your own file and is not labelled synthetic. Everything happens in your browser and nothing is uploaded.";
    }
    var s = data.summary;
    $("dataset-meta").textContent = (meta.case_id || "case") + " · " + num(s.files) + " files · " + num(s.timeline_events) + " timeline events";
    $("foot-meta").textContent = "Report written " + meta.generated_at + " by " + meta.tool + " v" + meta.version + " · case " + meta.case_id +
      " · raw images: " + (meta.raw_images || []).join(", ");
  }

  function kpi(n, label, opts) {
    opts = opts || {};
    var el = h(opts.onclick ? "button" : "div", { class: "kpi" + (opts.onclick ? "" : " static"), "data-sev": opts.sev || "info", type: opts.onclick ? "button" : null,
      "aria-pressed": opts.onclick ? "false" : null, onclick: opts.onclick || null }, [
      h("span", { class: "n" + (opts.small ? " small" : ""), text: n }), h("span", { class: "l", text: label })]);
    if (opts.id) el.id = opts.id;
    return el;
  }
  function buildKpis() {
    var box = $("kpis"); clear(box);
    var s = data.summary, sc = s.by_severity || {};
    SEV.forEach(function (sev) {
      box.appendChild(kpi(sc[sev] || 0, sev, { sev: sev, id: "kpi-" + sev, onclick: function () { toggleSev(sev); goTab("findings"); } }));
    });
    box.appendChild(kpi(s.flagged_files + " / " + s.files, "files look odd", { small: true, onclick: function () { state.fl.only = true; $("fl-only").checked = true; renderFiles(); goTab("files"); } }));
    box.appendChild(kpi((s.carved_complete || 0) + (s.carved_partial ? " + " + s.carved_partial : ""), "deleted files found (whole + partial)", { small: true, onclick: function () { goTab("recovered"); } }));
    var ok = data.integrity.ok && data.integrity.custody_chain_ok;
    box.appendChild(kpi(ok ? "UNCHANGED" : "CHANGED", "evidence", { sev: ok ? "ok" : "bad", small: true, onclick: function () { goTab("custody"); } }));
    syncKpis();
  }
  function syncKpis() {
    SEV.forEach(function (sev) { var k = $("kpi-" + sev); if (k) { var on = !!state.f.sev[sev]; k.classList.toggle("active", on); k.setAttribute("aria-pressed", on ? "true" : "false"); } });
  }

  function buildCase() {
    var m = data.meta, s = data.summary;
    $("case-id").textContent = m.case_id || "";
    $("case-name").textContent = m.title || "Untitled case";
    $("case-desc").textContent = m.description || "";
    var kv = $("case-kv"); clear(kv);
    function row(k, v) { kv.appendChild(h("dt", { text: k })); kv.appendChild(h("dd", { text: v })); }
    row("Examiner", m.examiner || "n/a");
    row("Evidence acquired", m.evidence_acquired_at || "n/a");
    row("Evidence root", m.evidence_root || "n/a");
    row("Incident window", data.window.start + " → " + data.window.end);
    row("Did it change?", data.integrity.ok ? "No. " + num(data.integrity.before.files || 0) + " files hashed before and after" : "YES, during analysis");
    var st = $("case-stats"); clear(st);
    [[s.files, "files"], [bytes(s.bytes), "of evidence"], [s.findings, "findings"], [s.known_bad, "known-bad files"], [s.signature_mismatches, "files in disguise"],
     [s.timestomp_likely, "faked dates"], [s.iocs + " (" + s.iocs_external + " outside)", "clues"], [s.usb_devices, "USB sticks"], [s.browser_visits, "browser visits"], [s.techniques, "ATT&CK techniques"]
    ].forEach(function (p) { st.appendChild(h("div", { class: "stat" }, [h("b", { text: String(p[0]) }), h("span", { text: p[1] })])); });
  }
  function gapText(ms) {
    var m = Math.round(ms / 60000), d = Math.floor(m / 1440), hh = Math.floor((m % 1440) / 60), mm = m % 60;
    if (d >= 1) return d + (d === 1 ? " day" : " days") + (hh ? " " + hh + "h" : "");
    return hh ? hh + "h" + (mm ? " " + mm + "m" : "") : mm + " min";
  }
  function buildStory() {
    var ol = $("story"); clear(ol);
    var prev = null;
    data.narrative.slice().sort(function (a, b) { return a.ms - b.ms; }).forEach(function (n) {
      var b = h("button", { type: "button", onclick: function () { var f = findingById(n.finding); if (f) openFinding(f); } }, [
        h("time", { text: utc(n.ms) }), h("span", { text: n.title })]);
      var li = h("li", null, [b]);
      li.style.setProperty("--c", SEV_COLOR[n.severity] || "#7a6e5a");
      if (prev !== null && n.ms - prev >= 600000) li.insertBefore(h("span", { class: "gap", text: gapText(n.ms - prev) + " later" }), b);
      prev = n.ms;
      ol.appendChild(li);
    });
  }

  // ------------------------------------------------------------------ timeline
  function sources() { var seen = {}; data.timeline.forEach(function (e) { seen[e.source] = 1; }); return Object.keys(seen).sort(); }
  function buildTimelineControls() {
    var lg = $("tl-legend"); clear(lg);
    sources().forEach(function (s) {
      var b = h("button", { type: "button", "aria-pressed": state.tl.off[s] ? "false" : "true", text: s, onclick: function () {
        state.tl.off[s] = !state.tl.off[s]; b.setAttribute("aria-pressed", state.tl.off[s] ? "false" : "true"); state.tl.range = null; renderTimeline(); } });
      b.style.setProperty("--c", SRC_COLOR[s] || "#7a6e5a");
      lg.appendChild(b);
    });
    var seg = $("tl-mode").querySelectorAll("button");
    for (var i = 0; i < seg.length; i++) (function (btn) {
      btn.setAttribute("aria-pressed", btn.getAttribute("data-mode") === state.tl.mode ? "true" : "false");
      btn.onclick = function () { state.tl.mode = btn.getAttribute("data-mode"); state.tl.range = null;
        for (var j = 0; j < seg.length; j++) seg[j].setAttribute("aria-pressed", seg[j] === btn ? "true" : "false"); renderTimeline(); };
    })(seg[i]);
    $("tl-search").value = "";
  }
  function tlFiltered() {                     // sources + text, no range
    var q = lc(state.tl.q);
    return data.timeline.filter(function (e) {
      if (state.tl.off[e.source]) return false;
      return !q || lc(e.path).indexOf(q) >= 0 || lc(e.description).indexOf(q) >= 0;
    });
  }
  function tlBounds() {
    if (state.tl.mode === "window") return [data.window.start_ms, data.window.end_ms];
    var lo = Infinity, hi = -Infinity;
    data.timeline.forEach(function (e) { if (!e.anomalous) { lo = Math.min(lo, e.ms); hi = Math.max(hi, e.ms); } });
    data.findings.forEach(function (f) { if (f.first_seen_ms) { lo = Math.min(lo, f.first_seen_ms); hi = Math.max(hi, f.first_seen_ms); } });
    if (lo === Infinity) return [data.window.start_ms, data.window.end_ms];
    return [lo, hi + 1];
  }
  function buildBins() {
    var b = tlBounds(), lo = b[0], hi = b[1], n = state.tl.mode === "window" ? Math.max(1, Math.round((hi - lo) / 3600000)) : 96;
    if (n > 168) n = 168;
    var w = Math.ceil((hi - lo) / n);
    bins = []; for (var i = 0; i < n; i++) bins.push({ lo: lo + i * w, hi: lo + (i + 1) * w, c: {}, total: 0, findings: [] });
    tlEvents.forEach(function (e) {
      if (e.ms < lo || e.ms >= hi) return;
      var bin = bins[Math.min(n - 1, Math.floor((e.ms - lo) / w))];
      bin.c[e.source] = (bin.c[e.source] || 0) + 1; bin.total++;
    });
    data.findings.forEach(function (f) {
      if (!f.first_seen_ms || f.first_seen_ms < lo || f.first_seen_ms >= hi) return;
      bins[Math.min(n - 1, Math.floor((f.first_seen_ms - lo) / w))].findings.push(f);
    });
  }
  function renderTimeline() {
    tlEvents = tlFiltered(); tlShown = PAGE; buildBins(); drawChart(); renderTlTable();
    var anom = data.timeline.filter(function (e) { return e.anomalous; }).length;
    $("tl-note").textContent = anom ? anom + " event" + (anom > 1 ? "s" : "") + " with an impossible timestamp (e.g. 1970) " + (anom > 1 ? "are" : "is") + " listed but not charted." : "";
    var ap = $("tl-active"); clear(ap);
    if (state.tl.range) ap.appendChild(pill(utc(state.tl.range[0]).slice(0, 16) + " → " + utc(state.tl.range[1]).slice(0, 16), function () { state.tl.range = null; renderTimeline(); }));
    if (state.tl.q) ap.appendChild(pill("text: " + state.tl.q, function () { state.tl.q = ""; $("tl-search").value = ""; renderTimeline(); }));
  }
  function tlRows() {
    var b = tlBounds(), r = state.tl.range;
    var rows = tlEvents.filter(function (e) {
      if (r) return e.ms >= r[0] && e.ms < r[1];
      return state.tl.mode === "all" || e.anomalous ? true : (e.ms >= b[0] && e.ms < b[1]);
    });
    return rows.slice().sort(function (a, b2) { return a.ms - b2.ms; });
  }
  function renderTlTable() {
    var rows = tlRows(), body = $("tl-table").tBodies[0]; clear(body);
    rows.slice(0, tlShown).forEach(function (e) {
      body.appendChild(h("tr", { class: "static-row" + (e.anomalous ? " anom" : "") }, [
        td(h("span", { class: "mono", text: e.time + (e.anomalous ? "  ⚠ impossible" : "") })), td(srcTag(e.source)), td(h("span", { class: "macb", text: e.macb || "" })),
        td(h("span", { class: "wrap-any", text: e.description }))]));
    });
    $("tl-count").textContent = num(rows.length) + " event" + (rows.length === 1 ? "" : "s");
    $("tl-more").hidden = rows.length <= tlShown;
    $("tl-more").textContent = "Show " + Math.min(PAGE, rows.length - tlShown) + " more (" + num(rows.length - tlShown) + " hidden)";
  }

  function chartGeom(cv) {
    var rect = cv.getBoundingClientRect();
    return { w: rect.width, h: rect.height, l: 38, r: 8, t: 20, b: 24 };
  }
  function drawChart() {
    var cv = $("timeline"), g = chartGeom(cv), dpr = window.devicePixelRatio || 1;
    if (g.w < 20 || !bins.length) return;                 // page hidden or nothing to draw yet
    cv.width = Math.max(1, Math.round(g.w * dpr)); cv.height = Math.max(1, Math.round(g.h * dpr));
    var ctx = cv.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, g.w, g.h);
    var pw = g.w - g.l - g.r, ph = g.h - g.t - g.b, n = bins.length;
    var max = 1; bins.forEach(function (b) { max = Math.max(max, b.total); });
    max = Math.ceil(max / 4) * 4 || 4;
    ctx.font = "11px \"Courier Prime\", \"Courier New\", monospace"; ctx.textBaseline = "middle"; ctx.fillStyle = INK2; ctx.strokeStyle = GRID; ctx.lineWidth = 1;
    for (var t = 0; t <= 4; t++) {
      var y = g.t + ph - (ph * t) / 4;
      ctx.beginPath(); ctx.moveTo(g.l, y + .5); ctx.lineTo(g.l + pw, y + .5); ctx.stroke();
      ctx.textAlign = "right"; ctx.fillText(String(Math.round((max * t) / 4)), g.l - 6, y);
    }
    var bw = pw / n, gap = bw > 4 ? 1 : 0, srcs = sources().filter(function (s) { return !state.tl.off[s]; });
    bins.forEach(function (b, i) {
      var x = g.l + i * bw, base = g.t + ph, sel = state.tl.range && state.tl.range[0] === b.lo;
      srcs.forEach(function (s) {
        var c = b.c[s]; if (!c) return;
        var hh = (c / max) * ph; base -= hh;
        ctx.fillStyle = SRC_COLOR[s] || "#7a6e5a"; ctx.globalAlpha = (state.tl.range && !sel) ? .35 : 1;
        ctx.fillRect(x + gap / 2, base, Math.max(1, bw - gap), hh);
      });
      ctx.globalAlpha = 1;
      if (i === hoverBin || sel) { ctx.strokeStyle = INK; ctx.lineWidth = 1.5; ctx.strokeRect(x + .5, g.t, Math.max(1, bw - 1), ph); ctx.lineWidth = 1; ctx.strokeStyle = GRID; }
      b.findings.forEach(function (f, k) {            // finding markers along the top
        ctx.fillStyle = SEV_COLOR[f.severity]; var cx = x + bw / 2, cy = 6 + (k % 2) * 7;
        ctx.beginPath(); ctx.moveTo(cx - 4, cy - 3); ctx.lineTo(cx + 4, cy - 3); ctx.lineTo(cx, cy + 4); ctx.closePath(); ctx.fill();
      });
    });
    ctx.fillStyle = INK2; ctx.textBaseline = "top"; ctx.strokeStyle = INK2;
    var lo = bins[0].lo, hi = bins[n - 1].hi, span = hi - lo, H = 3600000, D = 86400000, steps = [6 * H, 12 * H, D, 2 * D, 7 * D, 30 * D], step = 30 * D, k2;
    for (k2 = 0; k2 < steps.length; k2++) if (pw * steps[k2] / span >= 84) { step = steps[k2]; break; }
    var tickMs = [], t0;
    if (step >= 30 * D) { var d0 = new Date(lo); t0 = Date.UTC(d0.getUTCFullYear(), d0.getUTCMonth() + (d0.getUTCDate() > 1 || lo % D ? 1 : 0), 1); var mm = new Date(t0); while (t0 < hi) { tickMs.push(t0); mm = new Date(t0); t0 = Date.UTC(mm.getUTCFullYear(), mm.getUTCMonth() + 1, 1); } }
    else for (t0 = Math.ceil(lo / step) * step; t0 < hi; t0 += step) tickMs.push(t0);
    var lastX = -100;
    tickMs.forEach(function (tm) {
      var x = g.l + ((tm - lo) / span) * pw; if (x - lastX < 84 || x < g.l + 36 || x > g.l + pw - 36) return; lastX = x;
      ctx.beginPath(); ctx.moveTo(x + .5, g.t + ph); ctx.lineTo(x + .5, g.t + ph + 4); ctx.stroke();
      var dd = new Date(tm), lab = step >= 30 * D ? MONTHS[dd.getUTCMonth()] + " " + dd.getUTCFullYear() : axisLabel(tm, step < D);
      ctx.textAlign = "center"; ctx.fillText(lab, Math.min(Math.max(x, g.l + 24), g.l + pw - 24), g.t + ph + 7);
    });
  }
  function binAt(ev) {
    var cv = $("timeline"), rect = cv.getBoundingClientRect(), g = chartGeom(cv);
    var x = ev.clientX - rect.left - g.l, pw = g.w - g.l - g.r;
    if (x < 0 || x > pw) return -1;
    return Math.min(bins.length - 1, Math.floor((x / pw) * bins.length));
  }
  function setupChart() {
    var cv = $("timeline"), tip = $("tooltip");
    cv.addEventListener("mousemove", function (ev) {
      var i = binAt(ev);
      if (i !== hoverBin) { hoverBin = i; drawChart(); }
      if (i < 0 || !bins[i]) { tip.hidden = true; return; }
      var b = bins[i]; clear(tip);
      tip.appendChild(h("strong", { text: utc(b.lo).slice(0, 16) + " → " + utc(b.hi).slice(0, 16) + " UTC" }));
      tip.appendChild(h("div", { text: b.total + " event" + (b.total === 1 ? "" : "s") }));
      Object.keys(b.c).sort().forEach(function (s) { tip.appendChild(h("div", null, [srcTag(s), " " + b.c[s]])); });
      b.findings.forEach(function (f) { tip.appendChild(h("div", { text: "▼ " + f.id + " " + short(f.title, 48) })); });
      tip.hidden = false;
      var wrap = cv.parentNode.getBoundingClientRect(), x = ev.clientX - wrap.left + 14, y = ev.clientY - wrap.top + 14;
      var ty = ev.clientY - wrap.top > wrap.height * 0.45 ? y - 28 - tip.offsetHeight : y;
      tip.style.left = Math.max(0, Math.min(x, wrap.width - 290)) + "px"; tip.style.top = Math.max(0, ty) + "px";
    });
    cv.addEventListener("mouseleave", function () { hoverBin = -1; tip.hidden = true; drawChart(); });
    cv.addEventListener("click", function (ev) {
      var i = binAt(ev); if (i < 0) return;
      var b = bins[i];
      state.tl.range = (state.tl.range && state.tl.range[0] === b.lo) ? null : [b.lo, b.hi];
      renderTimeline();
    });
    window.addEventListener("resize", function () { if (data && tab === "timeline") drawChart(); });
  }

  // ------------------------------------------------------------------ pills / filters
  function pill(text, onx) { return h("span", { class: "pill" }, [text, h("button", { type: "button", "aria-label": "Remove filter " + text, text: "×", onclick: onx })]); }
  function toggleSev(sev) { state.f.sev[sev] = !state.f.sev[sev]; syncKpis(); syncSevChips(); renderFindings(); }
  function anySev() { return SEV.some(function (s) { return state.f.sev[s]; }); }
  function syncSevChips() { SEV.forEach(function (s) { var c = $("chip-" + s); if (c) c.setAttribute("aria-pressed", state.f.sev[s] ? "true" : "false"); }); }

  function buildFindingFilters() {
    var box = $("f-sev"); clear(box);
    SEV.forEach(function (s) { var c = h("button", { type: "button", id: "chip-" + s, class: "chip", "aria-pressed": "false", text: s, onclick: function () { toggleSev(s); } }); c.style.setProperty("--c", SEV_COLOR[s]); box.appendChild(c); });
    var sel = $("f-cat"); clear(sel); sel.appendChild(h("option", { value: "", text: "Every kind" }));
    var cats = {}; data.findings.forEach(function (f) { cats[f.category] = 1; });
    Object.keys(cats).sort().forEach(function (c) { sel.appendChild(h("option", { value: c, text: c })); });
    $("f-search").value = "";
  }
  function findingMatches(f) {
    var s = state.f;
    if (anySev() && !s.sev[f.severity]) return false;
    if (s.cat && f.category !== s.cat) return false;
    if (s.technique && !f.mitre.some(function (m) { return m.id === s.technique; })) return false;
    if (s.file && f.files.indexOf(s.file) < 0) return false;
    if (s.q) {
      var hay = lc([f.id, f.rule, f.title, f.summary, f.category, f.files.join(" "), f.mitre.map(function (m) { return m.id + " " + m.name; }).join(" ")].join(" "));
      if (hay.indexOf(lc(s.q)) < 0) return false;
    }
    return true;
  }
  function ecard(f) {
    var files = f.files.length ? f.files.length + (f.files.length === 1 ? " file" : " files") : "no single file";
    var c = h("button", { type: "button", class: "ecard sev-" + f.severity, "data-id": f.id, onclick: function () { openFinding(f); } }, [
      h("span", { class: "top" }, [sevBadge(f.severity), h("span", { class: "fid", text: f.id })]),
      h("h3", { text: f.title }), h("p", { text: short(f.summary, 150) }),
      h("span", { class: "cfoot" }, [h("span", { text: f.category }), h("span", { text: files }), h("span", { text: "first seen " + f.first_seen })])]);
    return c;
  }
  function renderFindings() {
    var s = state.f;
    var rows = data.findings.filter(findingMatches);
    rows.sort(function (a, b) {
      var r = s.sort === "time" ? (a.first_seen_ms - b.first_seen_ms) : (SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.first_seen_ms - b.first_seen_ms);
      return r * s.dir || (a.id < b.id ? -1 : 1);
    });
    var board = $("f-board"); clear(board);
    rows.forEach(function (f) { board.appendChild(ecard(f)); });
    var body = $("f-table").tBodies[0]; clear(body);
    rows.forEach(function (f) {
      body.appendChild(h("tr", { "data-id": f.id, tabindex: "0", onclick: function () { openFinding(f); }, onkeydown: function (e) { if (e.key === "Enter") { e.preventDefault(); openFinding(f); } } }, [
        td(sevBadge(f.severity)), td(h("span", { class: "mono", text: f.id })),
        td(h("span", null, [h("button", { type: "button", class: "linklike", text: f.title, tabindex: "-1" }), h("span", { class: "sub", text: short(f.summary, 140) })])),
        td(f.category, "hide-sm"), td(h("span", { class: "mono", text: f.first_seen }))]));
    });
    $("f-empty").hidden = rows.length > 0;
    $("f-count").textContent = rows.length + " of " + data.findings.length + " findings";
    $("f-order").value = s.sort === "time" ? "time" : "severity";
    var ap = $("f-active"); clear(ap);
    if (s.q) ap.appendChild(pill("text: " + s.q, function () { s.q = ""; $("f-search").value = ""; renderFindings(); }));
    if (s.cat) ap.appendChild(pill("category: " + s.cat, function () { s.cat = ""; $("f-cat").value = ""; renderFindings(); }));
    if (s.technique) ap.appendChild(pill("technique: " + s.technique, function () { s.technique = ""; renderFindings(); }));
    if (s.file) ap.appendChild(pill("file: " + nameOf(s.file), function () { s.file = ""; renderFindings(); }));
    var heads = $("f-table").querySelectorAll("button.sort");
    for (var i = 0; i < heads.length; i++) { var on = heads[i].getAttribute("data-sort") === s.sort; heads[i].classList.toggle("on", on); heads[i].setAttribute("data-dir", s.dir < 0 ? "↓" : "↑"); }
  }

  // ------------------------------------------------------------------ files
  function buildFileFilters() {
    var sel = $("fl-flag"); clear(sel); sel.appendChild(h("option", { value: "", text: "Any red flag" }));
    var fl = {}; data.files.forEach(function (f) { f.flags.forEach(function (x) { fl[x] = 1; }); });
    Object.keys(fl).sort().forEach(function (c) { sel.appendChild(h("option", { value: c, text: c })); });
    $("fl-search").value = ""; $("fl-only").checked = false; sel.value = "";
  }
  function fileWeight(f) {
    var w = 0; f.flags.forEach(function (x) { var s = FLAG_SEV[x]; w = Math.max(w, s && s !== "ok" ? SEV_RANK[s] : (x === "known_good" ? 0 : 0.5)); });
    return w * 100 + f.flags.length;
  }
  function renderFiles() {
    var s = state.fl, q = lc(s.q);
    var rows = data.files.filter(function (f) {
      if (s.only && !f.flags.some(function (x) { return FLAGGED.indexOf(x) >= 0; })) return false;
      if (s.flag && f.flags.indexOf(s.flag) < 0) return false;
      if (q && lc([f.path, f.detected, f.detected_type, f.ext, f.md5, f.sha1, f.sha256, f.flags.join(" ")].join(" ")).indexOf(q) < 0) return false;
      return true;
    });
    rows.sort(function (a, b) {
      var r = 0;
      if (s.sort === "path") r = a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
      else if (s.sort === "size") r = a.size - b.size;
      else if (s.sort === "type") r = lc(a.detected_type) < lc(b.detected_type) ? -1 : 1;
      else r = fileWeight(a) - fileWeight(b);
      return r * s.dir || (a.path < b.path ? -1 : 1);
    });
    var body = $("fl-table").tBodies[0]; clear(body);
    rows.forEach(function (f) {
      var flags = h("span", null, f.flags.map(flagTag));
      body.appendChild(h("tr", { tabindex: "0", onclick: function () { openFile(f); }, onkeydown: function (e) { if (e.key === "Enter") { e.preventDefault(); openFile(f); } } }, [
        td(pathCell(f.path)), td(num(f.size), "num"),
        td(h("span", null, [f.detected_type + (f.mismatch ? "" : ""), h("span", { class: "sub", text: "ext ." + (f.ext || "(none)") })]), "hide-sm"), td(flags),
        td(h("span", { class: "hash", text: f.sha256.slice(0, 16) + "…" }), "hide-sm")]));
    });
    $("fl-empty").hidden = rows.length > 0;
    $("fl-count").textContent = rows.length + " of " + data.files.length + " files";
    var ap = $("fl-active"); clear(ap);
    if (s.q) ap.appendChild(pill("text: " + s.q, function () { s.q = ""; $("fl-search").value = ""; renderFiles(); }));
    if (s.flag) ap.appendChild(pill("flag: " + s.flag, function () { s.flag = ""; $("fl-flag").value = ""; renderFiles(); }));
    var heads = $("fl-table").querySelectorAll("button.sort");
    for (var i = 0; i < heads.length; i++) { heads[i].classList.toggle("on", heads[i].getAttribute("data-sort") === s.sort); heads[i].setAttribute("data-dir", s.dir < 0 ? "↓" : "↑"); }
  }

  // ------------------------------------------------------------------ IOCs
  function buildIocFilters() {
    var types = {}, scopes = {};
    data.iocs.forEach(function (i) { types[i.type] = (types[i.type] || 0) + 1; scopes[i.scope] = 1; });
    var box = $("ioc-types"); clear(box);
    Object.keys(types).sort().forEach(function (t) {
      box.appendChild(h("button", { type: "button", class: "chip", "aria-pressed": "false", "data-type": t, text: t + " " + types[t], onclick: function () {
        state.ioc.type = state.ioc.type === t ? "" : t; renderIocs(); } }));
    });
    var sel = $("ioc-scope"); clear(sel); sel.appendChild(h("option", { value: "", text: "Inside or outside" }));
    Object.keys(scopes).sort().forEach(function (c) { sel.appendChild(h("option", { value: c, text: c })); });
    $("ioc-search").value = "";
  }
  function renderIocs() {
    var s = state.ioc, q = lc(s.q);
    var rows = data.iocs.filter(function (i) {
      return (!s.type || i.type === s.type) && (!s.scope || i.scope === s.scope) && (!q || lc(i.value + " " + i.sources.join(" ")).indexOf(q) >= 0);
    });
    var body = $("ioc-table").tBodies[0]; clear(body);
    rows.forEach(function (i) {
      var more = i.sources.length > 1 ? " (+" + (i.sources.length - 1) + " more)" : "";
      var src = h("span", { class: "wrap-any", title: i.sources.join("\n"), text: short(i.sources[0] || "", 60) + more });
      body.appendChild(h("tr", { class: "static-row" }, [td(h("span", { class: "flag", text: i.type })), td(h("span", { class: "ioc-val", text: i.value })), td(i.scope), td(String(i.count), "num"), td(src, "hide-sm")]));
    });
    $("ioc-empty").hidden = rows.length > 0;
    $("ioc-count").textContent = rows.length + " of " + data.iocs.length;
    var chips = $("ioc-types").querySelectorAll("button");
    for (var k = 0; k < chips.length; k++) chips[k].setAttribute("aria-pressed", chips[k].getAttribute("data-type") === s.type ? "true" : "false");
  }

  // ------------------------------------------------------------------ carved files
  function buildCarved() {
    var cf = data.carved.files, maps = $("carve-maps"); clear(maps);
    $("carve-count").textContent = cf.length + " recovered";
    data.carved.stats.forEach(function (st) {
      maps.appendChild(h("div", { class: "mono muted", text: st.image + " (" + num(st.bytes_scanned) + " bytes)" }));
      var map = h("div", { class: "imgmap", role: "group", "aria-label": "Where recovered files sit inside " + st.image });
      cf.filter(function (c) { return c.image === st.image; }).forEach(function (c) {
        var b = h("button", { type: "button", class: c.status === "complete" ? "" : "partial", title: c.id + " " + c.kind + " @ " + c.offset + " (" + c.length + " bytes, " + c.status + ")", "aria-label": "Open recovered file " + c.id, onclick: function () { openCarved(c); } });
        b.style.left = (c.offset / st.bytes_scanned * 100) + "%"; b.style.width = Math.max(0.2, c.length / st.bytes_scanned * 100) + "%";
        map.appendChild(b);
      });
      maps.appendChild(map);
      maps.appendChild(h("div", { class: "imgaxis" }, [h("span", { text: "0x0" }), h("span", { text: "0x" + st.bytes_scanned.toString(16) })]));
    });
    var box = $("carve-stats"); clear(box);
    data.carved.stats.forEach(function (st) {
      [[st.headers_found, "file headers spotted"], [st.complete, "whole files"], [st.partial, "partial files"], [st.rejected, "false alarms thrown out"], [st.nested_skipped, "headers inside other files, skipped"]]
        .forEach(function (p) { box.appendChild(h("div", { class: "stat" }, [h("b", { text: String(p[0]) }), h("span", { text: p[1] })])); });
    });
    var body = $("carve-table").tBodies[0]; clear(body);
    cf.forEach(function (c) {
      var m = [];
      if (c.matches_file) m.push("on disk as " + nameOf(c.matches_file));
      if (c.matches_recycle) m.push("recycle: " + c.matches_recycle.split("\\").pop());
      if (c.matches_mft) m.push("MFT: " + nameOf(c.matches_mft));
      if (c.hash_status) m.push(c.hash_status + " hash");
      var content = c.details && c.details.members ? c.details.members.length + " members: " + c.details.members.join(", ") :
        (c.details && c.details.width ? c.details.width + "×" + c.details.height + " px" : (c.details && c.details.pages ? c.details.pages + " page(s)" : ""));
      body.appendChild(h("tr", { tabindex: "0", onclick: function () { openCarved(c); }, onkeydown: function (e) { if (e.key === "Enter") { e.preventDefault(); openCarved(c); } } }, [
        td(h("span", { class: "mono", text: c.id })), td(h("span", { class: "flag", text: c.kind })), td(h("span", { class: "mono", text: "0x" + c.offset.toString(16) + " (" + num(c.offset) + ")" })),
        td(num(c.length), "num"), td(h("span", { class: "sev-badge " + (c.status === "complete" ? "sev-ok" : "sev-medium"), text: c.status })),
        td(h("span", { class: "wrap-any", text: short(content, 90) })), td(h("span", { class: "wrap-any", text: m.join("; ") || "no match" }), "hide-sm")]));
    });
  }

  // ------------------------------------------------------------------ integrity & custody
  function buildIntegrity() {
    var ig = data.integrity, st = $("integrity-status"); clear(st);
    var ok = ig.ok && ig.custody_chain_ok;
    st.className = "integrity-status" + (ok ? "" : " bad");
    st.appendChild(h("span", { class: "tick", "aria-hidden": "true", text: ok ? "✓" : "!" }));
    st.appendChild(h("div", null, [h("div", { class: "big", text: ok ? "Evidence unchanged. The hashes from before and after my analysis match." : (ig.ok ? "Problem with the custody log: " + ig.custody_chain_note : "EVIDENCE CHANGED while I was analysing it") }),
      h("div", { class: "muted", text: ig.differences.length ? ig.differences.length + " difference(s): " + ig.differences.map(function (d) { return (d.change || "change") + " " + (d.label || "") + (d.detail ? " (" + d.detail + ")" : ""); }).join("; ") :
        "Not one file differs in content, size, modified time or mode. Custody log: " + ig.custody_chain_note + "." })]));
    var mc = $("manifests"); clear(mc);
    [["Before I started", ig.before], ["After I finished", ig.after]].forEach(function (p) {
      mc.appendChild(h("div", { class: "mcard" }, [h("h4", { text: p[0] }), h("div", { text: num(p[1].files || 0) + " files, " + num(p[1].bytes || 0) + " bytes" }),
        h("div", { class: "hash wrap-any", text: "manifest SHA-256 " + (p[1].manifest_sha256 || "n/a") })]));
    });
    $("integrity-method").textContent = ig.method || "";
    $("chain-result").textContent = ""; $("chain-result").className = "chain-result";
    renderCustody(-1);
  }
  function renderCustody(brokenIdx) {
    var body = $("custody-table").tBodies[0]; clear(body);
    chainEntries.forEach(function (e, i) {
      body.appendChild(h("tr", { class: "static-row" + (i === brokenIdx ? " broken" : (e.seq === tamperedSeq ? " tampered" : "")) }, [
        td(String(e.seq), "num"), td(h("span", { class: "mono nowrap", text: e.time })), td(h("span", { class: "flag", text: e.action })), td(h("span", { class: "wrap-any", text: e.detail })),
        td(h("span", { class: "hash", title: "prev " + e.prev_hash, text: String(e.entry_hash).slice(0, 14) + "…" }), "hide-sm")]));
    });
  }
  // canonical JSON identical to Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
  function canon(v) {
    if (v === null || typeof v === "number" || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "string") return JSON.stringify(v).replace(/[\u007f-\uffff]/g, function (c) { return c === "\u007f" ? c : "\\u" + ("0000" + c.charCodeAt(0).toString(16)).slice(-4); });
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    return "{" + Object.keys(v).sort().map(function (k) { return canon(k) + ":" + canon(v[k]); }).join(",") + "}";
  }
  function sha256hex(text) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    });
  }
  function verifyChain() {
    var out = $("chain-result");
    function say(ok, msg) { out.textContent = msg; out.className = "chain-result " + (ok ? "ok" : "bad"); }
    if (!window.crypto || !crypto.subtle) { say(false, "Your browser only offers WebCrypto on HTTPS or localhost, so I cannot recalculate the chain here."); return; }
    var prev = new Array(65).join("0"), i = 0;
    function step() {
      if (i >= chainEntries.length) { renderCustody(-1); say(true, "Chain intact: all " + chainEntries.length + " entries recalculated in your browser and every prev_hash and entry_hash matches."); return; }
      var e = chainEntries[i], body = {}; Object.keys(e).forEach(function (k) { if (k !== "entry_hash") body[k] = e[k]; });
      sha256hex(canon(body)).then(function (hex) {
        var why = e.seq !== i + 1 ? "sequence number is " + e.seq : e.prev_hash !== prev ? "prev_hash does not match the previous entry" : hex !== e.entry_hash ? "contents do not match entry_hash (entry was edited)" : "";
        if (why) { renderCustody(i); say(false, "Chain BROKEN at entry " + (i + 1) + ": " + why + "."); return; }
        prev = e.entry_hash; i++; step();
      });
    }
    step();
  }
  function tamper() {
    if (tamperedSeq || chainEntries.length < 3) return;
    var e = chainEntries[2]; e.detail = e.detail + " [edited]"; tamperedSeq = e.seq; renderCustody(-1);
    var out = $("chain-result"); out.textContent = "Entry " + e.seq + " was edited in memory only. The report file is untouched. Now press “Check the chain here”."; out.className = "chain-result";
  }
  function resetChain() { chainEntries = JSON.parse(JSON.stringify(data.integrity.custody)); tamperedSeq = 0; renderCustody(-1); $("chain-result").textContent = ""; $("chain-result").className = "chain-result"; }

  // ------------------------------------------------------------------ artefacts / mitre / rules
  function fill(tableId, rows, empty) {
    var body = $(tableId).tBodies[0]; clear(body);
    if (!rows.length) { body.appendChild(h("tr", { class: "static-row" }, [h("td", { colspan: "9", class: "muted", text: empty })])); return; }
    rows.forEach(function (cells) { body.appendChild(h("tr", { class: "static-row" }, cells.map(function (c) { return c instanceof Node ? h("td", null, [c]) : td(String(c)); }))); });
  }
  function buildArtifacts() {
    var a = data.artifacts, thresholdMs = data.window.start_ms - 30 * 86400000;
    fill("usb-table", a.usb_devices.map(function (u) {
      var recent = parseNaive(u.last_arrival) >= thresholdMs;
      return [h("span", null, [u.friendly_name || (u.vendor + " " + u.product), h("span", { class: "sub", text: (u.drive_letter ? u.drive_letter + " " : "") + (recent ? "connected during the incident period" : "older connection") })]),
              h("span", { class: "mono", text: u.serial }), u.last_arrival, u.last_removal];
    }), "No USB devices recorded.");
    fill("pf-table", a.prefetch.slice().sort(function (x, y) { return x.executable < y.executable ? -1 : 1; }).map(function (p) {
      return [h("span", null, [p.executable, h("span", { class: "sub wrap-any", text: p.path || "" })]), String(p.run_count), (p.last_runs || []).slice(-1)[0] || ""];
    }), "No Prefetch entries.");
    fill("rd-table", a.recent_docs.map(function (r) { return [r.name, h("span", { class: "mono wrap-any", text: r.target }), r.time]; }), "None.");
    var br = data.browser.flagged_visits.map(function (v) { return [v.time, v.category.replace(/_/g, " "), h("span", { class: "ioc-val", text: v.url })]; });
    data.browser.flagged_searches.forEach(function (v) { br.push([v.time, "search: " + v.category.replace(/_/g, " "), h("span", { class: "ioc-val", text: "“" + v.term + "”" })]); });
    data.browser.downloads.forEach(function (v) { br.push([v.time, "download", h("span", { class: "ioc-val", text: v.target_path + " ← " + v.from })]); });
    br.sort(function (x, y) { return x[0] < y[0] ? -1 : 1; });
    fill("br-table", br, "No flagged browser activity.");
    var del = data.deleted.recycle_bin.map(function (r) { return ["Recycle Bin", h("span", { class: "mono wrap-any", text: r.original_path }), num(r.original_size), r.deleted, r.content_present ? "still present" : "content gone"]; });
    data.deleted.mft_entries.forEach(function (r) { del.push(["MFT (deleted)", h("span", { class: "mono wrap-any", text: r.path }), num(r.size), r.when, "not on disk"]); });
    fill("del-table", del, "No deleted-file records.");
  }
  function buildMitre() {
    var body = $("mitre-table").tBodies[0]; clear(body);
    data.mitre.forEach(function (m) {
      var link = /^T\d{4}(\.\d{3})?$/.test(m.id) ? h("a", { href: "https://attack.mitre.org/techniques/" + m.id.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", text: m.id }) : h("span", { text: m.id });
      body.appendChild(h("tr", { "data-tech": m.id, onclick: function (e) { if (e.target.tagName === "A") return; state.f.technique = state.f.technique === m.id ? "" : m.id; renderFindings(); goTab("findings"); } }, [
        td(link), td(m.name), td(m.findings.join(", "))]));
    });
  }
  function buildRules() {
    $("rule-count").textContent = data.rules.length;
    var body = $("rules-table").tBodies[0]; clear(body);
    data.rules.forEach(function (r) {
      body.appendChild(h("tr", { class: "static-row" }, [td(h("span", { class: "mono", text: r.id })), td(r.title), td(sevBadge(r.severity)), td(r.category), td((r.mitre || []).join(", ") || "n/a")]));
    });
  }

  // ------------------------------------------------------------------ drawer
  function section(title, content) { return h("div", { class: "d-sec" }, [h("h3", { text: title }), content]); }
  function kvList(pairs) {
    var kv = h("dl", { class: "kv" });
    pairs.forEach(function (p) { if (p[1] === "" || p[1] === undefined || p[1] === null) return; kv.appendChild(h("dt", { text: p[0] })); kv.appendChild(h("dd", { text: String(p[1]) })); });
    return kv;
  }
  function copyText(text, done) {
    function fallback() {
      var ta = h("textarea", { "aria-hidden": "true" }); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(true); } catch (e) { done(false); }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
    else fallback();
  }
  function showDrawer(badge, badgeClass, id, title, hash) {
    lastFocus = document.activeElement;
    $("d-sev").className = "sev-badge " + badgeClass; $("d-sev").textContent = badge;
    $("d-id").textContent = " " + id; $("drawer-title").textContent = title;
    $("scrim").hidden = false; $("drawer").hidden = false;
    try { history.replaceState(null, "", hash || (location.pathname + location.search)); } catch (e) { /* file:// or sandbox */ }
    $("drawer").scrollTop = 0; $("drawer-body").scrollTop = 0;
    $("d-close").focus();
  }
  function hideDrawer(silent) {
    if ($("drawer").hidden) return;
    $("drawer").hidden = true; $("scrim").hidden = true;
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) { /* ignore */ }
    if (!silent && lastFocus && lastFocus.focus) lastFocus.focus();
  }
  function fileChips(paths) {
    return h("div", { class: "chip-row" }, paths.map(function (p) {
      return h("button", { type: "button", class: "chip-btn", title: p, text: short(nameOf(p), 40), onclick: function () { var f = fileByPath(p); if (f) openFile(f); } });
    }));
  }
  function findingNote(f) {
    var lines = ["[" + f.severity.toUpperCase() + "] " + f.id + ": " + f.title, "Rule: " + f.rule + " | Category: " + f.category, "First seen: " + f.first_seen + " UTC",
      "Files: " + (f.files.join("; ") || "n/a"), "MITRE ATT&CK: " + (f.mitre.map(function (m) { return m.id + " " + m.name; }).join("; ") || "n/a"), "", "What was seen: " + f.summary, "", "Evidence:"];
    f.evidence.slice(0, 4).forEach(function (e) { lines.push("  - " + e); });
    lines.push("", "Recommended response:"); f.response.forEach(function (s, i) { lines.push((i + 1) + ". " + s); });
    lines.push("", "Status: open, not yet reviewed. (Synthetic data example.)");
    return lines.join("\n");
  }
  function openFinding(f) {
    showDrawer(f.severity, "sev-" + f.severity, f.id, f.title, "#finding=" + f.id);
    var body = $("drawer-body"); clear(body);
    body.appendChild(section("In short", h("p", { text: f.summary })));
    body.appendChild(section("Details", kvList([["Rule", f.rule], ["Kind", f.category], ["First seen", f.first_seen + " UTC"], ["Last seen", f.last_seen + " UTC"]])));
    if (f.files.length) body.appendChild(section("Files involved (click one)", fileChips(f.files)));
    if (f.mitre.length) body.appendChild(section("MITRE ATT&CK", h("div", { class: "chip-row" }, f.mitre.map(function (m) {
      return /^T\d{4}(\.\d{3})?$/.test(m.id) ? h("a", { class: "chip-btn", href: "https://attack.mitre.org/techniques/" + m.id.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", text: m.id + " " + m.name }) : h("span", { class: "chip-btn", text: m.id });
    }))));
    body.appendChild(section("Why I flagged it", h("ul", { class: "steps" }, f.evidence.map(function (e) { return h("li", { text: e }); }))));
    body.appendChild(section("What to do about it", h("ol", { class: "steps" }, f.response.map(function (s) { return h("li", { text: s }); }))));
    var msg = h("span", { class: "toast", role: "status" });
    body.appendChild(h("div", { class: "btn-row" }, [
      h("button", { type: "button", class: "btn", text: "Copy as a ticket note", onclick: function () { copyText(findingNote(f), function (ok) { msg.textContent = ok ? "Copied." : "Copy failed: select the text manually."; }); } }),
      h("button", { type: "button", class: "btn ghost", text: "Copy a link to this", onclick: function () { copyText(location.href.split("#")[0] + "#finding=" + f.id, function (ok) { msg.textContent = ok ? "Link copied." : "Copy failed."; }); } }),
      f.first_seen_ms ? h("button", { type: "button", class: "btn ghost", text: "Show it on the timeline", onclick: function () {
        var day = Math.floor(f.first_seen_ms / 3600000) * 3600000; state.tl.mode = f.first_seen_ms >= data.window.start_ms && f.first_seen_ms < data.window.end_ms ? "window" : "all";
        buildTimelineControls(); state.tl.range = [day, day + 3600000]; hideDrawer(true); renderTimeline(); goTab("timeline"); } }) : null, msg]));
  }
  function timesTable(t) {
    var rows = [["Created (B)", "created"], ["Modified (M)", "modified"], ["Accessed (A)", "accessed"], ["MFT changed (C)", "mft_changed"]];
    var tb = h("table", { class: "times" }, [h("thead", null, [h("tr", null, [h("th", { text: "" }), h("th", { text: "$STANDARD_INFORMATION" }), h("th", { text: "$FILE_NAME" })])])]);
    var body = h("tbody");
    rows.forEach(function (r) {
      var si = (t.si || {})[r[1]] || "", fn = (t.fn || {})[r[1]] || "";
      body.appendChild(h("tr", null, [h("th", { text: r[0] }), h("td", { class: fn && si && si !== fn ? "diff" : "", text: si || "n/a" }), h("td", { text: fn || "n/a" })]));
    });
    tb.appendChild(body); return tb;
  }
  function openFile(f) {
    var fl = f.flags.filter(function (x) { return x !== "known_good"; });
    var sevName = f.flags.indexOf("known_bad") >= 0 ? "critical" : f.timestomp.verdict === "likely" ? "high" : f.mismatch ? "medium" : f.timestomp.verdict === "weak" ? "low" : "";
    showDrawer(sevName || (fl.length ? "flagged" : "file"), sevName ? "sev-" + sevName : (f.flags.indexOf("known_good") >= 0 ? "sev-ok" : "sev-info"), "", nameOf(f.path), null);
    var body = $("drawer-body"); clear(body);
    body.appendChild(section("Path", h("p", { class: "mono wrap-any", text: f.path })));
    body.appendChild(section("What it is", kvList([["Size", num(f.size) + " bytes"], ["Detected from content", f.detected + " (" + f.detected_type + ")"],
      ["Extension", f.ext ? "." + f.ext : "(none)"], ["Extension expects", f.expected_types.join(", ") || "n/a"], ["Does the name fit the contents?", f.mismatch ? "MISMATCH: " + (typeof f.mismatch === "string" ? f.mismatch : JSON.stringify(f.mismatch)) : "yes, extension and contents agree"],
      ["On a hash list?", f.hash_status ? f.hash_status + (f.hash_label ? " (" + f.hash_label + ")" : "") : "not on any list"], ["Metadata source", f.metadata_source]])));
    body.appendChild(section("Hashes", kvList([["MD5", f.md5], ["SHA-1", f.sha1], ["SHA-256", f.sha256]])));
    if (f.flags.length) body.appendChild(section("Flags", h("div", null, f.flags.map(flagTag))));
    if (f.times && (f.times.si || f.times.fn)) body.appendChild(section("Timestamps (UTC)", timesTable(f.times)));
    if (f.embedded && (f.embedded.created || f.embedded.modified)) body.appendChild(section("Timestamps inside the document", kvList([["Created", f.embedded.created], ["Last saved", f.embedded.modified]])));
    if (f.timestomp.indicators.length) {
      body.appendChild(section("Were the dates faked? " + f.timestomp.verdict + " (score " + f.timestomp.score + ")", h("ul", { class: "steps" }, f.timestomp.indicators.map(function (i) { return h("li", { text: i.id + " (weight " + i.weight + "): " + i.detail }); }))));
    }
    if (f.suppressed && f.suppressed.length) body.appendChild(section("Suppressed because the hash is known-good", h("p", { class: "muted", text: f.suppressed.join(", ") })));
    var rel = data.findings.filter(function (x) { return x.files.indexOf(f.path) >= 0; });
    if (rel.length) body.appendChild(section("Findings about this file", h("div", { class: "chip-row" }, rel.map(function (x) {
      return h("button", { type: "button", class: "chip-btn", text: x.id + " " + short(x.title, 46), onclick: function () { openFinding(x); } }); }))));
    var cv = data.carved.files.filter(function (c) { return c.matches_file === f.path; });
    if (cv.length) body.appendChild(section("An identical copy was recovered from deleted space", h("div", { class: "chip-row" }, cv.map(function (c) {
      return h("button", { type: "button", class: "chip-btn", text: c.id + " @ 0x" + c.offset.toString(16), onclick: function () { openCarved(c); } }); }))));
    body.appendChild(h("div", { class: "btn-row" }, [
      h("button", { type: "button", class: "btn ghost", text: "Show it on the timeline", onclick: function () { state.tl.mode = "all"; state.tl.q = f.path; $("tl-search").value = f.path; buildTimelineControls(); $("tl-search").value = f.path; hideDrawer(true); renderTimeline(); goTab("timeline"); } }),
      h("button", { type: "button", class: "btn ghost", text: "Only findings about this file", onclick: function () { state.f.file = f.path; hideDrawer(true); renderFindings(); goTab("findings"); } })]));
  }
  function openCarved(c) {
    showDrawer(c.status, c.status === "complete" ? "sev-ok" : "sev-medium", c.id, c.name, null);
    var body = $("drawer-body"); clear(body);
    body.appendChild(section("Where I found it", kvList([["Image", c.image], ["Offset", "0x" + c.offset.toString(16) + " (" + num(c.offset) + ")"], ["Length", num(c.length) + " bytes"], ["Type", c.kind], ["Holds together to the end", c.validated ? "yes" : "no"]])));
    var det = c.details || {}, pairs = Object.keys(det).filter(function (k) { return k !== "members"; }).map(function (k) { return [k.replace(/_/g, " "), Array.isArray(det[k]) ? det[k].join(", ") : String(det[k])]; });
    if (det.members) pairs.unshift(["members", det.members.join(", ")]);
    if (pairs.length) body.appendChild(section("What is inside", kvList(pairs)));
    body.appendChild(section("Hashes", kvList([["MD5", c.md5], ["SHA-1", c.sha1], ["SHA-256", c.sha256], ["Hash lists", c.hash_status]])));
    var rel = [];
    if (c.matches_file) rel.push(["Same as a file still on disk", c.matches_file]);
    if (c.matches_recycle) rel.push(["Matches Recycle Bin record", c.matches_recycle]);
    if (c.matches_mft) rel.push(["Matches deleted MFT entry", c.matches_mft]);
    body.appendChild(section("Does it match anything?", rel.length ? kvList(rel) : h("p", { class: "muted", text: "No matching file, Recycle Bin or MFT record." })));
    if (c.matches_file && fileByPath(c.matches_file)) body.appendChild(h("div", { class: "btn-row" }, [h("button", { type: "button", class: "btn ghost", text: "Open the file that is still on disk", onclick: function () { openFile(fileByPath(c.matches_file)); } })]));
  }

  // ------------------------------------------------------------------ wiring
  function wire() {
    $("f-search").addEventListener("input", function (e) { state.f.q = e.target.value.trim(); renderFindings(); });
    $("f-cat").addEventListener("change", function (e) { state.f.cat = e.target.value; renderFindings(); });
    $("f-reset").addEventListener("click", function () { state.f = freshState().f; $("f-search").value = ""; $("f-cat").value = ""; syncKpis(); syncSevChips(); renderFindings(); });
    $("f-filters").addEventListener("submit", function (e) { e.preventDefault(); });
    var fh = $("f-table").querySelectorAll("button.sort");
    for (var i = 0; i < fh.length; i++) fh[i].addEventListener("click", function (e) { var k = e.currentTarget.getAttribute("data-sort"); state.f.dir = state.f.sort === k ? -state.f.dir : -1; state.f.sort = k; renderFindings(); });
    $("fl-search").addEventListener("input", function (e) { state.fl.q = e.target.value.trim(); renderFiles(); });
    $("fl-flag").addEventListener("change", function (e) { state.fl.flag = e.target.value; renderFiles(); });
    $("fl-only").addEventListener("change", function (e) { state.fl.only = e.target.checked; renderFiles(); });
    $("fl-reset").addEventListener("click", function () { state.fl = freshState().fl; $("fl-search").value = ""; $("fl-flag").value = ""; $("fl-only").checked = false; renderFiles(); });
    $("fl-filters").addEventListener("submit", function (e) { e.preventDefault(); });
    var lh = $("fl-table").querySelectorAll("button.sort");
    for (var j = 0; j < lh.length; j++) lh[j].addEventListener("click", function (e) { var k = e.currentTarget.getAttribute("data-sort"); state.fl.dir = state.fl.sort === k ? -state.fl.dir : (k === "path" || k === "type" ? 1 : -1); state.fl.sort = k; renderFiles(); });
    $("tl-search").addEventListener("input", function (e) { state.tl.q = e.target.value.trim(); state.tl.range = null; renderTimeline(); });
    $("tl-reset").addEventListener("click", function () { var m = state.tl.mode; state.tl = freshState().tl; state.tl.mode = m; buildTimelineControls(); renderTimeline(); });
    $("tl-filters").addEventListener("submit", function (e) { e.preventDefault(); });
    $("tl-more").addEventListener("click", function () { tlShown += PAGE; renderTlTable(); });
    $("ioc-search").addEventListener("input", function (e) { state.ioc.q = e.target.value.trim(); renderIocs(); });
    $("ioc-scope").addEventListener("change", function (e) { state.ioc.scope = e.target.value; renderIocs(); });
    $("ioc-filters").addEventListener("submit", function (e) { e.preventDefault(); });
    $("chain-verify").addEventListener("click", verifyChain);
    $("chain-tamper").addEventListener("click", tamper);
    $("chain-reset").addEventListener("click", resetChain);
    $("d-close").addEventListener("click", function () { hideDrawer(); });
    $("scrim").addEventListener("click", function () { hideDrawer(); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !$("drawer").hidden) hideDrawer();
      if (e.key === "Tab" && !$("drawer").hidden) {
        var f = $("drawer").querySelectorAll("button, a[href]");
        if (!f.length) return;
        var first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });
    $("file-input").addEventListener("change", function (e) {
      var file = e.target.files[0]; if (!file) return;
      var rd = new FileReader();
      rd.onload = function () { try { init(JSON.parse(rd.result)); } catch (err) { showError("Could not read that file: " + err.message); } };
      rd.readAsText(file); e.target.value = "";
    });
    $("f-order").addEventListener("change", function (e) { state.f.sort = e.target.value; state.f.dir = e.target.value === "time" ? 1 : -1; renderFindings(); });
    var views = $("f-view").querySelectorAll("button");
    for (var v = 0; v < views.length; v++) views[v].addEventListener("click", function (e) {
      var mode = e.currentTarget.getAttribute("data-view");
      for (var w = 0; w < views.length; w++) views[w].setAttribute("aria-pressed", views[w] === e.currentTarget ? "true" : "false");
      $("f-board").hidden = mode !== "board"; $("f-list").hidden = mode !== "list";
    });
    wireTabs();
    setupChart();
  }

  wire();
  load(DEFAULT_URL);
})();
