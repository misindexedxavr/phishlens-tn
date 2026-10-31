/* PhishLens TN front end. Plain JavaScript, no framework.
 * Everything coming from the analyzed page is inserted with textContent, never innerHTML. */
(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const SVG_NS = "http://www.w3.org/2000/svg";
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", positive: "Lowers risk" };
  const ERROR_TITLES = {
    invalid_url: "That link does not look right",
    invalid_request: "That request could not be read",
    blocked_address: "Blocked for safety",
    host_unresolved: "Domain not found",
    timeout: "The server took too long",
    connection_failed: "Could not connect",
    too_many_redirects: "Too many redirects",
    fetch_failed: "The page could not be read",
    rate_limited: "Slow down a little",
    busy: "The analyzer is busy",
    internal_error: "Something went wrong",
  };

  /* Static, developer-controlled SVG fragments (24x24, stroke icons). */
  const ICONS = {
    alert: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    redirect: '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
    form: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h5"/>',
    tag: '<path d="M20.59 13.41 13.42 20.58a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><path d="M7 7h.01"/>',
    type: '<path d="M4 7V4h16v3"/><path d="M9 20h6"/><path d="M12 4v16"/>',
    code: '<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    check: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m22 4-10 10.01-3-3.01"/>',
  };

  function icon(name, size = 22) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", String(size));
    svg.setAttribute("height", String(size));
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    svg.innerHTML = ICONS[name] || ICONS.alert; // constants above only
    return svg;
  }

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = value;
        else node.setAttribute(key, value === true ? "" : String(value));
      }
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const badge = (text, tone) => el("span", { class: "badge" + (tone ? " badge--" + tone : ""), text });
  const code = (text) => el("code", { text });
  const empty = (text) => el("p", { class: "empty", text });
  const note = (text) => el("p", { class: "note", text });

  function kv(pairs) {
    const dl = el("dl", { class: "kv" });
    for (const [label, value] of pairs) {
      if (value === null || value === undefined || value === "") continue;
      dl.append(el("dt", { text: label }), el("dd", null, value));
    }
    return dl;
  }

  function table(caption, headers, rows) {
    const head = el("tr", null, headers.map((h) => el("th", { scope: "col", text: h })));
    const body = rows.map((row) => el("tr", null, row.map((cell) => el("td", null, cell))));
    return el("div", { class: "table-wrap" }, el("table", null,
      el("caption", { class: "visually-hidden", text: caption }), el("thead", null, head), el("tbody", null, body)));
  }

  const fmtDate = (iso) => {
    if (!iso) return "unknown";
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? String(iso) : date.toISOString().slice(0, 10);
  };
  const yesNo = (value) => (value === true ? "Yes" : value === false ? "No" : "Unknown");
  const clamp = (n) => Math.max(0, Math.min(100, Number(n) || 0));

  /* ------------------------------------------------------------------ */
  /* elements and state                                                  */
  /* ------------------------------------------------------------------ */
  const form = $("#analyze-form");
  if (!form) return;
  const input = $("#url-input");
  const submit = $("#analyze-btn");
  const fieldError = $("#url-error");
  const progress = $("#progress");
  const errorPanel = $("#error-panel");
  const results = $("#results");
  const live = $("#sr-status");
  const state = { result: null, controller: null, lastUrl: "" };

  const show = (node) => { node.hidden = false; };
  const hide = (node) => { node.hidden = true; };
  const announce = (text) => { live.textContent = text; };

  function setBusy(busy) {
    submit.disabled = busy;
    submit.textContent = busy ? "Analyzing…" : "Analyze";
    form.setAttribute("aria-busy", String(busy));
  }

  function setStep(name, status, detail) {
    const item = $(`.step[data-step="${name}"]`);
    if (!item) return;
    item.dataset.status = status;
    const labels = { pending: "Pending", running: "In progress", done: "Done", failed: "Failed", skipped: "Skipped" };
    $(".step__status", item).textContent = labels[status] || status;
    $(".step__detail", item).textContent = detail || "";
    if (status === "running" || status === "failed") announce(`${$(".step__label", item).textContent}: ${labels[status]}`);
  }

  function resetProgress() {
    $$(".step").forEach((item) => setStep(item.dataset.step, "pending", ""));
  }

  /* ------------------------------------------------------------------ */
  /* running an analysis                                                 */
  /* ------------------------------------------------------------------ */
  form.addEventListener("submit", (event) => { event.preventDefault(); run(input.value); });
  $$("[data-example]").forEach((button) =>
    button.addEventListener("click", () => { input.value = button.dataset.example; run(input.value); }));
  $("#error-retry").addEventListener("click", () => { hide(errorPanel); input.focus(); input.select(); });
  $("#new-analysis").addEventListener("click", () => {
    hide(results); state.result = null; input.value = ""; window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" }); input.focus();
  });

  async function run(raw) {
    const url = raw.trim();
    if (!url) {
      fieldError.textContent = "Enter a URL to analyze.";
      show(fieldError);
      input.setAttribute("aria-invalid", "true");
      input.focus();
      return;
    }
    hide(fieldError); input.removeAttribute("aria-invalid");
    hide(results); hide(errorPanel); resetProgress(); show(progress);
    state.lastUrl = url; setBusy(true);
    if (state.controller) state.controller.abort();
    const controller = new AbortController();
    state.controller = controller;
    let finished = false;
    try {
      const response = await fetch("/api/analyze/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
      if (!response.ok) throw await apiError(response);
      finished = await consume(response);
      if (!finished) throw { code: "internal_error", message: "The analysis ended unexpectedly.", hint: "Please try again." };
    } catch (error) {
      if (error && error.name === "AbortError") return;
      showError(error && error.code ? error : { code: "internal_error", message: "Could not reach the analyzer.", hint: "Check your connection and try again." });
    } finally {
      if (state.controller === controller) { setBusy(false); state.controller = null; }
    }
  }

  async function apiError(response) {
    let payload = null;
    try { payload = await response.json(); } catch (e) { /* not JSON */ }
    const error = payload && payload.error;
    return error && error.code ? error : { code: "internal_error", message: `The server answered HTTP ${response.status}.`, hint: "Please try again." };
  }

  async function consume(response) {
    let done = false;
    const handle = (line) => {
      if (!line.trim()) return;
      const event = JSON.parse(line);
      if (event.event === "step") setStep(event.step, event.status, event.detail);
      else if (event.event === "result") { done = true; showResult(event.result); }
      else if (event.event === "error") { done = true; showError(event.error, event.step); }
    };
    if (response.body && response.body.getReader) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done: finishedReading } = await reader.read();
        if (finishedReading) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();
        lines.forEach(handle);
      }
      buffer += decoder.decode();
      handle(buffer);
    } else {
      (await response.text()).split("\n").forEach(handle);
    }
    return done;
  }

  function showError(error, step) {
    if (step) setStep(step, "failed", error.message);
    hide(results);
    $("#error-title").textContent = ERROR_TITLES[error.code] || ERROR_TITLES.internal_error;
    $("#error-message").textContent = error.message || "The analysis failed.";
    $("#error-hint").textContent = error.hint || "";
    show(errorPanel);
    $("#error-title").focus();
    announce(`Error: ${error.message || "analysis failed"}`);
  }

  /* ------------------------------------------------------------------ */
  /* rendering results                                                   */
  /* ------------------------------------------------------------------ */
  function showResult(result) {
    state.result = result;
    hide(progress); hide(errorPanel); show(results);
    renderGauge(result);
    renderFacts(result);
    renderSignals(result);
    renderForms(result);
    renderDomains(result);
    renderCertificate(result);
    renderRedirects(result);
    activateTab($("#tab-forms"), false);
    $("#results-title").focus({ preventScroll: true });
    results.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    announce(`Analysis complete. ${result.level} risk, score ${result.score} out of 100.`);
  }

  function renderGauge(result) {
    const score = clamp(result.score);
    const level = String(result.level || "Low").toLowerCase();
    const gauge = $("#gauge");
    gauge.dataset.level = level;
    gauge.setAttribute("aria-label", `Risk score ${score} out of 100. Level: ${result.level}.`);
    const arc = $("#gauge-arc");
    arc.style.strokeDashoffset = "100";
    const levelNode = $("#gauge-level");
    levelNode.dataset.level = level;
    levelNode.textContent = `${result.level} risk`;
    $("#verdict-text").textContent = result.verdict || "";
    const scoreNode = $("#gauge-score");
    if (reduceMotion) {
      arc.style.strokeDashoffset = String(100 - score);
      scoreNode.textContent = String(score);
      return;
    }
    scoreNode.textContent = "0";
    requestAnimationFrame(() => requestAnimationFrame(() => { arc.style.strokeDashoffset = String(100 - score); }));
    const start = performance.now();
    const duration = 1100;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration);
      scoreNode.textContent = String(Math.round(score * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  function renderFacts(result) {
    const facts = $("#result-facts");
    facts.replaceChildren();
    const brands = (result.brands && result.brands.targeted_brands) || [];
    const fetchInfo = result.fetch || {};
    const rows = [
      ["Analyzed link", code(result.url)],
      result.final_url && result.final_url !== result.url ? ["Landed on", code(result.final_url)] : null,
      ["Page title", (result.page && result.page.title) || "none"],
      ["HTTP status", fetchInfo.status_code ? `${fetchInfo.status_code} ${fetchInfo.reason || ""}`.trim() : "unknown"],
      ["Targeted brands", brands.length ? brands.join(", ") : "none detected"],
      ["Checked in", `${((result.duration_ms || 0) / 1000).toFixed(1)} s`],
    ].filter(Boolean);
    for (const [label, value] of rows) facts.append(el("div", null, el("dt", { text: label }), el("dd", null, value)));
  }

  function renderSignals(result) {
    const list = $("#signals-list");
    list.replaceChildren();
    const signals = (result.signals || []).slice().sort((a, b) => b.weight - a.weight);
    const risky = signals.filter((s) => s.weight > 0).length;
    $("#signals-count").textContent = signals.length ? `(${risky} warning${risky === 1 ? "" : "s"})` : "";
    if (!signals.length) {
      list.append(el("li", { class: "signal", "data-severity": "positive" },
        el("span", { class: "signal__icon" }, icon("check")),
        el("div", null, el("h4", { text: "No indicators triggered" }),
          el("p", { text: "None of the phishing rules matched. That is encouraging, but it is not a guarantee." }))));
      return;
    }
    for (const signal of signals) {
      const sign = signal.weight > 0 ? `+${signal.weight}` : `\u2212${Math.abs(signal.weight)}`;
      list.append(el("li", { class: "signal", "data-severity": signal.severity },
        el("span", { class: "signal__icon" }, icon(signal.icon)),
        el("div", null,
          el("div", { class: "signal__head" },
            el("h4", { text: signal.title }),
            el("span", { class: "signal__weight", "aria-label": `${signal.weight > 0 ? "adds" : "removes"} ${Math.abs(signal.weight)} points`, text: sign }),
            el("span", { class: "signal__tag", text: `${SEVERITY_LABEL[signal.severity] || signal.severity} · ${signal.category}` })),
          el("p", { text: signal.explanation }))));
    }
  }

  function renderForms(result) {
    const panel = $("#panel-forms");
    panel.replaceChildren();
    const page = result.page || {};
    (page.notes || []).forEach((text) => panel.append(note(text)));
    if (page.orphan_password_inputs) {
      panel.append(note(`${page.orphan_password_inputs} password field(s) sit outside any <form>. The page probably sends them with JavaScript, which PhishLens does not run.`));
    }
    const forms = page.forms || [];
    if (!forms.length) { panel.append(empty("No forms were found in the page.")); return; }
    for (const f of forms) {
      const header = el("header", null,
        el("h4", { text: `Form ${f.index}` }),
        badge(String(f.method).toUpperCase()),
        f.external_action ? badge("Posts to another domain", "bad") : badge("Same site", "good"),
        f.has_password ? badge("Password field", "warn") : null,
        f.action_scheme === "http" ? badge("Plain HTTP", "bad") : null);
      const details = kv([
        ["Sends data to", code(f.resolved_action || "(current page)")],
        ["Receiving domain", f.action_domain || "same as the page"],
        ["Sensitive data", (f.sensitive_fields || []).length ? (f.sensitive_fields || []).join(", ") : "none recognised"],
        ["Hidden fields", String(f.hidden_count)],
        ["Buttons", (f.submit_labels || []).join(", ")],
      ]);
      const rows = (f.inputs || []).map((i) => [
        i.type, i.name || i.id || "(unnamed)", i.placeholder || "",
        el("span", { class: "chips" }, (i.sensitive || []).map((s) => badge(s, s === "username" ? "" : "warn"))),
      ]);
      panel.append(el("article", { class: "detail-card" }, header, details,
        rows.length ? table(`Fields of form ${f.index}`, ["Type", "Name", "Placeholder", "Flags"], rows) : null));
    }
  }

  function renderDomains(result) {
    const panel = $("#panel-domains");
    panel.replaceChildren();
    const d = result.domain || {};
    const rdap = d.rdap || {};
    const page = result.page || {};
    const brands = result.brands || {};
    panel.append(el("article", { class: "detail-card" }, el("header", null, el("h4", { text: "Domain" })), kv([
      ["Host", code(d.host || "")],
      ["Registered domain", code(d.registered_domain || "")],
      ["Subdomain levels", String(d.subdomain_count ?? 0)],
      ["Public suffix", d.suffix ? "." + d.suffix : "none"],
      ["Frequently abused TLD", yesNo(d.suspicious_tld)],
      ["Punycode (xn--)", d.punycode ? `Yes, reads as ${d.unicode_host}` : "No"],
      ["Look-alike characters", d.homoglyph ? `Yes, reads as ${d.skeleton}` : "No"],
      ["Free or shared hosting", d.free_hosting || "No"],
      ["Registered on", rdap.available ? `${fmtDate(rdap.registered_at)} (${rdap.age_days} days ago)` : `Unavailable (${rdap.error || "no data"})`],
      ["Registrar", rdap.registrar],
    ])));

    const hits = brands.hits || [];
    const squats = brands.typosquats || [];
    const embedded = brands.embedded_official || [];
    if (brands.official_brand) panel.append(note(`This domain is listed as an official ${brands.official_brand} domain.`));
    if (hits.length || squats.length || embedded.length) {
      const items = [
        ...embedded.map((e) => ["Decoy", e.brand, `${e.host} contains ${e.official_domain}`]),
        ...squats.map((s) => ["Look-alike", s.brand, `${s.candidate} vs ${s.official_domain} (${s.technique})`]),
        ...hits.map((h) => [h.location, h.brand, h.evidence]),
      ];
      panel.append(el("h4", { text: "Brand findings" }), table("Brand findings", ["Where", "Brand", "Evidence"], items));
    }

    const external = page.external_summary || [];
    panel.append(el("h4", { text: "External domains referenced by the page" }));
    panel.append(external.length
      ? table("External domains", ["Domain", "References", "Used for"], external.map((e) => [code(e.domain), String(e.count), (e.categories || []).join(", ")]))
      : empty("The page does not reference any other domain."));

    const extras = [];
    for (const frame of page.iframes || []) {
      extras.push(["Iframe", frame.src || "(inline)", [frame.external ? "external" : "same site", frame.hidden ? "hidden" : "visible", frame.sandboxed ? "sandboxed" : ""].filter(Boolean).join(", ")]);
    }
    if (page.meta_refresh) extras.push(["Meta refresh", page.meta_refresh.resolved_url, `after ${page.meta_refresh.delay}s`]);
    if (page.js_redirect) extras.push(["Script redirect", page.js_redirect, "read statically, not executed"]);
    if (page.favicon_url) extras.push(["Favicon", page.favicon_url, page.favicon_external ? "another domain" : "same site"]);
    (page.exfil_endpoints || []).forEach((name) => extras.push(["Collection endpoint", name, "referenced in the page code"]));
    if ((page.script_indicators || []).length) extras.push(["Script patterns", page.script_indicators.join(", "), page.right_click_disabled ? "right-click disabled" : ""]);
    if (extras.length) panel.append(el("h4", { text: "Other page behaviour" }), table("Other behaviour", ["Item", "Value", "Note"], extras.map((r) => [r[0], code(r[1]), r[2]])));
  }

  function renderCertificate(result) {
    const panel = $("#panel-certificate");
    panel.replaceChildren();
    const tls = result.tls || {};
    if (tls.applicable === false) { panel.append(empty(tls.error || "The final page is not served over HTTPS, so there is no certificate to inspect.")); return; }
    if (!tls.available) {
      panel.append(empty(`No certificate could be read. ${tls.error || ""}`.trim()));
      if (tls.verification_error) panel.append(note(`Verification problem: ${tls.verification_error}`));
      return;
    }
    const status = [
      tls.trusted ? badge("Trusted chain", "good") : badge("Not trusted", "bad"),
      tls.matches_domain ? badge("Matches host", "good") : badge("Host mismatch", "bad"),
      tls.expired ? badge("Expired", "bad") : null,
      tls.self_signed ? badge("Self-signed", "bad") : null,
    ];
    panel.append(el("article", { class: "detail-card" },
      el("header", null, el("h4", { text: "Certificate" }), status),
      kv([
        ["Issuer", tls.issuer],
        ["Issued to", [tls.subject_cn, tls.subject_org].filter(Boolean).join(", ")],
        ["Valid from", fmtDate(tls.not_before)],
        ["Valid until", `${fmtDate(tls.not_after)} (${tls.days_until_expiry} days left)`],
        ["Certificate age", `${tls.age_days} days (lifetime ${tls.validity_days} days)`],
        ["Protocol", [tls.protocol, tls.cipher].filter(Boolean).join(", ")],
        ["Verification", tls.verification_error],
        ["SHA-256", code(tls.sha256 || "")],
        ["Names (SAN)", el("span", { class: "chips" }, (tls.san || []).slice(0, 30).map((n) => badge(n)))],
      ])));
  }

  function renderRedirects(result) {
    const panel = $("#panel-redirects");
    panel.replaceChildren();
    const chain = (result.fetch && result.fetch.redirect_chain) || [];
    if (!chain.length) { panel.append(empty("No request data.")); return; }
    if (chain.length === 1) panel.append(note("The link did not redirect. It loaded directly."));
    const list = el("ol", { class: "hops" });
    chain.forEach((hop, index) => {
      const last = index === chain.length - 1;
      list.append(el("li", { class: "hop" },
        el("span", { class: "hop__status", text: String(hop.status) }),
        code(hop.url),
        el("span", { class: "hop__meta", text: last ? `Final page${hop.ip ? " · " + hop.ip : ""}` : `Redirects onward${hop.ip ? " · " + hop.ip : ""}` })));
    });
    panel.append(list);
  }

  /* ------------------------------------------------------------------ */
  /* tabs (WAI-ARIA tabs pattern)                                        */
  /* ------------------------------------------------------------------ */
  const tabs = $$('[role="tab"]');
  function activateTab(tab, focus = true) {
    tabs.forEach((other) => {
      const selected = other === tab;
      other.setAttribute("aria-selected", String(selected));
      other.tabIndex = selected ? 0 : -1;
      document.getElementById(other.getAttribute("aria-controls")).hidden = !selected;
    });
    if (focus) tab.focus();
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => activateTab(tab));
    tab.addEventListener("keydown", (event) => {
      const keys = { ArrowRight: (index + 1) % tabs.length, ArrowLeft: (index - 1 + tabs.length) % tabs.length, Home: 0, End: tabs.length - 1 };
      if (event.key in keys) { event.preventDefault(); activateTab(tabs[keys[event.key]]); }
    });
  });

  /* ------------------------------------------------------------------ */
  /* export                                                              */
  /* ------------------------------------------------------------------ */
  function fileName(ext) {
    let host = "analysis";
    try { host = new URL(state.result.final_url || state.result.url).hostname.replace(/[^a-z0-9.-]/gi, "_"); } catch (e) { /* keep default */ }
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    return `phishlens-${host}-${stamp}.${ext}`;
  }

  function download(blob, name) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  $("#export-json").addEventListener("click", () => {
    if (!state.result) return;
    download(new Blob([JSON.stringify(state.result, null, 2)], { type: "application/json" }), fileName("json"));
    announce("JSON report downloaded.");
  });

  $("#export-md").addEventListener("click", async () => {
    if (!state.result) return;
    try {
      const response = await fetch("/api/export/markdown", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(state.result),
      });
      if (!response.ok) throw await apiError(response);
      download(await response.blob(), fileName("md"));
      announce("Markdown report downloaded.");
    } catch (error) {
      announce(`Markdown export failed. ${(error && error.message) || ""}`);
      window.alert(`Markdown export failed. ${(error && error.message) || "Please try again."}`);
    }
  });
})();
