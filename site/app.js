(() => {
  "use strict";

  const DATA_BASE_URL = new URL("./data/", document.baseURI);
  const DATA_INDEX_URL = new URL("index.json", DATA_BASE_URL);
  const PAGE_SIZE = 25;
  const state = { index: null, snapshot: null, domains: [], filtered: [], page: 1 };

  const byId = (id) => document.getElementById(id);
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };
  const safeArray = (value) => Array.isArray(value) ? value : [];
  const count = (value) => Number(value || 0).toLocaleString("en-AU");
  const ratio = (numerator, denominator) => denominator ? `${Math.round((numerator / denominator) * 100)}%` : "—";
  const display = (value) => value === null || value === undefined || value === "" ? "—" : String(value);
  const serialize = (value) => JSON.stringify(value ?? null, null, 2);

  function dateLabel(value, includeTime = false) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("en-AU", {
      timeZone: "Australia/Sydney", day: "2-digit", month: "short", year: "numeric",
      ...(includeTime ? { hour: "2-digit", minute: "2-digit", hour12: false } : {}),
    }).format(date);
  }

  function statusInfo(status) {
    const labels = {
      present_valid: ["Valid", "good"], present_invalid: ["Invalid", "bad"], absent: ["Absent", "dim"],
      lookup_error: ["Lookup error", "warn"], http_error: ["HTTP error", "warn"],
      not_collected: ["Not collected", "dim"], not_assessable: ["Not assessable", "dim"],
      valid: ["Valid", "good"], invalid: ["Invalid", "bad"], error: ["TLS error", "warn"],
      not_observed: ["Not observed", "dim"], secure: ["Secure", "good"], unsigned: ["Unsigned", "warn"],
      broken: ["Broken", "bad"], unknown: ["Unknown", "dim"], in_top_1m: ["Top 1M", "good"],
      outside_top_1m: [">1M", "warn"], present: ["Present", "good"],
    };
    return labels[status] || [display(status), "dim"];
  }

  function pill(status, label) {
    const [fallback, tone] = statusInfo(status);
    return el("span", `status-pill ${tone}`, label || fallback);
  }

  function object(value) { return value && typeof value === "object" && !Array.isArray(value) ? value : {}; }
  function summaryOf(snapshot) { return object(snapshot && snapshot.summary); }
  function statusCount(summary, family, status) { return Number(object(summary[family])[status] || 0); }
  function policyCount(summary, policy) { return Number(object(summary.dmarc_policies)[policy] || 0); }

  function setMetricCards(snapshot) {
    const target = byId("metrics");
    target.replaceChildren();
    const summary = summaryOf(snapshot);
    const total = Number(summary.domain_count || safeArray(snapshot.domains).length);
    const ranked = Number(object(summary.rank_status).in_top_1m ?? object(snapshot.source).au_entry_count ?? total);
    const enforced = policyCount(summary, "reject") + policyCount(summary, "quarantine");
    const hardFail = Number(object(summary.spf_qualifiers).fail || 0);
    const items = [
      ["Tracked .au names", count(total), "current rankings plus retained roster", "accent"],
      ["In current top 1M", count(ranked), `${ratio(ranked, total)} of tracked names`, ""],
      ["DMARC enforcement", count(enforced), "p=reject or p=quarantine", "good"],
      ["SPF hard fail", count(hardFail), "valid policies ending in -all", ""],
      ["DMARC record absent", count(statusCount(summary, "dmarc", "absent")), "no record found", ""],
      ["SPF record absent", count(statusCount(summary, "spf", "absent")), "no record found", ""],
      ["security.txt present", count(statusCount(summary, "security_txt", "present")), "well-known endpoint returned 2xx", ""],
      ["Valid security.txt", count(statusCount(summary, "security_txt_content_validity", "valid")), "content checks only", "good"],
    ];
    for (const [label, value, foot, tone] of items) {
      const card = el("article", `metric-card ${tone}`);
      card.append(el("span", "metric-label", label), el("strong", "metric-value", value), el("span", "metric-foot", foot));
      target.append(card);
    }
  }

  function drawBars(targetId, rows, ariaLabel) {
    const target = byId(targetId);
    target.replaceChildren();
    const scale = Math.max(1, ...rows.map((item) => Number(item.value || 0)));
    for (const item of rows) {
      const row = el("div", "bar-row");
      row.append(el("span", "bar-label", item.label));
      const track = el("div", "bar-track");
      const fill = el("div", "bar-fill");
      fill.dataset.tone = item.tone || "none";
      fill.style.width = `${item.value ? Math.max(2, (item.value / scale) * 100) : 0}%`;
      track.append(fill);
      row.append(track, el("span", "bar-value", count(item.value)));
      target.append(row);
    }
    target.setAttribute("aria-label", ariaLabel);
  }

  function drawCharts(snapshot) {
    const summary = summaryOf(snapshot);
    const total = Number(summary.domain_count || 0);
    drawBars("policy-chart", [
      { label: "Reject", value: policyCount(summary, "reject"), tone: "reject" },
      { label: "Quarantine", value: policyCount(summary, "quarantine"), tone: "quarantine" },
      { label: "None / monitor", value: policyCount(summary, "none"), tone: "none" },
      { label: "No record", value: statusCount(summary, "dmarc", "absent"), tone: "missing" },
      { label: "Invalid / error", value: statusCount(summary, "dmarc", "present_invalid") + statusCount(summary, "dmarc", "lookup_error"), tone: "missing" },
    ], `DMARC policy counts across ${count(total)} domains`);
    const dnssec = object(summary.dnssec);
    const mxDnssec = object(summary.mx_dnssec);
    drawBars("signals-chart", [
      { label: "Domain DNSSEC secure", value: dnssec.secure, tone: "reject" },
      { label: "Domain unsigned", value: dnssec.unsigned, tone: "none" },
      { label: "Domain broken / error", value: Number(dnssec.broken || 0) + Number(dnssec.lookup_error || 0), tone: "missing" },
      { label: "MX targets unsigned", value: mxDnssec.unsigned, tone: "none" },
      { label: "MX targets broken / error", value: Number(mxDnssec.broken || 0) + Number(mxDnssec.lookup_error || 0), tone: "quarantine" },
    ], "Domain and MX host DNSSEC findings");
    drawBars("web-chart", [
      { label: "Endpoint present", value: statusCount(summary, "security_txt", "present"), tone: "reject" },
      { label: "Endpoint absent", value: statusCount(summary, "security_txt", "absent"), tone: "none" },
      { label: "HTTP errors", value: statusCount(summary, "security_txt", "http_error"), tone: "quarantine" },
      { label: "Lookup errors", value: statusCount(summary, "security_txt", "lookup_error"), tone: "missing" },
      { label: "Content valid", value: statusCount(summary, "security_txt_content_validity", "valid"), tone: "reject" },
      { label: "Content invalid", value: statusCount(summary, "security_txt_content_validity", "invalid"), tone: "missing" },
      { label: "HTTPS response observed", value: Number(summary.security_txt_https_responses || 0), tone: "quarantine" },
    ], "security.txt endpoint availability and content validation");
    drawHistoryChart();
  }

  function drawHistoryChart() {
    const target = byId("history-chart");
    target.replaceChildren();
    const caption = byId("history-caption");
    const history = safeArray(state.index && state.index.snapshots).slice().sort((a, b) => new Date(a.generated_at) - new Date(b.generated_at));
    if (history.length < 2) {
      caption.textContent = "Historical trend appears after more snapshots are collected.";
      return;
    }
    const visible = history.slice(-52);
    for (let index = 0; index < visible.length; index += 1) {
      const item = visible[index];
      const summary = object(item.summary);
      const countDomains = Number(item.domain_count || summary.domain_count || 0);
      const enforced = Number(object(summary.dmarc_policies).reject || 0) + Number(object(summary.dmarc_policies).quarantine || 0);
      const percent = countDomains ? Math.round((enforced / countDomains) * 100) : 0;
      const point = el("div", "history-point");
      point.tabIndex = 0;
      point.dataset.latest = String(index === visible.length - 1);
      point.dataset.label = `${dateLabel(item.generated_at)} · ${percent}% enforced`;
      const bar = el("div", "history-bar");
      bar.style.height = `${Math.max(2, percent)}%`;
      point.append(bar);
      target.append(point);
    }
    caption.textContent = `Showing the latest ${count(visible.length)} of ${count(history.length)} scan snapshots.`;
  }

  function setSnapshotMeta(snapshot) {
    if (!snapshot) {
      byId("snapshot-meta").textContent = "Waiting for the first scan";
      byId("feed-status").textContent = "NO SCANS YET";
      return;
    }
    const source = object(snapshot.source);
    byId("snapshot-meta").textContent = `${dateLabel(snapshot.generated_at, true)} · Tranco ${display(source.list_id)} · ${count(source.au_entry_count)} current .au entries`;
    byId("feed-status").textContent = "LATEST SNAPSHOT LOADED";
  }

  function fillSnapshotSelector() {
    const select = byId("snapshot-select");
    select.replaceChildren();
    const snapshots = safeArray(state.index && state.index.snapshots);
    if (!snapshots.length) {
      select.append(el("option", "", "No scans yet"));
      select.disabled = true;
      return;
    }
    for (const item of snapshots.slice().sort((a, b) => new Date(b.generated_at) - new Date(a.generated_at))) {
      const option = el("option", "", `${dateLabel(item.generated_at, true)} · ${count(item.domain_count)} domains`);
      option.value = String(item.id);
      select.append(option);
    }
    select.disabled = false;
  }

  function providerNames(domain) {
    const clues = object(domain.provider_clues);
    const entries = [];
    for (const role of ["outbound", "inbound", "reporting"]) {
      for (const item of safeArray(clues[role])) {
        if (item && item.name) entries.push({ role, name: String(item.name), hosts: safeArray(item.observed_hosts) });
      }
    }
    return entries;
  }

  function populateProviderFilter() {
    const select = byId("provider-filter");
    select.replaceChildren();
    const all = el("option", "", "Any service");
    all.value = "all";
    select.append(all);
    const names = new Set();
    for (const domain of state.domains) for (const item of providerNames(domain)) if (item.name !== "Unclassified") names.add(item.name);
    for (const name of [...names].sort((a, b) => a.localeCompare(b))) {
      const option = el("option", "", name);
      option.value = name;
      select.append(option);
    }
    select.disabled = names.size === 0;
  }

  function searchableText(domain) {
    const fields = [domain.domain, domain.rank_display, object(domain.spf).record, object(domain.dmarc).record];
    for (const item of providerNames(domain)) fields.push(item.name, ...item.hosts);
    for (const host of safeArray(object(domain.mx).hosts)) fields.push(host.hostname);
    const request = object(object(domain.security_txt).request);
    for (const attempt of safeArray(request.attempts)) {
      fields.push(attempt.final_url);
      for (const hop of safeArray(attempt.hops)) {
        fields.push(hop.redirect_to);
        for (const value of Object.values(object(hop.headers))) fields.push(...(Array.isArray(value) ? value : [value]));
      }
    }
    return fields.filter(Boolean).join(" ").toLowerCase();
  }

  function getFilteredDomains() {
    const query = byId("search-input").value.trim().toLowerCase();
    const rankStatus = byId("rank-filter").value;
    const spfStatus = byId("spf-filter").value;
    const qualifier = byId("spf-qualifier-filter").value;
    const dmarcPolicy = byId("dmarc-filter").value;
    const provider = byId("provider-filter").value;
    const dnssec = byId("dnssec-filter").value;
    const availability = byId("securitytxt-filter").value;
    const contentValidity = byId("content-validity-filter").value;
    const certificate = byId("tls-filter").value;
    state.filtered = state.domains.filter((domain) => {
      if (query && !searchableText(domain).includes(query)) return false;
      if (rankStatus !== "all" && domain.rank_status !== rankStatus) return false;
      const spf = object(domain.spf);
      if (spfStatus !== "all" && spf.status !== spfStatus) return false;
      if (qualifier !== "all") {
        const terminal = object(spf.terminal);
        if (qualifier === "implicit" ? !terminal.implicit : terminal.outcome !== qualifier) return false;
      }
      const dmarc = object(domain.dmarc);
      if (dmarcPolicy !== "all") {
        if (["absent", "present_invalid", "lookup_error"].includes(dmarcPolicy)) {
          if (dmarc.status !== dmarcPolicy) return false;
        } else if (String(object(dmarc.policy).p || "").toLowerCase() !== dmarcPolicy || dmarc.status !== "present_valid") return false;
      }
      if (provider !== "all" && !providerNames(domain).some((item) => item.name === provider)) return false;
      if (dnssec !== "all" && object(domain.dnssec).status !== dnssec) return false;
      const security = object(domain.security_txt);
      if (availability !== "all" && security.availability !== availability) return false;
      if (contentValidity !== "all" && security.content_validity !== contentValidity) return false;
      if (certificate !== "all" && security.tls_certificate !== certificate) return false;
      return true;
    });
    state.page = Math.min(state.page, Math.max(1, Math.ceil(state.filtered.length / PAGE_SIZE)));
    renderTable();
  }

  function domainRank(domain) {
    const cell = el("div", "rank-cell");
    cell.append(el("span", "rank-primary", domain.rank_display || (domain.rank ? `#${count(domain.rank)}` : ">1,000,000")));
    if (domain.au_rank) cell.append(el("span", "", `.au #${count(domain.au_rank)}/${count(domain.au_rank_total)}`));
    else if (domain.last_rank) cell.append(el("span", "", `last #${count(domain.last_rank)} · .au #${count(domain.last_au_rank)}`));
    return cell;
  }

  function policyCell(family, record) {
    const cell = el("div", "policy-cell");
    cell.append(pill(record.status));
    if (family === "spf" && record.terminal) cell.append(el("div", "policy-label", record.terminal.label || record.terminal.outcome));
    if (family === "dmarc" && record.policy && record.policy.p) cell.append(el("div", "policy-label", `p=${record.policy.p}${record.discovery_source === "inherited" ? " · inherited" : ""}`));
    return cell;
  }

  function serviceCell(domain) {
    const cell = el("div", "service-list");
    const entries = providerNames(domain);
    if (!entries.length) cell.append(el("span", "service-chip unknown", "No provider identified"));
    for (const entry of entries.slice(0, 6)) {
      const chip = el("span", "service-chip", entry.name);
      chip.title = `${entry.role}: ${entry.hosts.join(", ")}`;
      cell.append(chip);
    }
    return cell;
  }

  function mxCell(domain) {
    const hosts = safeArray(object(domain.mx).hosts);
    if (!hosts.length) return pill(object(domain.mx).status || "unknown");
    const cell = el("div", "mx-list", hosts.slice(0, 4).map((item) => item.hostname).filter(Boolean).join(" · "));
    if (hosts.length > 4) cell.append(el("div", "", `+${hosts.length - 4} more`));
    return cell;
  }

  function securityCell(domain) {
    const finding = object(domain.security_txt);
    const cell = el("div", "extra-list");
    cell.append(pill(finding.availability, `File ${statusInfo(finding.availability)[0].toLowerCase()}`));
    cell.append(pill(finding.content_validity, `Content ${statusInfo(finding.content_validity)[0].toLowerCase()}`));
    cell.append(pill(finding.tls_certificate, `TLS ${statusInfo(finding.tls_certificate)[0].toLowerCase()}`));
    if (object(finding.request).redirects_to_https) cell.append(el("span", "extra-chip good", "Redirected to HTTPS"));
    return cell;
  }

  function emailExtras(domain) {
    const cell = el("div", "extra-list");
    const signals = [
      ["MTA-STS", object(domain.mta_sts).status],
      ["TLS-RPT", object(domain.tls_reporting).status],
      ["DNSSEC", object(domain.dnssec).status],
    ];
    for (const [label, status] of signals) {
      const [stateLabel, tone] = statusInfo(status || "unknown");
      cell.append(el("span", `extra-chip ${tone}`, `${label} ${stateLabel}`));
    }
    return cell;
  }

  function detailBlock(parent, title, value, wide = false) {
    const block = el("section", `detail-block${wide ? " wide" : ""}`);
    block.append(el("h4", "", title));
    const pre = el("pre", "", serialize(value));
    block.append(pre);
    parent.append(block);
  }

  function buildDetails(domain) {
    const row = el("tr", "detail-row");
    const cell = el("td");
    cell.colSpan = 8;
    const content = el("div", "detail-content");
    detailBlock(content, "Email authentication and routing", {
      spf: domain.spf, dmarc: domain.dmarc, mx: domain.mx, mta_sts: domain.mta_sts, tls_reporting: domain.tls_reporting,
    });
    detailBlock(content, "Email DNS and DNSSEC", {
      dnssec: domain.dnssec, nameservers: domain.nameservers, soa: domain.soa,
      mx_dnssec: safeArray(object(domain.mx).hosts).map((host) => ({ hostname: host.hostname, status: host.dnssec_status, evidence: host.dnssec_evidence })),
    });
    detailBlock(content, "Inferred mail services", domain.provider_clues || {});
    detailBlock(content, "security.txt endpoint observations", domain.security_txt || {}, true);
    if (domain.errors && Object.keys(domain.errors).length) detailBlock(content, "Collection notes", domain.errors, true);
    cell.append(content);
    row.append(cell);
    return row;
  }

  function renderTable() {
    const target = byId("domain-rows");
    target.replaceChildren();
    const total = state.filtered.length;
    const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const start = (state.page - 1) * PAGE_SIZE;
    for (const domain of state.filtered.slice(start, start + PAGE_SIZE)) {
      const row = el("tr", "data-row");
      const rank = el("td"); rank.append(domainRank(domain));
      const name = el("td");
      name.append(el("div", "domain-name", domain.domain));
      name.append(el("div", "domain-meta", object(domain).rank_status === "outside_top_1m" ? "retained outside current top million" : "current Tranco entry"));
      const toggle = el("button", "detail-toggle", "Inspect findings");
      toggle.type = "button";
      name.append(toggle);
      const spf = el("td"); spf.append(policyCell("spf", object(domain.spf)));
      const dmarc = el("td"); dmarc.append(policyCell("dmarc", object(domain.dmarc)));
      const security = el("td"); security.append(securityCell(domain));
      const services = el("td"); services.append(serviceCell(domain));
      const mx = el("td"); mx.append(mxCell(domain));
      const extras = el("td"); extras.append(emailExtras(domain));
      row.append(rank, name, spf, dmarc, security, services, mx, extras);
      const details = buildDetails(domain);
      details.hidden = true;
      toggle.addEventListener("click", () => {
        details.hidden = !details.hidden;
        toggle.textContent = details.hidden ? "Inspect findings" : "Hide findings";
      });
      target.append(row, details);
    }
    if (!total) {
      const row = el("tr");
      const cell = el("td", "empty-cell", "No domains match these filters.");
      cell.colSpan = 8;
      row.append(cell);
      target.append(row);
    }
    byId("result-count").textContent = `${count(total)} matching domains · showing ${count(total ? start + 1 : 0)}–${count(Math.min(start + PAGE_SIZE, total))}`;
    byId("page-label").textContent = `Page ${count(state.page)} of ${count(pageCount)}`;
    byId("previous-page").disabled = state.page <= 1;
    byId("next-page").disabled = state.page >= pageCount;
  }

  async function decodeSnapshot(response, path) {
    if (!response.ok) throw new Error(`Snapshot request failed (${response.status})`);
    if (!String(path).endsWith(".gz")) return response.json();
    const bytes = await response.arrayBuffer();
    const signature = new Uint8Array(bytes, 0, Math.min(2, bytes.byteLength));
    // Fetch may transparently decode HTTP Content-Encoding: gzip. Detect the
    // file signature so either encoded .gz files or already-decoded responses work.
    if (signature.length < 2 || signature[0] !== 0x1f || signature[1] !== 0x8b) {
      return JSON.parse(new TextDecoder().decode(bytes));
    }
    if (typeof DecompressionStream !== "function") throw new Error("This browser cannot decompress gzip snapshots");
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    const text = await new Response(stream).text();
    return JSON.parse(text);
  }

  async function loadSnapshot(entry) {
    const url = new URL(entry.path, DATA_BASE_URL);
    const response = await fetch(url, { cache: "force-cache" });
    const snapshot = await decodeSnapshot(response, entry.path);
    if (snapshot.schema_version !== 5) throw new Error(`Unsupported snapshot schema ${snapshot.schema_version}`);
    state.snapshot = snapshot;
    state.domains = safeArray(snapshot.domains);
    state.filtered = state.domains;
    state.page = 1;
    setSnapshotMeta(snapshot);
    setMetricCards(snapshot);
    drawCharts(snapshot);
    populateProviderFilter();
    getFilteredDomains();
    byId("empty-state").hidden = state.domains.length !== 0;
    byId("download-json").disabled = false;
    byId("download-csv").disabled = false;
    const raw = snapshot.raw_archive || entry.raw_archive;
    const rawLink = byId("download-raw");
    if (raw) {
      rawLink.href = new URL(raw, DATA_BASE_URL).href;
      rawLink.hidden = false;
    } else rawLink.hidden = true;
  }

  function csvCell(value) {
    const text = value === null || value === undefined ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
    return `"${text.replaceAll('"', '""')}"`;
  }

  function downloadFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = el("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function exportCSV() {
    const headers = [
      "domain", "rank_status", "rank_display", "tranco_rank", "au_rank", "au_rank_total", "last_rank", "last_au_rank", "last_rank_list_id", "last_ranked_at", "first_seen_at",
      "spf_status", "spf_valid", "spf_record", "spf_terminal", "spf_dns_lookups", "spf_void_lookups", "spf_mechanisms", "spf_service_targets",
      "dmarc_status", "dmarc_valid", "dmarc_record", "dmarc_location", "dmarc_discovery_source", "dmarc_policy_p", "dmarc_policy_sp", "dmarc_policy_np", "dmarc_alignment", "dmarc_test_mode", "dmarc_reporting_uris", "dmarc_reporting_hosts",
      "outbound_services", "inbound_services", "reporting_services", "mx_status", "mx_hosts", "mta_sts_status", "mta_sts_record", "tls_reporting_status", "tls_reporting_record", "dnssec_status", "dnssec_evidence", "mx_dnssec_evidence", "nameservers", "soa",
      "security_txt_availability", "security_txt_content_validity", "security_txt_tls_certificate", "security_txt_http_fallback", "security_txt_redirects_to_https", "security_txt_https_response_received", "security_txt_status_code", "security_txt_final_url", "security_txt_attempts", "security_txt_validation", "errors",
    ];
    const rows = [headers];
    for (const domain of state.filtered) {
      const providers = object(domain.provider_clues);
      const names = (role) => safeArray(providers[role]).map((item) => item.name).join("; ");
      const security = object(domain.security_txt);
      const request = object(security.request);
      const terminal = object(object(domain.spf).terminal);
      const mx = object(domain.mx);
      const securityDnssec = safeArray(mx.hosts).map((host) => ({ hostname: host.hostname, status: host.dnssec_status, evidence: host.dnssec_evidence }));
      rows.push([
        domain.domain, domain.rank_status, domain.rank_display, domain.rank, domain.au_rank, domain.au_rank_total, domain.last_rank, domain.last_au_rank, domain.last_rank_list_id, domain.last_ranked_at, domain.first_seen_at,
        object(domain.spf).status, object(domain.spf).valid, object(domain.spf).record, terminal.token ? `${terminal.token} ${terminal.outcome}` : terminal.outcome, object(domain.spf).dns_lookups, object(domain.spf).void_dns_lookups, object(domain.spf).mechanisms, object(domain.spf).service_targets,
        object(domain.dmarc).status, object(domain.dmarc).valid, object(domain.dmarc).record, object(domain.dmarc).location, object(domain.dmarc).discovery_source, object(object(domain.dmarc).policy).p, object(object(domain.dmarc).policy).sp, object(object(domain.dmarc).policy).np, object(domain.dmarc).alignment, object(domain.dmarc).test_mode, object(domain.dmarc).reporting_uris, object(domain.dmarc).reporting_hosts,
        names("outbound"), names("inbound"), names("reporting"), mx.status, safeArray(mx.hosts).map((host) => host.hostname).join("; "), object(domain.mta_sts).status, object(domain.mta_sts).record, object(domain.tls_reporting).status, object(domain.tls_reporting).record,
        object(domain.dnssec).status, domain.dnssec, securityDnssec, domain.nameservers, domain.soa,
        security.availability, security.content_validity, security.tls_certificate, request.fallback_attempted, request.redirects_to_https, request.https_response_received, request.status_code, request.final_url, request.attempts, security.validation, domain.errors,
      ]);
    }
    const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    const date = state.snapshot.generated_at ? state.snapshot.generated_at.slice(0, 10) : "snapshot";
    downloadFile(`au-mail-auth-${date}-filtered.csv`, `\uFEFF${csv}`, "text/csv;charset=utf-8");
  }

  function exportJSON() {
    const date = state.snapshot.generated_at ? state.snapshot.generated_at.slice(0, 10) : "snapshot";
    downloadFile(`au-mail-auth-${date}.json`, JSON.stringify(state.snapshot, null, 2), "application/json;charset=utf-8");
  }

  async function initialize() {
    try {
      const response = await fetch(DATA_INDEX_URL, { cache: "no-cache" });
      if (!response.ok) throw new Error(`Index request failed (${response.status})`);
      state.index = await response.json();
      if (state.index.schema_version !== 5) throw new Error(`Unsupported data index schema ${state.index.schema_version}`);
      drawHistoryChart();
      fillSnapshotSelector();
      const snapshots = safeArray(state.index.snapshots).slice().sort((a, b) => new Date(b.generated_at) - new Date(a.generated_at));
      if (!snapshots.length) {
        byId("feed-status").textContent = "NO SCANS YET";
        byId("metrics").replaceChildren();
        byId("policy-chart").textContent = "No scans yet";
        byId("signals-chart").textContent = "No scans yet";
        byId("web-chart").textContent = "No scans yet";
        byId("empty-state").hidden = false;
        byId("domain-rows").replaceChildren();
        setSnapshotMeta(null);
        renderTable();
        return;
      }
      const latest = snapshots.find((item) => item.path === state.index.latest) || snapshots[0];
      byId("snapshot-select").value = String(latest.id);
      await loadSnapshot(latest);
    } catch (error) {
      byId("feed-status").textContent = "DATA FEED UNAVAILABLE";
      byId("empty-state").hidden = true;
      byId("error-state").hidden = false;
      byId("error-state").textContent = `Unable to load the public snapshot: ${error.message}`;
      byId("result-count").textContent = "Data feed unavailable";
      byId("domain-rows").replaceChildren();
      const row = el("tr");
      const cell = el("td", "empty-cell", "The snapshot could not be loaded.");
      cell.colSpan = 8;
      row.append(cell);
      byId("domain-rows").append(row);
    }
  }

  byId("snapshot-select").addEventListener("change", async (event) => {
    const entry = safeArray(state.index && state.index.snapshots).find((item) => String(item.id) === event.target.value);
    if (!entry) return;
    try {
      byId("error-state").hidden = true;
      await loadSnapshot(entry);
    } catch (error) {
      byId("error-state").hidden = false;
      byId("error-state").textContent = `Unable to load the selected snapshot: ${error.message}`;
    }
  });

  for (const id of ["search-input", "rank-filter", "spf-filter", "spf-qualifier-filter", "dmarc-filter", "provider-filter", "dnssec-filter", "securitytxt-filter", "content-validity-filter", "tls-filter"]) {
    byId(id).addEventListener(id === "search-input" ? "input" : "change", () => { state.page = 1; getFilteredDomains(); });
  }
  byId("previous-page").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); renderTable(); });
  byId("next-page").addEventListener("click", () => { state.page += 1; renderTable(); });
  byId("download-csv").addEventListener("click", exportCSV);
  byId("download-json").addEventListener("click", exportJSON);
  initialize();
})();
