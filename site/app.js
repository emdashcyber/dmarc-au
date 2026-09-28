(() => {
  "use strict";

  const DATA_INDEX_URL = new URL("./data/index.json", document.baseURI);
  const PAGE_SIZE = 25;
  const state = {
    index: null,
    snapshot: null,
    domains: [],
    searchIndex: [],
    filtered: [],
    page: 1,
    hasData: false,
  };

  const byId = (id) => document.getElementById(id);
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };
  const count = (value) => Number(value || 0).toLocaleString("en-AU");
  const ratio = (numerator, denominator) => denominator ? `${Math.round((numerator / denominator) * 100)}%` : "—";
  const safeArray = (value) => Array.isArray(value) ? value : [];

  function dateLabel(value, includeTime = false) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("en-AU", {
      timeZone: "Australia/Sydney",
      day: "2-digit",
      month: "short",
      year: "numeric",
      ...(includeTime ? { hour: "2-digit", minute: "2-digit", hour12: false } : {}),
    }).format(date);
  }

  function displayStatus(status) {
    const values = {
      present_valid: ["Valid", "good"],
      present_invalid: ["Invalid", "bad"],
      absent: ["Absent", "dim"],
      lookup_error: ["Lookup error", "warn"],
      validated: ["Validated", "good"],
      not_validated: ["Not validated", "warn"],
      unknown: ["Unknown", "dim"],
    };
    return values[status] || ["Unknown", "dim"];
  }

  function makePill(status, labelOverride) {
    const [label, tone] = displayStatus(status);
    return el("span", `status-pill ${tone}`, labelOverride || label);
  }

  function summaryOf(snapshot) {
    if (snapshot && snapshot.summary) return snapshot.summary;
    const domains = safeArray(snapshot && snapshot.domains);
    const result = { domain_count: domains.length };
    for (const type of ["spf", "dmarc", "mx", "mta_sts", "tls_reporting"]) {
      result[type] = { present_valid: 0, present_invalid: 0, absent: 0, lookup_error: 0 };
      for (const domain of domains) {
        const status = domain && domain[type] && domain[type].status;
        if (Object.hasOwn(result[type], status)) result[type][status] += 1;
      }
    }
    result.spf_qualifiers = {};
    result.dmarc_policies = {};
    for (const domain of domains) {
      const outcome = domain.spf && domain.spf.terminal && domain.spf.terminal.outcome;
      if (outcome) result.spf_qualifiers[outcome] = (result.spf_qualifiers[outcome] || 0) + 1;
      const policy = domain.dmarc && domain.dmarc.policy && domain.dmarc.policy.p;
      if (policy) result.dmarc_policies[String(policy).toLowerCase()] = (result.dmarc_policies[String(policy).toLowerCase()] || 0) + 1;
    }
    return result;
  }

  function statusCount(summary, type, status) {
    return Number(summary && summary[type] && summary[type][status] || 0);
  }

  function policyCount(summary, policy) {
    return Number(summary && summary.dmarc_policies && summary.dmarc_policies[policy] || 0);
  }

  function setMetricCards(snapshot) {
    const metrics = byId("metrics");
    metrics.replaceChildren();
    const summary = summaryOf(snapshot);
    const total = Number(summary.domain_count || safeArray(snapshot.domains).length);
    const dmarcFound = statusCount(summary, "dmarc", "present_valid") + statusCount(summary, "dmarc", "present_invalid");
    const enforcement = policyCount(summary, "reject") + policyCount(summary, "quarantine");
    const hardFail = Number(summary.spf_qualifiers && summary.spf_qualifiers.fail || 0);
    const items = [
      { label: "Ranked .au domains", value: count(total), foot: "from the Tranco top‑1M list", className: "accent" },
      { label: "DMARC records", value: count(dmarcFound), percent: ratio(dmarcFound, total), foot: `${ratio(dmarcFound, total)} of scanned names publish a record` },
      { label: "Enforcement policy", value: count(enforcement), percent: ratio(enforcement, total), foot: "p=reject or p=quarantine", className: "good" },
      { label: "SPF hard fail", value: count(hardFail), percent: ratio(hardFail, total), foot: "effective -all ending" },
    ];
    for (const item of items) {
      const card = el("article", `metric-card ${item.className || ""}`);
      card.append(el("span", "metric-label", item.label));
      const value = el("strong", "metric-value");
      value.append(document.createTextNode(item.value));
      if (item.percent) value.append(el("span", "metric-percent", item.percent));
      card.append(value, el("span", "metric-foot", item.foot));
      metrics.append(card);
    }
  }

  function drawPolicyChart(snapshot) {
    const target = byId("policy-chart");
    target.replaceChildren();
    const summary = summaryOf(snapshot);
    const total = Number(summary.domain_count || 0);
    const counts = [
      { label: "Reject", value: policyCount(summary, "reject"), tone: "reject" },
      { label: "Quarantine", value: policyCount(summary, "quarantine"), tone: "quarantine" },
      { label: "None / monitor", value: policyCount(summary, "none"), tone: "none" },
      { label: "No record", value: statusCount(summary, "dmarc", "absent"), tone: "missing" },
      { label: "Invalid / error", value: statusCount(summary, "dmarc", "present_invalid") + statusCount(summary, "dmarc", "lookup_error"), tone: "missing" },
    ];
    const scale = Math.max(1, ...counts.map((item) => item.value));
    for (const item of counts) {
      const row = el("div", "bar-row");
      row.append(el("span", "bar-label", item.label));
      const track = el("div", "bar-track");
      const fill = el("div", "bar-fill");
      fill.dataset.tone = item.tone;
      fill.style.width = `${Math.max(item.value ? 2 : 0, (item.value / scale) * 100)}%`;
      track.append(fill);
      row.append(track, el("span", "bar-value", count(item.value)));
      target.append(row);
    }
    target.setAttribute("aria-label", `DMARC policy counts across ${count(total)} domains`);
  }

  function drawHistoryChart() {
    const target = byId("history-chart");
    target.replaceChildren();
    const caption = byId("history-caption");
    const history = safeArray(state.index && state.index.snapshots)
      .slice()
      .sort((a, b) => new Date(a.generated_at) - new Date(b.generated_at));
    if (history.length < 2) {
      caption.textContent = "Historical trend appears after more snapshots are collected.";
      return;
    }
    const visible = history.slice(-52);
    for (let index = 0; index < visible.length; index += 1) {
      const item = visible[index];
      const summary = item.summary || {};
      const total = Number(item.domain_count || summary.domain_count || 0);
      const enforced = Number(summary.dmarc_policies && summary.dmarc_policies.reject || 0)
        + Number(summary.dmarc_policies && summary.dmarc_policies.quarantine || 0);
      const percentage = total ? Math.round((enforced / total) * 100) : 0;
      const point = el("div", "history-point");
      point.tabIndex = 0;
      point.dataset.latest = String(index === visible.length - 1);
      point.dataset.label = `${dateLabel(item.generated_at)} · ${percentage}% enforced`;
      const bar = el("div", "history-bar");
      bar.style.height = `${Math.max(2, percentage)}%`;
      point.append(bar);
      target.append(point);
    }
    caption.textContent = `Showing the latest ${count(visible.length)} of ${count(history.length)} weekly snapshots.`;
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
    const sorted = snapshots.slice().sort((a, b) => new Date(b.generated_at) - new Date(a.generated_at));
    for (const item of sorted) {
      const option = el("option", "", `${dateLabel(item.generated_at, true)} · ${count(item.domain_count)} domains`);
      option.value = String(item.id);
      select.append(option);
    }
    select.disabled = false;
  }

  function providerNames(domain) {
    const clues = domain && domain.provider_clues || {};
    const entries = [];
    for (const role of ["outbound", "inbound", "reporting"]) {
      for (const item of safeArray(clues[role])) {
        if (!item || !item.name) continue;
        entries.push({ role, name: String(item.name), hosts: safeArray(item.observed_hosts) });
      }
    }
    return entries;
  }

  function populateProviderFilter() {
    const select = byId("provider-filter");
    select.replaceChildren();
    select.append(el("option", "", "Any service"));
    const names = new Set();
    for (const domain of state.domains) {
      for (const item of providerNames(domain)) if (item.name !== "Unclassified") names.add(item.name);
    }
    for (const name of [...names].sort((a, b) => a.localeCompare(b))) {
      const option = el("option", "", name);
      option.value = name;
      select.append(option);
    }
    select.disabled = names.size === 0;
  }

  function searchableText(domain) {
    const fields = [domain.domain, domain.spf && domain.spf.record, domain.dmarc && domain.dmarc.record];
    for (const item of providerNames(domain)) fields.push(item.name, ...item.hosts);
    fields.push(...safeArray(domain.spf && domain.spf.service_targets));
    for (const host of safeArray(domain.mx && domain.mx.hosts)) fields.push(host && host.hostname);
    return fields.filter(Boolean).join(" ").toLowerCase();
  }

  function matchesFilters(domain, index) {
    const query = byId("search-input").value.trim().toLowerCase();
    const spfStatus = byId("spf-filter").value;
    const qualifier = byId("spf-qualifier-filter").value;
    const dmarcPolicy = byId("dmarc-filter").value;
    const provider = byId("provider-filter").value;
    if (query && !state.searchIndex[index].includes(query)) return false;
    if (spfStatus !== "all" && (!domain.spf || domain.spf.status !== spfStatus)) return false;
    if (qualifier !== "all") {
      const terminal = domain.spf && domain.spf.terminal;
      if (!terminal) return false;
      if (qualifier === "implicit") {
        if (!terminal.implicit) return false;
      } else if (terminal.outcome !== qualifier) return false;
    }
    if (dmarcPolicy !== "all") {
      if (["absent", "present_invalid", "lookup_error"].includes(dmarcPolicy)) {
        if (!domain.dmarc || domain.dmarc.status !== dmarcPolicy) return false;
      } else {
        const p = domain.dmarc && domain.dmarc.policy && String(domain.dmarc.policy.p || "").toLowerCase();
        if (p !== dmarcPolicy) return false;
      }
    }
    if (provider) {
      const hasProvider = providerNames(domain).some((item) => item.name === provider);
      if (!hasProvider) return false;
    }
    return true;
  }

  function getFilteredDomains() {
    state.filtered = state.domains.filter((domain, index) => matchesFilters(domain, index));
    const maxPage = Math.max(1, Math.ceil(state.filtered.length / PAGE_SIZE));
    state.page = Math.min(state.page, maxPage);
    renderTable();
  }

  function makeServiceChips(domain) {
    const wrapper = el("div", "service-list");
    const names = providerNames(domain);
    if (!names.length) {
      wrapper.append(el("span", "domain-meta", "No provider clue"));
      return wrapper;
    }
    const unique = [];
    const seen = new Set();
    for (const item of names) {
      const key = `${item.role}:${item.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(item);
    }
    for (const item of unique.slice(0, 3)) {
      const role = item.role === "outbound" ? "Send" : item.role === "inbound" ? "Receive" : "Reports";
      wrapper.append(el("span", `service-chip ${item.name === "Unclassified" ? "unknown" : ""}`, `${role}: ${item.name}`));
    }
    if (unique.length > 3) wrapper.append(el("span", "service-chip", `+${unique.length - 3}`));
    return wrapper;
  }

  function makeMxList(domain) {
    const cell = el("div", "mx-list");
    const mx = domain.mx || {};
    if (mx.null_mx) {
      cell.textContent = "Null MX · no inbound mail";
      return cell;
    }
    const hosts = safeArray(mx.hosts).map((item) => item && item.hostname).filter(Boolean);
    cell.textContent = hosts.length ? hosts.slice(0, 2).join("\n") : displayStatus(mx.status)[0];
    return cell;
  }

  function makeExtras(domain) {
    const wrapper = el("div", "extra-list");
    const dnssec = domain.dnssec && domain.dnssec.validated;
    wrapper.append(el("span", `extra-chip ${dnssec ? "good" : ""}`, dnssec ? "DNSSEC" : "DNSSEC ?"));
    for (const [key, label] of [["mta_sts", "MTA-STS"], ["tls_reporting", "TLS-RPT"]]) {
      const value = domain[key] || {};
      if (value.status === "present_valid") wrapper.append(el("span", "extra-chip good", label));
      else if (value.status === "present_invalid") wrapper.append(el("span", "extra-chip bad", `${label} issue`));
      else if (value.status === "lookup_error") wrapper.append(el("span", "extra-chip", `${label} error`));
    }
    return wrapper;
  }

  function appendDetailBlock(container, title, value, wide = false) {
    const block = el("section", `detail-block ${wide ? "wide" : ""}`);
    block.append(el("h4", "", title));
    if (typeof value === "string") {
      block.append(el("pre", "", value || "No published record"));
    } else if (value === null || value === undefined) {
      block.append(el("p", "", "No value reported"));
    } else {
      block.append(el("pre", "", JSON.stringify(value, null, 2)));
    }
    container.append(block);
  }

  function createDetailRow(domain) {
    const row = el("tr", "detail-row");
    const cell = el("td");
    cell.colSpan = 7;
    const content = el("div", "detail-content");
    const spf = domain.spf || {};
    const dmarc = domain.dmarc || {};
    const terminal = spf.terminal;
    appendDetailBlock(content, "SPF record", spf.record || spf.error || "No SPF record found");
    appendDetailBlock(content, "SPF ending", terminal ? {
      effective_result: terminal.label,
      explicit_all: terminal.token,
      follows_redirect: terminal.redirect_domain,
      dns_lookups: spf.dns_lookups,
      void_dns_lookups: spf.void_dns_lookups,
      mechanisms: spf.mechanisms,
      service_targets: spf.service_targets,
      warnings: spf.warnings,
    } : { status: spf.status, error: spf.error });
    appendDetailBlock(content, "DMARC record", dmarc.record || dmarc.error || "No applicable DMARC record found");
    appendDetailBlock(content, "Related DNS signals", {
      discovery_source: dmarc.discovery_source,
      dmarc_location: dmarc.location,
      dmarc_policy: dmarc.policy,
      alignment: dmarc.alignment,
      test_mode: dmarc.test_mode,
      reporting_uris: dmarc.reporting_uris,
      mx: domain.mx,
      mta_sts: domain.mta_sts,
      tls_reporting: domain.tls_reporting,
      dnssec: domain.dnssec,
      provider_clues: domain.provider_clues,
    }, true);
    if (domain.errors && Object.keys(domain.errors).length) appendDetailBlock(content, "Lookup and collection errors", domain.errors, true);
    cell.append(content);
    row.append(cell);
    return row;
  }

  function createDomainRows(domains) {
    const fragment = document.createDocumentFragment();
    for (const domain of domains) {
      const row = el("tr", "data-row");
      const rank = el("td", "rank-cell", `#${count(domain.rank)}`);
      const domainCell = el("td");
      domainCell.append(el("div", "domain-name", domain.domain));
      const detailButton = el("button", "detail-toggle", "Inspect DNS");
      detailButton.type = "button";
      detailButton.setAttribute("aria-expanded", "false");
      domainCell.append(detailButton);

      const spfCell = el("td");
      const spf = domain.spf || {};
      spfCell.append(makePill(spf.status));
      if (spf.terminal && spf.status.startsWith("present_")) {
        spfCell.append(el("div", "policy-label", spf.terminal.label));
      }

      const dmarcCell = el("td");
      const dmarc = domain.dmarc || {};
      dmarcCell.append(makePill(dmarc.status));
      const p = dmarc.policy && dmarc.policy.p;
      if (p) dmarcCell.append(el("div", "policy-label", `p=${String(p).toLowerCase()}${dmarc.discovery_source === "inherited" ? " · inherited" : ""}`));

      const serviceCell = el("td");
      serviceCell.append(makeServiceChips(domain));
      const mxCell = el("td");
      mxCell.append(makeMxList(domain));
      const extraCell = el("td");
      extraCell.append(makeExtras(domain));
      row.append(rank, domainCell, spfCell, dmarcCell, serviceCell, mxCell, extraCell);

      const details = createDetailRow(domain);
      details.hidden = true;
      detailButton.addEventListener("click", () => {
        details.hidden = !details.hidden;
        detailButton.setAttribute("aria-expanded", String(!details.hidden));
        detailButton.textContent = details.hidden ? "Inspect DNS" : "Hide details";
      });
      fragment.append(row, details);
    }
    return fragment;
  }

  function renderTable() {
    const tbody = byId("domain-rows");
    tbody.replaceChildren();
    const total = state.filtered.length;
    const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const start = (state.page - 1) * PAGE_SIZE;
    const visible = state.filtered.slice(start, start + PAGE_SIZE);
    if (!visible.length) {
      const row = el("tr");
      const cell = el("td", "empty-cell", state.hasData ? "No domains match these filters." : "No scan has been published yet.");
      cell.colSpan = 7;
      row.append(cell);
      tbody.append(row);
    } else {
      tbody.append(createDomainRows(visible));
    }
    byId("result-count").textContent = state.hasData
      ? `${count(total)} matching ${total === 1 ? "domain" : "domains"} · sorted by source rank`
      : "No scan data available";
    byId("page-label").textContent = `Page ${state.page} of ${pageCount}`;
    byId("previous-page").disabled = state.page <= 1 || total === 0;
    byId("next-page").disabled = state.page >= pageCount || total === 0;
    byId("download-csv").disabled = !state.hasData;
    byId("download-json").disabled = !state.hasData;
  }

  function setSnapshotMeta(snapshot) {
    if (!snapshot) {
      byId("snapshot-meta").textContent = "Run the workflow to collect the first scan";
      byId("feed-status").textContent = "NO SNAPSHOT YET";
      return;
    }
    const source = snapshot.source || {};
    byId("snapshot-meta").textContent = `Scanned ${dateLabel(snapshot.generated_at, true)} · Tranco ${source.list_id || "list ID unavailable"}`;
    byId("feed-status").textContent = `UPDATED ${dateLabel(snapshot.generated_at).toUpperCase()}`;
  }

  async function loadSnapshot(entry) {
    const response = await fetch(new URL(entry.path, DATA_INDEX_URL), { cache: "no-cache" });
    if (!response.ok) throw new Error(`Snapshot request failed (${response.status})`);
    const snapshot = await response.json();
    if (!Array.isArray(snapshot.domains)) throw new Error("Snapshot is missing its domain list");
    state.snapshot = snapshot;
    state.domains = snapshot.domains;
    state.searchIndex = state.domains.map(searchableText);
    state.hasData = true;
    state.page = 1;
    setSnapshotMeta(snapshot);
    setMetricCards(snapshot);
    drawPolicyChart(snapshot);
    populateProviderFilter();
    getFilteredDomains();
    byId("empty-state").hidden = state.domains.length !== 0;
  }

  async function initialize() {
    try {
      const response = await fetch(DATA_INDEX_URL, { cache: "no-cache" });
      if (!response.ok) throw new Error(`Index request failed (${response.status})`);
      state.index = await response.json();
      drawHistoryChart();
      fillSnapshotSelector();
      const snapshots = safeArray(state.index.snapshots).slice().sort((a, b) => new Date(b.generated_at) - new Date(a.generated_at));
      if (!snapshots.length) {
        state.hasData = false;
        byId("metrics").replaceChildren();
        byId("policy-chart").textContent = "No scans yet";
        state.filtered = [];
        setSnapshotMeta(null);
        byId("empty-state").hidden = false;
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
      cell.colSpan = 7;
      row.append(cell);
      byId("domain-rows").append(row);
    }
  }

  function csvCell(value) {
    const text = value === null || value === undefined ? "" : String(value);
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
    const rows = [[
      "rank", "domain", "spf_status", "spf_record", "spf_terminal", "spf_dns_lookups",
      "dmarc_status", "dmarc_policy", "dmarc_source", "outbound_services",
      "inbound_services", "reporting_services", "mx_hosts", "mta_sts_status",
      "tls_reporting_status", "dnssec_validated",
    ]];
    for (const domain of state.filtered) {
      const providers = domain.provider_clues || {};
      const names = (role) => safeArray(providers[role]).map((item) => item.name).join("; ");
      const terminal = domain.spf && domain.spf.terminal;
      rows.push([
        domain.rank,
        domain.domain,
        domain.spf && domain.spf.status,
        domain.spf && domain.spf.record,
        terminal && `${terminal.token || "implicit"} · ${terminal.outcome}`,
        domain.spf && domain.spf.dns_lookups,
        domain.dmarc && domain.dmarc.status,
        domain.dmarc && domain.dmarc.policy && domain.dmarc.policy.p,
        domain.dmarc && domain.dmarc.location,
        names("outbound"),
        names("inbound"),
        names("reporting"),
        safeArray(domain.mx && domain.mx.hosts).map((item) => item.hostname).join("; "),
        domain.mta_sts && domain.mta_sts.status,
        domain.tls_reporting && domain.tls_reporting.status,
        domain.dnssec && domain.dnssec.validated,
      ]);
    }
    const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    const id = state.snapshot && state.snapshot.generated_at ? state.snapshot.generated_at.slice(0, 10) : "snapshot";
    downloadFile(`au-mail-auth-${id}-filtered.csv`, `\uFEFF${csv}`, "text/csv;charset=utf-8");
  }

  function exportJSON() {
    const id = state.snapshot && state.snapshot.generated_at ? state.snapshot.generated_at.slice(0, 10) : "snapshot";
    downloadFile(`au-mail-auth-${id}.json`, JSON.stringify(state.snapshot, null, 2), "application/json;charset=utf-8");
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

  for (const id of ["search-input", "spf-filter", "spf-qualifier-filter", "dmarc-filter", "provider-filter"]) {
    byId(id).addEventListener(id === "search-input" ? "input" : "change", () => {
      state.page = 1;
      getFilteredDomains();
    });
  }
  byId("previous-page").addEventListener("click", () => {
    state.page = Math.max(1, state.page - 1);
    renderTable();
  });
  byId("next-page").addEventListener("click", () => {
    state.page += 1;
    renderTable();
  });
  byId("download-csv").addEventListener("click", exportCSV);
  byId("download-json").addEventListener("click", exportJSON);
  initialize();
})();
