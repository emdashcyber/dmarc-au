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
    rawArchive: null,
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
      valid: ["Valid", "good"],
      valid_legacy: ["Valid · legacy path", "warn"],
      expired: ["Expired", "bad"],
      invalid: ["Invalid", "bad"],
      insecure_transport: ["HTTP only", "warn"],
      outside_top_1m: [">1M", "warn"],
      in_top_1m: ["Top 1M", "good"],
      present: ["Present", "good"],
      response: ["Responded", "good"],
      certificate_expired: ["Expired certificate", "bad"],
      certificate_not_yet_valid: ["Not yet valid", "bad"],
      certificate_name_mismatch: ["Name mismatch", "bad"],
      certificate_untrusted: ["Untrusted certificate", "bad"],
      tls_error: ["TLS error", "warn"],
      request_error: ["Request error", "warn"],
      redirect_limit: ["Redirect limit", "warn"],
      blocked_destination: ["Blocked target", "warn"],
      unavailable: ["Unavailable", "dim"],
      not_collected: ["Not collected", "dim"],
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
    result.dnssec = { secure: 0, unsigned: 0, broken: 0, lookup_error: 0, unknown: 0 };
    result.mx_dnssec = { secure: 0, unsigned: 0, broken: 0, lookup_error: 0, unknown: 0 };
    result.dkim = { found: 0, no_match: 0, incomplete: 0 };
    for (const domain of domains) {
      const outcome = domain.spf && domain.spf.terminal && domain.spf.terminal.outcome;
      if (outcome) result.spf_qualifiers[outcome] = (result.spf_qualifiers[outcome] || 0) + 1;
      const policy = domain.dmarc && domain.dmarc.policy && domain.dmarc.policy.p;
      if (policy) result.dmarc_policies[String(policy).toLowerCase()] = (result.dmarc_policies[String(policy).toLowerCase()] || 0) + 1;
      const dnssecStatus = domain.dnssec && domain.dnssec.status;
      if (Object.hasOwn(result.dnssec, dnssecStatus)) result.dnssec[dnssecStatus] += 1;
      for (const host of safeArray(domain.mx && domain.mx.hosts)) {
        const hostStatus = host && host.dnssec_status;
        if (Object.hasOwn(result.mx_dnssec, hostStatus)) result.mx_dnssec[hostStatus] += 1;
      }
      const dkimStatus = domain.dkim && domain.dkim.status;
      if (Object.hasOwn(result.dkim, dkimStatus)) result.dkim[dkimStatus] += 1;
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
    const currentRanked = summary.rank_status && Number.isFinite(Number(summary.rank_status.in_top_1m))
      ? Number(summary.rank_status.in_top_1m)
      : snapshot.source && snapshot.source.au_entry_count !== undefined
        ? Number(snapshot.source.au_entry_count)
        : total;
    const enforcement = policyCount(summary, "reject") + policyCount(summary, "quarantine");
    const hardFail = Number(summary.spf_qualifiers && summary.spf_qualifiers.fail || 0);
    const webTls = summary.web_tls || {};
    const securityTxt = summary.security_txt || {};
    const webDns = summary.web_dns || {};
    const effectiveCaa = webDns.caa_effective || {};
    const upgrades = summary.https_upgrade || {};
    const headers = summary.security_headers || {};
    const items = [
      { label: "Tracked .au names", value: count(total), foot: "current rankings plus retained roster", className: "accent" },
      { label: "In current top 1M", value: count(currentRanked), percent: ratio(currentRanked, total), foot: "ranked names in this Tranco list" },
      { label: "Enforcement policy", value: count(enforcement), percent: ratio(enforcement, total), foot: "p=reject or p=quarantine", className: "good" },
      { label: "SPF hard fail", value: count(hardFail), percent: ratio(hardFail, total), foot: "effective -all ending" },
      { label: "Valid HTTPS", value: count(webTls.valid), percent: ratio(webTls.valid, total), foot: "certificate verified at scan time", className: "good" },
      { label: "Valid security.txt", value: count(Number(securityTxt.valid || 0) + Number(securityTxt.valid_legacy || 0)), foot: "required fields, expiry, UTF-8, HTTPS" },
      { label: "Effective CAA", value: count(effectiveCaa.present), foot: "direct or inherited from an ancestor" },
      { label: "Active HSTS", value: count(upgrades.hsts_active), foot: `${count(headers["content-security-policy"])} also publish CSP` },
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

  function drawSignalsChart(snapshot) {
    const target = byId("signals-chart");
    target.replaceChildren();
    const summary = summaryOf(snapshot);
    const dnssec = summary.dnssec || {};
    const mxDnssec = summary.mx_dnssec || {};
    const dkim = summary.dkim || {};
    const rows = [
      { label: "DKIM selector match", value: Number(dkim.found || 0), tone: "reject" },
      { label: "DKIM no common match", value: Number(dkim.no_match || 0), tone: "missing" },
      { label: "DKIM lookup incomplete", value: Number(dkim.incomplete || 0), tone: "quarantine" },
      { label: "DNSSEC secure", value: Number(dnssec.secure || 0), tone: "reject" },
      { label: "DNSSEC unsigned", value: Number(dnssec.unsigned || 0), tone: "none" },
      { label: "DNSSEC broken / error", value: Number(dnssec.broken || 0) + Number(dnssec.lookup_error || 0), tone: "missing" },
      { label: "MX targets unsigned", value: Number(mxDnssec.unsigned || 0), tone: "none" },
      { label: "MX DNSSEC broken / error", value: Number(mxDnssec.broken || 0) + Number(mxDnssec.lookup_error || 0), tone: "quarantine" },
    ];
    const scale = Math.max(1, ...rows.map((item) => item.value));
    for (const item of rows) {
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
    target.setAttribute("aria-label", "DNSSEC chain states and common DKIM selector probe counts");
  }

  function drawHistoryChart() {
    const target = byId("history-chart");
    target.replaceChildren();
    const caption = byId("history-caption");
    const history = safeArray(state.index && state.index.snapshots)
      .slice()
      .sort((a, b) => new Date(a.generated_at) - new Date(b.generated_at));
    if (history.length < 2) {
      caption.textContent = "Historical trend appears after more scan snapshots are collected.";
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
    caption.textContent = `Showing the latest ${count(visible.length)} of ${count(history.length)} scan snapshots.`;
  }

  function drawWebHistoryChart() {
    const target = byId("web-history-chart");
    target.replaceChildren();
    const caption = byId("web-history-caption");
    const history = safeArray(state.index && state.index.snapshots)
      .slice()
      .sort((a, b) => new Date(a.generated_at) - new Date(b.generated_at));
    if (!history.length) {
      caption.textContent = "Web trends appear after snapshots are collected.";
      return;
    }
    const visible = history.slice(-52);
    for (let index = 0; index < visible.length; index += 1) {
      const item = visible[index];
      const summary = item.summary || {};
      const total = Number(item.domain_count || summary.domain_count || 0);
      const tls = Number(summary.web_tls && summary.web_tls.valid || 0);
      const security = Number(summary.security_txt && summary.security_txt.valid || 0)
        + Number(summary.security_txt && summary.security_txt.valid_legacy || 0);
      const hsts = Number(summary.https_upgrade && summary.https_upgrade.hsts_active || 0);
      const caa = Number(summary.web_dns && summary.web_dns.caa_effective && summary.web_dns.caa_effective.present || 0);
      const point = el("div", "history-point history-point-pair");
      point.tabIndex = 0;
      point.dataset.latest = String(index === visible.length - 1);
      point.dataset.label = `${dateLabel(item.generated_at)} · TLS ${ratio(tls, total)} · security.txt ${ratio(security, total)} · HSTS ${ratio(hsts, total)} · CAA ${ratio(caa, total)}`;
      const bars = el("div", "history-bars");
      for (const [name, value] of [["tls", tls], ["security", security], ["hsts", hsts], ["caa", caa]]) {
        const bar = el("div", `history-bar history-bar-${name}`);
        bar.style.height = `${Math.max(2, total ? (value / total) * 100 : 0)}%`;
        bars.append(bar);
      }
      point.append(bars);
      target.append(point);
    }
    caption.textContent = `${count(visible.length)} of ${count(history.length)} snapshots · TLS / security.txt / HSTS / CAA`;
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
    for (const item of safeArray(domain && domain.web_provider_clues)) {
      if (!item || !item.name) continue;
      entries.push({
        role: "web",
        name: String(item.name),
        hosts: safeArray(item.observed_hosts),
        headers: safeArray(item.observed_headers),
      });
    }
    return entries;
  }

  function populateProviderFilter() {
    const select = byId("provider-filter");
    select.replaceChildren();
    const anyOption = el("option", "", "Any service");
    anyOption.value = "all";
    select.append(anyOption);
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
    const fields = [
      domain.domain,
      domain.rank_display,
      domain.spf && domain.spf.record,
      domain.dmarc && domain.dmarc.record,
      domain.web && domain.web.page && domain.web.page.title,
    ];
    for (const item of providerNames(domain)) fields.push(item.name, ...item.hosts);
    const headers = domain.web && domain.web.headers || {};
    for (const value of Object.values(headers)) fields.push(...(Array.isArray(value) ? value : [value]));
    const webDns = domain.web_dns || {};
    for (const key of ["a", "aaaa", "cname", "https"]) {
      fields.push(...safeArray(webDns[key] && webDns[key].records));
      for (const link of safeArray(webDns[key] && webDns[key].cname_chain)) {
        fields.push(link && link.owner, ...safeArray(link && link.target));
      }
    }
    fields.push(...safeArray(domain.spf && domain.spf.service_targets));
    for (const host of safeArray(domain.mx && domain.mx.hosts)) fields.push(host && host.hostname);
    for (const selector of safeArray(domain.dkim && domain.dkim.selectors)) {
      if (selector) fields.push(selector.selector, ...safeArray(selector.records));
    }
    fields.push(...safeArray(domain.runtime_diagnostics));
    return fields.filter(Boolean).join(" ").toLowerCase();
  }

  function matchesFilters(domain, index) {
    const query = byId("search-input").value.trim().toLowerCase();
    const spfStatus = byId("spf-filter").value;
    const qualifier = byId("spf-qualifier-filter").value;
    const dmarcPolicy = byId("dmarc-filter").value;
    const provider = byId("provider-filter").value;
    const dnssecState = byId("dnssec-filter").value;
    const dkimState = byId("dkim-filter").value;
    const rankState = byId("rank-filter").value;
    const httpsState = byId("https-filter").value;
    const securityTxtState = byId("securitytxt-filter").value;
    const hstsState = byId("hsts-filter").value;
    const caaState = byId("caa-filter").value;
    const ipv6State = byId("ipv6-filter").value;
    const webDnsState = byId("web-dns-filter").value;
    const headerState = byId("header-filter").value;
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
    if (provider !== "all") {
      const hasProvider = providerNames(domain).some((item) => item.name === provider);
      if (!hasProvider) return false;
    }
    if (dnssecState !== "all" && (!domain.dnssec || domain.dnssec.status !== dnssecState)) return false;
    if (dkimState !== "all" && (!domain.dkim || domain.dkim.status !== dkimState)) return false;
    if (rankState !== "all" && (domain.rank_status || "in_top_1m") !== rankState) return false;
    if (httpsState !== "all" && (!domain.web || !domain.web.tls || domain.web.tls.status !== httpsState)) return false;
    if (securityTxtState !== "all" && (!domain.security_txt || domain.security_txt.status !== securityTxtState)) return false;
    const hsts = domain.web && domain.web.https_upgrade && domain.web.https_upgrade.hsts;
    if (hstsState === "active" && !(hsts && hsts.active)) return false;
    if (hstsState === "inactive" && (hsts && hsts.active)) return false;
    const caa = domain.web_dns && domain.web_dns.caa && domain.web_dns.caa.effective;
    if (caaState !== "all" && (!caa || caa.status !== (caaState === "present" ? "present" : caaState))) return false;
    const ipv6 = domain.web_dns && domain.web_dns.aaaa;
    if (ipv6State !== "all" && (!ipv6 || ipv6.status !== (ipv6State === "present" ? "present" : ipv6State))) return false;
    if (webDnsState !== "all" && (!domain.web_dns || !domain.web_dns[webDnsState] || domain.web_dns[webDnsState].status !== "present")) return false;
    if (headerState !== "all" && !(domain.web && domain.web.header_presence && domain.web.header_presence[headerState])) return false;
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
      const role = item.role === "outbound" ? "Send" : item.role === "inbound" ? "Receive" : item.role === "reporting" ? "Reports" : "Web";
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

  function makeHttpsCell(domain) {
    const cell = el("div", "posture-cell");
    const web = domain.web || {};
    const tls = web.tls || {};
    cell.append(makePill(tls.status || "unavailable"));
    const upgrade = web.https_upgrade || {};
    const signs = [];
    if (upgrade.redirects_to_https) signs.push("redirect");
    if (upgrade.meta_refresh_to_https) signs.push("meta refresh");
    if (upgrade.hsts && upgrade.hsts.active) signs.push(`HSTS ${upgrade.hsts.max_age}s`);
    cell.append(el("div", "domain-meta", signs.length ? signs.join(" · ") : "No HTTPS upgrade observed"));
    return cell;
  }

  function makeSecurityTxtCell(domain) {
    const cell = el("div", "posture-cell");
    const securityTxt = domain.security_txt || {};
    cell.append(makePill(securityTxt.status || "not_collected"));
    if (securityTxt.preferred_path) cell.append(el("div", "domain-meta", securityTxt.preferred_path));
    return cell;
  }

  function makeWebDnsCell(domain) {
    const cell = el("div", "extra-list web-dns-list");
    const dns = domain.web_dns || {};
    const a = safeArray(dns.a && dns.a.records).length;
    const aaaa = safeArray(dns.aaaa && dns.aaaa.records).length;
    const caa = dns.caa && dns.caa.effective || {};
    const cname = safeArray(dns.cname && dns.cname.records);
    cell.append(el("span", `extra-chip ${a ? "good" : ""}`, `A ${a}`));
    cell.append(el("span", `extra-chip ${aaaa ? "good" : ""}`, `AAAA ${aaaa}`));
    if (cname.length) cell.append(el("span", "extra-chip", "CNAME"));
    cell.append(el("span", `extra-chip ${caa.status === "present" ? "good" : caa.status === "lookup_error" ? "warn" : ""}`, `CAA ${caa.status === "present" ? caa.source || "yes" : caa.status === "lookup_error" ? "error" : "none"}`));
    return cell;
  }

  function makeExtras(domain) {
    const wrapper = el("div", "extra-list");
    const dnssecStatus = domain.dnssec && domain.dnssec.status || "unknown";
    const dnssecLabels = {
      secure: ["DNSSEC secure", "good"],
      unsigned: ["DNSSEC unsigned", "warn"],
      broken: ["DNSSEC broken", "bad"],
      lookup_error: ["DNSSEC lookup error", "warn"],
      unknown: ["DNSSEC unknown", ""],
    };
    const [dnssecLabel, dnssecTone] = dnssecLabels[dnssecStatus] || dnssecLabels.unknown;
    wrapper.append(el("span", `extra-chip ${dnssecTone}`, dnssecLabel));
    const mxIssues = safeArray(domain.mx && domain.mx.hosts).filter((host) => host && ["broken", "lookup_error"].includes(host.dnssec_status)).length;
    if (mxIssues) wrapper.append(el("span", "extra-chip bad", `MX DNSSEC issue ×${mxIssues}`));
    const mxUnsigned = safeArray(domain.mx && domain.mx.hosts).filter((host) => host && host.dnssec_status === "unsigned").length;
    if (mxUnsigned) wrapper.append(el("span", "extra-chip warn", `MX targets unsigned ×${mxUnsigned}`));
    const dkim = domain.dkim || {};
    if (dkim.status === "found") {
      wrapper.append(el("span", "extra-chip good", `DKIM ${safeArray(dkim.found_selectors).length} selector matches`));
    } else if (dkim.status === "incomplete") {
      wrapper.append(el("span", "extra-chip", "DKIM probe incomplete"));
    } else {
      wrapper.append(el("span", "extra-chip", "No common DKIM match"));
    }
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
    cell.colSpan = 10;
    const content = el("div", "detail-content");
    const spf = domain.spf || {};
    const dmarc = domain.dmarc || {};
    const terminal = spf.terminal;
    appendDetailBlock(content, "Current and last-known rank", {
      current_status: domain.rank_status,
      current_global_rank: domain.rank,
      current_display: domain.rank_display,
      current_au_position: domain.au_rank,
      current_au_total: domain.au_rank_total,
      last_global_rank: domain.last_rank,
      last_au_position: domain.last_au_rank,
      last_rank_list_id: domain.last_rank_list_id,
      last_ranked_at: domain.last_ranked_at,
      first_seen_at: domain.first_seen_at,
    });
    const web = domain.web || {};
    appendDetailBlock(content, "HTTP and HTTPS HEAD / GET observations", {
      page: web.page,
      http: web.requests && web.requests.http,
      https: web.requests && web.requests.https,
    }, true);
    appendDetailBlock(content, "HTTPS upgrade evidence", web.https_upgrade || {});
    appendDetailBlock(content, "TLS certificate and negotiated connection", web.tls || {});
    appendDetailBlock(content, "security.txt resources and validation", domain.security_txt || {}, true);
    appendDetailBlock(content, "Selected HTTPS headers and observations", {
      headers: web.headers,
      header_presence: web.header_presence,
      findings: web.header_findings,
      cookie_names_and_attributes: web.headers && web.headers["set-cookie-metadata"],
      web_provider_clues: domain.web_provider_clues,
    }, true);
    appendDetailBlock(content, "Web DNS evidence", domain.web_dns || {}, true);
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
      dkim: domain.dkim,
      runtime_diagnostics: domain.runtime_diagnostics,
      nameservers: domain.nameservers,
      soa: domain.soa,
      provider_clues: domain.provider_clues,
      web_provider_clues: domain.web_provider_clues,
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
      const rank = el("td", "rank-cell");
      rank.append(el("span", "rank-primary", domain.rank_display || (domain.rank ? `#${count(domain.rank)}` : ">1,000,000")));
      if (domain.au_rank) rank.append(el("span", "domain-meta", `.au ${count(domain.au_rank)} / ${count(domain.au_rank_total)}`));
      else if (domain.last_rank) rank.append(el("span", "domain-meta", `last #${count(domain.last_rank)} · .au ${count(domain.last_au_rank)}`));
      const domainCell = el("td");
      domainCell.append(el("div", "domain-name", domain.domain));
      const title = domain.web && domain.web.page && domain.web.page.title;
      if (title) domainCell.append(el("div", "domain-meta page-title", title));
      const detailButton = el("button", "detail-toggle", "Inspect posture");
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

      const httpsCell = el("td");
      httpsCell.append(makeHttpsCell(domain));
      const securityCell = el("td");
      securityCell.append(makeSecurityTxtCell(domain));
      const webDnsCell = el("td");
      webDnsCell.append(makeWebDnsCell(domain));

      const serviceCell = el("td");
      serviceCell.append(makeServiceChips(domain));
      const mxCell = el("td");
      mxCell.append(makeMxList(domain));
      const extraCell = el("td");
      extraCell.append(makeExtras(domain));
      row.append(rank, domainCell, spfCell, dmarcCell, httpsCell, securityCell, webDnsCell, serviceCell, mxCell, extraCell);

      const details = createDetailRow(domain);
      details.hidden = true;
      detailButton.addEventListener("click", () => {
        details.hidden = !details.hidden;
        detailButton.setAttribute("aria-expanded", String(!details.hidden));
        detailButton.textContent = details.hidden ? "Inspect posture" : "Hide details";
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
      cell.colSpan = 10;
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
    byId("download-raw").hidden = !state.hasData || !state.rawArchive;
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
    if (snapshot.schema_version !== 3) throw new Error(`Unsupported snapshot schema ${snapshot.schema_version}`);
    if (!Array.isArray(snapshot.domains)) throw new Error("Snapshot is missing its domain list");
    state.snapshot = snapshot;
    state.rawArchive = snapshot.raw_archive || entry.raw_archive || null;
    if (state.rawArchive) byId("download-raw").href = new URL(state.rawArchive, DATA_INDEX_URL).href;
    state.domains = snapshot.domains.slice().sort((left, right) => {
      const leftRank = left.rank === null || left.rank === undefined ? Number.MAX_SAFE_INTEGER : Number(left.rank);
      const rightRank = right.rank === null || right.rank === undefined ? Number.MAX_SAFE_INTEGER : Number(right.rank);
      const leftLast = Number(left.last_rank || Number.MAX_SAFE_INTEGER);
      const rightLast = Number(right.last_rank || Number.MAX_SAFE_INTEGER);
      if (leftRank !== rightRank) return leftRank - rightRank;
      if (leftRank === Number.MAX_SAFE_INTEGER && leftLast !== rightLast) return leftLast - rightLast;
      return String(left.domain).localeCompare(String(right.domain));
    });
    state.searchIndex = state.domains.map(searchableText);
    state.hasData = true;
    state.page = 1;
    setSnapshotMeta(snapshot);
    setMetricCards(snapshot);
    drawPolicyChart(snapshot);
    drawSignalsChart(snapshot);
    drawWebHistoryChart();
    populateProviderFilter();
    getFilteredDomains();
    byId("empty-state").hidden = state.domains.length !== 0;
  }

  async function initialize() {
    try {
      const response = await fetch(DATA_INDEX_URL, { cache: "no-cache" });
      if (!response.ok) throw new Error(`Index request failed (${response.status})`);
      state.index = await response.json();
      if (state.index.schema_version !== 3) throw new Error(`Unsupported data index schema ${state.index.schema_version}`);
      drawHistoryChart();
      fillSnapshotSelector();
      const snapshots = safeArray(state.index.snapshots).slice().sort((a, b) => new Date(b.generated_at) - new Date(a.generated_at));
      if (!snapshots.length) {
        state.hasData = false;
        byId("metrics").replaceChildren();
        byId("policy-chart").textContent = "No scans yet";
        byId("signals-chart").textContent = "No scans yet";
        byId("web-history-chart").textContent = "No scans yet";
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
      cell.colSpan = 10;
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
    const headers = [
      "domain", "rank_status", "rank_display", "tranco_rank", "au_rank", "au_rank_total",
      "last_rank", "last_au_rank", "last_rank_list_id", "last_ranked_at", "first_seen_at",
      "spf_status", "spf_valid", "spf_record", "spf_terminal", "spf_dns_lookups", "spf_void_lookups", "spf_mechanisms", "spf_services",
      "dmarc_status", "dmarc_valid", "dmarc_record", "dmarc_location", "dmarc_source", "dmarc_policy_p", "dmarc_policy_sp", "dmarc_policy_np", "dmarc_alignment", "dmarc_test_mode", "dmarc_reporting_uris",
      "outbound_services", "inbound_services", "reporting_services", "web_services", "web_service_evidence",
      "mx_hosts", "mta_sts_status", "tls_reporting_status", "dnssec_status", "dnssec_evidence", "mx_dnssec_evidence", "dkim_status", "dkim_found_selectors", "nameservers", "soa",
      "page_title", "http_head", "http_get", "https_head", "https_get", "https_upgrade", "tls_status", "tls_certificates",
      "security_txt_status", "security_txt_preferred_path", "security_txt_preferred_scheme", "security_txt_validation", "security_txt_text",
      "security_headers_source", "security_headers", "security_header_presence", "security_header_findings", "web_dns_a", "web_dns_aaaa", "web_dns_cname", "web_dns_https", "caa_direct", "caa_effective", "errors",
    ];
    const rows = [headers];
    const serialize = (value) => value === null || value === undefined ? "" : typeof value === "object" ? JSON.stringify(value) : value;
    for (const domain of state.filtered) {
      const providers = domain.provider_clues || {};
      const names = (role) => safeArray(providers[role]).map((item) => item.name).join("; ");
      const securityProviders = safeArray(domain.web_provider_clues);
      const web = domain.web || {};
      const securityTxt = domain.security_txt || {};
      const preferredResource = safeArray(securityTxt.resources).find((item) => item.path === securityTxt.preferred_path && item.scheme === securityTxt.preferred_scheme);
      const dns = domain.web_dns || {};
      const terminal = domain.spf && domain.spf.terminal;
      rows.push([
        domain.domain, domain.rank_status, domain.rank_display, domain.rank, domain.au_rank, domain.au_rank_total,
        domain.last_rank, domain.last_au_rank, domain.last_rank_list_id, domain.last_ranked_at, domain.first_seen_at,
        domain.spf && domain.spf.status, domain.spf && domain.spf.valid, domain.spf && domain.spf.record,
        terminal && `${terminal.token || "implicit"} · ${terminal.outcome}`, domain.spf && domain.spf.dns_lookups,
        domain.spf && domain.spf.void_dns_lookups, serialize(domain.spf && domain.spf.mechanisms),
        safeArray(domain.spf && domain.spf.service_targets).join("; "),
        domain.dmarc && domain.dmarc.status, domain.dmarc && domain.dmarc.valid, domain.dmarc && domain.dmarc.record,
        domain.dmarc && domain.dmarc.location, domain.dmarc && domain.dmarc.discovery_source,
        domain.dmarc && domain.dmarc.policy && domain.dmarc.policy.p,
        domain.dmarc && domain.dmarc.policy && domain.dmarc.policy.sp,
        domain.dmarc && domain.dmarc.policy && domain.dmarc.policy.np,
        serialize(domain.dmarc && domain.dmarc.alignment), domain.dmarc && domain.dmarc.test_mode,
        serialize(domain.dmarc && domain.dmarc.reporting_uris),
        names("outbound"), names("inbound"), names("reporting"),
        securityProviders.map((item) => item.name).join("; "), serialize(securityProviders),
        safeArray(domain.mx && domain.mx.hosts).map((item) => item.hostname).join("; "),
        domain.mta_sts && domain.mta_sts.status, domain.tls_reporting && domain.tls_reporting.status,
        domain.dnssec && domain.dnssec.status, serialize(domain.dnssec),
        serialize(safeArray(domain.mx && domain.mx.hosts).map((host) => ({ hostname: host.hostname, status: host.dnssec_status, evidence: host.dnssec_evidence }))),
        domain.dkim && domain.dkim.status, safeArray(domain.dkim && domain.dkim.found_selectors).join("; "),
        safeArray(domain.nameservers && domain.nameservers.nameservers || domain.nameservers).join("; "), serialize(domain.soa),
        web.page && web.page.title,
        serialize(web.requests && web.requests.http && web.requests.http.head),
        serialize(web.requests && web.requests.http && web.requests.http.get),
        serialize(web.requests && web.requests.https && web.requests.https.head),
        serialize(web.requests && web.requests.https && web.requests.https.get),
        serialize(web.https_upgrade), web.tls && web.tls.status, serialize(web.tls && web.tls.certificates),
        securityTxt.status, securityTxt.preferred_path, securityTxt.preferred_scheme,
        serialize(preferredResource && preferredResource.validation), preferredResource ? preferredResource.raw_text : securityTxt.raw_text,
        web.headers_source, serialize(web.headers), serialize(web.header_presence), serialize(web.header_findings),
        serialize(dns.a), serialize(dns.aaaa), serialize(dns.cname), serialize(dns.https),
        serialize(dns.caa && dns.caa.direct), serialize(dns.caa && dns.caa.effective), serialize(domain.errors),
      ]);
    }
    const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    const id = state.snapshot && state.snapshot.generated_at ? state.snapshot.generated_at.slice(0, 10) : "snapshot";
    downloadFile(`au-security-posture-${id}-filtered.csv`, `\uFEFF${csv}`, "text/csv;charset=utf-8");
  }

  function exportJSON() {
    const id = state.snapshot && state.snapshot.generated_at ? state.snapshot.generated_at.slice(0, 10) : "snapshot";
    downloadFile(`au-security-posture-${id}.json`, JSON.stringify(state.snapshot, null, 2), "application/json;charset=utf-8");
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

  for (const id of [
    "search-input", "rank-filter", "spf-filter", "spf-qualifier-filter", "dmarc-filter",
    "provider-filter", "dnssec-filter", "dkim-filter", "https-filter", "securitytxt-filter",
    "hsts-filter", "caa-filter", "ipv6-filter", "web-dns-filter", "header-filter",
  ]) {
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
