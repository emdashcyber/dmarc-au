let viewHelpers, browser;
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const zlib = require("node:zlib");

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.listeners = {};
    this.attributes = {};
    this.value = "";
    this.textContent = "";
    this.hidden = false;
    this.disabled = false;
  }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  click() { if (!this.disabled && this.listeners.click) this.listeners.click({ target: this }); }
  remove() {}
  focus() { this.focused = true; }
}

const path = require("node:path");
const sourceFiles = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory() ? sourceFiles(path.join(dir, entry.name)) : entry.name.endsWith(".astro") ? [path.join(dir, entry.name)] : []);
const html = sourceFiles("src").map((file) => fs.readFileSync(file, "utf8")).join("\n");
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);

const domains = [
  {
    rank: 2, rank_status: "in_top_1m", rank_display: "#2", au_rank: 1, au_rank_total: 2, last_rank: 2,
    domain: "portal.example.au",
    spf: { status: "present_valid", valid: true, record: "v=spf1 -all", terminal: { token: "-all", outcome: "fail", label: "Hard fail (-all)" } },
    dmarc: { status: "present_valid", valid: true, record: "v=DMARC1; p=reject", policy: { p: "reject" }, discovery_source: "direct" },
    provider_clues: { outbound: [{ name: "Google Workspace", observed_hosts: ["_spf.google.com"] }] },
    security_txt: { availability: "present", content_validity: "valid", freshness: "expired", tls_certificate: "valid", request: { fallback_attempted: false, redirects_to_https: true, cross_host_redirect: true, status_code: 200, final_url: "https://www.portal.example.au/.well-known/security.txt", attempts: [{ hops: [{ headers: { server: "nginx", "content-security-policy": "default-src 'self'" } }] }] }, validation: { contact_present: true, expires_present: true, expired: true, signature_status: "not_signed", reasons: [] } },
    mx: { status: "present_valid", hosts: [{ hostname: "mx.example.au", dnssec_status: "secure" }] },
    mta_sts: { status: "absent" }, tls_reporting: { status: "absent" }, dnssec: { status: "secure", validated: true }, nameservers: ["ns1.example.au"], soa: { mname: "ns1.example.au" }, errors: {},
  },
  {
    rank: 5, rank_status: "in_top_1m", rank_display: "#5", au_rank: 2, au_rank_total: 2, last_rank: 5,
    domain: "mail.example.gov.au", spf: { status: "absent" }, dmarc: { status: "absent" },
    provider_clues: { inbound: [{ name: "Microsoft 365", observed_hosts: ["mail.protection.outlook.com"] }] },
    security_txt: { availability: "absent", content_validity: "not_assessable", tls_certificate: "not_observed", request: { fallback_attempted: false, redirects_to_https: false, attempts: [{ status_code: 404, hops: [] }] }, validation: { reasons: [] } },
    mx: { status: "absent", hosts: [] }, mta_sts: { status: "absent" }, tls_reporting: { status: "absent" }, dnssec: { status: "unsigned" }, errors: {},
  },
  {
    rank: null, rank_status: "outside_top_1m", rank_display: ">1,000,000", au_rank: null, au_rank_total: 2, last_rank: 99, last_au_rank: 7,
    domain: "archived.example.au", spf: { status: "lookup_error" }, dmarc: { status: "lookup_error" }, provider_clues: {},
    security_txt: { availability: "lookup_error", content_validity: "not_assessable", tls_certificate: "error", request: { fallback_attempted: true, redirects_to_https: false, attempts: [{ state: "lookup_error", hops: [] }] }, validation: { reasons: [] } },
    mx: { status: "lookup_error", hosts: [] }, dnssec: { status: "lookup_error" }, errors: {},
  },
];
domains[0].security_txt.request.https_response_received = true;
const summary = {
  domain_count: domains.length,
  rank_status: { in_top_1m: 2, outside_top_1m: 1 },
  dmarc: { present_valid: 1, present_invalid: 0, absent: 1, lookup_error: 1 },
  spf: { present_valid: 4, present_invalid: 0, absent: 1, lookup_error: 1 },
  dmarc_policies: { reject: 1 }, spf_qualifiers: { fail: 2, softfail: 1, neutral: 1, pass: 0 },
  security_txt: { present: 1, absent: 1, lookup_error: 1, http_error: 0 },
  security_txt_content_validity: { valid: 1, invalid: 0, not_assessable: 2 },
  security_txt_freshness: { current: 0, expired: 1, unknown: 2 },
  security_txt_tls_certificate: { valid: 1, invalid: 0, error: 1, not_observed: 1 },
  security_txt_https_responses: 1,
  dnssec: { secure: 1, unsigned: 1, broken: 0, lookup_error: 1, unknown: 0 },
  mx_dnssec: { secure: 1 },
};
const currentSnapshot = { schema_version: 5, generated_at: "2026-09-29T00:00:00Z", source: { list_id: "ABC123", au_entry_count: 2 }, raw_archive: "raw/current.jsonl.gz", summary, domains };
const oldSummary = { ...summary, domain_count: 1, spf: { ...summary.spf, present_valid: 5 }, spf_qualifiers: { fail: 1, softfail: 2, neutral: 1, pass: 1 } };
const oldSnapshot = { ...currentSnapshot, generated_at: "2026-09-22T00:00:00Z", raw_archive: "raw/old.jsonl.gz", domains: domains.slice(0, 1), summary: oldSummary };
const entries = [
  { id: "current", path: "snapshots/current.json.gz", raw_archive: "raw/current.jsonl.gz", generated_at: currentSnapshot.generated_at, domain_count: domains.length, summary },
  { id: "old", path: "snapshots/old.json.gz", raw_archive: "raw/old.jsonl.gz", generated_at: oldSnapshot.generated_at, domain_count: 1, summary: oldSummary },
];
const index = { schema_version: 5, latest: entries[0].path, snapshots: entries };

const gzipByUrl = new Map([
  ["current.json.gz", zlib.gzipSync(Buffer.from(JSON.stringify(currentSnapshot)))],
  // Simulate a host that marks .gz as Content-Encoding:gzip and lets Fetch
  // transparently return the decompressed JSON bytes.
  ["old.json.gz", Buffer.from(JSON.stringify(oldSnapshot))],
]);
function responseFor(name) {
  return { ok: true, arrayBuffer: async () => {
    const bytes = gzipByUrl.get(name);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  } };
}

function startDashboard({ fetchSnapshot = ({ name }) => responseFor(name), fetchIndex = async () => ({ ok: true, json: async () => index }), url = "https://example.test/observatory/?snapshot=current" } = {}) {
  const b = browser(url);
  const elements = new Map(ids.map((id) => [id, new Element("div")]));
  for (const id of ["error-state", "empty-state", "download-raw"]) elements.get(id).hidden = true;
  for (const id of ["snapshot-select", "download-json", "download-csv"]) elements.get(id).disabled = true;
  for (const id of ["rank-filter", "spf-filter", "spf-qualifier-filter", "dmarc-filter", "provider-filter", "dnssec-filter", "securitytxt-filter", "content-validity-filter", "securitytxt-freshness-filter", "tls-filter"]) elements.get(id).value = "all";
  const downloads = [];
  const downloadNames = [];
  const document = {
    baseURI: "https://example.test/observatory/",
    body: new Element("body"),
    getElementById(id) { return elements.get(id) || null; },
    createElement(tag) {
      const node = new Element(tag);
      if (tag === "a") node.click = () => downloadNames.push(node.download);
      return node;
    },
    createTextNode(text) { return String(text); },
  };
  const browserURL = class extends URL {};
  browserURL.createObjectURL = (blob) => { downloads.push(blob); return "blob:test"; };
  browserURL.revokeObjectURL = () => {};
  const fetchCalls = [];
  const fetch = async (url, options = {}) => {
    fetchCalls.push(String(url));
    if (String(url).includes("index.json")) return fetchIndex(options.signal);
    return fetchSnapshot({ name: String(url).split("/").at(-1), signal: options.signal, cache: options.cache });
  };

  async function waitFor(predicate, description, timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs;
    while (!predicate() && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.ok(predicate(), `${description} (feed status: ${elements.get("feed-status").textContent}; error: ${elements.get("error-message").textContent || "none"})`);
  }

  const source = fs.readFileSync("src/scripts/dashboard.js", "utf8").replace(/^import .*view-state.mjs.*;\n/, "");
  vm.runInNewContext(source, { ...viewHelpers, searchDebounce: commit => viewHelpers.searchDebounce(commit, b.timers), window: b.window, URLSearchParams, setTimeout: b.timers.set, clearTimeout: b.timers.clear, document, URL: browserURL, fetch, AbortController, Blob, Response, DecompressionStream, TextDecoder, console, Intl, Date, Set, Map, Math, Number, String, Object, Array });
  return {
    ...b, elements, downloads, downloadNames, fetchCalls, waitFor,
    setIndexFetch(handler) { fetchIndex = handler; },
    setSnapshotFetch(handler = ({ name }) => responseFor(name)) { fetchSnapshot = handler; },
    select(id) {
      const target = elements.get("snapshot-select");
      target.value = id;
      return target.listeners.change({ target });
    },
    ready() { return waitFor(() => !elements.get("download-json").disabled || !elements.get("error-state").hidden, "Initial snapshot did not finish loading"); },
  };
}

const allText = (node) => [node.textContent, ...node.children.flatMap((child) => typeof child === "string" ? [child] : allText(child))].join(" ");

async function main() {
  const { elements, downloads, fetchCalls, waitFor, flush } = startDashboard();
  await assert.rejects(
    waitFor(() => false, "Synthetic dashboard wait timed out", 20),
    /Synthetic dashboard wait timed out.*feed status:/,
  );
  const rows = () => elements.get("domain-rows").children.filter((item) => item.className === "data-row");
  await waitFor(() => rows().length === 3 || !elements.get("error-state").hidden, "Dashboard did not finish loading the expected three rows");
  assert.equal(elements.get("error-state").hidden, true, elements.get("error-message").textContent);
  assert.equal(rows().length, 3);
  assert.equal(elements.get("metrics").children.length, 8);
  const findingsText = allText(elements.get("findings-list"));
  assert.equal(elements.get("findings-list").children.length, 5);
  assert.match(findingsText, /33% enforce DMARC/);
  assert.match(findingsText, /Microsoft 365 is the most common inbound mail clue/);
  const inboundRows = elements.get("provider-inbound-chart").children;
  assert.equal(inboundRows.length, 1);
  assert.match(allText(inboundRows[0]), /Microsoft 365/);
  assert.match(allText(elements.get("provider-outbound-chart").children[0]), /Google Workspace/);
  assert.equal(rows()[0].children.length, 6);
  assert.equal(rows()[0].children[2].dataset.label, "SPF");
  assert.ok(fetchCalls.some((url) => url.endsWith("current.json.gz")));
  const spfPoints = elements.get("spf-history-chart").children;
  assert.equal(spfPoints.length, 2);
  const latestSpfPoint = spfPoints.at(-1);
  const latestSegments = latestSpfPoint.children[0].children;
  assert.deepEqual(latestSegments.map((segment) => segment.dataset.outcome), ["fail", "softfail", "neutral", "pass"]);
  assert.deepEqual(latestSegments.map((segment) => segment.style.height), ["50%", "25%", "25%", "0%"]);
  assert.match(latestSpfPoint.dataset.label, /4 valid SPF records/);
  assert.match(latestSpfPoint.dataset.label, /Hardfail \(−all\): 2 \(50%\)/);
  assert.match(elements.get("spf-history-caption").textContent, /absent, invalid, and lookup-error records are excluded/);

  const filters = [
    ["rank-filter", "outside_top_1m"], ["provider-filter", "Microsoft 365"], ["tls-filter", "valid"],
    ["securitytxt-filter", "present"], ["content-validity-filter", "valid"], ["securitytxt-freshness-filter", "expired"], ["dnssec-filter", "secure"],
  ];
  for (const [id, value] of filters) {
    elements.get("clear-filters").click();
    for (const [filterId] of filters) elements.get(filterId).value = "all";
    const control = elements.get(id);
    control.value = value;
    control.listeners.change({ target: control });
    assert.equal(rows().length, 1, `${id} filter should return one row`);
  }
  for (const [filterId] of filters) elements.get(filterId).value = "all";
  elements.get("clear-filters").click();
  const freshnessFilter = elements.get("securitytxt-freshness-filter");
  freshnessFilter.value = "unknown";
  freshnessFilter.listeners.change({ target: freshnessFilter });
  assert.equal(rows().length, 2, "old or unavailable findings should filter as freshness unknown");

  elements.get("rank-filter").value = "all";
  elements.get("provider-filter").value = "all";
  elements.get("securitytxt-freshness-filter").value = "all";
  elements.get("clear-filters").click();
  const search = elements.get("search-input");
  search.value = "Google Workspace";
  search.listeners.input({ target: search });
  flush();
  assert.equal(rows().length, 1);
  const domainRow = rows()[0];
  const inspect = domainRow.children[1].children.find((item) => item.textContent === "Inspect findings");
  inspect.click();
  const detailRow = elements.get("domain-rows").children.find((item) => item.className === "detail-row");
  const detailText = allText(detailRow);
  assert.match(detailText, /v=spf1 -all/);
  assert.match(detailText, /Root HEAD and security\.txt/);
  assert.match(detailText, /present_unverified|signature_status/);
  assert.doesNotMatch(detailText.toLowerCase(), /fingerprint|subject_alt_names|certificate metadata/);

  const select = elements.get("snapshot-select");
  const previousSnapshotMeta = elements.get("snapshot-meta").textContent;
  select.value = "old";
  select.listeners.change({ target: select });
  await waitFor(
    () => elements.get("snapshot-meta").textContent !== previousSnapshotMeta || !elements.get("error-state").hidden,
    "Selected snapshot did not finish loading",
  );
  assert.equal(elements.get("error-state").hidden, true, elements.get("error-message").textContent);
  assert.ok(fetchCalls.some((url) => url.endsWith("old.json.gz")));

  elements.get("search-input").value = "";
  elements.get("download-csv").click();
  const csv = await downloads.at(-1).text();
  for (const name of ["tranco_rank", "spf_record", "dmarc_record", "security_txt_availability", "security_txt_content_validity", "security_txt_freshness", "security_txt_tls_certificate", "security_txt_cross_host_redirect", "security_txt_https_response_received"]) assert.ok(csv.includes(name));
  assert.ok(csv.includes("Google Workspace"));
  assert.doesNotMatch(csv, /sha256_fingerprint|subject_alt_names|security_txt_body/);
  elements.get("download-json").click();
  const json = await downloads.at(-1).text();
  assert.equal(JSON.parse(json).schema_version, 5);
  console.log("Dashboard gzip snapshot loading, selection, email/web filters, and JSON/CSV exports passed.");
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function deferRequests(harness) {
  const pending = [];
  // Deliberately ignore aborts to exercise the sequence guard as well as cancellation.
  harness.setSnapshotFetch((request) => {
    const result = { ...request, ...deferred() };
    pending.push(result);
    return result.promise;
  });
  return pending;
}

function visibleState({ elements }) {
  return JSON.stringify({
    selected: elements.get("snapshot-select").value,
    text: ["feed-status", "snapshot-meta", "metrics", "findings-list", "policy-chart", "signals-chart", "web-chart", "provider-inbound-chart", "provider-outbound-chart", "domain-rows", "result-count", "page-label"].map((id) => allText(elements.get(id))),
    error: [elements.get("error-state").hidden, elements.get("error-message").textContent],
    downloads: [elements.get("download-json").disabled, elements.get("download-csv").disabled, elements.get("download-raw").hidden, elements.get("download-raw").href],
  });
}

function assertLoading({ elements, downloads }) {
  assert.equal(elements.get("snapshot-select").disabled, false);
  assert.match(elements.get("feed-status").textContent, /Loading/);
  assert.equal(elements.get("download-json").disabled, true);
  assert.equal(elements.get("download-csv").disabled, true);
  assert.equal(elements.get("download-raw").hidden, true);
  const count = downloads.length;
  // Even a programmatic event must not export the previous snapshot while loading.
  elements.get("download-json").listeners.click();
  elements.get("download-csv").listeners.click();
  assert.equal(downloads.length, count);
}

async function assertLoaded({ elements, downloads, downloadNames }, id, snapshot) {
  assert.equal(elements.get("snapshot-select").value, id);
  const date = new Intl.DateTimeFormat("en-AU", { timeZone: "Australia/Sydney", day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(snapshot.generated_at));
  assert.ok(elements.get("snapshot-meta").textContent.startsWith(date));
  assert.equal(elements.get("domain-rows").children.filter((row) => row.className === "data-row").length, snapshot.domains.length);
  assert.equal(elements.get("download-json").disabled, false);
  assert.equal(elements.get("download-csv").disabled, false);
  assert.equal(elements.get("download-raw").hidden, false);
  assert.equal(elements.get("download-raw").href, new URL(snapshot.raw_archive, "https://example.test/observatory/data/").href);
  elements.get("download-json").click();
  assert.deepEqual(JSON.parse(await downloads.at(-1).text()), JSON.parse(JSON.stringify(snapshot)));
  assert.equal(downloadNames.at(-1), `au-mail-auth-${snapshot.generated_at.slice(0, 10)}.json`);
  elements.get("download-csv").click();
  assert.equal(downloadNames.at(-1), `au-mail-auth-${snapshot.generated_at.slice(0, 10)}-filtered.csv`);
  const csv = await downloads.at(-1).text();
  for (const domain of domains) assert.equal(csv.includes(`"${domain.domain}"`), snapshot.domains.some((row) => row.domain === domain.domain));
}

async function snapshotRaces() {
  const h = startDashboard();
  await h.ready();
  await assertLoaded(h, "current", currentSnapshot);
  const pending = deferRequests(h);
  const older = h.select("old");
  assertLoading(h);
  const newer = h.select("current");
  assert.equal(pending[0].signal.aborted, true);
  assert.equal(pending[1].signal.aborted, false);
  pending[1].resolve(responseFor("current.json.gz"));
  await newer;
  const accepted = visibleState(h);
  pending[0].resolve(responseFor("old.json.gz"));
  await older;
  assert.equal(visibleState(h), accepted, "a stale response changed the accepted snapshot");
  await assertLoaded(h, "current", currentSnapshot);

  const staleFailure = h.select("old");
  const latest = h.select("current");
  pending[3].resolve(responseFor("current.json.gz"));
  await latest;
  const beforeFailure = visibleState(h);
  pending[2].reject(new Error("Late network failure"));
  await staleFailure;
  assert.equal(visibleState(h), beforeFailure, "a stale error changed the accepted snapshot");

  const earlyFailure = h.select("old");
  const stillLoading = h.select("current");
  pending[4].reject(new Error("Superseded request failed"));
  await earlyFailure;
  assertLoading(h);
  assert.equal(h.elements.get("error-state").hidden, true);
  pending[5].resolve(responseFor("current.json.gz"));
  await stillLoading;
  await assertLoaded(h, "current", currentSnapshot);
}

async function staleDecoding() {
  const h = startDashboard();
  await h.ready();
  const body = deferred();
  const started = deferred();
  let olderSignal;
  h.setSnapshotFetch(({ name, signal }) => {
    if (name !== "old.json.gz") return responseFor(name);
    olderSignal = signal;
    return { ok: true, arrayBuffer() { started.resolve(); return body.promise; } };
  });
  const older = h.select("old");
  await started.promise;
  await h.select("current");
  assert.equal(olderSignal.aborted, true);
  const accepted = visibleState(h);
  body.resolve(await responseFor("old.json.gz").arrayBuffer());
  await older;
  assert.equal(visibleState(h), accepted, "decoding a superseded response changed the snapshot");
  await assertLoaded(h, "current", currentSnapshot);
}

async function selectionFailureAndRetry() {
  const h = startDashboard();
  await h.ready();
  const originalMetrics = allText(h.elements.get("metrics"));
  const pending = deferRequests(h);
  const selected = h.select("old");
  assertLoading(h);
  pending[0].resolve({ ok: false, status: 503 });
  await selected;
  assert.equal(h.elements.get("error-state").hidden, false);
  assert.match(h.elements.get("error-message").textContent, /503.*previous snapshot/);
  assert.equal(allText(h.elements.get("metrics")), originalMetrics);
  await assertLoaded(h, "current", currentSnapshot);

  for (const content of ["invalid JSON", JSON.stringify({ ...oldSnapshot, schema_version: 99 })]) {
    h.setSnapshotFetch(() => new Response(content));
    await h.select("old");
    assert.equal(h.elements.get("error-state").hidden, false);
    await assertLoaded(h, "current", currentSnapshot);
  }
  h.setSnapshotFetch();
  await h.select("old");
  assert.equal(h.elements.get("error-state").hidden, true);
  await assertLoaded(h, "old", oldSnapshot);
}

async function initialFailureAndRetry() {
  const h = startDashboard({ fetchSnapshot: () => ({ ok: false, status: 503 }) });
  await h.ready();
  assert.equal(h.elements.get("feed-status").textContent, "Data feed unavailable");
  assert.equal(h.elements.get("download-json").disabled, true);
  assert.equal(h.elements.get("download-csv").disabled, true);
  assert.equal(h.elements.get("download-raw").hidden, true);
  assert.equal(h.elements.get("snapshot-select").disabled, false);
  assert.equal(h.elements.get("domain-rows").children.filter((row) => row.className === "data-row").length, 0);
  h.elements.get("download-json").listeners.click();
  h.elements.get("download-csv").listeners.click();
  assert.equal(h.downloads.length, 0);
  h.setSnapshotFetch();
  await h.select("current");
  assert.equal(h.elements.get("error-state").hidden, true);
  await assertLoaded(h, "current", currentSnapshot);
}

async function supersededInitialLoad() {
  const initial = deferred();
  let initialSignal;
  const h = startDashboard({ fetchSnapshot: ({ name, signal }) => {
    if (name !== "current.json.gz") return responseFor(name);
    initialSignal = signal;
    return initial.promise;
  } });
  await h.waitFor(() => initialSignal, "Initial request did not start");
  await h.select("old");
  assert.equal(initialSignal.aborted, true);
  const accepted = visibleState(h);
  initial.reject(new Error("Initial request failed after a new selection"));
  // initialize() owns this promise; let its rejection handlers finish.
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(visibleState(h), accepted);
  await assertLoaded(h, "old", oldSnapshot);
}

async function navigation() {
  const { parseView, viewURL, searchDebounce } = viewHelpers;
  const url = new URL("https://example.test/nested/?snapshot=old&q=A%26B&spf=absent&provider=Missing&page=3&utm=x#results");
  const parsed = parseView(url.searchParams);
  assert.deepEqual(parseView(new URL(viewURL(url, parsed), url).searchParams), parsed);
  assert.equal(viewURL(url, parseView(new URLSearchParams())), "/nested/?utm=x#results");
  for (const page of ["0", "-1", "1.2", "oops", "9007199254740992"]) assert.equal(parseView(new URLSearchParams({ page, spf: "bad" })).page, 1);
  assert.equal(parseView(new URLSearchParams("spf=bad")).spf, "all");
  let callback; const changes = [];
  const debounce = searchDebounce(value => changes.push(value), { set(run) { callback = run; }, clear() {} });
  debounce.schedule("pending"); debounce.cancel(); callback(); assert.deepEqual(changes, []);
  const h = startDashboard({ url: "https://example.test/observatory/?utm=x#results" });
  await h.ready();
  await assertLoaded(h, "", currentSnapshot);
  assert.equal(h.window.location.search, "?utm=x");
  await h.select("old"); assert.match(h.window.location.search, /snapshot=old/);
  const length = h.history.length;
  const search = h.elements.get("search-input");
  search.value = "stale draft"; search.listeners.input();
  await h.go(-1); h.flush();
  assert.equal(search.value, ""); assert.equal(h.history.length, length);
  await assertLoaded(h, "", currentSnapshot);
  await h.go(1); await assertLoaded(h, "old", oldSnapshot);
  h.elements.get("provider-filter").value = "Microsoft 365";
  h.elements.get("provider-filter").listeners.change();
  assert.match(allText(h.elements.get("provider-filter")), /Microsoft 365 \(unavailable\)/);
  assert.match(h.elements.get("result-count").textContent, /^0 matching/);
  h.elements.get("clear-filters").click();
  assert.match(h.window.location.search, /snapshot=old/);
  await h.select("");
  h.setIndexFetch(async () => ({ ok: true, json: async () => ({ ...index, latest: entries[1].path }) }));
  await h.elements.get("refresh-data").listeners.click();
  await assertLoaded(h, "", oldSnapshot);
  assert.doesNotMatch(h.window.location.search, /snapshot=/);
  await h.select("current");
  await h.elements.get("refresh-data").listeners.click();
  await assertLoaded(h, "current", currentSnapshot);
  const missing = startDashboard({ url: "https://example.test/observatory/?snapshot=gone&page=77&utm=x#results" });
  await missing.ready(); await assertLoaded(missing, "", currentSnapshot);
  assert.equal(missing.window.location.search, "?utm=x");
  assert.equal(missing.elements.get("snapshot-notice").hidden, false);
  assert.match(missing.elements.get("snapshot-notice").textContent, /no longer available/);
  const pending = deferRequests(missing);
  const request = missing.select("old");
  missing.elements.get("search-input").value = "portal";
  missing.elements.get("search-input").listeners.input(); missing.flush();
  pending[0].resolve(responseFor("old.json.gz")); await request;
  assert.match(missing.window.location.search, /snapshot=old.*q=portal/);
  assert.match(missing.elements.get("result-count").textContent, /^1 matching/);
  const failed = missing.select("current"); pending[1].reject(new Error("Offline")); await failed;
  assert.match(missing.window.location.search, /snapshot=old/);
  missing.setSnapshotFetch(({ name, cache }) => { assert.equal(cache, "no-cache", "Retry must revalidate a cached failure"); return responseFor(name); });
  await missing.elements.get("retry-data").listeners.click();
  assert.match(missing.window.location.search, /snapshot=current/);
  assert.equal(missing.elements.get("error-state").hidden, true);
  missing.elements.get("download-json").click();
  assert.equal(JSON.parse(await missing.downloads.at(-1).text()).generated_at, currentSnapshot.generated_at);
  missing.elements.get("download-csv").click();
  const csv = await missing.downloads.at(-1).text();
  assert.match(csv, /portal.example.au/); assert.doesNotMatch(csv, /mail.example.gov.au/);
  const many = { ...currentSnapshot, domains: Array.from({ length: 52 }, (_, n) => ({ ...domains[0], domain: `domain${n}.au` })) };
  const paged = startDashboard({ url: "https://example.test/observatory/?page=99", fetchSnapshot: async () => new Response(JSON.stringify(many)) });
  await paged.ready();
  assert.match(paged.window.location.search, /page=3/);
  assert.match(paged.elements.get("result-count").textContent, /52 matching.*51–52/);
  paged.elements.get("previous-page").click(); assert.match(paged.window.location.search, /page=2/);
  await paged.go(-1); assert.match(paged.elements.get("page-label").textContent, /Page 3 of 3/);
  paged.elements.get("clear-filters").click();
  paged.elements.get("search-input").value = "domain";
  paged.elements.get("search-input").listeners.input();
  paged.elements.get("next-page").click(); paged.flush();
  assert.match(paged.elements.get("page-label").textContent, /Page 1 of 3/);
  assert.match(paged.window.location.search, /q=domain/);
  const initial = startDashboard({ fetchIndex: async () => { throw new Error("Index offline"); } });
  await initial.ready(); assert.match(initial.elements.get("error-message").textContent, /Index offline/);
  initial.setIndexFetch(async () => ({ ok: true, json: async () => index }));
  await initial.elements.get("retry-data").listeners.click(); await assertLoaded(initial, "current", currentSnapshot);
  initial.setIndexFetch(async () => { throw new Error("Refresh failed"); });
  await initial.elements.get("refresh-data").listeners.click(); await assertLoaded(initial, "current", currentSnapshot);
  assert.match(initial.elements.get("error-message").textContent, /Refresh failed/);
  const noSnapshots = startDashboard({ fetchIndex: async () => ({ ok: true, json: async () => ({ ...index, snapshots: [] }) }) });
  await noSnapshots.ready();
  assert.match(noSnapshots.elements.get("error-message").textContent, /No snapshots/);
  noSnapshots.setIndexFetch(async () => ({ ok: true, json: async () => index }));
  await noSnapshots.elements.get("retry-data").listeners.click();
  await assertLoaded(noSnapshots, "current", currentSnapshot);

  const emptySnapshot = startDashboard({ fetchSnapshot: async () => new Response(JSON.stringify({ ...currentSnapshot, domains: [], summary: {} })) });
  await emptySnapshot.ready();
  assert.match(allText(emptySnapshot.elements.get("domain-rows")), /This snapshot contains no domains/);
  assert.equal(emptySnapshot.elements.get("error-state").hidden, true);
  const decode = deferred();
  initial.setIndexFetch(async () => ({ ok: true, json: () => decode.promise }));
  const refreshing = initial.elements.get("refresh-data").listeners.click();
  await Promise.resolve(); await Promise.resolve();
  await initial.select("old");
  const accepted = visibleState(initial);
  decode.resolve({ ...index, latest: entries[0].path }); await refreshing;
  assert.equal(visibleState(initial), accepted, "stale index decoding changed the selected snapshot");
  console.log("URL navigation, latest/pinned snapshots, missing links, unavailable filters, clamping, refresh and retry passed.");
}

async function run() {
  viewHelpers = await import("../src/scripts/view-state.mjs");
  ({ browser } = await import("./browser.mjs"));
  await navigation();
  await main();
  await snapshotRaces();
  await staleDecoding();
  await selectionFailureAndRetry();
  await initialFailureAndRetry();
  await supersededInitialLoad();
  console.log("Snapshot request ordering, cancellation, decoding, failure recovery, and download consistency passed.");
}

run().catch((error) => { console.error(error); process.exitCode = 1; });
