const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

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
    this._fragment = false;
  }
  append(...items) {
    for (const item of items) {
      if (item && item._fragment) this.children.push(...item.children);
      else this.children.push(item);
    }
  }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  click() { if (this.listeners.click) this.listeners.click({ target: this }); }
  remove() {}
}

const headers = fs.readFileSync("site/index.html", "utf8");
const ids = [...headers.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
const elements = new Map(ids.map((id) => [id, new Element("div")]));
for (const id of ["search-input", "rank-filter", "spf-filter", "spf-qualifier-filter", "dmarc-filter", "provider-filter", "dnssec-filter", "https-filter", "securitytxt-filter", "securitytxt-validity-filter", "hsts-filter", "caa-filter", "ipv6-filter", "web-dns-filter", "header-filter"]) {
  elements.get(id).value = id === "search-input" ? "" : "all";
}

const cookieHeaders = { "content-security-policy": "default-src 'self'", "set-cookie-metadata": [{ name: "session", secure: true, httponly: true }] };
const domains = [
  {
    rank: 2, rank_status: "in_top_1m", rank_display: "#2", au_rank: 1, au_rank_total: 2, last_rank: 2,
    domain: "portal.example.au", spf: { status: "present_valid", record: "v=spf1 -all", terminal: { token: "-all", outcome: "fail", label: "Hard fail (-all)" } },
    dmarc: { status: "present_valid", policy: { p: "reject" }, discovery_source: "direct" },
    provider_clues: { outbound: [{ name: "Google Workspace", observed_hosts: ["_spf.google.com"] }] },
    web_provider_clues: [{ name: "Cloudflare", observed_hosts: ["edge.cloudflare.net"], observed_headers: [{ name: "server", value: "cloudflare" }] }],
    web: { tls: { status: "valid", certificates: [{ status: "valid", sha256_fingerprint: "a".repeat(64), days_until_expiry_at_scan: 94, protocol: "TLSv1.3" }] }, page: { title: "Civic Portal" }, headers: cookieHeaders, header_presence: { "content-security-policy": true }, header_findings: [], https_upgrade: { hsts: { active: true, max_age: 31536000 } }, requests: {} },
    security_txt: { status: "present", validity_status: "valid", sha256: "b".repeat(64), preferred_path: "/.well-known/security.txt", preferred_scheme: "https", resources: [{ path: "/.well-known/security.txt", scheme: "https", sha256: "b".repeat(64), presence: "present", validation: { valid: true } }] },
    web_dns: { a: { status: "present", records: ["192.0.2.1"] }, aaaa: { status: "absent", records: [] }, cname: { status: "present", records: ["edge.cloudflare.net."] }, https: { status: "absent", records: [] }, caa: { direct: { status: "absent" }, effective: { status: "present", source: "inherited", owner: "au" } } },
    mx: { status: "present_valid", hosts: [{ hostname: "mx.example.au", dnssec_status: "secure" }] },
    mta_sts: { status: "absent" }, tls_reporting: { status: "absent" }, dnssec: { status: "secure", validated: true }, errors: {},
  },
  {
    rank: 5, rank_status: "in_top_1m", rank_display: "#5", au_rank: 2, au_rank_total: 2, last_rank: 5,
    domain: "mail.example.gov.au", spf: { status: "absent" }, dmarc: { status: "absent" },
    provider_clues: { inbound: [{ name: "Microsoft 365", observed_hosts: ["mail.protection.outlook.com"] }] }, web_provider_clues: [],
    web: { tls: { status: "lookup_error", certificates: [] }, page: { title: null }, headers: {}, header_presence: {}, https_upgrade: { hsts: { active: false } }, requests: {} },
    security_txt: { status: "absent", validity_status: "absent", resources: [] },
    web_dns: { a: { status: "absent", records: [] }, aaaa: { status: "present", records: ["2001:db8::1"] }, cname: { status: "absent", records: [] }, https: { status: "absent", records: [] }, caa: { direct: { status: "absent" }, effective: { status: "absent" } } },
    mx: { status: "absent", hosts: [] }, mta_sts: { status: "absent" }, tls_reporting: { status: "absent" }, dnssec: { status: "unsigned" }, errors: {},
  },
  {
    rank: null, rank_status: "outside_top_1m", rank_display: ">1,000,000", au_rank: null, au_rank_total: 2, last_rank: 99, last_au_rank: 7,
    domain: "archived.example.au", spf: { status: "lookup_error" }, dmarc: { status: "lookup_error" }, provider_clues: {}, web_provider_clues: [],
    web: { tls: { status: "unavailable", certificates: [] }, page: { title: null }, headers: {}, header_presence: {}, https_upgrade: {}, requests: {} },
    security_txt: { status: "lookup_error", validity_status: "lookup_error", resources: [] }, web_dns: { a: { status: "lookup_error", records: [] }, aaaa: { status: "lookup_error", records: [] }, cname: { status: "lookup_error", records: [] }, https: { status: "lookup_error", records: [] }, caa: { direct: { status: "lookup_error" }, effective: { status: "lookup_error" } } },
    mx: { status: "lookup_error", hosts: [] }, dnssec: { status: "lookup_error" }, errors: {},
  },
];
const summary = {
  domain_count: domains.length,
  rank_status: { in_top_1m: 2, outside_top_1m: 1 },
  dmarc: { present_valid: 1, present_invalid: 0, absent: 1, lookup_error: 1 },
  dmarc_policies: { reject: 1 },
  spf_qualifiers: { fail: 1 },
  web_tls: { valid: 1, lookup_error: 1, unavailable: 1 },
  security_txt: { present: 1, absent: 1, lookup_error: 1 },
  security_txt_validity: { valid: 1, absent: 1, lookup_error: 1 },
  web_dns: { caa_effective: { present: 1, absent: 1, lookup_error: 1 } },
  https_upgrade: { hsts_active: 1 },
  security_headers: { "content-security-policy": 1 },
  dnssec: { secure: 1, unsigned: 1, lookup_error: 1 }, mx_dnssec: {},
};
const snapshot = { schema_version: 4, generated_at: "2026-09-29T00:00:00Z", source: { list_id: "ABC123", au_entry_count: 2 }, raw_archive: "raw/test.jsonl.gz", summary, domains };
const index = { schema_version: 4, latest: "snapshots/test.json", snapshots: [{ id: "test", path: "snapshots/test.json", raw_archive: "raw/test.jsonl.gz", generated_at: snapshot.generated_at, domain_count: domains.length, summary }] };

const document = {
  baseURI: "https://example.test/observatory/",
  body: new Element("body"),
  getElementById(id) { return elements.get(id) || null; },
  createElement(tagName) { return new Element(tagName); },
  createTextNode(text) { return String(text); },
  createDocumentFragment() { const fragment = new Element("fragment"); fragment._fragment = true; return fragment; },
};
const downloads = [];
const browserURL = class extends URL {};
browserURL.createObjectURL = (blob) => { downloads.push(blob); return "blob:test"; };
browserURL.revokeObjectURL = () => {};
globalThis.Blob = globalThis.Blob || require("node:buffer").Blob;
const certificateMetadata = { sha256_fingerprint: "a".repeat(64), subject: "CN=portal.example.au", issuer: "CN=Example CA", subject_alt_names: [{ type: "DNSName", value: "portal.example.au" }], not_before: "2026-01-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z" };
const fetch = async (url) => ({
  ok: true,
  json: async () => String(url).includes("index.json") ? index : String(url).includes("certificates/") ? certificateMetadata : snapshot,
});

async function main() {
  const source = fs.readFileSync("site/app.js", "utf8");
  vm.runInNewContext(source, { document, URL: browserURL, fetch, Blob: globalThis.Blob, console });
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(elements.get("domain-rows").children.filter((item) => item.className === "data-row").length, 3);
  assert.equal(elements.get("metrics").children.length, 8);

  const filters = [
    ["rank-filter", "outside_top_1m"],
    ["provider-filter", "Microsoft 365"],
    ["https-filter", "valid"],
    ["securitytxt-filter", "present"],
    ["securitytxt-validity-filter", "valid"],
    ["caa-filter", "present"],
    ["header-filter", "content-security-policy"],
    ["web-dns-filter", "cname"],
  ];
  for (const [id, value] of filters) {
    for (const [filterId] of filters) elements.get(filterId).value = "all";
    elements.get("securitytxt-filter").value = "all";
    elements.get("securitytxt-validity-filter").value = "all";
    const control = elements.get(id);
    control.value = value;
    control.listeners.change({ target: control });
    assert.equal(elements.get("domain-rows").children.filter((item) => item.className === "data-row").length, 1, `${id} filter should return one row`);
    if (id === "rank-filter") {
      const row = elements.get("domain-rows").children.find((item) => item.className === "data-row");
      assert.equal(row.children[0].children[0].textContent, ">1,000,000");
      assert.match(row.children[0].children[1].textContent, /last #99/);
    }
  }

  const search = elements.get("search-input");
  search.value = "Civic Portal";
  search.listeners.input({ target: search });
  assert.equal(elements.get("domain-rows").children.filter((item) => item.className === "data-row").length, 1);
  const domainRow = elements.get("domain-rows").children.find((item) => item.className === "data-row");
  const detailButton = domainRow.children[1].children.find((item) => item.textContent === "Inspect posture");
  detailButton.click();
  await new Promise((resolve) => setTimeout(resolve, 10));
  const detailRow = elements.get("domain-rows").children.find((item) => item.className === "detail-row");
  assert.match(detailRow.certificateMetadataTarget.textContent, /CN=portal\.example\.au/);
  const descendants = (node) => [node, ...node.children.flatMap(descendants)];
  assert.ok(descendants(detailRow).some((node) => node.href && node.href.endsWith(`/security-txt/${"b".repeat(64)}.txt`)));
  elements.get("download-csv").listeners.click();
  const csv = await downloads.at(-1).text();
  for (const name of ["tranco_rank", "au_rank_total", "tls_certificates", "security_txt_sha256", "security_txt_resources", "caa_effective", "web_service_evidence"]) assert.ok(csv.includes(name));
  assert.ok(csv.includes("b".repeat(64)));
  assert.ok(!csv.includes("security_txt_text"));
  elements.get("download-json").listeners.click();
  const json = await downloads.at(-1).text();
  assert.equal(JSON.parse(json).schema_version, 4);
  console.log("Dashboard schema-v4 load, filters, certificate references, and JSON/CSV exports passed.");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
