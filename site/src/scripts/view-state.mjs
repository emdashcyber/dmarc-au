export const controls = {
  q: "search-input", rank: "rank-filter", spf: "spf-filter", spfEnding: "spf-qualifier-filter",
  dmarc: "dmarc-filter", provider: "provider-filter", dnssec: "dnssec-filter", securityTxt: "securitytxt-filter",
  format: "content-validity-filter", freshness: "securitytxt-freshness-filter", tls: "tls-filter",
};
const choices = {
  rank: ["in_top_1m", "outside_top_1m"], spf: ["present_valid", "present_invalid", "absent", "lookup_error"],
  spfEnding: ["fail", "softfail", "neutral", "pass", "implicit"], dmarc: ["reject", "quarantine", "none", "absent", "present_invalid", "lookup_error"],
  dnssec: ["secure", "unsigned", "broken", "lookup_error", "unknown"], securityTxt: ["present", "absent", "http_error", "lookup_error"],
  format: ["valid", "invalid", "not_assessable"], freshness: ["current", "expired", "unknown"], tls: ["valid", "invalid", "error", "not_observed"],
};
export function parseView(params) {
  const view = { snapshot: params.get("snapshot") || "", q: params.get("q") || "", provider: params.get("provider") || "all" };
  for (const [key, values] of Object.entries(choices)) view[key] = values.includes(params.get(key)) ? params.get(key) : "all";
  const raw = params.get("page") || "1", page = Number(raw);
  view.page = /^\d+$/.test(raw) && Number.isSafeInteger(page) && page > 0 ? page : 1;
  return view;
}
export function viewURL(input, view) {
  const url = new URL(input), defaults = parseView(new URLSearchParams());
  for (const key of Object.keys(defaults)) {
    url.searchParams.delete(key);
    if (view[key] !== defaults[key]) url.searchParams.set(key, String(view[key]));
  }
  return url.pathname + url.search + url.hash;
}
export function searchDebounce(commit, timers = { set: (run, ms) => setTimeout(run, ms), clear: id => clearTimeout(id) }) {
  let timer, generation = 0;
  const cancel = () => { generation++; if (timer !== undefined) timers.clear(timer); timer = undefined; };
  return { cancel, schedule(value) { cancel(); const request = generation; timer = timers.set(() => { if (request === generation) { timer = undefined; commit(value); } }, 300); } };
}
