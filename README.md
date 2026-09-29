# .au Security Posture Observatory

A weekly, reproducible snapshot of public email, web, certificate, and DNS configuration for exact `.au` names appearing in the Tranco top one million. The static dashboard is built with HTML, CSS, and browser-side JavaScript and is published with GitHub Pages.

The data describes configuration observed at scan time. It does not measure email pass rates, exploitability, or a single site-wide security score. Provider labels are clues inferred from hostnames and headers; each clue keeps the evidence used to infer it.

## Collected signals

- **Ranking and roster:** current global Tranco rank, one-based placement among the `.au` names in that top-million list, and the list ID/date. The first schema-v4 run starts from an empty roster and seeds it from that list. Later runs check the union of currently ranked `.au` names and all previously tracked names. A retained name that is no longer in the downloaded top million is shown as `>1,000,000`; its last exact rank and `.au` placement remain available.
- **SPF and DMARC:** record presence, validity, parser warnings, SPF DNS and void lookup counts, mechanisms, include/redirect targets, effective terminal qualifier, DMARC discovery location, `p`/`sp`/`np`, alignment, test mode, report destinations, and likely related services. DNS errors stay distinct from absent and malformed records.
- **Mail routing and DNSSEC:** MX, MTA-STS, SMTP TLS reporting, nameservers, and SOA. DNSSEC records DS and DNSKEY query states and separates secure, unsigned, broken, lookup-error, and unknown results. A child DNSKEY without a parent DS is retained as evidence of an unsigned chain. DKIM selectors are not probed because a domain's selector set cannot be discovered comprehensively.
- **HTTP and HTTPS:** bounded `HEAD /` and `GET /` request chains, response codes, redirects, selected headers, `Server`, `X-Powered-By`, title, meta-refresh targets, and provider headers. At most 64 KiB of homepage HTML is read for extraction and discarded. Requests do not execute JavaScript or crawl links.
- **TLS and HTTPS upgrades:** peer certificate subject, issuer, SANs, validity dates, SHA-256 fingerprint, expiry days at scan time, negotiated TLS version/cipher/ALPN, and per-hop validation status. A bounded TLS-only handshake captures leaf metadata after certificate validation failures; that observation retains the original failure status and is never treated as trusted. Certificate metadata is stored once by fingerprint. Redirects, HTTP-page meta refreshes, and HSTS are recorded as separate upgrade evidence; they do not change certificate validity.
- **security.txt:** checks only `/.well-known/security.txt` over HTTP and HTTPS. It records presence, lookup errors, compact validity findings, and the SHA-256 hash of the exact response bytes. Each distinct body is stored once under its hash; snapshots point to that evidence file rather than embedding the text.
- **Security headers and cookies:** Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, COOP, COEP, CORP, CORS headers, and useful hosting/CDN clues. `Set-Cookie` values are discarded; cookie names and attributes such as Secure, HttpOnly, SameSite, expiry, and path are retained.
- **Web DNS:** A, AAAA, CNAME chain, HTTPS/SVCB, direct CAA, and effective CAA inherited from the nearest ancestor with a record. The CAA owner, records, TTL, and lookup status are retained.

Web findings are rule-based observations, not a score. HTTP requests only target globally routable addresses, reuse captured A/AAAA answers for the initial hostname, and pin each resolved address to prevent DNS rebinding. Redirect targets are resolved and checked independently. Requests allow standard HTTP/HTTPS ports, follow at most five redirects, and apply a five-second deadline to each request chain. Each domain's requests run sequentially; four domains run concurrently per shard.

## Collection and snapshots

The **Refresh .au security data and publish Pages** workflow runs Mondays at 03:00 Australia/Sydney time and supports **Run workflow**. It downloads and validates the complete current Tranco list before changing ranks. It divides the tracked roster into flat shards of at most 200 domains, runs up to eight shards concurrently, and keeps the 0.15-second inter-domain submission delay. Each shard permits four in-flight domain probes and prints progress counts and an ETA every 25 completions.

Completed shards are uploaded as run artifacts. The merge stage checks that every expected domain appears exactly once, publishes the schema-v4 snapshot and deduplicated evidence files, and writes the updated roster only after the complete scan succeeds. It prints serialized and gzip size estimates for snapshot and raw fields. Re-running failed jobs can reuse successful shard artifacts; there are no per-domain checkpoints. Each successful run retains a dated normalized JSON snapshot and compressed JSONL raw archive under `site/data/`. The index stores summaries for trend charts. Future snapshots are retained indefinitely.

The checked-in `site/data/registry.json` and schema-v4 index are empty to start future history fresh. No old snapshot is used to seed the roster.

## Run locally

Python 3.10 or newer is required. The collector pins `cryptography==50.0.1` to parse certificate DER and timezone-aware X.509 validity dates.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m collector.scan
python -m http.server 8000 --directory site
```

Open `http://localhost:8000`. A full collection reads the Tranco top million and checks the ranked `.au` set. `python -m collector.workflow prepare --rank-limit 10` can exercise input preparation against a compatible short Tranco response; it does not bypass the full-list validation for normal runs.

Provider mappings for mail platforms, web hosting, and server/header clues are in `collector/providers.json`. Unknown observed hostnames remain visible as `Unclassified` clues.

## GitHub Pages setup

Push the repository to GitHub and set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**. The workflow publishes site-only pushes without starting a scan. Scheduled/manual runs save the snapshot and roster, then deploy the site in the same run. The workflow declares minimal per-job permissions for artifact reads, snapshot commits, and Pages deployment.

## Offline checks

```sh
python3 -m unittest discover -s tests -v
node --check site/app.js
node tests/test_dashboard.js
```
