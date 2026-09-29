# .au Mail Authentication Observatory

A weekly snapshot of published email and DNS configuration for exact `.au` names appearing in the Tranco top one million, with a limited check of the well-known `security.txt` endpoint. The static dashboard uses HTML, CSS, and browser-side JavaScript and is published with GitHub Pages.

The data describes configuration observed at scan time. It does not measure message-level email pass rates, exploitability, or a single site-wide security score. Provider labels are inferences from observed mail-related hostnames and retain the evidence used for each clue.

## Collected signals

- **Ranking and roster:** current global Tranco rank, one-based placement among the `.au` names in that top-million list, and the list ID/date. The schema-v5 history starts with an empty roster and seeds it from the first new scan. Later runs check the union of currently ranked `.au` names and all previously tracked names. A retained name that is no longer in the downloaded top million is shown as `>1,000,000`; its last exact rank and `.au` placement remain available.
- **SPF and DMARC:** record presence, validity, parser warnings, SPF DNS and void lookup counts, mechanisms, include/redirect targets, effective terminal qualifier, DMARC discovery location, `p`/`sp`/`np`, alignment, test mode, report destinations, and likely related services. DNS errors stay distinct from absent and malformed records.
- **Mail routing and DNSSEC:** MX, MTA-STS, SMTP TLS reporting, nameservers, and SOA. DNSSEC records DS and DNSKEY query states and separates secure, unsigned, broken, lookup-error, and unknown results. A child DNSKEY without a parent DS remains visible as evidence of an unsigned chain. DKIM selectors are not probed because a domain's selector set cannot be discovered comprehensively.
- **Root HTTP and security.txt:** before the security.txt GET, make a bounded, bodyless `HEAD /` over HTTP and follow up to five redirects. Record whether the observed root response chain upgrades to HTTPS, its status and redirect path, TLS verification, and selected server/security headers including HSTS. Then make a bounded GET only for `http://{domain}/.well-known/security.txt`; follow up to five redirects, and try the HTTPS URL only when the HTTP request fails before receiving any response. Record endpoint availability (`present`, `absent`, `http_error`, or `lookup_error`), RFC 9116 content validity (`valid`, `invalid`, or `not_assessable`), expiry freshness (`current`, `expired`, or `unknown`), certificate verification (`valid`, `invalid`, `not_observed`, or `error`), final status, redirect path, cross-host redirect evidence, and selected headers from the security.txt request chain. Only a final 404 or 410 counts as absent. The root HEAD reports redirects observed for this request; it does not model browser-cached HSTS or other client-side upgrades.

The security.txt response body is limited to 32 KiB and is processed in memory, then discarded. The validator requires strict UTF-8 text served as `text/plain` (charset absent or UTF-8), LF or CRLF line endings, valid field lines, at least one URI-valid `Contact`, and exactly one RFC 3339 `Expires`. It accepts lowercase or uppercase `T`/`Z`, fractional seconds, timezone offsets, repeated `Contact` fields, RFC 9116 optional URI fields and `Preferred-Languages`, extension fields, and structurally valid OpenPGP clear-signed files. A past but well-formed `Expires` is reported as expired/stale rather than malformed. Signed-file structure is checked, but signatures are not cryptographically verified. Bodies above 32 KiB or beyond the parser's line/field safety limits are not assessable. Certificate details, TLS metadata, web DNS, response bodies, parsed security.txt field values, and hashes are not stored; only TLS certificate verification outcomes are retained. Requests only target globally routable addresses; redirect targets are resolved and checked independently. Each request chain has a five-second deadline. Each domain's email and web checks run sequentially, with four in-flight domains per shard.

## Collection and snapshots

The **Refresh .au security data and publish Pages** workflow runs Mondays at 03:00 Australia/Sydney time and supports **Run workflow**. It downloads and validates the complete current Tranco list before changing ranks. It divides the tracked roster into flat shards of at most 200 domains, runs up to eight shards concurrently, and keeps the 0.15-second inter-domain submission delay. Each shard allows four in-flight domain probes and prints progress counts and an ETA every 25 completions.

Completed shards are uploaded as run artifacts. The merge stage checks that every expected domain appears exactly once, publishes a schema-v5 gzip-compressed JSON snapshot and gzip-compressed JSONL email archive, then writes the updated roster. The plain JSON index stores summaries for trend charts. The collector prints serialized and gzip size estimates by field and stops with a size breakdown if either generated compressed file exceeds 45 MiB. Failed shard jobs can be rerun using successful shard artifacts; there are no per-domain checkpoints. Dated snapshots are retained indefinitely.

The checked-in `site/data/registry.json` and schema-v5 index are empty to start history fresh. No old snapshot is used to seed the roster.

## Run locally

Python 3.10 or newer is required. The collector pins its DNS, DNSSEC, and email-record parsing dependencies in `requirements.txt`.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m collector.scan
python -m http.server 8000 --directory site
```

Open `http://localhost:8000`. A full collection reads the Tranco top million and checks the ranked `.au` set. `python -m collector.workflow prepare --rank-limit 10` can exercise input preparation against a compatible short Tranco response; it does not bypass full-list validation for normal runs.

Provider mappings for mail platforms are in `collector/providers.json`. Unknown observed mail-related hostnames remain visible as `Unclassified` clues.

## GitHub Pages setup

Push the repository to GitHub and set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**. The workflow publishes site-only pushes without starting a scan. Scheduled/manual runs save the snapshot and roster, then deploy the site in the same run. The workflow declares minimal per-job permissions for artifact reads, snapshot commits, and Pages deployment.

## Offline checks

```sh
python3 -m unittest discover -s tests -v
node --check site/app.js
node tests/test_dashboard.js
```
