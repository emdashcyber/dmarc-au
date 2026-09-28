# .au Mail Authentication Observatory

A static dashboard and scheduled collector for email-authentication DNS records published by ranked `.au` domains.

The collector fetches the latest Tranco top one million list, preserves the rank and exact listed name for every entry ending at the `.au` label boundary, and checks public DNS. Each run creates a dated JSON snapshot under `site/data/snapshots/` and updates `site/data/index.json`. Snapshots are retained in the repository for historical comparison.

## Signals collected

- **SPF:** record presence and validity, DNS and void lookup counts, parsed mechanisms, include/redirect service targets, warnings, and the effective terminal result. The terminal result distinguishes `-all` hard fail, `~all` softfail, `?all` neutral, `+all` pass, and an implicit neutral result when no `all` or `redirect=` is published.
- **DMARC:** record presence and validity, RFC 9989 discovery location, `p`/`sp`/`np` policies, SPF/DKIM alignment modes, test mode, report destinations, and warnings.
- **Related mail posture:** MX routing, MTA-STS, SMTP TLS reporting, DNSSEC chain status, nameservers, and SOA data.
- **DKIM:** DNS TXT probes for a versioned set of common selectors. A match is useful evidence; no match is inconclusive because selectors are not exhaustively discoverable.
- **Likely services:** inferred from published SPF include/redirect targets, MX names, and DMARC report destinations. Observed hostnames remain visible in the snapshot and provider labels are not claims about a service contract.

DNS timeouts and other transient lookup failures are stored as `lookup_error`. They are never counted as missing records. SPF/DMARC status values are `present_valid`, `present_invalid`, `absent`, or `lookup_error`. DNSSEC is classified as `secure`, `unsigned`, `broken`, `lookup_error`, or `unknown`. A DNSKEY without a parent DS is unsigned; DS/DNSKEY query evidence, MX-host diagnostics, and full checker output are retained in the raw archive.

## Run locally

Python 3.10 or newer is required.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m collector.scan
python -m http.server 8000 --directory site
```

Open `http://localhost:8000`. A full collection reads the Tranco top one million and checks all matching `.au` entries. It prints progress every 25 names, keeps the 0.15-second inter-domain pause, and writes a compressed full-output JSONL archive beside each normalized snapshot. A test-only rank limit is available, for example `python -m collector.scan --rank-limit 10`, when exercising the source parser against a compatible short list response.

The service mapping lives in `collector/providers.json`; unmatched DNS hostnames are retained as `Unclassified` clues.

## GitHub Actions and Pages

The **Refresh .au email data and publish Pages** workflow:

- Runs Mondays at 03:00 Australia/Sydney time and can also be started with **Run workflow**.
- Deploys site-only changes on pushes to `main` without starting a DNS scan.
- Downloads Tranco once, keeps the `.au` names in rank order, and splits that flat list into jobs of at most 200 domains. Up to four jobs run concurrently, with progress logged every 25 names.
- Saves each completed shard as a run artifact and validates that every expected rank/name appears exactly once before merging. If a shard fails, **Re-run failed jobs** retries failed jobs and their dependent merge/deploy jobs without rescanning successful shards. There is no per-domain checkpoint, so a retry may repeat up to 200 domains.
- Commits each complete normalized snapshot and compressed JSONL archive of the full checker, DKIM, and DNSSEC observations, then deploys the site in the same scheduled or manual run.
- Disables MX SMTP/TLS probing; checks use DNS records and the MTA-STS policy file only.

To publish, push this repository to GitHub, set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**, and allow Actions to write repository contents if the organization’s token policy restricts it. The workflow already declares the required `contents`, `pages`, and OIDC permissions. Run it once manually to create the first dataset. Later code pushes publish the site without rescanning domains.

## Snapshot format

Each snapshot includes `schema_version`, UTC collection time, Tranco list ID and rank limit, checker version, collection settings, aggregate summary counts, a raw archive path, and one normalized result per matching ranked name. The gzip-compressed JSON Lines archive contains one row per ranked name with the full checker output and additional DNS evidence. The index stores each snapshot and archive path, date, and summary; the dashboard loads the normalized snapshot on demand and links to the raw archive.

The dataset represents published DNS configuration at scan time. It does not measure whether a specific email passed authentication or the volume of mail a domain sends.

## Offline checks

```sh
python -m unittest discover -s tests -v
node --check site/app.js
```
