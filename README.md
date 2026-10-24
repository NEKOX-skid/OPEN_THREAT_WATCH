# Open Threat Watch (OTW)

[![Update threat data](https://github.com/NEKOX-skid/OPEN_THREAT_WATCH/actions/workflows/update-threat-data.yml/badge.svg)](https://github.com/NEKOX-skid/OPEN_THREAT_WATCH/actions/workflows/update-threat-data.yml)

> **Observe threats. Verify intelligence. Defend systems.**

Open Threat Watch is a public cybersecurity intelligence dashboard. It collects the latest CVEs, CISA Known Exploited Vulnerabilities, security advisories and threat news from public sources and shows them in one place, with source links and freshness labels.

It is **database-free, account-free and anonymous by design**: a static website (HTML, CSS, vanilla JavaScript) hosted on GitHub Pages, plus a scheduled GitHub Action that saves public data as JSON snapshots in this repository.

**Live site:** https://nekox-skid.github.io/OPEN_THREAT_WATCH/

> OTW aggregates *available public intelligence*. It does not monitor all cyberattacks globally, and records can be delayed or incomplete. Always verify at the original source link.

## Features

| Page | What it shows |
|------|---------------|
| Dashboard | Counts and latest items from the loaded snapshots, plus data freshness for each source |
| CVE Explorer | NIST NVD records with severity, CVSS score, dates, products and references. Search, filters, pagination and an optional live NVD lookup |
| Known Exploited | CISA KEV catalog with remediation actions and due dates |
| Threat News | Headlines from public security RSS feeds, with category and source |
| Advisories | Official CERT and vendor advisories |
| Intel Sources | Which feeds worked on the last run |
| Report an Incident | Links to official reporting portals and responsible-disclosure guidance. Nothing is collected |
| About | Methodology and limitations |
| Privacy | What is and is not processed |

Search and filters work **only on the records in the current snapshot**, and the site says so.

## How it works

```
GitHub Action (every 6 hours)
   -> scripts/update-data.mjs fetches NVD, CISA KEV and RSS feeds
   -> validates the results
   -> writes data/kev.json, data/cves.json, data/news.json
   -> commits them to the repo
GitHub Pages serves the site, and the browser reads those JSON files.
```

- A source that fails is recorded and skipped. A failed or empty fetch **never overwrites** the last valid snapshot.
- Snapshots older than 48 hours are labelled **stale** on the site.
- Nothing is invented. If there is no data, the site shows an empty state.

## Repository layout

```
index.html, styles.css, app.js   the website (hash routing, no framework)
data/                            generated JSON snapshots
scripts/update-data.mjs          data collector (Node 20+, no dependencies)
scripts/sources.json             feed list and settings
tests/test.mjs                   parser and validation tests
.github/workflows/               scheduled update workflow
SECURITY.md                      responsible disclosure for this project
```

## Run locally

```bash
git clone https://github.com/NEKOX-skid/OPEN_THREAT_WATCH.git
cd OPEN_THREAT_WATCH
node tests/test.mjs            # run tests
node scripts/update-data.mjs   # fetch real data (internet, Node 20+)
python3 -m http.server 8080    # open http://localhost:8080
```

Open the site through a local server. Opening `index.html` directly (file://) will not load the snapshots.

## Deploy on GitHub Pages

1. Make sure the repo is **public** and `index.html` is in the repo root.
2. **Settings -> Pages -> Build and deployment**: Source = *Deploy from a branch*, Branch = `main`, folder = `/ (root)`.
3. **Settings -> Actions -> General -> Workflow permissions**: choose *Read and write permissions*.
4. **Actions -> Update threat data -> Run workflow** to create the first snapshots. After that it runs every 6 hours.

All paths are relative and routing uses `#/hash` links, so the site works under a project URL like `https://USERNAME.github.io/REPOSITORY/`.

## Add or remove data sources

Edit `scripts/sources.json`:

```json
{"name": "Example CERT", "url": "https://example.org/feed.xml", "kind": "advisory", "official": true}
```

- `kind`: `news` or `advisory`
- `official`: `true` only for CERTs and vendors. Other publications are labelled "Reported by ... (unverified by OTW)".

Commit the change and run the workflow. Feed health shows on the Intel Sources page.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Actions tab says "0 workflows" | `.github/workflows/update-threat-data.yml` is missing from `main`. Hidden folders are often skipped on upload |
| Workflow fails to push | Enable *Read and write permissions* (deploy step 3) |
| Site shows "No data has been generated yet" | Run the workflow once and check its log for `WROTE data/...` lines |
| A feed shows "Failed" on Intel Sources | The URL may have moved or blocked the request. Update `sources.json` |
| NVD returns 403 or 429 | Rate limit. The collector makes one NVD request per run. The live lookup needs about 30 seconds between searches |
| Only about 200 CVEs appear | The collector fetches one page of up to 200 recent CVEs. Paging is not implemented |
| Site shows STALE | The last successful update is older than 48 hours. Check the workflow runs |
| 404 on the Pages URL | Check the repo is public, `index.html` is in the root, and the Pages build finished |

## Privacy and security

- No accounts, cookies, analytics, advertising or database. Nothing is stored in your browser.
- Strict Content Security Policy. External text is rendered with `textContent` only, and links are validated as http(s).
- The only third-party request from the browser is the **optional, user-triggered** NVD lookup, which sends your query to `services.nvd.nist.gov`.
- Anonymity is not guaranteed. GitHub, your browser, your network provider and others may process connection metadata such as your IP address.
- No API keys are used or stored in this repository.

Report security issues in this project privately through the **Security** tab -> *Report a vulnerability* (see `SECURITY.md`). Do not include secrets or real victim data in reports.

## Data sources and credit

- [NIST National Vulnerability Database](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Public RSS/Atom feeds listed in `scripts/sources.json`

This product uses data from the NVD API but is not endorsed or certified by the NVD. Each item links to its original source. OTW shows only short excerpts and does not republish full articles.

## License

MIT. See `LICENSE`.
