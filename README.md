# Open Threat Watch (OTW)
Database-free, account-free cybersecurity intelligence dashboard. Static site (HTML/CSS/vanilla JS) on GitHub Pages. A scheduled GitHub Action fetches public sources and commits JSON snapshots to `data/`; the site only reads those files.

Sources: NIST NVD API, CISA KEV JSON, and RSS/Atom feeds listed in `scripts/sources.json`. OTW aggregates available public intelligence; it does not monitor all attacks.

## Run locally
```bash
git clone https://github.com/USERNAME/REPOSITORY.git && cd REPOSITORY
node tests/test.mjs            # parser/validation tests
node scripts/update-data.mjs   # fetch real data (needs internet, Node 20+)
python3 -m http.server 8080    # open http://localhost:8080
```
Opening index.html via file:// will not load the snapshots; use a local server.

## Deploy
1. Create a public GitHub repo, then:
```bash
git init && git add . && git commit -m "Initial commit"
git branch -M main && git remote add origin https://github.com/USERNAME/REPOSITORY.git && git push -u origin main
```
2. Settings > Pages > Source: "Deploy from a branch", Branch `main`, folder `/ (root)`. Site: `https://USERNAME.github.io/REPOSITORY/`. All paths are relative and routing uses `#/hash`, so project URLs work.
3. Settings > Actions > General > Workflow permissions: "Read and write permissions". Then Actions tab > "Update threat data" > Run workflow. It then runs every 6 hours.

Until the first run, the site shows empty states ("No data has been generated yet"). It ships no fabricated records.

## Add or remove sources
Edit `scripts/sources.json` (`name`, `url`, `kind`: `news` or `advisory`, `official`: true only for CERTs/vendors). Feed health appears on the Intel Sources page.

## How failures are handled
Each source is fetched independently with a timeout. A failed source is recorded in `feedStatus`. A snapshot is only overwritten if it validates (non-empty, valid timestamp); otherwise the previous one stays and the site labels it stale after 48 hours. The workflow also re-validates JSON before committing.

## Troubleshooting
- Workflow cannot push: enable write permission for Actions (step 3).
- NVD 403/429: rate limit; the updater makes one request per run. The live lookup on the CVE page needs ~30s between queries.
- Feed fails: check Intel Sources; URLs may have moved, so update `sources.json`.
- Snapshot at 200 CVEs/week cap: NVD paging is not implemented; raise `resultsPerPage` limits or add paging if you need more.

## Privacy
No accounts, cookies, analytics, storage or database. Strict CSP (`script-src 'self'`; the only third-party connection is the optional, user-triggered NVD lookup). External text is rendered with `textContent` and URLs are validated for http(s). See SECURITY.md and the in-site Privacy page.
