'use strict';
const STALE_HOURS = 48, PAGE = 25, NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGES = [['/', 'Dashboard'], ['/cve', 'CVE Explorer'], ['/kev', 'Known Exploited'], ['/news', 'Threat News'], ['/advisories', 'Advisories'], ['/sources', 'Intel Sources'], ['/report', 'Report an Incident'], ['/about', 'About'], ['/privacy', 'Privacy']];
const CATS = ['Ransomware', 'Data breach', 'Phishing', 'Malware', 'Exploited vulnerability', 'Supply-chain compromise', 'DDoS and service disruption', 'Security advisory', 'Patch release'];
const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const $ = (s) => document.querySelector(s);

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}
function safeUrl(u) { try { const x = new URL(u); return (x.protocol === 'https:' || x.protocol === 'http:') ? x.href : null; } catch { return null; } }
function link(u, text) { const s = safeUrl(u); return s ? h('a', { href: s, rel: 'noopener noreferrer nofollow', target: '_blank' }, text || s) : h('span', {}, text || '(invalid link)'); }
const fmtDate = (d) => { const t = Date.parse(d); return isNaN(t) ? '—' : new Date(t).toISOString().slice(0, 10); };
const badge = (s) => h('span', { class: 'b ' + (SEV.includes(s) ? s : '') }, s || 'N/A');

const snaps = {};
async function snap(name) {
  if (snaps[name]) return snaps[name];
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 15000);
    const r = await fetch('data/' + name + '.json', { cache: 'no-cache', signal: ctl.signal }); clearTimeout(t);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    if (!j || !Array.isArray(j.items)) throw new Error('Bad format');
    return (snaps[name] = j);
  } catch (e) { return (snaps[name] = { items: [], generatedAt: null, error: String(e.message || e) }); }
}
function fresh(s) {
  if (s.error) return h('div', { class: 'warn err' }, 'Snapshot unavailable (' + s.error + '). Nothing is shown rather than inventing records.');
  if (!s.generatedAt) return h('div', { class: 'warn' }, 'No data has been generated yet. Run the update workflow (see README). Records shown: 0.');
  const age = (Date.now() - Date.parse(s.generatedAt)) / 36e5, stale = age > STALE_HOURS;
  return h('div', { class: 'warn' + (stale ? ' err' : '') }, (stale ? 'STALE: ' : 'Fresh: ') + 'snapshot generated ' + s.generatedAt + ' (' + Math.round(age) + 'h ago). Search covers only the ' + s.items.length + ' records in this snapshot.');
}

function table(cols, rows) {
  const wrap = h('div'); let page = 0;
  function draw() {
    wrap.replaceChildren();
    if (!rows.length) { wrap.append(h('p', { class: 'note' }, 'No matching records.')); return; }
    const max = Math.ceil(rows.length / PAGE); page = Math.min(page, max - 1);
    const slice = rows.slice(page * PAGE, page * PAGE + PAGE);
    wrap.append(h('div', { class: 'tw' }, h('table', {}, h('thead', {}, h('tr', {}, cols.map((c) => h('th', { scope: 'col' }, c[0])))),
      h('tbody', {}, slice.map((r) => h('tr', {}, cols.map((c) => h('td', {}, c[1](r)))))))),
      h('div', { class: 'pager' }, h('button', { disabled: page === 0 ? 'disabled' : false, onclick: () => { page--; draw(); } }, 'Prev'),
        h('span', {}, 'Page ' + (page + 1) + ' of ' + max + ' (' + rows.length + ' records)'),
        h('button', { disabled: page >= max - 1 ? 'disabled' : false, onclick: () => { page++; draw(); } }, 'Next')));
  }
  draw(); return wrap;
}
function filtered(items, controls, test) {
  const out = h('div'); const bar = h('div', { class: 'bar' }, controls.map((c) => c.el));
  const run = () => { out.replaceChildren(table(out._cols, items.filter((i) => test(i, controls.map((c) => c.el.value))))); };
  controls.forEach((c) => c.el.addEventListener('input', run));
  return { bar, out, run };
}
const sel = (label, opts) => ({ el: h('select', { 'aria-label': label }, h('option', { value: '' }, label + ': all'), opts.map((o) => h('option', { value: o }, o))) });
const txt = (label) => ({ el: h('input', { type: 'search', placeholder: label, 'aria-label': label, maxlength: '100' }) });
const date = (label) => ({ el: h('input', { type: 'date', 'aria-label': label, title: label, style: 'min-width:0;flex:0' }) });
const has = (s, q) => !q || String(s || '').toLowerCase().includes(q.toLowerCase());

const cveCols = [['CVE', (r) => link('https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(r.id), r.id)], ['Severity', (r) => [badge(r.severity), r.score != null ? ' ' + r.score : '']],
  ['Description', (r) => (r.description || '').slice(0, 300)], ['Published', (r) => fmtDate(r.published)], ['Modified', (r) => fmtDate(r.modified)],
  ['Products', (r) => (r.products || []).slice(0, 3).join(', ') || '—'], ['References', (r) => (r.refs || []).slice(0, 3).map((u, i) => [link(u, 'ref' + (i + 1)), ' '])]];
const kevCols = [['CVE', (r) => link('https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(r.cve), r.cve)], ['Vendor / product', (r) => r.vendor + ' / ' + r.product], ['Name', (r) => r.name],
  ['Added', (r) => fmtDate(r.dateAdded)], ['Due', (r) => fmtDate(r.dueDate)], ['Required action', (r) => r.action]];
const newsCols = [['Headline', (r) => link(r.url, r.title)], ['Summary', (r) => r.summary || '—'], ['Source', (r) => r.source], ['Category', (r) => r.category], ['Status', (r) => r.verification], ['Published', (r) => fmtDate(r.published)]];

function parseNvd(v) {
  const c = v.cve, m = c.metrics || {}, k = (m.cvssMetricV31 || m.cvssMetricV40 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
  const d = (c.descriptions || []).find((x) => x.lang === 'en');
  const prods = new Set(); (c.configurations || []).forEach((cf) => (cf.nodes || []).forEach((n) => (n.cpeMatch || []).forEach((p) => { const a = (p.criteria || '').split(':'); if (a[3]) prods.add(a[3] + ' ' + a[4]); })));
  return { id: c.id, description: d ? d.value : '', published: c.published, modified: c.lastModified, score: k ? k.cvssData.baseScore : null, severity: k ? (k.cvssData.baseSeverity || k.baseSeverity || null) : null, products: [...prods].slice(0, 10), refs: (c.references || []).map((r) => r.url).filter(safeUrl).slice(0, 10) };
}

const views = {
  async '/'(m) {
    const [kev, news, cves] = await Promise.all([snap('kev'), snap('news'), snap('cves')]);
    const crit = cves.items.filter((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH');
    m.append(h('h1', {}, 'Dashboard'), h('p', { class: 'note' }, 'Counts reflect only the loaded snapshots, not global totals.'),
      h('div', { class: 'grid' }, [['CVEs in snapshot', cves.items.length], ['Critical/High in snapshot', crit.length], ['KEV entries', kev.items.length], ['News & advisories', news.items.length]].map((x) => h('div', { class: 'card' }, h('div', { class: 'note' }, x[0]), h('strong', {}, x[1])))),
      h('h2', {}, 'Data freshness'), ['kev', 'news', 'cves'].map((n, i) => [h('div', { class: 'note' }, n.toUpperCase()), fresh([kev, news, cves][i])]),
      h('h2', {}, 'Latest critical/high CVEs'), table(cveCols.slice(0, 4), crit.slice(0, 10)),
      h('h2', {}, 'Recently added to CISA KEV'), table(kevCols.slice(0, 4), kev.items.slice(0, 10)),
      h('h2', {}, 'Latest news'), table(newsCols.slice(0, 5).filter((_, i) => i !== 1), news.items.slice(0, 10)));
  },
  async '/cve'(m) {
    const s = await snap('cves');
    m.append(h('h1', {}, 'CVE Explorer'), fresh(s), h('p', { class: 'note' }, 'Data: NIST NVD. Severity and scores appear only when NVD provides them.'));
    const f = filtered(s.items, [txt('CVE ID or keyword'), sel('Severity', SEV), date('Published on/after')], (r, [q, sv, d]) => (!q || has(r.id + ' ' + r.description + ' ' + (r.products || []).join(' '), q)) && (!sv || r.severity === sv) && (!d || fmtDate(r.published) >= d));
    f.out._cols = cveCols; m.append(f.bar, f.out); f.run();
    const q = txt('Live NVD query (CVE ID or keyword)'), status = h('p', { class: 'note' }), live = h('div');
    m.append(h('h2', {}, 'Live NVD lookup (optional)'), h('p', { class: 'note' }, 'Pressing Search sends your query directly from your browser to services.nvd.nist.gov. Nothing goes anywhere else. NVD enforces rate limits (without a key, about 5 requests per 30 seconds).'),
      h('div', { class: 'bar' }, q.el, h('button', { onclick: async () => {
        const v = q.el.value.trim(); if (!v) return; status.textContent = 'Querying NVD…'; live.replaceChildren();
        const u = /^CVE-\d{4}-\d{4,}$/i.test(v) ? NVD + '?cveId=' + encodeURIComponent(v.toUpperCase()) : NVD + '?resultsPerPage=25&keywordSearch=' + encodeURIComponent(v);
        try { const c = new AbortController(); const t = setTimeout(() => c.abort(), 20000); const r = await fetch(u, { signal: c.signal }); clearTimeout(t);
          if (r.status === 403 || r.status === 429) throw new Error('rate limited by NVD; wait ~30s and retry');
          if (!r.ok) throw new Error('HTTP ' + r.status);
          const j = await r.json(); const rows = (j.vulnerabilities || []).map(parseNvd); status.textContent = rows.length + ' result(s) of ' + (j.totalResults || 0) + ' total from NVD (showing up to 25).'; live.append(table(cveCols, rows));
        } catch (e) { status.textContent = 'NVD unavailable: ' + (e.name === 'AbortError' ? 'timeout' : e.message) + '. Try ' + 'https://nvd.nist.gov/vuln/search directly.'; } } }, 'Search')), status, live);
  },
  async '/kev'(m) {
    const s = await snap('kev');
    m.append(h('h1', {}, 'Known Exploited Vulnerabilities'), h('div', { class: 'warn' }, 'A KEV listing means exploitation in the wild has been observed for that vulnerability. It does not mean every device running the affected product is compromised.'), fresh(s), h('p', {}, 'Source: ', link('https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'CISA KEV catalog')));
    const f = filtered(s.items, [txt('CVE, vendor, product or name'), date('Added on/after')], (r, [q, d]) => has([r.cve, r.vendor, r.product, r.name].join(' '), q) && (!d || fmtDate(r.dateAdded) >= d));
    f.out._cols = kevCols; m.append(f.bar, f.out); f.run();
  },
  async '/news'(m) { await newsPage(m, 'Threat News', 'news'); },
  async '/advisories'(m) { await newsPage(m, 'Security Advisories', 'advisory'); },
  async '/sources'(m) {
    const s = await snap('news');
    m.append(h('h1', {}, 'Threat Intelligence Sources'), h('p', { class: 'note' }, 'Feed health from the last snapshot run. Configure sources in scripts/sources.json.'), fresh(s),
      table([['Source', (r) => link(r.url, r.name)], ['Kind', (r) => r.kind], ['Last run', (r) => r.ok ? 'OK (' + r.count + ' items)' : 'Failed: ' + r.error]], s.feedStatus || []),
      h('ul', {}, [['https://nvd.nist.gov/developers/vulnerabilities', 'NIST NVD API'], ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'CISA KEV']].map((x) => h('li', {}, link(x[0], x[1])))));
  },
  async '/report'(m) {
    const guide = { Phishing: [['https://www.cisa.gov/report', 'CISA: report cyber incidents (US)'], ['https://reportphishing.apwg.org/', 'APWG: forward phishing'], ['https://www.ic3.gov/', 'FBI IC3 (US)']], Malware: [['https://www.cisa.gov/report', 'CISA incident reporting (US)'], ['https://www.virustotal.com/', 'VirusTotal (public: files you submit become visible to others)']], 'Suspected compromise': [['https://www.cisa.gov/report', 'CISA (US)'], ['https://www.ncsc.gov.uk/section/about-this-website/report-scam-website', 'UK NCSC reporting'], ['https://www.first.org/members/teams', 'FIRST: find your national CERT']], 'Vulnerability': [['https://www.kb.cert.org/vuls/report/', 'CERT/CC vulnerability reporting'], ['https://cveform.mitre.org/', 'MITRE CVE request form'], ['https://www.cisa.gov/coordinated-vulnerability-disclosure-process', 'CISA coordinated disclosure']] };
    const out = h('div'); const s = h('select', { 'aria-label': 'Incident category' }, h('option', { value: '' }, 'Choose a category'), Object.keys(guide).map((k) => h('option', { value: k }, k)));
    s.addEventListener('input', () => out.replaceChildren(h('ul', {}, (guide[s.value] || []).map((x) => h('li', {}, link(x[0], x[1]))))));
    m.append(h('h1', {}, 'Report an Incident'), h('div', { class: 'warn err' }, 'OTW does not collect or store reports. Never post passwords, tokens, stolen personal data, or victim information on public websites.'), h('p', {}, 'Choose a category to find official reporting channels. Links go to external sites that have their own privacy practices; verify the URL before sending anything.'), s, out,
      h('h2', {}, 'Responsible disclosure'), h('p', {}, 'Report vulnerabilities privately to the vendor first (look for a security.txt or security page) or to a coordinator such as CERT/CC. Allow reasonable time to fix, avoid accessing data that is not yours, and do not publish exploit details before a fix is available. Outside the US, find your national CERT via FIRST.'));
  },
  async '/about'(m) {
    m.append(h('h1', {}, 'About and Methodology'), h('p', {}, 'Open Threat Watch is a static aggregator of available public intelligence. It is not a complete view of global attacks, and records can be delayed or incomplete.'),
      h('ul', {}, ['A scheduled GitHub Action fetches NVD, CISA KEV and RSS feeds and commits validated JSON snapshots; the site reads those files.', 'A failed or empty fetch never overwrites a previous valid snapshot.', 'Snapshots older than ' + STALE_HOURS + ' hours are labelled stale.', 'News categories are assigned by keyword matching on titles and summaries and can be wrong. Treat them as hints.', 'Items from CERTs and vendors are labelled official; items from publications are labelled as reported by that outlet. Verify at the original link.', 'Severity and CVSS values are NVD data and are never estimated here.']
        .map((t) => h('li', {}, t))), h('p', {}, 'Categories: ' + CATS.join(', ') + '.'));
  },
  async '/privacy'(m) {
    m.append(h('h1', {}, 'Privacy and Responsible Disclosure'), h('p', {}, 'OTW has no accounts, cookies, analytics, advertising, or database, and stores nothing in your browser. It does not collect personal information.'),
      h('p', {}, 'Anonymity is not guaranteed. GitHub (hosting), your browser, your network provider and other infrastructure may process connection metadata such as your IP address. The optional live NVD lookup sends your query and IP to NIST. External links lead to sites with their own policies. Use Tor or a VPN if you need stronger protection.'),
      h('h2', {}, 'Security issues in this site'), h('p', {}, 'Report them privately through the repository\'s GitHub Security Advisories (see SECURITY.md).'));
  },
};
async function newsPage(m, title, kind) {
  const s = await snap('news'); const items = s.items.filter((i) => i.kind === kind);
  m.append(h('h1', {}, title), fresh(s), h('p', { class: 'note' }, 'Official advisories are from CERTs/vendors; other items are reported by the named outlet and not verified by OTW.'));
  const f = filtered(items, [txt('Keyword'), sel('Category', CATS), sel('Source', [...new Set(items.map((i) => i.source))].sort()), date('Published on/after')], (r, [q, c, so, d]) => has(r.title + ' ' + r.summary, q) && (!c || r.category === c) && (!so || r.source === so) && (!d || fmtDate(r.published) >= d));
  f.out._cols = newsCols; m.append(f.bar, f.out); f.run();
}

async function route() {
  const p = (location.hash.slice(1) || '/'); const v = views[p] || views['/']; const m = $('#view');
  m.replaceChildren(h('p', { class: 'note' }, 'Loading…'));
  document.querySelectorAll('nav a').forEach((a) => a.getAttribute('href') === '#' + p ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current'));
  const frag = h('div'); try { await v(frag); } catch (e) { frag.replaceChildren(h('div', { class: 'warn err' }, 'This page failed to render: ' + e.message)); }
  m.replaceChildren(...frag.childNodes); document.title = 'Open Threat Watch'; $('#nav').classList.remove('open'); $('#menu').setAttribute('aria-expanded', 'false');
}
$('#nav').append(...PAGES.map((x) => h('a', { href: '#' + x[0] }, x[1])));
$('#menu').addEventListener('click', () => { const o = $('#nav').classList.toggle('open'); $('#menu').setAttribute('aria-expanded', String(o)); });
window.addEventListener('hashchange', () => { route(); $('#view').focus(); });
route();
