// Fetches public sources and writes validated JSON snapshots to data/. Node 20+, no dependencies.
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const CATEGORY_RULES = [
  ['Ransomware', /ransomware|lockbit|extortion gang/i], ['Data breach', /data breach|leak(ed|s)?\b|exposed data|stolen data/i],
  ['Phishing', /phish|smishing|credential harvest/i], ['Supply-chain compromise', /supply[- ]chain|npm package|pypi|malicious package/i],
  ['DDoS and service disruption', /ddos|outage|service disruption/i], ['Exploited vulnerability', /actively exploited|zero[- ]day|exploited in the wild|known exploited/i],
  ['Patch release', /patch tuesday|security update|patches|hotfix/i], ['Malware', /malware|trojan|botnet|backdoor|infostealer|spyware/i],
];
export const categorize = (text, kind) => (CATEGORY_RULES.find(([, re]) => re.test(text)) || [kind === 'advisory' ? 'Security advisory' : 'Security advisory'])[0];
export const safeUrl = (u) => { try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:' ? x.href : null; } catch { return null; } };

const decode = (s) => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]*>/g, ' ')
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/\s+/g, ' ').trim();
const tag = (block, name) => { const m = block.match(new RegExp('<' + name + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + name + '>', 'i')); return m ? m[1] : ''; };

// Minimal RSS/Atom parser. Output text is plain; the front end renders it with textContent only.
export function parseFeed(xml, feed, limit = 40) {
  const blocks = xml.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) || [];
  return blocks.slice(0, limit).map((b) => {
    const title = decode(tag(b, 'title'));
    let url = decode(tag(b, 'link')) || (b.match(/<link[^>]*href="([^"]+)"/i) || [])[1] || decode(tag(b, 'guid'));
    url = safeUrl(url);
    const raw = decode(tag(b, 'description') || tag(b, 'summary') || tag(b, 'content'));
    const summary = raw.length > 240 ? raw.slice(0, 237).trimEnd() + '…' : raw; // short excerpt only
    const pub = Date.parse(decode(tag(b, 'pubDate') || tag(b, 'published') || tag(b, 'updated') || tag(b, 'dc:date')));
    if (!title || !url) return null;
    return { id: url, title, summary, source: feed.name, kind: feed.kind, category: categorize(title + ' ' + raw, feed.kind),
      published: isNaN(pub) ? null : new Date(pub).toISOString(), url, verification: feed.official ? 'Official advisory' : 'Reported by ' + feed.name + ' (unverified by OTW)' };
  }).filter(Boolean);
}
export const dedupe = (items) => { const seen = new Set(); return items.filter((i) => !seen.has(i.id) && seen.add(i.id)); };
export const sortNew = (items, k) => items.sort((a, b) => (Date.parse(b[k]) || 0) - (Date.parse(a[k]) || 0));

export function mapKev(j) {
  if (!j || !Array.isArray(j.vulnerabilities)) throw new Error('KEV: unexpected format');
  return sortNew(j.vulnerabilities.map((v) => ({ cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, dateAdded: v.dateAdded, dueDate: v.dueDate || null, action: v.requiredAction, ransomware: v.knownRansomwareCampaignUse })), 'dateAdded');
}
export function mapNvd(j) {
  if (!j || !Array.isArray(j.vulnerabilities)) throw new Error('NVD: unexpected format');
  return sortNew(j.vulnerabilities.map(({ cve: c }) => {
    const m = c.metrics || {}, k = (m.cvssMetricV31 || m.cvssMetricV40 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
    const d = (c.descriptions || []).find((x) => x.lang === 'en'); const prods = new Set();
    (c.configurations || []).forEach((cf) => (cf.nodes || []).forEach((n) => (n.cpeMatch || []).forEach((p) => { const a = (p.criteria || '').split(':'); if (a[3]) prods.add(a[3] + ' ' + a[4]); })));
    return { id: c.id, description: d ? d.value : '', published: c.published, modified: c.lastModified, score: k ? k.cvssData.baseScore : null,
      severity: k ? (k.cvssData.baseSeverity || k.baseSeverity || null) : null, products: [...prods].slice(0, 10), refs: (c.references || []).map((r) => r.url).filter(safeUrl).slice(0, 10) };
  }), 'published');
}
export function validate(snapshot, minItems = 1) {
  if (!snapshot || !Array.isArray(snapshot.items) || snapshot.items.length < minItems) return false;
  return !!Date.parse(snapshot.generatedAt);
}

async function get(url, ms = 25000) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), ms);
  try {
    const r = await fetch(url, { signal: c.signal, headers: { 'User-Agent': 'OpenThreatWatch/1.0 (+public GitHub Pages aggregator)' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r;
  } finally { clearTimeout(t); }
}
async function save(path, snapshot, minItems = 1) {
  if (!validate(snapshot, minItems)) { console.error('SKIP ' + path + ': validation failed, keeping previous snapshot'); return false; }
  await writeFile(path, JSON.stringify(snapshot)); console.log('WROTE ' + path + ' (' + snapshot.items.length + ' items)'); return true;
}
async function main() {
  const cfg = JSON.parse(await readFile(new URL('./sources.json', import.meta.url)));
  const now = () => new Date().toISOString();
  try { await save('data/kev.json', { generatedAt: now(), source: cfg.kevUrl, items: mapKev(await (await get(cfg.kevUrl)).json()) }); } catch (e) { console.error('KEV failed: ' + e.message); }
  try {
    const end = new Date(), start = new Date(end - cfg.nvdDays * 864e5);
    const u = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200&pubStartDate=' + start.toISOString().replace('Z', '') + '&pubEndDate=' + end.toISOString().replace('Z', '');
    await save('data/cves.json', { generatedAt: now(), source: 'NIST NVD', items: mapNvd(await (await get(u, 60000)).json()) });
  } catch (e) { console.error('NVD failed: ' + e.message); }
  const status = []; let all = [];
  for (const f of cfg.feeds) {
    try { const items = parseFeed(await (await get(f.url)).text(), f); all = all.concat(items); status.push({ name: f.name, url: f.url, kind: f.kind, ok: true, count: items.length }); }
    catch (e) { status.push({ name: f.name, url: f.url, kind: f.kind, ok: false, error: e.message }); console.error(f.name + ' failed: ' + e.message); }
  }
  await save('data/news.json', { generatedAt: now(), feedStatus: status, items: sortNew(dedupe(all), 'published').slice(0, 400) });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
