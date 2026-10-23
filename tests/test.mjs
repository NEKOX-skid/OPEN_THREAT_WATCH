import assert from 'node:assert/strict';
import { parseFeed, dedupe, mapKev, mapNvd, validate, safeUrl, categorize } from '../scripts/update-data.mjs';
const rss = `<rss><channel><item><title>New &amp; nasty ransomware hits hospital</title><link>https://example.com/a</link><description><![CDATA[<p>Short <b>text</b></p>]]></description><pubDate>Tue, 01 Oct 2024 10:00:00 GMT</pubDate></item>
<item><title>Bad link</title><link>javascript:alert(1)</link></item></channel></rss>`;
const items = parseFeed(rss, { name: 'T', kind: 'news', official: false });
assert.equal(items.length, 1); assert.equal(items[0].category, 'Ransomware'); assert.equal(items[0].summary, 'Short text'); assert.equal(items[0].title, 'New & nasty ransomware hits hospital');
assert.equal(dedupe([...items, ...items]).length, 1); assert.equal(safeUrl('javascript:alert(1)'), null); assert.equal(categorize('x', 'advisory'), 'Security advisory');
const kev = mapKev({ vulnerabilities: [{ cveID: 'CVE-1', vendorProject: 'V', product: 'P', vulnerabilityName: 'N', dateAdded: '2024-01-02', requiredAction: 'Patch' }] });
assert.equal(kev[0].cve, 'CVE-1');
const nvd = mapNvd({ vulnerabilities: [{ cve: { id: 'CVE-2', published: '2024-01-01T00:00:00', descriptions: [{ lang: 'en', value: 'd' }], metrics: {} } }] });
assert.equal(nvd[0].score, null); assert.equal(nvd[0].severity, null);
assert.equal(validate({ generatedAt: new Date().toISOString(), items: [] }), false); assert.equal(validate({ generatedAt: 'x', items: [1] }), false); assert.equal(validate({ generatedAt: new Date().toISOString(), items: [1] }), true);
assert.throws(() => mapKev({}));
console.log('all tests passed');
