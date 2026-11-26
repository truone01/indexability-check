#!/usr/bin/env node
// indexability-check: is each URL still indexable by Google?
// Checks robots.txt rules (RFC 9309), meta robots, X-Robots-Tag, canonical and status code.
// Zero dependencies, Node 18+.
// Usage: node indexability-check.mjs <url ...> [--sitemap <url>] [--max 50] [--ua Googlebot] [--json] [--public-only]

import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

const UA_HEADER = 'Mozilla/5.0 (compatible; indexability-check/1.0; +https://github.com/truone01/indexability-check)';

export function parseRobots(text) {
  const groups = [];
  let current = null;
  let lastWasAgent = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const value = m[2].trim();
    if (key === 'user-agent') {
      if (!lastWasAgent || !current) { current = { agents: [], rules: [] }; groups.push(current); }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
    } else if (key === 'allow' || key === 'disallow') {
      lastWasAgent = false;
      if (!current) continue;
      current.rules.push({ allow: key === 'allow', path: value });
    } else {
      lastWasAgent = false;
    }
  }
  return groups;
}

function rulesFor(groups, userAgent) {
  const token = userAgent.toLowerCase();
  const specific = groups.filter((g) => g.agents.some((a) => a !== '*' && token.startsWith(a)));
  if (specific.length) {
    // the most specific (longest) matching agent token wins; merge groups with that token
    const best = Math.max(...specific.flatMap((g) => g.agents.filter((a) => a !== '*' && token.startsWith(a)).map((a) => a.length)));
    return specific.filter((g) => g.agents.some((a) => a.length === best && token.startsWith(a))).flatMap((g) => g.rules);
  }
  return groups.filter((g) => g.agents.includes('*')).flatMap((g) => g.rules);
}

function patternToRegex(path) {
  const anchored = path.endsWith('$');
  const body = (anchored ? path.slice(0, -1) : path).split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp('^' + body + (anchored ? '$' : ''));
}

export function isAllowed(groups, userAgent, pathAndQuery) {
  const rules = rulesFor(groups, userAgent).filter((r) => r.path !== '');
  let best = null;
  for (const r of rules) {
    if (!patternToRegex(r.path).test(pathAndQuery)) continue;
    const len = r.path.length;
    if (!best || len > best.len || (len === best.len && r.allow && !best.allow)) best = { ...r, len };
  }
  return { allowed: !best || best.allow, rule: best ? `${best.allow ? 'Allow' : 'Disallow'}: ${best.path}` : null };
}

export function robotsDirectives(html, headers, userAgent) {
  const found = [];
  const ua = userAgent.toLowerCase().replace(/[^a-z]/g, '');
  const xrt = headers.get('x-robots-tag');
  if (xrt) {
    for (const part of xrt.split(/,(?=\s*[a-z-]+\s*:)|\n/i)) {
      const m = /^\s*([a-z-]+)\s*:\s*(.*)$/i.exec(part);
      if (m && !/^(noindex|nofollow|none|noarchive|nosnippet|max-|unavailable_after|noimageindex|notranslate|all|index|follow)/i.test(m[1])) {
        if (m[1].toLowerCase() === ua) found.push({ source: 'X-Robots-Tag', value: m[2] });
      } else {
        found.push({ source: 'X-Robots-Tag', value: part.trim() });
      }
    }
  }
  const metaRe = /<meta\b[^>]*>/gi;
  for (const tag of html.match(metaRe) ?? []) {
    const name = /\bname\s*=\s*["']?([^"'\s>]+)/i.exec(tag)?.[1]?.toLowerCase();
    const content = /\bcontent\s*=\s*["']([^"']*)["']/i.exec(tag)?.[1] ?? /\bcontent\s*=\s*([^\s>]+)/i.exec(tag)?.[1];
    if (!name || content === undefined) continue;
    if (name === 'robots' || name === ua) found.push({ source: `meta ${name}`, value: content });
  }
  const noindex = found.some((d) => /\b(noindex|none)\b/i.test(d.value));
  return { noindex, directives: found };
}

export function canonicalOf(html, headers, baseUrl) {
  const link = headers.get('link');
  if (link) {
    const m = /<([^>]+)>\s*;[^,]*rel\s*=\s*"?canonical"?/i.exec(link);
    if (m) return new URL(m[1], baseUrl).href;
  }
  for (const tag of html.match(/<link\b[^>]*>/gi) ?? []) {
    if (/\brel\s*=\s*["']?canonical\b/i.test(tag)) {
      const href = /\bhref\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
      if (href) return new URL(href, baseUrl).href;
    }
  }
  return null;
}

let publicOnly = false;
/** --public-only: refuse private, loopback, link-local and reserved addresses (for running the checker as a web service). */
export function setPublicOnly(on) { publicOnly = on; }

export function isPublicAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false; // this-net, private, loopback, multicast, reserved, broadcast
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
    if (a === 169 && b === 254) return false; // link-local, cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false; // IETF, TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
    if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
    return true;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return isPublicAddress(mapped[1]);
    const first = parseInt(lower.split(':')[0] || '0', 16);
    if ((first & 0xe000) !== 0x2000) return false; // only global unicast 2000::/3
    if (first === 0x2002) return false; // 6to4 can wrap private IPv4
    if (/^2001:(0?db8|0{0,4}):/.test(lower) || /^2001::/.test(lower)) return false; // documentation, Teredo
    return true;
  }
  return false;
}

function publicLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const bad = addresses.find((a) => !isPublicAddress(a.address));
    if (bad || !addresses.length) return callback(new Error(`refusing non-public address for ${hostname}`));
    if (options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

function fetchText(url, max = 2_000_000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return reject(new Error(`unsupported protocol ${u.protocol}`));
    if (publicOnly) {
      const host = u.hostname.replace(/^\[|\]$/g, '');
      if (u.port && u.port !== '80' && u.port !== '443') return reject(new Error('only ports 80 and 443 are checked'));
      if (net.isIP(host) && !isPublicAddress(host)) return reject(new Error('refusing non-public address'));
    }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.get(u, {
      headers: { 'user-agent': UA_HEADER, accept: 'text/html,application/xhtml+xml,*/*' },
      ...(publicOnly ? { lookup: publicLookup } : {}),
      timeout: 15000,
    }, (res) => {
      const headers = new Headers();
      for (const [k, v] of Object.entries(res.headers)) headers.set(k, Array.isArray(v) ? v.join(', ') : String(v));
      const status = res.statusCode;
      if (status >= 300 && status < 400) { res.destroy(); return resolve({ res: { status, headers }, text: '' }); }
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        chunks.push(chunk);
        if (size >= max) res.destroy();
      });
      const done = () => resolve({ res: { status, headers }, text: Buffer.concat(chunks).toString('utf8').slice(0, max) });
      res.on('end', done);
      res.on('close', done);
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timed out after 15s')));
    req.on('error', reject);
  });
}

const robotsCache = new Map();
async function robotsFor(origin) {
  if (robotsCache.has(origin)) return robotsCache.get(origin);
  let entry;
  try {
    const { res, text } = await fetchText(`${origin}/robots.txt`);
    if (res.status >= 200 && res.status < 300) entry = { status: res.status, groups: parseRobots(text) };
    else if (res.status >= 500) entry = { status: res.status, groups: parseRobots('User-agent: *\nDisallow: /'), note: 'robots.txt returns 5xx: Google treats the whole site as disallowed' };
    else entry = { status: res.status, groups: [] };
  } catch (err) {
    entry = { status: 0, groups: [], note: `robots.txt unreachable (${err.message})` };
  }
  robotsCache.set(origin, entry);
  return entry;
}

export async function checkUrl(url, userAgent) {
  const out = { url, status: null, finalUrl: url, redirects: [], problems: [], notes: [] };
  let current = url;
  for (let hop = 0; hop < 10; hop++) {
    const u = new URL(current);
    const robots = await robotsFor(u.origin);
    if (robots.note) out.notes.push(robots.note);
    const verdict = isAllowed(robots.groups, userAgent, u.pathname + u.search);
    if (!verdict.allowed) out.problems.push(`blocked by robots.txt (${verdict.rule}) at ${u.origin}/robots.txt`);
    let res, text;
    try {
      ({ res, text } = await fetchText(current));
    } catch (err) {
      out.problems.push(`fetch failed: ${err.message}`);
      return out;
    }
    out.status = res.status;
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      const next = new URL(res.headers.get('location'), current).href;
      out.redirects.push(`${res.status} -> ${next}`);
      current = next;
      continue;
    }
    out.finalUrl = current;
    if (res.status !== 200) out.problems.push(`HTTP ${res.status}`);
    const rd = robotsDirectives(text, res.headers, userAgent);
    if (rd.noindex) out.problems.push(`noindex (${rd.directives.filter((d) => /\b(noindex|none)\b/i.test(d.value)).map((d) => `${d.source}: ${d.value}`).join('; ')})`);
    const canonical = canonicalOf(text, res.headers, current);
    out.canonical = canonical;
    if (canonical) {
      const c = new URL(canonical);
      if (c.host !== new URL(current).host) out.problems.push(`canonical points to another host: ${canonical}`);
      else if (c.href.replace(/\/$/, '') !== new URL(current).href.replace(/\/$/, '')) out.notes.push(`canonical points to another URL: ${canonical}`);
    }
    if (out.redirects.length) out.notes.push(`redirects: ${out.redirects.join(', ')}`);
    out.problems = [...new Set(out.problems)];
    out.notes = [...new Set(out.notes)];
    return out;
  }
  out.problems.push('more than 10 redirects');
  return out;
}

async function sitemapUrls(url, max, seen = new Set()) {
  if (seen.has(url) || seen.size > 20) return [];
  seen.add(url);
  const { res, text } = await fetchText(url, 20_000_000);
  if (res.status !== 200) throw new Error(`sitemap ${url} returned HTTP ${res.status}`);
  const locs = [...text.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1].replace(/&amp;/g, '&'));
  if (/<sitemapindex/i.test(text)) {
    const urls = [];
    for (const child of locs) {
      if (urls.length >= max) break;
      urls.push(...(await sitemapUrls(child, max - urls.length, seen)));
    }
    return urls.slice(0, max);
  }
  return locs.slice(0, max);
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name, def) => { const i = args.indexOf(name); if (i === -1) return def; const v = args[i + 1]; args.splice(i, 2); return v; };
  const sitemap = opt('--sitemap', null);
  const max = Number(opt('--max', '50'));
  const userAgent = opt('--ua', 'Googlebot');
  const json = args.includes('--json');
  setPublicOnly(args.includes('--public-only'));
  const urls = args.filter((a) => !a.startsWith('--'));
  if (sitemap) urls.push(...(await sitemapUrls(sitemap, max)));
  if (!urls.length) {
    console.error('Usage: node indexability-check.mjs <url ...> [--sitemap <url>] [--max 50] [--ua Googlebot] [--json] [--public-only]');
    process.exit(2);
  }
  const results = [];
  for (const u of urls) results.push(await checkUrl(u, userAgent));
  const bad = results.filter((r) => r.problems.length);
  if (json) {
    console.log(JSON.stringify({ userAgent, checked: results.length, problems: bad.length, results }, null, 2));
  } else {
    for (const r of results) {
      console.log(`${r.problems.length ? 'FAIL' : 'ok  '}  ${r.url}${r.status ? `  [${r.status}]` : ''}`);
      for (const p of r.problems) console.log(`        - ${p}`);
      for (const n of r.notes) console.log(`        · ${n}`);
    }
    console.log(`\n${results.length} URL(s) checked as ${userAgent}, ${bad.length} not indexable.`);
  }
  process.exit(bad.length ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('indexability-check.mjs')) {
  main().catch((err) => { console.error(err.message); process.exit(3); });
}
