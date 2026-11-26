// Offline tests: node tests/test.mjs
import assert from 'node:assert/strict';
import { parseRobots, isAllowed, robotsDirectives, canonicalOf, isPublicAddress } from '../indexability-check.mjs';

const robots = parseRobots(`
User-agent: *
Disallow: /admin
Allow: /admin/public
Disallow: /*.pdf$

User-agent: Googlebot
User-agent: Bingbot
Disallow: /private
`);
assert.equal(isAllowed(robots, 'Googlebot', '/admin').allowed, true, 'Googlebot group replaces *');
assert.equal(isAllowed(robots, 'Googlebot', '/private/x').allowed, false);
assert.equal(isAllowed(robots, 'SomeBot', '/admin/x').allowed, false);
assert.equal(isAllowed(robots, 'SomeBot', '/admin/public/x').allowed, true, 'longest match wins');
assert.equal(isAllowed(robots, 'SomeBot', '/file.pdf').allowed, false, '$ anchor');
assert.equal(isAllowed(robots, 'SomeBot', '/file.pdf?x=1').allowed, true, '$ anchor with query');
assert.equal(isAllowed(parseRobots('User-agent: *\nDisallow: /'), 'Googlebot', '/').allowed, false, 'disallow all');
assert.equal(isAllowed(parseRobots('User-agent: *\nDisallow:'), 'Googlebot', '/').allowed, true, 'empty disallow');
assert.equal(isAllowed(parseRobots('User-agent: *\nDisallow: /p\nAllow: /p'), 'Googlebot', '/p').allowed, true, 'tie -> allow');
assert.equal(isAllowed([], 'Googlebot', '/').allowed, true, 'no robots.txt');

const h = (o) => new Headers(o);
assert.equal(robotsDirectives('<meta name="robots" content="noindex, follow">', h({}), 'Googlebot').noindex, true);
assert.equal(robotsDirectives('<meta content="none" name="googlebot">', h({}), 'Googlebot').noindex, true);
assert.equal(robotsDirectives('<meta name="bingbot" content="noindex">', h({}), 'Googlebot').noindex, false, 'other bot');
assert.equal(robotsDirectives('<meta name="robots" content="index,follow">', h({}), 'Googlebot').noindex, false);
assert.equal(robotsDirectives('', h({ 'x-robots-tag': 'noindex' }), 'Googlebot').noindex, true);
assert.equal(robotsDirectives('', h({ 'x-robots-tag': 'bingbot: noindex' }), 'Googlebot').noindex, false);
assert.equal(robotsDirectives('', h({ 'x-robots-tag': 'googlebot: noindex' }), 'Googlebot').noindex, true);

assert.equal(canonicalOf('<link rel="canonical" href="/a">', h({}), 'https://ex.com/b'), 'https://ex.com/a');
assert.equal(canonicalOf('', h({ link: '<https://staging.ex.com/a>; rel="canonical"' }), 'https://ex.com/a'), 'https://staging.ex.com/a');
assert.equal(canonicalOf('<p>none</p>', h({}), 'https://ex.com/'), null);
for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fc00::1', 'fd12::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '2002:7f00:1::', '2001:db8::1', '64:ff9b::7f00:1', 'not-an-ip']) {
  assert.equal(isPublicAddress(ip), false, `${ip} must be refused`);
}
for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '140.82.112.3', '2606:4700::1111', '2a00:1450:4001::1', '::ffff:8.8.8.8']) {
  assert.equal(isPublicAddress(ip), true, `${ip} must be allowed`);
}
console.log('all tests passed');
