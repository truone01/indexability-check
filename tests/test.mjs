// Offline tests: node tests/test.mjs
import assert from 'node:assert/strict';
import { parseRobots, isAllowed, robotsDirectives, canonicalOf } from '../indexability-check.mjs';

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
console.log('all tests passed');
