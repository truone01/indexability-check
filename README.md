# indexability-check

Is every important URL on your site still indexable by Google? One file, zero dependencies, Node 18+. Run it after each deploy, locally or in CI.

It catches the deploy mistakes that quietly drop pages out of Google:
- **robots.txt** blocking the URL (RFC 9309 matching: user-agent groups, longest match, `*` and `$`), including a robots.txt that returns 5xx, which Google treats as "disallow everything"
- **noindex** in `<meta name="robots">`, `<meta name="googlebot">` or the `X-Robots-Tag` header (including `googlebot:`-scoped values)
- a **canonical pointing to another host** (the classic: `staging.example.com` left in the template), in HTML or the `Link` header
- **non-200 status** after following redirects

```text
$ node indexability-check.mjs https://github.com/ https://github.com/settings
ok    https://github.com/  [200]
FAIL  https://github.com/settings  [200]
        - blocked by robots.txt (Disallow: /settings$) at https://github.com/robots.txt
        - blocked by robots.txt (Disallow: /*?return_to=*) at https://github.com/robots.txt
        · canonical points to another URL: https://github.com/login
        · redirects: 302 -> https://github.com/login?return_to=https%3A%2F%2Fgithub.com%2Fsettings

2 URL(s) checked as Googlebot, 1 not indexable.
```
(Real output, 26 November 2026.)

## Use

```bash
curl -O https://raw.githubusercontent.com/truone01/indexability-check/main/indexability-check.mjs
node indexability-check.mjs https://example.com/ https://example.com/pricing
node indexability-check.mjs --sitemap https://example.com/sitemap.xml --max 200
node indexability-check.mjs https://example.com/ --ua Bingbot --json
```

Exit code 1 means at least one URL isn't indexable, so it can fail a pipeline.

### After every deploy (GitHub Actions)

```yaml
- name: Indexability check
  run: |
    curl -sO https://raw.githubusercontent.com/truone01/indexability-check/main/indexability-check.mjs
    node indexability-check.mjs --sitemap https://example.com/sitemap.xml --max 100
```

## Limits

It reads the HTML the server returns. It doesn't run JavaScript, so a `noindex` injected client-side isn't seen (Google may render it). It checks what's true now. It doesn't watch for changes between deploys, or for edits made outside your pipeline (a CMS setting, a plugin update, a CDN rule).

If you look after **many client sites**, a hosted version is in development, **CrawlCanary**: it checks your important URLs every hour and emails you the moment one stops being indexable, whatever caused it. It isn't available yet. Price and waitlist: https://crawlcanary.2-29-18-178.sslip.io/?ref=github

## Test

`node tests/test.mjs` runs the offline tests for robots.txt matching, robots directives and canonicals.

## Licence

MIT. Issues and pull requests are welcome.
