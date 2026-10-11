import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const SITE = 'https://emdashcyber.com';
const SLUG = 'dmarc-au';
const PREFIX = `/${SLUG}`;
const read = (file) => readFileSync(new URL(`../dist/${file}`, import.meta.url), 'utf8');
const deployedFile = (path) => {
  const local = path.startsWith(`${PREFIX}/`) ? path.slice(PREFIX.length) : path;
  return new URL(`../dist${local.endsWith('/') ? `${local}index.html` : local}`, import.meta.url);
};
const meta = (html, attr, name) => html.match(new RegExp(`<meta[^>]*${attr}="${name}"[^>]*content="([^"]*)"`))?.[1];
const pages = ['index.html', '404.html'];

test('pages use en-AU and carry a script-src self CSP with no inline scripts', () => {
  for (const file of pages) {
    const html = read(file);
    assert.ok(html.includes('<html lang="en-AU">'), file);
    const csp = meta(html, 'http-equiv', 'Content-Security-Policy');
    assert.ok(csp?.includes("script-src 'self';"), file);
    for (const [, attrs, body] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      if (/application\/ld\+json/.test(attrs)) continue;
      const src = attrs.match(/\bsrc="([^"]+)"/)?.[1];
      assert.ok(src && body.trim() === '', `inline script in ${file}`);
      assert.equal(new URL(src, SITE).origin, SITE, src);
      assert.ok(existsSync(deployedFile(src)), src);
    }
  }
});

test('home page head: canonical, Open Graph, Twitter large card and icons', () => {
  const html = read('index.html');
  const url = `${SITE}${PREFIX}/`;
  assert.ok(html.includes(`<link rel="canonical" href="${url}"`));
  assert.equal(meta(html, 'property', 'og:url'), url);
  assert.equal(meta(html, 'property', 'og:locale'), 'en_AU');
  assert.equal(meta(html, 'property', 'og:image'), `${SITE}${PREFIX}/og-image.png`);
  assert.equal(meta(html, 'property', 'og:image:width'), '1200');
  assert.equal(meta(html, 'property', 'og:image:height'), '630');
  assert.ok(meta(html, 'property', 'og:image:alt'));
  assert.equal(meta(html, 'name', 'twitter:card'), 'summary_large_image');
  assert.equal(meta(html, 'name', 'twitter:image'), `${SITE}${PREFIX}/og-image.png`);
  assert.ok(!html.includes('content="noindex"'));
  assert.equal([...html.matchAll(/<h1[\s>]/g)].length, 1);
  for (const file of ['og-image.png', 'apple-touch-icon.png', 'favicon-32.png', 'emdash-mark.svg', 'theme.js']) {
    assert.ok(existsSync(new URL(`../dist/${file}`, import.meta.url)), file);
  }
});

test('404 is noindex without canonical or Open Graph URL', () => {
  const html = read('404.html');
  assert.ok(html.includes('content="noindex"'));
  assert.ok(!html.includes('rel="canonical"'));
  assert.ok(!html.includes('property="og:url"'));
});

test('header has a breadcrumb nav and the shared theme toggle; footer year is current', () => {
  for (const file of pages) {
    const html = read(file);
    const header = html.match(/<header class="site-header">([\s\S]*?)<\/header>/)[1];
    assert.ok(header.includes('<nav class="crumb" aria-label="Breadcrumb">'), file);
    assert.match(header, /id="theme-toggle"[^>]*aria-pressed="false"/);
    assert.ok(html.includes('class="skip-link" href="#main"'));
    assert.ok(html.includes(`&copy; ${new Date().getFullYear()} EmDash Cyber`), file);
  }
});

test('sitemap lists the home page and internal links resolve', () => {
  const locs = [...read('sitemap.xml').matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  assert.deepEqual(locs, [`${SITE}${PREFIX}/`]);
  assert.ok(!existsSync(new URL('../dist/robots.txt', import.meta.url)));
  for (const file of pages) {
    for (const [, path] of read(file).matchAll(/(?:href|src)="(\/[^"#?]*)/g)) {
      assert.ok(existsSync(deployedFile(path)), path);
    }
  }
});

const luminance = (hex) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const ratio = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

test('light and dark palettes meet WCAG contrast and need no script', () => {
  const css = readFileSync(new URL('../src/styles/global.css', import.meta.url), 'utf8');
  assert.ok(css.includes('color-scheme: light dark;'));
  const tokens = Object.fromEntries([...css.matchAll(/--([\w-]+):\s*light-dark\((#[0-9a-f]{6}),\s*(#[0-9a-f]{6})\)/g)].map((m) => [m[1], [m[2], m[3]]]));
  const pairs = [
    ['text', 'bg', 4.5], ['text', 'surface', 4.5], ['muted', 'bg', 4.5], ['muted', 'surface', 4.5], ['muted', 'surface-2', 4.5],
    ['accent', 'bg', 4.5], ['accent', 'surface', 4.5], ['accent', 'accent-soft', 4.5], ['bg', 'accent', 4.5],
    ...['good', 'warn', 'bad', 'info'].flatMap((k) => [[k, `${k}-soft`, 4.5], [k, 'surface', 4.5]]),
    ['muted', 'dim-soft', 4.5],
  ].filter(([a, b]) => tokens[a] && tokens[b]);
  assert.ok(pairs.length >= 9);
  for (const [fgName, bgName, min] of pairs) {
    for (const [i, theme] of ['light', 'dark'].entries()) {
      const r = ratio(tokens[fgName][i], tokens[bgName][i]);
      assert.ok(r >= min, `${theme} ${fgName} on ${bgName}: ${r.toFixed(2)} < ${min}`);
    }
  }
});
