// Render the site's pages with their own scripts and styles, as a browser would, and report what a visitor can see
// (decision 0114: copy is judged by what the page renders, not by strings in its source). stigready-web#70's lesson:
// one token in availabilityCell or one CSS rule can hide every listing while the source still "looks" right.
//
//   node render.mjs <site-root> <page.html> [<page.html> ...]   -> JSON on stdout
//
// For each page: the rows of every <tbody> (cells' visible text, visible or not), every link to an AWS Marketplace
// listing (href, visible or not), and the page's visible text. Only files under <site-root> are loaded (scripts,
// stylesheets, fetch() of catalog.json and friends); nothing else is fetched. A page whose scripts throw is reported
// with its errors, and the caller fails closed.
import fs from 'node:fs';
import path from 'node:path';
import jsdom from 'jsdom';
const { JSDOM, VirtualConsole, requestInterceptor } = jsdom;

const SITE_HOST = 'stigready.com';
const PP = 'https://aws.amazon.com/marketplace/pp/';
const SETTLE_MS = 400;

const [root, ...pages] = process.argv.slice(2);
if (!root || pages.length === 0) {
  console.error('usage: node render.mjs <site-root> <page.html> ...');
  process.exit(2);
}
const ROOT = path.resolve(root);

// A URL on the site maps to a file under ROOT; anything else (gtag, fonts, CDNs) is not loaded.
function localFile(u) {
  let url;
  try { url = new URL(u); } catch { return null; }
  if (url.hostname !== SITE_HOST) return null;
  let rel = decodeURIComponent(url.pathname).replace(/^\/+/, '');
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  const file = path.resolve(ROOT, rel);
  if (file !== ROOT && !file.startsWith(ROOT + path.sep)) return null;
  try {
    const st = fs.lstatSync(file);
    return st.isFile() ? file : null;   // never follow a symlink out of the tree
  } catch { return null; }
}

// Every request the page makes (scripts, stylesheets, fetch) is answered here, from the site tree or with a 404:
// nothing reaches the network.
function siteOnly(errors) {
  return requestInterceptor((request) => {
    const f = localFile(request.url);
    if (!f) {
      if (new URL(request.url).hostname === SITE_HOST) errors.push(`missing on the site: ${request.url}`);
      return new Response('', { status: 404 });
    }
    const type = f.endsWith('.css') ? 'text/css' : f.endsWith('.js') || f.endsWith('.mjs') ? 'application/javascript'
      : f.endsWith('.json') ? 'application/json' : 'application/octet-stream';
    return new Response(fs.readFileSync(f), { status: 200, headers: { 'content-type': type } });
  });
}

function makeFetch(win, errors) {
  return async (input) => {
    const u = new URL(String(input && input.url ? input.url : input), win.location.href).href;
    const f = localFile(u);
    if (!f) {
      errors.push(`fetch outside the site refused: ${u}`);
      return new Response('', { status: 404 });
    }
    return new Response(fs.readFileSync(f), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

function visible(win, el) {
  for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
    if (e.hidden) return false;
    const tag = e.tagName.toLowerCase();
    if (['script', 'style', 'noscript', 'template', 'head'].includes(tag)) return false;
    const cs = win.getComputedStyle(e);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') return false;
    if (cs.opacity !== '' && Number(cs.opacity) === 0) return false;
    if (cs.fontSize && /^0(\.0+)?(px|em|rem|%)?$/.test(cs.fontSize.trim())) return false;
    if (cs.clipPath && cs.clipPath.replace(/\s+/g, '') === 'inset(50%)') return false;
    if (e.getAttribute('aria-hidden') === 'true' && tag === 'a') return false;
  }
  return true;
}

function visibleText(win, node) {
  const out = [];
  const walk = (n) => {
    if (n.nodeType === 3) {
      if (n.parentElement && visible(win, n.parentElement)) out.push(n.nodeValue);
      return;
    }
    if (n.nodeType !== 1) return;
    const tag = n.tagName.toLowerCase();
    if (['script', 'style', 'noscript', 'template'].includes(tag)) return;
    const block = ['p', 'div', 'li', 'td', 'th', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'dd', 'dt', 'section',
      'br', 'header', 'footer', 'article', 'table', 'ul', 'ol', 'title'].includes(tag);
    if (block) out.push('\n');
    for (const c of n.childNodes) walk(c);
    if (block) out.push('\n');
  };
  walk(node);
  return out.join('').replace(/[ \t\r\f\v]+/g, ' ');
}

async function render(rel) {
  const file = path.join(ROOT, rel);
  const errors = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => {
    // Refused off-site loads (analytics, web fonts) are expected: the interceptor answers them 404 on purpose.
    if (e && e.type === 'resource-loading' && !String(e.url || e.message).includes(SITE_HOST)) return;
    // A redirect stub (stigapplied.html) asks to navigate; its own text is still read.
    if (e && e.type === 'not-implemented' && /navigation/i.test(String(e.message))) return;
    errors.push(`jsdom ${e && e.type || 'error'}: ${String(e && e.message || e).slice(0, 200)}`);
  });
  vc.on('error', (...a) => errors.push(`console.error: ${a.map(String).join(' ').slice(0, 200)}`));
  const dom = new JSDOM(fs.readFileSync(file, 'utf8'), {
    url: `https://${SITE_HOST}/${rel}`,
    runScripts: 'dangerously',
    resources: { interceptors: [siteOnly(errors)] },
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(win) {
      if (typeof win.fetch !== 'function') {
        win.fetch = makeFetch(win, errors);
        win.Response = Response;
      }
    },
  });
  const win = dom.window;
  await new Promise((resolve) => {
    if (win.document.readyState === 'complete') resolve();
    else win.addEventListener('load', () => resolve());
    setTimeout(resolve, 10000).unref();   // a page whose load never fires is read as it stands after 10 s
  });
  await new Promise((r) => setTimeout(r, SETTLE_MS));
  const doc = win.document;
  const rows = [];
  for (const tb of doc.querySelectorAll('tbody')) {
    for (const tr of tb.querySelectorAll('tr')) {
      rows.push({
        tbody: tb.id || '',
        visible: visible(win, tr),
        cells: [...tr.querySelectorAll('td,th')].map((td) => visibleText(win, td).replace(/\s+/g, ' ').trim()),
        text: visibleText(win, tr).replace(/\s+/g, ' ').trim(),
      });
    }
  }
  const links = [...doc.querySelectorAll('a[href]')]
    .filter((a) => a.href.startsWith(PP))
    .map((a) => ({ href: a.href, visible: visible(win, a) && visibleText(win, a).trim() !== '',
                   tbody: (a.closest('tbody') || {}).id || '' }));
  const result = { page: rel, rows, links, text: visibleText(win, doc.body || doc.documentElement), errors };
  win.close();
  return result;
}

const out = JSON.stringify(await Promise.all(pages.map((p) => render(p))));
process.stdout.write(out, () => process.exit(0));   // page timers must not keep the process alive
