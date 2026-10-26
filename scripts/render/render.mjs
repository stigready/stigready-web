// Render the site's pages with their own scripts and styles, as a browser would, and report what a visitor can see
// (decision 0114: copy is judged by what the page renders, not by strings in its source). stigready-web#70's lesson:
// one token in availabilityCell or one CSS rule can hide every listing while the source still "looks" right.
//
// Two stages, two processes (check-copy-vs-marketplace.py runs both):
//
//   node <hardening flags> render.mjs run <site-root> <page.html> ...   < key   -> "<hmac>\n<json>" on stdout
//   node render.mjs eval <site-root>                                     < json  -> JSON on stdout
//
// `run` executes each page's own scripts (jsdom) and serializes the DOM they leave. Page scripts are not trusted: the
// process must run with code generation from strings disallowed, frozen intrinsics and the permission model (read
// only, no child processes or workers), and it refuses to start otherwise; the modules it loads have their prototypes
// frozen before any page runs; its output is authenticated with a key the caller passes on stdin.
//
// `eval` never runs page code. It re-parses each serialized page in a fresh process and decides what is visible from
// the page's stylesheets, style attributes and markup with its own cascade, at every viewport width its media queries
// distinguish. Anything it cannot evaluate makes the page's listings count as not visible (fail closed).
//
// Output of `eval`, per page: the rows of every <tbody> (cells' visible text, visible or not), every link to an AWS
// Marketplace listing (href, visible or not, and the index of the row it sits in, or -1), the page's visible text, all
// of its body text (visible or not: the claims are read from this), why it could not be evaluated, and errors.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const SITE_HOST = 'stigready.com';
const PP = 'https://aws.amazon.com/marketplace/pp/';
const SETTLE_MS = 400;
// Off-site resources a page may load that the renderer does not fetch. Anything else off-site (a script or a
// stylesheet) could change what a visitor sees and is not evaluated: the page fails closed.
const OFFSITE_OK = { script: new Set(['www.googletagmanager.com']), style: new Set(['fonts.googleapis.com']) };

const [mode, root, ...pages] = process.argv.slice(2);
if (!['run', 'eval'].includes(mode) || !root || (mode === 'run' && pages.length === 0)) {
  console.error('usage: node render.mjs run <site-root> <page.html> ... | node render.mjs eval <site-root>');
  process.exit(2);
}
const ROOT = path.resolve(root);
const require = createRequire(import.meta.url);

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


// ===================================================================================================== stage 1: run

async function runStage() {
  // Refuse to run page scripts in a process they could take over.
  const bad = [];
  try { Function('return 1'); bad.push('code generation from strings is allowed'); } catch (e) {
    if (!(e instanceof EvalError)) bad.push('code generation check failed');
  }
  for (const [n, o] of [['Object', Object.prototype], ['Function', Function.prototype], ['Array', Array.prototype]]) {
    if (!Object.isFrozen(o)) bad.push(`${n}.prototype is not frozen`);
  }
  const perm = process.permission;
  if (!perm || typeof perm.has !== 'function') bad.push('the permission model is off');
  else for (const scope of ['fs.write', 'child', 'worker']) if (perm.has(scope)) bad.push(`permission ${scope} is granted`);
  if (bad.length) {
    console.error(`render run: not hardened (${bad.join('; ')}): run with --disallow-code-generation-from-strings ` +
                  '--frozen-intrinsics --permission --allow-fs-read=<site>,<renderer>');
    process.exit(2);
  }
  const key = fs.readFileSync(0, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(key)) { console.error('render run: no key on stdin'); process.exit(2); }
  const hmac = crypto.createHmac;

  const jsdom = require('jsdom');
  const { JSDOM, VirtualConsole, requestInterceptor } = jsdom;
  const idl = require(path.join(path.dirname(require.resolve('jsdom')), 'generated', 'idl', 'utils.js'));
  const implForWrapper = idl.implForWrapper;
  // Freeze every class and function the loaded modules export (jsdom's implementation classes, its CSSOM, parse5's
  // serializer...): page code can reach some of their instances, and must not be able to change how they behave.
  for (const m of Object.values(require.cache)) freezeExports(m && m.exports);

  const results = [];
  for (const rel of pages) results.push(await runPage(rel));
  const body = JSON.stringify({ pages: results });
  const mac = hmac('sha256', Buffer.from(key, 'hex')).update(body).digest('hex');
  process.stdout.write(`${mac}\n${body}`, () => process.exit(0));   // page timers must not keep the process alive

  function freezeExports(x, depth = 0) {
    if (x === null || (typeof x !== 'object' && typeof x !== 'function') || depth > 2) return;
    for (const k of Reflect.ownKeys(x)) {
      let v;
      try { v = Reflect.getOwnPropertyDescriptor(x, k)?.value; } catch { continue; }
      if (typeof v === 'function') {
        if (v.prototype && typeof v.prototype === 'object') Object.freeze(v.prototype);
        Object.freeze(v);
      } else if (v && typeof v === 'object' && depth < 2) freezeExports(v, depth + 1);
    }
    if (typeof x === 'function' && x.prototype && typeof x.prototype === 'object') Object.freeze(x.prototype);
  }

  async function runPage(rel) {
    const file = path.join(ROOT, rel);
    const errors = [];
    const reasons = [];
    const vc = new VirtualConsole();
    vc.on('jsdomError', (e) => {
      if (e && e.type === 'resource-loading' && !String(e.url || e.message).includes(SITE_HOST)) return;
      if (e && e.type === 'not-implemented' && /navigation/i.test(String(e.message))) return;
      errors.push(`jsdom ${e && e.type || 'error'}: ${String(e && e.message || e).slice(0, 200)}`);
    });
    vc.on('error', (...a) => errors.push(`console.error: ${a.map(String).join(' ').slice(0, 200)}`));
    const interceptor = requestInterceptor((request) => {
      const f = localFile(request.url);
      if (!f) {
        if (new URL(request.url).hostname === SITE_HOST) errors.push(`missing on the site: ${request.url}`);
        return new Response('', { status: 404 });
      }
      const type = f.endsWith('.css') ? 'text/css' : f.endsWith('.js') || f.endsWith('.mjs') ? 'application/javascript'
        : f.endsWith('.json') ? 'application/json' : 'application/octet-stream';
      return new Response(fs.readFileSync(f), { status: 200, headers: { 'content-type': type } });
    });
    let pristine = null;
    const dom = new JSDOM(fs.readFileSync(file, 'utf8'), {
      url: `https://${SITE_HOST}/${rel}`,
      runScripts: 'dangerously',
      resources: { interceptors: [interceptor] },
      pretendToBeVisual: true,
      virtualConsole: vc,
      beforeParse(win) {
        // The DOM and CSSOM accessors this stage reads with, taken before any page script can replace them.
        const get = (C, p) => Object.getOwnPropertyDescriptor(C.prototype, p)?.get;
        const fn = (C, p) => Object.getOwnPropertyDescriptor(C.prototype, p)?.value;
        pristine = {
          doc: win.document,
          styleSheets: get(win.Document, 'styleSheets'), adopted: get(win.Document, 'adoptedStyleSheets'),
          listLength: get(win.StyleSheetList, 'length'), listItem: fn(win.StyleSheetList, 'item'),
          cssRules: get(win.CSSStyleSheet, 'cssRules'), ruleLength: get(win.CSSRuleList, 'length'),
          ruleItem: fn(win.CSSRuleList, 'item'), cssText: get(win.CSSRule, 'cssText'),
          ownerNode: get(win.StyleSheet, 'ownerNode'), href: get(win.StyleSheet, 'href'),
          textContent: get(win.Node, 'textContent'), localName: get(win.Element, 'localName'),
          Sheet: win.CSSStyleSheet, replaceSync: fn(win.CSSStyleSheet, 'replaceSync'),
          firstChild: get(win.Node, 'firstChild'), nextSibling: get(win.Node, 'nextSibling'),
          nodeType: get(win.Node, 'nodeType'),
        };
        if (typeof win.fetch !== 'function') {
          win.fetch = async (input) => {
            const u = new URL(String(input && input.url ? input.url : input), `https://${SITE_HOST}/${rel}`).href;
            const f = localFile(u);
            if (!f) {
              errors.push(`fetch outside the site refused: ${u}`);
              return new Response('', { status: 404 });
            }
            return new Response(fs.readFileSync(f), { status: 200, headers: { 'content-type': 'application/json' } });
          };
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
    const html = dom.serialize();
    try {
      reasons.push(...styleState(pristine));
    } catch (e) {
      reasons.push(`the page's styles could not be read (${e && e.name})`);
    }
    win.close();
    return { page: rel, html, errors, reasons };
  }

  // What eval cannot see in serialized HTML: stylesheets changed through the CSSOM, adopted stylesheets, and shadow
  // roots (which hide an element's own children). Read with the accessors captured before the page ran.
  function styleState(p) {
    const call = (f, self, ...a) => Reflect.apply(f, self, a);
    const out = [];
    if (p.adopted) {
      const a = call(p.adopted, p.doc);
      if (a && a.length > 0) out.push('the page adopts constructed stylesheets');
    }
    const list = call(p.styleSheets, p.doc);
    const n = call(p.listLength, list);
    for (let i = 0; i < n; i++) {
      const sheet = call(p.listItem, list, i);
      const owner = call(p.ownerNode, sheet);
      let src = null;
      if (owner && call(p.localName, owner) === 'style') src = call(p.textContent, owner);
      else {
        const f = localFile(call(p.href, sheet) || '');
        if (f) src = fs.readFileSync(f, 'utf8');
      }
      if (src === null) continue;
      const fresh = Reflect.construct(p.Sheet, []);
      call(p.replaceSync, fresh, src.replace(/@import[^;]*;/gi, ''));
      if (rulesText(p, sheet).replace(/@import[^;]*;/gi, '') !== rulesText(p, fresh)) {
        out.push('a stylesheet was changed through the CSSOM after it loaded');
      }
    }
    // Any shadow root, open or closed.
    const stack = [p.doc];
    while (stack.length) {
      const node = stack.pop();
      if (call(p.nodeType, node) === 1) {
        const impl = implForWrapper(node);
        if (impl && impl._shadowRoot) { out.push('the page attaches a shadow root'); break; }
      }
      for (let c = call(p.firstChild, node); c; c = call(p.nextSibling, c)) stack.push(c);
    }
    return out;
  }

  function rulesText(p, sheet) {
    const rules = Reflect.apply(p.cssRules, sheet, []);
    const n = Reflect.apply(p.ruleLength, rules, []);
    const parts = [];
    for (let i = 0; i < n; i++) parts.push(Reflect.apply(p.cssText, Reflect.apply(p.ruleItem, rules, [i]), []));
    return parts.join('\n');
  }
}

// ==================================================================================================== stage 2: eval

async function evalStage() {
  const { JSDOM } = require('jsdom');
  const csstree = createRequire(require.resolve('jsdom'))('css-tree');
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const out = input.pages.map((pg) => evaluatePage(pg, JSDOM, csstree));
  process.stdout.write(JSON.stringify(out), () => process.exit(0));
}

// ---------------------------------------------------------------------------------------------- values and colours

const NAMED = {
  black: [0, 0, 0], white: [255, 255, 255], red: [255, 0, 0], green: [0, 128, 0], blue: [0, 0, 255],
  yellow: [255, 255, 0], gray: [128, 128, 128], grey: [128, 128, 128], silver: [192, 192, 192], navy: [0, 0, 128],
  maroon: [128, 0, 0], purple: [128, 0, 128], teal: [0, 128, 128], olive: [128, 128, 0], lime: [0, 255, 0],
  aqua: [0, 255, 255], cyan: [0, 255, 255], fuchsia: [255, 0, 255], magenta: [255, 0, 255], orange: [255, 165, 0],
  gold: [255, 215, 0], whitesmoke: [245, 245, 245], gainsboro: [220, 220, 220], lightgray: [211, 211, 211],
  lightgrey: [211, 211, 211], darkgray: [169, 169, 169], darkgrey: [169, 169, 169], dimgray: [105, 105, 105],
  dimgrey: [105, 105, 105], snow: [255, 250, 250], ivory: [255, 255, 240], beige: [245, 245, 220],
};

// [r, g, b, a] or null (cannot evaluate). 'currentcolor' is resolved by the caller.
function parseColor(v) {
  const s = v.trim().toLowerCase();
  if (s === 'transparent') return [0, 0, 0, 0];
  if (NAMED[s]) return [...NAMED[s], 1];
  let m = s.match(/^#([0-9a-f]{3,8})$/);
  if (m) {
    const h = m[1];
    if (h.length === 3 || h.length === 4) {
      const c = [...h].map((x) => parseInt(x + x, 16));
      return [c[0], c[1], c[2], h.length === 4 ? c[3] / 255 : 1];
    }
    if (h.length === 6 || h.length === 8) {
      const c = [0, 2, 4, 6].map((i) => parseInt(h.slice(i, i + 2), 16));
      return [c[0], c[1], c[2], h.length === 8 ? c[3] / 255 : 1];
    }
    return null;
  }
  m = s.match(/^(rgba?|hsla?)\((.*)\)$/);
  if (!m) return null;
  const parts = m[2].replace(/\//, ' / ').split(/[\s,]+/).filter(Boolean);
  const slash = parts.indexOf('/');
  let alpha = 1;
  let comps = parts;
  if (slash >= 0) { alpha = num01(parts[slash + 1]); comps = parts.slice(0, slash); } else if (parts.length === 4) {
    alpha = num01(parts[3]); comps = parts.slice(0, 3);
  }
  if (comps.length !== 3 || alpha === null) return null;
  if (m[1].startsWith('rgb')) {
    const c = comps.map((x) => (x.endsWith('%') ? parseFloat(x) * 2.55 : parseFloat(x)));
    return c.some((x) => !Number.isFinite(x)) ? null : [...c, alpha];
  }
  const h = parseFloat(comps[0]); const sat = parseFloat(comps[1]) / 100; const l = parseFloat(comps[2]) / 100;
  if (![h, sat, l].every(Number.isFinite)) return null;
  const k = (n) => (n + h / 30) % 12; const a = sat * Math.min(l, 1 - l);
  const f = (n) => 255 * (l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1))));
  return [f(0), f(8), f(4), alpha];
}

function num01(x) {
  if (x === undefined) return null;
  const n = parseFloat(x);
  if (!Number.isFinite(n)) return null;
  return x.endsWith('%') ? n / 100 : n;
}

function luminance([r, g, b]) {
  const c = [r, g, b].map((x) => { const v = x / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

function contrast(a, b) {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

// A length in px, or null. em/rem/% relative to `base`, vw/vh to `vp` (viewport width or height).
function lengthPx(v, base = 16, vp = 1024) {
  const s = String(v).trim().toLowerCase();
  if (s === '0') return 0;
  if (/^(calc|min|max|clamp)\(/.test(s)) {
    const r = mathValue(s, base, vp);
    return r && r.len ? r.n : (r && r.n === 0 ? 0 : null);
  }
  const m = s.match(/^(-?\d*\.?\d+(?:e-?\d+)?)(px|em|rem|%|vw|vh|vmin|vmax|svh|lvh|dvh|svw|lvw|dvw|pt|pc|in|cm|mm|q|ch|ex)$/);
  if (!m) return null;
  const n = parseFloat(m[1]);
  switch (m[2]) {
    case 'px': return n;
    case 'em': case 'ch': case 'ex': return n * base;
    case 'rem': return n * 16;
    case '%': return n / 100 * base;
    case 'pt': return n * 4 / 3;
    case 'pc': return n * 16;
    case 'in': return n * 96;
    case 'cm': return n * 96 / 2.54;
    case 'mm': return n * 96 / 25.4;
    case 'q': return n * 96 / 101.6;
    default: return n / 100 * vp;
  }
}

// calc(), min(), max(), clamp() over lengths and numbers: {n (px or a number), len (is a length)} or null.
function mathValue(expr, base, vp) {
  const src = expr.replace(/\s+/g, ' ');
  let i = 0;
  const peek = () => src[i];
  const ws = () => { while (src[i] === ' ') i++; };
  function primary() {
    ws();
    const fm = src.slice(i).match(/^(calc|min|max|clamp)\(/);
    if (fm) {
      i += fm[0].length;
      const args = [sum()];
      ws();
      while (peek() === ',') { i++; args.push(sum()); ws(); }
      if (peek() !== ')' || args.some((a) => a === null)) return null;
      i++;
      if (fm[1] === 'calc') return args.length === 1 ? args[0] : null;
      const len = args.some((a) => a.len);
      const ns = args.map((a) => a.n);
      if (fm[1] === 'min') return { n: Math.min(...ns), len };
      if (fm[1] === 'max') return { n: Math.max(...ns), len };
      return ns.length === 3 ? { n: Math.min(Math.max(ns[0], ns[1]), ns[2]), len } : null;
    }
    if (peek() === '(') { i++; const r = sum(); ws(); if (peek() !== ')') return null; i++; return r; }
    const m = src.slice(i).match(/^-?\d*\.?\d+(?:e-?\d+)?([a-z%]+)?/);
    if (!m) return null;
    i += m[0].length;
    if (!m[1]) return { n: parseFloat(m[0]), len: false };
    const px = lengthPx(m[0], base, vp);
    return px === null ? null : { n: px, len: true };
  }
  function product() {
    let a = primary();
    for (;;) {
      ws();
      const op = peek();
      if (a === null || (op !== '*' && op !== '/')) return a;
      i++;
      const b = primary();
      if (b === null) return null;
      if (op === '*') { if (a.len && b.len) return null; a = { n: a.n * b.n, len: a.len || b.len }; }
      else { if (b.len || b.n === 0) return null; a = { n: a.n / b.n, len: a.len }; }
    }
  }
  function sum() {
    let a = product();
    for (;;) {
      ws();
      const op = peek();
      if (a === null || (op !== '+' && op !== '-')) return a;
      i++;
      const b = product();
      if (b === null) return null;
      if (a.len !== b.len && a.n !== 0 && b.n !== 0) return null;
      a = { n: op === '+' ? a.n + b.n : a.n - b.n, len: a.len || b.len };
    }
  }
  const r = primary();
  ws();
  return i === src.length ? r : null;
}

// Split a value on top-level whitespace / commas, keeping functions whole.
function tokens(v) {
  const out = []; let cur = ''; let depth = 0;
  for (const ch of v) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (depth === 0 && /[\s,]/.test(ch)) { if (cur) out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

function funcs(v) {
  const out = []; const re = /([a-z-]+)\(/gi; let m;
  while ((m = re.exec(v))) {
    let depth = 1; let i = re.lastIndex;
    for (; i < v.length && depth; i++) { if (v[i] === '(') depth++; else if (v[i] === ')') depth--; }
    out.push({ name: m[1].toLowerCase(), args: v.slice(re.lastIndex, i - 1) });
    re.lastIndex = i;
  }
  return out;
}

// ------------------------------------------------------------------------------------------------- the properties

// Every property that can make content invisible on its own or with another one. A rule this evaluator cannot place
// (unknown condition, unsupported selector) that sets one of these makes the page unevaluable.
const SHORTHANDS = {
  inset: ['top', 'right', 'bottom', 'left'], 'inset-block': ['top', 'bottom'], 'inset-inline': ['left', 'right'],
  'inset-block-start': ['top'], 'inset-block-end': ['bottom'], 'inset-inline-start': ['left'], 'inset-inline-end': ['right'],
  margin: ['margin-top', 'margin-right', 'margin-bottom', 'margin-left'],
  'margin-block': ['margin-top', 'margin-bottom'], 'margin-inline': ['margin-left', 'margin-right'],
  'margin-block-start': ['margin-top'], 'margin-block-end': ['margin-bottom'],
  'margin-inline-start': ['margin-left'], 'margin-inline-end': ['margin-right'],
  overflow: ['overflow-x', 'overflow-y'], 'overflow-block': ['overflow-y'], 'overflow-inline': ['overflow-x'],
  'block-size': ['height'], 'inline-size': ['width'], 'max-block-size': ['max-height'], 'max-inline-size': ['max-width'],
  font: ['font-size', 'font-family'], background: ['background-color', 'background-image'],
  animation: ['animation-name'], '-webkit-text-fill-color': ['text-fill-color'],
  '-webkit-line-clamp': ['line-clamp'], 'grid-template': ['grid-template-rows', 'grid-template-columns'],
};
const TRACKED = new Set([
  'display', 'visibility', 'content-visibility', 'opacity', 'filter', 'mix-blend-mode', 'transform', 'translate',
  'scale', 'rotate', 'zoom', 'clip', 'clip-path', 'mask', 'color', 'text-fill-color', 'background-color',
  'background-image', 'font-size', 'font-family', 'font-size-adjust', 'height', 'max-height', 'width', 'max-width',
  'overflow-x', 'overflow-y', 'contain', 'position', 'top', 'right', 'bottom', 'left', 'margin-top', 'margin-right',
  'margin-bottom', 'margin-left', 'text-indent', 'z-index', 'letter-spacing', 'line-height', 'line-clamp',
  'animation-name', 'content', 'grid-template-rows', 'grid-template-columns', 'flex', 'flex-basis',
  'backdrop-filter', 'perspective', 'offset-path',
]);
const INHERITED = new Set(['visibility', 'color', 'text-fill-color', 'font-size', 'font-family', 'letter-spacing',
  'line-height', 'text-indent', 'font-size-adjust']);
const INITIAL = { display: 'inline', visibility: 'visible', opacity: '1', color: 'black', 'text-fill-color': 'currentcolor',
  'background-color': 'transparent', 'background-image': 'none', 'font-size': '16px', position: 'static',
  'z-index': 'auto', transform: 'none', 'content-visibility': 'visible' };

// Property name -> longhands this evaluator tracks ([] when none).
function longhands(prop) {
  if (prop.startsWith('--')) return [prop];
  if (prop.startsWith('mask') || prop.startsWith('-webkit-mask')) return ['mask'];
  if (prop === 'all') return [...TRACKED];
  return (SHORTHANDS[prop] || [prop]).filter((p) => TRACKED.has(p));
}

// Value of a longhand from a shorthand's value.
function fromShorthand(prop, long, value) {
  if (prop === long || prop === 'all' || prop.startsWith('--')) return value;
  if (prop === 'font') {
    const t = tokens(value.split('/')[0]);
    const size = t.find((x) => lengthPx(x) !== null || /^(xx?-small|small|medium|large|xx?x?-large|smaller|larger)$/.test(x));
    if (long === 'font-size') return size ?? '';
    const i = value.lastIndexOf(size ?? '\u0000');
    return i >= 0 ? value.slice(i + size.length).replace(/^\/\S+\s*/, '') : value;
  }
  if (prop === 'background') {
    if (long === 'background-image') return /(gradient|url|image)\(/i.test(value) ? value : 'none';
    const c = tokens(value).find((x) => parseColor(x) !== null);
    return c ?? 'transparent';
  }
  if (prop === 'animation') return value;   // names are matched against @keyframes below
  if (prop.startsWith('-webkit-') || ['block-size', 'inline-size', 'max-block-size', 'max-inline-size',
    'overflow-block', 'overflow-inline', 'grid-template'].includes(prop)) return value;
  const t = tokens(value);
  if (['inset', 'margin'].includes(prop)) {
    const order = prop === 'inset' ? ['top', 'right', 'bottom', 'left'] : ['margin-top', 'margin-right', 'margin-bottom', 'margin-left'];
    const idx = order.indexOf(long);
    const map = t.length === 1 ? [0, 0, 0, 0] : t.length === 2 ? [0, 1, 0, 1] : t.length === 3 ? [0, 1, 2, 1] : [0, 1, 2, 3];
    return t[map[idx]] ?? t[0];
  }
  if (prop === 'overflow') return long === 'overflow-x' ? t[0] : (t[1] ?? t[0]);
  if (prop.endsWith('-block') || prop.endsWith('-inline')) return long.endsWith('top') || long.endsWith('left') ? t[0] : (t[1] ?? t[0]);
  return value;
}

// ----------------------------------------------------------------------------------------------- the stylesheets

function evaluatePage(pg, JSDOM, csstree) {
  const reasons = [...(pg.reasons || [])];
  const errors = [...(pg.errors || [])];
  const dom = new JSDOM(pg.html, { url: `https://${SITE_HOST}/${pg.page}` });   // no scripts, no resources
  const doc = dom.window.document;
  const rules = [];                // {sels: [{sel, spec, pseudo}], decls, conds, layer, order}
  const keyframes = new Map();     // name -> [decls]
  const fontFaces = new Set();
  const layerOrder = [];
  const widths = new Set([320, 360, 390, 414, 768, 1024, 1280, 1440, 1920]);
  let order = 0;

  const layerIndex = (name) => {
    let i = layerOrder.indexOf(name);
    if (i < 0) { layerOrder.push(name); i = layerOrder.length - 1; }
    return i;
  };

  const declsOf = (block) => {
    const out = [];
    block.children.forEach((d) => {
      if (d.type === 'Declaration') {
        const prop = d.property.toLowerCase();
        const value = csstree.generate(d.value).trim();
        out.push({ prop, value, important: Boolean(d.important) });
      } else if (d.type === 'Rule' || d.type === 'Atrule') {
        out.nested = true;
      }
    });
    return out;
  };

  // Is a declaration (in isolation) one that can hide? Used where the evaluator cannot place a rule.
  const hidingCapable = (decls) => decls.some((d) => d.prop.startsWith('--') || longhands(d.prop).length > 0);

  function addSheet(text, conds, where) {
    let ast;
    try {
      ast = csstree.parse(text, { parseValue: false, parseAtrulePrelude: false, parseRulePrelude: false,
        parseCustomProperty: false, onParseError: (e) => { reasons.push(`${where}: CSS parse error (${e.message.slice(0, 60)})`); } });
    } catch (e) {
      reasons.push(`${where}: CSS could not be parsed`);
      return;
    }
    walk(ast.children, conds, null);

    function walk(list, conds, layer) {
      list.forEach((node) => {
        if (node.type === 'Rule') {
          const decls = declsOf(node.block);
          if (decls.nested) { reasons.push(`${where}: nested CSS rules are not evaluated`); return; }
          const prelude = csstree.generate(node.prelude);
          const sels = selectors(prelude);
          if (sels === null) {
            if (decls.some(hidesAlone)) reasons.push(`${where}: a rule this renderer cannot match hides content (${prelude.slice(0, 60)})`);
            return;
          }
          rules.push({ sels, decls, conds, layer, order: order++ });
        } else if (node.type === 'Atrule') {
          const name = node.name.toLowerCase();
          const prelude = node.prelude ? csstree.generate(node.prelude).trim() : '';
          if (name === 'media' || name === 'supports' || name === 'container') {
            const c = { type: name, text: prelude };
            if (name === 'media') mediaWidths(prelude).forEach((w) => widths.add(w));
            if (node.block) walk(node.block.children, [...conds, c], layer);
          } else if (name === 'layer') {
            if (!node.block) { prelude.split(',').map((s) => s.trim()).filter(Boolean).forEach(layerIndex); return; }
            const nm = (layer === null ? '' : `${layerOrder[layer]}.`) + (prelude || `anon${order}`);
            walk(node.block.children, conds, layerIndex(nm));
          } else if (name === 'keyframes' || name === '-webkit-keyframes') {
            const all = [];
            node.block?.children.forEach((r) => { if (r.type === 'Rule') all.push(...declsOf(r.block)); });
            keyframes.set(prelude.replace(/^["']|["']$/g, ''), all);
          } else if (name === 'font-face') {
            const fam = node.block ? declsOf(node.block).find((d) => d.prop === 'font-family') : null;
            if (fam) fontFaces.add(fam.value.replace(/["']/g, '').trim().toLowerCase());
          } else if (['charset', 'page', 'counter-style', 'font-feature-values', 'font-palette-values',
            'view-transition', 'starting-style'].includes(name)) {
            // no effect on what is visible at rest
          } else {
            reasons.push(`${where}: @${name} is not evaluated`);
          }
        }
      });
    }
  }

  // Selector list -> [{sel, spec, pseudo}] or null when this renderer cannot match it.
  function selectors(prelude) {
    let ast;
    try { ast = csstree.parse(prelude, { context: 'selectorList' }); } catch { return null; }
    const out = [];
    let ok = true;
    ast.children.forEach((sel) => {
      if (sel.type !== 'Selector') { ok = false; return; }
      let pseudo = null;
      const kept = [];
      sel.children.forEach((n) => {
        const legacy = n.type === 'PseudoClassSelector' && ['before', 'after', 'first-line', 'first-letter'].includes(n.name.toLowerCase());
        if (n.type === 'PseudoElementSelector' || legacy) { pseudo = n.name.toLowerCase(); return; }
        if (pseudo === null) kept.push(n);
      });
      const text = kept.length ? csstree.generate({ type: 'Selector', children: new csstree.List().fromArray(kept) }) : '*';
      try { doc.querySelector(text); } catch { ok = false; return; }
      out.push({ sel: text, spec: specificity(sel), pseudo });
    });
    return ok ? out : null;
  }

  function specificity(sel) {
    const s = [0, 0, 0];
    const add = (t) => { s[0] += t[0]; s[1] += t[1]; s[2] += t[2]; };
    const maxOf = (list) => {
      let best = [0, 0, 0];
      list?.children?.forEach((x) => {
        const t = x.type === 'Selector' ? specificity(x) : [0, 0, 0];
        if (t[0] > best[0] || (t[0] === best[0] && (t[1] > best[1] || (t[1] === best[1] && t[2] > best[2])))) best = t;
      });
      return best;
    };
    sel.children.forEach((n) => {
      if (n.type === 'IdSelector') s[0]++;
      else if (n.type === 'ClassSelector' || n.type === 'AttributeSelector') s[1]++;
      else if (n.type === 'TypeSelector') { if (n.name !== '*') s[2]++; }
      else if (n.type === 'PseudoElementSelector') s[2]++;
      else if (n.type === 'PseudoClassSelector') {
        const nm = n.name.toLowerCase();
        if (['before', 'after', 'first-line', 'first-letter'].includes(nm)) s[2]++;
        else if (nm === 'where') { /* 0 */ } else if (['is', 'not', 'has', 'matches', '-webkit-any', '-moz-any'].includes(nm)) {
          add(maxOf(n.children?.first));
        } else if (['nth-child', 'nth-last-child'].includes(nm)) {
          s[1]++;
          const nth = n.children?.first;
          if (nth?.selector) add(maxOf(nth.selector));
        } else s[1]++;
      }
    });
    return s;
  }

  // ---- the page's styles, in document order (style elements and stylesheet links; not inside template/noscript)
  for (const el of doc.querySelectorAll('link, style, script, meta[http-equiv]')) {
    if (el.closest('template, noscript')) continue;
    const tag = el.localName;
    if (tag === 'meta') {
      if (/refresh/i.test(el.getAttribute('http-equiv') || '')) reasons.push('the page redirects (meta refresh)');
      continue;
    }
    if (tag === 'script') {
      const src = el.getAttribute('src');
      if (!src) continue;
      const host = (() => { try { return new URL(el.src).hostname; } catch { return ''; } })();
      if (host !== SITE_HOST && !OFFSITE_OK.script.has(host)) reasons.push(`the page loads an off-site script (${host || src})`);
      continue;
    }
    const media = el.getAttribute('media');
    const conds = media ? [{ type: 'media', text: media }] : [];
    if (media) mediaWidths(media).forEach((w) => widths.add(w));
    const type = (el.getAttribute('type') || 'text/css').toLowerCase();
    if (type !== 'text/css') continue;
    if (tag === 'style') { addSheet(el.textContent, conds, `${pg.page} <style>`); continue; }
    const rel = (el.getAttribute('rel') || '').toLowerCase().split(/\s+/);
    if (!rel.includes('stylesheet') || rel.includes('alternate') || el.hasAttribute('disabled')) continue;
    const href = el.href;
    const f = localFile(href);
    if (f) { addSheet(fs.readFileSync(f, 'utf8'), conds, href.replace(`https://${SITE_HOST}/`, '')); continue; }
    const host = (() => { try { return new URL(href).hostname; } catch { return ''; } })();
    if (host === SITE_HOST) errors.push(`missing on the site: ${href}`);
    else if (!OFFSITE_OK.style.has(host)) reasons.push(`the page loads an off-site stylesheet (${host || href})`);
  }
  for (const r of rules) {
    if (r.conds.some((c) => condAt(c, 1024) === null) && r.decls.some((d) => longhands(d.prop).length > 0)) {
      reasons.push(`a rule under a condition this renderer cannot evaluate sets ${r.decls.map((d) => d.prop).join(', ').slice(0, 80)}`);
    }
  }

  // ---- cascade
  const matchCache = new Map();
  function matched(el) {
    let m = matchCache.get(el);
    if (m) return m;
    m = [];
    for (const r of rules) {
      for (const s of r.sels) {
        let hit = false;
        try { hit = s.sel === '*' || el.matches(s.sel); } catch { hit = false; }
        if (!hit) continue;
        for (const d of r.decls) {
          m.push({ ...d, spec: s.spec, pseudo: s.pseudo, conds: r.conds, layer: r.layer, order: r.order, inline: false });
        }
      }
    }
    const style = el.getAttribute('style');
    if (style) {
      try {
        const ast = csstree.parse(style, { context: 'declarationList', parseValue: false });
        ast.children.forEach((d) => {
          if (d.type === 'Declaration') {
            m.push({ prop: d.property.toLowerCase(), value: csstree.generate(d.value).trim(), important: Boolean(d.important),
              spec: [0, 0, 0], pseudo: null, conds: [], layer: null, order: 1e9, inline: true });
          }
        });
      } catch { reasons.push('a style attribute could not be parsed'); }
    }
    // Presentational hints, below every author rule.
    const hint = (prop, value) => m.push({ prop, value, important: false, spec: [0, 0, 0], pseudo: null, conds: [],
      layer: -1, order: -1, inline: false });
    if (el.localName === 'font' && el.hasAttribute('color')) hint('color', el.getAttribute('color'));
    if (el.hasAttribute('bgcolor')) hint('background-color', el.getAttribute('bgcolor'));
    matchCache.set(el, m);
    return m;
  }

  const rank = (d) => {
    // origin/importance, element-attached, layer, specificity, order
    const layer = d.layer === -1 ? -2 : d.layer === null ? (d.important ? -1 : 1e6) : (d.important ? 1e5 - d.layer : d.layer);
    return [d.important ? 1 : 0, d.inline ? 1 : 0, layer, ...d.spec, d.order];
  };
  const cmp = (a, b) => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };

  const memo = new Map();
  // Computed value of a tracked longhand or custom property for el (pseudo: null or a pseudo-element) at width W.
  // null: cannot evaluate.
  function computed(el, prop, W, pseudo = null) {
    const key = `${W}|${prop}|${pseudo}`;
    let per = memo.get(el);
    if (!per) { per = new Map(); memo.set(el, per); }
    if (per.has(key)) return per.get(key);
    per.set(key, null);   // cycle guard
    let best = null; let bestRank = null;
    for (const d of matched(el)) {
      if ((d.pseudo || null) !== pseudo) continue;
      if (!longhands(d.prop).includes(prop)) continue;
      if (!d.conds.every((c) => condAt(c, W) === true)) continue;
      const r = rank(d);
      if (!best || cmp(r, bestRank) >= 0) { best = d; bestRank = r; }
    }
    const parent = pseudo ? el : el.parentElement;
    const inherited = INHERITED.has(prop) || prop.startsWith('--');
    const initial = prop.startsWith('--') ? undefined : (INITIAL[prop] ?? '');
    const fromParent = () => (parent ? computed(parent, prop, W) : initial);
    let v;
    if (!best) v = inherited ? fromParent() : initial;
    else {
      v = fromShorthand(best.prop, prop, best.value);
      if (best.prop === 'all') v = v.trim().toLowerCase() === 'inherit' ? 'inherit' : (v.trim().toLowerCase() === 'unset' && inherited ? 'inherit' : 'initial');
      v = substitute(el, v, W);
      if (v !== null) {
        const kw = v.trim().toLowerCase();
        if (kw === 'inherit' || (kw === 'unset' && inherited) || ((kw === 'revert' || kw === 'revert-layer') && inherited)) v = fromParent();
        else if (kw === 'initial' || kw === 'unset' || kw === 'revert' || kw === 'revert-layer') v = initial;
      }
    }
    per.set(key, v);
    return v;
  }

  // Replace var(--x, fallback) with the custom property's computed value; null if one cannot be resolved.
  function substitute(el, v, W, depth = 0) {
    if (v === null || !/var\(/i.test(v)) return v;
    if (depth > 16) return null;
    const i = v.search(/var\(/i);
    let d = 1; let j = i + 4;
    for (; j < v.length && d; j++) { if (v[j] === '(') d++; else if (v[j] === ')') d--; }
    const inner = v.slice(i + 4, j - 1);
    const comma = inner.indexOf(',');
    const name = (comma < 0 ? inner : inner.slice(0, comma)).trim();
    let val = computed(el, name, W);
    if (val === null) return null;                  // a cycle, or a value that cannot be evaluated
    if (val === undefined) {                        // not set: the fallback, if any
      if (comma < 0) return null;
      val = inner.slice(comma + 1);
    }
    const sub = substitute(el, val, W, depth + 1);
    if (sub === null) return null;
    return substitute(el, v.slice(0, i) + sub + v.slice(j), W, depth + 1);
  }

  // ---- visibility
  const HIDDEN_TAGS = new Set(['script', 'style', 'noscript', 'template', 'head', 'title', 'iframe', 'object', 'embed',
    'video', 'audio', 'canvas', 'svg', 'math', 'select', 'option', 'datalist', 'optgroup', 'frameset', 'frame']);

  // Why el is not visible at width W, or null if it is.
  const chainMemo = new Map();
  function hiddenAt(el, W) { return chainState(el, W).why; }
  function chainState(e, W) {
    if (!e || e.nodeType !== 1) return { why: null, opacity: 1, scale: 1 };
    let per = chainMemo.get(e);
    if (!per) { per = new Map(); chainMemo.set(e, per); }
    if (per.has(W)) return per.get(W);
    const up = chainState(e.parentElement, W);
    let st;
    if (up.why) st = up;
    else {
      const why = ownHides(e, W, up);
      st = typeof why === 'string' ? { why, opacity: 0, scale: 0 } : why;
      if (!st.why) {
        const table = e.localName === 'tr' ? e.closest('table') : null;
        if (table) {
          for (const col of table.querySelectorAll('col, colgroup')) {
            const v = computed(col, 'visibility', W); const dsp = computed(col, 'display', W);
            if (v === null || dsp === null || /hidden|collapse/.test(v) || dsp.trim() === 'none') { st = { why: 'a table column hides it', opacity: 0, scale: 0 }; break; }
          }
        }
      }
    }
    per.set(W, st);
    return st;
  }
  function ownHides(e, W, up) {
    let opacity = up.opacity; let scale = up.scale;
    {
      const tag = e.localName;
      if (HIDDEN_TAGS.has(tag)) return `inside <${tag}>`;
      if (e.hasAttribute('hidden')) return 'hidden attribute';
      if (e.hasAttribute('popover')) return 'popover';
      if (tag === 'dialog' && !e.hasAttribute('open')) return 'closed dialog';
      const p = e.parentElement;
      if (p && p.localName === 'details' && !p.hasAttribute('open') && !(tag === 'summary' && p.querySelector(':scope > summary') === e)) {
        return 'inside a closed <details>';
      }
      if (tag === 'a' && e.getAttribute('aria-hidden') === 'true') return 'aria-hidden link';
      const c = (prop) => computed(e, prop, W);
      const why = elementHides(e, c, W);
      if (why) return why;
      const o = numberOrPct(c('opacity'));
      if (o === null) return 'opacity cannot be evaluated';
      opacity *= o;
      if (opacity < 0.1) return 'opacity';
      const s = transformScale(c('transform'), c('scale'), c('zoom'));
      if (s === null) return 'transform cannot be evaluated';
      scale *= s;
      if (scale < 0.1) return 'scaled down';
      for (const pseudo of ['first-line', 'first-letter']) {
        if (matched(e).some((d) => d.pseudo === pseudo)) return `::${pseudo} styles`;
      }
    }
    return { why: null, opacity, scale };
  }

  function elementHides(e, c, W) {
    const display = c('display'); if (display === null) return 'display cannot be evaluated';
    if (display.trim() === 'none') return 'display:none';
    const vis = c('visibility'); if (vis === null || /hidden|collapse/.test(vis)) return 'visibility';
    const cv = c('content-visibility'); if (cv === null || cv.trim() === 'hidden') return 'content-visibility';
    for (const p of ['filter', 'backdrop-filter']) {
      const f = c(p); if (f === null) return `${p} cannot be evaluated`;
      if (p === 'filter' && !filterOk(f)) return 'filter';
    }
    const mb = c('mix-blend-mode'); if (mb === null || !['', 'normal'].includes(mb.trim())) return 'mix-blend-mode';
    for (const p of ['clip-path', 'mask', 'offset-path']) {
      const v = c(p); if (v === null || !['', 'none'].includes(v.trim().toLowerCase())) return p;
    }
    const clip = c('clip'); if (clip === null || !['', 'auto'].includes(clip.trim().toLowerCase())) return 'clip';
    const rot = c('rotate'); if (rot === null || (rot.trim() && !/^(none|-?[\d.]+(deg|rad|turn|grad)|z\s.*)$/i.test(rot.trim()))) return 'rotate';
    const tr = c('translate'); if (tr === null || (tr.trim() && tr.trim() !== 'none' && farOff(tokens(tr), W) !== false)) return 'translate';
    const content = c('content'); if (content === null || !['', 'normal', 'none'].includes(content.trim())) return 'content replaces it';
    const ctn = c('contain'); if (ctn === null || /strict|size/.test(ctn)) return 'contain';
    const lc = c('line-clamp'); if (lc === null || !['', 'none'].includes(lc.trim())) return 'line-clamp';
    const fsa = c('font-size-adjust'); if (fsa === null || (fsa.trim() && !/^(none|from-font)$/.test(fsa.trim()) && !(parseFloat(fsa) >= 0.1))) return 'font-size-adjust';
    const z = c('z-index'); if (z === null || parseInt(z, 10) < 0) return 'negative z-index';
    // Moved off the page.
    const pos = c('position'); if (pos === null) return 'position cannot be evaluated';
    if (pos.trim() !== 'static' && pos.trim() !== '') {
      for (const side of ['top', 'right', 'bottom', 'left']) {
        const v = c(side); if (v === null) return `${side} cannot be evaluated`;
        if (v.trim() && v.trim() !== 'auto' && farOff([v], W) !== false) return `moved off the page (${side})`;
      }
    }
    for (const side of ['margin-top', 'margin-right', 'margin-bottom', 'margin-left', 'text-indent']) {
      const v = c(side); if (v === null) return `${side} cannot be evaluated`;
      const px = v.trim() && v.trim() !== 'auto' ? lengthPx(v, 16, W) : 0;
      if (px === null && !/^(auto|0|)$/.test(v.trim())) return `${side} cannot be evaluated`;
      if (px !== null && px <= -1000) return `moved off the page (${side})`;
      if (side === 'text-indent' && px !== null && px >= 1000) return 'text-indent';
    }
    const ls = c('letter-spacing'); if (ls === null) return 'letter-spacing cannot be evaluated';
    if (ls.trim() && ls.trim() !== 'normal') { const px = lengthPx(ls, 16, W); if (px === null || px <= -4) return 'letter-spacing'; }
    // Clipped to (almost) nothing.
    const ox = c('overflow-x'); const oy = c('overflow-y');
    if (ox === null || oy === null) return 'overflow cannot be evaluated';
    const clips = [ox, oy].some((v) => v.trim() && v.trim() !== 'visible');
    if (clips) {
      for (const p of ['height', 'max-height', 'width', 'max-width', 'line-height']) {
        const v = c(p); if (v === null) return `${p} cannot be evaluated`;
        const t = v.trim();
        if (!t || ['auto', 'none', 'normal', 'fit-content', 'max-content', 'min-content'].includes(t)) continue;
        const px = t.endsWith('%') ? (parseFloat(t) <= 1 ? 0 : 100) : lengthPx(t, 16, W);
        const n = /^\d*\.?\d+$/.test(t) ? parseFloat(t) * 16 : px;
        if (n === null) return `${p} cannot be evaluated`;
        if (n <= 10) return `clipped (${p})`;
      }
      const flex = c('flex'); const basis = c('flex-basis');
      if (flex === null || basis === null) return 'flex cannot be evaluated';
      const ft = tokens(flex.trim());
      const zero = (x) => /^0(px|%)?$/.test(x ?? '');
      if (ft.length >= 2 && parseFloat(ft[0]) === 0 && zero(ft[ft.length - 1])) return 'clipped (flex)';
      if (zero(basis.trim())) return 'clipped (flex-basis)';
      const parent = e.parentElement;
      if (parent) {
        for (const p of ['grid-template-rows', 'grid-template-columns']) {
          const v = computed(parent, p, W);
          if (v === null || /(^|\s)0(fr|px|%)?(\s|$)|minmax\(0/.test(v)) return `clipped by the parent grid (${p})`;
        }
      }
    }
    // Animated away: an animation whose keyframes set a property that can hide.
    const an = c('animation-name');
    if (an === null) return 'animation cannot be evaluated';
    for (const t of tokens(an)) {
      const k = keyframes.get(t.replace(/["']/g, ''));
      if (k && k.some((d) => longhands(d.prop).length > 0)) return 'an animation can hide it';
    }
    return null;
  }

  function numberOrPct(v) {
    const t = (v ?? '').trim();
    if (!t) return 1;
    const n = num01(t);
    return n === null ? null : n;
  }

  function filterOk(f) {
    const t = f.trim();
    if (!t || t === 'none') return true;
    const fs_ = funcs(t);
    if (!fs_.length) return false;
    return fs_.every(({ name, args }) => {
      const n = num01(args.trim());
      if (name === 'opacity' || name === 'brightness' || name === 'contrast') return n !== null && n >= 0.5;
      if (name === 'invert') return n !== null && n <= 0.2;
      if (name === 'blur') { const px = lengthPx(args.trim()); return px !== null && px < 2; }
      return ['drop-shadow', 'grayscale', 'sepia', 'saturate', 'hue-rotate'].includes(name);
    });
  }

  // Product of scale factors, or null when it cannot be evaluated.
  function transformScale(transform, scaleProp, zoom) {
    let s = 1;
    const sp = (scaleProp ?? '').trim();
    if (sp && sp !== 'none') {
      const t = tokens(sp).map(num01);
      if (t.some((x) => x === null)) return null;
      s *= Math.min(...t.map(Math.abs));
    }
    const z = (zoom ?? '').trim();
    if (z && !['normal', 'reset'].includes(z)) { const n = num01(z); if (n === null) return null; s *= n; }
    const t = (transform ?? '').trim();
    if (!t || t === 'none') return s;
    for (const { name, args } of funcs(t)) {
      const a = tokens(args);
      if (/^scale(3d|x|y|z)?$/.test(name)) {
        const n = a.map(num01); if (n.some((x) => x === null)) return null;
        s *= Math.min(...(name === 'scalez' ? [1] : n).map(Math.abs));
      } else if (/^translate(3d|x|y|z)?$/.test(name)) {
        if (farOff(name === 'translatez' ? [] : a.slice(0, 2), 1920) !== false) return 0;
      } else if (name === 'rotate' || name === 'rotatez') {
        // in-plane rotation keeps the text visible
      } else if (name === 'skew' || name === 'skewx' || name === 'skewy') {
        if (a.some((x) => !/^-?\d*\.?\d+deg$/.test(x) || Math.abs(parseFloat(x)) >= 60)) return 0;
      } else if (name === 'matrix') {
        const n = a.map(Number); if (n.length !== 6 || n.some((x) => !Number.isFinite(x))) return null;
        const det = Math.abs(n[0] * n[3] - n[1] * n[2]);
        if (Math.abs(n[4]) >= 1000 || Math.abs(n[5]) >= 1000) return 0;
        s *= Math.sqrt(det);
      } else return null;   // rotateX/Y, rotate3d, perspective, matrix3d: not evaluated
    }
    return s;
  }

  // false when every offset is near; true (or null: cannot evaluate) otherwise.
  function farOff(list, W) {
    for (const v of list) {
      const t = v.trim();
      if (!t || t === '0') continue;
      if (t.endsWith('%')) { if (Math.abs(parseFloat(t)) >= 100) return true; continue; }
      const px = lengthPx(t, 16, W);
      if (px === null) return null;
      if (Math.abs(px) >= 1000) return true;
    }
    return false;
  }

  // Text in el: hidden by its size, colour or font?
  const textMemo = new Map();
  function textHiddenAt(el, W) {
    const k = `${W}`;
    let per = textMemo.get(el);
    if (!per) { per = new Map(); textMemo.set(el, per); }
    if (!per.has(k)) per.set(k, textHiddenUncached(el, W));
    return per.get(k);
  }
  function textHiddenUncached(el, W) {
    let size = 16;
    const chain = [];
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) chain.unshift(e);
    for (const e of chain) {
      const v = computedOwn(e, 'font-size', W);
      if (v === undefined) continue;
      if (v === null) return 'font-size cannot be evaluated';
      const t = v.trim().toLowerCase();
      const kw = { 'xx-small': 9, 'x-small': 10, small: 13, medium: 16, large: 18, 'x-large': 24, 'xx-large': 32, 'xxx-large': 48 };
      if (kw[t]) size = kw[t];
      else if (t === 'smaller') size /= 1.2;
      else if (t === 'larger') size *= 1.2;
      else if (t === 'inherit' || t === 'unset' || t === '') { /* keeps the parent's */ } else if (t === 'initial') size = 16;
      else { const px = lengthPx(t, size, W); if (px === null) return 'font-size cannot be evaluated'; size = px; }
    }
    if (size < 4) return 'font-size';
    let color = colorOf(el, W);
    if (color === null) return 'colour cannot be evaluated';
    const fill = computed(el, 'text-fill-color', W);
    if (fill === null) return 'colour cannot be evaluated';
    if (fill.trim() && fill.trim().toLowerCase() !== 'currentcolor') {
      color = parseColor(fill);
      if (color === null) return 'colour cannot be evaluated';
    }
    if (color[3] < 0.1) return 'transparent text';
    const bg = backgroundOf(el, W);
    if (bg === null) return 'background cannot be evaluated';
    if (bg.some((b) => contrast(color, b) < 1.25)) return 'text the colour of its background';
    const fam = computed(el, 'font-family', W);
    if (fam === null) return 'font cannot be evaluated';
    if (tokens(fam).some((f) => fontFaces.has(f.replace(/["']/g, '').trim().toLowerCase()))) return 'a font this renderer cannot draw';
    return null;
  }

  // The winning own value (no inheritance) of a property, undefined if none.
  function computedOwn(e, prop, W) {
    const has = matched(e).some((d) => !d.pseudo && longhands(d.prop).includes(prop) && d.conds.every((c) => condAt(c, W) === true));
    return has ? computed(e, prop, W) : undefined;
  }

  function colorOf(el, W) {
    let v = computed(el, 'color', W);
    for (let e = el, n = 0; v !== null && /currentcolor/i.test(v) && n < 50; n++) {
      e = e.parentElement;
      v = e ? computed(e, 'color', W) : 'black';
    }
    return v === null ? null : parseColor(v);
  }

  // The colours text sits on: the nearest background (a colour or a gradient's stops); null if it is an image.
  function backgroundOf(el, W) {
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const img = computed(e, 'background-image', W);
      if (img === null) return null;
      if (img.trim() && img.trim() !== 'none') {
        if (/url\(|image\(|image-set\(|element\(|cross-fade\(/i.test(img)) return null;
        const stops = [];
        for (const { args } of funcs(img)) for (const t of tokens(args)) { const c = parseColor(t); if (c) stops.push(c); }
        if (!stops.length) return null;
        return stops.filter((s) => s[3] >= 0.1);
      }
      const bc = computed(e, 'background-color', W);
      if (bc === null) return null;
      const c = /currentcolor/i.test(bc) ? colorOf(e, W) : parseColor(bc || 'transparent');
      if (c === null) return null;
      if (c[3] >= 0.1) return [c];
    }
    return [[255, 255, 255, 1]];
  }

  // Elements positioned over the page (absolute or fixed, large, with a background): they can cover the listings.
  function overlayAt(W) {
    const walker = doc.createTreeWalker(doc.body || doc.documentElement, 1);
    for (let e = walker.currentNode; e; e = walker.nextNode()) {
      if (HIDDEN_TAGS.has(e.localName)) continue;
      if (e.localName === 'dialog' && e.hasAttribute('open')) return 'an open dialog';
      const positioned = matched(e).filter((d) => d.prop === 'position' || d.prop === 'all');
      if (!positioned.some((d) => /absolute|fixed|var\(|inherit|all/i.test(`${d.prop} ${d.value}`))) continue;
      for (const pseudo of [null, 'before', 'after']) {
        if (pseudo && !matched(e).some((d) => d.pseudo === pseudo && d.prop === 'content')) continue;
        if (pseudo) {
          const ct = computed(e, 'content', W, pseudo);
          if (ct !== null && ['', 'none', 'normal'].includes(ct.trim())) continue;
        }
        const c = (p) => computed(e, p, W, pseudo);
        const pos = c('position');
        if (pos === null) return 'position cannot be evaluated';
        if (!['absolute', 'fixed'].includes(pos.trim())) continue;
        if (!pseudo && hiddenAt(e, W)) continue;
        const big = (a, b, dim, frac) => {
          const sa = c(a); const sb = c(b); const d = c(dim);
          if (sa === null || sb === null || d === null) return true;
          if (sa.trim() && sa.trim() !== 'auto' && sb.trim() && sb.trim() !== 'auto') return true;
          const t = d.trim();
          if (!t || t === 'auto') return false;
          if (t.endsWith('%')) return parseFloat(t) >= frac * 100;
          const px = lengthPx(t, 16, W);
          return px === null || px >= frac * W;
        };
        if (!big('left', 'right', 'width', 0.5) || !big('top', 'bottom', 'height', 0.3)) continue;
        const bg = c('background-color'); const img = c('background-image'); const bf = c('backdrop-filter');
        const opaque = bg === null || img === null || bf === null || (parseColor(bg || 'transparent')?.[3] ?? 1) >= 0.1 ||
          (img.trim() && img.trim() !== 'none') || (bf.trim() && bf.trim() !== 'none');
        if (opaque) return `an element positioned over the page (<${e.localName}${pseudo ? `>::${pseudo}` : '>'})`;
      }
    }
    return null;
  }

  // ---- evaluate at every width the media queries distinguish
  const W_LIST = [...widths].filter((w) => w > 0).sort((a, b) => a - b);
  const pageReasons = [...reasons];
  for (const W of W_LIST) {
    const o = overlayAt(W);
    if (o) { pageReasons.push(`${o} at ${W}px`); break; }
  }
  const unevaluable = pageReasons.length > 0;

  const visibleAll = (el) => !unevaluable && W_LIST.every((W) => !hiddenAt(el, W));
  const textVisible = (el) => !unevaluable && W_LIST.every((W) => !hiddenAt(el, W) && !textHiddenAt(el, W));

  const visibleText = (node) => {
    const parts = [];
    const walk = (n) => {
      if (n.nodeType === 3) {
        if (n.parentElement && textVisible(n.parentElement)) parts.push(n.nodeValue);
        return;
      }
      if (n.nodeType !== 1) return;
      const tag = n.localName;
      if (HIDDEN_TAGS.has(tag)) return;
      const block = ['p', 'div', 'li', 'td', 'th', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'dd', 'dt', 'section',
        'br', 'header', 'footer', 'article', 'table', 'ul', 'ol', 'title'].includes(tag);
      if (block) parts.push('\n');
      for (const ch of n.childNodes) walk(ch);
      if (block) parts.push('\n');
    };
    walk(node);
    return parts.join('').replace(/[ \t\r\f\v]+/g, ' ');
  };

  const rows = [];
  const rowIndex = new Map();
  for (const tb of doc.querySelectorAll('tbody')) {
    for (const tr of tb.querySelectorAll('tr')) {
      rowIndex.set(tr, rows.length);
      rows.push({
        tbody: tb.id || '',
        visible: visibleAll(tr),
        cells: [...tr.querySelectorAll('td,th')].map((td) => visibleText(td).replace(/\s+/g, ' ').trim()),
        text: visibleText(tr).replace(/\s+/g, ' ').trim(),
      });
    }
  }
  const links = [...doc.querySelectorAll('a[href]')]
    .filter((a) => a.href.startsWith(PP))
    .map((a) => ({ href: a.href, visible: visibleAll(a) && visibleText(a).trim() !== '',
                   tbody: (a.closest('tbody') || {}).id || '', row: rowIndex.get(a.closest('tr')) ?? -1 }));
  const text = unevaluable ? '' : visibleText(doc.body || doc.documentElement);
  // Every word of copy in the body, visible or not: claims are checked on all of it, so hiding a sentence (or making
  // the page unevaluable) can never make a claim disappear.
  const all = [];
  const walkAll = (n) => {
    if (n.nodeType === 3) { all.push(n.nodeValue); return; }
    if (n.nodeType !== 1) return;
    if (['script', 'style', 'template'].includes(n.localName)) return;
    const block = !['a', 'span', 'b', 'i', 'em', 'strong', 'code', 'small', 'sup', 'sub', 'abbr', 'mark', 'u', 's'].includes(n.localName);
    if (block) all.push('\n');
    for (const ch of n.childNodes) walkAll(ch);
    if (block) all.push('\n');
  };
  walkAll(doc.body || doc.documentElement);
  const textAll = all.join('').replace(/[ \t\r\f\v]+/g, ' ');
  for (const r of pageReasons) errors.push(`not evaluated, listings count as not visible: ${r}`);
  dom.window.close();
  return { page: pg.page, rows, links, text, text_all: textAll, unevaluable: pageReasons, errors };
}

// --------------------------------------------------------------------------------------------------- conditions

// Width thresholds (px) a media query list names; each one and its neighbours are evaluated.
function mediaWidths(text) {
  const out = [];
  const re = /(-?\d*\.?\d+)(px|em|rem)/g; let m;
  while ((m = re.exec(text))) {
    const px = parseFloat(m[1]) * (m[2] === 'px' ? 1 : 16);
    out.push(Math.floor(px) - 1, Math.round(px), Math.ceil(px) + 1);
  }
  return out;
}

// true / false / null (cannot evaluate) for a condition at viewport width W (screen).
function condAt(c, W) {
  if (c.type !== 'media') return null;
  const list = c.text.split(',').map((s) => s.trim().toLowerCase());
  let unknown = false;
  for (const q of list) {
    const r = mediaQuery(q, W);
    if (r === true) return true;
    if (r === null) unknown = true;
  }
  return unknown ? null : false;
}

function mediaQuery(q, W) {
  if (!q) return true;
  let s = q; let neg = false;
  if (s.startsWith('not ')) { neg = true; s = s.slice(4).trim(); }
  if (s.startsWith('only ')) s = s.slice(5).trim();
  const parts = s.split(/\s+and\s+/);
  let result = true;
  for (const p of parts) {
    let r;
    if (/^(all|screen)$/.test(p)) r = true;
    else if (/^(print|speech|tty|tv|projection|handheld|braille|embossed|aural)$/.test(p)) r = false;
    else {
      const m = p.match(/^\(\s*(min-width|max-width|width)\s*:\s*(-?\d*\.?\d+)(px|em|rem)\s*\)$/);
      const rg = p.match(/^\(\s*width\s*(>=|<=|>|<)\s*(-?\d*\.?\d+)(px|em|rem)\s*\)$/);
      if (m) {
        const v = parseFloat(m[2]) * (m[3] === 'px' ? 1 : 16);
        r = m[1] === 'min-width' ? W >= v : m[1] === 'max-width' ? W <= v : W === v;
      } else if (rg) {
        const v = parseFloat(rg[2]) * (rg[3] === 'px' ? 1 : 16);
        r = { '>=': W >= v, '<=': W <= v, '>': W > v, '<': W < v }[rg[1]];
      } else r = null;
    }
    if (r === false) { result = false; break; }
    if (r === null) result = null;
  }
  if (result === null) return null;
  return neg ? !result : result;
}

function hidesAlone(d) {
  const v = d.value.trim().toLowerCase();
  if (d.prop.startsWith('--')) return true;
  const ls = longhands(d.prop);
  if (!ls.length) return false;
  if (ls.includes('display')) return v === 'none';
  if (ls.includes('visibility')) return /hidden|collapse/.test(v);
  if (ls.includes('opacity')) return !(num01(v) >= 0.1);
  if (ls.includes('color') || ls.includes('text-fill-color')) { const c = parseColor(v); return c === null || c[3] < 0.1; }
  if (ls.includes('font-size')) { const px = lengthPx(v); return px === null ? !/^(xx?-small|small|medium|large|xx?x?-large|smaller|larger|inherit|initial|unset)$/.test(v) : px < 4; }
  if (ls.some((l) => ['background-color', 'background-image', 'font-family', 'z-index', 'line-height'].includes(l))) return false;
  return true;
}

// Dispatch last: every constant above is initialised.
if (mode === 'run') await runStage(); else await evalStage();
