/*
 * APEX Blindfold: helpers shared by the three pages.
 */
import * as P from './paillier.js';

export { P };

/** Calls an APEX Ajax Callback process and resolves with its JSON answer. */
export function callback(name, data = {}) {
  return new Promise((resolve, reject) => {
    apex.server.process(name, data, {
      dataType: 'json',
      success: resolve,
      error: (xhr, status, message) => {
        const detail = xhr && xhr.responseJSON && xhr.responseJSON.error;
        reject(new Error(detail || message || status || 'The request failed'));
      },
    });
  });
}

/** Small DOM builder: el('p', { class: 'x' }, 'text', childNode). */
export function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === false || value === null || value === undefined) continue;
    if (name === 'class') node.className = value;
    else if (name === 'text') node.textContent = value;
    else if (name.startsWith('on')) node.addEventListener(name.slice(2), value);
    else node.setAttribute(name, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** First and last characters of a long hexadecimal number. */
export function short(hex, head = 20, tail = 10) {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

export const formatInt = (value) => Number(value).toLocaleString('en-US');

/** Yields to the browser so it can repaint during long computations. */
export const repaint = () => new Promise((resolve) => setTimeout(resolve, 0));

/** URL of another page of this application, in the same session. */
export function pageUrl(alias) {
  const url = new URL(window.location.href);
  url.pathname = url.pathname.replace(/[^/]*$/, alias);
  url.search = `?session=${apex.env.APP_SESSION}`;
  url.hash = '';
  return url.toString();
}

const MARK = `
<svg class="bf-mark" viewBox="0 0 320 200" aria-hidden="true" focusable="false">
  <path d="M 30 100 Q 160 4 290 100 Q 160 196 30 100 Z" fill="none" stroke="currentColor" stroke-width="11" stroke-linejoin="round"/>
  <circle cx="160" cy="100" r="40" fill="none" stroke="currentColor" stroke-width="11"/>
  <g transform="rotate(-7 160 100)">
    <rect x="6" y="74" width="308" height="52" rx="4" fill="#E8B339"/>
    <rect x="154" y="84" width="12" height="32" fill="#0A0A0A"/>
    <rect x="144" y="94" width="32" height="12" fill="#0A0A0A"/>
  </g>
</svg>`;

const PAGES = [
  { alias: 'vote', label: 'Vote' },
  { alias: 'ledger', label: 'What the database sees' },
  { alias: 'tally', label: 'Tally' },
];

/** Adds the header and the footer that every page shares. */
export function mountChrome(root, active) {
  const brand = el('a', { class: 'bf-brand', href: pageUrl('vote'), 'aria-label': 'APEX Blindfold' });
  brand.innerHTML = `${MARK}<span class="bf-word"><span class="bf-word__apex">APEX</span><span class="bf-word__name">Blindfold</span></span>`;

  const nav = el('nav', { class: 'bf-nav', 'aria-label': 'Pages' },
    PAGES.map((page) => el('a', {
      class: 'bf-nav__link',
      href: pageUrl(page.alias),
      'aria-current': page.alias === active ? 'page' : null,
    }, page.label)));

  root.prepend(el('header', { class: 'bf-top' }, brand, nav));

  const version = apex.env && apex.env.APEX_VERSION ? `Oracle APEX ${apex.env.APEX_VERSION.split('.').slice(0, 2).join('.')}` : 'Oracle APEX';
  const foot = el('footer', { class: 'bf-foot' },
    el('span', { class: 'bf-foot__claim' }, 'The database counts. It never sees.'),
    el('span', {}, 'Educational cryptography. Not a voting system.'),
    el('span', { class: 'bf-foot__tech' }, `Paillier · 2048-bit · ${version}`));
  (document.querySelector('.bf-foot-slot') || root).append(foot);
}

/** Shows a status line. kind: 'info' | 'ok' | 'error'. */
export function say(node, text, kind = 'info') {
  node.textContent = text;
  node.className = `bf-message bf-message--${kind}`;
}
