// Minimal browser surface for the dashboard's actual event handlers. No network or timers escape tests.
export function browser(href = 'https://example.test/dashboard/?campaign=keep#results') {
  const document = { activeElement: null, nodes: new Map() };
  class Element {
    constructor(tag = 'div', text = '') { this.tagName = tag; this.children = []; this.dataset = {}; this.style = {}; this.attributes = {}; this.listeners = {}; this.value = ''; this.hidden = false; this.disabled = false; this.clientWidth = 600; this.textContent = text; }
    get textContent() { return this.text + this.children.map(n => n.textContent ?? n).join(''); }
    set textContent(value) { this.text = String(value); this.replaceChildren(); }
    append(...nodes) { for (const n of nodes) { if (typeof n === 'object') n.parent = this; this.children.push(n); } }
    add(node) { this.append(node); }
    replaceChildren(...nodes) { if (this.contains(document.activeElement) && document.activeElement !== this) document.activeElement = document.body; this.children.forEach(n => { if (typeof n === 'object') n.parent = null; }); this.children = []; this.append(...nodes); }
    get options() { return this.children; }
    get cells() { return this.children; }
    setAttribute(key, value) { this.attributes[key] = String(value); }
    getAttribute(key) { return this.attributes[key]; }
    removeAttribute(key) { delete this.attributes[key]; }
    addEventListener(event, listener) { this.listeners[event] = listener; }
    dispatch(event) { return this.listeners[event]?.({ target: this }); }
    click() { if (!this.disabled) return this.dispatch('click'); }
    focus() { document.activeElement = this; this.dispatch('focus'); }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(n => n !== this); this.parent = null; }
    contains(node) { return this === node || this.children.some(n => typeof n === 'object' && n.contains(node)); }
    querySelectorAll(selector) { return this.children.flatMap(n => typeof n === 'object' ? [...((selector === '[data-model]' ? n.dataset.model : n.tagName === selector) ? [n] : []), ...n.querySelectorAll(selector)] : []); }
  }
  document.body = new Element('body');
  document.activeElement = document.body;
  document.createElement = tag => new Element(tag);
  document.createElementNS = (_, tag) => new Element(tag);
  document.createTextNode = value => String(value);
  document.getElementById = id => { if (!document.nodes.has(id)) { const n = new Element(); n.id = id; document.nodes.set(id, n); } return document.nodes.get(id); };
  document.querySelector = selector => document.getElementById(selector.slice(1));
  class Option extends Element { constructor(text, value) { super('option', text); this.value = value; } }
  const history = [href]; let position = 0;
  const media = { matches: false, addEventListener(_, cb) { this.change = cb; } };
  const window = { location: new URL(href), listeners: {}, matchMedia: () => media, addEventListener(event, cb) { this.listeners[event] = cb; } };
  window.history = {
    pushState(_, __, url) { window.location = new URL(url, window.location); history.splice(++position); history.push(window.location.href); },
    replaceState(_, __, url) { window.location = new URL(url, window.location); history[position] = window.location.href; },
  };
  const jobs = new Map(); let timerId = 0;
  const timers = { set(callback, ms) { if (ms !== 300) throw new Error('Expected 300ms debounce'); jobs.set(++timerId, callback); return timerId; }, clear(id) { jobs.delete(id); } };
  return { document, window, Option, media, history, timers,
    el: id => document.getElementById(id),
    flush() { const callbacks = [...jobs.values()]; jobs.clear(); callbacks.forEach(cb => cb()); },
    go(delta) { position = Math.min(history.length - 1, Math.max(0, position + delta)); window.location = new URL(history[position]); return window.listeners.popstate?.(); },
    navigate(url) { window.history.pushState(null, '', url); return window.listeners.popstate?.(); },
  };
}
export function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
