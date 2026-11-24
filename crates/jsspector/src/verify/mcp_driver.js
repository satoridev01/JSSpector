const http = require('http');
const https = require('https');
const spec = JSON.parse(process.argv[2]);
const hosts = ['127.0.0.1', '::1'];
const mods = spec.tls ? [['https', https], ['http', http]] : [['http', http], ['https', https]];
const combos = [];
for (const m of mods) { for (const h of hosts) { combos.push([m[0], m[1], h]); } }
const PROTOCOL = '2025-03-26';
const JSON_HEADERS = { 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream' };
const REQUEST_MS = spec.mode === 'discover' ? 5000 : 15000;
const MAX_RESPONSE_CHARS = 1024 * 1024;
const MAX_TOOLS = 512;

function meta(status) { try { process.stderr.write('__JSS_META__' + JSON.stringify({ status }) + '\n'); } catch (e) {} }
function finish(status, body) {
  meta(status);
  try { process.stdout.write(body || '', () => process.exit(0)); } catch (e) { process.exit(0); }
}

// The JSON-RPC message answering `id` in a body: a whole JSON reply, or a text/event-stream whose
// events each carry one message (a request's reply can follow progress or log notifications).
function messageIn(text, id) {
  const whole = parseJson(text);
  const wholeHit = pick(whole, id);
  if (wholeHit) { return wholeHit; }
  for (const event of text.split(/\r?\n\r?\n/)) {
    const data = event.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
    const hit = pick(parseJson(data), id);
    if (hit) { return hit; }
  }
  return null;
}
function parseJson(text) { try { return JSON.parse(text); } catch (e) { return null; } }
function pick(value, id) {
  const list = Array.isArray(value) ? value : [value];
  return list.find((m) => m && typeof m === 'object' && m.id === id && ('result' in m || 'error' in m)) || null;
}

// One HTTP exchange. With `want` (a JSON-RPC id) the reply is read until the message answering it
// has arrived — a stateful server may keep its event stream open afterwards — and returned parsed.
function exchange(mod, host, method, path, headers, body, want) {
  return new Promise((resolve, reject) => {
    const options = { host, port: spec.port, method, path, headers: Object.assign({}, headers), timeout: REQUEST_MS };
    if (mod === https) { options.rejectUnauthorized = false; }
    let settled = false;
    const req = mod.request(options, (res) => {
      let text = '';
      const done = (message) => {
        if (settled) { return; }
        settled = true;
        resolve({ status: res.statusCode || 0, headers: res.headers, text, message });
        try { req.destroy(); } catch (e) {}
      };
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        if (settled) { return; }
        text += chunk;
        if (want !== undefined) { const hit = messageIn(text, want); if (hit) { done(hit); } }
        if (text.length > MAX_RESPONSE_CHARS) {
          text = text.slice(0, MAX_RESPONSE_CHARS);
          try { res.destroy(); } catch (e) {}
          done(want !== undefined ? messageIn(text, want) : null);
        }
      });
      res.on('end', () => done(want !== undefined ? messageIn(text, want) : null));
      res.on('error', () => done(null));
    });
    req.on('error', (e) => { if (!settled) { settled = true; reject(e); } });
    req.on('timeout', () => { req.destroy(); if (!settled) { settled = true; reject(new Error('timeout')); } });
    if (body !== undefined) { req.write(body); }
    req.end();
  });
}

const rpc = (id, method, params) => JSON.stringify({ jsonrpc: '2.0', id, method, params });
const INITIALIZE = rpc(1, 'initialize', { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: { name: 'jsspector', version: '0' } });
const INITIALIZED = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' });

// Streamable HTTP: initialize, announce initialized, run `work`, end the session when the server
// issued one. A stateless server issues none, and the same three requests work against it. `null`
// means this path is not a Streamable HTTP MCP endpoint; `{ auth }` that it wants credentials.
async function streamable(mod, host, path, work) {
  const init = await exchange(mod, host, 'POST', path, JSON_HEADERS, INITIALIZE, 1);
  if (init.status === 401 || init.status === 403) { return { auth: init.status }; }
  if (!init.message || !init.message.result) { return null; }
  const sid = init.headers['mcp-session-id'];
  const headers = Object.assign({}, JSON_HEADERS, { 'MCP-Protocol-Version': init.message.result.protocolVersion || PROTOCOL });
  if (sid) { headers['Mcp-Session-Id'] = sid; }
  await exchange(mod, host, 'POST', path, headers, INITIALIZED).catch(() => {});
  const send = async (id, method, params) => (await exchange(mod, host, 'POST', path, headers, rpc(id, method, params), id)).message;
  const message = await work(send);
  if (sid) { await exchange(mod, host, 'DELETE', path, headers).catch(() => {}); }
  return { message };
}

// The legacy HTTP+SSE transport: a GET holds an event stream open, whose first event names the URL
// to POST messages to; replies arrive on the stream, not in the POST's own response.
function sse(mod, host, path, work) {
  return new Promise((resolve, reject) => {
    const options = { host, port: spec.port, method: 'GET', path, headers: { 'Accept': 'text/event-stream' }, timeout: REQUEST_MS };
    if (mod === https) { options.rejectUnauthorized = false; }
    let settled = false;
    const settle = (value, error) => { if (settled) { return; } settled = true; try { req.destroy(); } catch (e) {} error ? reject(error) : resolve(value); };
    const req = mod.request(options, (res) => {
      if (res.statusCode === 401 || res.statusCode === 403) { res.resume(); return settle({ auth: res.statusCode }); }
      if (res.statusCode !== 200 || !String(res.headers['content-type'] || '').includes('text/event-stream')) { res.resume(); return settle(null); }
      let buffer = '';
      let endpoint = null;
      const waiting = new Map();
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        buffer += chunk;
        if (buffer.length > MAX_RESPONSE_CHARS) { return settle(null); }
        let match;
        while ((match = /\r?\n\r?\n/.exec(buffer))) {
          const event = buffer.slice(0, match.index);
          buffer = buffer.slice(match.index + match[0].length);
          const name = (event.match(/^event:\s*(.*)$/m) || [])[1];
          const data = event.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
          if (name === 'endpoint' && !endpoint) { endpoint = data.trim(); begin(); }
          else { const message = parseJson(data); if (message && waiting.has(message.id)) { waiting.get(message.id)(message); waiting.delete(message.id); } }
        }
      });
      res.on('end', () => settle(null));
      res.on('error', () => settle(null));
      const post = (body) => new Promise((ok) => {
        const target = new URL(endpoint, 'http://' + host + ':' + spec.port);
        const r = mod.request({ host, port: spec.port, method: 'POST', path: target.pathname + target.search, headers: { 'Content-Type': 'application/json' }, timeout: REQUEST_MS }, (x) => { x.resume(); x.on('end', () => ok(x.statusCode)); });
        r.on('error', () => ok(0));
        r.end(body);
      });
      const send = (id, method, params) => new Promise((ok, fail) => {
        const timer = setTimeout(() => fail(new Error('timeout')), REQUEST_MS);
        waiting.set(id, (message) => { clearTimeout(timer); ok(message); });
        post(rpc(id, method, params));
      });
      async function begin() {
        try {
          const init = await send(1, 'initialize', { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: { name: 'jsspector', version: '0' } });
          if (!init || !init.result) { return settle(null); }
          await post(INITIALIZED);
          settle({ message: await work(send) });
        } catch (e) { settle(null, e); }
      }
    });
    req.on('error', (e) => settle(null, e));
    req.on('timeout', () => settle(null, new Error('timeout')));
    req.end();
  });
}

async function listTools(send) {
  const tools = [];
  let cursor;
  for (let page = 0; page < 20; page++) {
    const message = await send(100 + page, 'tools/list', cursor ? { cursor } : {});
    const result = message && message.result;
    if (!result || !Array.isArray(result.tools)) { break; }
    for (const tool of result.tools) {
      tools.push({ name: tool.name, inputSchema: tool.inputSchema || {} });
      if (tools.length >= MAX_TOOLS) { return { result: { tools } }; }
    }
    cursor = result.nextCursor;
    if (!cursor) { break; }
  }
  return { result: { tools } };
}

function statusFor(code, text) {
  if (code === -32602 || /MCP error -32602/.test(text)) { return /not found|unknown tool/i.test(text) ? 404 : 422; }
  if (code === -32601 || /method not found/i.test(text)) { return 404; }
  return 500;
}

// The reply a probe reads: the tool's text as the body, and a status standing for what happened —
// 200 it ran, 422 its input schema rejected the arguments (the payload never reached the handler),
// 404 no such tool, 500 the handler failed.
function normalize(message) {
  if (!message) { return { status: 502, body: '' }; }
  if (message.error) { const text = String(message.error.message || ''); return { status: statusFor(message.error.code, text), body: text }; }
  const result = message.result || {};
  const parts = [];
  for (const item of result.content || []) {
    if (item && typeof item.text === 'string') { parts.push(item.text); }
    else if (item && item.resource && typeof item.resource.text === 'string') { parts.push(item.resource.text); }
  }
  if (result.structuredContent !== undefined) { parts.push(JSON.stringify(result.structuredContent)); }
  const body = parts.join('\n');
  return { status: result.isError ? statusFor(null, body) : 200, body };
}

async function connect(mod, host, endpoint, work) {
  return endpoint.transport === 'sse' ? sse(mod, host, endpoint.path, work) : streamable(mod, host, endpoint.path, work);
}

async function discover() {
  const errors = [];
  let auth = null;
  for (const [name, mod, host] of combos) {
    for (const path of spec.paths) {
      for (const transport of ['streamable', 'sse']) {
        try {
          const r = await connect(mod, host, { transport, path }, listTools);
          if (r && r.auth) { auth = r.auth; continue; }
          if (r && r.message) { return finish(200, JSON.stringify({ endpoint: { transport, path }, tools: r.message.result.tools })); }
        } catch (e) { errors.push(name + '://' + host + path + ' ' + transport + ': ' + e.message); }
      }
    }
  }
  finish(auth || 404, JSON.stringify({ endpoint: null, auth, errors: errors.slice(0, 6) }));
}

async function call() {
  const errors = [];
  for (const [name, mod, host] of combos) {
    try {
      const r = await connect(mod, host, spec.endpoint, (send) => send(2, 'tools/call', { name: spec.tool, arguments: spec.arguments }));
      if (r && r.auth) { return finish(r.auth, ''); }
      if (r && r.message !== undefined) { const out = normalize(r.message); return finish(out.status, out.body); }
    } catch (e) { errors.push(name + '://' + host + ': ' + e.message); }
  }
  process.stderr.write(errors.join('; '));
  finish(0, '');
}

// `bridge`: the stdio bridge's own report (see jss-mcp-bridge.js), polled until it has settled — it
// is trying candidate commands, which can take longer than any single MCP request is allowed to.
async function bridge() {
  const deadline = Date.now() + (spec.waitMs || 120000);
  let last = null;
  while (Date.now() < deadline) {
    for (const [, mod, host] of combos) {
      try {
        const reply = await exchange(mod, host, 'GET', '/__bridge', {}, undefined, undefined);
        if (reply.status === 200) { last = parseJson(reply.text); break; }
      } catch (e) { /* not listening yet */ }
    }
    if (last && last.state !== 'starting' && last.state !== 'restarting') { break; }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  finish(last ? 200 : 504, JSON.stringify(last || { state: 'unreachable' }));
}

const BUDGET_MS = spec.mode === 'bridge' ? (spec.waitMs || 120000) + 5000 : spec.mode === 'discover' ? 60000 : 40000;
setTimeout(() => finish(504, ''), BUDGET_MS);
(spec.mode === 'bridge' ? bridge() : spec.mode === 'discover' ? discover() : call()).catch((e) => { process.stderr.write(String(e && e.message)); finish(0, ''); });
