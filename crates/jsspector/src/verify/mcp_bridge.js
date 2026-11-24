'use strict';
// An HTTP front for an MCP server that speaks only stdio.
//
// Most MCP servers are started by a client as a child process and talk newline-delimited JSON-RPC
// over its stdin and stdout; they bind no port. The verifier drives a server over HTTP, so this
// script is what the app's container runs instead of the app: it starts the repository's own stdio
// server as its child, and serves what the child says as a stateless Streamable HTTP endpoint on the
// session's port. Everything downstream — endpoint discovery, `tools/list`, the call driver, the
// oracles, the fix proof — then works on a stdio server exactly as on an HTTP one.
//
// Which command starts the server is not known for certain, so the spec lists candidates: each is
// tried in order, and the first that answers `initialize` is the one. `GET /__bridge` reports the
// state and every trial, so a launch that found nothing can say why.
//
// Usage: node jss-mcp-bridge.js '{"candidates":[["node","dist/index.js"],...],"startupMs":20000}'

const http = require('http');
const { spawn } = require('child_process');

const spec = JSON.parse(process.argv[2] || '{}');
const PORT = Number(process.env.PORT) || spec.port || 3000;
const STARTUP_MS = spec.startupMs || 20000;
const REQUEST_MS = spec.requestMs || 30000;
const MAX_MESSAGE_CHARS = 1024 * 1024;
const MAX_REQUEST_CHARS = 1024 * 1024;
const CANDIDATES = Array.isArray(spec.candidates) ? spec.candidates : [];
const PROTOCOL = '2025-03-26';

let live = null; // { child, info } of the server that answered `initialize`
let winner = null; // the command that started it
let initResult = null; // what it answered, handed to every client that initializes
let state = 'starting'; // starting | ready | restarting | failed
const trials = []; // one per candidate tried: { command, outcome, stderr }
let restarts = [];
let closing = false; // the bridge itself is being stopped: nothing is restarted
let nextId = 1;
let settle; // resolves `settled` once the first launch has an answer, good or bad
const settled = new Promise((resolve) => { settle = resolve; });
let readyAgain = Promise.resolve(); // pending while a crashed server is being restarted

function log(text) {
  try { process.stderr.write('[mcp-bridge] ' + text + '\n'); } catch (e) { /* nothing to tell */ }
}

// One server process and the requests waiting on it. Replies are matched by the bridge's own ids,
// so two clients using the same id never see each other's answers.
function launch(command) {
  const [file, ...args] = command;
  const env = Object.assign({}, process.env);
  // The port belongs to the bridge: a server that also speaks HTTP must not try to bind it.
  delete env.PORT;
  const info = { command, stderr: '', buffer: '', exited: null, pending: new Map() };
  const child = spawn(file, args, { cwd: spec.cwd || process.cwd(), env, stdio: ['pipe', 'pipe', 'pipe'] });
  info.child = child;
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { info.stderr = (info.stderr + chunk).slice(-4000); });
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    info.buffer += chunk;
    if (info.buffer.length > MAX_MESSAGE_CHARS) {
      info.stderr = (info.stderr + '\nstdout message exceeded verifier limit').slice(-4000);
      info.buffer = '';
      stop(info);
      return;
    }
    let at;
    while ((at = info.buffer.indexOf('\n')) >= 0) {
      const line = info.buffer.slice(0, at).trim();
      info.buffer = info.buffer.slice(at + 1);
      if (!line) { continue; }
      let message;
      try { message = JSON.parse(line); } catch (e) { continue; } // a log line on stdout
      onMessage(info, message);
    }
  });
  child.stdin.on('error', () => { /* the server died mid-write; the exit handler reports it */ });
  child.on('error', (error) => { info.stderr += String(error && error.message); finish(info, { code: -1, signal: null }); });
  child.on('exit', (code, signal) => finish(info, { code, signal }));
  return info;
}

function finish(info, how) {
  if (info.exited) { return; }
  info.exited = how;
  for (const [, entry] of info.pending) { entry.reject(new Error('exited')); }
  info.pending.clear();
  if (!closing && live && live.child === info.child && state === 'ready') {
    log('the MCP server exited (' + (how.code === null ? how.signal : how.code) + '); restarting it');
    restart();
  }
}

function onMessage(info, message) {
  if (message && message.id !== undefined && message.method === undefined && info.pending.has(message.id)) {
    const entry = info.pending.get(message.id);
    info.pending.delete(message.id);
    entry.resolve(message);
    return;
  }
  // A request the server makes of its client: answer what any client could, so it does not wait.
  if (message && message.id !== undefined && typeof message.method === 'string') {
    const reply = message.method === 'ping'
      ? { jsonrpc: '2.0', id: message.id, result: {} }
      : message.method === 'roots/list'
        ? { jsonrpc: '2.0', id: message.id, result: { roots: [] } }
        : { jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } };
    write(info, reply);
  }
}

function write(info, message) {
  if (info.exited) { return false; }
  try { info.child.stdin.write(JSON.stringify(message) + '\n'); return true; } catch (e) { return false; }
}

function request(info, method, params, ms) {
  return new Promise((resolve, reject) => {
    const id = 'b' + nextId++;
    const timer = setTimeout(() => { info.pending.delete(id); reject(new Error('timeout')); }, ms);
    info.pending.set(id, {
      resolve: (message) => { clearTimeout(timer); resolve(message); },
      reject: (error) => { clearTimeout(timer); reject(error); },
    });
    if (!write(info, { jsonrpc: '2.0', id, method, params })) {
      info.pending.delete(id);
      clearTimeout(timer);
      reject(new Error('exited'));
    }
  });
}

function stop(info) {
  if (!info || info.exited) { return; }
  try { info.child.kill('SIGKILL'); } catch (e) { /* already gone */ }
}

// Starts `command` and shakes hands with it. Resolves to the live server, or to why it was not one.
async function trial(command) {
  const info = launch(command);
  let outcome;
  try {
    const answer = await request(info, 'initialize', {
      protocolVersion: PROTOCOL,
      capabilities: {},
      clientInfo: { name: 'jsspector-bridge', version: '0' },
    }, STARTUP_MS);
    if (answer && answer.result) {
      write(info, { jsonrpc: '2.0', method: 'notifications/initialized' });
      return { info, result: answer.result };
    }
    outcome = 'answered initialize with an error: ' + JSON.stringify(answer && answer.error).slice(0, 200);
  } catch (error) {
    outcome = error.message === 'exited'
      ? 'exited (' + (info.exited && (info.exited.code === null ? info.exited.signal : info.exited.code)) + ') before answering initialize'
      : 'did not answer initialize within ' + STARTUP_MS + ' ms';
  }
  // A crashing server's last words are on stderr a moment after its exit; the tail is enough.
  await new Promise((resolve) => setTimeout(resolve, 50));
  trials.push({ command, outcome, stderr: info.stderr.slice(-600) });
  stop(info);
  return { info: null, outcome };
}

async function start() {
  for (const command of CANDIDATES) {
    const found = await trial(command);
    if (found.info) {
      live = { child: found.info.child, info: found.info };
      winner = command;
      initResult = found.result;
      state = 'ready';
      trials.push({ command, outcome: 'ready', stderr: '' });
      log('serving ' + JSON.stringify(command));
      settle();
      return;
    }
  }
  state = 'failed';
  log('no candidate started an MCP server');
  settle();
}

// The server died (a payload crashed it, a handler hung and was killed): bring the same command
// back so the attempts that follow still have a server to meet. A server that cannot stay up is
// given up on rather than restarted forever.
function restart() {
  const now = Date.now();
  restarts = restarts.filter((at) => now - at < 60000);
  restarts.push(now);
  if (restarts.length > 20 || !winner) {
    state = 'failed';
    return;
  }
  state = 'restarting';
  readyAgain = (async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      const found = await trial(winner);
      if (found.info) {
        live = { child: found.info.child, info: found.info };
        initResult = found.result;
        state = 'ready';
        return;
      }
    }
    state = 'failed';
  })();
}

async function forward(message) {
  const id = message.id;
  const params = message.params;
  for (let attempt = 0; attempt < 2; attempt++) {
    await settled;
    await readyAgain;
    if (state !== 'ready' || !live) { break; }
    const info = live.info;
    try {
      const answer = await request(info, message.method, params, REQUEST_MS);
      return Object.assign({}, answer, { id });
    } catch (error) {
      if (error.message === 'timeout') {
        // A handler that never answers has wedged the one thread the server has.
        stop(info);
        return { jsonrpc: '2.0', id, error: { code: -32001, message: 'the MCP server did not answer within ' + REQUEST_MS + ' ms' } };
      }
      // It exited under this request: the next try meets the restarted server.
      if (attempt === 0) {
        await readyAgain;
        continue;
      }
      return { jsonrpc: '2.0', id, error: { code: -32000, message: 'the MCP server exited: ' + info.stderr.slice(-300) } };
    }
  }
  return { jsonrpc: '2.0', id, error: { code: -32000, message: 'no MCP server is running' } };
}

function readBody(req) {
  return new Promise((resolve) => {
    let text = '';
    let oversized = false;
    req.on('data', (chunk) => {
      if (oversized) { return; }
      text += chunk;
      if (text.length > MAX_REQUEST_CHARS) { oversized = true; text = ''; }
    });
    req.on('end', () => resolve(text));
    req.on('error', () => resolve(''));
  });
}

function sendJson(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(value));
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://bridge');
    if (url.pathname === '/__bridge') {
      return sendJson(res, 200, { state, command: winner, trials });
    }
    if (req.method === 'DELETE') { res.writeHead(200); return res.end(); }
    if (req.method !== 'POST') { res.writeHead(404); return res.end(); }
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { error: 'not JSON' }); }
    await settled;
    if (state === 'failed') {
      return sendJson(res, 503, { error: 'no command started an MCP server over stdio', trials });
    }
    const batch = Array.isArray(body);
    const replies = [];
    for (const message of batch ? body : [body]) {
      if (!message || typeof message !== 'object') { continue; }
      if (message.method === 'initialize') {
        // The server was initialized once, by the bridge: every client is told the same.
        replies.push({ jsonrpc: '2.0', id: message.id, result: initResult });
      } else if (message.id === undefined) {
        // `notifications/initialized` was sent already; any other notification goes through.
        if (message.method !== 'notifications/initialized' && live) { write(live.info, message); }
      } else {
        replies.push(await forward(message));
      }
    }
    if (!replies.length) { res.writeHead(202); return res.end(); }
    return sendJson(res, 200, batch ? replies : replies[0]);
  } catch (error) {
    try { sendJson(res, 500, { error: String(error && error.message) }); } catch (e) { /* closed */ }
  }
});

function shutdown() {
  closing = true;
  stop(live && live.info);
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('exit', () => { closing = true; stop(live && live.info); });

// The trusted driver is executed in this same container/process namespace. Keeping the bridge on
// loopback prevents another container on the verification network from invoking the stdio tool.
server.listen(PORT, '127.0.0.1', () => {
  log('listening on ' + PORT + ' for ' + CANDIDATES.length + ' candidate command(s)');
  start().catch((error) => { log('launch failed: ' + (error && error.message)); state = 'failed'; settle(); });
});
