'use strict';

require('dotenv').config({ override: true });
const express = require('express');
const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const si = require('systeminformation');
const path = require('path');
const net = require('net');

const pkg = require('./package.json');
const APP_NAME = process.env.APP_NAME || pkg.name || 'koi_12';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.get('/', (req, res) => {
  res.status(200).json({ name: APP_NAME, status: 'running', uptime: process.uptime() });
});

app.get('/ui', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/servers', async (req, res) => {
  try {
    const connections = await si.networkConnections();
    const procData = await getProcessesWithTimeout(5000);
    const procByPid = await buildProcessMap(procData);
    const list = connections
      .filter((c) => c && c.state && String(c.state).toUpperCase().includes('LISTEN'))
      .map((c) => {
        const pid = Number(c.pid);
        const p = procByPid.get(pid);
        const threat = evaluateThreat(p, {
          pid,
          exePath: p && p.path,
          name: (p && (p.name || p.process || p.command)) || c.process,
          cmd: (p && [p.command, p.params].filter(Boolean).join(' ')) || '',
          localPort: Number(c.localPort),
          localAddress: c.localAddress,
          protocol: c.protocol,
        });
        return {
          name: deriveServerName(p, c.process, pid, procByPid),
          protocol: c.protocol,
          localAddress: c.localAddress,
          localPort: Number(c.localPort),
          pid,
          process: (p && (p.name || p.process || p.command)) || c.process,
          label: threat.label,
          score: threat.score,
          reasons: threat.reasons,
        };
      })
      .filter((i) => i.pid && i.localPort);
    const items = uniqueBy(list, (i) => `${i.pid}:${i.localPort}:${i.protocol}`);
    res.json({ count: items.length, items });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to list servers' });
  }
});

function deriveServerName(proc, fallbackProcessName, pid, procByPid) {
  if (pid && pid === process.pid) return `${APP_NAME} (server.js)`;

  const fallbackName = fallbackProcessName || (proc && (proc.name || proc.process || proc.command)) || 'unknown';
  if (!proc) return fallbackName;

  const rawName = String(proc.name || proc.process || proc.command || '').trim();
  const genericNames = new Set(['node', 'node.exe', 'python', 'python.exe', 'java', 'java.exe', 'cmd.exe', 'cmd', 'powershell.exe', 'powershell']);
  if (rawName && !genericNames.has(rawName.toLowerCase())) {
    return rawName;
  }

  const cmd = [proc.command, proc.params].filter(Boolean).join(' ');
  const npmRun = cmd.match(/\bnpm(?:\.cmd)?\s+run\s+([\w:-]+)/i);
  if (npmRun && npmRun[1]) return `${npmRun[1]} (npm script)`;

  let file = extractScriptPath(cmd) || proc.path || '';
  if (file) {
    const base = path.basename(file);
    let folder = path.basename(path.dirname(file));
    if (!folder || folder === '.' || folder === base) {
      const guessed = resolveFolderFromParents(pid, procByPid);
      if (guessed) folder = guessed;
    }
    if (folder && folder !== '.' && folder !== base) return `${folder} (${base})`;
    return base || fallbackName;
  }

  return rawName || fallbackName;
}

function resolveFolderFromParents(pid, procByPid) {
  try {
    let curPid = pid;
    for (let depth = 0; depth < 3; depth += 1) {
      const pr = procByPid.get(curPid);
      if (!pr) break;
      const c = [pr.command, pr.params].filter(Boolean).join(' ');
      const mWin = c.match(/\bcd\s+(?:\/d\s+)?([A-Za-z]:\\[^\s"']+)/i);
      if (mWin && mWin[1]) return path.basename(mWin[1]);
      const mNix = c.match(/\bcd\s+([\/~][^\s"']+)/i);
      if (mNix && mNix[1]) return path.basename(mNix[1]);
      curPid = Number(pr.parentPid);
      if (!curPid) break;
    }
  } catch (e) {
    // ignore
  }
  return '';
}

async function getProcessesWithTimeout(ms) {
  if (process.platform === 'win32') {
    return null;
  }
  try {
    return await Promise.race([
      si.processes(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('processes timeout')), ms)),
    ]);
  } catch (e) {
    return null;
  }
}

async function buildProcessMap(procData) {
  const result = new Map();
  let list = [];
  if (procData) {
    if (Array.isArray(procData.list)) {
      list = procData.list;
    } else if (procData.list && typeof procData.list === 'object') {
      list = Object.values(procData.list);
    }
  }

  for (const p of list) {
    if (p && p.pid) {
      result.set(Number(p.pid), { ...p, pid: Number(p.pid) });
    }
  }

  if (result.size) {
    return result;
  }

  return await buildProcessMapFromOS();
}

async function buildProcessMapFromOS() {
  try {
    if (process.platform === 'win32') {
      const stdout = await execCommand('powershell -NoProfile -Command "Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress"');
      return parseWindowsProcessList(stdout);
    }
    const stdout = await execCommand('ps -axo pid=,comm=');
    return parseUnixProcessList(stdout);
  } catch (e) {
    return new Map();
  }
}

function parseWindowsProcessList(stdout) {
  const map = new Map();
  try {
    const parsed = JSON.parse(String(stdout || '').trim() || '[]');
    const entries = Array.isArray(parsed) ? parsed : parsed && parsed.Id ? [parsed] : [];
    for (const item of entries) {
      const pid = Number(item?.Id);
      if (pid) {
        const name = String(item.ProcessName || '').trim();
        map.set(pid, { pid, name, process: name, command: '' });
      }
    }
  } catch (e) {
    // ignore parse failure
  }
  return map;
}

function parseUnixProcessList(stdout) {
  const map = new Map();
  const lines = String(stdout || '').split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    const pid = Number(parts.shift());
    if (!pid) continue;
    const name = parts.join(' ').trim();
    map.set(pid, { pid, name, process: name, command: name });
  }
  return map;
}

async function execCommand(cmd) {
  const { stdout } = await execAsync(cmd, { windowsHide: true, maxBuffer: 10 * 1024 * 1024 });
  return stdout;
}

function extractScriptPath(cmd) {
  if (!cmd) return '';
  const str = String(cmd);
  const abs = str.match(/([A-Za-z]:\\[^"'\s]+\.(?:js|mjs|cjs|ts)|\/[^"'\s]+\.(?:js|mjs|cjs|ts))/i);
  if (abs && abs[1]) return abs[1];

  const rel = str.match(/(?:^|\s)([^\s"']+\.(?:js|mjs|cjs|ts))(?:\s|$)/i);
  return rel ? rel[1] : '';
}

function evaluateThreat(proc, info) {
  // Default: clean, score 0
  if (info && info.pid === process.pid) {
    return { label: 'clean', score: 0, reasons: ['self'] };
  }
  let score = 0;
  const reasons = [];

  const name = (info.name || '').toLowerCase();
  const exe = (info.exePath || '').toLowerCase();
  const cmd = (info.cmd || '').toLowerCase();
  const port = Number(info.localPort) || 0;

  // Heuristic: encoded PowerShell or suspicious scripting
  if (cmd.includes('powershell') && (cmd.includes('-enc') || cmd.includes('-encodedcommand'))) {
    score += 5; reasons.push('powershell encoded command');
  }
  if ((name.includes('wscript') || name.includes('cscript')) && /\.(vbs|js|wsf)\b/.test(cmd)) {
    score += 4; reasons.push('wscript/cscript running script');
  }

  // Heuristic: system binaries outside system32
  if ((name === 'svchost.exe' || name === 'rundll32.exe' || name === 'wscript.exe' || name === 'cscript.exe') && exe) {
    if (!exe.includes('windows') || !exe.includes('system32')) {
      score += 5; reasons.push(`${name} not in system32`);
    }
  }

  // Heuristic: executable from temp/downloads/roaming/public
  const suspectDirs = [
    (process.env.TEMP || '').toLowerCase(),
    (process.env.TMP || '').toLowerCase(),
    (path.join(os.homedir(), 'Downloads')).toLowerCase(),
    (path.join(os.homedir(), 'AppData', 'Local', 'Temp')).toLowerCase(),
    (path.join(os.homedir(), 'AppData', 'Roaming')).toLowerCase(),
    (path.join('C:', 'Users', 'Public')).toLowerCase(),
  ].filter(Boolean);
  if (exe && suspectDirs.some((d) => d && exe.startsWith(d))) {
    score += 3; reasons.push('executable from user temp/downloads');
  }

  // Heuristic: common malware ports (approximate)
  const badPorts = new Set([4444, 5555, 1337, 31337]);
  if (badPorts.has(port)) { score += 2; reasons.push(`listening on commonly abused port ${port}`); }

  // Heuristic: random-looking exe names
  if (/^[a-z]{8,12}\.exe$/.test(name)) { score += 2; reasons.push('random-looking executable name'); }

  const label = score >= 7 ? 'virus' : score >= 3 ? 'suspicious' : 'clean';
  return { label, score, reasons };
}

app.post('/servers/kill', requireKillAuth, async (req, res) => {
  const { pid, port } = req.body || {};
  try {
    let pids = [];
    if (pid) {
      pids = Array.isArray(pid) ? pid.map(Number) : [Number(pid)];
    } else if (port) {
      const connections = await si.networkConnections();
      const list = connections.filter(
        (c) => c && c.state && String(c.state).toUpperCase().includes('LISTEN') && Number(c.localPort) === Number(port)
      );
      pids = Array.from(new Set(list.map((c) => Number(c.pid)).filter(Boolean)));
    } else {
      return res.status(400).json({ error: 'Provide pid or port' });
    }
    if (!pids.length) return res.status(404).json({ error: 'No matching processes found' });
    const results = [];
    for (const p of pids) {
      const r = await killPidSafe(p);
      results.push(r);
    }
    const killed = results.filter((r) => r.killed).map((r) => r.pid);
    const failed = results.filter((r) => !r.killed).map((r) => ({ pid: r.pid, error: r.error }));
    res.json({ killed, failed });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to kill process' });
  }
});

function uniqueBy(arr, keyFn) {
  const s = new Set();
  const out = [];
  for (const item of arr) {
    const k = keyFn(item);
    if (!s.has(k)) {
      s.add(k);
      out.push(item);
    }
  }
  return out;
}

function requireKillAuth(req, res, next) {
  const token = process.env.ADMIN_TOKEN;
  if (token) {
    const auth = req.headers.authorization || '';
    const ok = typeof auth === 'string' && auth.startsWith('Bearer ') && auth.slice(7) === token;
    if (!ok) return res.status(401).json({ error: 'Unauthorized' });
    return next();
  }
  if (isLocalRequest(req)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

function isLocalRequest(req) {
  const ip = req.ip || '';
  return ip === '127.0.0.1' || ip === '::1' || ip.endsWith('127.0.0.1');
}

function killPidSafe(pid) {
  return new Promise((resolve) => {
    const platform = os.platform();
    if (platform === 'win32') {
      exec(`taskkill /PID ${pid} /F`, (error, stdout, stderr) => {
        if (error) return resolve({ pid, killed: false, error: stderr || error.message });
        return resolve({ pid, killed: true });
      });
    } else {
      try {
        process.kill(pid, 'SIGKILL');
        resolve({ pid, killed: true });
      } catch (err) {
        resolve({ pid, killed: false, error: err.message });
      }
    }
  });
}

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

app.use((err, req, res, next) => {
  console.error('[Unhandled Error]', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

let server;
start();

async function start() {
  const preferred = normalizePort(process.env.PORT || '3000');
  const port = await startOnAvailablePort(preferred);
  process.env.PORT = String(port);
}

const shutdown = (signal) => {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  if (server) {
    server.close(() => {
      console.log('Server closed.');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
  setTimeout(() => process.exit(1), 10000).unref();
};

['SIGINT', 'SIGTERM'].forEach((sig) => {
  process.on(sig, () => shutdown(sig));
});

function normalizePort(val) {
  const portNum = parseInt(val, 10);
  if (Number.isNaN(portNum)) return val;
  if (portNum >= 0) return portNum;
  return false;
}

module.exports = app;

function checkPortAvailable(port) {
  return new Promise((resolve) => {
    const tester = net.createServer()
      .once('error', (err) => {
        if (err && (err.code === 'EADDRINUSE' || err.code === 'EACCES')) return resolve(false);
        return resolve(false);
      })
      .once('listening', () => {
        tester.once('close', () => resolve(true)).close();
      })
      .listen(port, '0.0.0.0');
  });
}

async function chooseAvailablePort(startPort) {
  let p = Number(startPort) || 3000;
  for (let i = 0; i < 20; i++) {
    // eslint-disable-next-line no-await-in-loop
    const ok = await checkPortAvailable(p);
    if (ok) return p;
    p += 1;
  }
  return p; // fallback last tried
}

async function startOnAvailablePort(startPort) {
  let p = Number(startPort) || 3000;
  for (let i = 0; i < 20; i++) {
    try {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve, reject) => {
        const s = app
          .listen(p, '0.0.0.0', () => {
            server = s;
            console.log(`koi_12 server listening on http://localhost:${p}`);
            resolve();
          })
          .on('error', (err) => {
            if (err && err.code === 'EADDRINUSE') return reject(err);
            return reject(err);
          });
      });
      return p;
    } catch (e) {
      if (e && e.code === 'EADDRINUSE') {
        p += 1;
        continue;
      }
      throw e;
    }
  }
  // Last attempt
  server = app.listen(p, '0.0.0.0', () => {
    console.log(`koi_12 server listening on http://localhost:${p}`);
  });
  return p;
}
