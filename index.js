// index.js
const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');

try { require('dotenv').config(); } catch (_) {}

const app = express();

// -------- Seguridad base
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'none'"],
      "connect-src": ["'self'", "https://api.github.com"],
      "img-src": ["'self'", "https:", "data:"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "script-src": ["'self'"]
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS
const ACCESS_ORIGIN = process.env.CORS_ORIGIN || '*';
app.use(cors({
  origin: ACCESS_ORIGIN === '*' ? true : ACCESS_ORIGIN,
  methods: ['GET', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['x-api-key', 'content-type'],
  maxAge: 86400,
}));

// Parsers (límites bajos)
app.use(express.json({ limit: '1kb' }));
app.use(express.urlencoded({ extended: false, limit: '1kb' }));

// Rate limit
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX || 60),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too Many Requests' },
});
app.use(limiter);

// Logs
morgan.token('rid', () => Math.random().toString(36).slice(2, 8));
app.use(morgan(':rid :method :url :status :response-time ms'));

const PORT = process.env.PORT || 3000;
const GITHUB_API = 'https://api.github.com';

// Defaults globales
const DEFAULTS = {
  owner: process.env.GITHUB_OWNER || 'OkumaruSenpai',
  repo:  process.env.GITHUB_REPO  || 'STCS',
  path:  process.env.GITHUB_PATH  || 'myST',
  ref:   process.env.GITHUB_REF   || 'main',
};

// ---------- Helpers ----------
function safeSeg(s, fallback) {
  const v = (s ?? '').toString().trim();
  if (!v) return fallback;
  if (v.length > 200) return fallback;
  if (v.includes('..') || v.startsWith('/') || v.includes('\\')) return fallback;
  return v.replace(/[\r\n\t]/g, '');
}

function getClientIp(req) {
  const ip = (req.ip || '').split(',')[0].trim();
  return ip || 'desconocida';
}

// Webhook NO autorizado
async function notifyDiscord({ ip, path, ua }) {
  try {
    const url = process.env.DISCORD_WEBHOOK;
    if (!url) return;
    await axios.post(url, {
      content: `🚨 **Acceso no autorizado**\n**IP:** \`${ip}\`\n**Ruta:** \`${path}\`\n**UA:** \`${ua || 'n/a'}\``,
    }, { timeout: 5000 });
  } catch (err) {
    console.error('Error enviando webhook a Discord (unauth):', err.message);
  }
}

// Webhook AUTORIZADO
async function notifyDiscordAuth({ ip, path, ua, owner, repo, filePath, slot }) {
  try {
    const url = process.env.DISCORD_WEBHOOK;
    if (!url) return;
    await axios.post(url, {
      content: `✅ **Acceso autorizado**\n**Slot:** \`${slot || 'default'}\`\n**IP:** \`${ip}\`\n**Ruta:** \`${path}\`\n**Repo:** \`${owner}/${repo}\`\n**Path:** \`${filePath}\`\n**UA:** \`${ua || 'n/a'}\``,
    }, { timeout: 5000 });
  } catch (err) {
    console.error('Error enviando webhook a Discord (auth):', err.message);
  }
}

function renderUnauthorizedHTML({ ip }) {
  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>No autorizado</title>
<style>
  :root { --bg:#0f1221; --card:#1a1f36; --text:#e6e9f2; --muted:#aab2cf; --accent:#ff5370; }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100svh; display:grid; place-items:center;
    background: radial-gradient(90rem 90rem at 50% -20%, #222a4d 10%, var(--bg) 45%);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Arial;
    color: var(--text); }
  .card { width:min(560px,92vw); background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
    border:1px solid rgba(255,255,255,.08); border-radius:16px; padding:28px 24px; text-align:center;
    box-shadow: 0 8px 30px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05); backdrop-filter: blur(6px); }
  .face { font-size:76px; line-height:1; margin-bottom:8px; filter: drop-shadow(0 6px 12px rgba(0,0,0,.35)); }
  h1 { margin:8px 0 6px; font-size:28px; letter-spacing:.3px; }
  p  { margin:6px 0 0; color: var(--muted); }
  .ip { display:inline-block; margin-top:14px; padding:8px 12px; border-radius:10px;
    background:#121629; color:#cbd2e9; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    border:1px solid rgba(255,255,255,.08); }
  .hint { margin-top:16px; font-size:14px; color:#97a0bd; }
  .btn { margin-top:18px; display:inline-block; padding:10px 14px; border-radius:10px;
    background: var(--accent); color:white; text-decoration:none; font-weight:600;
    box-shadow: 0 8px 20px rgba(255,83,112,.35); }
</style>
</head>
<body>
  <main class="card" role="main" aria-labelledby="t">
    <div class="face" aria-hidden="true">😢</div>
    <h1 id="t">No autorizado</h1>
    <p>Esta ruta requiere una <strong>API Key válida</strong> en el header <code>x-api-key</code>.</p>
    <div class="ip">Tu IP: ${ip}</div>
    <p class="hint">Si crees que es un error, verifica la clave/CORS y vuelve a intentar.</p>
    <a class="btn" href="/health">Ir al healthcheck</a>
  </main>
</body></html>`;
}

// -------- Health & debug
app.get('/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.get('/debug-env', (_req, res) => {
  res.json({
    API_KEY_present: Boolean(process.env.API_KEY),
    DISCORD_WEBHOOK_present: Boolean(process.env.DISCORD_WEBHOOK),
    defaults: DEFAULTS
  });
});

/**
 * 🔀 Selector de config por "slot" (1,2,3,...) con fallback a DEFAULTS y query
 * Variables por slot en Railway (ejemplos):
 *  - SCRIPT_OWNER_1, SCRIPT_REPO_1, SCRIPT_PATH_1, SCRIPT_REF_1
 *  - SCRIPT_OWNER_2, SCRIPT_REPO_2, SCRIPT_PATH_2, SCRIPT_REF_2
 */
function pickConfig(slot, query) {
  const qOwner = safeSeg(query.owner, undefined);
  const qRepo  = safeSeg(query.repo, undefined);
  const qPath  = safeSeg(query.path, undefined);
  const qRef   = safeSeg(query.ref, undefined);

  const envOwner = slot ? process.env[`SCRIPT_OWNER_${slot}`] : undefined;
  const envRepo  = slot ? process.env[`SCRIPT_REPO_${slot}`]  : undefined;
  const envPath  = slot ? process.env[`SCRIPT_PATH_${slot}`]  : undefined;
  const envRef   = slot ? process.env[`SCRIPT_REF_${slot}`]   : undefined;

  return {
    owner: qOwner || envOwner || DEFAULTS.owner,
    repo:  qRepo  || envRepo  || DEFAULTS.repo,
    path:  qPath  || envPath  || DEFAULTS.path,
    ref:   qRef   || envRef   || DEFAULTS.ref,
  };
}

/**
 * 🧰 Handler común para /obtener-script y /obtener-scriptN
 */
async function obtenerScriptHandler(req, res, slotNumber /* puede ser undefined */) {
  try {
    const serverKey = process.env.API_KEY;
    const clientKey = req.headers['x-api-key'];

    if (!serverKey) {
      return res.status(500).json({ error: 'CONFIG: Falta API_KEY en variables de entorno' });
    }
    if (clientKey !== serverKey) {
      const ip = getClientIp(req);
      notifyDiscord({ ip, path: req.originalUrl || req.url, ua: req.headers['user-agent'] });
      res.set('Cache-Control', 'no-store');
      res.type('html');
      return res.status(401).send(renderUnauthorizedHTML({ ip }));
    }

    // Config por slot + overrides por query
    const cfg = pickConfig(slotNumber, req.query);
    const { owner, repo, path, ref } = cfg;

    // Aviso de acceso autorizado (con slot)
    const ip = getClientIp(req);
    notifyDiscordAuth({
      ip,
      path: req.originalUrl || req.url,
      ua: req.headers['user-agent'],
      owner, repo, filePath: path, slot: slotNumber
    });

    // GitHub headers
    const headers = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'railway-github-proxy/1.0',
    };
    if (process.env.GITHUB_TOKEN) {
      headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    }

    // Llamada a /contents
    const url = `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`;
    const gh = await axios.get(url, { headers, validateStatus: () => true });

    if (gh.status === 404) {
      return res.status(404).json({ error: 'No encontrado en GitHub', details: { owner, repo, path, ref } });
    }
    if (gh.status >= 400) {
      return res.status(502).json({ error: 'Error desde GitHub', status: gh.status });
    }

    if (Array.isArray(gh.data)) {
      const files = gh.data
        .filter(i => i && i.type === 'file')
        .map(i => ({ name: i.name, path: i.path, size: i.size, download_url: i.download_url, sha: i.sha }));
      return res.json({ owner, repo, ref, path, files });
    }

    if (gh.data && gh.data.type === 'file' && gh.data.download_url) {
      const rawHeaders = {
        Accept: 'application/vnd.github.v3.raw',
        'User-Agent': 'railway-github-proxy/1.0',
      };
      if (process.env.GITHUB_TOKEN) rawHeaders.Authorization = `token ${process.env.GITHUB_TOKEN}`;

      const raw = await axios.get(gh.data.download_url, { headers: rawHeaders, responseType: 'text', validateStatus: () => true });
      if (raw.status >= 200 && raw.status < 300) {
        res.type('text/plain; charset=utf-8');
        return res.send(raw.data);
      }
      return res.status(502).json({ error: 'No se pudo obtener RAW de GitHub' });
    }

    return res.status(500).json({ error: 'Respuesta inesperada desde GitHub' });
  } catch (err) {
    console.error('[ERROR]', err?.message || err);
    return res.status(500).json({ error: 'Error interno' });
  }
}

// ---------- Rutas dinámicas ----------
// 1) Ruta default: /obtener-script
app.get('/obtener-script', (req, res) => obtenerScriptHandler(req, res, undefined));

// 2) Rutas numeradas: /obtener-script1, /obtener-script2, ...
//    Usamos una regex para capturar el número: ^/obtener-script(\d+)$
app.get(/^\/obtener-script(\d+)$/, (req, res) => {
  const slotStr = req.params[0]; // primer grupo capturado
  const slot = slotStr ? parseInt(slotStr, 10) : undefined;
  return obtenerScriptHandler(req, res, slot);
});

// 404
app.use((_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

// Error handler
app.use((err, _req, res, _next) => {
  console.error('[UNCAUGHT]', err?.message || err);
  res.status(500).json({ error: 'Error interno' });
});

app.listen(PORT, () => {
  console.log(`✅ Servidor escuchando en :${PORT}`);
});
