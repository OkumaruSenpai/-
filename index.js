// index.js
const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');

// Opcional en local; en Railway no es necesario
try { require('dotenv').config(); } catch (_) {}

const app = express();

// --- Seguridad base
app.disable('x-powered-by');
app.set('trust proxy', 1); // importante detrás del proxy de Railway

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'none'"],
      "connect-src": ["'self'", "https://api.github.com"],
      "img-src": ["'self'", "https:" , "data:"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "script-src": ["'self'"]
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS (configurable por env; por defecto permite todos *solo* para pruebas)
const ACCESS_ORIGIN = process.env.CORS_ORIGIN || '*';
app.use(cors({
  origin: ACCESS_ORIGIN === '*' ? true : ACCESS_ORIGIN,
  methods: ['GET', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['x-api-key', 'content-type'],
  maxAge: 86400,
}));

// Parsers mínimos (esta API es GET-centric, límites bajos)
app.use(express.json({ limit: '1kb' }));
app.use(express.urlencoded({ extended: false, limit: '1kb' }));

// Rate limit global
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

// Defaults (tu caso real)
const DEFAULTS = {
  owner: process.env.GITHUB_OWNER || 'OkumaruSenpai',
  repo:  process.env.GITHUB_REPO  || 'STCS',
  path:  process.env.GITHUB_PATH  || 'myST', // archivo o directorio
  ref:   process.env.GITHUB_REF   || 'main',
};

// saneo simple de segmentos
function safeSeg(s, fallback) {
  const v = (s ?? '').toString().trim();
  if (!v) return fallback;
  if (v.length > 200) return fallback;
  if (v.includes('..') || v.startsWith('/') || v.includes('\\')) return fallback;
  return v.replace(/[\r\n\t]/g, '');
}

// Health
app.get('/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// Debug (temporal: bórralo cuando termines)
app.get('/debug-env', (_req, res) => {
  res.json({
    API_KEY_present: Boolean(process.env.API_KEY),
    owner: DEFAULTS.owner,
    repo: DEFAULTS.repo,
    path: DEFAULTS.path,
    ref: DEFAULTS.ref
  });
});

/**
 * GET /obtener-script
 * Header obligatorio: x-api-key: <API_KEY>
 * Query opcional: owner, repo, path, ref
 * - Si path es directorio -> devuelve listado mínimo (files[])
 * - Si path es archivo -> devuelve el contenido RAW (text/plain)
 */
app.get('/obtener-script', async (req, res) => {
  try {
    // 1) Auth
    const serverKey = process.env.API_KEY;
    const clientKey = req.headers['x-api-key'];
    if (!serverKey) {
      return res.status(500).json({ error: 'CONFIG: Falta API_KEY en variables de entorno' });
    }
    if (clientKey !== serverKey) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    // 2) Params saneados o defaults
    const owner = safeSeg(req.query.owner, DEFAULTS.owner);
    const repo  = safeSeg(req.query.repo,  DEFAULTS.repo);
    const path  = safeSeg(req.query.path,  DEFAULTS.path);
    const ref   = safeSeg(req.query.ref,   DEFAULTS.ref);

    // 3) Headers para GitHub
    const headers = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'railway-github-proxy/1.0',
    };
    if (process.env.GITHUB_TOKEN) {
      headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    }

    // 4) Llamada a /contents
    const url = `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`;
    const gh = await axios.get(url, { headers, validateStatus: () => true });

    if (gh.status === 404) {
      return res.status(404).json({ error: 'No encontrado en GitHub', details: { owner, repo, path, ref } });
    }
    if (gh.status >= 400) {
      return res.status(502).json({ error: 'Error desde GitHub', status: gh.status });
    }

    // 5) Directorio -> listado mínimo
    if (Array.isArray(gh.data)) {
      const files = gh.data
        .filter(i => i && i.type === 'file')
        .map(i => ({
          name: i.name,
          path: i.path,
          size: i.size,
          download_url: i.download_url,
          sha: i.sha,
        }));
      return res.json({ owner, repo, ref, path, files });
    }

    // 6) Archivo -> traer RAW y devolver texto
    if (gh.data && gh.data.type === 'file' && gh.data.download_url) {
      const rawHeaders = {
        Accept: 'application/vnd.github.v3.raw',
        'User-Agent': 'railway-github-proxy/1.0',
      };
      if (process.env.GITHUB_TOKEN) {
        rawHeaders.Authorization = `token ${process.env.GITHUB_TOKEN}`;
      }
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
