// index.js
const express = require('express');
const axios = require('axios');
try { require('dotenv').config(); } catch (_) {}

const app = express();

// Railway define PORT automáticamente
const PORT = process.env.PORT || 3000;

// Ruta para probar que el servidor funciona
app.get('/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// Ruta para obtener scripts desde GitHub
app.get('/obtener-script', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const SERVER_API_KEY = process.env.API_KEY; // definida en Railway

  if (!SERVER_API_KEY || apiKey !== SERVER_API_KEY) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  const owner = process.env.GITHUB_OWNER || 'OkumaruSenpai';
  const repo  = process.env.GITHUB_REPO  || 'Sytem2.0';
  const path  = process.env.GITHUB_PATH  || 'LUAU';
  const ref   = process.env.GITHUB_REF   || 'main';

  try {
    const ghHeaders = {
      Accept: 'application/vnd.github.v3.raw',
      'User-Agent': 'railway-proxy/1.0'
    };

    if (process.env.GITHUB_TOKEN) {
      ghHeaders.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    }

    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`;
    const gh = await axios.get(url, { headers: ghHeaders });

    res.send(gh.data);
  } catch (err) {
    console.error(err?.response?.status, err?.response?.data || err.message);
    res.status(500).json({ error: 'Error al obtener el script' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor escuchando en :${PORT}`);
});
