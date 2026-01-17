import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

function getArgValue(flag) {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] || null;
}

const portValue = getArgValue('--port') || process.env.PLAYWRIGHT_TEST_PORT || process.env.PORT;
const port = Number.parseInt(portValue || '4173', 10);

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

function send(res, status, message) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end(message);
}

const server = http.createServer((req, res) => {
  const method = req.method || 'GET';
  if (method !== 'GET' && method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    return send(res, 405, 'Method Not Allowed');
  }

  let pathname;
  try {
    const base = `http://${req.headers.host || 'localhost'}`;
    pathname = decodeURIComponent(new URL(req.url || '/', base).pathname);
  } catch {
    return send(res, 400, 'Bad Request');
  }

  const filePath = path.join(rootDir, pathname);
  const normalized = path.normalize(filePath);
  if (!normalized.startsWith(rootDir + path.sep)) {
    return send(res, 403, 'Forbidden');
  }

  fs.stat(normalized, (err, stat) => {
    if (err || !stat.isFile()) {
      return send(res, 404, 'Not Found');
    }

    const ext = path.extname(normalized).toLowerCase();
    const contentType = mimeTypes[ext] || 'application/octet-stream';
    res.statusCode = 200;
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-cache');

    if (method === 'HEAD') {
      res.end();
      return;
    }

    const stream = fs.createReadStream(normalized);
    stream.on('error', () => {
      if (!res.headersSent) {
        send(res, 500, 'Internal Server Error');
      } else {
        res.destroy();
      }
    });
    stream.pipe(res);
  });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Browser test server listening on http://127.0.0.1:${port}`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
