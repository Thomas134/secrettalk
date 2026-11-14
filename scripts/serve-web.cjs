/**
 * SecretTalk · 生产静态站点服务器（零依赖，供 PM2 托管）
 * ---------------------------------------------------------------------------
 * 为什么不用 `vite preview`：部署产物应当是纯静态文件 + 极简 HTTP 服务，
 * 不依赖构建工具运行时，进程更小、攻击面更低、也便于 PM2 统一守护。
 *
 * 启动：pm2 start scripts/serve-web.cjs --name secrettalk-web
 * 环境变量：WEB_PORT（默认 5173）、WEB_HOST（默认 0.0.0.0）
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '../dist/web');
const PORT = Number(process.env.WEB_PORT || 5173);
const HOST = process.env.WEB_HOST || '0.0.0.0';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.map': 'application/json',
};

/**
 * 安全响应头：密钥存放在 JS 内存中，XSS 会直接导致全盘失守，
 * 因此这里默认下发严格 CSP。connect-src 需放行 5 台中继的 ws:// 连接；
 * 生产环境应把 `ws: wss:` 收窄为具体的 wss:// 域名白名单。
 */
const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "connect-src 'self' ws: wss: http: https:; img-src 'self' data: blob:; media-src 'self' data: blob:; " +
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(self), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};

const server = http.createServer((req, res) => {
  let urlPath;
  try {
    urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
  } catch {
    res.writeHead(400); res.end('Bad Request'); return;
  }
  // 统一解析到 ROOT 内，并做目录穿越防护
  let file = path.resolve(ROOT, '.' + (urlPath === '/' ? '/index.html' : urlPath));
  if (!file.startsWith(ROOT + path.sep) && file !== path.join(ROOT, 'index.html')) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  // SPA fallback：未知路径一律回 index.html
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    file = path.join(ROOT, 'index.html');
  }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not Found'); return; }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      ...SECURITY_HEADERS,
    });
    res.end(data);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[secrettalk-web] http://${HOST}:${PORT}  ->  ${ROOT}`);
});

const shutdown = () => server.close(() => process.exit(0));
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
