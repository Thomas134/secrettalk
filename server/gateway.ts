/**
 * 密语 SecretTalk · 单端口零知识网关（gateway.ts）
 * ===========================================================================
 * 【解决什么问题】
 * WebCrypto（crypto.subtle）只在安全上下文（https / localhost）可用；而云 PaaS 与
 * 手机访问又往往只能/只想暴露一个端口。本网关把「前端静态站点」与「5 台中继的
 * WebSocket」收进同一个端口：
 *
 *   https://<host>:<port>/            → 前端静态文件（dist/web，带严格安全头）
 *   https://<host>:<port>/relay/0     → 透明反代到 ws://127.0.0.1:3001
 *   https://<host>:<port>/relay/1..4  → 透明反代到 ws://127.0.0.1:3002~3005
 *   https://<host>:<port>/ca.crt      → 下载自签根 CA（手机安装后可消除警告，可选）
 *
 * 页面与 5 条 wss 连接「同源」，因此：
 *   1. 手机浏览器对自签证书点击一次「继续访问」后，同源 wss 不会被浏览器按
 *      混合内容 / 证书错误拦截（跨端口直连则无法豁免，这正是多端口方案的死穴）；
 *   2. 未来部署到任何 PaaS（自动换正规证书），前端无需改动。
 *
 * 【零知识边界】网关与中继同级：它只做 TLS 终结 + 字节管道。
 *   - 不解析、不缓存、不修改任何 WebSocket 帧；
 *   - 不 import 任何密码学模块（node:crypto 也没有）；
 *   - TLS 在此终结，因此它和 5 台中继一样「看得见密文碎片、看不见明文与密钥」。
 *   5 台中继仍是 5 个独立进程，rooms 互不共享，「单机多进程孤岛」语义完全保留。
 *
 * 【环境变量】
 *   GATEWAY_PORT      监听端口（默认 5173）
 *   GATEWAY_HOST      监听地址（默认 0.0.0.0）
 *   GATEWAY_TLS       '1' 时启用 TLS（https/wss），证书见下方路径
 *   TLS_KEY_PATH      服务器私钥（默认 certs/server.key，相对项目根）
 *   TLS_CERT_PATH     服务器证书（默认 certs/server.pem）
 *   GATEWAY_UPSTREAM_HOST  上游中继地址（默认 127.0.0.1）
 */
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import * as fs from 'node:fs';
import { extname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocket, WebSocketServer, type RawData } from 'ws';
import { RELAY_PORTS } from '../shared/protocol.js';
import { detectBlockedWebView } from '../shared/ua.js';

/** 项目根目录（dist/server/gateway.js 往上两级） */
const PROJECT_ROOT = fileURLToPath(new URL('../../', import.meta.url));

/** 安全响应头：密钥存放在 JS 内存中，XSS 会直接导致全盘失失守，这层不能省 */
const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "connect-src 'self' ws: wss:; img-src 'self' data: blob:; media-src 'self' data: blob:; " +
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  // 语音消息需要麦克风；相机/定位仍然禁用
  'Permissions-Policy': 'camera=(), microphone=(self), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Strict-Transport-Security': 'max-age=31536000', // 仅在 https 响应中生效
};

const MIME: Record<string, string> = {
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
  '.pem': 'application/x-pem-file',
  '.crt': 'application/x-x509-ca-cert',
};

export interface GatewayOptions {
  port?: number;
  host?: string;
  /** 是否启用 TLS（默认由 GATEWAY_TLS=1 决定） */
  secure?: boolean;
  tlsKeyPath?: string;
  tlsCertPath?: string;
  /** 自签 CA 证书路径，存在时提供 /ca.crt 下载（默认 certs/ca.pem） */
  caPath?: string;
  /** 静态文件根目录（默认 dist/web） */
  staticRoot?: string;
  /** 上游中继端口列表（默认 RELAY_PORTS = 3001~3005） */
  upstreamPorts?: number[];
  upstreamHost?: string;
  silent?: boolean;
  /**
   * 是否拒绝微信 / 企业微信内置浏览器（默认 true）。
   * 环境变量 BLOCK_WECHAT=0 可关闭，主要用于本地调试。
   */
  blockWeChat?: boolean;
}

export interface GatewayHandle {
  port: number;
  host: string;
  secure: boolean;
  close(): Promise<void>;
}

export async function startGateway(opts: GatewayOptions = {}): Promise<GatewayHandle> {
  const port = opts.port ?? Number(process.env.GATEWAY_PORT || 5173);
  const host = opts.host ?? (process.env.GATEWAY_HOST || '0.0.0.0');
  const staticRoot = resolvePath(opts.staticRoot ?? process.env.GATEWAY_STATIC_ROOT ?? join(PROJECT_ROOT, 'dist/web'));
  const upstreamPorts = opts.upstreamPorts ?? RELAY_PORTS;
  const upstreamHost = opts.upstreamHost ?? (process.env.GATEWAY_UPSTREAM_HOST || '127.0.0.1');
  const caPath = resolvePath(opts.caPath ?? join(PROJECT_ROOT, 'certs/ca.pem'));
  const blockWeChat = opts.blockWeChat ?? process.env.BLOCK_WECHAT !== '0';
  const log = opts.silent || process.env.GATEWAY_SILENT === '1'
    ? () => {}
    : (line: string) => console.log(`[secrettalk-gateway] ${line}`);

  const secure = opts.secure ?? process.env.GATEWAY_TLS === '1';

  /* ---------------- HTTP(S) 请求处理：静态文件 + CA 下载 ---------------- */
  const serveFile = (res: import('node:http').ServerResponse, file: string) => {
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404, SECURITY_HEADERS); res.end('Not Found'); return; }
      res.writeHead(200, {
        'Content-Type': MIME[extname(file).toLowerCase()] || 'application/octet-stream',
        'Cache-Control': 'no-cache',
        ...SECURITY_HEADERS,
      });
      res.end(data);
    });
  };

  /**
   * 微信 / 企业微信内置浏览器的拦截页。
   * 不引入任何脚本（CSP 是 script-src 'self'），避免被当成注入点。
   */
  const blockedPage = (name: string): string => `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>请在浏览器中打开 · 密语</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#f4f7fb;color:#16233a;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
  .card{max-width:420px;margin:24px;background:#fff;border:1px solid #d7e1f0;border-radius:18px;padding:28px 24px;
        line-height:1.7;box-shadow:0 6px 24px rgba(35,50,77,.08)}
  h1{font-size:20px;margin:0 0 12px;color:#1c3fa8}
  p{font-size:14px;margin:8px 0}
  .dim{color:#6b7a92;font-size:12.5px}
  .tip{margin-top:16px;padding:12px;background:#eef3ff;border-radius:12px;font-size:13px;color:#2b3f66}
</style></head>
<body><div class="card">
  <h1>请在浏览器中打开</h1>
  <p>检测到你正在 <b>${name}</b> 的内置浏览器里访问本页面。</p>
  <p>为了保证加密能力（WebCrypto）与会话不被系统中断，密语<b>不允许在微信内运行</b>。</p>
  <div class="tip">请点右上角「…」→「在浏览器打开」（Safari / Chrome / Edge），或把链接复制到浏览器粘贴打开。</div>
  <p class="dim">本页只是入口限制；真正的消息加密始终发生在浏览器内，中继与网关都看不到明文。</p>
</div></body></html>`;

  const requestHandler = (req: IncomingMessage, res: import('node:http').ServerResponse) => {
    let urlPath: string;
    try {
      urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    } catch {
      res.writeHead(400); res.end('Bad Request'); return;
    }

    // 【入口限制】微信 / 企业微信内置 WebView 一律拒绝：页面里切后台会被冻结，
    // 而本项目是「断开即销毁」，在微信里体验会变成频繁掉线，所以直接引导去浏览器。
    if (blockWeChat) {
      const ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '';
      const hit = detectBlockedWebView(ua);
      if (hit.blocked) {
        res.writeHead(403, { ...SECURITY_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
        res.end(blockedPage(hit.name));
        return;
      }
    }

    // 可选：下载自签根 CA（想消除手机警告时安装；不装也能点「继续访问」使用）
    if (urlPath === '/ca.crt' || urlPath === '/ca.pem') {
      if (fs.existsSync(caPath)) {
        res.writeHead(200, {
          'Content-Type': 'application/x-x509-ca-cert',
          'Content-Disposition': 'attachment; filename="SecretTalkCA.crt"',
          ...SECURITY_HEADERS,
        });
        res.end(fs.readFileSync(caPath));
        return;
      }
      res.writeHead(404, SECURITY_HEADERS); res.end('Not Found'); return;
    }

    // 静态文件：统一收进 staticRoot，防目录穿越；未知路径回退 index.html（SPA）
    let file = resolvePath(staticRoot, '.' + (urlPath === '/' ? '/index.html' : urlPath));
    if (!file.startsWith(staticRoot + /* sep */ '\\') && !file.startsWith(staticRoot + '/')) {
      res.writeHead(403, SECURITY_HEADERS); res.end('Forbidden'); return;
    }
    if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      file = join(staticRoot, 'index.html');
    }
    serveFile(res, file);
  };

  /* ---------------- WebSocket 升级：/relay/{i} → 上游中继 ---------------- */
  const wss = new WebSocketServer({ noServer: true });

  /** 把一条客户端连接与上游中继做成透明字节管道 */
  const pipeToUpstream = (client: WebSocket, upstreamPort: number, idx: number) => {
    const upstream = new WebSocket(`ws://${upstreamHost}:${upstreamPort}`);
    // 上游尚未 open 时缓存客户端帧（握手只需几十毫秒，缓存量可控）。
    // 【必须连帧类型一起缓存】ws 的 send(Buffer) 默认发二进制帧：中继的 JSON 帧
    // 都是文本帧，若在这里退化成二进制，浏览器会以 Blob 形式收到
    // （默认为 binaryType='blob'），JSON.parse 直接失败 —— 表现为「所有帧都无法解析、
    // 握手永远不完成、pong 收不到、20 秒后心跳超时自毁」。
    const pending: Array<{ data: RawData; isBinary: boolean }> = [];
    let upstreamOpen = false;

    upstream.on('open', () => {
      upstreamOpen = true;
      for (const p of pending) upstream.send(p.data, { binary: p.isBinary });
      pending.length = 0;
    });
    client.on('message', (data: RawData, isBinary: boolean) => {
      if (upstream.readyState === WebSocket.OPEN) upstream.send(data, { binary: isBinary });
      else if (!upstreamOpen) pending.push({ data, isBinary });
    });
    upstream.on('message', (data: RawData, isBinary: boolean) => {
      // 保留上游的帧类型：文本帧必须原样以文本帧下发，否则浏览器拿到的是 Blob
      if (client.readyState === WebSocket.OPEN) client.send(data, { binary: isBinary });
    });

    // 断开/异常双向传染：任一侧断，另一侧必须立刻断（对齐「断开即销毁」语义）
    client.on('close', () => { try { upstream.close(); } catch { /* 已断 */ } });
    upstream.on('close', () => { try { client.close(); } catch { /* 已断 */ } });
    client.on('error', () => { try { client.terminate(); } catch { /* 忽略 */ } try { upstream.close(); } catch { /* 忽略 */ } });
    upstream.on('error', () => { try { upstream.terminate(); } catch { /* 忽略 */ } try { client.close(); } catch { /* 忽略 */ } });

    log(`/relay/${idx} 管道已建立 → ws://${upstreamHost}:${upstreamPort}`);
  };

  const upgradeHandler = (req: IncomingMessage, socket: import('node:stream').Duplex, head: Buffer) => {
    // 微信内置浏览器连 WebSocket 也不许建连（页面被 403 拦截后，这里再兜一层）
    if (blockWeChat) {
      const ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '';
      if (detectBlockedWebView(ua).blocked) {
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        socket.destroy();
        return;
      }
    }
    const match = /^\/relay\/(\d+)\/?$/.exec((req.url || '').split('?')[0]);
    const idx = match ? Number(match[1]) : -1;
    if (idx < 0 || idx >= upstreamPorts.length) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (client) => pipeToUpstream(client, upstreamPorts[idx], idx));
  };

  /* ---------------- 创建服务器（http / https 双模式） ---------------- */
  let httpServer: HttpServer | HttpsServer;
  if (secure) {
    const keyPath = resolvePath(opts.tlsKeyPath ?? process.env.TLS_KEY_PATH ?? join(PROJECT_ROOT, 'certs/server.key'));
    const certPath = resolvePath(opts.tlsCertPath ?? process.env.TLS_CERT_PATH ?? join(PROJECT_ROOT, 'certs/server.pem'));
    httpServer = createHttpsServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, requestHandler);
  } else {
    httpServer = createHttpServer(requestHandler);
  }
  httpServer.on('upgrade', upgradeHandler);

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(port, host, () => resolve());
  });

  // port: 0 时由 OS 分配，必须回读实际端口
  const address = httpServer.address();
  const actualPort = typeof address === 'object' && address !== null ? address.port : port;

  const scheme = secure ? 'https' : 'http';
  log(`网关已启动 ${scheme}://${host}:${port}（上游 ${upstreamHost}:${upstreamPorts[0]}~${upstreamPorts[upstreamPorts.length - 1]}，路径 /relay/0~${upstreamPorts.length - 1}）`);

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    for (const client of wss.clients) client.terminate();
    await new Promise<void>((r) => wss.close(() => r()));
    await new Promise<void>((r) => httpServer.close(() => r()));
    log('已关闭');
  };

  return { port: actualPort, host, secure, close };
}

/* ========================================================================== *
 * 直接运行时（PM2 / node dist/server/gateway.js）：从 env 读取配置
 * 与 server.ts 相同的 PM2 坑：fork 模式下 argv[1] 不是本文件路径，
 * 因此 ecosystem 显式注入 SECRETTALK_AUTOSTART=1 作为兜底。
 * ========================================================================== */
const isDirectRun = Boolean(process.argv[1]) && pathToFileURL(process.argv[1]!).href === import.meta.url;
if (isDirectRun || process.env.SECRETTALK_AUTOSTART === '1') {
  const handle = await startGateway();
  const shutdown = async (): Promise<void> => {
    await handle.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
