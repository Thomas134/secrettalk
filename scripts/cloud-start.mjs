/**
 * 密语 SecretTalk · 云平台单容器启动器（免费托管用）
 * ===========================================================================
 * 免费 PaaS（Render / Koyeb / Hugging Face Spaces 等）通常只给「一个 web 服务 +
 * 一个端口」，而本项目需要 5 台中继 + 1 个网关。本脚本在同一台机器上：
 *
 *   1. 用 5 个独立子进程启动 5 台中继（仍是独立进程、独立内存，孤岛语义保留，
 *      但物理上同机 —— 仅演示级，真安全需要 5 台不同机器/信任域）；
 *   2. 等 5 台中继都健康后，在 $PORT 上启动网关（http 模式，TLS 交给平台）；
 *   3. 收到 SIGTERM/SIGINT 时优雅退出，子进程一并回收。
 *
 * 前端无需改动：host 留空时走同源 /relay/0~4，平台自动提供 https/wss。
 * 本地试运行：
 *   $env:PORT='8099'; $env:RELAY_BASE_PORT='3101'; node scripts/cloud-start.mjs
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = join(ROOT, 'dist/server/server.js');
const GATEWAY = join(ROOT, 'dist/server/gateway.js');

if (!existsSync(ENTRY) || !existsSync(GATEWAY)) {
  console.error('[cloud] 缺少 dist/server 构建产物，请先执行：npm run build && npm run build:server');
  process.exit(1);
}

const publicPort = Number(process.env.PORT || 8080);
// 中继只监听回环地址；若公开端口恰好占用 3001~3005 则顺延到 3101 起，避免端口冲突
let relayBase = Number(process.env.RELAY_BASE_PORT || 3001);
if (publicPort >= relayBase && publicPort < relayBase + 5) relayBase = 3101;
const relayPorts = [0, 1, 2, 3, 4].map((i) => relayBase + i);

const children = [];
let shuttingDown = false;

function launchRelay(index) {
  const child = spawn(process.execPath, [ENTRY], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(relayPorts[index]),
      HOST: '127.0.0.1',
      RELAY_INDEX: String(index),
      SECRETTALK_AUTOSTART: '1',
      ROOM_TTL_MS: process.env.ROOM_TTL_MS || String(5 * 60 * 1000),
    },
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  child.on('exit', (code, signal) => {
    if (shuttingDown) return;
    console.error(`[cloud] 中继 ${relayPorts[index]} 意外退出（code=${code} signal=${signal}），整组重启交给平台`);
    // 让容器整体退出，交给 PaaS 重启，避免出现「一半中继在线」的僵尸状态
    void shutdown(1);
  });
  children.push(child);
}

async function waitRelay(port, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return;
    } catch { /* 还没起来 */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`中继 ${port} 在 ${timeoutMs}ms 内未就绪`);
}

let gateway = null;

async function shutdown(exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('[cloud] 正在关闭中继与网关…');
  try { await gateway?.close(); } catch { /* 忽略 */ }
  for (const c of children) {
    try { c.kill('SIGTERM'); } catch { /* 已退出 */ }
  }
  setTimeout(() => process.exit(exitCode), 800);
}

process.on('SIGINT', () => { void shutdown(0); });
process.on('SIGTERM', () => { void shutdown(0); });

for (let i = 0; i < 5; i++) launchRelay(i);
await Promise.all(relayPorts.map((p) => waitRelay(p)));
console.log(`[cloud] 5 台中继已就绪：${relayPorts[0]}~${relayPorts[4]}（127.0.0.1）`);

const { startGateway } = await import(pathToFileURL(GATEWAY).href);
gateway = await startGateway({
  port: publicPort,
  host: '0.0.0.0',
  secure: false, // 平台负责 TLS，容器内跑明文 http 即可
  upstreamPorts: relayPorts,
  upstreamHost: '127.0.0.1',
});
console.log(`[cloud] 网关已监听 :${publicPort}，用平台分配的 https 域名访问即可`);
