/**
 * SecretTalk · 本地一体化启动器（会话内常驻版）
 * ---------------------------------------------------------------------------
 * 用途：在「不方便保留 PM2 daemon」的环境（例如受限沙箱 / 单次会话）中，
 * 依然按「5 个独立 Node.js 进程」的拓扑把整套系统跑起来。
 *
 * 与 PM2 方案的区别：
 *   - 5 台中继仍是 5 个彼此独立的 OS 进程（spawn 出来，各带自己的 PORT/RELAY_INDEX），
 *     rooms 依旧互不共享，孤岛语义不变；
 *   - 只是由本启动器统一持有进程树，而非 PM2 daemon 托管。
 *
 * 需要长期常驻、开机自启、日志分割时，请改用：npm run start:all（PM2）。
 *
 * 启动：node scripts/start-local.cjs
 */
const { spawn } = require('node:child_process');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const PORTS = [3001, 3002, 3003, 3004, 3005];
const children = [];
let shuttingDown = false;

function launch(name, script, env) {
  const child = spawn(process.execPath, [script], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  child.stdout.on('data', (d) => process.stdout.write(`[${name}] ${d}`));
  child.stderr.on('data', (d) => process.stderr.write(`[${name}] ${d}`));
  child.on('exit', (code, signal) => {
    if (!shuttingDown) console.log(`[launcher] ${name} 意外退出 code=${code} signal=${signal}`);
  });
  children.push({ name, child });
}

// 5 台孤岛中继：每台独占一个 PORT，且只知道自己的碎片下标
PORTS.forEach((port, i) => {
  launch(`relay-${port}`, path.join(ROOT, 'dist/server/server.js'), {
    PORT: String(port),
    HOST: '0.0.0.0',
    RELAY_INDEX: String(i),
    ROOM_TTL_MS: '300000',
  });
});

// 前端站点 + WebSocket 网关（独立进程，TLS 模式，手机点一次「继续访问」即可用）
launch('gateway', path.join(ROOT, 'dist/server/gateway.js'), {
  GATEWAY_PORT: '5173',
  GATEWAY_HOST: '0.0.0.0',
  GATEWAY_TLS: '1',
  SECRETTALK_AUTOSTART: '1',
});

console.log('[launcher] 5 台中继 + TLS 网关已拉起，前端 https://0.0.0.0:5173');

function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('\n[launcher] 正在停止全部子进程…');
  for (const { child } of children) {
    try { child.kill('SIGTERM'); } catch { /* 已退出 */ }
  }
  setTimeout(() => process.exit(0), 800);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
