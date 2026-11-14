#!/usr/bin/env node
/**
 * 密语 SecretTalk · 一键公网分享（方案 A）
 * ===========================================================================
 * 一条命令完成：按需构建 → 启动本地 5 中继 + 网关 → 启动 Cloudflare 快速隧道
 * → 打印（并复制）公网 https 链接。Ctrl+C 全部关闭，链接立即失效。
 *
 *   npm run share                # 默认 8080 端口
 *   npm run share -- --port 9000 # 指定端口
 *   npm run share -- --rebuild   # 强制重新构建
 *   npm run share -- --no-build  # 跳过构建检查
 *
 * 说明：
 *   - 首次运行会自动下载 cloudflared（约 30MB，存到 tools/ 目录，不污染系统）；
 *   - 隧道是「快速隧道」，无需 Cloudflare 账号，但每次重启链接会变；
 *   - 电脑必须保持开机且不休眠，否则链接失效。
 */
import { spawn, spawnSync } from 'node:child_process';
import { createWriteStream, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const IS_WIN = process.platform === 'win32';

const argv = process.argv.slice(2);
const skipBuild = argv.includes('--no-build');
const forceBuild = argv.includes('--rebuild');
const portIdx = argv.indexOf('--port');
const requestedPort = portIdx >= 0 ? Number(argv[portIdx + 1]) : null;
const mirrorIdx = argv.indexOf('--mirror');
const mirrorPrefix = mirrorIdx >= 0 ? argv[mirrorIdx + 1] : (process.env.CLOUDFLARED_MIRROR || null);
// 国内网络常见：UDP/7844 被运营商拦、IPv6 不通、DNS 被污染。
// --protocol http2 强制走 TCP，--edge-ip 4 强制 IPv4，往往能救回来。
const protocolIdx = argv.indexOf('--protocol');
const tunnelProtocol = protocolIdx >= 0 ? argv[protocolIdx + 1] : (process.env.CLOUDFLARED_PROTOCOL || 'auto');
const edgeIdx = argv.indexOf('--edge-ip');
const edgeIp = edgeIdx >= 0 ? argv[edgeIdx + 1] : (process.env.CLOUDFLARED_EDGE_IP || 'auto');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (m) => console.log(`\n[share] ${m}`);
const info = (m) => console.log(`        ${m}`);

let app = null;
let tunnel = null;
let closing = false;

/* ------------------------------------------------------------------ 端口 */
/**
 * 判断端口是否可用。
 * 先尝试连接：Windows 的 SO_REUSEADDR 会让「127.0.0.1 与 0.0.0.0 同端口」的
 * 二次 bind 假成功，只看 listen 会误判（本机 8080 已被 PM2/start:cloud 占用时，
 * 脚本会以为 8080 空闲，结果网关起不来、还把别人已有的页面当成自己的）。
 */
function portFree(port) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (free) => { if (!settled) { settled = true; resolve(free); } };
    const probe = connect({ port, host: '127.0.0.1' });
    probe.setTimeout(400, () => { probe.destroy(); bindCheck(); });
    probe.once('connect', () => { probe.destroy(); done(false); });
    probe.once('error', () => { probe.destroy(); bindCheck(); });

    function bindCheck() {
      const srv = createServer();
      srv.once('error', () => done(false));
      srv.once('listening', () => srv.close(() => done(true)));
      srv.listen(port, '127.0.0.1');
    }
  });
}

async function pickPublicPort() {
  if (requestedPort) {
    if (await portFree(requestedPort)) return requestedPort;
    log(`端口 ${requestedPort} 被占用，自动换一个`);
  }
  for (let p = 8080; p < 8120; p++) if (await portFree(p)) return p;
  throw new Error('8080~8119 都被占用了，请用 --port 指定端口');
}

/** 中继默认 3001~3005；若本机 PM2 正在跑，就自动顺延到 3101~3105 */
async function pickRelayBase() {
  for (const base of [3001, 3101, 3201, 3301, 3401]) {
    let ok = true;
    for (let i = 0; i < 5; i++) if (!(await portFree(base + i))) { ok = false; break; }
    if (ok) return base;
  }
  throw new Error('找不到连续 5 个空闲端口给中继，请先停掉占用端口的程序');
}

/* ------------------------------------------------------------------ 构建 */
function newestMtime(dir) {
  let newest = 0;
  try {
    for (const rel of readdirSync(dir, { recursive: true })) {
      const p = join(dir, String(rel));
      try { const st = statSync(p); if (st.isFile()) newest = Math.max(newest, st.mtimeMs); } catch { /* 跳过 */ }
    }
  } catch { /* 目录不存在 */ }
  return newest;
}

function needBuild() {
  if (forceBuild) return true;
  if (skipBuild) return false;
  const web = join(ROOT, 'dist/web/index.html');
  const srv = join(ROOT, 'dist/server/server.js');
  if (!existsSync(web) || !existsSync(srv)) return true;
  const built = Math.min(statSync(web).mtimeMs, statSync(srv).mtimeMs);
  const src = Math.max(
    newestMtime(join(ROOT, 'src')),
    newestMtime(join(ROOT, 'shared')),
    newestMtime(join(ROOT, 'server')),
    statSync(join(ROOT, 'index.html')).mtimeMs,
    statSync(join(ROOT, 'package.json')).mtimeMs,
  );
  return src > built;
}

function runNpm(task) {
  const r = spawnSync('npm', ['run', task], { cwd: ROOT, stdio: 'inherit', shell: IS_WIN });
  if (r.status !== 0) {
    console.error(`\n[share] 构建失败：npm run ${task}`);
    process.exit(1);
  }
}

/* -------------------------------------------------------------- cloudflared */
function isValidBinary(path) {
  try {
    const r = spawnSync(path, ['--version'], { encoding: 'utf8', timeout: 10_000 });
    return r.status === 0;
  } catch {
    return false;
  }
}

function findCloudflared() {
  const candidates = [
    join(ROOT, 'tools', IS_WIN ? 'cloudflared.exe' : 'cloudflared'),
    // 官方 MSI / winget 安装后的常见位置（这些不一定在当前终端的 PATH 里）
    IS_WIN && join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'cloudflared', 'cloudflared.exe'),
    IS_WIN && join(process.env.ProgramFiles || 'C:\\Program Files', 'cloudflared', 'cloudflared.exe'),
    IS_WIN && join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Links', 'cloudflared.exe'),
  ].filter(Boolean);

  for (const p of candidates) {
    if (!existsSync(p)) continue;
    if (isValidBinary(p)) return p;
    // 上次下载被中断留下的半截文件，删掉重下，避免拿去执行报错
    info(`发现无法执行的 cloudflared（${p}），已忽略`);
    if (p.startsWith(ROOT)) { try { rmSync(p, { force: true }); } catch { /* 忽略 */ } }
  }

  const probe = spawnSync(IS_WIN ? 'where' : 'which', ['cloudflared'], { encoding: 'utf8' });
  if (probe.status === 0) {
    const first = String(probe.stdout).split(/\r?\n/).map((s) => s.trim()).filter(Boolean)[0];
    if (first && isValidBinary(first)) return first;
  }
  return null;
}

async function downloadCloudflared() {
  if (!IS_WIN) {
    console.error('[share] 请先安装 cloudflared：brew install cloudflared / apt install cloudflared');
    process.exit(1);
  }
  const dest = join(ROOT, 'tools', 'cloudflared.exe');
  mkdirSync(dirname(dest), { recursive: true });
  const official = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe';
  const url = process.env.CLOUDFLARED_URL
    || (mirrorPrefix ? mirrorPrefix.replace(/\/?$/, '/') + official : official);
  log(`首次运行：正在下载 cloudflared（约 53MB）${mirrorPrefix ? '（使用镜像源）' : ''}…`);
  info(url);
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok || !res.body) throw new Error(`下载失败 HTTP ${res.status}`);
  const total = Number(res.headers.get('content-length') || 0);
  let got = 0;
  let nextMark = 5 * 1024 * 1024;
  let slowHinted = false;
  const startedAt = Date.now();
  const body = Readable.fromWeb(res.body);
  body.on('data', (chunk) => {
    got += chunk.length;
    if (got >= nextMark) {
      nextMark += 5 * 1024 * 1024;
      const sec = Math.max(1, (Date.now() - startedAt) / 1000);
      info(`已下载 ${(got / 1024 / 1024).toFixed(0)}MB / ${(total / 1024 / 1024).toFixed(0)}MB（${(got / sec / 1024).toFixed(0)} KB/s）`);
    }
    // 8 秒后速度仍低于 120KB/s：给一次可选加速提示，不擅自改用第三方镜像
    if (!slowHinted && Date.now() - startedAt > 8000 && got / ((Date.now() - startedAt) / 1000) < 120 * 1024) {
      slowHinted = true;
      console.warn('\n[share] 官方源较慢，可任选一种加速方式后重跑：');
      console.warn('        1) winget install --id Cloudflare.cloudflared -e');
      console.warn('        2) npm run share -- --mirror https://ghfast.top/   （第三方镜像，请自行评估风险）');
      console.warn('        3) 挂代理后重试\n');
    }
  });
  try {
    await pipeline(body, createWriteStream(dest));
  } catch (e) {
    try { rmSync(dest, { force: true }); } catch { /* 忽略 */ }
    throw e;
  }
  if (!isValidBinary(dest)) {
    try { rmSync(dest, { force: true }); } catch { /* 忽略 */ }
    throw new Error('下载的 cloudflared 无法执行，可能被截断；请重试或改用 winget 安装');
  }
  return dest;
}

/* ------------------------------------------------------------------ 进程 */
function killTree(pid) {
  if (!pid) return;
  if (IS_WIN) {
    spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    try { process.kill(pid, 'SIGTERM'); } catch { /* 已退出 */ }
  }
}

async function shutdown(code = 0) {
  if (closing) return;
  closing = true;
  console.log('\n[share] 正在关闭隧道与本地服务…');
  killTree(tunnel?.pid);
  killTree(app?.pid);
  await sleep(400);
  process.exit(code);
}

async function waitLocal(port, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return;
    } catch { /* 还没起来 */ }
    await sleep(250);
  }
  throw new Error(`本地服务 ${timeoutMs}ms 内没有就绪`);
}

async function startTunnel(cf, port) {
  const args = ['tunnel', '--url', `http://127.0.0.1:${port}`, '--no-autoupdate'];
  if (tunnelProtocol && tunnelProtocol !== 'auto') args.push('--protocol', tunnelProtocol);
  if (edgeIp && edgeIp !== 'auto') args.push('--edge-ip-version', edgeIp);
  if (tunnelProtocol !== 'auto' || edgeIp !== 'auto') {
    info(`隧道参数：protocol=${tunnelProtocol} edge-ip=${edgeIp}`);
  }
  const child = spawn(cf, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const seen = [];
  const errors = [];
  let url = null;
  let registered = false;
  const onData = (d) => {
    const text = d.toString();
    seen.push(text);
    if (seen.length > 40) seen.shift();
    for (const line of text.split(/\r?\n/)) {
      if (line.includes('"level":"error"')) {
        errors.push(line);
        if (errors.length > 8) errors.shift();
      }
      if (!registered && line.includes('Registered tunnel connection')) {
        registered = true;
        try {
          const j = JSON.parse(line);
          info(`隧道已注册（协议 ${j.protocol || '?'}，边缘 ${j.location || '?'}）`);
        } catch {
          info('隧道已注册');
        }
      }
    }
    const m = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/.exec(text);
    if (m && !url) url = m[0];
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);

  const deadline = Date.now() + 45_000;
  while (!url && Date.now() < deadline) {
    if (child.exitCode !== null) break;
    await sleep(150);
  }
  if (!url) {
    console.error('[share] 隧道启动失败，cloudflared 输出：');
    console.error(seen.join('').slice(-2000));
    throw new Error('未能获取 trycloudflare 公网地址');
  }
  return { child, url, errors };
}

/* ------------------------------------------------------------ 公网自检 */
async function probeLocal(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * 自检需要重试：新域名通常几秒内生效，偶发 DNS 传播 / 边缘注册延迟。
 * 同时校验返回的确实是我们的页面（Cloudflare 的 502/530 错误页也是 HTML）。
 */
async function checkPublic(url, attempts = 8, gapMs = 3000) {
  let lastReason = '';
  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      const body = await res.text();
      if (res.ok && (body.includes('SecretTalk') || body.includes('密语'))) {
        return { ok: true, attempts: i };
      }
      lastReason = `HTTP ${res.status}`;
    } catch (e) {
      lastReason = String(e?.cause?.code || e?.name || '未知错误');
    }
    if (i < attempts) await sleep(gapMs);
  }
  return { ok: false, reason: lastReason };
}

/** 清理上次异常退出遗留的、指向本端口的 cloudflared 进程（只清理匹配本端口的） */
function findStaleTunnels(port) {
  if (!IS_WIN) return [];
  try {
    const ps = spawnSync('powershell', ['-NoProfile', '-Command',
      `Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" | Where-Object { $_.CommandLine -like '*tunnel --url http://127.0.0.1:${port}*' } | Select-Object -ExpandProperty ProcessId`,
    ], { encoding: 'utf8', timeout: 10_000 });
    return String(ps.stdout || '')
      .split(/\s+/)
      .filter(Boolean)
      .map(Number)
      .filter((n) => Number.isInteger(n) && n > 0);
  } catch {
    return [];
  }
}

function copyToClipboard(text) {
  if (!IS_WIN) return;
  try {
    const r = spawnSync('powershell', ['-NoProfile', '-Command', 'Set-Clipboard', '-Value', text], { stdio: 'ignore' });
    if (r.status === 0) info('链接已复制到剪贴板');
  } catch { /* 复制失败不影响使用 */ }
}

/* ------------------------------------------------------------------ 主流程 */
process.on('SIGINT', () => void shutdown(0));
process.on('SIGTERM', () => void shutdown(0));
// 直接关掉终端窗口时也尽量回收子进程，避免残留中继/隧道
process.on('exit', () => {
  try { tunnel?.kill(); } catch { /* 忽略 */ }
  killTree(app?.pid);
});

try {
  const cf = findCloudflared() ?? await downloadCloudflared();
  log(`cloudflared: ${cf === 'cloudflared' ? '系统 PATH' : cf}`);

  if (needBuild()) {
    log('检测到源码有更新，正在构建前后端（约 10 秒）…');
    runNpm('build');
    runNpm('build:server');
  } else {
    log('构建产物已是最新，跳过构建');
  }

  const publicPort = await pickPublicPort();
  const relayBase = await pickRelayBase();
  // 上次被强行关掉窗口时，cloudflared 可能成为孤儿进程，继续指向这个端口。
  // 不清理的话会出现「新隧道 + 旧隧道抢同一个域名」的怪现象，所以先按端口清理。
  const staleTunnels = findStaleTunnels(publicPort);
  for (const pid of staleTunnels) {
    log(`清理上次遗留的隧道进程 ${pid}（指向 :${publicPort}）`);
    killTree(pid);
  }
  log(`正在启动本地服务：网关 :${publicPort}，中继 ${relayBase}~${relayBase + 4}`);

  app = spawn(process.execPath, [join(ROOT, 'scripts/cloud-start.mjs')], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(publicPort), RELAY_BASE_PORT: String(relayBase) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // 必须以「我们自己的进程打印了就绪日志」为准：同端口上可能还跑着别的服务
  // （比如用 start:cloud 起的旧实例），只看 HTTP 200 会把它当成自己的。
  const appReady = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('本地服务 30 秒内未就绪（端口可能被占用）')), 30_000);
    const scan = (d) => {
      if (String(d).includes('网关已监听')) { clearTimeout(timer); resolve(); }
    };
    app.stdout.on('data', scan);
    app.stderr.on('data', scan);
  });
  app.stdout.on('data', (d) => process.stdout.write(`[app] ${d}`));
  app.stderr.on('data', (d) => process.stderr.write(`[app] ${d}`));
  app.on('exit', (code) => {
    if (closing) return;
    console.error(`\n[share] 本地服务意外退出（code=${code}）`);
    void shutdown(1);
  });

  await appReady;
  await waitLocal(publicPort);
  log('本地服务就绪，正在建立公网隧道…');

  const started = await startTunnel(cf, publicPort);
  tunnel = started.child;
  tunnel.on('exit', (code) => {
    if (closing) return;
    console.error(`\n[share] 隧道断开（code=${code}），正在关闭本地服务`);
    killTree(app?.pid);
    process.exit(1);
  });

  const localUrl = `http://127.0.0.1:${publicPort}`;
  const bar = '='.repeat(66);
  console.log(`\n${bar}`);
  console.log('  已上线！把下面的公网地址发给对方（手机/电脑都能直接开）');
  console.log('');
  console.log(`  公网地址：  ${started.url}`);
  console.log(`  本机地址：  ${localUrl}`);
  console.log('');
  console.log('  两个标签页填同一个房间号即可进入，不用选 A/B。');
  console.log('  按 Ctrl+C 关闭，链接立即失效（电脑需保持开机、不休眠）。');
  console.log(`${bar}\n`);
  copyToClipboard(started.url);

  // 公网地址需要几秒生效，重试探测；失败时给出可操作的诊断，而不是一句“再等等”。
  const check = await checkPublic(started.url);
  if (check.ok) {
    log(`公网自检通过（第 ${check.attempts} 次探测，页面可访问）`);
  } else {
    const localAlive = await probeLocal(publicPort);
    console.warn(`\n[share] 公网自检未通过：${check.reason}`);
    if (!localAlive) {
      console.warn('[share] 本机服务已经不可达：通常是 share 所在窗口被关闭、或进程被结束。');
      console.warn('[share] 请重新运行 npm run share（隧道会拿到新地址）。');
    } else {
      console.warn('[share] 本机服务正常，通常是 Cloudflare 边缘还没生效：等 10~30 秒再刷新页面。');
      console.warn('[share] 若持续失败：检查是否被网络/防火墙拦截。');
      console.warn('[share] 国内网络可试：npm run share -- --protocol http2 --edge-ip 4（强制 TCP + IPv4）');
    }
    if (started.errors.length) {
      console.warn('[share] cloudflared 最近的错误：');
      for (const line of started.errors.slice(-3)) console.warn(`  ${line}`);
    }
  }

  // 兜底：本地服务如果中途死掉，隧道留着只会返回 502/530，直接一起收掉。
  setInterval(() => {
    if (closing) return;
    if (app.exitCode !== null || app.signalCode) {
      console.error('\n[share] 本地服务已退出，正在关闭隧道（公网链接将失效）');
      void shutdown(1);
    }
  }, 5000).unref();

  await new Promise(() => { /* 保持运行，等 Ctrl+C */ });
} catch (e) {
  console.error(`\n[share] 启动失败：${e.message}`);
  console.error('[share] 国内网络建议先试：npm run share -- --protocol http2 --edge-ip 4');
  await shutdown(1);
}
