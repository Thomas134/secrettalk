/**
 * 网关（gateway.ts）核心测试：
 *   1. /relay/{i} 路由到正确的孤岛中继（ rooms 只落在对应进程 ）
 *   2. ping/pong 经网关透明透传（via 正确）
 *   3. 非法 /relay/{n} 路径拒绝升级
 *   4. 一端经网关断开 → 中继广播 force_exit → 另一端收到（断开传染）
 *   5. 静态文件 + 严格安全响应头 + SPA 回退 + 目录穿越防护
 *   6. TLS 模式：自签证书下 https 页面与 wss 管道均可用（安全上下文的前提）
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { get as httpGet } from 'node:http';
import { get as httpsGet } from 'node:https';
import { WebSocket as WsWebSocket } from 'ws';
import forge from 'node-forge';
import { startGateway, type GatewayHandle } from '../server/gateway.js';
import { startCluster, connectClient, type RelayCluster } from './helpers.js';

let cluster: RelayCluster | null = null;
let gateway: GatewayHandle | null = null;
const tmpDirs: string[] = [];

afterEach(async () => {
  if (gateway) await gateway.close();
  if (cluster) await cluster.close();
  gateway = null;
  cluster = null;
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
  tmpDirs.length = 0;
});

/** 起 5 台随机端口中继 + 一台随机端口网关（http 模式），返回访问基地址 */
async function setupGateway(opts: Parameters<typeof startGateway>[0] = {}) {
  cluster = await startCluster(5);
  gateway = await startGateway({
    port: 0,
    host: '127.0.0.1',
    upstreamPorts: cluster.ports,
    silent: true,
    ...opts,
  });
  return { cluster, gateway };
}

describe('网关 · WebSocket 路由', () => {
  it('/relay/{i} 精确路由到对应孤岛：rooms 只落在第 i 台', async () => {
    const { cluster, gateway } = await setupGateway();
    const c = await connectClient(`ws://127.0.0.1:${gateway.port}/relay/2`);
    c.send({ type: 'hello', roomId: 'gw-room-route', publicKey: 'AAECAw==' });
    const welcome = await c.waitFor('welcome');
    expect(welcome.roomId).toBe('gw-room-route');
    // 只有 2 号中继创建了房间，其余 4 台完全不知情
    expect(cluster.handles[2].rooms.has('gw-room-route')).toBe(true);
    expect(cluster.handles[0].rooms.has('gw-room-route')).toBe(false);
    expect(cluster.handles[4].rooms.has('gw-room-route')).toBe(false);
    c.close();
  });

  it('文本帧经网关保持文本类型（否则浏览器拿到 Blob，所有帧都会解析失败）', async () => {
    const { gateway } = await setupGateway();
    const ws = new WsWebSocket(`ws://127.0.0.1:${gateway.port}/relay/0`);
    await new Promise<void>((resolve, reject) => { ws.once('open', () => resolve()); ws.once('error', reject); });

    const seen: Array<{ isBinary: boolean; text: string }> = [];
    const gotWelcome = new Promise<void>((resolve) => {
      ws.on('message', (data, isBinary) => {
        const text = data.toString();
        seen.push({ isBinary, text });
        if (text.includes('"welcome"')) resolve();
      });
    });
    ws.send(JSON.stringify({ type: 'hello', roomId: 'gw-frame-type', publicKey: 'AAECAw==' }));
    await gotWelcome;

    expect(seen.length).toBeGreaterThan(0);
    // 关键断言：中继的 JSON 全部是文本帧，网关不能把它们降级成二进制帧
    expect(seen.every((f) => f.isBinary === false)).toBe(true);
    expect(seen[0].text.startsWith('{')).toBe(true);
    ws.close();
  });

  it('ping/pong 经网关透明透传，via 与所选路径一致', async () => {
    const { gateway } = await setupGateway();
    const c = await connectClient(`ws://127.0.0.1:${gateway.port}/relay/3`);
    c.send({ type: 'ping', ts: 424242 });
    const pong = await c.waitFor('pong');
    expect(pong.ts).toBe(424242);
    // via 携带的是上游中继的实际端口号（服务器协议如此）
    expect(pong.via).toBe(cluster!.ports[3]);
    c.close();
  });

  it('越界路径 /relay/9 与未知路径拒绝 WebSocket 升级', async () => {
    const { gateway } = await setupGateway();
    await expect(connectClient(`ws://127.0.0.1:${gateway.port}/relay/9`)).rejects.toThrow();
    await expect(connectClient(`ws://127.0.0.1:${gateway.port}/nope`)).rejects.toThrow();
  });

  it('一端经网关断开，中继向另一端广播 force_exit（断开语义穿透管道）', async () => {
    const { gateway } = await setupGateway();
    const a = await connectClient(`ws://127.0.0.1:${gateway.port}/relay/1`);
    const b = await connectClient(`ws://127.0.0.1:${gateway.port}/relay/1`);
    a.send({ type: 'hello', roomId: 'gw-destroy', publicKey: 'AAECAw==' });
    b.send({ type: 'hello', roomId: 'gw-destroy', publicKey: 'AAECAw==' });
    await a.waitFor('welcome');
    await b.waitFor('welcome');
    a.close();
    const fe = await b.waitFor('force_exit', 6000);
    expect(fe.roomId).toBe('gw-destroy');
    b.close();
  });
});

describe('网关 · 静态站点', () => {
  it('服务 index.html 并下发严格安全响应头，未知路径 SPA 回退', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'st-gw-static-'));
    tmpDirs.push(dir);
    writeFileSync(join(dir, 'index.html'), '<!doctype html><title>SecretTalk GW Test</title>');
    cluster = await startCluster(1);
    gateway = await startGateway({
      port: 0, host: '127.0.0.1', staticRoot: dir,
      upstreamPorts: cluster.ports, silent: true,
    });

    const res = await fetch(`http://127.0.0.1:${gateway.port}/`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('SecretTalk GW Test');
    const csp = res.headers.get('content-security-policy') || '';
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("connect-src 'self'");

    const fallback = await fetch(`http://127.0.0.1:${gateway.port}/some/spa/route`);
    expect(fallback.status).toBe(200);
  });

  it('目录穿越被拒绝（403）', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'st-gw-static-'));
    tmpDirs.push(dir);
    writeFileSync(join(dir, 'index.html'), 'ok');
    cluster = await startCluster(1);
    gateway = await startGateway({
      port: 0, host: '127.0.0.1', staticRoot: dir,
      upstreamPorts: cluster.ports, silent: true,
    });
    // 用原始 http.get 避免客户端 URL 规范化吃掉 ../
    const status = await new Promise<number>((resolve, reject) => {
      httpGet({ host: '127.0.0.1', port: gateway!.port, path: '/%2e%2e/%2e%2e/package.json' },
        (r) => resolve(r.statusCode!)).on('error', reject);
    });
    expect(status).toBe(403);
  });

  it('微信内置浏览器访问页面被拒绝（403 + 引导页）', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'st-gw-wechat-'));
    tmpDirs.push(dir);
    writeFileSync(join(dir, 'index.html'), '<!doctype html><title>SHOULD-NOT-LOAD</title>');
    cluster = await startCluster(1);
    gateway = await startGateway({
      port: 0, host: '127.0.0.1', staticRoot: dir,
      upstreamPorts: cluster.ports, silent: true,
    });

    const res = await fetch(`http://127.0.0.1:${gateway.port}/`, {
      headers: { 'user-agent': 'Mozilla/5.0 (iPhone) MicroMessenger/8.0.42' },
    });
    expect(res.status).toBe(403);
    const html = await res.text();
    expect(html).toContain('在浏览器中打开');
    expect(html).not.toContain('SHOULD-NOT-LOAD');
  });

  it('微信内置浏览器无法建立 /relay WebSocket（拒绝升级）', async () => {
    const { gateway } = await setupGateway();
    const ws = new WsWebSocket(`ws://127.0.0.1:${gateway.port}/relay/0`, {
      headers: { 'user-agent': 'Mozilla/5.0 (iPhone) MicroMessenger/8.0.42' },
    });
    const outcome = await new Promise<string>((resolve) => {
      ws.once('open', () => resolve('open'));
      ws.once('error', () => resolve('rejected'));
      ws.once('close', () => resolve('rejected'));
    });
    expect(outcome).toBe('rejected');
  });

  it('blockWeChat: false 时微信可以正常访问（可关闭）', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'st-gw-wechat-off-'));
    tmpDirs.push(dir);
    writeFileSync(join(dir, 'index.html'), 'wechat-ok');
    cluster = await startCluster(1);
    gateway = await startGateway({
      port: 0, host: '127.0.0.1', staticRoot: dir, blockWeChat: false,
      upstreamPorts: cluster.ports, silent: true,
    });

    const res = await fetch(`http://127.0.0.1:${gateway.port}/`, {
      headers: { 'user-agent': 'Mozilla/5.0 (iPhone) MicroMessenger/8.0.42' },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('wechat-ok');
  });
});

describe('网关 · TLS（https / wss 同端口）', () => {
  /** 用 node-forge 快速生成测试专用自签证书（2048 位，仅测试环境） */
  function makeTestCerts(): { dir: string; key: string; cert: string } {
    const dir = mkdtempSync(join(tmpdir(), 'st-gw-tls-'));
    tmpDirs.push(dir);
    // Node 24 / OpenSSL 3.5 起，1024 位 RSA 会直接被拒绝握手（ee key too small），故用 2048 位
    const caKeys = forge.pki.rsa.generateKeyPair(2048);
    const ca = forge.pki.createCertificate();
    ca.publicKey = caKeys.publicKey;
    ca.serialNumber = '1';
    ca.validity.notBefore = new Date(Date.now() - 86400_000);
    ca.validity.notAfter = new Date(Date.now() + 86400_000);
    ca.setSubject([{ name: 'commonName', value: 'Test CA' }]);
    ca.setIssuer(ca.subject.attributes);
    ca.setExtensions([{ name: 'basicConstraints', cA: true }]);
    ca.sign(caKeys.privateKey, forge.md.sha256.create());

    const keys = forge.pki.rsa.generateKeyPair(2048);
    const crt = forge.pki.createCertificate();
    crt.publicKey = keys.publicKey;
    crt.serialNumber = '2';
    crt.validity.notBefore = ca.validity.notBefore;
    crt.validity.notAfter = ca.validity.notAfter;
    crt.setSubject([{ name: 'commonName', value: 'Test Gateway' }]);
    crt.setIssuer(ca.subject.attributes);
    crt.setExtensions([{
      name: 'subjectAltName',
      altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }],
    }]);
    crt.sign(caKeys.privateKey, forge.md.sha256.create());

    const keyPath = join(dir, 'test.key');
    const certPath = join(dir, 'test.pem');
    writeFileSync(keyPath, forge.pki.privateKeyToPem(keys.privateKey));
    writeFileSync(certPath, forge.pki.certificateToPem(crt));
    return { dir, key: keyPath, cert: certPath };
  }

  it('自签证书下：页面 https 200、wss /relay/{i} 管道可用且路由正确', async () => {
    const certs = makeTestCerts();
    writeFileSync(join(certs.dir, 'index.html'), '<!doctype html><title>TLS OK</title>');
    cluster = await startCluster(5);
    gateway = await startGateway({
      port: 0, host: '127.0.0.1', secure: true,
      tlsKeyPath: certs.key, tlsCertPath: certs.cert,
      staticRoot: certs.dir, upstreamPorts: cluster.ports, silent: true,
    });
    expect(gateway.secure).toBe(true);

    // https 静态页面（忽略自签校验，等价于手机浏览器点「继续访问」）
    const pageStatus = await new Promise<number>((resolve, reject) => {
      httpsGet({ host: '127.0.0.1', port: gateway!.port, path: '/', rejectUnauthorized: false },
        (r) => resolve(r.statusCode!)).on('error', reject);
    });
    expect(pageStatus).toBe(200);

    // wss 管道：连 /relay/4 应在 4 号中继创建房间
    const ws = new WsWebSocket(`wss://127.0.0.1:${gateway.port}/relay/4`, { rejectUnauthorized: false });
    ws.on('error', () => {});
    await new Promise<void>((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
    ws.send(JSON.stringify({ type: 'hello', roomId: 'gw-tls-room', publicKey: 'AAECAw==' }));
    const welcome: unknown = await new Promise((resolve, reject) => {
      ws.once('message', (raw) => resolve(JSON.parse(raw.toString())));
      setTimeout(() => reject(new Error('等待 welcome 超时')), 4000);
    });
    expect((welcome as { type: string }).type).toBe('welcome');
    expect(cluster.handles[4].rooms.has('gw-tls-room')).toBe(true);
    ws.close();
  });
});
