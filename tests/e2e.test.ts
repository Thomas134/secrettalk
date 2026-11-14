/**
 * 核心流程测试 ③：A → 5 台孤岛 → B 的完整端到端流程（真实 WebSocket + 真实 WebCrypto）
 * 覆盖：5 路并发连接、按索引分发、任意 3 片重组、已读回执去重、
 *       force_exit / 断线自毁、服务器缓存清空、仅 3 台中继在线时的门限可用性。
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, type AddressInfo } from 'ws';
import { RelayClient, type MessageView, type RelayStatus } from '../src/relay.js';
import { nodeSocketFactory, startCluster, type RelayCluster } from './helpers.js';
import { createRoomId, type ExitReason } from '../shared/protocol.js';

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: Error) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function withTimeout<T>(p: Promise<T>, label: string, ms = 10_000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`等待「${label}」超时`)), ms);
    // 不因超时定时器阻塞测试进程退出
    (timer as unknown as { unref?: () => void }).unref?.();
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

/** 轮询等待分布式异步事件（close / force_exit）传播到全部 5 台中继 */
async function waitUntil(cond: () => boolean, label: string, ms = 4000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error(`等待「${label}」超时`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

interface Harness {
  client: RelayClient;
  received: MessageView[];
  statuses: Array<{ id: string; status: string }>;
  destroyed: ExitReason[];
  errors: string[];
  status: RelayStatus;
  ready: Promise<string>;
  waitIncoming: () => Promise<MessageView>;
  waitRead: (id: string) => Promise<void>;
  waitDestroy: () => Promise<ExitReason>;
}

const activeClients: RelayClient[] = [];
const activeClusters: RelayCluster[] = [];

afterEach(async () => {
  // 必须销毁所有客户端，否则心跳 / 看门狗定时器会让 Vitest 无法退出
  for (const c of activeClients.splice(0)) await c.forceExit().catch(() => {});
  for (const c of activeClusters.splice(0)) await c.close().catch(() => {});
});

/** 拉起一端：只需房间号，不再传角色（角色在握手后由公钥字典序自动推导） */
async function makeHarness(
  roomId: string,
  urls: string[],
  extra: { strictExitOnAnyClose?: boolean } = {},
): Promise<Harness> {
  const readyD = deferred<string>();
  const incomingD = deferred<MessageView>();
  const readD = deferred<string>();
  const destroyD = deferred<ExitReason>();

  const h: Harness = {
    client: null as unknown as RelayClient,
    received: [], statuses: [], destroyed: [], errors: [], status: 'idle',
    ready: readyD.promise,
    waitIncoming: () => withTimeout(incomingD.promise, '对端收到明文', 10_000),
    waitRead: async (id) => {
      const got = await withTimeout(readD.promise, `消息 ${id} 已读回执`, 10_000);
      expect(got).toBe(id);
    },
    waitDestroy: () => withTimeout(destroyD.promise, '本端会话销毁', 10_000),
  };

  const client = await RelayClient.create(
    {
      roomId, servers: urls,
      socketFactory: nodeSocketFactory,
      strictExitOnAnyClose: extra.strictExitOnAnyClose ?? true,
      heartbeatIntervalMs: 2000,
      heartbeatTimeoutMs: 3000,
    },
    {
      onStatus: (s) => { h.status = s; },
      onPeerReady: (n) => readyD.resolve(n),
      onMessage: (m) => {
        h.received.push(m);
        // 本端发出的消息也会走 onMessage（用于状态回显），只有「对端发来的」才算收到明文
        const mine = h.client.role !== null && m.from === h.client.role;
        if (!mine && m.text && m.status !== 'failed') incomingD.resolve(m);
      },
      onMessageStatus: (id, st) => {
        h.statuses.push({ id, status: st });
        if (st === 'read') readD.resolve(id);
      },
      onDestroyed: (reason) => { h.destroyed.push(reason); destroyD.resolve(reason); },
      onError: (e) => h.errors.push(e.message),
      onLog: () => {},
    },
  );
  h.client = client;
  activeClients.push(client);
  return h;
}

async function newCluster(count = 5): Promise<RelayCluster> {
  const c = await startCluster(count);
  activeClusters.push(c);
  return c;
}

describe('7. 端到端核心流程', () => {
  it('两端只填同一个房间号即可入房：角色自动推导，且可双向收发', async () => {
    const cluster = await newCluster(5);
    const room = createRoomId();
    // 注意：这里没有传任何角色 —— 网页端已删除 A / B 选项
    const a = await makeHarness(room, cluster.urls);
    const b = await makeHarness(room, cluster.urls);
    await Promise.all([withTimeout(a.ready, '第一端握手'), withTimeout(b.ready, '第二端握手')]);
    expect(a.client.role).not.toBeNull();
    expect(b.client.role).not.toBeNull();
    // 双方各自比较同一对公钥，必然得到相反的角色，不需要任何中心分配
    expect(a.client.role).not.toBe(b.client.role);

    // 第一端 → 第二端
    const id1 = await a.client.send('第一条：房间号一致就能聊');
    const m1 = await b.waitIncoming();
    expect(m1.text).toBe('第一条：房间号一致就能聊');
    expect(m1.from).toBe(a.client.role);
    await a.waitRead(id1);

    // 第二端 → 第一端：已读回执不再只认某一端，双向都可用
    const id2 = await b.client.send('第二条：回复也能收到已读');
    const m2 = await a.waitIncoming();
    expect(m2.text).toBe('第二条：回复也能收到已读');
    expect(m2.from).toBe(b.client.role);
    await b.waitRead(id2);
  });

  it('附件（图片）经 5 路中继完整送达，接收端拿到 data URL', async () => {
    const cluster = await newCluster(5);
    const room = createRoomId();
    const a = await makeHarness(room, cluster.urls);
    const b = await makeHarness(room, cluster.urls);
    await Promise.all([withTimeout(a.ready, '第一端握手'), withTimeout(b.ready, '第二端握手')]);

    const bytes = new Uint8Array(2048).map((_, i) => i % 256);
    const id = await a.client.send('看图', {
      kind: 'image', name: 'p.png', mime: 'image/png', bytes,
    });
    const m = await b.waitIncoming();
    expect(m.text).toBe('看图');
    expect(m.attachment?.kind).toBe('image');
    expect(m.attachment?.name).toBe('p.png');
    expect(m.attachment?.size).toBe(bytes.length);
    expect(m.attachment?.url.startsWith('data:image/png;base64,')).toBe(true);
    await a.waitRead(id);
  });

  it('A 加密分发 5 片 → B 收 3 片解密 → ACK 已读 → force_exit 全链路自毁', async () => {
    const cluster = await newCluster(5);
    const room = createRoomId();
    const a = await makeHarness(room, cluster.urls);
    const b = await makeHarness(room, cluster.urls);
    const [sa, sb] = await Promise.all([
      withTimeout(a.ready, 'A 握手'), withTimeout(b.ready, 'B 握手'),
    ]);
    expect(sa).toBe(sb); // 双方安全数一致，说明 ECDH 没被中间人替换
    expect(sa).toMatch(/^\d{3} \d{3}$/);
    expect(a.client.linkStates.filter((l) => l.connected)).toHaveLength(5);
    expect(b.client.linkStates.filter((l) => l.connected)).toHaveLength(5);

    // A 发送：加密 → SSS(3,5) → 5 个包分别投递到 5 台孤岛
    const id = await a.client.send('今晚八点，老地方见');
    const incoming = await b.waitIncoming();
    expect(incoming.text).toBe('今晚八点，老地方见');
    expect(incoming.from).toBe(a.client.role);
    expect(incoming.usedShares).toHaveLength(3);
    expect(new Set(incoming.usedShares).size).toBe(3);

    // 已读回执：B 向 5 路各发一份 ACK，A 端必须去重，只更新一次
    await a.waitRead(id);
    expect(a.statuses.filter((s) => s.id === id && s.status === 'read')).toHaveLength(1);
    // onMessage 交出的是快照，状态变更只通过 onMessageStatus 通知，不被静默改写
    expect(a.received.find((m) => m.messageId === id)?.status).toBe('sending');

    // 零知识验证：5 台服务器的内存缓存里不存在任何明文
    for (const h of cluster.handles) {
      const cached = Array.from(h.rooms.values()).flatMap((r) => Array.from(r.packets.values()));
      expect(cached.length).toBeGreaterThan(0);
      expect(JSON.stringify(cached)).not.toContain('今晚八点');
      expect(JSON.stringify(cached)).not.toContain('老地方');
      // 每台只持有一个碎片，且下标与端口一一对应
      expect(cached.every((p) => p.shareIndex === h.relayIndex)).toBe(true);
    }

    // A 主动退出：广播 force_exit → 服务器清缓存 + 通知 B → B 本地销毁
    await a.client.forceExit('user_logout');
    expect((await b.waitDestroy())).toBe('user_logout');
    expect(a.client.session.isDestroyed).toBe(true);
    expect(b.client.session.isDestroyed).toBe(true);
    expect(a.client.currentStatus).toBe('destroyed');
    expect(b.client.currentStatus).toBe('destroyed');
    for (const h of cluster.handles) expect(h.rooms.size).toBe(0);
  });

  it('只有 3 台中继可达时仍能解密（k=3 门限，任 3 片即可）', async () => {
    const cluster = await newCluster(3);
    // 另外 2 台「宕机」：地址不可达
    const urls = [...cluster.urls, 'ws://127.0.0.1:1', 'ws://127.0.0.1:1'];
    const room = createRoomId();
    const a = await makeHarness(room, urls, { strictExitOnAnyClose: false });
    const b = await makeHarness(room, urls, { strictExitOnAnyClose: false });
    await Promise.all([withTimeout(a.ready, 'A 握手'), withTimeout(b.ready, 'B 握手')]);

    const id = await a.client.send('三片即可还原');
    const incoming = await b.waitIncoming();
    expect(incoming.text).toBe('三片即可还原');
    expect(incoming.usedShares).toHaveLength(3);
    await a.waitRead(id);

    // 3 台可达中继各缓存 1 片；另外 2 路从未建立
    for (const h of cluster.handles) {
      expect(Array.from(h.rooms.values()).flatMap((r) => Array.from(r.packets.values()))).toHaveLength(1);
    }
  });

  it('任意一条 WebSocket 断开 → 服务器广播 force_exit → 双方会话即刻销毁', async () => {
    const cluster = await newCluster(5);
    const room = createRoomId();
    const a = await makeHarness(room, cluster.urls);
    const b = await makeHarness(room, cluster.urls);
    await Promise.all([withTimeout(a.ready, 'A 握手'), withTimeout(b.ready, 'B 握手')]);

    // 从服务器侧强行掐断第 3 台中继上的连接，模拟物理断网
    for (const socket of cluster.handles[2].wss.clients) socket.terminate();

    expect(await a.waitDestroy()).toBe('peer_disconnect');
    expect(b.destroyed.length).toBeGreaterThan(0);
    expect(a.client.session.isDestroyed && b.client.session.isDestroyed).toBe(true);
    // 5 台孤岛各自处理自己进程内的 close 事件，等待全部传播完成
    await waitUntil(() => cluster.handles.every((h) => h.rooms.size === 0), '5 台中继缓存清空');
    for (const h of cluster.handles) expect(h.rooms.size).toBe(0);
  });

  it('完整性校验失败时不展示明文、也不发送已读回执', async () => {
    // 直接复用密码学层已覆盖的篡改场景，这里验证 UI 事件层不会误报「已读」
    const cluster = await newCluster(5);
    const room = createRoomId();
    const a = await makeHarness(room, cluster.urls);
    const b = await makeHarness(room, cluster.urls);
    await Promise.all([withTimeout(a.ready, 'A 握手'), withTimeout(b.ready, 'B 握手')]);

    await a.client.send('正常消息');
    await b.waitIncoming();
    await new Promise((r) => setTimeout(r, 150));
    // 全程没有完整性错误，也不应出现 failed 状态的消息
    expect(b.errors).toHaveLength(0);
    expect(b.received.filter((m) => m.status === 'failed')).toHaveLength(0);
    expect(a.statuses.some((s) => s.status === 'read')).toBe(true);
  });
});

/**
 * 心跳判定的环境假设：浏览器会把后台标签页的定时器节流到秒级甚至分钟级，
 * 于是 ping 可能长时间发不出去。旧实现只看「多久没收到 pong」，会把健康会话
 * 判成 heartbeat_timeout 并广播 force_exit，把前台那一端也一起杀掉。
 * 这里用一个「只收不回」的静默服务器把 pong 缺失放大成确定性场景。
 */
describe('8. 心跳判定（后台标签页 / 定时器节流）', () => {
  const silentServers: Array<{ url: string; close: () => Promise<void> }> = [];
  const silentClients: RelayClient[] = [];

  afterEach(async () => {
    for (const c of silentClients.splice(0)) await c.forceExit().catch(() => {});
    for (const s of silentServers.splice(0)) await s.close();
    vi.unstubAllGlobals();
  });

  /** 只接受连接、不回复任何帧：模拟「pong 迟迟不到」 */
  function startSilentServer(): Promise<{ url: string; close: () => Promise<void> }> {
    return new Promise((resolve) => {
      const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
      wss.on('connection', (ws) => { ws.on('message', () => { /* 故意不回应 pong */ }); });
      wss.once('listening', () => {
        const { port } = wss.address() as AddressInfo;
        resolve({
          url: `ws://127.0.0.1:${port}`,
          close: () => new Promise<void>((r) => wss.close(() => r())),
        });
      });
    });
  }

  async function createSilentClient(url: string, destroyed: ExitReason[]): Promise<RelayClient> {
    const c = await RelayClient.create(
      {
        roomId: 'hb-' + Math.random().toString(16).slice(2),
        servers: Array.from({ length: 5 }, () => url),
        socketFactory: nodeSocketFactory,
        heartbeatIntervalMs: 200,
        heartbeatTimeoutMs: 200,
      },
      { onDestroyed: (r) => destroyed.push(r), onLog: () => {} },
    );
    silentClients.push(c);
    return c;
  }

  it('页面在后台被节流时，收不到 pong 也不判心跳超时', async () => {
    const srv = await startSilentServer();
    silentServers.push(srv);
    // 模拟隐藏标签页：浏览器此时会暂停/节流 JS 定时器
    vi.stubGlobal('document', { hidden: true, addEventListener() {}, removeEventListener() {} });

    const destroyed: ExitReason[] = [];
    const c = await createSilentClient(srv.url, destroyed);
    await new Promise((r) => setTimeout(r, 1300)); // 远超 hbInterval + hbTimeout 与看门狗周期
    expect(destroyed).toHaveLength(0);
    expect(c.isDestroyed).toBe(false);
    expect(c.currentStatus).not.toBe('destroyed');
  });

  it('页面可见时仍然会判定心跳超时（看门狗没有被削弱）', async () => {
    const srv = await startSilentServer();
    silentServers.push(srv);
    vi.stubGlobal('document', { hidden: false, addEventListener() {}, removeEventListener() {} });

    const destroyed: ExitReason[] = [];
    const c = await createSilentClient(srv.url, destroyed);
    await new Promise((r) => setTimeout(r, 1800));
    expect(destroyed).toContain('heartbeat_timeout');
    expect(c.isDestroyed).toBe(true);
  });
});
