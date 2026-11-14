/**
 * 核心流程测试 ②：零知识中继服务器（5 个真实 ws 实例）
 * 覆盖：孤岛隔离、公钥/密文/ACK 转发、pull 拉取、TTL 清理、close 与 force_exit 清缓存。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  connectClient,
  fakePacket,
  serverSource,
  startCluster,
  type RelayCluster,
  type TestClient,
} from './helpers.js';
import { startRelayServer } from '../server/server.js';

const tick = (ms = 60) => new Promise((r) => setTimeout(r, ms));

/** 让两台客户端（无需角色）在同一台中继上完成入房 */
async function joinPair(url: string, roomId = 'room-srv') {
  const a = await connectClient(url);
  a.send({ type: 'hello', roomId, publicKey: 'PUBKEY-A' });
  await a.waitFor('welcome');
  const b = await connectClient(url);
  b.send({ type: 'hello', roomId, publicKey: 'PUBKEY-B' });
  await b.waitFor('welcome');
  return { a, b };
}

describe('6. 零知识中继服务器', () => {
  let cluster: RelayCluster;
  const openClients: TestClient[] = [];

  beforeEach(async () => { cluster = await startCluster(5); openClients.length = 0; });
  afterEach(async () => {
    for (const c of openClients) { try { c.close(); } catch { /* noop */ } }
    await tick(20);
    await cluster.close();
  });
  const track = <T extends TestClient>(c: T): T => { openClients.push(c); return c; };

  it('源码层面零知识：无 crypto 依赖、无加解密调用、不落盘', () => {
    const src = serverSource();
    expect(src).not.toMatch(/from\s+['"]node:crypto['"]/);
    expect(src).not.toMatch(/subtle\.(encrypt|decrypt|deriveBits|deriveKey|importKey)/);
    expect(src).not.toMatch(/\b(split|combine)\s*\(/);
    expect(src).not.toMatch(/writeFileSync|createWriteStream|appendFileSync/);
  });

  it('5 个实例的内存状态彼此完全隔离（孤岛语义）', async () => {
    const a = track(await connectClient(cluster.urls[0]));
    a.send({ type: 'hello', roomId: 'iso', publicKey: 'K' });
    await a.waitFor('welcome');
    a.send({ type: 'cipher', packet: fakePacket('iso', 0) });
    await tick();

    expect(cluster.handles[0].rooms.get('iso')?.packets.size).toBe(1);
    for (let i = 1; i < 5; i++) expect(cluster.handles[i].rooms.size).toBe(0);
  });

  it('同房间第三人在两人已在线时被拒绝（ROOM_FULL），且不影响已入房两端', async () => {
    const { a, b } = await joinPair(cluster.urls[0], 'room-full');
    openClients.push(a, b);

    // 房间是两人对聊：只要两人已在线，第三个连接一律拒绝（无角色可冲突，改为容量约束）
    const third = track(await connectClient(cluster.urls[0]));
    third.send({ type: 'hello', roomId: 'room-full', publicKey: 'PUBKEY-THIRD' });
    const err = await third.waitFor('error');
    expect(err.code).toBe('ROOM_FULL');
    // 被拒连接未入房，两端仍是 2 条连接且没收到任何错误
    expect(cluster.handles[0].rooms.get('room-full')?.peers.size).toBe(2);
    expect(a.frames.filter((f) => f.type === 'error')).toHaveLength(0);
    expect(b.frames.filter((f) => f.type === 'error')).toHaveLength(0);

    // 两端之间仍可正常交换公钥：房间号一致即可，无需选择角色
    expect((await a.waitFor('peer_key')).publicKey).toBe('PUBKEY-B');
  });

  it('心跳 ping → pong', async () => {
    const a = track(await connectClient(cluster.urls[3]));
    a.send({ type: 'ping', ts: 123456 });
    const pong = await a.waitFor('pong');
    expect(pong.ts).toBe(123456);
  });

  it('hello 双向转发 ECDH 公钥（服务器只看字符串）', async () => {
    const a = track(await connectClient(cluster.urls[0]));
    a.send({ type: 'hello', roomId: 'keys', publicKey: 'PUBKEY-A' });
    await a.waitFor('welcome');
    const b = track(await connectClient(cluster.urls[0]));
    b.send({ type: 'hello', roomId: 'keys', publicKey: 'PUBKEY-B' });
    await b.waitFor('welcome');

    expect((await a.waitFor('peer_key')).publicKey).toBe('PUBKEY-B');
    expect((await b.waitFor('peer_key')).publicKey).toBe('PUBKEY-A');
  });

  it('cipher 转发给同房间另一方，并只在自己进程内暂存', async () => {
    const { a, b } = await joinPair(cluster.urls[1]);
    openClients.push(a, b);
    const packet = fakePacket('room-srv', 1, 'msg-forward');
    a.send({ type: 'cipher', packet });
    const forwarded = await b.waitFor('cipher');
    expect(forwarded.packet.messageId).toBe('msg-forward');
    expect(forwarded.packet.encryptedShare).toBe(packet.encryptedShare); // 原样透传，未解码
    expect(cluster.handles[1].rooms.get('room-srv')?.packets.size).toBe(1);
    expect(cluster.handles[0].rooms.size).toBe(0);
  });

  it('B 后上线时通过 pull 拉取本进程暂存的碎片', async () => {
    const a = track(await connectClient(cluster.urls[2]));
    a.send({ type: 'hello', roomId: 'late', publicKey: 'K' });
    await a.waitFor('welcome');
    a.send({ type: 'cipher', packet: fakePacket('late', 2, 'msg-late') });
    await tick();

    const b = track(await connectClient(cluster.urls[2]));
    b.send({ type: 'hello', roomId: 'late', publicKey: 'K2' });
    await b.waitFor('welcome');
    b.send({ type: 'pull', roomId: 'late' });
    const cached = await b.waitFor('cached');
    expect(cached.packets).toHaveLength(1);
    expect(cached.packets[0].messageId).toBe('msg-late');
    expect(cached.packets[0].shareIndex).toBe(2);
  });

  it('ACK 已读回执原样转发 messageId', async () => {
    const { a, b } = await joinPair(cluster.urls[0]);
    openClients.push(a, b);
    b.send({ type: 'ack', roomId: 'room-srv', messageId: 'msg-ack-1', to: 'A' });
    expect((await a.waitFor('ack')).messageId).toBe('msg-ack-1');
  });

  it('投错端口的碎片被拒绝（路由下标校验，非密码学检查）', async () => {
    const a = track(await connectClient(cluster.urls[4]));
    a.send({ type: 'hello', roomId: 'wrong', publicKey: 'K' });
    await a.waitFor('welcome');
    a.send({ type: 'cipher', packet: fakePacket('wrong', 0) });
    const err = await a.waitFor('error');
    expect(err.code).toBe('WRONG_RELAY');
    expect(cluster.handles[4].rooms.get('wrong')?.packets.size ?? 0).toBe(0);
  });

  it('收到 force_exit：立刻清空 TTL 缓存并通知另一方', async () => {
    const { a, b } = await joinPair(cluster.urls[0], 'room-exit');
    openClients.push(a, b);
    a.send({ type: 'cipher', packet: fakePacket('room-exit', 0) });
    await tick();
    expect(cluster.handles[0].rooms.get('room-exit')?.packets.size).toBe(1);

    a.send({ type: 'force_exit', roomId: 'room-exit', reason: 'user_logout' });
    expect((await b.waitFor('force_exit')).reason).toBe('user_logout');
    expect(cluster.handles[0].rooms.size).toBe(0);
    expect(cluster.handles[0].rooms.get('room-exit')).toBeUndefined();
  });

  it('侦测到任意一方 close：清空 roomId 缓存并通知另一方', async () => {
    const { a, b } = await joinPair(cluster.urls[2], 'room-close');
    openClients.push(b);
    a.send({ type: 'cipher', packet: fakePacket('room-close', 2) });
    await tick();
    expect(cluster.handles[2].rooms.get('room-close')?.packets.size).toBe(1);

    a.close(); // 模拟 A 掉线
    expect((await b.waitFor('force_exit')).reason).toBe('peer_disconnect');
    expect(cluster.handles[2].rooms.size).toBe(0);
  });

  it('TTL 到期自动清空缓存并下发 room_expired（clearTimeout 无泄漏）', async () => {
    const short = await startCluster(1, { ttlMs: 120 });
    try {
      const a = track(await connectClient(short.urls[0]));
      a.send({ type: 'hello', roomId: 'ttl', publicKey: 'K' });
      await a.waitFor('welcome');
      a.send({ type: 'cipher', packet: fakePacket('ttl', 0) });
      await tick();
      expect(short.handles[0].rooms.get('ttl')?.packets.size).toBe(1);

      expect((await a.waitFor('room_expired', 3000)).roomId).toBe('ttl');
      expect(short.handles[0].rooms.size).toBe(0);
      expect(short.handles[0].rooms.get('ttl')).toBeUndefined();
    } finally {
      await short.close();
    }
  });

  it('close() 后定时器与缓存被清理，端口可复用', async () => {
    const a = track(await connectClient(cluster.urls[0]));
    a.send({ type: 'hello', roomId: 'recycle', publicKey: 'K' });
    await a.waitFor('welcome');
    a.send({ type: 'cipher', packet: fakePacket('recycle', 0) });
    await tick();
    expect(cluster.handles[0].rooms.size).toBe(1);

    const port = cluster.ports[0];
    await cluster.handles[0].close();
    expect(cluster.handles[0].rooms.size).toBe(0); // 所有 TTL 定时器与密文缓存已清

    const again = await startRelayServer({ port, host: '127.0.0.1', relayIndex: 0, silent: true });
    expect(again.port).toBe(port);
    await again.close();
  });
});
