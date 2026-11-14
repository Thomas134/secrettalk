/**
 * 密语 SecretTalk · 零知识中继服务器（server.ts）
 * ===========================================================================
 * 【零知识的硬性证明】
 * 本文件从头到尾没有 import 任何密码学模块（node:crypto 也没有），
 * 没有任何 key / decrypt / derive / SSS 相关代码。服务器对
 * encryptedShare / shareIv / ciphertext / cipherIv / publicKey 这些字段
 * 只做「是否存在、是否为字符串」的形状检查，然后原样透传。
 * 它看不到明文，看不到 AES 密钥，看不到 ECDH 私钥，也永远只持有 1 个碎片。
 *
 * 【部署拓扑】PM2 以 fork 模式在单机启动 5 个独立 Node.js 进程（3001~3005），
 * 通过 process.env.PORT 动态监听。5 个进程之间没有任何 IPC / 共享内存 / 数据库 /
 * 文件交换；每个进程内 rooms 是闭包局部变量，绝不共享。
 * 因此即使在同一台机器上，任一进程被攻陷也只能拿到 1/5 的密钥碎片（且是密文）。
 *
 * 【服务器职责边界】
 *   ✓ 接收并暂存（仅内存、带 TTL）密文包
 *   ✓ 转发 hello / 公钥 / 密文包 / ACK / force_exit
 *   ✓ 侦测 close 与死连接，清空 roomId 的缓存并通知另一方
 *   ✗ 不参与加解密、不生成密钥、不做 SSS 拆分或重组、不落盘、不写日志明文
 */
import { createServer, type Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { pathToFileURL } from 'node:url';
import {
  DEFAULT_ROOM_TTL_MS,
  SERVER_PING_INTERVAL_MS,
  SHARE_TOTAL,
  isClientFrame,
  type CipherPacket,
  type ClientFrame,
  type ExitReason,
  type ServerFrame,
} from '../shared/protocol.js';

const WS_OPEN = WebSocket.OPEN;

interface Peer {
  ws: AliveWebSocket;
  roomId: string;
  /** 本端 ECDH 公钥（base64/SPKI）—— 服务器只转发，不解析 */
  publicKeyB64: string;
  /** 会话已销毁标记：销毁后该连接发来的任何业务帧都被忽略 */
  dead: boolean;
}

type AliveWebSocket = WebSocket & { isAlive?: boolean };

interface Room {
  roomId: string;
  peers: Set<Peer>;
  /** 本进程暂存的碎片包：key = `${messageId}#${shareIndex}`，value 是不透明的密文包 */
  packets: Map<string, CipherPacket>;
  /** TTL 定时器句柄 —— 清理时必须 clearTimeout，否则闭包长期持有密文引用 */
  ttlTimer: ReturnType<typeof setTimeout> | null;
  expiresAt: number;
}

export interface RelayServerOptions {
  port?: number;
  host?: string;
  ttlMs?: number;
  /** 本进程负责的碎片下标（PM2 env.RELAY_INDEX），用于拒绝客户端投错端口 */
  relayIndex?: number;
  silent?: boolean;
}

export interface RelayServerHandle {
  port: number;
  relayIndex: number;
  /** 暴露给测试断言「force_exit 后缓存确实被清空」；生产环境无需读取 */
  rooms: Map<string, Room>;
  wss: WebSocketServer;
  close: () => Promise<void>;
}

/** 只做形状校验：绝不解码 base64、绝不解释密文内容（零知识） */
function isCipherPacket(v: unknown): v is CipherPacket {
  if (!v || typeof v !== 'object') return false;
  const p = v as Record<string, unknown>;
  return typeof p.roomId === 'string' && typeof p.messageId === 'string' &&
    (p.from === 'A' || p.from === 'B') &&
    Number.isInteger(p.shareIndex) && (p.shareIndex as number) >= 0 && (p.shareIndex as number) < SHARE_TOTAL &&
    typeof p.encryptedShare === 'string' && typeof p.shareIv === 'string' &&
    typeof p.ciphertext === 'string' && typeof p.cipherIv === 'string' &&
    typeof p.createdAt === 'number';
}

/**
 * 启动一台「孤岛」中继。每次调用都创建全新的 rooms / peers 状态，
 * 调用 N 次 = N 台互不通信的服务器（测试正是这样模拟 5 台物理机的）。
 */
export async function startRelayServer(options: RelayServerOptions = {}): Promise<RelayServerHandle> {
  // 注意：port 允许为 0（由 OS 分配，测试用），listen 后会回读真实端口
  let port = options.port ?? Number(process.env.PORT ?? 3001);
  const host = options.host ?? process.env.HOST ?? '0.0.0.0';
  const ttlMs = options.ttlMs ?? Number(process.env.ROOM_TTL_MS ?? DEFAULT_ROOM_TTL_MS);
  const envIndex = Number(process.env.RELAY_INDEX ?? NaN);
  const relayIndex = options.relayIndex ?? (Number.isInteger(envIndex) ? envIndex : -1);
  const silent = options.silent ?? false;
  /**
   * 【调试开关，默认关闭】DEBUG_FRAMES=1 时把收到的密文包原样写进日志。
   * 只用于验证「中继转发的是密文、不是明文」——日志里不会出现明文、AES 密钥、
   * ECDH 私钥或明文碎片。验证完请关掉并 flush，长期开启会累积元数据
   * （谁在何时发了多长的消息）。本文件依然不 import 任何密码学模块。
   */
  const debugFrames = process.env.DEBUG_FRAMES === '1';

  // ↓↓↓ 每个实例独占的状态，5 个进程/实例之间绝不共享 ↓↓↓
  const rooms = new Map<string, Room>();
  const peerBySocket = new WeakMap<WebSocket, Peer>();

  const log = (...args: unknown[]): void => { if (!silent) console.log(`[relay:${port}]`, ...args); };

  const httpServer: HttpServer = createServer((_req, res) => {
    // 只提供一个不含任何敏感信息的健康检查端点
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ service: 'secrettalk-relay', port, rooms: rooms.size, zeroKnowledge: true }));
  });

  // 附件（语音/图片/文件）随消息密文一起走：base64 后单条最大约 5.7MB，
  // 这里放到 8MB；仍是有界值，避免恶意客户端用超大帧打爆中继内存。
  const wss = new WebSocketServer({ server: httpServer, maxPayload: 8 * 1024 * 1024 });

  /** 向房间内所有（可选的排除者之外）连接发送帧 */
  function broadcast(room: Room, frame: ServerFrame, except?: Peer): void {
    const data = JSON.stringify(frame);
    for (const peer of room.peers) {
      if (peer === except || peer.dead) continue;
      if (peer.ws.readyState === WS_OPEN) {
        try { peer.ws.send(data); } catch { /* 对端正在关闭，交给 close 事件处理 */ }
      }
    }
  }

  function send(peer: Peer, frame: ServerFrame): void {
    if (peer.ws.readyState !== WS_OPEN) return;
    try { peer.ws.send(JSON.stringify(frame)); } catch { /* noop */ }
  }

  function getRoom(roomId: string): Room {
    let room = rooms.get(roomId);
    if (!room) {
      room = { roomId, peers: new Set(), packets: new Map(), ttlTimer: null, expiresAt: 0 };
      rooms.set(roomId, room);
    }
    return room;
  }

  /** 刷新 TTL：先 clearTimeout 旧定时器，再挂新的，杜绝定时器泄漏 */
  function armTtl(room: Room): void {
    if (room.ttlTimer) clearTimeout(room.ttlTimer);
    room.expiresAt = Date.now() + ttlMs;
    room.ttlTimer = setTimeout(() => {
      // TTL 到期只清内存缓存并通知客户端重新登记，不涉及任何密钥
      if (room.ttlTimer) clearTimeout(room.ttlTimer);
      room.ttlTimer = null;
      room.packets.clear();
      for (const peer of room.peers) send(peer, { type: 'room_expired', roomId: room.roomId, via: port });
      rooms.delete(room.roomId);
      log(`房间 ${room.roomId} TTL 到期，缓存已清空`);
    }, ttlMs);
  }

  /**
   * 销毁房间：清 TTL 定时器 → 清空全部暂存密文 → 从内存删除 → 通知仍在的另一方。
   * close 事件、force_exit 指令、进程退出都会走这里，且保证幂等。
   */
  function destroyRoom(roomId: string, reason: ExitReason): void {
    const room = rooms.get(roomId);
    if (!room) return;
    if (room.ttlTimer) clearTimeout(room.ttlTimer);
    room.ttlTimer = null;
    room.packets.clear();
    rooms.delete(roomId);
    // 先通知，再把连接标记为 dead（防止销毁后还有业务帧进入）
    for (const peer of room.peers) {
      peer.dead = true;
      send(peer, { type: 'force_exit', roomId, reason, via: port });
    }
    log(`房间 ${roomId} 已销毁（${reason}）：TTL 定时器与密文缓存均已清空`);
  }

  function removePeerFromRoom(peer: Peer): void {
    const room = rooms.get(peer.roomId);
    if (room) room.peers.delete(peer);
  }

  function handleFrame(peer: Peer, frame: ClientFrame): void {
    // 会话销毁后的连接只接受关闭，其余一律忽略
    if (peer.dead) return;

    switch (frame.type) {
      case 'hello': {
        // 入房只需要「房间号 + 公钥」：网页端已删除 A/B 选择，角色由客户端握手后自行推导，
        // 服务器既不参与分配、也不需要知道谁是 A 谁是 B。
        if (!frame.roomId || typeof frame.publicKey !== 'string') {
          send(peer, { type: 'error', code: 'BAD_HELLO', message: '入房参数不合法' });
          return;
        }
        if (peer.roomId && peer.roomId !== frame.roomId) removePeerFromRoom(peer);
        peer.roomId = frame.roomId;
        peer.publicKeyB64 = frame.publicKey;

        const room = getRoom(frame.roomId);
        const existing = Array.from(room.peers).filter((p) => p !== peer && !p.dead);

        // 【房间容量】会话是两人对聊：同房间已经有两端在线时，第三个连接直接拒绝。
        // 两端只要填同一个房间号即可入房，不再需要「一端 A / 一端 B」的角色约束，
        // 但也因此必须由服务器守住「最多两人」这条边界，避免第三者混入密钥协商。
        if (existing.length >= 2) {
          send(peer, {
            type: 'error', code: 'ROOM_FULL',
            message: '房间内已有两人在线，无法加入：请确认房间号只告知对方一人，或等对方退出后重试。',
          });
          log(`房间 ${frame.roomId} 已满（${existing.length} 人在线），拒绝新连接`);
          return; // 不入房，不下发 welcome
        }

        room.peers.add(peer);
        armTtl(room);

        send(peer, { type: 'welcome', port, roomId: frame.roomId, peerOnline: existing.length > 0 });

        // 公钥交换：本进程只把「看到的公钥」转发给同房间的其他连接，不理解内容。
        // 新来的 peer 拿到房内已有 peer 的公钥；已有 peer 拿到新 peer 的公钥。
        for (const other of existing) {
          send(peer, { type: 'peer_key', roomId: frame.roomId, publicKey: other.publicKeyB64 });
          send(other, { type: 'peer_key', roomId: frame.roomId, publicKey: peer.publicKeyB64 });
        }
        log(`房间 ${frame.roomId}：公钥入房，当前 ${room.peers.size} 条连接`);
        break;
      }

      case 'ping':
        send(peer, { type: 'pong', ts: frame.ts, via: port });
        break;

      case 'pull': {
        // 本进程只返回「自己暂存的那一份」，绝不去别的进程取数据（孤岛语义）
        const room = getRoom(frame.roomId);
        const packets = Array.from(room.packets.values());
        send(peer, { type: 'cached', packets, via: port });
        armTtl(room);
        break;
      }

      case 'cipher': {
        const packet = frame.packet;
        if (!isCipherPacket(packet)) {
          send(peer, { type: 'error', code: 'BAD_PACKET', message: '密文包结构不合法' });
          return;
        }
        // 路由正确性检查（非密码学）：第 i 个碎片必须投到第 i 台中继。
        // 这只是防止客户端配置错端口，服务器并不理解碎片内容。
        if (relayIndex >= 0 && packet.shareIndex !== relayIndex) {
          send(peer, { type: 'error', code: 'WRONG_RELAY', message: `本中继只接受碎片 #${relayIndex}` });
          return;
        }
        if (packet.roomId !== peer.roomId) {
          send(peer, { type: 'error', code: 'ROOM_MISMATCH', message: '房间号不匹配' });
          return;
        }
        const room = getRoom(packet.roomId);
        // 内存暂存 + 转发；TTL 到期或任一方 close 时立即清空
        room.packets.set(`${packet.messageId}#${packet.shareIndex}`, packet);
        armTtl(room);
        if (debugFrames) {
          // 仅调试：这里打印的就是将要转发的那份 base64 密文，服务器自己解不开
          log(`[debug] 密文包 room=${packet.roomId} msg=${packet.messageId} from=${packet.from} #${packet.shareIndex}（字段均为 base64，中继无解密能力）`);
          log(`[debug] ${JSON.stringify(packet)}`);
        }
        broadcast(room, { type: 'cipher', packet, via: port }, peer);
        break;
      }

      case 'ack': {
        // 已读回执：原样转发 messageId，服务器不知道「读」的是什么内容
        const room = rooms.get(frame.roomId);
        if (!room) return;
        broadcast(room, { type: 'ack', roomId: frame.roomId, messageId: frame.messageId, via: port }, peer);
        break;
      }

      case 'force_exit': {
        // 收到任一方的退出指令：立刻清本进程缓存，并通知另一方
        destroyRoom(frame.roomId, frame.reason);
        break;
      }
    }
  }

  wss.on('connection', (socket: AliveWebSocket) => {
    socket.isAlive = true;
    const peer: Peer = { ws: socket, roomId: '', publicKeyB64: '', dead: false };
    peerBySocket.set(socket, peer);

    socket.on('pong', () => { socket.isAlive = true; });

    socket.on('message', (raw) => {
      let frame: unknown;
      try { frame = JSON.parse(raw.toString()); }
      catch {
        send(peer, { type: 'error', code: 'BAD_JSON', message: '无法解析的帧' });
        return;
      }
      if (!isClientFrame(frame)) {
        send(peer, { type: 'error', code: 'UNKNOWN_FRAME', message: '不支持的帧类型' });
        return;
      }
      handleFrame(peer, frame);
    });

    socket.on('close', () => {
      const p = peerBySocket.get(socket);
      if (!p || !p.roomId) return;
      if (p.dead) return; // 已由 force_exit 销毁过，幂等返回
      removePeerFromRoom(p);
      // 【需求】任意一方 close → 立即清空该 roomId 的 TTL 缓存 + 通知另一方
      destroyRoom(p.roomId, 'peer_disconnect');
    });

    socket.on('error', () => { /* close 事件会紧接着触发，统一在那里清理 */ });
  });

  // 服务端 ws 原生 ping 探测：识别半开连接（浏览器会自动回 pong 帧）
  const pingTimer = setInterval(() => {
    for (const socket of wss.clients as Set<AliveWebSocket>) {
      if (socket.isAlive === false) { socket.terminate(); continue; }
      socket.isAlive = false;
      try { socket.ping(); } catch { socket.terminate(); }
    }
  }, SERVER_PING_INTERVAL_MS);

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(port, host, () => resolve());
  });

  // port: 0 时回读 OS 实际分配的端口（否则 via / handle.port 会一直是 0）
  const address = httpServer.address();
  if (typeof address === 'object' && address !== null) port = address.port;

  log(`零知识中继已启动 ws://${host}:${port}（碎片下标 ${relayIndex}，TTL ${ttlMs}ms）`);
  if (debugFrames) log('⚠ DEBUG_FRAMES=1 已开启：收到的密文包会写入日志（仅限调试，用完请关闭并 flush）');

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    clearInterval(pingTimer);
    // 进程退出前清空所有 TTL 定时器与密文缓存
    for (const roomId of Array.from(rooms.keys())) destroyRoom(roomId, 'ttl_expired');
    for (const socket of wss.clients) socket.terminate();
    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    log('已关闭');
  };

  return { port, relayIndex, rooms, wss, close };
}

/* ========================================================================== *
 * 直接运行时（PM2 / tsx / node dist/server/server.js）：从 env 读取 PORT
 * 被测试 import 时不会自动启动，避免占用端口。
 *
 * 【PM2 坑】fork 模式由 PM2 自己的 ProcessContainer 加载脚本，
 * 此时 process.argv[1] 指向 PM2 内部 wrapper 而非本文件，
 * 仅靠 import.meta.url 判断会误判成「被 import」，导致 startRelayServer()
 * 根本不执行：进程显示 online、零重启、日志全空、端口无监听。
 * 因此 ecosystem.config.cjs 显式注入 SECRETTALK_AUTOSTART=1 作为兜底，
 * 由部署配置明确声明「这是要独立运行的进程」，不再依赖 argv 的偶然性。
 * ========================================================================== */
const isDirectRun = Boolean(process.argv[1]) && pathToFileURL(process.argv[1]!).href === import.meta.url;
const autostartByEnv = process.env.SECRETTALK_AUTOSTART === '1';
if (isDirectRun || autostartByEnv) {
  const handle = await startRelayServer();
  const shutdown = async (): Promise<void> => {
    await handle.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
