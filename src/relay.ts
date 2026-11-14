/**
 * 密语 SecretTalk · 前端 WebSocket 多路连接管理（relay.ts）
 * ===========================================================================
 * 解决的核心问题：
 *   1. 同时与 5 个「互不通信的孤岛进程」建立 WebSocket，任何一路都不依赖另一路；
 *   2. 第 i 个 SSS 碎片严格只发往第 i 台服务器（RELAY_PORTS[i]）；
 *   3. 按 messageId 聚合碎片，任意 3 片到达即重组解密，绝不混用不同消息的碎片；
 *   4. 解密成功广播 ACK（含 messageId），发送端去重后把 UI 更新为「已读」；
 *   5. 任一方退出 / 断线 / 心跳超时 → force_exit 广播 + 本地密钥 0 覆写 + 清定时器；
 *   6. beforeunload 兜底清理，服务器 close 事件作为最终一致性保障。
 *
 * 【为什么需要 socketFactory】浏览器 WebSocket 与 Node 的 ws 实现略有差异，
 * 注入工厂后可直接在 Vitest 里拉起 5 台真实服务器跑端到端集成测试。
 */
import {
  SHARE_TOTAL,
  SHARE_THRESHOLD,
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_TIMEOUT_MS,
  createMessageId,
  type CipherPacket,
  type ClientFrame,
  type ExitReason,
  type Role,
  type ServerFrame,
} from '../shared/protocol.js';
import { CryptoSession, SecretTalkError, toB64, type DecryptedMessage, type OutgoingAttachment } from './crypto.js';
import type { AttachmentKind } from '../shared/protocol.js';

/** 与浏览器 WebSocket / ws 库都兼容的最小接口 */
export interface WebSocketLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((e: unknown) => void) | null;
  onmessage: ((e: { data: unknown }) => void) | null;
  onclose: ((e: unknown) => void) | null;
  onerror: ((e: unknown) => void) | null;
}

const WS_OPEN = 1;
const COLLECTOR_TTL_MS = 60_000; // 未凑齐 3 片的碎片最多在内存里停留 60 秒

export type RelayStatus = 'idle' | 'connecting' | 'online' | 'destroyed';
export type MessageStatus = 'sending' | 'sent' | 'read' | 'failed';

export interface LinkState {
  index: number;
  url: string;
  connected: boolean;
  lastPongAt: number;
}

export interface MessageView {
  messageId: string;
  text: string;
  from: Role;
  ts: number;
  status: MessageStatus;
  /** 接收端实际用于重组的碎片下标，例如 [0,2,4] */
  usedShares?: number[];
  /** 错误消息 */
  error?: string;
  /** 语音 / 图片 / 文件附件（url 为可直接用于 img/audio/a 的 data URL） */
  attachment?: {
    kind: AttachmentKind;
    name: string;
    mime: string;
    size: number;
    url: string;
  };
}

export interface RelayEvents {
  onStatus?: (status: RelayStatus, connected: number, total: number) => void;
  onLinks?: (links: LinkState[]) => void;
  /**
   * 握手完成后告知本端方向标签（A/B）。
   * 该标签由双方公钥字典序在本地推导，用户无需选择，也不会出现「两端都选 A」的冲突。
   */
  onRole?: (role: Role) => void;
  onPeerReady?: (safetyNumber: string) => void;
  onMessage?: (message: MessageView) => void;
  onMessageStatus?: (messageId: string, status: MessageStatus) => void;
  onDestroyed?: (reason: ExitReason) => void;
  onError?: (error: Error) => void;
  /** 链路日志，方便在手机上一眼看出 5 路各自的状态 */
  onLog?: (line: string) => void;
}

export interface RelayConfig {
  /** 两端填同一个房间号即可入房 —— 不再需要选择 A / B 角色 */
  roomId: string;
  /** 地址池，长度必须等于 SHARE_TOTAL(5)；下标 i 对应第 i 个碎片 */
  servers: string[];
  /**
   * 严格自毁（默认 true，符合需求「任意一方退出或断开，会话即刻销毁」）：
   * 5 路中任意一条连接断开，立即触发全局 force_exit。
   * 若改成 false，则只在「所有路都断开」时才销毁，可用性更高但安全性略降。
   */
  strictExitOnAnyClose?: boolean;
  heartbeatIntervalMs?: number;
  heartbeatTimeoutMs?: number;
  socketFactory?: (url: string) => WebSocketLike;
}

export class RelayClient {
  readonly roomId: string;
  readonly servers: string[];
  readonly session: CryptoSession;

  /**
   * 本端方向标签（A/B）。握手前为 null —— 它不是用户选项，
   * 而是双方交换公钥后各自按字典序比较得出的结果（见 CryptoSession.determineOwnRole）。
   */
  private selfRole: Role | null = null;

  private sockets: Array<WebSocketLike | null> = [];
  private links: LinkState[] = [];
  private events: RelayEvents;
  private strict: boolean;
  private hbIntervalMs: number;
  private hbTimeoutMs: number;
  private factory: (url: string) => WebSocketLike;

  /** 5 台孤岛几乎同时转发同一把对端公钥，用该标志保证握手（含角色推导）只执行一次 */
  private handshaking = false;
  /** 接收端：按 messageId 聚合来自不同孤岛的碎片 */
  private collector = new Map<string, CipherPacket[]>();
  private collectorTimers = new Map<string, ReturnType<typeof setTimeout>>();
  /** 正在解密 / 已解密的消息，防止 5 路同时到达造成重复解密与重复 ACK */
  private decrypting = new Set<string>();
  /** 发送端：ACK 去重（接收端会向 5 路各发一份回执） */
  private acked = new Set<string>();
  /** 本地消息表，仅用于状态回显 */
  private outbound = new Map<string, MessageView>();

  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private watchdogTimer: ReturnType<typeof setInterval> | null = null;
  private lifecycleBound = false;
  private beforeUnloadHandler: (() => void) | null = null;
  private pageHideHandler: (() => void) | null = null;
  private visibilityHandler: (() => void) | null = null;
  private pageshowHandler: (() => void) | null = null;
  /** 上次看门狗执行时间：用于识别浏览器节流 / 设备休眠造成的定时器中断 */
  private lastWatchdogTick = 0;
  /** 主动关闭标志：防止自己 close() 触发 onclose 后又反过来广播 force_exit，形成风暴 */
  private intentionalClose = false;
  private destroyed = false;
  private status: RelayStatus = 'idle';
  /** 「等待对端」提示定时器：进入会话后迟迟等不到另一端时给出可操作的提示 */
  private peerWaitTimer: ReturnType<typeof setTimeout> | null = null;

  private constructor(cfg: RelayConfig, events: RelayEvents, session: CryptoSession) {
    if (cfg.servers.length !== SHARE_TOTAL) {
      throw new SecretTalkError(`服务器地址池必须恰好 ${SHARE_TOTAL} 个，当前 ${cfg.servers.length} 个`, 'BAD_POOL');
    }
    this.roomId = cfg.roomId;
    this.servers = cfg.servers;
    this.events = events;
    this.session = session;
    this.strict = cfg.strictExitOnAnyClose ?? true;
    this.hbIntervalMs = cfg.heartbeatIntervalMs ?? HEARTBEAT_INTERVAL_MS;
    this.hbTimeoutMs = cfg.heartbeatTimeoutMs ?? HEARTBEAT_TIMEOUT_MS;
    this.factory = cfg.socketFactory ?? ((url) => new WebSocket(url) as unknown as WebSocketLike);
    this.sockets = new Array(SHARE_TOTAL).fill(null);
    this.links = cfg.servers.map((url, index) => ({ index, url, connected: false, lastPongAt: Date.now() }));
  }

  /** 创建会话：先生成 ECDH 密钥对，再同时拨通 5 条链路（角色在握手后自动确定） */
  static async create(cfg: RelayConfig, events: RelayEvents = {}): Promise<RelayClient> {
    const session = await CryptoSession.create(cfg.roomId);
    const client = new RelayClient(cfg, events, session);
    client.connect();
    client.bindLifecycle();
    client.startHeartbeat();

    // 【防呆】链路全通但迟迟等不到对端时，明确告诉用户该检查什么。
    // 之前这里是「静默死等」：房间号不一致 / 两端选了相同角色时毫无提示，
    // 用户只看到 5 个链路格子全亮，却永远出不来安全数。
    client.peerWaitTimer = setTimeout(() => {
      client.peerWaitTimer = null;
      if (!client.destroyed && client.session.safetyNumber === null) {
        client.events.onError?.(new SecretTalkError(
          '已连上全部中继，但 15 秒内未检测到对端。请逐项检查：' +
          '① 对方已点「进入会话」；② 两端房间号完全一致（建议用「复制」按钮发给对方粘贴）。',
          'WAITING_PEER',
        ));
      }
    }, 15_000);
    // 不让该提示定时器阻塞测试进程退出
    (client.peerWaitTimer as unknown as { unref?: () => void }).unref?.();
    return client;
  }

  get currentStatus(): RelayStatus { return this.status; }
  get linkStates(): LinkState[] { return this.links.map((l) => ({ ...l })); }
  get safetyNumber(): string | null { return this.session.safetyNumber; }
  get isDestroyed(): boolean { return this.destroyed; }
  /** 本端方向标签：握手完成前为 null（房间号匹配即可入房，无需用户选择） */
  get role(): Role | null { return this.selfRole; }

  private log(line: string): void { this.events.onLog?.(line); }
  private emitStatus(): void {
    const n = this.links.filter((l) => l.connected).length;
    this.events.onStatus?.(this.status, n, SHARE_TOTAL);
    this.events.onLinks?.(this.linkStates);
  }

  /* ====================================================================== *
   * 一、并发建立 5 条独立 WebSocket
   * ====================================================================== */
  private connect(): void {
    if (this.destroyed) return;
    this.status = 'connecting';
    this.emitStatus();

    this.servers.forEach((url, index) => {
      let ws: WebSocketLike;
      try {
        ws = this.factory(url);
      } catch (e) {
        this.log(`[链路 ${index}] 创建失败：${(e as Error).message}`);
        this.events.onError?.(e as Error);
        return;
      }
      this.sockets[index] = ws;
      /**
       * 浏览器 WebSocket 默认 binaryType='blob'：只要中间层把 JSON 帧转成二进制帧
       * （老版本网关就是这么转发 Buffer 的），onmessage 拿到的就是 Blob，
       * 下面的 JSON.parse 必然失败 —— 表现为握手永不完成、pong 收不到、心跳超时。
       * 强制成 arraybuffer 后可以直接同步按 UTF-8 解码，不依赖对端帧类型。
       */
      try { (ws as unknown as { binaryType?: string }).binaryType = 'arraybuffer'; } catch { /* 只读实现，忽略 */ }

      ws.onopen = () => {
        if (this.destroyed) { ws.close(); return; }
        this.links[index].connected = true;
        this.links[index].lastPongAt = Date.now();
        this.log(`[链路 ${index}] 已连接 ${url}`);
        // 每路都独立入房并携带本端 ECDH 公钥；5 个孤岛各自完成自己进程内的公钥转发。
        // 房间号就是唯一凭证：两端填同一个房间号即可入房，无需选择 A / B。
        this.sendOn(index, { type: 'hello', roomId: this.roomId, publicKey: this.session.getPublicKeyB64() });
        // 角色未确定时无法判断碎片属于谁，先不 pull；握手完成后由 pullCached() 统一补拉
        // （A 可能先于 B 发消息，B 必须把自己那一路暂存的碎片取回来）。
        if (this.selfRole !== null) this.sendOn(index, { type: 'pull', roomId: this.roomId });
        if (this.links.every((l) => l.connected) && this.status !== 'online') {
          this.status = 'online';
          this.log('5 条链路全部就绪，会话进入可用状态');
        }
        this.emitStatus();
      };

      ws.onmessage = (e) => {
        const d = e.data;
        // 文本帧（正常情况）
        if (typeof d === 'string') { this.handleRawText(index, d); return; }
        // 二进制帧：ArrayBuffer（binaryType='arraybuffer'）/ 某些实现给的 Uint8Array
        if (d instanceof ArrayBuffer) { this.handleRawText(index, new TextDecoder().decode(d)); return; }
        if (d instanceof Uint8Array) { this.handleRawText(index, new TextDecoder().decode(d)); return; }
        // 兜底：仍是 Blob（旧网关 + 未成功设置 binaryType 的环境），异步读取后解析
        if (typeof Blob !== 'undefined' && d instanceof Blob) {
          void d.text()
            .then((t) => this.handleRawText(index, t))
            .catch(() => this.log(`[链路 ${index}] 二进制帧读取失败，已丢弃`));
          return;
        }
        this.handleRawText(index, String(d));
      };

      ws.onerror = () => {
        // 浏览器不暴露具体错误，交给 onclose 统一处理自毁逻辑
        this.log(`[链路 ${index}] 发生错误`);
      };

      ws.onclose = () => {
        if (this.destroyed) return;
        this.links[index].connected = false;
        this.sockets[index] = null;
        this.emitStatus();
        if (this.intentionalClose) return;
        this.log(`[链路 ${index}] 断开`);
        const anyAlive = this.links.some((l) => l.connected);
        // 建立阶段若某路「秒失败」，其他路可能还在 CONNECTING；
        // 此时不能误判为「全部断开」，否则非严格模式下会把刚要握手的会话杀掉。
        const anyConnecting = this.sockets.some((s) => s && s.readyState === 0);
        // 严格模式：任意一路断开即视为「参与方离线」，立刻全局自毁
        // 非严格模式：仅当 5 路全断且无连接中的链路时才自毁（容忍单台中继抖动）
        if (this.strict || (!anyAlive && !anyConnecting)) {
          void this.forceExit('peer_disconnect');
        }
      };
    });
  }

  /* ====================================================================== *
   * 二、帧处理
   * ====================================================================== */
  /** 文本 / 二进制帧解码后的统一入口 */
  private handleRawText(index: number, text: string): void {
    let frame: ServerFrame;
    try { frame = JSON.parse(text) as ServerFrame; }
    catch { this.log(`[链路 ${index}] 收到无法解析的帧，已丢弃`); return; }
    void this.handleFrame(index, frame);
  }

  private async handleFrame(index: number, frame: ServerFrame): Promise<void> {
    if (this.destroyed) return;
    try {
      switch (frame.type) {
        case 'welcome':
          this.log(`[链路 ${index}] 入房成功，对端在线=${frame.peerOnline}`);
          break;

        case 'peer_key': {
          if (frame.roomId !== this.roomId) break;
          // 角色已确定后会继续收到「同一把对端公钥」的重复转发（5 台孤岛各一次），
          // 以及可能的第三端公钥 —— 一律忽略：本会话只有两个参与者。
          if (this.selfRole !== null) break;
          // 5 条链路的消息处理是并发的：只让第一个 peer_key 走完握手，避免重复推导 / 重复 pull
          if (this.handshaking) break;
          this.handshaking = true;
          try {
            // 5 个孤岛会各自转发一次同样的公钥，CryptoSession 内部按字节幂等去重
            const first = await this.session.setPeerPublicKeyB64(frame.publicKey);
            if (!first) break;
            // 双方公钥就绪 → 各自在本地比较字典序，必然得出相反的角色，无需任何中心分配
            const role = this.session.determineOwnRole();
            this.session.setRole(role);
            this.selfRole = role;
            if (this.peerWaitTimer) { clearTimeout(this.peerWaitTimer); this.peerWaitTimer = null; }
            this.log(`ECDH 握手完成，本端为 ${role} 端，安全数 ${this.session.safetyNumber}（请与对方线下核对）`);
            this.events.onRole?.(role);
            this.events.onPeerReady?.(this.session.safetyNumber!);
            // 角色确定后才能安全地接收缓存碎片：现在把 5 台孤岛各自的暂存包拉回来
            this.pullCached();
          } finally {
            this.handshaking = false;
          }
          break;
        }

        case 'cipher':
          this.collectPacket(frame.packet, index);
          break;

        case 'cached':
          for (const p of frame.packets) this.collectPacket(p, index);
          break;

        case 'ack': {
          // 对方解密成功后向 5 路都发 ACK，本端会收到 5 份，按 messageId 去重后只更新一次 UI。
          // 只有「本端确实发出过的消息」才更新状态，避免把别人的回执错记到自己头上。
          if (frame.roomId !== this.roomId) break;
          if (this.acked.has(frame.messageId)) break;
          if (!this.outbound.has(frame.messageId)) break;
          this.acked.add(frame.messageId);
          const m = this.outbound.get(frame.messageId)!;
          m.status = 'read';
          this.log(`消息 ${frame.messageId.slice(0, 8)}… 已读（经 ${frame.via} 端口回执）`);
          this.events.onMessageStatus?.(frame.messageId, 'read');
          break;
        }

        case 'pong':
          this.links[index].lastPongAt = Date.now();
          break;

        case 'force_exit':
          // 对端退出 / 服务器侦测到某方 close：本地立即销毁，不再回广播，避免指令风暴
          this.log(`收到 force_exit（${frame.reason}，来自 ${frame.via} 端口），立即销毁会话`);
          this.destroyLocal(frame.reason);
          break;

        case 'room_expired':
          // TTL 到期只是服务器清了内存房间，重新入房 + 拉取即可；已销毁的会话不处理
          this.log(`[链路 ${index}] 房间 TTL 到期，重新登记`);
          this.sendOn(index, { type: 'hello', roomId: this.roomId, publicKey: this.session.getPublicKeyB64() });
          if (this.selfRole !== null) this.sendOn(index, { type: 'pull', roomId: this.roomId });
          break;

        case 'error':
          this.events.onError?.(new SecretTalkError(frame.message, frame.code));
          break;
      }
    } catch (e) {
      this.events.onError?.(e as Error);
    }
  }

  /** 收集一个碎片包，凑够门限即触发重组解密 */
  private collectPacket(packet: CipherPacket, index: number): void {
    if (this.destroyed || this.session.isDestroyed) return;
    // 方向未确定前无法判断碎片归属，先不收集；握手完成后会统一 pull 一次补回
    if (this.selfRole === null) return;
    if (packet.roomId !== this.roomId || packet.from === this.selfRole) return;
    // 防御：某个孤岛发来不属于它下标的碎片（可能是恶意中继），直接拒绝
    if (packet.shareIndex !== index) {
      this.log(`[链路 ${index}] 碎片下标 ${packet.shareIndex} 与端口不匹配，已丢弃`);
      this.events.onError?.(new SecretTalkError('碎片与中继端口下标不匹配，已拒绝', 'SHARE_INDEX_MISMATCH'));
      return;
    }
    if (this.decrypting.has(packet.messageId)) return;

    const list = this.collector.get(packet.messageId) ?? [];
    if (!list.some((p) => p.shareIndex === packet.shareIndex)) list.push(packet);
    this.collector.set(packet.messageId, list);

    // 每个未完成的 messageId 都挂一个回收定时器，防止碎片无限堆积造成内存泄漏
    if (!this.collectorTimers.has(packet.messageId)) {
      this.collectorTimers.set(packet.messageId, setTimeout(() => {
        this.clearCollector(packet.messageId);
        this.log(`消息 ${packet.messageId.slice(0, 8)}… 碎片等待超时，已清理`);
      }, COLLECTOR_TTL_MS));
    }

    this.log(`[链路 ${index}] 收到碎片 #${packet.shareIndex}（${packet.messageId.slice(0, 8)}…），累计 ${list.length}/${SHARE_THRESHOLD}`);
    if (list.length >= SHARE_THRESHOLD) void this.decryptAndAck(packet.messageId, list.slice());
  }

  /** SSS 重组 + AES-GCM 完整性校验 + 已读回执 */
  private async decryptAndAck(messageId: string, packets: CipherPacket[]): Promise<void> {
    if (this.decrypting.has(messageId) || this.destroyed) return;
    this.decrypting.add(messageId);
    try {
      const result: DecryptedMessage = await this.session.tryDecrypt(packets, messageId);
      // 只有「解密 + tag 校验 + 明文封装校验」全部通过，才认为消息可信并展示
      this.events.onMessage?.({
        messageId, text: result.text, from: result.from, ts: result.ts,
        status: 'read', usedShares: result.usedShares,
        ...(result.attachment
          ? { attachment: { ...result.attachment, url: `data:${result.attachment.mime};base64,${result.attachment.data}` } }
          : {}),
      });
      this.log(`解密成功：由碎片 ${result.usedShares.join(' / ')} 重组，广播已读回执`);

      // ACK 带 messageId，向 5 路都发：发送端连着全部 5 路，任意一路通就能收到回执
      this.broadcast({ type: 'ack', roomId: this.roomId, messageId, to: result.from });
    } catch (e) {
      // 校验失败绝不 ACK、绝不展示明文，并把原因明确抛给 UI
      this.log(`解密/完整性校验失败：${(e as Error).message}`);
      this.events.onError?.(e as Error);
      this.events.onMessage?.({ messageId, text: '', from: this.otherRole(), ts: Date.now(), status: 'failed', error: (e as Error).message });
    } finally {
      this.clearCollector(messageId);
      this.decrypting.delete(messageId);
    }
  }

  private clearCollector(messageId: string): void {
    this.collector.delete(messageId);
    const t = this.collectorTimers.get(messageId);
    // 【内存防泄漏】必须 clearTimeout，否则定时器会一直持有碎片的闭包引用
    if (t) clearTimeout(t);
    this.collectorTimers.delete(messageId);
  }

  /* ====================================================================== *
   * 三、发送端：加密 → 5 片 → 按索引分发到 5 个端口
   * ====================================================================== */
  async send(text: string, attachment?: OutgoingAttachment): Promise<string> {
    if (this.destroyed) throw new SecretTalkError('会话已销毁，无法发送', 'SESSION_DESTROYED');
    if (!this.session.hasPeerKey || this.selfRole === null) throw new SecretTalkError('双方 ECDH 握手尚未完成，请等待对方上线', 'NO_PEER_KEY');

    const messageId = createMessageId();
    const view: MessageView = {
      messageId, text, from: this.selfRole, ts: Date.now(), status: 'sending',
      ...(attachment
        ? {
          attachment: {
            kind: attachment.kind,
            name: attachment.name,
            mime: attachment.mime,
            size: attachment.bytes.length,
            url: `data:${attachment.mime};base64,${toB64(attachment.bytes)}`,
          },
        }
        : {}),
    };
    this.outbound.set(messageId, view);
    // 传副本：状态变更一律通过 onMessageStatus 显式通知，
    // 绝不静默修改已交给 UI 的对象引用（否则 React 之外的订阅者会拿到脏数据）。
    this.events.onMessage?.({ ...view });

    try {
      const packets = await this.session.encryptMessage(text, messageId, attachment);
      if (packets.length !== SHARE_TOTAL) throw new SecretTalkError('碎片生成数量异常', 'SSS_SPLIT');
      let delivered = 0;
      for (let i = 0; i < SHARE_TOTAL; i++) {
        // 关键约束：第 i 片只发往 servers[i]，任一服务器永远只持有 1 片
        if (this.sendOn(i, { type: 'cipher', packet: packets[i] })) delivered++;
      }
      if (delivered === 0) throw new SecretTalkError('5 条中继链路均不可用，消息未发出', 'NO_RELAY');
      view.status = 'sent';
      this.events.onMessageStatus?.(messageId, 'sent');
      this.log(`消息 ${messageId.slice(0, 8)}… 已加密并分发 ${delivered}/${SHARE_TOTAL} 个碎片`);
      return messageId;
    } catch (e) {
      view.status = 'failed';
      view.error = (e as Error).message;
      this.events.onMessageStatus?.(messageId, 'failed');
      throw e;
    }
  }

  /* ====================================================================== *
   * 四、发送原语
   * ====================================================================== */
  private sendOn(index: number, frame: ClientFrame): boolean {
    if (this.destroyed) return false;
    const ws = this.sockets[index];
    if (!ws || ws.readyState !== WS_OPEN || !this.links[index].connected) return false;
    try { ws.send(JSON.stringify(frame)); return true; }
    catch { return false; }
  }

  private broadcast(frame: ClientFrame): number {
    let n = 0;
    for (let i = 0; i < SHARE_TOTAL; i++) if (this.sendOn(i, frame)) n++;
    return n;
  }

  /**
   * 向 5 台孤岛各自拉取暂存碎片（每台只返回自己那一份）。
   * 只在角色确定后调用：此前无法区分「自己发的碎片」与「对端发的碎片」。
   */
  private pullCached(): void {
    this.broadcast({ type: 'pull', roomId: this.roomId });
  }

  /** 对端的方向标签：会话固定两人，一端为 A 时另一端必为 B */
  private otherRole(): Role {
    return this.selfRole === 'B' ? 'A' : 'B';
  }

  /* ====================================================================== *
   * 五、心跳保活（应用层 ping/pong + 死链看门狗）
   * ====================================================================== */
  private startHeartbeat(): void {
    // 浏览器 WebSocket 无法主动发送 ping 控制帧，故使用应用层 JSON 心跳；
    // 服务端另外用 ws 原生 ping 帧做死连接探测，二者互为补充。
    this.heartbeatTimer = setInterval(() => {
      if (this.destroyed) return;
      this.pingAll();
    }, this.hbIntervalMs);

    const tickMs = Math.max(1000, Math.floor(this.hbIntervalMs / 2));
    this.lastWatchdogTick = Date.now();
    this.watchdogTimer = setInterval(() => {
      if (this.destroyed) return;
      const now = Date.now();
      const gap = now - this.lastWatchdogTick;
      this.lastWatchdogTick = now;

      // 【关键】页面在后台（切到别的标签页 / 手机息屏）时，浏览器会把定时器节流到
      // 秒级甚至分钟级：ping 发不出去，「18 秒没有 pong」完全不能证明链路已死。
      // 旧实现在这里把健康会话判成 heartbeat_timeout，再广播 force_exit 把前台那
      // 一端一起杀掉 —— 这正是「连上没多久就提示心跳超时」的根因（后端日志里也
      // 能看到改动前就有同样的记录）。后台一律不判死：真正的断线交给服务器
      // ws 原生 ping 超时与 close 事件兜底，那时浏览器会正常收到 onclose。
      if (typeof document !== 'undefined' && document.hidden) {
        this.resetHeartbeatBaseline();
        return;
      }

      // 定时器被系统休眠 / 标签页冻结打断：本次观测同样不可信，重置基线并补发一次 ping
      if (gap > tickMs * 3) {
        this.resetHeartbeatBaseline();
        this.pingAll();
        this.log(`检测到心跳定时器中断 ${Math.round(gap / 1000)} 秒（休眠/冻结），已重置判定基线`);
        return;
      }

      const dead = this.links.filter((l) => l.connected && now - l.lastPongAt > this.hbIntervalMs + this.hbTimeoutMs);
      if (dead.length) {
        this.log(`链路 ${dead.map((d) => d.index).join(',')} 心跳超时，判定会话已断`);
        void this.forceExit('heartbeat_timeout');
      }
    }, tickMs);
  }

  /** 向 5 路各发一次应用层心跳 */
  private pingAll(): void {
    const ts = Date.now();
    for (let i = 0; i < SHARE_TOTAL; i++) this.sendOn(i, { type: 'ping', ts });
  }

  /**
   * 重建心跳基线：把所有在线链路的 lastPongAt 重置为「现在」。
   * 用于定时器被节流/冻结、或页面从后台/往返缓存恢复之后 —— 这段空窗期的沉默
   * 并不能证明链路已死，直接沿用旧时间戳只会误杀健康会话。
   */
  private resetHeartbeatBaseline(): void {
    const now = Date.now();
    this.lastWatchdogTick = now;
    for (const link of this.links) if (link.connected) link.lastPongAt = now;
  }

  /* ====================================================================== *
   * 六、生命周期自毁
   * ====================================================================== */
  /** 绑定页面卸载钩子：刷新/关闭标签页时兜底清理 */
  private bindLifecycle(): void {
    if (typeof window === 'undefined' || this.lifecycleBound) return;
    this.lifecycleBound = true;
    this.beforeUnloadHandler = () => {
      // 尽力广播（页面卸载时不保证送达），服务器侧的 close 事件是最终保障
      this.broadcast({ type: 'force_exit', roomId: this.roomId, reason: 'beforeunload' });
      this.destroyLocal('beforeunload');
    };
    this.pageHideHandler = () => {
      if (!this.destroyed) this.destroyLocal('beforeunload');
    };
    // 【后台/息屏恢复】隐藏期间定时器被浏览器节流，沉默时间不能当作断线证据。
    // 回到前台时先重建基线并立即补一次 ping，避免「刚切回来就心跳超时」。
    this.visibilityHandler = () => {
      if (this.destroyed) return;
      if (typeof document !== 'undefined' && document.hidden) return;
      this.resetHeartbeatBaseline();
      this.pingAll();
      this.log('页面恢复可见，心跳判定已重建基线');
    };
    // bfcache 往返恢复：同样可能跨越很长的时间，需要重建基线
    this.pageshowHandler = () => {
      if (this.destroyed) return;
      this.resetHeartbeatBaseline();
      this.pingAll();
      this.log('页面从往返缓存恢复，心跳判定已重建基线');
    };
    window.addEventListener('beforeunload', this.beforeUnloadHandler);
    window.addEventListener('pagehide', this.pageHideHandler);
    window.addEventListener('pageshow', this.pageshowHandler);
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', this.visibilityHandler);
    }
    // 注意：手机切后台(visibilitychange)不触发自毁，否则移动端会频繁误杀会话；
    // 真正的断线由心跳超时 + 服务器 close 事件负责。
  }

  private unbindLifecycle(): void {
    if (typeof window === 'undefined') return;
    if (this.beforeUnloadHandler) window.removeEventListener('beforeunload', this.beforeUnloadHandler);
    if (this.pageHideHandler) window.removeEventListener('pagehide', this.pageHideHandler);
    if (this.pageshowHandler) window.removeEventListener('pageshow', this.pageshowHandler);
    if (this.visibilityHandler && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.visibilityHandler);
    }
    this.beforeUnloadHandler = null;
    this.pageHideHandler = null;
    this.pageshowHandler = null;
    this.visibilityHandler = null;
  }

  /** 用户点击「退出」或检测到断线：先广播指令，再彻底销毁本地状态 */
  async forceExit(reason: ExitReason = 'user_logout'): Promise<void> {
    if (this.destroyed) return;
    this.log(`触发 force_exit：${reason}`);
    // 先尽力通知 5 台中继（每台都会清自己的 room 缓存并通知另一方）
    this.broadcast({ type: 'force_exit', roomId: this.roomId, reason });
    this.destroyLocal(reason);
  }

  /** 本地强制销毁：清定时器 → 0 覆写密钥 → 断开引用 → 关连接 */
  private destroyLocal(reason: ExitReason): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.status = 'destroyed';

    // 1) 清所有定时器，防止闭包继续持有碎片/密钥引用
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.watchdogTimer) clearInterval(this.watchdogTimer);
    if (this.peerWaitTimer) clearTimeout(this.peerWaitTimer);
    this.heartbeatTimer = null;
    this.watchdogTimer = null;
    this.peerWaitTimer = null;
    for (const t of this.collectorTimers.values()) clearTimeout(t);
    this.collectorTimers.clear();

    // 2) 【核心】0 覆写 AES 密钥材料与 ECDH 私钥，销毁 CryptoSession
    this.session.destroy();

    // 3) 清空所有内存中的碎片、消息、回执集合
    this.collector.clear();
    this.decrypting.clear();
    this.acked.clear();
    this.outbound.clear();

    // 4) 关闭 5 条连接；intentionalClose 阻止 onclose 再次触发 force_exit 风暴
    this.intentionalClose = true;
    for (let i = 0; i < SHARE_TOTAL; i++) {
      const ws = this.sockets[i];
      if (ws) {
        ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null;
        try { ws.close(1000, 'force_exit'); } catch { /* 已关闭 */ }
      }
      this.sockets[i] = null;
      this.links[i].connected = false;
    }
    this.unbindLifecycle();

    this.log('会话已销毁：密钥已 0 覆写，内存缓存与定时器已清空');
    this.emitStatus();
    this.events.onDestroyed?.(reason);
  }
}
