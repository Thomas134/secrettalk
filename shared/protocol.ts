/**
 * SecretTalk · 共享通信协议（前端 / 中继服务器 / 测试 三方共用的唯一真源）
 * ---------------------------------------------------------------------------
 * 【零知识约束】本文件只定义「报文的形状」，不含任何加解密逻辑。
 * 服务器看到的所有密文字段都是不透明的 base64 字符串，它既不解码、也不校验、
 * 更不尝试解密；base64 在这里仅仅是「二进制 → 文本」的传输编码，不构成安全性。
 */

/* ============================ 全局常量 ============================ */

/** 5 台「物理隔离」的中继服务器端口（本机由 PM2 起 5 个独立进程模拟） */
export const RELAY_PORTS = [3001, 3002, 3003, 3004, 3005] as const;

/** Shamir 门限：n=5 片，任意 k=3 片可还原 AES 密钥 */
export const SHARE_TOTAL = 5;
export const SHARE_THRESHOLD = 3;

/** AES-256-GCM：32 字节密钥 + 12 字节 IV（GCM 标准 IV 长度，16 字节认证标签由 WebCrypto 自动附加在密文尾部） */
export const AES_256_KEY_BYTES = 32;
export const GCM_IV_BYTES = 12;

/** 明文封装魔数：接收端解密成功后二次校验，防止把「别的消息的碎片」错配重组出一个错误但长度合法的密钥 */
export const PLAINTEXT_MAGIC = 'SECRETTALK/V1';

/** 服务器内存房间 TTL（毫秒）：到期即清空，务必配合 clearTimeout */
export const DEFAULT_ROOM_TTL_MS = 5 * 60 * 1000;
/** 客户端应用层心跳周期 / 超时 */
export const HEARTBEAT_INTERVAL_MS = 10_000;
export const HEARTBEAT_TIMEOUT_MS = 8_000;
/** 服务端 ws 原生 ping 探测周期 */
export const SERVER_PING_INTERVAL_MS = 15_000;

/** 附件类型：语音 / 图片 / 普通文件（全部在浏览器内加密后才发出） */
export type AttachmentKind = 'audio' | 'image' | 'file';

/**
 * 单个附件的硬上限（原始字节，未 base64）。
 * 附件会随消息密文一起在 5 台中继各存一份，太大既吃内存又拖慢 5 路分发，
 * 因此客户端强制压缩/拒绝，服务端 maxPayload 也据此放到了 8MB。
 */
export const MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024;

/** 语音录制的最长时长（毫秒），到时自动停止并发送 */
export const MAX_VOICE_MS = 60_000;

/**
 * 会话内的「方向标签」。
 * 【不再由用户选择】网页端已经删掉 A / B 选项：两端只要填同一个房间号即可入房。
 * 双方交换 ECDH 公钥后，各自在本地按「公钥字节字典序」比较：
 * 较小的一端为 A，较大的一端为 B。由于比较的是同一对公钥，
 * 两端必然得出相反且互不冲突的结论，5 台互不通信的孤岛中继也无需协调。
 * 该标签只用于区分消息方向（`from` / `to`），不参与任何密钥派生。
 */
export type Role = 'A' | 'B';

/** 导致会话销毁的原因（用于审计与 UI 提示，不含任何敏感信息） */
export type ExitReason =
  | 'user_logout'          // 用户主动点击退出
  | 'peer_disconnect'      // 对端某条 WebSocket 断开（服务器侦测）
  | 'ttl_expired'          // 房间 TTL 到期
  | 'heartbeat_timeout'    // 心跳超时，判定链路已死
  | 'beforeunload'         // 页面关闭 / 刷新
  | 'integrity_failure';   // 完整性校验失败

/* ============================ 密文包 ============================ */

/**
 * 发送端组装的「碎片 + 消息密文」包。
 * 每一路只持有 1 个碎片（shareIndex 与端口下标一一对应），
 * 而 ciphertext 在 5 路冗余存放 —— 这样 B 收到「任意 3 路」都必然同时拿到密文，可立即重组校验。
 *
 * encryptedShare = AES-256-GCM(KEK, SSS碎片, AAD=roomId|messageId|shareIndex)
 * KEK 由 A/B 的 ECDH 共享秘密经 HKDF 派生，永不落在中继服务器上。
 */
export interface CipherPacket {
  roomId: string;
  messageId: string;
  from: Role;
  /** 0..4，对应 RELAY_PORTS[0..4] */
  shareIndex: number;
  /** base64(加密后的碎片，含 GCM tag) */
  encryptedShare: string;
  /** base64(该碎片独立的 12 字节 IV) */
  shareIv: string;
  /** base64(AES-256-GCM(msgKey, 明文封装)，含 GCM tag) */
  ciphertext: string;
  /** base64(消息密文的 12 字节 IV)，5 路相同 */
  cipherIv: string;
  /** 客户端生成时间戳，服务器只透传、不解释 */
  createdAt: number;
}

/* ============================ 客户端 → 服务器 ============================ */

export type ClientFrame =
  /**
   * 入房登记：携带本端 ECDH 公钥（SPKI / base64）。服务器仅转发，不理解其内容。
   * 注意：不再携带 role —— 两端填同一房间号即可入房，角色由客户端握手后自行推导。
   */
  | { type: 'hello'; roomId: string; publicKey: string }
  /** 应用层心跳（浏览器 WebSocket 无法主动发 ping 帧，故用 JSON 心跳） */
  | { type: 'ping'; ts: number }
  /** 接收端上线后向每台服务器拉取它各自暂存的碎片（服务器是孤岛，只返回自己那份） */
  | { type: 'pull'; roomId: string }
  /** 发送第 i 个碎片包：客户端保证只发往 RELAY_PORTS[i] */
  | { type: 'cipher'; packet: CipherPacket }
  /** 已读回执：B 解密校验成功后发出，服务器原样转发给 A */
  | { type: 'ack'; roomId: string; messageId: string; to: Role }
  /** 强制退出指令：任一方主动退出或断线时向所有服务器广播 */
  | { type: 'force_exit'; roomId: string; reason: ExitReason };

/* ============================ 服务器 → 客户端 ============================ */

export type ServerFrame =
  | { type: 'welcome'; port: number; roomId: string; peerOnline: boolean }
  /** 转发对端 ECDH 公钥（5 个孤岛各自转发一次，客户端按字节幂等去重；角色由客户端自行推导） */
  | { type: 'peer_key'; roomId: string; publicKey: string }
  /** 转发碎片包 */
  | { type: 'cipher'; packet: CipherPacket; via: number }
  /** pull 的响应：本进程暂存的全部碎片包 */
  | { type: 'cached'; packets: CipherPacket[]; via: number }
  /** 转发已读回执 */
  | { type: 'ack'; roomId: string; messageId: string; via: number }
  | { type: 'pong'; ts: number; via: number }
  /** 通知另一方：会话必须立即销毁 */
  | { type: 'force_exit'; roomId: string; reason: ExitReason; via: number }
  | { type: 'room_expired'; roomId: string; via: number }
  | { type: 'error'; code: string; message: string };

/* ============================ 轻量工具 ============================ */

/** 生成房间号：仅由客户端本地随机生成，服务器不负责分配、不参与密钥学过程 */
export function createRoomId(): string {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** 生成消息号 */
export function createMessageId(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** 类型守卫：确保收到的 JSON 至少是受支持的帧，避免畸形包导致服务端异常 */
export function isClientFrame(v: unknown): v is ClientFrame {
  if (!v || typeof v !== 'object') return false;
  const t = (v as { type?: unknown }).type;
  return t === 'hello' || t === 'ping' || t === 'pull' || t === 'cipher' ||
         t === 'ack' || t === 'force_exit';
}
