/**
 * 密语 SecretTalk · 前端密码学核心（crypto.ts）
 * ===========================================================================
 * 混合密码学体系，全部基于浏览器原生 WebCrypto，无任何自研算法：
 *
 *   1) ECDH (P-256)      A/B 各自生成密钥对，交换公钥后 deriveBits 得到 256bit 共享秘密
 *   2) HKDF (SHA-256)    共享秘密 → KEK（碎片包裹密钥），info 绑定 roomId，杜绝跨会话复用
 *   3) AES-256-GCM       ① 用随机 msgKey 加密聊天明文（GCM tag 提供完整性）
 *                        ② 用 KEK 分别加密 5 个 SSS 碎片（每个碎片独立 IV + AAD）
 *   4) Shamir SSS (3,5)  msgKey 拆成 5 片，任意 3 片可还原；单片信息论安全
 *
 * 【零知识边界】以上全部发生在客户端。中继服务器只见到 base64 字符串，
 * 它既没有 ECDH 私钥、也没有 KEK、更拿不到 3 个碎片（每个进程只有 1 片）。
 *
 * 【关于 base64】toB64/fromB64 仅仅是「二进制 ⇄ 文本」的传输编码，
 * 不是加密、不是混淆、不提供任何安全性。客户端收到后必须立刻 fromB64 转回
 * Uint8Array 再交给 WebCrypto；任何把 base64 当安全措施的做法都是错误的。
 *
 * 【关于内存擦除的诚实说明】JavaScript 无法保证物理内存被彻底擦除：
 * V8 GC 可能留下副本、字符串不可变且会被驻留、CryptoKey 内部内存不可从 JS 寻址、
 * 操作系统还可能把页换出到 swap。本模块做到的工程最优是：
 *   · 所有能被 JS 直接寻址的密钥字节（raw AES key、SSS 碎片、ECDH 共享秘密、
 *     导出的 PKCS8 私钥、明文封装）在使用后立刻 fill(0) 覆写；
 *   · 运行时 CryptoKey 全部 extractable:false，永不导出到 JS 堆；
 *   · force_exit 时断开所有 CryptoKey 引用，交给 GC 回收。
 * 生产环境若需要真正的抗取证，请改用 WASM + mlock / 原生客户端 / 禁用 swap，
 * 并把本页放在独立的、退出即销毁的浏览上下文中。
 */
import { split, combine } from 'shamir-secret-sharing';
import {
  AES_256_KEY_BYTES,
  GCM_IV_BYTES,
  SHARE_TOTAL,
  SHARE_THRESHOLD,
  PLAINTEXT_MAGIC,
  MAX_ATTACHMENT_BYTES,
  type AttachmentKind,
  type CipherPacket,
  type Role,
} from '../shared/protocol.js';

/* ========================================================================== *
 * 0. 配置开关
 * ========================================================================== */

/**
 * 是否额外导出一份「可覆写」的 ECDH PKCS8 私钥字节。
 * - true（默认）：严格满足需求「force_exit 时用 0 覆写 ECDH 私钥」。
 *   代价是 JS 堆里多一份私钥副本，但运行时的 CryptoKey 仍是不可导出的。
 * - false：更严格的做法 —— 私钥永不离开 WebCrypto 内部，销毁时只断开引用。
 *   安全性更高，但无法做字节级覆写。
 */
export const WIPE_EXTRACTABLE_PRIVATE_KEY = true;

/** 密码学相关错误的统一类型，便于 UI 精准提示、也便于测试断言 */
export class SecretTalkError extends Error {
  constructor(message: string, readonly code: string = 'CRYPTO_ERROR') {
    super(message);
    this.name = 'SecretTalkError';
  }
}

/* ========================================================================== *
 * 0.1 安全上下文（Secure Context）前置检查
 * ========================================================================== */

/**
 * WebCrypto 的 SubtleCrypto 只在「安全上下文」里存在：
 *   ✅ https://任意域名
 *   ✅ http://localhost 或 http://127.0.0.1（规范把回环地址视为潜在可信）
 *   ❌ http://192.168.x.x、http://<局域网 IP>、http://<普通域名>（明文 HTTP）
 *
 * 在非安全上下文中 window.crypto 对象依然存在，但 crypto.subtle === undefined，
 * 直接调用就会抛出：
 *   "Cannot read properties of undefined (reading 'generateKey')"
 * 这并非代码 bug，而是浏览器对密码学 API 的强制保护 —— 明文 HTTP 下
 * 脚本本身都可能被中间人替换，此时提供加密 API 只会制造虚假的安全感。
 *
 * 注意：绝不能用纯 JS 的 AES/ECDH polyfill「绕过」这个限制来让手机连上，
 * 那等于把密钥暴露在可被注入的页面里，直接摧毁端到端加密的前提。
 * 正确做法是把页面部署到 HTTPS，并让 5 条中继同步升级为 wss://
 * （https 页面连接 ws:// 会被浏览器按混合内容拦截）。
 *
 * @returns 不可用原因（中文，可直接展示给用户）；可用时返回 null
 */
export function webCryptoUnavailableReason(): string | null {
  if (typeof globalThis.crypto === 'undefined') {
    return '当前运行环境未提供 WebCrypto（globalThis.crypto 不存在），无法生成密钥。请使用较新的浏览器，并通过 HTTPS 或 localhost 访问。';
  }
  if (!globalThis.crypto.subtle) {
    const href = typeof location !== 'undefined' ? location.href : '当前页面';
    return (
      `当前页面不是安全上下文，WebCrypto 不可用：${href}。浏览器只允许 https:// ` +
      '或 http://localhost / 127.0.0.1 使用 crypto.subtle。' +
      '请改用 https 访问，或在本机打开 http://localhost:5173；' +
      '手机用局域网 IP 的 http:// 访问时，必须部署 HTTPS，且 5 台中继需同步改为 wss://。'
    );
  }
  return null;
}

/** 所有密码学入口统一前置调用：不安全上下文立即失败，绝不降级 */
function assertWebCrypto(): void {
  const reason = webCryptoUnavailableReason();
  if (reason) throw new SecretTalkError(reason, 'INSECURE_CONTEXT');
}

/* ========================================================================== *
 * 1. Base64 传输编码（仅此用途）
 * ========================================================================== */

/** Uint8Array → base64。分块避免展开超长数组触发调用栈上限 */
export function toB64(bytes: Uint8Array): string {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** base64 → Uint8Array。客户端收到网络数据后的第一件事，绝不把 base64 直接当密钥用 */
export function fromB64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

/** 用 0 覆写所有传入的敏感缓冲区；对不可变/已置空的入参安全跳过 */
export function secureWipe(...buffers: Array<Uint8Array | null | undefined>): void {
  for (const b of buffers) {
    if (b && b.length) b.fill(0);
  }
}

/**
 * TS 5.7+ 起 WebCrypto 的 BufferSource 要求 ArrayBuffer-backed 视图，
 * 而 Uint8Array 的类型参数默认是 ArrayBufferLike（可能指向 SharedArrayBuffer）。
 * 本模块所有待处理字节都是「完整视图」，故这里零拷贝返回底层 ArrayBuffer；
 * 万一遇到 subarray 视图则精确切片，绝不多带一个字节进入加密函数。
 */
function ab(b: Uint8Array): ArrayBuffer {
  const buf = b.buffer;
  if (buf instanceof ArrayBuffer && b.byteOffset === 0 && b.byteLength === buf.byteLength) return buf;
  return buf.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

/** 生成 GCM 标准 12 字节随机 IV（每次加密必须全新，严禁复用） */
function randomIv(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
}

/** 把原始 32 字节导入为不可导出的 AES-GCM CryptoKey */
async function importAesKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ab(raw), { name: 'AES-GCM', length: 256 }, false, usages);
}

/* ========================================================================== *
 * 2. 明文封装（第二层完整性校验）
 * ========================================================================== */

/** 待发送的附件（原始字节，加密前） */
export interface OutgoingAttachment {
  kind: AttachmentKind;
  name: string;
  mime: string;
  bytes: Uint8Array;
}

/** 加密封装里的附件（data 为 base64；随整条消息一起被 AES-GCM 加密） */
interface EnvelopeAttachment {
  kind: AttachmentKind;
  name: string;
  mime: string;
  size: number;
  data: string;
}

interface PlainEnvelope {
  /** 固定魔数：用于识别「用错误密钥碰巧解出合法填充」这类极端情况 */
  magic: string;
  messageId: string;
  roomId: string;
  from: Role;
  ts: number;
  text: string;
  /** 可选附件：语音 / 图片 / 文件，内容以 base64 放在加密信封里 */
  attachment?: EnvelopeAttachment;
}

/**
 * 为什么要封装而不是直接加密用户文本？
 * SSS 对「任意 3 片」都会算出一个 32 字节结果（哪怕碎片来自不同消息），
 * 此时 AES-GCM 解密会因 tag 不匹配而抛错 —— 这本身就是需求要求的完整性校验。
 * 再叠加 magic / messageId / roomId 的显式校验，可以把「碎片错配」与
 * 「密文被篡改」「双方 ECDH 不一致」区分开，给出可诊断的错误。
 */
function encodeEnvelope(env: PlainEnvelope): Uint8Array {
  return utf8(JSON.stringify(env));
}

function parseEnvelope(bytes: Uint8Array): PlainEnvelope | null {
  try {
    const v = JSON.parse(fromUtf8(bytes)) as Partial<PlainEnvelope>;
    if (typeof v.magic !== 'string' || typeof v.messageId !== 'string' ||
        typeof v.roomId !== 'string' || typeof v.text !== 'string' ||
        typeof v.ts !== 'number' || (v.from !== 'A' && v.from !== 'B')) return null;
    // 附件的形状与大小双重校验：对端不可信，超限的 base64 直接拒绝，避免内存被撑爆
    if (v.attachment !== undefined) {
      const a = v.attachment;
      if (!a || typeof a !== 'object') return null;
      if (a.kind !== 'audio' && a.kind !== 'image' && a.kind !== 'file') return null;
      if (typeof a.name !== 'string' || a.name.length > 255) return null;
      if (typeof a.mime !== 'string' || a.mime.length > 100) return null;
      if (typeof a.size !== 'number' || !Number.isFinite(a.size) || a.size < 0) return null;
      if (typeof a.data !== 'string') return null;
      const maxB64 = Math.ceil(MAX_ATTACHMENT_BYTES / 3) * 4 + 8;
      if (a.data.length > maxB64) return null;
      if (a.size > MAX_ATTACHMENT_BYTES) return null;
    }
    return v as PlainEnvelope;
  } catch {
    return null;
  }
}

/* ========================================================================== *
 * 3. ECDH 公钥指纹（SAS 短认证字符串）
 * ========================================================================== */

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/**
 * 计算 6 位安全数，供 A/B 线下口头核对。
 * 【为什么必须有它】零知识中继会转发 ECDH 公钥，若中继被攻陷可实施 MITM
 * （分别和 A、B 协商密钥）。E2EE 的身份验证不能依赖中继，只能靠带外比对：
 * 双方公钥按字典序拼接后取 SHA-256 前 6 位十进制，一致才说明没有中间人。
 */
export async function computeSafetyNumber(pubA: Uint8Array, pubB: Uint8Array): Promise<string> {
  const [x, y] = compareBytes(pubA, pubB) <= 0 ? [pubA, pubB] : [pubB, pubA];
  const joined = new Uint8Array(x.length + y.length);
  joined.set(x, 0);
  joined.set(y, x.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', joined));
  // 取前 5 字节拼成 40bit 整数，再模 10^6，避免浮点精度问题用 BigInt
  let n = 0n;
  for (let i = 0; i < 5; i++) n = (n << 8n) | BigInt(digest[i]);
  const code = (n % 1_000_000n).toString().padStart(6, '0');
  secureWipe(joined, digest);
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

/* ========================================================================== *
 * 4. 会话密钥容器：一个会话 = 一个 CryptoSession 实例
 * ========================================================================== */

export interface DecryptedMessage {
  messageId: string;
  from: Role;
  text: string;
  ts: number;
  /** 实际使用的碎片下标，UI 可显示「由 3001/3003/3005 三路重组」 */
  usedShares: number[];
  /** 附件（data 为 base64，UI 自行拼成 data URL） */
  attachment?: {
    kind: AttachmentKind;
    name: string;
    mime: string;
    size: number;
    data: string;
  };
}

export class CryptoSession {
  /** 本端 ECDH 私钥句柄（extractable:false） */
  private privateKey: CryptoKey | null = null;
  /** 本端 ECDH 公钥 SPKI 字节（公开信息，无需保密，但仍纳入覆写范围） */
  private publicKeyRaw: Uint8Array | null = null;
  /** 需求指定：可覆写的 PKCS8 私钥字节副本 */
  private privateKeyRaw: Uint8Array | null = null;
  /** 对端公钥字节 */
  private peerPublicKeyRaw: Uint8Array | null = null;
  private peerKey: CryptoKey | null = null;
  /** ECDH → HKDF 派生的碎片包裹密钥 */
  private kek: CryptoKey | null = null;
  private safetyNumberCache: string | null = null;
  private destroyed = false;
  /** 本端方向标签：握手后由双方公钥字典序推导，不再由用户选择 */
  private roleValue: Role | null;

  private constructor(readonly roomId: string, role: Role | null = null) {
    this.roleValue = role;
  }

  /**
   * 创建会话并生成 ECDH P-256 密钥对。
   * `role` 仅用于单元测试 / 已知方向的老调用方；正常流程传 null，
   * 等 `determineOwnRole()` 推导出结果后再 `setRole()`。
   */
  static async create(roomId: string, role: Role | null = null): Promise<CryptoSession> {
    // 必须先于任何 crypto.subtle.* 调用，否则非安全上下文会抛出难懂的 TypeError
    assertWebCrypto();
    const s = new CryptoSession(roomId, role);
    // 生成时允许导出，是为了拿到一份「可被 0 覆写」的私钥字节；
    // 随后立刻重新导入为 extractable:false 的运行时句柄。
    const kp = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      WIPE_EXTRACTABLE_PRIVATE_KEY,
      ['deriveBits', 'deriveKey'],
    )) as CryptoKeyPair;

    s.publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));

    if (WIPE_EXTRACTABLE_PRIVATE_KEY) {
      const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
      // 运行时使用的私钥：不可导出，杜绝后续任何 exportKey 把私钥再吐回 JS 堆
      s.privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits', 'deriveKey']);
      s.privateKeyRaw = pkcs8; // 保留可覆写副本，destroy() 时 fill(0)
    } else {
      s.privateKey = kp.privateKey;
    }
    return s;
  }

  get isDestroyed(): boolean { return this.destroyed; }
  get safetyNumber(): string | null { return this.safetyNumberCache; }
  /** 本端方向标签（A/B）；握手完成前为 null —— 它只是消息方向，不是用户选项 */
  get role(): Role | null { return this.roleValue; }

  /** 设定本端角色（握手后由公钥比较得出）；一旦确定就不允许中途变更 */
  setRole(role: Role): void {
    this.assertAlive();
    if (this.roleValue !== null && this.roleValue !== role) {
      throw new SecretTalkError('会话方向标签已确定，禁止中途变更', 'ROLE_LOCKED');
    }
    this.roleValue = role;
  }

  /**
   * 由「双方公钥的字典序」推导本端角色：公钥字节较小的一端为 A，较大的一端为 B。
   * 两端在本地对同一对公钥做同样的比较，因此必然得到相反的角色；
   * 5 台互不通信的孤岛中继不需要、也没有参与任何协调。
   */
  determineOwnRole(): Role {
    this.assertAlive();
    if (!this.publicKeyRaw || !this.peerPublicKeyRaw) {
      throw new SecretTalkError('公钥尚未交换完成，无法确定会话方向', 'NO_PEER_KEY');
    }
    const cmp = compareBytes(this.publicKeyRaw, this.peerPublicKeyRaw);
    if (cmp === 0) {
      // 两端生成同一把 ECDH 私钥在实践中不可能发生，遇到说明协议被破坏
      throw new SecretTalkError('对端公钥与本端完全相同，无法确定会话方向', 'ROLE_UNDETERMINED');
    }
    return cmp < 0 ? 'A' : 'B';
  }

  /** 内部统一入口：未确定角色时直接报错，绝不静默使用某个默认方向 */
  private requireRole(): Role {
    this.assertAlive();
    if (this.roleValue === null) {
      throw new SecretTalkError('本端方向尚未确定，请等待双方完成握手', 'NO_ROLE');
    }
    return this.roleValue;
  }

  /** 本端 ECDH 公钥（base64/SPKI），交给 hello 帧由中继转发 */
  getPublicKeyB64(): string {
    this.assertAlive();
    return toB64(this.publicKeyRaw!);
  }

  /**
   * 设置对端公钥。5 个孤岛服务器会各自转发一次，内容完全相同，
   * 这里按字节幂等去重，避免重复派生 KEK。返回 true 表示首次就绪。
   */
  async setPeerPublicKeyB64(b64: string): Promise<boolean> {
    this.assertAlive();
    const raw = fromB64(b64);
    if (this.peerPublicKeyRaw && compareBytes(raw, this.peerPublicKeyRaw) === 0) {
      secureWipe(raw);
      return false;
    }
    // 不允许握手过程中换公钥（防中继在会话中途替换密钥）
    if (this.peerPublicKeyRaw) {
      secureWipe(raw);
      throw new SecretTalkError('检测到对端公钥变更，可能存在中间人攻击，会话已拒绝继续', 'PEER_KEY_CHANGED');
    }
    try {
      this.peerKey = await crypto.subtle.importKey(
        'spki', ab(raw), { name: 'ECDH', namedCurve: 'P-256' }, false, [],
      );
    } catch {
      secureWipe(raw);
      throw new SecretTalkError('对端 ECDH 公钥格式非法', 'BAD_PEER_KEY');
    }
    this.peerPublicKeyRaw = raw;
    this.safetyNumberCache = await computeSafetyNumber(this.publicKeyRaw!, raw);
    await this.ensureKek(); // 双方公钥就绪即派生 KEK
    return true;
  }

  get hasPeerKey(): boolean { return this.peerPublicKeyRaw !== null; }

  /**
   * ECDH 共享秘密 → HKDF → KEK。
   * salt = SHA-256(roomId)，info = 用途标签 + roomId，保证不同房间/不同用途密钥隔离。
   */
  private async ensureKek(): Promise<CryptoKey> {
    if (this.kek) return this.kek;
    this.assertAlive();
    if (!this.privateKey || !this.peerKey) {
      throw new SecretTalkError('ECDH 握手尚未完成，无法派生 KEK', 'NO_PEER_KEY');
    }
    const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: this.peerKey }, this.privateKey, 256);
    const shared = new Uint8Array(bits); // ← 必须覆写的 ECDH 共享秘密
    try {
      const ikm = await crypto.subtle.importKey('raw', ab(shared), 'HKDF', false, ['deriveKey']);
      const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', ab(utf8(this.roomId))));
      const info = utf8(`SecretTalk/KEK/v1/${this.roomId}`);
      this.kek = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: ab(salt), info: ab(info) },
        ikm,
        { name: 'AES-GCM', length: 256 },
        false,              // KEK 永不可导出
        ['encrypt', 'decrypt'],
      );
      secureWipe(salt, info);
      return this.kek;
    } finally {
      // 共享秘密一旦派生完立即 0 覆写，绝不停留在内存中
      secureWipe(shared);
    }
  }

  /* ---------------------------------------------------------------------- *
   * A 端：加密一条消息 → 产出 5 个待分发的碎片包
   * ---------------------------------------------------------------------- */
  async encryptMessage(text: string, messageId: string, attachment?: OutgoingAttachment): Promise<CipherPacket[]> {
    this.assertAlive();
    const from = this.requireRole();

    // 附件上限在加密前就拦住（也早于 KEK 派生）：避免把几十 MB 的 base64
    // 塞进 5 路分发与中继缓存，同时让「超大附件」这类错误不必等到握手完成才报。
    if (attachment && attachment.bytes.length > MAX_ATTACHMENT_BYTES) {
      throw new SecretTalkError(
        `附件过大：${attachment.bytes.length} 字节，上限 ${MAX_ATTACHMENT_BYTES} 字节`,
        'ATTACHMENT_TOO_LARGE',
      );
    }
    const envelopeAttachment: EnvelopeAttachment | undefined = attachment
      ? {
        kind: attachment.kind,
        name: attachment.name,
        mime: attachment.mime,
        size: attachment.bytes.length,
        data: toB64(attachment.bytes),
      }
      : undefined;

    const kek = await this.ensureKek();

    // (1) 每条消息使用一把全新的随机 AES-256 密钥（一次一密）
    const msgKey = crypto.getRandomValues(new Uint8Array(AES_256_KEY_BYTES));
    const keyForSplit = msgKey.slice(); // split 内部只读，另给副本便于彻底擦除
    let msgKeyHandle: CryptoKey | null = null;
    let envelope: Uint8Array | null = null;
    let shares: Uint8Array[] | null = null;

    try {
      // (2) 明文封装 + AES-256-GCM 加密，AAD 绑定房间与消息号
      envelope = encodeEnvelope({
        magic: PLAINTEXT_MAGIC, messageId, roomId: this.roomId, from, ts: Date.now(), text,
        ...(envelopeAttachment ? { attachment: envelopeAttachment } : {}),
      });
      const cipherIv = randomIv();
      const msgAad = utf8(`${this.roomId}|${messageId}`);
      msgKeyHandle = await importAesKey(msgKey, ['encrypt']);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: ab(cipherIv), additionalData: ab(msgAad), tagLength: 128 },
        msgKeyHandle, ab(envelope),
      ));

      // (3) Shamir (3,5) 拆分 AES 密钥 —— 服务器完全不参与，只在客户端本地完成
      shares = await split(keyForSplit, SHARE_TOTAL, SHARE_THRESHOLD);
      if (shares.length !== SHARE_TOTAL) throw new SecretTalkError('SSS 碎片数量异常', 'SSS_SPLIT');

      // (4) 每个碎片用 KEK 单独加密：独立 IV + AAD(roomId|messageId|index)
      //     AAD 让碎片与「端口下标」强绑定，中继把碎片挪到别的端口会被 GCM 判为篡改。
      const packets: CipherPacket[] = [];
      for (let i = 0; i < SHARE_TOTAL; i++) {
        const shareIv = randomIv();
        const aad = utf8(`${this.roomId}|${messageId}|${i}`);
        const encryptedShare = new Uint8Array(await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: ab(shareIv), additionalData: ab(aad), tagLength: 128 },
          kek, ab(shares[i]),
        ));
        secureWipe(aad);
        packets.push({
          roomId: this.roomId,
          messageId,
          from,
          shareIndex: i,
          encryptedShare: toB64(encryptedShare),
          shareIv: toB64(shareIv),
          // 密文在 5 路冗余：保证 B 无论收到哪 3 路都一定同时拿到消息密文
          ciphertext: toB64(ciphertext),
          cipherIv: toB64(cipherIv),
          createdAt: Date.now(),
        });
      }
      secureWipe(cipherIv, msgAad);
      return packets;
    } finally {
      // (5) 加密完成即刻擦除：raw 消息密钥、明文、5 个明文碎片
      secureWipe(msgKey, keyForSplit, envelope, ...(shares ?? []));
      msgKeyHandle = null; // CryptoKey 不可导出，断开引用交 GC
    }
  }

  /* ---------------------------------------------------------------------- *
   * B 端：收到任意 3 个碎片包 → 重组 → 解密 → 完整性校验
   * ---------------------------------------------------------------------- */
  async tryDecrypt(packets: CipherPacket[], messageId: string): Promise<DecryptedMessage> {
    this.assertAlive();
    const self = this.requireRole();
    const kek = await this.ensureKek();

    // (1) 严格按 (roomId, messageId) 过滤并按 shareIndex 去重。
    //     绝不把不同消息的碎片混在一起喂给 combine()，
    //     否则会重组出一个「长度合法但错误」的密钥（随后 GCM 会拒绝，但错误难以定位）。
    const unique = new Map<number, CipherPacket>();
    for (const p of packets) {
      if (p.roomId !== this.roomId || p.messageId !== messageId) continue;
      if (p.from === self) continue;
      if (!Number.isInteger(p.shareIndex) || p.shareIndex < 0 || p.shareIndex >= SHARE_TOTAL) continue;
      unique.set(p.shareIndex, p);
    }
    if (unique.size < SHARE_THRESHOLD) {
      throw new SecretTalkError(`碎片不足：需要 ${SHARE_THRESHOLD} 片，当前仅 ${unique.size} 片`, 'NOT_ENOUGH_SHARES');
    }

    const chosen = Array.from(unique.values()).slice(0, SHARE_THRESHOLD);
    const plainShares: Uint8Array[] = [];
    let rawKey: Uint8Array | null = null;
    let plain: Uint8Array | null = null;

    try {
      // (2) 用 KEK 解开每个碎片；GCM 的 auth tag 顺带完成「碎片完整性 + AAD 上下文」校验
      for (const p of chosen) {
        const aad = utf8(`${this.roomId}|${messageId}|${p.shareIndex}`);
        try {
          const buf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ab(fromB64(p.shareIv)), additionalData: ab(aad), tagLength: 128 },
            kek, ab(fromB64(p.encryptedShare)),
          );
          plainShares.push(new Uint8Array(buf)); // ← 明文碎片，用完必须覆写
        } catch {
          throw new SecretTalkError(
            `第 ${p.shareIndex} 号碎片校验失败（GCM tag 不匹配）：碎片可能被篡改、跨端口重放或来自其他会话`,
            'SHARE_INTEGRITY',
          );
        } finally {
          secureWipe(aad);
        }
      }

      // (3) Shamir 重组出 32 字节 AES 密钥
      try {
        rawKey = await combine(plainShares);
      } catch {
        throw new SecretTalkError('SSS 重组失败：碎片集合不一致', 'SSS_COMBINE');
      }
      if (!rawKey || rawKey.length !== AES_256_KEY_BYTES) {
        throw new SecretTalkError(`重组出的密钥长度异常（期望 ${AES_256_KEY_BYTES} 字节）`, 'BAD_KEY_LENGTH');
      }

      // (4) 【需求：碎片完整性校验】用重组密钥尝试解密消息密文。
      //     AES-GCM 会在解密时验证 128bit auth tag：密钥错、密文被改、IV 不匹配都会抛 OperationError。
      //     这是判断「碎片是否可信」的最终判据，绝不能用「重组成功」代替「解密成功」。
      const any = chosen[0];
      const msgAad = utf8(`${this.roomId}|${messageId}`);
      const msgKeyHandle = await importAesKey(rawKey, ['decrypt']);
      try {
        const buf = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: ab(fromB64(any.cipherIv)), additionalData: ab(msgAad), tagLength: 128 },
          msgKeyHandle, ab(fromB64(any.ciphertext)),
        );
        plain = new Uint8Array(buf);
      } catch {
        throw new SecretTalkError(
          '完整性校验失败：重组出的密钥无法解密消息密文（碎片错配 / 密文被篡改 / 双方会话密钥不一致）',
          'MESSAGE_INTEGRITY',
        );
      } finally {
        secureWipe(msgAad);
      }

      // (5) 第二层校验：明文封装里的魔数与上下文
      const env = parseEnvelope(plain);
      if (!env || env.magic !== PLAINTEXT_MAGIC || env.messageId !== messageId ||
          env.roomId !== this.roomId || env.from === self) {
        throw new SecretTalkError('明文封装校验失败：消息上下文不匹配', 'ENVELOPE_MISMATCH');
      }

      return {
        messageId,
        from: env.from,
        text: env.text,   // 字符串不可覆写（JS 局限），由 UI 在 force_exit 时清空状态
        ts: env.ts,
        usedShares: chosen.map((p) => p.shareIndex).sort((a, b) => a - b),
        ...(env.attachment ? { attachment: env.attachment } : {}),
      };
    } finally {
      // (6) 无论成功失败，敏感字节一律 0 覆写
      secureWipe(rawKey, plain, ...plainShares);
    }
  }

  /* ---------------------------------------------------------------------- *
   * 生命周期自毁：force_exit 时调用
   * ---------------------------------------------------------------------- */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;

    // 字节级 0 覆写：AES 消息密钥在 encrypt/tryDecrypt 内已即时擦除；
    // 这里覆写的是长期驻留的材料 —— ECDH 私钥副本、公钥字节、对端公钥字节。
    secureWipe(this.privateKeyRaw, this.publicKeyRaw, this.peerPublicKeyRaw);
    this.privateKeyRaw = null;
    this.publicKeyRaw = null;
    this.peerPublicKeyRaw = null;
    this.safetyNumberCache = null;

    // CryptoKey 内部内存 JS 无法寻址，只能断开引用；
    // 由于全程 extractable:false，攻击者即使拿到堆快照也导不出密钥材料。
    this.privateKey = null;
    this.peerKey = null;
    this.kek = null;
  }

  private assertAlive(): void {
    if (this.destroyed) throw new SecretTalkError('会话已销毁，禁止继续使用密钥', 'SESSION_DESTROYED');
  }
}
