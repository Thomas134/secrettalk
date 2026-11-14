/**
 * 核心流程测试 ①：密码学核心（crypto.ts）
 * 覆盖：Base64 编解码语义、SSS 门限、ECDH/HKDF、AES-GCM 完整性、内存 0 覆写。
 */
import { describe, it, expect, vi } from 'vitest';
import { combine, split } from 'shamir-secret-sharing';
import {
  CryptoSession,
  SecretTalkError,
  computeSafetyNumber,
  fromB64,
  secureWipe,
  toB64,
} from '../src/crypto.js';
import { AES_256_KEY_BYTES, SHARE_THRESHOLD, SHARE_TOTAL, MAX_ATTACHMENT_BYTES } from '../shared/protocol.js';
import type { CipherPacket } from '../shared/protocol.js';

/** 构造一对已完成 ECDH 握手的会话 */
async function pair(roomId = 'test-room') {
  const a = await CryptoSession.create(roomId, 'A');
  const b = await CryptoSession.create(roomId, 'B');
  await a.setPeerPublicKeyB64(b.getPublicKeyB64());
  await b.setPeerPublicKeyB64(a.getPublicKeyB64());
  return { a, b };
}

/** 生成 C(5,3)=10 种碎片组合 */
function combinations3(): number[][] {
  const out: number[][] = [];
  for (let i = 0; i < SHARE_TOTAL; i++)
    for (let j = i + 1; j < SHARE_TOTAL; j++)
      for (let k = j + 1; k < SHARE_TOTAL; k++) out.push([i, j, k]);
  return out;
}

async function expectCode(p: Promise<unknown>, code: string) {
  await expect(p).rejects.toMatchObject({ name: 'SecretTalkError', code });
}

describe('1. Base64 与内存覆写', () => {
  it('toB64/fromB64 往返无损，且解码结果必须是 Uint8Array（绝不当字符串用）', () => {
    const raw = new Uint8Array([0, 1, 2, 127, 128, 254, 255]);
    const back = fromB64(toB64(raw));
    expect(back).toBeInstanceOf(Uint8Array);
    expect(Array.from(back)).toEqual(Array.from(raw));
  });

  it('secureWipe 用 0 覆写全部字节', () => {
    const buf = new Uint8Array([9, 8, 7, 6]);
    secureWipe(buf, null, undefined);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0]);
  });
});

describe('2. Shamir SSS (k=3, n=5)', () => {
  it('任意 3 片都能还原 32 字节 AES 密钥（遍历全部 10 种组合）', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(AES_256_KEY_BYTES));
    const expected = Array.from(secret);
    const shares = await split(secret, SHARE_TOTAL, SHARE_THRESHOLD);
    expect(shares).toHaveLength(5);
    // 每个 share 比原始秘密多 1 字节（x 坐标），且单片不含完整秘密
    expect(shares[0].length).toBe(AES_256_KEY_BYTES + 1);

    for (const combo of combinations3()) {
      const restored = await combine(combo.map((i) => shares[i]));
      expect(Array.from(restored)).toEqual(expected);
    }
    secureWipe(secret, ...shares);
  });

  it('只有 2 片时无法还原出正确密钥（证明门限有效）', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(AES_256_KEY_BYTES));
    const shares = await split(secret, SHARE_TOTAL, SHARE_THRESHOLD);
    const wrong = await combine([shares[0], shares[2]]);
    expect(wrong.length).toBe(AES_256_KEY_BYTES);
    expect(Array.from(wrong)).not.toEqual(Array.from(secret));
    secureWipe(secret, ...shares, wrong);
  });
});

describe('3. ECDH P-256 + HKDF', () => {
  it('双方各自派生出相同的 KEK，且算出相同的安全数', async () => {
    const { a, b } = await pair();
    expect(a.hasPeerKey && b.hasPeerKey).toBe(true);
    expect(a.safetyNumber).toBe(b.safetyNumber);
    expect(a.safetyNumber).toMatch(/^\d{3} \d{3}$/);

    // A 加密的消息 B 能解开，说明 ECDH 共享秘密 → HKDF → KEK 完全一致
    const packets = await a.encryptMessage('握手验证', 'msg-handshake');
    const m = await b.tryDecrypt(packets.slice(0, 3), 'msg-handshake');
    expect(m.text).toBe('握手验证');
    a.destroy(); b.destroy();
  });

  it('公钥按字典序拼接，A/B 顺序无关', async () => {
    const x = new Uint8Array([1, 2, 3]);
    const y = new Uint8Array([9, 8, 7]);
    expect(await computeSafetyNumber(x, y)).toBe(await computeSafetyNumber(y, x));
  });

  it('握手未完成就发消息会被拒绝', async () => {
    const a = await CryptoSession.create('r', 'A');
    await expectCode(a.encryptMessage('x', 'm1'), 'NO_PEER_KEY');
    a.destroy();
  });

  it('会话中途更换对端公钥会被判定为中间人攻击', async () => {
    const { a, b } = await pair();
    const other = await CryptoSession.create('r2', 'A');
    await expectCode(a.setPeerPublicKeyB64(other.getPublicKeyB64()), 'PEER_KEY_CHANGED');
    a.destroy(); b.destroy(); other.destroy();
  });
});

describe('4. AES-256-GCM 消息与碎片完整性校验', () => {
  it('任意 3 路碎片都能解密成功，并上报实际使用的碎片下标', async () => {
    const { a, b } = await pair('room-gcm');
    const packets = await a.encryptMessage('今晚八点，老地方见', 'msg-full');
    expect(packets).toHaveLength(SHARE_TOTAL);
    for (const combo of combinations3()) {
      const m = await b.tryDecrypt(combo.map((i) => packets[i]), 'msg-full');
      expect(m.text).toBe('今晚八点，老地方见');
      expect(m.usedShares).toEqual(combo);
      expect(m.messageId).toBe('msg-full');
    }
    a.destroy(); b.destroy();
  });

  it('带附件的消息可以完整往返（字节级一致）', async () => {
    const { a, b } = await pair('room-attach');
    const bytes = new Uint8Array([0, 1, 2, 3, 127, 128, 250, 251, 252, 253, 254, 255]);
    const packets = await a.encryptMessage('配文', 'msg-attach', {
      kind: 'audio', name: 'voice.webm', mime: 'audio/webm', bytes,
    });
    const m = await b.tryDecrypt(packets.slice(0, 3), 'msg-attach');
    expect(m.text).toBe('配文');
    expect(m.attachment?.kind).toBe('audio');
    expect(m.attachment?.name).toBe('voice.webm');
    expect(m.attachment?.mime).toBe('audio/webm');
    expect(m.attachment?.size).toBe(bytes.length);
    const data = fromB64(m.attachment!.data);
    expect(Array.from(data)).toEqual(Array.from(bytes));
    a.destroy(); b.destroy();
  });

  it('超过上限的附件在加密前就被拒绝', async () => {
    const a = await CryptoSession.create('room-big', 'A');
    await expectCode(
      a.encryptMessage('x', 'm-big', {
        kind: 'file', name: 'big.bin', mime: 'application/octet-stream',
        bytes: new Uint8Array(MAX_ATTACHMENT_BYTES + 1),
      }),
      'ATTACHMENT_TOO_LARGE',
    );
    a.destroy();
  });

  it('密文包里不出现任何明文（base64 只传密文）', async () => {
    const { a, b } = await pair();
    const packets = await a.encryptMessage('绝密内容SECRET-42', 'msg-noleak');
    const wire = JSON.stringify(packets);
    expect(wire).not.toContain('绝密内容');
    expect(wire).not.toContain('SECRET-42');
    // 5 路都带完整密文，保证任意 3 路凑齐时必然同时拿到 ciphertext
    expect(new Set(packets.map((p) => p.ciphertext)).size).toBe(1);
    a.destroy(); b.destroy();
  });

  it('碎片不足 3 片时直接拒绝重组', async () => {
    const { a, b } = await pair();
    const packets = await a.encryptMessage('x', 'msg-few');
    await expectCode(b.tryDecrypt(packets.slice(0, 2), 'msg-few'), 'NOT_ENOUGH_SHARES');
    a.destroy(); b.destroy();
  });

  it('加密后的碎片被篡改 → GCM tag 校验失败（SHARE_INTEGRITY）', async () => {
    const { a, b } = await pair();
    const packets = await a.encryptMessage('x', 'msg-tamper-share');
    const tampered: CipherPacket = { ...packets[0], encryptedShare: 'AAAA' + packets[0].encryptedShare.slice(4) };
    await expectCode(b.tryDecrypt([tampered, packets[1], packets[2]], 'msg-tamper-share'), 'SHARE_INTEGRITY');
    a.destroy(); b.destroy();
  });

  it('碎片被投到错误下标（AAD 上下文绑定）→ 校验失败', async () => {
    const { a, b } = await pair();
    const packets = await a.encryptMessage('x', 'msg-aad');
    // 攻击者把碎片 #0 伪装成 #2，AAD 里的 index 变化会让 GCM 认证失败
    const replayed: CipherPacket = { ...packets[0], shareIndex: 2 };
    await expectCode(b.tryDecrypt([packets[0], packets[1], replayed], 'msg-aad'), 'SHARE_INTEGRITY');
    a.destroy(); b.destroy();
  });

  it('消息密文被篡改 → 重组密钥解不开，报 MESSAGE_INTEGRITY', async () => {
    const { a, b } = await pair();
    const packets = await a.encryptMessage('x', 'msg-tamper-ct');
    const bad = packets.map((p) => ({ ...p, ciphertext: 'AAAA' + p.ciphertext.slice(4) }));
    await expectCode(b.tryDecrypt(bad.slice(0, 3), 'msg-tamper-ct'), 'MESSAGE_INTEGRITY');
    a.destroy(); b.destroy();
  });

  it('混入其他 messageId 的碎片会被过滤，绝不跨消息重组', async () => {
    const { a, b } = await pair();
    const p1 = await a.encryptMessage('第一条', 'msg-1');
    const p2 = await a.encryptMessage('第二条', 'msg-2');
    const mixed = [p1[0], p1[1], { ...p2[2], messageId: 'msg-1' }];
    await expectCode(b.tryDecrypt(mixed, 'msg-1'), 'SHARE_INTEGRITY');
    a.destroy(); b.destroy();
  });

  it('不同房间 / 错误 ECDH 对端都无法解密（房间号与 KEK 双重隔离）', async () => {
    const { a } = await pair('room-A');
    const packets = await a.encryptMessage('x', 'msg-cross-room');

    // ① 房间号不同：客户端直接拒绝不属于本会话的碎片，一片都不收
    const otherRoom = await CryptoSession.create('room-B', 'B');
    await otherRoom.setPeerPublicKeyB64(a.getPublicKeyB64());
    await expectCode(otherRoom.tryDecrypt(packets.slice(0, 3), 'msg-cross-room'), 'NOT_ENOUGH_SHARES');

    // ② 房间号相同、但 ECDH 对端不匹配：KEK 不同，碎片 GCM tag 校验失败
    const wrongPeer = await CryptoSession.create('room-A', 'B');
    await wrongPeer.setPeerPublicKeyB64(a.getPublicKeyB64());
    await expectCode(wrongPeer.tryDecrypt(packets.slice(0, 3), 'msg-cross-room'), 'SHARE_INTEGRITY');

    a.destroy(); otherRoom.destroy(); wrongPeer.destroy();
  });
});

describe('5. 生命周期自毁与内存防泄漏', () => {
  it('destroy() 用 0 覆写 ECDH 私钥 / 公钥字节，并禁止继续使用', async () => {
    const { a, b } = await pair();
    const priv = (a as unknown as { privateKeyRaw: Uint8Array }).privateKeyRaw;
    const pub = (a as unknown as { publicKeyRaw: Uint8Array }).publicKeyRaw;
    const peerPub = (a as unknown as { peerPublicKeyRaw: Uint8Array }).peerPublicKeyRaw;
    expect(priv.some((x) => x !== 0)).toBe(true); // 销毁前确实是非零私钥材料
    expect(pub.some((x) => x !== 0)).toBe(true);

    a.destroy();
    expect(priv.every((x) => x === 0)).toBe(true);
    expect(pub.every((x) => x === 0)).toBe(true);
    expect(peerPub.every((x) => x === 0)).toBe(true);
    expect(a.isDestroyed).toBe(true);
    await expectCode(a.encryptMessage('x', 'm'), 'SESSION_DESTROYED');
    b.destroy();
  });

  it('每条消息的 raw AES 密钥在加密结束后立即被 0 覆写', async () => {
    const { a, b } = await pair();
    const original = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    const captured: Uint8Array[] = [];
    const spy = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((arr: ArrayBufferView) => {
      const ret = original(arr as never);
      if (arr instanceof Uint8Array && arr.length === AES_256_KEY_BYTES) captured.push(arr);
      return ret;
    }) as never);

    try {
      const packets = await a.encryptMessage('一次一密', 'msg-wipe');
      expect(captured.length).toBeGreaterThan(0);
      // msgKey 已在 encryptMessage 的 finally 中被 fill(0)
      expect(captured.every((k) => k.every((x) => x === 0))).toBe(true);
      // 虽然原始密钥已擦除，分片仍可正常解密（split 内部已复制数据）
      const m = await b.tryDecrypt(packets.slice(0, 3), 'msg-wipe');
      expect(m.text).toBe('一次一密');
    } finally {
      spy.mockRestore();
      a.destroy(); b.destroy();
    }
  });
});
