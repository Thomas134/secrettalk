/**
 * 测试公共设施：在单进程内拉起 N 台「孤岛」中继，并提供 Node 版 WebSocket 工厂。
 * 之所以用 port: 0 让系统分配端口，是为了避免 CI / 本地端口占用导致测试 flaky。
 */
import { readFileSync } from 'node:fs';
import { WebSocket as WsWebSocket, type AddressInfo } from 'ws';
import { startRelayServer, type RelayServerHandle } from '../server/server.js';
import type { ServerFrame } from '../shared/protocol.js';
import type { WebSocketLike } from '../src/relay.js';

/** 把 ws 库的 WebSocket 适配成 RelayClient 需要的最小接口 */
export function nodeSocketFactory(url: string): WebSocketLike {
  const ws = new WsWebSocket(url);
  // 常驻 error 监听：地址不可达时避免 EventEmitter 抛出未捕获异常
  ws.on('error', () => {});
  return ws as unknown as WebSocketLike;
}

export interface RelayCluster {
  handles: RelayServerHandle[];
  urls: string[];
  /** 逐台取实际监听端口（port:0 时由 OS 分配） */
  ports: number[];
  close: () => Promise<void>;
}

export async function startCluster(
  count = 5,
  opts: { ttlMs?: number; host?: string } = {},
): Promise<RelayCluster> {
  const handles: RelayServerHandle[] = [];
  const urls: string[] = [];
  const ports: number[] = [];
  for (let i = 0; i < count; i++) {
    const h = await startRelayServer({
      port: 0,
      host: opts.host ?? '127.0.0.1',
      relayIndex: i,
      ttlMs: opts.ttlMs,
      silent: true,
    });
    const addr = h.wss.address() as AddressInfo;
    handles.push(h);
    ports.push(addr.port);
    urls.push(`ws://127.0.0.1:${addr.port}`);
  }
  return {
    handles, urls, ports,
    close: async () => { for (const h of handles) await h.close(); },
  };
}

export interface TestClient {
  ws: WsWebSocket;
  frames: ServerFrame[];
  send: (frame: unknown) => void;
  waitFor: <T extends ServerFrame['type']>(
    type: T,
    timeoutMs?: number,
  ) => Promise<Extract<ServerFrame, { type: T }>>;
  close: () => void;
}

export async function connectClient(url: string): Promise<TestClient> {
  const ws = new WsWebSocket(url);
  ws.on('error', () => {}); // 防止 close 阶段的 error 变成未捕获异常
  const frames: ServerFrame[] = [];
  interface Waiter { type: ServerFrame['type']; resolve: (f: ServerFrame) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }
  const waiters: Waiter[] = [];

  ws.on('message', (raw) => {
    let frame: ServerFrame;
    try { frame = JSON.parse(raw.toString()) as ServerFrame; } catch { return; }
    frames.push(frame);
    for (let i = waiters.length - 1; i >= 0; i--) {
      if (waiters[i].type === frame.type) {
        clearTimeout(waiters[i].timer);
        waiters[i].resolve(frame);
        waiters.splice(i, 1);
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  return {
    ws,
    frames,
    send: (frame) => ws.send(JSON.stringify(frame)),
    waitFor: <T extends ServerFrame['type']>(type: T, timeoutMs = 4000) =>
      new Promise<Extract<ServerFrame, { type: T }>>((resolve, reject) => {
        const found = frames.find((f) => f.type === type);
        if (found) { resolve(found as Extract<ServerFrame, { type: T }>); return; }
        const timer = setTimeout(() => {
          const i = waiters.findIndex((w) => w.timer === timer);
          if (i >= 0) waiters.splice(i, 1);
          reject(new Error(`等待 ${type} 帧超时`));
        }, timeoutMs);
        waiters.push({ type, resolve: resolve as (f: ServerFrame) => void, reject, timer });
      }),
    close: () => ws.close(),
  };
}

/** 读取服务器源码，供「零知识」静态断言使用 */
export const serverSource = (): string =>
  readFileSync(new URL('../server/server.ts', import.meta.url), 'utf8');

/** 生成一个形状合法但内容不透明的假密文包（服务器测试专用，无需真实加密） */
export function fakePacket(roomId: string, shareIndex: number, messageId = 'msg-test-001') {
  return {
    roomId, messageId, from: 'A' as const, shareIndex,
    encryptedShare: 'AQIDBAUGBwgJCg==', shareIv: 'AQIDBAUGBwgJ',
    ciphertext: 'k9m3n5p7q8r9s0t=', cipherIv: 'AQIDBAUGBwgJ',
    createdAt: Date.now(),
  };
}
