import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { RELAY_PORTS } from './shared/protocol.js';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    // 开发模式下把 /relay/0~4 的 WebSocket 代理到本机 5 个中继进程，
    // 与生产网关（server/gateway.ts）的路径规则保持一致，
    // 前端地址池无需区分 dev / prod。
    proxy: Object.fromEntries(
      RELAY_PORTS.map((p, i) => [`/relay/${i}`, { target: `ws://127.0.0.1:${p}`, ws: true, rewriteWsOrigin: true }]),
    ),
  },
  build: {
    // 与后端编译产物隔离：后端 tsc 输出 dist/server/**，
    // 若这里也用 dist，vite build 的 emptyOutDir 会把 server.js 一起删掉。
    outDir: 'dist/web',
  },
});
