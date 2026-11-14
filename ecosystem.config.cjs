/**
 * PM2 部署拓扑：单机多进程模拟 5 台「物理隔离」的中继服务器
 * ---------------------------------------------------------------------------
 * - exec_mode: 'fork' + instances: 1 —— 保证是 5 个彼此独立的 Node.js 进程，
 *   绝不走 cluster（cluster 会共享主进程，破坏「孤岛」语义）。
 * - 5 个进程之间没有任何 IPC / 共享内存 / 数据库 / 文件交换；
 *   每台只持有自己收到的那 1 个碎片（shareIndex = 端口下标）。
 * - 每个进程通过 env.PORT 动态监听，server.ts 不写死任何端口。
 *
 * 另外把前端静态站点也纳入同一个 ecosystem，好处是：
 *   - 启动/停止都只需一条 pm2 命令，避免 CMD 下多条命令拼接的兼容问题；
 *   - 全部 6 个进程由同一个 daemon 统一守护，状态与日志集中可见。
 *
 * 启动：npm run start:pm2（或 npm run start:all，含构建）
 * 停止：npm run stop:pm2     日志：npm run logs:pm2
 */
const PORTS = [3001, 3002, 3003, 3004, 3005];

const relayApps = PORTS.map((port, index) => ({
  name: `secrettalk-relay-${port}`,
  script: 'dist/server/server.js',
  cwd: __dirname,
  exec_mode: 'fork',
  instances: 1,
  autorestart: true,
  max_restarts: 5,
  env: {
    NODE_ENV: 'production',
    /** PM2 fork 下 argv[1] 不是本文件路径，必须显式声明「独立运行」才会监听端口 */
    SECRETTALK_AUTOSTART: '1',
    PORT: String(port),
    HOST: '0.0.0.0',
    /** 该进程负责的碎片下标，仅用于校验客户端有没有发错端口（不做密码学处理） */
    RELAY_INDEX: String(index),
    /** 内存房间 TTL（毫秒） */
    ROOM_TTL_MS: String(5 * 60 * 1000),
  },
}));

module.exports = {
  apps: [
    ...relayApps,
    {
      /**
       * 单端口零知识网关：https://<IP>:5173 同时提供前端页面与 /relay/0~4 的
       * WebSocket 反代（上游 127.0.0.1:3001~3005），手机点一次「继续访问」即可
       * 获得安全上下文（crypto.subtle 可用）且 wss 与页面同源不被拦截。
       * 证书由 `npm run gen:certs` 生成（scripts/gen-certs.cjs）。
       */
      name: 'secrettalk-gateway',
      script: 'dist/server/gateway.js',
      cwd: __dirname,
      exec_mode: 'fork',
      instances: 1,
      autorestart: true,
      max_restarts: 5,
      env: {
        NODE_ENV: 'production',
        SECRETTALK_AUTOSTART: '1',
        GATEWAY_PORT: '5173',
        GATEWAY_HOST: '0.0.0.0',
        GATEWAY_TLS: '1',
      },
    },
  ],
};
