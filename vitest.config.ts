import { defineConfig } from 'vitest/config';

/**
 * 测试配置与前端构建配置分离：
 * Vitest 2 自带一份 Vite，若不拆分，react 插件类型会与顶层 Vite 冲突。
 * 测试文件均为 .ts 且不加载任何 .tsx，因此这里无需 react 插件。
 */
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['tests/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // 集成测试会真实拉起 5 个 ws 服务，串行执行避免端口/定时器互相干扰
    fileParallelism: false,
  },
});
