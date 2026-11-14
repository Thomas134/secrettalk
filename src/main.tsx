import { createRoot } from 'react-dom/client';
import App from './App.js';

// 不使用 StrictMode：开发模式下它会重复挂载组件，
// 可能导致一次性拨出 10 条 WebSocket（5 路 × 2），干扰会话与测试。
createRoot(document.getElementById('root')!).render(<App />);
