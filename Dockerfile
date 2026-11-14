# 免费容器平台（Koyeb / Hugging Face Spaces / Fly.io 等）通用镜像
# 构建：docker build -t secrettalk .
# 运行：docker run -p 7860:7860 secrettalk   （平台会自动注入 PORT，本镜像已声明 7860）
FROM node:22-slim

WORKDIR /app
ENV NODE_ENV=production

# 先装依赖再拷源码，让 Docker 层缓存生效
COPY package.json package-lock.json ./
RUN npm ci --include=dev

COPY . .
# 前端 dist/web + 后端 dist/server
RUN npm run build && npm run build:server && npm prune --omit=dev

ENV PORT=7860
EXPOSE 7860
CMD ["node", "scripts/cloud-start.mjs"]
