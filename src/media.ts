/**
 * 附件准备（图片压缩 / 文件读取 / 语音整理）
 * ===========================================================================
 * 所有内容都在浏览器本地处理，加密之后才交给 RelayClient；
 * 这里只负责「把用户选的东西变成不超过上限的字节」。
 */
import { MAX_ATTACHMENT_BYTES, type AttachmentKind } from '../shared/protocol.js';

export interface OutgoingMedia {
  kind: AttachmentKind;
  name: string;
  mime: string;
  bytes: Uint8Array;
}

/** 超过这个大小的图片先压缩，避免手机直出 5MB 照片直接把中继缓存打满 */
const IMAGE_COMPRESS_THRESHOLD = 1.2 * 1024 * 1024;
const IMAGE_MAX_DIMENSION = 1600;
const IMAGE_JPEG_QUALITY = 0.82;

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

function assertSize(size: number, name: string): void {
  if (size > MAX_ATTACHMENT_BYTES) {
    throw new Error(`${name} 太大（${formatBytes(size)}），上限 ${formatBytes(MAX_ATTACHMENT_BYTES)}`);
  }
}

/** 用 canvas 把图片缩到最长边 1600、转 JPEG，透明区域填白 */
async function compressImage(file: File): Promise<Blob> {
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.src = url;
    await img.decode();

    const scale = Math.min(1, IMAGE_MAX_DIMENSION / Math.max(img.naturalWidth, img.naturalHeight));
    const width = Math.max(1, Math.round(img.naturalWidth * scale));
    const height = Math.max(1, Math.round(img.naturalHeight * scale));

    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('当前浏览器不支持图片压缩');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(img, 0, 0, width, height);

    const compressed = await new Promise<Blob | null>((resolve) => {
      canvas.toBlob(resolve, 'image/jpeg', IMAGE_JPEG_QUALITY);
    });
    if (!compressed) throw new Error('图片压缩失败');
    return compressed;
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** 图片：过大先压缩，仍然超限则拒绝 */
export async function prepareImage(file: File): Promise<OutgoingMedia> {
  if (!file.type.startsWith('image/')) throw new Error('请选择图片文件');

  let blob: Blob = file;
  let name = file.name || 'image';
  let mime = file.type || 'image/jpeg';

  if (file.size > IMAGE_COMPRESS_THRESHOLD) {
    try {
      blob = await compressImage(file);
      name = `${name.replace(/\.[^.]+$/, '') || 'image'}.jpg`;
      mime = 'image/jpeg';
    } catch {
      // 压缩失败就退回原图，再由下面的大小检查兜底
      blob = file;
    }
  }

  const bytes = await bytesOf(blob);
  assertSize(bytes.length, '图片');
  return { kind: 'image', name, mime, bytes };
}

/** 普通文件：只做大小检查 */
export async function prepareFile(file: File): Promise<OutgoingMedia> {
  assertSize(file.size, file.name || '文件');
  const bytes = await bytesOf(file);
  return {
    kind: 'file',
    name: file.name || 'file',
    mime: file.type || 'application/octet-stream',
    bytes,
  };
}

/** 语音：把 MediaRecorder 产出的 Blob 转成附件 */
export async function prepareVoice(blob: Blob, mime: string): Promise<OutgoingMedia> {
  const bytes = await bytesOf(blob);
  assertSize(bytes.length, '语音');
  const ext = mime.includes('mp4') ? 'm4a' : 'webm';
  const stamp = new Date().toLocaleTimeString('zh-CN', { hour12: false }).replace(/:/g, '-');
  return { kind: 'audio', name: `语音-${stamp}.${ext}`, mime, bytes };
}
