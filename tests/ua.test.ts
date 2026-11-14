/**
 * 内置浏览器识别测试：只拦微信 / 企业微信，不误伤普通浏览器。
 */
import { describe, it, expect } from 'vitest';
import { detectBlockedWebView } from '../shared/ua.js';

describe('微信内置浏览器识别', () => {
  it('手机微信 UA 被识别', () => {
    const ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.42(0x18002a2b) NetType/WIFI Language/zh_CN';
    expect(detectBlockedWebView(ua)).toEqual({ blocked: true, name: '微信' });
  });

  it('企业微信 UA 被识别', () => {
    const ua = 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0 Mobile Safari/537.36 wxwork/4.1.0';
    expect(detectBlockedWebView(ua)).toEqual({ blocked: true, name: '企业微信' });
  });

  it('微信桌面版 UA 被识别', () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36 WeChat/3.9.8';
    expect(detectBlockedWebView(ua).blocked).toBe(true);
  });

  it('普通浏览器 / 空 UA 不拦', () => {
    const safari = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
    const chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
    expect(detectBlockedWebView(safari).blocked).toBe(false);
    expect(detectBlockedWebView(chrome).blocked).toBe(false);
    expect(detectBlockedWebView('').blocked).toBe(false);
    expect(detectBlockedWebView(undefined).blocked).toBe(false);
  });
});
