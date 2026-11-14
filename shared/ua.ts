/**
 * 内置浏览器识别（客户端与网关共用）
 * ===========================================================================
 * 目的：微信 / 企业微信的内置 WebView 里，页面切后台会被系统冻结、用户也无法
 * 安装证书或控制缓存，而本项目的「断线即销毁」会让人频繁掉线、体验极差。
 * 因此默认拒绝在微信内运行，提示用户「在浏览器打开」。
 *
 * 【注意】UA 可以被伪造，这一层是体验护栏，不是安全边界。
 * 真正的安全仍然来自 E2E 加密与安全数核对。
 */
export interface BlockedWebView {
  blocked: boolean;
  /** 命中的客户端名称（用于提示文案） */
  name: string;
}

const RULES: ReadonlyArray<{ name: string; test: RegExp }> = [
  // 手机微信（iOS / Android）与小程序 web-view 都带 MicroMessenger
  { name: '微信', test: /MicroMessenger/i },
  // 企业微信
  { name: '企业微信', test: /wxwork/i },
  // 微信桌面版内置浏览器
  { name: '微信（桌面版）', test: /\bWeChat\b/i },
];

/** 判断 UA 是否属于被禁止的内置浏览器 */
export function detectBlockedWebView(userAgent?: string | null): BlockedWebView {
  const ua = userAgent || '';
  for (const rule of RULES) {
    if (rule.test.test(ua)) return { blocked: true, name: rule.name };
  }
  return { blocked: false, name: '' };
}
