/**
 * 密语 SecretTalk · 移动端优先的聊天界面
 * ---------------------------------------------------------------------------
 * UI 层不接触任何密钥材料：它只负责把 RelayClient 的事件渲染出来。
 * 收到 onDestroyed 时会主动清空消息数组，避免明文继续停留在 React 状态里。
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react';
import {
  MAX_VOICE_MS,
  RELAY_PORTS,
  createRoomId,
  type ExitReason,
  type Role,
} from '../shared/protocol.js';
import {
  RelayClient,
  type LinkState,
  type MessageStatus,
  type MessageView,
  type RelayStatus,
} from './relay.js';
import { webCryptoUnavailableReason } from './crypto.js';
import { detectBlockedWebView } from '../shared/ua.js';
import {
  formatBytes,
  prepareFile,
  prepareImage,
  prepareVoice,
  type OutgoingMedia,
} from './media.js';
import { VoiceCall, type VoiceState } from './voice.js';
import './styles.css';

const EXIT_TEXT: Record<ExitReason, string> = {
  user_logout: '你主动退出了会话',
  peer_disconnect: '检测到连接断开',
  ttl_expired: '房间缓存已过期',
  heartbeat_timeout: '心跳超时，链路已失效',
  beforeunload: '页面关闭或刷新',
  integrity_failure: '完整性校验失败',
};

/** 语音通话状态文案 */
function voiceStatusText(state: VoiceState, detail: string, secs: number): string {
  switch (state) {
    case 'calling': return '正在呼叫对方…';
    case 'ringing': return '对方邀请你进行语音通话';
    case 'connecting': return '正在建立 P2P 连接…';
    case 'active': return `通话中 ${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`;
    case 'error': return detail || '通话失败';
    case 'ended': return detail || '通话已结束';
    default: return '';
  }
}

export default function App() {
  const clientRef = useRef<RelayClient | null>(null);
  const logSeq = useRef(0);

  const [roomId, setRoomId] = useState(() => createRoomId());
  /**
   * 本端方向标签：不再由用户选择 A / B。
   * 双方只要填同一个房间号即可入房，角色在 ECDH 握手后由公钥字典序自动推导
   * （见 CryptoSession.determineOwnRole），两端必然相反且不冲突。
   */
  const [myRole, setMyRole] = useState<Role | null>(null);
  /** 中继地址：留空 = 同源网关模式（推荐，https 下 5 条 wss 与页面同源不被拦截） */
  const [host, setHost] = useState('');
  const [status, setStatus] = useState<RelayStatus>('idle');
  const [links, setLinks] = useState<LinkState[]>([]);
  const [messages, setMessages] = useState<MessageView[]>([]);
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [text, setText] = useState('');
  const [logs, setLogs] = useState<string[]>([]);
  const [notice, setNotice] = useState('');
  const [exitReason, setExitReason] = useState<ExitReason | null>(null);
  const [showLog, setShowLog] = useState(false);
  const [copied, setCopied] = useState(false);

  /* ---------------- 语音 / 图片 / 文件 ---------------- */
  const imageInputRef = useRef<HTMLInputElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const recordChunksRef = useRef<Blob[]>([]);
  const recordTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [recording, setRecording] = useState(false);
  const [recordSecs, setRecordSecs] = useState(0);
  const [mediaNotice, setMediaNotice] = useState('');

  /* ---------------- WebRTC 语音通话 ---------------- */
  const voiceRef = useRef<VoiceCall | null>(null);
  const remoteAudioRef = useRef<HTMLAudioElement | null>(null);
  const [voiceState, setVoiceState] = useState<VoiceState>('idle');
  const [voiceDetail, setVoiceDetail] = useState('');
  const [voiceMuted, setVoiceMuted] = useState(false);
  const [callSecs, setCallSecs] = useState(0);

  /** 非安全上下文下 crypto.subtle 不存在，此时直接给出可读提示并禁止进入会话 */
  const insecureReason = useMemo(() => webCryptoUnavailableReason(), []);

  /**
   * 微信 / 企业微信内置浏览器直接拒绝运行：
   * 这类 WebView 切后台会被冻结、无法安装证书、也控制不了缓存，而本项目是
   * 「断开即销毁」，在微信里体验会变成频繁掉线。网关侧也会按 UA 返回 403，
   * 这里再兜一层，覆盖 `npm run dev` 或直连网关等绕过网关的场景。
   */
  const blockedWebView = useMemo(
    () => detectBlockedWebView(typeof navigator === 'undefined' ? '' : navigator.userAgent),
    [],
  );
  const [blockedCopied, setBlockedCopied] = useState(false);

  // https 页面必须连 wss://，否则浏览器按「混合内容」直接拦截 ws://
  const wsScheme = typeof location !== 'undefined' && location.protocol === 'https:' ? 'wss' : 'ws';
  /**
   * 地址池两种模式：
   *  - host 留空（默认）：同源网关 wss://<当前页面host>/relay/0~4。
   *    页面与 5 条中继连接同源，自签证书只需在打开页面时点一次「继续访问」，
   *    部署到 PaaS（自动正规证书）时前端零改动。
   *  - host 填 IP/域名：传统直连模式 ws(s)://<host>:3001~3005（仅 localhost 可加密）。
   */
  const customHost = host.trim();
  const servers = useMemo(() => {
    if (!customHost) {
      const origin = typeof location !== 'undefined' && location.host
        ? `${wsScheme}://${location.host}`
        : `${wsScheme}://localhost:5173`;
      return RELAY_PORTS.map((_, i) => `${origin}/relay/${i}`);
    }
    return RELAY_PORTS.map((p) => `${wsScheme}://${customHost}:${p}`);
  }, [customHost, wsScheme]);

  const pushLog = useCallback((line: string) => {
    const stamp = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    setLogs((prev) => [`${stamp} ${line}`, ...prev].slice(0, 120));
  }, []);

  const upsertMessage = useCallback((m: MessageView) => {
    setMessages((prev) => {
      const i = prev.findIndex((x) => x.messageId === m.messageId);
      if (i < 0) return [...prev, m];
      const next = prev.slice();
      next[i] = { ...next[i], ...m };
      return next;
    });
  }, []);

  const join = useCallback(async () => {
    if (clientRef.current && !clientRef.current.isDestroyed) return;
    if (insecureReason) { setNotice(insecureReason); return; }
    setNotice('');
    setExitReason(null);
    setMessages([]);
    setSafetyNumber(null);
    setLogs([]);
    setMyRole(null);
    try {
      const c = await RelayClient.create(
        { roomId, servers, strictExitOnAnyClose: true },
        {
          onStatus: (s) => setStatus(s),
          onLinks: (l) => setLinks(l),
          onRole: (r) => {
            setMyRole(r);
            pushLog(`握手完成，本端方向为 ${r} 端（由双方公钥自动推导，无需选择）`);
          },
          onPeerReady: (n) => {
            // 握手成功后清掉「15 秒没等到对端」之类的旧提示，避免误导
            setNotice('');
            setSafetyNumber(n);
            pushLog(`安全数 ${n} 已生成，请与对方线下核对`);
          },
          onMessage: (m) => upsertMessage(m),
          onRtc: (signal) => { void voiceRef.current?.handleSignal(signal); },
          onMessageStatus: (id, st: MessageStatus) => {
            setMessages((prev) => prev.map((m) => (m.messageId === id ? { ...m, status: st } : m)));
          },
          onDestroyed: (reason) => {
            // 内存自毁：清空明文消息与安全数在 UI 层的残留
            setStatus('destroyed');
            setExitReason(reason);
            setMessages([]);
            setSafetyNumber(null);
            setMyRole(null);
            voiceRef.current?.dispose();
            voiceRef.current = null;
            setVoiceState('idle');
            setVoiceDetail('');
            setCallSecs(0);
            setVoiceMuted(false);
            setLinks((prev) => prev.map((l) => ({ ...l, connected: false })));
            clientRef.current = null;
            pushLog(`会话已销毁：${EXIT_TEXT[reason]}`);
          },
          onError: (e) => { setNotice(e.message); pushLog(`错误：${e.message}`); },
          onLog: (line) => { logSeq.current += 1; pushLog(line); },
        },
      );
      clientRef.current = c;

      // 语音通话只依赖中继转发信令，媒体走 P2P；与消息加密体系互相独立
      voiceRef.current?.dispose();
      voiceRef.current = new VoiceCall({
        send: (signal) => { c.sendRtc(signal); },
        onState: (state, detail) => {
          setVoiceState(state);
          setVoiceDetail(detail ?? '');
          if (state === 'ended' || state === 'error') setVoiceMuted(false);
          if (detail) pushLog(`语音通话：${detail}`);
        },
        onRemoteStream: (stream) => {
          if (remoteAudioRef.current) remoteAudioRef.current.srcObject = stream;
        },
      });
      setVoiceState('idle');
      setVoiceDetail('');
      setCallSecs(0);
      setVoiceMuted(false);

      pushLog(`房间 ${roomId} 已创建，正在连接 ${servers.length} 台孤岛中继`);
    } catch (e) {
      setNotice((e as Error).message);
    }
  }, [roomId, servers, insecureReason, pushLog, upsertMessage]);

  /** 复制房间号：手机上手抄 16 位十六进制极易出错，一键复制发给对方粘贴最稳 */
  const copyRoom = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(roomId);
      setCopied(true);
      pushLog('房间号已复制，发给对方粘贴即可');
      setTimeout(() => setCopied(false), 1500);
    } catch {
      pushLog('复制失败：请长按房间号输入框手动复制');
    }
  }, [roomId, pushLog]);

  const send = useCallback(async () => {
    const value = text.trim();
    if (!value) return;
    setText('');
    setNotice('');
    try {
      await clientRef.current?.send(value);
    } catch (e) {
      setNotice((e as Error).message);
    }
  }, [text]);

  const exit = useCallback(async () => {
    await clientRef.current?.forceExit('user_logout');
  }, []);

  /** 附件统一走这里：文字输入框里有内容就作为配文一起发 */
  const sendMedia = useCallback(async (media: OutgoingMedia) => {
    setNotice('');
    setMediaNotice('');
    try {
      await clientRef.current?.send(text.trim(), media);
      setText('');
    } catch (e) {
      setMediaNotice((e as Error).message);
    }
  }, [text]);

  const onPickImage = useCallback(async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    try {
      await sendMedia(await prepareImage(file));
    } catch (err) {
      setMediaNotice((err as Error).message);
    }
  }, [sendMedia]);

  const onPickFile = useCallback(async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    try {
      await sendMedia(await prepareFile(file));
    } catch (err) {
      setMediaNotice((err as Error).message);
    }
  }, [sendMedia]);

  const stopVoice = useCallback(() => {
    const rec = recorderRef.current;
    if (rec && rec.state !== 'inactive') rec.stop();
  }, []);

  const startVoice = useCallback(async () => {
    if (!clientRef.current || clientRef.current.isDestroyed) return;
    if (typeof MediaRecorder === 'undefined') {
      setMediaNotice('当前浏览器不支持录音（MediaRecorder 不可用）');
      return;
    }
    setMediaNotice('');
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const preferred = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4'];
      const mimeType = preferred.find((t) => MediaRecorder.isTypeSupported(t));
      const rec = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);

      recordChunksRef.current = [];
      rec.ondataavailable = (ev) => {
        if (ev.data.size > 0) recordChunksRef.current.push(ev.data);
      };
      rec.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        if (recordTimerRef.current) {
          clearInterval(recordTimerRef.current);
          recordTimerRef.current = null;
        }
        setRecording(false);

        const chunks = recordChunksRef.current;
        recordChunksRef.current = [];
        const type = rec.mimeType || 'audio/webm';
        const blob = new Blob(chunks, { type });

        // 会话已销毁 / 用户已退出：丢掉这次录音，不再发送
        if (!clientRef.current || clientRef.current.isDestroyed) return;
        if (blob.size < 300) {
          setMediaNotice('录音太短，已丢弃');
          return;
        }
        try {
          await sendMedia(await prepareVoice(blob, type));
        } catch (err) {
          setMediaNotice((err as Error).message);
        }
      };

      recorderRef.current = rec;
      rec.start();
      setRecording(true);
      setRecordSecs(0);
      recordTimerRef.current = setInterval(() => setRecordSecs((s) => s + 1), 1000);
    } catch (err) {
      setMediaNotice(`无法使用麦克风：${(err as Error).message}`);
    }
  }, [sendMedia]);

  const toggleVoice = useCallback(() => {
    if (recording) stopVoice();
    else void startVoice();
  }, [recording, startVoice, stopVoice]);

  // 录音到 60 秒自动停止并发送
  useEffect(() => {
    if (recording && recordSecs * 1000 >= MAX_VOICE_MS) stopVoice();
  }, [recording, recordSecs, stopVoice]);

  useEffect(() => () => {
    if (recordTimerRef.current) clearInterval(recordTimerRef.current);
  }, []);

  const connected = links.filter((l) => l.connected).length;
  const destroyed = status === 'destroyed';
  const canSend = status === 'online' && safetyNumber !== null && !destroyed;
  const callBusy = voiceState === 'calling' || voiceState === 'ringing' || voiceState === 'connecting';
  const callActive = voiceState === 'active';

  const startCall = useCallback(() => {
    if (!canSend || callBusy || callActive) return;
    void voiceRef.current?.startCall();
  }, [canSend, callBusy, callActive]);
  const acceptCall = useCallback(() => { void voiceRef.current?.acceptCall(); }, []);
  const rejectCall = useCallback(() => { voiceRef.current?.rejectCall(); }, []);
  const hangupCall = useCallback(() => { voiceRef.current?.hangup(); }, []);
  const toggleMute = useCallback(() => {
    setVoiceMuted(voiceRef.current?.toggleMute() ?? false);
  }, []);
  const dismissCall = useCallback(() => {
    setVoiceState('idle');
    setVoiceDetail('');
    setCallSecs(0);
  }, []);

  // 通话计时：只在 active 状态走秒
  useEffect(() => {
    if (voiceState !== 'active') { setCallSecs(0); return; }
    const timer = setInterval(() => setCallSecs((s) => s + 1), 1000);
    return () => clearInterval(timer);
  }, [voiceState]);

  /** 微信内置浏览器：不渲染任何会话 UI，也不创建 RelayClient（因此不会生成密钥） */
  if (blockedWebView.blocked) {
    const pageUrl = typeof location === 'undefined' ? '' : location.href;
    return (
      <div className="app">
        <section className="card blocked-view">
          <h2>请在浏览器中打开</h2>
          <p>
            检测到你正在 <strong>{blockedWebView.name}</strong> 的内置浏览器里访问本页面。
            为了保证加密能力（WebCrypto）与会话不被系统中断，密语<strong>不允许在微信内运行</strong>。
          </p>
          <p className="dim">请点右上角「…」→「在浏览器打开」（Safari / Chrome / Edge），或把下面的链接复制到浏览器粘贴打开：</p>
          <code className="blocked-url">{pageUrl}</code>
          <button
            className="primary wide"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(pageUrl);
                setBlockedCopied(true);
                setTimeout(() => setBlockedCopied(false), 1500);
              } catch {
                setBlockedCopied(false);
              }
            }}
          >
            {blockedCopied ? '已复制' : '复制链接'}
          </button>
          <p className="dim">本页只是入口限制；门禁按 UA 判断，真正的消息加密仍然只发生在浏览器内。</p>
        </section>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>密语 <span>SecretTalk</span></h1>
          <p className="sub">零知识中继 · AES-256-GCM · ECDH P-256 · SSS(3,5)</p>
        </div>
        <div className={`badge ${status}`}>
          {status === 'online' ? `${connected}/${RELAY_PORTS.length} 在线` :
           status === 'connecting' ? '连接中' :
           status === 'destroyed' ? '已销毁' : '未连接'}
        </div>
      </header>

      {/* 5 条链路状态：一眼看出哪台孤岛掉线 */}
      <div className="links">
        {RELAY_PORTS.map((p, i) => (
          <div key={p} className={`link ${links[i]?.connected ? 'on' : ''}`} title={servers[i]}>
            <i />
            <span>300{i + 1}</span>
            <small>#{i}</small>
          </div>
        ))}
      </div>

      {insecureReason && (
        <div className="insecure">
          <strong>当前页面无法使用加密功能</strong>
          <p>{insecureReason}</p>
          <p className="dim">
            本机调试请用 <code>http://localhost:5173</code>；
            手机通过局域网 IP 访问需要为页面部署 HTTPS，并把 5 台中继同步升级为 wss://。
          </p>
        </div>
      )}

      {destroyed ? (
        <div className="destroyed">
          <h2>会话已销毁</h2>
          <p>{EXIT_TEXT[exitReason ?? 'user_logout']}</p>
          <p className="dim">AES 密钥与 ECDH 私钥已用 0 覆写，5 台中继的内存缓存与 TTL 已清空。</p>
          <button className="primary" onClick={() => { setRoomId(createRoomId()); setStatus('idle'); setExitReason(null); setLinks([]); }}>
            创建新会话
          </button>
        </div>
      ) : (
        <>
          <section className="card config">
            <label>房间号（双方输入同一个即可入房，不用选角色）</label>
            <div className="row">
              <input value={roomId} onChange={(e) => setRoomId(e.target.value.trim())} disabled={status !== 'idle'} />
              <button onClick={copyRoom} disabled={status !== 'idle'}>{copied ? '已复制' : '复制'}</button>
              <button onClick={() => setRoomId(createRoomId())} disabled={status !== 'idle'}>换一个</button>
            </div>
            <p className="dim">把房间号发给对方，两人都点「进入会话」即自动握手。15 秒内未出现安全数时页面会提示原因（对方未进入 / 房间号不一致 / 房间已满）。</p>
            <label>中继地址（留空 = 同源网关，推荐；填 IP = 直连 3001~3005）</label>
            <input value={host} onChange={(e) => setHost(e.target.value)} disabled={status !== 'idle'} placeholder="留空自动走本页网关 /relay/0~4" />
            <div className="pool">{servers.map((s) => <code key={s}>{s}</code>)}</div>
            <button className="primary wide" onClick={join} disabled={status !== 'idle' || !!insecureReason}>进入会话</button>
          </section>

          {safetyNumber && (
            <section className="card sas">
              <span>安全数（双方核对一致才说明没有中间人）</span>
              <strong>{safetyNumber}</strong>
            </section>
          )}

          {notice && <div className="notice">{notice}</div>}

          <section className="card chat">
            <div className="chat-head">
              <span>消息</span>
              <div className="chat-actions">
                <button
                  className="ghost call-btn"
                  onClick={startCall}
                  disabled={!canSend || callBusy || callActive}
                  title="语音通话（WebRTC P2P，不经过中继）"
                >📞 语音</button>
                <button className="ghost" onClick={exit} disabled={status === 'idle'}>退出并销毁</button>
              </div>
            </div>

            {voiceState !== 'idle' && (
              <div className={`call-bar ${voiceState}`}>
                <span className="call-status">{voiceStatusText(voiceState, voiceDetail, callSecs)}</span>
                <div className="call-actions">
                  {voiceState === 'ringing' && (
                    <>
                      <button className="primary" onClick={acceptCall}>接听</button>
                      <button onClick={rejectCall}>拒绝</button>
                    </>
                  )}
                  {(voiceState === 'calling' || voiceState === 'connecting') && (
                    <button onClick={hangupCall}>取消</button>
                  )}
                  {voiceState === 'active' && (
                    <>
                      <button onClick={toggleMute}>{voiceMuted ? '取消静音' : '静音'}</button>
                      <button className="danger" onClick={hangupCall}>挂断</button>
                    </>
                  )}
                  {(voiceState === 'ended' || voiceState === 'error') && (
                    <button onClick={dismissCall}>关闭</button>
                  )}
                </div>
              </div>
            )}

            <audio ref={remoteAudioRef} autoPlay playsInline hidden />
            <div className="list">
              {messages.length === 0 && <p className="empty">尚无消息。文字、语音、图片、文件都会先在本地加密，再拆成 5 个碎片投递到 5 台孤岛中继。</p>}
              {messages.map((m) => (
                <div key={m.messageId} className={`bubble ${m.from === myRole ? 'mine' : 'theirs'}`}>
                  {m.attachment?.kind === 'image' && (
                    <img className="bubble-image" src={m.attachment.url} alt={m.attachment.name} />
                  )}
                  {m.attachment?.kind === 'audio' && (
                    <audio className="bubble-audio" controls preload="metadata" src={m.attachment.url} />
                  )}
                  {m.attachment?.kind === 'file' && (
                    <a
                      className="bubble-file"
                      href={m.attachment.url}
                      download={m.attachment.name}
                    >
                      📎 {m.attachment.name} <span className="bubble-file-size">（{formatBytes(m.attachment.size)}）</span>
                    </a>
                  )}
                  {m.error
                    ? <span className="err">{m.error}</span>
                    : (m.text ? <span>{m.text}</span> : null)}
                  <small>
                    {m.from === myRole ? '我' : '对方'} · {new Date(m.ts).toLocaleTimeString('zh-CN', { hour12: false })}
                    {m.status === 'sending' && ' · 加密中'}
                    {m.status === 'sent' && ' · 已发送'}
                    {m.status === 'read' && ' · 已读'}
                    {m.status === 'failed' && ' · 失败'}
                    {m.usedShares && ` · 碎片 ${m.usedShares.map((i) => `#${i}`).join('+')} 重组`}
                  </small>
                </div>
              ))}
            </div>
            <div className="composer">
              <button
                type="button"
                className="tool"
                title="发送图片"
                onClick={() => imageInputRef.current?.click()}
                disabled={!canSend}
              >🖼</button>
              <button
                type="button"
                className="tool"
                title="发送文件"
                onClick={() => fileInputRef.current?.click()}
                disabled={!canSend}
              >📎</button>
              <button
                type="button"
                className={`tool ${recording ? 'recording' : ''}`}
                title={recording ? '停止并发送语音' : '录制语音'}
                onClick={toggleVoice}
                disabled={!canSend && !recording}
              >{recording ? `⏹ ${recordSecs}s` : '🎤'}</button>
              <input
                value={text}
                onChange={(e) => setText(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') void send(); }}
                placeholder={canSend ? '输入密语…' : '等待双方上线并完成握手'}
                disabled={!canSend}
              />
              <button className="primary" onClick={send} disabled={!canSend}>发送</button>
              <input ref={imageInputRef} type="file" accept="image/*" hidden onChange={onPickImage} />
              <input ref={fileInputRef} type="file" hidden onChange={onPickFile} />
            </div>
            {recording && (
              <p className="recording-hint">录音中… {recordSecs}s / {Math.round(MAX_VOICE_MS / 1000)}s，点击 ⏹ 停止并发送</p>
            )}
            {mediaNotice && <p className="media-error">{mediaNotice}</p>}
          </section>

          <section className="card logs">
            <button className="log-toggle" onClick={() => setShowLog((v) => !v)}>
              链路日志 {showLog ? '收起' : '展开'}
            </button>
            {showLog && <pre>{logs.join('\n') || '暂无日志'}</pre>}
          </section>
        </>
      )}

      <footer>端到端加密 · 中继仅转发密文 · 任一方退出即刻销毁</footer>
    </div>
  );
}
