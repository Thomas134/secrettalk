/**
 * 密语 SecretTalk · WebRTC 语音通话（P2P）
 * ===========================================================================
 * 【范围】只做「一对一语音通话」的最小可用版本：
 *   - 信令（offer/answer/ice/hangup/reject）借用现有 5 台中继之一原样转发；
 *   - 语音媒体走 WebRTC P2P，由浏览器强制使用 DTLS-SRTP 加密，**不经过中继**；
 *   - 本阶段不接入应用层 E2E 封装（即不套 SSS/AES-GCM 那套），中继能看到
 *     SDP 与 ICE 候选（含 IP），但看不到声音。
 *
 * 只使用公共 STUN；对称 NAT / 严格防火墙下可能连不通，此时会明确报错。
 */
import { createMessageId, type RtcSignal } from '../shared/protocol.js';

export type VoiceState = 'idle' | 'calling' | 'ringing' | 'connecting' | 'active' | 'ended' | 'error';

export interface VoiceCallbacks {
  send: (signal: RtcSignal) => void;
  onState: (state: VoiceState, detail?: string) => void;
  onRemoteStream: (stream: MediaStream | null) => void;
}

const ICE_SERVERS: RTCIceServer[] = [
  { urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] },
];

/** 这些状态下一律视为「忙」 */
const BUSY: VoiceState[] = ['calling', 'ringing', 'connecting', 'active'];

export class VoiceCall {
  private pc: RTCPeerConnection | null = null;
  private localStream: MediaStream | null = null;
  private remoteStream: MediaStream | null = null;
  private callId = '';
  private role: 'caller' | 'callee' | null = null;
  private pendingOffer: string | null = null;
  private pendingCandidates: RTCIceCandidateInit[] = [];
  private remoteDescSet = false;
  private state: VoiceState = 'idle';
  private muted = false;

  constructor(private readonly cb: VoiceCallbacks) {}

  get currentState(): VoiceState { return this.state; }
  get isMuted(): boolean { return this.muted; }

  private setState(state: VoiceState, detail?: string): void {
    this.state = state;
    this.cb.onState(state, detail);
  }

  /** 主叫：采集麦克风 → 建 PC → 发 offer */
  async startCall(): Promise<void> {
    if (BUSY.includes(this.state)) return;
    this.reset();
    this.callId = createMessageId();
    this.role = 'caller';
    this.setState('calling');
    try {
      await this.ensureMic();
      this.createPeer();
      const offer = await this.pc!.createOffer();
      await this.pc!.setLocalDescription(offer);
      this.cb.send({ callId: this.callId, kind: 'offer', sdp: offer.sdp ?? '' });
    } catch (e) {
      this.fail(e);
    }
  }

  /** 被叫接听：采集麦克风 → 建 PC → 设远端 offer → 回 answer */
  async acceptCall(): Promise<void> {
    if (this.state !== 'ringing' || !this.pendingOffer) return;
    try {
      await this.ensureMic();
      this.createPeer();
      await this.pc!.setRemoteDescription({ type: 'offer', sdp: this.pendingOffer });
      this.remoteDescSet = true;
      await this.flushCandidates();
      const answer = await this.pc!.createAnswer();
      await this.pc!.setLocalDescription(answer);
      this.cb.send({ callId: this.callId, kind: 'answer', sdp: answer.sdp ?? '' });
      this.setState('connecting');
    } catch (e) {
      this.fail(e);
    }
  }

  rejectCall(): void {
    if (this.state !== 'ringing') return;
    this.cb.send({ callId: this.callId, kind: 'reject', reason: 'declined' });
    this.reset();
    this.setState('ended', '已拒绝通话');
  }

  hangup(): void {
    if (this.state === 'idle' || this.state === 'ended') return;
    this.cb.send({ callId: this.callId, kind: 'hangup' });
    this.reset();
    this.setState('ended', '通话已结束');
  }

  toggleMute(): boolean {
    this.muted = !this.muted;
    this.localStream?.getAudioTracks().forEach((t) => { t.enabled = !this.muted; });
    return this.muted;
  }

  /** 处理对端信令（由 RelayClient.onRtc 转发进来） */
  async handleSignal(signal: RtcSignal): Promise<void> {
    if (signal.kind === 'offer') {
      if (BUSY.includes(this.state)) {
        // 正在通话/呼叫中：礼貌拒绝新的来电
        this.cb.send({ callId: signal.callId, kind: 'reject', reason: 'busy' });
        return;
      }
      this.reset();
      this.callId = signal.callId;
      this.role = 'callee';
      this.pendingOffer = signal.sdp;
      this.setState('ringing');
      return;
    }

    // 迟到的旧通话信令直接丢弃
    if (!this.callId || signal.callId !== this.callId) return;

    switch (signal.kind) {
      case 'answer':
        if (this.role !== 'caller' || !this.pc) return;
        try {
          await this.pc.setRemoteDescription({ type: 'answer', sdp: signal.sdp });
          this.remoteDescSet = true;
          await this.flushCandidates();
          this.setState('connecting');
        } catch (e) {
          this.fail(e);
        }
        break;
      case 'ice':
        if (!this.pc || !this.remoteDescSet) {
          this.pendingCandidates.push(signal.candidate);
          return;
        }
        try { await this.pc.addIceCandidate(signal.candidate); } catch { /* 过期候选直接忽略 */ }
        break;
      case 'reject':
        this.reset();
        this.setState('ended', signal.reason === 'busy' ? '对方正在通话中' : '对方拒绝了通话');
        break;
      case 'hangup':
        this.reset();
        this.setState('ended', '对方已挂断');
        break;
    }
  }

  /** 会话销毁 / 组件卸载时调用：只清理本地资源，不再发信令 */
  dispose(): void {
    this.reset();
    this.setState('idle');
  }

  private async ensureMic(): Promise<void> {
    if (this.localStream) return;
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error('当前浏览器不支持麦克风采集（需要 https / localhost）');
    }
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: false,
    });
  }

  private createPeer(): void {
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    this.remoteDescSet = false;

    for (const track of this.localStream!.getTracks()) pc.addTrack(track, this.localStream!);

    pc.onicecandidate = (e) => {
      if (!e.candidate || !this.callId) return;
      const json = e.candidate.toJSON();
      this.cb.send({
        callId: this.callId,
        kind: 'ice',
        candidate: {
          candidate: json.candidate ?? '',
          sdpMid: json.sdpMid ?? null,
          sdpMLineIndex: json.sdpMLineIndex ?? null,
          ...(json.usernameFragment !== undefined ? { usernameFragment: json.usernameFragment } : {}),
        },
      });
    };

    pc.ontrack = (e) => {
      this.remoteStream = e.streams[0] ?? new MediaStream([e.track]);
      this.cb.onRemoteStream(this.remoteStream);
    };

    pc.onconnectionstatechange = () => {
      if (!this.pc) return;
      switch (this.pc.connectionState) {
        case 'connected':
          this.setState('active');
          break;
        case 'failed':
          this.fail(new Error('P2P 连接失败：双方网络受限（如需稳定跨网通话需部署 TURN 服务器）'));
          break;
        case 'disconnected':
          this.reset();
          this.setState('ended', '连接中断');
          break;
      }
    };

    this.pc = pc;
  }

  private async flushCandidates(): Promise<void> {
    const queued = this.pendingCandidates.splice(0);
    for (const c of queued) {
      try { await this.pc?.addIceCandidate(c); } catch { /* 忽略 */ }
    }
  }

  private reset(): void {
    const pc = this.pc;
    this.pc = null;
    if (pc) {
      pc.onicecandidate = null;
      pc.ontrack = null;
      pc.onconnectionstatechange = null;
      try { pc.close(); } catch { /* 忽略 */ }
    }
    this.localStream?.getTracks().forEach((t) => { try { t.stop(); } catch { /* 忽略 */ } });
    this.localStream = null;
    this.remoteStream = null;
    this.pendingCandidates = [];
    this.pendingOffer = null;
    this.remoteDescSet = false;
    this.muted = false;
    this.role = null;
    this.callId = '';
    this.cb.onRemoteStream(null);
  }

  private fail(e: unknown): void {
    const message = e instanceof Error ? e.message : String(e);
    this.reset();
    this.setError(message);
  }

  private setError(message: string): void {
    this.setState('error', message);
  }
}
