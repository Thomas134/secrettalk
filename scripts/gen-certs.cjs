/**
 * SecretTalk · 自签证书生成脚本（gen-certs.cjs）
 * ===========================================================================
 * 【为什么需要它】
 * WebCrypto（crypto.subtle）只在安全上下文可用：https:// 或 http://localhost。
 * 手机通过局域网 IP 以 http:// 访问时浏览器拒绝提供加密 API，因此本地部署
 * 必须上 HTTPS —— 网关（server/gateway.ts）用这里生成的证书终结 TLS。
 *
 * 【零外部依赖】用 node-forge 纯 JS 生成证书，不需要安装 openssl，
 * CMD / PowerShell / Git Bash 都能直接 `node scripts/gen-certs.cjs`。
 *
 * 【产物】（certs/ 已被 .gitignore 忽略，绝不入库）
 *   certs/ca.pem     自签根 CA —— 想免「不安全警告」的设备可安装并信任它
 *                    （网关也提供 https://<host>:<port>/ca.crt 下载）
 *   certs/server.key 服务器私钥
 *   certs/server.pem 服务器证书（由上面的 CA 签发，SAN 覆盖本机所有地址）
 *
 * 【SAN 覆盖】localhost、127.0.0.1、以及本机全部内网 IPv4（自动探测），
 * 换了 Wi-Fi / IP 变化后重新执行（--force）即可。
 *
 * 用法：
 *   node scripts/gen-certs.cjs           # certs/ 缺失时生成，已存在则跳过
 *   node scripts/gen-certs.cjs --force   # 删除旧的，强制重新生成
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const forge = require('node-forge');

const CERTS_DIR = path.resolve(__dirname, '../certs');
const CA_PEM = path.join(CERTS_DIR, 'ca.pem');
const SERVER_KEY = path.join(CERTS_DIR, 'server.key');
const SERVER_PEM = path.join(CERTS_DIR, 'server.pem');

/** 收集本机所有内网 IPv4 + 回环地址，写进证书 SAN，手机用任一 IP 访问都匹配 */
function collectHostNames() {
  const names = new Set(['localhost']);
  const ips = new Set(['127.0.0.1']);
  for (const list of Object.values(os.networkInterfaces())) {
    for (const ni of list || []) {
      if (ni.family !== 'IPv4' || ni.internal) continue;
      // 排除链路本地地址 169.254.x.x（无 DHCP 时的自动配置，不可用）
      if (ni.address.startsWith('169.254.')) continue;
      ips.add(ni.address);
    }
  }
  return { names: [...names], ips: [...ips] };
}

function generate() {
  const { names, ips } = collectHostNames();
  console.log('[gen-certs] SAN 域名:', names.join(', '), '| IP:', ips.join(', '));

  const now = new Date();
  const notAfter = new Date(now.getTime() + 10 * 365 * 24 * 3600 * 1000);

  // ---------- 1) 根 CA ----------
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const caCert = forge.pki.createCertificate();
  caCert.publicKey = caKeys.publicKey;
  caCert.serialNumber = String(Date.now());
  caCert.validity.notBefore = new Date(now.getTime() - 24 * 3600 * 1000); // 提前一天，容忍时钟偏差
  caCert.validity.notAfter = notAfter;
  caCert.setSubject([{ name: 'commonName', value: 'SecretTalk Local CA' }]);
  caCert.setIssuer(caCert.subject.attributes); // 自签
  caCert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
  ]);
  caCert.sign(caKeys.privateKey, forge.md.sha256.create());

  // ---------- 2) 服务器证书（CA 签发，SAN 覆盖本机地址） ----------
  const serverKeys = forge.pki.rsa.generateKeyPair(2048);
  const serverCert = forge.pki.createCertificate();
  serverCert.publicKey = serverKeys.publicKey;
  serverCert.serialNumber = String(Date.now() + 1);
  serverCert.validity.notBefore = caCert.validity.notBefore;
  serverCert.validity.notAfter = notAfter;
  serverCert.setSubject([{ name: 'commonName', value: 'SecretTalk Gateway' }]);
  serverCert.setIssuer(caCert.subject.attributes);
  serverCert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: [
        ...names.map((n) => ({ type: 2, value: n })), // type 2 = DNS
        ...ips.map((ip) => ({ type: 7, ip })),        // type 7 = IP
      ],
    },
  ]);
  serverCert.sign(caKeys.privateKey, forge.md.sha256.create());

  // ---------- 3) 落盘 ----------
  fs.writeFileSync(CA_PEM, forge.pki.certificateToPem(caCert) + '\n');
  fs.writeFileSync(SERVER_KEY, forge.pki.privateKeyToPem(serverKeys.privateKey) + '\n');
  fs.writeFileSync(SERVER_PEM, forge.pki.certificateToPem(serverCert) + '\n');

  console.log('[gen-certs] 已生成:');
  console.log('  CA     :', CA_PEM, '（可安装到手机以消除警告）');
  console.log('  私钥   :', SERVER_KEY);
  console.log('  证书   :', SERVER_PEM);
}

// ---- 入口 ----
if (process.argv.includes('--force')) {
  fs.rmSync(CERTS_DIR, { recursive: true, force: true });
  console.log('[gen-certs] --force：已删除旧证书');
}
if (fs.existsSync(CA_PEM) && fs.existsSync(SERVER_KEY) && fs.existsSync(SERVER_PEM)) {
  console.log('[gen-certs] certs/ 已存在，跳过生成（重新生成请加 --force）');
} else {
  fs.mkdirSync(CERTS_DIR, { recursive: true });
  generate();
}
