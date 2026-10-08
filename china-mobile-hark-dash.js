/*
 * 中国移动小组件（Egern 版，单文件三模式）· Hark 改版 v23（iOS 液态玻璃风格 + 用量洞察）
 * 状态：数据层已补全（逆向自 ChinaTelecomOperators/ChinaMobile 的 10086.js，加解密已验证）
 *
 * 三种用法（脚本 URL 填同一个文件）：
 *   1. generic 类型 → iOS 小组件：显示剩余话费 / 剩余流量 / 剩余语音
 *   2. http_request 类型 → 登录捕获：在「中国移动」App 里用短信验证码登录一次，
 *      自动存下加密参数（params）、x-qen 与 Cookie
 *   3. http_response 类型 → Cookie 刷新：自动从登录响应里抓 Set-Cookie
 *
 * 环境变量：
 *   CM_PHONENUMBER          移动手机号（必填，11 位）
 *   CM_SHOW_USED_FLOW       'true' 显示已用流量，否则显示剩余流量（默认剩余）
 *   CM_TITLE                小组件标题，默认 "中国移动"
 *   CM_WIDGET_STYLE         'glass'（默认）/ 'classic'
 *   CM_DEBUG                'true' 在小组件上显示调试信息
 *
 * 数据来源：
 *   https://app.10086.cn/biz-orange/BN/realFeeQuery/getRealFee
 *   https://app.10086.cn/biz-orange/BH/newPlanRemainQry/getNewPlanRemainQry
 */

'use strict';

/* ==================== 加解密（与 cm_crypto.js 同步，自研并经 node:crypto 验证） ==================== */

/*
 * cm_crypto.js — 自研 MD5 + AES-128-CBC（供 china-mobile.js 使用）
 * 与 node:crypto 交叉验证通过（见底部自测）
 * 注意：仅实现 AES-128（密钥/IV 均为 16 字节 UTF-8），CBC + Pkcs7
 */

'use strict';

/* ---------- UTF-8 / hex / base64 ---------- */

function utf8Bytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const lo = str.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
        i++;
      }
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return out;
}

function utf8String(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length;) {
    const b = bytes[i];
    if (b < 0x80) { s += String.fromCharCode(b); i++; }
    else if ((b & 0xe0) === 0xc0) { s += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f)); i += 2; }
    else if ((b & 0xf0) === 0xe0) { s += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f)); i += 3; }
    else {
      const c = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f);
      const v = c - 0x10000;
      s += String.fromCharCode(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
      i += 4;
    }
  }
  return s;
}

function bytesToHex(bytes) {
  return bytes.map((b) => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

const B64MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function base64Encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i], b1 = i + 1 < bytes.length ? bytes[i + 1] : 0, b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    s += B64MAP[(n >> 18) & 63] + B64MAP[(n >> 12) & 63] + (i + 1 < bytes.length ? B64MAP[(n >> 6) & 63] : '=') + (i + 2 < bytes.length ? B64MAP[n & 63] : '=');
  }
  return s;
}

/* ---------- MD5 ---------- */

function md5Hex(str) {
  const msg = utf8Bytes(str);
  const bitLen = msg.length * 8;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  for (let i = 0; i < 8; i++) msg.push((bitLen / Math.pow(2, i * 8)) & 0xff);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = [];
  for (let i = 0; i < 64; i++) K.push(Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0);

  const add = (x, y) => (x + y) >>> 0;
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

  for (let off = 0; off < msg.length; off += 64) {
    const M = [];
    for (let i = 0; i < 16; i++) {
      M.push((msg[off + i * 4] | (msg[off + i * 4 + 1] << 8) | (msg[off + i * 4 + 2] << 16) | (msg[off + i * 4 + 3] << 24)) >>> 0);
    }
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = add(add(add(F, A), K[i]), M[g]);
      A = D; D = C; C = B;
      B = add(B, rol(F, S[i]));
    }
    a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
  }
  const le = (x) => [x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff];
  return bytesToHex([].concat(le(a0), le(b0), le(c0), le(d0)));
}

/* ---------- AES-128 ---------- */

const AES_SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
const AES_INV_SBOX = new Array(256);
for (let i = 0; i < 256; i++) AES_INV_SBOX[AES_SBOX[i]] = i;
const AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function aesKeyExpand(keyBytes) {
  const Nk = 4, Nb = 4, Nr = 10;
  const W = new Array(4 * (Nr + 1));
  for (let i = 0; i < Nk; i++) {
    W[i] = (keyBytes[4*i] << 24) | (keyBytes[4*i+1] << 16) | (keyBytes[4*i+2] << 8) | keyBytes[4*i+3];
  }
  for (let i = Nk; i < 4 * (Nr + 1); i++) {
    let t = W[i - 1];
    if (i % Nk === 0) {
      t = ((AES_SBOX[(t >> 16) & 0xff] << 24) | (AES_SBOX[(t >> 8) & 0xff] << 16) | (AES_SBOX[t & 0xff] << 8) | AES_SBOX[(t >> 24) & 0xff]) ^ (AES_RCON[i / Nk - 1] << 24);
    }
    W[i] = (W[i - Nk] ^ t) >>> 0;
  }
  return W;
}

function xtime(a) { return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff; }
function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function aesAddRoundKey(s, W, round) {
  for (let c = 0; c < 4; c++) {
    const w = W[round * 4 + c];
    s[c*4+0] ^= (w >>> 24) & 0xff;
    s[c*4+1] ^= (w >>> 16) & 0xff;
    s[c*4+2] ^= (w >>> 8) & 0xff;
    s[c*4+3] ^= w & 0xff;
  }
}
function aesSubBytes(s, inv) {
  const box = inv ? AES_INV_SBOX : AES_SBOX;
  for (let i = 0; i < 16; i++) s[i] = box[s[i]];
}
function aesShiftRows(s, inv) {
  // state 按列存放: s[c*4+r]
  const t = s.slice();
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      const shift = inv ? (4 - r) % 4 : r;
      s[c*4+r] = t[((c + shift) % 4)*4+r];
    }
  }
}
function aesMixColumns(s, inv) {
  for (let c = 0; c < 4; c++) {
    const a = [s[c*4], s[c*4+1], s[c*4+2], s[c*4+3]];
    let b;
    if (!inv) {
      b = [gmul(a[0],2)^gmul(a[1],3)^a[2]^a[3],
            a[0]^gmul(a[1],2)^gmul(a[2],3)^a[3],
            a[0]^a[1]^gmul(a[2],2)^gmul(a[3],3),
            gmul(a[0],3)^a[1]^a[2]^gmul(a[3],2)];
    } else {
      b = [gmul(a[0],14)^gmul(a[1],11)^gmul(a[2],13)^gmul(a[3],9),
            gmul(a[0],9)^gmul(a[1],14)^gmul(a[2],11)^gmul(a[3],13),
            gmul(a[0],13)^gmul(a[1],9)^gmul(a[2],14)^gmul(a[3],11),
            gmul(a[0],11)^gmul(a[1],13)^gmul(a[2],9)^gmul(a[3],14)];
    }
    for (let r = 0; r < 4; r++) s[c*4+r] = b[r];
  }
}

function aesEncryptBlock(block16, W) {
  const s = block16.slice();
  aesAddRoundKey(s, W, 0);
  for (let r = 1; r < 10; r++) {
    aesSubBytes(s, false); aesShiftRows(s, false); aesMixColumns(s, false); aesAddRoundKey(s, W, r);
  }
  aesSubBytes(s, false); aesShiftRows(s, false); aesAddRoundKey(s, W, 10);
  return s;
}

function aesDecryptBlock(block16, W) {
  const s = block16.slice();
  aesAddRoundKey(s, W, 10);
  for (let r = 9; r >= 1; r--) {
    aesShiftRows(s, true); aesSubBytes(s, true); aesAddRoundKey(s, W, r); aesMixColumns(s, true);
  }
  aesShiftRows(s, true); aesSubBytes(s, true); aesAddRoundKey(s, W, 0);
  return s;
}

/* AES-128-CBC，key/iv 为字符串（按 UTF-8 取 16 字节） */
function aesCbcEncrypt(plainStr, keyStr, ivStr) {
  const key = utf8Bytes(keyStr).slice(0, 16);
  const iv = utf8Bytes(ivStr).slice(0, 16);
  let data = utf8Bytes(plainStr);
  const pad = 16 - (data.length % 16);
  for (let i = 0; i < pad; i++) data.push(pad);
  const W = aesKeyExpand(key);
  let prev = iv;
  const out = [];
  for (let off = 0; off < data.length; off += 16) {
    const block = [];
    for (let i = 0; i < 16; i++) block.push(data[off + i] ^ prev[i]);
    const enc = aesEncryptBlock(block, W);
    out.push(...enc);
    prev = enc;
  }
  return out;
}

function aesCbcDecrypt(cipherBytes, keyStr, ivStr) {
  const key = utf8Bytes(keyStr).slice(0, 16);
  const iv = utf8Bytes(ivStr).slice(0, 16);
  const W = aesKeyExpand(key);
  let prev = iv;
  const out = [];
  for (let off = 0; off < cipherBytes.length; off += 16) {
    const block = cipherBytes.slice(off, off + 16);
    const dec = aesDecryptBlock(block, W);
    for (let i = 0; i < 16; i++) out.push(dec[i] ^ prev[i]);
    prev = block;
  }
  const pad = out[out.length - 1];
  if (pad < 1 || pad > 16) throw new Error('bad padding');
  for (let i = 0; i < pad; i++) {
    if (out[out.length - 1 - i] !== pad) throw new Error('bad padding');
  }
  return out.slice(0, out.length - pad);
}

/* 对外接口：与原脚本语义一致（key/iv 作 UTF-8，输出 base64） */
function cmEncrypt(plainStr, keyStr, ivStr) {
  return base64Encode(aesCbcEncrypt(plainStr, keyStr, ivStr || '9791027341711819'));
}

function cmDecrypt(b64Str, keyStr, ivStr) {
  const raw = String(b64Str).replace(/[^A-Za-z0-9+/=]/g, '');
  const bytes = [];
  for (let i = 0; i < raw.length; i += 4) {
    const c = [0,1,2,3].map((k) => (raw[i+k] === '=' || !raw[i+k] ? 0 : B64MAP.indexOf(raw[i+k])));
    const n = (c[0] << 18) | (c[1] << 12) | (c[2] << 6) | c[3];
    bytes.push((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  }
  const padCount = (raw.match(/=+$/) || [''])[0].length;
  const trimmed = bytes.slice(0, bytes.length - padCount);
  return utf8String(aesCbcDecrypt(trimmed, keyStr, ivStr || '9791027341711819'));
}

function cmMd5(str) { return md5Hex(str); }


/* ==================== 常量（逆向所得） ==================== */

// 捕获参数的解密密钥（按 x-qen 选择）
const REQ_KEY = { '2': 'bAIgvwAuA4tbDr9d', '12': 'V0dSUFZtS1NWRnJa', '14': 'tVkdaRWRY0ZkV1Vr' };
const REQ_IV  = { '2': '9791027341711819', '12': 'UkdWMVpWTVVWaGVq', '14': 'VjFSQ1ZtVkQxRTlQ' };
// 查询请求/响应的加解密（x-qen 固定为 '1'）
const REQ1_KEY = 'foorettD7vcBawt3';
const RESP1_KEY = 'UVic06tpXgMNiApm';
const RESP2_KEY = 'GS7VelkJl5IT1uwQ';
const RESP14_KEY = 'RYV0hCV1lV25KYVJ';
const RESP14_IV = 'VjFSQ1ZtVkQxRTlQ';
const DEFAULT_IV = '9791027341711819';

const API_FEE = 'https://app.10086.cn/biz-orange/BN/realFeeQuery/getRealFee';
const API_PLAN = 'https://app.10086.cn/biz-orange/BH/newPlanRemainQry/getNewPlanRemainQry';
const UA_WAP = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148/wkwebview leadeon/9.2.5/CMCCIT';

const STORE = {
  paramsEnc: 'cm_params_enc',   // 捕获的 autoLogin 加密请求体
  xqen: 'cm_x_qen',             // 捕获的 x-qen（'2'/'12'/'14'）
  loginUrl: 'cm_login_url',     // 捕获的 autoLogin URL
  cookie: 'cm_cookie',          // Cookie / Set-Cookie
  loginTs: 'cm_login_ts',
  loginHeaders: 'cm_login_headers', // 捕获的 autoLogin 请求头（用于自动续期）
  refreshTs: 'cm_refresh_ts',       // 上次自动续期时间
  datasource: 'cm_datasource',
  rawDebug: 'cm_raw_debug',
  planDebug: 'cm_plan_debug',
};

/* ==================== 工具 ==================== */

function pad2(n) { return n < 10 ? `0${n}` : `${n}`; }

function fmtTime(ts) {
  const d = new Date(ts);
  return `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

function getHeader(headers, name) {
  if (!headers) return '';
  if (typeof headers.get === 'function') {
    try {
      const v = headers.get(name);
      if (v) return v;
    } catch (e) { /* ignore */ }
  }
  if (typeof headers.getSetCookie === 'function' && /set-cookie/i.test(name)) {
    try { return headers.getSetCookie().join('; '); } catch (e) { /* ignore */ }
  }
  const want = String(name).toLowerCase();
  for (const k of Object.keys(headers)) {
    if (String(k).toLowerCase() === want) {
      const v = headers[k];
      return Array.isArray(v) ? v.join('; ') : (v || '');
    }
  }
  return '';
}

function maskSecret(s, keep = 6) {
  s = String(s || '');
  if (s.length <= keep * 2) return s.slice(0, keep) + '***';
  return s.slice(0, keep) + '***' + s.slice(-keep);
}

function randomDigits(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += Math.floor(Math.random() * 10);
  return s;
}

/* ==================== 捕获 ==================== */

function isAutoLogin(url) {
  // 新主机：中国移动 App 实际走 10086.online-cmcc.cn:20010，登录路径待确认，先放行由 x-qen 过滤
  if (/10086\.online-cmcc\.cn/.test(url)) return true;
  // 老主机：autoLogin（登录）与 refreshSession（会话刷新，App 自动调用）都认
  return /client\.app\.coc\.10086\.cn/.test(url) &&
    /\/biz-orange\/[A-Z]{2}\/.*(autoLogin|refreshSession)/.test(url);
}

function dlog(ctx, msg) {
  // 侦察日志常开：只记方法+路径，不记查询参数与正文
  if (typeof console !== 'undefined' && console.log) {
    try { console.log(`[CM] ${msg}`); } catch (e) {}
  }
}

// http_request：在 App 登录时抓加密参数
async function handleCapture(ctx) {
  const req = ctx.request || {};
  const url = req.url || '';
  const headers = req.headers || {};
  const xqen = String(getHeader(headers, 'x-qen') || '').trim();
  const qmark = url.indexOf('?');
  dlog(ctx, `REQ ${req.method || ''} ${(qmark > 0 ? url.slice(0, qmark) : url).slice(0, 200)} x-qen=${xqen || '-'}`);
  dlog(ctx, `req keys=${Object.keys(req).join(',')}`);
  try {
    const g = (typeof $request !== 'undefined' && $request && $request.body);
    dlog(ctx, `global $request.body type=${g ? typeof g : 'n/a'} len=${g && g.length !== undefined ? g.length : 'n/a'}`);
  } catch (e) { dlog(ctx, `global $request 不可用`); }
  if (!isAutoLogin(url)) return;
  if (!REQ_KEY[xqen]) {
    dlog(ctx, `跳过：x-qen=${xqen || '(空)'} 不在 {2,12,14}`);
    return; // 只收 2/12/14 三种加密形态
  }

  // Egern ESM 的 ctx.request.body 可能是空对象，真正的 body 在传统全局 $request.body 里
  let rawBody = '';
  try {
    if (typeof $request !== 'undefined' && $request && typeof $request.body === 'string' && $request.body.length > 0) {
      rawBody = $request.body;
    }
  } catch (e) {}
  if (!rawBody) {
    const cb = req.body;
    rawBody = typeof cb === 'string' ? cb : JSON.stringify(cb || '');
  }
  const body = rawBody;
  dlog(ctx, `body类型=${typeof req.body} 长度=${body.length} base64=${/^[A-Za-z0-9+/=\r\n]+$/.test(body)}`);
  if (!body || body.length < 16) return;

  // 先验证能解密，防存坏数据；x-qen 指示的优先，不行就把所有已知组合试一遍
  let plain = null, usedQen = null;
  const tryOrder = [xqen, '2', '12', '14'].filter((v, i, a) => REQ_KEY[v] && a.indexOf(v) === i);
  for (const q of tryOrder) {
    try {
      const p = cmDecrypt(body, REQ_KEY[q], REQ_IV[q]);
      JSON.parse(p);
      plain = p; usedQen = q; break;
    } catch (e) { /* 换下一个组合试 */ }
  }
  if (!plain) {
    dlog(ctx, `解密失败（已试 ${tryOrder.join(',')}），跳过`);
    return;
  }
  dlog(ctx, `解密OK（x-qen=${usedQen}），顶层字段: ${Object.keys(JSON.parse(plain)).join(',').slice(0, 120)}`);

  const changed = ctx.storage.get(STORE.paramsEnc) !== body;
  ctx.storage.set(STORE.paramsEnc, body);
  ctx.storage.set(STORE.xqen, usedQen);
  ctx.storage.set(STORE.loginUrl, url);
  const cookie = String(getHeader(headers, 'cookie') || '').trim();
  if (cookie) ctx.storage.set(STORE.cookie, cookie);
  // 记下登录请求头，登录过期时用来自动重放续期
  try {
    const keep = {};
    const src = typeof headers.entries === 'function' ? Object.fromEntries(headers.entries()) : headers;
    for (const k of Object.keys(src || {})) {
      if (/^(cookie|content-length|connection|accept-encoding)$/i.test(k)) continue;
      keep[k] = Array.isArray(src[k]) ? src[k].join(', ') : String(src[k]);
    }
    ctx.storage.setJSON(STORE.loginHeaders, keep);
  } catch (e) {}

  if (changed) {
    ctx.storage.set(STORE.loginTs, String(Date.now()));
    ctx.notify({ title: '中国移动', body: '登录参数捕获成功，小组件将自动更新' });
    // 自检：用刚抓到的参数试一次话费查询，结果打日志（只在新捕获时跑一次）
    try {
      const params = JSON.parse(plain);
      const q = buildQuery(ctx, params, 'fee');
      dlog(ctx, `自检查询开始`);
      const resp = await ctx.http.post(q.url, { headers: q.headers, body: q.body, timeout: 15000 });
      dlog(ctx, `自检 HTTP=${resp ? resp.status : 'no-resp'}`);
      if (resp && resp.status === 200) {
        const text = typeof resp.text === 'function' ? await resp.text() : String(resp.body || '');
        const xpen = String(getHeader(resp.headers, 'x-pen') || '').trim();
        dlog(ctx, `自检 x-pen=${xpen} len=${text.length}`);
        let data;
        if (xpen === '1') {
          const inner = JSON.parse(text);
          data = JSON.parse(cmDecrypt(inner.body, RESP1_KEY, DEFAULT_IV));
        } else if (xpen === '2') {
          data = JSON.parse(cmDecrypt(text, RESP2_KEY, DEFAULT_IV));
        } else if (xpen === '14') {
          data = JSON.parse(cmDecrypt(text, RESP14_KEY, RESP14_IV));
        } else {
          data = JSON.parse(text);
        }
        const feeInfo = (data && (data.rspBody || (data.body && data.body.rspBody))) || {};
        dlog(ctx, `自检话费=${feeInfo.realBalanceFee || feeInfo.curFee || 'N/A'} ret=${(data && (data.retCode || '')) || ''}`);
      }
    } catch (e) {
      dlog(ctx, `自检失败: ${String((e && e.message) || e).slice(0, 120)}`);
    }
  }
}

// http_response：从登录响应里抓 Set-Cookie（保鲜）
async function handleRespCapture(ctx) {
  const req = ctx.request || {};
  const resp = ctx.response || {};
  const url = req.url || resp.url || '';
  if (!isAutoLogin(url)) return;
  // ESM 的 ctx.response.headers 可能为空，兜底读传统全局 $response
  let respHeaders = resp.headers || {};
  try {
    if (typeof $response !== 'undefined' && $response && $response.headers) {
      const gh = $response.headers;
      if (!respHeaders['set-cookie'] && !respHeaders['Set-Cookie'] && (gh['set-cookie'] || gh['Set-Cookie'])) {
        respHeaders = gh;
      }
    }
  } catch (e) {}
  const setCookie = String(getHeader(respHeaders, 'set-cookie') || '').trim();
  if (setCookie && ctx.storage.get(STORE.cookie) !== setCookie) {
    ctx.storage.set(STORE.cookie, setCookie);
  }
}

/* ==================== 数据层 ==================== */


// 手机号：优先读 Env，Env 为空时用本地备份；Env 里填了就备份到本地
function getPhone(ctx) {
  const fromEnv = (ctx.env.CM_PHONENUMBER || '').trim();
  if (/^\d{11}$/.test(fromEnv)) {
    try { ctx.storage.set('cm_phone_backup', fromEnv); } catch (e) {}
    return fromEnv;
  }
  try {
    const bak = (ctx.storage.get('cm_phone_backup') || '').trim();
    if (/^\d{11}$/.test(bak)) return bak;
  } catch (e) {}
  return '';
}

function decryptParams(ctx) {
  const enc = ctx.storage.get(STORE.paramsEnc) || '';
  const xqen = (ctx.storage.get(STORE.xqen) || '').trim();
  if (!enc || !REQ_KEY[xqen]) {
    const e = new Error('no-params');
    e.stage = 'capture';
    throw e;
  }
  const plain = cmDecrypt(enc, REQ_KEY[xqen], REQ_IV[xqen]);
  const params = JSON.parse(plain);
  return params;
}

function buildQuery(ctx, params, kind) {
  const phone = getPhone(ctx);
  if (!/^\d{11}$/.test(phone)) {
    const e = new Error('no-phone');
    e.stage = 'phone';
    throw e;
  }
  const cookie = ctx.storage.get(STORE.cookie) || '';
  const ts = Date.now();
  const nonce = randomDigits(8);
  const pathname = kind === 'fee'
    ? '/biz-orange/BN/realFeeQuery/getRealFee'
    : '/biz-orange/BH/newPlanRemainQry/getNewPlanRemainQry';

  // 明文正文：捕获参数 + 手机号 + cookie
  const bodyObj = Object.assign({}, params, { reqBody: { cellNum: phone }, t: cookie });
  if (kind === 'fee') bodyObj.nt = '5';
  const encBody = cmEncrypt(JSON.stringify(bodyObj), REQ1_KEY, DEFAULT_IV);

  // x-token：AES(xk_pathname_ts_nonce)
  const xk = params.xk || '';
  const tokenEnc = cmEncrypt(`${xk}_${pathname}_${ts}_${nonce}`, REQ1_KEY, DEFAULT_IV);

  // x-sign：MD5(x-token_ts_nonce_jsessionid)
  const m = cookie.match(/JSESSIONID=(.+?);/);
  const jsid = m ? m[1] : 'null';
  const xsign = cmMd5(`${tokenEnc}_${ts}_${nonce}_${jsid}`);

  const headers = {
    'Host': 'app.10086.cn',
    'x-qen': '1',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
    'x-sign': xsign,
    'x-nonce': nonce,
    'x-token': tokenEnc,
    'Sec-Fetch-Mode': 'cors',
    'Origin': 'https://h.app.coc.10086.cn',
    'User-Agent': UA_WAP,
    'x-time': String(ts),
    'Sec-Fetch-Des': 'empty',
  };
  return {
    url: `https://app.10086.cn${pathname}?` + encodeURI(cookie),
    headers,
    body: encBody,
  };
}

// 从任意响应里收 Set-Cookie，滚动保持会话
function absorbSetCookie(ctx, headers) {
  const sc = String(getHeader(headers, 'set-cookie') || '').trim();
  if (sc && /JSESSIONID=/i.test(sc) && ctx.storage.get(STORE.cookie) !== sc) {
    ctx.storage.set(STORE.cookie, sc);
    return true;
  }
  return false;
}

// 登录过期时：重放捕获到的 autoLogin 请求换新 Cookie（10 分钟内最多一次）
async function autoRefreshSession(ctx) {
  const url = ctx.storage.get(STORE.loginUrl) || '';
  const body = ctx.storage.get(STORE.paramsEnc) || '';
  if (!url || !body) return false;
  const last = parseInt(ctx.storage.get(STORE.refreshTs) || '0', 10);
  if (Date.now() - last < 10 * 60 * 1000) return false;
  ctx.storage.set(STORE.refreshTs, String(Date.now()));
  let headers = {};
  try { headers = ctx.storage.getJSON(STORE.loginHeaders) || {}; } catch (e) {}
  if (!Object.keys(headers).some((k) => /^x-qen$/i.test(k))) headers['x-qen'] = ctx.storage.get(STORE.xqen) || '2';
  if (!Object.keys(headers).some((k) => /^content-type$/i.test(k))) headers['Content-Type'] = 'application/json';
  if (!Object.keys(headers).some((k) => /^user-agent$/i.test(k))) headers['User-Agent'] = UA_WAP;
  const oldCookie = ctx.storage.get(STORE.cookie) || '';
  if (oldCookie) headers['Cookie'] = oldCookie;
  try {
    const resp = await ctx.http.post(url, { headers, body, timeout: 15000 });
    const ok = !!resp && resp.status === 200 && absorbSetCookie(ctx, resp.headers);
    dlog(ctx, `自动续期 HTTP=${resp ? resp.status : 'no-resp'} 新Cookie=${ok}`);
    return ok;
  } catch (e) {
    dlog(ctx, `自动续期失败: ${String((e && e.message) || e).slice(0, 80)}`);
    return false;
  }
}

async function queryKind(ctx, kind) {
  const params = decryptParams(ctx);
  const q = buildQuery(ctx, params, kind);
  const resp = await ctx.http.post(q.url, { headers: q.headers, body: q.body, timeout: 15000 });
  if (!resp || resp.status !== 200) {
    const e = new Error(`HTTP ${resp ? resp.status : 'no-response'}`);
    e.stage = 'network';
    throw e;
  }
  absorbSetCookie(ctx, resp.headers);
  const text = typeof resp.text === 'function' ? await resp.text() : String(resp.body || '');
  if (ctx.env.CM_DEBUG === 'true') ctx.storage.set(STORE.rawDebug, text.slice(0, 300));

  const xpen = String(getHeader(resp.headers, 'x-pen') || '').trim();
  let data;
  try {
    if (xpen === '1') {
      const inner = JSON.parse(text);
      data = JSON.parse(cmDecrypt(inner.body, RESP1_KEY, DEFAULT_IV));
    } else if (xpen === '2') {
      data = JSON.parse(cmDecrypt(text, RESP2_KEY, DEFAULT_IV));
    } else if (xpen === '14') {
      data = JSON.parse(cmDecrypt(text, RESP14_KEY, RESP14_IV));
    } else {
      data = JSON.parse(text);
    }
  } catch (e) {
    const err = new Error('decrypt-failed');
    err.stage = 'decrypt';
    throw err;
  }
  // 诊断：记下解密后数据的顶层结构（不记值）
  try {
    if (kind === 'plan' && ctx.env.CM_DEBUG === 'true') {
      const keys = data && typeof data === 'object' ? Object.keys(data).join(',') : typeof data;
      const inner = data && (data.rspBody || (data.body && data.body.rspBody)) || {};
      const innerKeys = inner && typeof inner === 'object' ? Object.keys(inner).join(',') : '';
      const resObj = (inner && inner.newPlanRemainQryRes) || {};
      const resKeys = resObj && typeof resObj === 'object' ? Object.keys(resObj).join(',') : '';
      const rc = data && (data.retCode || (data.body && data.body.retCode)) || '';
      const rd = data && (data.retDesc || (data.body && data.body.retDesc)) || '';
      ctx.storage.set(STORE.planDebug, `top:[${String(keys).slice(0, 120)}] rspBody:[${String(innerKeys).slice(0, 150)}] res:[${String(resKeys).slice(0, 200)}] ret:${rc}/${String(rd).slice(0, 60)}`);
    }
  } catch (e) {}
  return data;
}

function toFlowUnit(remain, unit) {
  if (unit === '03') {
    return remain >= 1024
      ? { number: (remain / 1024).toFixed(2), unit: 'GB' }
      : { number: remain.toFixed(2), unit: 'MB' };
  }
  if (unit === '04') return { number: remain.toFixed(2), unit: 'GB' };
  return { number: remain.toFixed(2), unit: String(unit || '') };
}

// 递归深搜：找包含指定键的数组（应对字段嵌套位置变化）
function deepFindArrays(obj, keyName, out, seen) {
  if (!obj || typeof obj !== 'object') return;
  if (seen.has(obj)) return;
  seen.add(obj);
  if (Array.isArray(obj)) {
    if (obj.length && obj[0] && typeof obj[0] === 'object' && keyName in obj[0]) out.push(obj);
    for (const item of obj) deepFindArrays(item, keyName, out, seen);
  } else {
    for (const k of Object.keys(obj)) deepFindArrays(obj[k], keyName, out, seen);
  }
}

function parseMobile(feeData, planData, opts) {
  const feeInfo = (feeData && (feeData.rspBody || (feeData.body && feeData.body.rspBody))) || {};
  const planBody = (planData && (planData.rspBody || (planData.body && planData.body.rspBody))) || {};
  // 套餐数据包在 rspBody.newPlanRemainQryRes 里（兼容直接平铺的旧结构）
  const planInfo = planBody.newPlanRemainQryRes || planBody;

  const feeNum = parseFloat(feeInfo.realBalanceFee || feeInfo.curFee || '0');
  const fee = {
    title: '剩余话费',
    number: Number.isFinite(feeNum) ? feeNum.toFixed(2) : '0.00',
    unit: '元',
  };

  // 流量：先直接取，取不到就深搜（严格判断数组防 .filter 炸）
  // 实际字段名为 planRemianFlowListRes（含 List）
  const flowArrDirect = Array.isArray(planInfo.planRemianFlowListRes) ? planInfo.planRemianFlowListRes
    : Array.isArray(planInfo.planRemianFlowRes) ? planInfo.planRemianFlowRes : [];
  let flowArrAll = flowArrDirect;
  let flows = flowArrDirect.filter((f) => f && f.flowtype == 0);
  if (!flows.length && planData) {
    const found = [];
    deepFindArrays(planData, 'flowRemainNum', found, new Set());
    const arr = Array.isArray(found[0]) ? found[0] : [];
    if (arr.length) flowArrAll = arr;
    flows = arr.filter((f) => f && f.flowtype == 0);
    if (!flows.length && arr.length) flows = arr.slice(0, 1); // 实在没有 flowtype 就取第一条
  }
  // 国内其他流量：flowtype != 0 的各项求和（统一按 MB 累加再格式化）
  let otherFlow = { title: '其他流量', number: '--', unit: '', percent: 0, color: '#5AC8FA' };
  const otherItems = flowArrAll.filter((f) => f && f.flowtype != 0);
  if (otherItems.length) {
    let totalMb = 0, sumMb = 0;
    for (const f of otherItems) {
      const remain = parseFloat(f.flowRemainNum || '0');
      if (!Number.isFinite(remain)) continue;
      const k = String(f.unit || '03') === '04' ? 1024 : 1;
      totalMb += remain * k;
      const s = parseFloat(f.flowSumNum || '0');
      if (Number.isFinite(s)) sumMb += s * k;
    }
    const u = totalMb >= 1024
      ? { number: (totalMb / 1024).toFixed(2), unit: 'GB' }
      : { number: totalMb.toFixed(2), unit: 'MB' };
    otherFlow = { title: '其他流量', number: u.number, unit: u.unit, percent: sumMb > 0 ? Math.max(0, Math.min(1, totalMb / sumMb)) : 0, color: '#5AC8FA' };
  }
  let flow = { title: '剩余流量', number: '--', unit: '', percent: 0, color: '#0A84FF' };
  if (flows.length) {
    const remain = parseFloat(flows[0].flowRemainNum || '0');
    const u = toFlowUnit(remain, String(flows[0].unit || '03'));
    const showUsed = opts && opts.showUsedFlow;
    flow = {
      title: showUsed ? '已用流量' : '剩余流量',
      number: u.number,
      unit: u.unit,
      percent: 0,
      color: '#0A84FF',
    };
    const sum = parseFloat(flows[0].flowSumNum || '0');
    if (Number.isFinite(sum) && sum > 0) flow.percent = Math.max(0, Math.min(1, remain / sum));
    flow.total = Number.isFinite(sum) && sum > 0 ? toFlowUnit(sum, String(flows[0].unit || '03')) : null;
    if (showUsed && flows[0].flowUsdNum) {
      const used = parseFloat(flows[0].flowUsdNum || '0');
      const uu = toFlowUnit(used, String(flows[0].unit || '03'));
      flow.number = uu.number;
      flow.unit = uu.unit;
    }
  }

  // 语音：先直接取，取不到就深搜（严格判断数组防 .filter 炸）
  const voiceArr = Array.isArray(planInfo.planRemianVoiceListRes) ? planInfo.planRemianVoiceListRes : [];
  let voices = voiceArr.filter((v) => v && v.voicetype == 0);
  if (!voices.length && planData) {
    const found = [];
    deepFindArrays(planData, 'voiceRemainNum', found, new Set());
    const arr = Array.isArray(found[0]) ? found[0] : [];
    voices = arr.filter((v) => v && v.voicetype == 0);
    if (!voices.length && arr.length) voices = arr.slice(0, 1);
  }
  let voice = { title: '剩余语音', number: '--', unit: '分钟', percent: 0, color: '#30D158' };
  if (voices.length) {
    const remain = parseInt(voices[0].voiceRemainNum || '0', 10);
    voice.number = String(Number.isFinite(remain) ? remain : 0);
    const vs = parseInt(voices[0].voiceSumNum || '0', 10);
    if (Number.isFinite(vs) && vs > 0) voice.percent = Math.max(0, Math.min(1, remain / vs));
  }

  const feeOk = feeInfo && (feeInfo.realBalanceFee != null || feeInfo.curFee != null);
  const valid = feeOk || flows.length > 0 || voices.length > 0;
  return { fee, flow, otherFlow, voice, updatedAt: Date.now(), valid };
}

async function loadData(ctx) {
  const debug = ctx.env.CM_DEBUG === 'true';
  const phone = getPhone(ctx);
  const hasParams = !!(ctx.storage.get(STORE.paramsEnc));
  if (!hasParams) return { configured: false, reason: 'capture', debug };
  if (!/^\d{11}$/.test(phone)) return { configured: false, reason: 'phone', debug };

  const fetchAll = async () => {
    const feeData = await queryKind(ctx, 'fee');
    const planData = await queryKind(ctx, 'plan');
    const ds = parseMobile(feeData, planData, {
      showUsedFlow: ctx.env.CM_SHOW_USED_FLOW === 'true',
    });
    return { feeData, planData, ds };
  };
  try {
    let { feeData, planData, ds } = await fetchAll();
    // 登录过期 → 自动重放登录续期，成功就再查一次
    if (!ds.valid && await autoRefreshSession(ctx)) {
      ({ feeData, planData, ds } = await fetchAll());
    }
    // 接口返回 200 但内容是错误（多为登录态过期）：不覆盖缓存，回退旧数据
    if (!ds.valid) {
      const rc = (d) => d && (d.retCode || (d.body && d.body.retCode)) || '';
      const rd = (d) => d && (d.retDesc || (d.body && d.body.retDesc)) || '';
      const err = new Error(`empty ${rc(feeData)}/${rc(planData)} ${String(rd(planData) || rd(feeData)).slice(0, 40)}`);
      err.stage = 'session';
      throw err;
    }
    delete ds.valid;
    if (debug) ds.planDebug = ctx.storage.get(STORE.planDebug) || '';
    ctx.storage.setJSON(STORE.datasource, ds);
    return { configured: true, ds, fromCache: false, debug };
  } catch (e) {
    let cached = ctx.storage.getJSON(STORE.datasource);
    // 旧版本可能把空数据写进了缓存，这种缓存不用
    if (cached && cached.flow && cached.flow.number === '--' && cached.voice && cached.voice.number === '--') cached = null;
    if (cached) cached.stale = (e && e.stage) === 'session' ? '登录过期' : '缓存';
    const errInfo = debug ? ` [${(e && e.stage) || '?'}:${String((e && e.message) || e).slice(0, 60)}]` : '';
    if (cached) cached.planDebug = (cached.planDebug || '') + errInfo;
    return {
      configured: true, ds: cached || null, fromCache: !!cached, debug,
      error: String((e && e.message) || e), stage: (e && e.stage) || '',
    };
  }
}

/* ==================== 渲染层（Widget DSL）· v23 iOS 液态玻璃风格 ==================== */
// 设计：Apple「健身圆环」式三环（通用流量/其他流量/语音）+ 液态玻璃卡片
// 新功能：今日已用流量、月底前日均可用、本月剩余天数、话费不足提醒

const C_FEE = '#FF9F0A';
const C_FLOW = '#0A84FF';
const C_OTHER = '#64D2FF';
const C_VOICE = '#30D158';
const WARN = '#FF453A';
const TXT = { light: '#000000', dark: '#FFFFFF' };
const SUB = { light: '#3C3C4399', dark: '#EBEBF599' };
const GLASS = { light: '#FFFFFFA6', dark: '#FFFFFF1A' };

function bg() {
  return {
    type: 'linear',
    colors: [{ light: '#EAF3FF', dark: '#0B1A33' }, { light: '#F4F0FF', dark: '#120B24' }, { light: '#E9FBF3', dark: '#03140F' }],
    stops: [0, 0.55, 1],
    startPoint: { x: 0, y: 0 },
    endPoint: { x: 1, y: 1 },
  };
}

/* ---------- 用量洞察 ---------- */

function toMB(d) {
  const n = parseFloat(d && d.number);
  if (!Number.isFinite(n)) return null;
  return d.unit === 'GB' ? n * 1024 : n;
}

function fmtMB(mb) {
  if (mb == null || !Number.isFinite(mb)) return '--';
  return mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(0)} MB`;
}

function insights(ctx, ds) {
  const now = new Date();
  const dayKey = `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}`;
  const dim = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const daysLeft = dim - now.getDate() + 1;
  // 按 通用 + 其他流量 合计剩余统计
  const _g = toMB(ds.flow), _o = toMB(ds.otherFlow);
  const flowMB = ctx.env.CM_SHOW_USED_FLOW === 'true' ? null
    : (_g == null && _o == null ? null : (_g || 0) + (_o || 0));
  let todayMB = null;
  if (flowMB != null) {
    let snap = null;
    try { snap = ctx.storage.getJSON('cm_day_snap'); } catch (e) {}
    // 新的一天，或流量变多（加油包/月初重置）→ 重新记起点
    if (!snap || snap.date !== dayKey || flowMB > snap.start + 1) {
      snap = { date: dayKey, start: flowMB };
      try { ctx.storage.setJSON('cm_day_snap', snap); } catch (e) {}
    }
    todayMB = Math.max(0, snap.start - flowMB);
  }
  // 近 7 天每日用量历史（旧 → 今天）
  const hist = [];
  if (todayMB != null) {
    let h = {};
    try { h = ctx.storage.getJSON('cm_hist') || {}; } catch (e) {}
    h[dayKey] = todayMB;
    const keep = {};
    for (let i = 7; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86400000);
      const k = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
      if (h[k] != null) keep[k] = h[k];
      if (i <= 6) hist.push(h[k] == null ? null : h[k]);
    }
    try { ctx.storage.setJSON('cm_hist', keep); } catch (e) {}
  }
  // 按近 6 天（不含今天）平均用量预测
  let forecast = { text: '用量统计中…', color: SUB };
  if (flowMB != null) {
    const past = hist.slice(0, 6).filter(v => v != null && v > 0);
    const vals = past.length ? past : (todayMB > 0 ? [todayMB] : []);
    if (vals.length) {
      const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
      const days = Math.floor(flowMB / avg);
      forecast = days >= daysLeft
        ? { text: days > 999 ? '按近期速度 充足' : `预计够用 ${days} 天 ✓`, color: C_VOICE }
        : { text: `约 ${days} 天用完 · 早于月底`, color: C_FEE };
    }
  }
  return {
    hist,
    forecast,
    daysLeft,
    monthPct: (now.getDate() - 1 + now.getHours() / 24) / dim,
    todayMB,
    dailyMB: flowMB != null ? flowMB / daysLeft : null,
    lowFee: (() => { const n = parseFloat(ds.fee.number); return Number.isFinite(n) && n < 10; })(),
  };
}

/* ---------- 图形 ---------- */

// 三层同心圆环（外→内：通用流量、其他流量、语音）
function ringsSvg(values, size, stroke, gap) {
  const h = size / 2;
  let body = '';
  values.forEach((v, i) => {
    const r = h - stroke / 2 - i * (stroke + gap);
    if (r <= stroke / 2) return;
    const c = 2 * Math.PI * r;
    const p = Math.max(0, Math.min(1, Number(v.pct) || 0));
    body += `<circle cx='${h}' cy='${h}' r='${r.toFixed(2)}' fill='none' stroke='${v.color}' stroke-opacity='0.22' stroke-width='${stroke}'/>`;
    if (p > 0) {
      // 用 path 圆弧绘制进度，不依赖 stroke-dasharray
      if (p >= 0.999) {
        body += `<circle cx='${h}' cy='${h}' r='${r.toFixed(2)}' fill='none' stroke='${v.color}' stroke-width='${stroke}'/>`;
      } else {
        const a = p * 2 * Math.PI;
        const x = (h + r * Math.sin(a)).toFixed(2), y = (h - r * Math.cos(a)).toFixed(2);
        body += `<path d='M ${h} ${(h - r).toFixed(2)} A ${r.toFixed(2)} ${r.toFixed(2)} 0 ${p > 0.5 ? 1 : 0} 1 ${x} ${y}' fill='none' stroke='${v.color}' stroke-width='${stroke}' stroke-linecap='round'/>`;
      }
    }
  });
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${size} ${size}'>${body}</svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

function ringSvg(pct, size, stroke) {
  return ringsSvg([{ pct, color: 'white' }], size, stroke, 0);
}

function barSvg(pct, color, w, h) {
  const p = Math.max(0, Math.min(1, Number(pct) || 0));
  const r = h / 2, fw = p > 0 ? Math.max(h, w * p) : 0;
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'>` +
    `<rect width='${w}' height='${h}' rx='${r}' fill='${color}' fill-opacity='0.2'/>` +
    (fw ? `<rect width='${fw.toFixed(1)}' height='${h}' rx='${r}' fill='${color}'/>` : '') + `</svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

// 半圆仪表
function gaugeSvg(pct, color, w) {
  const stroke = 12, r = (w - stroke) / 2, cx = w / 2, cy = w / 2, h = w / 2 + stroke / 2;
  const p = Math.max(0, Math.min(1, Number(pct) || 0));
  const pt = a => [(cx - r * Math.cos(a)).toFixed(2), (cy - r * Math.sin(a)).toFixed(2)];
  const [x0, y0] = pt(0), [x1, y1] = pt(Math.PI), [xp, yp] = pt(Math.PI * p);
  let body = `<path d='M ${x0} ${y0} A ${r} ${r} 0 0 1 ${x1} ${y1}' fill='none' stroke='${color}' stroke-opacity='0.22' stroke-width='${stroke}' stroke-linecap='round'/>`;
  if (p > 0.005) body += `<path d='M ${x0} ${y0} A ${r} ${r} 0 0 1 ${xp} ${yp}' fill='none' stroke='${color}' stroke-width='${stroke}' stroke-linecap='round'/>`;
  return 'data:image/svg+xml,' + encodeURIComponent(`<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'>${body}</svg>`);
}

// 近 7 天用量柱状图（最后一根是今天）
function sparkSvg(values, color, w, h) {
  const vals = values && values.length ? values : [null, null, null, null, null, null, null];
  const n = vals.length, gap = 3, bw = (w - gap * (n - 1)) / n;
  const max = Math.max(1, ...vals.map(v => v || 0));
  let body = '';
  vals.forEach((v, i) => {
    const bh = v ? Math.max(2, (v / max) * h) : 2;
    const op = v == null ? 0.15 : (i === n - 1 ? 1 : 0.55);
    body += `<rect x='${(i * (bw + gap)).toFixed(1)}' y='${(h - bh).toFixed(1)}' width='${bw.toFixed(1)}' height='${bh.toFixed(1)}' rx='${Math.min(2, bw / 2).toFixed(1)}' fill='${color}' fill-opacity='${op}'/>`;
  });
  return 'data:image/svg+xml,' + encodeURIComponent(`<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'>${body}</svg>`);
}

// 仪表卡：图标+名称 / 半圆仪表+百分比 / 数值
function gaugeCard(icon, color, d, fallbackTitle, opt) {
  const o = opt || {};
  const data = d || { title: fallbackTitle, number: '--', unit: '', percent: 0 };
  const pct = data.percent > 0 ? Math.round(data.percent * 100) : 0;
  const gw = o.gw || 46;
  return glass([
    {
      type: 'stack', direction: 'row', alignItems: 'center', gap: 3,
      children: [
        { type: 'image', src: `sf-symbol:${icon}`, width: 10, height: 10, color },
        t(o.title || data.title || fallbackTitle, 9, 'medium', SUB, { minScale: 1 }),
      ],
    },
    {
      type: 'stack', direction: 'column', alignItems: 'center', gap: -3,
      children: [
        { type: 'image', src: gaugeSvg(data.percent, color, 64), width: gw, height: Math.round(gw * 38 / 64) },
        t(`${pct}%`, 9, 'bold', color, { minScale: 1 }),
      ],
    },
    {
      type: 'stack', direction: 'row', alignItems: 'end', gap: 2,
      children: [
        t(data.number, o.numSize || 15, 'bold', TXT, { minScale: 0.7 }),
        t(data.unit || '', 9, 'semibold', SUB, { minScale: 1 }),
      ],
    },
  ], { flex: 1, alignItems: 'center', gap: 2, padding: [7, 4], borderRadius: 16, ...(o.height ? { height: o.height } : {}) });
}

function ringValues(ds) {
  const o = ds.otherFlow || {};
  return [
    { pct: ds.flow.percent, color: C_FLOW },
    { pct: o.percent, color: C_OTHER },
    { pct: ds.voice.percent, color: C_VOICE },
  ];
}

/* ---------- 组件 ---------- */

function t(text, size, weight, color, extra) {
  return Object.assign({ type: 'text', text: String(text), font: { size, weight: weight || 'regular' }, textColor: color || TXT, maxLines: 1, minScale: 0.6 }, extra || {});
}

function header(title, ds, fromCache) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
    children: [
      { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', width: 12, height: 12, color: C_FLOW },
      t(title, 'footnote', 'semibold'),
      { type: 'spacer' },
      t(`${fromCache ? ((ds && ds.stale) || '缓存') + ' · ' : ''}更新 ${ds && ds.updatedAt ? fmtTime(ds.updatedAt) : '--'}`, 10, 'regular', SUB, { minScale: 1 }),
    ],
  };
}

function feeBig(ds, ins, size) {
  const color = ins.lowFee ? WARN : TXT;
  return {
    type: 'stack', direction: 'column', alignItems: 'start', gap: 0,
    children: [
      t(ins.lowFee ? '话费不足' : '剩余话费', 'caption2', 'medium', ins.lowFee ? WARN : SUB),
      {
        type: 'stack', direction: 'row', alignItems: 'end', gap: 1,
        children: [
          t('¥', 'subheadline', 'semibold', ins.lowFee ? WARN : SUB),
          t(ds.fee.number, size || 28, 'bold', color),
        ],
      },
    ],
  };
}

function legendRow(icon, color, d, extra) {
  const data = d || { title: '', number: '--', unit: '' };
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 5,
    children: [
      { type: 'image', src: `sf-symbol:${icon}`, width: 12, height: 12, color },
      t(data.title, 'caption1', 'regular', SUB),
      { type: 'spacer' },
      t(data.number, 'subheadline', 'bold', TXT),
      t(data.unit ? ` ${data.unit}` : '', 'caption2', 'regular', SUB),
      ...(extra ? [t(`  ${extra}`, 'caption2', 'semibold', color)] : []),
    ],
  };
}

function pctText(d) { return d && d.percent > 0 ? `${Math.round(d.percent * 100)}%` : ''; }

function chip(icon, color, text) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 4, padding: [5, 8], borderRadius: 99,
    backgroundColor: GLASS,
    children: [
      { type: 'image', src: `sf-symbol:${icon}`, width: 11, height: 11, color },
      t(text, 'caption2', 'semibold', TXT),
    ],
  };
}

function glass(children, extra) {
  return Object.assign({ type: 'stack', direction: 'column', alignItems: 'start', gap: 6, padding: 12, borderRadius: 22, backgroundColor: GLASS, children }, extra || {});
}

/* ---------- 尺寸 ---------- */

function feeCard(ds, ins, size, extra) {
  const low = ins.lowFee;
  return glass([
    {
      type: 'stack', direction: 'row', alignItems: 'center', gap: 3,
      children: [
        { type: 'image', src: 'sf-symbol:yensign.circle.fill', width: 10, height: 10, color: low ? WARN : C_FEE },
        t(low ? '话费不足' : '剩余话费', 9, 'medium', low ? WARN : SUB, { minScale: 1 }),
      ],
    },
    { type: 'spacer' },
    {
      type: 'stack', direction: 'row', alignItems: 'end', gap: 1,
      children: [t('¥', 11, 'semibold', low ? WARN : SUB, { minScale: 1 }), t(ds.fee.number, size || 22, 'bold', low ? WARN : TXT, { minScale: 0.6 })],
    },
    t(`本月剩 ${ins.daysLeft} 天`, 9, 'medium', SUB, { minScale: 1 }),
    ...(extra && extra.alignItems === 'center' ? [{ type: 'spacer' }] : []),
  ], Object.assign({ gap: 2, padding: [7, 9], borderRadius: 16 }, extra || {}));
}

function statsStrip(ins, sparkW) {
  return glass([
    {
      type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
      children: [
        { type: 'image', src: sparkSvg(ins.hist, C_FLOW, 70, 14), width: sparkW || 46, height: 11 },
        t(`今日 ${fmtMB(ins.todayMB)}`, 9, 'semibold', TXT, { minScale: 1 }),
        t(`日均可用 ${fmtMB(ins.dailyMB)}`, 9, 'medium', SUB, { minScale: 1 }),
        { type: 'spacer' },
        t(ins.forecast.text, 9, 'semibold', ins.forecast.color, { minScale: 0.8 }),
      ],
    },
  ], { padding: [6, 9], borderRadius: 12, gap: 0 });
}

function refresh30() { return new Date(Date.now() + 30 * 60 * 1000).toISOString(); }

function buildSmall(title, ds, fromCache, ctx) {
  const ins = insights(ctx, ds);
  return {
    type: 'widget', padding: 12, gap: 5, backgroundGradient: bg(), refreshAfter: refresh30(),
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
        children: [
          { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', width: 11, height: 11, color: C_FLOW },
          t(title, 'caption1', 'semibold'),
          { type: 'spacer' },
          t(`¥${ds.fee.number}`, 11, 'bold', ins.lowFee ? WARN : C_FEE, { minScale: 1 }),
        ],
      },
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 4, flex: 1,
        children: [
          {
            type: 'stack', direction: 'column', alignItems: 'start', gap: 0,
            children: [
              t('剩余流量', 9, 'medium', SUB, { minScale: 1 }),
              { type: 'stack', direction: 'row', alignItems: 'end', gap: 2, children: [t(ds.flow.number, 22, 'bold', TXT), t(ds.flow.unit || '', 9, 'semibold', SUB, { minScale: 1 })] },
            ],
          },
          { type: 'spacer' },
          {
            type: 'stack', direction: 'column', alignItems: 'center', gap: -3,
            children: [
              { type: 'image', src: gaugeSvg(ds.flow.percent, C_FLOW, 64), width: 42, height: 25 },
              t(pctText(ds.flow) || '0%', 9, 'bold', C_FLOW, { minScale: 1 }),
            ],
          },
        ],
      },
      {
        type: 'stack', direction: 'row', alignItems: 'end', gap: 5,
        children: [
          { type: 'image', src: sparkSvg(ins.hist, C_FLOW, 70, 14), width: 44, height: 11 },
          t(`今日 ${fmtMB(ins.todayMB)}`, 9, 'semibold', TXT, { minScale: 1 }),
        ],
      },
      t(`语音 ${ds.voice.number}${ds.voice.unit || ''} · 日均 ${fmtMB(ins.dailyMB)}`, 9, 'medium', SUB, { minScale: 0.8 }),
      t(ins.forecast.text, 9, 'semibold', ins.forecast.color, { minScale: 0.8 }),
    ],
  };
}

function buildMedium(title, ds, fromCache, ctx) {
  const ins = insights(ctx, ds);
  return {
    type: 'widget', padding: [10, 11], gap: 6, backgroundGradient: bg(), refreshAfter: refresh30(),
    children: [
      header(title, ds, fromCache),
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 6, flex: 1,
        children: [
          feeCard(ds, ins, 21, { width: 84, height: 82, alignItems: 'center' }),
          gaugeCard('wifi', C_FLOW, ds.flow, '剩余流量', { height: 82 }),
          gaugeCard('globe.asia.australia.fill', C_OTHER, ds.otherFlow, '其他流量', { height: 82 }),
          gaugeCard('phone.fill', C_VOICE, ds.voice, '剩余语音', { height: 82 }),
        ],
      },
      statsStrip(ins, 40),
      ...(ds.planDebug ? [t(ds.planDebug, 'caption2', 'regular', SUB, { maxLines: 3 })] : []),
    ],
  };
}

function buildLarge(title, ds, fromCache, ctx) {
  const ins = insights(ctx, ds);
  const phone = getPhone(ctx);
  const masked = /^\d{11}$/.test(phone) ? `${phone.slice(0, 3)} **** ${phone.slice(7)}` : '';
  const labels = [];
  for (let i = 6; i >= 0; i--) { const d = new Date(Date.now() - i * 86400000); labels.push(i === 0 ? '今' : `${d.getDate()}`); }
  return {
    type: 'widget', padding: 14, gap: 9, backgroundGradient: bg(), refreshAfter: refresh30(),
    children: [
      header(title, ds, fromCache),
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 8,
        children: [
          feeCard(ds, ins, 30, { flex: 1, height: 74, padding: [9, 12] }),
          glass([
            t('当前号码', 9, 'medium', SUB, { minScale: 1 }),
            t(masked || '--', 13, 'semibold', TXT, { family: 'Menlo', minScale: 0.7 }),
            { type: 'spacer' },
            t(ins.forecast.text, 10, 'semibold', ins.forecast.color, { minScale: 0.7 }),
          ], { flex: 1, height: 74, gap: 2, padding: [9, 12], borderRadius: 16 }),
        ],
      },
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 8,
        children: [
          gaugeCard('wifi', C_FLOW, ds.flow, '剩余流量', { gw: 62, numSize: 18 }),
          gaugeCard('globe.asia.australia.fill', C_OTHER, ds.otherFlow, '其他流量', { gw: 62, numSize: 18 }),
          gaugeCard('phone.fill', C_VOICE, ds.voice, '剩余语音', { gw: 62, numSize: 18 }),
        ],
      },
      glass([
        {
          type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
          children: [
            { type: 'image', src: 'sf-symbol:chart.bar.fill', width: 10, height: 10, color: C_FLOW },
            t('近 7 天流量', 10, 'semibold', TXT, { minScale: 1 }),
            { type: 'spacer' },
            t(`今日 ${fmtMB(ins.todayMB)} · 日均可用 ${fmtMB(ins.dailyMB)}`, 9, 'medium', SUB, { minScale: 0.8 }),
          ],
        },
        { type: 'image', src: sparkSvg(ins.hist, C_FLOW, 290, 40), width: 290, height: 40 },
        {
          type: 'stack', direction: 'row', alignItems: 'center', gap: 0,
          children: labels.map(l => ({ type: 'stack', direction: 'row', flex: 1, children: [{ type: 'spacer' }, t(l, 8, 'medium', SUB, { minScale: 1 }), { type: 'spacer' }] })),
        },
      ], { gap: 5, padding: [9, 12], borderRadius: 16 }),
      { type: 'spacer' },
      ...(ds.planDebug ? [t(ds.planDebug, 'caption2', 'regular', SUB, { maxLines: 3 })] : []),
    ],
  };
}

function buildLockScreen(title, ds, family, ctx) {
  const ins = insights(ctx, ds);
  if (family === 'accessoryInline') {
    return { type: 'widget', children: [{ type: 'text', text: `¥${ds.fee.number} · ${ds.flow.number}${ds.flow.unit} · ${ds.voice.number}分`, maxLines: 1, minScale: 0.6 }] };
  }
  if (family === 'accessoryCircular') {
    const hasPct = ds.flow && ds.flow.percent > 0;
    return {
      type: 'widget', padding: 8, backgroundImage: ringSvg(hasPct ? ds.flow.percent : 0, 60, 6),
      children: [
        { type: 'spacer' },
        {
          type: 'stack', direction: 'column', alignItems: 'center', gap: 0,
          children: hasPct
            ? [
              { type: 'image', src: 'sf-symbol:wifi', width: 10, height: 10 },
              { type: 'text', text: String(ds.flow.number), font: { size: 14, weight: 'bold' }, textAlign: 'center', maxLines: 1, minScale: 0.5 },
              { type: 'text', text: ds.flow.unit, font: { size: 9 }, textAlign: 'center', opacity: 0.7 },
            ]
            : [
              { type: 'text', text: '¥', font: { size: 9 }, textAlign: 'center', opacity: 0.7 },
              { type: 'text', text: ds.fee.number, font: { size: 14, weight: 'bold' }, textAlign: 'center', maxLines: 1, minScale: 0.5 },
            ],
        },
        { type: 'spacer' },
      ],
    };
  }
  return {
    type: 'widget', padding: [2, 4], gap: 2,
    children: [
      { type: 'text', text: `¥${ds.fee.number}${ins.lowFee ? ' · 话费不足' : ''}`, font: { size: 'footnote', weight: 'bold' }, maxLines: 1, minScale: 0.6 },
      { type: 'text', text: `流量 ${ds.flow.number} ${ds.flow.unit} · 语音 ${ds.voice.number}分`, font: { size: 'caption2', weight: 'semibold' }, maxLines: 1, minScale: 0.6 },
      { type: 'text', text: ins.todayMB != null ? `今日 ${fmtMB(ins.todayMB)} · 日均 ${fmtMB(ins.dailyMB)}` : `还剩 ${ins.daysLeft} 天`, font: { size: 'caption2' }, opacity: 0.7, maxLines: 1, minScale: 0.6 },
    ],
  };
}

function buildError(title, message, extra) {
  const children = [
    t(title, 'footnote', 'semibold'),
    { type: 'spacer' },
    { type: 'image', src: 'sf-symbol:exclamationmark.triangle.fill', width: 22, height: 22, color: C_FEE },
    t(message, 'caption1', 'medium', TXT, { maxLines: 4, minScale: 0.7 }),
  ];
  if (extra) children.push(t(extra, 'caption2', 'regular', SUB, { maxLines: 3 }));
  children.push({ type: 'spacer' });
  return { type: 'widget', padding: 14, gap: 6, backgroundGradient: bg(), children };
}

/* ==================== 小组件（generic） ==================== */

async function handleWidget(ctx) {
  const title = (ctx.env.CM_TITLE || '中国移动').trim() || '中国移动';
  const r = await loadData(ctx);

  if (!r.configured) {
    if (r.reason === 'phone') {
      return buildError(title, '请在模块 Env 里填写 CM_PHONENUMBER（11 位移动手机号）');
    }
    return buildError(title, '还没抓到登录参数：打开「中国移动」App，用短信验证码登录一次');
  }
  if (!r.ds) {
    const hint = r.stage === 'decrypt'
      ? '解密失败：可能 App 升级了加密，请重新打开 App 抓一次'
      : r.stage === 'network'
        ? '网络请求失败，请检查网络或代理'
        : r.stage === 'session'
          ? '登录已过期：打开「中国移动」App 停留 10 秒刷新登录，再回桌面'
          : '查询失败：打开「中国移动」App 等 10 秒，让脚本刷新 Cookie 后再试';
    return buildError(title, hint, r.debug ? `错误: ${r.error || ''}` : '');
  }

  const family = ctx.widgetFamily || 'systemSmall';
  if (family === 'systemLarge' || family === 'systemExtraLarge') return buildLarge(title, r.ds, r.fromCache, ctx);
  if (family === 'systemMedium') return buildMedium(title, r.ds, r.fromCache, ctx);
  if (family.startsWith('accessory')) return buildLockScreen(title, r.ds, family, ctx);
  return buildSmall(title, r.ds, r.fromCache, ctx);
}

/* ==================== 入口：单文件三模式 ==================== */

export default async function (ctx) {
  // ctx.request 存在 → request/response 捕获；否则 → 小组件
  if (ctx.request && ctx.request.url) {
    // response 脚本同时带 request 与 response；优先按 response 处理
    if (ctx.response && (ctx.response.status || ctx.response.headers)) {
      return handleRespCapture(ctx);
    }
    return handleCapture(ctx);
  }
  // 定时保活：每 20 分钟查一次，防止会话因长时间不操作被注销（410000）
  if (ctx.env && ctx.env.CM_KEEPALIVE === 'true') return handleKeepAlive(ctx);
  return handleWidget(ctx);
}

async function handleKeepAlive(ctx) {
  const r = await loadData(ctx);
  const expired = r.configured && (r.stage === 'session' || !r.ds || r.fromCache);
  dlog(ctx, `保活 ${expired ? '失败:' + (r.error || '') : '成功'}`);
  if (expired && r.stage === 'session') {
    const last = parseInt(ctx.storage.get('cm_expire_notify') || '0', 10);
    if (Date.now() - last > 6 * 3600 * 1000) {
      ctx.storage.set('cm_expire_notify', String(Date.now()));
      ctx.notify({ title: '中国移动', body: '登录已过期，打开「中国移动」App 停留几秒即可恢复' });
    }
  } else if (!expired) {
    ctx.storage.set('cm_expire_notify', '0');
  }
}
