/**
 * 中国移动 · 签到领流量（Egern 原生版，Hark）
 * 每天自动在「中国移动」App 的「签到领流量」活动签到，并代领累计/连签奖励（流量券、话费券等）。
 *
 * 用法：
 *   1. 启用模块，确认 Egern 的 MITM 证书已安装并信任；
 *   2. 打开「中国移动」App →「我的」→「签到领流量」，进入签到页，看到「签到凭证已保存」通知即可；
 *   3. 之后每天定时自动签到领奖，结果用通知告诉你。小组件显示累计天数和最近领到的奖励。
 *
 * 接口链路（wx.10086.cn / qwhdhub mark31，参考 yupaiLy/cmcc-auto-checkin 抓包分析）：
 *   GET  /qwhdsso/login?actUrl=…            → 取一次性 loginPath(sid)
 *   POST /qwhdsso/appTokenLogin?sid=…        → 用 jwt（长期）或 App 票据换活动页 URL，并下发新 jwt
 *   GET  <活动页?token=…>                     → Set-Cookie: QWHD_SESSION_TOKEN
 *   POST /qwhdhub/api/mark/mark31/markstatus  → 签到状态 + 可领奖励
 *   POST /qwhdhub/api/mark/mark31/domark      → 签到
 *   POST /qwhdhub/api/mark/mark31/taskAward/<id> → 领奖
 *
 * env：CMCC_ACTIVITY_ID 活动 ID（默认 1021122301）；CMCC_CHANNEL_ID 渠道（默认 P00000109876）；
 *      CMCC_CLAIM 是否代领奖励（默认 true）；CMCC_NOTIFY 通知级别 all / fail / off（默认 all）；
 *      CMCC_CAPTURE 是否抓取凭证（默认 true）；MODE=sign 时作为定时任务签到。
 */

const BASE = 'https://wx.10086.cn';
const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148/wkwebview leadeon/12.5.2/CMCCIT';
const KEY = { cred: 'cmcc_sign_cred', last: 'cmcc_sign_last', live: 'cmcc_sign_live', seen: 'cmcc_sign_seen' };
const NAME = '中国移动签到';

const clean = (v) => String(v == null ? '' : v).trim();
const pad = (n) => String(n).padStart(2, '0');
const ymd = (d = new Date()) => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rand = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

function opts(ctx) {
  const e = ctx.env || {};
  return {
    activityId: clean(e.CMCC_ACTIVITY_ID) || '1021122301',
    channelId: clean(e.CMCC_CHANNEL_ID) || 'P00000109876',
    claim: clean(e.CMCC_CLAIM) !== 'false',
    notify: ['all', 'fail', 'off'].includes(clean(e.CMCC_NOTIFY)) ? clean(e.CMCC_NOTIFY) : 'all',
    capture: clean(e.CMCC_CAPTURE) !== 'false',
    mode: clean(e.MODE).toLowerCase(),
  };
}

function getCred(ctx) {
  try { return ctx.storage.getJSON(KEY.cred) || {}; } catch (_) { return {}; }
}
function setCred(ctx, c) { ctx.storage.setJSON(KEY.cred, c); }
function getLast(ctx) {
  try { return ctx.storage.getJSON(KEY.last) || {}; } catch (_) { return {}; }
}

function say(ctx, level, title, body) {
  const n = opts(ctx).notify;
  if (n === 'off') return;
  if (n === 'fail' && level !== 'fail') return;
  try { ctx.notify({ title: NAME, subtitle: title, body }); } catch (_) {}
}

async function readBody(obj, globalName) {
  // Egern ESM 下 body 偶尔为空，兜底读传统全局 $request / $response
  let text = '';
  try {
    const g = globalName === 'request'
      ? (typeof $request !== 'undefined' ? $request : null)
      : (typeof $response !== 'undefined' ? $response : null);
    if (g && typeof g.body === 'string' && g.body) text = g.body;
  } catch (_) {}
  let consumed = false;
  if (!text && obj && typeof obj.text === 'function') {
    try { text = await obj.text(); consumed = true; } catch (_) {}
  }
  return { text, consumed };
}

/* ==================== 凭证抓取（App 打开签到页时） ==================== */

async function captureRequest(ctx) {
  const { text, consumed } = await readBody(ctx.request, 'request');
  let b = null;
  try { b = JSON.parse(text); } catch (_) {}
  if (b && (b.token || b.jwtToken || b.userCheckId)) {
    const c = getCred(ctx);
    const next = {
      ...c,
      provinceCode: clean(b.provinceCode) || c.provinceCode || '',
      cityCode: clean(b.cityCode) || c.cityCode || '',
      userCheckId: clean(b.userCheckId) || c.userCheckId || '',
      carrierOperator: clean(b.carrierOperator) || c.carrierOperator || '002',
      appVersionCode: clean(b.appVersionCode) || c.appVersionCode || '12.5.2',
    };
    if (clean(b.token)) next.token = clean(b.token);
    if (clean(b.jwtToken) && clean(b.jwtToken) !== 'null') next.jwt = clean(b.jwtToken);
    next.capturedAt = Date.now();
    setCred(ctx, next);
    console.log(`[CMCC] 请求凭证已更新 province=${next.provinceCode} token=${next.token ? 'Y' : 'N'} jwt=${next.jwt ? 'Y' : 'N'}`);
  }
  return consumed ? { body: text } : undefined;
}

async function captureResponse(ctx) {
  const { text, consumed } = await readBody(ctx.response, 'response');
  let r = null;
  try { r = JSON.parse(text); } catch (_) {}
  const jwt = r && r.code === 'SUCCESS' && r.data && clean(r.data.jwt);
  if (jwt) {
    const c = getCred(ctx);
    const first = !c.jwt || c.expired;
    c.jwt = jwt;
    c.expired = false;
    c.jwtAt = Date.now();
    setCred(ctx, c);
    if (first) {
      try { ctx.notify({ title: NAME, subtitle: '签到凭证已保存', body: '之后每天会自动签到领流量，不用再打开这个页面' }); } catch (_) {}
    }
    console.log('[CMCC] jwt 已更新');
  }
  return consumed ? { body: text } : undefined;
}

// 签到页自己发出的活动请求里带着 *_SESSION_TOKEN（约 30 分钟有效）：存下来，立刻能直接签到
function saveLive(ctx, cookie, referer) {
  const m = String(cookie || '').match(/(?:^|;\s*)([A-Z]+_SESSION_TOKEN)=([^;]+)/);
  if (!m) return false;
  const prev = liveRaw(ctx);
  ctx.storage.setJSON(KEY.live, { cookie: String(cookie), referer: referer || (prev && prev.referer) || '', ts: Date.now() });
  return !prev || !String(prev.cookie).includes(m[2]);
}
function liveRaw(ctx) { try { return ctx.storage.getJSON(KEY.live); } catch (_) { return null; } }
function liveSession(ctx) {
  const l = liveRaw(ctx);
  if (!l || !l.cookie || Date.now() - (l.ts || 0) > 25 * 60000) return null;
  const jar = cookieJar();
  for (const kv of String(l.cookie).split(/;\s*/)) {
    const i = kv.indexOf('=');
    if (i > 0) jar.put(kv.slice(0, i).trim(), kv.slice(i + 1).trim());
  }
  return { jar, referer: l.referer || `${BASE}/qwhdhub/qwhdmark/1021122301?channelId=P00000109876`, live: true };
}

function markSeen(ctx, url) {
  // 第一次看到 wx.10086.cn 的活动请求时通知一次，证明 MITM 生效
  let seen = {};
  try { seen = ctx.storage.getJSON(KEY.seen) || {}; } catch (_) {}
  const path = String(url).replace(/^https:\/\/wx\.10086\.cn/, '').split('?')[0].split('/').slice(0, 3).join('/');
  console.log(`[CMCC] 看到请求 ${path}`);
  if (!seen.any) {
    seen.any = Date.now();
    try { ctx.notify({ title: NAME, subtitle: '已拦截到签到页请求', body: `MITM 正常（${path}），正在抓取凭证…` }); } catch (_) {}
  }
  seen[path] = (seen[path] || 0) + 1;
  ctx.storage.setJSON(KEY.seen, seen);
}

async function captureAny(ctx) {
  const url = ctx.request.url;
  markSeen(ctx, url);
  let cookie = '';
  try { cookie = ctx.request.headers.get('cookie') || ''; } catch (_) {}
  let referer = '';
  try { referer = ctx.request.headers.get('referer') || ''; } catch (_) {}
  if (/\/qwhdhub\/qwhdmark\//.test(url)) referer = url;
  if (!/^https:\/\/wx\.10086\.cn\/qwhdhub\//.test(referer)) referer = '';
  if (cookie && saveLive(ctx, cookie, referer)) {
    console.log('[CMCC] 抓到活动会话');
    const last = getLast(ctx);
    if (!(last.date === ymd() && last.ok)) {
      try {
        const rec = await runSign(ctx, { force: true });
        if (rec.ok && !getCred(ctx).jwt) {
          try { ctx.notify({ title: NAME, subtitle: '提示', body: '今天已签上；长期凭证还没抓到，之后若提示过期，再进一次签到页就行' }); } catch (_) {}
        }
      } catch (e) { console.log(`[CMCC] 即时签到出错 ${e.message}`); }
    }
  }
}

async function captureAnyResponse(ctx) {
  let list = [];
  try { list = ctx.response.headers.getAll('set-cookie') || []; } catch (_) {}
  const kv = list.map((x) => String(x).split(';')[0]).filter((x) => /_SESSION_TOKEN=/.test(x));
  if (kv.length) {
    const ref = /\/qwhdhub\/qwhdmark\//.test(ctx.request.url) ? ctx.request.url : '';
    saveLive(ctx, kv.join('; '), ref);
    console.log('[CMCC] 响应里抓到活动会话');
  }
}

/* ==================== 会话 ==================== */

function cookieJar() {
  const jar = {};
  return {
    take(resp) {
      let list = [];
      try { list = resp.headers.getAll('set-cookie') || []; } catch (_) {}
      if (!list.length) {
        try {
          const v = resp.headers.get('set-cookie');
          if (v) list = String(v).split(/,\s*(?=[A-Za-z0-9_\-]+=)/);
        } catch (_) {}
      }
      for (const raw of list) {
        const kv = String(raw).split(';')[0];
        const i = kv.indexOf('=');
        if (i > 0) jar[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
      }
    },
    put(k, v) { jar[k] = v; },
    header() { return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '); },
    has(re) { return Object.keys(jar).some((k) => re.test(k)); },
  };
}

async function req(ctx, jar, method, url, { body, headers = {}, redirect = 'follow' } = {}) {
  const h = { 'User-Agent': UA, 'Accept-Language': 'zh-CN,zh-Hans;q=0.9', ...headers };
  const ck = jar.header();
  if (ck) h.Cookie = ck;
  const o = { headers: h, timeout: 20000, credentials: 'omit', redirect };
  if (body !== undefined) o.body = typeof body === 'string' ? body : JSON.stringify(body);
  const resp = await (method === 'POST' ? ctx.http.post(url, o) : ctx.http.get(url, o));
  jar.take(resp);
  return resp;
}

async function json(resp) {
  const t = await resp.text();
  try { return JSON.parse(t); } catch (_) { throw new Error(`接口返回异常 HTTP ${resp.status}`); }
}

const apiHeaders = (referer) => ({
  Accept: '*/*',
  'Content-Type': 'application/json;charset=UTF-8',
  Origin: BASE,
  Referer: referer,
  'login-check': '1',
  'X-Requested-With': 'XMLHttpRequest',
});

class AuthError extends Error {}

async function openSession(ctx, o, cred) {
  const jar = cookieJar();
  const actUrl = `${BASE}/qwhdhub/qwhdmark/${o.activityId}?channelId=${o.channelId}`;
  const r1 = await req(ctx, jar, 'GET', `${BASE}/qwhdsso/login?dlwmh=true&actUrl=${encodeURIComponent(actUrl)}`);
  const html = await r1.text();
  const m = html.match(/loginPath\s*=\s*'([^']+)'/);
  if (!m) throw new Error('登录页未返回 sid，活动入口可能已变更');
  const loginUrl = `${BASE}/qwhdsso${m[1]}`;

  const base = {
    provinceCode: cred.provinceCode,
    cityCode: cred.cityCode,
    userCheckId: cred.userCheckId,
    carrierOperator: cred.carrierOperator || '002',
    appVersionCode: cred.appVersionCode || '12.5.2',
    took: rand(120, 900),
  };
  const jsonHdr = { 'Content-Type': 'application/json;charset=UTF-8', Origin: BASE, Referer: `${BASE}/qwhdsso/login` };

  let data = null;
  if (cred.jwt) {
    const r = await json(await req(ctx, jar, 'POST', loginUrl, { body: { ...base, jwtToken: cred.jwt, token: '' }, headers: jsonHdr }));
    if (r.code === 'SUCCESS' && r.data) data = r.data;
    else console.log(`[CMCC] jwt 续期失败：${r.code} ${r.msg || ''}`);
  }
  if (!data && cred.token) {
    const r = await json(await req(ctx, jar, 'POST', loginUrl, { body: { ...base, jwtToken: null, token: cred.token }, headers: jsonHdr }));
    if (r.code === 'SUCCESS' && r.data) data = r.data;
    else console.log(`[CMCC] App 票据登录失败：${r.code} ${r.msg || ''}`);
  }
  if (!data) throw new AuthError('登录凭证已过期');

  if (data.jwt && data.jwt !== cred.jwt) {
    cred.jwt = data.jwt;
    cred.jwtAt = Date.now();
    cred.expired = false;
    setCred(ctx, cred);
  }
  const page = clean(data.url);
  if (!/^https:\/\/wx\.10086\.cn\//.test(page)) throw new Error('活动页地址异常');
  const r3 = await req(ctx, jar, 'GET', page, { redirect: 'manual' });
  try { await r3.text(); } catch (_) {}
  if (!jar.has(/SESSION_TOKEN$/)) throw new Error('未取得活动会话令牌');
  return { jar, referer: page };
}

/* ==================== 签到 + 领奖 ==================== */

async function markStatus(ctx, s) {
  const r = await json(await req(ctx, s.jar, 'POST', `${BASE}/qwhdhub/api/mark/mark31/markstatus`, { body: {}, headers: apiHeaders(s.referer) }));
  if (r.code !== 'SUCCESS') throw new Error(`查询签到状态失败：${r.msg || r.code}`);
  return r.data || {};
}

function prizeText(p) {
  if (!p) return '';
  const unit = { FLOW: 'MB', FEE: '元' }[p.prizeCategory] || '';
  const name = p.prizeName || p.name || '';
  const val = p.prizeValue ? `${p.prizeValue}${unit}` : '';
  return [name, val && !name.includes(String(p.prizeValue)) ? `（${val}）` : ''].join('');
}

async function signOnce(ctx, o) {
  const cred = getCred(ctx);
  const live = liveSession(ctx);
  if (!live && (!cred.userCheckId || (!cred.jwt && !cred.token))) {
    return { ok: false, need: true, msg: '还没有签到凭证：打开中国移动 App →「我的」→「签到领流量」进一次签到页' };
  }
  let s = live;
  if (!s) try {
    s = await openSession(ctx, o, cred);
  } catch (e) {
    if (e instanceof AuthError) {
      cred.expired = true;
      setCred(ctx, cred);
      return { ok: false, need: true, msg: '登录凭证已过期：打开中国移动 App 进一次「签到领流量」页即可恢复' };
    }
    throw e;
  }

  const today = ymd();
  let st;
  try {
    st = await markStatus(ctx, s);
  } catch (e) {
    if (!live) throw e;
    ctx.storage.delete(KEY.live);
    if (!cred.userCheckId || (!cred.jwt && !cred.token)) return { ok: false, need: true, msg: '临时会话已失效：再进一次「签到领流量」页' };
    s = await openSession(ctx, o, cred);
    st = await markStatus(ctx, s);
  }
  let acc = (st.userinfo || {}).accumulateTimes;
  const signed = (st.markstatus || []).some((d) => d.date === today && String(d.status) === '1');
  const lines = [];
  let prizes = [];

  if (signed) {
    lines.push('今天已经签过了');
  } else {
    const r = await json(await req(ctx, s.jar, 'POST', `${BASE}/qwhdhub/api/mark/mark31/domark`, { body: { date: today }, headers: apiHeaders(s.referer) }));
    const msg = clean(r.msg);
    if (r.code === 'SUCCESS' || r.status === 'HAVE_MARKED' || msg.includes('已签')) {
      lines.push(r.status === 'HAVE_MARKED' ? '今天已经签过了' : '签到成功');
      const p = prizeText((r.data || {}).markPrize);
      if (p) prizes.push(p);
    } else {
      throw new Error(`签到失败：${msg || r.status || r.code}`);
    }
    await sleep(rand(800, 1600));
    try { st = await markStatus(ctx, s); acc = (st.userinfo || {}).accumulateTimes || acc; } catch (_) {}
  }

  if (o.claim) {
    for (const t of st.taskAwardChance || []) {
      if (!t || !t.id) continue;
      await sleep(rand(1000, 2000));
      try {
        const r = await json(await req(ctx, s.jar, 'POST', `${BASE}/qwhdhub/api/mark/mark31/taskAward/${t.id}`, { body: {}, headers: apiHeaders(s.referer) }));
        const d = r.data || {};
        if (d.prizeName) prizes.push(prizeText(d));
        else console.log(`[CMCC] 领奖 ${t.id}：${r.status || r.code} ${r.msg || ''}`);
      } catch (e) {
        console.log(`[CMCC] 领奖 ${t.id} 出错：${e.message}`);
      }
    }
  }
  return { ok: true, acc, lines, prizes };
}

async function runSign(ctx, { force = false } = {}) {
  const o = opts(ctx);
  const last = getLast(ctx);
  const today = ymd();
  if (!force && last.date === today && last.ok) return last;

  let res;
  try {
    res = await signOnce(ctx, o);
  } catch (e) {
    res = { ok: false, msg: String((e && e.message) || e) };
  }
  const rec = { date: today, ts: Date.now(), ...res };
  if (!res.ok && last.date === today && last.ok) return last;
  ctx.storage.setJSON(KEY.last, { ...rec, prizes: res.prizes || (last.date === today ? last.prizes : []) });

  if (res.ok) {
    const body = [res.lines.join('，') + (res.acc ? `，累计 ${res.acc} 天` : ''), res.prizes.length ? `领到：${res.prizes.join('、')}` : '']
      .filter(Boolean).join('\n');
    // 已签且没领到新东西时不打扰
    if (!(res.lines[0] === '今天已经签过了' && !res.prizes.length)) say(ctx, 'ok', res.prizes.length ? '签到 + 领奖成功' : '签到成功', body);
  } else {
    // 同一天同一种失败只通知一次
    const tag = `${today}|${res.msg}`;
    if (ctx.storage.get('cmcc_sign_failtag') !== tag) {
      ctx.storage.set('cmcc_sign_failtag', tag);
      say(ctx, 'fail', res.need ? '需要你操作一下' : '签到没成功', res.msg);
    }
  }
  return rec;
}

/* ==================== 小组件 ==================== */

const C = {
  text: { light: '#000000', dark: '#FFFFFF' },
  dim: { light: '#3C3C4399', dark: '#EBEBF599' },
  brand: '#0085D0',
  ok: '#30D158',
  warn: '#FF9F0A',
  bad: '#FF453A',
};

function widget(ctx, rec) {
  const family = ctx.widgetFamily || 'systemSmall';
  const today = ymd();
  const done = rec.date === today && rec.ok;
  const state = done ? '今日已签' : rec.need ? '需打开签到页' : rec.msg ? '签到失败' : '待签到';
  const color = done ? C.ok : rec.need ? C.warn : rec.msg ? C.bad : C.dim;
  const prize = (rec.prizes || []).filter(Boolean)[0] || '';

  if (family === 'accessoryInline') {
    return { type: 'widget', children: [{ type: 'text', text: `移动签到 · ${state}${rec.acc ? ` · ${rec.acc}天` : ''}` }] };
  }
  if (family.startsWith('accessory')) {
    return {
      type: 'widget', gap: 2,
      children: [
        { type: 'text', text: '移动签到', font: { size: 12, weight: 'semibold' } },
        { type: 'text', text: state, font: { size: 14, weight: 'bold' } },
        rec.acc ? { type: 'text', text: `累计 ${rec.acc} 天`, font: { size: 11 } } : { type: 'spacer', length: 1 },
      ],
    };
  }
  const children = [
    {
      type: 'stack', direction: 'row', gap: 6, alignItems: 'center',
      children: [
        { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', color: C.brand, width: 16, height: 16 },
        { type: 'text', text: '签到领流量', font: { size: 14, weight: 'semibold' }, textColor: C.text },
      ],
    },
    { type: 'spacer' },
    { type: 'text', text: state, font: { size: 22, weight: 'bold' }, textColor: color },
    { type: 'spacer', length: 4 },
    { type: 'text', text: rec.acc ? `累计签到 ${rec.acc} 天` : (rec.need ? rec.msg : '每天自动签到'), font: { size: 12 }, textColor: C.dim, maxLines: 2 },
  ];
  if (prize) children.push({ type: 'text', text: `🎁 ${prize}`, font: { size: 12, weight: 'medium' }, textColor: C.text, maxLines: 1 });
  if (rec.ts) {
    children.push({ type: 'spacer', length: 4 });
    children.push({
      type: 'stack', direction: 'row', gap: 3,
      children: [
        { type: 'text', text: '更新于', font: { size: 10 }, textColor: C.dim },
        { type: 'date', date: new Date(rec.ts).toISOString(), format: 'relative', font: { size: 10 }, textColor: C.dim },
      ],
    });
  }
  return { type: 'widget', padding: 14, children };
}

/* ==================== 入口 ==================== */

export default async function (ctx) {
  const o = opts(ctx);
  if (ctx.request && ctx.request.url) {
    if (!o.capture) return;
    const isLogin = /\/qwhdsso\/appTokenLogin/.test(ctx.request.url);
    if (ctx.response) {
      await captureAnyResponse(ctx);
      return isLogin ? captureResponse(ctx) : undefined;
    }
    if (isLogin) { markSeen(ctx, ctx.request.url); return captureRequest(ctx); }
    await captureAny(ctx);
    return;
  }
  if (o.mode === 'sign' || ctx.cron) {
    await sleep(rand(0, 20000)); // 错峰，避免整点集中请求
    await runSign(ctx);
    return;
  }
  // 小组件：今天还没签成功就顺手签一次
  let rec = getLast(ctx);
  if (!(rec.date === ymd() && rec.ok)) {
    try { rec = await runSign(ctx); } catch (_) {}
  }
  return widget(ctx, rec);
}
