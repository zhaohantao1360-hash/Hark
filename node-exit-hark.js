/**
 * Egern 小组件 · 节点出口（Hark）
 * 显示所选策略组当前的出口国家 / 城市 / 运营商 / 延迟。
 * 主出口用非 Cloudflare 的接口（ip-api.com，失败再用 ipinfo.io）查询，
 * 这样走 Cloudflare Workers 节点时看到的是真实出口，而不是反代 IP。
 * 另查一次 cloudflare.com/cdn-cgi/trace，显示「Cloudflare 网站」实际走的出口（edgetunnel 的 PROXYIP）。
 * 纯净度：ip-api 的 hosting/proxy/mobile + proxycheck.io 的 IP 类型；风险：scamalytics 欺诈分（失败用 proxycheck risk）。按 IP 缓存 6 小时。
 * env：POLICY 策略组名（留空按分流规则）；YS 隐藏 IP；TIMEOUT 超时毫秒。
 */

const C = {
  text: { light: '#000000', dark: '#FFFFFF' },
  dim: { light: '#3C3C4399', dark: '#EBEBF599' },
  faint: { light: '#3C3C4366', dark: '#EBEBF566' },
  glass: { light: '#FFFFFFA6', dark: '#FFFFFF1A' },
  accent: '#0A84FF',
  ok: '#30D158',
  mid: { light: '#B88A00', dark: '#FFD60A' },
  fail: '#FF453A',
};

const clean = (v) => String(v == null ? '' : v).trim();

function flag(cc) {
  cc = clean(cc).toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '🏳️';
  return String.fromCodePoint(...[...cc].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65));
}

const CN = {
  US: '美国', HK: '香港', SG: '新加坡', JP: '日本', KR: '韩国', TW: '台湾', DE: '德国', GB: '英国',
  FR: '法国', NL: '荷兰', CA: '加拿大', AU: '澳大利亚', IN: '印度', CN: '中国', MO: '澳门', RU: '俄罗斯',
  SE: '瑞典', FI: '芬兰', CH: '瑞士', IT: '意大利', ES: '西班牙', BR: '巴西', TH: '泰国', VN: '越南',
  MY: '马来西亚', ID: '印度尼西亚', PH: '菲律宾', TR: '土耳其', AE: '阿联酋', PL: '波兰', IE: '爱尔兰',
};
const ccName = (cc) => CN[clean(cc).toUpperCase()] || clean(cc).toUpperCase() || '未知';

function maskIp(ip, mask) {
  if (!ip) return '';
  if (!mask) return ip;
  if (ip.includes(':')) return ip.split(':').slice(0, 2).join(':') + ':…';
  return ip.replace(/^(\d+\.\d+)\.\d+\.\d+$/, '$1.*.*');
}

async function probe(ctx) {
  const env = ctx.env || {};
  const policy = clean(env.POLICY);
  const mask = !/^(0|false|否|显示)$/i.test(clean(env.YS));
  const t = Number(env.TIMEOUT);
  const timeout = Number.isFinite(t) && t > 0 ? Math.min(10000, Math.max(1500, t)) : 5000;

  async function get(url, wantBody = true) {
    const start = Date.now();
    try {
      const opt = { timeout, credentials: 'omit', headers: { 'Cache-Control': 'no-cache', Accept: '*/*' } };
      if (policy) opt.policy = policy;
      const r = await ctx.http.get(url, opt);
      const body = wantBody ? await r.text() : '';
      return { status: r.status, body, ms: Math.max(1, Date.now() - start) };
    } catch (_) {
      return { status: 0, body: '', ms: 0 };
    }
  }

  async function geo() {
    const a = await get('http://ip-api.com/json/?lang=zh-CN&fields=status,country,countryCode,regionName,city,isp,org,as,query,proxy,hosting,mobile');
    try {
      const j = JSON.parse(a.body || '{}');
      if (j.status === 'success') {
        return {
          ok: true, ip: j.query, cc: j.countryCode, country: j.country || ccName(j.countryCode),
          city: j.city || j.regionName || '', isp: j.isp || j.org || '',
          asn: clean(j.as).split(' ')[0] || '',
          flags: { proxy: !!j.proxy, hosting: !!j.hosting, mobile: !!j.mobile },
        };
      }
    } catch (_) {}
    const b = await get('https://ipinfo.io/json');
    try {
      const j = JSON.parse(b.body || '{}');
      if (j.ip) {
        const org = clean(j.org);
        return {
          ok: true, ip: j.ip, cc: j.country, country: ccName(j.country), city: j.city || j.region || '',
          isp: org.replace(/^AS\d+\s*/, ''), asn: (org.match(/^AS\d+/) || [''])[0],
        };
      }
    } catch (_) {}
    return { ok: false };
  }

  async function cfTrace() {
    const r = await get('https://www.cloudflare.com/cdn-cgi/trace');
    const d = {};
    for (const line of (r.body || '').split(/\r?\n/)) {
      const i = line.indexOf('=');
      if (i > 0) d[line.slice(0, i)] = line.slice(i + 1).trim();
    }
    return d.loc ? { ok: true, cc: d.loc, colo: d.colo || '', ip: d.ip || '' } : { ok: false };
  }

  // 纯净度 + 风险（按 IP 缓存 6 小时，省免费接口额度）
  async function quality(g) {
    if (!g.ok || !g.ip) return { ok: false };
    const qk = 'node_exit_q_' + g.ip;
    try { const c = ctx.storage && ctx.storage.getJSON(qk); if (c && Date.now() - c.ts < 6 * 3600000) return c; } catch (_) {}
    const [pc, sc] = await Promise.all([
      get(`https://proxycheck.io/v2/${g.ip}?vpn=1&risk=1`),
      get(`https://scamalytics.com/ip/${g.ip}`),
    ]);
    let type = '', pcProxy = false, pcRisk = NaN;
    try { const j = JSON.parse(pc.body || '{}')[g.ip] || {}; type = clean(j.type); pcProxy = j.proxy === 'yes'; pcRisk = Number(j.risk); } catch (_) {}
    let score = NaN;
    const m = (sc.body || '').match(/Fraud Score:\s*(\d+)/i) || (sc.body || '').match(/"score"\s*:\s*"?(\d+)/);
    if (m) score = Number(m[1]);
    const src = Number.isFinite(score) ? 'Scamalytics' : 'proxycheck';
    if (!Number.isFinite(score) && Number.isFinite(pcRisk)) score = pcRisk;
    const fl = g.flags || {};
    const t = type.toLowerCase();
    let kind, pure;
    if (/residential/.test(t)) { kind = '家宽住宅'; pure = 3; }
    else if (/wireless|mobile/.test(t) || fl.mobile) { kind = '移动网络'; pure = 3; }
    else if (fl.hosting || /hosting|data ?cent/.test(t)) { kind = '机房 IDC'; pure = 1; }
    else if (/business/.test(t)) { kind = '商业宽带'; pure = 2; }
    else if (type) { kind = type; pure = 2; }
    else { kind = fl.hosting === false ? '非机房' : '未知'; pure = fl.hosting === false ? 2 : 0; }
    const proxy = pcProxy || !!fl.proxy;
    if (proxy && pure > 1) pure -= 1;
    const q = { ok: true, ts: Date.now(), kind, pure, proxy, score, src };
    if (type || Number.isFinite(score)) { try { ctx.storage && ctx.storage.setJSON(qk, q); } catch (_) {} }
    return q;
  }

  const [g, cf, ping] = await Promise.all([geo(), cfTrace(), get('https://www.gstatic.com/generate_204', false)]);
  const alive = ping.status >= 200 && ping.status < 400;
  const res = {
    policy, mask, g, cf,
    ms: alive ? ping.ms : 0,
    msColor: !alive ? C.fail : ping.ms <= 300 ? C.ok : ping.ms <= 800 ? C.mid : C.fail,
    msText: alive ? `${ping.ms}ms` : '超时',
    ts: Date.now(),
  };

  // 失败时用上次结果兜底
  const key = 'node_exit_last_' + (policy || 'rule');
  try {
    if (g.ok) ctx.storage && ctx.storage.setJSON(key, { g, cf, ts: res.ts });
    else {
      const last = ctx.storage && ctx.storage.getJSON(key);
      if (last && last.g) { res.g = { ...last.g, stale: true }; res.cf = last.cf || cf; res.staleTs = last.ts; }
    }
  } catch (_) {}
  res.q = await quality(res.g);
  return res;
}

/* ============ 视图 ============ */

function T(v, size, color, weight = 'regular', extra = {}) {
  return { type: 'text', text: String(v), font: { size, weight }, textColor: color || C.text, maxLines: 1, minScale: 0.6, ...extra };
}
function icon(name, color, size = 11) {
  return { type: 'image', src: `sf-symbol:${name}`, width: size, height: size, color };
}
const row = (children, extra = {}) => ({ type: 'stack', direction: 'row', alignItems: 'center', gap: 4, children, ...extra });
const col = (children, extra = {}) => ({ type: 'stack', direction: 'column', alignItems: 'start', gap: 2, children, ...extra });
const spacer = (length) => (length == null ? { type: 'spacer' } : { type: 'spacer', length });

function bg() {
  return {
    type: 'linear',
    colors: [{ light: '#E8F4FF', dark: '#06172E' }, { light: '#F2EEFF', dark: '#120D30' }],
    stops: [0, 1], startPoint: { x: 0, y: 0 }, endPoint: { x: 1, y: 1 },
  };
}

// 固定显示刷新时刻（不再用会跳秒的相对时间）
function updated(d) {
  const t = new Date(d.staleTs || d.ts);
  return T(`${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`, 9, C.faint);
}

function cfLine(d) {
  if (!d.cf.ok) return 'CF 网站出口：未知';
  return `CF 网站出口 ${flag(d.cf.cc)} ${ccName(d.cf.cc)}${d.cf.colo ? ' · ' + d.cf.colo : ''}`;
}

function failWidget(d, small) {
  return {
    type: 'widget', padding: 14, gap: 6, backgroundGradient: bg(),
    children: [
      row([icon('globe.asia.australia.fill', C.accent, 13), T('节点出口', 13, C.text, 'semibold')]),
      spacer(),
      T('查询失败', small ? 18 : 22, C.fail, 'bold'),
      T(d.policy ? `策略「${d.policy}」无响应，检查节点或策略名` : '网络无响应', 11, C.dim, 'regular', { maxLines: 2 }),
    ],
  };
}

function chip(label, value, color) {
  return {
    type: 'stack', direction: 'column', alignItems: 'start', gap: 1, flex: 1, height: 36,
    padding: [5, 8], borderRadius: 10, backgroundColor: C.glass,
    children: [T(label, 8, C.dim), T(value, 12, color, 'bold')],
  };
}

function buildSmall(d) {
  const g = d.g;
  const pv = pureView(d.q), rv = riskView(d.q);
  return {
    type: 'widget', padding: 12, gap: 4, backgroundGradient: bg(),
    children: [
      row([icon('globe.asia.australia.fill', C.accent, 12), T(d.policy || '分流规则', 10, C.dim, 'medium'), spacer(),
        T(d.msText, 10, d.msColor, 'semibold')]),
      spacer(),
      row([
        T(flag(g.cc), 30, C.text),
        col([T(g.country, 18, C.text, 'bold'), T(g.city || '—', 11, C.dim, 'medium')], { gap: 0 }),
        spacer(),
      ], { gap: 8 }),
      row([T(g.isp || g.asn || '', 9, C.faint), spacer(), updated(d)], { gap: 3 }),
      spacer(),
      row([chip('纯净度', pv.short, pv.color), chip('风险', Number.isFinite(rv.score) ? `${rv.score} ${rv.short.replace('风险', '')}` : rv.short, rv.color)], { gap: 6, height: 36 }),
    ],
  };
}

function info(sym, label, value, color) {
  return row([icon(sym, C.dim, 10), T(label, 10, C.dim), spacer(), T(value, 11, color || C.text, 'medium')], { gap: 4 });
}

// 纯净度：3 高 / 2 中 / 1 低 / 0 未知
function pureView(q) {
  if (!q || !q.ok) return { text: '查询中', short: '—', color: C.faint, level: 0 };
  const map = { 3: ['纯净', C.ok], 2: ['一般', C.mid], 1: ['较差', C.fail], 0: ['未知', C.faint] };
  const [lv, color] = map[q.pure] || map[0];
  return { text: `${q.kind}${q.proxy ? ' · 代理' : ''}`, short: lv, color, level: q.pure };
}
function riskView(q) {
  if (!q || !q.ok || !Number.isFinite(q.score)) return { text: '—', short: '未知', color: C.faint, score: NaN };
  const s = q.score;
  const [lv, color] = s <= 25 ? ['低风险', C.ok] : s <= 60 ? ['中风险', C.mid] : ['高风险', C.fail];
  return { text: `${s} · ${lv}`, short: lv, color, score: s };
}
// 小进度条（0-100）
function meter(pct, color, h = 4) {
  const p = Math.max(0.04, Math.min(1, pct / 100));
  return row([
    { type: 'stack', direction: 'row', flex: p, height: h, borderRadius: h / 2, backgroundColor: color, children: [spacer()] },
    ...(p < 1 ? [{ type: 'stack', direction: 'row', flex: 1 - p, height: h, borderRadius: h / 2, backgroundColor: C.glass, children: [spacer()] }] : []),
  ], { gap: 0, height: h });
}

function buildMedium(d) {
  const g = d.g;
  const pv = pureView(d.q), rv = riskView(d.q);
  return {
    type: 'widget', padding: [12, 12, 12, 14], backgroundGradient: bg(),
    children: [
      row([
        col([
          row([icon('globe.asia.australia.fill', C.accent, 12), T('节点出口', 12, C.text, 'semibold')]),
          spacer(),
          T(flag(g.cc), 32, C.text),
          T(g.country, 19, C.text, 'bold'),
          T(g.city || '—', 11, C.dim, 'medium'),
          spacer(3),
          row([T(d.msText, 10, d.msColor, 'semibold'), T('·', 9, C.faint), updated(d)], { gap: 3 }),
        ], { width: 92, height: 128, alignItems: 'center' }),
        {
          type: 'stack', direction: 'column', alignItems: 'start', gap: 5, flex: 1, height: 128,
          padding: [9, 11], borderRadius: 16, backgroundColor: C.glass,
          children: [
            info('point.3.connected.trianglepath.dotted', '策略', d.policy || '分流规则'),
            info('number', 'IP', maskIp(g.ip, d.mask)),
            info('building.2', '运营商', g.isp || g.asn || '—'),
            info('leaf.fill', '纯净度', `${pv.text}`, pv.color),
            info('shield.lefthalf.filled', '风险', rv.text, rv.color),
            T(cfLine(d), 9, C.faint),
          ],
        },
      ], { gap: 10, alignItems: 'center' }),
    ],
  };
}

function scoreCard(sym, title, big, sub, color, pct) {
  return {
    type: 'stack', direction: 'column', alignItems: 'start', gap: 5, flex: 1, height: 84,
    padding: [10, 12], borderRadius: 14, backgroundColor: C.glass,
    children: [
      row([icon(sym, color, 11), T(title, 10, C.dim, 'medium')]),
      T(big, 22, color, 'bold'),
      T(sub, 9, C.dim),
      meter(pct, color),
    ],
  };
}

function buildLarge(d) {
  const g = d.g;
  const pv = pureView(d.q), rv = riskView(d.q);
  return {
    type: 'widget', padding: 16, gap: 0, backgroundGradient: bg(),
    children: [
      row([icon('globe.asia.australia.fill', C.accent, 13), T('节点出口', 13, C.text, 'semibold'), T(d.policy || '分流规则', 10, C.dim), spacer(),
        T(g.stale ? '上次 ·' : '更新', 9, C.faint), updated(d)]),
      spacer(),
      row([
        T(flag(g.cc), 50, C.text),
        col([
          T(`${g.country}${g.city ? ' · ' + g.city : ''}`, 20, C.text, 'bold'),
          T(g.isp || g.asn || '—', 11, C.dim, 'medium'),
        ], { gap: 2, flex: 1 }),
        col([T(d.msText, 20, d.msColor, 'bold'), T('延迟', 9, C.faint)], { alignItems: 'end', gap: 1 }),
      ], { gap: 12 }),
      spacer(),
      row([
        scoreCard('leaf.fill', '纯净度', pv.short, pv.text, pv.color, [10, 35, 65, 100][pv.level] || 10),
        scoreCard('shield.lefthalf.filled', '风险值', Number.isFinite(rv.score) ? String(rv.score) : '—', `${rv.short}${d.q && d.q.ok ? ' · ' + d.q.src : ''}`, rv.color, Number.isFinite(rv.score) ? rv.score : 0),
      ], { gap: 8, height: 84 }),
      spacer(),
      {
        type: 'stack', direction: 'column', alignItems: 'start', gap: 9, padding: [10, 12], borderRadius: 14, backgroundColor: C.glass,
        children: [
          info('number', 'IP', maskIp(g.ip, d.mask)),
          info('server.rack', 'ASN', g.asn || '—'),
          info('building.2', '运营商', g.isp || '—'),
          info('exclamationmark.shield', '代理标记', d.q && d.q.ok ? (d.q.proxy ? '已标记' : '未标记') : '—', d.q && d.q.proxy ? C.mid : C.ok),
          info('cloud.fill', 'CF 网站出口', d.cf.ok ? `${flag(d.cf.cc)} ${ccName(d.cf.cc)}${d.cf.colo ? ' · ' + d.cf.colo : ''}` : '未知'),
        ],
      },
    ],
  };
}

function buildLock(d, family) {
  const g = d.g;
  if (!g.ok) return { type: 'widget', children: [{ type: 'text', text: '出口查询失败', maxLines: 1 }] };
  if (family === 'accessoryInline') {
    return { type: 'widget', children: [{ type: 'text', text: `${flag(g.cc)} ${g.country} ${g.city} · ${d.msText}`, maxLines: 1, minScale: 0.6 }] };
  }
  if (family === 'accessoryCircular') {
    return {
      type: 'widget', padding: 4,
      children: [spacer(),
        { type: 'text', text: flag(g.cc), font: { size: 22 }, textAlign: 'center' },
        { type: 'text', text: g.country, font: { size: 10, weight: 'semibold' }, textAlign: 'center', maxLines: 1, minScale: 0.5 },
        spacer()],
    };
  }
  return {
    type: 'widget', padding: [2, 4], gap: 2,
    children: [
      { type: 'text', text: `${flag(g.cc)} ${g.country} · ${g.city || ''}`, font: { size: 'headline', weight: 'semibold' }, maxLines: 1, minScale: 0.6 },
      { type: 'text', text: g.isp || g.asn || '', font: { size: 'caption2' }, opacity: 0.75, maxLines: 1, minScale: 0.6 },
      { type: 'text', text: `延迟 ${d.msText}`, font: { size: 'caption2' }, opacity: 0.75, maxLines: 1 },
    ],
  };
}

export default async function (ctx) {
  const family = ctx.widgetFamily || 'systemMedium';
  const d = await probe(ctx);
  const refreshAfter = new Date(Date.now() + 10 * 60000).toISOString();
  let w;
  if (family.startsWith('accessory')) w = buildLock(d, family);
  else if (!d.g.ok) w = failWidget(d, family === 'systemSmall');
  else if (family === 'systemSmall') w = buildSmall(d);
  else if (family === 'systemLarge' || family === 'systemExtraLarge') w = buildLarge(d);
  else w = buildMedium(d);
  w.refreshAfter = refreshAfter;
  return w;
}
