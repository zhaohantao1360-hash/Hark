/**
 * Egern 小组件 · 节点出口（Hark）
 * 显示所选策略组当前的出口国家 / 城市 / 运营商 / 延迟。
 * 主出口用非 Cloudflare 的接口（ip-api.com，失败再用 ipinfo.io）查询，
 * 这样走 Cloudflare Workers 节点时看到的是真实出口，而不是反代 IP。
 * 另查一次 cloudflare.com/cdn-cgi/trace，显示「Cloudflare 网站」实际走的出口（edgetunnel 的 PROXYIP）。
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
    const a = await get('http://ip-api.com/json/?lang=zh-CN&fields=status,country,countryCode,regionName,city,isp,org,as,query');
    try {
      const j = JSON.parse(a.body || '{}');
      if (j.status === 'success') {
        return {
          ok: true, ip: j.query, cc: j.countryCode, country: j.country || ccName(j.countryCode),
          city: j.city || j.regionName || '', isp: j.isp || j.org || '',
          asn: clean(j.as).split(' ')[0] || '',
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

function updated(d) {
  return { type: 'date', date: new Date(d.staleTs || d.ts).toISOString(), format: 'relative', font: { size: 9 }, textColor: C.faint, maxLines: 1 };
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

function buildSmall(d) {
  const g = d.g;
  return {
    type: 'widget', padding: 14, gap: 3, backgroundGradient: bg(),
    children: [
      row([icon('globe.asia.australia.fill', C.accent, 12), T(d.policy || '分流规则', 11, C.dim, 'medium'), spacer(),
        T(d.msText, 10, d.msColor, 'semibold')]),
      spacer(),
      T(flag(g.cc), 34, C.text),
      T(g.country, 20, C.text, 'bold'),
      T(g.city || '—', 12, C.dim, 'medium'),
      T(g.isp || g.asn || '', 10, C.faint),
      spacer(4),
      row([T(g.stale ? '上次结果 ·' : '更新', 9, C.faint), updated(d)], { gap: 3 }),
    ],
  };
}

function info(sym, label, value, color) {
  return row([icon(sym, C.dim, 10), T(label, 10, C.dim), spacer(), T(value, 11, color || C.text, 'medium')], { gap: 4 });
}

function buildMedium(d) {
  const g = d.g;
  return {
    type: 'widget', padding: 14, backgroundGradient: bg(),
    children: [
      row([
        col([
          row([icon('globe.asia.australia.fill', C.accent, 12), T('节点出口', 12, C.text, 'semibold')]),
          spacer(),
          T(flag(g.cc), 36, C.text),
          T(g.country, 20, C.text, 'bold'),
          T(g.city || '—', 12, C.dim, 'medium'),
          row([T(g.stale ? '上次 ·' : '更新', 9, C.faint), updated(d)], { gap: 3 }),
        ], { width: 110, height: 120 }),
        {
          type: 'stack', direction: 'column', alignItems: 'start', gap: 6, flex: 1, height: 120,
          padding: [10, 12], borderRadius: 16, backgroundColor: C.glass,
          children: [
            info('point.3.connected.trianglepath.dotted', '策略', d.policy || '分流规则'),
            info('number', 'IP', maskIp(g.ip, d.mask)),
            info('building.2', '运营商', g.isp || g.asn || '—'),
            info('bolt.horizontal', '延迟', d.msText, d.msColor),
            T(cfLine(d), 10, C.dim),
          ],
        },
      ], { gap: 10, alignItems: 'center' }),
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
  else w = buildMedium(d);
  w.refreshAfter = refreshAfter;
  return w;
}
