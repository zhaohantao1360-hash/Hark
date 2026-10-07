/**
 * 彩票开奖小组件（Hark 仪表盘版）
 * 基于 IBL3ND/module Lottery-Widget.JS 改版
 *
 * 功能：
 *  • 最新开奖号码、期号、奖池、下期开奖倒计时
 *  • 近 N 期走势分析：热号（出现最多）、冷号（遗漏最久）、奇偶比、大小比、和值走势
 *  • 按冷热和遗漏加权生成「参考号码」，同一期内固定不变（仅供娱乐，开奖完全随机）
 *  • 与油价 / 中国移动 / 订阅流量统一的深色渐变 + 玻璃卡片风格
 *  • 失败时显示缓存；开奖前后自动加密刷新，平时 3 小时刷新一次
 *  • 支持锁屏（行内 / 圆形 / 矩形）
 *
 * 环境变量：
 *  彩票类型   双色球 / 大乐透 / 七乐彩 / 七星彩 / 排列三 / 排列五 / 福彩3D（默认 双色球）
 *  分析期数   默认 50（10–100）
 */

const API_URL = 'https://m.zhuying.com/api/lotapi/indexV2/1';
const HIST = 'https://datachart.500.com';
const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148';

// type: pool = 号码池（不重复）；digit = 每位 0–9
const GAMES = {
  ssq:  { name: '双色球', kind: 'pool', front: 6, fMax: 33, back: 1, bMax: 16, fColor: '#FF453A', bColor: '#0A84FF', hist: `${HIST}/ssq/history/newinc/history.php`, cf4: true },
  dlt:  { name: '大乐透', kind: 'pool', front: 5, fMax: 35, back: 2, bMax: 12, fColor: '#FF453A', bColor: '#0A84FF', hist: `${HIST}/dlt/history/newinc/history.php`, cf4: true },
  qlc:  { name: '七乐彩', kind: 'pool', front: 7, fMax: 30, back: 1, bMax: 30, fColor: '#FF9F0A', bColor: '#0A84FF', hist: `${HIST}/qlc/history/newinc/history.php`, special: true },
  qxc:  { name: '七星彩', kind: 'digit', front: 6, back: 1, bMax: 14, fColor: '#30D158', bColor: '#0A84FF', hist: `${HIST}/qxc/history/inc/history.php` },
  pl3:  { name: '排列三', kind: 'digit', front: 3, back: 0, fColor: '#30D158', bColor: '#0A84FF', hist: `${HIST}/pls/history/inc/history.php` },
  pl5:  { name: '排列五', kind: 'digit', front: 5, back: 0, fColor: '#FF9F0A', bColor: '#0A84FF', hist: `${HIST}/plw/history/inc/history.php` },
  fc3d: { name: '福彩3D', kind: 'digit', front: 3, back: 0, fColor: '#FF9F0A', bColor: '#0A84FF', hist: null },
};
const ALIAS = {
  '双色球': 'ssq', '大乐透': 'dlt', '七乐彩': 'qlc', '七星彩': 'qxc', '7星彩': 'qxc',
  '排列三': 'pl3', '排列3': 'pl3', '排列五': 'pl5', '排列5': 'pl5',
  '福彩3D': 'fc3d', '福彩 3D': 'fc3d', '3D': 'fc3d', '福利': 'fc3d',
};

// ---------------------------------------------------------------------------
// 视觉
// ---------------------------------------------------------------------------
const C = {
  text: { light: '#000000', dark: '#FFFFFF' },
  dim: { light: '#3C3C4399', dark: '#EBEBF599' },
  glass: { light: '#FFFFFFA6', dark: '#FFFFFF1A' },
  gold: '#FFB340',
  hot: '#FF6B5E',
  cold: '#64A8FF',
  white: '#FFFFFF',
};
const pad2 = n => String(n).padStart(2, '0');
function bg() {
  return {
    type: 'linear',
    colors: [{ light: '#FFF1F0', dark: '#2A0E10' }, { light: '#F4F0FF', dark: '#140F26' }, { light: '#EEF6FF', dark: '#07121F' }],
    stops: [0, 0.55, 1], startPoint: { x: 0, y: 0 }, endPoint: { x: 1, y: 1 },
  };
}
function T(text, size, color, weight = 'regular', extra = {}) {
  return { type: 'text', text: String(text ?? ''), font: { size, weight }, textColor: color || C.text, maxLines: 1, minScale: 0.7, ...extra };
}
function icon(name, color, size = 12) { return { type: 'image', src: `sf-symbol:${name}`, width: size, height: size, color }; }
function row(children, extra = {}) { return { type: 'stack', direction: 'row', alignItems: 'center', gap: 4, children, ...extra }; }
function glass(children, extra = {}) {
  return { type: 'stack', direction: 'column', alignItems: 'start', gap: 4, padding: [7, 10], borderRadius: 14, backgroundColor: C.glass, children, ...extra };
}
function ball(num, color, size, outline) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center', justifyContent: 'center', width: size, height: size, borderRadius: size / 2,
    backgroundColor: outline ? color + '33' : color,
    children: [T(num, Math.round(size * 0.46), outline ? color : C.white, 'bold', { minScale: 0.6 })],
  };
}
function svgUri(svg) { return 'data:image/svg+xml,' + encodeURIComponent(svg); }
function barsSvg(vals, color, w, h, mark) {
  const n = vals.length; if (!n) return null;
  const max = Math.max(...vals), min = Math.min(...vals), rg = max - min || 1;
  const gap = 3, bw = (w - gap * (n - 1)) / n;
  let s = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'>`;
  vals.forEach((v, i) => {
    const bh = Math.max(3, 4 + (h - 6) * (v - min) / rg);
    s += `<rect x='${(i * (bw + gap)).toFixed(1)}' y='${(h - bh).toFixed(1)}' width='${bw.toFixed(1)}' height='${bh.toFixed(1)}' rx='${Math.min(2, bw / 2)}' fill='${color}' fill-opacity='${i === n - 1 ? 1 : 0.45}'/>`;
  });
  if (mark != null) {
    const y = h - Math.max(3, 4 + (h - 6) * (mark - min) / rg);
    s += `<line x1='0' x2='${w}' y1='${y.toFixed(1)}' y2='${y.toFixed(1)}' stroke='${color}' stroke-opacity='0.6' stroke-dasharray='2 2' stroke-width='1'/>`;
  }
  return svgUri(s + '</svg>');
}

// ---------------------------------------------------------------------------
// 数据
// ---------------------------------------------------------------------------
async function getText(ctx, url, timeout = 10000) {
  const r = await ctx.http.get(url, { timeout, headers: { 'User-Agent': UA, Accept: '*/*' } });
  if (r.status && r.status !== 200) throw new Error(`HTTP ${r.status}`);
  return await r.text();
}

async function fetchLatest(ctx, type) {
  const json = JSON.parse(await getText(ctx, API_URL, 8000));
  const it = (json.data || []).find(x => x.lotteryType === type);
  if (!it || !it.firstNumbers) throw new Error('接口无数据');
  const split = s => String(s || '').split(',').map(x => x.trim()).filter(Boolean);
  return {
    issue: String(it.issue || ''),
    front: split(it.firstNumbers),
    back: split(it.lastNumbers),
    openTime: it.openTime || '',
    pool: Number(it.poolAmount) || 0,
    frequency: it.frequency || '',
    officeTime: (it.officeOpenTime || '').slice(0, 5),
  };
}

// 500.com 历史开奖（HTML 表格）
async function fetchHistory(ctx, g, limit) {
  if (!g.hist) return [];
  const html = await getText(ctx, `${g.hist}?limit=${limit}`, 12000);
  const rows = html.match(/<tr class="t_tr1">[\s\S]*?<\/tr>/g) || [];
  const out = [];
  for (const raw of rows) {
    const r = raw.replace(/<!--[\s\S]*?-->/g, '');
    const issue = (r.match(/<td[^>]*>\s*(\d{5,7})\s*<\/td>/) || [])[1];
    if (!issue) continue;
    const nums = [];
    const re = /<td[^>]*class="(?:t_)?cfont(2|4)"[^>]*>([\s\S]*?)<\/td>/g;
    let m;
    while ((m = re.exec(r))) {
      if (m[1] === '4' && !g.cf4) continue;
      (m[2].replace(/<[^>]+>/g, ' ').match(/\d+/g) || []).forEach(x => nums.push(x));
    }
    const need = g.front + g.back;
    if (nums.length < need) continue;
    out.push({ issue: normIssue(issue), front: nums.slice(0, g.front), back: nums.slice(g.front, need) });
  }
  return out;
}
const normIssue = s => (String(s).length === 5 ? '20' + s : String(s));

// ---------------------------------------------------------------------------
// 分析
// ---------------------------------------------------------------------------
function analyze(g, draws) {
  const N = draws.length;
  if (N < 5) return null;
  const res = { N };
  if (g.kind === 'pool') {
    const zone = (key, max) => {
      const freq = Array(max + 1).fill(0), miss = Array(max + 1).fill(N);
      draws.forEach((d, i) => d[key].forEach(x => { const n = Number(x); if (n >= 1 && n <= max) { freq[n]++; if (miss[n] === N) miss[n] = i; } }));
      const nums = Array.from({ length: max }, (_, i) => i + 1);
      return {
        freq, miss,
        hot: nums.slice().sort((a, b) => freq[b] - freq[a] || miss[a] - miss[b]),
        cold: nums.slice().sort((a, b) => miss[b] - miss[a] || freq[a] - freq[b]),
      };
    };
    res.f = zone('front', g.fMax);
    if (g.back && !g.special) res.b = zone('back', g.bMax);
    const last = draws[0].front.map(Number);
    res.odd = last.filter(n => n % 2).length;
    res.big = last.filter(n => n > g.fMax / 2).length;
    res.span = Math.max(...last) - Math.min(...last);
    res.sums = draws.slice(0, 12).map(d => d.front.reduce((a, x) => a + Number(x), 0)).reverse();
    res.avgSum = Math.round(draws.reduce((a, d) => a + d.front.reduce((s, x) => s + Number(x), 0), 0) / N);
  } else {
    // 每位 0–9 的频率与遗漏
    res.pos = Array.from({ length: g.front }, (_, p) => {
      const freq = Array(10).fill(0), miss = Array(10).fill(N);
      draws.forEach((d, i) => { const n = Number(d.front[p]); if (n >= 0 && n <= 9) { freq[n]++; if (miss[n] === N) miss[n] = i; } });
      const ds = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
      return { freq, miss, hot: ds.slice().sort((a, b) => freq[b] - freq[a])[0], cold: ds.slice().sort((a, b) => miss[b] - miss[a])[0] };
    });
    const all = Array(10).fill(0), miss = Array(10).fill(N);
    draws.forEach((d, i) => d.front.forEach(x => { const n = Number(x); all[n]++; if (miss[n] === N) miss[n] = i; }));
    const ds = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    res.hotD = ds.slice().sort((a, b) => all[b] - all[a]);
    res.coldD = ds.slice().sort((a, b) => miss[b] - miss[a]);
    res.missD = miss;
    const last = draws[0].front.map(Number);
    res.odd = last.filter(n => n % 2).length;
    res.big = last.filter(n => n >= 5).length;
    res.sums = draws.slice(0, 12).map(d => d.front.reduce((a, x) => a + Number(x), 0)).reverse();
    res.avgSum = Math.round(draws.reduce((a, d) => a + d.front.reduce((s, x) => s + Number(x), 0), 0) / N);
  }
  return res;
}

// 可复现的随机数（同一期同一组号码不变）
function rng(seed) {
  let a = 0; for (const ch of String(seed)) a = (a * 31 + ch.charCodeAt(0)) >>> 0;
  return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
function weightedPick(rand, items, weights, k) {
  const pool = items.slice(), w = weights.slice(), out = [];
  while (out.length < k && pool.length) {
    const sum = w.reduce((a, b) => a + b, 0);
    let r = rand() * sum, i = 0;
    while (r > w[i] && i < w.length - 1) { r -= w[i]; i++; }
    out.push(pool[i]); pool.splice(i, 1); w.splice(i, 1);
  }
  return out;
}
// 热号与长遗漏冷号各占一部分权重，再加均匀底数
function zoneWeights(z, max, N) {
  const nums = Array.from({ length: max }, (_, i) => i + 1);
  const fMax = Math.max(...nums.map(n => z.freq[n])) || 1, mMax = Math.max(...nums.map(n => z.miss[n])) || 1;
  return { nums, w: nums.map(n => 1 + 1.6 * z.freq[n] / fMax + 1.0 * z.miss[n] / mMax) };
}
function suggest(g, A, seed) {
  const rand = rng(seed);
  if (!A) {
    // 数据不足时纯随机
    if (g.kind === 'pool') {
      const f = weightedPick(rand, range(1, g.fMax), Array(g.fMax).fill(1), g.front).sort((a, b) => a - b);
      const b = g.back && !g.special ? weightedPick(rand, range(1, g.bMax), Array(g.bMax).fill(1), g.back).sort((a, b) => a - b) : [];
      return { front: f.map(pad2), back: b.map(pad2) };
    }
    return { front: Array.from({ length: g.front }, () => String(Math.floor(rand() * 10))), back: g.back ? [String(Math.floor(rand() * (g.bMax + 1)))] : [] };
  }
  if (g.kind === 'pool') {
    const fz = zoneWeights(A.f, g.fMax, A.N);
    const front = weightedPick(rand, fz.nums, fz.w, g.front).sort((a, b) => a - b).map(pad2);
    let back = [];
    if (A.b) { const bz = zoneWeights(A.b, g.bMax, A.N); back = weightedPick(rand, bz.nums, bz.w, g.back).sort((a, b) => a - b).map(pad2); }
    return { front, back };
  }
  const front = A.pos.map(p => {
    const fm = Math.max(...p.freq) || 1, mm = Math.max(...p.miss) || 1;
    return String(weightedPick(rand, range(0, 9), range(0, 9).map(d => 1 + 1.4 * p.freq[d] / fm + 0.8 * p.miss[d] / mm), 1)[0]);
  });
  return { front, back: g.back ? [String(Math.floor(rand() * (g.bMax + 1)))] : [] };
}
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);

// ---------------------------------------------------------------------------
// 下期开奖时间
// ---------------------------------------------------------------------------
function nextDraw(freq, officeTime, now) {
  const map = { 日: 0, 天: 0, 一: 1, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6 };
  let days;
  if (/每天|每日/.test(freq)) days = [0, 1, 2, 3, 4, 5, 6];
  else days = (String(freq).match(/[日天一二三四五六]/g) || []).map(c => map[c]);
  if (!days.length) return null;
  const [hh, mm] = (officeTime || '21:15').split(':').map(Number);
  for (let i = 0; i < 8; i++) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() + i, hh, mm, 0);
    if (days.includes(d.getDay()) && d > now) return d;
  }
  return null;
}
const WEEK = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
function fmtCountdown(d, now) {
  const mins = Math.max(0, Math.round((d - now) / 60000));
  const dd = Math.floor(mins / 1440), hh = Math.floor((mins % 1440) / 60), mm = mins % 60;
  return dd > 0 ? `${dd}天${hh}时` : hh > 0 ? `${hh}时${mm}分` : `${mm}分`;
}
function fmtPool(n) {
  if (!n) return '--';
  if (n >= 1e8) return (n / 1e8).toFixed(2) + '亿';
  if (n >= 1e4) return (n / 1e4).toFixed(0) + '万';
  return String(Math.round(n));
}

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------
async function getState(ctx) {
  const env = ctx.env || {};
  const typeIn = String(env['彩票类型'] || env.LOTTERY || '双色球').trim();
  const type = ALIAS[typeIn] || (GAMES[typeIn] ? typeIn : 'ssq');
  const g = GAMES[type];
  const N = Math.max(10, Math.min(100, Number(env['分析期数'] || env.PERIODS) || 50));
  const now = new Date();
  const kLatest = `lot.hark.latest.${type}`, kHist = `lot.hark.hist.${type}`, kHistT = `lot.hark.histT.${type}`;
  const st = ctx.storage;

  let latest = null, error = null;
  try {
    latest = await fetchLatest(ctx, type);
    st && st.setJSON(kLatest, { ...latest, at: Date.now() });
  } catch (e) {
    error = e && e.message ? e.message : String(e);
    try { latest = st && st.getJSON(kLatest); } catch (_) {}
  }

  // 历史：本地累计 + 500.com，每 6 小时或出现新期号时重拉
  let hist = [];
  try { hist = (st && st.getJSON(kHist)) || []; } catch (_) {}
  const lastFetch = Number((st && st.get(kHistT)) || 0);
  const haveLatest = latest && hist.some(h => h.issue === latest.issue);
  if (g.hist && (!haveLatest || Date.now() - lastFetch > 6 * 3600e3 || hist.length < N)) {
    try {
      const fresh = await fetchHistory(ctx, g, Math.max(N, 30));
      if (fresh.length) { hist = mergeHist(fresh, hist); st && st.set(kHistT, String(Date.now())); }
    } catch (_) {}
  }
  if (latest && latest.issue) hist = mergeHist([{ issue: latest.issue, front: latest.front, back: latest.back }], hist);
  hist = hist.slice(0, 100);
  try { st && st.setJSON(kHist, hist); } catch (_) {}

  const draws = hist.slice(0, N);
  const A = analyze(g, draws);
  const nextIssue = latest && latest.issue ? String(Number(latest.issue) + 1) : '';
  const picks = [suggest(g, A, `${type}-${nextIssue}-1`), suggest(g, A, `${type}-${nextIssue}-2`)];
  const nd = latest ? nextDraw(latest.frequency, latest.officeTime, now) : null;
  return { type, g, latest, error, A, picks, nd, nextIssue, now, N: draws.length };
}
function mergeHist(a, b) {
  const map = new Map();
  [...a, ...b].forEach(d => { if (d && d.issue && !map.has(d.issue)) map.set(d.issue, d); });
  return [...map.values()].sort((x, y) => Number(y.issue) - Number(x.issue));
}

// ---------------------------------------------------------------------------
// 组件
// ---------------------------------------------------------------------------
function header(S, size = 13) {
  const L = S.latest;
  const d = L && L.openTime ? new Date(L.openTime.replace(' ', 'T')) : null;
  return row([
    icon('ticket.fill', S.g.fColor, size - 1),
    T(S.g.name, size, C.text, 'semibold', { minScale: 1 }),
    T(L ? `第${L.issue.slice(-3)}期` : '', size - 2, C.dim, 'medium', { minScale: 1 }),
    { type: 'spacer' },
    T(`${S.error ? '缓存 · ' : ''}${d ? `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${WEEK[d.getDay()]}` : ''}`, 10, S.error ? C.gold : C.dim, 'regular', { minScale: 1 }),
  ]);
}
function ballsRow(g, front, back, size, gap, outline) {
  return row([
    ...front.map(n => ball(n, g.fColor, size, outline)),
    ...back.map(n => ball(n, g.bColor, size, outline)),
  ], { gap });
}
function drawCountdown(S) {
  if (!S.nd) return T('', 10, C.dim);
  const mins = (S.nd - S.now) / 60000;
  const c = mins < 180 ? C.hot : C.gold;
  return row([
    icon('clock.fill', c, 10),
    T(`下期 ${WEEK[S.nd.getDay()]} ${pad2(S.nd.getHours())}:${pad2(S.nd.getMinutes())}`, 10, C.text, 'semibold', { minScale: 1 }),
    T(`${fmtCountdown(S.nd, S.now)}后`, 10, c, 'semibold', { minScale: 1 }),
  ]);
}
function poolText(S) {
  return S.latest && S.latest.pool ? row([T('奖池', 10, C.dim, 'medium', { minScale: 1 }), T(fmtPool(S.latest.pool), 10, C.gold, 'bold', { minScale: 1 })], { gap: 3 }) : T('', 10, C.dim);
}
function hotColdLine(S, nHot = 3, nCold = 2) {
  const A = S.A;
  if (!A) return T(`走势数据累计中（${S.N} 期）`, 10, C.dim, 'medium');
  let hot, cold;
  if (S.g.kind === 'pool') { hot = A.f.hot.slice(0, nHot).map(pad2); cold = A.f.cold.slice(0, nCold).map(pad2); }
  else { hot = A.hotD.slice(0, nHot).map(String); cold = A.coldD.slice(0, nCold).map(String); }
  const n = S.g.front;
  return row([
    T('热', 10, C.hot, 'bold', { minScale: 1 }), T(hot.join(' '), 10, C.text, 'semibold', { minScale: 1 }),
    T('冷', 10, C.cold, 'bold', { minScale: 1 }), T(cold.join(' '), 10, C.text, 'semibold', { minScale: 1 }),
    { type: 'spacer' },
    T(`奇偶 ${A.odd}:${n - A.odd}  大小 ${A.big}:${n - A.big}`, 10, C.dim, 'medium', { minScale: 0.8 }),
  ]);
}
function refreshAfter(S) {
  let mins = 180;
  if (S.nd) {
    const m = (S.nd - S.now) / 60000;
    if (m < 180) mins = Math.max(5, Math.min(mins, m + 20));
  }
  // 开奖后 2 小时内若接口仍是旧期号，10 分钟重试
  const L = S.latest;
  if (L && L.openTime) {
    const prev = nextDraw(L.frequency, L.officeTime, new Date(S.now.getTime() - 2 * 3600e3));
    const opened = new Date(L.openTime.replace(' ', 'T'));
    if (prev && prev <= S.now && opened < prev - 60000) mins = 10;
  }
  return new Date(Date.now() + mins * 60000).toISOString();
}
function fitBall(n, width, maxSize, gap) { return Math.min(maxSize, Math.floor((width - gap * (n - 1)) / n)); }

function errorWidget(S) {
  return {
    type: 'widget', padding: 14, gap: 6, backgroundGradient: bg(),
    children: [header(S), { type: 'spacer' }, icon('exclamationmark.triangle.fill', C.gold, 20), T('开奖数据加载失败', 14, C.text, 'semibold'), T(S.error || '', 10, C.dim, 'regular', { maxLines: 3 }), { type: 'spacer' }],
  };
}

function buildSmall(S) {
  const L = S.latest, g = S.g, n = L.front.length + L.back.length;
  const two = n > 5;
  const per = two ? Math.ceil(n / 2) : n;
  const size = fitBall(per, 132, 26, 4);
  const all = [...L.front.map(x => [x, g.fColor]), ...L.back.map(x => [x, g.bColor])];
  const rows = two ? [all.slice(0, per), all.slice(per)] : [all];
  return {
    type: 'widget', padding: 12, gap: 6, backgroundGradient: bg(), refreshAfter: refreshAfter(S),
    children: [
      row([icon('ticket.fill', g.fColor, 11), T(g.name, 12, C.text, 'semibold', { minScale: 1 }), { type: 'spacer' }, T(`${L.issue.slice(-3)}期`, 10, C.dim, 'medium', { minScale: 1 })]),
      { type: 'spacer' },
      { type: 'stack', direction: 'column', alignItems: 'center', gap: 4, children: rows.map(r => row(r.map(([x, c]) => ball(x, c, size)), { gap: 4 })) },
      { type: 'spacer' },
      poolText(S),
      S.nd ? T(`下期 ${WEEK[S.nd.getDay()]} · ${fmtCountdown(S.nd, S.now)}后`, 9, C.dim, 'semibold') : T('', 9, C.dim),
    ],
  };
}

function buildMedium(S) {
  const L = S.latest, g = S.g, n = L.front.length + L.back.length;
  const size = fitBall(n, 300, 32, 6), small = fitBall(n, 230, 19, 4);
  const p = S.picks[0];
  return {
    type: 'widget', padding: [11, 12], gap: 7, backgroundGradient: bg(), refreshAfter: refreshAfter(S),
    children: [
      header(S),
      row([{ type: 'spacer' }, ballsRow(g, L.front, L.back, size, 6), { type: 'spacer' }]),
      row([T('参考', 10, C.dim, 'medium', { minScale: 1 }), ballsRow(g, p.front, p.back, small, 4, true), { type: 'spacer' }, poolText(S)], { gap: 6 }),
      glass([
        row([drawCountdown(S), { type: 'spacer' }, T(S.A ? `近${S.A.N}期` : '', 10, C.dim, 'medium', { minScale: 1 })]),
        hotColdLine(S),
      ], { gap: 4, padding: [6, 10], borderRadius: 12 }),
    ],
  };
}

function buildLarge(S) {
  const L = S.latest, g = S.g, A = S.A, n = L.front.length + L.back.length;
  const size = fitBall(n, 310, 34, 7), small = fitBall(n, 240, 22, 5), chip = 18;
  const panel = [];
  if (A) {
    let hotBalls, coldBalls, hotLbl, coldLbl;
    if (g.kind === 'pool') {
      hotBalls = A.f.hot.slice(0, 6).map(x => ball(pad2(x), C.hot, chip));
      coldBalls = A.f.cold.slice(0, 6).map(x => ball(pad2(x), C.cold, chip, true));
      hotLbl = `出现 ${A.f.freq[A.f.hot[0]]} 次`; coldLbl = `遗漏 ${A.f.miss[A.f.cold[0]]} 期`;
    } else {
      hotBalls = A.hotD.slice(0, 5).map(x => ball(String(x), C.hot, chip));
      coldBalls = A.coldD.slice(0, 5).map(x => ball(String(x), C.cold, chip, true));
      hotLbl = '全位置'; coldLbl = `遗漏 ${A.missD[A.coldD[0]]} 期`;
    }
    panel.push(
      row([T('热号', 10, C.hot, 'bold', { minScale: 1 }), ...hotBalls, { type: 'spacer' }, T(hotLbl, 9, C.dim, 'medium', { minScale: 1 })], { gap: 4 }),
      row([T('冷号', 10, C.cold, 'bold', { minScale: 1 }), ...coldBalls, { type: 'spacer' }, T(coldLbl, 9, C.dim, 'medium', { minScale: 1 })], { gap: 4 }),
    );
    if (A.b) panel.push(row([T(g.name === '大乐透' ? '后区' : '蓝球', 10, g.bColor, 'bold', { minScale: 1 }), T(`热 ${A.b.hot.slice(0, 3).map(pad2).join(' ')}`, 10, C.text, 'semibold', { minScale: 1 }), T(`冷 ${A.b.cold.slice(0, 3).map(pad2).join(' ')}`, 10, C.text, 'semibold', { minScale: 1 }), { type: 'spacer' }], { gap: 8 }));
    const bars = barsSvg(A.sums, g.fColor, 130, 26, A.avgSum);
    panel.push(row([
      { type: 'stack', direction: 'column', alignItems: 'start', gap: 2, children: [
        T(`和值 ${A.sums[A.sums.length - 1]}（均 ${A.avgSum}）`, 10, C.text, 'semibold', { minScale: 1 }),
        T(`奇偶 ${A.odd}:${g.front - A.odd} · 大小 ${A.big}:${g.front - A.big}${A.span != null ? ` · 跨度 ${A.span}` : ''}`, 10, C.dim, 'medium', { minScale: 0.8 }),
      ] },
      { type: 'spacer' },
      ...(bars ? [{ type: 'image', src: bars, width: 130, height: 26 }] : []),
    ]));
  } else {
    panel.push(T(`走势数据累计中（${S.N} 期），开奖几期后自动出现`, 10, C.dim, 'medium', { maxLines: 2 }));
  }
  return {
    type: 'widget', padding: 14, gap: 8, backgroundGradient: bg(), refreshAfter: refreshAfter(S),
    children: [
      header(S, 14),
      row([{ type: 'spacer' }, ballsRow(g, L.front, L.back, size, 7), { type: 'spacer' }]),
      row([drawCountdown(S), { type: 'spacer' }, poolText(S)]),
      glass([
        row([icon('chart.bar.fill', C.gold, 10), T(A ? `近 ${A.N} 期走势` : '走势', 10, C.dim, 'semibold', { minScale: 1 }), { type: 'spacer' }]),
        ...panel,
      ], { gap: 6, padding: [8, 12] }),
      glass([
        row([icon('sparkles', C.gold, 10), T(`第${S.nextIssue.slice(-3)}期参考号`, 10, C.dim, 'semibold', { minScale: 1 }), { type: 'spacer' }, T('仅供娱乐 · 开奖完全随机', 9, C.dim, 'regular', { minScale: 1 })]),
        ...S.picks.map(p => row([ballsRow(g, p.front, p.back, small, 5, true), { type: 'spacer' }])),
      ], { gap: 6, padding: [8, 12] }),
      { type: 'spacer' },
    ],
  };
}

function buildLock(S, family) {
  const L = S.latest;
  const nums = `${L.front.join(' ')}${L.back.length ? ' + ' + L.back.join(' ') : ''}`;
  if (family === 'accessoryInline') return { type: 'widget', children: [T(`${S.g.name} ${nums}`, 12, C.text, 'medium')] };
  if (family === 'accessoryCircular') {
    return { type: 'widget', padding: 4, gap: 0, children: [{ type: 'spacer' }, icon('ticket.fill', C.text, 12), T(`${L.issue.slice(-3)}期`, 11, C.text, 'bold'), T(S.nd ? fmtCountdown(S.nd, S.now) : '', 8, C.dim, 'medium'), { type: 'spacer' }] };
  }
  return {
    type: 'widget', gap: 2, children: [
      row([icon('ticket.fill', C.text, 11), T(`${S.g.name} 第${L.issue.slice(-3)}期`, 11, C.text, 'semibold')]),
      T(nums, 12, C.text, 'bold', { minScale: 0.6 }),
      T(S.nd ? `下期 ${WEEK[S.nd.getDay()]} ${pad2(S.nd.getHours())}:${pad2(S.nd.getMinutes())} · 奖池 ${fmtPool(L.pool)}` : `奖池 ${fmtPool(L.pool)}`, 10, C.dim, 'medium'),
    ],
  };
}

export default async function (ctx) {
  const S = await getState(ctx);
  const family = ctx.widgetFamily || 'systemMedium';
  if (!S.latest) return errorWidget(S);
  if (family.startsWith('accessory')) return buildLock(S, family);
  if (family === 'systemSmall') return buildSmall(S);
  if (family === 'systemLarge' || family === 'systemExtraLarge') return buildLarge(S);
  return buildMedium(S);
}
