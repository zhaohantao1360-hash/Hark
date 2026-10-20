/**
 * Egern 小组件 · 每日打卡（Hark）
 * 上下班打卡、每日安全隐患排查、每周办进京证，按时间自动切换「现在该做什么」。
 * 工作日按国务院节假日安排（含调休补班）判断，数据来自 NateScarlet/holiday-cn，按年缓存。
 * 打卡机无法联网确认，状态按时间推断：到点前提醒、过点后视为已过。
 * env：WORK_START 上班时间；WORK_END 下班时间；CHECK_TIME 安全排查提醒时间；
 *      JJZ_DAY 办进京证的星期（1=周一）；JJZ_TIME 进京证提醒时间；REMIND_BEFORE 打卡提前提醒分钟；
 *      MODE=notify 时作为定时任务只发通知（模块里的 schedule 已设置）。
 */

const C = {
  text: { light: '#000000', dark: '#FFFFFF' },
  dim: { light: '#3C3C4399', dark: '#EBEBF599' },
  faint: { light: '#3C3C4366', dark: '#EBEBF566' },
  glass: { light: '#FFFFFFA6', dark: '#FFFFFF1A' },
  accent: '#0A84FF',
  ok: '#30D158',
  now: '#FF9F0A',
  rest: '#BF5AF2',
  jjz: '#64D2FF',
};

const clean = (v) => String(v == null ? '' : v).trim();
const pad = (n) => String(n).padStart(2, '0');
const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const WD = ['日', '一', '二', '三', '四', '五', '六'];

function hm(v, def) {
  const m = clean(v).match(/^(\d{1,2})[:：](\d{2})$/);
  const [h, mi] = m ? [Number(m[1]), Number(m[2])] : def;
  return h * 60 + mi;
}
const fmt = (min) => `${pad(Math.floor(min / 60))}:${pad(min % 60)}`;
function at(base, min) {
  const d = new Date(base);
  d.setHours(Math.floor(min / 60), min % 60, 0, 0);
  return d;
}

function cfg(ctx) {
  const e = ctx.env || {};
  const jd = Number(clean(e.JJZ_DAY) || 1);
  const rb = Number(clean(e.REMIND_BEFORE) || 10);
  return {
    start: hm(e.WORK_START, [8, 0]),
    end: hm(e.WORK_END, [17, 0]),
    check: hm(e.CHECK_TIME, [9, 30]),
    jjzTime: hm(e.JJZ_TIME, [8, 30]),
    jjzDay: jd >= 0 && jd <= 7 ? jd % 7 : 1,
    before: Number.isFinite(rb) && rb >= 0 && rb <= 120 ? rb : 10,
    mode: clean(e.MODE).toLowerCase(),
  };
}

// ---------- 节假日 ----------
async function holidays(ctx, year) {
  const key = `duty_holiday_${year}`;
  let cache = null;
  try { cache = ctx.storage.getJSON(key); } catch (_) {}
  if (cache && cache.days && Date.now() - (cache.ts || 0) < 7 * 86400000) return cache.days;
  const urls = [
    `https://cdn.jsdelivr.net/gh/NateScarlet/holiday-cn@master/${year}.json`,
    `https://raw.githubusercontent.com/NateScarlet/holiday-cn/master/${year}.json`,
  ];
  for (const u of urls) {
    try {
      const r = await ctx.http.get(u, { timeout: 6000 });
      if (r.status !== 200) continue;
      const j = JSON.parse(await r.text());
      const days = {};
      for (const it of j.days || []) days[it.date] = { off: !!it.isOffDay, name: it.name };
      ctx.storage.setJSON(key, { ts: Date.now(), days });
      return days;
    } catch (_) {}
  }
  return (cache && cache.days) || {};
}

async function dayInfo(ctx, d, hcache) {
  const y = d.getFullYear();
  if (!hcache[y]) hcache[y] = await holidays(ctx, y);
  const h = hcache[y][ymd(d)];
  const wd = d.getDay();
  if (h) return { work: !h.off, name: h.off ? h.name : `${h.name}补班` };
  return { work: wd >= 1 && wd <= 5, name: '' };
}

// ---------- 状态 ----------
// state: later 未到 / now 该做 / past 已过 / rest 休息
function buildState(now, c, today) {
  const m = now.getHours() * 60 + now.getMinutes();
  const items = [];
  if (today.work) {
    items.push({
      id: 'in', sym: 'sunrise.fill', name: '上班打卡', time: fmt(c.start), target: at(now, c.start),
      state: m < c.start - 60 ? 'later' : m < c.start ? 'now' : 'past',
      tip: m < c.start ? `${fmt(c.start)} 前` : '已过',
    });
    items.push({
      id: 'check', sym: 'checklist', name: '安全隐患排查', time: '今日', target: at(now, c.end),
      state: m < c.start ? 'later' : m < c.end ? 'now' : 'past',
      tip: m < c.start ? '上班后' : m < c.end ? '今日待排查' : '已过',
    });
    items.push({
      id: 'out', sym: 'sunset.fill', name: '下班打卡', time: fmt(c.end), target: at(now, c.end),
      state: m < c.end - 30 ? 'later' : m < c.end + 90 ? 'now' : 'past',
      tip: m < c.end ? `${fmt(c.end)} 后` : m < c.end + 90 ? '可以打卡了' : '已过',
    });
  }
  // 进京证：每周固定一天办，按 7 天有效计算
  const wd = now.getDay();
  const since = (wd - c.jjzDay + 7) % 7;
  const jjzToday = since === 0;
  const left = 7 - since;
  items.push({
    id: 'jjz', sym: 'car.fill', name: '进京证', time: `周${WD[c.jjzDay]}`, target: at(now, c.jjzTime),
    state: jjzToday ? (m < 22 * 60 ? 'now' : 'past') : 'past',
    tip: jjzToday ? '今天要办' : `还剩 ${left} 天`,
    left, jjzToday,
  });
  const focus = items.find((i) => i.state === 'now') || items.find((i) => i.state === 'later') || null;
  return { items, focus, m };
}

function stateColor(s) {
  return s === 'now' ? C.now : s === 'later' ? C.dim : C.faint;
}
function stateSym(it) {
  if (it.id === 'jjz' && !it.jjzToday) return 'checkmark.seal.fill';
  return it.state === 'now' ? 'exclamationmark.circle.fill' : it.state === 'later' ? 'clock' : 'checkmark.circle';
}

// 下次需要刷新的时刻：每个状态切换点
function nextRefresh(now, c) {
  const pts = [c.start - 60, c.start, c.end - 30, c.end, c.end + 90, 22 * 60, 24 * 60 + 1];
  const m = now.getHours() * 60 + now.getMinutes();
  const n = pts.filter((p) => p > m).sort((a, b) => a - b)[0];
  const t = at(now, Math.min(n, 24 * 60 - 1));
  if (n >= 24 * 60) t.setTime(t.getTime() + 2 * 60000);
  return new Date(Math.min(t.getTime(), now.getTime() + 60 * 60000)).toISOString();
}

// ---------- 通知（schedule 模式） ----------
async function notifyMode(ctx, c) {
  const now = new Date();
  const today = await dayInfo(ctx, now, {});
  const m = now.getHours() * 60 + now.getMinutes();
  const ev = [];
  if (today.work) {
    ev.push(['in', c.start - c.before, '上班打卡', `${fmt(c.start)} 上班，记得去打卡机打卡`]);
    ev.push(['check', c.check, '安全隐患排查', '今天的安全隐患排查别忘了']);
    ev.push(['out', c.end, '下班打卡', `${fmt(c.end)} 下班了，打完卡再走`]);
  }
  if (now.getDay() === c.jjzDay) ev.push(['jjz', c.jjzTime, '办进京证', '今天要办本周进京证，打开「北京交警」App 申请']);
  const k = `duty_notified_${ymd(now)}`;
  let done = {};
  try { done = ctx.storage.getJSON(k) || {}; } catch (_) {}
  for (const [id, t, title, body] of ev) {
    if (m >= t && m < t + 15 && !done[id]) {
      ctx.notify({ title, body });
      done[id] = 1;
    }
  }
  ctx.storage.setJSON(k, done);
}

// ---------- UI ----------
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
    colors: [{ light: '#FFF4E6', dark: '#1C1206' }, { light: '#EEF2FF', dark: '#0D1030' }],
    stops: [0, 1], startPoint: { x: 0, y: 0 }, endPoint: { x: 1, y: 1 },
  };
}
const dateTitle = (now) => `${now.getMonth() + 1}/${now.getDate()} 周${WD[now.getDay()]}`;

function header(now, today, size = 12) {
  return row([
    icon('checkmark.rectangle.stack.fill', C.now, size), T('每日打卡', size, C.text, 'semibold'), spacer(),
    T(today.name || (today.work ? '工作日' : '休息日'), size - 3, today.work ? C.dim : C.rest, 'medium'),
    T(dateTitle(now), size - 3, C.faint),
  ]);
}

function focusBlock(st, today, big) {
  const f = st.focus;
  if (!f) {
    return col([
      T(today.work ? '今天都搞定了' : '今天休息', big ? 22 : 18, today.work ? C.ok : C.rest, 'bold'),
      T(today.work ? '下班愉快' : (today.name || '好好休息'), big ? 11 : 10, C.dim),
    ], { gap: 2 });
  }
  const color = f.state === 'now' ? (f.id === 'jjz' ? C.jjz : C.now) : C.text;
  const sub = f.state === 'now' ? f.tip : `${f.time} · `;
  return col([
    row([icon(f.sym, color, big ? 16 : 13), T(f.name, big ? 22 : 18, color, 'bold')], { gap: 5 }),
    f.state === 'later'
      ? row([T(sub, big ? 11 : 10, C.dim), { type: 'date', date: f.target.toISOString(), format: 'relative', font: { size: big ? 11 : 10 }, textColor: C.dim, maxLines: 1, minScale: 0.6 }], { gap: 0 })
      : T(sub, big ? 11 : 10, C.dim),
  ], { gap: 3 });
}

function itemRow(it, size = 11) {
  const col1 = it.id === 'jjz' ? (it.jjzToday ? C.jjz : C.dim) : stateColor(it.state);
  return row([
    icon(it.sym, it.state === 'now' ? (it.id === 'jjz' ? C.jjz : C.now) : C.dim, size),
    T(it.name, size, it.state === 'past' && it.id !== 'jjz' ? C.dim : C.text, 'medium'),
    spacer(),
    T(it.tip, size - 1, col1, it.state === 'now' ? 'semibold' : 'regular'),
    icon(stateSym(it), it.id === 'jjz' && !it.jjzToday ? C.ok : col1, size - 1),
  ], { gap: 5 });
}

function buildSmall(now, st, today) {
  const list = st.items.filter((i) => i !== st.focus).slice(0, 3);
  return {
    type: 'widget', padding: 12, gap: 0, backgroundGradient: bg(),
    children: [
      row([icon('checkmark.rectangle.stack.fill', C.now, 11), T(dateTitle(now), 10, C.dim, 'medium'), spacer(),
        T(today.work ? '工作日' : '休息', 9, today.work ? C.faint : C.rest)]),
      spacer(),
      focusBlock(st, today, false),
      spacer(),
      col(list.map((i) => itemRow(i, 10)), { gap: 5 }),
    ],
  };
}

function buildMedium(now, st, today) {
  return {
    type: 'widget', padding: [12, 12, 12, 14], backgroundGradient: bg(),
    children: [
      row([
        col([
          row([icon('checkmark.rectangle.stack.fill', C.now, 12), T('每日打卡', 12, C.text, 'semibold')]),
          T(`${dateTitle(now)}${today.name ? ' · ' + today.name : ''}`, 9, today.work ? C.faint : C.rest),
          spacer(),
          focusBlock(st, today, false),
          spacer(),
        ], { width: 118, height: 128 }),
        {
          type: 'stack', direction: 'column', alignItems: 'start', gap: 0, flex: 1, height: 128,
          padding: [10, 11], borderRadius: 16, backgroundColor: C.glass,
          children: st.items.flatMap((it, i) => (i ? [spacer(), itemRow(it, 11)] : [itemRow(it, 11)])),
        },
      ], { gap: 10 }),
    ],
  };
}

function weekStrip(week, c) {
  return row(week.map((d) => {
    const isJ = d.date.getDay() === c.jjzDay;
    return {
      type: 'stack', direction: 'column', alignItems: 'center', gap: 3, flex: 1, height: 58, padding: [6, 0],
      borderRadius: 10, backgroundColor: d.today ? { light: '#FF9F0A33', dark: '#FF9F0A33' } : C.glass,
      children: [
        T(`周${WD[d.date.getDay()]}`, 9, d.today ? C.now : C.dim, 'medium'),
        T(String(d.date.getDate()), 14, d.info.work ? C.text : C.rest, 'bold'),
        T(isJ ? '办证' : d.info.work ? (d.info.name ? '补班' : '上班') : '休', 8, isJ ? C.jjz : d.info.work ? C.faint : C.rest, 'medium'),
      ],
    };
  }), { gap: 5, height: 58 });
}

function buildLarge(now, st, today, week, c) {
  const j = st.items.find((i) => i.id === 'jjz');
  return {
    type: 'widget', padding: 16, gap: 0, backgroundGradient: bg(),
    children: [
      header(now, today, 13),
      spacer(),
      row([
        focusBlock(st, today, true),
        spacer(),
        col([T(j.jjzToday ? '今天办' : `${j.left} 天`, 20, j.jjzToday ? C.jjz : C.text, 'bold'), T(j.jjzToday ? '进京证' : '进京证剩余', 9, C.faint)], { alignItems: 'end', gap: 1 }),
      ], { height: 52 }),
      spacer(),
      {
        type: 'stack', direction: 'column', alignItems: 'start', gap: 0, height: 140, padding: [12, 12], borderRadius: 14, backgroundColor: C.glass,
        children: st.items.flatMap((it, i) => (i ? [spacer(), itemRow(it, 12)] : [itemRow(it, 12)])),
      },
      spacer(),
      T('本周', 10, C.dim, 'medium'),
      spacer(5),
      weekStrip(week, c),
    ],
  };
}

function buildLock(now, st, today, family) {
  const f = st.focus;
  const line = f ? `${f.name} · ${f.tip}` : (today.work ? '今天都搞定了' : '今天休息');
  if (family === 'accessoryInline') return { type: 'widget', children: [{ type: 'text', text: line, maxLines: 1, minScale: 0.6 }] };
  if (family === 'accessoryCircular') {
    const j = st.items.find((i) => i.id === 'jjz');
    return {
      type: 'widget', padding: 4, children: [spacer(),
        { type: 'text', text: j.jjzToday ? '办证' : String(j.left), font: { size: 18, weight: 'bold' }, textAlign: 'center' },
        { type: 'text', text: j.jjzToday ? '进京证' : '天', font: { size: 9 }, textAlign: 'center' }, spacer()],
    };
  }
  return {
    type: 'widget', padding: [2, 4], gap: 2,
    children: st.items.slice(0, 3).map((it) => ({ type: 'text', text: `${it.state === 'now' ? '●' : '○'} ${it.name} ${it.tip}`, font: { size: 12, weight: it.state === 'now' ? 'semibold' : 'regular' }, maxLines: 1, minScale: 0.6 })),
  };
}

export default async function (ctx) {
  const c = cfg(ctx);
  if (c.mode === 'notify') return notifyMode(ctx, c);
  const now = new Date();
  const hc = {};
  const today = await dayInfo(ctx, now, hc);
  const st = buildState(now, c, today);
  const family = ctx.widgetFamily || 'systemMedium';
  let w;
  if (family.startsWith('accessory')) w = buildLock(now, st, today, family);
  else if (family === 'systemSmall') w = buildSmall(now, st, today);
  else if (family === 'systemLarge' || family === 'systemExtraLarge') {
    const mon = new Date(now); mon.setHours(12, 0, 0, 0);
    mon.setDate(mon.getDate() - ((now.getDay() + 6) % 7));
    const week = [];
    for (let i = 0; i < 7; i++) {
      const d = new Date(mon); d.setDate(mon.getDate() + i);
      week.push({ date: d, info: await dayInfo(ctx, d, hc), today: ymd(d) === ymd(now) });
    }
    w = buildLarge(now, st, today, week, c);
  } else w = buildMedium(now, st, today);
  w.refreshAfter = nextRefresh(now, c);
  return w;
}
