// Telegram 重定向（Egern 原生版）
// 逻辑参考 lylywayr/NetWork-Module 的 TelegramRedirect.js 与可莉 TelegramRedirect.lpx，由 Hark 改写为 Egern 脚本。
// 客户端在模块设置页「客户端」里选（ctx.env.APP），无效或未选时回退官方 tg。
const SCHEMES = {
  tg: 'tg', telegram: 'tg',
  sg: 'sg', swiftgram: 'sg',
  turrit: 'turrit',
  ime: 'ime',
  ng: 'ng', nicegram: 'ng',
  lingo: 'lingo', lingogram: 'lingo',
};

const enc = (v) => encodeURIComponent(v || '');

function q(qs, key) {
  const m = (qs || '').match(new RegExp('(?:^|&)' + key + '=([^&]*)'));
  if (!m) return '';
  try { return decodeURIComponent(m[1].replace(/\+/g, ' ')); } catch (_) { return m[1]; }
}

function deepLink(s, path, qs) {
  const p = path.split('/').filter(Boolean);
  if (!p[0]) return '';
  if (p[0].startsWith('+')) return `${s}://join?invite=${enc(p[0].slice(1))}`;
  if (p[0] === 'joinchat' && p[1]) return `${s}://join?invite=${enc(p[1])}`;
  if (p[0] === 'addstickers' && p[1]) return `${s}://addstickers?set=${enc(p[1])}`;
  if (p[0] === 'addemoji' && p[1]) return `${s}://addemoji?set=${enc(p[1])}`;
  if (p[0] === 'share' && p[1] === 'url') return `${s}://msg_url?url=${enc(q(qs, 'url'))}&text=${enc(q(qs, 'text'))}`;
  if (p[0] === 'c' && p[1] && p[2] && /^\d+$/.test(p[2])) return `${s}://privatepost?channel=${enc(p[1])}&post=${enc(p[2])}`;
  if (p[0] === 'proxy' || p[0] === 'socks') return `${s}://${p[0]}?${qs}`;
  // 话题消息 t.me/group/话题/消息 取最后一段为消息号
  if (p[1] && /^\d+$/.test(p[1])) {
    const post = p[2] && /^\d+$/.test(p[2]) ? p[2] : p[1];
    const thread = p[2] && /^\d+$/.test(p[2]) ? `&thread=${enc(p[1])}` : '';
    return `${s}://resolve?domain=${enc(p[0])}&post=${enc(post)}${thread}`;
  }
  const start = q(qs, 'start');
  return `${s}://resolve?domain=${enc(p[0])}${start ? '&start=' + enc(start) : ''}`;
}

export default async function (ctx) {
  const m = ctx.request.url.match(/^https?:\/\/(?:www\.)?(?:t|telegram)\.me\/(.+)$/i);
  if (!m) return;
  const key = String((ctx.env && ctx.env.APP) || 'tg').trim().toLowerCase();
  const scheme = SCHEMES[key] || 'tg';
  let tail = m[1];
  if (tail.startsWith('s/')) tail = tail.slice(2);
  const i = tail.indexOf('?');
  const link = deepLink(scheme, i < 0 ? tail : tail.slice(0, i), i < 0 ? '' : tail.slice(i + 1));
  if (!link) return;
  return ctx.respond({ status: 302, headers: { Location: link, 'Cache-Control': 'no-store, no-cache' }, body: '' });
}
