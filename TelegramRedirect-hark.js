// Telegram 重定向（Egern 原生版，Hark 改写自可莉 TelegramRedirect.lpx）
// 客户端在模块设置页「客户端」里选，读 ctx.env.APP，默认 tg
const ALLOWED = ['tg', 'sg', 'turrit', 'ime', 'ng', 'lingo'];

export default async function (ctx) {
  const app = ALLOWED.includes((ctx.env && ctx.env.APP) || '') ? ctx.env.APP : 'tg';
  const url = ctx.request.url;
  let m = url.match(/^https:\/\/t\.me\/([A-Za-z][A-Za-z0-9_]{3,30}[A-Za-z0-9])\/?$/);
  let target = null;
  if (m) target = `${app}://resolve?domain=${m[1]}`;
  else if ((m = url.match(/^https:\/\/t\.me\/\+([A-Za-z0-9_-]+)\/?$/))) target = `${app}://join?invite=${m[1]}`;
  if (!target) return; // 其它 t.me 链接原样放行
  return ctx.respond({ status: 307, headers: { Location: target } });
}
