/* BESTPRIME DNS panel — vanilla JS, no external assets. */
'use strict';

const state = {
  settings: null,
  routes: [],
  clients: [],
  meta: {},
  stats: null,
  view: 'dashboard',
  routeFilter: '',
  clientFilter: '',
};

/* ── helpers ─────────────────────────────────────────────── */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const nf = new Intl.NumberFormat('fa-IR');

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function num(n) { return nf.format(Number(n) || 0); }

function bytes(n) {
  n = Number(n) || 0;
  const units = ['بایت', 'کیلوبایت', 'مگابایت', 'گیگابایت', 'ترابایت'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${nf.format(i > 0 ? Number(n.toFixed(2)) : n)} ${units[i]}`;
}

function qps(v) { return `${num(Math.round(Number(v) || 0))} کوئری/ثانیه`; }

function faDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  try {
    return new Intl.DateTimeFormat('fa-IR', { dateStyle: 'medium', timeStyle: 'short' }).format(d);
  } catch (e) { return d.toISOString().slice(0, 16).replace('T', ' '); }
}

function daysLeft(iso) {
  if (!iso) return null;
  const ms = new Date(iso).getTime() - Date.now();
  return Math.ceil(ms / 86400000);
}

function pct(a, b) { return b > 0 ? Math.min(100, Math.round((a / b) * 100)) : 0; }

function toast(msg, kind = 'ok') {
  const box = $('#toasts');
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = '.3s'; }, 3200);
  setTimeout(() => el.remove(), 3600);
}

async function api(path, opts = {}) {
  const headers = Object.assign({ 'X-Requested-With': 'bestdns' }, opts.headers || {});
  if (opts.body && !(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts, { headers }));
  if (res.status === 401) { window.location.href = '/login'; throw new Error('unauthorized'); }
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch (e) { data = { raw: text }; } }
  if (!res.ok) throw new Error((data && data.error) || `خطا (${res.status})`);
  return data;
}

async function copy(text, label = 'کپی شد') {
  try {
    await navigator.clipboard.writeText(text);
    toast(label);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
    toast(label);
  }
}

function origin() { return window.location.origin; }

/* ── navigation ──────────────────────────────────────────── */
const VIEW_META = {
  dashboard: ['داشبورد', 'نمای زندهٔ ترافیک و وضعیت سرویس'],
  routes: ['مسیرها', 'دامنه‌هایی که باید از این سرور عبور کنند'],
  clients: ['کلاینت‌ها', 'دسته‌بندی‌شده بر اساس مسیرهایی که خودت ساختی'],
  settings: ['تنظیمات', 'پیکربندی سرویس، امنیت و پشتیبان‌گیری'],
};

function setView(view) {
  state.view = view;
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${view}`));
  const [title, sub] = VIEW_META[view] || ['', ''];
  $('#view-title').textContent = title;
  $('#view-sub').textContent = sub;
  renderTopbar();
  if (view === 'dashboard') pollStats();
}

function renderTopbar() {
  const box = $('#topbar-actions');
  box.innerHTML = '';
  const pill = document.createElement('span');
  pill.className = 'pill count';
  pill.id = 'top-pill';
  pill.textContent = state.stats ? qps(state.stats.qps) : 'در حال اتصال';
  box.appendChild(pill);
}

/* ── data ────────────────────────────────────────────────── */
async function loadState() {
  const data = await api('/api/state');
  state.settings = data.settings;
  state.routes = data.routes || [];
  state.clients = data.clients || [];
  state.meta = data.meta || {};
  renderAll();
}

async function pollStats() {
  try {
    const s = await api('/api/stats');
    state.stats = s;
    renderDashboardStats();
    if (state.view === 'dashboard') renderTopbar();
  } catch (e) { /* transient */ }
}

/* ── render ──────────────────────────────────────────────── */
function renderAll() {
  $('#side-dns-ip').textContent = state.meta.dns_ip || '—';
  $('#nav-routes-count').textContent = num(state.routes.length);
  $('#nav-clients-count').textContent = num(state.clients.length);
  renderRoutes();
  renderClients();
  renderSettings();
  renderDashboardRoutes();
  renderServiceStatus();
}

function renderDashboardStats() {
  const s = state.stats;
  if (!s) return;
  $('#st-total').textContent = num(s.queries_total);
  $('#st-qps').textContent = qps(s.qps);
  $('#st-routed').textContent = num(s.queries_routed);
  $('#st-routed-pct').textContent = `${num(pct(s.queries_routed, s.queries_total))} درصد از کل`;
  $('#st-cached').textContent = num(s.queries_cached);
  $('#st-refused').textContent = num(s.queries_refused);
  $('#st-active').textContent = num(s.proxy_active || 0);
  $('#st-proxy-conn').textContent = `${num(s.proxy_connections)} اتصال موفق`;
  $('#st-bytes').textContent = bytes(s.proxy_bytes);
  $('#st-failed').textContent = `${num(s.queries_failed)} خطا · ${num(s.proxy_errors)} رله`;
  const pill = $('#top-pill');
  if (pill) pill.textContent = qps(s.qps);
  drawChart(s.series || []);
  renderTopDomains(s.top_domains || []);
  $('#side-uptime').textContent = `فعال از ${Math.floor((s.uptime_seconds || 0) / 60)} دقیقه پیش`;
  $('#side-status').classList.remove('off');
}

function drawChart(series) {
  const canvas = $('#qps-chart');
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 400;
  const h = 150;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(1, ...series);
  $('#chart-max').textContent = `اوج ${num(max)} در ثانیه`;
  const pad = 6;
  const step = (w - pad * 2) / Math.max(1, series.length - 1);
  // grid
  ctx.strokeStyle = 'rgba(148,163,184,.12)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = pad + ((h - pad * 2) / 3) * i;
    ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke();
  }
  // area + line
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(34,211,238,.35)');
  grad.addColorStop(1, 'rgba(34,211,238,0)');
  ctx.beginPath();
  series.forEach((v, i) => {
    const x = pad + step * i;
    const y = h - pad - ((v / max) * (h - pad * 2));
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#22d3ee';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.stroke();
  ctx.lineTo(w - pad, h - pad);
  ctx.lineTo(pad, h - pad);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();
}

function renderTopDomains(list) {
  const tbody = $('#top-domains');
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="muted center">هنوز کوئری‌ای ثبت نشده</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(d => {
    const routed = routeFor(d.name);
    return `<tr>
      <td class="name">${esc(d.name)}</td>
      <td class="num">${num(d.count)}</td>
      <td>${routed ? `<span class="badge pub">${esc(routed.name)}</span>` : '<span class="badge off">مستقیم</span>'}</td>
    </tr>`;
  }).join('');
}

function routeFor(name) {
  return state.routes.find(r => r.enabled && r.domains.some(p => matchPattern(name, p)));
}

function matchPattern(name, pattern) {
  name = name.toLowerCase(); pattern = pattern.toLowerCase();
  if (pattern.startsWith('keyword:')) return name.includes(pattern.slice(8));
  if (pattern.startsWith('=')) return name === pattern.slice(1);
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2);
    return name.endsWith('.' + base);
  }
  return name === pattern || name.endsWith('.' + pattern);
}

function renderDashboardRoutes() {
  const box = $('#dash-routes');
  const active = state.routes.filter(r => r.enabled);
  if (!active.length) {
    box.innerHTML = '<p class="muted small">هنوز مسیری نساخته‌ای. از بخش «مسیرها» اولین دامنه‌ها را اضافه کن.</p>';
    return;
  }
  box.innerHTML = active.map(r => {
    const count = state.clients.filter(c => (c.route_ids || []).includes(r.id)).length;
    return `<span class="chip"><span class="dot" style="background:${esc(r.color)}"></span>${esc(r.name)}
      <b class="muted tiny">${num(r.domains.length)} دامنه</b>
      ${count ? `<b class="tiny" style="color:var(--accent)">${num(count)} کلاینت</b>` : ''}</span>`;
  }).join('');
}

function renderServiceStatus() {
  const s = state.settings || {};
  const st = state.stats || {};
  const rows = [
    ['آدرس DNS', state.meta.dns_ip || '—'],
    ['پورت‌های رله', (s.proxy_ports || []).join(', ') || '—'],
    ['DNS بالادست', (s.upstreams || []).join(', ') || '—'],
    ['DoH', s.doh_port || 'غیرفعال'],
    ['کش', `${num(st.cache_entries || 0)} رکورد · ${num(st.cache_hits || 0)} hit`],
    ['حالت دسترسی', s.allow_all ? 'همه (آزاد)' : 'فقط کلاینت‌های ثبت‌شده'],
    ['نسخه', state.meta.version || '—'],
  ];
  $('#service-status').innerHTML = rows.map(([k, v]) =>
    `<li><span>${esc(k)}</span><strong>${esc(v)}</strong></li>`).join('');
}

/* ── routes ──────────────────────────────────────────────── */
function renderRoutes() {
  const box = $('#routes-list');
  const q = state.routeFilter.trim().toLowerCase();
  const list = state.routes.filter(r => !q ||
    r.name.toLowerCase().includes(q) || r.domains.some(d => d.includes(q)));
  if (!list.length) {
    box.innerHTML = `<div class="empty">${state.routes.length ? 'چیزی پیدا نشد.' : 'هنوز مسیری نساخته‌ای. اولین مسیر را بساز و دامنه‌هایش را وارد کن.'}</div>`;
    return;
  }
  box.innerHTML = list.map(r => {
    const clients = state.clients.filter(c => (c.route_ids || []).includes(r.id)).length;
    const preview = r.domains.slice(0, 8).map(d => `<span>${esc(d)}</span>`).join('') +
      (r.domains.length > 8 ? `<span>+${num(r.domains.length - 8)}</span>` : '');
    return `<article class="card route-card" style="--rc:${esc(r.color)}">
      <div class="client-top">
        <h4><span class="dot" style="width:9px;height:9px;border-radius:50%;background:${esc(r.color)};display:inline-block"></span>${esc(r.name)}</h4>
        <button class="btn tiny ghost" data-toggle-route="${esc(r.id)}">${r.enabled ? 'توقف موقت' : 'فعال کردن'}</button>
      </div>
      <div class="route-meta">
        <span class="badge ${r.enabled ? 'on' : 'off'}">${r.enabled ? 'فعال' : 'غیرفعال'}</span>
        <span class="badge ${r.public ? 'pub' : ''}">${r.public ? 'برای همهٔ کلاینت‌ها' : 'فقط کلاینت‌های انتخابی'}</span>
        <span class="badge">${num(r.domains.length)} دامنه</span>
        ${clients ? `<span class="badge">${num(clients)} کلاینت</span>` : ''}
      </div>
      ${r.note ? `<p class="tiny muted" style="margin-bottom:8px">${esc(r.note)}</p>` : ''}
      <div class="domain-preview">${preview || '<span class="muted">بدون دامنه</span>'}</div>
      <div class="route-actions">
        <button class="btn tiny ghost" data-edit-route="${esc(r.id)}">ویرایش دامنه‌ها</button>
        <button class="btn tiny ghost" data-copy-route="${esc(r.id)}">کپی لیست</button>
        <button class="btn tiny danger" data-del-route="${esc(r.id)}">حذف</button>
      </div>
    </article>`;
  }).join('');

  $$('[data-edit-route]', box).forEach(b => b.onclick = () => routeModal(b.dataset.editRoute));
  $$('[data-del-route]', box).forEach(b => b.onclick = () => deleteRoute(b.dataset.delRoute));
  $$('[data-toggle-route]', box).forEach(b => b.onclick = () => toggleRoute(b.dataset.toggleRoute));
  $$('[data-copy-route]', box).forEach(b => b.onclick = () => {
    const r = state.routes.find(x => x.id === b.dataset.copyRoute);
    if (r) copy(r.domains.join('\n'), 'لیست دامنه‌ها کپی شد');
  });
}

async function toggleRoute(id) {
  const r = state.routes.find(x => x.id === id);
  if (!r) return;
  try {
    await api(`/api/routes/${id}`, {
      method: 'PUT',
      body: JSON.stringify(Object.assign({}, r, { enabled: !r.enabled })),
    });
    await loadState();
    toast(r.enabled ? 'مسیر غیرفعال شد' : 'مسیر فعال شد');
  } catch (e) { toast(e.message, 'err'); }
}

async function deleteRoute(id) {
  const r = state.routes.find(x => x.id === id);
  if (!r) return;
  if (!confirm(`مسیر «${r.name}» حذف شود؟ این مسیر از کلاینت‌ها هم برداشته می‌شود.`)) return;
  try {
    await api(`/api/routes/${id}`, { method: 'DELETE' });
    await loadState();
    toast('مسیر حذف شد');
  } catch (e) { toast(e.message, 'err'); }
}

function routeModal(id) {
  const r = id ? state.routes.find(x => x.id === id) : null;
  openModal({
    title: r ? `ویرایش مسیر «${r.name}»` : 'مسیر جدید',
    submitLabel: r ? 'ذخیرهٔ تغییرات' : 'ساخت مسیر',
    fields: [
      { name: 'name', label: 'نام مسیر', type: 'text', value: r ? r.name : '', required: true, placeholder: 'مثلاً: بازی، تلگرام، هوش مصنوعی' },
      {
        name: 'domains', label: 'دامنه‌ها و ساب‌دامین‌ها (هر خط یک مورد)', type: 'textarea',
        value: r ? r.domains.join('\n') : '',
        hint: 'example.com → خودش + همهٔ ساب‌دامین‌ها · *.example.com → فقط ساب‌دامین‌ها · =example.com → فقط همان دامنه · keyword:text → هر دامنه‌ای که این متن را دارد',
      },
      { name: 'public', label: 'برای همهٔ کلاینت‌ها اعمال شود', type: 'checkbox', value: r ? r.public : true },
      { name: 'enabled', label: 'مسیر فعال باشد', type: 'checkbox', value: r ? r.enabled : true },
      { name: 'color', label: 'رنگ', type: 'color', value: r ? r.color : '#22d3ee' },
      { name: 'note', label: 'یادداشت (اختیاری)', type: 'text', value: r ? r.note : '' },
    ],
    onSubmit: async (values) => {
      const payload = {
        name: values.name,
        domains: values.domains.split('\n').map(s => s.trim()).filter(Boolean),
        public: values.public,
        enabled: values.enabled,
        color: values.color,
        note: values.note,
      };
      if (r) await api(`/api/routes/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
      else await api('/api/routes', { method: 'POST', body: JSON.stringify(payload) });
      await loadState();
      toast(r ? 'مسیر ذخیره شد' : 'مسیر ساخته شد');
    },
  });
}

/* ── clients ─────────────────────────────────────────────── */
function renderClients() {
  const box = $('#clients-groups');
  const q = state.clientFilter.trim().toLowerCase();
  const match = (c) => !q || c.name.toLowerCase().includes(q) ||
    (c.ips || []).some(ip => ip.includes(q)) || (c.token || '').toLowerCase().includes(q);
  const clients = state.clients.filter(match);

  if (!state.clients.length) {
    box.innerHTML = '<div class="empty">هنوز کلاینتی نساخته‌ای. کلاینت بساز تا IP ثبت‌شده‌اش از مسیرهای انتخابی عبور کند.</div>';
    return;
  }

  const groups = state.routes.map(r => ({ route: r, clients: clients.filter(c => (c.route_ids || []).includes(r.id)) }));
  const loose = clients.filter(c => !(c.route_ids || []).length);
  groups.push({ route: null, clients: loose });

  const html = groups.filter(g => g.route || g.clients.length).map(g => {
    const color = g.route ? g.route.color : '#64748b';
    const title = g.route ? g.route.name : 'بدون مسیر (فقط DNS عادی)';
    const sub = g.route
      ? `${num(g.route.domains.length)} دامنه · ${g.clients.length ? num(g.clients.length) + ' کلاینت' : 'بدون کلاینت'}`
      : 'این کلاینت‌ها هیچ مسیری ندارند و فقط resolve عادی می‌گیرند';
    const cards = g.clients.length
      ? `<div class="client-grid">${g.clients.map(clientCard).join('')}</div>`
      : `<div class="empty">هنوز کلاینتی به این مسیر وصل نشده.</div>`;
    return `<section style="--rc:${esc(color)}">
      <div class="group-head"><span class="bar"></span>
        <div><h3>${esc(title)}</h3><p class="tiny muted">${esc(sub)}</p></div>
      </div>${cards}
    </section>`;
  }).join('');

  box.innerHTML = html;
  $$('[data-edit-client]', box).forEach(b => b.onclick = () => clientModal(b.dataset.editClient));
  $$('[data-del-client]', box).forEach(b => b.onclick = () => deleteClient(b.dataset.delClient));
  $$('[data-rotate-client]', box).forEach(b => b.onclick = () => rotateClient(b.dataset.rotateClient));
  $$('[data-copy]', box).forEach(b => b.onclick = () => copy(b.dataset.copy, b.dataset.copyLabel || 'کپی شد'));
}

function clientCard(c) {
  const active = c.enabled && (!c.expires_at || new Date(c.expires_at) > new Date()) &&
    (!c.quota_bytes || c.used_bytes < c.quota_bytes);
  const used = c.quota_bytes ? pct(c.used_bytes, c.quota_bytes) : 0;
  const meterClass = used > 90 ? 'danger' : used > 70 ? 'warn' : '';
  const left = daysLeft(c.expires_at);
  const routeNames = (c.route_ids || []).map(id => (state.routes.find(r => r.id === id) || {}).name).filter(Boolean);
  return `<article class="card client-card">
    <div class="client-top">
      <div>
        <div class="client-name">${esc(c.name)}</div>
        <div class="client-ip">${(c.ips || []).length ? esc(c.ips.join(', ')) : 'IP ثبت نشده'}</div>
      </div>
      <span class="badge ${active ? 'on' : 'off'}">${active ? 'فعال' : 'غیرفعال'}</span>
    </div>
    <div class="client-rows">
      <div><span>انقضا</span><b>${c.expires_at ? `${faDate(c.expires_at)}${left !== null ? ` (${num(left)} روز)` : ''}` : 'بی‌نهایت'}</b></div>
      <div><span>مصرف</span><b>${c.quota_bytes ? `${bytes(c.used_bytes)} / ${bytes(c.quota_bytes)}` : bytes(c.used_bytes)}</b></div>
      <div><span>کوئری</span><b>${num(c.queries)}</b></div>
      <div><span>مسیرها</span><b style="direction:rtl;font-family:var(--font)">${routeNames.length ? esc(routeNames.join('، ')) : '—'}</b></div>
    </div>
    ${c.quota_bytes ? `<div class="meter ${meterClass}"><i style="width:${used}%"></i></div>` : ''}
    <div class="token-box">
      <code>${esc(c.token)}</code>
      <button class="btn tiny ghost" data-copy="${esc(origin() + '/ip/' + c.token)}" data-copy-label="لینک ثبت IP کپی شد">لینک ثبت IP</button>
    </div>
    <div class="client-actions">
      <button class="btn tiny ghost" data-copy="${esc(origin() + '/p/' + c.token)}" data-copy-label="لینک پورتال کپی شد">پورتال</button>
      <button class="btn tiny ghost" data-edit-client="${esc(c.id)}">ویرایش</button>
      <button class="btn tiny ghost" data-rotate-client="${esc(c.id)}">توکن جدید</button>
      <button class="btn tiny danger" data-del-client="${esc(c.id)}">حذف</button>
    </div>
  </article>`;
}

function clientModal(id) {
  const c = id ? state.clients.find(x => x.id === id) : null;
  const routeBoxes = state.routes.length
    ? state.routes.map(r => `<label class="switch" style="padding:9px 12px">
        <input type="checkbox" name="route_${esc(r.id)}" ${c && (c.route_ids || []).includes(r.id) ? 'checked' : ''}>
        <span></span>
        <div><strong>${esc(r.name)}</strong><em class="hint">${num(r.domains.length)} دامنه${r.public ? ' · عمومی' : ''}</em></div>
      </label>`).join('')
    : '<p class="hint">هنوز مسیری نساخته‌ای؛ کلاینت فقط DNS عادی می‌گیرد.</p>';

  const expiry = c && c.expires_at ? new Date(c.expires_at).toISOString().slice(0, 10) : '';
  openModal({
    title: c ? `ویرایش کلاینت «${c.name}»` : 'کلاینت جدید',
    submitLabel: c ? 'ذخیرهٔ تغییرات' : 'ساخت کلاینت',
    fields: [
      { name: 'name', label: 'نام کلاینت', type: 'text', value: c ? c.name : '', required: true, placeholder: 'مثلاً: موبایل علی' },
      { name: 'ips', label: 'IP دستی (اختیاری، با کاما)', type: 'text', value: c ? (c.ips || []).join(', ') : '', placeholder: '2.144.x.x', ltr: true, hint: 'اگر خالی بماند، کلاینت با لینک ثبت IP خودش را ثبت می‌کند.' },
      { name: 'expiry', label: 'تاریخ انقضا (خالی = بی‌نهایت)', type: 'date', value: expiry },
      { name: 'quota', label: 'سقف ترافیک (گیگابایت، ۰ = بی‌نهایت)', type: 'number', value: c && c.quota_bytes ? (c.quota_bytes / 1073741824).toFixed(2) : 0 },
      { name: 'enabled', label: 'کلاینت فعال باشد', type: 'checkbox', value: c ? c.enabled : true },
      { name: 'note', label: 'یادداشت', type: 'text', value: c ? c.note : '' },
      { name: 'routes', label: 'مسیرهای این کلاینت', type: 'html', html: routeBoxes },
    ],
    onSubmit: async (values, form) => {
      const routeIDs = $$('input[name^="route_"]', form).filter(i => i.checked).map(i => i.name.slice(6));
      const payload = {
        name: values.name,
        ips: values.ips ? values.ips.split(',').map(s => s.trim()).filter(Boolean) : [],
        expires_at: values.expiry ? new Date(values.expiry + 'T23:59:59').toISOString() : null,
        quota_bytes: Math.max(0, Math.round((Number(values.quota) || 0) * 1073741824)),
        enabled: values.enabled,
        note: values.note,
        route_ids: routeIDs,
      };
      let created;
      if (c) {
        await api(`/api/clients/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
      } else {
        created = await api('/api/clients', { method: 'POST', body: JSON.stringify(payload) });
      }
      await loadState();
      toast(c ? 'کلاینت ذخیره شد' : 'کلاینت ساخته شد');
      if (created && created.token) {
        copy(`${origin()}/ip/${created.token}`, 'لینک ثبت IP کلاینت جدید کپی شد');
      }
    },
  });
}

async function deleteClient(id) {
  const c = state.clients.find(x => x.id === id);
  if (!c) return;
  if (!confirm(`کلاینت «${c.name}» حذف شود؟`)) return;
  try {
    await api(`/api/clients/${id}`, { method: 'DELETE' });
    await loadState();
    toast('کلاینت حذف شد');
  } catch (e) { toast(e.message, 'err'); }
}

async function rotateClient(id) {
  if (!confirm('توکن جدید ساخته شود؟ لینک قبلی از کار می‌افتد.')) return;
  try {
    const c = await api(`/api/clients/${id}/rotate`, { method: 'POST' });
    await loadState();
    copy(`${origin()}/ip/${c.token}`, 'توکن جدید ساخته و کپی شد');
  } catch (e) { toast(e.message, 'err'); }
}

/* ── settings ────────────────────────────────────────────── */
function renderSettings() {
  const s = state.settings;
  if (!s) return;
  const form = $('#settings-form');
  form.proxy_ip.value = s.proxy_ip || '';
  form.proxy_ports.value = (s.proxy_ports || []).join(',');
  form.upstreams.value = (s.upstreams || []).join(', ');
  form.doh_port.value = s.doh_port || '';
  form.cache_ttl.value = s.cache_ttl || 0;
  form.routed_ttl.value = s.routed_ttl || 60;
  form.rate_limit.value = s.rate_limit || 0;
  form.max_conns.value = s.max_conns || 2048;
  form.proxy_timeout.value = s.proxy_timeout || 10;
  form.panel_title.value = s.panel_title || '';
  form.allow_all.checked = !!s.allow_all;
  form.fragment.checked = !!s.fragment;
  form.answer_ipv6.checked = !!s.answer_ipv6;
}

/* ── modal ───────────────────────────────────────────────── */
let modalSubmit = null;

function openModal({ title, fields, submitLabel, onSubmit }) {
  $('#modal-title').textContent = title;
  $('#modal-submit').textContent = submitLabel || 'ذخیره';
  $('#modal-error').hidden = true;
  const box = $('#modal-fields');
  box.innerHTML = fields.map(f => {
    const val = f.value == null ? '' : f.value;
    const req = f.required ? 'required' : '';
    switch (f.type) {
      case 'textarea':
        return `<label class="field"><span>${esc(f.label)}</span>
          <textarea class="input" name="${esc(f.name)}" ${req} placeholder="${esc(f.placeholder || '')}">${esc(val)}</textarea>
          ${f.hint ? `<em class="hint">${esc(f.hint)}</em>` : ''}</label>`;
      case 'checkbox':
        return `<label class="switch"><input type="checkbox" name="${esc(f.name)}" ${val ? 'checked' : ''}><span></span>
          <div><strong>${esc(f.label)}</strong>${f.hint ? `<em class="hint">${esc(f.hint)}</em>` : ''}</div></label>`;
      case 'color':
        return `<label class="field"><span>${esc(f.label)}</span>
          <input class="input" type="color" name="${esc(f.name)}" value="${esc(val)}" style="height:42px;padding:4px"></label>`;
      case 'html':
        return `<div class="field"><span>${esc(f.label)}</span>${f.html}</div>`;
      default:
        return `<label class="field"><span>${esc(f.label)}</span>
          <input class="input" type="${esc(f.type || 'text')}" name="${esc(f.name)}" value="${esc(val)}" ${req}
            placeholder="${esc(f.placeholder || '')}" ${f.ltr ? 'dir="ltr" style="direction:ltr"' : ''}
            ${f.type === 'number' ? 'step="any"' : ''}>
          ${f.hint ? `<em class="hint">${esc(f.hint)}</em>` : ''}</label>`;
    }
  }).join('');
  $('#modal-backdrop').hidden = false;
  document.body.classList.add('modal-open');
  const first = box.querySelector('input,textarea');
  if (first) setTimeout(() => first.focus(), 40);

  modalSubmit = async (form) => {
    const values = {};
    fields.forEach(f => {
      if (f.type === 'html') return;
      const el = form.elements[f.name];
      if (!el) return;
      values[f.name] = f.type === 'checkbox' ? el.checked : el.value;
    });
    await onSubmit(values, form);
  };
}

function closeModal() {
  $('#modal-backdrop').hidden = true;
  document.body.classList.remove('modal-open');
  modalSubmit = null;
}

/* ── wiring ──────────────────────────────────────────────── */
function wire() {
  $$('.nav-item').forEach(b => b.onclick = () => setView(b.dataset.view));
  document.addEventListener('click', (e) => {
    const goto = e.target.closest('[data-goto]');
    if (goto) setView(goto.dataset.goto);
  });

  $('#add-route').onclick = () => routeModal(null);
  $('#add-client').onclick = () => clientModal(null);
  $('#route-search').oninput = (e) => { state.routeFilter = e.target.value; renderRoutes(); };
  $('#client-search').oninput = (e) => { state.clientFilter = e.target.value; renderClients(); };

  $('#modal-close').onclick = closeModal;
  $('#modal-cancel').onclick = closeModal;
  $('#modal-backdrop').addEventListener('click', (e) => {
    if (e.target === $('#modal-backdrop')) closeModal();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  $('#modal-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!modalSubmit) return;
    const err = $('#modal-error');
    const btn = $('#modal-submit');
    err.hidden = true; btn.disabled = true;
    try {
      await modalSubmit(e.target);
      closeModal();
    } catch (ex) {
      err.textContent = ex.message || 'خطا در ذخیره';
      err.hidden = false;
    } finally { btn.disabled = false; }
  });

  $('#logout').onclick = async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
    window.location.href = '/login';
  };

  $('#settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    const payload = {
      proxy_ip: f.proxy_ip.value.trim(),
      proxy_ports: f.proxy_ports.value.split(',').map(s => parseInt(s.trim(), 10)).filter(n => n > 0 && n < 65536),
      upstreams: f.upstreams.value.split(',').map(s => s.trim()).filter(Boolean),
      doh_port: f.doh_port.value.trim(),
      cache_ttl: parseInt(f.cache_ttl.value, 10) || 0,
      routed_ttl: parseInt(f.routed_ttl.value, 10) || 60,
      rate_limit: parseInt(f.rate_limit.value, 10) || 0,
      max_conns: parseInt(f.max_conns.value, 10) || 2048,
      proxy_timeout: parseInt(f.proxy_timeout.value, 10) || 10,
      panel_title: f.panel_title.value.trim(),
      allow_all: f.allow_all.checked,
      fragment: f.fragment.checked,
      answer_ipv6: f.answer_ipv6.checked,
    };
    try {
      const res = await api('/api/settings', { method: 'POST', body: JSON.stringify(payload) });
      state.settings = res.settings;
      renderAll();
      toast(res.restart ? 'ذخیره شد — برای اعمال پورت‌ها سرویس را ری‌استارت کن' : 'تنظیمات ذخیره شد');
    } catch (ex) { toast(ex.message, 'err'); }
  });

  $('#flush-cache').onclick = async () => {
    try { await api('/api/cache/flush', { method: 'POST' }); toast('کش خالی شد'); }
    catch (e) { toast(e.message, 'err'); }
  };

  $('#password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await api('/api/password', {
        method: 'POST',
        body: JSON.stringify({ current: f.current.value, next: f.next.value }),
      });
      f.reset();
      toast('رمز عبور تغییر کرد');
    } catch (ex) { toast(ex.message, 'err'); }
  });

  $('#restore-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (!confirm('بازیابی، تمام داده‌های فعلی را جایگزین می‌کند. مطمئنی؟')) { e.target.value = ''; return; }
    try {
      const text = await file.text();
      const doc = JSON.parse(text);
      const res = await api('/api/restore', { method: 'POST', body: JSON.stringify(doc) });
      $('#restore-hint').textContent = res.message || 'بازیابی انجام شد.';
      await loadState();
      toast('بازیابی انجام شد');
    } catch (ex) {
      $('#restore-hint').textContent = ex.message;
      toast(ex.message, 'err');
    }
    e.target.value = '';
  });
}

/* ── boot ────────────────────────────────────────────────── */
(async function boot() {
  wire();
  setView('dashboard');
  try {
    await loadState();
    await pollStats();
    setInterval(() => { if (state.view === 'dashboard') pollStats(); }, 2500);
    setInterval(async () => { try { await loadState(); } catch (e) {} }, 30000);
  } catch (e) {
    if (e.message !== 'unauthorized') toast('بارگذاری داده‌ها ناموفق بود', 'err');
  }
})();
