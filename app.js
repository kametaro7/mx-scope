/* MXスコープ — UI（入力の解釈・並列判定・集計・表・エクスポート・表示言語） */
(function () {
  'use strict';
  const { rules, dns, classify, i18n } = globalThis.MXC;
  const $ = (id) => document.getElementById(id);
  const el = {
    tabPaste: $('tabPaste'), tabCsv: $('tabCsv'), panePaste: $('panePaste'), paneCsv: $('paneCsv'),
    inputText: $('inputText'), dropZone: $('dropZone'), csvFile: $('csvFile'), csvPreview: $('csvPreview'),
    runBtn: $('runBtn'), cancelBtn: $('cancelBtn'), optDeep: $('optDeep'), optConc: $('optConc'), inputCount: $('inputCount'),
    progress: $('progress'), progressBar: $('progressBar'), progressText: $('progressText'),
    summary: $('summary'), results: $('results'), resBody: $('resBody'), resTable: $('resTable'), bars: $('bars'),
    tTotal: $('tTotal'), tSub: $('tSub'), tA: $('tA'), tB: $('tB'), tG: $('tG'), tC: $('tC'),
    fText: $('fText'), fProspect: $('fProspect'), fHosting: $('fHosting'), fPlatform: $('fPlatform'), shownCount: $('shownCount'),
    copyBtn: $('copyBtn'), csvBtn: $('csvBtn'), jsonBtn: $('jsonBtn'), clearBtn: $('clearBtn'), restoreBtn: $('restoreBtn'),
    resolverBadge: $('resolverBadge'), toast: $('toast'),
    langBtn: $('langBtn'), langLabel: $('langLabel'), langMenu: $('langMenu'),
  };
  const state = { mode: 'paste', csvRecords: null, csvInfo: null, results: [], running: false, cancel: false, sort: { k: null, asc: true }, expanded: new Set(), progress: null, resolver: null };
  const doneRows = () => state.results.filter(Boolean);
  // スクリプトの ?v= を辞書の読み込みにも使う（更新時に古い辞書を掴まない）
  const VERSION = (() => { try { return new URL(document.currentScript.src).searchParams.get('v') || '1'; } catch (e) { return '1'; } })();

  // ---- 表示言語 --------------------------------------------------------------
  let lang = 'ja';
  const T = (key, vars) => i18n.t(lang, key, vars);
  let numFmt = null;
  const fmt = (n) => { try { return numFmt ? numFmt.format(n) : String(n); } catch (e) { return String(n); } };

  // ---- 小物 ----------------------------------------------------------------
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let toastTimer = null;
  function toast(msg) { el.toast.textContent = msg; el.toast.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => el.toast.classList.remove('show'), 2200); }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) { /* noop */ } }

  // ---- タブ ----------------------------------------------------------------
  function setTab(mode) {
    state.mode = mode;
    el.tabPaste.setAttribute('aria-selected', String(mode === 'paste'));
    el.tabCsv.setAttribute('aria-selected', String(mode === 'csv'));
    el.panePaste.hidden = mode !== 'paste'; el.paneCsv.hidden = mode !== 'csv';
    updateInputCount();
  }
  el.tabPaste.addEventListener('click', () => setTab('paste'));
  el.tabCsv.addEventListener('click', () => setTab('csv'));

  // ---- 入力の解釈 -----------------------------------------------------------
  // 会社名などの引き継ぎ列は、言語を切り替えても見出しが変わらないよう内部キーで持つ
  const EXTRA_LINE = '\u0000line';
  const extraKeyLabel = (k) => (k === EXTRA_LINE ? T('extras.line_other') : k);
  function parsePaste(text) {
    const recs = []; const seen = new Set(); let invalid = 0, dup = 0;
    // 1行に複数の URL が連結されていても、区切りが無くても取り出す。
    // ドメインとして読めなかった語（会社名など）は、その行の結果に引き継ぐ。
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim(); if (!line) continue;
      const { domains, rest } = dns.extractDomains(line);
      if (!domains.length) { invalid++; continue; }
      const extras = {};
      if (rest.length) extras[EXTRA_LINE] = rest.join(' / ');
      for (const d of domains) {
        if (seen.has(d.domain)) { dup++; continue; }
        seen.add(d.domain);
        recs.push({ input: d.input, domain: d.domain, extras: Object.assign({}, extras) });
      }
    }
    return { recs, invalid, dup };
  }
  function decodeBytes(buf) {
    const u8 = new Uint8Array(buf);
    const hasBom = u8.length >= 3 && u8[0] === 0xEF && u8[1] === 0xBB && u8[2] === 0xBF;
    try { return { text: new TextDecoder('utf-8', { fatal: true }).decode(hasBom ? u8.subarray(3) : u8), enc: hasBom ? 'UTF-8 (BOM)' : 'UTF-8' }; }
    catch (e) { /* Shift_JIS を試す */ }
    try { return { text: new TextDecoder('shift_jis').decode(u8), enc: 'Shift_JIS' }; }
    catch (e) { return { text: new TextDecoder('utf-8').decode(u8), enc: 'utf8-replaced' }; }
  }
  function parseCsv(text, delim) {
    const rows = []; let row = [], cell = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; }
        else cell += c;
      } else if (c === '"') q = true;
      else if (c === delim) { row.push(cell); cell = ''; }
      else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; }
      else cell += c;
    }
    if (cell.length || row.length) { row.push(cell); rows.push(row); }
    return rows.filter(r => r.some(c => c.trim() !== ''));
  }
  function detectDelim(text) {
    const head = text.split(/\r?\n/).slice(0, 20).join('\n');
    const cnt = (ch) => (head.match(new RegExp(ch === '\t' ? '\t' : '\\' + ch, 'g')) || []).length;
    const c = { '\t': cnt('\t'), ',': cnt(','), ';': cnt(';') };
    const best = Object.entries(c).sort((a, b) => b[1] - a[1])[0];
    return best[1] > 0 ? best[0] : ',';
  }
  // 見出しからドメイン列らしいものを探す（各言語の「URL・ドメイン・メール・サイト」）
  const DOMAIN_HEADER = /url|domain|dominio|domaine|domäne|domein|domena|домен|mail|correo|courriel|e-?posta|website|web ?site|site|sitio|homepage|hp|web|ドメイン|メール|サイト|ホームページ|域名|网址|網址|网站|網站|邮箱|郵箱|도메인|웹사이트|이메일|سایت|دامنه|نطاق|موقع|बेवसाइट|वेबसाइट|डोमेन|เว็บไซต์|โดเมน|trang web|tên miền/i;
  function analyzeCsv(text) {
    const delim = detectDelim(text);
    const rows = parseCsv(text, delim);
    if (!rows.length) return null;
    const width = Math.max(...rows.map(r => r.length));
    const validCount = new Array(width).fill(0);
    const cellDomains = (c) => dns.extractDomains(c || '').domains;
    for (const r of rows) for (let i = 0; i < width; i++) if (cellDomains(r[i]).length) validCount[i]++;
    const firstValid = rows[0].some(c => cellDomains(c).length);
    const hasHeader = !firstValid && rows.length > 1;
    const header = hasHeader ? rows[0].map((h, i) => (h || '').trim() || null) : rows[0].map(() => null);
    let col = validCount.indexOf(Math.max(...validCount));
    if (hasHeader) {
      const pref = header.findIndex(h => h && DOMAIN_HEADER.test(h));
      if (pref >= 0 && validCount[pref] > 0 && validCount[pref] >= validCount[col] * 0.6) col = pref;
    }
    return { rows, hasHeader, header, col, validCount, delim, width };
  }
  // 見出しの無い列は「列1」などの内部キーで持ち、表示の時に訳す
  const colKey = (info, i) => info.header[i] || `\u0000col${i + 1}`;
  const colLabel = (k) => { const m = /^\u0000col(\d+)$/.exec(k); return m ? T('csv.col_default', { n: m[1] }) : extraKeyLabel(k); };
  function csvToRecords(info) {
    const body = info.hasHeader ? info.rows.slice(1) : info.rows;
    const recs = []; let invalid = 0;
    const seen = new Set(); let dup = 0;
    for (const r of body) {
      const cellv = (r[info.col] || '').trim();
      const found = dns.extractDomains(cellv).domains;
      if (!found.length) { invalid++; continue; }
      const extras = {};
      for (let i = 0; i < info.width; i++) if (i !== info.col && (r[i] || '').trim() !== '') extras[colKey(info, i)] = (r[i] || '').trim();
      for (const d of found) {
        if (seen.has(d.domain)) { dup++; continue; }
        seen.add(d.domain);
        recs.push({ input: d.input, domain: d.domain, extras: Object.assign({}, extras) });
      }
    }
    return { recs, invalid, dup };
  }
  function renderCsvPreview() {
    const info = state.csvInfo; if (!info) { el.csvPreview.hidden = true; return; }
    const body = (info.hasHeader ? info.rows.slice(1) : info.rows).slice(0, 5);
    const enc = state.csvEnc === 'utf8-replaced' ? T('csv.enc_replaced') : state.csvEnc;
    const cols = Array.from({ length: info.width }, (_, i) => colLabel(colKey(info, i)));
    let h = `<div>${esc(T('csv.summary', { name: state.csvName, rows: fmt(info.rows.length - (info.hasHeader ? 1 : 0)), cols: fmt(info.width), enc }))} <select id="csvCol">` +
      cols.map((x, i) => `<option value="${i}" ${i === info.col ? 'selected' : ''}>${esc(T('csv.col_option', { name: x, n: fmt(info.validCount[i]), _count: info.validCount[i] }))}</option>`).join('') + `</select></div>`;
    h += '<div class="csv-scroll"><table><thead><tr>' + cols.map((x, i) => `<th class="${i === info.col ? 'pick' : ''}">${esc(x)}</th>`).join('') + '</tr></thead><tbody>';
    for (const r of body) h += '<tr>' + cols.map((_, i) => `<td>${esc((r[i] || '').slice(0, 40))}</td>`).join('') + '</tr>';
    h += '</tbody></table></div>';
    el.csvPreview.innerHTML = h; el.csvPreview.hidden = false;
    $('csvCol').addEventListener('change', (e) => { info.col = parseInt(e.target.value, 10); state.csvRecords = csvToRecords(info); renderCsvPreview(); updateInputCount(); });
  }
  async function loadCsvFile(file) {
    const buf = await file.arrayBuffer();
    const { text, enc } = decodeBytes(buf);
    state.csvName = file.name; state.csvEnc = enc;
    state.csvInfo = analyzeCsv(text);
    state.csvRecords = state.csvInfo ? csvToRecords(state.csvInfo) : { recs: [], invalid: 0, dup: 0 };
    renderCsvPreview(); updateInputCount();
  }
  el.csvFile.addEventListener('change', () => { if (el.csvFile.files[0]) loadCsvFile(el.csvFile.files[0]); });
  ['dragenter', 'dragover'].forEach(ev => el.dropZone.addEventListener(ev, (e) => { e.preventDefault(); el.dropZone.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => el.dropZone.addEventListener(ev, (e) => { e.preventDefault(); el.dropZone.classList.remove('over'); }));
  el.dropZone.addEventListener('drop', (e) => { const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (f) { setTab('csv'); loadCsvFile(f); } });
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => { if (e.target.closest && e.target.closest('#dropZone')) return; e.preventDefault(); const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (f) { setTab('csv'); loadCsvFile(f); } });

  function currentRecords() {
    if (state.mode === 'csv') return state.csvRecords || { recs: [], invalid: 0, dup: 0 };
    return parsePaste(el.inputText.value);
  }
  function updateInputCount() {
    const r = currentRecords();
    const parts = [T('count.items', { n: fmt(r.recs.length), _count: r.recs.length })];
    if (r.dup) parts.push(T('count.dup', { n: fmt(r.dup), _count: r.dup }));
    if (r.invalid) parts.push(T('count.invalid', { n: fmt(r.invalid), _count: r.invalid }));
    el.inputCount.textContent = r.recs.length || r.invalid ? parts.join(T('sep.list')) : '';
    el.runBtn.disabled = state.running || r.recs.length === 0;
  }
  el.inputText.addEventListener('input', updateInputCount);

  // ---- 実行 ----------------------------------------------------------------
  function renderProgress() {
    const p = state.progress; if (!p) return;
    el.progressBar.style.width = `${(p.done / Math.max(1, p.total)) * 100}%`;
    const eta = p.done < p.total && p.eta != null ? T('progress.eta', { sec: fmt(p.eta) }) : '';
    let s = T('progress.main', { done: fmt(p.done), total: fmt(p.total), sec: fmt(p.sec), eta });
    if (p.stats) s += T('progress.stats', { q: fmt(p.stats.queries), c: fmt(p.stats.cacheHits), e: fmt(p.stats.errors) }) + (p.cancelled ? T('progress.cancelled') : '');
    el.progressText.textContent = s;
  }
  async function run() {
    const { recs } = currentRecords();
    if (!recs.length || state.running) return;
    state.running = true; state.cancel = false; state.results = []; state.expanded.clear();
    el.runBtn.disabled = true; el.cancelBtn.hidden = false; el.progress.hidden = false;
    el.summary.hidden = false; el.results.hidden = false;
    const conc = parseInt(el.optConc.value, 10) || 8;
    const deep = el.optDeep.checked ? 'auto' : 'never';
    const t0 = performance.now();
    let done = 0, next = 0, dirty = false;
    const tick = () => {
      const sec = (performance.now() - t0) / 1000;
      const rate = done / Math.max(sec, 0.001);
      state.progress = { done, total: recs.length, sec: Math.round(sec), eta: rate > 0 ? Math.round((recs.length - done) / rate) : null };
      renderProgress();
    };
    const painter = setInterval(() => {
      if (dirty) { dirty = false; if (recs.length <= 400) renderAll(); else { renderSummary(doneRows()); el.shownCount.textContent = T('shown.running', { n: fmt(done), _count: done }); } }
      tick();
    }, 400);
    const worker = async () => {
      while (!state.cancel) {
        const i = next++; if (i >= recs.length) return;
        const rec = recs[i];
        let data;
        try { data = await dns.lookupDomain(rec.input, { deep }); }
        catch (e) { data = { input: rec.input, domain: rec.domain, mxStatus: 'error', mx: [], errorCode: 'dns', errorDetail: String(e && e.message || e), signals: {} }; }
        const slimmed = slim(data);
        state.results[i] = { idx: i, rec, data: slimmed, cls: classify(slimmed, lang) };
        done++; dirty = true;
      }
    };
    await Promise.all(Array.from({ length: Math.min(conc, recs.length) }, worker));
    clearInterval(painter);
    state.results = state.results.filter(Boolean);
    state.running = false; el.cancelBtn.hidden = true; el.runBtn.disabled = false;
    renderAll(); tick();
    const st = dns.state.stats;
    state.progress.stats = { queries: st.queries, cacheHits: st.cacheHits, errors: st.errors };
    state.progress.cancelled = state.cancel;
    renderProgress();
    saveLast();
  }
  // 判定に使う DNS データだけを残す（言語を切り替えた時は、ここから判定文を作り直す）
  function slim(d) {
    return { input: d.input, domain: d.domain, checkedDomain: d.checkedDomain, mxStatus: d.mxStatus, mx: d.mx || [], aFallback: d.aFallback || null,
      spf: d.spf ? { raw: d.spf.raw, includes: d.spf.includes, nested: d.spf.nested || [], aHosts: d.spf.aHosts || [] } : null, dmarc: d.dmarc || null,
      signals: d.signals || {}, ns: d.ns || [], sibling: d.sibling || null, errorCode: d.errorCode || '', errorDetail: d.errorDetail || '', error: d.error || '' };
  }
  el.runBtn.addEventListener('click', run);
  el.cancelBtn.addEventListener('click', () => { state.cancel = true; });

  // ---- 集計・表示 -----------------------------------------------------------
  const THROUGH = new Set(['gateway', 'relay']);
  function effectivePlatform(cls) {
    // 基盤の内訳用: ゲートウェイ/リレー配下で裏側が分かる場合は裏側を数える
    if (cls.backend && cls.platform && THROUGH.has(cls.platform.cat)) return cls.backend.name;
    return cls.platformName;
  }
  function isGoogle(cls) { return cls.platformId === 'google_workspace' || (cls.backend && cls.backend.id === 'google_workspace'); }
  function renderSummary(rows) {
    const c = { A: 0, B: 0, G: 0, C: 0 };
    for (const r of rows) {
      if (isGoogle(r.cls)) c.G++;
      else if (r.cls.prospect === 'A') c.A++;
      else if (r.cls.prospect === 'B') c.B++;
      else c.C++;
    }
    el.tTotal.textContent = fmt(rows.length); el.tA.textContent = fmt(c.A); el.tB.textContent = fmt(c.B); el.tG.textContent = fmt(c.G); el.tC.textContent = fmt(c.C);
    el.tSub.textContent = state.running ? T('tile.running') : '';
    const totalLabel = document.querySelector('[data-i18n="tile.total"]'); if (totalLabel) totalLabel.textContent = T('tile.total', { _count: rows.length });
    const counts = new Map();
    for (const r of rows) { const k = effectivePlatform(r.cls); counts.set(k, (counts.get(k) || 0) + 1); }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const top = sorted.slice(0, 14); const rest = sorted.slice(14).reduce((s, x) => s + x[1], 0);
    const max = Math.max(1, ...top.map(x => x[1]));
    let h = '';
    for (const [name, n] of top) h += `<div class="r" data-p="${esc(name)}" title="${esc(T('chart.hint'))}"><span class="n">${esc(name)}</span><span class="b"><i style="width:${(n / max) * 100}%"></i></span><span class="c">${fmt(n)}</span></div>`;
    if (rest) h += `<div class="r"><span class="n">${esc(T('chart.other', { n: fmt(sorted.length - 14), _count: sorted.length - 14 }))}</span><span class="b"><i style="width:${(rest / max) * 100}%"></i></span><span class="c">${fmt(rest)}</span></div>`;
    el.bars.innerHTML = h || `<span class="muted">${esc(T('chart.empty'))}</span>`;
    el.bars.querySelectorAll('.r[data-p]').forEach(r => r.addEventListener('click', () => { fillSelect(el.fPlatform, platformOptions(), r.dataset.p); el.fPlatform.value = r.dataset.p; renderTable(); }));
  }
  function platformOptions() {
    const counts = new Map();
    for (const r of doneRows()) { const k = effectivePlatform(r.cls); counts.set(k, (counts.get(k) || 0) + 1); }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, k, n]);
  }
  // 区分の絞り込みは、言語を変えても外れないよう区分コードを値にする
  function hostingOptions() {
    const counts = new Map();
    for (const r of doneRows()) counts.set(r.cls.hosting, (counts.get(r.cls.hosting) || 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([code, n]) => [code, rules.hostingName(code, lang), n]);
  }
  function fillSelect(sel, opts, keep) {
    const cur = keep != null ? keep : sel.value;
    const first = sel.options[0].outerHTML;
    sel.innerHTML = first + opts.map(([v, label, n]) => `<option value="${esc(v)}">${esc(label)} (${fmt(n)})</option>`).join('');
    sel.value = [...sel.options].some(o => o.value === cur) ? cur : '';
  }
  function filteredRows() {
    const q = el.fText.value.trim().toLowerCase();
    const fp = el.fProspect.value, fh = el.fHosting.value, fpl = el.fPlatform.value;
    const all = doneRows();
    let rows = all.filter(r => {
      const c = r.cls;
      if (fp && c.prospect !== fp) return false;
      if (fh && c.hosting !== fh) return false;
      if (fpl && effectivePlatform(c) !== fpl) return false;
      if (q) {
        const hay = [r.rec.input, r.rec.domain, c.label, c.hostingLabel, ...Object.values(r.rec.extras || {}), ...(r.data.mx || []).map(m => m.host)].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    const { k, asc } = state.sort;
    if (k) {
      const key = (r) => k === 'domain' ? r.rec.domain : k === 'mx' ? ((r.data.mx[0] || {}).host || '') : k === 'spf' ? ((r.data.spf || {}).includes || []).join(',') : k === 'dmarc' ? ((r.data.dmarc || {}).p || '') : k === 'prospect' ? 'ABCX?'.indexOf(r.cls.prospect) : (r.cls[k] || '');
      let coll = null; try { coll = new Intl.Collator(i18n.locales(lang)); } catch (e) { /* 既定の比較 */ }
      rows = rows.slice().sort((a, b) => {
        const x = key(a), y = key(b);
        const d = typeof x === 'string' && typeof y === 'string' && coll ? coll.compare(x, y) : (x < y ? -1 : x > y ? 1 : 0);
        return d * (asc ? 1 : -1);
      });
    }
    return rows;
  }
  function renderTable() {
    const rows = filteredRows();
    const total = doneRows().length;
    el.shownCount.textContent = rows.length === total ? T('shown.all', { n: fmt(rows.length), _count: rows.length }) : T('shown.part', { n: fmt(rows.length), total: fmt(total), _count: total });
    const h = [];
    for (const r of rows) {
      const c = r.cls, d = r.data;
      const extras = Object.entries(r.rec.extras || {}).map(([k, v]) => `${colLabel(k)}: ${v}`).join(' / ');
      const mx0 = d.mx && d.mx[0];
      const spfInc = d.spf ? d.spf.includes.slice(0, 4).join(' ') + (d.spf.includes.length > 4 ? ` +${d.spf.includes.length - 4}` : '') : (d.mxStatus === 'ok' ? T('row.spf_none') : '');
      const dm = d.dmarc ? `p=${d.dmarc.p || '?'}` : (d.mxStatus === 'ok' || d.mxStatus === 'nomx' ? T('row.dmarc_none') : '');
      const pcls = c.prospect === '?' ? 'Q' : c.prospect;
      h.push(`<tr data-i="${r.idx}">
        <td class="dom"><bdi>${esc(c.checkedDomain || r.rec.domain)}</bdi>${c.checkedDomain !== r.rec.domain ? `<small>${esc(T('row.input', { v: r.rec.domain }))}</small>` : ''}${extras ? `<small>${esc(extras)}</small>` : ''}</td>
        <td class="lab"><span class="conf ${c.confidence}" title="${esc(T('row.conf_title', { v: c.confidenceLabel }))}"></span>${esc(c.label)}${c.notes && c.notes.length ? `<small>${esc(c.notes.join(T('sep.sentence')))}</small>` : ''}</td>
        <td><span class="chip host">${esc(c.hostingLabel)}</span></td>
        <td><span class="chip p-${pcls}">${esc(c.prospectLabel)}</span></td>
        <td class="mono mx">${mx0 ? esc(mx0.host) + (d.mx.length > 1 ? ` <span class="muted">+${d.mx.length - 1}</span>` : '') : '<span class="muted">—</span>'}</td>
        <td class="mono">${esc(spfInc)}</td>
        <td class="mono">${esc(dm)}</td>
        <td><button class="exp" data-i="${r.idx}">${esc(state.expanded.has(r.idx) ? T('row.close') : T('row.details'))}</button></td>
      </tr>`);
      if (state.expanded.has(r.idx)) h.push(`<tr class="detail"><td colspan="8">${detailHtml(r)}</td></tr>`);
    }
    el.resBody.innerHTML = h.join('') || `<tr><td colspan="8" class="empty">${esc(total ? T('table.no_match') : T('table.empty'))}</td></tr>`;
    el.resBody.querySelectorAll('button.exp').forEach(b => b.addEventListener('click', () => { const i = parseInt(b.dataset.i, 10); if (state.expanded.has(i)) state.expanded.delete(i); else state.expanded.add(i); renderTable(); }));
  }
  function detailHtml(r) {
    const d = r.data, c = r.cls, s = d.signals || {};
    const mx = (d.mx || []).map(m => `<li><code>${m.pref} ${esc(m.host)}</code>${m.ip ? ` → <code>${esc(m.ip)}</code>` : ''}${m.ptr ? `${esc(T('sep.list'))}${esc(T('det.ptr'))} <code>${esc(m.ptr)}</code>` : ''}${m.asn ? `${esc(T('sep.list'))}AS${m.asn} ${esc(m.asName || '')}` : ''}</li>`).join('');
    const dl = [];
    if (d.spf) dl.push(['SPF', d.spf.raw]);
    if (d.spf && d.spf.nested && d.spf.nested.length) dl.push([T('det.spf_nested'), d.spf.nested.join(' ')]);
    dl.push(['DMARC', d.dmarc ? d.dmarc.raw : T('det.dmarc_none')]);
    if (s.deep) {
      dl.push(['google._domainkey', s.googleDkim ? T('det.google_dkim_yes') : T('det.none')]);
      dl.push(['selector1._domainkey', s.selector1 || T('det.none')]);
      dl.push(['autodiscover', s.autodiscoverCname || s.autodiscoverA || T('det.none')]);
      if (s.mailCname) dl.push(['mail.' + (c.checkedDomain || ''), s.mailCname]);
    }
    if (d.ns && d.ns.length) dl.push(['NS', d.ns.join(' ')]);
    if (d.aFallback) dl.push([T('det.a_record'), `${d.aFallback.ip}${d.aFallback.ptr ? ` (${d.aFallback.ptr})` : ''}${d.aFallback.asn ? ` AS${d.aFallback.asn} ${d.aFallback.asName || ''}` : ''}`]);
    if (d.errorDetail || d.error) dl.push([T('det.error'), d.errorDetail || d.error]);
    return `<div class="detail-grid">
      <div><b>${esc(T('det.mx'))}</b>${mx ? `<ul>${mx}</ul>` : `<div class="muted">${esc(T('det.none'))}</div>`}<b class="det-h">${esc(T('det.evidence'))}</b><ul>${c.evidence.map(e => `<li>${esc(e)}</li>`).join('')}</ul></div>
      <div><dl class="dl">${dl.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></div></div>`;
  }
  function renderAll() {
    renderSummary(doneRows());
    fillSelect(el.fHosting, hostingOptions()); fillSelect(el.fPlatform, platformOptions());
    renderTable();
  }
  [el.fText, el.fProspect, el.fHosting, el.fPlatform].forEach(x => x.addEventListener('input', renderTable));
  el.resTable.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {
    const k = th.dataset.k;
    if (state.sort.k === k) state.sort.asc = !state.sort.asc; else { state.sort.k = k; state.sort.asc = true; }
    el.resTable.querySelectorAll('th').forEach(t => t.classList.remove('sorted', 'asc'));
    th.classList.add('sorted'); if (state.sort.asc) th.classList.add('asc');
    renderTable();
  }));

  // ---- エクスポート（見出しと判定文は表示中の言語） -----------------------------
  function exportRows(rows) {
    const extraKeys = []; for (const r of rows) for (const k of Object.keys(r.rec.extras || {})) if (!extraKeys.includes(k)) extraKeys.push(k);
    const head = ['ex.input', 'ex.domain', 'ex.platform', 'ex.backend', 'ex.hosting', 'ex.prospect', 'ex.confidence', 'ex.mx', 'ex.mx_ip', 'ex.ptr', 'ex.asn', 'ex.as_name', 'ex.spf', 'ex.dmarc', 'ex.evidence'].map(k => T(k)).concat(extraKeys.map(colLabel));
    const body = rows.map(r => {
      const d = r.data, c = r.cls, m0 = d.mx && d.mx[0] || {};
      return [r.rec.input, c.checkedDomain || r.rec.domain, c.platformName, c.backendName, c.hostingLabel, c.prospectLabel, c.confidenceLabel,
        (d.mx || []).map(m => `${m.pref} ${m.host}`).join(' | '), m0.ip || '', m0.ptr || '', m0.asn || '', m0.asName || '',
        d.spf ? d.spf.raw : '', d.dmarc ? d.dmarc.raw : '', c.evidence.join(' / '), ...extraKeys.map(k => (r.rec.extras || {})[k] || '')];
    });
    return { head, body };
  }
  const csvCell = (v) => { const s = String(v == null ? '' : v); return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  function download(name, text, type) {
    const blob = new Blob([text], { type }); const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  const stamp = () => { const d = new Date(); const p = (n) => String(n).padStart(2, '0'); return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`; };
  el.csvBtn.addEventListener('click', () => {
    const { head, body } = exportRows(filteredRows());
    download(`mxscope-${stamp()}.csv`, '﻿' + [head, ...body].map(r => r.map(csvCell).join(',')).join('\r\n'), 'text/csv;charset=utf-8');
  });
  el.copyBtn.addEventListener('click', async () => {
    const { head, body } = exportRows(filteredRows());
    const tsv = [head, ...body].map(r => r.map(v => String(v == null ? '' : v).replace(/[\t\r\n]+/g, ' ')).join('\t')).join('\n');
    try { await navigator.clipboard.writeText(tsv); toast(T('toast.copied', { n: fmt(body.length), _count: body.length })); }
    catch (e) { download(`mxscope-${stamp()}.tsv`, tsv, 'text/tab-separated-values'); }
  });
  el.jsonBtn.addEventListener('click', () => download(`mxscope-${stamp()}.json`, JSON.stringify(filteredRows().map(r => ({
    input: r.rec.input,
    extras: Object.fromEntries(Object.entries(r.rec.extras || {}).map(([k, v]) => [colLabel(k), v])),
    result: r.cls, dns: r.data,
  })), null, 1), 'application/json'));
  el.clearBtn.addEventListener('click', () => { state.results = []; state.expanded.clear(); state.progress = null; el.summary.hidden = true; el.results.hidden = true; el.progress.hidden = true; lsDel('mxscope:last'); el.restoreBtn.hidden = true; });

  // ---- 前回結果の保存・復元（DNS データだけを保存し、判定文は表示時に作る） -------------
  let saved = null;
  function saveLast() {
    if (!state.results.length) return;
    const payload = JSON.stringify({ v: 2, ts: Date.now(), results: doneRows().map(r => ({ idx: r.idx, rec: r.rec, data: r.data })) });
    if (payload.length > 4_000_000) { lsDel('mxscope:last'); return; }
    if (lsSet('mxscope:last', payload)) el.restoreBtn.hidden = true;
  }
  function renderRestoreButton() {
    if (!saved) return;
    let date = ''; try { date = new Date(saved.ts).toLocaleString(i18n.locales(lang)); } catch (e) { date = new Date(saved.ts).toISOString(); }
    el.restoreBtn.textContent = T('restore.btn', { n: fmt(saved.results.length), date });
  }
  (function offerRestore() {
    const raw = lsGet('mxscope:last'); if (!raw) return;
    try { const j = JSON.parse(raw); if (j.results && j.results.length) { saved = j; el.restoreBtn.hidden = false; } } catch (e) { lsDel('mxscope:last'); }
  })();
  el.restoreBtn.addEventListener('click', () => {
    try {
      const j = saved || JSON.parse(lsGet('mxscope:last'));
      state.results = j.results.map(r => ({ idx: r.idx, rec: r.rec, data: r.data, cls: classify(r.data, lang) }));
      el.summary.hidden = false; el.results.hidden = false; renderAll(); el.restoreBtn.hidden = true;
    } catch (e) { toast(T('restore.fail')); }
  });

  // ---- リゾルバ表示 ---------------------------------------------------------
  function renderResolver() {
    const ok = state.resolver;
    el.resolverBadge.className = 'badge' + (ok === true ? ' ok' : ok === false ? ' warn' : '');
    el.resolverBadge.innerHTML = `<span class="dot"></span>${esc(ok === true ? T('dns.local') : ok === false ? T('dns.doh') : T('dns.checking'))}`;
  }
  dns.detectLocalApi().then(ok => { state.resolver = !!ok; renderResolver(); });

  // ---- 表示言語の切り替え ------------------------------------------------------
  const loading = {};
  function loadLang(code) {
    if (i18n.DICT[code]) return Promise.resolve();
    if (loading[code]) return loading[code];
    loading[code] = new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = `i18n/${code}.js?v=${VERSION}`;
      s.onload = s.onerror = () => resolve();
      document.head.appendChild(s);
    });
    return loading[code];
  }
  function detectLang() {
    const q = new URLSearchParams(location.search).get('lang');
    if (q && i18n.CODES.has(q)) return q;
    const savedLang = lsGet('mxscope:lang');
    if (savedLang && i18n.CODES.has(savedLang)) return savedLang;
    return i18n.fromNavigator(navigator.languages || [navigator.language]) || 'en';
  }
  function applyStatic() {
    const root = document.documentElement;
    root.lang = lang; root.dir = i18n.RTL.has(lang) ? 'rtl' : 'ltr';
    document.title = T('meta.title');
    const md = document.querySelector('meta[name="description"]'); if (md) md.setAttribute('content', T('meta.description'));
    document.querySelectorAll('[data-i18n]').forEach(n => { n.textContent = T(n.dataset.i18n); });
    document.querySelectorAll('[data-i18n-html]').forEach(n => { n.innerHTML = T(n.dataset.i18nHtml, { n: fmt(rules.VENDORS.length) }); });
    document.querySelectorAll('[data-i18n-ph]').forEach(n => { n.setAttribute('placeholder', T(n.dataset.i18nPh)); });
    document.querySelectorAll('[data-i18n-title]').forEach(n => { n.setAttribute('title', T(n.dataset.i18nTitle)); n.setAttribute('aria-label', T(n.dataset.i18nTitle)); });
    // 見込み度の絞り込み（値はコードのまま）
    const pv = el.fProspect.value;
    el.fProspect.innerHTML = `<option value="">${esc(T('f.prospect_all'))}</option>` + ['A', 'B', 'C', 'X', '?'].map(c => `<option value="${c}">${esc(rules.prospectLabel(c, lang))}</option>`).join('');
    el.fProspect.value = pv;
    el.fHosting.options[0].textContent = T('f.hosting_all');
    el.fPlatform.options[0].textContent = T('f.platform_all');
    const cur = i18n.LANGS.find(l => l[0] === lang);
    el.langLabel.textContent = cur ? cur[1] : lang;
    el.langLabel.lang = lang;
  }
  async function setLang(code, initial) {
    await loadLang('en');
    if (code !== 'en') await loadLang(code);
    lang = i18n.DICT[code] ? code : 'en';
    try { numFmt = new Intl.NumberFormat(i18n.locales(lang)); } catch (e) { numFmt = null; }
    if (!initial) lsSet('mxscope:lang', lang);
    try {
      const url = new URL(location.href);
      if (initial && !url.searchParams.get('lang')) { /* 初回は URL を変えない */ }
      else { url.searchParams.set('lang', lang); history.replaceState(null, '', url); }
    } catch (e) { /* file:// など */ }
    applyStatic();
    // 判定済みの結果は DNS データから判定文を作り直す（区分・見込み度の絞り込みは維持）
    if (state.results.length) {
      state.results = state.results.map(r => (r ? Object.assign({}, r, { cls: classify(r.data, lang) }) : r));
      el.fPlatform.value = '';
      renderAll();
    }
    if (state.csvInfo) renderCsvPreview();
    updateInputCount(); renderProgress(); renderResolver(); renderRestoreButton(); buildLangMenu();
  }

  function buildLangMenu() {
    el.langMenu.replaceChildren();
    for (const [code, native, english] of i18n.LANGS) {
      const b = document.createElement('button');
      b.type = 'button'; b.dataset.code = code; b.setAttribute('role', 'option'); b.setAttribute('aria-selected', String(code === lang));
      if (code === lang) b.classList.add('active');
      const nm = document.createElement('span'); nm.textContent = native; nm.lang = code; nm.dir = i18n.RTL.has(code) ? 'rtl' : 'ltr';
      const en = document.createElement('small'); en.textContent = english; en.lang = 'en';
      b.append(nm, en);
      el.langMenu.appendChild(b);
    }
  }
  // メニューはボタンの端に揃えるが、画面からはみ出す時は画面内に収める（スマホではボタンが左に回り込むため）
  function placeLangMenu() {
    const m = el.langMenu, wrap = m.parentElement;
    m.style.left = ''; m.style.right = '';
    const vw = document.documentElement.clientWidth, pad = 12;
    const wr = wrap.getBoundingClientRect(), mw = m.offsetWidth;
    let left = document.documentElement.dir === 'rtl' ? wr.left : wr.right - mw;
    left = Math.max(pad, Math.min(left, vw - pad - mw));
    m.style.left = `${Math.round(left - wr.left)}px`; m.style.right = 'auto';
  }
  function toggleLangMenu(open) {
    const want = open != null ? open : el.langMenu.hidden;
    el.langMenu.hidden = !want;
    el.langBtn.setAttribute('aria-expanded', String(want));
    if (want) { placeLangMenu(); const a = el.langMenu.querySelector('.active') || el.langMenu.querySelector('button'); if (a) a.focus({ preventScroll: true }); }
  }
  window.addEventListener('resize', () => { if (!el.langMenu.hidden) placeLangMenu(); });
  el.langBtn.addEventListener('click', (e) => { e.stopPropagation(); toggleLangMenu(); });
  el.langMenu.addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    toggleLangMenu(false); el.langBtn.focus();
    setLang(b.dataset.code);
  });
  el.langMenu.addEventListener('keydown', (e) => {
    const items = [...el.langMenu.querySelectorAll('button')];
    const i = items.indexOf(document.activeElement);
    const cols = getComputedStyle(el.langMenu).gridTemplateColumns.split(' ').length || 1;
    const move = { ArrowDown: cols, ArrowUp: -cols, ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (move != null) { e.preventDefault(); const rtl = document.documentElement.dir === 'rtl' && Math.abs(move) === 1 ? -1 : 1; const n = items[Math.min(items.length - 1, Math.max(0, i + move * rtl))]; if (n) n.focus(); }
    else if (e.key === 'Escape') { toggleLangMenu(false); el.langBtn.focus(); }
    else if (e.key === 'Home') { e.preventDefault(); items[0].focus(); }
    else if (e.key === 'End') { e.preventDefault(); items[items.length - 1].focus(); }
  });
  document.addEventListener('click', (e) => { if (!el.langMenu.hidden && !e.target.closest('.lang-wrap')) toggleLangMenu(false); });

  renderResolver();
  updateInputCount();
  setLang(detectLang(), true);
})();
