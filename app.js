/* MXスコープ — UI（入力の解釈・並列判定・集計・表・エクスポート） */
(function () {
  'use strict';
  const { rules, dns, classify } = globalThis.MXC;
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
    resolverBadge: $('resolverBadge'), toast: $('toast'), vendorCount: $('vendorCount'),
  };
  const state = { mode: 'paste', csvRecords: null, csvInfo: null, results: [], running: false, cancel: false, sort: { k: null, asc: true }, expanded: new Set() };
  const doneRows = () => state.results.filter(Boolean);
  el.vendorCount.textContent = String(rules.VENDORS.length);

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
  function splitLine(line) {
    if (line.includes('\t')) return line.split('\t');
    if (line.includes(',')) return line.split(',');
    if (line.includes(';')) return line.split(';');
    return line.split(/\s+/);
  }
  function parsePaste(text) {
    const recs = []; const seen = new Set(); let invalid = 0, dup = 0;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim(); if (!line) continue;
      const cells = splitLine(line).map(c => c.trim()).filter(Boolean);
      let domain = null, pick = -1;
      for (let i = 0; i < cells.length; i++) { const d = dns.normalizeInput(cells[i]); if (d) { domain = d; pick = i; break; } }
      if (!domain) { invalid++; continue; }
      if (seen.has(domain)) { dup++; continue; }
      seen.add(domain);
      const extras = {};
      const others = cells.filter((c, i) => i !== pick);
      if (others.length) extras['入力行の他の項目'] = others.join(' / ');
      recs.push({ input: cells[pick], domain, extras });
    }
    return { recs, invalid, dup };
  }
  function decodeBytes(buf) {
    const u8 = new Uint8Array(buf);
    const hasBom = u8.length >= 3 && u8[0] === 0xEF && u8[1] === 0xBB && u8[2] === 0xBF;
    try { return { text: new TextDecoder('utf-8', { fatal: true }).decode(hasBom ? u8.subarray(3) : u8), enc: hasBom ? 'UTF-8 (BOM)' : 'UTF-8' }; }
    catch (e) { /* Shift_JIS を試す */ }
    try { return { text: new TextDecoder('shift_jis').decode(u8), enc: 'Shift_JIS' }; }
    catch (e) { return { text: new TextDecoder('utf-8').decode(u8), enc: 'UTF-8 (不正なバイトを置換)' }; }
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
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0][1] > 0 ? Object.entries(c).sort((a, b) => b[1] - a[1])[0][0] : ',';
  }
  function analyzeCsv(text) {
    const delim = detectDelim(text);
    const rows = parseCsv(text, delim);
    if (!rows.length) return null;
    const width = Math.max(...rows.map(r => r.length));
    const validCount = new Array(width).fill(0);
    for (const r of rows) for (let i = 0; i < width; i++) if (dns.normalizeInput(r[i] || '')) validCount[i]++;
    const firstValid = rows[0].some(c => dns.normalizeInput(c));
    const hasHeader = !firstValid && rows.length > 1;
    const header = hasHeader ? rows[0].map((h, i) => (h || '').trim() || `列${i + 1}`) : rows[0].map((_, i) => `列${i + 1}`);
    let col = validCount.indexOf(Math.max(...validCount));
    if (hasHeader) {
      const pref = header.findIndex(h => /url|ドメイン|domain|メール|mail|サイト|hp|ホームページ|web/i.test(h));
      if (pref >= 0 && validCount[pref] > 0 && validCount[pref] >= validCount[col] * 0.6) col = pref;
    }
    return { rows, hasHeader, header, col, validCount, delim, width };
  }
  function csvToRecords(info) {
    const body = info.hasHeader ? info.rows.slice(1) : info.rows;
    const recs = []; let invalid = 0;
    for (const r of body) {
      const cellv = (r[info.col] || '').trim();
      const domain = dns.normalizeInput(cellv);
      if (!domain) { invalid++; continue; }
      const extras = {};
      info.header.forEach((h, i) => { if (i !== info.col && (r[i] || '').trim() !== '') extras[h] = (r[i] || '').trim(); });
      recs.push({ input: cellv, domain, extras });
    }
    return { recs, invalid, dup: 0 };
  }
  function renderCsvPreview() {
    const info = state.csvInfo; if (!info) { el.csvPreview.hidden = true; return; }
    const body = (info.hasHeader ? info.rows.slice(1) : info.rows).slice(0, 5);
    let h = `<div>${esc(state.csvName)} — ${info.rows.length - (info.hasHeader ? 1 : 0)} 行、${info.width} 列（${esc(state.csvEnc)}）。ドメイン列: <select id="csvCol">` +
      info.header.map((x, i) => `<option value="${i}" ${i === info.col ? 'selected' : ''}>${esc(x)}（有効 ${info.validCount[i]}）</option>`).join('') + `</select></div>`;
    h += '<table><thead><tr>' + info.header.map((x, i) => `<th class="${i === info.col ? 'pick' : ''}">${esc(x)}</th>`).join('') + '</tr></thead><tbody>';
    for (const r of body) h += '<tr>' + info.header.map((_, i) => `<td>${esc((r[i] || '').slice(0, 40))}</td>`).join('') + '</tr>';
    h += '</tbody></table>';
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
    const parts = [`${r.recs.length} 件`];
    if (r.dup) parts.push(`重複 ${r.dup}`);
    if (r.invalid) parts.push(`解釈不能 ${r.invalid}`);
    el.inputCount.textContent = r.recs.length || r.invalid ? parts.join('、') : '';
    el.runBtn.disabled = state.running || r.recs.length === 0;
  }
  el.inputText.addEventListener('input', updateInputCount);

  // ---- 実行 ----------------------------------------------------------------
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
      el.progressBar.style.width = `${(done / recs.length) * 100}%`;
      const sec = (performance.now() - t0) / 1000;
      const rate = done / Math.max(sec, 0.001);
      const eta = rate > 0 ? Math.round((recs.length - done) / rate) : 0;
      el.progressText.textContent = `${done} / ${recs.length}（${sec.toFixed(0)} 秒経過${done < recs.length ? `、残り約 ${eta} 秒` : ''}）`;
    };
    const painter = setInterval(() => {
      if (dirty) { dirty = false; if (recs.length <= 400) renderAll(); else { renderSummary(doneRows()); el.shownCount.textContent = `${done} 件（判定中…）`; } }
      tick();
    }, 400);
    const worker = async () => {
      while (!state.cancel) {
        const i = next++; if (i >= recs.length) return;
        const rec = recs[i];
        let data, cls;
        try { data = await dns.lookupDomain(rec.input, { deep }); cls = classify(data); }
        catch (e) { data = { input: rec.input, domain: rec.domain, mxStatus: 'error', mx: [], error: String(e && e.message || e), signals: {} }; cls = classify(data); }
        state.results[i] = { idx: i, rec, data: slim(data), cls };
        done++; dirty = true;
      }
    };
    await Promise.all(Array.from({ length: Math.min(conc, recs.length) }, worker));
    clearInterval(painter);
    state.results = state.results.filter(Boolean);
    state.running = false; el.cancelBtn.hidden = true; el.runBtn.disabled = false;
    renderAll(); tick();
    const st = dns.state.stats;
    el.progressText.textContent += ` — DNS 問い合わせ ${st.queries} 回（キャッシュ ${st.cacheHits}、失敗 ${st.errors}）` + (state.cancel ? ' ※中止' : '');
    saveLast();
  }
  function slim(d) {
    return { input: d.input, domain: d.domain, checkedDomain: d.checkedDomain, mxStatus: d.mxStatus, mx: d.mx || [], aFallback: d.aFallback || null,
      spf: d.spf ? { raw: d.spf.raw, includes: d.spf.includes, nested: d.spf.nested || [], aHosts: d.spf.aHosts || [] } : null, dmarc: d.dmarc || null, signals: d.signals || {}, ns: d.ns || [], error: d.error || '' };
  }
  el.runBtn.addEventListener('click', run);
  el.cancelBtn.addEventListener('click', () => { state.cancel = true; });

  // ---- 集計・表示 -----------------------------------------------------------
  function effectivePlatform(cls) {
    // 基盤の内訳用: ゲートウェイ/リレー配下で裏側が分かる場合は裏側を数える
    if (cls.backend && cls.platform && (cls.platform.cat === 'gateway' || cls.platform.cat === 'relay' || /^リレー経由/.test(cls.platform.name))) return cls.backend.name;
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
    el.tTotal.textContent = rows.length; el.tA.textContent = c.A; el.tB.textContent = c.B; el.tG.textContent = c.G; el.tC.textContent = c.C;
    el.tSub.textContent = state.running ? '（判定中…）' : '';
    const counts = new Map();
    for (const r of rows) { const k = effectivePlatform(r.cls); counts.set(k, (counts.get(k) || 0) + 1); }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const top = sorted.slice(0, 14); const rest = sorted.slice(14).reduce((s, x) => s + x[1], 0);
    const max = Math.max(1, ...top.map(x => x[1]));
    let h = '';
    for (const [name, n] of top) h += `<div class="r" data-p="${esc(name)}" title="クリックで絞り込み"><span class="n">${esc(name)}</span><span class="b"><i style="width:${(n / max) * 100}%"></i></span><span class="c">${n}</span></div>`;
    if (rest) h += `<div class="r"><span class="n">その他 (${sorted.length - 14} 種)</span><span class="b"><i style="width:${(rest / max) * 100}%"></i></span><span class="c">${rest}</span></div>`;
    el.bars.innerHTML = h || '<span class="muted">まだ結果がありません</span>';
    el.bars.querySelectorAll('.r[data-p]').forEach(r => r.addEventListener('click', () => { fillSelect(el.fPlatform, platformOptions(), r.dataset.p); el.fPlatform.value = r.dataset.p; renderTable(); }));
  }
  function platformOptions() {
    const counts = new Map();
    for (const r of doneRows()) { const k = effectivePlatform(r.cls); counts.set(k, (counts.get(k) || 0) + 1); }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }
  function hostingOptions() {
    const counts = new Map();
    for (const r of doneRows()) { const k = rules.HOSTING_JA[r.cls.hosting] || r.cls.hostingLabel; counts.set(k, (counts.get(k) || 0) + 1); }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }
  function fillSelect(sel, opts, keep) {
    const cur = keep != null ? keep : sel.value;
    const first = sel.options[0].outerHTML;
    sel.innerHTML = first + opts.map(([k, n]) => `<option value="${esc(k)}">${esc(k)} (${n})</option>`).join('');
    sel.value = [...sel.options].some(o => o.value === cur) ? cur : '';
  }
  function filteredRows() {
    const q = el.fText.value.trim().toLowerCase();
    const fp = el.fProspect.value, fh = el.fHosting.value, fpl = el.fPlatform.value;
    const all = doneRows();
    let rows = all.filter(r => {
      const c = r.cls;
      if (fp && c.prospect !== fp) return false;
      if (fh && (rules.HOSTING_JA[c.hosting] || c.hostingLabel) !== fh) return false;
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
      rows = rows.slice().sort((a, b) => { const x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * (asc ? 1 : -1); });
    }
    return rows;
  }
  function renderTable() {
    const rows = filteredRows();
    const total = doneRows().length;
    el.shownCount.textContent = rows.length === total ? `${rows.length} 件` : `${rows.length} / ${total} 件`;
    const h = [];
    for (const r of rows) {
      const c = r.cls, d = r.data;
      const extras = Object.entries(r.rec.extras || {}).map(([k, v]) => `${k}: ${v}`).join(' / ');
      const mx0 = d.mx && d.mx[0];
      const spfInc = d.spf ? d.spf.includes.slice(0, 4).join(' ') + (d.spf.includes.length > 4 ? ` +${d.spf.includes.length - 4}` : '') : (d.mxStatus === 'ok' ? '（なし）' : '');
      const dm = d.dmarc ? `p=${d.dmarc.p || '?'}` : (d.mxStatus === 'ok' || d.mxStatus === 'nomx' ? '未設定' : '');
      const pcls = c.prospect === '?' ? 'Q' : c.prospect;
      h.push(`<tr data-i="${r.idx}">
        <td class="dom">${esc(c.checkedDomain || r.rec.domain)}${c.checkedDomain !== r.rec.domain ? `<small>入力: ${esc(r.rec.domain)}</small>` : ''}${extras ? `<small>${esc(extras)}</small>` : ''}</td>
        <td class="lab"><span class="conf ${c.confidence}" title="信頼度 ${c.confidence}"></span>${esc(c.label)}${c.notes && c.notes.length ? `<small>${esc(c.notes.join('。'))}</small>` : ''}</td>
        <td><span class="chip host">${esc(c.hostingLabel)}</span></td>
        <td><span class="chip p-${pcls}">${esc(c.prospectLabel)}</span></td>
        <td class="mono mx">${mx0 ? esc(mx0.host) + (d.mx.length > 1 ? ` <span class="muted">+${d.mx.length - 1}</span>` : '') : '<span class="muted">—</span>'}</td>
        <td class="mono">${esc(spfInc)}</td>
        <td class="mono">${esc(dm)}</td>
        <td><button class="exp" data-i="${r.idx}">${state.expanded.has(r.idx) ? '閉じる' : '詳細'}</button></td>
      </tr>`);
      if (state.expanded.has(r.idx)) h.push(`<tr class="detail"><td colspan="8">${detailHtml(r)}</td></tr>`);
    }
    el.resBody.innerHTML = h.join('') || `<tr><td colspan="8" class="empty">${total ? '条件に合う行がありません' : '判定結果はここに表示されます'}</td></tr>`;
    el.resBody.querySelectorAll('button.exp').forEach(b => b.addEventListener('click', () => { const i = parseInt(b.dataset.i, 10); if (state.expanded.has(i)) state.expanded.delete(i); else state.expanded.add(i); renderTable(); }));
  }
  function detailHtml(r) {
    const d = r.data, c = r.cls, s = d.signals || {};
    const mx = (d.mx || []).map(m => `<li><code>${m.pref} ${esc(m.host)}</code>${m.ip ? ` → ${esc(m.ip)}` : ''}${m.ptr ? `、逆引き <code>${esc(m.ptr)}</code>` : ''}${m.asn ? `、AS${m.asn} ${esc(m.asName || '')}${m.asCC ? ` (${esc(m.asCC)})` : ''}` : ''}</li>`).join('');
    const dl = [];
    if (d.spf) dl.push(['SPF', d.spf.raw]);
    if (d.spf && d.spf.nested && d.spf.nested.length) dl.push(['SPF 入れ子', d.spf.nested.join(' ')]);
    dl.push(['DMARC', d.dmarc ? d.dmarc.raw : '（未設定）']);
    if (s.deep) {
      dl.push(['google._domainkey', s.googleDkim ? 'あり（Google Workspace の DKIM）' : 'なし']);
      dl.push(['selector1._domainkey', s.selector1 || 'なし']);
      dl.push(['autodiscover', s.autodiscoverCname || s.autodiscoverA || 'なし']);
      if (s.mailCname) dl.push(['mail.' + (c.checkedDomain || ''), s.mailCname]);
    }
    if (d.ns && d.ns.length) dl.push(['NS', d.ns.join(' ')]);
    if (d.aFallback) dl.push(['A レコード', `${d.aFallback.ip}${d.aFallback.ptr ? ` (${d.aFallback.ptr})` : ''}${d.aFallback.asn ? ` AS${d.aFallback.asn} ${d.aFallback.asName || ''}` : ''}`]);
    if (d.error) dl.push(['エラー', d.error]);
    return `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:8px 24px">
      <div><b>MX レコード</b>${mx ? `<ul>${mx}</ul>` : '<div class="muted">なし</div>'}<b style="display:block;margin-top:8px">根拠</b><ul>${c.evidence.map(e => `<li>${esc(e)}</li>`).join('')}</ul></div>
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

  // ---- エクスポート ---------------------------------------------------------
  function exportRows(rows) {
    const extraKeys = []; for (const r of rows) for (const k of Object.keys(r.rec.extras || {})) if (!extraKeys.includes(k)) extraKeys.push(k);
    const head = ['入力', '判定ドメイン', '判定（メール基盤）', '裏側の基盤', '区分', '見込み度', '信頼度', 'MX レコード', 'MX の IP', '逆引き (PTR)', 'AS 番号', 'AS 名', 'SPF', 'DMARC', '根拠', ...extraKeys];
    const body = rows.map(r => {
      const d = r.data, c = r.cls, m0 = d.mx && d.mx[0] || {};
      return [r.rec.input, c.checkedDomain || r.rec.domain, c.platformName, c.backendName, c.hostingLabel, c.prospectLabel, c.confidence,
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
    try { await navigator.clipboard.writeText(tsv); toast(`${body.length} 行をコピーしました（Excel / スプレッドシートに貼り付け可）`); }
    catch (e) { download(`mxscope-${stamp()}.tsv`, tsv, 'text/tab-separated-values'); }
  });
  el.jsonBtn.addEventListener('click', () => download(`mxscope-${stamp()}.json`, JSON.stringify(filteredRows().map(r => ({ input: r.rec.input, extras: r.rec.extras, result: r.cls, dns: r.data })), null, 1), 'application/json'));
  el.clearBtn.addEventListener('click', () => { state.results = []; state.expanded.clear(); el.summary.hidden = true; el.results.hidden = true; el.progress.hidden = true; lsDel('mxscope:last'); el.restoreBtn.hidden = true; });

  // ---- 前回結果の保存・復元 -------------------------------------------------
  function saveLast() {
    if (!state.results.length) return;
    const payload = JSON.stringify({ ts: Date.now(), results: doneRows() });
    if (payload.length > 4_000_000) { lsDel('mxscope:last'); return; }
    if (lsSet('mxscope:last', payload)) el.restoreBtn.hidden = true;
  }
  (function offerRestore() {
    const raw = lsGet('mxscope:last'); if (!raw) return;
    try { const j = JSON.parse(raw); if (j.results && j.results.length) { el.restoreBtn.hidden = false; el.restoreBtn.textContent = `前回の結果を復元（${j.results.length} 件・${new Date(j.ts).toLocaleString('ja-JP')}）`; } } catch (e) { lsDel('mxscope:last'); }
  })();
  el.restoreBtn.addEventListener('click', () => {
    try { const j = JSON.parse(lsGet('mxscope:last')); state.results = j.results; el.summary.hidden = false; el.results.hidden = false; renderAll(); el.restoreBtn.hidden = true; } catch (e) { toast('復元できませんでした'); }
  });

  // ---- リゾルバ検出 ---------------------------------------------------------
  dns.detectLocalApi().then(ok => {
    el.resolverBadge.className = 'badge ' + (ok ? 'ok' : 'warn');
    el.resolverBadge.innerHTML = `<span class="dot"></span>DNS: ${ok ? 'ローカル (Node リゾルバ・高速)' : 'DNS over HTTPS (Google / Cloudflare)'}`;
  });
  updateInputCount();
})();
