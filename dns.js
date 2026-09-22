/* MXスコープ — DNS リゾルバ（DNS over HTTPS / ローカルAPI）とドメイン単位の収集
 * ブラウザ・Node 双方で動く（fetch が必要）。globalThis.MXC.dns を提供する。
 */
(function (root) {
  'use strict';
  const MXC = root.MXC = root.MXC || {};
  const TYPES = { A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33 };

  const state = {
    localApi: null,        // '/api/resolve' が使えるなら true
    stats: { queries: 0, cacheHits: 0, errors: 0, byProvider: {} },
    cache: new Map(),      // "TYPE:name" -> Promise<result>
    timeoutMs: 8000,
  };

  const providers = [
    { name: 'local', url: (n, t) => `./api/resolve?name=${encodeURIComponent(n)}&type=${t}`, headers: {}, enabled: () => state.localApi === true },
    { name: 'google', url: (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`, headers: {}, enabled: () => true },
    { name: 'cloudflare', url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`, headers: { accept: 'application/dns-json' }, enabled: () => true },
  ];

  async function detectLocalApi() {
    if (state.localApi !== null) return state.localApi;
    try {
      // ローカルサーバー以外（GitHub Pages・file:// など）では問い合わせない（無駄な 404 を出さない）
      if (typeof location === 'undefined' || !/^https?:$/.test(location.protocol)) { state.localApi = false; return false; }
      if (!/^(localhost|127\.0\.0\.1|\[?::1\]?|0\.0\.0\.0)$/i.test(location.hostname)) { state.localApi = false; return false; }
      const r = await fetch('./api/ping', { cache: 'no-store' });
      state.localApi = r.ok && /json/i.test(r.headers.get('content-type') || '') && (await r.json()).ok === true;
    } catch (e) { state.localApi = false; }
    return state.localApi;
  }

  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  function strip(s) { return String(s || '').trim().replace(/\.$/, '').toLowerCase(); }
  function unquoteTxt(data) {
    // "abc" "def" → abcdef（DoH は TXT を引用符付きで返す）
    const parts = [];
    const reQ = /"((?:[^"\\]|\\.)*)"/g; let m; let found = false;
    while ((m = reQ.exec(data)) !== null) { found = true; parts.push(m[1].replace(/\\(.)/g, '$1')); }
    return found ? parts.join('') : data;
  }

  async function fetchJson(p, name, type) {
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), state.timeoutMs) : null;
    try {
      const r = await fetch(p.url(name, type), { headers: p.headers, signal: ctrl ? ctrl.signal : undefined, cache: 'no-store' });
      if (r.status === 429 || r.status >= 500) { const e = new Error('HTTP ' + r.status); e.retryable = true; throw e; }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } finally { if (timer) clearTimeout(timer); }
  }

  /** 生の問い合わせ: {status, answers:[{name,type,data,ttl}]}  status: 0 NOERROR, 3 NXDOMAIN, 2 SERVFAIL... */
  function resolve(name, type) {
    const t = TYPES[type] || type;
    const key = `${t}:${strip(name)}`;
    if (state.cache.has(key)) { state.stats.cacheHits++; return state.cache.get(key); }
    const pr = (async () => {
      state.stats.queries++;
      const order = providers.filter(p => p.enabled());
      let lastErr = null;
      for (let attempt = 0; attempt < 4; attempt++) {
        const p = order[Math.min(attempt, order.length - 1)];
        try {
          const j = await fetchJson(p, strip(name), t);
          state.stats.byProvider[p.name] = (state.stats.byProvider[p.name] || 0) + 1;
          const answers = (j.Answer || []).filter(a => a.type === t || (t === TYPES.TXT && a.type === TYPES.TXT)).map(a => ({
            name: strip(a.name), type: a.type, ttl: a.TTL, data: a.type === TYPES.TXT ? unquoteTxt(a.data) : String(a.data),
          }));
          return { status: j.Status, answers, provider: p.name, raw: j };
        } catch (e) {
          lastErr = e; state.stats.errors++;
          if (attempt < 3) await sleep((e && e.retryable ? 800 : 300) * (attempt + 1));
        }
      }
      state.cache.delete(key);
      const err = new Error(`DNS 問い合わせ失敗 ${type} ${name}: ${lastErr && lastErr.message}`);
      err.cause = lastErr; throw err;
    })();
    state.cache.set(key, pr);
    return pr;
  }

  function parseMx(answers) {
    return answers.map(a => {
      const m = /^(\d+)\s+(\S*)$/.exec(a.data.trim());
      if (!m) return null;
      return { pref: parseInt(m[1], 10), host: strip(m[2]) };
    }).filter(Boolean);
  }
  function parseSpf(txts) {
    const spf = txts.find(t => /^v=spf1(\s|$)/i.test(t.trim()));
    if (!spf) return null;
    const includes = [], mechs = [], aHosts = [];
    for (const tok of spf.trim().split(/\s+/)) {
      const m = /^[+\-~?]?(include|redirect)[:=](.+)$/i.exec(tok);
      if (m) { includes.push(strip(m[2])); continue; }
      const a = /^[+\-~?]?(a|mx):([^/]+)/i.exec(tok);
      if (a) aHosts.push(strip(a[2]));
      mechs.push(tok);
    }
    return { raw: spf, includes, mechs, aHosts };
  }
  function parseDmarc(txts) {
    const d = txts.find(t => /^v=dmarc1/i.test(t.trim()));
    if (!d) return null;
    const p = (/(?:^|;)\s*p=([a-z]+)/i.exec(d) || [])[1] || '';
    return { raw: d, p: p.toLowerCase() };
  }
  function revIp(ip) { return ip.split('.').reverse().join('.'); }

  async function ipInfo(ip) {
    // PTR + Team Cymru の AS 情報（すべて DNS 経由）
    const info = { ip, ptr: '', asn: null, asName: '', asCC: '' };
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return info;
    const rev = revIp(ip);
    const [ptrR, orgR] = await Promise.allSettled([resolve(`${rev}.in-addr.arpa`, 'PTR'), resolve(`${rev}.origin.asn.cymru.com`, 'TXT')]);
    if (ptrR.status === 'fulfilled' && ptrR.value.answers[0]) info.ptr = strip(ptrR.value.answers[0].data);
    if (orgR.status === 'fulfilled' && orgR.value.answers[0]) {
      const f = orgR.value.answers[0].data.split('|').map(s => s.trim());
      const asn = parseInt((f[0] || '').split(/\s+/)[0], 10);
      if (asn) {
        info.asn = asn; info.asCC = f[2] || '';
        try {
          const nm = await resolve(`AS${asn}.asn.cymru.com`, 'TXT');
          if (nm.answers[0]) { const g = nm.answers[0].data.split('|').map(s => s.trim()); info.asName = g[4] || ''; info.asCC = info.asCC || g[1] || ''; }
        } catch (e) { /* AS名は無くても可 */ }
      }
    }
    return info;
  }

  /** 入力（URL/メール/ドメイン）→ 判定対象ドメイン。無効なら null */
  function normalizeInput(raw) {
    let s = String(raw || '').trim();
    if (!s) return null;
    s = s.replace(/^[\s"'<>`「」『』【】〈〉《》（(\[]+|[\s"'<>`「」『』【】〈〉《》）)\],;。、]+$/g, '');
    if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^\/\//.test(s)) {
      try { s = new URL(s.startsWith('//') ? 'http:' + s : s).hostname; } catch (e) { return null; }
    } else {
      s = s.split(/[\/?#]/)[0];
      s = s.replace(/:\d+$/, '');
      try { s = new URL('http://' + s).hostname; } catch (e) { return null; }
    }
    s = strip(s).replace(/^www\d*\./, '');
    if (!/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/.test(s)) return null;
    return s;
  }


  // 区切りが無い貼り付けからドメインを取り出す ---------------------------------
  // 例: "https://a.co.jp/https://b.co.jp/" や "www.a.co.jpwww.b.co.jp" のような
  // URL が連結された文字列、会社名とURLが混ざった行にも対応する。
  const FILE_EXT = new Set(['md','txt','csv','tsv','xlsx','xls','docx','doc','pptx','ppt','pdf','png','jpg','jpeg','gif','webp','svg','zip','rar','js','mjs','ts','json','html','htm','css','py','rb','go','php','sh','exe','dmg','pkg','log','tmp','bak','xml','yml','yaml','mp4','mp3','wav','mov','avi','ini','conf','lock','sql']);

  /** 文字列を「1つずつのトークン」に割る（連結された URL を切り離す） */
  function tokenize(text) {
    let s = String(text || '');
    if (!s) return [];
    s = s.replace(/[　 ]/g, ' ')                  // 全角スペース・NBSP
         .replace(/[、。，；・｜|]/g, ' ')                   // 日本語の区切り
         .replace(/[：／．]/g, (c) => ({ '：': ':', '／': '/', '．': '.' }[c]))  // 全角 : / .
         .replace(/[ａ-ｚＡ-Ｚ０-９]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xFEE0)); // 全角英数
    s = s.replace(/(.)(?=https?:\/\/)/gi, '$1\n');          // 連結された http(s):// の直前で切る
    s = s.replace(/(.)(?=mailto:)/gi, '$1\n');
    s = s.replace(/([a-z0-9\-.])(?=www\.)/gi, '$1\n');      // "…co.jpwww.…" の www. の直前で切る（"://www." は対象外）
    s = s.replace(/(\.(?:co|ne|or|ac|go|ad|ed|gr|lg)\.jp)(?=[a-z0-9])/gi, '$1\n'); // "…co.jp" の直後に文字が続く連結
    // 全角のかっこ類は区切りにしない（「（株）八天堂」のような社名を壊さないため）
    return s.split(/[\s"'<>`\\\[\]{}(),;]+/).filter(Boolean);
  }

  /** トークン1個からドメインを取り出す（取れなければ null） */
  function domainFromToken(tok) {
    const t = String(tok || '').trim();
    if (!t) return null;
    const explicit = /^[a-z][a-z0-9+.-]*:\/\//i.test(t) || t.includes('@') || /^mailto:/i.test(t);
    const d = normalizeInput(t.replace(/^mailto:/i, ''));
    if (d) return explicit || !FILE_EXT.has(d.split('.').pop()) ? d : null;
    if (explicit) return null;
    // 余計な文字が混ざったトークンから、ドメインらしい部分を拾う
    const m = t.match(/[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+/i);
    if (!m) return null;
    const cand = normalizeInput(m[0]);
    if (!cand) return null;
    const tld = cand.split('.').pop();
    if (FILE_EXT.has(tld) || /\d/.test(tld)) return null;
    return cand;
  }

  /**
   * 任意のテキストからドメインを順番に取り出す。
   * @returns {{domains: Array<{input:string, domain:string}>, rest: string[]}}
   *   rest はドメインとして解釈できなかったトークン（会社名など）
   */
  function extractDomains(text) {
    const domains = [], rest = [];
    for (const tok of tokenize(text)) {
      const d = domainFromToken(tok);
      if (d) domains.push({ input: tok, domain: d });
      else rest.push(tok);
    }
    return { domains, rest };
  }

  /**
   * ドメイン1件ぶんの DNS 情報をすべて集める。
   * opts: { deep: 'auto'|'always'|'never', maxMx: 4 }
   */
  async function lookupDomain(input, opts) {
    opts = Object.assign({ deep: 'auto', maxMx: 4 }, opts || {});
    const domain = normalizeInput(input);
    const d = { input, domain, checkedDomain: domain, mxStatus: 'error', mx: [], aFallback: null, spf: null, dmarc: null, signals: {}, error: '' };
    if (!domain) { d.error = 'ドメインとして解釈できない入力'; return d; }
    const rules = MXC.rules;
    try {
      let mxR = await resolve(domain, 'MX');
      let checked = domain;
      const reg = rules ? rules.registrableDomain(domain) : domain;
      if (mxR.status === 3 && reg !== domain) { const r2 = await resolve(reg, 'MX'); if (r2.status !== 3) { mxR = r2; checked = reg; } }
      if (mxR.status === 0 && parseMx(mxR.answers).length === 0 && reg !== domain) {
        const r2 = await resolve(reg, 'MX');
        if (r2.status === 0 && parseMx(r2.answers).length > 0) { mxR = r2; checked = reg; }
      }
      d.checkedDomain = checked;
      if (mxR.status === 3) { d.mxStatus = 'nxdomain'; return d; }
      if (mxR.status !== 0) { d.mxStatus = 'error'; d.error = `DNS 応答コード ${mxR.status}`; return d; }
      let mx = parseMx(mxR.answers).sort((a, b) => a.pref - b.pref);
      if (mx.length === 1 && (mx[0].host === '' || mx[0].host === '.')) { d.mxStatus = 'nullmx'; d.mx = []; }
      else if (mx.length === 0) d.mxStatus = 'nomx';
      else d.mxStatus = 'ok';

      // TXT (SPF / MS=) と DMARC を並行取得
      const [txtR, dmarcR] = await Promise.allSettled([resolve(checked, 'TXT'), resolve(`_dmarc.${checked}`, 'TXT')]);
      const txts = txtR.status === 'fulfilled' ? txtR.value.answers.map(a => a.data) : [];
      d.spf = parseSpf(txts);
      d.signals.msTxt = txts.some(t => /^MS=ms\d+/i.test(t.trim()));
      d.signals.gwsRecovery = txts.some(t => /^google-gws-recovery-domain-verification=/i.test(t.trim()));
      d.dmarc = dmarcR.status === 'fulfilled' ? parseDmarc(dmarcR.value.answers.map(a => a.data)) : null;
      // 未知の include を1段だけ辿る（リセラー経由の SPF を解決）
      if (d.spf) {
        d.spf.nested = [];
        const unknown = d.spf.includes.filter(i => !(rules && rules.matchSpf(i))).slice(0, 4);
        const nestedR = await Promise.allSettled(unknown.map(i => resolve(i, 'TXT')));
        for (const r of nestedR) if (r.status === 'fulfilled') { const p = parseSpf(r.value.answers.map(a => a.data)); if (p) d.spf.nested.push(...p.includes); }
      }

      if (d.mxStatus === 'nomx') {
        const aR = await resolve(checked, 'A');
        const ip = (aR.answers[0] || {}).data;
        if (ip) d.aFallback = await ipInfo(ip);
        // 関連ドメイン（example.jp ⇔ example.co.jp ⇔ example.com）に MX があればヒントとして記録
        const base = checked.replace(/\.(co\.jp|ne\.jp|or\.jp|jp|com|net)$/, '');
        if (base && base !== checked && !base.includes('.')) {
          const cands = [`${base}.co.jp`, `${base}.jp`, `${base}.com`].filter(c => c !== checked);
          const rs = await Promise.allSettled(cands.map(c => resolve(c, 'MX')));
          for (let i = 0; i < rs.length; i++) {
            const r = rs[i]; if (r.status !== 'fulfilled' || r.value.status !== 0) continue;
            const list = parseMx(r.value.answers).sort((a, b) => a.pref - b.pref).filter(m => m.host && m.host !== '.');
            if (list.length) { d.sibling = { domain: cands[i], mx: list.map(m => m.host) }; break; }
          }
        }
      }

      // MX ホストの IP / PTR / AS（署名に一致しないホストのみ深掘り。先頭は常に IP を引く）
      const hosts = mx.slice(0, opts.maxMx);
      d.mx = await Promise.all(hosts.map(async (m, idx) => {
        const rec = { pref: m.pref, host: m.host, ip: '', ptr: '', asn: null, asName: '', asCC: '' };
        const known = rules ? rules.matchMx(m.host) : null;
        if (known && idx > 0) return rec;
        try {
          const aR = await resolve(m.host, 'A');
          const ip = (aR.answers.find(a => /^\d+\.\d+\.\d+\.\d+$/.test(a.data)) || {}).data;
          if (ip) {
            rec.ip = ip;
            if (!known) Object.assign(rec, await ipInfo(ip));
          }
        } catch (e) { /* IP が引けなくても続行 */ }
        return rec;
      }));

      // 主 MX が署名に一致せず自社ドメイン内なら NS も引く（レンタルサーバーの推定材料）
      const primaryVendor = d.mx[0] && rules ? rules.matchMx(d.mx[0].host) : null;
      if (d.mx[0] && !primaryVendor && !(d.mx[0].ptr && rules && rules.matchPtr(d.mx[0].ptr))) {
        try { const nsR = await resolve(checked, 'NS'); d.ns = nsR.answers.map(a => strip(a.data)); } catch (e) { d.ns = []; }
      }
      // 詳細シグナル（DKIM / autodiscover / mail.{domain}）
      const conclusive = primaryVendor && (primaryVendor.cat === 'saas' || primaryVendor.cat === 'consumer');
      const needDeep = opts.deep === 'always' || (opts.deep === 'auto' && !conclusive);
      if (needDeep) {
        const q = await Promise.allSettled([
          resolve(`google._domainkey.${checked}`, 'TXT'),
          resolve(`selector1._domainkey.${checked}`, 'CNAME'),
          resolve(`selector2._domainkey.${checked}`, 'CNAME'),
          resolve(`autodiscover.${checked}`, 'CNAME'),
          resolve(`mail.${checked}`, 'CNAME'),
        ]);
        const val = (r) => r.status === 'fulfilled' ? r.value : null;
        const mc = val(q[4]); d.signals.mailCname = mc && mc.answers[0] ? strip(mc.answers[0].data) : '';
        const g = val(q[0]);
        d.signals.googleDkim = !!(g && g.answers.some(a => /v=dkim1|k=rsa|p=/i.test(a.data)));
        const s1 = val(q[1]), s2 = val(q[2]), ad = val(q[3]);
        d.signals.selector1 = s1 && s1.answers[0] ? strip(s1.answers[0].data) : '';
        d.signals.selector2 = s2 && s2.answers[0] ? strip(s2.answers[0].data) : '';
        d.signals.autodiscoverCname = ad && ad.answers[0] ? strip(ad.answers[0].data) : '';
        if (!d.signals.autodiscoverCname && ad && ad.status === 0) {
          try { const aa = await resolve(`autodiscover.${checked}`, 'A'); d.signals.autodiscoverA = (aa.answers[0] || {}).data || ''; } catch (e) { /* なし */ }
        }
        d.signals.deep = true;
      }
      return d;
    } catch (e) {
      d.mxStatus = 'error'; d.error = e.message || String(e); return d;
    }
  }

  MXC.dns = { resolve, lookupDomain, normalizeInput, extractDomains, tokenize, domainFromToken, ipInfo, detectLocalApi, state, TYPES, parseSpf, parseMx };
})(typeof globalThis !== 'undefined' ? globalThis : this);
