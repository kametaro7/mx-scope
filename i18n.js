/* MXスコープ — 多言語対応の土台（言語一覧・翻訳関数）
 * 辞書は i18n/<code>.js が MXC_I18N[<code>] に登録する。ブラウザでも Node でも動く。
 * 言語一覧と自動判定の順序は世界ライブカメラマップ（world-livecam-map）と揃えている。
 */
(function (root) {
  'use strict';
  const MXC = root.MXC = root.MXC || {};
  const DICT = root.MXC_I18N = root.MXC_I18N || {};

  // [コード, その言語での名前, 英語名]
  const LANGS = [
    ['en', 'English', 'English'], ['zh-CN', '简体中文', 'Chinese (Simplified)'], ['zh-TW', '繁體中文', 'Chinese (Traditional)'],
    ['es', 'Español', 'Spanish'], ['hi', 'हिन्दी', 'Hindi'], ['ru', 'Русский', 'Russian'], ['fr', 'Français', 'French'],
    ['pt', 'Português', 'Portuguese'], ['ar', 'العربية', 'Arabic'], ['ja', '日本語', 'Japanese'], ['de', 'Deutsch', 'German'],
    ['id', 'Bahasa Indonesia', 'Indonesian'], ['tr', 'Türkçe', 'Turkish'], ['it', 'Italiano', 'Italian'], ['ko', '한국어', 'Korean'],
    ['fa', 'فارسی', 'Persian'], ['bn', 'বাংলা', 'Bengali'], ['vi', 'Tiếng Việt', 'Vietnamese'], ['ur', 'اردو', 'Urdu'],
    ['th', 'ไทย', 'Thai'], ['pl', 'Polski', 'Polish'], ['mr', 'मराठी', 'Marathi'], ['te', 'తెలుగు', 'Telugu'], ['ta', 'தமிழ்', 'Tamil'],
    ['jv', 'Basa Jawa', 'Javanese'], ['nl', 'Nederlands', 'Dutch'], ['gu', 'ગુજરાતી', 'Gujarati'], ['uk', 'Українська', 'Ukrainian'],
    ['kn', 'ಕನ್ನಡ', 'Kannada'], ['ro', 'Română', 'Romanian'], ['az', 'Azərbaycanca', 'Azerbaijani'],
  ];
  const CODES = new Set(LANGS.map((l) => l[0]));
  const RTL = new Set(['ar', 'fa', 'ur']);

  const plurals = {};
  function pluralOf(lang, n) {
    try { return (plurals[lang] || (plurals[lang] = new Intl.PluralRules(locales(lang)))).select(n); } catch (e) { return n === 1 ? 'one' : 'other'; }
  }

  /** 翻訳。言語 → 英語 → 日本語 → キーの順で探す。{name} を vars で置き換える。
   *  vars._count に件数を渡すと、その言語で単数になる数の時は "<キー>.one" があればそちらを使う */
  function t(lang, key, vars) {
    const pick = (l, k) => (DICT[l] && DICT[l][k || key] != null ? DICT[l][k || key] : null);
    let s = null;
    if (vars && vars._count != null && pluralOf(lang, Number(vars._count)) === 'one') s = pick(lang, key + '.one');
    if (s == null) s = pick(lang);
    if (s == null) s = pick('en');
    if (s == null) s = pick('ja');
    if (s == null) s = key;
    if (vars) {
      if (RTL.has(lang)) {
        // 右から左の言語では、差し込むドメイン名・ブランド名などを方向の分離記号（FSI…PDI）で囲み、並び順の崩れを防ぐ。
        // "AS{asn}" "mail.{domain}" "include:{inc}" "p={p}" のように英字が直前にくっついている時は、その英字ごと囲む
        s = s.replace(/([A-Za-z0-9._:=-]*)\{(\w+)\}/g, (m, pre, k) => {
          if (vars[k] == null) return m;
          const v = String(vars[k]);
          return v || pre ? '\u2068' + pre + v + '\u2069' : '';
        });
      } else {
        s = s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] != null ? String(vars[k]) : m));
      }
    }
    return s;
  }

  /** ブラウザの言語設定から対応言語を選ぶ（無ければ null） */
  function fromNavigator(list) {
    for (const raw of list || []) {
      const low = String(raw || '').toLowerCase();
      if (!low) continue;
      if (low.startsWith('zh')) return /tw|hk|mo|hant/.test(low) ? 'zh-TW' : 'zh-CN';
      const base = low.split('-')[0];
      if (CODES.has(base)) return base;
      if (base === 'ms') return 'id';
    }
    return null;
  }

  /** Intl に渡すロケール（ジャワ語は環境によって未対応なのでインドネシア語を後ろに置く） */
  function locales(lang) { return lang === 'jv' ? ['jv', 'id', 'en'] : [lang, 'en']; }

  MXC.i18n = { LANGS, CODES, RTL, DICT, t, fromNavigator, locales };
})(typeof globalThis !== 'undefined' ? globalThis : this);
