/* MXスコープ — 判定ルール（ベンダー署名DB + 分類ロジック）
 * ブラウザでも Node でも動く純粋関数群。globalThis.MXC.rules / MXC.classify を提供する。
 */
(function (root) {
  'use strict';
  const MXC = root.MXC = root.MXC || {};

  // ---- 区分（hosting type）------------------------------------------------
  // saas: クラウドSaaS（グループウェア）, hosting: レンタルサーバー/ホスティング,
  // gateway: メールセキュリティゲートウェイ, isp: ISPメール, iaas: IaaS上の自社運用,
  // relay: 転送/配信サービス, consumer: 個人向け, onprem: オンプレ, unknown
  const HOSTING_JA = {
    saas: 'クラウド (SaaS)',
    hosting: 'クラウド (レンタルサーバー)',
    gateway: 'ゲートウェイ経由',
    isp: 'ISPメール',
    iaas: 'IaaS上で自社運用',
    relay: '転送・配信サービス',
    consumer: '個人向けメール',
    onprem: 'オンプレ (自社運用)',
    onprem_maybe: 'オンプレの可能性',
    none: 'メール未使用',
    unknown: '不明',
  };

  // 見込み度: A=◎有望, B=○競合SaaS(リプレース提案), C=△要確認, X=✕対象外, ?=不明
  const PROSPECT_JA = {
    A: { mark: '◎', label: '有望', desc: 'レンタルサーバー／ISP／自社運用メール。Google Workspace への移行提案が刺さりやすい' },
    B: { mark: '○', label: '競合SaaS', desc: '他社クラウド利用中。リプレース提案の対象' },
    C: { mark: '△', label: '要確認', desc: 'ゲートウェイ配下などで裏側の基盤が読み取れない' },
    X: { mark: '✕', label: '対象外', desc: 'すでに Google Workspace、またはメール未使用' },
    '?': { mark: '?', label: '不明', desc: '判定材料が足りない' },
  };

  // ---- ベンダー署名DB -------------------------------------------------------
  // mx / ptr: MXホスト名（小文字・末尾ドット無し）に対する JS 正規表現ソース
  // spf: SPF の include: / redirect= に現れるホストの正規表現ソース
  // dkim: {sel, kind:'txt'|'cname', re?} — セレクタの存在/CNAME先で判定
  // asn: そのベンダーが保有する AS 番号（自社ホスト名に MX を向けている顧客を PTR/AS から拾う）
  // prospect: 見込み度、cat: 区分
  const VENDORS = [
    // ---------- グローバル SaaS ----------
    { id: 'google_workspace', name: 'Google Workspace', cat: 'saas', prospect: 'X',
      mx: ['(^|\\.)aspmx\\.l\\.google\\.com$', '(^|\\.)aspmx\\d*\\.googlemail\\.com$', '^smtp\\.google\\.com$'],
      spf: ['^_spf\\.google\\.com$', '^_netblocks\\d*\\.google\\.com$'],
      dkim: [{ sel: 'google', kind: 'txt' }],
      signals: [{ type: 'CNAME', name: 'mail.{domain}', re: '^ghs\\.(googlehosted|google)\\.com$', meaning: 'Google Workspace のカスタム URL (mail.example.com)' },
                { type: 'TXT', name: '{domain}', re: '^google-gws-recovery-domain-verification=', meaning: 'Google Workspace テナントの復旧用ドメイン確認' }],
      asn: [15169] },
    { id: 'gmail_consumer', name: 'Gmail (個人向け)', cat: 'consumer', prospect: 'X',
      mx: ['(^|\\.)gmail-smtp-in\\.l\\.google\\.com$'] },
    { id: 'google_domains_forwarding', name: 'Google Domains メール転送', cat: 'relay', prospect: 'C',
      mx: ['(^|\\.)gmr-smtp-in\\.l\\.google\\.com$'] },
    { id: 'microsoft_365', name: 'Microsoft 365 (Exchange Online)', cat: 'saas', prospect: 'B',
      mx: ['(^|\\.)mail\\.protection\\.outlook\\.com$', '(^|\\.)mx\\.microsoft$', '(^|\\.)mail\\.eo\\.outlook\\.com$', '(^|\\.)mail\\.protection\\.office365\\.us$', '(^|\\.)mail\\.protection\\.partner\\.outlook\\.cn$', '(^|\\.)mail\\.protection\\.outlook\\.de$'],
      spf: ['^spf\\.protection\\.outlook\\.com$', '^spf\\.protection\\.outlook\\.de$', '^spf\\.protection\\.office365\\.us$'],
      dkim: [{ sel: 'selector1', kind: 'cname', re: '\\.onmicrosoft\\.com$' }, { sel: 'selector2', kind: 'cname', re: '\\.onmicrosoft\\.com$' }],
      signals: [{ type: 'CNAME', name: 'autodiscover.{domain}', re: '^autodiscover\\.outlook\\.com$', meaning: 'Exchange Online の autodiscover' },
                { type: 'TXT', name: '{domain}', re: '^MS=ms\\d+', meaning: 'Microsoft 365 ドメイン所有確認' }],
      asn: [8075] },
    { id: 'outlook_consumer', name: 'Outlook.com (個人向け)', cat: 'consumer', prospect: 'X',
      mx: ['(^|\\.)olc\\.protection\\.outlook\\.com$'] },
    { id: 'zoho_mail', name: 'Zoho Mail', cat: 'saas', prospect: 'B',
      mx: ['^mx\\d*\\.zoho\\.(com|jp|eu|in|com\\.au|com\\.cn|sa|ca|uk)$', '^mx\\d*\\.zohomail\\.(com|jp|eu|in|com\\.au|cn|sa|ca|uk)$'],
      spf: ['^(one\\.|spf\\.)?zoho\\.(com|jp|eu|in|com\\.au|com\\.cn|sa|ca|uk)$', '^(spf\\.)?zohomail(360)?\\.(com|jp|eu|in|com\\.au|cn|sa|ca|uk)$'] },
    // ---------- 日本の SaaS ----------
    { id: 'line_works', name: 'LINE WORKS', cat: 'saas', prospect: 'B',
      mx: ['^(jp|kr)\\d+-aspmx\\d+\\.worksmobile\\.com$', '(^|\\.)worksmobile\\.com$', '(^|\\.)worksmobile\\.jp$'],
      spf: ['(^|\\.)worksmobile\\.com$'],
      asn: [23576], dkim: [] },
    { id: 'cybermail', name: 'CYBERMAIL Σ (サイバーソリューションズ)', cat: 'saas', prospect: 'B',
      mx: ['(^|\\.)cybermail\\.jp$', '(^|\\.)cybermail\\.ne\\.jp$', '^mg\\d*\\.cybersolutions\\.co\\.jp$', '(^|\\.)mailgates\\.jp$', '(^|\\.)mailbase\\.jp$'],
      spf: ['(^|\\.)cybermail\\.jp$', '^spf\\.cybersolutions\\.co\\.jp$'], ptr: ['^mg[a-z0-9]*\\.cybermail\\.jp$', '^mg\\d*\\.cybersolutions\\.co\\.jp$'] },
    { id: 'hennge', name: 'HENNGE One (メールセキュリティ)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)hdems\\.com$', '(^|\\.)hdemail\\.jp$', '(^|\\.)archive\\.hennge\\.com$', '(^|\\.)smtps\\.jp$'],
      spf: ['(^|\\.)hdems\\.com$', '(^|\\.)hdemail\\.jp$'], ptr: ['\\.hdems\\.com$'] },
    { id: 'iij_secure_mx', name: 'IIJ セキュアMXサービス', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)securemx\\.jp$', '(^|\\.)omgi\\.iij\\.ad\\.jp$', '(^|\\.)mx\\.iij\\.ad\\.jp$'],
      spf: ['(^|\\.)securemx\\.jp$'], ptr: ['\\.securemx\\.jp$'] },
    // ---------- 日本のレンタルサーバー ----------
    { id: 'sakura_vps', name: 'さくらのVPS/クラウド/専用サーバ (自社運用)', cat: 'iaas', prospect: 'A',
      mx: ['(^|\\.)vs\\.sakura\\.ne\\.jp$', '^www\\d+[a-z]{1,2}\\.sakura\\.ne\\.jp$'],
      ptr: ['\\.vs\\.sakura\\.ne\\.jp$', '^www\\d+[a-z]{1,2}\\.sakura\\.ne\\.jp$'] },
    { id: 'sakura', name: 'さくらのレンタルサーバ / メールボックス', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)sakura\\.ne\\.jp$'],
      spf: ['(^|\\.)sakura\\.ne\\.jp$'],
      ptr: ['^www\\d+\\.sakura\\.ne\\.jp$', '\\.sakura\\.ne\\.jp$'],
      ns: ['^ns[12]\\.dns\\.ne\\.jp$'],
      asn: [7684, 9370, 9371] },
    { id: 'xserver_vps', name: 'Xserver VPS (自社運用)', cat: 'iaas', prospect: 'A',
      mx: ['(^|\\.)static\\.xvps\\.ne\\.jp$'], ptr: ['\\.static\\.xvps\\.ne\\.jp$'] },
    { id: 'xserver_business', name: 'Xserverビジネス', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)xbiz\\.ne\\.jp$'], spf: ['(^|\\.)xbiz\\.ne\\.jp$'], ptr: ['\\.xbiz\\.ne\\.jp$'], ns: ['^ns[1-5]\\.xbiz\\.ne\\.jp$'] },
    { id: 'xserver', name: 'エックスサーバー (Xserver)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)xserver\\.jp$', '(^|\\.)xsrv\\.jp$', '(^|\\.)sixcore\\.ne\\.jp$', '(^|\\.)wpx\\.ne\\.jp$', '(^|\\.)wpx\\.jp$', '(^|\\.)xserver\\.ne\\.jp$'],
      spf: ['(^|\\.)xserver\\.jp$', '(^|\\.)sixcore\\.ne\\.jp$', '(^|\\.)wpx\\.ne\\.jp$'],
      ptr: ['\\.xserver\\.jp$', '\\.sixcore\\.ne\\.jp$', '\\.xsrv\\.jp$', '\\.wpx\\.ne\\.jp$'],
      ns: ['^ns[1-5]\\.xserver\\.jp$', '^ns[1-5]\\.(wpx|sixcore)\\.ne\\.jp$'],
      asn: [131965] },
    { id: 'lolipop', name: 'ロリポップ！ (GMOペパボ)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)lolipop\\.jp$'], spf: ['(^|\\.)lolipop\\.jp$'], ptr: ['\\.lolipop\\.jp$'], ns: ['^uns0[12]\\.lolipop\\.jp$', '^dns0[12]\\.chicappa\\.jp$'] },
    { id: 'heteml', name: 'ヘテムル (GMOペパボ)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)heteml\\.jp$'], spf: ['(^|\\.)heteml\\.jp$'], ptr: ['\\.heteml\\.jp$'], ns: ['^dns[01]\\.heteml\\.jp$'] },
    { id: 'muumuu', name: 'ムームーメール (GMOペパボ)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)muumuu-mail\\.com$', '(^|\\.)muumuu-domain\\.com$'], spf: ['(^|\\.)muumuu-mail\\.com$'] },
    { id: 'onamae', name: 'お名前.com (お名前メール/レンタルサーバー)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)gmoserver\\.jp$', '(^|\\.)onamae\\.ne\\.jp$'],
      spf: ['(^|\\.)gmoserver\\.jp$', '(^|\\.)onamae\\.ne\\.jp$', '^_spf\\.onamae\\.com$'], ptr: ['\\.gmoserver\\.jp$', '\\.onamae\\.ne\\.jp$'], ns: ['^(dns0[12]|ns-rs[12])\\.gmoserver\\.jp$'] },
    { id: 'conoha_vps', name: 'ConoHa VPS (自社運用)', cat: 'iaas', prospect: 'A',
      mx: ['(^|\\.)static\\.cnode\\.io$'], ptr: ['\\.static\\.cnode\\.io$'] },
    { id: 'conoha', name: 'ConoHa WING (GMO)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)conoha\\.ne\\.jp$', '(^|\\.)conohawing\\.com$'],
      spf: ['(^|\\.)conoha\\.ne\\.jp$'], ptr: ['\\.conoha\\.ne\\.jp$', '\\.conohawing\\.com$'], ns: ['^ns-a\\d\\.conoha\\.io$'] },
    { id: 'wadax', name: 'WADAX', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)wadax-sv\\.(jp|com)$', '(^|\\.)anshin-sv\\.jp$', '(^|\\.)wadax\\.ne\\.jp$'], spf: ['(^|\\.)wadax-sv\\.(jp|com)$', '(^|\\.)anshin-sv\\.jp$', '(^|\\.)wadax\\.ne\\.jp$'], ptr: ['\\.wadax-sv\\.(jp|com)$', '\\.anshin-sv\\.jp$', '\\.wadax\\.ne\\.jp$'], ns: ['\\.(wadax-sv|anshin-sv)\\.jp$'], asn: [131921] },
    { id: 'gmo_cloud', name: 'GMOクラウド共用 (iCLUSTA+/旧ラピッドサイト)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)hmk-temp\\.com$', '(^|\\.)iclusta\\.com$', '(^|\\.)rapidsite\\.jp$'], spf: ['(^|\\.)iclusta\\.com$', '(^|\\.)rapidsite\\.jp$'],
      ptr: ['\\.hmk-temp\\.com$', '\\.iclusta\\.com$', '\\.rapidsite\\.jp$'], ns: ['^ns2?\\.namedserver\\.net$'], asn: [131921] },
    { id: 'speever', name: 'スピーバー (Speever)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)domainserver\\.ne\\.jp$', '(^|\\.)hosting-srv\\.net$', '(^|\\.)speever\\.(jp|net)$'], spf: ['(^|\\.)domainserver\\.ne\\.jp$'],
      ptr: ['\\.domainserver\\.ne\\.jp$', '\\.ride\\.ne\\.jp$'], ns: ['^ns0[12]\\.domainserver\\.ne\\.jp$'] },
    { id: 'nospamcloud', name: '使えるねっと nospamcloud (迷惑メールGW)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)nospamcloud\\.com$'], spf: ['(^|\\.)nospamcloud\\.com$'], asn: [63997] },
    { id: 'iij_xsp_mail', name: 'IIJ xSP/メールアウトソーシング (ISP向け基盤)', cat: 'isp', prospect: 'A',
      mx: ['(^|\\.)xspmail\\.jp$', '(^|\\.)mose-mail\\.jp$'] },
    { id: 'freebit_cloud_mail', name: 'フリービット クラウドメール (ISP向け基盤)', cat: 'isp', prospect: 'A',
      mx: ['(^|\\.)cloud-mail\\.jp$'] },
    { id: 'webarena', name: 'NTTPC WebARENA (SuiteX/メールホスティング)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)mailsecure\\.jp$', '(^|\\.)arena\\.ne\\.jp$', '(^|\\.)webarena\\.ne\\.jp$', '(^|\\.)suitepro\\.jp$', '(^|\\.)etius\\.jp$'],
      spf: ['(^|\\.)etius\\.jp$', '(^|\\.)arena\\.ne\\.jp$', '(^|\\.)webarena\\.ne\\.jp$'],
      ptr: ['\\.mailsecure\\.jp$', '\\.arena\\.ne\\.jp$', '\\.suitepro\\.jp$', '\\.etius\\.jp$'] },
    { id: 'bizmw', name: 'NTT Bizメール&ウェブ (ビジネス/プレミアム)', cat: 'hosting', prospect: 'A',
      mx: ['^mwbgw\\d+\\.ocn\\.ad\\.jp$', '^mwpremgw\\d+\\.ocn\\.ad\\.jp$', '(^|\\.)bizmw\\.com$', '(^|\\.)mwprem\\.net$'],
      spf: ['(^|\\.)mwprem\\.net$', '^mailgw(mwb)?-spf\\d\\.ocn\\.ad\\.jp$', '(^|\\.)bizmw\\.com$', '^spf\\.moweb\\.jp$'],
      ptr: ['\\.bizmw\\.com$', '\\.mwprem\\.net$', '^mw[bp]-[a-z0-9-]+\\.ocn\\.ad\\.jp$', '^oogw\\d+\\.ocn\\.ad\\.jp$'] },
    { id: 'alpha_mail', name: 'アルファメール (大塚商会)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)alpha-prm\\.jp$', '(^|\\.)alpha-mail\\.(jp|ne\\.jp|net)$', '(^|\\.)alpha-lt\\.net$', '(^|\\.)alpha-web\\.jp$', '(^|\\.)alpha-plt\\.jp$', '(^|\\.)aics\\.ne\\.jp$'],
      spf: ['(^|\\.)alpha-mail\\.(jp|ne\\.jp|net)$', '(^|\\.)alpha-prm\\.jp$', '(^|\\.)alpha-web\\.jp$', '^spf\\.aams\\d*\\.jp$'],
      ptr: ['\\.alpha-(mail|prm|lt|plt|web)\\.(jp|ne\\.jp|net)$', '\\.aics\\.ne\\.jp$', '\\.otsuka-office365\\.jp$'], asn: [17514] },
    { id: 'cpi', name: 'CPI (KDDIウェブコミュニケーションズ)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)secure\\.ne\\.jp$', '(^|\\.)secure\\.jp$', '(^|\\.)cpi\\.ad\\.jp$'],
      spf: ['(^|\\.)secure\\.ne\\.jp$', '(^|\\.)cpi\\.ad\\.jp$', '-kw\\.im\\.kddi\\.ne\\.jp$'], ptr: ['\\.secure\\.ne\\.jp$', '\\.secure\\.jp$', '\\.cpi\\.ad\\.jp$'], asn: [9597] },
    { id: 'biglobe_business', name: 'BIGLOBE ビジネスメール/ホスティング', cat: 'isp', prospect: 'A',
      mx: ['^bgmgate\\d+\\.biglobe\\.ne\\.jp$', '(^|\\.)biglobe\\.ne\\.jp$', '(^|\\.)mesh\\.ad\\.jp$'], spf: ['(^|\\.)biglobe\\.ne\\.jp$', '^spf-bg\\.im\\.kddi\\.ne\\.jp$'], ptr: ['-bg\\.im\\.kddi\\.ne\\.jp$'] },
    { id: 'softbank_lg_secure_cloud', name: 'ソフトバンク 自治体情報セキュリティクラウド', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)sbt-isc\\.jp$'], asn: [146969] },
    { id: 'kagoya_vps', name: 'KAGOYA CLOUD VPS (自社運用)', cat: 'iaas', prospect: 'A', mx: ['^v\\d+-\\d+-\\d+-\\d+\\.vir\\.kagoya\\.net$'], ptr: ['\\.vir\\.kagoya\\.net$'] },
    { id: 'kagoya', name: 'KAGOYA (カゴヤ・ジャパン)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)kagoya\\.net$'], spf: ['(^|\\.)kagoya\\.net$', '^spf-(cp|ms)\\.kagoya\\.jp$'], ptr: ['\\.kagoya\\.net$'], asn: [24282] },
    { id: 'zenlogic', name: 'Zenlogic (旧ファーストサーバ / IDCフロンティア)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)znlc\\.jp$', '(^|\\.)zenlogic\\.jp$', '(^|\\.)mngsvr\\.com$', '(^|\\.)fsv\\.jp$', '(^|\\.)firstserver\\.ne\\.jp$'],
      spf: ['(^|\\.)znlc\\.jp$', '(^|\\.)mngsvr\\.com$', '(^|\\.)zenlogic\\.jp$', '(^|\\.)fsv\\.jp$'], ptr: ['\\.znlc\\.jp$', '\\.mngsvr\\.com$', '\\.fsv\\.jp$'] },
    { id: 'mixhost', name: 'mixhost', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)mixhost\\.jp$', '(^|\\.)mixh\\.jp$'], spf: ['(^|\\.)mixhost\\.jp$'], ptr: ['\\.mixhost\\.jp$'] },
    { id: 'colorfulbox', name: 'カラフルボックス', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)cbsv\\.jp$', '(^|\\.)cfbx\\.jp$'], spf: ['(^|\\.)cbsv\\.jp$'], ptr: ['\\.cbsv\\.jp$'] },
    { id: 'starserver', name: 'スターサーバー (ネットオウル)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)star\\.ne\\.jp$', '(^|\\.)netowl\\.jp$', '(^|\\.)starfree\\.jp$'], spf: ['(^|\\.)netowl\\.jp$'], ptr: ['\\.star\\.ne\\.jp$', '\\.netowl\\.jp$'] },
    { id: 'coreserver', name: 'コアサーバー/XREA/バリューサーバー (GMOデジロック)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)coreserver\\.jp$', '(^|\\.)xrea\\.com$', '(^|\\.)valueserver\\.jp$', '(^|\\.)value-domain\\.com$'], ptr: ['\\.coreserver\\.jp$', '\\.xrea\\.com$', '\\.valueserver\\.jp$'], asn: [37907] },
    { id: 'ablenet', name: 'ABLENET', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)mail-servers\\.org$', '(^|\\.)ablenet\\.jp$'], ptr: ['\\.ablenet\\.jp$', '\\.mail-servers\\.org$'] },
    { id: 'jetboy', name: 'JETBOY', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)jetboy\\.jp$', '(^|\\.)andcloud\\.jp$'], ptr: ['\\.jetboy\\.jp$'] },
    { id: 'littleserver', name: 'リトルサーバー', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)lsv\\.jp$'], ptr: ['\\.lsv\\.jp$'] },
    { id: 'rakkoserver', name: 'ラッコサーバー', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)rakko\\.zone$'], ptr: ['\\.rakko\\.zone$'] },
    { id: 'chicappa', name: 'チカッパ (旧GMOペパボ)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)chicappa\\.jp$'] },
    { id: 'jimdo', name: 'Jimdo (KDDIウェブ) メール', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)jimdo\\.com$'] },
    { id: 'goope', name: 'グーペ (GMOペパボ)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)goope\\.jp$'], spf: ['(^|\\.)goope\\.jp$'] },
    { id: 'js_hpbs', name: 'ホームページ・ビルダー サービス (ジャストシステム)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)js-hpbs\\.jp$'], spf: ['(^|\\.)js-hpbs\\.jp$'] },
    { id: 'xaas3', name: 'アイフラッグ XaaS', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)xaas\\d*\\.jp$'] },
    { id: 'jpserve', name: 'SPEEDIA (jpserve.jp)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)jpserve\\.jp$'] },
    { id: 'linkclub', name: 'リンククラブ', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)linkclub\\.jp$'] },
    { id: 'weblife', name: 'BiND/WebLiFE (デジタルステージ)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)weblife\\.me$'] },
    { id: 'interq', name: 'GMO interQ MEMBERS (旧GMOホスティング)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)interq\\.or\\.jp$'] },
    { id: 'presinet', name: 'プレジネット', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)presinet\\.ne\\.jp$'], ptr: ['\\.presinet\\.ne\\.jp$'] },
    { id: 'ntt_smartconnect', name: 'NTTスマートコネクト ホスティング', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)mcnet\\.ad\\.jp$', '(^|\\.)smartconnect\\.ne\\.jp$'], ptr: ['\\.mcnet\\.ad\\.jp$'], asn: [7671] },
    { id: 'ocnk', name: 'おちゃのこネット (ECサイト)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)ocnk\\.me$'] },
    { id: 'tokai_business', name: 'TOKAIコミュニケーションズ 法人メール', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)basmail\\.jp$', '(^|\\.)oneoffice\\.jp$', '(^|\\.)t-com\\.ne\\.jp$'] },
    { id: 'stnet_hosting', name: 'STNet ホスティング', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)mss\\.stnet\\.co\\.jp$'], ptr: ['\\.mss\\.stnet\\.co\\.jp$'] },
    { id: 'squarespace', name: 'Squarespace (メール転送/Google Workspace再販)', cat: 'relay', prospect: 'C', mx: ['^mx\\.squarespace\\.com$'] },
    { id: 'shopify_forwarding', name: 'Shopify (メール転送)', cat: 'relay', prospect: 'C', mx: ['^mx\\.shopify\\.com$'] },
    { id: 'domain_parking', name: 'ドメインパーキング (失効・売却中)', cat: 'none', prospect: 'X',
      mx: ['(^|\\.)hostedmxserver\\.com$', '(^|\\.)sedoparking\\.com$', '(^|\\.)bodis\\.com$', '(^|\\.)above\\.com$', '(^|\\.)parkingcrew\\.net$', '(^|\\.)parklogic\\.com$'] },
    // ---------- セキュリティゲートウェイ ----------
    { id: 'trend_micro_email_security', name: 'Trend Micro Email Security', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)(tmes|tmems|hes)(-[a-z0-9]+)?\\.trendmicro\\.(com|eu)$'],
      spf: ['(^|\\.)(tmes|tmems|hes)(-[a-z0-9]+)?\\.trendmicro\\.(com|eu)$'] },
    { id: 'proofpoint', name: 'Proofpoint Email Protection', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)g?pphosted\\.com$', '(^|\\.)ppe-hosted\\.com$', '(^|\\.)ppops\\.net$', '(^|\\.)ppsmtp\\.(com|net)$'],
      spf: ['(^|\\.)g?pphosted\\.com$', '(^|\\.)ppe-hosted\\.com$', '(^|\\.)ppops\\.net$'], ptr: ['\\.g?pphosted\\.com$', '\\.ppe-hosted\\.com$'], asn: [26211, 22843, 52129, 13916] },
    { id: 'symantec_email_security_cloud', name: 'Symantec/Broadcom Email Security.cloud', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)messagelabs\\.com$', '(^|\\.)messagelabs\\.net$'], spf: ['(^|\\.)messagelabs\\.com$'] },
    { id: 'barracuda', name: 'Barracuda Email Protection', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)ess(\\.[a-z]{2})?\\.barracudanetworks\\.com$', '(^|\\.)barracudanetworks\\.com$', '(^|\\.)ess\\.barracuda\\.com$', '(^|\\.)cuda-inc\\.com$'], spf: ['(^|\\.)barracudanetworks\\.com$', '(^|\\.)ess\\.barracuda\\.com$'] },
    { id: 'mimecast', name: 'Mimecast', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)mimecast\\.com$', '(^|\\.)mimecast\\.co\\.za$', '(^|\\.)mimecast-offshore\\.com$', '(^|\\.)mimecast\\.de$'],
      spf: ['(^|\\.)mimecast\\.com$', '(^|\\.)mimecast\\.co\\.za$', '(^|\\.)mimecast-offshore\\.com$'], asn: [30031, 42427, 136792, 39588] },
    { id: 'cisco_secure_email', name: 'Cisco Secure Email (IronPort Cloud)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)iphmx\\.com$'], spf: ['(^|\\.)iphmx\\.com$'], ptr: ['(^|\\.)iphmx\\.com$'], asn: [16417, 30215, 30238] },
    { id: 'fortinet_fortimail', name: 'Fortinet FortiMail Cloud', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)fortimail\\.com$', '(^|\\.)fortimailcloud\\.com$'], spf: ['(^|\\.)fortimail\\.com$'], asn: [40934] },
    { id: 'sophos_email', name: 'Sophos Email', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)hydra\\.sophos\\.com$', '(^|\\.)sophos\\.com$', '(^|\\.)mailanyone\\.net$', '(^|\\.)mx25\\.net$', '(^|\\.)electric\\.net$'], spf: ['(^|\\.)sophos\\.com$', '(^|\\.)mailanyone\\.net$'] },
    { id: 'cloudflare_email_security', name: 'Cloudflare Email Security (Area 1)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)cf-emailsecurity\\.net$', '(^|\\.)mxrecord\\.(io|mx)$'], spf: ['(^|\\.)cf-emailsecurity\\.net$', '(^|\\.)mxrecord\\.(io|mx)$'] },
    { id: 'checkpoint_harmony_email', name: 'Check Point Harmony Email (Avanan)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)avanan\\.net$', '(^|\\.)avanan\\.com$'], spf: ['(^|\\.)avanan\\.net$'] },
    { id: 'hornetsecurity', name: 'Hornetsecurity', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)hornetsecurity\\.com$', '(^|\\.)antispameurope\\.(com|de)$', '(^|\\.)everycloudtech\\.com$'], spf: ['(^|\\.)hornetsecurity\\.com$', '(^|\\.)antispameurope\\.com$'] },
    { id: 'trellix_email_security', name: 'Trellix Email Security Cloud (旧FireEye)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)fireeyecloud\\.com$'], spf: ['(^|\\.)fireeyecloud\\.com$'] },
    { id: 'forcepoint_email_security', name: 'Forcepoint Email Security Cloud', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)mailcontrol\\.com$'], spf: ['(^|\\.)mailcontrol\\.com$'], asn: [44444] },
    { id: 'guardianwall', name: 'GUARDIANWALL クラウド (キヤノンITS)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)guardianwall\\.jp$', '(^|\\.)guardianwall\\.com$'], spf: ['(^|\\.)guardianwall\\.jp$'], ptr: ['\\.guardianwall\\.jp$'] },
    { id: 'nec_mail_security', name: 'NEC クラウドメールセキュリティ', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)mailsecurity-nec\\.jp$'], spf: ['(^|\\.)mailsecurity-nec\\.jp$'] },
    { id: 'bbsec_aams', name: 'BBSec AAMS メールセキュリティ', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)aams\\d*\\.jp$'] },
    { id: 'spamsniper', name: 'SPAMSNIPER クラウド (ジラン)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)spamsniper\\.jp$'] },
    { id: 'm_filter', name: 'm-FILTER クラウド (デジタルアーツ)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)digitalartscloud\\.com$', '(^|\\.)m-filter\\.jp$', '(^|\\.)mfilter\\.jp$'], spf: ['(^|\\.)digitalartscloud\\.com$', '(^|\\.)m-filter\\.jp$'], ptr: ['\\.digitalartscloud\\.com$'] },
    { id: 'active_gate', name: 'Active! gate SS (クオリティア)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)active-w\\.net$', '(^|\\.)activegate-ss\\.jp$', '(^|\\.)activezone-ss\\.jp$'], spf: ['(^|\\.)active-w\\.net$', '(^|\\.)activegate-ss\\.jp$', '(^|\\.)activezone-ss\\.jp$'], ptr: ['\\.activegate-ss\\.jp$', '\\.active-w\\.net$'], asn: [132504] },
    { id: 'securemail_plus', name: '@Securemail Plus (ケイティケイソリューションズ)', cat: 'gateway', prospect: 'C',
      mx: ['(^|\\.)ktk-sol\\.co\\.jp$', '(^|\\.)securemail-plus\\.com$', '(^|\\.)securemail-asp\\.com$'], spf: ['(^|\\.)ktk-sol\\.co\\.jp$', '(^|\\.)securemail-plus\\.com$'], ptr: ['\\.ktk-sol\\.co\\.jp$', '\\.securemail-plus\\.com$', '\\.ktknet\\.net$'] },
    // ---------- 転送・配信 ----------
    { id: 'cloudflare_email_routing', name: 'Cloudflare Email Routing (転送)', cat: 'relay', prospect: 'C',
      mx: ['(^|\\.)mx\\.cloudflare\\.net$'], spf: ['^_spf\\.mx\\.cloudflare\\.net$'] },
    { id: 'improvmx', name: 'ImprovMX (転送)', cat: 'relay', prospect: 'C', mx: ['(^|\\.)improvmx\\.com$'] },
    { id: 'forwardemail', name: 'Forward Email (転送)', cat: 'relay', prospect: 'C', mx: ['(^|\\.)forwardemail\\.net$'] },
    { id: 'mailgun', name: 'Mailgun (受信)', cat: 'relay', prospect: 'C', mx: ['(^|\\.)mailgun\\.org$'], spf: ['^mailgun\\.org$'] },
    { id: 'sendgrid', name: 'SendGrid (受信)', cat: 'relay', prospect: 'C', mx: ['(^|\\.)sendgrid\\.net$'], spf: ['^sendgrid\\.net$'] },
    // ---------- グローバル ホスティング/メール ----------
    { id: 'amazon_workmail', name: 'Amazon WorkMail / SES 受信', cat: 'saas', prospect: 'B',
      mx: ['^inbound-smtp\\.[a-z0-9-]+\\.amazonaws\\.com$'], spf: [] },  // amazonses.com の include は配信用途が大半なので裏側判定に使わない
    { id: 'opensrs_hostedemail', name: 'OpenSRS Hosted Email (Tucows)', cat: 'hosting', prospect: 'A',
      mx: ['(^|\\.)hostedemail\\.com$'] },
    { id: 'godaddy', name: 'GoDaddy', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)secureserver\\.net$'], spf: ['^secureserver\\.net$'] },
    { id: 'ionos', name: 'IONOS (1&1)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)ionos\\.(com|de|co\\.uk|es|fr|it|mx)$', '(^|\\.)1and1\\.(com|de)$', '(^|\\.)kundenserver\\.de$'] },
    { id: 'rackspace', name: 'Rackspace Email', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)emailsrvr\\.com$'], spf: ['^emailsrvr\\.com$'] },
    { id: 'namecheap', name: 'Namecheap Private Email', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)privateemail\\.com$', '(^|\\.)registrar-servers\\.com$'] },
    { id: 'titan', name: 'Titan Email (Hostinger等)', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)titan\\.email$', '(^|\\.)hostinger\\.com$'] },
    { id: 'bluehost', name: 'Bluehost / HostGator', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)bluehost\\.com$', '(^|\\.)hostgator\\.com$', '(^|\\.)websitewelcome\\.com$'] },
    { id: 'dreamhost', name: 'DreamHost', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)dreamhost\\.com$'] },
    { id: 'siteground', name: 'SiteGround', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)mailspamprotection\\.com$', '(^|\\.)siteground\\.(com|net|biz|us|eu)$'] },
    { id: 'ovh', name: 'OVHcloud', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)mail\\.ovh\\.net$', '(^|\\.)ovh\\.net$'] },
    { id: 'hetzner', name: 'Hetzner', cat: 'hosting', prospect: 'A', mx: ['(^|\\.)your-server\\.de$', '(^|\\.)hetzner\\.(com|de)$'] },
    { id: 'yandex', name: 'Yandex 360', cat: 'saas', prospect: 'B', mx: ['(^|\\.)mx\\.yandex\\.net$', '(^|\\.)yandex\\.(net|ru)$'] },
    { id: 'tencent_exmail', name: 'Tencent 企業メール (Exmail)', cat: 'saas', prospect: 'B', mx: ['^mxbiz\\d*\\.qq\\.com$', '(^|\\.)exmail\\.qq\\.com$', '^cloudmx\\.qq\\.com$'] },
    { id: 'alibaba_mail', name: 'Alibaba Mail', cat: 'saas', prospect: 'B', mx: ['(^|\\.)mxhichina\\.com$', '(^|\\.)qiye\\.aliyun\\.com$', '(^|\\.)mail\\.aliyun\\.com$', '(^|\\.)alibaba-inc\\.com$'] },
    { id: 'naver_works', name: 'NAVER WORKS', cat: 'saas', prospect: 'B', mx: ['(^|\\.)navercorp\\.com$', '(^|\\.)naver\\.com$'] },
    { id: 'icloud', name: 'iCloud メール (カスタムドメイン)', cat: 'consumer', prospect: 'X', mx: ['(^|\\.)mail\\.icloud\\.com$'] },
    { id: 'fastmail', name: 'Fastmail', cat: 'saas', prospect: 'B', mx: ['(^|\\.)messagingengine\\.com$'] },
    { id: 'proton', name: 'Proton Mail', cat: 'saas', prospect: 'B', mx: ['(^|\\.)protonmail\\.ch$', '(^|\\.)proton\\.me$'] },
    { id: 'yahoo', name: 'Yahoo Mail', cat: 'consumer', prospect: 'X', mx: ['(^|\\.)yahoodns\\.net$'] },
    { id: 'yahoo_japan', name: 'Yahoo! JAPAN メール', cat: 'consumer', prospect: 'X', mx: ['(^|\\.)mail\\.yahoo\\.co\\.jp$', '(^|\\.)yahoo\\.co\\.jp$'] },
    // ---------- 日本の ISP メール ----------
    { id: 'isp_ocn', name: 'OCN (NTT) ホスティング/メール', cat: 'isp', prospect: 'A', mx: ['(^|\\.)ocn\\.ne\\.jp$', '(^|\\.)ocn\\.ad\\.jp$'], ptr: ['\\.ocn\\.ad\\.jp$', '\\.ocn\\.ne\\.jp$'] },
    { id: 'isp_sonet', name: 'So-net', cat: 'isp', prospect: 'A', mx: ['(^|\\.)so-net\\.ne\\.jp$'] },
    { id: 'isp_nifty', name: '@nifty', cat: 'isp', prospect: 'A', mx: ['(^|\\.)nifty\\.com$', '(^|\\.)nifty\\.ne\\.jp$'] },
    { id: 'isp_plala', name: 'ぷらら', cat: 'isp', prospect: 'A', mx: ['(^|\\.)plala\\.or\\.jp$'] },
    { id: 'isp_dti', name: 'DTI', cat: 'isp', prospect: 'A', mx: ['(^|\\.)dti\\.ne\\.jp$'] },
    { id: 'isp_iij', name: 'IIJ メールホスティング', cat: 'isp', prospect: 'A', mx: ['(^|\\.)2iij\\.net$', '(^|\\.)iij\\.ad\\.jp$', '(^|\\.)iij4u\\.or\\.jp$'], ptr: ['\\.2iij\\.net$'] },
    { id: 'isp_kddi', name: 'KDDI (au one net / ホスティング)', cat: 'isp', prospect: 'A', mx: ['(^|\\.)kddi\\.ne\\.jp$', '(^|\\.)auone-net\\.jp$', '(^|\\.)kddi\\.com$'] },
    { id: 'isp_odn', name: 'ODN / SoftBank', cat: 'isp', prospect: 'A', mx: ['(^|\\.)odn\\.ne\\.jp$', '(^|\\.)odn\\.ad\\.jp$', '(^|\\.)bbtec\\.net$'] },
    { id: 'isp_asahinet', name: 'ASAHIネット', cat: 'isp', prospect: 'A', mx: ['(^|\\.)asahi-net\\.or\\.jp$'] },
    { id: 'isp_regional', name: '地域ISP/CATV メール (ZTV・ZAQ・eo・BAI 等)', cat: 'isp', prospect: 'A',
      mx: ['(^|\\.)ztv\\.ne\\.jp$', '(^|\\.)zaq\\.ne\\.jp$', '(^|\\.)eonet\\.ne\\.jp$', '(^|\\.)mailgw\\.jp$', '(^|\\.)bai\\.ne\\.jp$', '(^|\\.)cty-net\\.ne\\.jp$', '(^|\\.)ccsnet\\.ne\\.jp$', '(^|\\.)kcn\\.ne\\.jp$', '(^|\\.)pikara\\.ne\\.jp$', '(^|\\.)megaegg\\.ne\\.jp$', '(^|\\.)bbiq\\.jp$', '(^|\\.)commufa\\.jp$', '(^|\\.)tnc\\.ne\\.jp$', '(^|\\.)mirai\\.ne\\.jp$', '(^|\\.)air\\.ne\\.jp$', '(^|\\.)cyberhome\\.jp$', '(^|\\.)ucom\\.ne\\.jp$', '(^|\\.)vectant\\.ne\\.jp$', '(^|\\.)janis\\.or\\.jp$', '(^|\\.)jway\\.ne\\.jp$'] },
  ];

  // ---- AS番号テーブル（オンプレ/IaaS/ホスティング判定用）------------------------
  // kind: isp | hosting | cloud | cdn | saas
  const ASN_TABLE = {
    // 日本の ISP / キャリア（法人向け回線）: 自社ドメインMX + これらのAS → オンプレ濃厚
    4713: { name: 'OCN (NTTコミュニケーションズ)', kind: 'isp' },
    2914: { name: 'NTT (NTT Ltd/NTT America)', kind: 'isp' },
    2516: { name: 'KDDI', kind: 'isp' },
    17676: { name: 'SoftBank (BBTEC)', kind: 'isp' },
    4725: { name: 'ODN (SoftBank)', kind: 'isp' },
    2497: { name: 'IIJ', kind: 'isp' },
    2518: { name: 'BIGLOBE', kind: 'isp' },
    2527: { name: 'So-net', kind: 'isp' },
    2510: { name: '@nifty', kind: 'isp' },
    4685: { name: 'ASAHIネット', kind: 'isp' },
    2514: { name: 'NTTPC (InfoSphere)', kind: 'isp' },
    4680: { name: 'DTI', kind: 'isp' },
    7521: { name: 'ARTERIA', kind: 'isp' },
    17506: { name: 'ARTERIA (UCOM)', kind: 'isp' },
    9824: { name: 'J:COM', kind: 'isp' },
    10010: { name: 'TOKAI', kind: 'isp' },
    17511: { name: 'OPTAGE (eo)', kind: 'isp' },
    17685: { name: '中部テレコミュニケーション', kind: 'isp' },
    9595: { name: 'QTnet', kind: 'isp' },
    2907: { name: 'SINET (学術情報ネットワーク)', kind: 'isp' },
    9600: { name: 'So-net (法人)', kind: 'isp' },
    2519: { name: 'ARTERIA (VECTANT)', kind: 'isp' },
    10013: { name: 'フリービット (DTI)', kind: 'isp' },
    7679: { name: 'QTnet', kind: 'isp' },
    9358: { name: 'OPTAGE', kind: 'isp' },
    18126: { name: '中部テレコミュニケーション (コミュファ)', kind: 'isp' },
    7522: { name: 'STNet', kind: 'isp' },
    24278: { name: 'USEN', kind: 'isp' },
    10021: { name: 'KVH (Colt)', kind: 'isp' },
    7670: { name: 'エネコム', kind: 'isp' },
    18144: { name: 'エネコム', kind: 'isp' },
    7668: { name: '北陸通信ネットワーク', kind: 'isp' },
    7682: { name: '北海道総合通信網 (HOTnet)', kind: 'isp' },
    7690: { name: 'ミライ・コミュニケーション・ネットワーク', kind: 'isp' },
    23777: { name: 'NTTビジネスソリューションズ', kind: 'isp' },
    138384: { name: '楽天モバイル', kind: 'isp' },
    7516: { name: 'トークネット', kind: 'isp' },
    18068: { name: 'ドリームウェーブ静岡', kind: 'isp' },
    7524: { name: 'アイテック阪急阪神 (BAI)', kind: 'isp' },
    18263: { name: '名鉄コム', kind: 'isp' },
    7503: { name: 'エアインターネットサービス', kind: 'isp' },
    2915: { name: 'BBIX (ソフトバンク系)', kind: 'isp' },
    18081: { name: '近鉄ケーブルネットワーク', kind: 'isp' },
    55900: { name: 'GLBB Japan', kind: 'isp' },
    55381: { name: 'シティーケーブル周南', kind: 'isp' },
    // データセンター / コロケーション（自社サーバーをDCに設置 → オンプレ相当）
    9999: { name: 'アット東京 (データセンター)', kind: 'colo' },
    15830: { name: 'Equinix', kind: 'colo' },
    17941: { name: 'Equinix Japan (旧ビットアイル)', kind: 'colo' },
    4693: { name: 'SCSK netXDC (データセンター)', kind: 'colo' },
    9993: { name: 'CTC (データセンター)', kind: 'colo' },
    9607: { name: 'ブロードバンドタワー (データセンター)', kind: 'colo' },
    // 組織自身の AS（大学・自治体）
    59124: { name: '京都府', kind: 'own' },
    7665: { name: '岡山県', kind: 'own' },
    37915: { name: '和歌山県', kind: 'own' },
    7509: { name: '北海道大学', kind: 'own' },
    38635: { name: '慶應義塾大学', kind: 'own' },
    23623: { name: '中央大学', kind: 'own' },
    55379: { name: '法政大学', kind: 'own' },
    55380: { name: '金沢大学', kind: 'own' },
    2501: { name: '東京大学', kind: 'own' },
    23634: { name: 'NTT東日本 (フレッツ)', kind: 'isp' },
    17934: { name: 'NTT西日本 (フレッツ)', kind: 'isp' },
    9605: { name: 'NTTドコモ', kind: 'isp' },
    4732: { name: 'ぷらら (NTTドコモ)', kind: 'isp' },
    // 日本のホスティング
    7684: { name: 'さくらインターネット', kind: 'hosting', vendor: 'sakura_vps' },
    9370: { name: 'さくらインターネット', kind: 'hosting', vendor: 'sakura_vps' },
    9371: { name: 'さくらインターネット', kind: 'hosting', vendor: 'sakura_vps' },
    7506: { name: 'GMOインターネット', kind: 'hosting' },
    24282: { name: 'KAGOYA', kind: 'hosting', vendor: 'kagoya' },
    4694: { name: 'IDCフロンティア', kind: 'hosting' },
    131965: { name: 'エックスサーバー', kind: 'hosting', vendor: 'xserver_vps' },
    58791: { name: 'GMOインターネット', kind: 'hosting' },
    131921: { name: 'GMOグローバルサイン・HD (WADAX/iCLUSTA+)', kind: 'hosting' },
    63997: { name: '使えるねっと', kind: 'hosting' },
    23576: { name: 'NAVER (LINE WORKS)', kind: 'cloud' },
    18088: { name: '九電ビジネスソリューションズ (DC)', kind: 'hosting' },
    7671: { name: 'NTTスマートコネクト', kind: 'hosting' },
    17516: { name: 'NTTコムウェア', kind: 'hosting' },
    18072: { name: 'NTTドコモビジネス SaaS基盤', kind: 'cloud' },
    24270: { name: 'CRCソリューションズ', kind: 'hosting' },
    17955: { name: '電算 (長野)', kind: 'hosting' },
    18121: { name: '石川コンピュータ・センター', kind: 'hosting' },
    17534: { name: '日本システム開発', kind: 'hosting' },
    63805: { name: '両備システムズ', kind: 'hosting' },
    37907: { name: 'GMOデジロック (コアサーバー/XREA)', kind: 'hosting' },
    9597: { name: 'KDDIウェブコミュニケーションズ (CPI)', kind: 'hosting', vendor: 'cpi' },
    17514: { name: '大塚商会 (アルファメール)', kind: 'hosting', vendor: 'alpha_mail' },
    23394: { name: 'Pacific Software Publishing', kind: 'hosting' },
    55374: { name: '富士通 FJcloud', kind: 'cloud' },
    146969: { name: 'ソフトバンク (自治体セキュリティクラウド)', kind: 'cloud' },
    19551: { name: 'Imperva Incapsula', kind: 'cdn' },
    30215: { name: 'Cisco (IronPort)', kind: 'cloud' },
    16417: { name: 'Cisco (IronPort)', kind: 'cloud' },
    22843: { name: 'Proofpoint', kind: 'cloud' },
    26211: { name: 'Proofpoint', kind: 'cloud' },
    52129: { name: 'Proofpoint', kind: 'cloud' },
    13916: { name: 'Proofpoint', kind: 'cloud' },
    30031: { name: 'Mimecast', kind: 'cloud' },
    40934: { name: 'Fortinet', kind: 'cloud' },
    8560: { name: 'IONOS', kind: 'hosting' },
    27357: { name: 'Rackspace', kind: 'hosting' },
    19994: { name: 'Rackspace', kind: 'hosting' },
    22612: { name: 'Namecheap', kind: 'hosting' },
    46606: { name: 'Unified Layer (Bluehost/HostGator)', kind: 'hosting' },
    26347: { name: 'DreamHost', kind: 'hosting' },
    21499: { name: 'GoDaddy (Host Europe)', kind: 'hosting' },
    13238: { name: 'Yandex', kind: 'cloud' },
    714: { name: 'Apple', kind: 'cloud' },
    62371: { name: 'Proton', kind: 'cloud' },
    23816: { name: 'LINEヤフー', kind: 'cloud' },
    53831: { name: 'Squarespace', kind: 'cloud' },
    // グローバル クラウド IaaS
    16509: { name: 'Amazon (AWS)', kind: 'cloud' },
    14618: { name: 'Amazon (AWS)', kind: 'cloud' },
    15169: { name: 'Google', kind: 'cloud' },
    396982: { name: 'Google Cloud', kind: 'cloud' },
    8075: { name: 'Microsoft (Azure)', kind: 'cloud' },
    8068: { name: 'Microsoft', kind: 'cloud' },
    31898: { name: 'Oracle Cloud', kind: 'cloud' },
    36351: { name: 'IBM Cloud (SoftLayer)', kind: 'cloud' },
    45102: { name: 'Alibaba Cloud', kind: 'cloud' },
    132203: { name: 'Tencent Cloud', kind: 'cloud' },
    16276: { name: 'OVHcloud', kind: 'cloud' },
    24940: { name: 'Hetzner', kind: 'cloud' },
    63949: { name: 'Akamai/Linode', kind: 'cloud' },
    14061: { name: 'DigitalOcean', kind: 'cloud' },
    20473: { name: 'Vultr', kind: 'cloud' },
    13335: { name: 'Cloudflare', kind: 'cdn' },
    16625: { name: 'Akamai', kind: 'cdn' },
    20940: { name: 'Akamai', kind: 'cdn' },
    54113: { name: 'Fastly', kind: 'cdn' },
  };
  // AS名に含まれるキーワードでの補助判定（テーブルに無いAS用）
  const AS_KEYWORDS = {
    own: ['UNIVERSITY', 'UNIV', 'COLLEGE', 'INSTITUTE', 'RESEARCH', 'HOSPITAL', 'BANK', 'CITY OF', 'PREFECTURE', 'GOVERNMENT', 'MINISTRY', 'SCHOOL', 'LABORATORY', 'CORPORATION', 'CO., LTD', 'CO.,LTD', 'KABUSHIKI', 'K.K.'],
    cloud: ['AMAZON', 'AWS', 'GOOGLE', 'MICROSOFT', 'AZURE', 'ORACLE', 'ALIBABA', 'TENCENT', 'OVH', 'HETZNER', 'LINODE', 'DIGITALOCEAN', 'VULTR', 'AKAMAI', 'CLOUDFLARE', 'NIFCLOUD', 'FJCT', 'IDCF', 'CLOUD'],
    hosting: ['SAKURA', 'GMO', 'XSERVER', 'KAGOYA', 'HOSTING', 'HOST', 'SERVER', 'RENTAL', 'WEBARENA', 'ARENA', 'PEPABO', 'LOLIPOP', 'CPI', 'FIRSTSERVER', 'ZENLOGIC', 'MIXHOST', 'DIGIROCK', 'NETOWL', 'IDCF', 'IDC FRONTIER', 'SMARTCONNECT', 'MCNET', 'AICS', 'OTSUKA'],
    isp: ['OCN', 'NTT', 'KDDI', 'DION', 'SOFTBANK', 'BBTEC', 'ODN', 'GIGAINFRA', 'IIJ', 'BIGLOBE', 'SO-NET', 'SONY', 'NIFTY', 'ASAHI', 'PLALA', 'INFOSPHERE', 'ARTERIA', 'VECTANT', 'UCOM', 'JCOM', 'J:COM', 'TOKAI', 'OPTAGE', 'EONET', 'QTNET', 'STNET', 'ENECOM', 'ENERGIA', 'HOTNET', 'HTCN', 'TOHKNET', 'CTC', 'COMMUFA', 'TELECOM', 'COMMUNICATIONS', 'INTERNET SERVICE', 'BROADBAND', 'CABLE', 'CATV', 'DTI', 'FREEBIT', 'KVH', 'COLT', 'USEN', 'MEITETSU', 'HANSHIN', 'RAKUTEN MOBILE', 'NURO', 'DOCOMO', 'AU ', 'MOBILE'],
    colo: ['EQUINIX', 'AT TOKYO', 'ATTOKYO', 'BIT-ISLE', 'BBTOWER', 'BROADBAND TOWER', 'NETXDC', 'CSK-IT', 'DATACENTER', 'DATA CENTER', 'IDC ', 'COLOCATION'],
  };

  // ---- 多段パブリックサフィックス（eTLD+1 算出の簡易版）------------------------
  const MULTI_SUFFIX = new Set(['co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
    'com.sg', 'com.hk', 'com.tw', 'co.kr', 'or.kr', 'ne.kr', 'com.cn', 'net.cn', 'org.cn', 'com.br', 'com.mx', 'co.in', 'co.nz', 'com.my', 'co.th', 'co.id', 'com.vn', 'com.tr', 'com.ar', 'co.za', 'com.ph', 'co.il', 'com.pl', 'com.ua', 'co.at', 'com.es', 'com.pt']);
  const JP_PREFS = ['hokkaido', 'aomori', 'iwate', 'miyagi', 'akita', 'yamagata', 'fukushima', 'ibaraki', 'tochigi', 'gunma', 'saitama', 'chiba', 'tokyo', 'kanagawa', 'niigata', 'toyama', 'ishikawa', 'fukui', 'yamanashi', 'nagano', 'gifu', 'shizuoka', 'aichi', 'mie', 'shiga', 'kyoto', 'osaka', 'hyogo', 'nara', 'wakayama', 'tottori', 'shimane', 'okayama', 'hiroshima', 'yamaguchi', 'tokushima', 'kagawa', 'ehime', 'kochi', 'fukuoka', 'saga', 'nagasaki', 'kumamoto', 'oita', 'miyazaki', 'kagoshima', 'okinawa'];
  for (const p of JP_PREFS) MULTI_SUFFIX.add(p + '.jp');

  function registrableDomain(host) {
    if (!host) return host;
    const labels = host.toLowerCase().replace(/\.$/, '').split('.');
    if (labels.length <= 2) return labels.join('.');
    const last2 = labels.slice(-2).join('.');
    const last3 = labels.slice(-3).join('.');
    // 3段サフィックス（例: city.xxx.lg.jp は lg.jp 直下が組織）
    if (MULTI_SUFFIX.has(last2)) {
      // pref.jp の下に city.chiyoda.tokyo.jp のような形式: 4ラベル以上なら市区町村名までを組織とみなす
      if (JP_PREFS.includes(labels[labels.length - 2]) && labels.length >= 4 && ['city', 'town', 'vill', 'pref', 'metro'].includes(labels[labels.length - 4])) {
        return labels.slice(-4).join('.');
      }
      return last3;
    }
    // 汎用: 2文字ccTLD + com/net/org/co/gov/edu/ac
    const tld = labels[labels.length - 1], sld = labels[labels.length - 2];
    if (tld.length === 2 && /^(com|net|org|co|gov|edu|ac|or|ne|go)$/.test(sld)) return last3;
    return last2;
  }

  // ---- ユーティリティ -------------------------------------------------------
  const compiled = new Map();
  function re(src) {
    let r = compiled.get(src);
    if (!r) { r = new RegExp(src, 'i'); compiled.set(src, r); }
    return r;
  }
  function norm(host) { return String(host || '').trim().toLowerCase().replace(/\.$/, ''); }
  const byId = new Map(VENDORS.map(v => [v.id, v]));

  function matchMx(host) {
    const h = norm(host);
    for (const v of VENDORS) for (const p of (v.mx || [])) if (re(p).test(h)) return v;
    return null;
  }
  function matchPtr(ptr) {
    const h = norm(ptr);
    if (!h) return null;
    for (const v of VENDORS) for (const p of (v.ptr || [])) if (re(p).test(h)) return v;
    // PTR が MX パターンに一致する場合も拾う（例: sv123.xserver.jp）
    return matchMx(h);
  }
  function matchSpf(include) {
    const h = norm(include);
    for (const v of VENDORS) for (const p of (v.spf || [])) if (re(p).test(h)) return v;
    return null;
  }
  function matchNs(ns) {
    const h = norm(ns);
    if (!h) return null;
    for (const v of VENDORS) for (const p of (v.ns || [])) if (re(p).test(h)) return v;
    return null;
  }
  // SPF の a:host / mx:host に現れるホスト名（例: a:sv1234.xserver.jp, a:www1234.sakura.ne.jp）
  function matchSpfHost(host) { const h = norm(host); return matchPtr(h) || matchMx(h); }
  function asnInfo(asn) {
    if (asn == null) return null;
    const t = ASN_TABLE[asn];
    return t ? { asn, ...t } : null;
  }
  function asnKind(asn, asName) {
    const t = asnInfo(asn);
    if (t) return t.kind;
    const n = String(asName || '').toUpperCase();
    if (!n) return null;
    for (const k of ['cloud', 'colo', 'hosting', 'isp', 'own']) for (const kw of AS_KEYWORDS[k]) if (n.includes(kw)) return k;
    return null;
  }

  // ---- 分類 ----------------------------------------------------------------
  /**
   * @param {object} d lookupDomain() の結果
   *  { input, domain, checkedDomain, mxStatus:'ok'|'nomx'|'nxdomain'|'nullmx'|'error',
   *    mx:[{pref, host, ip, ptr, asn, asName, asCC}], aFallback:{ip,ptr,asn,asName}|null,
   *    spf:{raw, includes:[...], nested:[...]}, dmarc:{raw, p}|null,
   *    signals:{googleDkim, selector1, selector2, autodiscoverCname, autodiscoverA, msTxt}, error }
   */
  function classify(d) {
    const ev = [];
    const out = {
      input: d.input, domain: d.domain, checkedDomain: d.checkedDomain || d.domain,
      platform: null, backend: null, hosting: 'unknown', hostingLabel: '', confidence: 'low',
      prospect: '?', prospectLabel: '', label: '', evidence: ev, mixed: false, notes: [],
    };
    if (d.checkedDomain && d.checkedDomain !== d.domain) ev.push(`入力「${d.domain}」には MX が無いため、組織ドメイン「${d.checkedDomain}」で判定`);

    if (d.mxStatus === 'error') {
      out.platform = { id: 'error', name: '判定できず (DNS エラー)', cat: 'unknown' };
      out.hosting = 'unknown'; out.label = out.platform.name; ev.push(d.error || 'DNS 問い合わせに失敗');
      return finish(out);
    }
    if (d.mxStatus === 'nxdomain') {
      out.platform = { id: 'nxdomain', name: 'ドメインが存在しない (NXDOMAIN)', cat: 'unknown' };
      out.hosting = 'none'; out.prospect = '?'; out.label = out.platform.name; out.confidence = 'high';
      ev.push('DNS にドメインが登録されていない（www も含めて引けない）');
      out.notes.push('リストの URL が古い可能性（ドメイン失効・社名変更・入力ミス）');
      return finish(out);
    }
    if (d.mxStatus === 'nullmx') {
      out.platform = { id: 'null_mx', name: 'メール受信なし (Null MX)', cat: 'none' };
      out.hosting = 'none'; out.prospect = 'X'; out.label = out.platform.name; out.confidence = 'high';
      ev.push('MX "." (RFC 7505 Null MX) — このドメインはメールを受け取らない宣言');
      return finish(out);
    }

    // --- 裏側（バックエンド）の推定: DKIM / autodiscover / SPF ---
    const s = d.signals || {};
    const backendVotes = []; // {vendor, weight, why}
    if (s.googleDkim) backendVotes.push({ vendor: byId.get('google_workspace'), weight: 3, why: 'DKIM セレクタ google._domainkey が存在（Google Workspace の署名鍵）' });
    if (/^ghs\.(googlehosted|google)\.com$/.test(norm(s.mailCname || ''))) backendVotes.push({ vendor: byId.get('google_workspace'), weight: 3, why: `mail.${out.checkedDomain} が ${s.mailCname}（Google Workspace のカスタム URL）` });
    if (s.gwsRecovery) backendVotes.push({ vendor: byId.get('google_workspace'), weight: 2, why: 'TXT に google-gws-recovery-domain-verification（Workspace テナントの復旧用確認）がある' });
    const sel1 = norm(s.selector1 || ''), sel2 = norm(s.selector2 || '');
    if (/\.onmicrosoft\.com$/.test(sel1) || /\.onmicrosoft\.com$/.test(sel2)) backendVotes.push({ vendor: byId.get('microsoft_365'), weight: 3, why: `DKIM selector1/2 が ${sel1 || sel2} (onmicrosoft.com) を指す` });
    const adc = norm(s.autodiscoverCname || '');
    if (/^autodiscover\.outlook\.com$/.test(adc)) backendVotes.push({ vendor: byId.get('microsoft_365'), weight: 3, why: 'autodiscover が autodiscover.outlook.com を指す（Exchange Online）' });
    if (s.msTxt) backendVotes.push({ vendor: byId.get('microsoft_365'), weight: 1, why: 'TXT に MS=ms… (Microsoft 365 ドメイン確認) がある' });
    const spfIncludes = (d.spf && d.spf.includes) || [];
    const spfVendors = [];
    for (const inc of spfIncludes) {
      const v = matchSpf(inc);
      if (v && !spfVendors.some(x => x.id === v.id)) { spfVendors.push(v); backendVotes.push({ vendor: v, weight: (v.cat === 'saas' ? 2 : 1), why: `SPF include:${inc}` }); }
    }
    for (const inc of ((d.spf && d.spf.nested) || [])) {
      const v = matchSpf(inc);
      if (v && !spfVendors.some(x => x.id === v.id)) { spfVendors.push(v); backendVotes.push({ vendor: v, weight: 1, why: `SPF（入れ子）include:${inc}` }); }
    }
    // 集計（SaaS/ISP/ホスティングのみを裏側候補とする。ゲートウェイは裏側ではない）
    const tally = new Map();
    for (const b of backendVotes) {
      if (!b.vendor || b.vendor.cat === 'gateway' || b.vendor.cat === 'relay') continue;
      const t = tally.get(b.vendor.id) || { vendor: b.vendor, score: 0, whys: [] };
      t.score += b.weight; t.whys.push(b.why); tally.set(b.vendor.id, t);
    }
    const ranked = [...tally.values()].sort((a, b) => b.score - a.score);
    // Google と Microsoft の両方に強い署名がある場合は「併用」として両方を示す
    const dual = ranked.length >= 2 && ranked[0].score >= 3 && ranked[1].score >= 3 && ranked[0].vendor.cat === 'saas' && ranked[1].vendor.cat === 'saas' ? ranked[1] : null;
    const applyDual = () => {
      if (!dual || !out.backend || out.backend.id !== ranked[0].vendor.id) return;
      out.backend2 = dual.vendor; ev.push(...dual.whys);
      out.notes.push(`${ranked[0].vendor.name} と ${dual.vendor.name} の両方の設定がある（併用・移行中の可能性）`);
      if (ranked[0].vendor.id === 'google_workspace' || dual.vendor.id === 'google_workspace') { out.prospect = 'C'; out.notes.push('Google Workspace の署名あり — 既存契約の有無を要確認'); }
    };

    // --- MX ホストごとのベンダー判定 ---
    const mxList = (d.mx || []).slice().sort((a, b) => a.pref - b.pref);
    const regDom = registrableDomain(out.checkedDomain);
    const analyzed = mxList.map(m => {
      const host = norm(m.host);
      const r = { ...m, host, vendor: null, how: '', ownHost: false, asKind: null, asInfo: null };
      r.ownHost = host === out.checkedDomain || host.endsWith('.' + out.checkedDomain) || registrableDomain(host) === regDom;
      const v = matchMx(host);
      if (v) { r.vendor = v; r.how = 'mx'; return r; }
      r.asInfo = asnInfo(m.asn) || (m.asn ? { asn: m.asn, name: m.asName || '', kind: asnKind(m.asn, m.asName) } : null);
      r.asKind = r.asInfo ? r.asInfo.kind : null;
      const pv = m.ptr ? matchPtr(m.ptr) : null;
      if (pv) { r.vendor = pv; r.how = 'ptr'; return r; }
      // SPF の a:/mx: 機構に事業者のサーバー名がある（Xserver / さくら / Xserverビジネス の公式テンプレート）
      for (const h of ((d.spf && d.spf.aHosts) || [])) { const sv = matchSpfHost(h); if (sv && sv.cat !== 'gateway' && sv.cat !== 'saas') { r.vendor = sv; r.how = 'spf'; r.spfHost = h; return r; } }
      if (r.asInfo && r.asInfo.vendor && byId.get(r.asInfo.vendor)) { r.vendor = byId.get(r.asInfo.vendor); r.how = 'asn'; return r; }
      if (r.ownHost) { for (const n of (d.ns || [])) { const nv = matchNs(n); if (nv && (!r.asInfo || r.asInfo.kind === 'hosting' || !r.asInfo.kind)) { r.vendor = nv; r.how = 'ns'; r.nsHost = n; return r; } } }
      return r;
    });

    if (d.mxStatus === 'nomx') {
      const a = d.aFallback;
      if (!a || !a.ip) {
        out.platform = { id: 'no_mail', name: 'MX なし・A レコードなし（このドメインでは受信しない）', cat: 'none' };
        out.hosting = 'none'; out.prospect = 'C'; out.confidence = 'high'; out.label = out.platform.name;
        ev.push('MX も A レコードも無く、このドメイン宛てのメールは受信できない');
        out.notes.push('別ドメインでメール運用している可能性（会社の正式ドメインを要確認）');
        return finish(out);
      }
      // A レコードへのフォールバック配送（RFC 5321）
      const pv = a.ptr ? matchPtr(a.ptr) : null;
      const ai = asnInfo(a.asn) || (a.asn ? { asn: a.asn, name: a.asName || '', kind: asnKind(a.asn, a.asName) } : null);
      if (d.sibling && d.sibling.mx && d.sibling.mx.length) {
        const sv = matchMx(d.sibling.mx[0]);
        const sname = sv ? sv.name : `MX ${d.sibling.mx[0]}`;
        out.sibling = { domain: d.sibling.domain, vendor: sv || null, name: sname };
        ev.push(`関連ドメイン ${d.sibling.domain} に MX あり（${sname}）— メールはそちらで運用の可能性`);
      }
      ev.push(`MX が無く A レコード (${a.ip}) 宛て配送になる${a.ptr ? `、逆引き ${a.ptr}` : ''}${ai ? `、AS${ai.asn} ${ai.name}` : ''}`);
      if (pv) {
        out.platform = { ...pv, name: pv.name + '（MXなし・Aレコード配送）' }; out.hosting = pv.cat; out.confidence = 'low';
      } else if (ai && (ai.kind === 'isp' || ai.kind === 'own' || ai.kind === 'colo')) {
        out.platform = { id: 'no_mx_onprem', name: 'MX なし（自社サーバー宛て配送の可能性）', cat: 'onprem' }; out.hosting = 'onprem_maybe';
      } else {
        out.platform = { id: 'no_mx', name: 'MX なし（このドメインでは受信しない）', cat: 'none' }; out.hosting = 'none';
      }
      // MX が無い＝受信していないので、SPF から基盤が見えても「要確認」に留める
      out.prospect = pv ? pv.prospect : 'C';
      if (ranked.length) {
        out.backend = ranked[0].vendor; ev.push(...ranked[0].whys);
        out.notes.push(`送信側の設定は ${ranked[0].vendor.name}。ただし MX が無いため、受信は別ドメインの可能性`);
      }
      out.label = out.platform.name + (out.backend ? ` → ${out.backend.name}` : '');
      if (out.sibling) {
        const sv = out.sibling.vendor;
        out.label = `MX なし（関連ドメイン ${out.sibling.domain} は ${out.sibling.name}）`;
        out.platform = { id: 'no_mx_sibling', name: out.label, cat: sv ? sv.cat : 'none' };
        out.hosting = sv ? sv.cat : 'none';
        out.hostingLabel = `関連ドメインで運用${sv ? ` → ${HOSTING_JA[sv.cat] || '不明'}` : ''}`;
        out.prospect = sv ? prospectFor(sv) : 'C';
        out.notes.push(`${out.sibling.domain} の判定を参考にしてください`);
      }
      return finish(out);
    }

    // --- 主 MX（最小プリファレンス）で基盤を決める ---
    const primary = analyzed[0];
    const vendorsSeen = [...new Set(analyzed.filter(x => x.vendor).map(x => x.vendor.id))];
    if (vendorsSeen.length > 1) { out.mixed = true; out.notes.push('MX が複数ベンダーに分散: ' + vendorsSeen.map(id => byId.get(id).name).join(' / ')); }

    if (primary.vendor) {
      const v = primary.vendor;
      out.platform = v;
      out.confidence = primary.how === 'mx' ? 'high' : primary.how === 'ns' ? 'low' : 'medium';
      ev.push(primary.how === 'mx' ? `MX ${primary.host} が ${v.name} のホスト`
        : primary.how === 'ptr' ? `MX ${primary.host} (${primary.ip}) の逆引き ${primary.ptr} が ${v.name} のサーバー`
        : primary.how === 'spf' ? `MX ${primary.host} は自社ドメイン内だが、SPF が ${v.name} のサーバー ${primary.spfHost} を許可（公式テンプレート）`
        : primary.how === 'ns' ? `MX ${primary.host} は自社ドメイン内。ネームサーバー ${primary.nsHost} が ${v.name} のもの（推定）`
        : `MX ${primary.host} (${primary.ip}) の AS${primary.asn} が ${v.name.replace(/ \(.*$/, '')} の保有。逆引き${primary.ptr ? ` ${primary.ptr}` : ''}は共用サーバー名ではない → 自前運用のサーバー`);
      if (v.cat === 'none') {
        out.hosting = 'none'; out.prospect = 'X';
      } else if (v.cat === 'gateway' || v.cat === 'relay') {
        out.hosting = v.cat;
        if (ranked.length) {
          out.backend = ranked[0].vendor; ev.push(...ranked[0].whys);
          out.hostingLabel = `${HOSTING_JA[v.cat]} → ${HOSTING_JA[ranked[0].vendor.cat] || '不明'}`;
          out.prospect = prospectFor(ranked[0].vendor);
        } else {
          out.hostingLabel = `${HOSTING_JA[v.cat]}（裏側の基盤は不明: オンプレの可能性）`;
          out.prospect = 'C';
          if (s.autodiscoverA && !adc) { ev.push(`autodiscover.${out.checkedDomain} が自社IP ${s.autodiscoverA} を指す → 裏側は Exchange Server (オンプレ) の可能性`); out.notes.push('裏側: Exchange Server オンプレ疑い'); out.prospect = 'A'; }
        }
      } else {
        out.hosting = v.cat;
        out.prospect = v.prospect;
        // 裏側が別 SaaS を強く示す場合（移行中/併用）
        if (ranked.length && ranked[0].vendor.id !== v.id && ranked[0].score >= 3) {
          ev.push(...ranked[0].whys);
          out.notes.push(`${ranked[0].vendor.name} の設定もある（移行中・併用の可能性）`);
          if (v.cat === 'saas' || v.cat === 'consumer') {
            // SaaS 同士の併用（例: MX は Google、DKIM/autodiscover は Microsoft 365）
            out.backend2 = ranked[0].vendor;
            if (v.id === 'google_workspace') out.prospect = 'X';
            else if (ranked[0].vendor.id === 'google_workspace') { out.prospect = 'C'; out.notes.push('Google Workspace の署名あり — 既存契約の有無を要確認'); }
          } else { out.backend = ranked[0].vendor; out.prospect = prospectFor(ranked[0].vendor); out.hostingLabel = `${HOSTING_JA[v.cat]} → ${HOSTING_JA[ranked[0].vendor.cat] || '不明'}`; }
        }
        for (const t of ranked) if (t.vendor.id === v.id) ev.push(...t.whys);
      }
    } else if (primary.ownHost) {
      // 自社ドメイン内のホストに MX → PTR/AS で切り分け
      const ai = primary.asInfo;
      const where = `MX ${primary.host}${primary.ip ? ` (${primary.ip})` : ''} は自社ドメイン内のホスト`;
      if (ai && ai.kind === 'own') {
        out.platform = { id: 'onprem', name: 'オンプレ（自社運用メールサーバー）', cat: 'onprem' }; out.hosting = 'onprem'; out.confidence = 'high';
        ev.push(`${where}。IP の AS${ai.asn} は組織自身の AS (${ai.name}) → 自社ネットワーク上のサーバー`);
      } else if (ai && ai.kind === 'colo') {
        out.platform = { id: 'onprem_colo', name: 'オンプレ（データセンター設置の自社サーバー）', cat: 'onprem' }; out.hosting = 'onprem'; out.confidence = 'medium';
        ev.push(`${where}。IP の AS${ai.asn} はデータセンター事業者 (${ai.name}) → 自社サーバーをDCに設置`);
      } else if (ai && ai.kind === 'isp') {
        out.platform = { id: 'onprem', name: 'オンプレ（自社運用メールサーバー）', cat: 'onprem' }; out.hosting = 'onprem'; out.confidence = 'medium';
        ev.push(`${where}。IP の AS${ai.asn} は ISP/通信事業者 (${ai.name}) → 自社設置の可能性大`);
      } else if (ai && ai.kind === 'cloud') {
        out.platform = { id: 'iaas_self', name: `IaaS 上で自社運用 (${ai.name})`, cat: 'iaas' }; out.hosting = 'iaas'; out.confidence = 'medium';
        ev.push(`${where}。IP の AS${ai.asn} は ${ai.name} → クラウド IaaS 上の自前メールサーバー`);
      } else if (ai && ai.kind === 'hosting') {
        out.platform = { id: 'hosting_' + ai.asn, name: `${ai.name} 系ホスティング（ブランド不明）`, cat: 'hosting' }; out.hosting = 'hosting'; out.confidence = 'medium';
        ev.push(`${where}。IP の AS${ai.asn} はホスティング事業者 (${ai.name})。逆引きからブランドは特定できず`);
      } else {
        out.platform = { id: 'onprem_maybe', name: 'オンプレの可能性（自社ドメイン内 MX）', cat: 'onprem' }; out.hosting = 'onprem_maybe'; out.confidence = 'low';
        ev.push(where + (ai ? `。AS${ai.asn} ${ai.name}（種別不明）` : '。IP の AS 情報は取得できず'));
      }
      if (primary.ptr) ev.push(`逆引き: ${primary.ptr}`);
      if (s.autodiscoverA && !adc) { ev.push(`autodiscover.${out.checkedDomain} が ${s.autodiscoverA} を指す → Exchange Server (オンプレ) の可能性`); out.platform = { ...out.platform, name: out.platform.name.replace('オンプレ', 'Exchange Server オンプレ') }; }
      out.prospect = 'A';
      if (ranked.length) {
        out.backend = ranked[0].vendor; ev.push(...ranked[0].whys);
        const exchangeOnprem = !!(s.autodiscoverA && !adc);
        if (ranked[0].score >= 2 && ranked[0].vendor.cat === 'saas' && !(exchangeOnprem && ranked[0].score < 3)) {
          // 自社のリレー/ゲートウェイの裏で SaaS を利用（例: mailgate.example.ac.jp → Google Workspace）
          out.platform = { id: 'own_relay', name: `自社リレー (${primary.host})`, cat: 'relay' };
          out.hosting = 'relay'; out.hostingLabel = `自社ゲートウェイ経由 → ${HOSTING_JA[ranked[0].vendor.cat] || '不明'}`;
          out.prospect = prospectFor(ranked[0].vendor); out.confidence = ranked[0].score >= 3 ? 'medium' : 'low';
          out.notes.push(ranked[0].score >= 3 ? '自社ドメイン内の MX（リレー）の裏側で SaaS を利用' : 'SPF のみの推定（DKIM/autodiscover は未検出）');
        } else if (ranked[0].score >= 3) { out.notes.push(`${ranked[0].vendor.name} の設定もある（併用・移行中の可能性）`); out.prospect = prospectFor(ranked[0].vendor); }
      }
    } else {
      // 外部の未知ホスト
      const ai = primary.asInfo;
      const hostOrg = registrableDomain(primary.host);
      if (ai && ai.kind === 'cloud') {
        out.platform = { id: 'other_cloud', name: `その他 (${hostOrg} / ${ai.name} 上)`, cat: 'relay' }; out.hosting = 'relay'; out.hostingLabel = `外部サービス経由 (${hostOrg})`;
      } else if (ai && ai.kind === 'hosting') {
        out.platform = { id: 'other_hosting', name: `その他ホスティング (${hostOrg})`, cat: 'hosting' }; out.hosting = 'hosting';
      } else if (ai && (ai.kind === 'isp' || ai.kind === 'own' || ai.kind === 'colo')) {
        out.platform = { id: 'other_isp', name: `その他 (${hostOrg} / ${ai.kind === 'colo' ? 'データセンター' : 'ISP 回線'}上)`, cat: 'onprem' }; out.hosting = 'onprem_maybe';
      } else {
        // 自社ドメイン外の MX ＝ 誰かのメールサービスを使っている。事業者名までは特定できないが、
        // Google Workspace への乗り換え提案の対象にはなる。
        out.platform = { id: 'other_provider', name: `他社のメールサービス (${hostOrg})`, cat: 'hosting' };
        out.hosting = 'hosting'; out.hostingLabel = `他社のメールサービス (${hostOrg})`;
        out.notes.push('署名に無い事業者。逆引きや AS からも特定できず');
      }
      out.confidence = 'low';
      ev.push(`MX ${primary.host}${primary.ip ? ` (${primary.ip})` : ''} は登録外のホスト${primary.ptr ? `、逆引き ${primary.ptr}` : ''}${ai ? `、AS${ai.asn} ${ai.name}` : ''}`);
      // 他社のメールサービス／レンタルサーバー／自社運用は、いずれも乗り換え提案の対象
      out.prospect = out.platform.id === 'other_provider' || (ai && (ai.kind === 'hosting' || ai.kind === 'isp' || ai.kind === 'own' || ai.kind === 'colo')) ? 'A' : 'C';
      if (ranked.length) {
        out.backend = ranked[0].vendor; ev.push(...ranked[0].whys);
        if (ranked[0].score >= 2) out.prospect = prospectFor(ranked[0].vendor);
        const exchangeOnprem = !!(s.autodiscoverA && !adc);
        if (ranked[0].score >= 2 && ranked[0].vendor.cat === 'saas' && !(exchangeOnprem && ranked[0].score < 3)) { out.hostingLabel = `リレー経由 (${hostOrg}) → ${HOSTING_JA[ranked[0].vendor.cat] || '不明'}`; out.platform = { id: 'other_relay', name: `リレー経由 (${hostOrg})`, cat: 'relay' }; out.hosting = 'relay'; if (ranked[0].score < 3) out.notes.push('SPF のみの推定（DKIM/autodiscover は未検出）'); }
      }
    }
    if (analyzed.length > 1) ev.push(`MX ${analyzed.length} 件: ` + analyzed.map(x => `${x.pref} ${x.host}`).join(', '));
    if (d.dmarc && d.dmarc.p) ev.push(`DMARC p=${d.dmarc.p}`); else if (d.dmarc === null) ev.push('DMARC 未設定');
    applyDual();
    const showBackend = out.backend && out.backend.id !== out.platform.id;
    out.label = out.platform.name + (showBackend ? ` → ${out.backend.name}` : '') + (out.backend2 ? ` ＋ ${out.backend2.name}（併用）` : '');
    return finish(out);
  }

  function prospectFor(vendor) {
    if (!vendor) return '?';
    return vendor.prospect || (vendor.cat === 'saas' ? 'B' : vendor.cat === 'hosting' || vendor.cat === 'isp' ? 'A' : 'C');
  }
  function finish(out) {
    if (!out.hostingLabel) out.hostingLabel = HOSTING_JA[out.hosting] || HOSTING_JA.unknown;
    const p = PROSPECT_JA[out.prospect] || PROSPECT_JA['?'];
    out.prospectLabel = `${p.mark} ${p.label}`;
    out.platformId = out.platform ? out.platform.id : 'unknown';
    out.platformName = out.platform ? out.platform.name : '不明';
    out.backendName = (out.backend ? out.backend.name : '') + (out.backend2 ? ` ＋ ${out.backend2.name}` : '');
    return out;
  }

  MXC.rules = { VENDORS, ASN_TABLE, AS_KEYWORDS, HOSTING_JA, PROSPECT_JA, registrableDomain, matchMx, matchPtr, matchSpf, matchNs, matchSpfHost, asnKind, asnInfo, byId };
  MXC.classify = classify;
})(typeof globalThis !== 'undefined' ? globalThis : this);
