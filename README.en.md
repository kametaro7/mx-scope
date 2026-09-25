# MX Scope

English · [日本語](README.md)

Enter domains (URLs or email addresses work too) and MX Scope reads public DNS to tell you **which email platform each organization uses** and whether it runs **on-premises or in the cloud**.
It was built for Google Workspace sales teams, so every result also gets a **prospect rating** (◎ Strong / ○ Competing SaaS / △ Check / ✕ Not a target).

## Use it now (no install)

**https://www.kameishouten.com/mx-scope/?lang=en**

Everything runs in your browser. DNS lookups go through DNS over HTTPS at Google / Cloudflare, and the classification happens locally — the domains you enter and the results are never sent to our servers.

## Languages (31)

English, Chinese (Simplified / Traditional), Spanish, Hindi, Russian, French, Portuguese, Arabic, Japanese, German, Indonesian, Turkish, Italian, Korean, Persian, Bengali, Vietnamese, Urdu, Thai, Polish, Marathi, Telugu, Tamil, Javanese, Dutch, Gujarati, Ukrainian, Kannada, Romanian and Azerbaijani.

- Switch with the globe button at the top right, or link to a language directly with `?lang=` (e.g. `?lang=de`).
- On first visit the language comes from the URL, then your previous choice, then your browser settings; unsupported languages fall back to English.
- Switching languages after a check rebuilds the table, the evidence, the summary and the exported CSV headers in the new language. The classification itself does not change.
- Arabic, Persian and Urdu are shown right-to-left; domains and DNS values stay left-to-right.

## Run it locally (faster for large lists)

- `node server.js 8791`, then open http://localhost:8791 (uses a local Node resolver instead of DNS over HTTPS)
- Or simply open `index.html` in a browser (DNS over HTTPS, like the hosted version)

## How to use

1. **Paste** URLs, email addresses or domains. They do not have to be one per line — URLs run together with no separator (`…co.jp/https://…`) are split apart, and extra columns pasted from Excel (company names, etc.) are carried over into the results.
2. **Upload CSV**: drop a CSV / TSV file. UTF-8 and Shift_JIS are detected automatically, and the domain column is found automatically (you can change it).
3. **Check**: thousands of domains in one go; stop any time.
4. Export with **Copy table (TSV)** for Excel / Google Sheets, **Download CSV** (UTF-8 with BOM) or **JSON**.

## How it works

1. Each input is reduced to the organization's domain. If there is no MX record, the parent domain is tried, and related domains (example.jp ⇔ example.co.jp ⇔ example.com) are checked as a hint.
2. **MX** host names are matched against a signature database of 117 providers (`VENDORS` in `rules.js`).
3. When the MX host is not a known provider (many Japanese hosts point MX at the customer's own domain), the **reverse DNS (PTR)** of the MX IP, server names in SPF such as `a:sv####.xserver.jp`, the **AS number** (via Team Cymru's DNS service) and the name servers are used to tell a hosting provider from an on-premises server on a business ISP line or a self-managed server on IaaS.
4. **SPF** includes, **DKIM** selectors (`google._domainkey`, `selector1._domainkey`) and **autodiscover** reveal the platform behind a security gateway (Proofpoint, Trend Micro and others).
5. **DMARC** presence and policy are shown as well.

The tool never connects to the mail servers themselves — it only reads DNS.

## Prospect ratings

| Mark | Meaning |
|---|---|
| ◎ Strong | Web hosting, ISP mail or a self-managed server (on-premises or IaaS) — the easiest case for moving to Google Workspace |
| ○ Competing SaaS | Microsoft 365, LINE WORKS, CYBERMAIL, Zoho and other cloud suites — a replacement opportunity |
| △ Check | The platform behind a gateway could not be read, among other cases |
| ✕ Not a target | Already on Google Workspace, or the domain receives no email |

## Tests and tools

- `node test/parse.test.mjs` — unit tests for the paste parser (no DNS)
- `node test/run.mjs` — regression test against about 200 real organizations with known platforms (uses live DNS)
- `node tools/check_i18n.js` — checks every translation against English: missing keys, `{placeholders}` and HTML tags

## Limits

- If a company's website domain differs from its email domain, the tool cannot see its email (a hint for related domains is shown).
- Behind a security gateway with no DKIM / autodiscover, the platform behind it cannot be read.
- "On-premises" is inferred from an MX inside the company's own domain on an ISP line or the organization's own AS; it also covers the company's own server housed in a data center.
