# Spec: threat-intel reference data + typed accessors
OWN: uniphish/assets/tlds.yaml, lots.yaml, shorteners.yaml, lures.yaml, freemail.yaml,
dyndns.yaml, open_redirects.yaml, disposable_domains.txt.gz, top_sites.txt.gz,
assets/README.md (sources+licenses), uniphish/assets/lists.py, tests/assets/test_lists.py.

PURPOSE: centralise all reference lists (no hard-coded lists elsewhere). Grounded in
public research; cite sources in README.md.

- tlds.yaml: abused TLDs with a calibrated risk weight (0.3..1.5 log-odds) + notes,
  grounded in public abuse research (Spamhaus most-abused TLDs, Interisle, Netcrath).
  e.g. top, xyz, shop, online, site, icu, cfd, sbs, bond, cyou, buzz, rest, click, link,
  live, cam, monster, quest, lol, mom, zip, mov, tk/ml/ga/cf/gq, pw.
- lots.yaml ('living off trusted sites' — legitimate hosts abused for hosting): kind
  (hosting|serverless|forms|storage|docs|ipfs|tunnel|blog|site_builder|file_share) +
  match (host suffix, optional path prefix). 120+ entries: pages.dev, workers.dev,
  web.app, firebaseapp.com, appspot.com, netlify.app, vercel.app, github.io, gitlab.io,
  glitch.me, repl.co, herokuapp.com, onrender.com, fly.dev, azurewebsites.net,
  blob.core.windows.net, storage.googleapis.com, firebasestorage.googleapis.com,
  sites.google.com, forms.gle, 1drv.ms, forms.office.com, sharepoint.com, dropbox.com/scl,
  weebly/wixsite/webflow.io/notion.site/canva.site, ipfs gateways (ipfs.io, dweb.link,
  w3s.link), tunnels (ngrok-free.app, trycloudflare.com, loca.lt, serveo.net), telegra.ph,
  r2.dev.
- shorteners.yaml (150+), dyndns.yaml (duckdns, no-ip family, afraid.org, dynu),
  freemail.yaml (global + regional incl. qq.com, 163.com, naver.com, mail.ru, yandex,
  gmx, web.de, proton, rediffmail), open_redirects.yaml (well-known open-redirect
  endpoints abused to launder links: google.com/url, bing.com/ck/a, youtube.com/redirect,
  t.co, l.facebook.com/l.php, safelinks.protection.outlook.com, urldefense.com — with the
  parameter name carrying the destination).
- lures.yaml: credential/urgency terms for host/path matching (login, signin, verify,
  account, update, secure, unlock, suspended, invoice, payment, password, auth, sso, mfa,
  2fa, recovery, wallet, billing, refund, delivery, parcel, tax, kyc) in 25+ languages
  (es pt fr de it nl pl ru uk tr ar fa hi+hinglish bn ta zh-Hans zh-Hant ja ko vi id th
  sw tl) — each term: lang, weight, category.
- disposable_domains.txt.gz: curl
  https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf
- top_sites.txt.gz: Tranco top-1M (https://tranco-list.eu/top-1m.csv.zip) -> top 100,000
  registrable domains in rank order. Record list id/date in README. Retry on failure; do
  not fabricate.

lists.py (lazy, cached): tld_risk(suffix)->float|None; lots_match(host,path='')->LotsEntry|None;
is_shortener(host); is_dyndns(host); open_redirect_match(host,path,query)->OpenRedirect|None
(+extracted destination); find_lures(text)->list[LureHit(term,lang,category,weight,start,end)]
(one compiled linear-time matcher; Latin token-aware, CJK substring); is_freemail(domain);
is_disposable(domain); top_rank(registrable)->int|None; is_top_site(registrable,n). Host
suffix matching label-boundary safe.
TESTS: accessors, boundary safety, data integrity, find_lures performance (<50ms/100KB).
