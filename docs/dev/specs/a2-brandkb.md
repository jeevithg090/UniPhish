# Spec: brand knowledge base
OWN: uniphish/assets/brands.yaml, uniphish/url/brandkb.py, tests/url/test_brandkb.py.

PURPOSE: know which brands are commonly impersonated and which domains legitimately
belong to them, so impersonation detection is accurate and false positives are low.
Accuracy of official_domains directly controls false-positive rate — when unsure
whether a brand owns a domain, OMIT it rather than guess.

brands.yaml: >= 250 of the most-impersonated brands worldwide AND by region (global
tech/SaaS incl. Microsoft 365/Outlook/OneDrive/SharePoint/Teams, Google/Gmail/Drive,
Apple/iCloud, Amazon/AWS, Meta family, LinkedIn, Netflix, Adobe, DocuSign, Dropbox,
Zoom, Slack, Okta, Salesforce, GitHub, OpenAI/ChatGPT; banks & card networks; crypto
exchanges & wallets; postal/logistics worldwide; tax/government portals [IRS, HMRC, CRA,
ATO, India income-tax/UIDAI/EPFO, ...]; telcos; marketplaces; gaming; travel; webmail;
strong India/China/Japan/Korea/Middle-East/LatAm/Europe/CIS/Africa coverage).
Per brand: id (snake_case), name, category, regions, official_domains (registrable
domains truly owned), login_hosts (canonical sign-in hosts e.g. login.microsoftonline.com,
accounts.google.com), cdn_hosts (official asset hosts kits hot-link e.g.
aadcdn.msftauth.net), user_content_domains (brand-owned but anyone-can-host:
sharepoint.com, sites.google.com, blogspot.com, github.io, web.app — official status
must NOT apply here), keywords (lowercase ASCII tokens), native_names (names in native
scripts), ambiguous (true for common-word/short names: ups, sbi, line, orange — needs
stronger context), aliases.

brandkb.py: dataclass Brand; class BrandKB: all(), get(id),
official_brand_for_host(host) -> Brand|None (host == or label-boundary subdomain of an
official domain AND not under a user_content_domain), is_user_content_host(host) ->
Brand|None, keyword_index() (longest-first), native_name_index(),
brands_mentioned_in(text) -> list[Brand] (token-aware for Latin, substring for native
scripts, respects ambiguous), cdn_brand_for_host(host). get_kb() cached singleton.
Validate at load (schema, duplicate ids, lowercase domains, no scheme/path). Use simple
suffix logic internally; do NOT import uniphish.url.parse.

TESTS: whole-file schema/consistency, key lookups (login.microsoftonline.com->microsoft;
evil.sharepoint.com is user-content not official; notpaypal.com is not paypal),
multilingual mentions.
