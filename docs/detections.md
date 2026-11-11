# Detection catalog

Every signal UniPhish 2.0.0 can emit: **200 signals across 12 analyzers**. This page is **generated** from the `signals` declarations of the registered analyzers (`uniphish.core.analyzer.signal_catalog()`), so it cannot drift from the code.

```bash
# regenerate the raw list yourself
uniphish catalog                 # table
uniphish catalog --json          # machine-readable
uniphish catalog -a kits         # one analyzer
uniphish catalog -s clipboard    # search ids and titles
curl localhost:8080/v1/meta/analyzers   # same data over the API
```

This file lists *what can fire*. It does not list weights: each signal's weight, confidence and evidence are decided at run time and shown in every verdict (see [architecture](architecture.md#fusion-how-a-verdict-is-computed)). Signal weights are hand-set log-odds priors on the scale below, **not** fitted likelihood ratios.

## How to read a signal

| Part | Meaning |
|---|---|
| `id` | Lower-case dotted id, namespaced by area (`brand.idn`, `page.clickfix_lure`). Stable; safe to key rules on. |
| title | Plain-language headline shown to users (<= 70 chars). |
| category | Evidence family. Signals in the same family are **damped** when fused (correlated evidence); different families add up. |
| weight | Signed log-odds. Positive = phishing evidence, negative = legitimacy evidence. |

Weight scale used by every analyzer:

| Weight | Reads as | Typical example |
|---|---|---|
| +6 to +8 | decisive | AiTM kit fingerprint, ClickFix payload |
| +3 to +5 | strong | brand homoglyph, credential form posting to a foreign host |
| +1 to +2 | moderate | abused TLD, new domain, urgency language, shortener |
| +0.2 to +1 | weak / contextual | many hyphens, lure word in the path |
| -1 to -4 | legitimacy | official brand domain, top-ranked site, aligned DMARC pass |

## Analyzers at a glance

| Analyzer | Reads | Stage | Network | Signals | What it looks at |
|---|---|---|---|---|---|
| [`url`](#url) | url | 0 | offline | 41 | URL structure, IDN/homoglyph spoofing and brand impersonation: emits explainable signals, IOCs, the impersonated brand, techniques and redirect-target child artifacts. |
| [`ml`](#ml) | url | 0 | offline | 3 | Byte-level CNN URL classifier (NumPy runtime) with occlusion saliency |
| [`page`](#page) | page | 0 | offline | 12 | HTML structure: credential forms, brand/content mismatch, obfuscation, ClickFix |
| [`kits`](#kits) | page | 0 | offline | 22 | Phishing-kit fingerprints: AiTM reverse proxies, ClickFix, Browser-in-the-Browser, OAuth/device-code, callback and wallet-drainer pages |
| [`injection`](#injection) | page, text | 0 | offline | 6 | Prompt injection aimed at AI agents: instruction override, role hijack, data exfiltration/leakage, tool abuse, including hidden and obfuscated (Unicode-tag/zero-width/homoglyph/base64) payloads. |
| [`text`](#text) | text | 0 | offline | 8 | Smishing / chat / social-engineering language (urgency, authority, OTP, payment, callback, crypto asks) plus link extraction and brand-link mismatch |
| [`email`](#email) | email | 0 | offline | 29 | Email headers, SPF/DKIM/DMARC, sender spoofing, BEC language, child fan-out |
| [`file`](#file) | file | 0 | offline | 54 | Attachments: disguised executables, macros, encrypted archives, HTML/SVG smuggling, PDF actions, QR codes; extracts embedded URLs as children |
| [`reputation`](#reputation) | email, url | 10 | offline | 7 | Local IOC allow/deny DB, Tranco top-site legitimacy (never for LOTS hosts), domain novelty, and optional Safe Browsing / VirusTotal / urlscan.io lookups |
| [`infra`](#infra) | url | 20 | online | 12 | Infrastructure: domain age (RDAP), TLS certificate, DNS and hosting ASN |
| [`fetch`](#fetch) | url | 30 | online | 3 | Safely fetches the URL and follows its redirect chain; exposes the landing page as a child artifact and flags risky redirect hand-offs |
| [`detonate`](#detonate) | url | 30 | detonation | 3 | Renders the URL in a hardened sandboxed headless browser to detect cloaking, runtime clipboard writes (ClickFix) and client-side redirects |

Stages run in order (0 static, 10 uses earlier results, 20 network enrichment, 30 active fetch / sandbox); analyzers inside a stage run concurrently. *Offline* analyzers always run. *Online* analyzers run only when the scan is online (`--online`, `online: true` and the server operator allowing it). `fetch` additionally needs `fetch_pages`, and `detonate` needs `detonate` plus an installed Playwright browser.

One signal family is not declared by any analyzer: the engine adds `engine.child.<kind>` (category `child`) to a parent artifact when one of its children (an email's link, an attachment, a QR payload) is suspicious or malicious. It carries 90 % of the child's log-odds excess over the prior.

---

## url

URL structure, IDN/homoglyph spoofing and brand impersonation: emits explainable signals, IOCs, the impersonated brand, techniques and redirect-target child artifacts. Reads `url`; stage 0; works offline. **41 signals.**

| Signal id | What it means |
|---|---|
| `brand.bitsquat` | Domain differs from a brand by one flipped bit |
| `brand.combosquat` | Brand name combined with extra words in the domain |
| `brand.content` | Page content impersonates a brand |
| `brand.homoglyph` | Domain imitates a brand using look-alike characters |
| `brand.idn` | Internationalised domain imitates a brand |
| `brand.official` | URL belongs to the brand's official domain (legitimacy evidence) |
| `brand.path` | Brand name appears in the URL path of an unrelated site |
| `brand.sender` | Sender impersonates a brand |
| `brand.subdomain` | Brand name placed in a sub-domain of an unrelated site |
| `brand.typosquat` | Domain is a typo-variant of a brand |
| `unicode.bidi_control` | Host contains bidirectional control characters |
| `unicode.combining_mark` | Host stacks combining marks on Latin letters |
| `unicode.confusable_host` | Host contains characters that imitate ASCII letters |
| `unicode.dangerous_char` | Host contains characters that imitate URL delimiters |
| `unicode.digit_lookalike` | Host contains characters that imitate digits |
| `unicode.disallowed_char` | Host contains disallowed identifier characters |
| `unicode.invisible_char` | Host contains invisible characters |
| `unicode.mixed_script_host` | Host mixes characters from multiple writing systems |
| `unicode.punycode` | Host uses punycode (xn--) encoding |
| `unicode.punycode_lookalike` | Punycode host decodes to a look-alike domain |
| `unicode.skeleton_matches_top_domain` | Host is a look-alike of a popular domain |
| `unicode.whole_script_confusable` | A whole host label in another script reads as Latin |
| `url.at_redirect` | Deceptive text before '@' in the URL |
| `url.credential_lure_host` | Host contains sign-in / security lure words |
| `url.credential_lure_path` | Path contains sign-in / security lure words |
| `url.dangerous_scheme` | URL uses a data:/javascript: scheme carrying inline content |
| `url.double_encoding` | URL uses double percent-encoding to hide content |
| `url.double_extension` | File in the path uses a deceptive double extension |
| `url.dynamic_dns` | Host is on a dynamic-DNS service |
| `url.ip_host` | Link uses a raw IP address as the host |
| `url.ip_obfuscation` | IP address written in an obfuscated numeric form |
| `url.long_url` | Unusually long URL |
| `url.lots_hosting` | Hosted on a legitimate platform anyone can publish on |
| `url.many_hyphens` | Unusually many hyphens in the host |
| `url.many_subdomains` | Excessive sub-domain labels hide the real domain |
| `url.non_standard_port` | Connection uses a non-standard port |
| `url.open_redirect` | URL abuses an open-redirect endpoint |
| `url.random_label` | Host label looks randomly generated |
| `url.shortener` | URL uses a link-shortening service |
| `url.suspicious_file_ext` | Path points at a dangerous downloadable file |
| `url.suspicious_tld` | Top-level domain is frequently abused for phishing |

## ml

Byte-level CNN URL classifier (NumPy runtime) with occlusion saliency. Reads `url`; stage 0; works offline. **3 signals.**

| Signal id | What it means |
|---|---|
| `ml.cnn.benign` | Byte-level ML model rates this URL as likely legitimate |
| `ml.cnn.phishing` | Byte-level ML model rates this URL as likely phishing |
| `ml.cnn.salient_chars` | Characters that drove the ML model's score |

## page

HTML structure: credential forms, brand/content mismatch, obfuscation, ClickFix. Reads `page`; stage 0; works offline. **12 signals.**

| Signal id | What it means |
|---|---|
| `brand.content_mismatch` | Page presents a brand it does not belong to |
| `brand.favicon_mismatch` | Page uses a brand's favicon on an unrelated domain |
| `page.brand_consistent` | Page branding matches the official domain serving it |
| `page.clickfix_lure` | Page tells the visitor to paste a command into Run or a terminal |
| `page.clipboard_write` | Page script writes to the clipboard |
| `page.form.otp_offsite` | One-time-code form posts to a different website |
| `page.form.password_cross_origin` | Password form posts to a different website |
| `page.form.password_data_uri` | Password form submits to an inline data: URI |
| `page.form.password_offsite_js` | Password form is submitted by script to an outside site |
| `page.iframe_hidden_offsite` | Page hides an embedded frame from another website |
| `page.meta_refresh_offsite` | Page automatically redirects to another website |
| `page.obfuscated_script` | Page contains packed or obfuscated inline script |

## kits

Phishing-kit fingerprints: AiTM reverse proxies, ClickFix, Browser-in-the-Browser, OAuth/device-code, callback and wallet-drainer pages. Reads `page`; stage 0; works offline. **22 signals.**

| Signal id | What it means |
|---|---|
| `kit.aitm.google_accounts_assets` | Password page loads Google Accounts sign-in assets from another host |
| `kit.aitm.ms_ests_config` | Proxied Microsoft sign-in page served from a non-Microsoft host |
| `kit.aitm.ms_login_assets` | Password page loads Microsoft sign-in assets from another host |
| `kit.bitb.fake_window` | Fake browser window with its own address bar and a password field |
| `kit.captcha.fake_gate` | "Verify you are human" page without any real CAPTCHA provider |
| `kit.clickfix.captcha_paste` | Fake human-verification page tells you to paste a command (ClickFix) |
| `kit.clickfix.command_staged` | Clipboard script stages a download-and-run style command |
| `kit.clickfix.run_dialog_clipboard` | Page copies text to clipboard and tells you to paste it into Run |
| `kit.clickfix.run_dialog_text` | Page instructs you to paste text into the Run dialog or a terminal |
| `kit.drainer.approval_flow` | Wallet-connect page with token-approval calls and a claim lure |
| `kit.drainer.connect_lure` | "Connect/validate your wallet to claim" lure text |
| `kit.drainer.seed_phrase_form` | Page asks you to type a wallet recovery (seed) phrase into a form |
| `kit.generic.cloned_page_comment` | Cloned login page ("saved from url" comment) with a password field |
| `kit.generic.devtools_block` | Login page blocks right-click and developer tools |
| `kit.generic.discord_webhook_exfil` | Password page contains a Discord webhook for exfiltration |
| `kit.generic.form_handler_script` | Password form posts to a kit-style handler script on another site |
| `kit.generic.telegram_exfil` | Password page contains a Telegram bot API endpoint for exfiltration |
| `kit.generic.victim_email_fragment` | Page decodes the victim's address from the URL fragment |
| `kit.oauth.consent_clone` | Imitation of an OAuth "Permissions requested" consent screen |
| `kit.oauth.device_code_lure` | Page asks you to enter a code at a device-login address |
| `kit.toad.billing_callback` | Fake charge or subscription notice urging you to phone a number |
| `kit.toad.tech_support` | Fake virus or security alert urging you to call "support" |

## injection

Prompt injection aimed at AI agents: instruction override, role hijack, data exfiltration/leakage, tool abuse, including hidden and obfuscated (Unicode-tag/zero-width/homoglyph/base64) payloads. Reads `page`, `text`; stage 0; works offline. **6 signals.**

| Signal id | What it means |
|---|---|
| `agent.injection.data_leak` | Content asks an AI agent to reveal its hidden system prompt |
| `agent.injection.exfiltration` | Content tells an AI agent to send data to an attacker |
| `agent.injection.instruction_override` | Content tells an AI agent to ignore its instructions |
| `agent.injection.obfuscation` | Hidden or encoded instructions aimed at an AI agent |
| `agent.injection.role_hijack` | Content fakes system/assistant turns to hijack an AI agent |
| `agent.injection.tool_abuse` | Content tells an AI agent to run commands or approve actions |

## text

Smishing / chat / social-engineering language (urgency, authority, OTP, payment, callback, crypto asks) plus link extraction and brand-link mismatch. Reads `text`; stage 0; works offline. **8 signals.**

| Signal id | What it means |
|---|---|
| `social.brand_link_mismatch` | Message names a brand but links to an unrelated site |
| `social.callback_number` | Message pushes you to call a phone number |
| `social.crypto_seed_request` | Message asks for a crypto wallet recovery phrase |
| `social.link_in_pressure_message` | Pressure message pushes you to open a link |
| `social.otp_request` | Message asks you to hand over a one-time code |
| `social.payment_request` | Message asks for a payment, gift cards or a wire transfer |
| `social.pressure` | Message uses pressure tactics typical of phishing |
| `social.urgent_credential_ask` | Urgent request to verify or enter account credentials |

## email

Email headers, SPF/DKIM/DMARC, sender spoofing, BEC language, child fan-out. Reads `email`; stage 0; works offline. **29 signals.**

| Signal id | What it means |
|---|---|
| `auth.aligned_pass` | Authenticated as its own From domain (DMARC aligned) |
| `auth.aligned_pass.known` | Authenticated as a well-known sender (DMARC aligned) |
| `auth.dkim.fail` | DKIM signature failed verification |
| `auth.dmarc.fail` | DMARC failed for the sender's domain |
| `auth.dmarc.unaligned` | Message did not authenticate as the From domain |
| `auth.forged_results` | Sender planted a fake Authentication-Results header |
| `auth.spf.fail` | SPF check failed for the sending server |
| `auth.spf.softfail` | SPF soft-failed for the sending server |
| `brand.sender.display_name` | Sender name claims a brand the address does not belong to |
| `brand.sender.lookalike_domain` | Sender domain imitates a known brand |
| `email.attachment.bidi_filename` | Attachment name uses a right-to-left override |
| `email.bec.mobile_excuse` | 'Sent from mobile' excuse combined with reply redirection |
| `email.bec.payment_pressure` | No-link payment/gift-card demand from a suspect sender |
| `email.bec.payment_secrecy` | Confidential payment request with no links |
| `email.header.date_skew` | Date header disagrees with the first Received timestamp |
| `email.header.duplicate_from` | Message has multiple From headers or addresses |
| `email.header.malformed` | Message headers are malformed in a way used to evade filters |
| `email.header.missing_fields` | Message lacks standard Date or Message-ID headers |
| `email.html.hidden_text` | HTML hides text from the reader |
| `email.link.anchor_mismatch` | Link text shows one site but goes to another |
| `email.link.dangerous_scheme` | Link uses a javascript: or data: address |
| `email.message_id.domain_mismatch` | Message-ID domain differs from the From domain |
| `email.received.dynamic_origin` | Message originated from a dynamic/residential host |
| `email.reply_to.mismatch` | Replies are redirected to a different domain |
| `email.return_path.mismatch` | Envelope sender domain differs from the From domain |
| `email.sender.display_name_domain` | Sender name embeds a different domain or address |
| `social.email.callback_number` | Email pushes the reader to phone a number (callback scam) |
| `social.email.otp_request` | Email asks the reader to hand over a one-time code |
| `social.email.pressure` | Email uses pressure and manipulation language |

## file

Attachments: disguised executables, macros, encrypted archives, HTML/SVG smuggling, PDF actions, QR codes; extracts embedded URLs as children. Reads `file`; stage 0; works offline. **54 signals.**

| Signal id | What it means |
|---|---|
| `file.archive.bomb` | Archive declares an extreme expansion ratio (zip bomb) |
| `file.archive.disguised_entry` | Archive entry has a double extension or RTLO name |
| `file.archive.encrypted` | Password-protected archive hides its contents from scanners |
| `file.archive.executable_entry` | Archive contains an executable or script entry |
| `file.archive.malformed` | Archive structure is corrupt or unreadable |
| `file.archive.nested` | Archive contains another archive or disk image |
| `file.archive.path_traversal` | Archive entry names escape the extraction folder |
| `file.archive.single_payload` | Archive wraps a single executable/script/shortcut/macro file |
| `file.archive.too_many_entries` | Archive has too many entries to inspect safely |
| `file.disguised_executable` | Executable disguised under a harmless extension |
| `file.double_extension` | Double extension hides the real file type |
| `file.executable.packed` | Executable is packed or encrypted (very high entropy) |
| `file.ext_mismatch` | File content does not match its extension |
| `file.html.data_uri_navigation` | Link/frame points at an embedded data: document |
| `file.html.external_form_action` | Attached page form posts to a remote URL |
| `file.html.large_base64` | Very large base64 blob embedded in the document |
| `file.html.meta_refresh` | Attached page redirects via meta refresh |
| `file.html.obfuscated_script` | Heavily obfuscated script (eval/atob/escape chains) |
| `file.html.password_form` | Attached page contains a password field |
| `file.html.smuggling.pattern` | Blob + download-anchor pattern (HTML smuggling) |
| `file.html.smuggling.payload` | Embedded base64 blob decodes to an executable/archive |
| `file.lnk.command` | Shortcut embeds an interpreter command line |
| `file.office.autoexec` | Macro runs automatically when the document opens |
| `file.office.dde` | Document uses DDE field execution |
| `file.office.embedded_object` | Document embeds an OLE/ActiveX object |
| `file.office.external_object` | Document links an external OLE object or frame |
| `file.office.macro` | Office document contains VBA macros |
| `file.office.protocol_handler` | Document references a risky URL protocol handler |
| `file.office.remote_template` | Document loads a remote template (template injection) |
| `file.office.suspicious_keywords` | Macro uses download/execute/obfuscation keywords |
| `file.office.xlm_macro` | Excel 4.0 (XLM) macro sheet present |
| `file.pdf.embedded_file` | PDF embeds another file |
| `file.pdf.javascript` | PDF contains JavaScript |
| `file.pdf.launch` | PDF can launch an external program or file |
| `file.pdf.obfuscated_names` | PDF keywords are hex-escaped to evade scanners |
| `file.pdf.open_action` | PDF runs an action automatically on open |
| `file.pdf.submit_form` | PDF form submits data to a remote server |
| `file.pdf.uri` | PDF contains outbound link(s) |
| `file.rtlo_filename` | Filename uses a right-to-left override to fake its extension |
| `file.script.suspicious_commands` | Script downloads or runs hidden/encoded commands |
| `file.svg.event_handler` | SVG element has an on* event handler |
| `file.svg.external_link` | SVG is wrapped in a clickable external link |
| `file.svg.external_ref` | SVG loads external content |
| `file.svg.foreign_object` | SVG embeds HTML via foreignObject |
| `file.svg.redirect` | SVG script redirects the browser |
| `file.svg.script` | SVG image contains script |
| `file.svg.xml_entities` | SVG declares XML entities (entity-expansion attack) |
| `file.type.disk_image` | Disk image (ISO/IMG/VHD) used to dodge mark-of-the-web |
| `file.type.executable` | Executable program delivered as a file |
| `file.type.html_attachment` | HTML document delivered as a file |
| `file.type.onenote` | OneNote file delivered as a file (embedded-object lure) |
| `file.type.script` | Script file (JS/VBS/PowerShell/batch/HTA) delivered as a file |
| `file.type.shortcut` | Windows shortcut (.lnk) delivered as a file |
| `qr.url_in_image` | Image carries a QR code that points to a web address |

## reputation

Local IOC allow/deny DB, Tranco top-site legitimacy (never for LOTS hosts), domain novelty, and optional Safe Browsing / VirusTotal / urlscan.io lookups. Reads `email`, `url`; stage 10; works offline. **7 signals.**

| Signal id | What it means |
|---|---|
| `rep.local_allowlist` | Observable is on the local allow list |
| `rep.local_denylist` | Observable is on the local deny list |
| `rep.never_seen` | Domain has never been seen before by this installation |
| `rep.safebrowsing` | Google Safe Browsing lists this URL as unsafe |
| `rep.top_site` | Domain is a long-established, highly ranked site |
| `rep.urlscan` | urlscan.io judged this host malicious |
| `rep.virustotal` | VirusTotal engines flag this domain |

## infra

Infrastructure: domain age (RDAP), TLS certificate, DNS and hosting ASN. Reads `url`; stage 20; online only. **12 signals.**

| Signal id | What it means |
|---|---|
| `infra.asn.brand_on_abuse_hosting` | Brand lookalike hosted on an abuse-prone network |
| `infra.asn.brand_on_residential` | Brand lookalike hosted on a consumer-ISP-like network |
| `infra.cert.free_ca_brand` | Free-CA certificate on a brand-impersonating site |
| `infra.cert.fresh` | TLS certificate issued less than 7 days ago |
| `infra.cert.san_mismatch` | TLS certificate does not cover this host name |
| `infra.cert.self_signed` | Self-signed certificate on a login-style page |
| `infra.dns.fast_flux` | Many low-TTL addresses across unrelated networks (fast-flux) |
| `infra.dns.no_mx` | Login/brand-style domain has no mail exchanger |
| `infra.domain.age_gt_2y` | Domain registered more than two years ago |
| `infra.domain.age_lt_30d` | Domain registered less than 30 days ago |
| `infra.domain.age_lt_7d` | Domain registered less than 7 days ago |
| `infra.domain.age_lt_90d` | Domain registered less than 90 days ago |

## fetch

Safely fetches the URL and follows its redirect chain; exposes the landing page as a child artifact and flags risky redirect hand-offs. Reads `url`; stage 30; online only. **3 signals.**

| Signal id | What it means |
|---|---|
| `fetch.landing_data_uri` | Redirect chain ends at an inline data: URI |
| `fetch.redirect_cross` | Redirect chain crosses into a risky or unrelated host |
| `fetch.ssrf_blocked` | Page tried to redirect the scanner to a private address |

## detonate

Renders the URL in a hardened sandboxed headless browser to detect cloaking, runtime clipboard writes (ClickFix) and client-side redirects. Reads `url`; stage 30; needs detonation. **3 signals.**

| Signal id | What it means |
|---|---|
| `fetch.cloaking` | Rendered page differs materially from the static HTML |
| `fetch.js_redirect` | Page uses script to redirect to another site when rendered |
| `fetch.runtime_clipboard` | Page writes to the clipboard when rendered (ClickFix) |

