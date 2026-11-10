# Spec: domain permutation engine + brand watch
OWN: uniphish/hunt/permutations.py, uniphish/hunt/brandwatch.py, tests/hunt/
test_permutations.py, tests/hunt/test_brandwatch.py. Depends on uniphish.url.confusables
(a1), uniphish.url.brandkb (a2), uniphish.assets.lists (a3, tlds), engine/infra for
optional liveness. Pure-compute core; optional online liveness check.

permutations.py: generate_permutations(domain, *, kinds=all, max=...) -> list[Permutation(
domain, kind, note)] — a dnstwist-class generator for DEFENSIVE monitoring of look-alikes
of YOUR OWN domain: kinds = homoglyph (confusables.lookalikes_of per char),
typo (insertion/omission/repetition/transposition/replacement on adjacent-key or general),
bitsquat (single bit flips), hyphenation, subdomain-insertion, combosquat
(brand+keyword from lures), tld-swap (over the abused + common TLDs), omission/addition,
vowel-swap, double-char, punycode/idn-homograph (ascii->confusable homograph then puny).
Dedupe; bound output; valid-domain output only.
brandwatch.py: class BrandWatch(engine=None, store=None): watch(domain_or_brand) ->
generate permutations and (offline) score each as a potential impersonation (reuse
url.brands + techniques), returning ranked candidate look-alikes; async check_live(perms)
(optional, online) resolves which permutations currently exist (DNS via core.net) and
scores live ones higher; persist findings to the store/hunt_events. A convenience
monitor_brand(brand_id) using BrandKB official_domains.
TESTS (offline): permutations for 'paypal.com' include the known homoglyph/typo/tld-swap
forms and exclude the exact domain; counts bounded; brandwatch ranks obvious look-alikes
above noise; no network (mock liveness).
