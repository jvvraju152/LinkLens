"""Build data/independent_holdout.csv, the holdout used to judge the detector after tuning.

Written AFTER the round-2 rules were frozen and never used to change a rule. Reproducible: `python tools/build_holdout_v2.py`.

Be clear about what it is and is not:
* Legitimate URLs are real, widely used sites (recalled from memory of popular domains, not a Tranco export)
  plus first-party domains deliberately NOT in the detector's allow-lists, to measure how far allow-lists generalise.
* Phishing URLs are synthetic. ~100 come from a seeded generator whose brand pool mixes brands the detector knows
  and brands it does not; the rest are hand-written, including patterns the rules were not designed for.
* It is independent of the tuning, NOT of the author. For genuine independence use tools/build_feed_dataset.py.
"""
import csv
import ipaddress
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "independent_holdout.csv"
DEV = ROOT / "data" / "labelled_urls.csv"
L, P = "benign", "phishing"
rows = []


def add(label, cat, src, urls):
    rows.extend((u, label, cat, "holdout", src) for u in urls.split())


# ------------------------------------------------------------------ legitimate
add(L, "top-sites", "recalled-top-sites", """
https://www.google.com/ https://www.youtube.com/ https://www.facebook.com/ https://www.baidu.com/
https://en.wikipedia.org/wiki/Computer_security https://www.instagram.com/ https://x.com/home https://www.linkedin.com/
https://www.reddit.com/ https://www.netflix.com/ https://www.amazon.com/ https://www.microsoft.com/ https://www.apple.com/
https://github.com/ https://stackoverflow.com/ https://www.bbc.com/ https://www.cnn.com/ https://www.nytimes.com/
https://www.theguardian.com/international https://timesofindia.indiatimes.com/ https://www.ndtv.com/
https://www.hindustantimes.com/ https://www.flipkart.com/ https://www.myntra.com/ https://www.yahoo.com/ https://www.bing.com/
https://duckduckgo.com/ https://www.cloudflare.com/ https://wordpress.com/ https://medium.com/ https://www.quora.com/
https://www.pinterest.com/ https://www.twitch.tv/ https://open.spotify.com/ https://www.imdb.com/ https://www.espn.com/
https://weather.com/ https://www.booking.com/ https://www.airbnb.com/ https://www.uber.com/ https://www.tripadvisor.com/
https://www.etsy.com/ https://www.ebay.com/ https://www.walmart.com/ https://www.target.com/ https://www.bestbuy.com/
https://www.nike.com/ https://www.ikea.com/ https://slack.com/ https://www.notion.so/ https://www.figma.com/
https://www.canva.com/ https://www.box.com/ https://www.adobe.com/ https://www.salesforce.com/ https://www.oracle.com/
https://www.ibm.com/ https://www.intel.com/ https://www.nvidia.com/ https://www.mozilla.org/ https://www.npmjs.com/
https://www.docker.com/ https://kubernetes.io/ https://www.w3schools.com/ https://developer.mozilla.org/en-US/
https://www.udemy.com/ https://www.edx.org/ https://www.un.org/ https://www.nih.gov/ https://www.cdc.gov/ https://www.irs.gov/
https://www.usa.gov/ https://www.nhs.uk/ https://www.tesco.com/ https://www.barclays.co.uk/ https://www.hsbc.com/
https://www.santander.com/ https://www.americanexpress.com/ https://www.mastercard.com/ https://www.visa.com/
https://www.dhl.de/ https://zoom.us/ https://telegram.org/ https://www.tiktok.com/ https://www.snapchat.com/
https://discord.com/ https://www.dropbox.com/ https://www.binance.us/ https://www.usps.com/ https://opensea.io/
https://www.uniswap.org/ https://www.chase.com/ https://www.citi.com/ https://www.royalmail.com/
""")
add(L, "login-pages-legit", "curated-legit", """
https://accounts.snapchat.com/accounts/login https://login.salesforce.com/ https://github.com/login/device
https://gitlab.com/users/sign_in https://www.reddit.com/login/ https://login.yahoo.com/ https://www.twitch.tv/login
https://discord.com/login https://secure.chase.com/web/auth/ https://account.microsoft.com/security
https://account.apple.com/sign-in https://www.paypal.com/myaccount/summary https://myaccount.google.com/security-checkup
https://id.atlassian.com/login?application=jira https://www.facebook.com/login/ https://login.microsoftonline.com/common/login
https://signin.aws.amazon.com/console https://auth.openai.com/log-in https://www.amazon.com/ap/signin
""")
add(L, "first-party-listed", "curated-legit", """
https://drive.google.com/drive/my-drive https://docs.google.com/document/d/abc123/edit https://calendar.google.com/calendar/u/0/r
https://outlook.live.com/mail/0/ https://onedrive.live.com/about/en-us/ https://www.office.com/launch/word
https://s3.amazonaws.com/bucket/file.pdf https://developer.amazon.com/alexa https://www.gstatic.com/images/branding/product/1x/gmail_48dp.png
https://www.google.com/url?q=https://www.python.org/&sa=D https://www.microsoft.com/en-us/security/blog/
""")
add(L, "first-party-unlisted", "curated-legit", """
https://chromium.googlesource.com/chromium/src https://groups.google.com/g/golang-nuts https://www.googlegroups.com/
https://mail.googlemail.com/ https://www.amazonpay.in/ https://www.microsoft365.com/ https://www.facebookmail.com/
""")
add(L, "lookalike-but-legit", "curated-legit", """
https://www.citibikenyc.com/ https://www.axis.com/ https://www.dpdgroup.com/ https://www.jiocinema.com/ https://www.jiosaavn.com/
https://www.hdfclife.com/ https://www.sbilife.co.in/ https://www.icicipruamc.com/ https://www.paytmmall.com/
https://www.freecodecamp.org/news/ https://www.securityweek.com/ https://www.accountingtoday.com/
""")
add(L, "ip-host-legit", "curated-legit", "https://1.0.0.1/ https://8.8.4.4/ https://104.16.132.229/")
add(L, "long-url", "curated-legit", """
https://www.google.com/search?q=best+laptops+under+60000&oq=best+laptops+under+60000&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIHCAEQIRigATIHCAIQIRigAdIBCDU3MjFqMGo3qAIAsAIA&sourceid=chrome&ie=UTF-8
https://www.youtube.com/watch?v=aqz-KE-bpKQ&list=PLabcdefghijklmnopqrstuvwxyz012345&index=4&t=120s&ab_channel=Demo&pp=iAQB
https://www.amazon.com/dp/B08N5WRWNW/ref=sr_1_2?crid=3ABCDEFGHIJ&keywords=echo+dot&qid=1700000000&sprefix=echo%2Caps%2C200&sr=8-2
""")
add(L, "http-or-port", "curated-legit", "http://neverssl.com:80/ https://httpbin.org:443/get http://www.gutenberg.org/ http://example.net/")
add(L, "download-legit", "curated-legit", """
https://download.mozilla.org/?product=firefox-latest&os=win https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe
https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js https://code.jquery.com/jquery-3.7.1.min.js
https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js
""")
add(L, "shortener", "curated-legit", "https://bit.ly/pricing https://t.co/abc123XYZ")

# ------------------------------------------------------------------ hand-written phishing
add(P, "handwritten-unlisted-brand", "handwritten-phish", """
https://hsbc-secure-login.top/ https://barclays-verify.click/account https://tesco-clubcard-reward.xyz/claim
https://nhs-covid-pass.top/apply https://zoom-meeting-invite.click/join https://docusign-secure-document.top/view
https://adobe-sign-review.xyz/ https://steam-gift-free.top/redeem https://telegram-premium-free.click/
https://snapchat-verify.xyz/ https://twitter-support-ticket.top/ https://airbnb-booking-confirm.xyz/
https://uber-driver-bonus.click/ https://swiggy-refund-help.top/ https://zomato-gold-offer.xyz/claim
https://myntra-sale-winner.top/ https://lic-policy-renew.top/pay https://hsbc-online-secure.com/
""")
add(P, "handwritten-no-brand", "handwritten-phish", """
https://secure-banking-portal.com/login https://xk3j9d-secure.top/login https://a1b2c3d4.xyz/account/verify
https://account-security-center.net/update/password https://congratulations-winner-iphone.top/
https://claim-your-reward-today.xyz/ https://free-netflix-premium.click/ https://lucky-spin-cashback.icu/
https://evil-redirect.top/?u=paypal.com&login=1 https://bank-alert-update.info/verify
""")
add(P, "handwritten-path-only", "handwritten-phish", """
https://lisbon-travel-deals.com/paypal/signin http://my-photo-studio.net/amazon/login.php
https://www.maple-hardware.com/includes/hdfc/verify.php http://www.kids-yoga-studio.org/images/dhl/tracking/login.php
https://www.bluebird-bakery.com/wp-content/uploads/office365/login.php
""")
add(P, "handwritten-typo-homoglyph", "handwritten-phish", """
https://paypa1.net/ https://netfl1x.com/login https://rnicrosoft-support.com/ https://xn--paypl-7ve.com/signin
https://xn--amzon-5ve.com/ap/signin
""")
add(P, "handwritten-ip-userinfo", "handwritten-phish", """
http://45.9.148.114/hdfc/login.html http://5.188.62.20:8080/dhl/track.php https://accounts.google.com@bit-secure.top/
http://www.amazon.in:login@45.9.148.114/ https://paypal.com@login-help.xyz/
""")
add(P, "handwritten-hosting", "handwritten-phish", """
https://hsbc-login.netlify.app/ https://amazon-prime-gift.web.app/ https://paypal-resolution.pages.dev/
https://microsoft-verify.vercel.app/ https://sbi-netbanking.github.io/login/ https://apple-support.glitch.me/
https://myntra-offer.blogspot.com/
""")
add(P, "handwritten-download", "handwritten-phish", """
https://chrome-update-required.top/chrome-setup.exe https://flash-player-update.xyz/install.msi https://secure-pdf-viewer.click/viewer.apk
""")
add(P, "handwritten-redirect-wrapped", "handwritten-phish", """
https://www.bing.com/ck/a?u=https://paypal-secure.top/ https://click.mailer-example.com/r?url=https%3A%2F%2Famazon-refund.top%2F
""")
add(P, "handwritten-trusted-host-abuse", "handwritten-phish", """
https://sites.google.com/view/paypal-help-center https://forms.gle/AbCdEf123456 https://docs.google.com/presentation/d/e/2PACX-demo/pub
https://storage.googleapis.com/secure-docs-bucket/login.html https://www.dropbox.com/s/abc123/Invoice.pdf
""")

# ------------------------------------------------------------------ generated phishing
BRANDS = ["paypal", "amazon", "netflix", "microsoft", "apple", "google", "facebook", "instagram", "whatsapp", "sbi", "hdfc",
          "icici", "axis", "paytm", "phonepe", "flipkart", "irctc", "dhl", "fedex", "usps", "royalmail", "coinbase", "binance",
          "metamask", "chase", "wellsfargo", "hsbc", "barclays", "americanexpress", "linkedin", "dropbox", "adobe", "ebay",
          "spotify", "telegram", "zoom", "airbnb", "uber", "swiggy", "zomato", "myntra", "bsnl", "vodafone", "tesco", "santander"]
KEYWORDS = ["secure", "login", "verify", "update", "account", "support", "help", "billing", "alert", "unlock", "confirm", "kyc",
            "refund", "claim", "rewards", "service", "portal", "customer", "wallet", "payment", "order", "delivery", "track"]
CHEAP = ["top", "xyz", "click", "icu", "buzz", "cyou", "work", "support", "cam"]
COMMON = ["com", "net", "org", "info", "online", "site", "store", "live", "app"]
NEUTRAL = ["cloudnest", "brightway", "oakline", "greenfield", "softedge", "northpeak", "bluerock", "sunvalley", "urbanlane",
           "pixelhub", "datagrove", "skyforge"]
PATHS = ["", "/", "/login", "/signin", "/verify", "/account/update", "/secure/login.php", "/webapps/auth", "/id/unlock", "/claim",
         "/track?id=12345"]
PLATFORMS = ["netlify.app", "web.app", "pages.dev", "vercel.app", "herokuapp.com", "weebly.com", "blogspot.com"]


def typo(rng, w):
    kind = rng.choice(["digit", "double", "drop", "swap"])
    if kind == "digit":
        for a, b in (("o", "0"), ("l", "1"), ("e", "3"), ("a", "4")):
            if a in w:
                i = w.rindex(a)
                return w[:i] + b + w[i + 1:]
        kind = "double"
    i = rng.randrange(1, len(w) - 1)
    if kind == "double":
        return w[:i] + w[i] + w[i:]
    if kind == "drop":
        return w[:i] + w[i + 1:]
    return w[:i] + w[i + 1] + w[i] + w[i + 2:]


def public_ip(rng):
    while True:
        ip = ipaddress.IPv4Address(rng.getrandbits(32))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def generate(n=105, seed=20261018):
    rng = random.Random(seed)
    structures = (["brand-kw"] * 18 + ["kw-brand"] * 14 + ["brand-subdomain"] * 12 + ["glued"] * 10 + ["path-only"] * 12 +
                  ["hosting"] * 10 + ["ip"] * 6 + ["typo"] * 8 + ["kw-only"] * 10)
    out = []
    for _ in range(n):
        s = rng.choice(structures)
        b, k, k2 = rng.choice(BRANDS), rng.choice(KEYWORDS), rng.choice(KEYWORDS)
        tld = rng.choice(CHEAP) if rng.random() < 0.55 else rng.choice(COMMON)
        scheme = "https" if rng.random() < 0.75 else "http"
        path = rng.choice(PATHS)
        d = rng.choice(NEUTRAL)
        host = {
            "brand-kw": f"{b}-{k}.{tld}", "kw-brand": f"{k}-{b}.{tld}", "brand-subdomain": f"{b}.com.{k}-{d}.{tld}",
            "glued": f"{b}{k}.{tld}", "path-only": f"{d}-{rng.choice(NEUTRAL)}.{tld}",
            "hosting": f"{b}-{k}.{rng.choice(PLATFORMS)}", "ip": public_ip(rng),
            "typo": f"{typo(rng, b)}.{rng.choice(CHEAP + COMMON)}", "kw-only": f"{k}-{k2}-{rng.choice(['center', 'portal', 'service'])}.{tld}",
        }[s]
        if s == "path-only":
            path = f"/{b}/{rng.choice(['login', 'signin', 'verify'])}.{rng.choice(['php', 'html'])}"
        out.append(f"{scheme}://{host}{path}")
    return out


add(P, "generated", "generated-phish", " ".join(generate()))

# ------------------------------------------------------------------ write
dev = {r["url"] for r in csv.DictReader(open(DEV, encoding="utf-8"))}
seen, final = set(), []
for r in rows:
    if r[0] in dev or r[0] in seen:
        print("dropped duplicate:", r[0], file=sys.stderr)
        continue
    seen.add(r[0])
    final.append(r)
with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["url", "label", "category", "split", "source"])
    w.writerows(final)
print(f"wrote {len(final)} rows: {sum(r[1] == P for r in final)} phishing, {sum(r[1] == L for r in final)} benign")
