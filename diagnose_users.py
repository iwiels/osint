import httpx
from urllib.parse import quote

usernames = ["[objetivo-1]", "[objetivo-2]", "𝖌𝖍", "[objetivo-3]", "[objetivo-6]", "[objetivo-4]", "[objetivo-5]"]

platforms = {
    "GitHub": ("https://api.github.com/users/{}", "status_200"),
    "DockerHub": ("https://hub.docker.com/v2/users/{}", "status_200"),
    "HackerNews": ("https://hacker-news.firebaseio.com/v0/user/{}.json", "hn_json"),
    "Keybase": ("https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "keybase_json"),
    "Telegram": ("https://t.me/{}", "telegram_body"),
    "Reddit": ("https://www.reddit.com/user/{}/about.json", "reddit_json"),
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

with httpx.Client(headers=headers, timeout=4.0, follow_redirects=True) as client:
    for u in usernames:
        print(f"Target: {u}")
        found = False
        for name, (url_tpl, ctype) in platforms.items():
            url = url_tpl.format(quote(u))
            try:
                r = client.get(url)
                if ctype == "status_200" and r.status_code == 200:
                    print(f"  [+] {name}: https://{name.lower()}.com/{u}")
                    found = True
                elif ctype == "hn_json" and r.status_code == 200:
                    data = r.json()
                    if data is not None:
                        print(f"  [+] HackerNews: id={data.get('id')} karma={data.get('karma')}")
                        found = True
                elif ctype == "keybase_json" and r.status_code == 200:
                    data = r.json()
                    if data.get("them") and data["them"][0] is not None:
                        print(f"  [+] Keybase: https://keybase.io/{u}")
                        found = True
                elif ctype == "telegram_body" and r.status_code == 200:
                    if "tgme_page_action" in r.text and "View in Telegram" in r.text:
                        print(f"  [+] Telegram: https://t.me/{u}")
                        found = True
            except Exception as e:
                pass
        if not found:
            print("  [-] Sin coincidencias públicas directas en este conjunto de plataformas.")
        print()
