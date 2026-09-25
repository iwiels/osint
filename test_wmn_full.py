import asyncio
import json
import unicodedata
from urllib.parse import quote
import httpx

data = json.load(open("data/wmn-data.json", encoding="utf-8"))
sites = data["sites"]

raw_usernames = [
    "[objetivo-1]",
    "[objetivo-2]",
    "𝖌𝖍",
    "[objetivo-3]",
    "[objetivo-6]",
    "@[objetivo-4]",
    "[objetivo-5]",
]

def normalize_user(u: str) -> str:
    cleaned = u.strip().lstrip("@")
    # Normalizar fuentes fraktur / matemáticas / unicode
    return unicodedata.normalize("NFKD", cleaned)

def is_wmn_match(site: dict, response_code: int, response_text: str) -> bool:
    e_code = site.get("e_code")
    e_str = site.get("e_string")
    m_code = site.get("m_code")
    m_str = site.get("m_string")

    if m_code and response_code == m_code:
        return False
    if m_str and m_str in response_text:
        return False
    if e_code and response_code != e_code:
        return False
    if e_str and e_str not in response_text:
        return False

    if e_code or e_str:
        return True
    return response_code == 200

async def check_site(client: httpx.AsyncClient, site: dict, username: str):
    url = site["uri_check"].replace("{account}", quote(username))
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }
    if "headers" in site and isinstance(site["headers"], dict):
        headers.update(site["headers"])

    try:
        r = await client.get(url, headers=headers, timeout=4.0, follow_redirects=True)
        if is_wmn_match(site, r.status_code, r.text):
            pretty_url = site.get("uri_pretty", url).replace("{account}", quote(username))
            return {
                "name": site["name"],
                "url": pretty_url,
                "category": site.get("cat", "other"),
            }
    except Exception:
        return None
    return None

async def run():
    print(f"Loaded {len(sites)} sites from WhatsMyName database.")
    limits = httpx.Limits(max_connections=80, max_keepalive_connections=20)
    async with httpx.AsyncClient(limits=limits) as client:
        for raw_u in raw_usernames:
            norm_u = normalize_user(raw_u)
            users_to_test = [norm_u]
            if raw_u != norm_u:
                users_to_test.append(raw_u)

            print(f"\n==========================================")
            print(f"Target: {raw_u} (normalized: {norm_u})")
            print(f"==========================================")

            for target in users_to_test:
                tasks = [check_site(client, s, target) for s in sites]
                results = await asyncio.gather(*tasks)
                matches = [m for m in results if m is not None]
                print(f"Scan for '{target}' -> {len(matches)} matches found:")
                for m in matches:
                    print(f"  [{m['category']}] {m['name']}: {m['url']}")

if __name__ == "__main__":
    asyncio.run(run())
