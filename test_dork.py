import httpx
import re
from urllib.parse import unquote

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

r = httpx.post("https://html.duckduckgo.com/html/", data={"q": "[objetivo-6]"}, headers=headers, timeout=10.0)
matches = re.findall(r'<a class="result__snippet"[^>]*href="([^"]+)"', r.text)
if not matches:
    matches = re.findall(r'<a[^>]+class="result__url"[^>]*href="([^"]+)"', r.text)
if not matches:
    matches = re.findall(r'href="([^"]*uddg=[^"]*)"', r.text)

print("Found matches count:", len(matches))
for m in matches[:5]:
    if "uddg=" in m:
        extracted = unquote(m.split("uddg=")[1].split("&")[0])
        print("  Real URL:", extracted)
    else:
        print("  Direct link:", m)
