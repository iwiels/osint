import json
import httpx

data = json.load(open("data/wmn-data.json", encoding="utf-8"))
sites = data["sites"]

github_site = next(s for s in sites if s["name"] == "GitHub (User)")
print("Site:", github_site)

user = "[objetivo-6]"
url = github_site["uri_check"].replace("{account}", user)
headers = github_site.get("headers", {})
if "User-Agent" not in headers:
    headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

r = httpx.get(url, headers=headers, timeout=5.0)
print("Response status:", r.status_code)
print("e_string:", repr(github_site["e_string"]))
print("e_string in text:", github_site["e_string"] in r.text)
