import requests
import re
import sys
import json
from datetime import datetime
from time import sleep

# Try to use tqdm for loading
try:
    from tqdm import tqdm
    use_tqdm = True
except ImportError:
    use_tqdm = False

def show_banner():
    banner = r"""
 _   _                   _ 
| \ | |   ___    _ __   (_)
|  \| |  / _ \  | '_ \  | |
| |\  | | (_) | | | | | | |
\_| \_/  \___/  |_| |_| |_|

        by n0ur1
    """
    print(banner)
    if use_tqdm:
        for _ in tqdm(range(30), desc="Loading", ncols=70):
            sleep(0.02)
    else:
        print("Loading", end="")
        for _ in range(10):
            print(".", end="", flush=True)
            sleep(0.2)
        print("\n")

def extract_info(js_content, url):
    findings = {}

    patterns = {
        "API Key": r'(?i)(api[_-]?key[\'"\s:=]+)([A-Za-z0-9_\-]{16,})',
        "Token": r'(?i)(token[\'"\s:=]+)([A-Za-z0-9\-_]{10,})',
        "Secret": r'(?i)(secret[\'"\s:=]+)([A-Za-z0-9\-_]{8,})',
        "Password": r'(?i)(password|pwd)[\'"\s:=]+([^\s\'"]{4,})',
        "Hardcoded Credentials": r'(?i)(username|user|login)[\'"\s:=]+[\'"]?([A-Za-z0-9._%-]+)[\'"]?',
        "JWT Token": r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        "AWS Access Key ID": r'AKIA[0-9A-Z]{16}',
        "AWS Secret Key": r'(?i)aws(.{0,20})?(secret|private)?(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
        "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
        "Heroku API Key": r'(?i)heroku[\'"\s:=]+([0-9a-f]{32})',
        "Google Maps API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "Stripe Key": r'sk_live_[0-9a-zA-Z]{24,}',
        "Config File": r'([A-Za-z0-9/_-]+\.config(\.js)?)',
        "Database URL": r'(?i)(mongodb|mysql|postgres|mariadb):\/\/[^\s\'"]+',
        "URL/Endpoint": r'https?://[^\s\'"]+',
        "IP Address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "Base64 Strings": r'([A-Za-z0-9+/]{40,}={0,2})',
        "Private Key": r'-----BEGIN (RSA|EC|DSA|PGP|OPENSSH|PRIVATE) KEY-----[\s\S]+?-----END \1 KEY-----',
        "Email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    }

    for label, pattern in patterns.items():
        matches = re.findall(pattern, js_content)
        if matches:
            if isinstance(matches[0], tuple):
                extracted = [m[-1] for m in matches]
            else:
                extracted = matches
            findings[label] = list(set(extracted))

    return findings if findings else None

def process_js_urls(file_path):
    results = {}

    try:
        with open(file_path, "r") as f:
            js_urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[x] File not found: {file_path}")
        return

    for url in js_urls:
        try:
            print(f"\n[.] Fetching: {url}")
            res = requests.get(url, timeout=15)
            if res.status_code == 200 and res.text.strip():
                info = extract_info(res.text, url)
                if info:
                    results[url] = info
                    print(f"[+] Findings in {url}:")
                    for key, vals in info.items():
                        print(f"   - {key} ({len(vals)}):")
                        for val in vals:
                            print(f"       {val[:100]}{'...' if len(val) > 100 else ''}")
                else:
                    print("[-] No sensitive info found.")
            else:
                print(f"[x] Skipped ({res.status_code}) => {url}")
        except requests.RequestException as e:
            print(f"[x] Error fetching {url}: {e}")

    if results:
        out_file = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out_file, "w") as out:
            json.dump(results, out, indent=2)
        print(f"\n✅ Results saved to: {out_file}")
    else:
        print("\n[-] No findings saved.")

if __name__ == "__main__":
    show_banner()
    if len(sys.argv) != 2:
        print("Usage: python3 js_disclosure_scan.py js_urls.txt")
    else:
        process_js_urls(sys.argv[1])
