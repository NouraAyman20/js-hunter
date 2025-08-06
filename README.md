# 🔍 JS Hunter

A Python tool built to help bug bounty hunters and security researchers identify sensitive information inside JavaScript files.

---

## 🚀 Features

- Extracts **API Keys**, **Tokens**, **Secrets**, **JWTs**, **Private Keys**, **Emails**, **Database URLs**, and more.
- Uses customizable **regex patterns**.
- Saves results in clean JSON format.


---

## 📦 Installation

```bash
git clone https://github.com/nouraayman/js-hunter.git
cd js-hunter
pip install -r requirements.txt




## 🛠 How to Use
1. Prepare your subdomains list in a file named `subdomains.txt`.
2. Run the following command to extract all valid JavaScript URLs (with HTTP 200 OK):

```bash
cat subdomains.txt | waybackurls | grep -v '^$' | \
xargs -I {} sh -c 'code=$(curl -s -o /dev/null -w "%{http_code}" "{}"); \
[ "$code" = "200" ] && echo "[200 OK] {}"' > alive_urls.txt

grep -Eo 'https?://[^ ]+\.js' alive_urls.txt > js_urls.txt


