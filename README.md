# Blackhat API Fuzzer: Extreme Black-Hat Grade API Fuzzing Tool 🚨

![image](https://github.com/user-attachments/assets/aa619f85-15ca-496f-bf92-00a9a125f8a0)


![Banner](https://img.shields.io/badge/status-unstoppable-critical?style=flat-square&logo=python)
![Lang](https://img.shields.io/badge/made%20with-python-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

## 🔥 What is Blackhat API Fuzzer?

**Blackhat API Fuzzer** is a full-blown, one-file, elite-grade API Fuzzer designed to:

- Brute-force **parameter names** & **values**
- Exploit **WAF-evading payloads**
- Auto-refresh OAuth tokens
- Build **curl PoCs**
- Analyze **exploit chains**
- Export an **HTML bug bounty report**

Built for offensive security researchers, bug bounty hunters, and red teams who want more than just FFUF and Turbo Intruder.

---

## 🚀 Features

✅ Brute-force both keys and values  
✅ Smart payload mutation engine  
✅ OAuth2 token auto-refresh  
✅ Dynamic headers + spoofing  
✅ Proxy support  
✅ Profiles: `stealth`, `redteam`, `zeroday`  
✅ Live dashboard  
✅ Exploit chain tracking  
✅ HTML PoC report (`nb2r_report.html`)

---

## ⚙️ Usage

```bash
python3 nb2r.py \
  --url https://api.victim.com/endpoint \
  --method POST \
  --json '{"user":"admin", "pass":"FUZZ"}' \
  --wordlist rockyou.txt \
  --match-length-diff \
  --profile redteam \
  --fuzz-keys \
  --proxy http://127.0.0.1:8080

Example with OAuth token refresh:

python3 nb2r.py \
  --url https://api.target.com/data \
  --json '{"FUZZ":"test"}' \
  --wordlist params.txt \
  --oauth-refresh '{"url":"https://auth.com/token","client_id":"abc","client_secret":"xyz","refresh_token":"longtoken..."}'


🧪 Output
📜 Exploits → nb2r_exploits.log
💣 curl PoCs → nb2r_poc.sh
📊 HTML Report → nb2r_report.html
📈 CLI Dashboard → Auto-updates every 10 fuzz cycles


🛡 Profiles

stealth > Delays, spoofed headers
redteam > Faster, randomized agents
zeroday > No delay, full speed fuzzing

It tracks param behavior and tells you when a single input is triggering multiple reactions — a clear sign of a chainable exploit (e.g., auth bypass + XSS).

👨‍💻 Author:
Crafted with pain, caffeine, and dreams by yourstruely 🧠
Inspired by tools like FFUF, Turbo Intruder, and every time Burp Suite crashes.
