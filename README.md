# Blackhat API Fuzzer: Just another API Fuzzing Tool, but with HTML PoCs 🚨

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
- (LIMITATIONS) It's currently not modular obviously, it's all code within one file. So FFUF definately has advantages in other areas. I will slowly upgrade this more when I get time.

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

![image](https://github.com/user-attachments/assets/0a9589d5-d2e7-4fcd-89ce-1017d25d20e8)


---

![image](https://github.com/user-attachments/assets/e7b936f7-645e-4a9e-829d-bd4fd2fa9a28)


✅ What’s Being Added:
🔍 Automated Scanners
scan_rce(), scan_sqli(), scan_ssrf(), scan_jwt(), scan_idor(), scan_file_inclusion(), scan_auth_bypass(), scan_xss()

Each scanner can be toggled and runs in threads, respecting delays and baselines

⚙️ JWT Manipulation Engine
> Detects JWT in Authorization header
> Decodes and mutates claims (role, alg, scope)
> Tries "none", known weak keys, role escalation

⚙️ OpenAPI/Swagger Import
> Loads Swagger/OpenAPI JSON
> Builds attack queue from all defined paths, methods, headers, bodies
> Categorizes endpoints by auth required, input type, and body schema

⚙️ Race Condition Detection
> Sends concurrent POST/PUT/DELETE with same payload
> Detects inconsistent or duplicated outcomes

⚙️ SSRF Detection (Blind & Active)
> Interact.sh support (auto-DNS callback payloads)
> Logs SSRF confirmation when DNS log hit matches ID

⚙️ Enhanced PoC Report
> Grouped by vulnerability type
> CVSS estimation
> Impact explanation, screenshot slot, working exploit script (curl + Python)


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

✅ Requirements
Python 3 is installed (which Parrot comes with by default)

You install the only dependency manually:
pip install colorama
______________________________________________________________________________________

Optional Tools (if using features like proxies):
A proxy like Burp Suite can be run on localhost for request inspection

curl is only used for PoC logging (not a runtime requirement)


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
