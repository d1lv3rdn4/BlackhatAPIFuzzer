# BlackhatAPIFuzzer - Version 1
# Ultimate Black-Hat Grade API Fuzzer (All-in-One Script)

import requests, time, json, threading, argparse, random, hashlib, sys, uuid, shutil
from urllib.parse import quote
from colorama import init, Fore, Style
from collections import defaultdict

init(autoreset=True)

# === CONFIGURABLE ===
MAX_THREADS = 15
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) Chrome/109.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
]
ATTACK_PROFILES = {
    "stealth": {"delay": 2.0, "randomize_headers": True},
    "redteam": {"delay": 1.0, "randomize_headers": True},
    "zeroday": {"delay": 0.2, "randomize_headers": False}
}

chain_map = defaultdict(list)  # param → [types of impact observed]
dashboard_counter = 0

# === TOKEN MANAGER ===
def refresh_token(oauth):
    try:
        r = requests.post(oauth['url'], data={
            "client_id": oauth['client_id'],
            "client_secret": oauth['client_secret'],
            "grant_type": "refresh_token",
            "refresh_token": oauth['refresh_token']
        })
        return r.json().get("access_token")
    except:
        return None

# === HEADER MUTATOR ===
def mutate_headers(base, profile):
    headers = base.copy()
    if profile.get("randomize_headers"):
        headers["User-Agent"] = random.choice(USER_AGENTS)
        headers[random.choice(["X-Api-Key", "x-api-key", "X-Forwarded-For"])] = str(uuid.uuid4())
    return headers

# === VISUAL + LOGGING ===
def log_hit(url, payload, response, reason):
    k = list(payload.keys())[0] if isinstance(payload, dict) else "unknown"
    impact = reason.lower()
    chain_map[k].append(impact)
    with open("nb2r_exploits.log", "a") as f:
        f.write(f"\n[!] {reason} @ {url}\nStatus: {response.status_code}\nLength: {len(response.text)}\nPayload: {json.dumps(payload)}\n---\n")

def suggest_chains():
    print(Fore.MAGENTA + "\n[🧠] Exploit Chain Suggestions:")
    for key, impacts in chain_map.items():
        unique = set(impacts)
        if len(unique) >= 2:
            print(Fore.LIGHTMAGENTA_EX + f" - ⚡ '{key}' shows multiple effects: {', '.join(unique)} → possible chain!")
        elif "string match" in unique:
            print(Fore.CYAN + f" - 🔍 '{key}' triggered match string → investigate reflection")
        elif "length diff" in unique:
            print(Fore.YELLOW + f" - ✴️ '{key}' caused diff in output → possible bypass")

def update_dashboard():
    global dashboard_counter
    dashboard_counter += 1
    if dashboard_counter % 10 == 0:
        width = shutil.get_terminal_size().columns
        print("\n" + Fore.BLUE + "=" * width)
        print(Fore.BLUE + "📊 NB2R LIVE DASHBOARD".center(width))
        print(Fore.BLUE + "=" * width + "\n")
        for key, vals in sorted(chain_map.items()):
            print(Fore.LIGHTBLUE_EX + f"{key:20} => {len(vals)} hits ({', '.join(set(vals))})")
        print(Fore.BLUE + "\n" + "=" * width)

# === OUTPUT ===
def export_poc(url, headers, payload):
    cmd = f"curl -X POST {url} \\
"
    for k, v in headers.items():
        cmd += f"  -H \"{k}: {v}\" \\
"
    cmd += f"  -d '{json.dumps(payload)}'"
    with open("nb2r_poc.sh", "a") as f:
        f.write(cmd + "\n\n")

# === FUZZING ===
def build_key_payloads(word):
    return [
        {word: "test"}, {f"__{word}__": "1"}, {f"{word}[0]": "v"},
        {f"{word.upper()}": "caps"}, {quote(word): "enc"},
        {word.replace(".", "[dot]"): "alt"}
    ]

def recursive_value_payloads(template, value):
    targets = []
    def walk(obj, path=[]):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, path + [k])
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, path + [i])
        else:
            targets.append(path)
    walk(template)
    mutated = []
    for path in targets:
        clone = json.loads(json.dumps(template))
        cursor = clone
        for p in path[:-1]:
            cursor = cursor[p]
        cursor[path[-1]] = value
        mutated.append(clone)
    return mutated

# === ADVANCED HTML PoC REPORT BUILDER ===
from datetime import datetime

def generate_html_report():
    try:
        with open("nb2r_exploits.log", "r") as f:
            log_data = f.read()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""
        <html>
        <head>
        <title>NB2R Exploit Report</title>
        <style>
        body {{ font-family: Arial, sans-serif; background-color: #111; color: #eee; padding: 20px; }}
        h1 {{ color: #00ffe7; }}
        h2 {{ color: #ff4081; margin-bottom: 5px; }}
        h3 {{ color: #1ecbe1; margin: 10px 0 5px; }}
        .block {{ background: #222; padding: 16px; border-radius: 10px; margin-bottom: 30px; }}
        .impact {{ color: #ffcc00; font-weight: bold; }}
        .section {{ background: #2a2a2a; padding: 10px; border-radius: 8px; margin-bottom: 10px; }}
        .payload, .curl {{ background: #1a1a1a; padding: 10px; border-radius: 6px; font-family: monospace; white-space: pre-wrap; }}
        .meta {{ font-size: 13px; color: #ccc; margin-bottom: 5px; }}
        </style>
        </head>
        <body>
        <h1>NB2R Exploit PoC Report</h1>
        <p class='meta'>Generated: {timestamp}</p>
        <hr>
        """

        with open("nb2r_poc.sh", "r") as curlfile:
            curls = curlfile.read().split("curl -X POST")

        for i, block in enumerate(log_data.strip().split("---")):
            if not block.strip():
                continue
            html += "<div class='block'>"
            lines = block.strip().splitlines()
            url, reason, status, length, payload = "", "", "", "", ""
            for line in lines:
                if "@" in line:
                    parts = line.split(" @ ")
                    if len(parts) == 2:
                        reason, url = parts
                elif line.startswith("Status"):
                    status = line.split(":", 1)[1].strip()
                elif line.startswith("Length"):
                    length = line.split(":", 1)[1].strip()
                elif line.startswith("Payload"):
                    payload = line.split(":", 1)[1].strip()

            html += f"<h2>🔍 Finding: {reason}</h2>"
            html += f"<div class='meta'>Target: {url} | HTTP {status} | Response Length: {length}</div>"

            # Explanation
            html += "<div class='section'><h3>What Was Found</h3>"
            html += f"<p>This endpoint responded differently to the payload <code>{payload}</code>. The reason categorized was: <strong class='impact'>{reason}</strong>.</p></div>"

            # How it was found
            html += "<div class='section'><h3>How It Was Discovered</h3>"
            html += "<p>NB2R tested this payload during a fuzzing session using randomized headers and adaptive delay logic. It detected a response anomaly (match or length diff), suggesting behavioral variation.</p></div>"

            # Replication steps
            html += "<div class='section'><h3>How To Reproduce</h3><ol>"
            html += f"<li>Send a POST request to <code>{url}</code> with the following headers:</li><pre class='payload'>Content-Type: application/json</pre>"
            html += f"<li>Use the following body:</li><div class='payload'>{payload}</div>"
            html += f"<li>Observe the response code and length. A difference indicates the endpoint behavior can be manipulated.</li></ol></div>"

            # Exploit PoC
            html += "<div class='section'><h3>Working Exploit (curl)</h3>"
            if i < len(curls):
                curl_cmd = curls[i].strip()
                if curl_cmd:
                    html += f"<div class='curl'>curl -X POST {curl_cmd}</div>"
                else:
                    html += "<p>Exploit command was not captured.</p>"
            html += "</div>"

            html += "</div>"  # end of .block

        html += "</body></html>"

        with open("nb2r_report.html", "w") as report:
            report.write(html)

        print(Fore.CYAN + "[✓] Advanced HTML report saved as nb2r_report.html")

    except Exception as e:
        print(Fore.RED + f"[!] HTML report generation failed: {e}")

# Done. All-in-one script now includes a full HTML PoC report generator for bug bounty submissions. 🎯

# === MAIN ATTACK THREAD ===
def attack(args, word, base_hash, profile):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/json"
    }
    if args.auth_token:
        headers["Authorization"] = args.auth_token
    if args.oauth_refresh:
        token = refresh_token(json.loads(args.oauth_refresh))
        if token:
            headers["Authorization"] = f"Bearer {token}"
    headers = mutate_headers(headers, profile)
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    try:
        if args.fuzz_keys:
            payloads = build_key_payloads(word)
        else:
            json_template = json.loads(args.json)
            payloads = recursive_value_payloads(json_template, word)
    except Exception as e:
        print(Fore.RED + f"[!] Payload build failed: {e}")
        return

    for payload in payloads:
        try:
            r = requests.request(args.method.upper(), args.url, headers=headers, json=payload, timeout=10, proxies=proxies)
            diff = hashlib.md5(r.text.encode()).hexdigest()
            if args.match_string and args.match_string in r.text:
                print(Fore.CYAN + f"[MATCH] '{word}' matched string")
                log_hit(args.url, payload, r, "string match")
                export_poc(args.url, headers, payload)
            elif args.match_length_diff and diff != base_hash:
                print(Fore.GREEN + f"[DIFF] '{word}' changed content length")
                log_hit(args.url, payload, r, "length diff")
                export_poc(args.url, headers, payload)
            else:
                print(Fore.YELLOW + f"[-] '{word}' no effect")
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")
        update_dashboard()
        time.sleep(profile['delay'] + random.uniform(0.1, 0.5))

# === CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NB2R - API Fuzzer Extreme Edition")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="POST")
    parser.add_argument("--json", required=True)
    parser.add_argument("--wordlist", required=True)
    parser.add_argument("--auth-token")
    parser.add_argument("--oauth-refresh", help="JSON string: {url,client_id,client_secret,refresh_token}")
    parser.add_argument("--extra-headers", nargs="*")
    parser.add_argument("--delay", type=float, help="Override profile delay")
    parser.add_argument("--match-length-diff", action="store_true")
    parser.add_argument("--match-string")
    parser.add_argument("--fuzz-keys", action="store_true")
    parser.add_argument("--proxy")
    parser.add_argument("--profile", choices=["stealth", "redteam", "zeroday"], default="stealth")
    args = parser.parse_args()

    profile = ATTACK_PROFILES[args.profile]
    if args.delay: profile['delay'] = args.delay

    try:
        json_obj = json.loads(args.json.replace("FUZZ", "nb2r_baseline"))
        headers = {"Content-Type": "application/json", "User-Agent": random.choice(USER_AGENTS)}
        if args.auth_token:
            headers["Authorization"] = args.auth_token
        proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        r = requests.request(args.method.upper(), args.url, headers=headers, json=json_obj, proxies=proxies)
        base_hash = hashlib.md5(r.text.encode()).hexdigest()
    except Exception as e:
        print(Fore.RED + f"[!] Baseline error: {e}")
        sys.exit(1)

    with open(args.wordlist, "r") as f:
        for line in f:
            while threading.active_count() > MAX_THREADS:
                time.sleep(0.2)
            t = threading.Thread(target=attack, args=(args, line.strip(), base_hash, profile))
            t.start()

    print(Fore.GREEN + "[✓] NB2R fuzzing complete. Results:")
    suggest_chains()
    update_dashboard()
    generate_html_report()
