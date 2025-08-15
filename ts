#!/usr/bin/env python3
# TS HACKER - Termux Subdomain Finder v2.0
# Telegram: @teamsatved71
# Works with zero balance

import requests, sys, os, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from itertools import product
import string
import time

# Colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
W = "\033[0m"

UA = {"User-Agent": "Termux-SubFinder/2.0"}

def clear(): os.system("clear")

def banner():
    clear()
    print(f"""{C}
╔═══════════════════════════════╗
      🔍 Termux Subdomain Finder
        By TS HACKER - 2025
╚═══════════════════════════════╝
{W}""")

def normalize_domain(d):
    d = d.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0]
    return d.strip('.')

def is_valid_domain(d):
    pattern = re.compile(r'^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$')
    return bool(pattern.match(d))

# --- Public sources ---
def fetch_crtsh(domain):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20, headers=UA)
        if r.status_code == 200:
            data = r.json()
            for e in data:
                for name in str(e.get("name_value","")).splitlines():
                    name = name.strip().lower()
                    if name.startswith("*."): name = name[2:]
                    if name.endswith(domain): subs.add(name)
    except: pass
    return subs

def fetch_hackertarget(domain):
    subs = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20, headers=UA)
        if r.status_code==200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith(domain): subs.add(host)
    except: pass
    return subs

def fetch_threatcrowd(domain):
    subs = set()
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=20, headers=UA)
        j = r.json()
        for s in j.get("subdomains", []):
            if s.strip().endswith(domain): subs.add(s.strip().lower())
    except: pass
    return subs

# --- DNS A–Z brute force ---
def dns_bruteforce(domain, letters):
    found = set()
    for prefix in letters:
        target = f"{prefix}.{domain}"
        try:
            r = requests.get("https://dns.google/resolve", params={"name": target,"type":"A"}, timeout=8, headers=UA)
            if r.status_code==200 and r.json().get("Status",1)==0:
                found.add(target)
        except: pass
    return found

# --- Generate all 1-2 letter combinations for A-Z brute ---
def generate_letters():
    letters = list(string.ascii_lowercase)
    # 1-letter + 2-letter combinations
    for a,b in product(string.ascii_lowercase, repeat=2):
        letters.append(a+b)
    return letters

def save_results(domain, subs):
    os.makedirs("results", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"results/subdomains_{domain}_{ts}.txt"
    with open(path,"w") as f:
        for s in sorted(subs): f.write(s+"\n")
    return path

# --- Main scanning function ---
def scan_domain(domain):
    all_subs = set()
    print(f"{B}[*] Gathering subdomains for: {domain}{W}")
    sources = [("crt.sh", fetch_crtsh), ("HackerTarget", fetch_hackertarget), ("ThreatCrowd", fetch_threatcrowd)]

    # Fetch public sources in threads
    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futs = {ex.submit(fn, domain): name for name,fn in sources}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                res = fut.result()
                before = len(all_subs)
                all_subs.update(res)
                print(f"{G}[+] {name}: {len(res)} found (total {len(all_subs)}){W}")
            except: print(f"{R}[-] {name} failed{W}")

    # DNS brute-force A–Z + common
    print(f"{B}[*] Starting A–Z + common subdomain brute-force...{W}")
    letters = generate_letters()
    common_subs = ["www","mail","ftp","api","dev","test","blog","shop","admin","vpn","secure","m","portal","cpanel","webmail"]
    letters = list(set(letters + common_subs))
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = [ex.submit(dns_bruteforce, domain, [l]) for l in letters]
        for fut in as_completed(futs):
            res = fut.result()
            before = len(all_subs)
            all_subs.update(res)
            if res: print(f"{G}[+] {len(res)} new from brute-force (total {len(all_subs)}){W}")

    # Clean results
    cleaned = set(s.strip().lower().lstrip("*.") for s in all_subs if s.endswith(domain))
    print(f"{C}[✓] Total unique subdomains found: {len(cleaned)}{W}")

    # Show results
    for sub in sorted(cleaned): print(" -", sub)
    path = save_results(domain, cleaned)
    print(f"{G}[✓] Saved results: {path}{W}")

# --- Menu system ---
def main_menu():
    while True:
        banner()
        print("1. Scan a domain")
        print("2. Exit")
        choice = input(f"{Y}[?] Choose: {W}").strip()
        if choice=="1":
            domain = input(f"{Y}[?] Enter domain (example.com): {W}").strip()
            domain = normalize_domain(domain)
            if not is_valid_domain(domain):
                print(f"{R}[!] Invalid domain{W}")
                time.sleep(2)
                continue
            scan_domain(domain)
            post_scan_menu()
        elif choice=="2":
            print(f"{G}[✓] Exiting...{W}")
            sys.exit(0)
        else:
            print(f"{R}[!] Invalid choice{W}")
            time.sleep(1)

def post_scan_menu():
    while True:
        print(f"\n{B}Scan finished. What next?{W}")
        print("1. Scan another domain")
        print("2. Back to main menu")
        print("3. Exit")
        choice = input(f"{Y}[?] Choose: {W}").strip()
        if choice=="1":
            domain = input(f"{Y}[?] Enter domain (example.com): {W}").strip()
            domain = normalize_domain(domain)
            if not is_valid_domain(domain):
                print(f"{R}[!] Invalid domain{W}")
                continue
            scan_domain(domain)
        elif choice=="2":
            return
        elif choice=="3":
            print(f"{G}[✓] Exiting...{W}")
            sys.exit(0)
        else:
            print(f"{R}[!] Invalid choice{W}")

if __name__=="__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Interrupted by user{W}")
        sys.exit(0)
