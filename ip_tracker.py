#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Address Tracker - Complete Python Project
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Features:
  1. Track any IPv4/IPv6 address (geolocation, ISP, ASN, timezone, proxy/hosting flags)
  2. Track your own public IP
  3. Reverse DNS lookup
  4. Bulk tracking from a text file
  5. Local history (SQLite) with search
  6. Export history to JSON / CSV
  7. Private / reserved IP detection and risk summary
  8. Google Maps link for each result

Dependencies: Python 3.8+ standard library only.
Usage:
  python3 ip_tracker.py                 -> interactive menu
  python3 ip_tracker.py 8.8.8.8          -> direct lookup
  python3 ip_tracker.py --me             -> your public IP
  python3 ip_tracker.py --file ips.txt   -> bulk lookup

Use only for lawful, authorized security and research purposes.
"""

import argparse
import csv
import ipaddress
import json
import os
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

# --------------------------------------------------------------------------- #
#  Banner / credit
# --------------------------------------------------------------------------- #
BANNER = r"""
⠀⠀⠀⠀⠀⢀⣤⣶⣾⣿⣿⣿⣷⣶⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀
⠀⠀⠀⠀⢰⡟⠛⠉⠙⢻⣿⡟⠋⠉⠙⢻⡇⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣷⣀⣀⣠⣾⠛⣷⣄⣀⣀⣼⡏⠀⠀⠀⠀
⠀⠀⣀⠀⠀⠛⠋⢻⣿⣧⣤⣸⣿⡟⠙⠛⠀⠀⣀⠀⠀
⢀⣰⣿⣦⠀⠀⠀⠼⣿⣿⣿⣿⣿⡷⠀⠀⠀⣰⣿⣆⡀
⢻⣿⣿⣿⣧⣄⠀⠀⠁⠉⠉⠋⠈⠀⠀⣀⣴⣿⣿⣿⡿
⠀⠀⠀⠈⠙⠻⣿⣶⣄⡀⠀⢀⣠⣴⣿⠿⠛⠉⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⣻⣿⣷⣿⣟⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣠⣴⣿⠿⠋⠉⠙⠿⣷⣦⣄⡀⠀⠀⠀⠀
⣴⣶⣶⣾⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣷⣶⣶⣦
⠙⢻⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⡿⠋
⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀
"""

TITLE = "IP ADDRESS TRACKER"
CREDIT = "Coded by Mr Sabaz Ali Khan | Cyber Security Engineer"

# ANSI colours (auto-disabled when not a TTY)
USE_COLOR = sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR")
def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text
GREEN, RED, YELLOW, CYAN, BOLD = "92", "91", "93", "96", "1"

DB_PATH = os.path.join(os.path.expanduser("~"), ".ip_tracker_history.db")
USER_AGENT = "IPTracker/1.0 (Mr Sabaz Ali Khan)"
TIMEOUT = 10

# ip-api.com free endpoint (HTTP only on the free tier, 45 requests/min)
IPAPI_FIELDS = (
    "status,message,continent,country,countryCode,regionName,city,zip,"
    "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)


def show_banner():
    print(c(BANNER, CYAN))
    print(c(f"  {TITLE}", BOLD + ";" + GREEN))
    print(c(f"  {CREDIT}", YELLOW))
    print(c("  " + "=" * 52, CYAN))
    print()


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
def http_get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def validate_ip(value):
    """Return an ipaddress object or None."""
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def classify_ip(ip_obj):
    """Describe special-purpose address ranges."""
    flags = []
    if ip_obj.is_private:
        flags.append("private")
    if ip_obj.is_loopback:
        flags.append("loopback")
    if ip_obj.is_link_local:
        flags.append("link-local")
    if ip_obj.is_multicast:
        flags.append("multicast")
    if ip_obj.is_reserved:
        flags.append("reserved")
    if ip_obj.is_unspecified:
        flags.append("unspecified")
    return flags


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_public_ip():
    """Discover our own public IP using several fallbacks."""
    sources = [
        ("https://api.ipify.org?format=json", "ip"),
        ("https://api64.ipify.org?format=json", "ip"),
        ("https://ipinfo.io/json", "ip"),
    ]
    for url, key in sources:
        try:
            return http_get_json(url).get(key)
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- #
#  Lookup
# --------------------------------------------------------------------------- #
def lookup_ipapi(ip):
    url = f"http://ip-api.com/json/{ip}?fields={IPAPI_FIELDS}"
    data = http_get_json(url)
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "lookup failed"))
    return {
        "ip": data.get("query", ip),
        "continent": data.get("continent"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "zip": data.get("zip"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "as_name": data.get("asname"),
        "reverse": data.get("reverse") or None,
        "mobile": data.get("mobile"),
        "proxy": data.get("proxy"),
        "hosting": data.get("hosting"),
        "source": "ip-api.com",
    }


def lookup_ipinfo(ip):
    """Fallback provider (ipinfo.io, HTTPS)."""
    data = http_get_json(f"https://ipinfo.io/{ip}/json")
    if "bogon" in data or data.get("error"):
        raise RuntimeError("ipinfo: bogon or error response")
    lat = lon = None
    if data.get("loc"):
        try:
            lat, lon = (float(x) for x in data["loc"].split(","))
        except ValueError:
            pass
    return {
        "ip": data.get("ip", ip),
        "continent": None,
        "country": data.get("country"),
        "country_code": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "zip": data.get("postal"),
        "lat": lat,
        "lon": lon,
        "timezone": data.get("timezone"),
        "isp": data.get("org"),
        "org": data.get("org"),
        "asn": (data.get("org") or "").split(" ")[0] or None,
        "as_name": None,
        "reverse": data.get("hostname"),
        "mobile": None,
        "proxy": None,
        "hosting": None,
        "source": "ipinfo.io",
    }


def track_ip(ip_text):
    """Validate and look up one IP. Returns a result dict (never raises)."""
    ip_obj = validate_ip(ip_text)
    if ip_obj is None:
        return {"ip": ip_text, "error": "Invalid IP address format"}

    special = classify_ip(ip_obj)
    if special and (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                    or ip_obj.is_reserved or ip_obj.is_unspecified or ip_obj.is_multicast):
        return {
            "ip": str(ip_obj),
            "version": ip_obj.version,
            "special": special,
            "reverse": reverse_dns(str(ip_obj)),
            "note": "Non-public address: no geolocation data exists for it.",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

    result, errors = None, []
    for provider in (lookup_ipapi, lookup_ipinfo):
        try:
            result = provider(str(ip_obj))
            break
        except urllib.error.URLError as exc:
            errors.append(f"{provider.__name__}: network error ({exc.reason})")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{provider.__name__}: {exc}")

    if result is None:
        return {"ip": str(ip_obj), "error": " | ".join(errors)}

    result["version"] = ip_obj.version
    result["special"] = []
    if not result.get("reverse"):
        result["reverse"] = reverse_dns(str(ip_obj))
    result["risk"] = assess_risk(result)
    if result.get("lat") is not None and result.get("lon") is not None:
        result["map_url"] = f"https://www.google.com/maps?q={result['lat']},{result['lon']}"
    result["timestamp"] = datetime.now().isoformat(timespec="seconds")
    return result


def assess_risk(r):
    """Very simple indicator-based summary (not a reputation score)."""
    notes = []
    if r.get("proxy"):
        notes.append("Proxy/VPN/Tor indicator")
    if r.get("hosting"):
        notes.append("Hosting / datacenter range")
    if r.get("mobile"):
        notes.append("Mobile carrier network")
    level = "HIGH" if r.get("proxy") else "MEDIUM" if r.get("hosting") else "LOW"
    return {"level": level, "notes": notes or ["No anonymizer/hosting indicators"]}


# --------------------------------------------------------------------------- #
#  Display
# --------------------------------------------------------------------------- #
def print_result(r):
    print(c("\n  " + "-" * 52, CYAN))
    if "error" in r:
        print(c(f"  [!] {r['ip']}: {r['error']}", RED))
        return
    print(c(f"  Target     : {r['ip']}  (IPv{r.get('version', '?')})", BOLD))
    if r.get("special"):
        print(c(f"  Type       : {', '.join(r['special'])}", YELLOW))
        print(f"  Reverse DNS: {r.get('reverse') or 'N/A'}")
        print(c(f"  Note       : {r['note']}", YELLOW))
        return

    rows = [
        ("Country", f"{r.get('country')} ({r.get('country_code')})"),
        ("Continent", r.get("continent")),
        ("Region", r.get("region")),
        ("City", r.get("city")),
        ("ZIP", r.get("zip")),
        ("Coordinates", f"{r.get('lat')}, {r.get('lon')}"),
        ("Timezone", r.get("timezone")),
        ("ISP", r.get("isp")),
        ("Organization", r.get("org")),
        ("ASN", r.get("asn")),
        ("Reverse DNS", r.get("reverse")),
        ("Mobile", r.get("mobile")),
        ("Proxy/VPN", r.get("proxy")),
        ("Hosting", r.get("hosting")),
        ("Map", r.get("map_url")),
        ("Source", r.get("source")),
    ]
    for label, val in rows:
        if val in (None, "", "None, None"):
            val = "N/A"
        print(f"  {label:<13}: {val}")
    risk = r.get("risk", {})
    colour = RED if risk.get("level") == "HIGH" else YELLOW if risk.get("level") == "MEDIUM" else GREEN
    print(c(f"  Risk hint   : {risk.get('level')} - {'; '.join(risk.get('notes', []))}", colour))


# --------------------------------------------------------------------------- #
#  History (SQLite)
# --------------------------------------------------------------------------- #
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ip TEXT, country TEXT, city TEXT, isp TEXT,
               lat REAL, lon REAL, risk TEXT, raw TEXT, ts TEXT)"""
    )
    return conn


def save_history(r):
    if "error" in r:
        return
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO history (ip,country,city,isp,lat,lon,risk,raw,ts) VALUES (?,?,?,?,?,?,?,?,?)",
            (r.get("ip"), r.get("country"), r.get("city"), r.get("isp"),
             r.get("lat"), r.get("lon"), (r.get("risk") or {}).get("level"),
             json.dumps(r), r.get("timestamp")),
        )


def show_history(term=None, limit=50):
    with db_connect() as conn:
        if term:
            like = f"%{term}%"
            cur = conn.execute(
                "SELECT ts,ip,country,city,isp,risk FROM history "
                "WHERE ip LIKE ? OR country LIKE ? OR city LIKE ? OR isp LIKE ? "
                "ORDER BY id DESC LIMIT ?", (like, like, like, like, limit))
        else:
            cur = conn.execute(
                "SELECT ts,ip,country,city,isp,risk FROM history ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
    if not rows:
        print(c("\n  No history records found.", YELLOW))
        return
    print(c(f"\n  {'TIME':<20}{'IP':<18}{'COUNTRY':<16}{'CITY':<16}{'RISK':<7}ISP", BOLD))
    for ts, ip, country, city, isp, risk in rows:
        print(f"  {ts or '':<20}{ip or '':<18}{(country or '')[:14]:<16}{(city or '')[:14]:<16}{risk or '':<7}{(isp or '')[:28]}")


def export_history(path):
    with db_connect() as conn:
        rows = conn.execute("SELECT raw FROM history ORDER BY id").fetchall()
    records = [json.loads(r[0]) for r in rows]
    if not records:
        print(c("  Nothing to export.", YELLOW))
        return
    if path.lower().endswith(".csv"):
        keys = ["timestamp", "ip", "country", "region", "city", "zip", "lat", "lon",
                "timezone", "isp", "org", "asn", "reverse", "proxy", "hosting", "mobile"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, ensure_ascii=False)
    print(c(f"  [+] Exported {len(records)} record(s) to {path}", GREEN))


def clear_history():
    with db_connect() as conn:
        conn.execute("DELETE FROM history")
    print(c("  [+] History cleared.", GREEN))


# --------------------------------------------------------------------------- #
#  Actions
# --------------------------------------------------------------------------- #
def do_track(ip_text):
    print(c(f"\n  [*] Tracking {ip_text} ...", CYAN))
    r = track_ip(ip_text)
    print_result(r)
    save_history(r)
    return r


def do_my_ip():
    print(c("\n  [*] Detecting your public IP ...", CYAN))
    ip = get_public_ip()
    if not ip:
        print(c("  [!] Could not detect public IP (check your internet).", RED))
        return
    do_track(ip)


def do_bulk(path):
    if not os.path.isfile(path):
        print(c(f"  [!] File not found: {path}", RED))
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        ips = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    print(c(f"\n  [*] {len(ips)} address(es) loaded from {path}", CYAN))
    for i, ip in enumerate(ips, 1):
        print(c(f"\n  ({i}/{len(ips)})", BOLD))
        do_track(ip)
        time.sleep(1.5)  # stay under the free API rate limit (45/min)


def do_reverse(ip_text):
    if validate_ip(ip_text) is None:
        print(c("  [!] Invalid IP address.", RED))
        return
    host = reverse_dns(ip_text.strip())
    print(c(f"\n  Reverse DNS for {ip_text}: {host or 'no PTR record found'}", GREEN if host else YELLOW))


# --------------------------------------------------------------------------- #
#  Menu
# --------------------------------------------------------------------------- #
MENU = """
  [1] Track an IP address
  [2] Track my public IP
  [3] Reverse DNS lookup
  [4] Bulk track from file
  [5] View history
  [6] Search history
  [7] Export history (JSON / CSV)
  [8] Clear history
  [0] Exit
"""


def interactive():
    while True:
        print(c(MENU, CYAN))
        try:
            choice = input(c("  ip-tracker> ", GREEN)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye.")
            return
        if choice == "1":
            do_track(input("  Enter IP address: ").strip())
        elif choice == "2":
            do_my_ip()
        elif choice == "3":
            do_reverse(input("  Enter IP address: ").strip())
        elif choice == "4":
            do_bulk(input("  Path to file (one IP per line): ").strip())
        elif choice == "5":
            show_history()
        elif choice == "6":
            show_history(input("  Search term: ").strip())
        elif choice == "7":
            out = input("  Output file (e.g. report.json or report.csv): ").strip() or "ip_history.json"
            export_history(out)
        elif choice == "8":
            if input("  Clear ALL history? (y/N): ").strip().lower() == "y":
                clear_history()
        elif choice == "0":
            print(c(f"\n  {CREDIT}\n  Goodbye.\n", YELLOW))
            return
        else:
            print(c("  [!] Invalid option.", RED))


def main():
    parser = argparse.ArgumentParser(description="IP Address Tracker - coded by Mr Sabaz Ali Khan")
    parser.add_argument("ip", nargs="?", help="IP address to track")
    parser.add_argument("--me", action="store_true", help="track your own public IP")
    parser.add_argument("--file", help="bulk track IPs from a text file")
    parser.add_argument("--rdns", help="reverse DNS lookup for an IP")
    parser.add_argument("--export", help="export history to .json or .csv")
    parser.add_argument("--no-banner", action="store_true", help="hide the banner")
    args = parser.parse_args()

    if not args.no_banner:
        show_banner()

    if args.ip:
        do_track(args.ip)
    elif args.me:
        do_my_ip()
    elif args.file:
        do_bulk(args.file)
    elif args.rdns:
        do_reverse(args.rdns)
    elif args.export:
        export_history(args.export)
    else:
        interactive()


if __name__ == "__main__":
    main()
