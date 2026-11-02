# IP Address Tracker

```
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
```

**A lightweight, dependency-free Python tool for IP geolocation and basic threat-context lookups.**

*Coded by Mr Sabaz Ali Khan | Cyber Security Engineer*

---

## Overview

IP Address Tracker looks up any IPv4 or IPv6 address and reports its geolocation, ISP, ASN, timezone and proxy/hosting indicators. It keeps a local history of every lookup in SQLite, supports bulk tracking from a file, and can export results to JSON or CSV. It runs entirely on the Python standard library, so there is nothing to install.

## Features

- Track any IPv4 / IPv6 address (country, region, city, ZIP, coordinates, timezone)
- ISP, organization and ASN details
- Proxy / VPN, hosting and mobile-network flags
- Simple risk hint (LOW / MEDIUM / HIGH) based on anonymizer and hosting indicators
- Track your own public IP
- Reverse DNS (PTR) lookup
- Bulk tracking from a text file
- Detection of private, loopback, link-local, multicast, reserved and unspecified addresses
- Google Maps link for each result
- Local history in SQLite with search
- Export history to JSON or CSV
- Automatic fallback between two providers (ip-api.com, then ipinfo.io)
- Colored terminal output (auto-disabled when not in a TTY)

## Requirements

- Python 3.8 or newer
- Internet connection (for lookups)
- No third-party packages

## Installation

```bash
git clone <https://github.com/whoami592/ip_Tracker.git
cd ip_Tracker
chmod +x ip_tracker.py   # optional, Linux/macOS
```

Or simply download `ip_tracker.py` and run it.

## Usage

### Interactive menu

```bash
python3 ip_tracker.py
```

```
[1] Track an IP address
[2] Track my public IP
[3] Reverse DNS lookup
[4] Bulk track from file
[5] View history
[6] Search history
[7] Export history (JSON / CSV)
[8] Clear history
[0] Exit
```

### Command line

| Command | Description |
|---|---|
| `python3 ip_tracker.py 8.8.8.8` | Track a specific IP address |
| `python3 ip_tracker.py --me` | Track your own public IP |
| `python3 ip_tracker.py --file ips.txt` | Bulk track IPs from a file |
| `python3 ip_tracker.py --rdns 8.8.8.8` | Reverse DNS lookup |
| `python3 ip_tracker.py --export report.csv` | Export history to `.json` or `.csv` |
| `python3 ip_tracker.py --no-banner 8.8.8.8` | Hide the banner |

### Bulk file format

One IP address per line. Empty lines and lines starting with `#` are ignored.

```text
# my targets
8.8.8.8
1.1.1.1
2001:4860:4860::8888
```

## Example Output

```
  Target     : 8.8.8.8  (IPv4)
  Country      : United States (US)
  City         : Ashburn
  Coordinates  : 39.03, -77.5
  Timezone     : America/New_York
  ISP          : Google LLC
  ASN          : AS15169 Google LLC
  Proxy/VPN    : False
  Hosting      : True
  Map          : https://www.google.com/maps?q=...
  Source       : ip-api.com
  Risk hint    : MEDIUM - Hosting/datacenter IP
```

*(Actual values depend on the provider's data.)*

## Data Storage

Lookup history is stored locally in an SQLite database at:

```
~/.ip_tracker_history.db
```

Nothing is sent anywhere except the IP address you query, which is sent to the lookup providers. Use menu option `[8]` to clear the history at any time.

## Data Sources and Limits

| Provider | Protocol | Notes |
|---|---|---|
| [ip-api.com](https://ip-api.com) | HTTP (free tier) | Primary; about 45 requests per minute |
| [ipinfo.io](https://ipinfo.io) | HTTPS | Fallback provider |
| [ipify.org](https://www.ipify.org) | HTTPS | Used to detect your public IP |

- Bulk mode waits 1.5 seconds between lookups to stay under the free rate limit.
- The free ip-api.com endpoint uses plain HTTP, so queried IPs are not encrypted in transit on that request.
- IP geolocation is approximate. It usually identifies the ISP's region, not an exact street address.
- Private and reserved addresses have no geolocation data and are reported as non-public.

## Project Structure

```
ip_tracker.py   # complete tool (single file)
README.md       # this file
```

## Disclaimer

This tool is intended for **lawful, authorized security and research purposes only**. The author is not responsible for misuse. Always respect privacy laws and the terms of service of the data providers.

## Author

**Mr Sabaz Ali Khan**, Cyber Security Engineer

*Coded by Mr Sabaz Ali Khan*
