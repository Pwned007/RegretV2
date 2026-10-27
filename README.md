# Regret v2

**By Syed Sadam Hussain Shah** — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)

A full-featured network attack GUI for **authorized** LAN security assessments. Regret v2
combines ARP spoofing, traffic interception, DNS manipulation, SSL stripping, stress testing,
passive recon, DHCP attacks, and more — all from a single dark-themed tkinter interface with
a login screen and session management.

> **Authorized use only.** Only run on networks you own or have written permission to test.
> This tool makes significant changes to the network stack (iptables, sysctl, ip_forward).
> Always restore ARP and stop all engines before disconnecting.

---

## Capabilities

### Attack engines

| Engine | Description |
|---|---|
| **ARP MITM (per-host)** | Bidirectional ARP spoof; optional per-target bandwidth cap via `tc` HTB |
| **GARP broadcast** | Gratuitous ARP to entire LAN — DoS or MITM mode |
| **DNS Spoof** | Intercepts UDP/53 queries and returns spoofed A records for matching domains |
| **SSL Strip / HSTS** | Transparent mitmproxy proxy; strips HSTS headers, rewrites `https://` → `http://` in HTML/JS, extracts POST credentials |
| **Stress Test** | SYN / UDP / ICMP / HTTP floods via hping3 (fast) or multi-threaded Scapy (fallback) |
| **Auto-Attack** | Periodic ARP scan; auto-applies GARP DoS to any new host not in the baseline |
| **Lockout** | Snapshot allowed hosts at activation; ARP-DoS any new device that joins the network |

### Layer 2 / Layer 3

| Feature | Description |
|---|---|
| **NDP / IPv6 Spoof** | Forges ICMPv6 Neighbor Advertisements — bypasses DAI entirely |
| **DHCP Starvation** | Floods DHCP server with random-MAC DISCOVERs to exhaust the address pool |
| **Rogue DHCP** | Answers DISCOVER/REQUEST faster than the real server with a fake gateway and DNS |

### Recon

| Feature | Description |
|---|---|
| **Active scan** | Broadcast ARP scan over any CIDR; host enrichment: reverse DNS, NetBIOS name, MAC vendor, TTL-based OS guess |
| **Passive discovery** | Zero-packet recon — listens for ARP, DHCP, mDNS, SSDP traffic without sending a frame |
| **Packet sniffer** | Parses HTTP requests (URL + Host header), DNS queries, FTP/Telnet plaintext; highlights credential fields from POST bodies; PCAP export |

### Identity & identity management

| Feature | Description |
|---|---|
| **MAC randomization** | Generates locally-administered unicast MAC; applies via `ip link` (no macchanger needed) |
| **Hostname spoof** | Changes hostname via `hostnamectl` and patches `/etc/hosts` |
| **Session / profile** | Save, load, and delete named scan sessions as JSON files (`~/.regret/sessions/`) |

### Application

| Feature | Description |
|---|---|
| **Login screen** | SHA-256 password, stored in `~/.regret/creds.json` (mode 600); default `admin` / `regret@2024` |
| **Dark GUI** | tkinter with custom dark palette; per-engine tabs |
| **Per-target bandwidth** | Throttle individual hosts independently via `tc` HTB classid allocation |

---

## Requirements

| Requirement | Notes |
|---|---|
| **Python 3.8+** | |
| **scapy** | `pip install scapy` |
| **tkinter** | Bundled with Python; on Kali/Debian: `apt install python3-tk` |
| **Root / CAP_NET_RAW** | `sudo python3 regretv2.py` |
| **Linux** | Uses `/proc/sys/net/ipv4/ip_forward`, `iptables`, `sysctl`, `tc`, `ip link` |

### Optional dependencies

| Package | Purpose | Install |
|---|---|---|
| `mitmproxy` | SSL Strip / HSTS tab | `pip install mitmproxy` |
| `hping3` | Faster stress test engine | `apt install hping3` |
| `nmblookup` | NetBIOS name resolution in host scan | `apt install samba-common-bin` |
| `nmap` | MAC vendor prefix file (OUI lookup) | `apt install nmap` |
| `ethtool` | Read hardware-burned-in MAC | `apt install ethtool` |
| `iproute2` | `tc` bandwidth limiting, `ip link` MAC change | `apt install iproute2` |

```bash
pip install scapy
pip install mitmproxy    # optional — SSL Strip tab
apt install python3-tk hping3 samba-common-bin nmap ethtool iproute2
```

---

## Usage

```bash
sudo python3 regretv2.py
```

A login screen appears on first run. Default credentials: **admin** / **regret@2024**.
The credential file is stored at `~/.regret/creds.json` (owner-read-only).

### Tab overview

| Tab | What to do |
|---|---|
| **Scan** | Pick interface, enter CIDR, click Scan. Hosts populate the table with IP, MAC, vendor, hostname, OS guess. Check boxes to select targets for attack tabs. Enable Passive Discovery to populate without sending packets. |
| **Attack** | Start/stop per-host ARP spoof and GARP. Set optional kbps cap per host. Toggle ip_forward for MITM vs. DoS mode. |
| **DNS Spoof** | Add `domain → redirect IP` rules. Requires MITM active (Attack tab) so queries flow through you. |
| **Sniffer** | Capture HTTP requests, DNS queries, FTP/Telnet plaintext from intercepted traffic. Save to `.pcap`. |
| **HSTS Strip** | Start the mitmproxy transparent proxy (requires `mitmproxy` installed). Captured credentials appear in the credentials panel. |
| **Stress Test** | Choose mode (SYN / UDP / ICMP / HTTP), target IP, port, spoof random source. Prefers hping3, falls back to Scapy. |
| **Auto-Attack** | Seed known-good hosts, set interval, start. Any new host detected triggers automatic GARP DoS. |
| **Lockout** | Snapshot current hosts as allowed, start. New devices joining the network are immediately ARP-DoS'd. |
| **DHCP** | DHCP Starvation (exhaust pool) or Rogue DHCP (inject fake gateway + DNS). |
| **NDP** | IPv6 Neighbor Advertisement spoofing against selected hosts. |
| **Identity** | Randomize or restore MAC address. Change system hostname. |
| **Sessions** | Save the current host list and configuration as a named session; reload it later. |

---

## Safety notes

- Stop all engines before closing the window — `stop_all()` restores ARP and removes `tc` rules automatically on clean shutdown.
- Stress Test and DHCP Starvation are high-impact; confirm scope before starting.
- SSL Strip requires kernel IP forwarding and iptables PREROUTING rules; these are removed when the engine stops.
- ICMP redirects are disabled while SSL Strip is active and re-enabled on stop.

---

## License

MIT — see [LICENSE](LICENSE). Contributions and issues welcome.

**Author:** Syed Sadam Hussain Shah — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)
