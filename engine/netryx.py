#!/usr/bin/env python3
"""Netryx - a feature-rich local network scanner & discovery web app.

Pure Python standard library only (no pip installs). Runs a small local web
server and serves the Network Intelligence dashboard (ui.html) in your browser.

Features: ping-sweep + TCP-fallback host discovery, MAC/vendor (OUI) lookup
with full-IEEE-database download, reverse-DNS + mDNS/Bonjour + SNMP enrichment,
parallel TCP port scanning with banners + clickable web URLs, OS/device-type
guessing, card/table/topology views, live monitoring + desktop alerts, scan
history, Wake-on-LAN, names/notes, CSV/JSON export.

Usage:
    python netryx.py [--host H] [--port P] [--no-browser]
Env: NETRYX_HOST, NETRYX_PORT, NETRYX_NO_BROWSER, NETRYX_DATA
"""

import argparse
import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import platform
import random
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode, quote

VERSION = os.environ.get("NETRYX_VERSION", "1.0.0").strip() or "1.0.0"
IS_WINDOWS = platform.system().lower().startswith("win")
SUBPROC_KW = {"creationflags": 0x08000000} if IS_WINDOWS else {}  # CREATE_NO_WINDOW

APP_DIR = os.path.dirname(os.path.abspath(
    sys.argv[0] if getattr(sys, "frozen", False) else __file__))


def _default_data_dir():
    """Where scan history, names, baseline, tokens etc. live.
    NETRYX_DATA always wins. Running from source: beside the script. As an
    installed/frozen binary (which may sit in a read-only /usr/bin, /Applications
    or Program Files): under the user's profile, per-OS convention."""
    env = os.environ.get("NETRYX_DATA")
    if env:
        return env
    if not getattr(sys, "frozen", False):
        return os.path.join(APP_DIR, "netryx_data")
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "Netryx")


DATA_DIR = _default_data_dir()
HISTORY_DIR = os.path.join(DATA_DIR, "history")
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")
SEEN_FILE = os.path.join(DATA_DIR, "seen_macs.json")
# Access control. When any of these are set (or any API token exists), the whole
# app (UI + /api + /mcp) requires auth, except requests from localhost when
# NETRYX_TRUST_LOCALHOST is on. Humans use admin Basic auth; agents use tokens.
NETRYX_TOKEN = os.environ.get("NETRYX_TOKEN", "").strip()          # legacy static bearer token
NETRYX_USER = (os.environ.get("NETRYX_USER", "admin").strip() or "admin")
NETRYX_PASS = os.environ.get("NETRYX_PASS", "")
NETRYX_TRUST_LOCALHOST = os.environ.get("NETRYX_TRUST_LOCALHOST", "0").strip().lower() \
    in ("1", "true", "yes", "on")
NETRYX_OPEN = os.environ.get("NETRYX_OPEN", "").strip().lower() in ("1", "true", "yes", "on")
# Set when terminating TLS in front of Netryx (e.g. nginx https) so session
# cookies carry the Secure attribute and are never sent over plain HTTP.
NETRYX_SECURE_COOKIES = os.environ.get("NETRYX_SECURE_COOKIES", "").strip().lower() \
    in ("1", "true", "yes", "on")
COOKIE_ATTRS = "; HttpOnly; SameSite=Lax" + ("; Secure" if NETRYX_SECURE_COOKIES else "")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
for _d in (DATA_DIR, HISTORY_DIR):
    try:
        os.makedirs(_d, exist_ok=True)
    except Exception:
        pass


def log(msg):
    """Minimal timestamped stderr logging for operational visibility (HTTP
    access logs stay suppressed; this is for notable server-side events)."""
    try:
        sys.stderr.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
        sys.stderr.flush()
    except Exception:
        pass


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "Printer", 548: "AFP", 554: "RTSP", 587: "SMTP-Sub",
    631: "IPP/Printer", 873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    1883: "MQTT", 1900: "UPnP/SSDP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2375: "Docker", 2376: "Docker-TLS", 3000: "Dev/HTTP", 3128: "Proxy",
    3306: "MySQL", 3389: "RDP", 3478: "STUN", 4444: "Alt", 4500: "IPsec-NAT",
    5000: "HTTP/UPnP", 5001: "HTTP-alt", 5060: "SIP", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5555: "ADB/Android", 5601: "Kibana", 5672: "AMQP",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis", 6443: "Kubernetes",
    7000: "HTTP-alt", 7070: "HTTP-alt", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8009: "AJP", 8080: "HTTP-alt", 8081: "HTTP-alt", 8086: "InfluxDB",
    8088: "HTTP-alt", 8123: "HomeAssistant", 8443: "HTTPS-alt", 8554: "RTSP",
    8888: "HTTP-alt", 9000: "HTTP-alt", 9090: "HTTP-alt", 9100: "Printer-RAW",
    9200: "Elasticsearch", 9300: "Elastic", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 32400: "Plex", 49152: "UPnP", 51820: "WireGuard",
    62078: "iOS-lockdown",
}
WEB_PORTS_HTTP = {80, 591, 2082, 3000, 5000, 5001, 7000, 7070, 8000, 8008, 8080,
                  8081, 8086, 8088, 8123, 8888, 9000, 9090, 5601, 10000, 32400}
WEB_PORTS_HTTPS = {443, 2083, 8443, 6443}
PORT_PROFILES = ("quick", "extended", "full")

# --------------------------------------------------------------------------- #
# Exposure / risk model
#
# A lightweight, opinionated heuristic: open ports that are commonly abused or
# that expose a management/data plane raise a device's exposure score. This is
# a *pure* function of already-collected scan data (no extra network I/O), so
# it's safe to attach to every device and to call from the CLI / MCP layers.
# --------------------------------------------------------------------------- #

RISK_TIERS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_TIER_NAME = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# port -> (service label, tier, why)
RISKY_PORTS = {
    23:    ("Telnet", "critical", "unencrypted remote login"),
    2323:  ("Telnet-alt", "critical", "unencrypted remote login"),
    6379:  ("Redis", "critical", "frequently unauthenticated - remote code execution risk"),
    27017: ("MongoDB", "critical", "frequently unauthenticated database"),
    2375:  ("Docker", "critical", "unauthenticated Docker API exposes full host control"),
    11211: ("Memcached", "critical", "unauthenticated; DDoS amplification vector"),
    21:    ("FTP", "high", "often plaintext credentials"),
    69:    ("TFTP", "high", "unauthenticated file transfer"),
    512:   ("rexec", "high", "legacy remote execution"),
    513:   ("rlogin", "high", "legacy remote login"),
    445:   ("SMB", "high", "file sharing - common worm/ransomware vector"),
    139:   ("NetBIOS-SSN", "high", "legacy SMB session service"),
    3389:  ("RDP", "high", "remote desktop - common ransomware entry point"),
    5900:  ("VNC", "high", "remote desktop, often weakly authenticated"),
    5555:  ("ADB", "high", "Android Debug Bridge grants full device control"),
    1433:  ("MSSQL", "high", "database directly exposed"),
    3306:  ("MySQL", "high", "database directly exposed"),
    5432:  ("PostgreSQL", "high", "database directly exposed"),
    9200:  ("Elasticsearch", "high", "often unauthenticated; data disclosure"),
    9300:  ("Elasticsearch", "high", "cluster transport exposed"),
    1521:  ("Oracle", "high", "database directly exposed"),
    5984:  ("CouchDB", "high", "often unauthenticated database"),
    135:   ("MSRPC", "medium", "Windows RPC endpoint mapper"),
    137:   ("NetBIOS", "medium", "legacy name service"),
    161:   ("SNMP", "medium", "management plane; default community strings are common"),
    111:   ("RPC", "medium", "portmapper - service/info disclosure"),
    1900:  ("UPnP/SSDP", "medium", "UPnP exposed - history of CVEs"),
    514:   ("Syslog/rsh", "medium", "legacy remote shell / log service"),
    2049:  ("NFS", "medium", "network file system exposed"),
    873:   ("rsync", "medium", "file sync service exposed"),
    8086:  ("InfluxDB", "medium", "time-series database exposed"),
    10000: ("Webmin", "medium", "server admin panel"),
    5601:  ("Kibana", "medium", "analytics dashboard exposed"),
}


def risk_of(d):
    """Heuristic exposure assessment for a device, from its open ports.

    Returns {"tier", "score", "reasons"} where tier is one of
    none/low/medium/high/critical. Pure function - no network I/O."""
    ports = d.get("ports", []) or []
    reasons, score, worst = [], 0, 0
    seen = set()
    for p in ports:
        port = p.get("port")
        info = RISKY_PORTS.get(port)
        if info and port not in seen:
            seen.add(port)
            label, tier, why = info
            w = RISK_TIERS.get(tier, 1)
            score += w
            worst = max(worst, w)
            reasons.append({"port": port, "service": label, "tier": tier, "why": why})
    n_open = len({p.get("port") for p in ports})
    if n_open >= 15:
        score += 2
        worst = max(worst, 2)
        reasons.append({"port": None, "service": "broad surface", "tier": "medium",
                        "why": "%d open ports widen the attack surface" % n_open})
    elif n_open >= 8:
        score += 1
        worst = max(worst, 1)
    tier = _TIER_NAME.get(worst, "none") if n_open else "none"
    return {"tier": tier, "score": score, "reasons": reasons}

OUI = {
    "FCFBFB": "Apple", "F0F61C": "Apple", "A4B197": "Apple", "3C0754": "Apple",
    "8866A5": "Apple", "ACBC32": "Apple", "DCA904": "Apple", "F018A9": "Amazon",
    "44650D": "Amazon", "FCA667": "Amazon", "68543D": "Amazon", "B47C9C": "Amazon",
    "001A11": "Google", "F4F5E8": "Google", "3C5AB4": "Google", "A47733": "Google",
    "DA0F0E": "Google", "54600E": "Samsung", "E8508B": "Samsung", "FCC734": "Samsung",
    "5CF6DC": "Samsung", "D0176A": "Samsung", "8425DB": "Samsung", "B0EC8F": "Samsung",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi", "001132": "Synology",
    "0011D8": "Asustek", "0019DB": "Dell", "001A2B": "Cisco", "00000C": "Cisco",
    "F09FC2": "Ubiquiti", "FCECDA": "Ubiquiti", "245A4C": "Ubiquiti", "788A20": "Ubiquiti",
    "B4FBE3": "Ubiquiti", "0418D6": "Ubiquiti", "EC4364": "TP-Link", "50C7BF": "TP-Link",
    "C46E1F": "TP-Link", "1C61B4": "TP-Link", "9C5322": "TP-Link", "AC84C6": "TP-Link",
    "F4EC38": "TP-Link", "001E2A": "Netgear", "A040A0": "Netgear", "9CD36D": "Netgear",
    "20E52A": "Netgear", "44944C": "Netgear", "002590": "Supermicro", "000C29": "VMware",
    "005056": "VMware", "001C42": "Parallels", "080027": "VirtualBox", "525400": "QEMU/KVM",
    "001D0F": "TP-Link", "B0BE76": "TP-Link", "D8074F": "Belkin/Linksys", "C0C9E3": "Belkin",
    "000D4B": "Roku", "DC3A5E": "Roku", "B83E59": "Roku", "CC6DA0": "Roku",
    "001788": "Philips Hue", "00178A": "Philips", "ECB5FA": "Philips Hue",
    "D052A8": "Wink/IoT", "18B430": "Nest", "641666": "Nest", "F4F5D8": "Google Nest",
    "B0C554": "D-Link", "1CBDB9": "D-Link", "284C53": "Sony", "FCF152": "Sony",
    "60BEB5": "Microsoft", "7C1E52": "Microsoft", "C83F26": "Microsoft Surface",
    "001AA0": "Dell", "F8BC12": "Dell", "A4BB6D": "Dell", "B083FE": "Dell",
    "001B21": "Intel", "A0A8CD": "Intel", "8CC681": "Intel", "3C970E": "Intel",
    "9C7BEF": "Hewlett-Packard", "643150": "Hewlett-Packard", "001321": "HP",
    "70106F": "HP", "00904C": "Epson", "44D244": "Sonos", "5CAAFD": "Sonos",
    "B8E937": "Sonos", "000E58": "Sonos", "78281D": "Sonos", "001E8C": "Asus",
    "2C56DC": "Asus", "AC220B": "Asus", "04D4C4": "Asus", "D850E6": "Asus",
    "1831BF": "Asus", "186472": "Aruba", "94B40F": "Aruba", "ACA31E": "Aruba",
}

# --------------------------------------------------------------------------- #
# Network helpers
# --------------------------------------------------------------------------- #


def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def default_subnet():
    ip = get_primary_ip()
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


def default_gateway():
    try:
        if IS_WINDOWS:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=10, **SUBPROC_KW).stdout
            gws = re.findall(r"Default Gateway[ .:]*([\d]+\.[\d]+\.[\d]+\.[\d]+)", out)
            if gws:
                return gws[0]
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"default via ([\d.]+)", out)
            if m:
                return m.group(1)
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"gateway:\s*([\d.]+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def ping(host, timeout_ms=700):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    elif sys.platform == "darwin":
        # BSD/macOS ping: -W is the per-reply timeout in MILLISECONDS.
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms))), host]
    else:
        # Linux iputils ping: -W is in SECONDS.
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_ms / 1000.0)))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_ms / 1000.0 + 2, **SUBPROC_KW)
        text = (out.stdout or "") + (out.stderr or "")
        low = text.lower()
        alive = out.returncode == 0 and "unreachable" not in low and "100% packet loss" not in low
        if "ttl=" not in low and "ttl:" not in low:
            alive = alive and ("bytes from" in low or "reply from" in low)
            if IS_WINDOWS:
                alive = False
        ttl = None
        m = re.search(r"ttl[=\s:]*(\d+)", text, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
        latency = None
        m2 = re.search(r"time[=<]\s*([\d.]+)\s*ms", text, re.IGNORECASE)
        if m2:
            latency = float(m2.group(1))
        return alive, ttl, latency
    except Exception:
        return False, None, None


def scan_port(ip, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


_TCP_FALLBACK_PORTS = (80, 443, 22, 445, 139, 53, 8080, 3389)


def tcp_alive(ip, timeout=0.35):
    for p in _TCP_FALLBACK_PORTS:
        if scan_port(ip, p, timeout):
            return True
    return False


def host_alive_tcp(ip, ports=(80, 443, 22, 445), timeout=0.45):
    """Liveness without spawning a process: a connect that succeeds OR is refused
    (RST) proves the host is up. Scales to huge ranges where ping cannot."""
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def probe_host(ip):
    alive, ttl, latency = ping(ip)
    if alive:
        return {"ip": ip, "ttl": ttl, "latency": latency, "via": "icmp"}
    if tcp_alive(ip):
        return {"ip": ip, "ttl": None, "latency": None, "via": "tcp"}
    return None


def grab_banner(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in WEB_PORTS_HTTP or port == 80:
            s.sendall(("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Netryx\r\n\r\n" % ip).encode())
        try:
            data = s.recv(512)
        except Exception:
            data = b""
        s.close()
        if not data:
            return None
        text = data.decode("utf-8", errors="ignore")
        m = re.search(r"Server:\s*(.+)", text, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:80]
        line = re.sub(r"[^\x20-\x7e]", "", text.strip().splitlines()[0]) if text.strip() else ""
        return line[:80] or None
    except Exception:
        return None


def get_arp_table():
    table = {}
    try:
        if IS_WINDOWS:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                 timeout=15, **SUBPROC_KW).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
                if m:
                    table[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=15).stdout
            if not out.strip():
                out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines():
                ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                macm = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                if ipm and macm:
                    table[ipm.group(1)] = macm.group(1).lower()
    except Exception:
        pass
    return table


def reverse_dns(ip):
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def os_from_ttl(ttl):
    if ttl is None:
        return None
    if ttl > 128:
        return "Network device / Router"
    if ttl > 64:
        return "Windows"
    if ttl > 32:
        return "Linux / Unix / macOS / mobile"
    return "Unknown"


def web_url(ip, port):
    if port in WEB_PORTS_HTTPS:
        return "https://%s%s" % (ip, "" if port == 443 else ":%d" % port)
    if port in WEB_PORTS_HTTP:
        return "http://%s%s" % (ip, "" if port == 80 else ":%d" % port)
    return None


def get_ports(profile):
    if profile == "extended":
        s = set(range(1, 1025))
        s.update(COMMON_PORTS.keys())
        return sorted(s)
    if profile == "full":
        return list(range(1, 65536))
    return sorted(COMMON_PORTS.keys())


def wake_on_lan(mac):
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        raise ValueError("Invalid MAC address")
    packet = b"\xff" * 6 + bytes.fromhex(clean) * 16
    sent = 0
    for addr in ("255.255.255.255", "<broadcast>"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for port in (9, 7):
                s.sendto(packet, (addr, port))
                sent += 1
            s.close()
        except Exception:
            pass
    return sent > 0


# --------------------------------------------------------------------------- #
# SNMP (minimal v2c GET, pure stdlib BER/ASN.1)
# --------------------------------------------------------------------------- #

SNMP_SYSDESCR = "1.3.6.1.2.1.1.1.0"
SNMP_SYSNAME = "1.3.6.1.2.1.1.5.0"


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = b""
    while n:
        b = bytes([n & 0xFF]) + b
        n >>= 8
    return bytes([0x80 | len(b)]) + b


def _ber(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(n):
    if n == 0:
        body = b"\x00"
    else:
        body = b""
        x = n
        while x:
            body = bytes([x & 0xFF]) + body
            x >>= 8
        if body[0] & 0x80:
            body = b"\x00" + body
    return _ber(0x02, body)


def _ber_oid(oid):
    parts = [int(p) for p in oid.strip(".").split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            chunk = [p & 0x7F]
            p >>= 7
            while p:
                chunk.insert(0, (p & 0x7F) | 0x80)
                p >>= 7
            body += bytes(chunk)
    return _ber(0x06, body)


def _ber_tlvs(data):
    out = []
    i, n = 0, len(data)
    while i < n:
        tag = data[i]
        i += 1
        if i >= n:
            break
        ln = data[i]
        i += 1
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(data[i:i + k], "big")
            i += k
        out.append((tag, data[i:i + ln]))
        i += ln
    return out


def _decode_oid(body):
    if not body:
        return ""
    arcs = [body[0] // 40, body[0] % 40]
    v = 0
    for b in body[1:]:
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(v)
            v = 0
    return ".".join(str(a) for a in arcs)


def _decode_val(tag, body):
    if tag == 0x04:
        return body.decode("utf-8", "ignore").replace("\x00", "").strip()
    if tag == 0x06:
        return _decode_oid(body)
    if tag in (0x02, 0x41, 0x42, 0x43, 0x44, 0x46):
        return int.from_bytes(body, "big") if body else 0
    if tag == 0x05:
        return None
    return body.decode("latin-1", "ignore").strip()


def _snmp_parse(data):
    res = {}
    try:
        top = _ber_tlvs(data)
        if not top:
            return res
        seq = _ber_tlvs(top[0][1])
        pdu = None
        for tag, body in seq:
            if 0xA0 <= tag <= 0xA5:
                pdu = body
        if pdu is None:
            return res
        vblist = None
        for tag, body in _ber_tlvs(pdu):
            if tag == 0x30:
                vblist = body
        if vblist is None:
            return res
        for _tag, body in _ber_tlvs(vblist):
            kv = _ber_tlvs(body)
            if len(kv) >= 2:
                res[_decode_oid(kv[0][1])] = _decode_val(kv[1][0], kv[1][1])
    except Exception:
        pass
    return res


def _snmp_send(ip, oids, pdu_tag, community, timeout, port=161):
    """Send a v2c PDU (0xA0 GET / 0xA1 GETNEXT) and return the raw response bytes."""
    req_id = random.randint(1, 0x7FFFFFFF)
    vbs = b""
    for oid in oids:
        vbs += _ber(0x30, _ber_oid(oid) + _ber(0x05, b""))
    pdu = _ber(pdu_tag, _ber_int(req_id) + _ber_int(0) + _ber_int(0) + _ber(0x30, vbs))
    msg = _ber(0x30, _ber_int(1) + _ber(0x04, community.encode()) + pdu)  # version 1 == v2c
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (ip, int(port)))
        data, _ = s.recvfrom(8192)
        return data
    finally:
        try:
            s.close()
        except Exception:
            pass


def _snmp_parse_vbs(data):
    """Parse a response into (error_status, [(oid, value_tag, value), ...]), in order."""
    err, vbs = 0, []
    try:
        top = _ber_tlvs(data)
        if not top:
            return err, vbs
        seq = _ber_tlvs(top[0][1])
        pdu = None
        for tag, body in seq:
            if 0xA0 <= tag <= 0xA5:
                pdu = body
        if pdu is None:
            return err, vbs
        items = _ber_tlvs(pdu)
        if len(items) >= 2 and items[1][0] == 0x02 and items[1][1]:
            err = int.from_bytes(items[1][1], "big")
        vblist = None
        for tag, body in items:
            if tag == 0x30:
                vblist = body
        if vblist is None:
            return err, vbs
        for _t, body in _ber_tlvs(vblist):
            kv = _ber_tlvs(body)
            if len(kv) >= 2:
                vbs.append((_decode_oid(kv[0][1]), kv[1][0], _decode_val(kv[1][0], kv[1][1])))
    except Exception:
        pass
    return err, vbs


def snmp_get(ip, oids, community="public", timeout=0.9, port=161):
    """SNMP v2c GET one or more OIDs. Returns {oid: value} ({} on no response)."""
    try:
        data = _snmp_send(ip, oids, 0xA0, community, timeout, port)
    except Exception:
        return {}
    _err, vbs = _snmp_parse_vbs(data)
    return {oid: val for oid, _tag, val in vbs}


def snmp_walk(ip, base_oid, community="public", timeout=0.9, max_rows=256, port=161):
    """SNMP v2c walk (GETNEXT) of a subtree. Returns [{oid, value}, ...] in order."""
    base = (base_oid or "").strip().strip(".")
    if not base:
        return []
    prefix, cur, rows, seen = base + ".", base, [], set()
    try:
        max_rows = max(1, min(5000, int(max_rows)))
    except Exception:
        max_rows = 256
    for _ in range(max_rows):
        try:
            data = _snmp_send(ip, [cur], 0xA1, community, timeout, port)
        except Exception:
            break
        err, vbs = _snmp_parse_vbs(data)
        if err or not vbs:
            break
        oid, tag, val = vbs[0]
        if tag in (0x80, 0x81, 0x82):       # noSuchObject / noSuchInstance / endOfMibView
            break
        if not (oid == base or oid.startswith(prefix)):
            break
        if oid in seen:                     # guard against agents that loop
            break
        seen.add(oid)
        rows.append({"oid": oid, "value": val})
        cur = oid
    return rows


def snmp_probe(ip):
    r = snmp_get(ip, [SNMP_SYSDESCR, SNMP_SYSNAME, SNMP_SYSUPTIME,
                      SNMP_SYSLOCATION, SNMP_SYSCONTACT])
    if not r:
        return None
    out = {}
    if r.get(SNMP_SYSNAME):
        out["name"] = str(r[SNMP_SYSNAME])[:80]
    if r.get(SNMP_SYSDESCR):
        out["descr"] = str(r[SNMP_SYSDESCR])[:160]
    if r.get(SNMP_SYSLOCATION):
        out["location"] = str(r[SNMP_SYSLOCATION])[:80]
    if r.get(SNMP_SYSCONTACT):
        out["contact"] = str(r[SNMP_SYSCONTACT])[:80]
    up = r.get(SNMP_SYSUPTIME)
    if isinstance(up, int) and up > 0:
        out["uptime"] = _fmt_uptime(up)
    return out or None


# --------------------------------------------------------------------------- #
# mDNS / Bonjour
# --------------------------------------------------------------------------- #

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
MDNS_SERVICES = [
    "_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local",
    "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",
    "_scanner._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local",
    "_raop._tcp.local", "_spotify-connect._tcp.local", "_ssh._tcp.local",
    "_sftp-ssh._tcp.local", "_smb._tcp.local", "_afpovertcp._tcp.local",
    "_workstation._tcp.local", "_companion-link._tcp.local", "_homekit._tcp.local",
    "_hap._tcp.local", "_sonos._tcp.local", "_amzn-wplay._tcp.local",
    "_device-info._tcp.local", "_rfb._tcp.local",
]
SERVICE_MAP = {
    "_googlecast": "Chromecast", "_airplay": "AirPlay", "_raop": "AirPlay Audio",
    "_spotify-connect": "Spotify", "_ipp": "Printer", "_ipps": "Printer",
    "_printer": "Printer", "_pdl-datastream": "Printer", "_scanner": "Scanner",
    "_http": "Web UI", "_https": "Web UI", "_ssh": "SSH", "_sftp-ssh": "SSH",
    "_smb": "File share", "_afpovertcp": "Apple file share", "_nfs": "NFS",
    "_workstation": "Computer", "_homekit": "HomeKit", "_hap": "HomeKit",
    "_companion-link": "Apple device", "_sonos": "Sonos", "_amzn-wplay": "Amazon device",
    "_rfb": "VNC", "_device-info": "Device", "_hue": "Philips Hue",
}


def _service_label(svc):
    for k, v in SERVICE_MAP.items():
        if svc.startswith(k):
            return v
    return None


def _dns_encode_name(name):
    out = b""
    for part in name.split("."):
        if part == "":
            continue
        b = part.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _mdns_build_query(names, qtype=12):
    header = struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0)
    body = b""
    for n in names:
        body += _dns_encode_name(n) + struct.pack(">HH", qtype, 0x8001)  # QU + class IN
    return header + body


def _dns_read_name(data, off):
    labels = []
    next_off = None
    guard = 0
    while guard < 128:
        guard += 1
        if off >= len(data):
            break
        ln = data[off]
        if (ln & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                break
            if next_off is None:
                next_off = off + 2
            off = ((ln & 0x3F) << 8) | data[off + 1]
            continue
        off += 1
        if ln == 0:
            if next_off is None:
                next_off = off
            break
        labels.append(data[off:off + ln].decode("utf-8", "ignore"))
        off += ln
    if next_off is None:
        next_off = off
    return ".".join(labels), next_off


def _mdns_classify(owner, target, rec):
    label = _service_label(owner.split(".")[0])
    if label:
        rec["services"].add(label)
    if target and "._" in target:
        inst = target.split("._")[0]
        if inst and not inst.startswith("_"):
            rec["instances"].add(inst.replace("\\032", " ").strip())


def _mdns_parse(data, src_ip, found):
    try:
        if len(data) < 12:
            return
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
        off = 12
        for _ in range(qd):
            _, off = _dns_read_name(data, off)
            off += 4
        rec = found.setdefault(src_ip, {"host": None, "services": set(), "instances": set(), "model": None})
        for _ in range(an + ns + ar):
            name, off = _dns_read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rend = off + rdlen
            if rtype == 12:
                target, _ = _dns_read_name(data, off)
                _mdns_classify(name, target, rec)
            elif rtype == 33 and rdlen >= 6:
                target, _ = _dns_read_name(data, off + 6)
                if target.endswith(".local") and not rec["host"]:
                    rec["host"] = target[:-6]
            elif rtype == 1 and rdlen == 4:
                if name.endswith(".local") and not rec["host"]:
                    rec["host"] = name[:-6]
            elif rtype == 16 and rdlen > 0:
                _mdns_txt(data[off:off + rdlen], rec)
            off = rend
    except Exception:
        pass


def mdns_sweep(timeout=2.5):
    found = {}
    try:
        q = _mdns_build_query(MDNS_SERVICES)
    except Exception:
        return {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        bound = True
        try:
            s.bind(("", MDNS_PORT))
        except Exception:
            bound = False
            try:
                s.bind(("", 0))
            except Exception:
                pass
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except Exception:
            pass
        if bound:
            try:
                mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except Exception:
                pass
        s.settimeout(0.4)
        s.sendto(q, (MDNS_ADDR, MDNS_PORT))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                continue
            except Exception:
                break
            _mdns_parse(data, addr[0], found)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    out = {}
    for ip, rec in found.items():
        out[ip] = {"host": rec.get("host"), "services": sorted(rec["services"]),
                   "name": sorted(rec["instances"])[0] if rec["instances"] else None,
                   "model": rec.get("model")}
    return out


# --------------------------------------------------------------------------- #
# OUI vendor database
# --------------------------------------------------------------------------- #

_OUI_EXT = None
OUI_URLS = [
    "https://standards-oui.ieee.org/oui/oui.txt",
    "http://standards-oui.ieee.org/oui/oui.txt",
    "https://standards-oui.ieee.org/oui/oui.csv",
]


def _oui_search_paths():
    paths = []
    for d in (DATA_DIR, APP_DIR):
        for name in ("oui.csv", "oui.txt"):
            paths.append(os.path.join(d, name))
    return paths


def _load_oui_ext():
    global _OUI_EXT
    if _OUI_EXT is not None:
        return
    _OUI_EXT = {}
    for path in _oui_search_paths():
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = re.search(
                        r"([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})"
                        r"[\s,\"]+(?:\(hex\))?\s*[,\t]*\s*(.+)", line)
                    if m:
                        key = (m.group(1) + m.group(2) + m.group(3)).upper()
                        vendor = m.group(4).strip().strip('"').strip()
                        if key and vendor and key not in _OUI_EXT:
                            _OUI_EXT[key] = vendor[:60]
        except Exception:
            pass
        break


def oui_vendor(mac):
    if not mac:
        return None
    _load_oui_ext()
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    if key in OUI:
        return OUI[key]
    if _OUI_EXT and key in _OUI_EXT:
        return _OUI_EXT[key]
    return None


def oui_status():
    _load_oui_ext()
    path = None
    for p in _oui_search_paths():
        if os.path.exists(p):
            path = os.path.basename(p)
            break
    return {"builtin": len(OUI), "extended": len(_OUI_EXT or {}), "file": path}


def download_oui():
    global _OUI_EXT
    last_err = "no url reachable"
    for url in OUI_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Netryx/" + VERSION})
            with urllib.request.urlopen(req, timeout=90) as r:
                data = r.read()
            if not data or len(data) < 1000:
                last_err = "downloaded file looked empty"
                continue
            dest = os.path.join(DATA_DIR, "oui.csv" if url.endswith(".csv") else "oui.txt")
            with open(dest, "wb") as f:
                f.write(data)
            _OUI_EXT = None
            _load_oui_ext()
            return {"ok": True, "file": os.path.basename(dest),
                    "bytes": len(data), "entries": len(_OUI_EXT or {})}
        except Exception as e:
            last_err = str(e)
    return {"ok": False, "error": last_err}


# --------------------------------------------------------------------------- #
# Device-type heuristic
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Extra discovery probes (NetBIOS, SSDP/UPnP, HTTP title, TLS, presence, etc.)
# --------------------------------------------------------------------------- #

SNMP_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
SNMP_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
SNMP_SYSCONTACT = "1.3.6.1.2.1.1.4.0"
SNMP_SYSLOCATION = "1.3.6.1.2.1.1.6.0"
PRESENCE_FILE = os.path.join(DATA_DIR, "presence.json")


def mac_is_random(mac):
    """True if the MAC is locally-administered (randomized/private, e.g. a phone)."""
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02) and not bool(first & 0x01)
    except Exception:
        return False


def ttl_hops(ttl):
    if ttl is None:
        return None
    for base in (64, 128, 255):
        if ttl <= base:
            return base - ttl
    return None


def _fmt_uptime(ticks):
    secs = int(ticks) // 100
    d, h, m = secs // 86400, (secs % 86400) // 3600, (secs % 3600) // 60
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m


# ---- NetBIOS (Windows name / workgroup) ----------------------------------- #

def _nb_encode(name16):
    enc = b""
    for ch in name16:
        enc += bytes([0x41 + ((ch >> 4) & 0xF), 0x41 + (ch & 0xF)])
    return bytes([0x20]) + enc + b"\x00"


def netbios_query(ip, timeout=0.7):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    pkt = header + _nb_encode(b"*" + b"\x00" * 15) + struct.pack(">HH", 0x0021, 0x0001)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(2048)
        return _parse_nbstat(data)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _parse_nbstat(data):
    try:
        qd = struct.unpack(">H", data[4:6])[0]
        i = 12
        for _ in range(qd):
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            i += 1 + 4
        while i < len(data) and data[i] != 0:
            i += 1 + data[i]
        i += 1 + 8  # null + type(2)+class(2)+ttl(4)
        i += 2      # rdlength
        num = data[i]
        i += 1
        comp = wg = None
        for _ in range(num):
            nm = data[i:i + 15].decode("ascii", "ignore").strip()
            suffix = data[i + 15]
            flags = struct.unpack(">H", data[i + 16:i + 18])[0]
            i += 18
            grp = bool(flags & 0x8000)
            if suffix == 0x00 and not grp and not comp:
                comp = nm
            if suffix == 0x00 and grp and not wg:
                wg = nm
        if comp or wg:
            return {"name": comp, "group": wg}
    except Exception:
        pass
    return None


# ---- SSDP / UPnP ---------------------------------------------------------- #

def ssdp_sweep(timeout=3.0):
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    locations = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        s.bind(("", 0))
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except Exception:
            pass
        s.settimeout(0.5)
        s.sendto(msg, ("239.255.255.250", 1900))
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            m = re.search(r"LOCATION:\s*(\S+)", data.decode("utf-8", "ignore"), re.IGNORECASE)
            if m:
                locations.setdefault(addr[0], set()).add(m.group(1).strip())
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    out = {}

    def fetch(item):
        ip, urls = item
        for url in list(urls)[:1]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Netryx"})
                with urllib.request.urlopen(req, timeout=2.5) as r:
                    xml = r.read(16000).decode("utf-8", "ignore")
                info = {}
                for tag in ("friendlyName", "manufacturer", "modelName",
                            "modelNumber", "modelDescription", "deviceType"):
                    mm = re.search(r"<%s>([^<]+)</%s>" % (tag, tag), xml, re.IGNORECASE)
                    if mm:
                        info[tag] = mm.group(1).strip()[:80]
                if info:
                    return (ip, info)
            except Exception:
                continue
        return (ip, None)

    items = list(locations.items())
    if items:
        with ThreadPoolExecutor(max_workers=min(40, len(items))) as ex:
            for ip, info in ex.map(fetch, items):
                if info:
                    out[ip] = info
    return out


# ---- HTTP page title ------------------------------------------------------ #

def http_title(ip, port, timeout=1.5):
    scheme = "https" if port in WEB_PORTS_HTTPS else "http"
    url = "%s://%s:%d/" % (scheme, ip, port)
    ctx = None
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        except Exception:
            ctx = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Netryx"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            html = r.read(8192).decode("utf-8", "ignore")
        m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE | re.DOTALL)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()[:80] or None
    except Exception:
        return None
    return None


# ---- TLS certificate ------------------------------------------------------ #

def _fmt_asn1_time(tag, body):
    s = body.decode("ascii", "ignore")
    try:
        if tag == 0x17 and len(s) >= 6:       # UTCTime YYMMDD...
            yy = int(s[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return "%04d-%s-%s" % (year, s[2:4], s[4:6])
        if tag == 0x18 and len(s) >= 8:       # GeneralizedTime YYYYMMDD...
            return "%s-%s-%s" % (s[0:4], s[4:6], s[6:8])
    except Exception:
        pass
    return None


def _x509_find_cn(name_body):
    try:
        for _t, rdn in _ber_tlvs(name_body):          # RDN SET
            for _t2, atv in _ber_tlvs(rdn):            # AttributeTypeAndValue SEQ
                kv = _ber_tlvs(atv)
                if len(kv) >= 2 and kv[0][1] == b"\x55\x04\x03":   # OID 2.5.4.3 (CN)
                    return kv[1][1].decode("utf-8", "ignore")[:80]
    except Exception:
        pass
    return None


def _x509_cn_expiry(der):
    try:
        cert = _ber_tlvs(der)[0][1]
        tbs = _ber_tlvs(cert)[0][1]
        seqs = [b for (t, b) in _ber_tlvs(tbs) if t == 0x30]
        # seqs = [sigAlg, issuer, validity, subject, spki, ...]
        issuer_b, validity_b, subject_b = seqs[1], seqs[2], seqs[3]
        times = _ber_tlvs(validity_b)
        exp = _fmt_asn1_time(times[1][0], times[1][1]) if len(times) >= 2 else None
        cn = _x509_find_cn(subject_b)
        icn = _x509_find_cn(issuer_b)
        return cn, exp, bool(cn and cn == icn)
    except Exception:
        return None, None, False


def tls_info(ip, port, timeout=1.8):
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                info["proto"] = ss.version()
                c = ss.cipher()
                if c:
                    info["cipher"] = c[0]
                der = ss.getpeercert(binary_form=True)
        if der:
            cn, exp, self_signed = _x509_cn_expiry(der)
            if cn:
                info["cn"] = cn
            if exp:
                info["expires"] = exp
            info["self_signed"] = self_signed
    except Exception:
        return None
    return info or None


# ---- DNS servers / presence ----------------------------------------------- #

def dns_servers():
    out = set()
    try:
        if IS_WINDOWS:
            txt = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                                 timeout=10, **SUBPROC_KW).stdout
            in_dns = False
            for line in txt.splitlines():
                if "DNS Servers" in line:
                    in_dns = True
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        out.add(m.group(1))
                    continue
                if in_dns:
                    if re.match(r"\s+\d+\.\d+\.\d+\.\d+\s*$", line):
                        out.add(line.strip())
                    else:
                        in_dns = False
        else:
            try:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        m = re.match(r"\s*nameserver\s+([\d.]+)", line)
                        if m:
                            out.add(m.group(1))
            except Exception:
                pass
    except Exception:
        pass
    return out


def update_presence(devices):
    now = int(time.time())
    pres = _load_json(PRESENCE_FILE, {})
    for d in devices:
        k = d.get("mac") or d.get("ip")
        if not k:
            continue
        e = pres.get(k, {})
        e["first"] = e.get("first", now)
        e["last"] = now
        e["count"] = e.get("count", 0) + 1
        pres[k] = e
        d["first_seen"] = e["first"]
        d["last_seen"] = e["last"]
        d["seen_count"] = e["count"]
    _save_json(PRESENCE_FILE, pres)


def enrich_web(alive, job):
    targets = []
    for d in alive:
        for p in d.get("ports", []):
            if p.get("url"):
                targets.append((d["ip"], p))
    if not targets:
        return
    job["phase"] = "Reading web titles & TLS certificates"

    def work(item):
        ip, p = item
        t = http_title(ip, p["port"])
        if t:
            p["title"] = t
        if p["port"] in WEB_PORTS_HTTPS:
            ti = tls_info(ip, p["port"])
            if ti:
                p["tls"] = ti
        return None

    run_bounded(work, targets, 40, job)




def _mdns_txt(txt, rec):
    i = 0
    while i < len(txt):
        ln = txt[i]
        i += 1
        kv = txt[i:i + ln].decode("utf-8", "ignore")
        i += ln
        if "=" in kv:
            k, v = kv.split("=", 1)
            if k.lower() in ("model", "md", "ty") and v and not rec.get("model"):
                rec["model"] = v[:60]


def guess_device_type(d):
    ports = {p["port"] for p in d.get("ports", [])}
    vendor = (d.get("vendor") or "").lower()
    services = [s.lower() for s in d.get("mdns_services", [])]
    descr = ((d.get("snmp") or {}).get("descr") or "").lower()
    dtype = ((d.get("upnp") or {}).get("deviceType") or "").lower()
    model = (d.get("model") or "").lower()
    if "internetgatewaydevice" in dtype or "wandevice" in dtype:
        return "Router / Gateway"
    if "mediarenderer" in dtype or "mediaserver" in dtype:
        return "Media / Streaming"
    if "printer" in dtype or "printer" in model:
        return "Printer"
    if d.get("is_gateway") or any(k in descr for k in ("router", "gateway")):
        return "Router / Gateway"
    if any(k in descr for k in ("switch", "access point", "wireless")) or "aruba" in vendor:
        return "Network device"
    if "chromecast" in services or "airplay" in services or "sonos" in services or "roku" in vendor or "sonos" in vendor:
        return "Media / Streaming"
    if 32400 in ports or "plex" in vendor:
        return "Media server (Plex)"
    if "printer" in services or "scanner" in services or ports & {9100, 515, 631} or "epson" in vendor or "printer" in descr:
        return "Printer"
    if "homekit" in services or 8123 in ports or 1883 in ports or "hue" in services or "philips" in vendor or "nest" in vendor:
        return "IoT / Smart home"
    if "camera" in services or "axis" in vendor:
        return "Camera"
    if 62078 in ports or "apple" in vendor or "apple device" in services:
        return "Apple device"
    if 5555 in ports:
        return "Android device"
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if "synology" in vendor or "file share" in services or 2049 in ports:
        return "NAS / Storage"
    if ports & {3389, 445, 139} or "windows" in (d.get("os") or "").lower() or "microsoft" in vendor:
        return "Windows PC / Server"
    if ports & {22} and ports & {80, 443, 3306, 5432, 6379, 8080, 8443}:
        return "Server"
    if 22 in ports or "computer" in services:
        return "Computer"
    if ports & {80, 443}:
        return "Web-enabled device"
    return "Device"


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


_SAVE_LOCK = threading.Lock()


def _save_json(path, data):
    """Durably persist JSON: serialize under a lock, write to a temp file in the
    same directory, fsync, then atomically os.replace() into place. A crash or
    container kill can never leave a half-written tokens.json / auth.json /
    baseline.json behind, and concurrent writers can't interleave."""
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with _SAVE_LOCK:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        return True
    except Exception as e:
        try:
            os.remove(tmp)
        except Exception:
            pass
        # Don't fail silently — a non-writable data dir is the usual cause and
        # otherwise looks like "the UI/API did nothing".
        log("WARNING: could not write %s (%s) — is the data directory writable?" % (path, e))
        return False


def load_devices_meta():
    return _load_json(DEVICES_FILE, {})


def save_device_meta(key, name, notes):
    """Store a device's friendly name / notes. ``key`` is the MAC when we have
    one, otherwise the IP — devices on another subnet (behind a router) have no
    resolvable MAC, so we fall back to the IP as a stable-enough identity. MACs
    (colons) and IPs (dots) never collide as keys."""
    if not key:
        return False
    meta = load_devices_meta()
    entry = meta.get(key, {})
    if name is not None:
        entry["name"] = name
    if notes is not None:
        entry["notes"] = notes
    meta[key] = entry
    return _save_json(DEVICES_FILE, meta)


def load_seen():
    return set(_load_json(SEEN_FILE, []))


def save_seen(seen):
    _save_json(SEEN_FILE, sorted(seen))


def save_history(subnet, devices, source="unknown", status="complete"):
    """Persist a scan snapshot. ``source`` records what triggered the scan
    (manual / monitor / schedule / mcp / api / cli) and ``status`` whether it
    completed or was stopped — so every scan in history is differentiable."""
    ts = int(time.time())
    _save_json(os.path.join(HISTORY_DIR, "scan_%d.json" % ts),
               {"time": ts, "subnet": subnet, "count": len(devices),
                "source": source or "unknown", "status": status, "devices": devices})
    try:
        files = sorted(f for f in os.listdir(HISTORY_DIR) if f.startswith("scan_"))
        for old in files[:-50]:
            os.remove(os.path.join(HISTORY_DIR, old))
    except Exception:
        pass


def list_history():
    items = []
    try:
        for f in os.listdir(HISTORY_DIR):
            if f.startswith("scan_") and f.endswith(".json"):
                rec = _load_json(os.path.join(HISTORY_DIR, f), None)
                if rec:
                    items.append({"file": f, "time": rec.get("time"),
                                  "subnet": rec.get("subnet"), "count": rec.get("count"),
                                  "source": rec.get("source") or "unknown",
                                  "status": rec.get("status") or "complete"})
    except Exception:
        pass
    items.sort(key=lambda x: x.get("time") or 0, reverse=True)
    return items


# --------------------------------------------------------------------------- #
# Known-good baseline + proactive events (rogue / new-open-port detection)
#
# Approve the current network as a "baseline", then every later scan is diffed
# against it. The first sighting of an unapproved device or an unapproved open
# port becomes an event: logged locally and pushed to a webhook and/or MQTT.
# All optional and configured via environment variables.
# --------------------------------------------------------------------------- #

BASELINE_FILE = os.path.join(DATA_DIR, "baseline.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
ALERTS_FILE = os.path.join(DATA_DIR, "alerts_seen.json")
EVENTS_MAX = 500
NETRYX_WEBHOOK = os.environ.get("NETRYX_WEBHOOK", "").strip()
NETRYX_MQTT = os.environ.get("NETRYX_MQTT", "").strip()          # host or host:port
NETRYX_MQTT_TOPIC = os.environ.get("NETRYX_MQTT_TOPIC", "netryx/events").strip()
NETRYX_MQTT_USER = os.environ.get("NETRYX_MQTT_USER", "").strip()
NETRYX_MQTT_PASS = os.environ.get("NETRYX_MQTT_PASS", "")


def _bkey(d):
    return d.get("mac") or d.get("ip")


def _baseline_entry(d, now):
    return {"ip": d.get("ip"), "mac": d.get("mac"),
            "name": d.get("name") or d.get("hostname") or d.get("mdns_name"),
            "ports": sorted({p.get("port") for p in d.get("ports", [])}),
            "approved": now}


def load_baseline():
    return _load_json(BASELINE_FILE, {"created": None, "updated": None, "devices": {}})


def save_baseline(b):
    _save_json(BASELINE_FILE, b)
    return b


def baseline_from_devices(devices):
    """Replace the baseline with the supplied devices (approve current state)."""
    now = time.time()
    b = load_baseline()
    b["created"] = b.get("created") or now
    b["updated"] = now
    b["devices"] = {_bkey(d): _baseline_entry(d, now) for d in devices if _bkey(d)}
    return save_baseline(b)


def approve_devices(keys, devices):
    """Add specific devices (by mac/ip key) to the existing baseline."""
    now = time.time()
    b = load_baseline()
    b["created"] = b.get("created") or now
    by = {_bkey(d): d for d in devices}
    for k in keys:
        if by.get(k):
            b["devices"][k] = _baseline_entry(by[k], now)
    b["updated"] = now
    return save_baseline(b)


def clear_baseline():
    return save_baseline({"created": None, "updated": None, "devices": {}})


def diff_against_baseline(devices, b=None):
    """Compare devices to the baseline: rogue (unapproved) devices, unapproved
    open ports on approved devices, and approved devices now missing."""
    b = b if b is not None else load_baseline()
    base = b.get("devices", {})
    rogue, new_ports, seen = [], [], set()
    for d in devices:
        k = _bkey(d)
        if not k:
            continue
        seen.add(k)
        if k not in base:
            rogue.append({"key": k, "ip": d.get("ip"), "mac": d.get("mac"),
                          "name": d.get("name") or d.get("hostname") or d.get("mdns_name"),
                          "vendor": d.get("vendor"), "device_type": d.get("device_type"),
                          "open_ports": [p.get("port") for p in d.get("ports", [])],
                          "risk": (d.get("risk") or risk_of(d)).get("tier")})
        else:
            approved = set(base[k].get("ports", []))
            for p in d.get("ports", []):
                if p.get("port") not in approved:
                    new_ports.append({"key": k, "ip": d.get("ip"), "port": p.get("port"),
                                      "service": p.get("service"), "url": p.get("url")})
    missing = [{"key": k, "ip": v.get("ip"), "mac": v.get("mac"), "name": v.get("name")}
               for k, v in base.items() if k not in seen]
    return {"rogue_devices": rogue, "new_ports": new_ports,
            "missing_devices": missing, "baseline_size": len(base)}


# ---- event hub: in-memory ring + ids + a condition for push (SSE / long-poll) ----
EVENT_SEVERITY = {
    "rogue_device": "critical", "new_open_port": "high", "exposure_alert": "high",
    "device_missing": "warning", "scan_complete": "info",
}
SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}
EVENTS_LOCK = threading.Lock()
RECENT_EVENTS = []          # [{id,time,kind,severity,data}], newest last
_EVENT_SEQ = 0


class _EventHub:
    """Notify-on-new-event primitive for same-process SSE / long-poll waiters."""
    def __init__(self):
        self.cond = threading.Condition()
        self.seq = 0

    def publish(self):
        with self.cond:
            self.seq += 1
            self.cond.notify_all()

    def wait(self, last_seq, timeout):
        with self.cond:
            if self.seq <= last_seq:
                self.cond.wait(timeout)
            return self.seq


EVENT_HUB = _EventHub()


def _load_recent_events():
    global RECENT_EVENTS, _EVENT_SEQ
    evs = _load_json(EVENTS_FILE, []) or []
    seq = 0
    for e in evs:
        if not e.get("id"):
            seq += 1
            e["id"] = seq
        else:
            seq = max(seq, e["id"])
        e.setdefault("severity", EVENT_SEVERITY.get(e.get("kind"), "info"))
    RECENT_EVENTS = evs[-EVENTS_MAX:]
    _EVENT_SEQ = max([e.get("id", 0) for e in RECENT_EVENTS], default=0)
    EVENT_HUB.seq = _EVENT_SEQ


def list_events(limit=100):
    with EVENTS_LOCK:
        evs = list(RECENT_EVENTS)
    return (evs[-int(limit):] if limit else evs)[::-1]


def events_since(since):
    with EVENTS_LOCK:
        return [e for e in RECENT_EVENTS if e.get("id", 0) > since]


def record_event(kind, data):
    global _EVENT_SEQ
    with EVENTS_LOCK:
        _EVENT_SEQ += 1
        ev = {"id": _EVENT_SEQ, "time": time.time(), "kind": kind,
              "severity": EVENT_SEVERITY.get(kind, "info"), "data": data}
        RECENT_EVENTS.append(ev)
        if len(RECENT_EVENTS) > EVENTS_MAX:
            del RECENT_EVENTS[:-EVENTS_MAX]
        _save_json(EVENTS_FILE, RECENT_EVENTS)
    EVENT_HUB.publish()          # wake SSE / long-poll waiters (same process)
    return ev


def _sse_frame(e):
    # No "event:" line so browser EventSource.onmessage receives every event;
    # kind/severity live inside the JSON payload.
    return ("id: %d\ndata: %s\n\n" % (e.get("id", 0), json.dumps(e))).encode("utf-8")


try:
    _load_recent_events()
except Exception:
    pass


def _emit(events):
    """Best-effort delivery of fresh events to webhook + MQTT, off-thread."""
    if not events or not (NETRYX_WEBHOOK or NETRYX_MQTT):
        return
    payload = {"source": "netryx", "host": get_primary_ip(),
               "time": time.time(), "events": events}

    def worker():
        if NETRYX_WEBHOOK:
            try:
                req = urllib.request.Request(
                    NETRYX_WEBHOOK, data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).read()
            except Exception:
                pass
        if NETRYX_MQTT:
            try:
                mqtt_publish(NETRYX_MQTT_TOPIC, json.dumps(payload))
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()


def evaluate_baseline(devices):
    """Diff a finished scan against the baseline and emit an event the first
    time each rogue device / unapproved open port is seen."""
    b = load_baseline()
    if not b.get("devices"):
        return None  # no baseline -> nothing to police
    diff = diff_against_baseline(devices, b)
    seen = set(_load_json(ALERTS_FILE, []))
    fresh = []
    for r in diff["rogue_devices"]:
        sig = "rogue:" + str(r["key"])
        if sig not in seen:
            seen.add(sig)
            fresh.append(record_event("rogue_device", r))
    for p in diff["new_ports"]:
        sig = "port:%s:%s" % (p["key"], p["port"])
        if sig not in seen:
            seen.add(sig)
            fresh.append(record_event("new_open_port", p))
    _save_json(ALERTS_FILE, sorted(seen))
    _emit(fresh)
    return diff


def _emit_scan_events(job, alive, subnet):
    """After a finished scan: critical-exposure alerts (deduped) + scan_complete."""
    fresh = []
    seen = set(_load_json(ALERTS_FILE, []))
    changed = False
    for d in alive:
        r = d.get("risk") or risk_of(d)
        if r.get("tier") == "critical":
            sig = "exp:" + str(_bkey(d))
            if sig not in seen:
                seen.add(sig)
                changed = True
                fresh.append(record_event("exposure_alert", {
                    "key": _bkey(d), "ip": d.get("ip"),
                    "name": d.get("name") or d.get("hostname") or d.get("mdns_name"),
                    "tier": r.get("tier"), "score": r.get("score"),
                    "reasons": r.get("reasons"),
                    "open_ports": [p.get("port") for p in d.get("ports", [])]}))
    if changed:
        _save_json(ALERTS_FILE, sorted(seen))
    fresh.append(record_event("scan_complete", {
        "subnet": subnet, "count": len(alive),
        "new_devices": len(job.get("new_devices") or []),
        "new_ports": job.get("new_ports", 0)}))
    _emit(fresh)


# ---- minimal MQTT 3.1.1 QoS0 publisher (stdlib sockets only) ----

def _mqtt_rl(n):
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            return bytes(out)


def _mqtt_str(text):
    raw = text.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


def mqtt_publish(topic, message, timeout=5):
    """Publish one QoS0 message to NETRYX_MQTT ('host' or 'host:port'),
    then disconnect. Returns True on success."""
    host, _, port = NETRYX_MQTT.partition(":")
    port = int(port) if port else 1883
    flags = 0x02  # clean session
    body = _mqtt_str("netryx-%d" % (os.getpid() & 0xFFFF))
    if NETRYX_MQTT_USER:
        flags |= 0x80
        body += _mqtt_str(NETRYX_MQTT_USER)
        if NETRYX_MQTT_PASS:
            flags |= 0x40
            body += _mqtt_str(NETRYX_MQTT_PASS)
    var = _mqtt_str("MQTT") + bytes([0x04, flags]) + struct.pack("!H", 60)
    connect = bytes([0x10]) + _mqtt_rl(len(var + body)) + var + body
    pub_var = _mqtt_str(topic)
    pub_pay = message.encode("utf-8")
    publish = bytes([0x30]) + _mqtt_rl(len(pub_var + pub_pay)) + pub_var + pub_pay
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(connect)
        try:
            sock.recv(4)  # CONNACK (best-effort)
        except Exception:
            pass
        sock.sendall(publish)
        sock.sendall(bytes([0xE0, 0x00]))  # DISCONNECT
    finally:
        sock.close()
    return True


# --------------------------------------------------------------------------- #
# API tokens + access control
# --------------------------------------------------------------------------- #

def load_tokens():
    d = _load_json(TOKENS_FILE, {"tokens": []})
    if "tokens" not in d:
        d = {"tokens": []}
    return d


def save_tokens(d):
    _save_json(TOKENS_FILE, d)
    return d


def list_tokens():
    return load_tokens().get("tokens", [])


def create_token(name="token", expires_days=None):
    d = load_tokens()
    exp = None
    try:
        if expires_days not in (None, "", 0, "0"):
            exp = time.time() + float(expires_days) * 86400
    except Exception:
        exp = None
    rec = {"id": secrets.token_hex(5), "name": (str(name or "token"))[:60],
           "token": "nsk_" + secrets.token_urlsafe(32),
           "created": time.time(), "last_used": None, "expires": exp}
    d.setdefault("tokens", []).append(rec)
    save_tokens(d)
    return rec


def delete_token(tid):
    d = load_tokens()
    n0 = len(d.get("tokens", []))
    d["tokens"] = [t for t in d.get("tokens", []) if t.get("id") != tid]
    save_tokens(d)
    return len(d["tokens"]) != n0


def token_valid(value):
    if not value:
        return False
    if NETRYX_TOKEN and hmac.compare_digest(value, NETRYX_TOKEN):
        return True
    d = load_tokens()
    now = time.time()
    hit = None
    for t in d.get("tokens", []):
        if hmac.compare_digest(value, t.get("token", "")):
            if t.get("expires") and now > t["expires"]:
                return False
            hit = t
            break
    if hit:
        hit["last_used"] = now
        save_tokens(d)
        return True
    return False


PBKDF2_ITER = 200000


def _hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, PBKDF2_ITER).hex()


def set_admin(username, password):
    salt = secrets.token_bytes(16)
    a = {"username": (str(username or "admin").strip() or "admin"),
         "salt": salt.hex(), "hash": _hash_pw(password or "admin", salt),
         "algo": "pbkdf2_sha256", "iter": PBKDF2_ITER, "updated": time.time()}
    _save_json(AUTH_FILE, a)
    return a


def load_admin():
    a = _load_json(AUTH_FILE, None)
    if a and a.get("hash") and a.get("salt") and a.get("username"):
        return a
    # First launch: seed from env if a password was supplied, else default admin/admin.
    return set_admin(NETRYX_USER, NETRYX_PASS or "admin")


def verify_admin(username, password):
    a = load_admin()
    try:
        calc = _hash_pw(password, bytes.fromhex(a["salt"]))
    except Exception:
        return False
    if hmac.compare_digest(str(username or ""), a.get("username", "")) and \
            hmac.compare_digest(calc, a.get("hash", "")):
        return True
    # Env credentials always work too (recovery / ops override).
    if NETRYX_PASS and hmac.compare_digest(str(username or ""), NETRYX_USER) and \
            hmac.compare_digest(str(password or ""), NETRYX_PASS):
        return True
    return False


def is_default_admin():
    return verify_admin("admin", "admin")


def auth_configured():
    # Auth is on by default: a default admin/admin credential is always present.
    # Set NETRYX_OPEN=1 to run fully open on a trusted segment.
    return not NETRYX_OPEN


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238) - optional second factor at login.
# Compatible with Google Authenticator, Microsoft Authenticator, Authy,
# 1Password, Bitwarden - anything that speaks the standard otpauth:// URI.
# Stdlib only: secrets + hmac + hashlib + struct + base64.
# --------------------------------------------------------------------------- #
TOTP_FILE = os.path.join(DATA_DIR, "totp.json")
TOTP_LOCK = threading.Lock()
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1   # accept the previous + next 30s step to tolerate clock skew


def _b32_encode(raw):
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32_decode(s):
    s = (s or "").strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * ((-len(s)) % 8))


def totp_secret_new():
    """Fresh 160-bit base32 secret per RFC 6238 recommendation."""
    return _b32_encode(secrets.token_bytes(20))


def totp_compute(secret_b32, counter):
    try:
        key = _b32_decode(secret_b32)
    except Exception:
        return ""
    msg = struct.pack(">Q", int(counter))
    h = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (((h[off] & 0x7F) << 24) | ((h[off + 1] & 0xFF) << 16)
            | ((h[off + 2] & 0xFF) << 8) | (h[off + 3] & 0xFF))
    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def totp_verify(secret_b32, code):
    if not secret_b32 or not code:
        return False
    code = str(code).strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return False
    now_counter = int(time.time() // TOTP_PERIOD)
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if hmac.compare_digest(code, totp_compute(secret_b32, now_counter + delta)):
            return True
    return False


def _totp_key(username):
    return (username or "").strip().lower()


def totp_load():
    return _load_json(TOTP_FILE, {})


def totp_save(data):
    _save_json(TOTP_FILE, data)


def totp_enabled(username):
    return bool(totp_load().get(_totp_key(username), {}).get("secret"))


def totp_get_secret(username):
    return totp_load().get(_totp_key(username), {}).get("secret")


def totp_set(username, secret):
    with TOTP_LOCK:
        d = totp_load()
        d[_totp_key(username)] = {"secret": secret, "enabled_at": time.time()}
        totp_save(d)


def totp_clear(username):
    with TOTP_LOCK:
        d = totp_load()
        if d.pop(_totp_key(username), None) is not None:
            totp_save(d)
            return True
    return False


def totp_provisioning_uri(username, secret, issuer="Netryx"):
    label = quote("%s:%s" % (issuer, username), safe="")
    params = urlencode({"secret": secret, "issuer": issuer,
                        "algorithm": "SHA1", "digits": TOTP_DIGITS,
                        "period": TOTP_PERIOD})
    return "otpauth://totp/%s?%s" % (label, params)


# ---------------------------------------------------------------------------
# Pure-stdlib QR encoder (ISO/IEC 18004) — byte mode, EC level L, versions 1-10.
# Validated bit-perfect against the qrcode python library across 21 fixed-mask tests.
# Used only by the TOTP enrollment endpoint to render an inline scannable QR SVG.
# ---------------------------------------------------------------------------
# GF(256) tables (primitive poly x^8+x^4+x^3+x^2+1 = 0x11d)
_EXP=[0]*512; _LOG=[0]*256
_x=1
for _i in range(255):
    _EXP[_i]=_x; _LOG[_x]=_i; _x<<=1
    if _x&0x100: _x^=0x11d
for _i in range(255,512): _EXP[_i]=_EXP[_i-255]

def _mul(a,b):
    if a==0 or b==0: return 0
    return _EXP[_LOG[a]+_LOG[b]]

def _rs_gen(degree):
    g=[1]
    for i in range(degree):
        ng=[0]*(len(g)+1)
        for j in range(len(g)):
            ng[j]^=g[j]
            ng[j+1]^=_mul(g[j], _EXP[i])
        g=ng
    return g

def _rs_encode(data, ec_len):
    g=_rs_gen(ec_len)
    msg=list(data)+[0]*ec_len
    for i in range(len(data)):
        c=msg[i]
        if c:
            for j in range(len(g)):
                msg[i+j]^=_mul(g[j],c)
    return msg[len(data):]

# Each spec entry is a list of groups: [(num_blocks, data_per_block, ec_per_block), ...]
# Authoritative values from qrcode lib / ISO/IEC 18004 Table 9 (EC level L)
_SPEC={1:[(1,19,7)],2:[(1,34,10)],3:[(1,55,15)],4:[(1,80,20)],5:[(1,108,26)],
       6:[(2,68,18)],7:[(2,78,20)],8:[(2,97,24)],9:[(2,116,30)],
       10:[(2,68,18),(2,69,18)]}
_ALIGN={1:[],2:[6,18],3:[6,22],4:[6,26],5:[6,30],6:[6,34],
        7:[6,22,38],8:[6,24,42],9:[6,26,46],10:[6,28,50]}
_REM={1:0,2:7,3:7,4:7,5:7,6:7,7:0,8:0,9:0,10:0}

def _cap(v):
    total=sum(n*dpb for n,dpb,_ in _SPEC[v])
    cci = 16 if v>=10 else 8
    return (total*8 - 4 - cci) // 8

def _pick(n):
    for v in range(1,11):
        if _cap(v)>=n: return v
    raise ValueError("payload too long for v1-10 L: %d bytes" % n)

def _build_cws(text, v):
    groups=_SPEC[v]
    total=sum(n*dpb for n,dpb,_ in groups)
    data=text.encode('utf-8')
    bits=[]
    def push(val,n):
        for i in range(n-1,-1,-1): bits.append((val>>i)&1)
    push(0b0100,4)
    push(len(data), 16 if v>=10 else 8)   # byte mode: 8-bit count for v1-9, 16-bit for v10+
    for b in data: push(b,8)
    push(0, min(4, total*8-len(bits)))
    while len(bits)%8: bits.append(0)
    cws=[]
    for i in range(0,len(bits),8):
        v8=0
        for j in range(8): v8=(v8<<1)|bits[i+j]
        cws.append(v8)
    pad=[0xEC,0x11]; pi=0
    while len(cws)<total:
        cws.append(pad[pi%2]); pi+=1
    # Split into blocks per group, compute EC per block
    blk_d=[]; blk_e=[]; pos=0
    for nb,dpb,ecpb in groups:
        for _ in range(nb):
            b=cws[pos:pos+dpb]; pos+=dpb
            blk_d.append(b); blk_e.append(_rs_encode(b,ecpb))
    # Interleave column-major across all blocks (handles mixed sizes too)
    max_d=max(len(b) for b in blk_d)
    max_e=max(len(e) for e in blk_e)
    out=[]
    for col in range(max_d):
        for b in blk_d:
            if col<len(b): out.append(b[col])
    for col in range(max_e):
        for e in blk_e:
            if col<len(e): out.append(e[col])
    return out

def _mask(p,r,c):
    if p==0: return (r+c)%2==0
    if p==1: return r%2==0
    if p==2: return c%3==0
    if p==3: return (r+c)%3==0
    if p==4: return (r//2 + c//3)%2==0
    if p==5: return (r*c)%2 + (r*c)%3 == 0
    if p==6: return ((r*c)%2 + (r*c)%3)%2 == 0
    if p==7: return ((r+c)%2 + (r*c)%3)%2 == 0
    return False

def _build_matrix(v, cws, mask):
    size=17+4*v
    m=[[0]*size for _ in range(size)]
    fn=[[False]*size for _ in range(size)]
    def F(r,c,val):
        if 0<=r<size and 0<=c<size:
            m[r][c]=val; fn[r][c]=True
    # Finders + separators
    def finder(top, left):
        for dr in range(-1,8):
            for dc in range(-1,8):
                r,c=top+dr, left+dc
                if not(0<=r<size and 0<=c<size): continue
                if dr in (-1,7) or dc in (-1,7): F(r,c,0)
                elif dr in (0,6) or dc in (0,6): F(r,c,1)
                elif 2<=dr<=4 and 2<=dc<=4: F(r,c,1)
                else: F(r,c,0)
    finder(0,0); finder(0,size-7); finder(size-7,0)
    # Timing
    for i in range(8, size-8):
        F(6,i,(i+1)%2); F(i,6,(i+1)%2)
    # Alignment
    centers=_ALIGN[v]
    for cy in centers:
        for cx in centers:
            if (cy==6 and cx==6) or (cy==6 and cx==size-7) or (cy==size-7 and cx==6):
                continue
            for dr in range(-2,3):
                for dc in range(-2,3):
                    r,c=cy+dr, cx+dc
                    if abs(dr)==2 or abs(dc)==2: F(r,c,1)
                    elif abs(dr)==1 or abs(dc)==1: F(r,c,0)
                    else: F(r,c,1)
    # Dark module
    F(size-8, 8, 1)
    # Reserve format info
    for i in range(9):
        if not fn[8][i]: F(8,i,0)
        if not fn[i][8]: F(i,8,0)
    for i in range(size-8, size):
        if not fn[8][i]: F(8,i,0)
        if not fn[i][8]: F(i,8,0)
    # Reserve version info (v7+)
    if v>=7:
        for i in range(18):
            r=i//3; c=size-11+(i%3)
            F(r,c,0); F(c,r,0)
    # Data placement (zigzag from bottom-right)
    bits=[]
    for cw in cws:
        for i in range(7,-1,-1): bits.append((cw>>i)&1)
    for _ in range(_REM[v]): bits.append(0)
    bit_idx=0; up=True
    col=size-1
    while col>0:
        if col==6: col-=1
        rows = range(size-1,-1,-1) if up else range(size)
        for r in rows:
            for cc in (col, col-1):
                if cc<0: continue
                if not fn[r][cc]:
                    bit = bits[bit_idx] if bit_idx<len(bits) else 0
                    bit_idx+=1
                    if _mask(mask, r, cc): bit^=1
                    m[r][cc] = bit
        col -= 2
        up = not up
    return m, fn

def _bch15_5(d):
    g=0b10100110111
    rem=d<<10
    for i in range(14,9,-1):
        if rem & (1<<i):
            rem ^= g<<(i-10)
    return (d<<10)|rem

def _bch18_6(d):
    g=0b1111100100101
    rem=d<<12
    for i in range(17,11,-1):
        if rem & (1<<i):
            rem ^= g<<(i-12)
    return (d<<12)|rem

def _place_format(m, size, mask):
    fmt = _bch15_5((0b01<<3) | mask) ^ 0b101010000010010
    # Positions (15 bits, two copies)
    tl=[(8,0),(8,1),(8,2),(8,3),(8,4),(8,5),(8,7),(8,8),
        (7,8),(5,8),(4,8),(3,8),(2,8),(1,8),(0,8)]
    br=[(size-1,8),(size-2,8),(size-3,8),(size-4,8),(size-5,8),(size-6,8),(size-7,8),
        (8,size-8),(8,size-7),(8,size-6),(8,size-5),(8,size-4),(8,size-3),(8,size-2),(8,size-1)]
    for i in range(15):
        bit=(fmt>>(14-i))&1
        m[tl[i][0]][tl[i][1]]=bit
        m[br[i][0]][br[i][1]]=bit

def _place_version(m, size, v):
    if v<7: return
    vi=_bch18_6(v)
    for i in range(18):
        bit=(vi>>i)&1
        r=i//3; c=size-11+(i%3)
        m[r][c]=bit
        m[c][r]=bit

def _score(m, size):
    s=0
    # N1: runs >=5
    for r in range(size):
        rc=-1; rl=0
        for c in range(size):
            if m[r][c]==rc: rl+=1
            else:
                if rl>=5: s+=3+(rl-5)
                rc=m[r][c]; rl=1
        if rl>=5: s+=3+(rl-5)
    for c in range(size):
        rc=-1; rl=0
        for r in range(size):
            if m[r][c]==rc: rl+=1
            else:
                if rl>=5: s+=3+(rl-5)
                rc=m[r][c]; rl=1
        if rl>=5: s+=3+(rl-5)
    # N2: 2x2 blocks
    for r in range(size-1):
        for c in range(size-1):
            v=m[r][c]
            if m[r][c+1]==v and m[r+1][c]==v and m[r+1][c+1]==v:
                s+=3
    # N3: finder-like pattern
    p1=[1,0,1,1,1,0,1,0,0,0,0]
    p2=[0,0,0,0,1,0,1,1,1,0,1]
    for r in range(size):
        row=m[r]
        for c in range(size-10):
            seg=row[c:c+11]
            if seg==p1 or seg==p2: s+=40
    for c in range(size):
        col=[m[r][c] for r in range(size)]
        for r in range(size-10):
            if col[r:r+11]==p1 or col[r:r+11]==p2: s+=40
    # N4: dark percentage deviation
    dark=sum(1 for r in range(size) for c in range(size) if m[r][c]==1)
    pct=(dark*100)//(size*size)
    s += (abs(pct-50)//5)*10
    return s

def encode(text):
    """Return (matrix, version, mask) — best mask chosen by penalty score."""
    data=text.encode('utf-8')
    v=_pick(len(data))
    cws=_build_cws(text, v)
    best=None
    for mask in range(8):
        m,fn=_build_matrix(v, cws, mask)
        size=17+4*v
        _place_format(m, size, mask)
        _place_version(m, size, v)
        sc=_score(m, size)
        if best is None or sc<best[0]:
            best=(sc, m, mask)
    return best[1], v, best[2]

def to_svg(m, quiet=4):
    """Render the QR matrix as a responsive inline SVG (sizes to its container)."""
    size=len(m); full=size+2*quiet
    paths=[]
    for r in range(size):
        for c in range(size):
            if m[r][c]==1:
                paths.append('M%d %dh1v1h-1z'%(quiet+c, quiet+r))
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" '
            'width="100%%" preserveAspectRatio="xMidYMid meet" shape-rendering="crispEdges">'
            '<rect width="100%%" height="100%%" fill="#ffffff"/>'
            '<path d="%s" fill="#000000"/></svg>') % (full,full,''.join(paths))


def _qr_svg(text):
    """Encode text and return a scannable QR as an SVG string."""
    m, _v, _mask = encode(text)
    return to_svg(m)



def token_name(value):
    """Name of the managed token matching `value` (for audit / caller identity)."""
    if not value:
        return None
    if NETRYX_TOKEN and hmac.compare_digest(value, NETRYX_TOKEN):
        return "env-token"
    for t in load_tokens().get("tokens", []):
        if hmac.compare_digest(value, t.get("token", "")):
            return t.get("name") or t.get("id")
    return None


# ---- MCP / API audit trail (append-only JSONL) + live subscriber registry ----
AUDIT_FILE = os.path.join(DATA_DIR, "mcp_audit.log")
AUDIT_MAX = 2000
SUBSCRIBERS_FILE = os.path.join(DATA_DIR, "mcp_subscribers.json")
_AUDIT_LOCK = threading.Lock()


def audit(kind, **rec):
    """Best-effort append of one audit record. Never raises into the caller."""
    try:
        rec["kind"] = kind
        rec["time"] = time.time()
        line = json.dumps(rec, default=str)
        with _AUDIT_LOCK:
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            if os.path.getsize(AUDIT_FILE) > 1500000:        # trim when large
                with open(AUDIT_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-AUDIT_MAX:]
                with open(AUDIT_FILE, "w", encoding="utf-8") as f:
                    f.writelines(lines)
    except Exception:
        pass


def list_audit(limit=200):
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return []
    out = []
    for ln in (lines[-int(limit):] if limit else lines):
        ln = ln.strip()
        if ln:
            try:
                out.append(json.loads(ln))
            except Exception:
                pass
    return out[::-1]


def sub_register(sid, **info):
    try:
        with _AUDIT_LOCK:
            d = _load_json(SUBSCRIBERS_FILE, {}) or {}
            cur = d.get(sid, {})
            cur.update(info)
            cur["id"] = sid
            cur.setdefault("since", time.time())
            cur["last_seen"] = time.time()
            d[sid] = cur
            _save_json(SUBSCRIBERS_FILE, d)
    except Exception:
        pass


def sub_heartbeat(sid):
    try:
        with _AUDIT_LOCK:
            d = _load_json(SUBSCRIBERS_FILE, {}) or {}
            if sid in d:
                d[sid]["last_seen"] = time.time()
                _save_json(SUBSCRIBERS_FILE, d)
    except Exception:
        pass


def sub_remove(sid):
    try:
        with _AUDIT_LOCK:
            d = _load_json(SUBSCRIBERS_FILE, {}) or {}
            if d.pop(sid, None) is not None:
                _save_json(SUBSCRIBERS_FILE, d)
    except Exception:
        pass


def list_subscribers(active_secs=45):
    d = _load_json(SUBSCRIBERS_FILE, {}) or {}
    now = time.time()
    items = sorted(d.values(), key=lambda x: x.get("last_seen", 0), reverse=True)
    for it in items:
        it["active"] = (now - it.get("last_seen", 0)) <= active_secs
    return items


def _audit_mcp(transport, who, ip, req):
    """Audit one JSON-RPC request (initialize / tools/call) — best effort."""
    try:
        m = req.get("method")
        if m == "initialize":
            ci = (req.get("params") or {}).get("clientInfo") or {}
            audit("init", transport=transport, caller=who, ip=ip,
                  client=ci.get("name"), client_version=ci.get("version"))
        elif m == "tools/call":
            audit("call", transport=transport, caller=who, ip=ip,
                  tool=((req.get("params") or {}).get("name")))
    except Exception:
        pass


# ---- browser login sessions (cookie-based; in-memory) ----
SESSIONS = {}                # token -> expiry epoch
SESSIONS_LOCK = threading.Lock()
try:
    SESSION_TTL = max(1, int(os.environ.get("NETRYX_SESSION_DAYS", "30"))) * 86400
except Exception:
    SESSION_TTL = 30 * 86400


def new_session():
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with SESSIONS_LOCK:
        for k in [k for k, v in SESSIONS.items() if v < now]:
            SESSIONS.pop(k, None)
        SESSIONS[tok] = now + SESSION_TTL
    return tok


def session_valid(tok):
    if not tok:
        return False
    with SESSIONS_LOCK:
        exp = SESSIONS.get(tok)
        if exp and exp > time.time():
            return True
        if exp:
            SESSIONS.pop(tok, None)
    return False


def drop_session(tok):
    with SESSIONS_LOCK:
        SESSIONS.pop(tok, None)


def login_page():
    hint = ('<div class="hint">Default login is <b>admin</b> / <b>admin</b> — change it after signing in.</div>'
            if is_default_admin() else '')
    return ("""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Netryx - Sign in</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAzMiAzMic+PHJlY3Qgd2lkdGg9JzMyJyBoZWlnaHQ9JzMyJyByeD0nNycgZmlsbD0nIzBkMTExNycvPjxjaXJjbGUgY3g9JzE2JyBjeT0nMTYnIHI9JzExJyBmaWxsPSdub25lJyBzdHJva2U9JyMzMDM2M2QnIHN0cm9rZS13aWR0aD0nMicvPjxjaXJjbGUgY3g9JzE2JyBjeT0nMTYnIHI9JzcnIGZpbGw9J25vbmUnIHN0cm9rZT0nIzFmNmZlYicgc3Ryb2tlLXdpZHRoPScyJy8+PGNpcmNsZSBjeD0nMTYnIGN5PScxNicgcj0nMycgZmlsbD0nIzU4YTZmZicvPjwvc3ZnPg==">
<script>(function(){try{var t=localStorage.getItem('ns_theme');if(t!=='light'&&t!=='dark'&&t!=='medium')t=(window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';document.documentElement.setAttribute('data-theme',t);}catch(_){document.documentElement.setAttribute('data-theme','dark');}})();</script>
<style>
/* Dark dimmed (default). The early <script> applies the saved ns_theme so the login page
   matches whatever the user last chose in the app (dark / medium / light). */
:root{--bg:#22272e;--panel:#2d333b;--border:#444c56;--text:#adbac7;--muted:#768390;--cyan:#539bf5;--blue:#316dca;--red:#e5534b;
  --primary:#347d39;--primary-hi:#46954a;--inbg:#1c2128}
html[data-theme="light"]{--bg:#ffffff;--panel:#f6f8fa;--border:#d0d7de;--text:#1f2328;--muted:#656d76;--cyan:#0969da;--blue:#0969da;--red:#cf222e;
  --primary:#1f883d;--primary-hi:#1a7f37;--inbg:#ffffff}
html[data-theme="medium"]{--bg:#d4dbe3;--panel:#e2e7ed;--border:#b0bac5;--text:#1c2128;--muted:#4a5560;--cyan:#0a5cc0;--blue:#0a5cc0;--red:#cf222e;
  --primary:#1f883d;--primary-hi:#1a7f37;--inbg:#eaeef2}
/* No-JS fallback: honour OS preference only when no theme has been chosen yet */
@media (prefers-color-scheme: light){html:not([data-theme]){--bg:#ffffff;--panel:#f6f8fa;--border:#d0d7de;--text:#1f2328;--muted:#656d76;--cyan:#0969da;--blue:#0969da;--red:#cf222e;
  --primary:#1f883d;--primary-hi:#1a7f37;--inbg:#ffffff}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--text);
  background:var(--bg)}
.card{width:min(380px,92vw);background:var(--panel);
  border:1px solid var(--border);border-radius:6px;padding:34px 30px;box-shadow:0 8px 24px rgba(1,4,9,.5)}
.brand{display:flex;flex-direction:column;align-items:center;text-align:center;margin-bottom:22px}
.brand h1{font-size:18px;letter-spacing:4px;margin:14px 0 2px;font-weight:700}
.brand .namerow{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;justify-content:center}
.brand .tagsep{color:var(--muted);opacity:.6;font-size:12px}
.brand .tag{font-size:10.5px;letter-spacing:3px;text-transform:uppercase;color:var(--muted);font-family:ui-monospace,monospace}
.brand .tagline{font-size:9px;letter-spacing:1.4px;text-transform:uppercase;color:var(--muted);opacity:.6;font-family:ui-monospace,monospace}
label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:14px 0 6px}
input{width:100%;background:var(--inbg);border:1px solid var(--border);color:var(--text);
  border-radius:6px;padding:11px 13px;font-size:14px;outline:none;transition:.15s}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(83,155,245,.4)}
button{width:100%;margin-top:20px;border:1px solid rgba(205,217,229,.1);border-radius:6px;padding:12px;font-size:14px;font-weight:500;
  color:#fff;background:var(--primary);cursor:pointer}
button:hover{background:var(--primary-hi)}
button:active{transform:translateY(1px)}
.err{margin-top:14px;min-height:18px;color:var(--red);font-size:12.5px;text-align:center}
.hint{margin-top:18px;text-align:center;color:var(--muted);font-size:11px;font-family:ui-monospace,monospace}
.hint b{color:var(--cyan);font-weight:600}
.remember{display:flex;align-items:center;gap:8px;margin-top:16px;font-size:13px;color:var(--muted)}
.remember input{width:auto;margin:0;cursor:pointer}
.remember label{margin:0;text-transform:none;letter-spacing:0;font-size:13px;color:var(--muted);cursor:pointer}
</style></head><body>
<form class="card" id="f" onsubmit="return go(event)">
  <div class="brand">
    <svg width="46" height="46" viewBox="0 0 40 40" fill="none">
      <circle cx="20" cy="20" r="18" stroke="#203a5e"/><circle cx="20" cy="20" r="12" stroke="#203a5e"/>
      <circle cx="20" cy="20" r="6" stroke="#49d8f2"/><circle cx="20" cy="20" r="3" fill="#ecb24a"/>
      <circle cx="32" cy="20" r="1.7" fill="#49d8f2"/><circle cx="14" cy="8" r="1.7" fill="#49d8f2"/>
      <circle cx="9" cy="27" r="1.7" fill="#3b82f6"/><circle cx="28" cy="31" r="1.7" fill="#49d8f2"/></svg>
    <div class="namerow"><h1>NETRYX</h1><span class="tagsep">·</span><span class="tag">Network Intelligence</span><span class="tagline">› Discover · Monitor · Automate</span></div>
  </div>
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" autofocus required>
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <div id="totp-step" style="display:none;margin-top:14px">
    <label for="c">6-digit code</label>
    <input id="c" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" placeholder="123456" style="font-family:ui-monospace,monospace;font-size:18px;letter-spacing:.25em;text-align:center">
  </div>
  <div class="remember">
    <input type="checkbox" id="rm" checked>
    <label for="rm">Remember me on this device</label>
  </div>
  <button type="submit">Sign in</button>
  <div class="err" id="err"></div>
  __HINT__
</form>
<script>
async function go(e){
  e.preventDefault();
  var err=document.getElementById('err'); err.textContent='';
  try{
    var rm=document.getElementById('rm').checked;
    try{localStorage.setItem('ns_remember',rm?'1':'0');}catch(_){}
    var body={username:document.getElementById('u').value,password:document.getElementById('p').value,remember:rm};
    var codeEl=document.getElementById('c');
    if(codeEl && codeEl.value) body.code=codeEl.value.replace(/\\D/g,'');
    var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    var d=await r.json().catch(function(){return {};});
    if(r.ok && d.ok){location.href='/';return false;}
    if(d.requires_2fa){
      var step=document.getElementById('totp-step'); if(step)step.style.display='';
      var c=document.getElementById('c'); if(c){c.required=true;c.focus();}
      err.textContent=d.error||'Enter the 6-digit code from your authenticator app.';
      return false;
    }
    err.textContent=d.error||'Sign in failed';
  }catch(_){err.textContent='Could not reach the server';}
  return false;
}
// Restore the user's last "Remember me" choice (default checked).
(function(){try{var v=localStorage.getItem('ns_remember');if(v==='0'){var el=document.getElementById('rm');if(el)el.checked=false;}}catch(_){}})();
</script></body></html>""").replace("__HINT__", hint)


# --------------------------------------------------------------------------- #
# Job manager
# --------------------------------------------------------------------------- #

JOBS = {}
JOBS_LOCK = threading.Lock()
JOB_COUNTER = 0
LAST_RESULTS = {"subnet": None, "devices": []}
SCAN_LOCK = threading.Lock()          # guarantees only one discovery scan runs at a time


def discovery_running():
    """Return the currently-running discovery job, if any (else None)."""
    for j in list(JOBS.values()):
        if j.get("type") == "discovery" and j.get("status") == "running":
            return j
    return None


# ---- scheduled scans (server-side; runs even with no browser open) ----
SCHEDULE_FILE = os.path.join(DATA_DIR, "schedule.json")
SCHEDULE_MIN = 60               # 1 minute
SCHEDULE_MAX = 2592000          # 30 days
_LAST_SCHED_RUN = 0.0


def load_schedule():
    s = _load_json(SCHEDULE_FILE, {}) or {}
    try:
        interval = max(SCHEDULE_MIN, min(SCHEDULE_MAX, int(s.get("interval", 3600))))
    except Exception:
        interval = 3600
    return {"enabled": bool(s.get("enabled")), "interval": interval,
            "targets": s.get("targets") or "", "scan_ports": bool(s.get("scan_ports", False)),
            "port_profile": s.get("port_profile", "quick"), "use_mdns": bool(s.get("use_mdns", True)),
            "use_snmp": bool(s.get("use_snmp", True)), "workers": s.get("workers", "auto"),
            "last_run": s.get("last_run")}


def save_schedule(patch):
    cur = load_schedule()
    cur.update(patch or {})
    try:
        cur["interval"] = max(SCHEDULE_MIN, min(SCHEDULE_MAX, int(cur.get("interval", 3600))))
    except Exception:
        cur["interval"] = 3600
    _save_json(SCHEDULE_FILE, cur)
    return cur


def _scheduler_loop():
    global _LAST_SCHED_RUN
    _LAST_SCHED_RUN = time.time()       # wait one full interval before the first scheduled run
    while True:
        try:
            s = load_schedule()
            if s.get("enabled") and (time.time() - _LAST_SCHED_RUN) >= s["interval"] \
                    and not discovery_running():
                targets = (s.get("targets") or "").strip() or default_subnet()
                _LAST_SCHED_RUN = time.time()
                save_schedule({"last_run": _LAST_SCHED_RUN})
                log("scheduler: starting scheduled scan of %s" % targets)
                start_job("discovery", run_discovery, targets, s.get("scan_ports", False),
                          s.get("port_profile", "quick"), s.get("use_mdns", True),
                          s.get("use_snmp", True), s.get("workers", "auto"), source="schedule")
        except Exception as e:
            log("scheduler error: %s" % e)
        time.sleep(10)


def _restore_last_results():
    """On startup, repopulate LAST_RESULTS from the most recent saved scan so the
    dashboard, baseline diff and MCP reflect the previous run after a restart."""
    try:
        hist = list_history()
        if hist:
            rec = _load_json(os.path.join(HISTORY_DIR, hist[0]["file"]), None)
            if rec and rec.get("devices"):
                LAST_RESULTS["subnet"] = rec.get("subnet")
                # Overlay the latest saved friendly names — the snapshot may
                # predate a rename done after that scan.
                LAST_RESULTS["devices"] = apply_meta(rec.get("devices", []))
    except Exception:
        pass


def new_job(jtype):
    global JOB_COUNTER
    with JOBS_LOCK:
        JOB_COUNTER += 1
        jid = str(JOB_COUNTER)
        JOBS[jid] = {"id": jid, "type": jtype, "status": "running", "phase": "Starting",
                     "total": 0, "done": 0, "devices": [], "result": None,
                     "error": None, "new_devices": [], "new_ports": 0,
                     "cancel": False, "stopped": False, "started": time.time()}
    return jid, JOBS[jid]


def run_bounded(fn, items, workers, job, on_result=None):
    """Run fn over items with bounded concurrency and cooperative cancellation.

    Keeps at most ~`workers` futures in flight (memory-safe even for a full
    65535-port sweep), and stops promptly when job['cancel'] is set.
    """
    it = iter(items)
    inflight = set()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        try:
            for _ in range(workers):
                inflight.add(ex.submit(fn, next(it)))
        except StopIteration:
            pass
        while inflight:
            done, inflight = wait(inflight, timeout=0.5, return_when=FIRST_COMPLETED)
            inflight = set(inflight)
            for f in done:
                if on_result is not None:
                    try:
                        on_result(f.result())
                    except Exception:
                        pass
            if job.get("cancel"):
                for f in inflight:
                    f.cancel()
                break
            try:
                for _ in range(len(done)):
                    inflight.add(ex.submit(fn, next(it)))
            except StopIteration:
                pass


def start_job(jtype, fn, *args, source=None):
    jid, job = new_job(jtype)
    if source:
        job["source"] = source

    def wrap():
        try:
            fn(job, *args)
        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)

    threading.Thread(target=wrap, daemon=True).start()
    return jid


def compute_workers(profile, requested="auto"):
    """Pick a worker count. An explicit positive number wins; otherwise auto-scale
    from this machine's CPU count and the scan profile (I/O-bound, so generous)."""
    try:
        if requested not in (None, "", "auto", "Auto", "AUTO"):
            n = int(requested)
            if n > 0:
                return max(1, min(2000, n))
    except Exception:
        pass
    cpu = os.cpu_count() or 4
    if profile == "full":
        return max(200, min(1000, cpu * 128))
    if profile == "extended":
        return max(150, min(800, cpu * 96))
    return max(100, min(400, cpu * 64))


def parse_targets(text):
    """Expand a free-form list of CIDRs / IPs / ranges into a deduped host list.
    Accepts e.g. "192.168.1.0/24, 10.0.0.5, 10.20.1.1-50, 10.5.0.0/22".
    Returns (hosts, target_index_per_host, targets_meta, errors)."""
    toks = [t for t in re.split(r"[\s,;]+", (text or "").strip()) if t]
    specs, errors = [], []
    for t in toks:
        try:
            if "-" in t and "/" not in t:
                lo, hi = t.split("-", 1)
                lo_i = int(ipaddress.ip_address(lo.strip()))
                hs = hi.strip()
                hi_i = int(ipaddress.ip_address(hs)) if "." in hs \
                    else int(ipaddress.ip_address(lo.strip().rsplit(".", 1)[0] + "." + hs))
                if hi_i < lo_i:
                    lo_i, hi_i = hi_i, lo_i
                if hi_i - lo_i + 1 > 65536:
                    raise ValueError("range larger than a /16")
                specs.append((t, "range", lo_i, hi_i))
            elif "/" in t:
                _net = ipaddress.ip_network(t, strict=False)
                if _net.version == 4 and _net.prefixlen < 16:
                    raise ValueError("prefix broader than /16")
                specs.append((t, "net", _net))
            else:
                ipaddress.ip_address(t)
                specs.append((t, "ip", t))
        except Exception:
            errors.append(t)
    hosts, idx, targets, seen, LIMIT = [], [], [], set(), 65534
    for ti, spec in enumerate(specs):
        c0 = len(hosts)
        if spec[1] == "net":
            net = spec[2]
            gen = (str(h) for h in net.hosts()) if net.num_addresses > 2 else (str(a) for a in net)
            for ip in gen:
                if ip in seen:
                    continue
                seen.add(ip); hosts.append(ip); idx.append(ti)
                if len(hosts) >= LIMIT:
                    break
        elif spec[1] == "ip":
            if spec[2] not in seen:
                seen.add(spec[2]); hosts.append(spec[2]); idx.append(ti)
        else:
            for n in range(spec[2], spec[3] + 1):
                ip = str(ipaddress.ip_address(n))
                if ip in seen:
                    continue
                seen.add(ip); hosts.append(ip); idx.append(ti)
                if len(hosts) >= LIMIT:
                    break
        targets.append({"cidr": spec[0], "total": len(hosts) - c0, "done": 0, "found": 0})
        if len(hosts) >= LIMIT:
            break
    return hosts, idx, targets, errors


def _prev_snapshot(subnet):
    """Devices from the most recent prior scan of this subnet (for change detection)."""
    if LAST_RESULTS.get("subnet") == subnet and LAST_RESULTS.get("devices"):
        return LAST_RESULTS["devices"]
    for it in list_history():
        if it.get("subnet") == subnet:
            rec = _load_json(os.path.join(HISTORY_DIR, it["file"]), None)
            if rec:
                return rec.get("devices", [])
    return []


def _dkey(d):
    return d.get("mac") or d.get("ip")


def apply_meta(devices):
    """Overlay the latest saved friendly name / notes (keyed by MAC, else IP)
    onto a device list. Names live in devices.json independent of any scan
    snapshot, so this keeps them correct after a restart or when loading an
    older scan from history."""
    meta = load_devices_meta()
    for d in devices or []:
        m = meta.get(d.get("mac") or d.get("ip"))
        if m:
            if m.get("name") is not None:
                d["name"] = m.get("name")
            if m.get("notes") is not None:
                d["notes"] = m.get("notes")
    return devices


def _finalize(job, alive, subnet, cancelled):
    alive.sort(key=lambda d: socket.inet_aton(d["ip"]))
    job["devices"] = alive
    src = job.get("source") or "unknown"
    if cancelled:
        job["stopped"] = True
        job["phase"] = "Stopped"
        job["status"] = "done"
        # A stopped scan still ran — record it (tagged) so nothing is missed.
        save_history(subnet, alive, src, status="stopped")
        return
    job["phase"] = "Done"
    job["status"] = "done"
    LAST_RESULTS["subnet"] = subnet
    LAST_RESULTS["devices"] = alive
    save_history(subnet, alive, src, status="complete")


def run_discovery(job, subnet, scan_ports=False, port_profile="quick",
                  use_mdns=True, use_snmp=True, req_workers="auto"):
    """Single-scan gate: only one discovery scan runs at a time. If a scan is
    already in flight (manual, live-monitor or scheduled), this job is skipped
    rather than run in parallel — it keeps the last results and returns."""
    if not SCAN_LOCK.acquire(blocking=False):
        other = next((j for j in list(JOBS.values())
                      if j.get("type") == "discovery" and j.get("status") == "running"
                      and j.get("id") != job.get("id")), None)
        job["status"] = "done"
        job["phase"] = "Skipped — a scan is already running"
        job["note"] = "skipped: a scan was already running" + (
            " (job %s)" % other["id"] if other and other.get("id") else "")
        job["skipped"] = True
        job["devices"] = list(LAST_RESULTS.get("devices", []))
        job["total"] = len(job["devices"])
        job["done"] = job["total"]
        return
    try:
        _run_discovery_inner(job, subnet, scan_ports, port_profile,
                             use_mdns, use_snmp, req_workers)
    finally:
        SCAN_LOCK.release()


def _run_discovery_inner(job, subnet, scan_ports=False, port_profile="quick",
                         use_mdns=True, use_snmp=True, req_workers="auto"):
    hosts, host_idx, targets, errors = parse_targets(subnet)
    if not hosts:
        job["status"] = "error"
        job["error"] = "No valid targets" + (": " + ", ".join(errors) if errors else "")
        return
    notes = []
    if errors:
        notes.append("ignored: " + ", ".join(errors[:6]))
    if len(hosts) >= 65534:
        notes.append("capped at 65534 hosts")
    if notes:
        job["note"] = " · ".join(notes)
    job["targets"] = targets
    subnet = " ".join(sorted(t for t in re.split(r"[\s,;]+", (subnet or "").strip()) if t))
    big = len(hosts) > 1024
    items = list(zip(hosts, host_idx))

    # snapshot of the previous scan, used to highlight new devices and new ports
    prev_devices = _prev_snapshot(subnet)
    have_prev = len(prev_devices) > 0
    prev_map = {_dkey(d): {p["port"] for p in d.get("ports", [])} for d in prev_devices}

    job["phase"] = "Discovering live hosts" + (" (fast TCP sweep)" if big else "")
    job["total"] = len(hosts)
    job["done"] = 0
    alive = []
    lock = threading.Lock()

    if big:
        def probe(item):
            ip, ti = item
            if job.get("cancel"):
                return
            up = host_alive_tcp(ip)
            with lock:
                job["done"] += 1
                targets[ti]["done"] += 1
                if up:
                    targets[ti]["found"] += 1
                    alive.append({"ip": ip, "ttl": None, "latency": None, "via": "tcp"})
        run_bounded(probe, items, compute_workers("full", req_workers), job)
        alive.sort(key=lambda d: socket.inet_aton(d["ip"]))
        job["devices"] = list(alive)
    else:
        def probe(item):
            ip, ti = item
            if job.get("cancel"):
                return
            r = probe_host(ip)
            with lock:
                job["done"] += 1
                targets[ti]["done"] += 1
                if r:
                    targets[ti]["found"] += 1
                    alive.append(r)
                    job["devices"] = sorted(alive, key=lambda d: socket.inet_aton(d["ip"]))
        run_bounded(probe, items, 160, job)
    if job.get("cancel"):
        for d in alive:
            d.setdefault("ports", [])
            d["device_type"] = "Device"
            d["new"] = False
        return _finalize(job, alive, subnet, True)

    job["phase"] = "Resolving names, vendors, mDNS & SNMP"
    job["total"] = 0
    arp = get_arp_table()
    gw = default_gateway()
    self_ip = get_primary_ip()
    dnssrv = dns_servers()
    meta = load_devices_meta()
    mdns_map, ssdp_map = {}, {}
    if not job.get("cancel"):
        with ThreadPoolExecutor(max_workers=2) as _ex:
            _fm = _ex.submit(mdns_sweep) if use_mdns else None
            _fs = _ex.submit(ssdp_sweep)
            try:
                mdns_map = _fm.result() if _fm else {}
            except Exception:
                mdns_map = {}
            try:
                ssdp_map = _fs.result()
            except Exception:
                ssdp_map = {}

    def enrich(d):
        ip = d["ip"]
        if big and d.get("ttl") is None and not job.get("cancel"):
            _al, _ttl, _lat = ping(ip)
            if _ttl is not None:
                d["ttl"] = _ttl
            if _lat is not None:
                d["latency"] = _lat
        mac = arp.get(ip)
        d["mac"] = mac
        d["vendor"] = oui_vendor(mac) if mac else None
        d["random_mac"] = mac_is_random(mac)
        d["hostname"] = reverse_dns(ip)
        d["os"] = os_from_ttl(d.get("ttl"))
        d["hops"] = ttl_hops(d.get("ttl"))
        d["detect"] = d.get("via")
        d["is_gateway"] = bool(gw and ip == gw)
        d["is_self"] = (ip == self_ip)
        d["is_dns"] = (ip in dnssrv)
        m = meta.get(mac or ip)   # MAC when we have one, else the IP fallback key
        d["name"] = (m or {}).get("name")
        d["notes"] = (m or {}).get("notes")
        md = mdns_map.get(ip)
        d["mdns_services"] = md.get("services", []) if md else []
        d["mdns_name"] = md.get("name") if md else None
        d["model"] = md.get("model") if md else None
        if md and not d["hostname"] and md.get("host"):
            d["hostname"] = md["host"] + ".local"
        sd = ssdp_map.get(ip)
        if sd:
            d["upnp"] = sd
            if not d["model"] and sd.get("modelName"):
                d["model"] = sd["modelName"] + (
                    " " + sd["modelNumber"] if sd.get("modelNumber") else "")
            if not d["mdns_name"] and sd.get("friendlyName"):
                d["mdns_name"] = sd["friendlyName"]
        if not job.get("cancel"):
            nb = netbios_query(ip)
            if nb:
                d["netbios"] = nb
                if not d["hostname"] and nb.get("name"):
                    d["hostname"] = nb["name"]
        if use_snmp and not job.get("cancel"):
            sn = snmp_probe(ip)
            if sn:
                d["snmp"] = sn
                if not d["hostname"] and sn.get("name"):
                    d["hostname"] = sn["name"]
        return d

    with ThreadPoolExecutor(max_workers=64) as ex:
        alive = list(ex.map(enrich, alive))

    if scan_ports and not job.get("cancel"):
        ports = get_ports(port_profile)
        pairs = [(d["ip"], p) for d in alive for p in ports]
        job["phase"] = "Scanning %d ports across %d hosts" % (len(ports), len(alive))
        job["total"] = max(1, len(pairs))
        job["done"] = 0
        results = {d["ip"]: [] for d in alive}
        timeout = 0.35 if port_profile == "full" else 0.5
        # I/O-bound connect scan: scale concurrency with the workload (bounded).
        workers = compute_workers(port_profile, req_workers)

        def scan_pair(pair):
            if job.get("cancel"):
                return None
            ip, p = pair
            ok = scan_port(ip, p, timeout)
            with lock:
                job["done"] += 1
            return (ip, p) if ok else None

        def collect(res):
            if res:
                results[res[0]].append(res[1])

        run_bounded(scan_pair, pairs, workers, job, on_result=collect)

        open_pairs = [(ip, p) for ip, ps in results.items() for p in ps]
        banners = {}
        if open_pairs and not job.get("cancel"):
            run_bounded(lambda t: (t[0], t[1], grab_banner(t[0], t[1])), open_pairs, 80, job,
                        on_result=lambda r: banners.__setitem__((r[0], r[1]), r[2]))
        for d in alive:
            ops = sorted(results.get(d["ip"], []))
            d["ports"] = [{"port": p, "service": COMMON_PORTS.get(p, "unknown"),
                           "banner": banners.get((d["ip"], p)), "url": web_url(d["ip"], p)}
                          for p in ops]
            d["device_type"] = guess_device_type(d)
    else:
        for d in alive:
            d.setdefault("ports", [])
            d["device_type"] = guess_device_type(d)

    # ---- change detection vs the previous scan ----
    new_devices, new_ports_total = [], 0
    for d in alive:
        k = _dkey(d)
        d["new"] = bool(have_prev and k not in prev_map)
        prevports = prev_map.get(k)
        changed = False
        for p in d.get("ports", []):
            isnew = bool(prevports is not None and p["port"] not in prevports)
            p["new"] = isnew
            if isnew:
                changed = True
                new_ports_total += 1
        d["changed"] = changed and not d["new"]
        d["risk"] = risk_of(d)
        if d["new"]:
            new_devices.append(k)
    job["new_devices"] = new_devices
    job["new_ports"] = new_ports_total

    if not job.get("cancel"):
        enrich_web(alive, job)
        update_presence(alive)
        try:
            evaluate_baseline(alive)
        except Exception:
            pass
        try:
            _emit_scan_events(job, alive, subnet)
        except Exception:
            pass

    _finalize(job, alive, subnet, bool(job.get("cancel")))


def run_portscan(job, ip, profile="extended", req_workers="auto"):
    ports = get_ports(profile)
    job["phase"] = "Scanning %d ports on %s" % (len(ports), ip)
    job["total"] = len(ports)
    job["done"] = 0
    lock = threading.Lock()
    found = []
    timeout = 0.35 if profile == "full" else 0.5

    def scan_one(p):
        if job.get("cancel"):
            return None
        ok = scan_port(ip, p, timeout)
        with lock:
            job["done"] += 1
        return p if ok else None

    run_bounded(scan_one, ports, compute_workers(profile, req_workers), job,
                on_result=lambda r: found.append(r) if r is not None else None)
    found.sort()
    open_ports = [{"port": p, "service": COMMON_PORTS.get(p, "unknown"),
                   "banner": grab_banner(ip, p), "url": web_url(ip, p)} for p in found]
    job["result"] = open_ports
    prev_ports = set()
    for d in LAST_RESULTS.get("devices", []):
        if d.get("ip") == ip:
            prev_ports = {p["port"] for p in d.get("ports", [])}
            for op in open_ports:
                op["new"] = op["port"] not in prev_ports
            d["ports"] = open_ports
            d["device_type"] = guess_device_type(d)
            d["risk"] = risk_of(d)
            break
    if job.get("cancel"):
        job["stopped"] = True
        job["phase"] = "Stopped"
    else:
        job["phase"] = "Done"
    job["status"] = "done"


def run_oui_download(job):
    job["phase"] = "Downloading IEEE OUI vendor database (~5 MB)"
    res = download_oui()
    if res.get("ok"):
        job["result"] = res
        job["phase"] = "Done"
        job["status"] = "done"
    else:
        job["status"] = "error"
        job["error"] = res.get("error", "download failed")


# --------------------------------------------------------------------------- #
# Synchronous API (used by the CLI and the MCP server)
# --------------------------------------------------------------------------- #


def discover(targets, scan_ports=False, port_profile="quick",
             use_mdns=True, use_snmp=True, req_workers="auto", source="api"):
    """Run one full discovery synchronously and return the result.

    This is the building block shared by the ``--scan`` CLI and the MCP server:
    it drives the same ``run_discovery`` pipeline the web UI uses, but in the
    caller's thread, and hands back a plain dict instead of a background job.

    Returns {"devices", "new_devices", "new_ports", "targets", "note", "error"}.
    """
    _jid, job = new_job("discovery")
    job["source"] = source or "api"
    run_discovery(job, targets, bool(scan_ports), port_profile,
                  bool(use_mdns), bool(use_snmp), req_workers)
    return {
        "devices": job.get("devices", []),
        "new_devices": job.get("new_devices", []),
        "new_ports": job.get("new_ports", 0),
        "targets": job.get("targets", []),
        "note": job.get("note"),
        "error": job.get("error"),
    }


def _print_scan_table(res):
    """Human-readable summary of a discover() result for the CLI."""
    devs = res.get("devices", [])
    note = (" - " + res["note"]) if res.get("note") else ""
    print("Found %d device(s)%s\n" % (len(devs), note))
    hdr = "%-15s  %-17s  %-24s  %-8s  %s" % ("IP", "MAC", "NAME / HOSTNAME", "RISK", "OPEN PORTS")
    print(hdr)
    print("-" * len(hdr))
    for d in devs:
        ports = ",".join(str(p["port"]) for p in d.get("ports", []))
        risk = (d.get("risk") or {}).get("tier", "none")
        name = d.get("name") or d.get("hostname") or d.get("mdns_name") or ""
        flags = []
        if d.get("is_gateway"):
            flags.append("GW")
        if d.get("is_self"):
            flags.append("YOU")
        if d.get("new"):
            flags.append("NEW")
        nm = (name + (" [" + "/".join(flags) + "]" if flags else ""))[:24]
        print("%-15s  %-17s  %-24s  %-8s  %s" % (
            d.get("ip", ""), d.get("mac") or "-", nm, risk, ports or "-"))
    nd = res.get("new_devices") or []
    if nd:
        print("\nNew since last scan: %d device(s), %d new port(s)." % (
            len(nd), res.get("new_ports", 0)))


# --------------------------------------------------------------------------- #
# Export + UI loading
# --------------------------------------------------------------------------- #


def devices_to_csv(devices):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["IP", "MAC", "Name", "Hostname", "Vendor", "OS", "Type",
                "Latency(ms)", "mDNS Services", "Open Ports", "Web URLs"])
    for d in devices:
        ports = "; ".join("%d/%s" % (p["port"], p["service"]) for p in d.get("ports", []))
        urls = "; ".join(p["url"] for p in d.get("ports", []) if p.get("url"))
        w.writerow([d.get("ip", ""), d.get("mac") or "", d.get("name") or "",
                    d.get("hostname") or "", d.get("vendor") or "", d.get("os") or "",
                    d.get("device_type") or "",
                    d.get("latency") if d.get("latency") is not None else "",
                    "; ".join(d.get("mdns_services", [])), ports, urls])
    return buf.getvalue()


OPENAPI_VERSION = VERSION


def openapi_spec():
    """The OpenAPI 3.0 description of the HTTP API (single source of truth).

    Served as JSON at /openapi.json and as YAML at /openapi.yaml."""
    ok = {"description": "OK"}
    job = {"200": {"description": "Job accepted",
                   "content": {"application/json": {"schema": {"type": "object",
                               "properties": {"job_id": {"type": "string"}}}}}}}
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Netryx API",
            "version": OPENAPI_VERSION,
            "description": "Local network scanner & discovery engine. Discovers "
                           "devices, ports and services, assesses exposure, tracks a "
                           "known-good baseline, and exposes an MCP endpoint for AI agents. "
                           "All data stays on the host.",
            "license": {"name": "MIT"},
        },
        "servers": [{"url": "/", "description": "This Netryx instance"}],
        "tags": [
            {"name": "discovery", "description": "Scan the network and inspect results"},
            {"name": "devices", "description": "Per-device actions"},
            {"name": "security", "description": "Baseline & proactive events"},
            {"name": "system", "description": "Host info, vendor DB, export"},
            {"name": "agent", "description": "Model Context Protocol endpoint"},
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer",
                               "description": "An API token: Authorization: Bearer nsk_... (manage tokens in the dashboard)."},
                "basicAuth": {"type": "http", "scheme": "basic",
                              "description": "Admin username/password (NETRYX_USER / NETRYX_PASS)."}
            }
        },
        "security": [{"bearerAuth": []}, {"basicAuth": []}],
        "paths": {
            "/api/info": {"get": {"tags": ["system"], "summary": "Host & network context",
                "description": "Local IP, gateway, suggested subnet, platform, CPU count and OUI DB status.",
                "responses": {"200": ok}}},
            "/api/oui": {"get": {"tags": ["system"], "summary": "OUI vendor database status",
                "responses": {"200": ok}}},
            "/api/oui/download": {"post": {"tags": ["system"],
                "summary": "Download the full IEEE OUI database (background job)",
                "responses": job}},
            "/api/scan": {"post": {"tags": ["discovery"], "summary": "Start a discovery scan",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["subnet"], "properties": {
                        "subnet": {"type": "string", "description": "CIDR/IP/range list, e.g. '192.168.1.0/24, 10.0.0.5'"},
                        "scan_ports": {"type": "boolean"},
                        "port_profile": {"type": "string", "enum": ["quick", "extended", "full"]},
                        "use_mdns": {"type": "boolean"},
                        "use_snmp": {"type": "boolean"},
                        "workers": {"type": "string", "description": "number or 'auto'"},
                        "source": {"type": "string", "enum": ["manual", "monitor", "api", "schedule", "mcp", "cli"],
                                   "description": "Trigger tag recorded in history (default 'api' for token callers). Tells scheduled/manual/monitor/mcp/api scans apart."}}}}}},
                "responses": {"200": job["200"], "400": {"description": "subnet required"}}}},
            "/api/job": {"get": {"tags": ["discovery"], "summary": "Poll a running/finished job",
                "parameters": [{"name": "id", "in": "query", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": ok, "404": {"description": "no such job"}}}},
            "/api/job/stop": {"post": {"tags": ["discovery"], "summary": "Cancel a running job",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}}}},
                "responses": {"200": ok, "404": {"description": "no such job"}}}},
            "/api/portscan": {"post": {"tags": ["discovery"], "summary": "Scan ports on one host",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["ip"], "properties": {
                        "ip": {"type": "string"},
                        "profile": {"type": "string", "enum": ["quick", "extended", "full"]},
                        "workers": {"type": "string"}}}}}},
                "responses": {"200": job["200"], "400": {"description": "ip required"}}}},
            "/api/history": {"get": {"tags": ["discovery"], "summary": "List scan snapshots, or fetch one",
                "parameters": [{"name": "file", "in": "query", "required": False,
                                "schema": {"type": "string"},
                                "description": "e.g. scan_1700000000.json; omit to list all"}],
                "responses": {"200": ok, "404": {"description": "not found"}}}},
            "/api/export": {"get": {"tags": ["system"], "summary": "Export the latest results",
                "parameters": [{"name": "format", "in": "query", "required": False,
                                "schema": {"type": "string", "enum": ["json", "csv"]}}],
                "responses": {"200": {"description": "File download (JSON or CSV)"}}}},
            "/api/snmp": {"post": {"tags": ["devices"],
                "summary": "Send an SNMP v2c GET or walk to a host",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["ip"], "properties": {
                        "ip": {"type": "string"},
                        "oid": {"type": "string", "description": "Single OID (or subtree root when walk=true)"},
                        "oids": {"type": "array", "items": {"type": "string"}},
                        "community": {"type": "string", "description": "Default 'public'"},
                        "walk": {"type": "boolean", "description": "GETNEXT-walk the subtree under 'oid'"},
                        "max_rows": {"type": "integer", "description": "Walk row cap (default 256)"},
                        "timeout": {"type": "number"}, "port": {"type": "integer", "description": "Default 161"}}}}}},
                "responses": {"200": ok, "400": {"description": "ip / oid required"}}}},
            "/api/wol": {"post": {"tags": ["devices"], "summary": "Wake-on-LAN a MAC address",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["mac"], "properties": {"mac": {"type": "string"}}}}}},
                "responses": {"200": ok, "400": {"description": "bad mac"}}}},
            "/api/device": {"post": {"tags": ["devices"],
                "summary": "Set a device name/notes (by MAC, or by IP when there's no MAC)",
                "description": "Identity is the MAC when one is known, otherwise the IP. Devices on another subnet (behind a router) have no resolvable MAC, so pass the IP. Send at least one of mac/ip.",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "properties": {
                        "mac": {"type": "string", "description": "Device MAC (preferred identity)"},
                        "ip": {"type": "string", "description": "Device IP (used as identity when no MAC)"},
                        "name": {"type": "string"},
                        "notes": {"type": "string"}}}}}},
                "responses": {"200": ok, "400": {"description": "mac or ip required"}}}},
            "/api/baseline": {
                "get": {"tags": ["security"], "summary": "Get the known-good baseline + live diff",
                        "responses": {"200": ok}},
                "post": {"tags": ["security"], "summary": "Manage the baseline",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "properties": {
                            "action": {"type": "string", "enum": ["set", "approve", "clear"]},
                            "keys": {"type": "array", "items": {"type": "string"}}}}}}},
                    "responses": {"200": ok, "400": {"description": "unknown action"}}}},
            "/api/events": {"get": {"tags": ["security"], "summary": "Recent proactive events",
                "parameters": [{"name": "limit", "in": "query", "required": False,
                                "schema": {"type": "integer", "default": 100}}],
                "responses": {"200": ok}}},
            "/api/events/poll": {"get": {"tags": ["security"],
                "summary": "Long-poll for events newer than 'since' (blocks up to 'timeout's)",
                "parameters": [
                    {"name": "since", "in": "query", "schema": {"type": "integer", "default": 0},
                     "description": "Return events with id greater than this"},
                    {"name": "timeout", "in": "query", "schema": {"type": "integer", "default": 25},
                     "description": "Seconds to block waiting for a new event (1-60)"}],
                "responses": {"200": ok}}},
            "/api/events/stream": {"get": {"tags": ["security"],
                "summary": "Server-Sent Events stream of live events (text/event-stream)",
                "parameters": [{"name": "since", "in": "query", "schema": {"type": "integer", "default": 0},
                                "description": "Replay events after this id before streaming live"}],
                "responses": {"200": {"description": "text/event-stream of event frames"}}}},
            "/api/mcp/audit": {"get": {"tags": ["security"],
                "summary": "MCP/API audit log (tool calls, subscribes, pushed events)",
                "parameters": [{"name": "limit", "in": "query", "required": False,
                                "schema": {"type": "integer", "default": 200}}],
                "responses": {"200": ok}}},
            "/api/mcp/subscribers": {"get": {"tags": ["security"],
                "summary": "Live MCP/SSE/long-poll subscribers (with active flag)",
                "responses": {"200": ok}}},
            "/api/schedule": {
                "get": {"tags": ["discovery"],
                    "summary": "Get the server-side scan schedule (with next_run / running state)",
                    "responses": {"200": ok}},
                "post": {"tags": ["discovery"],
                    "summary": "Update the server-side scan schedule",
                    "description": "Scheduled scans run on the server even with no browser open. They use this endpoint's own targets/options (independent of the live monitor), and only one scan runs at a time — a tick is skipped if a scan is already running.",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "properties": {
                            "enabled": {"type": "boolean"},
                            "interval": {"type": "integer",
                                         "description": "Seconds between scans (clamped 60 .. 2592000)"},
                            "targets": {"type": "string",
                                        "description": "CIDR/IP/range list; blank uses the suggested subnet"},
                            "scan_ports": {"type": "boolean"},
                            "port_profile": {"type": "string", "enum": ["quick", "extended", "full"]},
                            "use_mdns": {"type": "boolean"},
                            "use_snmp": {"type": "boolean"},
                            "workers": {"type": "string"}}}}}},
                    "responses": {"200": ok}}},
            "/api/tokens": {
                "get": {"tags": ["security"], "summary": "List API tokens (values are viewable)",
                        "responses": {"200": ok}},
                "post": {"tags": ["security"], "summary": "Create or delete an API token",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "properties": {
                            "action": {"type": "string", "enum": ["create", "delete"]},
                            "name": {"type": "string"},
                            "expires_days": {"type": "integer", "description": "Omit for a long-lived token"},
                            "id": {"type": "string"}}}}}},
                    "responses": {"200": ok, "400": {"description": "unknown action"}}}},
            "/api/credentials": {"post": {"tags": ["security"],
                "summary": "Change the admin username/password (persisted, hashed)",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["password", "current_password"], "properties": {
                        "username": {"type": "string"},
                        "current_password": {"type": "string"},
                        "password": {"type": "string"}}}}}},
                "responses": {"200": ok, "400": {"description": "password required"},
                              "403": {"description": "current password incorrect"}}}},
            "/login": {"get": {"tags": ["system"], "summary": "Login page (HTML)",
                "security": [], "responses": {"200": ok}}},
            "/api/login": {"post": {"tags": ["security"], "summary": "Log in; sets a session cookie",
                "security": [],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["username", "password"], "properties": {
                        "username": {"type": "string"}, "password": {"type": "string"}}}}}},
                "responses": {"200": ok, "401": {"description": "invalid username or password"}}}},
            "/api/logout": {"post": {"tags": ["security"], "summary": "Log out (clears the session)",
                "responses": {"200": ok}}},
            "/mcp": {"post": {"tags": ["agent"],
                "summary": "Model Context Protocol endpoint (JSON-RPC 2.0)",
                "description": "Streamable-HTTP MCP transport. Methods: initialize, "
                               "tools/list, tools/call, ping. Gated by NETRYX_TOKEN when set.",
                "security": [{"bearerAuth": []}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "properties": {
                        "jsonrpc": {"type": "string", "enum": ["2.0"]},
                        "id": {"type": ["integer", "string"]},
                        "method": {"type": "string"},
                        "params": {"type": "object"}}}}}},
                "responses": {"200": {"description": "JSON-RPC response"},
                              "202": {"description": "Accepted (notification, no body)"},
                              "401": {"description": "Unauthorized"}}}},
            "/openapi.json": {"get": {"tags": ["system"], "summary": "This spec as JSON",
                "responses": {"200": ok}}},
            "/openapi.yaml": {"get": {"tags": ["system"], "summary": "This spec as YAML",
                "responses": {"200": ok}}},
        },
    }


def _yaml_scalar(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


_YAML_SPECIAL = set(" :/{}[]#,&*!|>%@`\"'")


def _yaml_key(k):
    sk = str(k)
    if (not sk) or sk.isdigit() or sk.lower() in ("true", "false", "null", "yes", "no", "on", "off") \
            or any(c in _YAML_SPECIAL for c in sk):
        return _yaml_scalar(k)
    return sk


def _yaml_dict(obj, indent):
    pad = "  " * indent
    out = []
    for k, v in obj.items():
        kk = _yaml_key(k)
        if isinstance(v, dict):
            out.append("%s%s:" % (pad, kk)) if v else out.append("%s%s: {}" % (pad, kk))
            if v:
                out += _yaml_dict(v, indent + 1)
        elif isinstance(v, list):
            out.append("%s%s:" % (pad, kk)) if v else out.append("%s%s: []" % (pad, kk))
            if v:
                out += _yaml_list(v, indent)
        else:
            out.append("%s%s: %s" % (pad, kk, _yaml_scalar(v)))
    return out


def _yaml_list(items, indent):
    pad = "  " * indent
    out = []
    for it in items:
        if isinstance(it, dict) and it:
            sub = _yaml_dict(it, indent + 1)
            out.append(pad + "- " + sub[0][len("  " * (indent + 1)):])
            out += sub[1:]
        elif isinstance(it, list) and it:
            sub = _yaml_list(it, indent + 1)
            out.append(pad + "- " + sub[0][len("  " * (indent + 1)):])
            out += sub[1:]
        else:
            out.append(pad + "- " + _yaml_scalar(it))
    return out


def openapi_yaml():
    return "\n".join(_yaml_dict(openapi_spec(), 0)) + "\n"


_UI_CACHE = None


def load_ui():
    global _UI_CACHE
    if _UI_CACHE is not None:
        return _UI_CACHE
    cands = []
    if getattr(sys, "frozen", False):
        cands.append(os.path.join(getattr(sys, "_MEIPASS", APP_DIR), "ui.html"))
    cands.append(os.path.join(APP_DIR, "ui.html"))
    for c in cands:
        try:
            if os.path.exists(c):
                with open(c, "r", encoding="utf-8") as f:
                    _UI_CACHE = f.read()
                    return _UI_CACHE
        except Exception:
            pass
    _UI_CACHE = ("<!DOCTYPE html><meta charset=utf-8><body style='font-family:sans-serif;"
                 "background:#0b0f17;color:#e6edf3;padding:40px'>"
                 "<h1>Netryx</h1><p>ui.html was not found next to the app. "
                 "Keep <code>ui.html</code> in the same folder as the program.</p></body>")
    return _UI_CACHE


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

MAX_BODY_BYTES = 2 * 1024 * 1024     # reject request bodies larger than this (anti-OOM)
MAX_STREAMS = 64                     # max concurrent SSE + long-poll connections
_STREAMS = {"n": 0}
_STREAMS_LOCK = threading.Lock()


def _stream_acquire():
    with _STREAMS_LOCK:
        if _STREAMS["n"] >= MAX_STREAMS:
            return False
        _STREAMS["n"] += 1
        return True


def _stream_release():
    with _STREAMS_LOCK:
        _STREAMS["n"] = max(0, _STREAMS["n"] - 1)


# Per-IP login throttle: lock out an IP after too many failures within a window.
LOGIN_MAX_FAILS = 10
LOGIN_WINDOW = 300                   # seconds
_LOGIN_FAILS = {}                    # ip -> [count, window_start]
_LOGIN_LOCK = threading.Lock()


def login_blocked(ip):
    with _LOGIN_LOCK:
        c, t = _LOGIN_FAILS.get(ip, (0, 0))
        return c >= LOGIN_MAX_FAILS and (time.time() - t) < LOGIN_WINDOW


def login_fail(ip):
    now = time.time()
    with _LOGIN_LOCK:
        c, t = _LOGIN_FAILS.get(ip, (0, 0))
        if now - t > LOGIN_WINDOW:
            c, t = 0, now
        _LOGIN_FAILS[ip] = (c + 1, t or now)
        if len(_LOGIN_FAILS) > 1024:     # opportunistic prune of stale entries
            for k in [k for k, v in _LOGIN_FAILS.items() if now - v[1] > LOGIN_WINDOW]:
                _LOGIN_FAILS.pop(k, None)


def login_ok(ip):
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(ip, None)


class Handler(BaseHTTPRequestHandler):
    server_version = "Netryx/" + VERSION

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY_BYTES:      # refuse oversized bodies before reading (anti-OOM)
                self.close_connection = True
                return {}
            return json.loads((self.rfile.read(length) if length else b"{}").decode("utf-8") or "{}")
        except Exception:
            return {}

    def _client_is_local(self):
        ip = self.client_address[0] if self.client_address else ""
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _bearer(self):
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Bearer "):
            return hdr[7:].strip()
        # A query-string token is only honored on the streaming endpoints, where
        # EventSource/long-poll clients can't set an Authorization header. This
        # keeps tokens out of URLs (and proxy logs) everywhere else.
        if urlparse(self.path).path.startswith("/api/events/"):
            return (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        return ""

    def _basic_ok(self):
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(hdr[6:].strip()).decode("utf-8", "replace").partition(":")
        except Exception:
            return False
        return verify_admin(user, pw)

    def _cookie(self, name):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _auth_method(self):
        if NETRYX_OPEN:
            return "open"
        if NETRYX_TRUST_LOCALHOST and self._client_is_local():
            return "localhost"
        if session_valid(self._cookie("ns_session")):
            return "session"
        tok = self._bearer()
        if tok and token_valid(tok):
            return "token"
        if self._basic_ok():
            return "basic"
        return "none"

    def _authed(self):
        return self._auth_method() != "none"

    def _deny(self):
        # Browsers navigating to a page are redirected to the styled login screen;
        # API / fetch callers get a plain 401 (no WWW-Authenticate -> no browser popup).
        p = urlparse(self.path).path
        accept = self.headers.get("Accept", "")
        if self.command == "GET" and (p in ("/", "/index.html") or "text/html" in accept):
            return self._send(302, b"", extra={"Location": "/login"})
        return self._send(401, {"error": "unauthorized"})

    def _client_ip(self):
        return self.client_address[0] if self.client_address else ""

    def _caller_label(self):
        m = self._auth_method()
        if m == "token":
            return token_name(self._bearer()) or "token"
        if m == "basic":
            return "admin"
        if m == "session":
            return "admin (session)"
        return m   # localhost / open / none

    def do_GET(self):
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        if path == "/login":
            return self._send(200, login_page(), "text/html; charset=utf-8",
                              extra={"Cache-Control": "no-store"})
        if path == "/logout":
            drop_session(self._cookie("ns_session"))
            return self._send(302, b"", extra={"Location": "/login",
                "Set-Cookie": "ns_session=; Path=/; Max-Age=0%s" % COOKIE_ATTRS})
        if not self._authed():
            return self._deny()
        if path in ("/", "/index.html"):
            return self._send(200, load_ui(), "text/html; charset=utf-8",
                              extra={"Cache-Control": "no-store"})
        if path == "/openapi.json":
            return self._send(200, json.dumps(openapi_spec(), indent=2), "application/json")
        if path in ("/openapi.yaml", "/openapi.yml"):
            return self._send(200, openapi_yaml(), "application/yaml; charset=utf-8")
        if path == "/api/info":
            return self._send(200, {
                "subnet": default_subnet(), "local_ip": get_primary_ip(),
                "gateway": default_gateway(), "cpu": os.cpu_count(),
                "platform": platform.system() + " " + platform.release(),
                "oui": oui_status(),
                "auth": {"enabled": auth_configured(),
                         "method": self._auth_method(),
                         "username": load_admin().get("username"),
                         "default_creds": is_default_admin(),
                         "trust_localhost": NETRYX_TRUST_LOCALHOST}})
        if path == "/api/oui":
            return self._send(200, oui_status())
        if path == "/api/totp/status":
            user = load_admin().get("username")
            return self._send(200, {"enabled": totp_enabled(user), "username": user})
        if path == "/api/job":
            job = JOBS.get((qs.get("id") or [None])[0])
            return self._send(200, job) if job else self._send(404, {"error": "no such job"})
        if path == "/api/history":
            f = (qs.get("file") or [None])[0]
            if f:
                if not re.match(r"^scan_\d+\.json$", f):
                    return self._send(400, {"error": "bad file"})
                rec = _load_json(os.path.join(HISTORY_DIR, f), None)
                if rec:
                    # Show current friendly names, even if this snapshot predates a rename.
                    apply_meta(rec.get("devices", []))
                    return self._send(200, rec)
                return self._send(404, {"error": "not found"})
            return self._send(200, list_history())
        if path == "/api/export":
            fmt = (qs.get("format") or ["json"])[0]
            devs = LAST_RESULTS.get("devices", [])
            if fmt == "csv":
                return self._send(200, devices_to_csv(devs), "text/csv",
                                  {"Content-Disposition": "attachment; filename=netryx.csv"})
            return self._send(200, json.dumps(devs, indent=2), "application/json",
                              {"Content-Disposition": "attachment; filename=netryx.json"})
        if path == "/api/baseline":
            b = load_baseline()
            diff = diff_against_baseline(LAST_RESULTS.get("devices", []), b) \
                if b.get("devices") else None
            return self._send(200, {
                "created": b.get("created"), "updated": b.get("updated"),
                "size": len(b.get("devices", {})),
                "devices": list(b.get("devices", {}).values()), "diff": diff})
        if path == "/api/events":
            try:
                limit = int((qs.get("limit") or ["100"])[0])
            except Exception:
                limit = 100
            return self._send(200, {"events": list_events(limit)})
        if path == "/api/mcp/audit":
            try:
                alim = int((qs.get("limit") or ["200"])[0])
            except Exception:
                alim = 200
            return self._send(200, {"audit": list_audit(alim)})
        if path == "/api/mcp/subscribers":
            return self._send(200, {"subscribers": list_subscribers()})
        if path == "/api/schedule":
            s = load_schedule()
            running = discovery_running()
            if s.get("enabled"):
                base = s.get("last_run") or _LAST_SCHED_RUN or time.time()
                s["next_run"] = base + s["interval"]
            else:
                s["next_run"] = None
            s["running"] = bool(running)
            s["min"] = SCHEDULE_MIN
            s["max"] = SCHEDULE_MAX
            return self._send(200, s)
        if path == "/api/events/poll":
            try:
                since = int((qs.get("since") or ["0"])[0])
            except Exception:
                since = 0
            try:
                timeout = max(1, min(60, int((qs.get("timeout") or ["25"])[0])))
            except Exception:
                timeout = 25
            if not _stream_acquire():
                return self._send(503, {"error": "too many concurrent connections"})
            sid = "poll-" + secrets.token_hex(3)
            try:
                sub_register(sid, transport="long-poll", caller=self._caller_label(), ip=self._client_ip())
                EVENT_HUB.wait(since, timeout)
            finally:
                sub_remove(sid)
                _stream_release()
            return self._send(200, {"events": events_since(since), "seq": EVENT_HUB.seq})
        if path == "/api/events/stream":
            sv = (qs.get("since") or [None])[0]
            if sv is None:                       # honor EventSource reconnect header
                sv = self.headers.get("Last-Event-ID") or "0"
            last = int(sv) if str(sv).isdigit() else 0
            if not _stream_acquire():
                return self._send(503, {"error": "too many concurrent connections"})
            # Everything after acquire is inside try/finally so the stream slot is
            # ALWAYS released — even if send_response/headers raise on a client that
            # vanished mid-handshake (otherwise the slot leaks and we hit the cap).
            sid = "sse-" + secrets.token_hex(4)
            who = "?"
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "keep-alive")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Accel-Buffering", "no")   # don't let nginx buffer SSE
                self.end_headers()
                who = self._caller_label()
                sub_register(sid, transport="sse", caller=who, ip=self._client_ip())
                audit("subscribe", transport="sse", caller=who, ip=self._client_ip(), sid=sid)
                self.wfile.write(b": connected\n\n")
                for e in events_since(last):
                    self.wfile.write(_sse_frame(e))
                    last = e["id"]
                self.wfile.flush()
                while True:
                    EVENT_HUB.wait(last, 20)
                    evs = events_since(last)
                    if evs:
                        for e in evs:
                            self.wfile.write(_sse_frame(e))
                            last = e["id"]
                    else:
                        self.wfile.write(b": keepalive\n\n")   # heartbeat
                    self.wfile.flush()
                    sub_heartbeat(sid)
            except Exception:
                pass          # client disconnected
            finally:
                sub_remove(sid)
                _stream_release()
                audit("unsubscribe", transport="sse", caller=who, sid=sid)
            return
        if path == "/api/tokens":
            return self._send(200, {"tokens": list_tokens(),
                                    "trust_localhost": NETRYX_TRUST_LOCALHOST,
                                    "admin": bool(NETRYX_PASS)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._body()
        if path == "/api/login":
            ip = self._client_ip()
            if login_blocked(ip):
                return self._send(429, {"error": "too many attempts — wait a few minutes"})
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""
            if not verify_admin(username, password):
                login_fail(ip)
                time.sleep(0.5)          # slow scripted brute force
                return self._send(401, {"error": "invalid username or password"})
            # Password OK. If TOTP/2FA is enabled for this user, require the code too.
            if totp_enabled(username):
                code = (data.get("code") or "").strip()
                if not code:
                    # Two-step UI - ask for the 6-digit code in a second prompt.
                    # Not counted as a failed attempt (no throttle).
                    return self._send(200, {"requires_2fa": True})
                if not totp_verify(totp_get_secret(username), code):
                    login_fail(ip)
                    time.sleep(0.5)
                    return self._send(401, {"requires_2fa": True,
                                            "error": "invalid 2FA code"})
            login_ok(ip)
            tok = new_session()
            # "Remember me" - true (default): 30-day persistent cookie.
            # false: session cookie (no Max-Age) - browser drops it on close.
            remember = bool(data.get("remember", True))
            cookie = (("ns_session=%s; Path=/; Max-Age=%d%s" % (tok, SESSION_TTL, COOKIE_ATTRS))
                      if remember else
                      ("ns_session=%s; Path=/%s" % (tok, COOKIE_ATTRS)))
            return self._send(200, {"ok": True}, extra={"Set-Cookie": cookie})
        if path == "/api/logout":
            drop_session(self._cookie("ns_session"))
            return self._send(200, {"ok": True}, extra={"Set-Cookie":
                "ns_session=; Path=/; Max-Age=0%s" % COOKIE_ATTRS})
        if not self._authed():
            return self._deny()
        if path == "/api/totp/begin":
            user = load_admin().get("username")
            secret = totp_secret_new()
            uri = totp_provisioning_uri(user, secret)
            try:
                qr_svg = _qr_svg(uri)
            except Exception as e:
                log("QR generation failed: %s" % e); qr_svg = ""
            return self._send(200, {
                "secret": secret,
                "uri": uri,
                "qr_svg": qr_svg,
                "issuer": "Netryx", "username": user,
                "digits": TOTP_DIGITS, "period": TOTP_PERIOD})
        if path == "/api/totp/confirm":
            user = load_admin().get("username")
            secret = (data.get("secret") or "").strip()
            code = (data.get("code") or "").strip()
            if not secret or not totp_verify(secret, code):
                return self._send(400, {"error": "code did not verify - check your app's clock and try again"})
            totp_set(user, secret)
            return self._send(200, {"ok": True, "enabled": True})
        if path == "/api/totp/disable":
            user = load_admin().get("username")
            pw = data.get("password") or ""
            if not verify_admin(user, pw):
                return self._send(403, {"error": "current password incorrect"})
            totp_clear(user)
            return self._send(200, {"ok": True, "enabled": False})
        if path == "/mcp":
            try:
                import netryx_mcp as mcpmod
            except Exception as e:
                log("MCP module unavailable: %s" % e)
                return self._send(500, {"error": "MCP module unavailable: %s" % e})
            # Bind the MCP tools to *this* running engine instance so /mcp sees
            # the same live scan results and jobs the web UI does.
            mcpmod.engine = sys.modules[__name__]
            items = data if isinstance(data, list) else [data]
            who, ip = self._caller_label(), self._client_ip()
            for it in items:
                if isinstance(it, dict):
                    _audit_mcp("http", who, ip, it)
            out = [r for r in (mcpmod.dispatch(it) for it in items) if r is not None]
            if not out:
                return self._send(202, b"")  # only notifications -> no body
            return self._send(200, out if isinstance(data, list) else out[0])
        if path == "/api/scan":
            subnet = (data.get("subnet") or "").strip()
            if not subnet:
                return self._send(400, {"error": "subnet required"})
            # Only one discovery scan runs at a time. If one is already in flight
            # (manual, live-monitor or scheduled), attach to it instead of
            # spawning a parallel scan.
            busy = discovery_running()
            if busy:
                return self._send(200, {"job_id": busy["id"], "busy": True,
                                        "note": "a scan is already running"})
            profile = data.get("port_profile", "quick")
            if profile not in PORT_PROFILES:
                profile = "quick"
            # Trigger source: the browser declares manual vs monitor; a
            # programmatic (token-authed) caller defaults to "api".
            src = (data.get("source") or "").strip().lower()
            if src not in ("manual", "monitor", "api", "schedule", "mcp", "cli"):
                src = "api" if self._auth_method() == "token" else "manual"
            jid = start_job("discovery", run_discovery, subnet, bool(data.get("scan_ports")),
                            profile, bool(data.get("use_mdns", True)), bool(data.get("use_snmp", True)),
                            data.get("workers", "auto"), source=src)
            return self._send(200, {"job_id": jid})
        if path == "/api/portscan":
            ip = (data.get("ip") or "").strip()
            if not ip:
                return self._send(400, {"error": "ip required"})
            profile = data.get("profile", "extended")
            if profile not in PORT_PROFILES:
                profile = "extended"
            return self._send(200, {"job_id": start_job("portscan", run_portscan, ip, profile, data.get("workers", "auto"))})
        if path == "/api/oui/download":
            return self._send(200, {"job_id": start_job("oui", run_oui_download)})
        if path == "/api/job/stop":
            j = JOBS.get((data.get("id") or "").strip())
            if j:
                j["cancel"] = True
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "no such job"})
        if path == "/api/wol":
            try:
                return self._send(200, {"ok": wake_on_lan((data.get("mac") or "").strip())})
            except Exception as e:
                return self._send(400, {"error": str(e)})
        if path == "/api/snmp":
            ip = (data.get("ip") or data.get("host") or "").strip()
            if not ip:
                return self._send(400, {"error": "ip (or host) required"})
            community = data.get("community") or "public"
            try:
                timeout = max(0.2, min(5.0, float(data.get("timeout", 1.5))))
            except Exception:
                timeout = 1.5
            try:
                port = int(data.get("port", 161))
            except Exception:
                port = 161
            if data.get("walk"):
                base = (data.get("oid") or "").strip()
                if not base and data.get("oids"):
                    base = str(data["oids"][0])
                if not base:
                    return self._send(400, {"error": "oid (subtree root) required for walk"})
                rows = snmp_walk(ip, base, community, timeout, data.get("max_rows", 256), port)
                return self._send(200, {"ip": ip, "walk": base, "community": community,
                                        "count": len(rows), "results": rows})
            oids = data.get("oids") or ([data.get("oid")] if data.get("oid") else [])
            if not oids:
                return self._send(400, {"error": "oid or oids required"})
            res = snmp_get(ip, oids, community, timeout, port)
            return self._send(200, {"ip": ip, "community": community, "results": res,
                "note": None if res else "no response (host unreachable, SNMP disabled, or wrong community)"})
        if path == "/api/device":
            mac = (data.get("mac") or "").strip().lower()
            ip = (data.get("ip") or "").strip()
            # Identity is the MAC when we have one, else the IP — devices on
            # another subnet (behind a router) have no resolvable MAC.
            key = mac or ip
            if not key:
                return self._send(400, {"error": "mac or ip required"})
            ok = save_device_meta(key, data.get("name"), data.get("notes"))
            for d in LAST_RESULTS.get("devices", []):
                if (d.get("mac") or d.get("ip")) == key:
                    if data.get("name") is not None:
                        d["name"] = data.get("name")
                    if data.get("notes") is not None:
                        d["notes"] = data.get("notes")
            return self._send(200, {"ok": ok})
        if path == "/api/baseline":
            action = (data.get("action") or "set").strip().lower()
            devs = LAST_RESULTS.get("devices", [])
            if action == "set":
                b = baseline_from_devices(devs)
                _save_json(ALERTS_FILE, [])  # reset alert de-dup state
                return self._send(200, {"ok": True, "action": "set",
                                        "size": len(b.get("devices", {}))})
            if action == "clear":
                clear_baseline()
                _save_json(ALERTS_FILE, [])
                return self._send(200, {"ok": True, "action": "clear", "size": 0})
            if action == "approve":
                b = approve_devices(data.get("keys") or [], devs)
                return self._send(200, {"ok": True, "action": "approve",
                                        "size": len(b.get("devices", {}))})
            return self._send(400, {"error": "unknown action"})
        if path == "/api/tokens":
            action = (data.get("action") or "create").strip().lower()
            if action == "create":
                return self._send(200, {"ok": True,
                                        "token": create_token(data.get("name"), data.get("expires_days"))})
            if action == "delete":
                return self._send(200, {"ok": delete_token((data.get("id") or "").strip())})
            return self._send(400, {"error": "unknown action"})
        if path == "/api/credentials":
            newpw = data.get("password") or ""
            if not newpw:
                return self._send(400, {"error": "password required"})
            cur_user = load_admin().get("username")
            if not verify_admin(cur_user, data.get("current_password") or ""):
                return self._send(403, {"error": "current password incorrect"})
            a = set_admin(data.get("username") or cur_user, newpw)
            return self._send(200, {"ok": True, "username": a["username"]})
        if path == "/api/schedule":
            global _LAST_SCHED_RUN
            patch = {}
            if "enabled" in data:
                patch["enabled"] = bool(data.get("enabled"))
            if "interval" in data:
                try:
                    patch["interval"] = max(SCHEDULE_MIN, min(SCHEDULE_MAX, int(data["interval"])))
                except Exception:
                    pass
            if "targets" in data:
                patch["targets"] = (data.get("targets") or "").strip()
            if "scan_ports" in data:
                patch["scan_ports"] = bool(data.get("scan_ports"))
            if "port_profile" in data:
                pp = data.get("port_profile", "quick")
                patch["port_profile"] = pp if pp in PORT_PROFILES else "quick"
            if "use_mdns" in data:
                patch["use_mdns"] = bool(data.get("use_mdns"))
            if "use_snmp" in data:
                patch["use_snmp"] = bool(data.get("use_snmp"))
            if "workers" in data:
                patch["workers"] = data.get("workers", "auto")
            cur = save_schedule(patch)
            # Restart the countdown so a fresh save/enable waits a full interval.
            _LAST_SCHED_RUN = time.time()
            if cur.get("enabled"):
                cur["next_run"] = _LAST_SCHED_RUN + cur["interval"]
            else:
                cur["next_run"] = None
            return self._send(200, {"ok": True, **cur})
        return self._send(404, {"error": "not found"})


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def find_free_port(preferred, host):
    for p in [preferred] + list(range(8765, 8820)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, p))
            s.close()
            return p
        except Exception:
            continue
    return preferred


def main():
    ap = argparse.ArgumentParser(description="Netryx - local network scanner web app")
    ap.add_argument("--host", default=os.environ.get("NETRYX_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("NETRYX_PORT", "8765")))
    ap.add_argument("--no-browser", action="store_true",
                    default=bool(os.environ.get("NETRYX_NO_BROWSER")))
    # One-shot CLI scan (no server) - handy for scripts, cron and AI agents.
    ap.add_argument("--scan", metavar="TARGETS",
                    help="Scan TARGETS (CIDR/IP/range list, e.g. '192.168.1.0/24') once and exit")
    ap.add_argument("--ports", action="store_true",
                    help="With --scan: also scan ports on each live host")
    ap.add_argument("--profile", default="quick", choices=list(PORT_PROFILES),
                    help="With --ports: port profile (default: quick)")
    ap.add_argument("--workers", default="auto",
                    help="Worker count or 'auto' (default: auto)")
    ap.add_argument("--no-mdns", action="store_true", help="With --scan: skip mDNS discovery")
    ap.add_argument("--no-snmp", action="store_true", help="With --scan: skip SNMP probing")
    ap.add_argument("--json", action="store_true",
                    help="With --scan: print the result as JSON instead of a table")
    ap.add_argument("--reset-2fa", metavar="USER",
                    help="Clear TOTP / two-factor authentication for USER and exit. "
                         "Use this if you have lost your authenticator app and cannot log in.")
    args = ap.parse_args()

    if args.scan:
        res = discover(args.scan, scan_ports=args.ports, port_profile=args.profile,
                       use_mdns=not args.no_mdns, use_snmp=not args.no_snmp,
                       req_workers=args.workers, source="cli")
        if res.get("error"):
            print(json.dumps({"error": res["error"]}) if args.json
                  else ("Error: " + res["error"]), file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            _print_scan_table(res)
        return 0

    if args.reset_2fa:
        if totp_clear(args.reset_2fa):
            print("2FA cleared for user '%s'. You can now sign in with just username + password." % args.reset_2fa)
        else:
            print("No 2FA was set for user '%s' - nothing to clear." % args.reset_2fa)
        return 0

    # Fail loudly if the data directory isn't writable — otherwise saves (baseline,
    # tokens, device names, subscriber/live tracking) silently no-op and the UI
    # just "does nothing". Common cause: a non-root container on a root-owned volume.
    _probe = os.path.join(DATA_DIR, ".write_test")
    try:
        with open(_probe, "w") as _pf:
            _pf.write("ok")
        os.remove(_probe)
    except Exception as _e:
        log("FATAL-ish: data directory %s is NOT writable (%s). Baseline, tokens, "
            "device names and live-connection tracking will not persist. Fix the "
            "volume permissions (e.g. chown to the container's uid) or run as root."
            % (DATA_DIR, _e))

    _restore_last_results()
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    port = find_free_port(args.port, args.host)
    httpd = ThreadingHTTPServer((args.host, port), Handler)
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = "http://%s:%d" % (shown, port)

    print("=" * 64)
    print("  Netryx %s - Network Intelligence" % VERSION)
    print("  Open:  " + url)
    print("  Data:  " + DATA_DIR)
    print("  Press Ctrl+C to stop.")
    print("=" * 64)

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Netryx...")
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main() or 0)
