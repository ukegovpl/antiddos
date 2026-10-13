#!/usr/bin/env python3
# (Evil) DDoS Pcap Parser
# Quick and dirty pcap analyzer to get a bit of data from DDoS samples. 
# Feel free to fix and modify 

"""
ddos_analyze.py - summarise DDoS traffic captured with tcpdump.

Input is auto-detected and can be:
  * a pcap or pcapng file written with `tcpdump -w` (gzip-compressed is fine)
  * tcpdump text output (`tcpdump -nn ...`), from a file or piped on stdin

Examples
  tcpdump -nn -i eth0 -w attack.pcap                       # capture
  ./ddos_analyze.py attack.pcap                            # analyse
  ./ddos_analyze.py attack.pcap --top 30 --json report.json
  ./ddos_analyze.py attack.pcap --dst 198.51.100.10        # only traffic to the victim
  tcpdump -nn -r attack.pcap | ./ddos_analyze.py -         # text input
  sudo tcpdump -nn -l -i eth0 dst host 198.51.100.10 | ./ddos_analyze.py -
                                                           # live: Ctrl-C prints the report
  ./ddos_analyze.py attack.pcap --asn-db GeoLite2-ASN.mmdb # offline AS lookup

AS lookups default to Team Cymru's bulk whois service (whois.cymru.com:43),
cached in ~/.cache/ddos_analyze/asn_cache.json. For offline use pass
--asn-db (MaxMind GeoLite2-ASN .mmdb, `pip install maxminddb`) or
--pyasn (pyasn database, `pip install pyasn`), or skip with --no-asn.

Byte counts: with pcap input they are bytes on the wire. With text input
they are whatever tcpdump printed as `length N` (usually L4 payload), unless
tcpdump ran with -e (frame length) or -v (IP total length).
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import io
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import sys
import time
from collections import Counter

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP",
    115: "L2TP", 132: "SCTP", 136: "UDPLite",
}

# bit -> letter (tcpdump order-ish). '.' in tcpdump output means ACK.
TCP_FLAG_BITS = ((0x02, "S"), (0x10, "A"), (0x08, "P"), (0x01, "F"),
                 (0x04, "R"), (0x20, "U"), (0x40, "E"), (0x80, "C"))
TCP_FLAG_LEGEND = "S=SYN A=ACK P=PSH F=FIN R=RST U=URG E=ECE C=CWR"

# ports worth naming in a DDoS report; (*) marks common amplification/reflection sources
PORT_NAMES = {
    7: "echo(*)", 17: "qotd(*)", 19: "chargen(*)", 22: "ssh", 25: "smtp",
    53: "dns(*)", 69: "tftp(*)", 80: "http", 111: "portmap(*)", 123: "ntp(*)",
    137: "netbios-ns(*)", 161: "snmp(*)", 389: "ldap/cldap(*)", 443: "https",
    500: "isakmp(*)", 520: "rip(*)", 623: "ipmi(*)", 1194: "openvpn",
    1434: "mssql(*)", 1701: "l2tp", 1900: "ssdp(*)", 3283: "apple-rd(*)",
    3389: "rdp", 3478: "stun(*)", 3702: "ws-discovery(*)", 4500: "ipsec-nat",
    5060: "sip", 5353: "mdns(*)", 5683: "coap(*)", 6881: "bittorrent",
    8080: "http-alt", 10001: "ubnt-discovery(*)", 11211: "memcached(*)",
    27015: "steam(*)", 32414: "plex(*)", 37810: "dvr-dhcp(*)", 51820: "wireguard",
}

SIZE_BUCKETS = ((64, "<=64"), (128, "65-128"), (256, "129-256"), (512, "257-512"),
                (1024, "513-1024"), (1500, "1025-1500"), (1 << 31, ">1500"))

ETH_IPV4, ETH_IPV6, ETH_PPPOE = 0x0800, 0x86DD, 0x8864
VLAN_TAGS = {0x8100, 0x88A8, 0x9100}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
GZIP_MAGIC = b"\x1f\x8b"


def warn(msg: str) -> None:
    print(f"[warn] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------

def size_bucket(n: int) -> str:
    for limit, label in SIZE_BUCKETS:
        if n <= limit:
            return label
    return SIZE_BUCKETS[-1][1]


class Stats:
    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.non_ip = 0
        self.filtered = 0
        self.unparsed_lines = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.ts_mode = "epoch"          # 'epoch' or 'tod' (time-of-day only, tcpdump default text)
        self.src_pkts: Counter = Counter()
        self.src_bytes: Counter = Counter()
        self.dst_pkts: Counter = Counter()
        self.dst_bytes: Counter = Counter()
        self.proto_pkts: Counter = Counter()
        self.proto_bytes: Counter = Counter()
        self.dport: Counter = Counter()     # (proto, port)
        self.sport: Counter = Counter()
        self.tcp_flags: Counter = Counter()
        self.per_sec_pkts: Counter = Counter()
        self.per_sec_bytes: Counter = Counter()
        self.size_hist: Counter = Counter()
        self.interrupted = False

    def add(self, ts, src, dst, proto, sport, dport, length, flags) -> None:
        self.packets += 1
        self.bytes += length
        if ts is not None:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
            sec = int(ts)
            self.per_sec_pkts[sec] += 1
            self.per_sec_bytes[sec] += length
        self.src_pkts[src] += 1
        self.src_bytes[src] += length
        self.dst_pkts[dst] += 1
        self.dst_bytes[dst] += length
        self.proto_pkts[proto] += 1
        self.proto_bytes[proto] += length
        if dport is not None:
            self.dport[(proto, dport)] += 1
        if sport is not None:
            self.sport[(proto, sport)] += 1
        if flags is not None:
            self.tcp_flags[flags] += 1
        self.size_hist[size_bucket(length)] += 1

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(self.last_ts - self.first_ts, 0.0)


# ---------------------------------------------------------------------------
# input handling
# ---------------------------------------------------------------------------

class _Prefixed(io.RawIOBase):
    """Raw stream that replays `prefix` before reading from `stream`."""

    def __init__(self, prefix: bytes, stream) -> None:
        self._p = prefix
        self._s = stream

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        if self._p:
            n = min(len(b), len(self._p))
            b[:n] = self._p[:n]
            self._p = self._p[n:]
            return n
        data = self._s.read(len(b))
        n = len(data)
        b[:n] = data
        return n


def open_input(path: str):
    """Return (stream, kind, head) where kind is 'pcap', 'pcapng' or 'text'."""
    raw = sys.stdin.buffer if path == "-" else open(path, "rb")
    head = raw.read(4)
    stream = io.BufferedReader(_Prefixed(head, raw), buffer_size=1 << 20)
    if head[:2] == GZIP_MAGIC:
        gz = gzip.GzipFile(fileobj=stream)
        head = gz.read(4)
        stream = io.BufferedReader(_Prefixed(head, gz), buffer_size=1 << 20)
    if head in PCAP_MAGICS:
        return stream, "pcap", head
    if head == PCAPNG_MAGIC:
        return stream, "pcapng", head
    return stream, "text", head


def iter_pcap(stream, head: bytes):
    """Yield (ts, linktype, frame_bytes, wire_len) from a classic pcap stream."""
    endian, tsdiv = PCAP_MAGICS[head]
    stream.read(4)  # consume magic (replayed by _Prefixed)
    hdr = stream.read(20)
    if len(hdr) < 20:
        return
    linktype = struct.unpack(endian + "HHiIII", hdr)[5] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    read = stream.read
    while True:
        h = read(16)
        if len(h) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = rec.unpack(h)
        data = read(incl_len)
        if len(data) < incl_len:
            return
        yield ts_sec + ts_frac / tsdiv, linktype, data, orig_len or incl_len


def _pcapng_tsresol(options: bytes, endian: str) -> int:
    """Return timestamp divisor from IDB options (default microseconds)."""
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[off:off + 4])
        if code == 0:
            break
        val = options[off + 4:off + 4 + length]
        if code == 9 and len(val) >= 1:
            v = val[0]
            return (2 ** (v & 0x7F)) if (v & 0x80) else (10 ** (v & 0x7F))
        off += 4 + ((length + 3) & ~3)
    return 1_000_000


def iter_pcapng(stream, head: bytes):
    """Yield (ts, linktype, frame_bytes, wire_len) from a pcapng stream."""
    endian = None
    interfaces: list[tuple[int, int, int]] = []   # (linktype, tsdiv, snaplen)
    last_ts = 0.0
    read = stream.read
    while True:
        btype = read(4)
        if len(btype) < 4:
            return
        if btype == PCAPNG_MAGIC:                       # Section Header Block
            raw_len = read(4)
            bom = read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("pcapng: bad byte-order magic")
            total_len = struct.unpack(endian + "I", raw_len)[0]
            read(total_len - 12)
            interfaces = []
            continue
        if endian is None:
            raise ValueError("pcapng: block before section header")
        total_len = struct.unpack(endian + "I", read(4))[0]
        body_len = total_len - 12
        body = read(body_len)
        read(4)                                         # trailing total length
        if len(body) < body_len:
            return
        bt = struct.unpack(endian + "I", btype)[0]
        if bt == 1:                                     # Interface Description Block
            linktype, _res, snaplen = struct.unpack(endian + "HHI", body[:8])
            interfaces.append((linktype, _pcapng_tsresol(body[8:], endian), snaplen))
        elif bt == 6:                                   # Enhanced Packet Block
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            linktype, tsdiv, _ = interfaces[if_id] if if_id < len(interfaces) else (1, 1_000_000, 0)
            last_ts = ((ts_hi << 32) | ts_lo) / tsdiv
            yield last_ts, linktype, body[20:20 + cap_len], orig_len
        elif bt == 3:                                   # Simple Packet Block (no timestamp)
            orig_len = struct.unpack(endian + "I", body[:4])[0]
            linktype, _, snaplen = interfaces[0] if interfaces else (1, 1_000_000, 0)
            cap = min(orig_len, snaplen) if snaplen else orig_len
            yield last_ts, linktype, body[4:4 + cap], orig_len
        # other block types (NRB, ISB, custom) are skipped


# ---------------------------------------------------------------------------
# packet decoding (binary)
# ---------------------------------------------------------------------------

def link_to_ip(linktype: int, data: bytes) -> bytes | None:
    """Strip the link-layer header; return the IP packet or None if not IP."""
    if linktype == 1:                                   # Ethernet
        if len(data) < 14:
            return None
        etype = (data[12] << 8) | data[13]
        off = 14
        while etype in VLAN_TAGS:
            if len(data) < off + 4:
                return None
            etype = (data[off + 2] << 8) | data[off + 3]
            off += 4
        if etype == ETH_PPPOE:
            if len(data) < off + 8:
                return None
            ppp = (data[off + 6] << 8) | data[off + 7]
            off += 8
            etype = ETH_IPV4 if ppp == 0x0021 else ETH_IPV6 if ppp == 0x0057 else 0
        if etype == ETH_IPV4 or etype == ETH_IPV6:
            return data[off:]
        return None
    if linktype == 113:                                 # Linux cooked (SLL)
        if len(data) < 16:
            return None
        etype = (data[14] << 8) | data[15]
        return data[16:] if etype in (ETH_IPV4, ETH_IPV6) else None
    if linktype == 276:                                 # Linux cooked v2 (SLL2)
        if len(data) < 20:
            return None
        etype = (data[0] << 8) | data[1]
        return data[20:] if etype in (ETH_IPV4, ETH_IPV6) else None
    if linktype in (101, 12, 14, 228, 229):             # raw IP
        return data
    if linktype in (0, 108):                            # BSD loopback / OpenBSD loop
        return data[4:]
    return None


_inet_ntop = socket.inet_ntop
_AF_INET, _AF_INET6 = socket.AF_INET, socket.AF_INET6


def decode_ip(ip: bytes):
    """Return (src, dst, proto_name, sport, dport, tcp_flags) or None."""
    if not ip:
        return None
    ver = ip[0] >> 4
    fragmented = False
    if ver == 4:
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 0x0F) << 2
        proto = ip[9]
        if ((ip[6] & 0x1F) << 8) | ip[7]:              # non-zero fragment offset
            fragmented = True
        src = _inet_ntop(_AF_INET, ip[12:16])
        dst = _inet_ntop(_AF_INET, ip[16:20])
        l4 = ip[ihl:]
    elif ver == 6:
        if len(ip) < 40:
            return None
        nh = ip[6]
        src = _inet_ntop(_AF_INET6, ip[8:24])
        dst = _inet_ntop(_AF_INET6, ip[24:40])
        off = 40
        n = len(ip)
        while True:
            if nh in (0, 43, 60):                       # hop-by-hop, routing, dest opts
                if n < off + 2:
                    break
                nh, off = ip[off], off + (ip[off + 1] + 1) * 8
            elif nh == 44:                              # fragment header
                if n < off + 8:
                    break
                if ((ip[off + 2] << 8) | ip[off + 3]) >> 3:
                    fragmented = True
                nh, off = ip[off], off + 8
            elif nh == 51:                              # AH
                if n < off + 2:
                    break
                nh, off = ip[off], off + (ip[off + 1] + 2) * 4
            else:
                break
        proto = nh
        l4 = ip[off:]
    else:
        return None

    name = PROTO_NAMES.get(proto) or f"proto-{proto}"
    sport = dport = flags = None
    if fragmented:
        name += "-frag"
    elif proto in (6, 17, 132, 136) and len(l4) >= 4:
        sport = (l4[0] << 8) | l4[1]
        dport = (l4[2] << 8) | l4[3]
        if proto == 6 and len(l4) >= 14:
            f = l4[13]
            flags = "".join(ch for bit, ch in TCP_FLAG_BITS if f & bit) or "-"
    elif proto in (1, 58) and l4:
        dport = l4[0]                                   # ICMP type goes in the dport slot
    return src, dst, name, sport, dport, flags


# ---------------------------------------------------------------------------
# tcpdump text parsing
# ---------------------------------------------------------------------------

_TS = (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?"      # -tttt
       r"|\d{2}:\d{2}:\d{2}(?:\.\d+)?"                        # default
       r"|\d+\.\d+")                                           # -tt epoch
_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"

TEXT_LINE_RE = re.compile(
    rf"^(?:(?P<ts>{_TS})\s+)?"
    rf"(?:{_MAC} > {_MAC}, ethertype \S+ \(0x[0-9a-fA-F]+\), length (?P<flen>\d+): )?"
    r"(?:(?P<fam>IP6|IP)(?: \((?P<hdr>.*?)\))?\s+)?"       # -v on IPv6 keeps the header inline
    r"(?P<src>\S+) > (?P<dst>\S+?):(?:\s+(?P<rest>.*))?$"
)
# `-v` on IPv4 prints the header line alone, then the addresses on an indented continuation line
TEXT_VHDR_RE = re.compile(
    rf"^(?:(?P<ts>{_TS})\s+)?(?P<fam>IP6|IP) \((?P<hdr>.*)\)\s*$"
)
TEXT_VCONT_RE = re.compile(r"^\s+(?P<src>\S+) > (?P<dst>\S+?):(?:\s+(?P<rest>.*))?$")
_LEN_RE = re.compile(r"length (\d+)")
_FLAGS_RE = re.compile(r"Flags \[([^\]]*)\]")
_IPPROTO_RE = re.compile(r"^ip-proto-(\d+)")
_HDR_PROTO_RE = re.compile(r"(?:proto|next-header) (\w+) \((\d+)\)")
_HDR_LEN_RE = re.compile(r"(payload )?length:? (\d+)")


def header_hints(fam: str, hdr: str):
    """(proto_name, total_length) from the parenthesised IP header that tcpdump -v prints."""
    pname = None
    pm = _HDR_PROTO_RE.search(hdr)
    if pm:
        pname = PROTO_NAMES.get(int(pm.group(2))) or pm.group(1)
        if fam == "IP" and "offset " in hdr and not re.search(r"offset 0[,)]", hdr):
            pname += "-frag"
    length = None
    lm = _HDR_LEN_RE.search(hdr)
    if lm:
        length = int(lm.group(2)) + (40 if lm.group(1) else 0)   # IPv6 reports payload length
    return pname, length

_TCPDUMP_FLAG_MAP = {".": "A", "S": "S", "P": "P", "F": "F", "R": "R", "U": "U", "E": "E", "W": "C"}


def parse_ts(s: str | None):
    if s is None:
        return None
    if " " in s:                                        # -tttt: YYYY-MM-DD HH:MM:SS.frac
        d, t = s.split(" ")
        y, mo, da = (int(x) for x in d.split("-"))
        hh, mm, ss = t.split(":")
        sec = float(ss)
        frac = int(round((sec - int(sec)) * 1_000_000))
        return dt.datetime(y, mo, da, int(hh), int(mm), int(sec), min(frac, 999_999)).timestamp()
    if ":" in s:                                        # HH:MM:SS.frac (time of day only)
        hh, mm, ss = s.split(":")
        return int(hh) * 3600 + int(mm) * 60 + float(ss)
    return float(s)


_serv_cache: dict[str, int | None] = {}


def _port(tok: str | None) -> int | None:
    if tok is None:
        return None
    if tok.isdigit():
        return int(tok)
    if tok not in _serv_cache:
        try:
            _serv_cache[tok] = socket.getservbyname(tok)
        except OSError:
            _serv_cache[tok] = None
    return _serv_cache[tok]


def split_host_port(tok: str) -> tuple[str, str | None]:
    """'203.0.113.5.54321' -> ('203.0.113.5', '54321'); '2001:db8::1.443' -> (...)"""
    if ":" in tok:                                      # IPv6
        if "." in tok and not tok.startswith("::ffff:"):
            host, port = tok.rsplit(".", 1)
            return host, port
        return tok, None
    dots = tok.count(".")
    if dots == 4:
        host, port = tok.rsplit(".", 1)
        return host, port
    return tok, None


def _norm_flags(s: str) -> str:
    return "".join(_TCPDUMP_FLAG_MAP.get(ch, "") for ch in s) or "-"


def _text_proto(rest: str, sport, dport, hint: str | None):
    """Return (proto_name, flags) from the decoded part of a tcpdump line."""
    flags = None
    if rest.startswith("Flags ["):
        m = _FLAGS_RE.match(rest)
        return "TCP", _norm_flags(m.group(1)) if m else "-"
    if hint:
        return hint, None
    if rest.startswith("ICMP6"):
        return "ICMPv6", None
    if rest.startswith("ICMP"):
        return "ICMP", None
    if rest.startswith("UDP"):
        return "UDP", None
    m = _IPPROTO_RE.match(rest)
    if m:                                               # non-first fragment or unknown proto
        p = int(m.group(1))
        return (PROTO_NAMES.get(p) or f"proto-{p}") + "-frag", None
    low = rest[:6].lower()
    if low.startswith("gre"):
        return "GRE", None
    if low.startswith("esp"):
        return "ESP", None
    if low.startswith("ah"):
        return "AH", None
    if low.startswith("sctp"):
        return "SCTP", None
    if sport is not None or dport is not None:
        return "UDP", None                              # tcpdump decoded an app protocol over UDP
    return "other", flags


def parse_text(stream, stats: Stats):
    """Yield (ts, src, dst, proto, sport, dport, length, flags) from tcpdump text."""
    pending = None   # (ts, proto_hint, total_len) from a -v header line
    for raw in stream:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            continue
        hint_proto = hint_len = None
        ts = None
        if pending is not None and line[0] in " \t":
            m = TEXT_VCONT_RE.match(line)
            ts, hint_proto, hint_len = pending
            pending = None
            if not m:
                stats.unparsed_lines += 1
                continue
            flen = None
        else:
            pending = None
            m = TEXT_LINE_RE.match(line)
            if not m:
                mh = TEXT_VHDR_RE.match(line)
                if mh:
                    pname, plen = header_hints(mh.group("fam"), mh.group("hdr"))
                    pending = (parse_ts(mh.group("ts")), pname, plen)
                    continue
                if line[0] not in " \t":                # continuation lines of -v/-X dumps are fine
                    stats.unparsed_lines += 1
                continue
            ts = parse_ts(m.group("ts"))
            flen = m.group("flen")
            if m.group("hdr"):
                hint_proto, hint_len = header_hints(m.group("fam"), m.group("hdr"))
        src, sp = split_host_port(m.group("src"))
        dst, dp = split_host_port(m.group("dst"))
        if not (src and dst and src[0].isdigit() or ":" in src):
            stats.unparsed_lines += 1
            continue
        rest = m.group("rest") or ""
        sport, dport = _port(sp), _port(dp)
        proto, flags = _text_proto(rest, sport, dport, hint_proto)
        if proto.startswith("ICMP"):
            sport = dport = None
        if flen is not None:
            length = int(flen)
        elif hint_len is not None:
            length = hint_len
        else:
            lm = None
            for lm in _LEN_RE.finditer(rest):
                pass
            length = int(lm.group(1)) if lm else 0
        yield ts, src, dst, proto, sport, dport, length, flags


# ---------------------------------------------------------------------------
# AS lookup
# ---------------------------------------------------------------------------

def is_global_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class AsnResolver:
    CYMRU = ("whois.cymru.com", 43)
    BATCH = 500

    def __init__(self, backend: str, mmdb_path=None, pyasn_path=None,
                 cache_path=None, timeout: float = 20.0) -> None:
        self.backend = backend
        self.timeout = timeout
        self.cache_path = cache_path
        self.cache: dict = {}
        self._mmdb = self._pyasn = None
        if backend == "mmdb":
            try:
                import maxminddb  # type: ignore
            except ImportError:
                sys.exit("--asn-db needs the maxminddb module: pip install maxminddb")
            self._mmdb = maxminddb.open_database(mmdb_path)
        elif backend == "pyasn":
            try:
                import pyasn  # type: ignore
            except ImportError:
                sys.exit("--pyasn needs the pyasn module: pip install pyasn")
            self._pyasn = pyasn.pyasn(pyasn_path)
        elif backend == "cymru" and cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as fh:
                    self.cache = json.load(fh)
            except (OSError, ValueError) as e:
                warn(f"could not read ASN cache {cache_path}: {e}")

    def label(self) -> str:
        return {"cymru": "Team Cymru whois", "mmdb": "MaxMind ASN db", "pyasn": "pyasn db"}[self.backend]

    @staticmethod
    def _rec(asn, name, prefix=None, cc=None) -> dict:
        return {"asn": asn, "name": name, "prefix": prefix, "cc": cc}

    def resolve(self, ips: list[str]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        pending: list[str] = []
        for ip in ips:
            if not is_global_ip(ip):
                out[ip] = self._rec(None, "private/reserved")
            elif self.backend == "mmdb":
                r = self._mmdb.get(ip) or {}
                asn = r.get("autonomous_system_number")
                out[ip] = self._rec(asn, r.get("autonomous_system_organization") or ("unknown" if asn is None else f"AS{asn}"))
            elif self.backend == "pyasn":
                asn, prefix = self._pyasn.lookup(ip)
                out[ip] = self._rec(asn, f"AS{asn}" if asn else "unknown", prefix)
            elif ip in self.cache:
                out[ip] = self.cache[ip]
            else:
                pending.append(ip)
        if pending:
            fetched = self._cymru(pending)
            out.update(fetched)
            self.cache.update(fetched)
            self._save_cache()
        return out

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.cache, fh)
            os.replace(tmp, self.cache_path)
        except OSError as e:
            warn(f"could not write ASN cache: {e}")

    def _cymru(self, ips: list[str]) -> dict[str, dict]:
        results: dict[str, dict] = {}
        total = len(ips)
        tty = sys.stderr.isatty()
        for i in range(0, total, self.BATCH):
            chunk = ips[i:i + self.BATCH]
            try:
                with socket.create_connection(self.CYMRU, timeout=self.timeout) as s:
                    s.sendall(("begin\nverbose\nnoheader\n" + "\n".join(chunk) + "\nend\n").encode())
                    buf = []
                    while True:
                        b = s.recv(65536)
                        if not b:
                            break
                        buf.append(b)
            except OSError as e:
                warn(f"Team Cymru lookup failed after {len(results)}/{total} IPs ({e}); "
                     f"use --asn-db/--pyasn for offline lookups")
                break
            for line in b"".join(buf).decode("utf-8", "replace").splitlines():
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 7:
                    continue
                asn, ip, prefix, cc, _reg, _alloc, name = parts[:7]
                try:
                    ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    continue
                asn = asn.split()[0] if asn else ""          # MOAS prefixes list several origins
                if asn.isdigit():
                    results[ip] = self._rec(int(asn), name, None if prefix == "NA" else prefix,
                                            None if cc == "NA" else cc)
                else:
                    results[ip] = self._rec(None, "unknown (not routed)")
            if tty:
                print(f"\r[asn] resolved {min(i + self.BATCH, total):,}/{total:,} IPs", end="", file=sys.stderr)
        if tty and total:
            print(file=sys.stderr)
        return results


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n):,} B"
        n /= 1024
    return f"{n:,.1f} TB"


def human_bits(bps: float) -> str:
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"):
        if bps < 1000 or unit == "Tbit/s":
            return f"{bps:,.1f} {unit}"
        bps /= 1000
    return f"{bps:,.1f} Tbit/s"


def pct(n: float, total: float) -> str:
    return f"{100.0 * n / total:5.1f}%" if total else "   - "


def fmt_time(ts: float | None, stats: Stats, with_date: bool = False) -> str:
    if ts is None:
        return "-"
    if stats.ts_mode == "tod":
        s = int(ts)
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"
    d = dt.datetime.fromtimestamp(ts)
    return d.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def fmt_table(headers, rows, right=()) -> str:
    srows = [[str(c) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in srows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))

    def line(cells):
        return "  ".join((c.rjust(widths[i]) if i in right else c.ljust(widths[i]))
                         for i, c in enumerate(cells)).rstrip()

    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in srows])


def port_label(proto: str, port: int) -> str:
    if proto.startswith("ICMP"):
        return f"type {port}"
    name = PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def asn_label(rec: dict | None) -> str:
    if rec is None:
        return "not resolved"
    if rec["asn"] is None:
        return rec["name"]
    return f"AS{rec['asn']} {rec['name']}"


def prefix_of(ip: str) -> str:
    if ":" in ip:
        try:
            return str(ipaddress.ip_network(f"{ip}/48", strict=False))
        except ValueError:
            return ip
    return ip.rsplit(".", 1)[0] + ".0/24"


def timeline_rows(stats: Stats, buckets: int):
    """Collapse per-second counters into at most `buckets` rows (O(seconds seen), not O(span))."""
    if not stats.per_sec_pkts:
        return []
    first = min(stats.per_sec_pkts)
    last = max(stats.per_sec_pkts)
    span = last - first + 1
    width = max(1, -(-span // buckets))                  # ceil
    bp: Counter = Counter()
    bb: Counter = Counter()
    for sec, p in stats.per_sec_pkts.items():
        bp[(sec - first) // width] += p
    for sec, b in stats.per_sec_bytes.items():
        bb[(sec - first) // width] += b
    rows = []
    for i in range(-(-span // width)):
        start = first + i * width
        rows.append((start, min(start + width, last + 1) - start, bp.get(i, 0), bb.get(i, 0)))
    return rows


def build_report(stats: Stats, top: int, asn_info, source_label: str, kind: str):
    resolved, resolver_label, lookup_cov_pkts, lookup_ips = asn_info
    out: list[str] = []
    P = stats.packets
    B = stats.bytes
    dur = stats.duration
    byte_note = "wire bytes" if kind != "text" else "bytes as printed by tcpdump (payload unless -e/-v)"

    out.append("DDoS traffic summary")
    out.append("=" * 72)
    skipped = []
    if stats.non_ip:
        skipped.append(f"{stats.non_ip:,} non-IP frames skipped")
    if stats.filtered:
        skipped.append(f"{stats.filtered:,} packets excluded by --dst")
    if stats.unparsed_lines:
        skipped.append(f"{stats.unparsed_lines:,} lines not parsed")
    out.append(f"Input:            {source_label} ({kind}{'; ' + ', '.join(skipped) if skipped else ''})")
    if stats.first_ts is not None:
        out.append(f"Capture window:   {fmt_time(stats.first_ts, stats, True)} - "
                   f"{fmt_time(stats.last_ts, stats, True)}  ({dur:,.1f} s)")
    out.append(f"Packets:          {P:,}")
    out.append(f"Bytes:            {human_bytes(B)}  [{byte_note}]")
    if dur > 0:
        out.append(f"Average rate:     {P / dur:,.0f} pps / {human_bits(B * 8 / dur)}")
    if stats.per_sec_pkts:
        peak_sec, peak_p = max(stats.per_sec_pkts.items(), key=lambda kv: kv[1])
        peakb_sec, peak_b = max(stats.per_sec_bytes.items(), key=lambda kv: kv[1])
        out.append(f"Peak (1 s):       {peak_p:,} pps at {fmt_time(peak_sec, stats)} / "
                   f"{human_bits(peak_b * 8)} at {fmt_time(peakb_sec, stats)}")
    out.append(f"Unique sources:   {len(stats.src_pkts):,}    Unique destinations: {len(stats.dst_pkts):,}")
    if stats.interrupted:
        out.append("(capture interrupted - partial results)")
    if P == 0:
        return "\n".join(out)

    # protocols
    out += ["", "Protocols"]
    rows = [(proto, f"{n:,}", pct(n, P), human_bytes(stats.proto_bytes[proto]), pct(stats.proto_bytes[proto], B))
            for proto, n in stats.proto_pkts.most_common()]
    out.append(fmt_table(["proto", "packets", "pkt %", "bytes", "byte %"], rows, right={1, 2, 3, 4}))

    # tcp flags
    if stats.tcp_flags:
        tcp_total = sum(stats.tcp_flags.values())
        out += ["", f"TCP flags  ({TCP_FLAG_LEGEND})"]
        rows = [(f, f"{n:,}", pct(n, tcp_total)) for f, n in stats.tcp_flags.most_common(top)]
        out.append(fmt_table(["flags", "packets", "% of TCP"], rows, right={1, 2}))

    # top source IPs
    out += ["", f"Top {top} source IPs"]
    rows = []
    for ip, n in stats.src_pkts.most_common(top):
        b = stats.src_bytes[ip]
        rows.append((ip, f"{n:,}", pct(n, P), human_bytes(b), f"{b / n:,.0f}", asn_label(resolved.get(ip)) if resolved is not None else ""))
    headers = ["source IP", "packets", "pkt %", "bytes", "avg size", "AS"]
    if resolved is None:
        headers = headers[:-1]
        rows = [r[:-1] for r in rows]
    out.append(fmt_table(headers, rows, right={1, 2, 3, 4}))

    # top source prefixes
    pfx_pkts: Counter = Counter()
    pfx_ips: Counter = Counter()
    for ip, n in stats.src_pkts.items():
        p = prefix_of(ip)
        pfx_pkts[p] += n
        pfx_ips[p] += 1
    out += ["", f"Top {top} source prefixes (/24, /48)"]
    rows = [(p, f"{n:,}", pct(n, P), f"{pfx_ips[p]:,}") for p, n in pfx_pkts.most_common(top)]
    out.append(fmt_table(["prefix", "packets", "pkt %", "src IPs"], rows, right={1, 2, 3}))

    # top ASes
    if resolved is not None:
        asn_pkts: Counter = Counter()
        asn_bytes: Counter = Counter()
        asn_ips: Counter = Counter()
        for ip in lookup_ips:
            rec = resolved.get(ip)
            key = asn_label(rec)
            asn_pkts[key] += stats.src_pkts[ip]
            asn_bytes[key] += stats.src_bytes[ip]
            asn_ips[key] += 1
        out += ["", f"Top {top} source ASes  [{resolver_label}: {len(lookup_ips):,} of {len(stats.src_pkts):,} "
                    f"source IPs looked up, covering {pct(lookup_cov_pkts, P).strip()} of packets]"]
        rows = [(k, f"{n:,}", pct(n, P), human_bytes(asn_bytes[k]), f"{asn_ips[k]:,}") for k, n in asn_pkts.most_common(top)]
        out.append(fmt_table(["AS", "packets", "pkt %", "bytes", "src IPs"], rows, right={1, 2, 3, 4}))

    # destinations
    out += ["", f"Top {min(top, len(stats.dst_pkts))} destination IPs"]
    rows = [(ip, f"{n:,}", pct(n, P), human_bytes(stats.dst_bytes[ip])) for ip, n in stats.dst_pkts.most_common(top)]
    out.append(fmt_table(["destination IP", "packets", "pkt %", "bytes"], rows, right={1, 2, 3}))

    if stats.dport:
        out += ["", f"Top {top} destination ports / ICMP types"]
        rows = [(proto, port_label(proto, port), f"{n:,}", pct(n, P)) for (proto, port), n in stats.dport.most_common(top)]
        out.append(fmt_table(["proto", "dst port", "packets", "pkt %"], rows, right={2, 3}))
    if stats.sport:
        out += ["", f"Top {top} source ports  ((*) = common amplification/reflection service)"]
        rows = [(proto, port_label(proto, port), f"{n:,}", pct(n, P)) for (proto, port), n in stats.sport.most_common(top)]
        out.append(fmt_table(["proto", "src port", "packets", "pkt %"], rows, right={2, 3}))

    # sizes
    out += ["", "Packet size distribution"]
    rows = [(label, f"{stats.size_hist[label]:,}", pct(stats.size_hist[label], P))
            for _, label in SIZE_BUCKETS if stats.size_hist[label]]
    out.append(fmt_table(["bytes", "packets", "pkt %"], rows, right={1, 2}))

    # timeline
    tl = timeline_rows(stats, 24)
    if len(tl) > 1:
        maxp = max(r[2] for r in tl)
        out += ["", "Timeline"]
        rows = []
        for start, width, p, b in tl:
            pps = p / width
            bar = "#" * int(round(30 * p / maxp)) if maxp else ""
            rows.append((fmt_time(start, stats), f"{width}s", f"{pps:,.0f}", human_bits(b * 8 / width), bar))
        out.append(fmt_table(["from", "bin", "avg pps", "avg rate", ""], rows, right={2, 3}))
    return "\n".join(out)


def build_json(stats: Stats, top: int, asn_info, source_label: str, kind: str) -> dict:
    resolved, resolver_label, lookup_cov_pkts, lookup_ips = asn_info
    P = stats.packets
    doc = {
        "input": source_label,
        "input_kind": kind,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "packets": P,
        "bytes": stats.bytes,
        "non_ip_frames": stats.non_ip,
        "filtered_out": stats.filtered,
        "unparsed_lines": stats.unparsed_lines,
        "interrupted": stats.interrupted,
        "first_ts": stats.first_ts,
        "last_ts": stats.last_ts,
        "timestamp_mode": stats.ts_mode,
        "duration_s": stats.duration,
        "avg_pps": P / stats.duration if stats.duration else None,
        "avg_bps": stats.bytes * 8 / stats.duration if stats.duration else None,
        "peak_pps": max(stats.per_sec_pkts.values()) if stats.per_sec_pkts else None,
        "peak_bps": max(stats.per_sec_bytes.values()) * 8 if stats.per_sec_bytes else None,
        "unique_sources": len(stats.src_pkts),
        "unique_destinations": len(stats.dst_pkts),
        "protocols": [{"proto": k, "packets": v, "bytes": stats.proto_bytes[k]} for k, v in stats.proto_pkts.most_common()],
        "tcp_flags": [{"flags": k, "packets": v} for k, v in stats.tcp_flags.most_common()],
        "top_sources": [{"ip": ip, "packets": n, "bytes": stats.src_bytes[ip],
                         **({"as": resolved.get(ip)} if resolved is not None else {})}
                        for ip, n in stats.src_pkts.most_common(top)],
        "top_destinations": [{"ip": ip, "packets": n, "bytes": stats.dst_bytes[ip]} for ip, n in stats.dst_pkts.most_common(top)],
        "top_dst_ports": [{"proto": p, "port": port, "packets": n} for (p, port), n in stats.dport.most_common(top)],
        "top_src_ports": [{"proto": p, "port": port, "packets": n} for (p, port), n in stats.sport.most_common(top)],
        "size_distribution": [{"bucket": label, "packets": stats.size_hist[label]} for _, label in SIZE_BUCKETS],
        "timeline": [{"start": s, "width_s": w, "packets": p, "bytes": b} for s, w, p, b in timeline_rows(stats, 120)],
    }
    pfx: Counter = Counter()
    for ip, n in stats.src_pkts.items():
        pfx[prefix_of(ip)] += n
    doc["top_source_prefixes"] = [{"prefix": p, "packets": n} for p, n in pfx.most_common(top)]
    if resolved is not None:
        asn_pkts: Counter = Counter()
        asn_bytes: Counter = Counter()
        asn_ips: Counter = Counter()
        asn_rec: dict = {}
        for ip in lookup_ips:
            rec = resolved.get(ip)
            key = asn_label(rec)
            asn_pkts[key] += stats.src_pkts[ip]
            asn_bytes[key] += stats.src_bytes[ip]
            asn_ips[key] += 1
            asn_rec[key] = rec
        doc["asn_lookup"] = {"backend": resolver_label, "ips_looked_up": len(lookup_ips),
                             "packets_covered": lookup_cov_pkts}
        doc["top_ases"] = [{"label": k, "asn": (asn_rec[k] or {}).get("asn"), "name": (asn_rec[k] or {}).get("name"),
                            "packets": n, "bytes": asn_bytes[k], "source_ips": asn_ips[k]}
                           for k, n in asn_pkts.most_common(top)]
    return doc


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def ingest(stream, kind: str, head: bytes, stats: Stats, dst_filter: set[str] | None, show_progress: bool) -> None:
    add = stats.add
    count = 0
    t0 = time.monotonic()
    try:
        if kind == "text":
            for ts, src, dst, proto, sport, dport, length, flags in parse_text(stream, stats):
                if dst_filter and dst not in dst_filter:
                    stats.filtered += 1
                    continue
                add(ts, src, dst, proto, sport, dport, length, flags)
                count += 1
                if show_progress and count % 500_000 == 0:
                    print(f"\r[read] {count:,} packets ({count / (time.monotonic() - t0):,.0f}/s)", end="", file=sys.stderr)
        else:
            records = iter_pcap(stream, head) if kind == "pcap" else iter_pcapng(stream, head)
            for ts, linktype, data, wire_len in records:
                ip = link_to_ip(linktype, data)
                d = decode_ip(ip) if ip is not None else None
                if d is None:
                    stats.non_ip += 1
                    continue
                src, dst, proto, sport, dport, flags = d
                if dst_filter and dst not in dst_filter:
                    stats.filtered += 1
                    continue
                add(ts, src, dst, proto, sport, dport, wire_len, flags)
                count += 1
                if show_progress and count % 500_000 == 0:
                    print(f"\r[read] {count:,} packets ({count / (time.monotonic() - t0):,.0f}/s)", end="", file=sys.stderr)
    except KeyboardInterrupt:
        stats.interrupted = True
    except (ValueError, struct.error) as e:
        warn(f"stopped reading input: {e}")
    if show_progress and count >= 500_000:
        print(file=sys.stderr)
    # tcpdump's default text timestamps carry no date: seconds since midnight
    if stats.first_ts is not None and stats.last_ts is not None and stats.last_ts < 2 * 86400:
        stats.ts_mode = "tod"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Summarise DDoS traffic from tcpdump (pcap/pcapng or text).",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("input", help="pcap/pcapng file, tcpdump text file, or - for stdin")
    ap.add_argument("--top", type=int, default=20, metavar="N", help="rows per table (default 20)")
    ap.add_argument("--dst", action="append", metavar="IP", help="only count packets to this destination (repeatable)")
    ap.add_argument("--json", metavar="FILE", help="also write the full report as JSON")
    asn = ap.add_argument_group("AS lookup")
    asn.add_argument("--no-asn", action="store_true", help="skip AS lookups")
    asn.add_argument("--asn-db", metavar="FILE.mmdb", help="MaxMind GeoLite2-ASN database (offline)")
    asn.add_argument("--pyasn", metavar="FILE.dat", help="pyasn database (offline)")
    asn.add_argument("--asn-limit", type=int, default=5000, metavar="N",
                     help="with Team Cymru, only look up the N busiest source IPs (0 = all; default 5000)")
    asn.add_argument("--asn-cache", metavar="FILE",
                     default=os.path.join(os.path.expanduser("~"), ".cache", "ddos_analyze", "asn_cache.json"),
                     help="Team Cymru result cache (default ~/.cache/ddos_analyze/asn_cache.json)")
    asn.add_argument("--asn-timeout", type=float, default=20.0, metavar="SEC", help="whois connection timeout")
    args = ap.parse_args(argv)

    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    dst_filter = None
    if args.dst:
        try:
            dst_filter = {str(ipaddress.ip_address(x)) for x in args.dst}
        except ValueError as e:
            ap.error(f"--dst: {e}")

    try:
        stream, kind, head = open_input(args.input)
    except OSError as e:
        ap.error(str(e))
    source_label = "stdin" if args.input == "-" else args.input

    stats = Stats()
    ingest(stream, kind, head, stats, dst_filter, show_progress=sys.stderr.isatty())

    # AS lookup for the busiest sources
    asn_info = (None, None, 0, [])
    if not args.no_asn and stats.src_pkts:
        backend = "mmdb" if args.asn_db else "pyasn" if args.pyasn else "cymru"
        resolver = AsnResolver(backend, args.asn_db, args.pyasn, args.asn_cache, args.asn_timeout)
        if backend == "cymru" and args.asn_limit > 0:
            lookup_ips = [ip for ip, _ in stats.src_pkts.most_common(args.asn_limit)]
        else:
            lookup_ips = list(stats.src_pkts)
        resolved = resolver.resolve(lookup_ips)
        lookup_ips = [ip for ip in lookup_ips if ip in resolved]
        covered = sum(stats.src_pkts[ip] for ip in lookup_ips)
        asn_info = (resolved, resolver.label(), covered, lookup_ips)

    print(build_report(stats, args.top, asn_info, source_label, kind))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(build_json(stats, args.top, asn_info, source_label, kind), fh, indent=2)
        print(f"\nJSON report written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
