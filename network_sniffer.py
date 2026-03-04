#!/usr/bin/env python3
"""
=============================================================
  Basic Network Sniffer — CodeAlpha Cybersecurity Internship
  Task 1: Capture and analyze network traffic packets
=============================================================
  Author   : Intern (CodeAlpha)
  Libraries: scapy (primary), socket (fallback)
  Usage    : sudo python3 network_sniffer.py [options]
=============================================================
"""

import sys
import os
import argparse
import datetime
import socket
import struct
import textwrap

# ── Colour helpers ────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C = {
        "header":  Fore.CYAN + Style.BRIGHT,
        "info":    Fore.GREEN,
        "warn":    Fore.YELLOW,
        "error":   Fore.RED + Style.BRIGHT,
        "proto":   Fore.MAGENTA,
        "payload": Fore.WHITE,
        "reset":   Style.RESET_ALL,
    }
except ImportError:
    C = {k: "" for k in ("header", "info", "warn", "error", "proto", "payload", "reset")}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — Scapy-based sniffer (rich dissection)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def banner():
    print(C["header"] + """
╔══════════════════════════════════════════════════════════╗
║        Basic Network Sniffer — CodeAlpha Intern          ║
║  Capture · Dissect · Analyze Network Traffic Packets     ║
╚══════════════════════════════════════════════════════════╝
""" + C["reset"])


# ── Protocol registry ─────────────────────────────────────────────────────────
PROTO_MAP = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

PORT_MAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

packet_count = 0
start_time   = None
stats        = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}


def port_service(port: int) -> str:
    return PORT_MAP.get(port, "")


def format_payload(data: bytes, max_bytes: int = 64) -> str:
    """Return hex + ASCII side-by-side representation."""
    data = data[:max_bytes]
    hex_part  = " ".join(f"{b:02x}" for b in data)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"  HEX  : {hex_part}\n  ASCII: {ascii_part}"


def divider(char="─", width=60):
    print(C["info"] + char * width + C["reset"])


# ── Scapy packet callback ─────────────────────────────────────────────────────
def scapy_callback(pkt, show_payload: bool = False, log_file=None):
    global packet_count, stats
    packet_count += 1
    ts  = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    out = []

    out.append(C["header"] + f"\n[#{packet_count:04d}] {ts}" + C["reset"])

    # ── Ethernet ──────────────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        out.append(f"  {C['proto']}[Ethernet]{C['reset']}  src={eth.src}  dst={eth.dst}  type=0x{eth.type:04x}")

    # ── ARP ───────────────────────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op  = "REQUEST" if arp.op == 1 else "REPLY"
        out.append(f"  {C['proto']}[ARP]{C['reset']}  op={op}  sender={arp.psrc} ({arp.hwsrc})  target={arp.pdst} ({arp.hwdst})")
        stats["ARP"] += 1

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(IP):
        ip  = pkt[IP]
        proto_name = PROTO_MAP.get(ip.proto, f"proto#{ip.proto}")
        out.append(
            f"  {C['proto']}[IPv4]{C['reset']}  {ip.src} → {ip.dst}  "
            f"proto={proto_name}  ttl={ip.ttl}  len={ip.len}"
        )

        # ── TCP ───────────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp  = pkt[TCP]
            flags = []
            flag_map = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST",
                        "P": "PSH", "U": "URG"}
            for f, name in flag_map.items():
                if f in str(tcp.flags):
                    flags.append(name)
            sport_svc = f" ({port_service(tcp.sport)})" if port_service(tcp.sport) else ""
            dport_svc = f" ({port_service(tcp.dport)})" if port_service(tcp.dport) else ""
            out.append(
                f"  {C['proto']}[TCP]{C['reset']}  "
                f"sport={tcp.sport}{sport_svc}  dport={tcp.dport}{dport_svc}  "
                f"flags=[{','.join(flags)}]  seq={tcp.seq}  ack={tcp.ack}  win={tcp.window}"
            )
            stats["TCP"] += 1

        # ── UDP ───────────────────────────────────────────────────────────────
        elif pkt.haslayer(UDP):
            udp  = pkt[UDP]
            sport_svc = f" ({port_service(udp.sport)})" if port_service(udp.sport) else ""
            dport_svc = f" ({port_service(udp.dport)})" if port_service(udp.dport) else ""
            out.append(
                f"  {C['proto']}[UDP]{C['reset']}  "
                f"sport={udp.sport}{sport_svc}  dport={udp.dport}{dport_svc}  len={udp.len}"
            )
            stats["UDP"] += 1

            # DNS sub-dissection
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                qr  = "RESPONSE" if dns.qr else "QUERY"
                if dns.qd:
                    try:
                        qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                        out.append(f"  {C['proto']}[DNS]{C['reset']}  {qr}  qname={qname}")
                    except Exception:
                        pass

        # ── ICMP ──────────────────────────────────────────────────────────────
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            icmp_types = {0: "Echo-Reply", 3: "Dest-Unreachable",
                          8: "Echo-Request", 11: "Time-Exceeded"}
            type_name = icmp_types.get(icmp.type, f"type={icmp.type}")
            out.append(f"  {C['proto']}[ICMP]{C['reset']}  {type_name}  code={icmp.code}")
            stats["ICMP"] += 1

        else:
            stats["Other"] += 1

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        out.append(f"  {C['proto']}[IPv6]{C['reset']}  {ip6.src} → {ip6.dst}  nh={ip6.nh}  hlim={ip6.hlim}")
        stats["Other"] += 1

    # ── Raw payload ───────────────────────────────────────────────────────────
    if show_payload and pkt.haslayer(Raw):
        raw_data = bytes(pkt[Raw])
        if raw_data:
            out.append(f"  {C['payload']}[Payload]  {len(raw_data)} bytes{C['reset']}")
            out.append(format_payload(raw_data))

    msg = "\n".join(out)
    print(msg)

    if log_file:
        log_file.write(msg + "\n")


def print_stats():
    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    print(C["header"] + "\n══ Capture Summary ══" + C["reset"])
    print(f"  Duration   : {elapsed:.1f}s")
    print(f"  Total pkts : {packet_count}")
    for proto, cnt in stats.items():
        pct = (cnt / packet_count * 100) if packet_count else 0
        print(f"  {proto:<8}: {cnt}  ({pct:.1f}%)")


# ── Scapy main ────────────────────────────────────────────────────────────────
def detect_windows_l3():
    """Return True if we're on Windows without Npcap (need L3 fallback)."""
    if sys.platform != "win32":
        return False
    try:
        from scapy.arch.windows import get_windows_if_list
        import scapy.config
        # Try importing winpcap/npcap support
        from scapy.arch.windows.npcap import NpcapPacketListType  # noqa
        return False  # Npcap is present
    except Exception:
        return True


def run_scapy(args):
    global start_time
    banner()

    use_l3 = detect_windows_l3()

    print(C["info"] + f"[+] Using Scapy engine" + C["reset"])
    if use_l3:
        print(C["warn"] + "[!] Npcap not found — using Layer-3 socket (L2 headers won't be shown)" + C["reset"])
        print(C["warn"] + "[!] For full L2 capture install Npcap from: https://npcap.com" + C["reset"])
    print(C["info"] + f"[+] Interface : {args.iface or 'default'}" + C["reset"])
    print(C["info"] + f"[+] Filter    : '{args.filter}'" + C["reset"])
    print(C["info"] + f"[+] Count     : {args.count or 'unlimited'}" + C["reset"])
    print(C["info"] + f"[+] Payload   : {'yes' if args.payload else 'no'}" + C["reset"])

    log_file = None
    if args.log:
        log_file = open(args.log, "w", encoding="utf-8")
        print(C["info"] + f"[+] Logging to: {args.log}" + C["reset"])

    divider()
    start_time = datetime.datetime.now()

    try:
        sniff_kwargs = dict(
            count=args.count,
            prn=lambda pkt: scapy_callback(pkt, show_payload=args.payload, log_file=log_file),
            store=False,
        )

        if use_l3:
            # Windows without Npcap: use Layer-3 raw sockets
            from scapy.config import conf
            sniff_kwargs["opened_socket"] = conf.L3socket()
            # BPF filters don't work on L3socket; warn user
            if args.filter:
                print(C["warn"] + f"[!] BPF filter '{args.filter}' ignored in L3 mode (Npcap required for filters)" + C["reset"])
        else:
            if args.iface:
                sniff_kwargs["iface"] = args.iface
            if args.filter:
                sniff_kwargs["filter"] = args.filter

        print(C["info"] + "[+] Sniffing started — press Ctrl+C to stop\n" + C["reset"])
        sniff(**sniff_kwargs)

    except PermissionError:
        print(C["error"] + "\n[!] Permission denied — run as Administrator." + C["reset"])
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(C["error"] + f"\n[!] Error: {e}" + C["reset"])
        print(C["warn"] + "[!] Try running as Administrator, or install Npcap from https://npcap.com" + C["reset"])
    finally:
        print_stats()
        if log_file:
            log_file.close()
            print(C["info"] + f"[+] Log saved to {args.log}" + C["reset"])


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — Raw-socket fallback sniffer (no external deps)
# ─────────────────────────────────────────────────────────────────────────────

ETH_P_ALL = 0x0003
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def parse_ethernet(data):
    dst = ":".join(f"{b:02x}" for b in data[0:6])
    src = ":".join(f"{b:02x}" for b in data[6:12])
    proto = struct.unpack("!H", data[12:14])[0]
    return dst, src, proto, data[14:]


def parse_ipv4(data):
    ver_ihl = data[0]
    ihl     = (ver_ihl & 0x0F) * 4
    ttl, proto = data[8], data[9]
    src  = socket.inet_ntoa(data[12:16])
    dst  = socket.inet_ntoa(data[16:20])
    return src, dst, proto, ttl, data[ihl:]


def parse_tcp(data):
    src_port, dst_port, seq, ack = struct.unpack("!HHLL", data[0:12])
    offset   = ((data[12] >> 4) * 4)
    flag_byte = data[13]
    flags = []
    if flag_byte & 0x02: flags.append("SYN")
    if flag_byte & 0x10: flags.append("ACK")
    if flag_byte & 0x01: flags.append("FIN")
    if flag_byte & 0x04: flags.append("RST")
    if flag_byte & 0x08: flags.append("PSH")
    if flag_byte & 0x20: flags.append("URG")
    return src_port, dst_port, seq, ack, flags, data[offset:]


def parse_udp(data):
    src_port, dst_port, length = struct.unpack("!HHH", data[0:6])
    return src_port, dst_port, length, data[8:]


def parse_icmp(data):
    icmp_type, code = data[0], data[1]
    return icmp_type, code


def raw_socket_sniffer(args):
    global packet_count, start_time
    banner()
    print(C["warn"] + "[!] Scapy not found — falling back to raw-socket sniffer (Linux only)" + C["reset"])

    if sys.platform != "linux":
        print(C["error"] + "[!] Raw-socket sniffer requires Linux. Install scapy for cross-platform support." + C["reset"])
        print(C["info"] + "    pip install scapy colorama" + C["reset"])
        sys.exit(1)

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        print(C["error"] + "[!] Permission denied — run with sudo." + C["reset"])
        sys.exit(1)

    if args.iface:
        s.bind((args.iface, 0))

    divider()
    start_time = datetime.datetime.now()
    print(C["info"] + f"[+] Listening on {args.iface or 'all interfaces'} ... (Ctrl+C to stop)\n" + C["reset"])

    log_file = open(args.log, "w", encoding="utf-8") if args.log else None

    try:
        while True:
            if args.count and packet_count >= args.count:
                break
            raw, _ = s.recvfrom(65535)
            packet_count += 1
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            out = [C["header"] + f"[#{packet_count:04d}] {ts}" + C["reset"]]

            eth_dst, eth_src, eth_type, payload = parse_ethernet(raw)
            out.append(f"  {C['proto']}[Ethernet]{C['reset']}  src={eth_src}  dst={eth_dst}  type=0x{eth_type:04x}")

            if eth_type == 0x0800:  # IPv4
                try:
                    src, dst, proto, ttl, seg = parse_ipv4(payload)
                    proto_name = PROTO_NAMES.get(proto, f"#{proto}")
                    out.append(f"  {C['proto']}[IPv4]{C['reset']}  {src} → {dst}  proto={proto_name}  ttl={ttl}")

                    if proto == 6:
                        sp, dp, seq, ack, flags, data = parse_tcp(seg)
                        sp_s = f" ({port_service(sp)})" if port_service(sp) else ""
                        dp_s = f" ({port_service(dp)})" if port_service(dp) else ""
                        out.append(f"  {C['proto']}[TCP]{C['reset']}  sport={sp}{sp_s}  dport={dp}{dp_s}  flags={flags}  seq={seq}")
                        stats["TCP"] += 1
                        if args.payload and data:
                            out.append(f"  {C['payload']}[Payload] {len(data)} bytes{C['reset']}")
                            out.append(format_payload(data))

                    elif proto == 17:
                        sp, dp, length, data = parse_udp(seg)
                        sp_s = f" ({port_service(sp)})" if port_service(sp) else ""
                        dp_s = f" ({port_service(dp)})" if port_service(dp) else ""
                        out.append(f"  {C['proto']}[UDP]{C['reset']}  sport={sp}{sp_s}  dport={dp}{dp_s}  len={length}")
                        stats["UDP"] += 1

                    elif proto == 1:
                        icmp_type, code = parse_icmp(seg)
                        out.append(f"  {C['proto']}[ICMP]{C['reset']}  type={icmp_type}  code={code}")
                        stats["ICMP"] += 1

                    else:
                        stats["Other"] += 1

                except Exception:
                    stats["Other"] += 1

            elif eth_type == 0x0806:  # ARP
                out.append(f"  {C['proto']}[ARP]{C['reset']}")
                stats["ARP"] += 1
            else:
                stats["Other"] += 1

            msg = "\n".join(out)
            print(msg)
            if log_file:
                log_file.write(msg + "\n")

    except KeyboardInterrupt:
        pass
    finally:
        print_stats()
        if log_file:
            log_file.close()


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry-point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Basic Network Sniffer — CodeAlpha Cybersecurity Task 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          sudo python3 network_sniffer.py
          sudo python3 network_sniffer.py -i eth0 -c 50 -f "tcp port 80"
          sudo python3 network_sniffer.py -i wlan0 --payload --log capture.txt
          sudo python3 network_sniffer.py -f "udp port 53"   # DNS only
          sudo python3 network_sniffer.py -f "icmp"          # ICMP only
        """),
    )
    p.add_argument("-i", "--iface",   metavar="IFACE",  help="Network interface (e.g. eth0, wlan0)")
    p.add_argument("-c", "--count",   metavar="N", type=int, default=0, help="Stop after N packets (0 = unlimited)")
    p.add_argument("-f", "--filter",  metavar="BPF", default="", help="BPF filter string (Scapy mode only)")
    p.add_argument("-p", "--payload", action="store_true", help="Display packet payload (hex + ASCII)")
    p.add_argument("-l", "--log",     metavar="FILE", help="Save output to a log file")
    return p.parse_args()


def is_admin() -> bool:
    """Return True if the current process has admin / root privileges."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin():
    """Re-launch this script with UAC elevation on Windows."""
    import ctypes
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{a}"' for a in sys.argv[1:]])
    print(C["warn"] + "[!] Not running as Administrator." + C["reset"])
    print(C["warn"] + "[!] A UAC prompt will appear — please click Yes to allow." + C["reset"])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    if ret <= 32:
        print(C["error"] + f"[!] Elevation failed (code {ret})." + C["reset"])
        print(C["warn"] + "[!] Please right-click your terminal and choose Run as Administrator." + C["reset"])
    sys.exit(0)


if __name__ == "__main__":
    # Auto-elevate on Windows if not already admin
    if sys.platform == "win32" and not is_admin():
        relaunch_as_admin()

    args = parse_args()
    if SCAPY_AVAILABLE:
        run_scapy(args)
    else:
        raw_socket_sniffer(args)