# 🛡️ Basic Network Sniffer — CodeAlpha Cybersecurity Internship Task 1

A Python-based network packet sniffer that captures and analyzes live network traffic in real time.

---

## 📌 Features

- ✅ Captures live packets using **Scapy** (with raw-socket fallback on Linux)
- ✅ Dissects **Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS** layers
- ✅ Displays **source/destination IPs, ports, protocol flags, TTL, sequence numbers**
- ✅ Maps port numbers to service names (HTTP, HTTPS, SSH, DNS, RDP, etc.)
- ✅ Optional **hex + ASCII payload dump**
- ✅ **BPF filter** support (e.g. capture only DNS or HTTP traffic)
- ✅ **Live statistics** summary on exit (per-protocol packet counts)
- ✅ **Log to file** support
- ✅ **Auto-elevates** to Administrator on Windows via UAC prompt
- ✅ Graceful fallback to Layer-3 socket if Npcap is not installed

---

## 🖥️ Requirements

- Python 3.10+
- [Scapy](https://scapy.net/)
- [Colorama](https://pypi.org/project/colorama/) _(optional, for coloured output)_
- [Npcap](https://npcap.com) _(Windows only — recommended for full L2 capture)_

Install dependencies:

```bash
pip install scapy colorama
```

---

## 🚀 Usage

```bash
# Basic capture (auto-requests admin on Windows)
python network_sniffer.py

# Capture 50 packets on a specific interface
python network_sniffer.py -i eth0 -c 50

# Show raw payload (hex + ASCII)
python network_sniffer.py --payload -c 20

# Filter DNS traffic only (requires Npcap on Windows)
python network_sniffer.py -f "udp port 53"

# Filter ICMP (ping) traffic
python network_sniffer.py -f "icmp"

# Save output to a log file
python network_sniffer.py -c 100 --log capture.txt
```

---

## ⚙️ Command-Line Options

| Flag             | Description                                            |
| ---------------- | ------------------------------------------------------ |
| `-i IFACE`       | Network interface to capture on (e.g. `eth0`, `Wi-Fi`) |
| `-c N`           | Stop after N packets (default: unlimited)              |
| `-f BPF`         | BPF filter string — requires Npcap on Windows          |
| `-p / --payload` | Show hex + ASCII dump of packet payload                |
| `-l FILE`        | Save capture output to a log file                      |

---

## 📸 Sample Output

```
╔══════════════════════════════════════════════════════════╗
║        Basic Network Sniffer — CodeAlpha Intern          ║
║  Capture · Dissect · Analyze Network Traffic Packets     ║
╚══════════════════════════════════════════════════════════╝

[#0001] 14:32:01.221
  [Ethernet]  src=a4:c3:f0:12:34:56  dst=ff:ff:ff:ff:ff:ff  type=0x0800
  [IPv4]  192.168.1.5 → 8.8.8.8  proto=UDP  ttl=64  len=72
  [UDP]   sport=52341  dport=53 (DNS)  len=52
  [DNS]   QUERY  qname=www.google.com

══ Capture Summary ══
  Duration   : 59.8s
  Total pkts : 1101
  TCP        : 257  (23.3%)
  UDP        : 844  (76.7%)
  ICMP       : 0    (0.0%)
  ARP        : 0    (0.0%)
  Other      : 0    (0.0%)
```

---

## 🔧 Troubleshooting

| Problem                        | Fix                                                     |
| ------------------------------ | ------------------------------------------------------- |
| `WARNING: No libpcap provider` | Install [Npcap](https://npcap.com) for full capture     |
| `Permission denied`            | Run as Administrator (Windows) or with `sudo` (Linux)   |
| `0 packets captured`           | Specify interface: `python network_sniffer.py -i Wi-Fi` |
| BPF filter ignored             | Requires Npcap on Windows                               |
| `scapy not found`              | Run `pip install scapy`                                 |

---

## 🏗️ Project Structure

```
CodeAlpha_Basic_network_Sniffer/
│
├── network_sniffer.py   # Main sniffer script
└── README.md            # This file
```

---

## 📚 Libraries Used

- **[Scapy](https://scapy.net/)** — Packet capture and dissection
- **[socket](https://docs.python.org/3/library/socket.html)** — Raw socket fallback (built-in)
- **[colorama](https://pypi.org/project/colorama/)** — Coloured terminal output
- **[argparse](https://docs.python.org/3/library/argparse.html)** — CLI argument parsing (built-in)

---

## 🎓 About

Built as part of the **CodeAlpha Cybersecurity Internship — Task 1**.

> CodeAlpha is a leading software development company dedicated to building secure and resilient systems.

---

## 📄 License

This project is for educational purposes as part of the CodeAlpha internship program.
