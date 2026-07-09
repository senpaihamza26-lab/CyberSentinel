# ⚔ CyberSentinel — Network Vulnerability Scanner

A multi-threaded network vulnerability scanner built in Python. CyberSentinel scans a target host, identifies open ports, cross-references them against a built-in vulnerability advisory database, checks TLS/SSL configuration on secure ports, and generates professional HTML / JSON / CSV reports.

Built as a defensive security tool for authorized penetration testing, security audits, and infrastructure hardening.

---

## ✨ Features

- **Multi-threaded TCP port scanner** — scan hundreds of ports in seconds using a configurable thread pool
- **Vulnerability advisory engine** — 25+ well-known ports mapped to real-world risk context (e.g. exposed Redis/MongoDB, RDP ransomware vector, EternalBlue-class SMB risk)
- **Banner grabbing** — identifies running services via response banners
- **TLS/SSL auditing** — detects weak protocol versions (SSLv3/TLSv1/TLSv1.1) and reports negotiated cipher suites
- **Risk scoring** — aggregates findings into an overall Critical / High / Medium / Low rating
- **Multi-format reporting** — clean, presentation-ready HTML report (dark theme) plus JSON and CSV exports for integration into other tooling
- **Flexible port targeting** — scan common ports, custom ranges (`1-1024`), specific ports (`22,80,443`), or a full `1-65535` sweep

## 🖥 Sample Output

```
Scan Results for 192.168.1.10 (192.168.1.10)
┌──────┬──────────┬──────────┬─────────────────────────────────────┬──────────────┐
│ Port │ Service  │   Risk   │ Advisory                             │ Banner       │
├──────┼──────────┼──────────┼─────────────────────────────────────┼──────────────┤
│  22  │ SSH      │   Low    │ Ensure key-based auth, disable root  │ SSH-2.0-...  │
│  445 │ SMB      │ Critical │ Top ransomware entry vector...       │ -            │
│ 3389 │ RDP      │ Critical │ RDP exposed to internet is a top...  │ -            │
└──────┴──────────┴──────────┴─────────────────────────────────────┴──────────────┘
```

The HTML report includes summary cards by severity and a full findings table, styled for direct inclusion in client-facing security reports.

## 🚀 Installation

```bash
git clone https://github.com/senpaihamza26-lab/cybersentinel.git
cd cybersentinel
pip install -r requirements.txt
```

## 🔧 Usage

```bash
# Scan common/well-known ports
python3 cybersentinel.py 192.168.1.10

# Scan a specific port range
python3 cybersentinel.py 192.168.1.10 -p 1-1024

# Scan specific ports
python3 cybersentinel.py scanme.example.com -p 22,80,443,3389

# Full port sweep with more threads
python3 cybersentinel.py 192.168.1.10 -p all -t 300

# Choose report format (json / csv / html / all)
python3 cybersentinel.py 192.168.1.10 -o all
```

### CLI Options

| Flag | Description | Default |
|---|---|---|
| `target` | IP address or hostname to scan | required |
| `-p, --ports` | Ports: `22,80,443`, `1-1024`, or `all` | common ports |
| `-t, --threads` | Concurrent scan threads | 150 |
| `--timeout` | Per-port connection timeout (seconds) | 1.0 |
| `-o, --output` | Report format: json / csv / html / all | html |
| `--outdir` | Report output directory | `scan_reports/` |

## 🛠 Tech Stack

- Python 3 (standard library: `socket`, `ssl`, `concurrent.futures`)
- [Rich](https://github.com/Textualize/rich) for the terminal UI
- No external network dependencies — pure Python scanning engine

## 🗺 Roadmap

- [ ] Async scanning engine (`asyncio`) for even larger port ranges
- [ ] CVE database integration via NVD API
- [ ] OS fingerprinting (TTL/window-size heuristics)
- [ ] Scheduled scanning + diff reports between scans
- [ ] Slack/Discord webhook alerts on critical findings

## ⚖ Legal Disclaimer

This tool is intended **only** for scanning systems you own or have explicit written authorization to test. Unauthorized scanning of networks or hosts is illegal in most jurisdictions. The author assumes no liability for misuse.

## 👤 Author

**Hamza** — Cloud Security Engineering enthusiast | Python Developer
- GitHub: [@senpaihamza26-lab](https://github.com/senpaihamza26-lab)
- LinkedIn: Saiyed Hamja
- Instagram: [@otakuprogrammerr](https://instagram.com/otakuprogrammerr)

## 📄 License

MIT License — free to use, modify, and distribute.
