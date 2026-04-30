# 🔍 OSINT Profiler

> A comprehensive Open Source Intelligence (OSINT) investigation tool for gathering and analyzing publicly available information — featuring a sleek PyQt6 GUI, full CLI mode, and multi-format reporting.

## 📦 Download

| Option | For who | Link |
|---|---|---|
| 🐍 **Source** | Developers, CLI users | use .py file |
| 🪟 **Windows EXE** | Non-technical users, GUI-only | [Releases →](../../releases/latest) |

---

## ✨ Features

| Feature | Description |
|---|---|
| 📧 **Email Investigation** | Multi-platform registration check, 40+ targeted web queries, Holehe API integration |
| 📱 **Phone Investigation** | Carrier lookup, line type, country identification, spam database check, Truecaller API |
| 👤 **Username Investigation** | Forensic-grade variant generation, 11+ platform probing, Sherlock API integration |
| 🌐 **Web Intelligence** | DuckDuckGo-powered stealth search, proxy support, smart rate limiting |
| 📊 **Graph Visualization** | Interactive vis.js network graph, PNG/JPG export, multiple layout modes |
| 📄 **Report Generation** | Export to JSON, TXT, HTML, and PDF with full customization |
| 🎛️ **GUI + CLI** | Full PyQt6 desktop app (dark/light theme) and feature-complete CLI |
| 🔒 **Smart Filtering** | Confidence scoring, spam detection, anomaly detection, noise domain filtering |

---

## 📸 Screenshots

![GUI](gui.png)

---

## 🚀 Installation (Source)

```bash
pip install -r requirements.txt
```

### Optional integrations
These tools are not required, but significantly expand results when present in your PATH:

```bash
pip install holehe               # Email registration across 120+ sites
pip install sherlock-project     # Username search across 300+ platforms
pip install truecallerpy         # Caller ID and name lookup
```

---

## 🖥️ Usage

### GUI Mode

```bash
python osint_profiler.py
```

Launches the full desktop interface. Enter any combination of email, phone, and username to begin.
Double click on the .py/.exe file for GUI.
---

### CLI Mode

```bash
# Investigate an email
python osint_profiler.py --email target@example.com --format all

# Investigate a phone number
python osint_profiler.py --phone +1234567890 --country-code 91 --format pdf

# Investigate a username
python osint_profiler.py --username johndoe --format html

# Combine all inputs
python osint_profiler.py --email target@example.com --phone +1234567890 --username johndoe

# Deep scan with proxy
python osint_profiler.py --email target@example.com --deep --proxy http://user:pass@host:port
```

### All CLI flags

| Flag | Short | Description |
|---|---|---|
| `--email` | `-e` | Target email address |
| `--phone` | `-p` | Target phone number |
| `--username` | `-u` | Target username |
| `--country-code` | `-c` | Country code for phone (`91` India, `1` USA, `44` UK …) |
| `--format` | `-f` | Output format: `json` `txt` `html` `pdf` `all` |
| `--output` | `-o` | Output directory (default: `reports/`) |
| `--deep` | `-d` | Remove query limits — thorough but slower |
| `--proxy` | | Proxy URL for anonymized queries |
| `--truecaller-id` | | Truecaller installation ID |
| `--timezone` | `-t` | Report timezone (default: `UTC`) |
| `--verbose` | `-v` | Enable debug logging |
| `--gui` | `-g` | Force GUI launch |

---

## 🗺️ Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full breakdown of the system design.

---

## 📁 Output Structure

```
reports/
├── osint_target@email.com.json
├── osint_target@email.com.txt
├── osint_target@email.com.html
├── osint_target@email.com.pdf
└── graph_target_20260101_120000.html     ← interactive network graph
```

---

## ⚙️ Report Configuration (GUI)

The GUI includes a full report configuration dialog:

- **Timezone** — 15+ global timezones
- **Page Size** — A4 / Letter / Legal
- **Font** — any installed system font
- **Sections** — Executive Summary, Findings, Anomaly Detection, Statistics
- **Confidence Grouping** — auto-categorize high vs. low confidence results
- **Deep Scan Mode** — bypass query limits

---

## ⚠️ Disclaimer

This tool is intended **for educational and legitimate OSINT purposes only.**

- Only investigate targets you have **explicit authorization** to research
- Comply with all applicable local and international laws
- Respect the privacy rights and terms of service of all platforms
- The author is **not responsible** for any misuse of this tool

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

_Built for the OSINT & cybersecurity community. If this tool helped you, consider leaving a ⭐_
