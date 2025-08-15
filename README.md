# 🦅 CVE Hawk — Advanced CVE Lookup for the Command Line

**CVE Hawk** is a **blazing-fast**, **multi-threaded** vulnerability intelligence tool designed for security researchers, pentesters, and sysadmins who want **all their CVE hunting power right in the terminal**.

It goes beyond basic CVE lookups by:

* 📡 **Live data** from NVD, GitHub, Exploit-DB, PacketStorm, Rapid7, and more
* 🔍 **Smart POC detection** with advanced ranking & quality analysis
* 📊 **EPSS integration** for exploit prediction scoring
* 💾 **Export in HTML, CSV, or JSON** — ready for reports or dashboards
* ⚡ **Multi-platform proof-of-concept search** with intelligent filtering
* 🎯 **Relevance scoring** so the best POCs are always on top

---

## ✨ Key Features

* **Multi-threaded search engine** for lightning-fast results
* **Advanced CVE parsing & normalization** (handles weird dash formats, typos, and variants)
* **Smart severity color coding** in terminal output
* **Automatic GitHub API optimization** to avoid rate limits
* **Comprehensive POC scoring** (stars, forks, activity, language, quality level)
* **Beautiful HTML reports** with stats, EPSS data, and ranked POCs
* **Fully configurable** via YAML (API keys, filters, output settings)

---

## 🚀 Installation
### Linux
```bash
# Clone the repository
git clone https://github.com/alsh4rfi/cvehawk.git
cd cvehawk
pip install -r requirements.txt

# Run the installer
chmod 777 cvehawk_setup.sh
sudo ./cvehawk_setup.sh

# Run the application
cvehawk -c CVE-1234-1234
```
### Windows
```bash
# Clone the repository
git clone https://github.com/alsh4rfi/cvehawk.git
cd cvehawk

# Run as Administrator
python3 cvehawk.py -c CVE-1234-1234
```
---

## 📦 Export Formats

* **HTML** — interactive, styled professional reports
* **CSV** — spreadsheet-ready vulnerability data
* **JSON** — for pipelines, dashboards, and automation

---

## 📜 License

MIT — use it, modify it, and spread the knowledge.

---

💡 *CVE Hawk is built for those who live in the terminal, thrive on speed, and demand actionable vulnerability intelligence without leaving their shell.*
