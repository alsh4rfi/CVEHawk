#!/usr/bin/env bash

# CVEHawk System-Wide Installation Script
# Script made by Abdullah Al-Sharafi
# GitHub: @alsh4rfi | Instagram: @alsh4rfi | Twitter: @alsh4rfi
# This script installs CVEHawk to make it accessible from anywhere

set -e  # Exit on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║               CVEHawk System-Wide Installer v2.1                 ║"
echo "║                                                                   ║"
echo "║              Script made by Abdullah Al-Sharafi                  ║"
echo "║                                                                   ║"
echo "║         GitHub: @alsh4rfi | Instagram: @alsh4rfi                 ║"
echo "║                    Twitter: @alsh4rfi                            ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] This script needs sudo privileges to install system-wide${NC}"
    echo -e "${BLUE}[*] Re-running with sudo...${NC}"
    exec sudo "$0" "$@"
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CVEHAWK_SCRIPT="$SCRIPT_DIR/cvehawk.py"

if [ ! -f "$CVEHAWK_SCRIPT" ]; then
    echo -e "${RED}[ERROR] cvehawk.py not found in current directory!${NC}"
    echo -e "${YELLOW}[INFO] Please run this script from the CVEHawk directory${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Found cvehawk.py at: $CVEHAWK_SCRIPT${NC}"

echo -e "${BLUE}[*] Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python3 is not installed!${NC}"
    echo -e "${YELLOW}[INFO] Please install Python3 first${NC}"
    exit 1
fi

PYTHON_PATH=$(which python3)
echo -e "${GREEN}[✓] Python3 found at: $PYTHON_PATH${NC}"

INSTALL_DIR="/opt/cvehawk"
BIN_PATH="/usr/local/bin/cvehawk"

echo -e "${BLUE}[*] Creating installation directory...${NC}"
mkdir -p "$INSTALL_DIR"

echo -e "${BLUE}[*] Copying CVEHawk files...${NC}"
cp "$CVEHAWK_SCRIPT" "$INSTALL_DIR/"

if [ -f "$SCRIPT_DIR/cvehawk.yaml" ]; then
    cp "$SCRIPT_DIR/cvehawk.yaml" "$INSTALL_DIR/"
    echo -e "${GREEN}[✓] Configuration file copied${NC}"
fi

mkdir -p "$INSTALL_DIR/cvehawk_reports"
chmod 755 "$INSTALL_DIR/cvehawk_reports"

echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip3 install requests >/dev/null 2>&1 || true

echo -e "${BLUE}[*] Installing optional dependencies...${NC}"
OPTIONAL_PACKAGES="pyyaml"
for package in $OPTIONAL_PACKAGES; do
    pip3 install $package >/dev/null 2>&1 && echo -e "${GREEN}[✓] Installed $package${NC}" || echo -e "${YELLOW}[!] Could not install $package (optional)${NC}"
done

echo -e "${BLUE}[*] Creating wrapper script...${NC}"
cat > "$BIN_PATH" << 'EOF'
#!/usr/bin/env bash
# CVEHawk wrapper script
# Created by Abdullah Al-Sharafi (@alsh4rfi)

SCRIPT_PATH="/opt/cvehawk/cvehawk.py"

if [ $# -eq 0 ]; then
    python3 "$SCRIPT_PATH" -h
else
    python3 "$SCRIPT_PATH" "$@"
fi
EOF

chmod +x "$BIN_PATH"
chmod +x "$INSTALL_DIR/cvehawk.py"

CONFIG_DIR="/etc/cvehawk"
mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/cvehawk.yaml" ]; then
    cat > "$CONFIG_DIR/cvehawk.yaml" << 'EOF'
# CVEHawk System Configuration
# Created by Abdullah Al-Sharafi (@alsh4rfi)

api_keys:
  github: ""  # Add your GitHub token here for higher API limits

output:
  format: "detailed"
  colors: true

filters:
  min_severity: "none"

export:
  directory: "~/cvehawk_reports"
  default_formats: ["json", "html"]

search:
  max_poc_results: 10
  search_timeout: 30
  alternative_platforms: true
EOF
    echo -e "${GREEN}[✓] Created default configuration at $CONFIG_DIR/cvehawk.yaml${NC}"
fi

echo -e "${BLUE}[*] Creating man page...${NC}"
MAN_DIR="/usr/local/share/man/man1"
mkdir -p "$MAN_DIR"
cat > "$MAN_DIR/cvehawk.1" << 'EOF'
.TH CVEHAWK 1 "2024" "2.1" "CVEHawk Manual"
.SH NAME
cvehawk \- Advanced CVE Lookup Tool with Enhanced POC Search
.SH SYNOPSIS
.B cvehawk
[\fB\-c\fR \fICVE-ID\fR...]
[\fB\-f\fR \fIFILE\fR]
[\fB\-\-search\fR \fIKEYWORD\fR]
[\fB\-\-export\fR \fIFORMAT\fR]
.SH DESCRIPTION
CVEHawk is an advanced CVE lookup tool that searches for vulnerability information
and proof-of-concept exploits across multiple platforms including GitHub,
Exploit-DB, PacketStorm, and Rapid7.
.SH OPTIONS
.TP
\fB\-c\fR, \fB\-\-cve\fR \fICVE-ID\fR...
One or more CVE IDs to lookup
.TP
\fB\-f\fR, \fB\-\-file\fR \fIFILE\fR
File containing CVE IDs (one per line)
.TP
\fB\-\-search\fR \fIKEYWORD\fR
Search CVEs by keyword
.TP
\fB\-\-year\fR \fIYEAR\fR
Filter CVEs by year
.TP
\fB\-\-severity\fR \fISEVERITY\fR
Filter by severity (critical,high,medium,low)
.TP
\fB\-\-export\fR \fIFORMAT\fR
Export formats (json,html,csv)
.TP
\fB\-t\fR, \fB\-\-threads\fR \fINUM\fR
Number of threads for parallel processing (default: 5)
.SH EXAMPLES
cvehawk -c CVE-2021-44228
cvehawk --search "remote code execution" --year 2024 --limit 5
cvehawk -c CVE-2021-44228 --export json,html
.SH AUTHOR
Created by Abdullah Al-Sharafi (@alsh4rfi)
GitHub: https://github.com/alsh4rfi
Instagram: https://instagram.com/alsh4rfi
Twitter: https://twitter.com/alsh4rfi
.SH SEE ALSO
Project repository: https://github.com/alsh4rfi/cvehawk
EOF

gzip -f "$MAN_DIR/cvehawk.1"
echo -e "${GREEN}[✓] Man page created (use 'man cvehawk' to view)${NC}"

echo -e "${BLUE}[*] Creating uninstall script...${NC}"
cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/usr/bin/env bash
# CVEHawk Uninstaller
# Created by Abdullah Al-Sharafi (@alsh4rfi)

echo "Uninstalling CVEHawk..."
sudo rm -f /usr/local/bin/cvehawk
sudo rm -rf /opt/cvehawk
sudo rm -f /usr/local/share/man/man1/cvehawk.1.gz
sudo rm -rf /etc/cvehawk
echo "CVEHawk has been uninstalled."
echo "Thank you for using CVEHawk!"
echo "- Abdullah Al-Sharafi (@alsh4rfi)"
EOF
chmod +x "$INSTALL_DIR/uninstall.sh"

echo -e "${BLUE}[*] Verifying installation...${NC}"
if [ -f "$BIN_PATH" ] && [ -x "$BIN_PATH" ]; then
    echo -e "${GREEN}[✓] CVEHawk successfully installed!${NC}"
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    Installation Complete!                        ║${NC}"
    echo -e "${CYAN}║                                                                   ║${NC}"
    echo -e "${CYAN}║                Created by Abdullah Al-Sharafi                    ║${NC}"
    echo -e "${CYAN}║                                                                   ║${NC}"
    echo -e "${CYAN}║    ${MAGENTA}GitHub:${NC} ${CYAN}@alsh4rfi  ${MAGENTA}Instagram:${NC} ${CYAN}@alsh4rfi  ${MAGENTA}Twitter:${NC} ${CYAN}@alsh4rfi    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  cvehawk -c CVE-2021-44228"
    echo "  cvehawk --search \"remote code execution\" --year 2024"
    echo "  cvehawk --help"
    echo ""
    echo -e "${YELLOW}Configuration:${NC}"
    echo "  System config: /etc/cvehawk/cvehawk.yaml"
    echo "  Installation: /opt/cvehawk/"
    echo ""
    echo -e "${YELLOW}Uninstall:${NC}"
    echo "  sudo /opt/cvehawk/uninstall.sh"
    echo ""
    echo -e "${MAGENTA}Follow Abdullah Al-Sharafi for updates:${NC}"
    echo "  GitHub:    https://github.com/alsh4rfi"
    echo "  Instagram: https://instagram.com/alsh4rfi"
    echo "  Twitter:   https://twitter.com/alsh4rfi"
    echo ""

    echo -e "${BLUE}[*] Testing installation...${NC}"
    cvehawk --version 2>/dev/null && echo -e "${GREEN}[✓] CVEHawk is working correctly!${NC}" || echo -e "${YELLOW}[!] Test failed, but installation completed${NC}"
else
    echo -e "${RED}[ERROR] Installation failed!${NC}"
    exit 1
fi
