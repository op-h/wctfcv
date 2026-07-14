#!/bin/bash
# wctfsv installer for Kali Linux
# Created by oph

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ██╗    ██╗███████╗██████╗    ███████╗██╗  ██╗███████╗"
echo "  ██║    ██║██╔════╝██╔══██╗   ██╔════╝██║  ██║██╔════╝"
echo "  ██║ █╗ ██║█████╗  ██████╔╝   ███████╗███████║█████╗  "
echo "  ██║███╗██║██╔══╝  ██╔══██╗   ╚════██║██╔══██║██╔══╝  "
echo "  ╚███╔███╔╝███████╗██████╔╝██╗███████║██║  ██║███████╗"
echo "   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${GREEN}Web CTF Solver Installer${NC}"
echo -e "${CYAN}Created by op-h${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}[!] Do not run as root${NC}"
    exit 1
fi

# Check if Kali Linux
if ! grep -qi "kali" /etc/os-release 2>/dev/null; then
    echo -e "${RED}[!] This installer is designed for Kali Linux${NC}"
    echo -e "${RED}    Continuing anyway...${NC}"
fi

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Installing...${NC}"
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi

echo -e "${CYAN}[*] Setting up virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "${CYAN}[*] Installing dependencies...${NC}"
pip install -r requirements.txt -q

echo -e "${CYAN}[*] Setting up wctfsv command...${NC}"
chmod +x wctfsv

mkdir -p ~/.local/bin
ln -sf "$(pwd)/wctfsv" ~/.local/bin/wctfsv

if ! grep -q '.local/bin' ~/.zshrc 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
fi

export PATH="$HOME/.local/bin:$PATH"

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo -e "${CYAN}Run from anywhere:${NC}"
echo -e "  wctfsv --help"
echo -e "  wctfsv sqli -u \"http://target.com/page?id=1\""
echo -e "  wctfsv all -u \"http://target.com\""
echo ""
echo -e "${CYAN}If wctfsv is not found, run:${NC}"
echo -e "  source ~/.zshrc"
echo ""
