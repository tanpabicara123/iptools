
#!/bin/bash

# Warna
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}===========================================${NC}"
echo -e "${CYAN}   IP TOOLS - AUTOMATIC INSTALLER SETUP    ${NC}"
echo -e "${CYAN}===========================================${NC}"

# Cek apakah di Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${YELLOW}[!] Peringatan: Script ini dioptimalkan untuk Termux.${NC}"
fi

# 1. Update & Upgrade
echo -e "${GREEN}[1/3] Memperbarui sistem...${NC}"
pkg update && pkg upgrade -y

# 2. Instalasi Tools Sistem
echo -e "${GREEN}[2/3] Menginstal tools sistem (traceroute, whois, git)...${NC}"
pkg install python traceroute whois git -y

# 3. Instalasi Library Python
echo -e "${GREEN}[3/3] Menginstal modul Python (Rich, DNSPython, Speedtest)...${NC}"
pip install --upgrade pip
pip install rich dnspython speedtest-cli requests

# Verifikasi akhir
echo -e "\n${CYAN}--- Verifikasi Instalasi ---${NC}"
command -v traceroute >/dev/null 2>&1 && echo -e "${GREEN}✔ Traceroute terpasang.${NC}" || echo -e "${RED}✘ Traceroute gagal.${NC}"
python -c "import rich; import dns; import speedtest; print('✔ Library Python siap!')" >/dev/null 2>&1 \
    && echo -e "${GREEN}✔ Library Python (Rich, DNS, Speedtest) siap!${NC}" \
    || echo -e "${RED}✘ Terjadi kesalahan pada library Python.${NC}"

echo -e "\n${GREEN}Semua persiapan selesai!${NC}"
echo -e "Jalankan dengan: ${YELLOW}python main.py${NC}"
echo -e "${CYAN}===========================================${NC}"

