#!/usr/bin/env bash
# ==============================================================================
# Digital Footprint Scanner - Automated Linux 1-Click Installer
# Repository: https://github.com/Schello805/Digital-Footprint-Scanner.git
# ==============================================================================

set -e

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "=========================================================================="
echo "      🚀 Digital Footprint Scanner - All-in-One OSINT Suite"
echo "                 Automatisierte Linux-Installation"
echo "=========================================================================="
echo -e "${NC}"

REPO_URL="https://github.com/Schello805/Digital-Footprint-Scanner.git"
SERVICE_NAME="digital-footprint-scanner"

# Determine target installation directory
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/opt/digital-footprint-scanner"
    SUDO_CMD=""
else
    if command -v sudo >/dev/null 2>&1; then
        INSTALL_DIR="/opt/digital-footprint-scanner"
        SUDO_CMD="sudo"
    else
        INSTALL_DIR="$HOME/digital-footprint-scanner"
        SUDO_CMD=""
    fi
fi

echo -e "${CYAN}➜ Zielverzeichnis:${NC} $INSTALL_DIR"

# 1. Package Manager Detection & Dependency Installation
echo -e "\n${CYAN}➜ 1. Systempakete aktualisieren und Abhängigkeiten installieren...${NC}"

if command -v apt-get >/dev/null 2>&1; then
    echo -e "   Erkannt: Debian/Ubuntu (apt)"
    $SUDO_CMD apt-get update -y -q
    $SUDO_CMD apt-get install -y -q git python3 python3-pip python3-venv curl
elif command -v dnf >/dev/null 2>&1; then
    echo -e "   Erkannt: Fedora/RHEL/CentOS (dnf)"
    $SUDO_CMD dnf install -y -q git python3 python3-pip curl
elif command -v yum >/dev/null 2>&1; then
    echo -e "   Erkannt: CentOS/RHEL (yum)"
    $SUDO_CMD yum install -y -q git python3 python3-pip curl
elif command -v pacman >/dev/null 2>&1; then
    echo -e "   Erkannt: Arch Linux (pacman)"
    $SUDO_CMD pacman -Sy --noconfirm git python python-pip curl
elif command -v apk >/dev/null 2>&1; then
    echo -e "   Erkannt: Alpine Linux (apk)"
    $SUDO_CMD apk add --no-cache git python3 py3-pip curl bash
else
    echo -e "${YELLOW}⚠️ Kein bekannter Paketmanager gefunden. Bitte stelle sicher, dass git, python3, pip und venv vorhanden sind.${NC}"
fi

# 2. Clone or Update Repository
echo -e "\n${CYAN}➜ 2. Repository von GitHub beziehen...${NC}"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "   Vorhandenes Repository in $INSTALL_DIR gefunden. Aktualisiere..."
    cd "$INSTALL_DIR"
    $SUDO_CMD git fetch origin main
    $SUDO_CMD git reset --hard origin/main
else
    $SUDO_CMD mkdir -p "$INSTALL_DIR"
    $SUDO_CMD git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Fix ownership if running as root or with sudo
if [ -n "$SUDO_USER" ]; then
    $SUDO_CMD chown -R "$SUDO_USER:$SUDO_USER" "$INSTALL_DIR"
fi

# 3. Setup Python Virtual Environment
echo -e "\n${CYAN}➜ 3. Python Virtualenv und Pakete einrichten...${NC}"
cd "$INSTALL_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv || $SUDO_CMD python3 -m venv venv
fi

# Ensure pip & install dependencies
./venv/bin/pip install --upgrade pip -q
./venv/bin/pip install -r requirements.txt -q

# 4. Create Systemd Service for Auto-Start (if systemctl is available)
if command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
    echo -e "\n${CYAN}➜ 4. Systemd-Dienst einrichten & aktivieren...${NC}"
    
    RUN_USER="${SUDO_USER:-root}"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    $SUDO_CMD bash -c "cat <<EOF > $SERVICE_FILE
[Unit]
Description=Digital Footprint Scanner (OSINT Suite)
After=network.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python run.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
Environment=HOST=0.0.0.0
Environment=PORT=8000
EnvironmentFile=-$INSTALL_DIR/.env

[Install]
WantedBy=multi-user.target
EOF"

    $SUDO_CMD systemctl daemon-reload
    $SUDO_CMD systemctl enable "$SERVICE_NAME"
    $SUDO_CMD systemctl restart "$SERVICE_NAME"
    
    echo -e "${GREEN}✓ Systemd-Dienst '${SERVICE_NAME}' gestartet und für Autostart registriert.${NC}"

    # Check and allow UFW firewall if active
    if command -v ufw >/dev/null 2>&1; then
        if $SUDO_CMD ufw status | grep -q "Status: active"; then
            $SUDO_CMD ufw allow 8000/tcp comment 'Digital Footprint Scanner' >/dev/null 2>&1 || true
            echo -e "${GREEN}✓ Firewall-Port 8000/tcp in UFW freigeschaltet.${NC}"
        fi
    fi
else
    echo -e "\n${YELLOW}⚠️ Kein systemd erkannt. Starte Server im Hintergrund...${NC}"
    nohup ./venv/bin/python run.py > app.log 2>&1 &
    echo -e "${GREEN}✓ Server im Hintergrund gestartet (PID: $!).${NC}"
fi

# 5. Determine Server IP for Easy Access
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="localhost"
fi

# Fetch current revision
CURRENT_REV=$(git rev-list --count HEAD 2>/dev/null || cat VERSION 2>/dev/null || echo "19")
COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "main")

echo -e "\n${GREEN}${BOLD}=========================================================================="
echo "🎉 Installation erfolgreich abgeschlossen!"
echo "=========================================================================="
echo -e "${NC}"
echo -e "  • ${BOLD}Installierte Version:${NC} Rev. ${CURRENT_REV} (${COMMIT_HASH})"
echo -e "  • ${BOLD}Web-Interface:${NC}       ${CYAN}http://${SERVER_IP}:8000${NC} oder ${CYAN}http://localhost:8000${NC}"
echo -e "  • ${BOLD}Verzeichnis:${NC}         $INSTALL_DIR"
if command -v systemctl >/dev/null 2>&1; then
    echo -e "  • ${BOLD}Status prüfen:${NC}       systemctl status ${SERVICE_NAME}"
    echo -e "  • ${BOLD}Logs ansehen:${NC}        journalctl -u ${SERVICE_NAME} -f"
    echo -e "  • ${BOLD}Neustart:${NC}            systemctl restart ${SERVICE_NAME}"
fi
echo -e "  • ${BOLD}Update-Befehl:${NC}       curl -sSL https://raw.githubusercontent.com/Schello805/Digital-Footprint-Scanner/main/update.sh | bash"
echo -e "${GREEN}==========================================================================${NC}\n"
