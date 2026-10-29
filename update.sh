#!/usr/bin/env bash
# ==============================================================================
# Digital Footprint Scanner - 1-Click Update Script
# Repository: https://github.com/Schello805/Digital-Footprint-Scanner.git
# ==============================================================================

set -e

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "=========================================================================="
echo "      🔄 Digital Footprint Scanner - 1-Click Update Manager"
echo "=========================================================================="
echo -e "${NC}"

SERVICE_NAME="digital-footprint-scanner"

# Find installation directory
INSTALL_DIR=""
if [ -d "./.git" ] && [ -f "./run.py" ]; then
    INSTALL_DIR="$(pwd)"
elif [ -d "/opt/digital-footprint-scanner/.git" ]; then
    INSTALL_DIR="/opt/digital-footprint-scanner"
elif [ -d "$HOME/digital-footprint-scanner/.git" ]; then
    INSTALL_DIR="$HOME/digital-footprint-scanner"
fi

if [ -z "$INSTALL_DIR" ]; then
    echo -e "${RED}❌ Kein gültiges Digital-Footprint-Scanner-Verzeichnis gefunden!${NC}"
    echo "Bitte wechsle in das Projektverzeichnis oder installiere es via install.sh."
    exit 1
fi

echo -e "${CYAN}➜ Gefundenes Installationsverzeichnis:${NC} $INSTALL_DIR"
cd "$INSTALL_DIR"

SUDO_CMD=""
if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    # Test if write permission exists in directory
    if [ ! -w "$INSTALL_DIR" ]; then
        SUDO_CMD="sudo"
    fi
fi

# 1. Fetch Remote State
echo -e "\n${CYAN}➜ 1. Prüfe auf neue Versionen auf GitHub (origin/main)...${NC}"
$SUDO_CMD git fetch origin main -q

LOCAL_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
REMOTE_HASH=$(git rev-parse --short origin/main 2>/dev/null || echo "unknown")
OLD_REV=$(git rev-list --count HEAD 2>/dev/null || cat VERSION 2>/dev/null || echo "?")

echo -e "   Lokale Version:  ${BOLD}Rev. ${OLD_REV} (${LOCAL_HASH})${NC}"
echo -e "   Neueste Version: ${BOLD}(${REMOTE_HASH})${NC}"

if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
    echo -e "\n${GREEN}✓ Das System ist bereits auf dem neuesten Stand! Keine Aktualisierung erforderlich.${NC}"
    exit 0
fi

# 2. Pull Updates
echo -e "\n${CYAN}➜ 2. Aktualisiere Quellcode auf neuesten Commit...${NC}"
$SUDO_CMD git reset --hard origin/main -q

NEW_REV=$(git rev-list --count HEAD 2>/dev/null || cat VERSION 2>/dev/null || echo "?")
NEW_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "main")
COMMIT_MSG=$(git log -1 --pretty=%B | head -n 1)

echo -e "${GREEN}✓ Quellcode aktualisiert auf Rev. ${NEW_REV} (${NEW_HASH}): \"${COMMIT_MSG}\"${NC}"

# 3. Update Dependencies
echo -e "\n${CYAN}➜ 3. Aktualisiere Python-Abhängigkeiten...${NC}"
if [ -d "venv" ]; then
    $SUDO_CMD ./venv/bin/pip install --upgrade pip -q
    $SUDO_CMD ./venv/bin/pip install -r requirements.txt -q
    echo -e "${GREEN}✓ Abhängigkeiten erfolgreich geprüft und aktualisiert.${NC}"
else
    echo -e "${YELLOW}⚠️ Kein venv gefunden. Überspringe Pip-Update.${NC}"
fi

# 4. Restart Service
echo -e "\n${CYAN}➜ 4. Starte Dienst neu...${NC}"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    $SUDO_CMD systemctl restart "$SERVICE_NAME"
    echo -e "${GREEN}✓ Systemd-Dienst '${SERVICE_NAME}' erfolgreich neu gestartet.${NC}"
elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "$SERVICE_NAME"; then
    $SUDO_CMD systemctl restart "$SERVICE_NAME"
    echo -e "${GREEN}✓ Systemd-Dienst '${SERVICE_NAME}' gestartet.${NC}"
else
    # Check if a python run.py process is running and restart it
    PID=$(pgrep -f "python.*run.py" || true)
    if [ -n "$PID" ]; then
        echo -e "   Stoppe vorherigen Prozess (PID: $PID)..."
        kill -9 $PID 2>/dev/null || true
        sleep 1
    fi
    if [ -d "venv" ]; then
        nohup ./venv/bin/python run.py > app.log 2>&1 &
        echo -e "${GREEN}✓ Server im Hintergrund neu gestartet (PID: $!).${NC}"
    fi
fi

echo -e "\n${GREEN}${BOLD}=========================================================================="
echo "🎉 Update erfolgreich abgeschlossen!"
echo "=========================================================================="
echo -e "${NC}"
echo -e "  • ${BOLD}Aktualisiert von:${NC}   Rev. ${OLD_REV} (${LOCAL_HASH})"
echo -e "  • ${BOLD}Jetzt aktiv:${NC}        ${GREEN}${BOLD}Rev. ${NEW_REV} (${NEW_HASH})${NC}"
echo -e "  • ${BOLD}Letzte Änderung:${NC}    ${COMMIT_MSG}"
echo -e "${GREEN}==========================================================================${NC}\n"
