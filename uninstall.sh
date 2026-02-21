#!/usr/bin/env bash
# BEATRIX CLI — Uninstaller
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}Uninstalling Beatrix CLI...${RESET}"
echo ""

# pipx
if command -v pipx &>/dev/null; then
    pipx uninstall beatrix-cli 2>/dev/null && \
        echo -e "  ${GREEN}✓${RESET} Removed pipx install" || true
fi

# pip user
python3 -m pip uninstall -y beatrix-cli 2>/dev/null && \
    echo -e "  ${GREEN}✓${RESET} Removed pip user install" || true

# pip system
sudo python3 -m pip uninstall -y beatrix-cli 2>/dev/null && \
    echo -e "  ${GREEN}✓${RESET} Removed pip system install" || true

# Config (ask first — before removing the venv directory)
if [[ -f "$HOME/.beatrix/config.yaml" ]]; then
    echo ""
    read -rp "  Remove config (~/.beatrix/config.yaml)? [y/N] " answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        # Preserve config — move it temporarily
        _beatrix_cfg_backup=$(mktemp)
        cp "$HOME/.beatrix/config.yaml" "$_beatrix_cfg_backup"
    fi
fi

# venv + symlink
if [[ -d "$HOME/.beatrix" ]]; then
    rm -rf "$HOME/.beatrix"
    echo -e "  ${GREEN}✓${RESET} Removed ~/.beatrix venv"
fi

# Restore config if user chose to keep it
if [[ -n "${_beatrix_cfg_backup:-}" ]]; then
    mkdir -p "$HOME/.beatrix"
    mv "$_beatrix_cfg_backup" "$HOME/.beatrix/config.yaml"
    echo -e "  ${GREEN}✓${RESET} Config preserved"
fi

if [[ -L "/usr/local/bin/beatrix" ]]; then
    sudo rm -f /usr/local/bin/beatrix
    echo -e "  ${GREEN}✓${RESET} Removed /usr/local/bin/beatrix symlink"
fi

echo ""
echo -e "${GREEN}${BOLD}Beatrix CLI has been uninstalled.${RESET}"
echo -e "${DIM}\"You and I have unfinished business.\"${RESET}"
echo ""
