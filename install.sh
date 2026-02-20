#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  BEATRIX CLI — The Black Mamba
#  One-command installer for Linux systems
#
#  Usage:
#    git clone https://github.com/SudoPacman-Syuu/Beatrix.git && cd Beatrix && ./install.sh
#
#  Or:
#    curl -sSL https://raw.githubusercontent.com/SudoPacman-Syuu/Beatrix/main/install.sh | bash
#
#  "Those of you lucky enough to have your lives, take them with you."
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

MIN_PYTHON="3.11"
INSTALL_DIR="${BEATRIX_INSTALL_DIR:-/usr/local/bin}"

# ── Banner ───────────────────────────────────────────────────

banner() {
    echo -e "${YELLOW}"
    cat <<'EOF'
    ____             __       _     
   / __ )___  ____ _/ /______(_)  __
  / __  / _ \/ __ `/ __/ ___/ / |/_/
 / /_/ /  __/ /_/ / /_/ /  / />  <  
/_____/\___/\__,_/\__/_/  /_/_/|_|  
EOF
    echo -e "${RESET}"
    echo -e "${DIM}The Black Mamba — Installer${RESET}"
    echo ""
}

# ── Helpers ──────────────────────────────────────────────────

info()    { echo -e "  ${CYAN}▸${RESET} $1"; }
success() { echo -e "  ${GREEN}✓${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; exit 1; }

command_exists() { command -v "$1" &>/dev/null; }

version_gte() {
    # Returns 0 if $1 >= $2 (semver-ish comparison)
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# ── Checks ───────────────────────────────────────────────────

check_python() {
    local py=""

    for candidate in python3.13 python3.12 python3.11 python3; do
        if command_exists "$candidate"; then
            local ver
            ver="$($candidate --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)"
            if version_gte "$ver" "$MIN_PYTHON"; then
                py="$candidate"
                break
            fi
        fi
    done

    if [[ -z "$py" ]]; then
        fail "Python >= $MIN_PYTHON is required. Install it first:
         ${DIM}sudo apt install python3.11  # Debian/Ubuntu
         sudo dnf install python3.11  # Fedora
         sudo pacman -S python        # Arch${RESET}"
    fi

    PYTHON="$py"
    PYTHON_VERSION="$($PYTHON --version 2>&1)"
    success "Found $PYTHON_VERSION"
}

check_pip() {
    if ! $PYTHON -m pip --version &>/dev/null; then
        warn "pip not found. Installing..."
        $PYTHON -m ensurepip --upgrade 2>/dev/null || \
            fail "Cannot install pip. Run: ${DIM}sudo apt install python3-pip${RESET}"
    fi
    success "pip available"
}

# ── Install Methods ──────────────────────────────────────────

install_with_pipx() {
    info "Installing with pipx (isolated environment)..."

    if ! command_exists pipx; then
        info "Installing pipx first..."
        $PYTHON -m pip install --user pipx 2>/dev/null || \
            sudo $PYTHON -m pip install pipx 2>/dev/null || \
            { warn "Could not install pipx, falling back to pip"; return 1; }
        $PYTHON -m pipx ensurepath 2>/dev/null || true
    fi

    pipx install --force . || return 1
    success "Installed via pipx"
    return 0
}

install_with_pip_user() {
    info "Installing with pip (user-level)..."
    $PYTHON -m pip install --user --break-system-packages . 2>/dev/null || \
        $PYTHON -m pip install --user . 2>/dev/null || \
        { warn "User install failed, trying system-level..."; return 1; }

    # Ensure ~/.local/bin is on PATH
    local user_bin="$HOME/.local/bin"
    if [[ ":$PATH:" != *":$user_bin:"* ]]; then
        warn "$user_bin is not on your PATH"
        _add_to_path "$user_bin"
    fi

    success "Installed via pip (user)"
    return 0
}

install_with_pip_system() {
    info "Installing system-wide (requires sudo)..."
    sudo $PYTHON -m pip install --break-system-packages . 2>/dev/null || \
        sudo $PYTHON -m pip install . || \
        fail "System install failed. Try: pipx install ."

    success "Installed system-wide"
    return 0
}

install_with_venv() {
    info "Installing with dedicated venv + symlink..."

    local venv_dir="$HOME/.beatrix"
    $PYTHON -m venv "$venv_dir"
    "$venv_dir/bin/pip" install --upgrade pip
    "$venv_dir/bin/pip" install .

    # Symlink to a dir on PATH
    local link_target="$INSTALL_DIR/beatrix"
    if [[ -w "$INSTALL_DIR" ]]; then
        ln -sf "$venv_dir/bin/beatrix" "$link_target"
    else
        sudo ln -sf "$venv_dir/bin/beatrix" "$link_target"
    fi

    success "Installed to $venv_dir with symlink at $link_target"
    return 0
}

# ── PATH helper ──────────────────────────────────────────────

_add_to_path() {
    local dir="$1"
    local shell_rc=""

    if [[ -f "$HOME/.zshrc" ]]; then
        shell_rc="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        shell_rc="$HOME/.bashrc"
    elif [[ -f "$HOME/.profile" ]]; then
        shell_rc="$HOME/.profile"
    fi

    if [[ -n "$shell_rc" ]]; then
        if ! grep -q "$dir" "$shell_rc" 2>/dev/null; then
            echo "" >> "$shell_rc"
            echo "# Beatrix CLI" >> "$shell_rc"
            echo "export PATH=\"$dir:\$PATH\"" >> "$shell_rc"
            info "Added $dir to PATH in $shell_rc"
            info "Run: ${BOLD}source $shell_rc${RESET} or restart your terminal"
        fi
    fi
}

# ── Optional Tools ───────────────────────────────────────────

check_optional_tools() {
    echo ""
    echo -e "${BOLD}Optional tools (not required, but unlock more features):${RESET}"

    local tools=("nuclei" "httpx" "subfinder" "ffuf" "katana" "sqlmap" "nmap" "adb" "mitmproxy" "playwright" "amass" "whatweb" "wappalyzer" "gospider" "hakrawler" "gau" "dirsearch" "dalfox" "commix" "jwt_tool" "msfconsole")
    local missing=()

    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            success "$tool"
        else
            echo -e "  ${DIM}○ $tool (not installed)${RESET}"
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${DIM}Install missing tools:${RESET}"
        echo -e "  ${DIM}  Go-based: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${RESET}"
        echo -e "  ${DIM}  Or:       sudo apt install nmap sqlmap adb mitmproxy amass dalfox commix${RESET}"
        echo -e "  ${DIM}  Python:   pip install dirsearch jwt_tool${RESET}"
        echo -e "  ${DIM}  Node:     npm install -g wappalyzer playwright${RESET}"
    fi
}

# ── Main ─────────────────────────────────────────────────────

main() {
    banner

    # If we're being piped from curl, clone the repo first
    if [[ ! -f "pyproject.toml" ]]; then
        info "Cloning Beatrix CLI..."
        if command_exists git; then
            git clone https://github.com/SudoPacman-Syuu/Beatrix.git /tmp/beatrix_cli_install
            cd /tmp/beatrix_cli_install
        else
            fail "git is required. Install it: ${DIM}sudo apt install git${RESET}"
        fi
    fi

    echo -e "${BOLD}Checking requirements...${RESET}"
    check_python
    check_pip

    echo ""
    echo -e "${BOLD}Installing Beatrix CLI...${RESET}"

    # Try install methods in order of preference
    install_with_pipx || \
    install_with_pip_user || \
    install_with_pip_system || \
    install_with_venv

    # Verify installation
    echo ""
    echo -e "${BOLD}Verifying...${RESET}"

    # Need to refresh PATH for current session
    export PATH="$HOME/.local/bin:$PATH"

    if command_exists beatrix; then
        local installed_ver
        installed_ver="$(beatrix --version 2>&1)"
        success "beatrix is on your PATH"
        success "$installed_ver"
    else
        warn "beatrix was installed but is not on your PATH yet"
        info "Try: ${BOLD}source ~/.bashrc${RESET} or restart your terminal"
    fi

    check_optional_tools

    echo ""
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}Quick start:${RESET}"
    echo -e "    ${CYAN}beatrix${RESET}                          Show commands"
    echo -e "    ${CYAN}beatrix hunt example.com${RESET}         Scan a target"
    echo -e "    ${CYAN}beatrix help hunt${RESET}                Detailed help"
    echo -e "    ${CYAN}beatrix arsenal${RESET}                  View all modules"
    echo ""
    echo -e "  ${DIM}\"Revenge is a dish best served with a working PoC.\"${RESET}"
    echo ""

    # Cleanup if we cloned to /tmp
    if [[ "$(pwd)" == /tmp/beatrix_cli_install* ]]; then
        cd ~
        rm -rf /tmp/beatrix_cli_install
    fi
}

main "$@"
