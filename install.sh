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

# ── Package Manager Detection ────────────────────────────────

detect_pkg_manager() {
    if command_exists apt-get; then
        PKG_MGR="apt"
    elif command_exists dnf; then
        PKG_MGR="dnf"
    elif command_exists pacman; then
        PKG_MGR="pacman"
    elif command_exists apk; then
        PKG_MGR="apk"
    else
        PKG_MGR="unknown"
    fi
}

pkg_install() {
    local pkg="$1"
    case "$PKG_MGR" in
        apt)    sudo apt-get install -y -qq "$pkg" 2>/dev/null ;;
        dnf)    sudo dnf install -y -q "$pkg" 2>/dev/null ;;
        pacman) sudo pacman -S --noconfirm --needed "$pkg" 2>/dev/null ;;
        apk)    sudo apk add --quiet "$pkg" 2>/dev/null ;;
        *)      return 1 ;;
    esac
}

# ── Go Toolchain ─────────────────────────────────────────────

ensure_go() {
    if command_exists go; then
        success "Go already installed ($(go version | grep -oP 'go\d+\.\d+\.\d+'))"
        return 0
    fi

    info "Installing Go toolchain..."
    local GO_VERSION="1.22.5"
    local ARCH
    ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
    local GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"

    curl -sSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}" || { warn "Failed to download Go"; return 1; }
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}" || { warn "Failed to extract Go"; return 1; }
    rm -f "/tmp/${GO_TAR}"

    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    _add_to_path "/usr/local/go/bin"
    _add_to_path "$HOME/go/bin"

    if command_exists go; then
        success "Go installed ($(go version | grep -oP 'go\d+\.\d+\.\d+'))"
        return 0
    else
        warn "Go installation failed"
        return 1
    fi
}

go_install_tool() {
    local name="$1"
    local pkg="$2"
    if command_exists "$name"; then
        success "$name (already installed)"
        return 0
    fi
    info "Installing $name..."
    go install -v "$pkg" &>/dev/null && success "$name" || { warn "Failed to install $name"; return 1; }
}

# ── Node.js / npm ────────────────────────────────────────────

ensure_node() {
    if command_exists node && command_exists npm; then
        return 0
    fi
    info "Installing Node.js..."
    case "$PKG_MGR" in
        apt)
            curl -fsSL https://deb.nodesource.com/setup_20.x 2>/dev/null | sudo -E bash - &>/dev/null
            sudo apt-get install -y -qq nodejs 2>/dev/null
            ;;
        dnf)    sudo dnf install -y -q nodejs npm 2>/dev/null ;;
        pacman) sudo pacman -S --noconfirm --needed nodejs npm 2>/dev/null ;;
        *)      warn "Cannot auto-install Node.js on this system"; return 1 ;;
    esac
    command_exists node && success "Node.js installed" || { warn "Node.js install failed"; return 1; }
}

# ── External Tools Installer ─────────────────────────────────

install_external_tools() {
    # Temporarily disable exit-on-error (tool installs may fail gracefully)
    set +e

    echo ""
    echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}${BOLD}║       ⚔️  ARMING THE ARSENAL  ⚔️         ║${RESET}"
    echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════╝${RESET}"
    echo ""

    local installed=0
    local failed=0
    local skipped=0
    local total=21

    detect_pkg_manager
    info "Detected package manager: ${BOLD}${PKG_MGR}${RESET}"

    # ── 1. System packages (apt/dnf/pacman) ──────────────
    echo ""
    echo -e "${BOLD}[1/6] System packages...${RESET}"

    if [[ "$PKG_MGR" == "apt" ]]; then
        sudo apt-get update -qq 2>/dev/null
    fi

    declare -A SYS_PKGS
    case "$PKG_MGR" in
        apt)
            SYS_PKGS=(
                [nmap]="nmap"
                [sqlmap]="sqlmap"
                [whatweb]="whatweb"
                [adb]="android-tools-adb"
            )
            ;;
        dnf)
            SYS_PKGS=(
                [nmap]="nmap"
                [sqlmap]="sqlmap"
                [whatweb]="whatweb"
                [adb]="android-tools"
            )
            ;;
        pacman)
            SYS_PKGS=(
                [nmap]="nmap"
                [sqlmap]="sqlmap"
                [whatweb]="whatweb"
                [adb]="android-tools"
            )
            ;;
        *)
            SYS_PKGS=()
            ;;
    esac

    for tool in nmap sqlmap whatweb adb; do
        if command_exists "$tool"; then
            success "$tool (already installed)"
            ((skipped++))
        elif [[ -n "${SYS_PKGS[$tool]+x}" ]]; then
            info "Installing $tool..."
            if pkg_install "${SYS_PKGS[$tool]}"; then
                success "$tool"
                ((installed++))
            else
                warn "Failed to install $tool"
                ((failed++))
            fi
        else
            warn "Cannot auto-install $tool on this system"
            ((failed++))
        fi
    done

    # ── 2. Go-based tools ────────────────────────────────
    echo ""
    echo -e "${BOLD}[2/6] Go-based security tools...${RESET}"

    if ensure_go; then
        export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
        export GOPATH="${GOPATH:-$HOME/go}"
        export GOBIN="$GOPATH/bin"
        mkdir -p "$GOBIN"

        declare -A GO_TOOLS=(
            [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
            [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            [ffuf]="github.com/ffuf/ffuf/v2@latest"
            [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
            [gospider]="github.com/jaeles-project/gospider@latest"
            [hakrawler]="github.com/hakluke/hakrawler@latest"
            [gau]="github.com/lc/gau/v2/cmd/gau@latest"
            [dalfox]="github.com/hahwul/dalfox/v2@latest"
            [amass]="github.com/owasp-amass/amass/v4/...@master"
        )

        for tool in nuclei httpx subfinder ffuf katana gospider hakrawler gau dalfox amass; do
            if command_exists "$tool"; then
                success "$tool (already installed)"
                ((skipped++))
            else
                if go_install_tool "$tool" "${GO_TOOLS[$tool]}"; then
                    ((installed++))
                else
                    ((failed++))
                fi
            fi
        done

        _add_to_path "$GOBIN"
    else
        warn "Skipping Go tools (Go not available)"
        ((failed+=10))
    fi

    # ── 3. Python tools ──────────────────────────────────
    echo ""
    echo -e "${BOLD}[3/6] Python security tools...${RESET}"

    for tool in mitmproxy commix; do
        if command_exists "$tool"; then
            success "$tool (already installed)"
            ((skipped++))
        else
            info "Installing $tool..."
            if $PYTHON -m pip install --user --break-system-packages "$tool" &>/dev/null || \
               $PYTHON -m pip install --user "$tool" &>/dev/null; then
                success "$tool"
                ((installed++))
            else
                warn "Failed to install $tool"
                ((failed++))
            fi
        fi
    done

    # jwt_tool
    if command_exists jwt_tool || command_exists jwt_tool.py; then
        success "jwt_tool (already installed)"
        ((skipped++))
    else
        info "Installing jwt_tool..."
        local JWT_DIR="$HOME/.local/share/jwt_tool"
        mkdir -p "$JWT_DIR"
        if curl -sSL "https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py" -o "$JWT_DIR/jwt_tool.py" && \
           chmod +x "$JWT_DIR/jwt_tool.py" && \
           $PYTHON -m pip install --user --break-system-packages termcolor cprint pycryptodomex requests &>/dev/null; then
            mkdir -p "$HOME/.local/bin"
            cat > "$HOME/.local/bin/jwt_tool" <<WRAPPER
#!/usr/bin/env bash
exec $PYTHON "$JWT_DIR/jwt_tool.py" "\$@"
WRAPPER
            chmod +x "$HOME/.local/bin/jwt_tool"
            success "jwt_tool"
            ((installed++))
        else
            warn "Failed to install jwt_tool"
            ((failed++))
        fi
    fi

    # dirsearch
    if command_exists dirsearch; then
        success "dirsearch (already installed)"
        ((skipped++))
    else
        info "Installing dirsearch..."
        if $PYTHON -m pip install --user --break-system-packages dirsearch &>/dev/null || \
           $PYTHON -m pip install --user dirsearch &>/dev/null; then
            success "dirsearch"
            ((installed++))
        else
            warn "Failed to install dirsearch"
            ((failed++))
        fi
    fi

    # ── 4. Playwright (browser automation) ───────────────
    echo ""
    echo -e "${BOLD}[4/6] Playwright (browser automation)...${RESET}"

    if command_exists playwright; then
        success "playwright (already installed)"
        ((skipped++))
    else
        info "Installing playwright..."
        if $PYTHON -m pip install --user --break-system-packages playwright &>/dev/null || \
           $PYTHON -m pip install --user playwright &>/dev/null; then
            info "Installing Chromium browser for playwright..."
            $PYTHON -m playwright install chromium --with-deps &>/dev/null && \
                success "playwright + Chromium" || \
                { success "playwright (run 'playwright install chromium' for browser)"; }
            ((installed++))
        else
            warn "Failed to install playwright"
            ((failed++))
        fi
    fi

    # ── 5. Node.js tools ─────────────────────────────────
    echo ""
    echo -e "${BOLD}[5/6] Node.js tools...${RESET}"

    if command_exists wappalyzer; then
        success "wappalyzer (already installed)"
        ((skipped++))
    else
        if ensure_node; then
            info "Installing wappalyzer..."
            if sudo npm install -g wappalyzer &>/dev/null || npm install -g wappalyzer &>/dev/null; then
                success "wappalyzer"
                ((installed++))
            else
                warn "Failed to install wappalyzer"
                ((failed++))
            fi
        else
            warn "Skipping wappalyzer (Node.js not available)"
            ((failed++))
        fi
    fi

    # ── 6. Metasploit Framework ──────────────────────────
    echo ""
    echo -e "${BOLD}[6/6] Metasploit Framework...${RESET}"

    if command_exists msfconsole; then
        success "metasploit (already installed)"
        ((skipped++))
    else
        info "Installing Metasploit Framework (this may take a few minutes)..."
        if curl -sSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall 2>/dev/null && \
           chmod +x /tmp/msfinstall && \
           sudo /tmp/msfinstall &>/dev/null; then
            rm -f /tmp/msfinstall
            success "metasploit"
            ((installed++))
        else
            rm -f /tmp/msfinstall
            warn "Failed to install metasploit (try manually: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod +x msfinstall && sudo ./msfinstall)"
            ((failed++))
        fi
    fi

    # ── Summary ──────────────────────────────────────────
    echo ""
    echo -e "${BOLD}Arsenal Summary:${RESET}"
    echo -e "  ${GREEN}✓ Installed:${RESET}  $installed"
    echo -e "  ${CYAN}○ Skipped:${RESET}   $skipped (already present)"
    if [[ $failed -gt 0 ]]; then
        echo -e "  ${RED}✗ Failed:${RESET}    $failed"
    fi

    local ready=$((installed + skipped))
    echo ""
    echo -e "  ${BOLD}${ready}/${total} tools armed.${RESET}"

    if [[ $failed -gt 0 ]]; then
        echo ""
        echo -e "  ${DIM}Run ${BOLD}beatrix setup${DIM} anytime to retry failed installations.${RESET}"
    fi

    # Re-enable strict mode
    set -euo pipefail
}

# ── Optional Tools (check only) ──────────────────────────────

check_optional_tools() {
    echo ""
    echo -e "${BOLD}External tools status:${RESET}"

    local tools=("nuclei" "httpx" "subfinder" "ffuf" "katana" "sqlmap" "nmap" "adb" "mitmproxy" "playwright" "amass" "whatweb" "wappalyzer" "gospider" "hakrawler" "gau" "dirsearch" "dalfox" "commix" "jwt_tool" "msfconsole")
    local found=0
    local total=${#tools[@]}

    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            success "$tool"
            found=$((found + 1))
        else
            echo -e "  ${DIM}○ $tool (not installed)${RESET}"
        fi
    done

    echo ""
    echo -e "  ${found}/${total} tools available."
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
    echo -e "${BOLD}Installing external tools (the full arsenal)...${RESET}"
    install_external_tools

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
