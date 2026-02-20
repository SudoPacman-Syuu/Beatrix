#!/usr/bin/env bash
# ============================================================================
# BEATRIX Remote Access — Tailscale VPN + xrdp (RDP)
# ============================================================================
#
# Gives you full real-time RDP access to your KDE Plasma desktop from iPhone,
# secured through a WireGuard-based VPN tunnel (Tailscale). No port forwarding
# needed - works through any NAT.
#
# iPhone setup:
#   1. Install "Tailscale" from App Store → sign in with same account
#   2. Install "Microsoft Remote Desktop" from App Store
#   3. Add PC → use your Tailscale IP (100.x.x.x) shown after setup
#
# Usage:
#   chmod +x setup.sh && sudo ./setup.sh
#
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ____             __       _         ____                       __     
   / __ )___  ____ _/ /______(_)  __   / __ \___  ____ ___  ____  / /____ 
  / __  / _ \/ __ `/ __/ ___/ / |/_/  / /_/ / _ \/ __ `__ \/ __ \/ __/ _ \
 / /_/ /  __/ /_/ / /_/ /  / />  <   / _, _/  __/ / / / / / /_/ / /_/  __/
/_____/\___/\__,_/\__/_/  /_/_/|_|  /_/ |_|\___/_/ /_/ /_/\____/\__/\___/ 
                                                                           
    VPN-Secured Remote Desktop Access
EOF
    echo -e "${NC}"
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

preflight() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (sudo ./setup.sh)"
        exit 1
    fi

    if ! command -v pacman &>/dev/null; then
        err "This script is for Arch-based systems (EndeavourOS). pacman not found."
        exit 1
    fi

    # Get the real user (not root)
    REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo usr)}"
    REAL_HOME=$(eval echo ~"$REAL_USER")
    
    log "Running as root, real user: $REAL_USER"
    log "Home directory: $REAL_HOME"
}

# ============================================================================
# STEP 1: INSTALL TAILSCALE
# ============================================================================

install_tailscale() {
    info "Step 1/4: Installing Tailscale VPN..."
    
    if command -v tailscale &>/dev/null; then
        log "Tailscale already installed: $(tailscale version 2>/dev/null | head -1)"
    else
        pacman -S --noconfirm tailscale 2>/dev/null || {
            # If not in official repos, install from AUR
            warn "Not in official repos, trying AUR..."
            sudo -u "$REAL_USER" yay -S --noconfirm tailscale-bin 2>/dev/null || {
                # Manual install as last resort
                info "Installing Tailscale via official script..."
                curl -fsSL https://tailscale.com/install.sh | sh
            }
        }
        log "Tailscale installed"
    fi
    
    # Enable and start tailscaled
    systemctl enable --now tailscaled
    log "tailscaled service running"
    
    # Check if already authenticated
    if tailscale status &>/dev/null 2>&1; then
        log "Tailscale already authenticated"
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
        if [[ -n "$TAILSCALE_IP" ]]; then
            log "Tailscale IP: $TAILSCALE_IP"
        fi
    else
        info "Tailscale needs authentication. Running 'tailscale up'..."
        echo ""
        echo -e "${BOLD}${YELLOW}>>> Open the URL below on any device to authenticate: ${NC}"
        echo ""
        tailscale up 2>&1 || true
        echo ""
        
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
        if [[ -n "$TAILSCALE_IP" ]]; then
            log "Authenticated! Tailscale IP: $TAILSCALE_IP"
        else
            warn "Could not get Tailscale IP. Run 'tailscale up' manually after setup."
        fi
    fi
}

# ============================================================================
# STEP 2: INSTALL XRDP
# ============================================================================

install_xrdp() {
    info "Step 2/4: Installing xrdp (RDP server)..."
    
    if command -v xrdp &>/dev/null; then
        log "xrdp already installed"
    else
        # xrdp is in AUR for Arch
        info "Installing xrdp from AUR (this may take a few minutes)..."
        sudo -u "$REAL_USER" yay -S --noconfirm xrdp xorgxrdp 2>/dev/null || {
            err "Failed to install xrdp from AUR. You may need to install manually:"
            err "  yay -S xrdp xorgxrdp"
            return 1
        }
        log "xrdp installed from AUR"
    fi
}

# ============================================================================
# STEP 3: CONFIGURE XRDP FOR KDE PLASMA + VPN-ONLY
# ============================================================================

configure_xrdp() {
    info "Step 3/4: Configuring xrdp..."
    
    # --- 3a: Session script for KDE Plasma ---
    STARTWM="/etc/xrdp/startwm.sh"
    if [[ -f "$STARTWM" ]]; then
        cp "$STARTWM" "${STARTWM}.bak"
    fi
    
    cat > "$STARTWM" << 'STARTWM_EOF'
#!/bin/sh
# xrdp session startup — launch KDE Plasma Wayland or X11

# Unset problematic session variables
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR

# Set display variables
export XDG_SESSION_TYPE=x11

# Try KDE Plasma first, fall back to xfce4, then generic
if command -v startplasma-x11 >/dev/null 2>&1; then
    exec startplasma-x11
elif command -v startkde >/dev/null 2>&1; then
    exec startkde
elif command -v startxfce4 >/dev/null 2>&1; then
    exec startxfce4
else
    exec xterm
fi
STARTWM_EOF
    
    chmod +x "$STARTWM"
    log "Session startup configured for KDE Plasma"
    
    # --- 3b: xrdp.ini — bind to Tailscale interface only ---
    XRDP_INI="/etc/xrdp/xrdp.ini"
    if [[ -f "$XRDP_INI" ]]; then
        cp "$XRDP_INI" "${XRDP_INI}.bak"
        
        # Set port to only listen on Tailscale IP (or localhost as fallback)
        # We'll use the address directive
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "127.0.0.1")
        
        # Update the address line (or the port line to include bind address)
        if grep -q "^address=" "$XRDP_INI"; then
            sed -i "s|^address=.*|address=${TAILSCALE_IP}|" "$XRDP_INI"
        elif grep -q "^port=" "$XRDP_INI"; then
            # Add address directive after port
            sed -i "/^port=/a address=${TAILSCALE_IP}" "$XRDP_INI"
        fi
        
        # Set max color depth for good iPhone experience
        sed -i 's|^max_bpp=.*|max_bpp=24|' "$XRDP_INI"
        
        # Enable TLS
        if grep -q "^security_layer=" "$XRDP_INI"; then
            sed -i 's|^security_layer=.*|security_layer=tls|' "$XRDP_INI"
        fi
        if grep -q "^crypt_level=" "$XRDP_INI"; then
            sed -i 's|^crypt_level=.*|crypt_level=high|' "$XRDP_INI"
        fi
        
        log "xrdp.ini configured: bound to $TAILSCALE_IP, TLS enabled, 24bpp"
    else
        warn "xrdp.ini not found at $XRDP_INI — xrdp may not be fully installed yet"
    fi
    
    # --- 3c: sesman.ini — allow the real user ---
    SESMAN_INI="/etc/xrdp/sesman.ini"
    if [[ -f "$SESMAN_INI" ]]; then
        cp "$SESMAN_INI" "${SESMAN_INI}.bak"
        
        # Ensure AllowRootLogin is No for security
        sed -i 's|^AllowRootLogin=.*|AllowRootLogin=false|' "$SESMAN_INI"
        
        log "sesman.ini configured: root login disabled"
    fi
    
    # --- 3d: Polkit rule so RDP sessions can access system services ---
    mkdir -p /etc/polkit-1/rules.d
    cat > /etc/polkit-1/rules.d/02-allow-colord.rules << 'POLKIT_EOF'
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.color-manager.create-device" ||
         action.id == "org.freedesktop.color-manager.create-profile" ||
         action.id == "org.freedesktop.color-manager.delete-device" ||
         action.id == "org.freedesktop.color-manager.delete-profile" ||
         action.id == "org.freedesktop.color-manager.modify-device" ||
         action.id == "org.freedesktop.color-manager.modify-profile" ||
         action.id == "org.freedesktop.packagekit.system-sources-refresh") &&
        subject.isInGroup("users")) {
        return polkit.Result.YES;
    }
});
POLKIT_EOF
    log "Polkit rules configured for RDP color management"
}

# ============================================================================
# STEP 4: FIREWALL — RDP ONLY VIA TAILSCALE
# ============================================================================

configure_firewall() {
    info "Step 4/4: Configuring firewall (RDP via VPN only)..."
    
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
    
    # Block RDP (3389) on all interfaces EXCEPT tailscale0
    # This ensures RDP is ONLY accessible through the VPN tunnel
    
    # Remove any existing xrdp rules first
    iptables -D INPUT -p tcp --dport 3389 -j DROP 2>/dev/null || true
    iptables -D INPUT -i tailscale0 -p tcp --dport 3389 -j ACCEPT 2>/dev/null || true
    
    # Allow RDP only on tailscale0 interface
    iptables -I INPUT -i tailscale0 -p tcp --dport 3389 -j ACCEPT
    iptables -A INPUT -p tcp --dport 3389 -j DROP
    
    log "Firewall: RDP (3389) allowed ONLY via Tailscale VPN"
    
    # Save iptables rules
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/iptables.rules
        systemctl enable iptables 2>/dev/null || true
        log "Firewall rules saved and persistent"
    fi
}

# ============================================================================
# STEP 5: ENABLE AND START SERVICES
# ============================================================================

start_services() {
    info "Starting services..."
    
    systemctl enable xrdp
    systemctl enable xrdp-sesman
    systemctl restart xrdp
    systemctl restart xrdp-sesman
    
    log "xrdp service enabled and running"
    
    # Verify
    if systemctl is-active --quiet xrdp; then
        log "xrdp is active"
    else
        warn "xrdp may have failed to start. Check: systemctl status xrdp"
    fi
    
    if systemctl is-active --quiet tailscaled; then
        log "tailscaled is active"
    else
        warn "tailscaled not running. Check: systemctl status tailscaled"
    fi
}

# ============================================================================
# STATUS REPORT
# ============================================================================

status_report() {
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "NOT CONFIGURED")
    HOSTNAME=$(tailscale status 2>/dev/null | head -1 | awk '{print $2}' || hostname)
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}           BEATRIX Remote Access — Setup Complete           ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Tailscale VPN IP:${NC}  ${BOLD}${TAILSCALE_IP}${NC}                           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Hostname:${NC}          ${BOLD}${HOSTNAME}${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}RDP Port:${NC}          ${BOLD}3389 (VPN-only)${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}RDP User:${NC}          ${BOLD}${REAL_USER}${NC}                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Security:${NC}          ${BOLD}WireGuard + TLS${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}iPhone Setup:${NC}                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  1. Install ${BOLD}Tailscale${NC} from App Store                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     → Sign in with same account                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     → Toggle ON to connect                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  2. Install ${BOLD}Microsoft Remote Desktop${NC} from App Store       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     → Add PC → hostname: ${BOLD}${TAILSCALE_IP}${NC}                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     → User: ${BOLD}${REAL_USER}${NC} → enter your Linux password          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     → Display: 1920×1080 or Auto                             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  3. Connect! Full KDE desktop with VS Code access            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     → Approve Copilot actions, view diffs, run terminals     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}Management Commands:${NC}                                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   tailscale status          — VPN status & connected devices ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   systemctl status xrdp     — RDP server status              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   beatrix-remote status     — Full status check              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   beatrix-remote stop       — Stop remote access             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   beatrix-remote start      — Start remote access            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================================================
# MANAGEMENT SCRIPT
# ============================================================================

install_management_script() {
    cat > /usr/local/bin/beatrix-remote << 'MGMT_EOF'
#!/usr/bin/env bash
# Beatrix Remote Access management

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

case "${1:-status}" in
    status)
        echo -e "${CYAN}=== Beatrix Remote Access Status ===${NC}"
        echo ""
        
        # Tailscale
        if systemctl is-active --quiet tailscaled; then
            TS_IP=$(tailscale ip -4 2>/dev/null || echo "?")
            echo -e "  Tailscale:  ${GREEN}● active${NC}  IP: ${BOLD}${TS_IP}${NC}"
            PEERS=$(tailscale status 2>/dev/null | tail -n +2 | wc -l)
            echo -e "  Peers:      ${BOLD}${PEERS}${NC} connected devices"
        else
            echo -e "  Tailscale:  ${RED}● inactive${NC}"
        fi
        
        # xrdp
        if systemctl is-active --quiet xrdp; then
            LISTEN=$(ss -tlnp | grep :3389 | head -1)
            echo -e "  xrdp:       ${GREEN}● active${NC}  ${LISTEN}"
        else
            echo -e "  xrdp:       ${RED}● inactive${NC}"
        fi
        
        # Active sessions
        SESSIONS=$(who | grep -c ".*:.*" 2>/dev/null || echo "0")
        echo -e "  Sessions:   ${BOLD}${SESSIONS}${NC} active"
        
        # Firewall
        if iptables -C INPUT -i tailscale0 -p tcp --dport 3389 -j ACCEPT 2>/dev/null; then
            echo -e "  Firewall:   ${GREEN}● RDP locked to VPN only${NC}"
        else
            echo -e "  Firewall:   ${YELLOW}● RDP may be accessible on LAN${NC}"
        fi
        echo ""
        ;;
    
    start)
        echo "Starting remote access..."
        sudo systemctl start tailscaled
        sudo systemctl start xrdp xrdp-sesman
        echo -e "${GREEN}Remote access started${NC}"
        $0 status
        ;;
    
    stop)
        echo "Stopping remote access..."
        sudo systemctl stop xrdp xrdp-sesman
        echo -e "${YELLOW}RDP stopped. Tailscale still running for other uses.${NC}"
        echo "To also stop VPN: sudo systemctl stop tailscaled"
        ;;
    
    restart)
        echo "Restarting..."
        sudo systemctl restart xrdp xrdp-sesman
        echo -e "${GREEN}Restarted${NC}"
        $0 status
        ;;
    
    sessions)
        echo -e "${CYAN}=== Active RDP Sessions ===${NC}"
        who 2>/dev/null || echo "No sessions"
        echo ""
        echo -e "${CYAN}=== xrdp Sessions ===${NC}"
        ls /tmp/.xrdp/ 2>/dev/null || echo "No xrdp session files"
        ;;
    
    logs)
        echo -e "${CYAN}=== Recent xrdp logs ===${NC}"
        journalctl -u xrdp -n 30 --no-pager
        ;;
    
    *)
        echo "Usage: beatrix-remote {status|start|stop|restart|sessions|logs}"
        ;;
esac
MGMT_EOF
    
    chmod +x /usr/local/bin/beatrix-remote
    log "Management script installed: beatrix-remote"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    banner
    preflight
    
    echo ""
    info "This will install and configure:"
    info "  • Tailscale VPN (WireGuard-based, no port forwarding needed)"
    info "  • xrdp (RDP server for KDE Plasma)"
    info "  • Firewall rules (RDP only via VPN tunnel)"
    info "  • Management script (beatrix-remote)"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Proceed with installation? [Y/n]:${NC} )" -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        err "Aborted."
        exit 1
    fi
    
    echo ""
    install_tailscale
    echo ""
    install_xrdp
    echo ""
    configure_xrdp
    echo ""
    configure_firewall
    echo ""
    install_management_script
    echo ""
    start_services
    echo ""
    status_report
}

main "$@"
