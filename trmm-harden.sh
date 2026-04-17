#!/usr/bin/env bash
# =============================================================================
#  TacticalRMM Server Hardening Script
#  Target  : rmm.ainnrmm.us (Ubuntu 22.04 LTS)
#  Covers  : UFW firewall, SSH hardening, fail2ban, sysctl kernel hardening,
#            unattended security upgrades, service lockdown, file permissions
#
#  ⚠️  READ BEFORE RUNNING:
#      1. Make sure you have SSH key-based auth working BEFORE running this.
#      2. Keep your current SSH session open while testing a NEW session.
#      3. Know your admin IP if you want to restrict SSH to it.
# =============================================================================

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Root check ─────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Run as root: sudo ./trmm-harden.sh"

# ── Backup directory ───────────────────────────────────────────────────────
BACKUP_DIR="/root/harden-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
info "Config backups will be saved to: ${BACKUP_DIR}"

# ═══════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         TacticalRMM Server Hardening Script                  ║"
echo "║         rmm.ainnrmm.us  |  Ubuntu 22.04 LTS                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  ⚠️  KEEP YOUR CURRENT SSH SESSION OPEN DURING THIS SCRIPT  ║"
echo "║     Test with a NEW terminal before disconnecting.           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ═══════════════════════════════════════════════════════════════════════════
#  GATHER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
section "Configuration"

# SSH port
read -rp "$(echo -e "${CYAN}SSH port to use [default: 22]:${RESET} ")" SSH_PORT
SSH_PORT="${SSH_PORT:-22}"
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
    die "Invalid port number: $SSH_PORT"
fi

# Admin IP restriction for SSH
echo ""
echo -e "  ${YELLOW}Restricting SSH to a specific IP is strongly recommended.${RESET}"
echo -e "  Enter your admin/office IP, or leave blank to allow SSH from anywhere."
read -rp "$(echo -e "${CYAN}Your admin IP (e.g. 203.0.113.10) or leave blank:${RESET} ")" ADMIN_IP

# SSH key check
echo ""
if [[ -f /home/tactical/.ssh/authorized_keys ]] || \
   find /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null | grep -q .; then
    warn "SSH authorized_keys file detected."
else
    warn "No SSH authorized_keys found. If you disable password auth you may lock yourself out!"
fi

read -rp "$(echo -e "${YELLOW}Disable SSH password authentication? (key-only login) [y/N]:${RESET} ")" DISABLE_SSH_PASS
DISABLE_SSH_PASS="${DISABLE_SSH_PASS,,}"

# Confirm before proceeding
echo ""
echo -e "${BOLD}── Settings Summary ──────────────────────────────────────────${RESET}"
echo -e "  SSH Port           : ${SSH_PORT}"
echo -e "  SSH IP restriction : ${ADMIN_IP:-"none (allow all)"}"
echo -e "  Disable SSH passwd : ${DISABLE_SSH_PASS}"
echo ""
read -rp "$(echo -e "${YELLOW}Proceed with hardening? [y/N]:${RESET} ")" CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && { info "Aborted."; exit 0; }

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 1 — System update
# ═══════════════════════════════════════════════════════════════════════════
section "Step 1 — System Update"
info "Running apt update & upgrade..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
apt-get autoremove -y -qq
success "System updated."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 2 — Install required tools
# ═══════════════════════════════════════════════════════════════════════════
section "Step 2 — Install Security Tools"
info "Installing fail2ban, ufw, unattended-upgrades, auditd, logwatch..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    auditd \
    audispd-plugins \
    logwatch \
    libpam-pwquality \
    rsyslog
success "Security tools installed."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 3 — UFW Firewall
# ═══════════════════════════════════════════════════════════════════════════
section "Step 3 — UFW Firewall"

# Backup existing rules
ufw status verbose > "${BACKUP_DIR}/ufw-before.txt" 2>&1 || true

# Reset and set defaults
info "Resetting UFW to defaults..."
ufw --force reset > /dev/null
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# SSH — restricted to admin IP if provided
if [[ -n "$ADMIN_IP" ]]; then
    info "Allowing SSH (port ${SSH_PORT}) from ${ADMIN_IP} only..."
    ufw allow from "$ADMIN_IP" to any port "$SSH_PORT" proto tcp comment "SSH admin access"
else
    warn "Allowing SSH (port ${SSH_PORT}) from ANY source. Consider restricting to your IP."
    ufw allow "${SSH_PORT}/tcp" comment "SSH"
fi

# HTTPS — required for agents, web UI, MeshCentral (all via nginx/443)
info "Allowing HTTPS (443/tcp) — agents, web UI, MeshCentral..."
ufw allow 443/tcp comment "HTTPS - TRMM agents + web UI + MeshCentral"

# HTTP — required for Let's Encrypt renewal (certbot http-01) and nginx redirect
info "Allowing HTTP (80/tcp) — Let's Encrypt cert renewal..."
ufw allow 80/tcp comment "HTTP - Let's Encrypt renewal + redirect to HTTPS"

# Rate limit SSH to slow brute-force (applies on top of IP restriction)
ufw limit "${SSH_PORT}/tcp" comment "SSH rate limit"

# Enable UFW
info "Enabling UFW..."
ufw --force enable
success "UFW enabled and configured."

echo ""
info "Current UFW rules:"
ufw status verbose

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 4 — SSH Hardening
# ═══════════════════════════════════════════════════════════════════════════
section "Step 4 — SSH Hardening"

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${BACKUP_DIR}/sshd_config.bak"
info "Backed up ${SSHD_CONFIG} to ${BACKUP_DIR}"

# Write a hardened drop-in config (avoids fighting with existing directives)
SSHD_HARDENED="/etc/ssh/sshd_config.d/99-trmm-hardening.conf"
cat > "$SSHD_HARDENED" <<EOF
# TacticalRMM Server SSH Hardening
# Applied by trmm-harden.sh — $(date)

Port ${SSH_PORT}

# Authentication
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30

# Only allow the tactical user and any other admin users
# AllowUsers tactical        # Uncomment and adjust as needed

# Keys only (if enabled)
$([ "$DISABLE_SSH_PASS" = "y" ] && echo "PasswordAuthentication no" || echo "PasswordAuthentication yes")
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Disable dangerous features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
PrintMotd no

# Use modern crypto only
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256

# Connection hardening
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Validate config before restarting
sshd -t -f "$SSHD_CONFIG" || die "SSH config validation failed. Check ${SSHD_HARDENED}"
systemctl restart ssh
success "SSH hardened and restarted."
[[ "$DISABLE_SSH_PASS" = "y" ]] && warn "Password authentication is DISABLED. Ensure your SSH key works before closing this session."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 5 — fail2ban
# ═══════════════════════════════════════════════════════════════════════════
section "Step 5 — fail2ban"

cp /etc/fail2ban/jail.conf "${BACKUP_DIR}/jail.conf.bak" 2>/dev/null || true

cat > /etc/fail2ban/jail.local <<EOF
# TacticalRMM fail2ban jail configuration
# Applied by trmm-harden.sh — $(date)

[DEFAULT]
# Ban for 1 hour
bantime  = 3600
# Look-back window: 10 minutes
findtime = 600
# Max retries before ban
maxretry = 3
# Use UFW as the ban backend
banaction = ufw
# Ignore localhost and private ranges
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
$([ -n "$ADMIN_IP" ] && echo "         $ADMIN_IP")

# ── SSH ───────────────────────────────────────────────────────────────────
[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200

# ── Nginx bad requests / scanning ────────────────────────────────────────
[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 10
bantime  = 86400

# ── Repeated 404/403 — block scanners ────────────────────────────────────
[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

# ── Aggressive repeat offenders — permanent-ish ban ──────────────────────
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = ufw[name=recidive, port="ssh,http,https", protocol=tcp]
bantime  = 604800
findtime = 86400
maxretry = 3
EOF

systemctl enable --now fail2ban
sleep 2
systemctl restart fail2ban
success "fail2ban configured and running."
fail2ban-client status | head -5

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 6 — Kernel / sysctl hardening
# ═══════════════════════════════════════════════════════════════════════════
section "Step 6 — Kernel Hardening (sysctl)"

cp /etc/sysctl.conf "${BACKUP_DIR}/sysctl.conf.bak"

cat > /etc/sysctl.d/99-trmm-hardening.conf <<'EOF'
# TacticalRMM kernel hardening — applied by trmm-harden.sh

# ── Network: IP spoofing / source routing ──────────────────────────────
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# ── Network: ICMP redirects ────────────────────────────────────────────
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ── Network: SYN flood protection ─────────────────────────────────────
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# ── Network: TIME_WAIT / port reuse ───────────────────────────────────
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# ── Network: Martian packets + ICMP ignore broadcasts ─────────────────
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Network: IPv6 (disable router advertisements) ─────────────────────
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# ── Network: Disable IP forwarding (not a router) ─────────────────────
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ── Memory: ASLR — randomise address space ────────────────────────────
kernel.randomize_va_space = 2

# ── Memory: Prevent core dumps leaking sensitive data ─────────────────
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# ── Kernel: Restrict /proc and dmesg ──────────────────────────────────
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3

# ── Kernel: Protect hardlinks and symlinks ────────────────────────────
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# ── Kernel: Disable magic SysRq (not needed on a server) ─────────────
kernel.sysrq = 0

# ── Shared memory: Prevent ptrace exploitation ────────────────────────
kernel.yama.ptrace_scope = 2

# ── Performance / swap tuning ─────────────────────────────────────────
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

sysctl --system > /dev/null 2>&1
success "Kernel hardening applied."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 7 — Disable unnecessary services
# ═══════════════════════════════════════════════════════════════════════════
section "Step 7 — Disable Unnecessary Services"

SERVICES_TO_DISABLE=(
    avahi-daemon      # mDNS/Bonjour — not needed on a server
    cups              # Printing — not needed
    bluetooth         # Bluetooth
    whoopsie          # Ubuntu crash reporter
    apport            # Crash reporting
    snapd             # Snap package manager (optional — TRMM doesn't use it)
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$svc" 2>/dev/null | grep -qE "enabled|static"; then
        systemctl disable --now "$svc" 2>/dev/null && info "Disabled: $svc" || true
    else
        info "Already disabled or not present: $svc"
    fi
done
success "Unnecessary services disabled."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 8 — Unattended security upgrades
# ═══════════════════════════════════════════════════════════════════════════
section "Step 8 — Automatic Security Updates"

cat > /etc/apt/apt.conf.d/50unattended-upgrades-trmm <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
    // Don't auto-update these — let you control TRMM updates manually
    "tactical*";
    "meshcentral";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades-trmm <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable --now unattended-upgrades
success "Automatic security updates enabled."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 9 — File & directory permission hardening
# ═══════════════════════════════════════════════════════════════════════════
section "Step 9 — File Permission Hardening"

# TRMM config files — readable only by tactical user
if [[ -d /rmm ]]; then
    info "Hardening /rmm permissions..."
    chown -R tactical:tactical /rmm/api/tacticalrmm/tacticalrmm/local_settings.py 2>/dev/null || true
    chmod 640 /rmm/api/tacticalrmm/tacticalrmm/local_settings.py 2>/dev/null || true
fi

# Let's Encrypt private keys — already protected but double-check
if [[ -d /etc/letsencrypt/live ]]; then
    info "Checking Let's Encrypt key permissions..."
    chmod 700 /etc/letsencrypt/live 2>/dev/null || true
    chmod 700 /etc/letsencrypt/archive 2>/dev/null || true
fi

# Cloudflare credentials
if [[ -f /etc/letsencrypt/cloudflare/credentials.ini ]]; then
    info "Locking down Cloudflare credentials..."
    chmod 600 /etc/letsencrypt/cloudflare/credentials.ini
    chown root:root /etc/letsencrypt/cloudflare/credentials.ini
fi

# /tmp and /var/tmp — prevent execution
if ! grep -q "noexec" /etc/fstab 2>/dev/null; then
    info "Note: Consider adding noexec,nosuid to /tmp in /etc/fstab for additional hardening."
fi

# Restrict cron access
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

# Restrict passwd/shadow
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow

success "File permissions hardened."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 10 — Audit logging
# ═══════════════════════════════════════════════════════════════════════════
section "Step 10 — Audit Logging"

cat > /etc/audit/rules.d/99-trmm-hardening.rules <<'EOF'
# TacticalRMM audit rules — applied by trmm-harden.sh

# Delete all existing rules first
-D

# Audit buffer size
-b 8192

# Failure mode: 1=log, 2=panic
-f 1

# Monitor authentication
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH config changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor TRMM config
-w /rmm/api/tacticalrmm/tacticalrmm/local_settings.py -p wa -k trmm_config

# Monitor login/logout
-w /var/log/auth.log -p wa -k auth_log
-w /var/run/faillock/ -p wa -k faillock

# Monitor cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/ufw/ -p wa -k firewall

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands

# Make rules immutable (requires reboot to change) — comment out during initial setup
# -e 2
EOF

systemctl enable --now auditd
augenrules --load > /dev/null 2>&1 || auditctl -R /etc/audit/rules.d/99-trmm-hardening.rules 2>/dev/null || true
success "Audit logging configured."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 11 — Password quality policy
# ═══════════════════════════════════════════════════════════════════════════
section "Step 11 — Password Policy"

cat > /etc/security/pwquality.conf <<'EOF'
# Password quality requirements
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
gecoscheck = 1
EOF

# Set account lockout policy
cat > /etc/security/faillock.conf <<'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF

success "Password policy configured."

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 12 — MOTD / login banner
# ═══════════════════════════════════════════════════════════════════════════
section "Step 12 — Login Banner"

cat > /etc/issue.net <<'EOF'
╔══════════════════════════════════════════════════════╗
║  AUTHORIZED ACCESS ONLY                              ║
║  This system is monitored and all activity logged.   ║
║  Unauthorized access is prohibited and prosecuted.   ║
╚══════════════════════════════════════════════════════╝
EOF

cp /etc/issue.net /etc/issue

# Enable banner in SSH config
if ! grep -q "Banner" /etc/ssh/sshd_config.d/99-trmm-hardening.conf 2>/dev/null; then
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config.d/99-trmm-hardening.conf
fi

# Disable dynamic MOTD news
chmod -x /etc/update-motd.d/91-release-upgrade 2>/dev/null || true
chmod -x /etc/update-motd.d/95-hwe-eol 2>/dev/null || true

success "Login banner configured."

# ═══════════════════════════════════════════════════════════════════════════
#  FINAL RESTART & VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
section "Final Validation"

info "Restarting SSH..."
sshd -t && systemctl restart ssh
info "Restarting fail2ban..."
systemctl restart fail2ban
info "Reloading nginx..."
systemctl reload nginx 2>/dev/null || true

echo ""
echo -e "${BOLD}${GREEN}══ Hardening Complete ═══════════════════════════════════════${RESET}"
echo ""
echo -e "${BOLD}Firewall Status:${RESET}"
ufw status verbose
echo ""
echo -e "${BOLD}Active Security Services:${RESET}"
for svc in ufw fail2ban auditd unattended-upgrades ssh nginx; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
    if [[ "$status" == "active" ]]; then
        echo -e "  ${GREEN}●${RESET} $svc"
    else
        echo -e "  ${RED}●${RESET} $svc ($status)"
    fi
done

echo ""
echo -e "${BOLD}Ports open (public):${RESET}"
echo -e "  ${GREEN}443/tcp${RESET}  — HTTPS (agents + web UI + MeshCentral)"
echo -e "  ${GREEN}80/tcp${RESET}   — HTTP (Let's Encrypt renewal + redirect)"
echo -e "  ${GREEN}${SSH_PORT}/tcp${RESET}   — SSH${ADMIN_IP:+ (restricted to $ADMIN_IP)}"
echo ""
echo -e "${BOLD}Ports BLOCKED (all others):${RESET}"
echo -e "  ${RED}✗${RESET} All other inbound traffic denied by UFW"
echo ""
echo -e "${BOLD}${YELLOW}⚠️  Action Required:${RESET}"
echo -e "  1. ${YELLOW}Test SSH in a NEW terminal before closing this session${RESET}"
echo -e "     ssh -p ${SSH_PORT} tactical@rmm.ainnrmm.us"
echo -e "  2. Verify TRMM web UI: https://rmm.ainnrmm.us"
echo -e "  3. Check fail2ban: ${CYAN}sudo fail2ban-client status${RESET}"
echo -e "  4. Check UFW: ${CYAN}sudo ufw status verbose${RESET}"
echo -e "  5. Check audit: ${CYAN}sudo auditctl -l${RESET}"
echo ""
echo -e "${BOLD}Useful monitoring commands:${RESET}"
echo -e "  ${CYAN}sudo fail2ban-client status sshd${RESET}        — SSH ban status"
echo -e "  ${CYAN}sudo fail2ban-client status nginx-botsearch${RESET} — Web scanner bans"
echo -e "  ${CYAN}sudo ufw status numbered${RESET}                — Numbered firewall rules"
echo -e "  ${CYAN}sudo ausearch -k identity${RESET}               — Audit: auth changes"
echo -e "  ${CYAN}sudo ausearch -k root_commands${RESET}           — Audit: root commands"
echo -e "  ${CYAN}sudo journalctl -u fail2ban -f${RESET}           — Live fail2ban log"
echo -e "  ${CYAN}sudo tail -f /var/log/auth.log${RESET}           — Live auth log"
echo ""
echo -e "  Backup of original configs saved to: ${BACKUP_DIR}"
echo -e "${BOLD}${GREEN}═════════════════════════════════════════════════════════════${RESET}"
