#!/usr/bin/env bash
# Proxmox VE 9.2 (Debian 13 Trixie) Ultimate Security Hardening & Performance
# Compatible with PVE 9.2+ (Kernel 6.14+ / AMD Strix Point)
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION='1.0'
MODE='audit'

# Значения по умолчанию (будут перезаписаны из конфига, если он есть)
SETUP_ADMIN_USER=true
ADMIN_USER="proxadmin"
SSH_PORT=4444
SSH_ROOT_KEY_ONLY=true
CHANGE_PVE_PORT=false
NEW_PVE_PORT=4443
APPLY_SYSCTL_TUNING=true
PURGE_LEGACY_MODULES=true
DISABLE_SUBSCRIPTION_NAG=true
INSTALL_PACKAGES=true
SETUP_FIREWALL=true
MANAGE_WEB_GUI=true
WEB_GUI_ENABLED=true

# Загружаем сохраненную конфигурацию, если она существует (для корректного audit)
if [[ -f /etc/proxmox-hardening.conf ]]; then
  # Load only a root-owned config file; never source a writable/untrusted file.
  if [[ $(stat -c '%u' /etc/proxmox-hardening.conf 2>/dev/null || echo 99999) == 0 && ! -L /etc/proxmox-hardening.conf ]]; then
    # shellcheck disable=SC1091
    source /etc/proxmox-hardening.conf
  else
    echo "[WARN] Ignoring /etc/proxmox-hardening.conf: must be a regular root-owned file." >&2
  fi
fi

ask_yn() {
  local prompt_msg="$1"
  local default_val="${2:-y}"
  local ans
  if [[ "$MODE" != "apply" ]]; then
    [[ "$default_val" =~ ^[yY] ]] && return 0 || return 1
  fi
  local hint="Y/n"
  [[ "$default_val" =~ ^[nN]$ ]] && hint="y/N"
  read -rp "$prompt_msg [$hint]: " ans || true
  ans="${ans:-$default_val}"
  [[ "$ans" =~ ^[yY][eE]?[sS]?$ ]]
}

for arg in "$@"; do
  case "$arg" in
    --apply)       MODE='apply' ;;
    --audit)       MODE='audit' ;;
    --enable-web)  MODE='enable-web' ;;
    --disable-web) MODE='disable-web' ;;
    --help|-h)
      cat <<'HELP'
Usage: sudo ./proxmox.sh [--audit|--apply|--enable-web|--disable-web|--help]

  --audit       Report current security posture (default, no changes)
  --apply       Backup managed files, apply interactive hardening & log everything
  --enable-web  Quickly enable and start Proxmox Web GUI (pveproxy)
  --disable-web Quickly disable and stop Proxmox Web GUI (pveproxy) for security
  --help        Display this help message

Designed for Proxmox VE 9.2+ / Debian 13 Trixie bare-metal deployments.
HELP
      exit 0
      ;;
    *)
      if [[ -n "$arg" ]]; then
        echo "Unknown argument: $arg. Use --help." >&2
        exit 2
      fi
      ;;
  esac
done

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

ok()     { printf '%s[OK]%s      %s\n' "$GREEN"  "$NC" "$*"; }
fixed()  { printf '%s[APPLIED]%s %s\n' "$BLUE"   "$NC" "$*"; }
warn()   { printf '%s[WARN]%s    %s\n' "$YELLOW" "$NC" "$*"; }
fail()   { printf '%s[FAIL]%s    %s\n' "$RED"    "$NC" "$*"; }
info()   { printf '          %s\n' "$*"; }
section(){ printf '\n%s=== %s ===%s\n' "$CYAN" "$*" "$NC"; }

die() { fail "$*"; exit 1; }

if (( EUID != 0 )); then
  die "This script must be run as root or via sudo."
fi

if [[ ! -r /etc/os-release ]] || ! grep -qE '^ID=(debian|proxmox)$' /etc/os-release; then
  die "This script is designed exclusively for Proxmox VE / Debian Linux."
fi

# Quick Actions handlers
if [[ $MODE == "enable-web" ]]; then
  section 'Quick Action: Enabling Proxmox Web GUI (pveproxy)'
  systemctl enable --now pveproxy.service || die "Could not enable/start pveproxy.service."
  fixed "Web GUI (pveproxy) successfully enabled and started."
  exit 0
fi

if [[ $MODE == "disable-web" ]]; then
  section 'Quick Action: Disabling Proxmox Web GUI (pveproxy)'
  systemctl disable --now proxmox-web-port-forward.service 2>/dev/null || true
  systemctl disable --now pveproxy.service || die "Could not disable pveproxy.service."
  fixed "Web GUI (pveproxy) successfully disabled and stopped for security."
  exit 0
fi

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups/proxmox-hardening/$STAMP"
LOG_FILE="/var/log/proxmox-hardening.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $MODE == apply ]]; then
  install -d -m 0700 "$BACKUP_DIR"
  touch "$LOG_FILE"
  chmod 0600 "$LOG_FILE"
  exec 3>&1
  exec > >(tee -a "$LOG_FILE" >&3) 2>&1
  info "Backup directory : $BACKUP_DIR"
  info "Log file         : $LOG_FILE"
fi

backup_file() {
  local f=$1
  if [[ -e $f || -L $f ]]; then
    install -d -m 0700 "$BACKUP_DIR$(dirname "$f")"
    cp -a -- "$f" "$BACKUP_DIR$f" 2>/dev/null || true
  fi
}

write_managed() {
  local dest=$1 mode=$2
  local tmp
  install -d -m 0755 "$(dirname "$dest")"
  tmp=$(mktemp "$(dirname "$dest")/.secure-hardening.XXXXXX")
  cat > "$tmp"
  chmod "$mode" "$tmp" 2>/dev/null || true
  if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    ok "Already up-to-date: $dest"
    return 0
  fi
  backup_file "$dest"
  
  # Для путей в /etc/pve (pmxcfs FUSE) нельзя делать chown/install с изменением владельца
  if [[ "$dest" == /etc/pve/* ]]; then
    mv -f "$tmp" "$dest"
  else
    install -o root -g root -m "$mode" "$tmp" "$dest"
  fi
  
  rm -f "$tmp"
  fixed "Updated: $dest"
}

printf '\n=== Proxmox VE 9.2 Ultimate Security & Performance Hardening v%s ===\n' "$VERSION"
printf 'Mode: %s | Date: %s | Host: %s | Kernel: %s\n' \
  "$MODE" "$(date -Is)" "$(hostname)" "$(uname -r)"

if [[ $MODE == apply ]]; then
  section 'Interactive Hardening Configuration'

  if ask_yn "1. Create non-root admin user with sudo privileges?" "y"; then
    SETUP_ADMIN_USER=true
    read -rp "   Enter new admin username (default: proxadmin): " input_user || true
    ADMIN_USER="${input_user:-proxadmin}"
  else
    SETUP_ADMIN_USER=false
  fi

  read -rp "2. Enter custom SSH port (default: 4444): " input_ssh_port || true
  SSH_PORT="${input_ssh_port:-4444}"
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1024 || SSH_PORT > 65535 )); then
    warn "Invalid port range. Falling back to default SSH port 4444."
    SSH_PORT=4444
  fi

  if ask_yn "3. Restrict root login strictly to SSH Keys (no password)?" "y"; then
    SSH_ROOT_KEY_ONLY=true
  else
    SSH_ROOT_KEY_ONLY=false
  fi

  if ask_yn "4. Disable Proxmox VE No-Subscription Nag popup & configure free pve-no-subscription repo?" "y"; then
    DISABLE_SUBSCRIPTION_NAG=true
  else
    DISABLE_SUBSCRIPTION_NAG=false
  fi

  if ask_yn "5. Install useful system administration packages (htop, mc, curl, nvme-cli, smartmontools, etc.)?" "y"; then
    INSTALL_PACKAGES=true
  else
    INSTALL_PACKAGES=false
  fi

  if ask_yn "6. Apply aggressive sysctl performance & kernel self-protection tuning?" "y"; then
    APPLY_SYSCTL_TUNING=true
  else
    APPLY_SYSCTL_TUNING=false
  fi

  if ask_yn "7. Purge and blacklist legacy hardware/network kernel modules?" "y"; then
    PURGE_LEGACY_MODULES=true
  else
    PURGE_LEGACY_MODULES=false
  fi

  if ask_yn "8. Configure Proxmox firewall (host-level DROP policy + management rules)?" "y"; then
    SETUP_FIREWALL=true
  else
    SETUP_FIREWALL=false
  fi

  if ask_yn "9. Manage Web GUI (pveproxy) state & alternative port?" "y"; then
    MANAGE_WEB_GUI=true
    if ask_yn "   Keep Web GUI enabled after hardening?" "y"; then
      WEB_GUI_ENABLED=true
      read -rp "   Enter custom Web GUI port (default: 4443, standard 8006): " input_pve_port || true
      NEW_PVE_PORT="${input_pve_port:-4443}"
      if ! [[ "$NEW_PVE_PORT" =~ ^[0-9]+$ ]] || (( NEW_PVE_PORT < 1024 || NEW_PVE_PORT > 65535 )); then
        warn "Invalid port range. Falling back to 4443."
        NEW_PVE_PORT=4443
      fi
    else
      WEB_GUI_ENABLED=false
    fi
  else
    MANAGE_WEB_GUI=false
  fi

  # Сохраняем конфигурацию для последующих аудитов и запусков
  cat <<CONF > /etc/proxmox-hardening.conf
SETUP_ADMIN_USER="$SETUP_ADMIN_USER"
ADMIN_USER="$ADMIN_USER"
SSH_PORT="$SSH_PORT"
SSH_ROOT_KEY_ONLY="$SSH_ROOT_KEY_ONLY"
NEW_PVE_PORT="$NEW_PVE_PORT"
APPLY_SYSCTL_TUNING="$APPLY_SYSCTL_TUNING"
PURGE_LEGACY_MODULES="$PURGE_LEGACY_MODULES"
DISABLE_SUBSCRIPTION_NAG="$DISABLE_SUBSCRIPTION_NAG"
INSTALL_PACKAGES="$INSTALL_PACKAGES"
SETUP_FIREWALL="$SETUP_FIREWALL"
MANAGE_WEB_GUI="$MANAGE_WEB_GUI"
WEB_GUI_ENABLED="$WEB_GUI_ENABLED"
CONF
  chmod 0600 /etc/proxmox-hardening.conf
  fixed "Configuration saved to /etc/proxmox-hardening.conf"
fi

section '1. Administrative User & SSH Keys Auto-Provisioning'

parse_local_keys() {
  local target_user="$1"
  local target_home="$2"
  local auth_keys_file="$target_home/.ssh/authorized_keys"

  install -d -m 0700 "$target_home/.ssh"
  if [[ "$target_user" != "root" ]]; then
    chown -R "$target_user:$target_user" "$target_home/.ssh" 2>/dev/null || true
  fi
  
  touch "$auth_keys_file"
  if [[ "$target_user" != "root" ]]; then
    chown "$target_user:$target_user" "$auth_keys_file" 2>/dev/null || true
  fi
  chmod 0600 "$auth_keys_file"

  local keys_found=0
  local files_found_count=0
  local search_patterns=("$SCRIPT_DIR/authorized_keys" "$SCRIPT_DIR"/*.pub)
  declare -A processed_files=()

  for pub_pattern in "${search_patterns[@]}"; do
    for pub_file in $pub_pattern; do
      if [[ -f "$pub_file" ]]; then
        [[ -n "${processed_files[$pub_file]:-}" ]] && continue
        processed_files["$pub_file"]=1
        ((++files_found_count))

        info "Found public key candidate: $(basename "$pub_file")"
        while IFS= read -r line || [[ -n "$line" ]]; do
          line=$(echo "$line" | xargs)
          [[ -z "$line" || "$line" =~ ^# ]] && continue
          if [[ "$line" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp|sk-ssh-ed25519) ]]; then
            if ! grep -qF "$line" "$auth_keys_file"; then
              echo "$line" >> "$auth_keys_file"
              ((++keys_found))
            fi
          fi
        done < "$pub_file"
      fi
    done
  done

  if (( keys_found > 0 )); then
    fixed "Imported $keys_found SSH key(s) into $auth_keys_file"
  elif (( files_found_count > 0 )); then
    ok "SSH keys in $auth_keys_file are already up-to-date."
  else
    warn "No valid .pub or authorized_keys files found in script directory ($SCRIPT_DIR)."
  fi
}

if [[ $SETUP_ADMIN_USER == true && $MODE == apply ]]; then
  if ! id "$ADMIN_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$ADMIN_USER"
    usermod -aG sudo "$ADMIN_USER"
    fixed "Created user '$ADMIN_USER' and added to sudo group."
    info "Please set password for '$ADMIN_USER':"
    passwd "$ADMIN_USER" || warn "Password setting was skipped or failed."
  else
    ok "User '$ADMIN_USER' already exists."
  fi

  ADMIN_HOME=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
  parse_local_keys "$ADMIN_USER" "$ADMIN_HOME" || true
  parse_local_keys "root" "/root" || true
else
  if [[ $MODE == audit ]]; then
    if id "$ADMIN_USER" &>/dev/null; then
      ok "Admin user '$ADMIN_USER' present"
    else
      warn "Admin user '$ADMIN_USER' missing (will be created on --apply)"
    fi
  fi
fi

section '2. OpenSSH Server Hardening'

SSH_CONF_DIR="/etc/ssh/sshd_config.d"
SSH_HARDEN_FILE="$SSH_CONF_DIR/99-proxmox-hardening.conf"

ROOT_LOGIN_POLICY="prohibit-password"
[[ $SSH_ROOT_KEY_ONLY == false ]] && ROOT_LOGIN_POLICY="no"

if [[ $MODE == apply ]]; then
  write_managed "$SSH_HARDEN_FILE" 0600 <<EOF
# Managed by proxmox.sh v$VERSION
Port $SSH_PORT
PermitRootLogin $ROOT_LOGIN_POLICY
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding yes
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 10
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF

  systemctl try-reload-or-restart ssh 2>/dev/null || systemctl try-reload-or-restart sshd 2>/dev/null || true
  fixed "OpenSSH hardened on Port $SSH_PORT. Password auth disabled."
  warn "CRITICAL: Open a secondary terminal to test SSH access on port $SSH_PORT before closing your session!"
else
  if [[ -f $SSH_HARDEN_FILE ]]; then
    ok "SSH hardening configuration exists"
  else
    warn "SSH hardening configuration missing"
  fi
fi

section '3. Sysctl Kernel Self-Protection & Performance Tuning'

SYSCTL_FILE="/etc/sysctl.d/99-proxmox-hardening.conf"

if [[ $APPLY_SYSCTL_TUNING == true && $MODE == apply ]]; then
  write_managed "$SYSCTL_FILE" 0644 <<'SYSCTL_EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.conf.all.route_localnet = 1

net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
kernel.kexec_load_disabled = 1
kernel.oops_limit = 100
kernel.warn_limit = 100
kernel.panic = -1
kernel.panic_on_oops = 1
fs.suid_dumpable = 0
fs.protected_regular = 2
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535
fs.aio-max-nr = 1048576
fs.file-max = 2097152

vm.swappiness = 10
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
vm.vfs_cache_pressure = 50
vm.max_map_count = 262144
SYSCTL_EOF

  sysctl --system >/dev/null 2>&1 || true
  fixed "Performance & security sysctl rules applied."
else
  info "Sysctl performance/security tuning skipped or in audit mode."
fi

if [[ $MODE == apply ]]; then
  info "Configuring optimal I/O schedulers for modern NVMe SSDs..."
  for nvme in /sys/block/nvme[0-9]n[0-9]; do
    if [[ -d "$nvme" && -f "$nvme/queue/scheduler" ]]; then
      echo "none" > "$nvme/queue/scheduler" 2>/dev/null || true
      fixed "Set I/O scheduler to 'none' for $(basename "$nvme")"
    fi
  done
fi

section '4. Legacy Protocols & Unused Hardware Blacklisting'

MODPROBE_FILE="/etc/modprobe.d/99-proxmox-blacklist.conf"
MODPROBE_CONTENT=$(cat <<'MOD_EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install can /bin/false
install atm /bin/false

install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install sysv /bin/false
install minix /bin/false
install nilfs2 /bin/false

install floppy /bin/false
install parport /bin/false
install parport_pc /bin/false
install lp /bin/false
install ppdev /bin/false
install pcspkr /bin/false
install firewire-core /bin/false
install firewire-ohci /bin/false
install nfc /bin/false
install uwb /bin/false
MOD_EOF
)

if [[ $PURGE_LEGACY_MODULES == true && $MODE == apply ]]; then
  write_managed "$MODPROBE_FILE" 0644 <<<"$MODPROBE_CONTENT"
  fixed "Blacklisted legacy filesystems, buses, and obsolete protocols."
fi

services_to_mask=(
  avahi-daemon.service avahi-daemon.socket
  cups.service cups.socket cups.path
  pcscd.service ModemManager.service
  rpcbind.service rpcbind.socket
  bluetooth.service
)

for srv in "${services_to_mask[@]}"; do
  if systemctl list-unit-files "$srv" --no-legend 2>/dev/null | grep -q "^$srv"; then
    if systemctl is-enabled --quiet "$srv" 2>/dev/null || systemctl is-active --quiet "$srv" 2>/dev/null; then
      if [[ $MODE == apply ]]; then
        systemctl disable --now "$srv" 2>/dev/null || true
        systemctl mask "$srv" 2>/dev/null || true
        fixed "Disabled & masked: $srv"
      else
        warn "Active service can be masked: $srv"
      fi
    else
      ok "Service installed but inactive: $srv"
    fi
  fi
done

section '5. Proxmox VE Repositories & Essential System Packages'

if [[ $DISABLE_SUBSCRIPTION_NAG == true && $MODE == apply ]]; then
  for enterprise_file in /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/pve-enterprise.list; do
    if [[ -f "$enterprise_file" ]]; then
      backup_file "$enterprise_file"
      if [[ "$enterprise_file" == *.sources ]]; then
        if grep -q "^Enabled:" "$enterprise_file"; then
          sed -i 's/^Enabled:.*/Enabled: false/' "$enterprise_file"
        else
          sed -i '1i Enabled: false' "$enterprise_file"
        fi
      else
        sed -i 's/^deb/#deb/g' "$enterprise_file"
      fi
      fixed "Disabled enterprise repository: $enterprise_file"
    fi
  done

  PVE_NO_SUB_SOURCES="/etc/apt/sources.list.d/pve-no-subscription.sources"
  if [[ ! -f "$PVE_NO_SUB_SOURCES" ]]; then
    write_managed "$PVE_NO_SUB_SOURCES" 0644 <<'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
    fixed "Added pve-no-subscription.sources (deb822)."
  fi

  if [[ -f /etc/apt/sources.list.d/ceph.sources ]]; then
    backup_file /etc/apt/sources.list.d/ceph.sources
    if grep -q "^Enabled:" /etc/apt/sources.list.d/ceph.sources; then
      sed -i 's/^Enabled:.*/Enabled: false/' /etc/apt/sources.list.d/ceph.sources
    else
      sed -i '1i Enabled: false' /etc/apt/sources.list.d/ceph.sources
    fi
    write_managed /etc/apt/sources.list.d/ceph-no-subscription.sources 0644 <<'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/ceph-tentacle
Suites: trixie
Components: no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
    fixed "Switched Ceph to no-subscription repository."
  fi

  for deb_src in /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; do
    if [[ -f "$deb_src" ]]; then
      backup_file "$deb_src"
      if [[ "$deb_src" == *.sources ]]; then
        sed -i 's/Components: \(.*\)/Components: \1 contrib non-free non-free-firmware/' "$deb_src" 2>/dev/null || true
        sed -i 's/contrib non-free non-free-firmware contrib non-free non-free-firmware/contrib non-free non-free-firmware/g' "$deb_src" 2>/dev/null || true
      else
        sed -i 's/\(main\)/\1 contrib non-free non-free-firmware/g' "$deb_src" 2>/dev/null || true
        sed -i 's/contrib non-free non-free-firmware contrib non-free non-free-firmware/contrib non-free non-free-firmware/g' "$deb_src" 2>/dev/null || true
      fi
      fixed "Enabled non-free/contrib repositories in $deb_src"
    fi
  done

  PVE_MANAGER_JS="/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
  if [[ -f "$PVE_MANAGER_JS" ]]; then
    backup_file "$PVE_MANAGER_JS"
    sed -Ezi.bak "s/(Ext.Msg.show\(\{\s+title: gettext\('No valid sub)/void\(\{ \/\/\1/g" "$PVE_MANAGER_JS" || true
    systemctl restart pveproxy.service 2>/dev/null || true
    fixed "Proxmox subscription nag popup removed."
  fi

  DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
fi

if [[ $INSTALL_PACKAGES == true && $MODE == apply ]]; then
  info "Installing essential administration tools..."
  DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    htop \
    mc \
    zip \
    unzip \
    unrar \
    atool \
    curl \
    nvme-cli \
    inxi \
    smartmontools \
    rclone \
    ffmpeg \
    mediainfo 2>/dev/null || warn "Some administration packages failed to install."
  fixed "Installed administration utilities (htop, mc, unrar, atool, nvme-cli, smartmontools, etc.)."
fi

section '6. Fail2ban Proxmox Web GUI & SSH Protection'

if [[ $MODE == apply ]]; then
  info "Installing and configuring Fail2ban..."
  DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban 2>/dev/null || warn "Failed to install fail2ban via apt."

  write_managed /etc/fail2ban/jail.d/proxmox.conf 0644 <<EOF
# Managed by proxmox.sh v$VERSION
[sshd]
enabled = true
port    = $SSH_PORT
maxretry = 3
findtime = 600
bantime  = 14400

[proxmox]
enabled = true
port    = $NEW_PVE_PORT
filter  = proxmox
logpath = /var/log/daemon.log
maxretry = 3
findtime = 600
bantime  = 14400
EOF

  write_managed /etc/fail2ban/filter.d/proxmox.conf 0644 <<'EOF'
[Definition]
failregex = pvedaemon\[.* authentication failure; rhost=<HOST> user=.* msg=.*
ignoreregex =
EOF

  systemctl enable --now fail2ban 2>/dev/null || true
  fixed "Fail2ban configured for SSH (port $SSH_PORT) and Proxmox Web GUI (port $NEW_PVE_PORT)."
fi

section '7. Firewall rules for management ports'

if [[ $SETUP_FIREWALL == true && $MODE == apply ]]; then
  # Use a dedicated, idempotent iptables chain instead of writing host.fw
  # rules that differ between the legacy and nftables Proxmox firewall backends.
  # Default INPUT policy is deliberately not changed to avoid remote lockout.
  apply_managed_filter() {
    local bin="$1"
    command -v "$bin" >/dev/null 2>&1 || return 0
    "$bin" -N PROXMOX_HARDENING 2>/dev/null || true
    "$bin" -F PROXMOX_HARDENING
    "$bin" -A PROXMOX_HARDENING -i lo -j RETURN
    "$bin" -A PROXMOX_HARDENING -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    "$bin" -A PROXMOX_HARDENING -p tcp --dport "$SSH_PORT" -j RETURN
    if [[ "$WEB_GUI_ENABLED" == true ]]; then
      "$bin" -A PROXMOX_HARDENING -p tcp --dport "$NEW_PVE_PORT" -j RETURN
    fi
    "$bin" -A PROXMOX_HARDENING -p tcp --dport 3128 -j RETURN
    "$bin" -A PROXMOX_HARDENING -p tcp --dport 5900:5999 -j RETURN
    if [[ "$bin" == ip6tables ]]; then
      "$bin" -A PROXMOX_HARDENING -p ipv6-icmp -j RETURN 2>/dev/null || true
    else
      "$bin" -A PROXMOX_HARDENING -p icmp -j RETURN 2>/dev/null || true
    fi
    # Block direct access to the standard PVE GUI port. Local loopback above remains allowed.
    "$bin" -A PROXMOX_HARDENING -p tcp --dport 8006 -j DROP
    "$bin" -A PROXMOX_HARDENING -j RETURN
    "$bin" -C INPUT -j PROXMOX_HARDENING 2>/dev/null || "$bin" -I INPUT 1 -j PROXMOX_HARDENING
  }

  command -v iptables >/dev/null 2>&1 || die "iptables is required for the managed port filter."
  apply_managed_filter iptables
  apply_managed_filter ip6tables

  # Persist the current rules without replacing them with a hand-written template.
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save || die "Failed to persist firewall rules."
    systemctl enable netfilter-persistent.service >/dev/null 2>&1 || true
  else
    warn "netfilter-persistent is missing; installing iptables-persistent is recommended to preserve rules after reboot."
  fi
  fixed "Managed port filter installed: SSH $SSH_PORT; GUI $NEW_PVE_PORT; direct GUI port 8006 blocked."
fi

section '8. Web GUI (pveproxy) Management & Port Mapping'

if [[ $MANAGE_WEB_GUI == true && $MODE == apply ]]; then
  if [[ $WEB_GUI_ENABLED == true ]]; then
    # pveproxy must remain on its native internal port 8006.
    # Do NOT set PORT=4443 in /etc/default/pveproxy.
    if [[ -f /etc/default/pveproxy ]]; then
      backup_file /etc/default/pveproxy
      sed -i '/^[[:space:]]*PORT[[:space:]]*=/d' /etc/default/pveproxy
    fi

    systemctl enable --now pveproxy.service ||
      die "Could not start pveproxy."

    # Ensure socat is installed.
    if ! command -v socat >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y socat ||
        die "Could not install socat."
    fi

    # Forward the custom external port to pveproxy on loopback:8006.
    if (( NEW_PVE_PORT != 8006 )); then
      write_managed /etc/systemd/system/proxmox-web-port-forward.service 0644 <<EOF
[Unit]
Description=Forward custom Proxmox GUI port to local pveproxy
After=network.target pveproxy.service
Wants=pveproxy.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:${NEW_PVE_PORT},bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:8006
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

      systemctl daemon-reload
      systemctl enable --now proxmox-web-port-forward.service ||
        die "Could not start the GUI port forwarder."
    fi

    # Block direct access to port 8006 from non-loopback interfaces.
    # Keep loopback available for socat -> 127.0.0.1:8006.
    for bin in iptables ip6tables; do
      command -v "$bin" >/dev/null 2>&1 || continue

      "$bin" -C INPUT ! -i lo -p tcp --dport 8006 -j DROP 2>/dev/null ||
        "$bin" -I INPUT 1 ! -i lo -p tcp --dport 8006 -j DROP ||
        die "Could not block external TCP/8006 using $bin."
    done

    if command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save ||
        die "Could not persist firewall rules."
      systemctl enable netfilter-persistent.service >/dev/null 2>&1 || true
    else
      warn "netfilter-persistent not found: the port 8006 block may not survive reboot."
    fi

    # Verify that pveproxy and the forwarder are active.
    systemctl is-active --quiet pveproxy.service ||
      die "pveproxy is not active."
    if (( NEW_PVE_PORT != 8006 )); then
      systemctl is-active --quiet proxmox-web-port-forward.service ||
        die "GUI port forwarder is not active."
    fi

    fixed "GUI configured on port $NEW_PVE_PORT; external port 8006 blocked."
  else
    systemctl disable --now proxmox-web-port-forward.service 2>/dev/null || true
    systemctl disable --now pveproxy.service 2>/dev/null || true
    fixed "Web GUI disabled."
  fi

  if [[ -f /usr/bin/pvebanner ]]; then
    sed -i "s/:8006/:$NEW_PVE_PORT/g" /usr/bin/pvebanner 2>/dev/null || true
  fi
fi

section 'Execution Summary'

if [[ $MODE == apply ]]; then
  info "Proxmox VE 9.2 hardening completed successfully."
  info "Backups stored in : $BACKUP_DIR"
  info "Execution log     : $LOG_FILE"
  info ""
  info "IMPORTANT REMINDERS:"
  info "  1. SSH Custom Port        : $SSH_PORT"
  info "  2. Created Admin User     : $ADMIN_USER"
  info "  3. Test SSH connectivity in a new terminal NOW:"
  info "     ssh -p $SSH_PORT $ADMIN_USER@<your-proxmox-ip>"
  if [[ $WEB_GUI_ENABLED == true ]]; then
    info "  4. Proxmox Web GUI URL    : https://<your-proxmox-ip>:$NEW_PVE_PORT"
  else
    info "  4. Web GUI is DISABLED. Enable when needed via: sudo $0 --enable-web"
  fi
  info "  5. Reboot the host to fully apply kernel module blacklists and sysctl parameters."
else
  info "Audit mode finished. No changes were made."
  info "To apply hardening, run: sudo $0 --apply"
  info "Quick toggles available : sudo $0 --enable-web | --disable-web"
fi
echo
