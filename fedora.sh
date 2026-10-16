#!/usr/bin/env bash
#
# Fedora Ultimate Security Hardening (Auditor & Enforcer)
# Compatible with Fedora 40–45+ (traditional RPM/DNF systems)
# Inspired by secureblue, Kicksecure, madaidan hardening guide and CIS.
# Privacy-first, aggressive surface reduction.
#
# Usage:
#   sudo ./fedora.sh            # audit (default)
#   sudo ./fedora.sh --audit
#   sudo ./fedora.sh --apply
#
# Check kernel error: sudo sysctl --system
#

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION='1.0'
MODE='audit'
FORCE_SSH_KEEP=true          # set to false if you really want to remove SSH from public zone
AGGRESSIVE_USERNS=false      # set to true to disable unprivileged user namespaces (breaks Flatpak/Podman rootless)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --apply)   MODE='apply' ;;
    --audit)   MODE='audit' ;;
    --help|-h)
      cat <<'HELP'
Usage: sudo ./secure-fedora-ultimate.sh [--audit|--apply|--help]

  --audit   Report current security posture (default, no changes)
  --apply   Backup managed files, apply hardening, log everything

Designed for traditional Fedora Workstation/Server (DNF + systemd).
Not for Atomic/Silverblue/Kinoite (use secureblue or rpm-ostree kargs).
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

# ---------------------------------------------------------------------------
# Colors & helpers
# ---------------------------------------------------------------------------
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

ok()    { printf '%s[OK]%s      %s\n' "$GREEN"  "$NC" "$*"; }
fixed() { printf '%s[APPLIED]%s %s\n' "$BLUE"   "$NC" "$*"; }
warn()  { printf '%s[WARN]%s    %s\n' "$YELLOW" "$NC" "$*"; }
fail()  { printf '%s[FAIL]%s    %s\n' "$RED"    "$NC" "$*"; }
info()  { printf '          %s\n' "$*"; }
section(){ printf '\n%s=== %s ===%s\n' "$CYAN" "$*" "$NC"; }

die() { fail "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if (( EUID != 0 )); then
  die "Run as root or via sudo."
fi

if [[ ! -r /etc/os-release ]] || ! grep -q '^ID=fedora$' /etc/os-release; then
  die "This script is only for Fedora Linux."
fi

# Detect desktop vs server roughly
IS_DESKTOP=false
if systemctl is-active --quiet graphical.target 2>/dev/null || \
   [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
  IS_DESKTOP=true
fi

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups/secure-fedora-hardening/$STAMP"
LOG_FILE="/var/log/secure-fedora-hardening.log"

if [[ $MODE == apply ]]; then
  install -d -m 0700 "$BACKUP_DIR"
  touch "$LOG_FILE"
  chmod 0600 "$LOG_FILE"
  # Tee everything to log
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
  chmod "$mode" "$tmp"
  if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    ok "Already correct: $dest"
    return 0
  fi
  backup_file "$dest"
  install -o root -g root -m "$mode" "$tmp" "$dest"
  rm -f "$tmp"
  fixed "Updated: $dest"
}

printf '\n=== Fedora Security Hardening Ultimate v%s ===\n' "$VERSION"
printf 'Mode: %s | Date: %s | Host: %s | Kernel: %s\n' \
  "$MODE" "$(date -Is)" "$(hostname)" "$(uname -r)"
printf 'Desktop detected: %s\n' "$IS_DESKTOP"

if [[ $MODE == audit ]]; then
  info "Audit mode — no changes will be made. Use --apply to enforce."
fi

# ===========================================================================
# 1. Bootloader & Kernel Command Line
# ===========================================================================
section '1. Bootloader & Kernel Security Parameters'

# Core set (safe + high value)
KARGS_CORE=(
  slab_nomerge
  init_on_alloc=1
  init_on_free=1
  page_alloc.shuffle=1
  randomize_kstack_offset=on
  iommu=force
  iommu.strict=1
  iommu.passthrough=0
  pti=on
  vsyscall=none
  random.trust_cpu=off
  random.trust_bootloader=off
)

# Extra aggressive (may break some hardware / VMs)
KARGS_EXTRA=(
  spectre_v2=on
  spec_store_bypass_disable=on
  l1d_flush=on
  gather_data_sampling=force
  module.sig_enforce=1
  lockdown=confidentiality
)

if command -v grubby &>/dev/null; then
  # Remove rhgb quiet (information leak + slower recovery)
  if grubby --info=DEFAULT 2>/dev/null | grep -qE 'rhgb|quiet'; then
    if [[ $MODE == apply ]]; then
      grubby --update-kernel=ALL --remove-args="rhgb quiet" && \
        fixed "Removed rhgb quiet from kernel cmdline"
    else
      warn "rhgb/quiet present (will be removed with --apply)"
    fi
  else
    ok "rhgb/quiet already absent"
  fi

  current=$(grubby --info=DEFAULT 2>/dev/null || true)
  missing_args=()

  for arg in "${KARGS_CORE[@]}" "${KARGS_EXTRA[@]}"; do
    if grep -Fq -- "$arg" <<<"$current"; then
      ok "Kernel arg present: $arg"
    else
      warn "Missing kernel arg: $arg"
      missing_args+=("$arg")
    fi
  done

  if [[ $MODE == apply && ${#missing_args[@]} -gt 0 ]]; then
    joined_args=$(IFS=' '; echo "${missing_args[*]}")
    if grubby --update-kernel=ALL --args="$joined_args"; then
      fixed "Added missing kernel args: $joined_args"
    else
      fail "Failed to add missing kernel args"
    fi
  fi

  # Ensure /etc/kernel/cmdline is updated and persists all arguments for kernel-install
  if [[ $MODE == apply ]]; then
    all_current_args=$(grubby --info=DEFAULT 2>/dev/null | grep '^args=' | cut -d= -f2- | tr -d '"' || true)
    if [[ -n "$all_current_args" ]]; then
      echo "$all_current_args" > /etc/kernel/cmdline
      chmod 0600 /etc/kernel/cmdline
      fixed "Updated /etc/kernel/cmdline for kernel-install persistence"
    fi
  fi
else
  warn "grubby not found — skipping kernel args"
fi

# ===========================================================================
# 2. PackageKit / Polkit offline updates
# ===========================================================================
section '2. PackageKit offline-update restriction'

RULE_FILE="/etc/polkit-1/rules.d/99-disable-offline-update.rules"
EXPECTED_RULE='polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.packagekit.trigger-offline-update") {
        return polkit.Result.NO;
    }
});'

if [[ -f $RULE_FILE ]] && grep -q 'org.freedesktop.packagekit.trigger-offline-update' "$RULE_FILE"; then
  ok "Polkit offline-update rule already present"
elif [[ $MODE == apply ]]; then
  write_managed "$RULE_FILE" 0644 <<<"$EXPECTED_RULE"
  systemctl try-restart polkit 2>/dev/null || true
else
  warn "Polkit offline-update rule missing"
fi

# ===========================================================================
# 3. Systemd DefaultTimeoutStopSec
# ===========================================================================
section '3. Systemd DefaultTimeoutStopSec'

TIMEOUT_CONF="/etc/systemd/system.conf.d/99-timeout.conf"
if [[ -f $TIMEOUT_CONF ]] && grep -q 'DefaultTimeoutStopSec=3s' "$TIMEOUT_CONF"; then
  ok "DefaultTimeoutStopSec=3s already set"
elif [[ $MODE == apply ]]; then
  write_managed "$TIMEOUT_CONF" 0644 <<'EOF'
[Manager]
DefaultTimeoutStopSec=3s
DefaultTimeoutStartSec=10s
EOF
  systemctl daemon-reload
else
  warn "DefaultTimeoutStopSec not hardened"
fi

# ===========================================================================
# 4. Services & Packages reduction
# ===========================================================================
section '4. Services & Packages Reduction'

services_to_mask=(
  wsdd.service wsdd.socket
  gssproxy.service
  avahi-daemon.service avahi-daemon.socket
  # dnf5-daemon.service
  abrtd.service abrt-journal-core.service abrt-oops.service
  abrt-vmcore.service abrt-xorg.service
  iscsi.service iscsid.service iscsiuio.service
  livesys.service livesys-late.service
  flatpak-add-fedora-repos.service
  cups.service cups.socket cups.path
  pcscd.service
)

for srv in "${services_to_mask[@]}"; do
  if systemctl is-enabled --quiet "$srv" 2>/dev/null || \
     systemctl is-active  --quiet "$srv" 2>/dev/null; then
    if [[ $MODE == apply ]]; then
      systemctl disable --now "$srv" 2>/dev/null || true
      systemctl mask "$srv" 2>/dev/null || true
      fixed "Masked: $srv"
    else
      warn "Active/enabled: $srv"
    fi
  else
    ok "Already disabled/absent: $srv"
  fi
done

pkgs_to_remove=(wsdd psimon firefox)
for pkg in "${pkgs_to_remove[@]}"; do
  if rpm -q "$pkg" &>/dev/null; then
    if [[ $MODE == apply ]]; then
      dnf remove -y --no-autoremove "$pkg" 2>/dev/null || true
      fixed "Removed package: $pkg"
    else
      warn "Package present: $pkg"
    fi
  else
    ok "Package absent: $pkg"
  fi
done

# ===========================================================================
# 5. Name resolution (LLMNR / mDNS)
# ===========================================================================
section '5. LLMNR / mDNS Hardening'

RESOLVED_CONF="/etc/systemd/resolved.conf.d/99-nomdns.conf"
if [[ -f $RESOLVED_CONF ]] && grep -q 'LLMNR=no' "$RESOLVED_CONF"; then
  ok "systemd-resolved: LLMNR/MulticastDNS disabled"
elif [[ $MODE == apply ]]; then
  write_managed "$RESOLVED_CONF" 0644 <<'EOF'
[Resolve]
LLMNR=no
MulticastDNS=no
DNSOverTLS=opportunistic
EOF
  systemctl try-restart systemd-resolved 2>/dev/null || true
else
  warn "systemd-resolved LLMNR/mDNS not disabled"
fi

NM_CONF="/etc/NetworkManager/conf.d/99-no-mdns.conf"
if [[ -f $NM_CONF ]] && grep -q 'mdns=0' "$NM_CONF"; then
  ok "NetworkManager: mdns/llmnr disabled"
elif [[ $MODE == apply ]]; then
  write_managed "$NM_CONF" 0644 <<'EOF'
[connection]
mdns=0
llmnr=0
EOF
  systemctl try-restart NetworkManager 2>/dev/null || true
else
  warn "NetworkManager mdns/llmnr not disabled"
fi

# ===========================================================================
# 6. Bluetooth
# ===========================================================================
section '6. Bluetooth Hardening'

BT_CONF="/etc/bluetooth/main.conf"
if [[ -f $BT_CONF ]] && grep -qE '^[[:space:]]*AutoEnable[[:space:]]*=[[:space:]]*false' "$BT_CONF"; then
  ok "Bluetooth AutoEnable=false"
elif [[ $MODE == apply ]]; then
  backup_file "$BT_CONF"
  install -d -m 0755 /etc/bluetooth
  if [[ -f $BT_CONF ]]; then
    if grep -q 'AutoEnable=' "$BT_CONF"; then
      sed -i 's/^#\?[[:space:]]*AutoEnable=.*/AutoEnable=false/' "$BT_CONF"
    else
      sed -i '/^\[General\]/a AutoEnable=false' "$BT_CONF" || \
        printf '\n[General]\nAutoEnable=false\n' >> "$BT_CONF"
    fi
  else
    cat > "$BT_CONF" <<'EOF'
[General]
AutoEnable=false
EOF
  fi
  fixed "Bluetooth AutoEnable set to false"
  systemctl try-restart bluetooth 2>/dev/null || true
else
  warn "Bluetooth AutoEnable not disabled"
fi

# ===========================================================================
# 7. Firewalld
# ===========================================================================
section '7. Firewalld Hardening'

if command -v firewall-cmd &>/dev/null; then
  if ! systemctl is-active --quiet firewalld; then
    if [[ $MODE == apply ]]; then
      systemctl enable --now firewalld
      fixed "firewalld started and enabled"
    else
      warn "firewalld is not active"
    fi
  else
    ok "firewalld is active"
  fi

  if [[ $MODE == apply ]]; then
    # Public zone → DROP (very aggressive)
    firewall-cmd --permanent --zone=public --set-target=DROP 2>/dev/null || true
    firewall-cmd --permanent --zone=public --remove-service=mdns 2>/dev/null || true
    firewall-cmd --permanent --zone=public --remove-service=ssh 2>/dev/null || true

    if [[ $FORCE_SSH_KEEP == true ]]; then
      firewall-cmd --permanent --zone=public --add-service=ssh 2>/dev/null || true
      info "SSH kept in public zone (FORCE_SSH_KEEP=true)"
    else
      warn "!!! WARNING !!! SSH will be REMOVED from public zone."
      warn "Ensure you have console or out-of-band access before proceeding."
      read -rp "Type 'yes' to continue: " confirm
      [[ "$confirm" == "yes" ]] || die "Aborted by user."
    fi

    # WireGuard / VPN client zone
    if ! firewall-cmd --permanent --get-zones 2>/dev/null | grep -qw wireguard; then
      firewall-cmd --permanent --new-zone=wireguard >/dev/null
      fixed "Created firewalld zone: wireguard"
    fi
    firewall-cmd --permanent --zone=wireguard --set-target=DROP 2>/dev/null || true

    # Bind existing VPN interfaces (wg* and tun*)
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(wg|tun)[0-9]+$' || true); do
      cur=$(firewall-cmd --get-zone-of-interface="$iface" 2>/dev/null || true)
      if [[ $cur != wireguard ]]; then
        firewall-cmd --permanent --zone=wireguard --add-interface="$iface" 2>/dev/null || true
        fixed "Bound $iface → wireguard zone"
      else
        ok "$iface already in wireguard zone"
      fi
    done

    # Drop multicast on public + wireguard
    for zone in public wireguard; do
      firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule='rule family=ipv4 destination address=224.0.0.0/4 drop' 2>/dev/null || true
      firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule='rule family=ipv6 destination address=ff00::/8 drop' 2>/dev/null || true
    done

    firewall-cmd --reload >/dev/null
    fixed "firewalld rules reloaded"
  else
    info "firewalld hardening (DROP public, wireguard zone, multicast drop) will be applied with --apply"
  fi
else
  warn "firewall-cmd not installed"
fi

# ===========================================================================
# 8. Kernel Sysctl (secureblue-inspired + extra)
# ===========================================================================
section '8. Kernel Sysctl Hardening'

SYSCTL_FILE="/etc/sysctl.d/99-secure-fedora-hardening.conf"

SYSCTL_CONTENT=$(cat <<'SYSCTL_EOF'
# Network
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0
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
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# Kernel self-protection
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 3
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
kernel.kexec_load_disabled = 1
kernel.io_uring_disabled = 2
kernel.oops_limit = 100
kernel.warn_limit = 100
kernel.panic = -1

# Filesystem
fs.suid_dumpable = 0
fs.protected_regular = 2
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
# fs.binfmt_misc.status = 0

# Memory / ASLR
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
kernel.randomize_va_space = 2
kernel.core_pattern = |/bin/false
kernel.printk = 3 3 3 3
SYSCTL_EOF
)

if [[ $AGGRESSIVE_USERNS == true ]]; then
  SYSCTL_CONTENT+=$'\n# Aggressive: break Flatpak / rootless Podman\nuser.max_user_namespaces = 0\n'
fi

if [[ $MODE == apply ]]; then
  write_managed "$SYSCTL_FILE" 0644 <<<"$SYSCTL_CONTENT"

  # Capture only stderr (errors). "2>&1 >/dev/null" order is intentional.
  sysctl_err=$(sysctl --system 2>&1 >/dev/null || true)

  if [[ -z "$sysctl_err" ]]; then
    fixed "sysctl parameters applied cleanly"
  else
    # Extract offending key names from sysctl stderr
    mapfile -t failed_keys < <(
      printf '%s\n' "$sysctl_err" \
        | sed -nE '
            s/^.*setting key "([^"]+)".*$/\1/p;
            s|^.*cannot stat /proc/sys/([^:]+).*$|\1|p;
          ' \
        | tr '/' '.' \
        | sort -u
    )

    if (( ${#failed_keys[@]} == 0 )); then
      warn "sysctl --system reported errors (could not classify keys):"
      printf '%s\n' "$sysctl_err" | sed 's/^/          /'
    else
      warn "sysctl: ${#failed_keys[@]} parameter(s) not applied:"
      for k in "${failed_keys[@]}"; do
        cur=$(sysctl -n "$k" 2>/dev/null || true)
        if [[ -z "$cur" ]]; then
          info "  - $k"
          info "      -> NOT SUPPORTED by this kernel (benign; remove from $SYSCTL_FILE)"
        else
          info "  - $k"
          info "      -> current = $cur   (kernel refused write: value locked by earlier sysctl.d or already stricter)"
        fi
      done
      info "  Raw sysctl stderr:"
      printf '%s\n' "$sysctl_err" | sed 's/^/          /'
    fi
  fi
else
  if [[ -f $SYSCTL_FILE ]]; then
    ok "Sysctl hardening file exists"
  else
    warn "Sysctl hardening file missing"
  fi
fi

# Core dumps via limits
LIMITS_FILE="/etc/security/limits.d/99-nocore.conf"
if [[ -f $LIMITS_FILE ]] && grep -q 'hard core 0' "$LIMITS_FILE"; then
  ok "Core dumps disabled via limits"
elif [[ $MODE == apply ]]; then
  write_managed "$LIMITS_FILE" 0644 <<<"* hard core 0"$'\n'
else
  warn "Core dump limits not set"
fi

# ===========================================================================
# 9. Wi-Fi MAC randomization
# ===========================================================================
section '9. Wi-Fi MAC Address Randomization'

MAC_CONF="/etc/NetworkManager/conf.d/99-mac-rand.conf"
if [[ -f $MAC_CONF ]] && grep -q 'wifi.cloned-mac-address=random' "$MAC_CONF"; then
  ok "Wi-Fi MAC randomization enabled"
elif [[ $MODE == apply ]]; then
  write_managed "$MAC_CONF" 0644 <<'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
# ethernet.cloned-mac-address=random
EOF
  fixed "Wi-Fi + Ethernet MAC randomization enabled"
else
  warn "MAC randomization not configured"
fi

# ===========================================================================
# 10. Chrony + DNF timers
# ===========================================================================
section '10. Chrony & Automatic Update Timers'

if [[ -f /etc/chrony.conf ]]; then
  if grep -qxF 'port 0' /etc/chrony.conf && grep -qxF 'cmdport 0' /etc/chrony.conf; then
    ok "Chrony network ports closed"
  elif [[ $MODE == apply ]]; then
    backup_file /etc/chrony.conf
    grep -qxF 'port 0'    /etc/chrony.conf || echo 'port 0'    >> /etc/chrony.conf
    grep -qxF 'cmdport 0' /etc/chrony.conf || echo 'cmdport 0' >> /etc/chrony.conf
    systemctl try-restart chronyd 2>/dev/null || true
    fixed "Chrony ports closed (port 0 / cmdport 0)"
  else
    warn "Chrony still listens on network ports"
  fi
fi

for unit in dnf-makecache.timer packagekit.service fwupd-refresh.timer; do
  if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    if [[ $MODE == apply ]]; then
      systemctl disable --now "$unit" 2>/dev/null || true
      fixed "Disabled: $unit"
    else
      info "Timer/service enabled: $unit (can be disabled)"
    fi
  else
    ok "Already disabled: $unit"
  fi
done

# ===========================================================================
# 11. SELinux
# ===========================================================================
section '11. SELinux Enforcement'

if command -v getenforce &>/dev/null; then
  current=$(getenforce 2>/dev/null || echo Unknown)
  if [[ $current == Enforcing ]]; then
    ok "SELinux is Enforcing"
  elif [[ $MODE == apply ]]; then
    setenforce 1 2>/dev/null || true
    if [[ -f /etc/selinux/config ]]; then
      backup_file /etc/selinux/config
      sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    fi
    fixed "SELinux set to Enforcing"
  else
    warn "SELinux is $current (will be set to Enforcing)"
  fi
else
  warn "SELinux tools not found"
fi

# ===========================================================================
# 12. Kernel Module Blacklisting
# ===========================================================================
section '12. Kernel Module Blacklisting'

MODPROBE_FILE="/etc/modprobe.d/99-hardening-blacklist.conf"
MODPROBE_CONTENT=$(cat <<'MOD_EOF'
# Unused network protocols
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

# Legacy / rarely needed filesystems
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
# squashfs is used by live images and some containers — keep if needed
# install squashfs /bin/false

# Hardware that is rarely needed and increases attack surface
install firewire-core /bin/false
install floppy /bin/false
# install thunderbolt /bin/false   # uncomment if you don't use Thunderbolt
# install bluetooth /bin/false     # uncomment for maximum Bluetooth lockdown
MOD_EOF
)

if [[ -f $MODPROBE_FILE ]]; then
  ok "Module blacklist already exists"
elif [[ $MODE == apply ]]; then
  write_managed "$MODPROBE_FILE" 0644 <<<"$MODPROBE_CONTENT"
  fixed "Created kernel module blacklist"
else
  warn "Module blacklist missing"
fi

# ===========================================================================
# 13. Journald hardening
# ===========================================================================
section '13. Journald Hardening'

JOURNAL_CONF="/etc/systemd/journald.conf.d/99-hardening.conf"
if [[ -f $JOURNAL_CONF ]] && grep -q 'Storage=persistent' "$JOURNAL_CONF"; then
  ok "Journald hardening present"
elif [[ $MODE == apply ]]; then
  write_managed "$JOURNAL_CONF" 0644 <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
RuntimeMaxUse=100M
MaxFileSec=1month
ForwardToWall=no
EOF
  systemctl try-restart systemd-journald 2>/dev/null || true
  fixed "Journald hardened"
else
  warn "Journald not hardened"
fi

# ===========================================================================
# 14. DNF security defaults
# ===========================================================================
section '14. DNF Security Defaults'

DNF_CONF="/etc/dnf/dnf.conf"
if [[ -f $DNF_CONF ]]; then
  if grep -q '^gpgcheck=1' "$DNF_CONF" && grep -q '^localpkg_gpgcheck=1' "$DNF_CONF"; then
    ok "DNF gpgcheck already strict"
  elif [[ $MODE == apply ]]; then
    backup_file "$DNF_CONF"
    sed -i 's/^gpgcheck=.*/gpgcheck=1/' "$DNF_CONF" || echo 'gpgcheck=1' >> "$DNF_CONF"
    if ! grep -q '^localpkg_gpgcheck=' "$DNF_CONF"; then
      echo 'localpkg_gpgcheck=1' >> "$DNF_CONF"
    else
      sed -i 's/^localpkg_gpgcheck=.*/localpkg_gpgcheck=1/' "$DNF_CONF"
    fi
    fixed "DNF gpgcheck + localpkg_gpgcheck enforced"
  else
    warn "DNF gpg settings can be stricter"
  fi
fi

# ===========================================================================
# 15. Complete Telemetry & Metrics Blocking / Removal
# ===========================================================================
section '15. Telemetry & Metrics Removal'

telemetry_services=(
  eos-event-recorder-daemon.service
  metrics-collector.service
)

for srv in "${telemetry_services[@]}"; do
  if systemctl is-enabled --quiet "$srv" 2>/dev/null || \
     systemctl is-active  --quiet "$srv" 2>/dev/null; then
    if [[ $MODE == apply ]]; then
      systemctl disable --now "$srv" 2>/dev/null || true
      systemctl mask "$srv" 2>/dev/null || true
      fixed "Masked telemetry service: $srv"
    else
      warn "Active telemetry service found: $srv"
    fi
  else
    ok "Telemetry service absent or already disabled: $srv"
  fi
done

telemetry_pkgs=(
  eos-metrics
  eos-metrics-instrumentation
  eos-event-recorder-daemon
)

for pkg in "${telemetry_pkgs[@]}"; do
  if rpm -q "$pkg" &>/dev/null; then
    if [[ $MODE == apply ]]; then
      dnf remove -y --noautoremove "$pkg" 2>/dev/null || true
      fixed "Removed telemetry package: $pkg"
    else
      warn "Telemetry package present: $pkg"
    fi
  else
    ok "Telemetry package absent: $pkg"
  fi
done

# ===========================================================================
# 16. Optional GNOME Bloatware Removal
# ===========================================================================
section '16. Optional GNOME Bloatware Removal'

PURGE_GNOME_BLOAT=true
gnome_bloat_pkgs=(
  gnome-tour
  gnome-weather
  gnome-maps
  gnome-clocks
  gnome-contacts
  gnome-calendar
  gnome-characters
  evince
  cheese
  simple-scan
  yelp
  gnome-user-docs
  gnome-text-editor
  gnome-logs
)

if [[ $PURGE_GNOME_BLOAT == true ]]; then
  info "GNOME bloatware removal is enabled (PURGE_GNOME_BLOAT=true)"
  for pkg in "${gnome_bloat_pkgs[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
      if [[ $MODE == apply ]]; then
        dnf remove -y "$pkg" 2>/dev/null || true
        fixed "Removed GNOME app: $pkg"
      else
        warn "GNOME app present (will be removed): $pkg"
      fi
    else
      ok "GNOME app already absent: $pkg"
    fi
  done
else
  info "GNOME bloatware removal is skipped (set PURGE_GNOME_BLOAT=true in script to activate)"
fi

# ===========================================================================
# 17. Optional Software & Security Tools Deployment (Strict Flatpak / DNF)
# ===========================================================================
section '17. Optional Software Deployment'

INSTALL_OPTIONAL_SOFTWARE=true
dnf_apps=(
  htop
  mc
  zip
  unzip
  unrar-free
  curl 
  nvme-cli
  inxi
  smartmontools
  rclone
  ffmpeg-free 
  mediainfo
  cryptsetup
  nethogs
)
declare -A flatpak_apps=(
  [flatseal]="com.github.tchx84.Flatseal"
  [firefox]="org.mozilla.firefox"
  [filezilla]="org.filezillaproject.Filezilla"
  [keepassxc]="org.keepassxc.KeePassXC"
  [telegram]="org.telegram.desktop"
  [gimp]="org.gimp.GIMP"
  [qbittorrent]="org.qbittorrent.qBittorrent"
)

if [[ $INSTALL_OPTIONAL_SOFTWARE == true ]]; then
  info "Optional software deployment is enabled (INSTALL_OPTIONAL_SOFTWARE=true)"

  has_flatpak=false
  if command -v flatpak &>/dev/null; then
    has_flatpak=true
    if [[ $MODE == apply ]]; then
      flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo 2>/dev/null || true
    fi
  else
    warn "Flatpak is not installed on the system. Flatpak-targeted apps will be skipped."
  fi

  for name in "${!flatpak_apps[@]}"; do
    appid="${flatpak_apps[$name]}"
    
    if [[ $has_flatpak == true ]]; then
      if flatpak info "$appid" &>/dev/null; then
        ok "Already installed via Flatpak: $name ($appid)"
        continue
      elif rpm -q "$name" &>/dev/null; then
        warn "Package '$name' is installed via DNF, but target policy requires Flatpak. Skipping DNF duplicate."
        continue
      fi

      if [[ $MODE == apply ]]; then
        info "Installing via Flatpak: $appid..."
        if flatpak install -y flathub --noninteractive "$appid" 2>/dev/null; then
          fixed "Installed via Flatpak: $appid"
        else
          warn "Failed to install via Flatpak: $appid (check Flathub availability)"
        fi
      else
        warn "App will be installed via Flatpak: $appid (mode: audit)"
      fi
    else
      warn "Skipping Flatpak app '$name' because Flatpak is unavailable."
    fi
  done

  for pkg in "${dnf_apps[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
      ok "Already installed (DNF): $pkg"
    elif dnf info "$pkg" &>/dev/null; then
      if [[ $MODE == apply ]]; then
        if dnf install -y "$pkg" 2>/dev/null; then
          fixed "Installed via DNF: $pkg"
        else
          warn "Failed to install package via DNF: $pkg"
        fi
      else
        warn "Package available in DNF (will be installed): $pkg"
      fi
    else
      warn "Package not found in DNF: $pkg"
    fi
  done

else
  info "Optional software deployment is skipped (set INSTALL_OPTIONAL_SOFTWARE=true in script to activate)"
fi

# ===========================================================================
# 18. Hardened Malloc & Flatpak Sandbox Hardening (Secureblue-style Default)
# ===========================================================================
section '18. Hardened Malloc & Flatpak Sandbox Hardening'

INSTALL_HARDENED_MALLOC=true

if [[ $INSTALL_HARDENED_MALLOC == true ]]; then
  LIB_DEST="/usr/local/lib/libhardened_malloc.so"
  REPO_URL="https://github.com/GrapheneOS/hardened_malloc/archive/refs/heads/main.tar.gz"
  WORK_DIR="/var/tmp/hardened_malloc_build"
  HASH_FILE="/var/lib/hardened_malloc.sha256"

  # Определяем реального пользователя системы
  REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"

  # Проверка состояния в режиме аудита
  if [[ -f "$LIB_DEST" ]]; then
    ok "Hardened malloc library is present at $LIB_DEST"
  else
    warn "Hardened malloc library is missing at $LIB_DEST"
  fi

  if [[ $MODE == apply ]]; then
    info "Hardened malloc deployment enabled"

    if ! command -v make &>/dev/null || ! command -v gcc &>/dev/null || ! command -v g++ &>/dev/null; then
      warn "Build tools (make, gcc, gcc-c++) not found. Installing via DNF..."
      dnf install -y make gcc gcc-c++ glibc-devel 2>/dev/null || die "Failed to install build dependencies for hardened_malloc"
    fi

    install -d -m 0755 "$WORK_DIR"
    cd "$WORK_DIR"

    info "Downloading latest GrapheneOS hardened_malloc source..."
    if curl -sL "$REPO_URL" -o source.tar.gz; then
      NEW_HASH=$(sha256sum source.tar.gz | awk '{print $1}')
      OLD_HASH=""
      [[ -f "$HASH_FILE" ]] && OLD_HASH=$(cat "$HASH_FILE")

      if [[ "$NEW_HASH" != "$OLD_HASH" ]] || [[ ! -f "$LIB_DEST" ]]; then
        info "Building hardened_malloc from source..."
        tar -xzf source.tar.gz
        cd hardened_malloc-*
        
        make -j$(nproc) || die "Failed to compile hardened_malloc"
        
        install -d -m 0755 "$(dirname "$LIB_DEST")"
        install -m 0755 out/libhardened_malloc.so "$LIB_DEST"
        restorecon -v "$LIB_DEST" 2>/dev/null || true
        
        echo "$NEW_HASH" > "$HASH_FILE"
        fixed "hardened_malloc successfully built and updated at $LIB_DEST"
        
        cd "$WORK_DIR"
        rm -rf hardened_malloc-* source.tar.gz
      else
        ok "hardened_malloc is already up-to-date, compilation skipped."
      fi
    else
      warn "Failed to download hardened_malloc source from GitHub."
    fi
  else
    warn "Hardened malloc compilation pending (mode: audit)"
  fi

  # Настройка глобального системного дефолта (как в secureblue)
  if command -v flatpak &>/dev/null; then
    section '18.1. Flatpak Global System Defaults & Sandbox Hardening'

    if [[ $MODE == apply ]]; then
      info "Applying global system-wide Flatpak override for hardened_malloc..."
      # Прописываем глобально на уровне системы (--system). 
      # Это переживает сброс (Reset) в Flatseal для отдельных приложений.
      flatpak override --system --filesystem="$LIB_DEST":ro --env=LD_PRELOAD="$LIB_DEST"
      fixed "Global system Flatpak default set: LD_PRELOAD enabled for all apps."
    else
      info "Would apply global system Flatpak override for hardened_malloc (mode: audit)"
    fi

    # Аудит и ужесточение прав для уже установленных приложений
    mapfile -t installed_flatpaks < <(sudo -u "$REAL_USER" flatpak list --app --columns=application 2>/dev/null || true)
    
    if (( ${#installed_flatpaks[@]} > 0 )); then
      info "Auditing and enforcing strict sandbox defaults on ${#installed_flatpaks[@]} installed Flatpak app(s)..."
      
      for app in "${installed_flatpaks[@]}"; do
        app_info=$(sudo -u "$REAL_USER" flatpak info --show-permissions "$app" 2>/dev/null || true)
        
        has_x11=false
        has_host_fs=false
        has_full_device=false
        has_session_bus=false
        
        if grep -qE 'sockets=.*x11' <<< "$app_info"; then has_x11=true; fi
        if grep -qE 'filesystems=.*;host' <<< "$app_info" || grep -qE 'filesystems=full' <<< "$app_info"; then has_host_fs=true; fi
        if grep -qE 'devices=all' <<< "$app_info"; then has_full_device=true; fi
        if grep -qE 'sockets=.*session-bus' <<< "$app_info"; then has_session_bus=true; fi

        # Формируем команду для принудительного закрытия дыр по умолчанию
        enforce_cmd="flatpak override --user"
        [[ $has_x11 == true ]]         && enforce_cmd+=" --nosocket=x11"
        [[ $has_host_fs == true ]]     && enforce_cmd+=" --nofilesystem=host"
        [[ $has_full_device == true ]] && enforce_cmd+=" --nodevice=all"
        [[ $has_session_bus == true ]] && enforce_cmd+=" --nosocket=session-bus"
        enforce_cmd+=" $app"

        if [[ $MODE == apply ]]; then
          # Если у приложения были небезопасные права — принудительно забираем их (но пользователь сможет вернуть их в Flatseal при необходимости)
          if [[ $has_x11 == true || $has_host_fs == true || $has_full_device == true || $has_session_bus == true ]]; then
            eval "$enforce_cmd" 2>/dev/null || true
            fixed "Revoked risky broad permissions for: $app"
          fi
        else
          if [[ $has_x11 == true || $has_host_fs == true || $has_full_device == true || $has_session_bus == true ]]; then
            warn "App '$app' currently has broad permissions (will be restricted on --apply):"
            [[ $has_x11 == true ]]         && info "    - Uses X11 socket"
            [[ $has_host_fs == true ]]     && info "    - Host filesystem access"
            [[ $has_full_device == true ]] && info "    - Full device access"
            [[ $has_session_bus == true ]] && info "    - Session D-Bus access"
          else
            ok "App '$app': sandbox is isolated."
          fi
        fi
      done
    else
      info "No Flatpak apps currently installed to audit."
    fi
  else
    info "Flatpak is not installed; skipping Flatpak integration."
  fi

else
  info "Hardened malloc deployment is skipped (set INSTALL_HARDENED_MALLOC=true to activate)"
fi

# ===========================================================================
# Summary
# ===========================================================================
section 'Summary'

if [[ $MODE == apply ]]; then
  info "All requested changes have been applied."
  info "Backups stored in: $BACKUP_DIR"
  info "Full log written to: $LOG_FILE"
  info ""
  info "IMPORTANT: Reboot the system for kernel arguments and module blacklist to take full effect."
  info "After reboot verify with: grubby --info=DEFAULT  and  sysctl -a | grep -E 'yama|kptr|bpf'"
else
  info "Audit finished. No changes were made."
  info "To apply hardening:  sudo $0 --apply"
fi

echo