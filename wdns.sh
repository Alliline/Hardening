#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHITELIST_SOURCE="${WHITELIST_SOURCE:-$SCRIPT_DIR/whitelist.txt}"

WDNS_DIR="/etc/wdns-whitelist"
STATE_FILE="$WDNS_DIR/state.conf"
DOH_BLOCKLIST_FILE="$WDNS_DIR/doh-blocklist.txt"
DOH_IPSET_FILE="$WDNS_DIR/doh-ips.nft"

DNSMASQ_CONF_DIR="/etc/dnsmasq.d"
DNSMASQ_CONF_FILE="$DNSMASQ_CONF_DIR/90-wdns-whitelist.conf"
WHITELIST_TARGET="$WDNS_DIR/whitelist.txt"

NM_CONF_DIR="/etc/NetworkManager/conf.d"
NM_DNS_NONE_FILE="$NM_CONF_DIR/90-wdns-whitelist.conf"
NM_IPV6_DISABLE_FILE="$NM_CONF_DIR/90-wdns-disable-ipv6.conf"

RESOLVED_DROPIN_DIR="/etc/systemd/resolved.conf.d"
RESOLVED_STUB_DROPIN="$RESOLVED_DROPIN_DIR/90-wdns-disable-stub.conf"

SYSCTL_FILE="/etc/sysctl.d/90-wdns-disable-ipv6.conf"

RESOLV_CONF="/etc/resolv.conf"
RESOLV_CONF_BACKUP="/etc/resolv.conf.wdns-backup"

DNSMASQ_SERVICE="dnsmasq.service"
RESOLVED_SERVICE="systemd-resolved.service"
NM_SERVICE="NetworkManager.service"
WDNS_NFT_SERVICE="wdns-nftables.service"
WDNS_ENSURE_SERVICE="wdns-ensure.service"
WDNS_NFT_FILE="$WDNS_DIR/wdns-output-filter.nft"
WDNS_NFT_APPLY="$WDNS_DIR/apply-nft.sh"
WDNS_NFT_FLUSH="$WDNS_DIR/flush-nft.sh"
WDNS_ENSURE_SCRIPT="$WDNS_DIR/ensure.sh"

# IPv4 loopback only. IPv6 is fully disabled.
LISTEN_ADDRESSES="127.0.0.1"
DEFAULT_DNS_SERVERS="${DEFAULT_DNS_SERVERS:-1.1.1.1,1.0.0.1}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $*"; }
err()  { echo -e "${RED}[$(date +%H:%M:%S)]${NC} $*" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Run with sudo"
    exit 1
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Command not found: $1"
    exit 1
  }
}

validate_domain() {
  local domain="$1"
  local len=${#domain}

  [[ -z "$domain" || $len -gt 253 ]] && return 1
  [[ "$domain" == .* || "$domain" == *. || "$domain" == -* || "$domain" == *- ]] && return 1
  [[ "$domain" == *..* ]] && return 1
  [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] || return 1

  local label
  IFS='.' read -ra labels <<< "$domain"
  for label in "${labels[@]}"; do
    [[ ${#label} -gt 63 || ${#label} -eq 0 ]] && return 1
  done
  return 0
}

validate_dns_server() {
  local value="$1"
  if [[ "$value" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]}
    (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )) && return 0
  fi
  return 1
}

ensure_paths() {
  mkdir -p "$WDNS_DIR" "$DNSMASQ_CONF_DIR" "$NM_CONF_DIR" "$RESOLVED_DROPIN_DIR"
  chmod 0700 "$WDNS_DIR"
}

backup_resolv_conf_once() {
  if [[ ! -e "$RESOLV_CONF_BACKUP" && -e "$RESOLV_CONF" ]]; then
    cp -a "$RESOLV_CONF" "$RESOLV_CONF_BACKUP" || true
    log "Saved backup $RESOLV_CONF -> $RESOLV_CONF_BACKUP"
  fi
}

write_default_doh_blocklist() {
  cat > "$DOH_BLOCKLIST_FILE" <<'EOF_DOH'
# Major public DoH / DoT / ODoH endpoints
cloudflare-dns.com
mozilla.cloudflare-dns.com
chrome.cloudflare-dns.com
dns.google
dns.google.com
dns.adguard-dns.com
dns.adguard.com
doh.opendns.com
familyshield.opendns.com
dns.quad9.net
doh.quad9.net
security.cloudflare-dns.com
family.cloudflare-dns.com
one.one.one.one
odoh.cloudflare-dns.com
mask.icloud.com
mask-h2.icloud.com
doh.dns.sb
doh.cleanbrowsing.org
dns.nextdns.io
doh.mullvad.net
dns.controld.com
zero.dns0.eu
doh.dns.apple.com
doh.sb
dns.sb
common.dot.dns.apple.com
doh.pub
dns.alidns.com
doh.pub.cloudflare-dns.com
ordns.he.net
dns.switch.ch
doh.switch.ch
dns.digitale-gesellschaft.ch
doh.digitale-gesellschaft.ch
dns.twnic.tw
doh.twnic.tw
EOF_DOH
  chmod 0644 "$DOH_BLOCKLIST_FILE"
}

write_doh_ip_set() {
  cat > "$DOH_IPSET_FILE" <<'EOF_IPS'
# Cloudflare
1.1.1.1
1.0.0.1
1.1.1.2
1.0.0.2
1.1.1.3
1.0.0.3
104.16.248.249
104.16.249.249
# Google
8.8.8.8
8.8.4.4
# Quad9
9.9.9.9
149.112.112.112
# AdGuard
94.140.14.14
94.140.15.15
94.140.14.15
94.140.15.16
# NextDNS
45.90.28.0/24
45.90.30.0/24
# OpenDNS
208.67.222.222
208.67.220.220
# Mullvad
194.242.2.2
194.242.2.3
# Control D
76.76.2.0
76.76.10.0
# dns0.eu
193.110.81.0
185.253.5.0
EOF_IPS
  chmod 0644 "$DOH_IPSET_FILE"
}

write_state() {
  local dns_servers="$1"
  cat > "$STATE_FILE" <<EOF_STATE
DNS_SERVERS="$dns_servers"
EOF_STATE
  chmod 0600 "$STATE_FILE"
}

load_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    err "State file not found: $STATE_FILE. Run apply first"
    exit 1
  fi
  DNS_SERVERS="$(grep -E '^DNS_SERVERS=' "$STATE_FILE" | cut -d= -f2- | tr -d '"' || true)"
  if [[ -z "${DNS_SERVERS:-}" ]]; then
    err "Failed to read DNS_SERVERS from $STATE_FILE"
    exit 1
  fi
}

reset_nm_connections_dns() {
  local conn
  while IFS= read -r conn; do
    [[ -z "$conn" ]] && continue
    if nmcli -g connection.type connection show "$conn" 2>/dev/null | grep -qE 'loopback|bridge|bond|team|vlan'; then
      continue
    fi
    nmcli connection modify "$conn" \
      ipv4.ignore-auto-dns no \
      ipv4.dns "" \
      ipv4.dns-priority 0 \
      ipv6.method auto \
      ipv6.ignore-auto-dns no \
      ipv6.dns "" 2>/dev/null || true
  done < <(nmcli -g NAME connection show 2>/dev/null || true)
}

force_nm_connections_dns() {
  local conn
  while IFS= read -r conn; do
    [[ -z "$conn" ]] && continue
    if nmcli -g connection.type connection show "$conn" 2>/dev/null | grep -qE 'loopback|bridge|bond|team|vlan'; then
      continue
    fi
    nmcli connection modify "$conn" \
      ipv4.ignore-auto-dns yes \
      ipv4.dns "127.0.0.1" \
      ipv4.dns-priority -1 \
      ipv6.method disabled \
      ipv6.ignore-auto-dns yes \
      ipv6.dns "" 2>/dev/null || true
    log "NM connection «$conn»: DNS → 127.0.0.1 (ignore-auto-dns)"
  done < <(nmcli -g NAME connection show 2>/dev/null || true)

  local active
  while IFS= read -r active; do
    [[ -z "$active" ]] && continue
    nmcli connection up "$active" 2>/dev/null || true
  done < <(nmcli -g NAME connection show --active 2>/dev/null || true)
}

disable_ipv6_permanently() {
  cat > "$SYSCTL_FILE" <<'EOF_SYSCTL'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF_SYSCTL
  sysctl --system >/dev/null 2>&1 || true

  cat > "$NM_IPV6_DISABLE_FILE" <<'EOF_NM_IPV6'
[ipv6]
method=disabled
EOF_NM_IPV6
  chmod 0644 "$NM_IPV6_DISABLE_FILE"

  if command -v grubby >/dev/null 2>&1; then
    if ! grubby --info=ALL 2>/dev/null | grep -q 'ipv6.disable=1'; then
      grubby --update-kernel=ALL --args="ipv6.disable=1" 2>/dev/null || true
      warn "Added kernel parameter ipv6.disable=1 (reboot required for full effect)"
    fi
  fi

  log "IPv6 disabled (sysctl + NetworkManager + kernel param)"
}

configure_networkmanager_static_resolv() {
  cat > "$NM_DNS_NONE_FILE" <<'EOF_NM'
[main]
dns=none
systemd-resolved=false
rc-manager=unmanaged
EOF_NM
  chmod 0644 "$NM_DNS_NONE_FILE"

  chattr -i "$RESOLV_CONF" 2>/dev/null || true
  rm -f "$RESOLV_CONF"
  cat > "$RESOLV_CONF" <<'EOF_RESOLV'
# generated by wdns — IPv4 only
nameserver 127.0.0.1
options edns0 trust-ad
EOF_RESOLV
  chmod 0644 "$RESOLV_CONF"
  chattr +i "$RESOLV_CONF" 2>/dev/null || true

  log "NetworkManager: dns=none; /etc/resolv.conf → 127.0.0.1 (immutable)"

  force_nm_connections_dns
}

configure_resolved_for_no_conflict() {
  cat > "$RESOLVED_STUB_DROPIN" <<'EOF_RESOLVED'
[Resolve]
DNSStubListener=no
DNS=
FallbackDNS=
EOF_RESOLVED
  chmod 0644 "$RESOLVED_STUB_DROPIN"

  systemctl restart "$RESOLVED_SERVICE" >/dev/null 2>&1 || true
  systemctl stop systemd-resolved-stub.socket 2>/dev/null || true
  systemctl stop systemd-resolved.socket 2>/dev/null || true
  systemctl disable systemd-resolved-stub.socket >/dev/null 2>&1 || true
  systemctl disable systemd-resolved.socket >/dev/null 2>&1 || true

  local i
  for i in {1..15}; do
    if ! ss -lntup 2>/dev/null | grep -qE '127\.0\.0\.(1|53):53\b'; then
      break
    fi
    sleep 0.3
  done

  log "systemd-resolved: stub listener disabled"
}

build_dnsmasq_config() {
  local dns_servers_csv="$1"
  local dnsmasq_tmp="$WDNS_DIR/dnsmasq.generated.conf"
  local doh_count=0 allowed=0 blocked=0 invalid=0
  local line trimmed domain server

  [[ -f "$WHITELIST_SOURCE" ]] || { err "Whitelist not found: $WHITELIST_SOURCE"; exit 1; }

  cat > "$dnsmasq_tmp" <<EOF_DNSMASQ
# Generated by wdns — whitelist only, everything else REFUSED
listen-address=${LISTEN_ADDRESSES}
interface=lo
bind-interfaces
no-resolv
no-hosts
cache-size=2000
neg-ttl=60
strict-order
domain-needed
bogus-priv
EOF_DNSMASQ

  IFS=',' read -ra DNS_SERVERS_ARR <<< "$dns_servers_csv"
  for server in "${DNS_SERVERS_ARR[@]}"; do
    server="$(echo "$server" | xargs)"
    [[ -z "$server" ]] && continue
    if ! validate_dns_server "$server"; then
      err "Invalid DNS server (IPv4 only): $server"
      exit 1
    fi
  done

  while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed="${line%%#*}"
    trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [[ -z "$trimmed" ]] && continue

    if [[ "$trimmed" == '!'* ]]; then
      domain="${trimmed#!}"
      if validate_domain "$domain"; then
        echo "server=/$domain/" >> "$dnsmasq_tmp"
        blocked=$((blocked + 1))
      else
        warn "Skipped invalid blocked domain: $domain"
        invalid=$((invalid + 1))
      fi
      continue
    fi

    domain="$trimmed"
    if validate_domain "$domain"; then
      for server in "${DNS_SERVERS_ARR[@]}"; do
        server="$(echo "$server" | xargs)"
        [[ -z "$server" ]] && continue
        echo "server=/$domain/$server" >> "$dnsmasq_tmp"
      done
      allowed=$((allowed + 1))
    else
      warn "Skipped invalid domain: $domain"
      invalid=$((invalid + 1))
    fi
  done < "$WHITELIST_SOURCE"

  while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed="${line%%#*}"
    trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [[ -z "$trimmed" ]] && continue
    if validate_domain "$trimmed"; then
      echo "server=/$trimmed/" >> "$dnsmasq_tmp"
      doh_count=$((doh_count + 1))
    fi
  done < "$DOH_BLOCKLIST_FILE"

  install -m 0644 "$dnsmasq_tmp" "$DNSMASQ_CONF_FILE"
  install -m 0644 "$WHITELIST_SOURCE" "$WHITELIST_TARGET"
  rm -f "$dnsmasq_tmp"

  if ! dnsmasq --test; then
    err "dnsmasq configuration test failed"
    exit 1
  fi

  systemctl enable "$DNSMASQ_SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$DNSMASQ_SERVICE"

  local ready=0
  local i
  for i in {1..30}; do
    if ss -lntup 2>/dev/null | grep -qE '127\.0\.0\.1:53\b'; then
      ready=1
      break
    fi
    sleep 0.5
  done
  if [[ $ready -ne 1 ]]; then
    err "dnsmasq is not listening on 127.0.0.1:53 after restart"
    systemctl --no-pager -l status "$DNSMASQ_SERVICE" || true
    journalctl -u "$DNSMASQ_SERVICE" -n 30 --no-pager 2>/dev/null || true
    exit 1
  fi

  log "dnsmasq: Allowed=$allowed, Explicit-block=$blocked, DoH-domains=$doh_count, Invalid=$invalid (REFUSED mode)"
}

render_nft_rules() {
  local dnsmasq_uid
  dnsmasq_uid="$(id -u dnsmasq 2>/dev/null || true)"
  if [[ -z "$dnsmasq_uid" ]]; then
    err "User 'dnsmasq' not found. Install the dnsmasq package."
    exit 1
  fi

  local ip_elements=""
  while IFS= read -r ip || [[ -n "$ip" ]]; do
    ip="$(echo "$ip" | sed 's/[[:space:]]*#.*$//' | xargs || true)"
    [[ -z "$ip" ]] && continue
    if [[ "$ip" =~ ^[0-9./]+$ ]]; then
      ip_elements+=" $ip,"
    fi
  done < "$DOH_IPSET_FILE"
  ip_elements="${ip_elements%,}"

  cat > "$WDNS_NFT_FILE" <<EOF_NFT
table inet wdns_whitelist {
  set doh_ips {
    type ipv4_addr
    flags interval
    elements = { ${ip_elements} }
  }

  chain output {
    type filter hook output priority 0; policy accept;

    ct state established,related accept
    oifname "lo" accept

    meta skuid $dnsmasq_uid udp dport 53 accept
    meta skuid $dnsmasq_uid tcp dport 53 accept
    meta skuid $dnsmasq_uid tcp dport 853 accept

    udp dport 53 drop
    tcp dport 53 drop
    tcp dport 853 drop
    udp dport 853 drop

    ip daddr @doh_ips tcp dport 443 drop
    ip daddr @doh_ips udp dport 443 drop
  }
}
EOF_NFT
  chmod 0644 "$WDNS_NFT_FILE"
}

write_nft_helper_scripts() {
  cat > "$WDNS_NFT_APPLY" <<EOF_APPLY
#!/usr/bin/env bash
set -euo pipefail
nft delete table inet wdns_whitelist 2>/dev/null || true
nft -f "$WDNS_NFT_FILE"
EOF_APPLY

  cat > "$WDNS_NFT_FLUSH" <<'EOF_FLUSH'
#!/usr/bin/env bash
set -euo pipefail
/usr/sbin/nft delete table inet wdns_whitelist 2>/dev/null || true
EOF_FLUSH

  chmod 0755 "$WDNS_NFT_APPLY" "$WDNS_NFT_FLUSH"
}

write_ensure_script() {
  cat > "$WDNS_ENSURE_SCRIPT" <<'EOF_ENSURE'
#!/usr/bin/env bash
set -euo pipefail

WDNS_DIR="/etc/wdns-whitelist"
RESOLV_CONF="/etc/resolv.conf"
DNSMASQ_SERVICE="dnsmasq.service"
WDNS_NFT_FILE="$WDNS_DIR/wdns-output-filter.nft"
WDNS_NFT_APPLY="$WDNS_DIR/apply-nft.sh"

log() { echo "[wdns-ensure] $*"; }

# Ensure resolv.conf points to local dnsmasq and is immutable
chattr -i "$RESOLV_CONF" 2>/dev/null || true
if [[ ! -f "$RESOLV_CONF" ]] || ! grep -q 'nameserver 127.0.0.1' "$RESOLV_CONF" 2>/dev/null; then
  cat > "$RESOLV_CONF" <<'EOF_RESOLV'
# generated by wdns — IPv4 only
nameserver 127.0.0.1
options edns0 trust-ad
EOF_RESOLV
  chmod 0644 "$RESOLV_CONF"
fi
chattr +i "$RESOLV_CONF" 2>/dev/null || true

# Force DNS settings on all relevant NM connections
if command -v nmcli >/dev/null 2>&1; then
  while IFS= read -r conn; do
    [[ -z "$conn" ]] && continue
    if nmcli -g connection.type connection show "$conn" 2>/dev/null | grep -qE 'loopback|bridge|bond|team|vlan'; then
      continue
    fi
    nmcli connection modify "$conn" \
      ipv4.ignore-auto-dns yes \
      ipv4.dns "127.0.0.1" \
      ipv4.dns-priority -1 \
      ipv6.method disabled \
      ipv6.ignore-auto-dns yes \
      ipv6.dns "" 2>/dev/null || true
  done < <(nmcli -g NAME connection show 2>/dev/null || true)
fi

# Ensure dnsmasq is running and listening
systemctl start "$DNSMASQ_SERVICE" 2>/dev/null || true
if ! ss -lntup 2>/dev/null | grep -qE '127\.0\.0\.1:53\b'; then
  systemctl restart "$DNSMASQ_SERVICE" 2>/dev/null || true
  sleep 1
fi

# Ensure nftables table is present
if ! nft list table inet wdns_whitelist >/dev/null 2>&1; then
  if [[ -x "$WDNS_NFT_APPLY" && -f "$WDNS_NFT_FILE" ]]; then
    "$WDNS_NFT_APPLY" || true
  fi
fi

log "ensure completed"
EOF_ENSURE
  chmod 0755 "$WDNS_ENSURE_SCRIPT"
}

write_wdns_nft_service() {
  cat > "/etc/systemd/system/$WDNS_NFT_SERVICE" <<EOF_UNIT
[Unit]
Description=WDNS host output nftables restrictions
After=network-pre.target
Before=NetworkManager.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=$WDNS_NFT_APPLY
ExecStop=$WDNS_NFT_FLUSH
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_UNIT
  chmod 0644 "/etc/systemd/system/$WDNS_NFT_SERVICE"
}

write_wdns_ensure_service() {
  cat > "/etc/systemd/system/$WDNS_ENSURE_SERVICE" <<EOF_UNIT
[Unit]
Description=WDNS post-NetworkManager ensure (resolv.conf, DNS, nft, dnsmasq)
After=NetworkManager.service dnsmasq.service
Wants=NetworkManager.service

[Service]
Type=oneshot
ExecStart=$WDNS_ENSURE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_UNIT
  chmod 0644 "/etc/systemd/system/$WDNS_ENSURE_SERVICE"
}

apply_firewall() {
  write_doh_ip_set
  render_nft_rules
  write_nft_helper_scripts
  write_wdns_nft_service
  systemctl daemon-reload
  systemctl enable "$WDNS_NFT_SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$WDNS_NFT_SERVICE"
  log "nftables rules (including known DoH IP blocking) applied"
}

cleanup_previous() {
  log "Cleaning previous wdns state for clean re-apply..."

  systemctl stop "$WDNS_ENSURE_SERVICE" 2>/dev/null || true
  systemctl stop "$WDNS_NFT_SERVICE" 2>/dev/null || true
  systemctl stop "$DNSMASQ_SERVICE" 2>/dev/null || true

  chattr -i "$RESOLV_CONF" 2>/dev/null || true

  rm -f "$DNSMASQ_CONF_FILE" \
        "$NM_DNS_NONE_FILE" \
        "$NM_IPV6_DISABLE_FILE" \
        "$RESOLVED_STUB_DROPIN" \
        "$SYSCTL_FILE" \
        "/etc/systemd/system/$WDNS_NFT_SERVICE" \
        "/etc/systemd/system/$WDNS_ENSURE_SERVICE"

  /usr/sbin/nft delete table inet wdns_whitelist 2>/dev/null || true

  reset_nm_connections_dns

  systemctl daemon-reload >/dev/null 2>&1 || true
}

apply_all() {
  local dns_servers_csv="${1:-$DEFAULT_DNS_SERVERS}"

  require_root
  require_cmd dnsmasq
  require_cmd nft
  require_cmd systemctl
  require_cmd ss
  require_cmd nmcli

  cleanup_previous
  ensure_paths
  backup_resolv_conf_once
  write_default_doh_blocklist
  disable_ipv6_permanently
  configure_resolved_for_no_conflict

  write_state "$dns_servers_csv"

  build_dnsmasq_config "$dns_servers_csv"

  configure_networkmanager_static_resolv
  systemctl restart "$NM_SERVICE" >/dev/null 2>&1 || true
  sleep 1
  force_nm_connections_dns

  apply_firewall

  write_ensure_script
  write_wdns_ensure_service
  systemctl daemon-reload
  systemctl enable "$WDNS_ENSURE_SERVICE" >/dev/null 2>&1 || true
  systemctl start "$WDNS_ENSURE_SERVICE" >/dev/null 2>&1 || true

  log "Done. Host is now in DNS whitelist mode (stone castle)."
  log "Reboot is recommended so that ipv6.disable=1 takes full effect."
}

update_whitelist() {
  require_root
  load_state
  require_cmd dnsmasq
  require_cmd nft

  build_dnsmasq_config "$DNS_SERVERS"
  apply_firewall

  if [[ -x "$WDNS_ENSURE_SCRIPT" ]]; then
    "$WDNS_ENSURE_SCRIPT" || true
  fi

  log "Configuration updated successfully."
}

restore_defaults() {
  require_root

  chattr -i "$RESOLV_CONF" 2>/dev/null || true

  systemctl stop "$WDNS_ENSURE_SERVICE" >/dev/null 2>&1 || true
  systemctl disable "$WDNS_ENSURE_SERVICE" >/dev/null 2>&1 || true
  systemctl stop "$WDNS_NFT_SERVICE" >/dev/null 2>&1 || true
  systemctl disable "$WDNS_NFT_SERVICE" >/dev/null 2>&1 || true

  rm -f "$DNSMASQ_CONF_FILE" \
        "$NM_DNS_NONE_FILE" \
        "$NM_IPV6_DISABLE_FILE" \
        "$RESOLVED_STUB_DROPIN" \
        "$SYSCTL_FILE" \
        "/etc/systemd/system/$WDNS_NFT_SERVICE" \
        "/etc/systemd/system/$WDNS_ENSURE_SERVICE"

  rm -rf "$WDNS_DIR"

  systemctl daemon-reload >/dev/null 2>&1 || true

  /usr/sbin/nft delete table inet wdns_whitelist 2>/dev/null || true

  systemctl stop "$DNSMASQ_SERVICE" >/dev/null 2>&1 || true
  systemctl disable "$DNSMASQ_SERVICE" >/dev/null 2>&1 || true

  if [[ -e "$RESOLV_CONF_BACKUP" ]]; then
    rm -f "$RESOLV_CONF"
    cp -a "$RESOLV_CONF_BACKUP" "$RESOLV_CONF"
    log "Restored /etc/resolv.conf from backup"
  else
    rm -f "$RESOLV_CONF"
  fi

  if command -v grubby >/dev/null 2>&1; then
    grubby --update-kernel=ALL --remove-args="ipv6.disable=1" 2>/dev/null || true
  fi

  sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true

  reset_nm_connections_dns

  systemctl enable "$RESOLVED_SERVICE" >/dev/null 2>&1 || true
  systemctl start "$RESOLVED_SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$NM_SERVICE" >/dev/null 2>&1 || true

  log "Stock network and DNS settings restored."
  log "A reboot may be required for full IPv6 restoration."
}

show_status() {
  if [[ -f "$STATE_FILE" ]]; then
    load_state
  fi

  echo "=== state ==="
  [[ -f "$STATE_FILE" ]] && cat "$STATE_FILE" || echo "not configured"
  echo

  echo "=== /etc/resolv.conf ==="
  ls -l "$RESOLV_CONF" 2>/dev/null || true
  [[ -f "$RESOLV_CONF" || -L "$RESOLV_CONF" ]] && { echo; sed -n '1,20p' "$RESOLV_CONF" 2>/dev/null || true; }
  echo

  echo "=== NetworkManager DNS mode ==="
  [[ -f "$NM_DNS_NONE_FILE" ]] && cat "$NM_DNS_NONE_FILE" || echo "wdns conf absent"
  echo

  echo "=== IPv6 status ==="
  sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null || true
  ip -6 addr show 2>/dev/null | head -5 || echo "(no IPv6 addresses)"
  echo

  echo "=== systemd-resolved ==="
  systemctl --no-pager --full status "$RESOLVED_SERVICE" 2>/dev/null | sed -n '1,12p' || true
  echo

  echo "=== dnsmasq ==="
  systemctl --no-pager --full status "$DNSMASQ_SERVICE" 2>/dev/null | sed -n '1,12p' || true
  echo

  echo "=== wdns-nftables ==="
  systemctl --no-pager --full status "$WDNS_NFT_SERVICE" 2>/dev/null | sed -n '1,12p' || true
  echo

  echo "=== wdns-ensure ==="
  systemctl --no-pager --full status "$WDNS_ENSURE_SERVICE" 2>/dev/null | sed -n '1,12p' || true
  echo

  echo "=== port 53 listeners ==="
  ss -lntup 2>/dev/null | grep -E ':53\b' || echo "(none)"
  echo

  echo "=== nftables rules (summary) ==="
  nft list table inet wdns_whitelist 2>/dev/null | head -40 || echo "table inet wdns_whitelist absent"
}

usage() {
  cat <<EOF
Usage:
  sudo $0 apply [DNS1,DNS2]    - Initial install / apply (IPv4 only)
  sudo $0 update               - Update configuration after editing whitelist.txt
  sudo $0 status               - Show current status
  sudo $0 restore              - Restore stock network/DNS settings

Whitelist format (whitelist.txt):
  example.com          # allow
  !bad.example.com     # explicitly block (REFUSED)
  # comment

Everything not listed in the whitelist → REFUSED.
IPv6 is fully disabled.
DoH/DoT: domains blocked in dnsmasq, known IPs blocked in nftables.
EOF
  exit 1
}

case "${1:-}" in
  apply)     apply_all "${2:-}" ;;
  update)    update_whitelist ;;
  status)    show_status ;;
  restore)   restore_defaults ;;
  *)         usage ;;
esac