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
NM_DISPATCHER_SCRIPT="/etc/NetworkManager/dispatcher.d/90-wdns-force-dns"

# --- Per-app DoH bypass (opt-in via: bypass-setup) ---
# Идентификация приложения — по GID (nft: meta skgid). Приложение запускается
# через `sg wdns-bypass`; для этой группы открыт ТОЛЬКО tcp/443 на IP из
# BYPASS_IPS_FILE. Порты 53/853 и остальные DoH-IP для неё остаются закрытыми.
BYPASS_GROUP="wdns-bypass"
BYPASS_IPS_FILE="$WDNS_DIR/bypass-doh-ips.txt"
BYPASS_APP_ID="${BYPASS_APP_ID:-io.gitlab.librewolf-community}"
BYPASS_DOH_URI="${BYPASS_DOH_URI:-https://1.1.1.1/dns-query}"
BYPASS_LAUNCHER="/usr/local/bin/wdns-bypass-librewolf"
BYPASS_DESKTOP_NAME="wdns-bypass-librewolf.desktop"

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

validate_ipv4() { validate_dns_server "$1"; }

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

  local dev
  while IFS= read -r dev; do
    [[ -z "$dev" ]] && continue
    nmcli device reapply "$dev" 2>/dev/null || true
  done < <(nmcli -t -f DEVICE,STATE device status 2>/dev/null | grep ':connected' | cut -d: -f1 || true)
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
    grubby --update-kernel=ALL --args="ipv6.disable=1" 2>/dev/null || true
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
  # Важный момент: DNS=127.0.0.1
  # На Fedora nsswitch предпочитает модуль «resolve» (systemd-resolved).
  # Если у resolved нет upstream — curl/getaddrinfo падают,
  # даже когда dig @127.0.0.1 и dnsmasq работают.
  # Мы оставляем resolved живым, но заставляем его ходить только в dnsmasq.
  cat > "$RESOLVED_STUB_DROPIN" <<'EOF_RESOLVED'
[Resolve]
DNSStubListener=no
DNS=127.0.0.1
FallbackDNS=
Domains=
DNSSEC=no
DNSOverTLS=no
EOF_RESOLVED
  chmod 0644 "$RESOLVED_STUB_DROPIN"

  # Neutralize distro tmpfiles rule that would re-symlink /etc/resolv.conf
  # at boot (overrides /usr/lib/tmpfiles.d/systemd-resolve.conf).
  : > /etc/tmpfiles.d/systemd-resolve.conf
  chmod 0644 /etc/tmpfiles.d/systemd-resolve.conf

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

  log "systemd-resolved: stub disabled, upstream → 127.0.0.1 (dnsmasq)"
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
  if [[ -f "$WHITELIST_SOURCE" ]]; then
    install -m 0644 "$WHITELIST_SOURCE" "$WHITELIST_TARGET"
  fi
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

  # --- bypass: активен только если группа существует и есть валидные IP ---
  local bypass_gid bypass_elements="" bypass_set_block="" bypass_rule="" bip
  bypass_gid="$(getent group "$BYPASS_GROUP" 2>/dev/null | cut -d: -f3 || true)"
  if [[ -n "$bypass_gid" && -f "$BYPASS_IPS_FILE" ]]; then
    while IFS= read -r bip || [[ -n "$bip" ]]; do
      bip="$(echo "$bip" | sed 's/[[:space:]]*#.*$//' | xargs || true)"
      [[ -z "$bip" ]] && continue
      if validate_ipv4 "$bip"; then
        bypass_elements+=" $bip,"
      else
        warn "Skipped invalid bypass IP: $bip"
      fi
    done < "$BYPASS_IPS_FILE"
    bypass_elements="${bypass_elements%,}"
  fi
  if [[ -n "$bypass_gid" && -n "$bypass_elements" ]]; then
    bypass_set_block=$'  set bypass_doh_ips {\n    type ipv4_addr\n    elements = {'"$bypass_elements"$' }\n  }\n'
    bypass_rule=$'    # Per-app DoH bypass: только группа '"$BYPASS_GROUP"$', только tcp/443 на выбранные IP\n    meta skgid '"$bypass_gid"$' ip daddr @bypass_doh_ips tcp dport 443 counter accept\n\n'
    log "nftables: DoH bypass enabled for group $BYPASS_GROUP (gid $bypass_gid)"
  fi

  cat > "$WDNS_NFT_FILE" <<EOF_NFT
table inet wdns_whitelist {
  set doh_ips {
    type ipv4_addr
    flags interval
    elements = { ${ip_elements} }
  }
${bypass_set_block}
  chain output {
    type filter hook output priority 0; policy accept;

    ct state established,related accept
    oifname "lo" accept

    meta skuid $dnsmasq_uid udp dport 53 accept
    meta skuid $dnsmasq_uid tcp dport 53 accept
    meta skuid $dnsmasq_uid tcp dport 853 accept

    # Разрешаем запросы локально на петлю (для приложений, идущих на 127.0.0.1:53)
    oifname "lo" udp dport 53 accept
    oifname "lo" tcp dport 53 accept

${bypass_rule}    # Блокируем прямой уход DNS наружу для всех остальных
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
  local nft_bin
  nft_bin="$(command -v nft || true)"
  [[ -z "$nft_bin" ]] && nft_bin="/usr/sbin/nft"
  cat > "$WDNS_NFT_APPLY" <<EOF_APPLY
#!/usr/bin/env bash
set -euo pipefail
$nft_bin delete table inet wdns_whitelist 2>/dev/null || true
$nft_bin -f "$WDNS_NFT_FILE"
EOF_APPLY

  cat > "$WDNS_NFT_FLUSH" <<'EOF_FLUSH'
#!/usr/bin/env bash
set -euo pipefail
/usr/sbin/nft delete table inet wdns_whitelist 2>/dev/null || true
EOF_FLUSH

  chmod 0755 "$WDNS_NFT_APPLY" "$WDNS_NFT_FLUSH"
}

write_nm_dispatcher() {
  cat > "$NM_DISPATCHER_SCRIPT" <<'EOF_DISP'
#!/usr/bin/env bash
# WDNS: force local DNS on every connection up
interface="$1"
action="$2"

case "$action" in
  up|reapply|dhcp4-change|dhcp6-change)
    ;;
  *)
    exit 0
    ;;
esac

# Skip virtual/loopback-type interfaces
if [[ "$interface" == lo || "$interface" == docker* || "$interface" == veth* || \
      "$interface" == br* || "$interface" == virbr* || "$interface" == tun* || \
      "$interface" == tap* ]]; then
  exit 0
fi

# Force DNS on the connection that just came up
conn=$(nmcli -t -f GENERAL.CONNECTION device show "$interface" 2>/dev/null | cut -d: -f2-)
if [[ -n "$conn" ]]; then
  nmcli connection modify "$conn" \
    ipv4.ignore-auto-dns yes \
    ipv4.dns "127.0.0.1" \
    ipv4.dns-priority -1 \
    ipv6.method disabled \
    ipv6.ignore-auto-dns yes \
    ipv6.dns "" 2>/dev/null || true
fi

# Ensure resolv.conf is correct and immutable
chattr -i /etc/resolv.conf 2>/dev/null || true
cat > /etc/resolv.conf <<'EOF_RESOLV'
# generated by wdns — IPv4 only
nameserver 127.0.0.1
options edns0 trust-ad
EOF_RESOLV
chmod 0644 /etc/resolv.conf
chattr +i /etc/resolv.conf 2>/dev/null || true

# Make sure dnsmasq is listening
if ! ss -lntup 2>/dev/null | grep -qE '127\.0\.0\.1:53\b'; then
  systemctl restart dnsmasq.service 2>/dev/null || true
fi

exit 0
EOF_DISP
  chmod 0755 "$NM_DISPATCHER_SCRIPT"
  chown root:root "$NM_DISPATCHER_SCRIPT"
}

write_ensure_script() {
  cat > "$WDNS_ENSURE_SCRIPT" <<'EOF_ENSURE'
#!/usr/bin/env bash
# Не используем set -e: boot-time ensure должен быть максимально толерантным
set -uo pipefail

WDNS_DIR="/etc/wdns-whitelist"
RESOLV_CONF="/etc/resolv.conf"
DNSMASQ_SERVICE="dnsmasq.service"
WDNS_NFT_FILE="$WDNS_DIR/wdns-output-filter.nft"
WDNS_NFT_APPLY="$WDNS_DIR/apply-nft.sh"

log() { echo "[wdns-ensure] $*"; }

# 1. Всегда переписываем и лочим resolv.conf (симлинк от resolved/tmpfiles убиваем)
chattr -i "$RESOLV_CONF" 2>/dev/null || true
rm -f "$RESOLV_CONF"
cat > "$RESOLV_CONF" <<'EOF_RESOLV'
# generated by wdns — IPv4 only
nameserver 127.0.0.1
options edns0 trust-ad
EOF_RESOLV
chmod 0644 "$RESOLV_CONF"
chattr +i "$RESOLV_CONF" 2>/dev/null || true

# 2. Повторно форсим DNS на всех NM-соединениях (после reboot профили иногда «забывают»)
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

  while IFS= read -r dev; do
    [[ -z "$dev" ]] && continue
    nmcli device reapply "$dev" 2>/dev/null || true
  done < <(nmcli -t -f DEVICE,STATE device status 2>/dev/null | grep ':connected' | cut -d: -f1 || true)
fi

# 3. Гарантируем, что dnsmasq слушает 127.0.0.1:53
systemctl restart "$DNSMASQ_SERVICE" 2>/dev/null || true

for i in {1..15}; do
  if ss -lntup 2>/dev/null | grep -qE '127\.0\.0\.1:53\b'; then
    break
  fi
  sleep 1
done

# 4. Применяем nftables (после firewalld, см. unit)
if [[ -x "$WDNS_NFT_APPLY" && -f "$WDNS_NFT_FILE" ]]; then
  "$WDNS_NFT_APPLY" || true
fi

log "ensure completed successfully"
EOF_ENSURE
  chmod 0755 "$WDNS_ENSURE_SCRIPT"
}

write_wdns_nft_service() {
  cat > "/etc/systemd/system/$WDNS_NFT_SERVICE" <<EOF_UNIT
[Unit]
Description=WDNS host output nftables restrictions
After=network-pre.target network.target
After=firewalld.service
Wants=network.target
# Не делаем Requires=firewalld — на серверах без firewalld тоже должно работать

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
Description=WDNS boot-time DNS and firewall enforcement
Wants=NetworkManager.service dnsmasq.service
After=NetworkManager.service dnsmasq.service network.target
After=firewalld.service
After=wdns-nftables.service
Requires=wdns-nftables.service
# Не ставим network-online.target — иначе возможен deadlock (wait-online ждёт DNS)

[Service]
Type=oneshot
ExecStart=$WDNS_ENSURE_SCRIPT
RemainAfterExit=yes
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
EOF_UNIT
  chmod 0644 "/etc/systemd/system/$WDNS_ENSURE_SERVICE"
}

write_default_bypass_ips() {
  [[ -f "$BYPASS_IPS_FILE" ]] && return 0
  cat > "$BYPASS_IPS_FILE" <<'EOF_BIPS'
# DoH-серверы, доступные ТОЛЬКО группе wdns-bypass (tcp/443).
# Один IPv4 на строку. Держите список минимальным.
# Должен содержать IP из BYPASS_DOH_URI (по умолчанию https://1.1.1.1/dns-query).
1.1.1.1
1.0.0.1
EOF_BIPS
  chmod 0644 "$BYPASS_IPS_FILE"
}

bypass_target_user() {
  local u="${SUDO_USER:-}"
  if [[ -z "$u" || "$u" == "root" ]] || ! id "$u" >/dev/null 2>&1; then
    err "Run via sudo from your regular user (SUDO_USER is empty or root)"
    exit 1
  fi
  echo "$u"
}

bypass_cleanup_files() {
  getent group "$BYPASS_GROUP" >/dev/null 2>&1 && groupdel "$BYPASS_GROUP" 2>/dev/null || true
  rm -f "$BYPASS_LAUNCHER"
  local u="${SUDO_USER:-}" h
  if [[ -n "$u" && "$u" != "root" ]]; then
    h="$(getent passwd "$u" | cut -d: -f6 || true)"
    [[ -n "$h" ]] && rm -f "$h/.local/share/applications/$BYPASS_DESKTOP_NAME"
  fi
}

bypass_setup() {
  require_root
  require_cmd nft
  require_cmd sg
  require_cmd getent
  require_cmd runuser
  [[ -f "$STATE_FILE" ]] || { err "Run 'apply' first"; exit 1; }
  ensure_paths

  local user home profile doh_host
  user="$(bypass_target_user)"
  home="$(getent passwd "$user" | cut -d: -f6)"
  profile="$home/.var/app/$BYPASS_APP_ID/data/wdns-bypass-profile"

  if ! runuser -u "$user" -- flatpak info "$BYPASS_APP_ID" >/dev/null 2>&1; then
    warn "Flatpak app $BYPASS_APP_ID not found for user $user (continuing)"
  fi

  if [[ ! "$BYPASS_DOH_URI" =~ ^https://[0-9.]+(:[0-9]+)?/[A-Za-z0-9._/-]*$ ]]; then
    err "BYPASS_DOH_URI must be https://<IPv4>/path (IP literal, no hostname): $BYPASS_DOH_URI"
    exit 1
  fi
  doh_host="${BYPASS_DOH_URI#https://}"; doh_host="${doh_host%%[:/]*}"
  validate_ipv4 "$doh_host" || { err "Invalid IPv4 in BYPASS_DOH_URI: $doh_host"; exit 1; }

  # 1) группа + членство
  getent group "$BYPASS_GROUP" >/dev/null 2>&1 || groupadd -r "$BYPASS_GROUP"
  usermod -aG "$BYPASS_GROUP" "$user"
  log "Group $BYPASS_GROUP ready; user $user added"

  # 2) список разрешённых DoH-IP
  write_default_bypass_ips
  if ! grep -qE "^[[:space:]]*${doh_host//./\\.}([[:space:]]|#|$)" "$BYPASS_IPS_FILE"; then
    warn "$doh_host is NOT in $BYPASS_IPS_FILE — DoH will be blocked until you add it"
  fi

  # 3) launcher
  cat > "$BYPASS_LAUNCHER" <<EOF_LAUNCH
#!/usr/bin/env bash
# Generated by wdns. Запускает LibreWolf (flatpak) в группе $BYPASS_GROUP
# с отдельным профилем и DoH. Остальная система остаётся на whitelist.
set -euo pipefail
APP_ID="$BYPASS_APP_ID"
GROUP="$BYPASS_GROUP"
PROFILE_DIR="\$HOME/.var/app/\$APP_ID/data/wdns-bypass-profile"

LOG="\${XDG_CACHE_HOME:-\$HOME/.cache}/wdns-bypass.log"
mkdir -p "\$(dirname "\$LOG")"
exec >>"\$LOG" 2>&1
echo "--- \$(date -Is) launch: \$*"

fail() {
  echo "ERROR: \$*"
  command -v notify-send >/dev/null 2>&1 && notify-send "wdns bypass" "\$*" || true
  exit 1
}

[[ \$EUID -eq 0 ]] && fail "Do not run as root"
command -v sg >/dev/null 2>&1 || fail "sg not found"
getent group "\$GROUP" | cut -d: -f4 | tr ',' '\n' | grep -qx "\$(id -un)" \\
  || fail "user is not in group \$GROUP (run: sudo wdns.sh bypass-setup)"
[[ -d "\$PROFILE_DIR" ]] || fail "profile dir missing: \$PROFILE_DIR"

CMD="\$(printf '%q ' /usr/bin/flatpak run --command=librewolf --no-documents-portal "\$APP_ID" \\
  --no-remote --profile "\$PROFILE_DIR" "\$@")"
echo "exec: \$CMD"
exec sg "\$GROUP" -c "\$CMD" </dev/null
EOF_LAUNCH
  chmod 0755 "$BYPASS_LAUNCHER"
  chown root:root "$BYPASS_LAUNCHER"

  # 4) отдельный профиль с DoH-only (от имени пользователя)
  runuser -u "$user" -- mkdir -p -m 0700 "$profile"
  runuser -u "$user" -- tee "$profile/user.js" >/dev/null <<EOF_USERJS
// Generated by wdns — DoH-only профиль (TRR mode 3: без отката на системный DNS)
user_pref("network.trr.mode", 3);
user_pref("network.trr.uri", "$BYPASS_DOH_URI");
user_pref("network.trr.custom_uri", "$BYPASS_DOH_URI");
user_pref("network.trr.default_provider_uri", "$BYPASS_DOH_URI");
user_pref("network.trr.confirmationNS", "skip");
user_pref("network.trr.allow-rfc1918", false);
user_pref("doh-rollout.disable-heuristics", true);
user_pref("network.dns.disableIPv6", true);
EOF_USERJS

  # 5) .desktop (намеренно БЕЗ MimeType — не становится браузером по умолчанию)
  runuser -u "$user" -- mkdir -p "$home/.local/share/applications"
  runuser -u "$user" -- tee "$home/.local/share/applications/$BYPASS_DESKTOP_NAME" >/dev/null <<EOF_DESKTOP
[Desktop Entry]
Type=Application
Name=LibreWolf (DoH bypass)
Comment=Isolated profile with DoH, bypasses local DNS whitelist
Exec=$BYPASS_LAUNCHER %u
Icon=$BYPASS_APP_ID
Terminal=false
StartupNotify=true
StartupWMClass=librewolf
X-MultipleArgs=false
Keywords=Internet;WWW;Browser;Web;Explorer;
Categories=Network;WebBrowser;
EOF_DESKTOP
  runuser -u "$user" -- update-desktop-database "$home/.local/share/applications" >/dev/null 2>&1 || true

  # 6) firewall
  apply_firewall

  log "Bypass configured. Launch: $BYPASS_LAUNCHER   (or menu: «LibreWolf (DoH bypass)»)"
  log "Profile: $profile"
  warn "Проверьте в запущенном браузере: about:networking#dns и about:preferences#privacy"
  warn "Обычный запуск LibreWolf не затронут и по-прежнему идёт через whitelist."
}

bypass_remove() {
  require_root
  bypass_cleanup_files
  [[ -f "$STATE_FILE" ]] && apply_firewall || true
  log "Bypass removed (group, launcher, rule). Profile directory kept — delete manually if desired."
}

apply_firewall() {
  write_default_bypass_ips
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
  nmcli connection reload 2>/dev/null || true
  sleep 1
  force_nm_connections_dns

  apply_firewall

  write_ensure_script
  write_nm_dispatcher
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
      "$NM_DISPATCHER_SCRIPT" \
      "/etc/systemd/system/$WDNS_NFT_SERVICE" \
      "/etc/systemd/system/$WDNS_ENSURE_SERVICE"

  bypass_cleanup_files
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

  echo "=== DoH bypass ==="
  getent group "$BYPASS_GROUP" || echo "group $BYPASS_GROUP absent (bypass disabled)"
  [[ -f "$BYPASS_IPS_FILE" ]] && grep -vE '^[[:space:]]*(#|$)' "$BYPASS_IPS_FILE" || true
  nft list chain inet wdns_whitelist output 2>/dev/null | grep -E 'skgid' || echo "(no bypass rule active)"
  echo

  echo "=== nftables rules (summary) ==="
  nft list table inet wdns_whitelist 2>/dev/null | head -60 || echo "table inet wdns_whitelist absent"
}

usage() {
  cat <<EOF
Usage:
  sudo $0 apply [DNS1,DNS2]    - Initial install / apply (IPv4 only)
  sudo $0 update               - Update configuration after editing whitelist.txt
  sudo $0 status               - Show current status
  sudo $0 restore              - Restore stock network/DNS settings
  sudo $0 bypass-setup         - Per-app DoH bypass for LibreWolf (flatpak), isolated profile
  sudo $0 bypass-remove        - Remove the bypass

Whitelist format (whitelist.txt):
  example.com          # allow
  !bad.example.com     # explicitly block (REFUSED)
  # comment

Everything not listed in the whitelist → REFUSED.
IPv6 is fully disabled.
DoH/DoT: domains blocked in dnsmasq, known IPs blocked in nftables.

Bypass (optional): group $BYPASS_GROUP may reach ONLY tcp/443 of IPs listed in
  $BYPASS_IPS_FILE. Env: BYPASS_APP_ID, BYPASS_DOH_URI (must be https://<IPv4>/...).
EOF
  exit 1
}

case "${1:-}" in
  apply)     apply_all "${2:-}" ;;
  update)    update_whitelist ;;
  status)    show_status ;;
  restore)   restore_defaults ;;
  bypass-setup)  bypass_setup ;;
  bypass-remove) bypass_remove ;;
  *)         usage ;;
esac
