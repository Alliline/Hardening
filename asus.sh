#!/bin/sh

echo "============================================="
echo " Starting Hardened Network Setup (Zero Trust)"
echo "============================================="

# 1. Enable JFFS script support in NVRAM
nvram set jffs2_scripts=1

# 2. Hardening: Total shutdown of USB, modems, file services, WPS & IPv6
nvram set modem_enable=0
nvram set usb_modem_act=0
nvram set enable_ftp=0
nvram set enable_samba=0
nvram set dms_enable=0
nvram set afpd_enable=0
nvram set irdmi_enable=0

# Disable WPS completely
nvram set wps_enable=0
nvram set wps_enable_x=0
nvram set wl_wps_mode=disabled
nvram set wl0_wps_mode=disabled
nvram set wl1_wps_mode=disabled

# Disable IPv6 to prevent IPv6 leaks across VLANs (if not explicitly used)
nvram set ipv6_service=disabled
nvram set ipv6_enable=0

# 3. Hardening: Disable all VPNs, Tor, and tunnels
nvram set vpn_server1_enable=0
nvram set vpn_server2_enable=0
nvram set vpn_client1_enable=0
nvram set vpn_client2_enable=0
nvram set vpn_client3_enable=0
nvram set vpn_client4_enable=0
nvram set vpn_client5_enable=0
nvram set wgs_enable=0
nvram set wgc_enable=0
nvram set tor_enable=0
nvram set ipsec_enable=0

# 4. Hardening: Disable Discovery, clouds, UPnP, and telemetry
nvram set upnp_enable=0
nvram set avahi_enable=0
nvram set wsdd2_enable=0
nvram set lldpd_enable=0
nvram set bt_enable=0
nvram set aae_enable=0
nvram set feedback_enable=0
nvram set uptime_enable=0
nvram set nat_autofw_enable=0
nvram set cfg_client=0
nvram set cfg_server=0
nvram set snmp_enable=0
nvram set cloud_sync=0
nvram set apps_enable=0
nvram set networkmap_enable=0
nvram set conn_diag_enable=0
nvram set reaper_wanbounce_enable=0

# 5. Disable Web Control Panel
nvram set http_enable=1
nvram set misc_http_x=0
nvram set sshd_wan=0
nvram set misc_ping_x=0
nvram set fw_dos_x=1

# Save settings to NVRAM
nvram commit

# 5. Force kill daemon processes on the fly
killall -9 httpd tor openvpn charon swanctl l2tpd pptpd networkmap infosvr conn_diag asusdiscovery 2>/dev/null
killall -9 smbd nmbd vsftpd minidlna afpd avahi-daemon wsdd2 miniupnpd lldpd snmpd ookla wg 2>/dev/null

# Create script directory
mkdir -p /jffs/scripts

# ==================================================
# Generate /jffs/scripts/services-start
# ==================================================
echo "[+] Generating /jffs/scripts/services-start..."
cat << 'EOF' > /jffs/scripts/services-start
#!/bin/sh

sleep 3

# --- Sysctl Network Hardening (Anti-Spoofing & Redirects) ---
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 0 > /proc/sys/net/ipv4/conf/default/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route
echo 0 > /proc/sys/net/ipv4/conf/all/secure_redirects
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
[ -e /proc/sys/net/ipv6/conf/default/disable_ipv6 ] && echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
[ -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# --- Hardening: Aggressive unloading of unused kernel modules ---
UNWANTED_MODULES="
  cifs
  xt_sctp
  tntfs
  tfat
  thfsplus
  qmi_wwan
  cdc_ncm
  rndis_host
  ipheth
  option
  usb_wwan
  usblp
  sr_mod
  wireguard
  ah4
  esp4
  ipcomp
  proxysta
  xfrm4_tunnel
  xfrm_user
  ax88179_178a
  asix
  cdc_ether
  cdc_acm
  cdc_wdm
  usbnet
  nf_conntrack_ftp
  nf_nat_ftp
"

for i in 1 2; do
    for mod in $UNWANTED_MODULES; do
        if lsmod | grep -q "^$mod "; then
            rmmod "$mod" 2>/dev/null
        fi
    done
    sleep 1
done

# --- 1. Cleanup old VLAN interfaces and bridges ---
for vlan in 10 20 30 40; do
    ip link set dev vlan${vlan} down 2>/dev/null
    ip link delete vlan${vlan} 2>/dev/null
    ip link set dev br${vlan} down 2>/dev/null
    brctl delbr br${vlan} 2>/dev/null
done

# --- 2. Configure physical port eth2 (10G Trunk) ---
brctl delif br0 eth2 2>/dev/null
ip link set dev eth2 up

# --- 3. Create tagged interfaces and bridges ---
for vlan in 10 20 30 40; do
    ip link add link eth2 name vlan${vlan} type vlan id ${vlan}
    ip link set dev vlan${vlan} up
    
    brctl addbr br${vlan}
    brctl addif br${vlan} vlan${vlan}
    ip link set dev br${vlan} up
done

# --- 4. Assign subnet gateway IP addresses ---
ip addr add 10.10.10.1/24 dev br10 2>/dev/null
ip addr add 10.10.20.1/24 dev br20 2>/dev/null
ip addr add 10.10.30.1/24 dev br30 2>/dev/null
ip addr add 10.10.40.1/24 dev br40 2>/dev/null

EOF
chmod +x /jffs/scripts/services-start

# ==================================================
# Generate /jffs/scripts/dnsmasq.postconf
# ==================================================
echo "[+] Generating /jffs/scripts/dnsmasq.postconf..."
cat << 'EOF' > /jffs/scripts/dnsmasq.postconf
#!/bin/sh
CONFIG=$1

if ! grep -q "interface=br10" "$CONFIG"; then
    cat >> "$CONFIG" << 'CONFIG_EOF'

# VLAN 10 (Trusted)
interface=br10
dhcp-range=br10,10.10.10.100,10.10.10.200,255.255.255.0,86400s

# VLAN 20 (Semi Trusted)
interface=br20
dhcp-range=br20,10.10.20.100,10.10.20.200,255.255.255.0,86400s

# VLAN 30 (IoT)
interface=br30
dhcp-range=br30,10.10.30.100,10.10.30.200,255.255.255.0,86400s

# VLAN 40 (Guest)
interface=br40
dhcp-range=br40,10.10.40.100,10.10.40.200,255.255.255.0,86400s
CONFIG_EOF
fi

EOF
chmod +x /jffs/scripts/dnsmasq.postconf

# ==================================================
# Generate /jffs/scripts/firewall-start
# ==================================================
echo "[+] Generating /jffs/scripts/firewall-start..."
cat << 'EOF' > /jffs/scripts/firewall-start
#!/bin/sh

IPT="iptables"
NAS_IP="10.10.10.10"

# Locate a rule in a chain and return its iptables rule number.
find_rule() {
    "$IPT" -S "$1" | awk -v target="$2" '
        BEGIN { n = 1 }
        /^-A / {
            if ($0 == target) {
                print n
                exit
            }
            n++
        }
    '
}

# Insert a jump before an existing system rule.
insert_before() {
    chain="$1"
    target="$2"
    jump="$3"

    pos=$(find_rule "$chain" "$target")

    if [ -z "$pos" ]; then
        echo "WARNING: anchor not found in $chain, inserting at top: $target" >&2
        pos=1
    fi

    "$IPT" -I "$chain" "$pos" -j "$jump"
}

# Create or refresh only our own chains.
for chain in HOMELAB_INPUT HOMELAB_ISO HOMELAB_WAN HOMELAB_EGRESS; do
    "$IPT" -N "$chain" 2>/dev/null || true
    "$IPT" -F "$chain"
done

# Remove our previous jump references to make reruns idempotent.
while "$IPT" -D INPUT -j HOMELAB_INPUT 2>/dev/null; do :; done
while "$IPT" -D FORWARD -j HOMELAB_ISO 2>/dev/null; do :; done
while "$IPT" -D FORWARD -j HOMELAB_WAN 2>/dev/null; do :; done
while "$IPT" -D FORWARD -j HOMELAB_EGRESS 2>/dev/null; do :; done

# ------------------------------------------------------------
# 1. INPUT: Access to the router itself.
# ------------------------------------------------------------

# Preserve loopback access.
"$IPT" -A HOMELAB_INPUT -i lo -j RETURN

# Connection tracking baseline.
"$IPT" -A HOMELAB_INPUT -m conntrack --ctstate INVALID -j DROP
"$IPT" -A HOMELAB_INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# WAN: drop all new inbound ICMP (ping, ICMP tunnels). ICMP errors for
# existing flows are RELATED and were accepted above.
for wan in eth0 eth1; do
    "$IPT" -A HOMELAB_INPUT -i "$wan" -p icmp -j DROP
done

# Allow DHCP requests from local networks.
for iface in br0 br10 br20 br30 br40; do
    "$IPT" -A HOMELAB_INPUT -i "$iface" \
        -p udp --dport 67 -j ACCEPT
done

# Allow DNS requests from local networks.
for iface in br0 br10 br20 br30 br40; do
    "$IPT" -A HOMELAB_INPUT -i "$iface" \
        -p udp --dport 53 -j ACCEPT

    "$IPT" -A HOMELAB_INPUT -i "$iface" \
        -p tcp --dport 53 -j ACCEPT
done

# Allow management access only from Trusted VLAN.
for port in 22 80 443 445 3389 4444 4443 9090 8006; do
    "$IPT" -A HOMELAB_INPUT -i br10 \
        -p tcp --dport "$port" -j ACCEPT
done

# Block router management ports from every other interface.
for port in 22 80 443 445 3389 4444 4443 9090 8006; do
    "$IPT" -A HOMELAB_INPUT \
        -p tcp --dport "$port" -j DROP
done

# Never accept redirects / probing ICMP types from any interface.
for t in redirect timestamp-request address-mask-request router-advertisement; do
    "$IPT" -A HOMELAB_INPUT -p icmp --icmp-type "$t" -j DROP
done

# Ping to the router: Trusted/SemiTrusted only, small and rate limited.
for iface in br10 br20; do
    "$IPT" -A HOMELAB_INPUT -i "$iface" -p icmp --icmp-type echo-request \
        -m length --length 28:128 \
        -m limit --limit 5/second --limit-burst 10 -j ACCEPT
    "$IPT" -A HOMELAB_INPUT -i "$iface" -p icmp --icmp-type echo-request -j DROP
done

# IoT and Guest: DHCP and DNS only (accepted above), everything else dropped.
for iface in br30 br40; do
    "$IPT" -A HOMELAB_INPUT -i "$iface" -j DROP
done

# Leave unrelated router traffic to the existing firewall.
"$IPT" -A HOMELAB_INPUT -j RETURN

# ------------------------------------------------------------
# 2. FORWARD: Inter-VLAN isolation.
# ------------------------------------------------------------

# Connection tracking baseline.
"$IPT" -A HOMELAB_ISO -m conntrack --ctstate INVALID -j DROP
"$IPT" -A HOMELAB_ISO -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Prevent new routed connections to IoT and Guest VLANs,
# including connections created by port forwarding.
"$IPT" -A HOMELAB_ISO -o br30 -j DROP
"$IPT" -A HOMELAB_ISO -o br40 -j DROP

# IoT and Guest may not initiate connections outside their VLANs,
# except connections directed to the WAN.
for iface in br30 br40; do
    for wan in eth0 eth1; do
        "$IPT" -A HOMELAB_ISO -i "$iface" -o "$wan" -j RETURN
    done
    "$IPT" -A HOMELAB_ISO -i "$iface" -j DROP
done

# Allow Trusted VLAN to reach the main LAN.
"$IPT" -A HOMELAB_ISO -i br10 -o br0 -j ACCEPT

# Allow Trusted VLAN to access selected SemiTrusted VLAN services.
for port in 22 445 3389 4444 11434; do
    "$IPT" -A HOMELAB_ISO -i br10 -o br20 \
        -p tcp --dport "$port" -j ACCEPT
done

# Allow SemiTrusted VLAN to access using SMB, NFSv4, RDP.
"$IPT" -A HOMELAB_ISO -i br20 -o br10 \
    -d "$NAS_IP" -p tcp -m multiport --dports 445,2049,3389 -j ACCEPT

# Block all other new connections between Trusted and SemiTrusted.
"$IPT" -A HOMELAB_ISO -i br10 -o br20 -j DROP
"$IPT" -A HOMELAB_ISO -i br20 -o br10 -j DROP

# Block all other routed traffic between bridge interfaces.
"$IPT" -A HOMELAB_ISO -i br+ -o br+ -j DROP

# Preserve traffic not covered by the homelab policy.
"$IPT" -A HOMELAB_ISO -j RETURN

# ------------------------------------------------------------
# 3. FORWARD: Internet access for VLANs.
# ------------------------------------------------------------

# Allow outbound Internet access from each VLAN.
# System VPN chains are evaluated before this chain.
for iface in br10 br20 br30 br40; do
    "$IPT" -A HOMELAB_WAN -i "$iface" -o eth0 -j ACCEPT
    "$IPT" -A HOMELAB_WAN -i "$iface" -o eth1 -j ACCEPT
done

# Preserve the existing firewall for all other traffic.
"$IPT" -A HOMELAB_WAN -j RETURN

# ------------------------------------------------------------
# 3b. FORWARD: Egress and tunnelling protection.
# ------------------------------------------------------------
WAN_IFACES="eth0 eth1"

# Invalid packets (includes unsolicited echo-replies from reverse ICMP tunnels).
"$IPT" -A HOMELAB_EGRESS -m conntrack --ctstate INVALID -j DROP

# ptunnel / ptunnel-ng magic value (needs xt_string; skipped if unavailable).
"$IPT" -A HOMELAB_EGRESS -p icmp -m string --algo bm --hex-string '|d5200880|' -j DROP 2>/dev/null \
    || echo "NOTE: xt_string unavailable, ptunnel signature rule skipped" >&2

# Inbound: no new ICMP from the Internet to LAN hosts.
for wan in $WAN_IFACES; do
    "$IPT" -A HOMELAB_EGRESS -i "$wan" -p icmp -m conntrack --ctstate NEW -j DROP
done

# IoT/Guest: no outbound ping or probing ICMP at all.
for iface in br30 br40; do
    for t in echo-request timestamp-request address-mask-request redirect; do
        "$IPT" -A HOMELAB_EGRESS -i "$iface" -p icmp --icmp-type "$t" -j DROP
    done
done

# Trusted/SemiTrusted/main LAN to Internet: small, rate-limited pings only.
# Tunnels need large or frequent echo packets; normal ping is <=128 bytes.
for wan in $WAN_IFACES; do
    for iface in br0 br10 br20; do
        "$IPT" -A HOMELAB_EGRESS -i "$iface" -o "$wan" -p icmp --icmp-type echo-request \
            -m length --length 129:65535 -j DROP
        "$IPT" -A HOMELAB_EGRESS -i "$iface" -o "$wan" -p icmp --icmp-type echo-request \
            -m limit --limit 10/second --limit-burst 20 -j RETURN
        "$IPT" -A HOMELAB_EGRESS -i "$iface" -o "$wan" -p icmp --icmp-type echo-request -j DROP
    done
done

# IoT/Guest: no DNS-over-TLS/QUIC and no direct DNS (fallback; see NAT redirect below).
for iface in br30 br40; do
    "$IPT" -A HOMELAB_EGRESS -i "$iface" -p tcp --dport 853 -j DROP
    "$IPT" -A HOMELAB_EGRESS -i "$iface" -p udp --dport 853 -j DROP
    "$IPT" -A HOMELAB_EGRESS -i "$iface" -p tcp --dport 53 -j DROP
    "$IPT" -A HOMELAB_EGRESS -i "$iface" -p udp --dport 53 -j DROP
done

# IoT/Guest: force hardcoded DNS (8.8.8.8 etc.) to the router's dnsmasq.
for iface in br30 br40; do
    for proto in udp tcp; do
        "$IPT" -t nat -C PREROUTING -i "$iface" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null \
            || "$IPT" -t nat -I PREROUTING -i "$iface" -p "$proto" --dport 53 -j REDIRECT --to-ports 53
    done
done

# ------------------------------------------------------------
# 4. Install hooks without resetting system firewall rules.
# ------------------------------------------------------------

# Apply router access restrictions before the vendor service rules.
insert_before INPUT \
    "-A INPUT ! -i br0 -j PTCSRVWAN" \
    HOMELAB_INPUT || exit 1

# Apply VLAN isolation before the existing DNAT acceptance rule.
insert_before FORWARD \
    "-A FORWARD -m conntrack --ctstate DNAT -j logaccept" \
    HOMELAB_ISO || exit 1

# Apply VLAN Internet permissions before the SDN forwarding rules.
insert_before FORWARD \
    "-A FORWARD -j SDN_FF" \
    HOMELAB_WAN || exit 1

# Egress/tunnel filter first: it only DROPs or RETURNs, never ACCEPTs.
"$IPT" -I FORWARD 1 -j HOMELAB_EGRESS

echo "Homelab VLAN firewall rules installed."

EOF
chmod +x /jffs/scripts/firewall-start

# ==================================================
# Apply
# ==================================================
echo "[+] Applying scripts and restarting services..."
/jffs/scripts/services-start
/jffs/scripts/firewall-start
service restart_dnsmasq

echo "=================================================="
echo " Ultra-Hardened Setup Completed Successfully!"
echo "=================================================="
