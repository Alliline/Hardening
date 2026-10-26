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
nvram set http_enable=0
nvram set https_enable=0

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
ip link set dev eth2 promisc on

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
        echo "ERROR: Anchor rule not found in $chain: $target" >&2
        return 1
    fi

    "$IPT" -I "$chain" "$pos" -j "$jump"
}

# Create or refresh only our own chains.
for chain in HOMELAB_INPUT HOMELAB_ISO HOMELAB_WAN; do
    "$IPT" -N "$chain" 2>/dev/null || true
    "$IPT" -F "$chain"
done

# Remove our previous jump references to make reruns idempotent.
while "$IPT" -D INPUT -j HOMELAB_INPUT 2>/dev/null; do :; done
while "$IPT" -D FORWARD -j HOMELAB_ISO 2>/dev/null; do :; done
while "$IPT" -D FORWARD -j HOMELAB_WAN 2>/dev/null; do :; done

# ------------------------------------------------------------
# 1. INPUT: Access to the router itself.
# ------------------------------------------------------------

# Preserve loopback access.
"$IPT" -A HOMELAB_INPUT -i lo -j RETURN

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
for port in 22 80 443 4444 4443; do
    "$IPT" -A HOMELAB_INPUT -i br10 \
        -p tcp --dport "$port" -j ACCEPT
done

# Block router management ports from every other interface.
for port in 22 80 443 4444 4443; do
    "$IPT" -A HOMELAB_INPUT \
        -p tcp --dport "$port" -j DROP
done

# Leave unrelated router traffic to the existing firewall.
"$IPT" -A HOMELAB_INPUT -j RETURN

# ------------------------------------------------------------
# 2. FORWARD: Inter-VLAN isolation.
# ------------------------------------------------------------

# Prevent new routed connections to IoT and Guest VLANs,
# including connections created by port forwarding.
"$IPT" -A HOMELAB_ISO -o br30 -j DROP
"$IPT" -A HOMELAB_ISO -o br40 -j DROP

# IoT and Guest may not initiate connections outside their VLANs,
# except connections directed to the WAN.
"$IPT" -A HOMELAB_ISO -i br30 ! -o eth0 -j DROP
"$IPT" -A HOMELAB_ISO -i br30 ! -o eth1 -j DROP

"$IPT" -A HOMELAB_ISO -i br40 ! -o eth0 -j DROP
"$IPT" -A HOMELAB_ISO -i br40 ! -o eth1 -j DROP

# Allow Trusted VLAN to reach the main LAN.
"$IPT" -A HOMELAB_ISO -i br10 -o br0 -j ACCEPT

# Allow Trusted VLAN to access selected SemiTrusted VLAN services.
for port in 22 4444 4443 11434; do
    "$IPT" -A HOMELAB_ISO -i br10 -o br20 \
        -p tcp --dport "$port" -j ACCEPT
done

# Allow SemiTrusted VLAN to access the NAS using NFSv4.
# Enable this rule only if the Proxmox host actually exports NFS.
"$IPT" -A HOMELAB_ISO -i br20 -o br10 \
    -d "$NAS_IP" -p tcp --dport 2049 -j ACCEPT

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
