#!/bin/sh

echo "=================================================="
echo " Starting Ultra-Hardened Network Setup (Zero Trust)"
echo "=================================================="

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

# Save settings to NVRAM
nvram commit

# 5. Force kill daemon processes on the fly
killall -9 tor openvpn charon swanctl l2tpd pptpd networkmap infosvr conn_diag asusdiscovery 2>/dev/null
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

# 1. Mandatory forwarding to WAN and back for all VLANs
iptables -I FORWARD 1 -i br10 -o eth0 -j ACCEPT
iptables -I FORWARD 1 -i eth0 -o br10 -j ACCEPT

iptables -I FORWARD 1 -i br20 -o eth0 -j ACCEPT
iptables -I FORWARD 1 -i eth0 -o br20 -j ACCEPT

iptables -I FORWARD 1 -i br30 -o eth0 -j ACCEPT
iptables -I FORWARD 1 -i eth0 -o br30 -j ACCEPT

iptables -I FORWARD 1 -i br40 -o eth0 -j ACCEPT
iptables -I FORWARD 1 -i eth0 -o br40 -j ACCEPT

# Admin Router/Switch access strictly from VLAN 10 (Trusted)
iptables -I INPUT 1 -i br10 -p tcp --dport 80 -j ACCEPT
iptables -I INPUT 1 -i br10 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -i br10 -p tcp --dport 22 -j ACCEPT
iptables -I INPUT 1 -i br10 -p tcp --dport 4444 -j ACCEPT

# 2. NAT (Masquerade) for internet access across all subnets via WAN (eth0)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERODE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 3. Unconditional permission for incoming DHCP and DNS from all bridges
iptables -I INPUT 1 -p udp --dport 67:68 -j ACCEPT
iptables -I INPUT 1 -p udp --sport 67:68 -j ACCEPT
iptables -I INPUT 1 -p udp --dport 53 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT

# 4. Allow WAN routing for remaining subnets
iptables -A FORWARD -i br0 -o eth0 -j ACCEPT
iptables -A FORWARD -i br20 -o eth0 -j ACCEPT
iptables -A FORWARD -i br30 -o eth0 -j ACCEPT
iptables -A FORWARD -i br40 -o eth0 -j ACCEPT

# 5. Trusted (VLAN 10) has access to all other segments and Management network
iptables -A FORWARD -i br10 -o br0 -j ACCEPT
iptables -A FORWARD -i br10 -o br20 -j ACCEPT
iptables -A FORWARD -i br10 -o br30 -j ACCEPT
iptables -A FORWARD -i br10 -o br40 -j ACCEPT

# 6. Allow responses to established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 7. Segment isolation (inter-VLAN firewall barrier)
iptables -A FORWARD -i br20 -o br10 -j DROP
iptables -A FORWARD -i br20 -o br30 -j DROP
iptables -A FORWARD -i br20 -o br40 -j DROP

iptables -A FORWARD -i br30 -o br0 -j DROP
iptables -A FORWARD -i br30 -o br10 -j DROP
iptables -A FORWARD -i br30 -o br20 -j DROP
iptables -A FORWARD -i br30 -o br40 -j DROP

iptables -A FORWARD -i br40 -o br0 -j DROP
iptables -A FORWARD -i br40 -o br10 -j DROP
iptables -A FORWARD -i br40 -o br20 -j DROP
iptables -A FORWARD -i br40 -o br30 -j DROP

# 8. Protect router management interface from IoT (VLAN 30) and Guest (VLAN 40)
iptables -A INPUT -i br30 -p tcp --dport 80 -j DROP
iptables -A INPUT -i br30 -p tcp --dport 443 -j DROP
iptables -A INPUT -i br30 -p tcp --dport 22 -j DROP
iptables -A INPUT -i br30 -p tcp --dport 4444 -j DROP

iptables -A INPUT -i br40 -p tcp --dport 80 -j DROP
iptables -A INPUT -i br40 -p tcp --dport 443 -j DROP
iptables -A INPUT -i br40 -p tcp --dport 22 -j DROP
iptables -A INPUT -i br40 -p tcp --dport 4444 -j DROP

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
