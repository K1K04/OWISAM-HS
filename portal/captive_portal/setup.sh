#!/bin/bash
# setup.sh — Levanta el stack completo del portal cautivo
# Uplink: ens33 (192.168.20.47) | AP: wlx98038e5c6843

set -e

AP_IFACE="wlx98038e5c6843"
UPLINK="ens33"
AP_IP="10.0.0.1"
AP_SUBNET="10.0.0.0/24"
PORTAL_PORT="5000"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Comprobando dependencias..."
for cmd in hostapd dnsmasq python3 iptables; do
    command -v $cmd &>/dev/null || { echo "[-] Falta: $cmd"; exit 1; }
done

echo "[*] Configurando interfaz AP: $AP_IFACE"
ip link set $AP_IFACE up
ip addr flush dev $AP_IFACE
ip addr add $AP_IP/24 dev $AP_IFACE

echo "[*] Activando IP forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[*] Configurando iptables..."
# NAT: clientes del AP salen por ens33
iptables -t nat -A POSTROUTING -o $UPLINK -j MASQUERADE

# Redirigir TODO el tráfico HTTP de clientes al portal (DNS hijack hace el resto)
iptables -t nat -A PREROUTING -i $AP_IFACE -p tcp --dport 80 -j DNAT --to-destination $AP_IP:$PORTAL_PORT
iptables -t nat -A PREROUTING -i $AP_IFACE -p tcp --dport 443 -j DNAT --to-destination $AP_IP:$PORTAL_PORT

# Permitir tráfico entre AP e internet UNA VEZ que el cliente esté autorizado
iptables -A FORWARD -i $AP_IFACE -o $UPLINK -j ACCEPT
iptables -A FORWARD -i $UPLINK -o $AP_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# Interceptar connectivity checks (Android, iOS, Windows, Linux)
iptables -t nat -A PREROUTING -i $AP_IFACE -p tcp --dport 80 -d 216.58.0.0/16 -j DNAT --to $AP_IP:$PORTAL_PORT
iptables -t nat -A PREROUTING -i $AP_IFACE -p tcp --dport 80 -d 23.215.0.0/16 -j DNAT --to $AP_IP:$PORTAL_PORT

echo "[*] Arrancando dnsmasq..."
pkill dnsmasq 2>/dev/null || true
dnsmasq -C $SCRIPT_DIR/dnsmasq.conf

echo "[*] Arrancando hostapd..."
pkill hostapd 2>/dev/null || true
hostapd -B $SCRIPT_DIR/hostapd.conf

echo "[*] Arrancando portal Flask..."
cd $SCRIPT_DIR
python3 portal.py &
echo $! > /tmp/portal.pid

echo ""
echo "[+] Stack activo:"
echo "    AP SSID  : FreeWiFi_Lab"
echo "    AP IP    : $AP_IP"
echo "    Portal   : http://$AP_IP:$PORTAL_PORT"
echo "    Admin    : http://$AP_IP:$PORTAL_PORT/admin"
echo "    Uplink   : $UPLINK ($(ip -4 addr show $UPLINK | grep inet | awk '{print $2}'))"
echo ""
echo "[!] Para detener: sudo bash teardown.sh"
