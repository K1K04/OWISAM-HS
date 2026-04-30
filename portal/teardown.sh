#!/bin/bash
# teardown.sh — Limpia todo el stack del portal cautivo

AP_IFACE="wlx98038e5c6843"
UPLINK="ens33"

echo "[*] Parando procesos..."
pkill hostapd 2>/dev/null && echo "    hostapd detenido" || echo "    hostapd no estaba corriendo"
pkill dnsmasq 2>/dev/null && echo "    dnsmasq detenido" || echo "    dnsmasq no estaba corriendo"
[ -f /tmp/portal.pid ] && kill $(cat /tmp/portal.pid) 2>/dev/null && rm /tmp/portal.pid && echo "    Flask detenido"

echo "[*] Limpiando iptables..."
iptables -t nat -F
iptables -t nat -X
iptables -F FORWARD

echo "[*] Desactivando IP forwarding..."
echo 0 > /proc/sys/net/ipv4/ip_forward

echo "[*] Limpiando interfaz AP..."
ip addr flush dev $AP_IFACE
ip link set $AP_IFACE down

echo "[+] Stack detenido y entorno limpio."
