#!/bin/sh
set -e

echo "[INFO] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Detect interfaces based on subnet
CLIENT_NET_IFACE=$(ip -o -4 addr show | awk '/172\.21\./ {print $2; exit}')
SERVER_NET_IFACE=$(ip -o -4 addr show | awk '/172\.20\./ {print $2; exit}')

echo "[INFO] Detected client iface: $CLIENT_NET_IFACE"
echo "[INFO] Detected server iface: $SERVER_NET_IFACE"

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -X

# Default policies
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# Allow forwarding between client <-> server
iptables -A FORWARD -i "$CLIENT_NET_IFACE" -o "$SERVER_NET_IFACE" -j ACCEPT
iptables -A FORWARD -i "$SERVER_NET_IFACE" -o "$CLIENT_NET_IFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT (so packets from client appear from firewall when reaching server)
iptables -t nat -A POSTROUTING -o "$SERVER_NET_IFACE" -j MASQUERADE

echo "[INFO] Firewall routing rules active:"
iptables -L -v -n
iptables -t nat -L -v -n

# Keep container alive
tail -f /dev/null
