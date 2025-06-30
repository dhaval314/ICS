#!/bin/bash
echo "[+] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "[+] IP forwarding enabled."
