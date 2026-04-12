#!/bin/bash
# RansomEye firewall rules (PRD-17, PRD-15 Air-Gap)
# Enforces loopback-only bindings for internal services.
# Blocks ALL outbound traffic (air-gap enforcement).

set -euo pipefail

echo "[RansomEye] Applying firewall rules..."

# Flush existing rules
iptables -F INPUT
iptables -F OUTPUT
iptables -F FORWARD

# Default policies: DROP all
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related connections (for gRPC streams)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow gRPC inbound on port 50051 (agent connections via mTLS)
iptables -A INPUT -p tcp --dport 50051 -j ACCEPT

# Block external access to internal ports (defense-in-depth)
iptables -A INPUT -p tcp --dport 50052 -s ! 127.0.0.1 -j DROP
iptables -A INPUT -p tcp --dport 50053 -s ! 127.0.0.1 -j DROP
iptables -A INPUT -p tcp --dport 5432  -s ! 127.0.0.1 -j DROP
iptables -A INPUT -p tcp --dport 6379  -s ! 127.0.0.1 -j DROP
iptables -A INPUT -p tcp --dport 8443  -s ! 127.0.0.1 -j DROP

# Allow HTTPS inbound for SOC Dashboard
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Block ALL outbound (air-gap: no external calls, no DNS, no telemetry)
# Only loopback outbound is permitted (already allowed above)

echo "[RansomEye] Firewall rules applied (air-gap enforced)."
