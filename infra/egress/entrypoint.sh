#!/bin/sh
set -eu

if [ -z "${RIFT_ALLOWED_TARGET_CIDRS:-}" ] || [ -z "${RIFT_DATABASE_CIDRS:-}" ]; then
  echo "RIFT_ALLOWED_TARGET_CIDRS and RIFT_DATABASE_CIDRS are required" >&2
  exit 1
fi

iptables -F OUTPUT
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

old_ifs="$IFS"
IFS=','
for cidr in $RIFT_DATABASE_CIDRS; do
  case "$cidr" in
    ""|0.0.0.0/0|10.*|127.*|169.254.*|172.1[6-9].*|172.2?.*|172.3[01].*|192.168.*)
      echo "unsafe or empty database CIDR: $cidr" >&2
      exit 1
      ;;
  esac
  iptables -A OUTPUT -p tcp -d "$cidr" --dport 5432 -j ACCEPT
done
for cidr in $RIFT_ALLOWED_TARGET_CIDRS; do
  case "$cidr" in
    ""|0.0.0.0/0|10.*|127.*|169.254.*|172.1[6-9].*|172.2?.*|172.3[01].*|192.168.*)
      echo "unsafe or empty target CIDR: $cidr" >&2
      exit 1
      ;;
  esac
  iptables -A OUTPUT -p tcp -d "$cidr" --dport 443 -j ACCEPT
done
IFS="$old_ifs"

touch /tmp/egress-ready
exec su-exec rift-egress tail -f /dev/null
