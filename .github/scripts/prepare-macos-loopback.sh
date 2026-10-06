#!/usr/bin/env bash
set -euo pipefail

# The TURN lab deliberately gives independent relays distinct IP addresses because
# RFC 5766 permissions are IP-scoped. BSD only binds loopback aliases that exist;
# Linux and Windows already route/bind the 127/8 loopback range.
if [[ "$(uname -s)" == Darwin ]]; then
  for host in {2..254}; do
    sudo ifconfig lo0 alias "127.0.0.$host" netmask 255.0.0.0
  done
fi
