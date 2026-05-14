#!/bin/sh
set -eu

failures=0

check() {
  description="$1"
  shift
  if "$@"; then
    printf 'ok: %s\n' "$description"
  else
    printf 'error: %s\n' "$description" >&2
    failures=$((failures + 1))
  fi
}

unit_contains() {
  unit="$1"
  text="$2"
  systemctl cat "$unit" 2>/dev/null | grep -Fq "$text"
}

path_exists() {
  test -e "$1"
}

socket_exists_or_is_protected() {
  socket="$1"
  service="$2"
  if test -e "$socket"; then
    return 0
  fi
  if active "$service" && test -d /run/aegis && ! test -x /run/aegis; then
    return 0
  fi
  return 1
}

not_failed() {
  ! systemctl is-failed --quiet "$1"
}

active() {
  systemctl is-active --quiet "$1"
}

check "aegis CLI is installed" path_exists /usr/local/bin/aegis
check "aegisctl is installed" path_exists /usr/local/bin/aegisctl
check "aegisd is installed" path_exists /usr/local/libexec/aegis/aegisd
check "aegis-reviewd is installed" path_exists /usr/local/libexec/aegis/aegis-reviewd

check "aegis-monitor.service uses /usr/local/bin/aegis" \
  unit_contains aegis-monitor.service "ExecStart=/usr/local/bin/aegis doctor"
check "aegis-reviewd.service uses /usr/local/libexec" \
  unit_contains aegis-reviewd.service "ExecStart=/usr/local/libexec/aegis/aegis-reviewd --socket /run/aegis/aegis-reviewd.sock"
check "aegisd.service uses /usr/local/libexec" \
  unit_contains aegisd.service "ExecStart=/usr/local/libexec/aegis/aegisd --socket /run/aegis/aegisd.sock"

check "aegis-reviewd.service is active" active aegis-reviewd.service
check "aegisd.service is active" active aegisd.service
check "aegis-monitor.timer is active" active aegis-monitor.timer
check "aegis-monitor.service is not failed" not_failed aegis-monitor.service

check "runtime directory exists" path_exists /run/aegis
check "review daemon socket exists or is protected" \
  socket_exists_or_is_protected /run/aegis/aegis-reviewd.sock aegis-reviewd.service
check "executor daemon socket exists or is protected" \
  socket_exists_or_is_protected /run/aegis/aegisd.sock aegisd.service
check "state directory exists" path_exists /var/lib/aegis
check "cache directory exists" path_exists /var/cache/aegis
check "log directory exists" path_exists /var/log/aegis

if [ "$failures" -ne 0 ]; then
  printf '%s\n' "Aegis native service verification failed with $failures issue(s)." >&2
  printf '%s\n' "Inspect live units with: systemctl cat aegis-monitor.service aegis-reviewd.service aegisd.service" >&2
  printf '%s\n' "If unit paths still point at /usr/bin or /usr/libexec, run packaging/install-native.sh from a shell where id -u prints 0." >&2
  exit 1
fi

printf '%s\n' "Aegis native service verification passed."
