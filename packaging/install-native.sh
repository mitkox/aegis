#!/bin/sh
set -eu

usage() {
  cat <<'USAGE'
Usage: packaging/install-native.sh [--build] [--no-enable]

Install Aegis native Linux service assets. Run this script as root from the
repository checkout. Build as an unprivileged user first, or pass --build.

Required prebuilt binaries:
  target/release/aegis
  target/release/aegisctl
  target/release/aegisd
  target/release/aegis-reviewd
USAGE
}

assert_systemd_property() {
  unit="$1"
  property="$2"
  expected_fragment="$3"
  actual="$(systemctl show "$unit" --property="$property" --value)"
  case "$actual" in
    *"$expected_fragment"*)
      return 0
      ;;
  esac
  printf '%s\n' "error: $unit $property mismatch after install" >&2
  printf '%s\n' "  expected to contain: $expected_fragment" >&2
  printf '%s\n' "  actual:   $actual" >&2
  printf '%s\n' "hint: inspect with: systemctl cat $unit" >&2
  exit 1
}

assert_file_contains() {
  path="$1"
  needle="$2"
  if ! grep -Fq "$needle" "$path"; then
    printf '%s\n' "error: $path does not contain expected text: $needle" >&2
    exit 1
  fi
}

build=0
enable_units=1
for arg in "$@"; do
  case "$arg" in
    --build)
      build=1
      ;;
    --no-enable)
      enable_units=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' "error: run this installer from a root shell before starting Aegis services" >&2
  printf '%s\n' "hint: build as your normal user first, then become root and rerun: packaging/install-native.sh" >&2
  printf '%s\n' "note: this script intentionally does not invoke sudo or any package manager" >&2
  exit 1
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

if [ "$build" -eq 1 ]; then
  cargo build --release --locked --package aegis-cli --bins
fi

for bin in aegis aegisctl aegisd aegis-reviewd; do
  if [ ! -x "target/release/$bin" ]; then
    printf '%s\n' "error: missing target/release/$bin; run cargo build --release --locked --package aegis-cli --bins first" >&2
    exit 1
  fi
done

getent group aegis-admin >/dev/null || groupadd --system aegis-admin
getent group aegis-review >/dev/null || groupadd --system aegis-review
getent passwd aegis-review >/dev/null || \
  useradd --system --home-dir /var/lib/aegis-review --shell /usr/sbin/nologin --gid aegis-review aegis-review

install -d -m 0755 /usr/local/bin
install -d -m 0755 /usr/local/libexec/aegis
install -d -m 0750 -o root -g aegis-admin /etc/aegis
install -d -m 0750 -o root -g aegis-admin /var/lib/aegis
install -d -m 0750 -o root -g aegis-admin /var/cache/aegis
install -d -m 0750 -o root -g aegis-admin /var/log/aegis

install -m 0755 target/release/aegis /usr/local/bin/aegis
install -m 0755 target/release/aegisctl /usr/local/bin/aegisctl
install -m 0755 target/release/aegisd /usr/local/libexec/aegis/aegisd
install -m 0755 target/release/aegis-reviewd /usr/local/libexec/aegis/aegis-reviewd

install -m 0644 packaging/systemd/aegisd.service /etc/systemd/system/aegisd.service
install -m 0644 packaging/systemd/aegis-reviewd.service /etc/systemd/system/aegis-reviewd.service
install -m 0644 packaging/systemd/aegis-monitor.service /etc/systemd/system/aegis-monitor.service
install -m 0644 packaging/systemd/aegis-monitor.timer /etc/systemd/system/aegis-monitor.timer

systemctl disable aegisd.socket >/dev/null 2>&1 || true
rm -f /etc/systemd/system/aegisd.socket

if [ ! -f /etc/aegis/aegisd.env ]; then
  umask 077
  cat > /etc/aegis/aegisd.env <<'ENV'
# Set this to the public_key_hex produced by:
#   aegisctl keygen
AEGIS_SIGNING_PUBLIC_KEY_HEX=
ENV
fi

if [ ! -f /etc/aegis/aegis-reviewd.env ]; then
  umask 077
  cat > /etc/aegis/aegis-reviewd.env <<'ENV'
AEGIS_AI_BASE_URL=http://localhost:8000/v1
AEGIS_AI_MODEL=deepseek-v4-flash
ENV
fi

systemctl daemon-reload
systemctl reset-failed aegis-reviewd.service aegis-monitor.service aegisd.service >/dev/null 2>&1 || true

assert_file_contains /etc/systemd/system/aegis-monitor.service "ExecStart=/usr/local/bin/aegis doctor"
assert_file_contains /etc/systemd/system/aegis-reviewd.service "ExecStart=/usr/local/libexec/aegis/aegis-reviewd --socket /run/aegis/aegis-reviewd.sock"
assert_file_contains /etc/systemd/system/aegisd.service "ExecStart=/usr/local/libexec/aegis/aegisd --socket /run/aegis/aegisd.sock"
assert_systemd_property aegis-monitor.service ExecStart "path=/usr/local/bin/aegis ; argv[]=/usr/local/bin/aegis doctor"
assert_systemd_property aegis-reviewd.service ExecStart "path=/usr/local/libexec/aegis/aegis-reviewd ; argv[]=/usr/local/libexec/aegis/aegis-reviewd --socket /run/aegis/aegis-reviewd.sock"
assert_systemd_property aegisd.service ExecStart "path=/usr/local/libexec/aegis/aegisd ; argv[]=/usr/local/libexec/aegis/aegisd --socket /run/aegis/aegisd.sock"

if [ "$enable_units" -eq 1 ]; then
  systemctl enable aegis-reviewd.service aegis-monitor.timer
  if grep -Eq '^AEGIS_SIGNING_PUBLIC_KEY_HEX="?([[:xdigit:]]{64})"?$' /etc/aegis/aegisd.env; then
    systemctl enable aegisd.service
  else
    printf '%s\n' "warning: aegisd.service not enabled; set AEGIS_SIGNING_PUBLIC_KEY_HEX in /etc/aegis/aegisd.env first" >&2
  fi
fi

printf '%s\n' "installed Aegis native Linux assets"
