#!/usr/bin/env bash
set -euo pipefail

REPO="${PORTAL_PROXY_REPO:-DigitalPals/portal-proxy}"
INSTALLER_REF="${PORTAL_PROXY_INSTALLER_REF:-main}"
INSTALLER_URL="${PORTAL_PROXY_INSTALLER_URL:-https://raw.githubusercontent.com/${REPO}/${INSTALLER_REF}/scripts/install-debian.sh}"
RELEASE_VERSION="${PORTAL_PROXY_VERSION:-latest}"
INSTALL_DIR="${PORTAL_PROXY_INSTALL_DIR:-/usr/local/bin}"
STATE_DIR="${PORTAL_PROXY_STATE_DIR:-/var/lib/portal-proxy}"
USER_NAME="${PORTAL_PROXY_USER:-portal-proxy}"
INSTALL_SSHD_CONFIG="${PORTAL_PROXY_INSTALL_SSHD_CONFIG:-${PORTAL_PROXY_INSTALL_SSHD_MATCH:-1}}"
SSHD_PORT="${PORTAL_PROXY_SSH_PORT:-2222}"
INSTALL_PRUNE_TIMER="${PORTAL_PROXY_INSTALL_PRUNE_TIMER:-1}"
MAX_LOG_BYTES="${PORTAL_PROXY_MAX_LOG_BYTES:-67108864}"
ENDED_OLDER_THAN_DAYS="${PORTAL_PROXY_PRUNE_DAYS:-14}"

log() {
  printf 'portal-proxy installer: %s\n' "$*"
}

die() {
  printf 'portal-proxy installer: error: %s\n' "$*" >&2
  exit 1
}

need_root() {
  if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    return 0
  fi

  command -v sudo >/dev/null 2>&1 || die "this installer needs root; re-run as root or install sudo"
  command -v curl >/dev/null 2>&1 || die "curl is required to re-run installer through sudo"

  log "not running as root; re-running through sudo"
  curl -fsSL "$INSTALLER_URL" | sudo env \
    PORTAL_PROXY_REPO="$REPO" \
    PORTAL_PROXY_INSTALLER_REF="$INSTALLER_REF" \
    PORTAL_PROXY_INSTALLER_URL="$INSTALLER_URL" \
    PORTAL_PROXY_VERSION="$RELEASE_VERSION" \
    PORTAL_PROXY_INSTALL_DIR="$INSTALL_DIR" \
    PORTAL_PROXY_STATE_DIR="$STATE_DIR" \
    PORTAL_PROXY_USER="$USER_NAME" \
    PORTAL_PROXY_INSTALL_SSHD_CONFIG="$INSTALL_SSHD_CONFIG" \
    PORTAL_PROXY_SSH_PORT="$SSHD_PORT" \
    PORTAL_PROXY_INSTALL_PRUNE_TIMER="$INSTALL_PRUNE_TIMER" \
    PORTAL_PROXY_MAX_LOG_BYTES="$MAX_LOG_BYTES" \
    PORTAL_PROXY_PRUNE_DAYS="$ENDED_OLDER_THAN_DAYS" \
    bash
  exit $?
}

check_os() {
  [ -r /etc/os-release ] || die "/etc/os-release not found"
  local os_id os_id_like
  os_id="$(. /etc/os-release && printf '%s' "${ID:-}")"
  os_id_like="$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")"

  case "$os_id" in
    debian|ubuntu)
      return 0
      ;;
  esac

  case " ${os_id_like} " in
    *" debian "*)
      return 0
      ;;
  esac

  die "this installer supports Debian/Ubuntu LXCs only; detected ID=${os_id:-unknown}"
}

detect_asset() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf 'portal-proxy-linux-x86_64.tar.gz'
      ;;
    *)
      die "no prebuilt release asset for architecture $(uname -m)"
      ;;
  esac
}

release_url() {
  local asset="$1"
  if [ "$RELEASE_VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO" "$asset"
  else
    printf 'https://github.com/%s/releases/download/%s/%s\n' "$REPO" "$RELEASE_VERSION" "$asset"
  fi
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  log "installing package requirements"
  apt-get update
  apt-get install -y \
    ca-certificates \
    curl \
    dtach \
    openssh-client \
    openssh-server \
    tar \
    util-linux

  if ! command -v tailscale >/dev/null 2>&1; then
    if apt-cache policy tailscale 2>/dev/null | grep -q 'Candidate: [^()]'; then
      apt-get install -y tailscale
    else
      log "tailscale package is not available from configured apt repositories"
      log "install and enable Tailscale before using this proxy"
    fi
  fi
}

ensure_user_and_dirs() {
  local shell_path="/bin/sh"
  [ -x "$shell_path" ] || shell_path="/usr/bin/sh"

  if ! id "$USER_NAME" >/dev/null 2>&1; then
    log "creating dedicated user ${USER_NAME}"
    useradd --system --create-home --shell "$shell_path" "$USER_NAME"
  else
    usermod --shell "$shell_path" "$USER_NAME"
  fi

  local home_dir
  home_dir="$(getent passwd "$USER_NAME" | cut -d: -f6)"
  [ -n "$home_dir" ] || die "could not determine home directory for ${USER_NAME}"

  install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$STATE_DIR"
  install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "${home_dir}/.ssh"
  if [ ! -e "${home_dir}/.ssh/authorized_keys" ]; then
    install -o "$USER_NAME" -g "$USER_NAME" -m 0600 /dev/null "${home_dir}/.ssh/authorized_keys"
  else
    chown "$USER_NAME:$USER_NAME" "${home_dir}/.ssh/authorized_keys"
    chmod 0600 "${home_dir}/.ssh/authorized_keys"
  fi
}

install_binary() {
  local asset url tmpdir archive binary
  asset="$(detect_asset)"
  url="$(release_url "$asset")"
  tmpdir="$(mktemp -d)"
  archive="${tmpdir}/${asset}"

  log "downloading ${RELEASE_VERSION} from ${url}"
  curl -fsSL "$url" -o "$archive"
  tar -xzf "$archive" -C "$tmpdir"

  binary="$(find "$tmpdir" -maxdepth 2 -type f -name 'portal-proxy*' -perm -111 | head -n 1)"
  [ -n "$binary" ] || die "release archive did not contain an executable portal-proxy binary"

  install -d -m 0755 "$INSTALL_DIR"
  install -m 0755 "$binary" "${INSTALL_DIR}/portal-proxy"
  rm -rf "$tmpdir"
}

validate_sshd_port() {
  case "$SSHD_PORT" in
    ''|*[!0-9]*)
      die "PORTAL_PROXY_SSH_PORT must be a numeric TCP port"
      ;;
  esac

  [ "$SSHD_PORT" -ge 1 ] && [ "$SSHD_PORT" -le 65535 ] \
    || die "PORTAL_PROXY_SSH_PORT must be between 1 and 65535"
}

current_sshd_ports() {
  local sshd_bin="$1"
  "$sshd_bin" -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -n -u
}

reload_or_start_sshd() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
      || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    return 0
  fi

  if command -v service >/dev/null 2>&1; then
    service ssh reload 2>/dev/null || service sshd reload 2>/dev/null \
      || service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
  fi
}

install_sshd_config() {
  [ "$INSTALL_SSHD_CONFIG" = "1" ] || return 0
  [ -d /etc/ssh/sshd_config.d ] || return 0
  validate_sshd_port

  local config="/etc/ssh/sshd_config.d/99-portal-proxy.conf"
  local sshd_bin
  sshd_bin="$(command -v sshd)"
  sshd_bin="$(readlink -f "$sshd_bin" 2>/dev/null || printf '%s' "$sshd_bin")"
  mkdir -p /run/sshd

  local existing_ports written port
  existing_ports="$(current_sshd_ports "$sshd_bin" || true)"
  [ -n "$existing_ports" ] || existing_ports="22"

  log "installing sshd port config for port ${SSHD_PORT}"
  {
    printf '# Managed by Portal Proxy installer.\n'
    written=""
    for port in $existing_ports "$SSHD_PORT"; do
      case " $written " in
        *" $port "*) continue ;;
      esac
      printf 'Port %s\n' "$port"
      written="${written} ${port}"
    done
  } > "$config"

  if "$sshd_bin" -t; then
    reload_or_start_sshd
  else
    rm -f "$config"
    die "sshd config validation failed; removed ${config}"
  fi
}

install_prune_timer() {
  [ "$INSTALL_PRUNE_TIMER" = "1" ] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0
  [ -d /etc/systemd/system ] || return 0

  log "installing daily prune timer"
  cat > /etc/systemd/system/portal-proxy-prune.service <<EOF
[Unit]
Description=Prune Portal Proxy ended sessions and logs

[Service]
Type=oneshot
User=${USER_NAME}
Environment=PORTAL_PROXY_STATE_DIR=${STATE_DIR}
ExecStart=${INSTALL_DIR}/portal-proxy prune --ended-older-than-days ${ENDED_OLDER_THAN_DAYS} --max-log-bytes ${MAX_LOG_BYTES}
EOF

  cat > /etc/systemd/system/portal-proxy-prune.timer <<EOF
[Unit]
Description=Run Portal Proxy pruning daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now portal-proxy-prune.timer
}

run_doctor() {
  log "running doctor"
  runuser -u "$USER_NAME" -- env PORTAL_PROXY_STATE_DIR="$STATE_DIR" "${INSTALL_DIR}/portal-proxy" doctor
}

print_next_steps() {
  local home_dir
  home_dir="$(getent passwd "$USER_NAME" | cut -d: -f6)"

  cat <<EOF

Portal Proxy is installed.

Next steps:
1. Make sure this LXC is reachable only through Tailscale.
   If Tailscale was not already installed from your apt repositories, install it
   from Tailscale's official Debian/Ubuntu instructions and run: sudo tailscale up
2. Add your Portal client public key to:
   ${home_dir}/.ssh/authorized_keys

   Use this forced-command prefix:
   restrict,pty,agent-forwarding,command="${INSTALL_DIR}/portal-proxy serve --stdio" ssh-ed25519 AAAA...

3. In Portal settings, configure:
   Host: this LXC's Tailscale name or IP
   Port: ${SSHD_PORT}
   Username: ${USER_NAME}
   Identity file: the private key matching the public key above

Update later by running this installer again.
EOF
}

main() {
  need_root
  check_os
  install_packages
  ensure_user_and_dirs
  install_binary
  install_sshd_config
  install_prune_timer
  run_doctor
  print_next_steps
}

main "$@"
