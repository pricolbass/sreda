#!/bin/sh
# Run inside the intended Debian LXC, after reviewing this script.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Установка требует root внутри LXC.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Поддерживается Debian LXC.' >&2; exit 1; }
[ -r /etc/os-release ] || { echo 'Не найден /etc/os-release.' >&2; exit 1; }
. /etc/os-release
[ "${ID:-}" = debian ] || { echo 'Поддерживается Debian 12 или 13.' >&2; exit 1; }
case "${VERSION_ID:-}" in 12|13) ;; *) echo 'Поддерживается Debian 12 или 13.' >&2; exit 1;; esac
[ "$(cat /proc/1/comm)" = systemd ] || { echo 'Нужен LXC с systemd.' >&2; exit 1; }
command -v wg-quick >/dev/null || { echo 'Сначала установите: apt-get update && apt-get install -y wireguard-tools iproute2 ca-certificates' >&2; exit 1; }
command -v ip >/dev/null
[ "$#" = 1 ] || { echo 'Использование: install.sh /путь/к/linux-бинарнику/sreda-agent' >&2; exit 1; }
[ -f "$1" ] && [ -x "$1" ] || { echo 'Бинарник агента не найден или не исполним.' >&2; exit 1; }
# Probe kernel WireGuard plus the namespace capability without contacting the gateway.
check_name="sreda-check-$$"
ip link add dev "$check_name" type wireguard || { echo 'WireGuard недоступен: проверьте модуль на Proxmox-хосте и CAP_NET_ADMIN в LXC. Установка не завершена.' >&2; exit 1; }
trap 'ip link del dev "$check_name" 2>/dev/null || true' EXIT HUP INT TERM
ip link del dev "$check_name"
trap - EXIT HUP INT TERM
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -m 0755 "$1" /usr/local/bin/sreda-agent
install -d -m 0700 /var/lib/sreda-agent
install -m 0644 "$script_dir/sreda-agent.service" /etc/systemd/system/sreda-agent.service
systemctl daemon-reload
systemctl enable sreda-agent.service
printf '%s\n' 'Служба установлена и включена для автозапуска. Теперь выполните:' 'sreda-agent enroll --origin https://АДРЕС-КАБИНЕТА' 'Затем: systemctl start sreda-agent'
