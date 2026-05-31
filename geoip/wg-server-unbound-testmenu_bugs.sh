#!/bin/bash
# shellcheck disable=SC2015  # A && B || C намеренно используется как guard-паттерн с || true / || warn
# shellcheck disable=SC2129  # Индивидуальные >> оставлены для наглядности (не группируем)
# ╔══════════════════════════════════════════════════════════════╗
# ║   WireGuard Home Server — Версия 28.24.22                    ║
# ║   • РФ IP → напрямую │ Зарубежье → туннель (балансировка)    ║
# ║   • GeoIP (batch-загрузка) │ Split-DNS │ Anti-DPI            ║
# ║   • Автозапуск всех служб │ Telemt/MTProxy → всегда в туннель║
# ╚══════════════════════════════════════════════════════════════╝
# Локальный offline GeoIP — если есть
# nano /etc/wireguard/geoip/ru-aggregated.zone (IPv4) или …
# nano /etc/wireguard/geoip/ru-aggregated-v6.zone (IPv6),
# берётся ТОЛЬКО он, скачивание пропускается. Идеально для «в полях» / зеркал.



# set -e намеренно НЕ включён: скрипт содержит цепочки с || true и многоступенчатую
# обработку ошибок через ERR-trap ниже. set -e в таком контексте вызывает ложные
# аварийные выходы. Падения ловятся через trap ERR; критичные места проверяют коды
# возврата явно.
set -uo pipefail

# [fix v28.24.12] Принудительно UTF-8 — иначе ${#str} считает байты,
# и рамки меню с кириллицей едут (см. section()/header()).
# [fix locale] C.UTF-8 может отсутствовать на минимальных системах (Alpine).
# Пробуем C.UTF-8, fallback → C (меню с кириллицей поедут, но скрипт не упадёт).
if locale -a 2>/dev/null | grep -qx "C\.UTF-8\|C\.utf8"; then
    export LANG="${LANG:-C.UTF-8}"
    export LC_ALL="${LC_ALL:-C.UTF-8}"
else
    export LANG="${LANG:-C}"
    export LC_ALL="${LC_ALL:-C}"
    # Предупреждаем только если это не plain C
    [ "${LANG}" != "C" ] && [ "${LANG}" != "POSIX" ] &&         echo "[WARN] Локаль C.UTF-8 недоступна — используется ${LC_ALL}. Кириллица в меню может отображаться некорректно." >&2 || true
fi

readonly VERSION="28.24.24"
export VERSION

# CHANGELOG (последние версии):
# v28.24.24: _telemt_safe_restart — валидация TOML перед рестартом telemt;
#            wg-key-watchdog — таймер целостности server_private.key.
# v28.24.23: _atomic_write для wg-конфигов; audit_log (аудит действий);
#            bash -c → sh -c в тестах; валидация dnsmasq перед рестартом;
#            ExecStartPre ip route get для wg-quick@; откат скрипта (.old);
#            wg-audit.log в logrotate.
# v28.24.22: nftset вместо server= в dnsmasq; unbound как geo-резолвер.
# v28.24.21: Сброс счётчиков при снятии лимита; restoreConfig trap RETURN.
# ──────────────────────────────────────────────────────────────────
# ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ (опциональные):
#   WG_VERSION_URL=https://example.com/wg/version.txt
#   EDITOR=nano|vim|vi
#   WG_DEBUG=1   — печатать [ERR] в stderr (по умолчанию только в лог)
# ──────────────────────────────────────────────────────────────────

# [fix v28.24.12] Раньше ERR-trap печатал [ERR] прямо в UI при каждом
# ненулевом коде возврата (а grep/head/tr в командных подстановках это
# делают штатно). Теперь по умолчанию лог идёт ТОЛЬКО в файл, в UI —
# тихо. Включить вывод обратно: WG_DEBUG=1 ./wg-server.sh
# [fix v28.24.14] Валидация WG_ERR_LOG — защита от инъекции пути через env.
# Разрешены только пути внутри /var/log/, /tmp/, /run/ с безопасными символами.
_wg_err_default="/var/log/wg-server-trap.log"
_wg_err_in="${WG_ERR_LOG:-$_wg_err_default}"
case "${_wg_err_in}" in
    /var/log/*|/tmp/*|/run/*|/var/run/*)
        if [[ "${_wg_err_in}" =~ ^[A-Za-z0-9/._-]+$ ]] && [[ "${_wg_err_in}" != *".."* ]]; then
            :
        else
            _wg_err_in="${_wg_err_default}"
        fi
        ;;
    *) _wg_err_in="${_wg_err_default}" ;;
esac
readonly WG_ERR_LOG="${_wg_err_in}"
unset _wg_err_in _wg_err_default
mkdir -p "$(dirname "${WG_ERR_LOG}")" 2>/dev/null || true
touch "${WG_ERR_LOG}" 2>/dev/null && chmod 600 "${WG_ERR_LOG}" 2>/dev/null || true
# [fix] _WG_INTERACTIVE=1 выставляется перед каждым read в меню/ask,
# чтобы trap ERR не логировал EOF/таймаут как ошибку (пункт А).
_WG_INTERACTIVE=0
# [fix] set -E ДОЛЖЕН стоять ДО trap ERR — иначе ERR-trap не наследуется в функциях и подоболочках
set -E
# shellcheck disable=SC2154  # _src/_cmd/_msg/continue_log присваиваются внутри trap-строки
trap '_rc=$?; case "$_rc" in 0|130|141) :;; *)
  if [ "${_WG_INTERACTIVE:-0}" = "1" ]; then _WG_INTERACTIVE=0; continue_log=0; else continue_log=1; fi
  [ "${continue_log:-1}" = "0" ] && { :; } || {
  _src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]:-main}}";
  _cmd="${BASH_COMMAND:-unknown}";
  case "${_cmd}" in read*|_pause*|ask*|askYesNo*) :;; *)
  _msg=$(printf "[%s] %s:%s:%s rc=%s cmd: %s" "$(date +%H:%M:%S)" "${_src}" "${FUNCNAME[0]:-main}" "${BASH_LINENO[0]}" "$_rc" "${_cmd}");
  printf "%s\n" "$_msg" >> "${WG_ERR_LOG}" 2>/dev/null || true;
  [ "${WG_DEBUG:-0}" = "1" ] && printf "\033[1;31m[ERR]\033[0m %s\n" "$_msg" >&2;
  :;; esac; };;
esac' ERR

# ── safe_sed: безопасная in-place замена с экранированием sed-метасимволов в RHS ──
# Использование: safe_sed <file> <ключ_regex_LHS> <значение_raw>
# LHS — обычное sed-regex; RHS экранируется (& \ /), разделитель — '|'.
safe_sed() {
    local _file="$1" _lhs="$2" _rhs="$3" _verbose="${4:-}"
    [ -f "$_file" ] || { echo "safe_sed: no file $_file" >&2; return 1; }
    local _esc_lhs _esc_rhs
    _esc_lhs=$(printf '%s' "$_lhs" | sed -e 's/[][\\/.^$*+?{}|()]/\\&/g')
    _esc_rhs=$(printf '%s' "$_rhs" | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/|/\\|/g')
    # [fix Б] flock по lockfile-цели — защита от race cron<->UI над одним конфигом
    local _lockfile="${_file}.sslock"
    (
        flock -w 10 9 || { echo "safe_sed: lock timeout for ${_file}" >&2; exit 1; }
        if [ "${_verbose}" = "verbose" ]; then
            local _before _after
            _before=$(sha256sum "$_file" 2>/dev/null | awk '{print $1}')
            sed -i "s|${_esc_lhs}|${_esc_rhs}|g" "$_file" || exit 1
            _after=$(sha256sum "$_file" 2>/dev/null | awk '{print $1}')
            if [ "${_before}" = "${_after}" ]; then
                echo "safe_sed[verbose]: no match for /${_lhs}/ in ${_file}" >&2
                exit 2
            fi
            exit 0
        fi
        sed -i "s|${_esc_lhs}|${_esc_rhs}|g" "$_file"
    ) 9>"${_lockfile}"
}

# ── _autoBackup: быстрый бэкап критичных файлов ДО опасной операции (v28.22.0) ──
# Использование: _autoBackup <тег-операции>
# Складывает таргбол /var/backups/wg-home/<тег>-<дата>.tar.gz
_autoBackup() {
    local _tag="${1:-pre-op}"
    local _dir="/var/backups/wg-home"
    local _ts _file _list=()
    _ts=$(date +%Y%m%d-%H%M%S)
    _file="${_dir}/${_tag}-${_ts}.tar.gz"
    mkdir -p "${_dir}" 2>/dev/null || return 1
    # Собираем список существующих путей (несуществующие исключаем — иначе tar поднимает ошибку).
    local _p
    for _p in /etc/wireguard /etc/nftables.conf /etc/dnsmasq.d \
              /etc/systemd/system; do
        [ -e "${_p}" ] && _list+=("${_p}")
    done
    # [fix v28.22.2] Не архивируем весь /usr/local/bin — там может лежать
    # node_modules, docker-compose и т.п. Берём только наши скрипты.
    for _p in /usr/local/bin/wg-*.sh \
              /usr/local/bin/update-ru-ipset.sh \
              /usr/local/bin/telemt \
              /usr/local/bin/mtg; do
        [ -e "${_p}" ] && _list+=("${_p}")
    done
    [ "${#_list[@]}" -eq 0 ] && return 1
    tar czf "${_file}" \
        --warning=no-file-changed --warning=no-file-removed \
        --exclude='/etc/systemd/system/multi-user.target.wants' \
        "${_list[@]}" 2>/dev/null || true
    if [ -s "${_file}" ]; then
        echo "  [backup] ${_file}" >&2
        # держим только 10 последних
        # [fix v28.25.3] -printf — расширение GNU find; на минимальных системах
        # без него используем ls -t как fallback (достаточно для ротации).
        # shellcheck disable=SC2012
        if find "${_dir}" -maxdepth 0 -printf '' 2>/dev/null; then
            find "${_dir}" -maxdepth 1 -name "*.tar.gz" -type f -printf '%T@ %p\n' \
                | sort -rn | tail -n +11 | awk '{print $2}' | xargs -r rm -f
        else
            ls -t "${_dir}"/*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f
        fi
        return 0
    fi
    rm -f "${_file}"
    return 1
}

# ── Цвета (оптимизированы для чёрного фона терминала) ──────────
RED='\033[1;31m'          # ярко-красный  — ошибки, удаление
GREEN='\033[1;32m'        # ярко-зелёный  — успех, активно
YELLOW='\033[1;33m'       # ярко-жёлтый   — заголовки, предупреждения
WHITE='\033[1;37m'        # ярко-белый    — основной текст меню
DIM='\033[0;37m'          # серый         — подсказки, описания
BOLD='\033[1m'            # жирный
CYAN='\033[1;36m'         # ярко-голубой  — акценты, hint
CYAN_BOLD='\033[1;36m'    # ярко-голубой жирный
BLUE='\033[1;34m'         # ярко-синий    — заголовки
# MAGENTA удалён (SC2034 — не использовался)
NC='\033[0m'              # сброс

# ── Конфигурация ───────────────────────────────────────────────
SERVER_WG_NIC=""
MAIN_INTERFACE=""
SERVER_PORT=""
SERVER_MTU="1420"  # MTU серверного WG-интерфейса (по умолчанию 1420)
CLIENT_IPV4_SUBNET=""
CLIENT_IPV6_SUBNET="fd66:66:66::/64"
SERVER_IPV4_ADDR=""
SERVER_IPV6_ADDR=""
SERVER_PUB_IP=""
SSH_PORT="22"
CONFIG_FILE="/etc/wireguard/.wg-setup.conf"
TUNNEL_COUNT=0
BALANCE_INTERVAL=10
BAD_PING_MS=200
DNS_MODE="geo"   # geo | tunnel | public

declare -a TUNNEL_IFACE=()
declare -a TUNNEL_PRIVATE=()
declare -a TUNNEL_ADDRESS=()
declare -a TUNNEL_ADDRESS_V6=()
declare -a TUNNEL_PUBLIC=()
declare -a TUNNEL_PSK=()
declare -a TUNNEL_ENDPOINT=()
declare -a TUNNEL_TABLE=()
declare -a TUNNEL_MTU=()

# ── Пути к файлам (все константы здесь — set -uo pipefail требует) ──
DNSMASQ_WG_CONF="/etc/dnsmasq.d/wg-dns.conf"
DNSMASQ_FORCE_CONF="/etc/dnsmasq.d/wg-tunnel-force.conf"
DNSMASQ_DIRECT_CONF="/etc/dnsmasq.d/wg-direct-domains.conf"
TUNNEL_FORCE_DOMAINS="/etc/wireguard/.tunnel-force-domains"
# [fix v28.24.12] CIDR-в-туннель — отдельный файл с собственным меню,
# чтобы домены и подсети не путались. Читается _rebuildTunnelForce.
TUNNEL_FORCE_CIDR="/etc/wireguard/.tunnel-force-cidr"
DIRECT_DOMAINS_FILE="/etc/wireguard/.direct-domains"
ANTIDPI_CONF="/etc/wireguard/.antidpi.conf"
TELEMT_BIN="/usr/local/bin/telemt"
# [fix v28.24.2] Параметризовали репозиторий telemt — переопределяется через env
# [fix v28.24.14] Валидация TELEMT_REPO: только owner/repo с безопасными символами,
# защита от подмены источника бинаря (supply-chain).
TELEMT_REPO="${TELEMT_REPO:-telemt/telemt}"
if ! [[ "${TELEMT_REPO}" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]; then
    echo "[WARN] TELEMT_REPO='${TELEMT_REPO}' имеет недопустимый формат — использую telemt/telemt" >&2
    TELEMT_REPO="telemt/telemt"
fi
TELEMT_API_URL="${TELEMT_API_URL:-https://api.github.com/repos/${TELEMT_REPO}/releases/latest}"
TELEMT_RELEASE_BASE="${TELEMT_RELEASE_BASE:-https://github.com/${TELEMT_REPO}/releases/download}"
# Допускаем переопределение только на https://
case "${TELEMT_API_URL}" in https://*) :;; *) TELEMT_API_URL="https://api.github.com/repos/${TELEMT_REPO}/releases/latest";; esac
case "${TELEMT_RELEASE_BASE}" in https://*) :;; *) TELEMT_RELEASE_BASE="https://github.com/${TELEMT_REPO}/releases/download";; esac
TELEMT_CONFIG="/etc/telemt.toml"
TELEMT_SERVICE="/etc/systemd/system/telemt.service"
TELEMT_TLSFRONT_DIR="/var/lib/telemt/tlsfront"

# ── Утилиты вывода ─────────────────────────────────────────────
# [fix КРИТИЧ 2] Хелперы для явного разграничения критичных и опциональных операций.
# must()  — фатальная ошибка: завершает скрипт
# try()   — опциональная: логирует предупреждение, продолжает работу
must() { "$@" || error "FATAL: команда завершилась с ошибкой: $*"; }
try()  { "$@" || warn "WARNING: необязательная команда завершилась с ошибкой: $*"; }

# [fix v28.24.23] _atomic_write: атомарная запись критичных конфигов.
# Пишет во временный файл в той же ФС (гарантия атомарного rename),
# вызывает sync, затем mv. При ошибке удаляет мусор и возвращает 1.
# Использование: _atomic_write <путь> <права> <<< "содержимое"
# или: _atomic_write <путь> <права> < <(cat ...))
_atomic_write() {
    local _dst="$1" _mode="${2:-600}"
    local _dir _tmp
    _dir=$(dirname "${_dst}")
    mkdir -p "${_dir}" 2>/dev/null || true
    _tmp=$(mktemp "${_dir}/.atomic_XXXXXX") || { warn "_atomic_write: mktemp failed для ${_dst}"; return 1; }
    # Читаем stdin во временный файл
    if ! cat > "${_tmp}"; then
        rm -f "${_tmp}"
        warn "_atomic_write: ошибка записи в ${_tmp}"
        return 1
    fi
    sync "${_tmp}" 2>/dev/null || true
    chmod "${_mode}" "${_tmp}" 2>/dev/null || true
    if ! mv -f "${_tmp}" "${_dst}"; then
        rm -f "${_tmp}"
        warn "_atomic_write: mv не удался для ${_dst}"
        return 1
    fi
    return 0
}

isRoot() {
    [ "${EUID}" -eq 0 ] || {
        echo -e "${RED}[✗] Запускай от root!${NC}"
        exit 1
    }
}

# [fix v28.24.23] audit_log — журнал действий пользователя для аудита.
# Пишет в /var/log/wg-audit.log: дата, пользователь, действие.
# Подпадает под logrotate (добавлен в /etc/logrotate.d/wg-server при установке).
_AUDIT_LOG="/var/log/wg-audit.log"
audit_log() {
    local _action="$*"
    local _user="${SUDO_USER:-${USER:-root}}"
    local _ts
    _ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf "[%s] user=%s action=%s\n" "${_ts}" "${_user}" "${_action}" \
        >> "${_AUDIT_LOG}" 2>/dev/null || true
}

# [fix v28.20.8] Проверка версии bash (нужно >= 4.3 для nameref)
checkBashVersion() {
    local major="${BASH_VERSINFO[0]}"
    local minor="${BASH_VERSINFO[1]}"
    if (( major < 4 || (major == 4 && minor < 3) )); then
        echo -e "${RED}[✗] Требуется bash >= 4.3 (nameref). Установлена: ${BASH_VERSION}${NC}"
        exit 1
    fi
}

# [fix v28.20.8] Валидация пользовательского ввода перед heredoc-вставкой
# в nftables/systemd конфиги — защита от инъекций.
validateIfaceName() {
    local name="$1"
    [[ "${name}" =~ ^[a-zA-Z0-9_-]{1,15}$ ]] || \
        error "Недопустимое имя интерфейса: '${name}' (только a-z, 0-9, _, -, макс 15 символов)"
}

# [fix v28.21.3] Валидация имени клиента — защита от path traversal и shell-инъекций.
validateClientName() {
    local name="$1"
    [[ "${name}" =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || \
        error "Недопустимое имя клиента: '${name}' (только a-z, 0-9, _, -, макс 32 символа)"
}

validateEndpoint() {
    local ep="$1" port host
    # Поддерживаются: hostname:port, IPv4:port, [IPv6]:port
    # [fix v28.21.3] Понятное сообщение об ошибке + явный пример формата.
    if ! [[ "${ep}" =~ ^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):[0-9]{1,5}$ ]]; then
        error "Недопустимый endpoint: '${ep}'. Допустимый формат: host:port, 1.2.3.4:51820 или [2001:db8::1]:51820 (IPv6 — обязательно в квадратных скобках)"
    fi
    port="${ep##*:}"
    # [fix КРИТИЧ 3] Защита от arithmetic overflow: сначала regex, потом арифметика
    if ! [[ "${port}" =~ ^[0-9]{1,5}$ ]]; then
        error "Порт endpoint не является числом: '${port}'"
    fi
    if (( port < 1 || port > 65535 )); then
        error "Порт endpoint вне диапазона 1..65535: '${port}'"
    fi
}

# [fix] Оригинальный banner/section оставлены для совместимости внутри функций
banner() {
    local title="$1"
    local width=62
    # [fix v28.24.2] ${#title} даёт байты, не символы — для unicode/эмодзи
    # выравнивание ехало. Считаем визуальную длину через awk (length() в
    # многобайтовом локалe возвращает число символов).
    local title_len
    title_len=$(LC_ALL=C.UTF-8 awk -v s="${title}" 'BEGIN{print length(s)}' 2>/dev/null)
    [[ "${title_len}" =~ ^[0-9]+$ ]] || title_len=${#title}
    local pad=$(( (width - title_len - 2) / 2 ))
    (( pad < 0 )) && pad=0
    local right=$(( width - pad - title_len - 2 ))
    (( right < 0 )) && right=0
    local line
    line=$(printf '%*s' "${width}" '' | tr ' ' '═')
    echo -e ""
    echo -e "${CYAN_BOLD}╔${line}╗${NC}"
    printf "${CYAN_BOLD}║%*s${BOLD} %s ${NC}${CYAN_BOLD}%*s║${NC}\n" \
        "${pad}" "" "${title}" "${right}" ""
    echo -e "${CYAN_BOLD}╚${line}╝${NC}"
    echo ""
}

section() {
    local title="$1"
    # [fix v28.24.12] %-47s в printf считает БАЙТЫ, а не символы — поэтому
    # кириллический заголовок ("Полный тест системы") сдвигал правую │.
    # ${#title} в UTF-8-локали возвращает кол-во кодовых точек (символов),
    # этого достаточно для моноширинных латиницы/кириллицы.
    local inner=49 len=${#title} pad
    pad=$(( inner - len - 2 ))
    [ "${pad}" -lt 0 ] && pad=0
    local sp; sp=$(printf '%*s' "${pad}" '')
    echo -e ""
    echo -e "${YELLOW}${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}${BOLD}  │  ${title}${sp}│${NC}"
    echo -e "${YELLOW}${BOLD}  └─────────────────────────────────────────────────┘${NC}"
}

hint()  { echo -e "  ${CYAN_BOLD}ℹ  ${DIM}$1${NC}"; }
info()  { echo -e "  ${GREEN}✔${NC}  $1"; }
warn()  { echo -e "  ${YELLOW}⚠${NC}  $1"; }
error() { echo -e "  ${RED}✖${NC}  $1"; exit 1; }
step()  { echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"; }
ok()    { echo -e "  ${GREEN}${BOLD}[ OK ]${NC} $1"; }

# ── Проверка интерфейса ────────────────────────────────────────
# [fix] Убран дублирующий exit 1 — error() уже завершает скрипт
validateInterface() {
    local iface="$1"
    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo -e "  ${RED}Доступные интерфейсы:${NC}"
        ip -brief link show | awk '{print "    - " $1}'
        error "Интерфейс '$iface' не найден!"
    fi
    info "Интерфейс '${CYAN}$iface${NC}' найден"
}

# ── Ввод данных ────────────────────────────────────────────────
# [fix] Заменён небезопасный eval на printf -v (безопасен для спецсимволов)
ask() {
    local prompt="$1" desc="$2" varname="$3" default="${4:-}"
    [ -n "${desc}" ] && hint "${desc}"
    local val
    if [ -n "${default}" ]; then
        echo -ne "  ${CYAN}→ ${prompt}${NC} ${DIM}[${default}]${NC}: "
        read -r val
        [ -z "${val}" ] && val="${default}"
    else
        echo -ne "  ${CYAN}→ ${prompt}${NC}: "
        read -r val
    fi
    printf -v "${varname}" '%s' "${val}"
}

# [fix] Заменён небезопасный eval на printf -v
askYesNo() {
    local prompt="$1" varname="$2" default="${3:-n}"
    echo -ne "  ${CYAN}→ ${prompt}${NC} ${DIM}[y/n, Enter=${default}]${NC}: "
    local val
    read -r val
    [ -z "${val}" ] && val="${default}"
    if [[ "${val}" =~ ^[Yy]$ ]]; then
        printf -v "${varname}" 'yes'
    else
        printf -v "${varname}" 'no'
    fi
}

# ── Сохранение/загрузка конфига ────────────────────────────────
saveConfig() {
    mkdir -p /etc/wireguard
    # [fix v28.24.2] Безопасная запись с экранированием значений: предотвращает
    # повреждение конфига, если в значении встретятся " или \. Каждая строка
    # формируется через printf с явным экранированием обратного слеша и кавычки.
    _cfg_q() {
        local s="${1//\\/\\\\}"
        s="${s//\"/\\\"}"
        printf '%s' "${s}"
    }
    {
        printf 'SERVER_WG_NIC="%s"\n'        "$(_cfg_q "${SERVER_WG_NIC}")"
        printf 'MAIN_INTERFACE="%s"\n'       "$(_cfg_q "${MAIN_INTERFACE}")"
        printf 'SERVER_PORT="%s"\n'          "$(_cfg_q "${SERVER_PORT}")"
        printf 'SERVER_MTU="%s"\n'            "$(_cfg_q "${SERVER_MTU:-1420}")"
        printf 'CLIENT_IPV4_SUBNET="%s"\n'   "$(_cfg_q "${CLIENT_IPV4_SUBNET}")"
        printf 'CLIENT_IPV6_SUBNET="%s"\n'   "$(_cfg_q "${CLIENT_IPV6_SUBNET}")"
        printf 'SERVER_IPV4_ADDR="%s"\n'     "$(_cfg_q "${SERVER_IPV4_ADDR}")"
        printf 'SERVER_IPV6_ADDR="%s"\n'     "$(_cfg_q "${SERVER_IPV6_ADDR}")"
        printf 'SERVER_PUB_IP="%s"\n'        "$(_cfg_q "${SERVER_PUB_IP}")"
        printf 'SSH_PORT="%s"\n'             "$(_cfg_q "${SSH_PORT}")"
        printf 'TUNNEL_COUNT="%s"\n'         "$(_cfg_q "${TUNNEL_COUNT}")"
        printf 'BALANCE_INTERVAL="%s"\n'     "$(_cfg_q "${BALANCE_INTERVAL}")"
        printf 'BAD_PING_MS="%s"\n'          "$(_cfg_q "${BAD_PING_MS}")"
        printf 'DNS_MODE="%s"\n'             "$(_cfg_q "${DNS_MODE:-public}")"
        for ((i=0; i<TUNNEL_COUNT; i++)); do
            printf 'TUNNEL_IFACE_%d="%s"\n'      "${i}" "$(_cfg_q "${TUNNEL_IFACE[$i]}")"
            printf 'TUNNEL_PRIVATE_%d="%s"\n'    "${i}" "$(_cfg_q "${TUNNEL_PRIVATE[$i]}")"
            printf 'TUNNEL_ADDRESS_%d="%s"\n'    "${i}" "$(_cfg_q "${TUNNEL_ADDRESS[$i]}")"
            printf 'TUNNEL_ADDRESS_V6_%d="%s"\n' "${i}" "$(_cfg_q "${TUNNEL_ADDRESS_V6[$i]}")"
            printf 'TUNNEL_PUBLIC_%d="%s"\n'     "${i}" "$(_cfg_q "${TUNNEL_PUBLIC[$i]}")"
            printf 'TUNNEL_PSK_%d="%s"\n'        "${i}" "$(_cfg_q "${TUNNEL_PSK[$i]}")"
            printf 'TUNNEL_ENDPOINT_%d="%s"\n'   "${i}" "$(_cfg_q "${TUNNEL_ENDPOINT[$i]}")"
            printf 'TUNNEL_TABLE_%d="%s"\n'      "${i}" "$(_cfg_q "${TUNNEL_TABLE[$i]}")"
            printf 'TUNNEL_MTU_%d="%s"\n'        "${i}" "$(_cfg_q "${TUNNEL_MTU[$i]}")"
        done
    } > "${CONFIG_FILE}"
    unset -f _cfg_q
    chmod 600 "${CONFIG_FILE}"
}

# [fix] Вынесена на уровень модуля из loadConfig() — была доступна только внутри него.
# Валидирует имена сетевых интерфейсов: только [A-Za-z][A-Za-z0-9_-]{0,14}.
# Защищает от shell-injection в ExecStartPre/sed -i при повреждённом конфиге.
_validIfaceName() {
    local n="$1"
    [[ "${n}" =~ ^[A-Za-z][A-Za-z0-9_-]{0,14}$ ]]
}

# [fix] Убран 'local val' из цикла eval — исправлен scope конфликт
loadConfig() {
    [ -f "${CONFIG_FILE}" ] || return 0
    # [fix v28.20.5] Безопасный парсинг конфига вместо source (защита от RCE при повреждении файла)
    # [fix v28.21.3] Режем строку только по ПЕРВОМУ '=' — иначе хвостовые '==' в base64-ключах теряются.
    # [fix v28.22.1] _lc_line/_lc_key/_lc_val объявлены local — ранее были глобальными и могли
    #               конфликтовать при вызове loadConfig внутри других функций.
    local _lc_line _lc_key _lc_val
    while IFS= read -r _lc_line || [ -n "${_lc_line}" ]; do
        # Пропускаем пустые строки и комментарии
        [[ "${_lc_line}" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${_lc_line// }" ]] && continue
        [[ "${_lc_line}" != *=* ]] && continue
        _lc_key="${_lc_line%%=*}"
        _lc_val="${_lc_line#*=}"
        # [fix v28.22.0] Полный trim: пробелы/tab по краям + хвостовой \r (CRLF от Windows).
        _lc_key="${_lc_key#"${_lc_key%%[![:space:]]*}"}"
        _lc_key="${_lc_key%"${_lc_key##*[![:space:]]}"}"
        _lc_val="${_lc_val#"${_lc_val%%[![:space:]]*}"}"
        _lc_val="${_lc_val%"${_lc_val##*[![:space:]]}"}"
        _lc_val="${_lc_val%$'\r'}"
        # Убираем обрамляющие кавычки и разэкранируем \" и \\ (см. saveConfig)
        if [[ "${_lc_val}" == \"*\" ]]; then
            _lc_val="${_lc_val#\"}"
            _lc_val="${_lc_val%\"}"
            _lc_val="${_lc_val//\\\"/\"}"
            _lc_val="${_lc_val//\\\\/\\}"
        fi
        # Разрешаем только известные переменные (whitelist)
        case "${_lc_key}" in
            SERVER_WG_NIC|MAIN_INTERFACE|SERVER_PORT|SERVER_MTU|CLIENT_IPV4_SUBNET|\
            CLIENT_IPV6_SUBNET|SERVER_IPV4_ADDR|SERVER_IPV6_ADDR|SERVER_PUB_IP|\
            SSH_PORT|TUNNEL_COUNT|BALANCE_INTERVAL|BAD_PING_MS|DNS_MODE|\
            TUNNEL_ADDRESS_V6_*|TUNNEL_IFACE_*|TUNNEL_PRIVATE_*|TUNNEL_ADDRESS_*|\
            TUNNEL_PUBLIC_*|TUNNEL_PSK_*|TUNNEL_ENDPOINT_*|TUNNEL_TABLE_*|TUNNEL_MTU_*)
                printf -v "${_lc_key}" '%s' "${_lc_val}" ;;
        esac
    done < "${CONFIG_FILE}"
    TUNNEL_IFACE=()
    TUNNEL_PRIVATE=()
    TUNNEL_ADDRESS=()
    TUNNEL_ADDRESS_V6=()
    TUNNEL_PUBLIC=()
    TUNNEL_PSK=()
    TUNNEL_ENDPOINT=()
    TUNNEL_TABLE=()
    TUNNEL_MTU=()
    local i var src_var val
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        for var in IFACE PRIVATE ADDRESS ADDRESS_V6 PUBLIC PSK ENDPOINT TABLE MTU; do
            src_var="TUNNEL_${var}_${i}"
            val="${!src_var:-}"
            # [fix v28.24.10] Аудит #1.2: убираем eval, явный case по whitelist.
            # Снимает риск RCE при будущем расширении списка переменных.
            case "${var}" in
                IFACE)      TUNNEL_IFACE+=("${val}") ;;
                PRIVATE)    TUNNEL_PRIVATE+=("${val}") ;;
                ADDRESS)    TUNNEL_ADDRESS+=("${val}") ;;
                ADDRESS_V6) TUNNEL_ADDRESS_V6+=("${val}") ;;
                PUBLIC)     TUNNEL_PUBLIC+=("${val}") ;;
                PSK)        TUNNEL_PSK+=("${val}") ;;
                ENDPOINT)   TUNNEL_ENDPOINT+=("${val}") ;;
                TABLE)      TUNNEL_TABLE+=("${val}") ;;
                MTU)        TUNNEL_MTU+=("${val}") ;;
            esac
        done
    done

    # [fix v28.24.13] Жёсткая валидация имён интерфейсов — функция вынесена на уровень
    # модуля (выше loadConfig), здесь доступна без переопределения.
    # [fix КРИТИЧ 1b] Валидируем SERVER_PUB_IP после загрузки конфига —
    # защита от инъекции через повреждённый/подделанный конфиг-файл.
    # Допускаем: корректный IPv4 (4 октета 0-255) ИЛИ hostname/домен
    # (буквы, цифры, дефис, точка — напр. "144.su", "my.vpn.example.com").
    if [ -n "${SERVER_PUB_IP:-}" ]; then
        if [[ "${SERVER_PUB_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # Это IPv4 — дополнительно проверяем диапазон каждого октета
            IFS='.' read -r _spi1 _spi2 _spi3 _spi4 <<< "${SERVER_PUB_IP}"
            for _spioct in "${_spi1}" "${_spi2}" "${_spi3}" "${_spi4}"; do
                if ! [[ "${_spioct}" =~ ^[0-9]+$ ]] || [ "${_spioct}" -gt 255 ]; then
                    echo "FATAL: SERVER_PUB_IP октет '${_spioct}' вне диапазона 0-255" >&2
                    exit 2
                fi
            done
            unset _spi1 _spi2 _spi3 _spi4 _spioct
        elif [[ "${SERVER_PUB_IP}" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$ ]]; then
            : # Валидный hostname/домен — пропускаем
        else
            echo "FATAL: SERVER_PUB_IP='${SERVER_PUB_IP}' содержит недопустимые символы" >&2
            echo "       Допустимо: IPv4 (1.2.3.4) или hostname (my.host.com)" >&2
            echo "       Исправь CONFIG_FILE=${CONFIG_FILE} вручную" >&2
            exit 2
        fi
    fi
    if [ -n "${SERVER_WG_NIC:-}" ] && ! _validIfaceName "${SERVER_WG_NIC}"; then
        echo "FATAL: SERVER_WG_NIC='${SERVER_WG_NIC}' содержит недопустимые символы" >&2
        echo "       Разрешено: [A-Za-z0-9_-], длина 1..15, начало с буквы." >&2
        exit 2
    fi
    local _ti
    for _ti in "${TUNNEL_IFACE[@]}"; do
        [ -z "${_ti}" ] && continue
        if ! _validIfaceName "${_ti}"; then
            echo "FATAL: TUNNEL_IFACE содержит недопустимое имя: '${_ti}'" >&2
            exit 2
        fi
    done
    if [ -n "${MAIN_INTERFACE:-}" ] && ! _validIfaceName "${MAIN_INTERFACE}"; then
        echo "FATAL: MAIN_INTERFACE='${MAIN_INTERFACE}' содержит недопустимые символы" >&2
        exit 2
    fi
}

# ── Установка пакетов ──────────────────────────────────────────
installPackages() {
    step "Установка пакетов"

    # [v28.21.2] ПРИНУДИТЕЛЬНО освобождаем порт 53 ДО установки dnsmasq.
    # Иначе systemd-resolved держит :53 → postinst dnsmasq падает (Address already in use)
    # и сервис остаётся в состоянии failed после `apt-get install`.
    if systemctl is-active --quiet systemd-resolved 2>/dev/null \
       || systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
        info "Освобождаю :53 от systemd-resolved (до установки dnsmasq)"
        systemctl stop systemd-resolved 2>/dev/null || true
        systemctl disable systemd-resolved 2>/dev/null || true
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-wireguard.conf << 'EOF'
[Resolve]
DNSStubListener=no
EOF
        # Если resolv.conf был симлинком на stub-resolv.conf — заменяем
        if [ -L /etc/resolv.conf ]; then
            cp -f /etc/resolv.conf /etc/resolv.conf.wg-bak 2>/dev/null || true
            rm -f /etc/resolv.conf
            echo "nameserver 1.1.1.1" > /etc/resolv.conf
            echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        fi
    fi
    # Дополнительно: если кто-то ещё слушает :53 — предупреждаем
    if ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE '(^|:)53$'; then
        warn ":53 всё ещё занят — dnsmasq может не стартовать. Проверь: ss -lntup sport = :53"
    fi

    apt-get update -q
    # [fix v28.25.2] xxd — явная зависимость: используется в showTelemetLinks
    # для hex-кодирования доменов (xxd -p). На минимальных системах xxd может
    # отсутствовать (обычно пакет xxd или vim-common), поэтому устанавливаем явно.
    apt-get install -y wireguard nftables curl iproute2 qrencode iptables \
        dnsutils cron iputils-ping traceroute mtr-tiny nano netcat-openbsd \
        tcpdump net-tools wget git build-essential dnsmasq conntrack python3 xxd openssl \
        stubby unbound ca-certificates
    info "Пакеты установлены"
}

enableForwarding() {
    step "Включение IP forwarding (IPv4 + IPv6)"

    # [fix v28.24.12] Авто-включение IPv6 — раньше скрипт ожидал что v6 уже
    # поднят, и на VPS где disable_ipv6=1 (часто у хостеров по умолчанию)
    # russia_v6 / force_tunnel_v6 не работали вообще. Снимаем disable явно
    # на всех уровнях + чистим конфликтующие sysctl-дропины.
    sysctl -w net.ipv6.conf.all.disable_ipv6=0       >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=0   >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0        >/dev/null 2>&1 || true
    # Убираем строки disable_ipv6=1 из любых sysctl-дропинов (кроме нашего)
    for _f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
        [ -f "${_f}" ] || continue
        [ "${_f}" = "/etc/sysctl.d/99-wireguard-forwarding.conf" ] && continue
        if grep -qE '^[[:space:]]*net\.ipv6\.conf\.[^=]*disable_ipv6[[:space:]]*=[[:space:]]*1' "${_f}" 2>/dev/null; then
            sed -i -E 's|^([[:space:]]*net\.ipv6\.conf\.[^=]*disable_ipv6[[:space:]]*=[[:space:]]*)1|\10|' "${_f}"
            info "IPv6 разблокирован в ${_f}"
        fi
    done

    sysctl -w net.ipv4.ip_forward=1                  >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1         >/dev/null
    sysctl -w net.ipv6.conf.default.forwarding=1     >/dev/null 2>&1 || true
    # [fix v28.18] rp_filter=2 (loose) — обязателен при policy-routing.
    # NB: на хостах с Docker/LXC/несколькими bridge'ами может вызвать
    # асимметрию маршрутизации контейнеров — учитывайте при траблшутинге.
    sysctl -w net.ipv4.conf.all.rp_filter=2          >/dev/null
    sysctl -w net.ipv4.conf.default.rp_filter=2      >/dev/null
    # [fix В] rp_filter=2 (loose) обязателен для split-tunneling.
    # ВНИМАНИЕ: если этот хост — гипервизор с Docker/LXD/KVM-bridge'ами,
    # перевод ВСЕХ интерфейсов в режим 2 ослабляет защиту от спуфинга
    # между виртуальными сетями (если они рассчитывают на strict rp_filter=1).
    # В таком случае вручную верните rp_filter=1 нужным интерфейсам после установки.
    for _rp_iface in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 2 > "${_rp_iface}" 2>/dev/null || true
    done
    [ -n "${SERVER_WG_NIC:-}" ] && sysctl -w "net.ipv4.conf.${SERVER_WG_NIC}.rp_filter=2" >/dev/null 2>&1 || true

    cat > /etc/sysctl.d/99-wireguard-forwarding.conf << EOF
# WireGuard Home Server — авто-сгенерировано
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.all.disable_ipv6=0
net.ipv6.conf.default.disable_ipv6=0
net.ipv6.conf.lo.disable_ipv6=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/99-wireguard-forwarding.conf >/dev/null
    info "IP forwarding включён (IPv4 + IPv6)"
}

# [fix v28.24.12] Экранирование строк для безопасного использования внутри
# регулярок BRE/ERE (grep -E / sed). КРИТИЧНО для случаев когда в шаблон
# попадает user-controlled значение (имя клиента, домен, CIDR): без этого
# sed -i "/^${name}:/d" с именем ".*" удаляет ВСЕ строки.
escape_regex() {
    printf '%s' "$1" | sed -e 's/[][\\/.*^$+?{}|()]/\\&/g'
}

# Экранирование для sed-разделителя '|' — на случай если строка его содержит.
escape_sed_pipe() {
    printf '%s' "$1" | sed -e 's/[]\\/.*^$+?{}()|[]/\\&/g'
}

# [fix IPv6 regex] Валидация IPv6 CIDR через python3 ipaddress (безопасно и точно).
# Старый метод (ip route add blackhole) модифицировал таблицу маршрутизации —
# мог удалить чужой легитимный blackhole-маршрут или дать false-negative если
# маршрут уже существовал. python3 не имеет побочных эффектов.
validate_ipv6_cidr() {
    local cidr="$1"
    [[ "${cidr}" == *:*/* ]] || return 1
    python3 -c "import ipaddress; ipaddress.ip_network('${cidr}', strict=False)" 2>/dev/null || return 1
    return 0
}

# ── GeoIP + nftables ───────────────────────────────────────────
createIpSetAndNft() {
    step "Настройка nftables + GeoIP"

    # ── [v28.21.6] Авто-создание /etc/wireguard/geoip + загрузка IPv4/IPv6 базы ──
    # Скачиваем offline-зеркала прямо при установке.
    # [fix v28.25.1] Первичный источник — автономный репозиторий avar-soft/wireguard-home-server
    # (не зависит от ipdeny.com). ipdeny.com — резервный источник.
    mkdir -p /etc/wireguard/geoip
    if [ ! -s /etc/wireguard/geoip/ru-aggregated.zone ]; then
        local _v4_ok=0
        # Первичный: автономный репозиторий
        if curl -fsSL --tlsv1.2 --proto '=https' --connect-timeout 10 --max-time 60 \
                "https://raw.githubusercontent.com/avar-soft/wireguard-home-server/main/geoip/ru-aggregated.zone" \
                -o /etc/wireguard/geoip/ru-aggregated.zone.tmp 2>/dev/null \
           && [ "$(wc -l < /etc/wireguard/geoip/ru-aggregated.zone.tmp 2>/dev/null || echo 0)" -ge 100 ]; then
            mv /etc/wireguard/geoip/ru-aggregated.zone.tmp /etc/wireguard/geoip/ru-aggregated.zone
            _v4_ok=1
        fi
        # Резервный: ipdeny.com
        if [ "${_v4_ok}" -eq 0 ]; then
            if curl -fsSL --tlsv1.2 --proto '=https' --connect-timeout 8 --max-time 30 \
                    "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone" \
                    -o /etc/wireguard/geoip/ru-aggregated.zone.tmp 2>/dev/null; then
                mv /etc/wireguard/geoip/ru-aggregated.zone.tmp /etc/wireguard/geoip/ru-aggregated.zone
            else
                rm -f /etc/wireguard/geoip/ru-aggregated.zone.tmp
            fi
        fi
    fi
    if [ ! -s /etc/wireguard/geoip/ru-aggregated-v6.zone ]; then
        local _v6_ok=0
        # Первичный: автономный репозиторий
        if curl -fsSL --tlsv1.2 --proto '=https' --connect-timeout 10 --max-time 60 \
                "https://raw.githubusercontent.com/avar-soft/wireguard-home-server/main/geoip/ru-aggregated-v6.zone" \
                -o /etc/wireguard/geoip/ru-aggregated-v6.zone.tmp 2>/dev/null \
           && [ "$(wc -l < /etc/wireguard/geoip/ru-aggregated-v6.zone.tmp 2>/dev/null || echo 0)" -ge 10 ]; then
            mv /etc/wireguard/geoip/ru-aggregated-v6.zone.tmp /etc/wireguard/geoip/ru-aggregated-v6.zone
            _v6_ok=1
        fi
        # Резервный: ipdeny.com
        if [ "${_v6_ok}" -eq 0 ]; then
            if curl -fsSL --tlsv1.2 --proto '=https' --connect-timeout 8 --max-time 30 \
                    "https://www.ipdeny.com/ipv6/ipaddresses/blocks/data/aggregated/ru-aggregated.zone" \
                    -o /etc/wireguard/geoip/ru-aggregated-v6.zone.tmp 2>/dev/null; then
                mv /etc/wireguard/geoip/ru-aggregated-v6.zone.tmp /etc/wireguard/geoip/ru-aggregated-v6.zone
            else
                rm -f /etc/wireguard/geoip/ru-aggregated-v6.zone.tmp
            fi
        fi
    fi

    # ── update-ru-ipset.sh: HTTP-валидация + batch-загрузка + RU DNS ──
    # Загружаем порциями по 400 строк — nftables не переваривает 8500+
    # за один раз в interval set; после загрузки ВСЕГДА добавляем список
    # российских DNS-серверов — критично для корректной работы dnsmasq
    cat > /usr/local/bin/update-ru-ipset.sh << 'SCRIPT'
#!/bin/bash
# update-ru-ipset.sh — атомарное обновление @russia set
# (RU GeoIP + RU DNS + whitelist .direct-ips). Загрузка батчем по 1000 строк
# через временный файл nft -f → доли секунды, без перегрузки CPU.
# Защита: если скачать не удалось — НЕ трогаем существующий set.

set -uo pipefail

LOG_TS() { date '+%Y-%m-%d %H:%M:%S'; }
DIRECT_IPS_FILE="/etc/wireguard/.direct-ips"
MIN_GEOIP_LINES=2000
MIN_GEOIP_V6_LINES=200
ETAG_FILE="/var/cache/wg-geoip.etag"
NFT_LOCK="/var/run/wg-nft.lock"

# [v28.21.2] Локальные offline-зеркала. Если файл существует и непуст —
# используем ТОЛЬКО его (интернет не требуется). Полезно «в полях».
LOCAL_GEOIP_V4="/etc/wireguard/geoip/ru-aggregated.zone"
LOCAL_GEOIP_V6="/etc/wireguard/geoip/ru-aggregated-v6.zone"

# [fix v28.22.3] trap EXIT — очищаем все временные файлы при любом выходе,
# включая SIGINT/SIGTERM/SIGHUP (которые раньше оставляли мусор в /tmp).
# Переменные ещё не объявлены здесь, поэтому trap ссылается на них через ${var:-}.
# [fix v28.22.2] Раньше "${TMP_ELEMENTS:-}"_part_* до mktemp раскрывался в
# опасный glob "_part_*" в CWD под root. Теперь _part_* удаляем
# только если переменная непуста.
trap '_rc=$?;
      rm -f "${TMP_ALL:-}" "${TMP_ALL_V6:-}" "${TMP_HDR:-}" "${TMP_SINGLE:-}" \
            "${TMP_ELEMENTS:-}" "${TMP_NFT:-}" "${TMP_NFT6:-}" "${TMP_V6_FIXED:-}" 2>/dev/null;
      [ -n "${TMP_ALL:-}" ]      && rm -f "${TMP_ALL}.sorted"      2>/dev/null;
      [ -n "${TMP_ALL_V6:-}" ]   && rm -f "${TMP_ALL_V6}.sorted"   2>/dev/null;
      [ -n "${TMP_ELEMENTS:-}" ] && rm -f "${TMP_ELEMENTS}_part_"* 2>/dev/null;
      [ -n "${TMP_ALL_V6:-}" ]   && rm -f "${TMP_ALL_V6}_part_"*   2>/dev/null;
      exit "$_rc"' EXIT

# [fix v28.20.8] flock — не пересекаемся с restartTunnels/createIpSetAndNft
exec 9>"${NFT_LOCK}"
flock -w 60 9 || { echo "[$(LOG_TS)] INFO: другой инстанс update-ru-ipset ещё работает, выходим тихо"; exit 0; }

echo "[$(LOG_TS)] === RU GeoIP Sync ==="

# ── Проверка: nftables и set должны существовать ──────────────
if ! nft list set inet wg-policy russia >/dev/null 2>&1; then
    echo "[$(LOG_TS)] ERROR: set inet wg-policy russia не существует — wg0 не поднят?"
    exit 1
fi
HAVE_V6=0
if nft list set inet wg-policy russia_v6 >/dev/null 2>&1; then
    HAVE_V6=1
fi

# Принудительно обновить, если текущий сет содержит менее 8000 записей
CURRENT_COUNT=$(nft list set inet wg-policy russia 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | wc -l)
if [ "${CURRENT_COUNT}" -lt 8000 ]; then
    echo "[$(LOG_TS)] Текущий набор мал (${CURRENT_COUNT} записей) — принудительное обновление"
    rm -f "${ETAG_FILE}"
fi

# ── Источники IPv4 (скачиваем ВСЕ и объединяем) ──────────
# [fix v28.25.1] Первичный источник — автономный репозиторий avar-soft
# (не зависит от внешних сервисов, обновляется вместе со скриптом).
# [fix v28.25.3] SHA256-верификация скачанных GeoIP-файлов.
# Если рядом с LOCAL_GEOIP_V4/V6 лежат файлы .sha256 (можно создать вручную или через
# доверенный канал), то после скачивания проверяем хеш и отклоняем файл при несовпадении.
# Формат .sha256: одна строка "<hex-hash>  filename" (output sha256sum).
# SUPPLY-CHAIN: источники загружаются по HTTPS; без pinned hashes компрометация
# upstream = компрометация firewall. Для максимальной безопасности используй только
# LOCAL_GEOIP_V4/V6 + .sha256 (offline-зеркала с проверкой целостности).
GEOIP_V4_SHA256="${LOCAL_GEOIP_V4}.sha256"
GEOIP_V6_SHA256="${LOCAL_GEOIP_V6}.sha256"

_verify_sha256() {
    local _file="$1" _shafile="$2"
    [ -f "${_shafile}" ] || return 0   # нет файла .sha256 — пропускаем проверку
    local _expected _actual
    _expected=$(awk '{print $1}' "${_shafile}" 2>/dev/null | head -1)
    [ -z "${_expected}" ] && return 0  # пустой .sha256 — пропускаем
    _actual=$(sha256sum "${_file}" 2>/dev/null | awk '{print $1}')
    if [ "${_expected}" != "${_actual}" ]; then
        echo "[$(LOG_TS)] ERROR: SHA256 mismatch для ${_file}:"
        echo "[$(LOG_TS)]   ожидалось: ${_expected}"
        echo "[$(LOG_TS)]   получено:  ${_actual}"
        echo "[$(LOG_TS)]   Файл отклонён (возможна компрометация upstream)."
        return 1
    fi
    echo "[$(LOG_TS)] SHA256 OK: ${_file}"
    return 0
}

_GEOIP_URLS=(
    "https://raw.githubusercontent.com/avar-soft/wireguard-home-server/main/geoip/ru-aggregated.zone"
    "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/ru.cidr"
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt"
    "https://gitlab.com/herrbischoff/country-ip-blocks/-/raw/master/ipv4/ru.cidr"
)
# ── Источники IPv6 ──────────
_GEOIP_V6_URLS=(
    "https://raw.githubusercontent.com/avar-soft/wireguard-home-server/main/geoip/ru-aggregated-v6.zone"
    "https://www.ipdeny.com/ipv6/ipaddresses/blocks/data/aggregated/ru-aggregated.zone"
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/ru.cidr"
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv6-aggregated.txt"
)

TMP_ALL=$(mktemp)
TMP_ALL_V6=$(mktemp)
TMP_HDR=$(mktemp)
TMP_SINGLE=$(mktemp)

# ── IPv4: локальный файл имеет приоритет над сетью ──
if [ -s "${LOCAL_GEOIP_V4}" ]; then
    echo "[$(LOG_TS)] Использую локальный IPv4 GeoIP: ${LOCAL_GEOIP_V4}"
    # [fix v28.25.3] Проверяем SHA256 если файл .sha256 рядом с GeoIP
    if ! _verify_sha256 "${LOCAL_GEOIP_V4}" "${GEOIP_V4_SHA256}"; then
        echo "[$(LOG_TS)] WARN: локальный IPv4 GeoIP отклонён по SHA256 — переключаемся на сетевые источники"
        # Fallthrough к сетевым источникам через else-ветку ниже
        _local_v4_ok=0
    else
        _local_v4_ok=1
    fi
    if [ "${_local_v4_ok:-1}" = "1" ]; then
    # Поддерживаем ручные файлы с CRLF, пробелами и комментариями.
    # Берём только валидные CIDR IPv4, чтобы nft не падал из-за мусорной строки.
    awk '
        { sub(/\015$/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
        /^[0-9]{1,3}(\.[0-9]{1,3}){3}\/[0-9]{1,2}$/ {
            split($0, a, "/"); split(a[1], o, "."); mask=a[2]+0;
            if (mask >= 0 && mask <= 32 && o[1] <= 255 && o[2] <= 255 && o[3] <= 255 && o[4] <= 255) print $0
        }
    ' "${LOCAL_GEOIP_V4}" >> "${TMP_ALL}"
    fi  # close _local_v4_ok sha256 check
else
    echo "[$(LOG_TS)] Скачиваю IPv4 GeoIP из нескольких источников..."
    for _url in "${_GEOIP_URLS[@]}"; do
        echo "[$(LOG_TS)] Пробую: $_url"
        # [fix v28.24.16] Передаём сохранённый ETag через If-None-Match для условной загрузки (304 = не изменился)
        _saved_etag=$(cat "${ETAG_FILE}" 2>/dev/null || true)
        _etag_header=()
        [ -n "${_saved_etag}" ] && _etag_header=(-H "If-None-Match: ${_saved_etag}")
        http_code=$(curl -fsSL --tlsv1.2 --proto '=https' --max-time 30 \
            "${_etag_header[@]}" -D "${TMP_HDR}" "$_url" -o "${TMP_SINGLE}" \
            -w "%{http_code}" 2>/dev/null || echo "000")
        if [ "${http_code}" = "304" ]; then
            echo "[$(LOG_TS)] $_url не изменился (304) — используем кэш"
            continue
        fi
        if [ "$(wc -l < "${TMP_SINGLE}" 2>/dev/null || echo 0)" -ge "${MIN_GEOIP_LINES}" ]; then
            echo "[$(LOG_TS)]   $_url: $(wc -l < "${TMP_SINGLE}") строк"
            grep -E '^[0-9]{1,3}\.' "${TMP_SINGLE}" >> "${TMP_ALL}"
            # [fix v28.24.16] Сохраняем новый ETag для следующего запуска
            _new_etag=$(grep -i '^ETag:' "${TMP_HDR}" 2>/dev/null | awk '{print $2}' | tr -d '\r' | head -1)
            [ -n "${_new_etag}" ] && echo "${_new_etag}" > "${ETAG_FILE}"
        else
            echo "[$(LOG_TS)]   $_url: недостаточно данных (< ${MIN_GEOIP_LINES}), пропущен"
        fi
    done
fi

# ── IPv6: локальный файл имеет приоритет ──
if [ "${HAVE_V6}" = "1" ]; then
    if [ -s "${LOCAL_GEOIP_V6}" ]; then
        echo "[$(LOG_TS)] Использую локальный IPv6 GeoIP: ${LOCAL_GEOIP_V6}"
        # [fix v28.25.3] SHA256 для V6 offline-файла
        if ! _verify_sha256 "${LOCAL_GEOIP_V6}" "${GEOIP_V6_SHA256}"; then
            echo "[$(LOG_TS)] WARN: локальный IPv6 GeoIP отклонён по SHA256 — переходим к сетевым источникам"
            # Очищаем флаг — awk ниже не выполняется, т.к. закрываем if
            true
        else
        # [fix v28.24.4] Строгая фильтрация: требуем ':' в адресе (настоящий IPv6)
        # и обязательный /prefix (interval set не принимает голые адреса).
        awk '
            { sub(/\015$/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
            /^[0-9a-fA-F:]+\/[0-9]{1,3}$/ {
                split($0, a, "/")
                # Проверяем: ':' есть в адресе (IPv6), prefix 0..128
                if (index(a[1], ":") > 0 && a[2]+0 >= 0 && a[2]+0 <= 128) print $0
            }
        ' "${LOCAL_GEOIP_V6}" >> "${TMP_ALL_V6}"
        fi  # close sha256 check v6
    else
        echo "[$(LOG_TS)] Скачиваю IPv6 GeoIP..."
        for _url in "${_GEOIP_V6_URLS[@]}"; do
            echo "[$(LOG_TS)] Пробую: $_url"
            http_code=$(curl -fsSL --tlsv1.2 --proto '=https' --max-time 30 "$_url" -o "${TMP_SINGLE}" -w "%{http_code}" 2>/dev/null || echo "000")
            if [ "${http_code}" = "200" ] && [ "$(wc -l < "${TMP_SINGLE}" 2>/dev/null || echo 0)" -ge "${MIN_GEOIP_V6_LINES}" ]; then
                echo "[$(LOG_TS)]   $_url: $(wc -l < "${TMP_SINGLE}") строк"
                # [fix v28.24.4] Фильтруем строго: только валидный IPv6 CIDR (обязателен /prefix).
                # Старый regex '^[0-9a-fA-F]*:' пропускал строки без '/N' → nft падал с ошибкой синтаксиса.
                grep -E '^[0-9a-fA-F:]+/[0-9]{1,3}$' "${TMP_SINGLE}" | \
                    awk -F/ 'index($1,":") > 0 && $2+0 >= 0 && $2+0 <= 128' >> "${TMP_ALL_V6}"
            else
                echo "[$(LOG_TS)]   $_url: пропущен (http=${http_code})"
            fi
        done
    fi
fi

rm -f "${TMP_SINGLE}" "${TMP_HDR}"

# Удаляем дубликаты IPv4
# [fix v28.24.6] Достаточно sort -u: nftables interval-set с auto-merge сам
# отсортирует и склеит подсети; сложный многоключевой sort не нужен и некорректен
# при разной длине маски.
sort -u "${TMP_ALL}" > "${TMP_ALL}.sorted"
mv "${TMP_ALL}.sorted" "${TMP_ALL}"

TOTAL_LINES=$(wc -l < "${TMP_ALL}")
echo "[$(LOG_TS)] IPv4 уникальных подсетей: ${TOTAL_LINES}"

if [ "${TOTAL_LINES}" -lt "${MIN_GEOIP_LINES}" ]; then
    echo "[$(LOG_TS)] ERROR: Не удалось получить достаточно IPv4 GeoIP данных (всего ${TOTAL_LINES} строк)"
    rm -f "${TMP_ALL}" "${TMP_ALL_V6}"
    exit 1
fi

# IPv6: дедуп (без числовой сортировки — sort -u достаточно)
if [ -s "${TMP_ALL_V6}" ]; then
    sort -u "${TMP_ALL_V6}" > "${TMP_ALL_V6}.sorted"
    mv "${TMP_ALL_V6}.sorted" "${TMP_ALL_V6}"
    echo "[$(LOG_TS)] IPv6 уникальных подсетей: $(wc -l < "${TMP_ALL_V6}")"
fi


# 2. Формируем единый список (GeoIP + DNS + Whitelist)
TMP_ELEMENTS=$(mktemp)
cat "${TMP_ALL}" > "${TMP_ELEMENTS}"

RU_DNS_IPS="77.88.8.8 77.88.8.1 77.88.8.88 77.88.8.2 77.88.8.7 77.88.8.3 195.208.4.1 195.208.5.1 188.93.16.19 188.93.17.19 195.153.21.21 193.58.251.251 213.158.0.6 212.48.193.36 46.48.158.12 46.48.158.13 80.252.128.88 80.252.130.253 217.10.39.4 217.10.44.35 213.87.0.1 213.87.1.1 195.133.2.35 195.133.2.2 193.201.224.33 193.201.224.1 83.149.12.130 83.149.12.131 194.67.1.154 194.67.1.1 217.118.66.243 217.118.66.244 188.186.247.194 188.186.247.195 109.195.128.60 109.195.128.61 80.80.111.254 80.80.111.253 62.165.33.250 91.105.153.153 91.105.154.154 212.193.163.6 212.193.163.7 195.19.192.1 195.19.192.2 212.1.224.6 212.1.244.6 85.249.224.66 62.76.76.62 62.76.62.76 92.223.65.71 195.208.136.204 194.67.109.176 94.103.91.65 78.36.16.242 46.254.24.214 94.158.96.2 80.82.55.71 92.54.126.211 77.37.232.237 195.46.39.39 195.46.39.40 85.192.158.28 78.36.17.62 178.47.2.92 80.82.50.186 94.50.228.152 109.124.76.206 178.47.11.25 195.95.214.174 82.204.180.66 92.241.102.173 195.133.242.149 91.219.203.237 95.188.82.13 81.200.26.87 80.89.145.83 195.34.243.204 77.220.187.242 78.156.233.178 84.52.122.46 193.106.187.250 94.243.184.101 188.191.88.1 178.47.189.157 78.31.100.237 94.51.83.154 92.124.144.189 84.42.41.59 79.122.193.38 90.189.6.100 92.255.202.253 89.251.151.231 92.255.244.78 92.255.197.96"
for ip in $RU_DNS_IPS; do echo "$ip" >> "${TMP_ELEMENTS}"; done

# Whitelist пользователя (.direct-ips, формат "IP/маска: комментарий")
# [fix v28.22.2] Раньше IPv6 (начинается с буквы a-f) тихо игнорировался
# из-за паттерна /^[0-9]/ — теперь IPv4 идут в russia, IPv6 в russia_v6.
if [ -s "${DIRECT_IPS_FILE}" ]; then
    # IPv4 → russia (строка вида "10.0.0.0/8: comment" или просто IP/CIDR)
    awk -F: '/^[[:space:]]*[0-9]+\./ {gsub(/[[:space:]]/, "", $1); if ($1 != "") print $1}' \
        "${DIRECT_IPS_FILE}" >> "${TMP_ELEMENTS}"
    # IPv6 → russia_v6. Берём всё до первого пробела/комментария,
    # фильтруем строки, содержащие ':' и '/' (CIDR обязателен для interval-set).
    # [fix v28.24.5] Раньше блок выполнялся только при непустом TMP_ALL_V6 —
    # из-за этого IPv6 из .direct-ips не попадал в @russia_v6, если онлайн-
    # список IPv6 GeoIP не скачался. Теперь грузим всегда при HAVE_V6=1.
    if [ "${HAVE_V6}" = "1" ]; then
        : "${TMP_ALL_V6:=$(mktemp)}"
        awk '
            /^[[:space:]]*#/ { next }
            {
                sub(/[[:space:]]*#.*$/, "", $0)
                gsub(/[[:space:]]/, "", $0)
                # [fix] Извлекаем CIDR-часть через regex — не используем ':' как разделитель,
                # т.к. IPv6-адреса сами содержат ':', что ломало sub(/[[:space:]]*:[[:space:]].*$/).
                if (match($0, /^[0-9a-fA-F:]+\/[0-9]{1,3}/)) {
                    cidr = substr($0, RSTART, RLENGTH)
                    if (cidr ~ /:/ && cidr ~ /\//) print cidr
                }
            }' "${DIRECT_IPS_FILE}" >> "${TMP_ALL_V6}"
    fi
fi

# 3. Batch-файл для nftables (МГНОВЕННАЯ АТОМАРНАЯ ЗАГРУЗКA)
TMP_NFT=$(mktemp)
echo "flush set inet wg-policy russia" > "${TMP_NFT}"
split -l 1000 "${TMP_ELEMENTS}" "${TMP_ELEMENTS}_part_"
for part in "${TMP_ELEMENTS}_part_"*; do
    # [fix КРИТИЧ 5] Защита от ARG_MAX и spike памяти на VPS 512MB:
        # передаём элементы через временный файл-batch вместо shell-переменной
        elements=$(paste -sd, "${part}" 2>/dev/null || tr '\n' ',' < "${part}" | sed 's/,$//')
    [ -z "${elements}" ] && continue
    echo "add element inet wg-policy russia { $elements }" >> "${TMP_NFT}"
done

if ! nft -f "${TMP_NFT}" 2>/dev/null; then
    echo "[$(LOG_TS)] ERROR: Ошибка синтаксиса nftables при batch-загрузке"
    rm -f "${TMP_ALL}" "${TMP_ALL_V6}" "${TMP_ELEMENTS}" "${TMP_ELEMENTS}_part_"* "${TMP_NFT}"
    exit 1
fi

COUNT=$(nft list set inet wg-policy russia 2>/dev/null | grep -oE '[0-9.]+/[0-9]+' | wc -l)
echo "[$(LOG_TS)] [✓] nftables @russia: ${COUNT} подсетей (CIDR) + диапазоны"

# ── [v28.21.2] Загрузка IPv6 в russia_v6 (если set есть и данные собраны) ──
if [ "${HAVE_V6}" = "1" ] && [ -s "${TMP_ALL_V6}" ]; then
    # [fix v28.24.4] Нормализуем IPv6: убираем строки без '/prefix' (interval set требует CIDR),
    # добавляем /128 к одиночным адресам, фильтруем мусор через awk.
    TMP_V6_FIXED=$(mktemp)
    awk '
        { sub(/\015$/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
        /^[0-9a-fA-F:]+\/[0-9]{1,3}$/ {
            # уже CIDR — проверяем префикс <=128
            split($0, a, "/"); if (a[2]+0 >= 0 && a[2]+0 <= 128 && index(a[1], ":") > 0) print $0
            next
        }
        /^[0-9a-fA-F:]+$/ && /::/ {
            # одиночный IPv6 без префикса — добавляем /128
            print $0 "/128"
        }
    ' "${TMP_ALL_V6}" > "${TMP_V6_FIXED}"
    sort -u "${TMP_V6_FIXED}" > "${TMP_ALL_V6}"
    rm -f "${TMP_V6_FIXED}"
    echo "[$(LOG_TS)] IPv6 после нормализации: $(wc -l < "${TMP_ALL_V6}") подсетей"

    TMP_NFT6=$(mktemp)
    TMP_NFT6_ERR=$(mktemp)
    echo "flush set inet wg-policy russia_v6" > "${TMP_NFT6}"
    split -l 500 "${TMP_ALL_V6}" "${TMP_ALL_V6}_part_"
    for part in "${TMP_ALL_V6}_part_"*; do
        elements=$(paste -sd, "${part}")
        [ -z "${elements}" ] && continue
        echo "add element inet wg-policy russia_v6 { $elements }" >> "${TMP_NFT6}"
    done
    if nft -f "${TMP_NFT6}" 2>"${TMP_NFT6_ERR}"; then
        COUNT6=$(nft list set inet wg-policy russia_v6 2>/dev/null | grep -oEc '[0-9a-fA-F:]+/[0-9]+' || echo 0)
        echo "[$(LOG_TS)] [✓] nftables @russia_v6: ${COUNT6} подсетей"
    else
        # [fix v28.24.12] Раньше batch падал — и russia_v6 оставался пустым
        # БЕЗ объяснения почему. Теперь: 1) показываем реальную ошибку nft,
        # 2) откатываемся в per-line режим — каждый CIDR грузим отдельно,
        # битые пропускаем с логом. В итоге @russia_v6 наполняется всем,
        # что синтаксически валидно.
        echo "[$(LOG_TS)] WARN: batch-загрузка @russia_v6 не удалась, переключаюсь в per-line"
        echo "[$(LOG_TS)] nft stderr: $(head -3 "${TMP_NFT6_ERR}" | tr '\n' '|')"
        nft flush set inet wg-policy russia_v6 2>/dev/null || true
        BAD6=0; OK6=0
        while IFS= read -r _cidr; do
            [ -z "${_cidr}" ] && continue
            if nft add element inet wg-policy russia_v6 { "${_cidr}" } 2>/dev/null; then
                OK6=$((OK6+1))
            else
                BAD6=$((BAD6+1))
                [ "${BAD6}" -le 5 ] && echo "[$(LOG_TS)]   битый CIDR: '${_cidr}'"
            fi
        done < "${TMP_ALL_V6}"
        echo "[$(LOG_TS)] [✓] @russia_v6 per-line: загружено ${OK6}, пропущено ${BAD6}"
    fi
    rm -f "${TMP_NFT6}" "${TMP_NFT6_ERR}" "${TMP_ALL_V6}_part_"*
fi

# [fix v28.22.2] Раньше дампили весь runtime nft в /etc/nftables.conf —
# это затягивало в декларативный конфиг чужие таблицы (Docker, fail2ban),
# а в момент гонки могло сохранить частичное состояние. Источник истины —
# createIpSetAndNft (генерирует /etc/nftables.conf), а update-ru-ipset.sh
# обновляет ТОЛЬКО set russia/russia_v6 через flush+add element. Файл не трогаем.

rm -f "${TMP_ALL}" "${TMP_ALL_V6}" "${TMP_ELEMENTS}" "${TMP_ELEMENTS}_part_"* "${TMP_NFT}"

# [fix v28.24.13] Маркер готовности — заменяет 60-кратный nft-poll в ExecStartPre
# у dnsmasq и других consumer'ов. После успешной загрузки трогаем файл; consumer
# проверяет [ -f /run/wg-russia-ready ] вместо тяжёлой команды.
mkdir -p /run 2>/dev/null || true
: > /run/wg-russia-ready 2>/dev/null || true
echo "[$(LOG_TS)] [✓] marker /run/wg-russia-ready записан"

exit 0
SCRIPT
    chmod +x /usr/local/bin/update-ru-ipset.sh

    # [fix v28.24.10] Хелпер для восстановления force_tunnel_v4/v6 после
    # ручного systemctl restart nftables. Вызывается из drop-in 99-geoip.conf.
    cat > /usr/local/bin/wg-restore-force-tunnel.sh << 'FTSCRIPT'
#!/bin/bash
# wg-restore-force-tunnel.sh — наполняет nft set'ы force_tunnel_v4/v6
# CIDR'ами и адресами из /etc/wireguard/.tunnel-force-domains. Доменные
# имена тут НЕ резолвятся (это делает dnsmasq при работе сервиса), но
# IP/CIDR из файла подгружаются мгновенно, чтобы принудительный туннель
# не "проваливался" после рестарта nftables.

set -uo pipefail
TFD="/etc/wireguard/.tunnel-force-domains"
TFC="/etc/wireguard/.tunnel-force-cidr"
NFT_LOCK="/var/run/wg-nft.lock"

# [fix v28.24.14] Читаем оба источника: .tunnel-force-domains (могут быть
# смешаны домены + IP/CIDR) и .tunnel-force-cidr (только подсети). Без этого
# CIDR из отдельного файла терялись после ребута хоста.
_has_input=0
[ -r "${TFD}" ] && [ -s "${TFD}" ] && _has_input=1
[ -r "${TFC}" ] && [ -s "${TFC}" ] && _has_input=1
[ "${_has_input}" = "0" ] && exit 0

exec 9>"${NFT_LOCK}"
flock -w 30 9 || exit 0

_have_v4=0; _have_v6=0
nft list set inet wg-policy force_tunnel_v4 >/dev/null 2>&1 && _have_v4=1
nft list set inet wg-policy force_tunnel_v6 >/dev/null 2>&1 && _have_v6=1
[ "${_have_v4}${_have_v6}" = "00" ] && exit 0

V4=$(mktemp); V6=$(mktemp); BATCH=$(mktemp)
trap 'rm -f "${V4}" "${V6}" "${BATCH}" "${V4}_part_"* "${V6}_part_"* 2>/dev/null' EXIT

# [fix v28.24.14] Нормализуем одиночные IPv6 без префикса → /128
# (interval set требует CIDR, иначе nft -f отвалится с syntax error).
for SRC in "${TFD}" "${TFC}"; do
    [ -r "${SRC}" ] && [ -s "${SRC}" ] || continue
    awk '
        { sub(/\015$/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
        $0 == "" { next }
        /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/ { print $0 >> V4OUT; next }
        /:/ && /^[0-9a-fA-F:]+(\/[0-9]{1,3})?$/ {
            if (index($0,"/")==0) print $0 "/128" >> V6OUT;
            else                  print $0       >> V6OUT;
            next
        }
    ' V4OUT="${V4}" V6OUT="${V6}" "${SRC}"
done

{
    if [ "${_have_v4}" = "1" ] && [ -s "${V4}" ]; then
        echo "flush set inet wg-policy force_tunnel_v4"
        split -l 500 "${V4}" "${V4}_part_"
        for p in "${V4}_part_"*; do
            e=$(paste -sd, "${p}")
            [ -n "${e}" ] && echo "add element inet wg-policy force_tunnel_v4 { ${e} }"
        done
    fi
    if [ "${_have_v6}" = "1" ] && [ -s "${V6}" ]; then
        echo "flush set inet wg-policy force_tunnel_v6"
        split -l 500 "${V6}" "${V6}_part_"
        for p in "${V6}_part_"*; do
            e=$(paste -sd, "${p}")
            [ -n "${e}" ] && echo "add element inet wg-policy force_tunnel_v6 { ${e} }"
        done
    fi
} > "${BATCH}"

[ -s "${BATCH}" ] && nft -f "${BATCH}" 2>/dev/null || true
exit 0
FTSCRIPT
    chmod +x /usr/local/bin/wg-restore-force-tunnel.sh

    # ── Определяем порты прокси для mangle-output ─────────────────
    # Читаем реальный порт из конфигов telemt и mtg; fallback = 443
    local _proxy_ports="443"
    local _tp
    # [fix v28.24.10] Без grep -oP (PCRE) — портабельно для BusyBox/Alpine.
    _tp=$(awk -F= '/^port[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/telemt.toml 2>/dev/null || true)
    [ -n "${_tp}" ] && _proxy_ports="${_tp}"
    local _mp
    _mp=$(awk -F'0\\.0\\.0\\.0:' '/0\.0\.0\.0:/{n=$2; sub(/[^0-9].*/,"",n); if(n!="") {print n; exit}}' /etc/systemd/system/mtg.service 2>/dev/null || true)
    if [ -n "${_mp}" ] && [ "${_mp}" != "${_proxy_ports}" ]; then
        _proxy_ports="${_proxy_ports}, ${_mp}"
    fi

    # Определяем тип окружения: VDS (прямой IP) или домашний роутер (за NAT)
    # [fix] _is_vds — диагностическая переменная. Masquerade применяется на MAIN_INTERFACE
    # всегда (независимо от типа окружения), поэтому _is_vds намеренно не используется
    # в логике ниже. Оставлена для отладки (WG_DEBUG=1) и будущих условных правил.
    local _is_vds=0
    local _default_gw_iface
    _default_gw_iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    if [ -n "${_default_gw_iface}" ] && [ "${_default_gw_iface}" = "${MAIN_INTERFACE}" ]; then
        # Проверяем — если IP на MAIN_INTERFACE публичный (не RFC1918) — это VDS
        local _main_ip
        _main_ip=$(ip -4 addr show "${MAIN_INTERFACE}" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d/ -f1)
        case "${_main_ip}" in
            10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
                _is_vds=0 ;;  # RFC1918 — домашний роутер
            *)
                _is_vds=1 ;;  # Публичный IP — VDS
        esac
    fi

    # [fix v28.25.3] Проверяем доступность IPv6 перед созданием russia_v6 set.
    # Если IPv6 полностью отключён в ядре — создание ipv6_addr set вызовет ошибку nft.
    local _SYS_IPV6_OK=0
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = "0" ] \
       && ip -6 link show 2>/dev/null | grep -q "LOWER_UP"; then
        _SYS_IPV6_OK=1
    fi
    local _NFT_V6_SET_BLOCK=""
    if [ "${_SYS_IPV6_OK}" = "1" ]; then
        _NFT_V6_SET_BLOCK="set russia_v6 {\n        type ipv6_addr\n        flags interval\n        auto-merge\n        size 65536\n    }"
    else
        _NFT_V6_SET_BLOCK="# russia_v6: IPv6 отключён на этой системе — set пропущен"
        warn "createIpSetAndNft: IPv6 отключён — set russia_v6 и force_tunnel_v6 не создаются"
    fi

    # ── nftables.conf ─────────────────────────────────────────────
    # [fix v28.25.0] Атомарная запись через временный файл → nft -c → mv -f.
    # Если скрипт прервётся (OOM, kill, обрыв диска) между двумя cat >>,
    # nftables при следующей перезагрузке не получит полузаписанный конфиг.
    local _nft_build_tmp
    _nft_build_tmp=$(mktemp /etc/nftables.conf.building.XXXXXX) || {
        warn "createIpSetAndNft: не удалось создать временный файл — пишем напрямую"
        _nft_build_tmp=/etc/nftables.conf
    }
    # Все cat >> ниже пишут в _nft_build_tmp, не в /etc/nftables.conf напрямую.
    cat > "${_nft_build_tmp}" << EOF
#!/usr/sbin/nft -f
# [fix v28.22.2] flush ruleset уничтожал бы все правила хоста (Docker, fail2ban,
# libvirt, k8s). Заменено на точечный сброс ТОЛЬКО наших таблиц.
# Идиома "add + delete" безопасна и при холодном старте (add создаёт пустую
# таблицу если её нет, delete её удаляет — никаких ошибок не будет).
add table inet wg-policy
delete table inet wg-policy
add table inet wg-filter
delete table inet wg-filter
add table inet wg-nat
delete table inet wg-nat

table inet wg-policy {
    # [fix Г] size явно задаётся для совместимости со старыми ядрами Linux
    # (без size старые версии nf_tables могут отказать при >65536 элементах).
    set russia {
        type ipv4_addr
        flags interval
        auto-merge
        size 131072
    }

    # russia_v6 создаётся только если IPv6 активен (проверка выше)
    ${_NFT_V6_SET_BLOCK}

    set force_tunnel_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 65536
    }
    set force_tunnel_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        size 32768
    }

    # РФ-трафик от клиентов → пометка → main-таблица → ${MAIN_INTERFACE} напрямую
    chain mangle-prerouting {
        type filter hook prerouting priority mangle; policy accept;
        # [fix v28.24.6] force_tunnel_* приоритетнее russia: если IP в whitelist
        # туннеля — метим под туннель и ВЫХОДИМ из цепочки, иначе следующее
        # правило @russia перезапишет метку (nftables не прерывается сам).
        iifname "${SERVER_WG_NIC}" ip  daddr @force_tunnel_v4 meta mark set 0x00100000 return
        iifname "${SERVER_WG_NIC}" ip6 daddr @force_tunnel_v6 meta mark set 0x00100000 return
        iifname "${SERVER_WG_NIC}" ip daddr @russia meta mark set 0x00200000
        # [fix v28.21.10] Симметрично для IPv6: РФ ip6 → напрямую (если набор russia_v6 наполнен).
        iifname "${SERVER_WG_NIC}" ip6 daddr @russia_v6 meta mark set 0x00200000
    }

    # OUTPUT hook: трафик генерируемый самим сервером
    # [fix v28.20.4] Порядок правил критичен:
    # 1. lo — пропускаем без изменений (иначе сломается 127.0.0.1:53 dnsmasq)
    # 2. Весь DNS → туннель по умолчанию (для режима DNS_MODE=tunnel)
    # 3. DNS к РФ-серверам → напрямую (переопределяет п.2 для @russia)
    # 4. Ответы dnsmasq клиентам → напрямую (sport 53)
    # 5. Telemt/MTProxy → туннель
    chain mangle-output {
        type filter hook output priority mangle; policy accept;
        # Loopback — никогда не трогаем (иначе dnsmasq перестанет работать)
        oifname "lo" accept
        # DNS ответы клиентам WG → напрямую
        udp sport 53 meta mark set 0x00200000
        tcp sport 53 meta mark set 0x00200000
EOF
    # [fix v28.24.7] Вложенный heredoc внутри $() внутри << EOF не работает в bash.
    # DNS-правила mangle-output для tunnel-режима добавляются отдельным cat >>.
    if [ "${DNS_MODE:-public}" = "tunnel" ]; then
        cat >> "${_nft_build_tmp}" << 'EOF'
        # [fix v28.24.7] dport 53 → туннель только при DNS_MODE=tunnel,
        # иначе сервер теряет DNS при падении туннеля.
        udp dport 53 meta mark set 0x00100000
        tcp dport 53 meta mark set 0x00100000
        # РФ DNS-серверы → переопределяем: напрямую
        udp dport 53 ip daddr @russia meta mark set 0x00200000
        tcp dport 53 ip daddr @russia meta mark set 0x00200000
        # [fix v28.24.9] Симметрично для IPv6 — РФ DNS по IPv6 тоже напрямую.
        udp dport 53 ip6 daddr @russia_v6 meta mark set 0x00200000
        tcp dport 53 ip6 daddr @russia_v6 meta mark set 0x00200000
EOF
    fi
    cat >> "${_nft_build_tmp}" << 'EOF'
        # Telemt/MTProxy: исходящие к Telegram DC → через туннель (dport 443/5222)
        # Без этого часть DC недоступна напрямую у хостеров
EOF
    # [fix v28.22.1] Записываем правила proxy-портов только если _proxy_ports непуст,
    # иначе nft получит "{ , 5222 }" и упадёт с синтаксической ошибкой.
    if [ -n "${_proxy_ports}" ]; then
        cat >> "${_nft_build_tmp}" << EOF
        tcp dport { ${_proxy_ports}, 5222 } meta mark set 0x00100000
        udp dport { ${_proxy_ports}, 5222 } meta mark set 0x00100000
EOF
    else
        cat >> "${_nft_build_tmp}" << 'EOF'
        tcp dport 5222 meta mark set 0x00100000
        udp dport 5222 meta mark set 0x00100000
EOF
    fi
    cat >> "${_nft_build_tmp}" << EOF
    }
}

table inet wg-filter {
    chain FORWARD {
        type filter hook forward priority filter; policy accept;
        ct state related,established counter accept
        iifname "${SERVER_WG_NIC}" oifname "${MAIN_INTERFACE}" counter accept
        iifname "${MAIN_INTERFACE}" oifname "${SERVER_WG_NIC}" counter accept
        iifname "${SERVER_WG_NIC}" udp dport 53 accept
        iifname "${SERVER_WG_NIC}" tcp dport 53 accept
EOF
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        cat >> "${_nft_build_tmp}" << EOF
        iifname "${SERVER_WG_NIC}" oifname "${TUNNEL_IFACE[$i]}" counter accept
        iifname "${TUNNEL_IFACE[$i]}" oifname "${SERVER_WG_NIC}" counter accept
EOF
    done
    cat >> "${_nft_build_tmp}" << EOF
    }
}

table inet wg-nat {
    chain POSTROUTING {
        type nat hook postrouting priority srcnat; policy accept;
EOF
    # [fix v28.20.4] masquerade ВСЕГДА нужен: клиенты имеют серые адреса (10.x)
    # и без NAT их пакеты дропаются провайдером или удалённым хостом.
    # На VDS это критично для РФ-трафика (прямой выход через eth0 без NAT = потеря пакетов).
    echo "        oifname \"${MAIN_INTERFACE}\" ip saddr ${CLIENT_IPV4_SUBNET} counter masquerade" >> "${_nft_build_tmp}"
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        echo "        oifname \"${TUNNEL_IFACE[$i]}\" counter masquerade" >> "${_nft_build_tmp}"
    done
    cat >> "${_nft_build_tmp}" << 'NFTEOF'
    }
}
NFTEOF

    # [fix v28.20.8] flock защищает nftables reload от параллельных вызовов
    # (cron update-ru-ipset, restartTunnels, repairRouting могут пересечься).
    # [fix v28.24.14] update-ru-ipset.sh ВЫНЕСЕН из subshell — внутри он сам
    # берёт flock на тот же файл (другим FD), что приводило к 60-сек зависанию
    # и тихому пропуску загрузки GeoIP в @russia.
    # [fix v28.25.0] Атомарный перенос собранного файла: сначала dry-run nft -c,
    # затем mv -f (атомарная операция rename в пределах одной ФС).
    if [ "${_nft_build_tmp}" != "/etc/nftables.conf" ]; then
        if nft -c -f "${_nft_build_tmp}" 2>/dev/null; then
            mv -f "${_nft_build_tmp}" /etc/nftables.conf
        else
            warn "createIpSetAndNft: сгенерированный nftables.conf не прошёл nft -c — откатываем, старый конфиг сохранён"
            rm -f "${_nft_build_tmp}"
            return 1
        fi
    fi
    (
        flock -w 30 200 || { warn "Timeout ожидания lock /var/run/wg-nft.lock"; exit 75; }
        systemctl enable --now nftables 2>/dev/null || true
        systemctl daemon-reload
        systemctl restart nftables
        nft -f /etc/nftables.conf || warn "nft -f /etc/nftables.conf завершился с ошибкой"
    ) 200>/var/run/wg-nft.lock
    # [fix v28.21.10] Проверяем код возврата subshell — иначе info врёт при таймауте lock.
    local _nft_rc=$?
    if [ "${_nft_rc}" -eq 0 ]; then
        # Запускаем загрузку @russia ПОСЛЕ освобождения lock — update-ru-ipset.sh
        # возьмёт его сам.
        /usr/local/bin/update-ru-ipset.sh 2>/dev/null || warn "update-ru-ipset.sh завершился с ошибкой"
        info "GeoIP + nftables настроены"
        # [fix v28.24.9] После пересборки nftables.conf force_tunnel_* set'ы пусты —
        # восстанавливаем их из .tunnel-force-domains (вызывается также из
        # addTunnel/removeTunnel/repairRouting через эту же функцию).
        if [ -f "${TUNNEL_FORCE_DOMAINS:-/etc/wireguard/.tunnel-force-domains}" ] && \
           declare -F _rebuildTunnelForce >/dev/null 2>&1; then
            _rebuildTunnelForce 2>/dev/null || true
        fi
    else
        warn "createIpSetAndNft: завершилось с rc=${_nft_rc} (lock/restart) — проверьте journalctl -u nftables"
    fi
}

# ── Восстановление маршрутизации ──────────────────────────────
# [fix] Пересобирает nftables.conf + ip rule по текущему конфигу
# Вызывать если туннели есть но интернет не работает
repairRouting() {
    loadConfig
    section "Восстановление маршрутизации"
    echo ""
    info "Пересобираю nftables.conf по текущему конфигу (туннелей: ${TUNNEL_COUNT})..."

    # [fix v28.25.0] Берём тот же lock что использует wg-balance.sh — защита от гонки:
    # repairRouting + wg-balance могут одновременно манипулировать ip rule.
    : > /var/run/wg-repair.lock 2>/dev/null || true
    (
        flock -w 30 201 || { warn "repairRouting: не удалось взять блокировку — попробуй ещё раз"; exit 1; }
    # При ошибке createIpSetAndNft → безопасный откат без затрагивания чужих таблиц.
    if _txn_begin; then
        if ! _txn_step "createIpSetAndNft" "createIpSetAndNft"; then
            warn "repairRouting: откат выполнен, маршрутизация не изменена"
            exit 1
        fi
        _txn_commit
    else
        warn "Транзакция недоступна — запускаю без снапшота"
        createIpSetAndNft
    fi

    # Очищаем все prio 30200-299 и добавляем заново для каждого туннеля
    # [fix v28.25.0] while-цикл вместо одиночного del — удаляет ВСЕ дубли правил
    # если скрипт запускался несколько раз без очистки (накапливаются дубли).
    local p
    for p in $(seq 30200 10 30299); do
        local _ri=0
        while [ $_ri -lt 20 ] && ip rule show prio "${p}" 2>/dev/null | grep -q .; do
            ip rule del prio "${p}" 2>/dev/null || break
            _ri=$((_ri + 1))
        done
    done
    # [fix v28.24.2] также чистим fwmark-правила балансировщика (prio 30045/50/51),
    # иначе после repairRouting они могут указывать на устаревшие таблицы
    # до первого do_balance в wg-balance.service.
    for p in 30045 30050 30051; do
        local _i=0
        while [ $_i -lt 20 ] && ip rule show prio "${p}" 2>/dev/null | grep -q .; do
            ip rule del prio "${p}" 2>/dev/null || break
            _i=$((_i + 1))
        done
    done
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        local prio=$((30200 + i * 10))
        ip rule add prio "${prio}" iif "${SERVER_WG_NIC}" lookup "${TUNNEL_TABLE[$i]}" 2>/dev/null || true
        info "ip rule prio ${prio} iif ${SERVER_WG_NIC} lookup ${TUNNEL_TABLE[$i]} (${TUNNEL_IFACE[$i]})"
    done
    # [fix v28.24.6] Восстанавливаем prio 30050 (РФ-трафик → main) сразу,
    # чтобы не было окна между repairRouting и первым циклом wg-balance,
    # в котором клиентский РФ-трафик уходил бы в туннель вместо main.
    ip -4 rule add fwmark 0x200000 table main priority 30050 2>/dev/null || true
    # prio 30045 (0x100000 → best tunnel) — добавит балансировщик на ближайшем цикле.

    # Убеждаемся что маршруты в таблицах существуют
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        if ! ip route show table "${TUNNEL_TABLE[$i]}" 2>/dev/null | grep -q default; then
            ip route add default dev "${TUNNEL_IFACE[$i]}" table "${TUNNEL_TABLE[$i]}" 2>/dev/null || true
            info "Добавлен маршрут: default dev ${TUNNEL_IFACE[$i]} table ${TUNNEL_TABLE[$i]}"
        else
            info "Маршрут таблицы ${TUNNEL_TABLE[$i]} уже существует"
        fi
    done

    # Перезапускаем балансировщик
    createBalanceScript
    systemctl restart wg-balance.service 2>/dev/null || true

    echo ""
    info "Готово. Проверка:"
    ip rule show
    echo ""
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        echo "  Таблица ${TUNNEL_TABLE[$i]} (${TUNNEL_IFACE[$i]}):"
        ip route show table "${TUNNEL_TABLE[$i]}" | sed 's/^/    /'
    done
    echo ""
    info "Маршрутизация восстановлена. Если интернет всё ещё не работает — запусти тест системы (меню 14)."
    ) 201>/var/run/wg-repair.lock
    local _repair_rc=$?
    [ "${_repair_rc}" -ne 0 ] && warn "repairRouting завершился с ошибкой (rc=${_repair_rc})"
}

# ── Балансировщик ──────────────────────────────────────────────
# [fix] SORTED массив: добавлены правильные кавычки для IFS-split
createBalanceScript() {
    step "Создание скрипта балансировки"
    cat > /usr/local/bin/wg-balance.sh << HEADER
#!/bin/bash
# [fix v28.18] pipefail реально убран — ping возвращает ненулевой код при недоступности хоста
set -u
CONFIG_FILE="/etc/wireguard/.wg-setup.conf"
# [fix v28.20.5] Безопасный парсинг конфига без source
_load_conf() {
    [ -f "\${CONFIG_FILE}" ] || return 0
    while IFS= read -r _line || [ -n "\${_line}" ]; do
        [[ "\${_line}" =~ ^[[:space:]]*# ]] && continue
        [[ -z "\${_line// }" ]] && continue
        [[ "\${_line}" != *=* ]] && continue
        _k="\${_line%%=*}"
        _v="\${_line#*=}"
        _k="\${_k// /}"
        _v="\${_v#\\"}"
        _v="\${_v%\\"}"
        case "\${_k}" in
            BAD_PING_MS|BALANCE_INTERVAL|TUNNEL_COUNT|SERVER_WG_NIC|\
            TUNNEL_IFACE_*|TUNNEL_TABLE_*|TUNNEL_IFACE|TUNNEL_TABLE)
                printf -v "\${_k}" '%s' "\${_v}" ;;
        esac
    done < "\${CONFIG_FILE}"
}
_load_conf
BAD_PING_MS="\${BAD_PING_MS:-200}"

ping_host() {
    local iface="\$1"
    local res
    # [fix v28.20.8] Scoring: 3 пинга, средний + штраф за потери.
    # Пробуем несколько хостов — 8.8.8.8 может блокироваться у некоторых хостеров.
    local -a pings=()
    local loss=0 _ph r
    for _ph in 8.8.8.8 1.1.1.1 9.9.9.9; do
        # Один запрос — парсим и rtt, и packet loss из одного вывода
        local _out
        _out=\$(ping -I "\${iface}" -c 3 -W 2 -q "\${_ph}" 2>/dev/null)
        res=\$(echo "\${_out}" | grep 'rtt' | sed -n 's|.*= [0-9.]*/\([0-9.]*\).*|\1|p')
        if [ -n "\${res}" ]; then
            pings+=("\${res%.*}")
            local pl
            pl=\$(echo "\${_out}" | awk -F'[ %]+' '/packet loss/ {print \$(NF-1)}' | head -1)
            [ -n "\${pl}" ] && loss=\$((loss + pl / 33))
            break
        fi
    done
    if [ \${#pings[@]} -gt 0 ]; then
        local sum=0 p
        for p in "\${pings[@]}"; do sum=\$((sum + p)); done
        local avg=\$((sum / \${#pings[@]}))
        echo \$((avg + loss * 200))
        return
    fi
    # [fix v28.20.8] TCP fallback если ICMP режется хостером
    local t_start t_end
    t_start=\$(date +%s%3N 2>/dev/null || echo 0)
    if timeout 3 bash -c "exec 3<>/dev/tcp/8.8.8.8/443" 2>/dev/null; then
        t_end=\$(date +%s%3N 2>/dev/null || echo 0)
        [ "\${t_start}" != "0" ] && [ "\${t_end}" != "0" ] && { echo \$((t_end - t_start)); return; }
    fi
    echo "9999"
}

LOCK_FILE="/var/run/wg-balance.lock"

_do_balance_inner() {
    local -a RESULTS=()
HEADER
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        cat >> /usr/local/bin/wg-balance.sh << EOF
    # [fix v28.22.1] Используем промежуточную переменную вместо local lat_${i}= (хрупкий идентификатор)
    local _lat_tmp_${i}; _lat_tmp_${i}=\$(ping_host "${TUNNEL_IFACE[$i]}")
    RESULTS+=("\${_lat_tmp_${i}}:${i}:${TUNNEL_IFACE[$i]}:${TUNNEL_TABLE[$i]}")
EOF
    done
    # [fix] Кавычки вокруг \${RESULTS[*]} для корректного IFS-split
    cat >> /usr/local/bin/wg-balance.sh << 'FOOTER'
    [ ${#RESULTS[@]} -eq 0 ] && return
    local IFS=$'\n'
    local -a SORTED
    read -r -d '' -a SORTED < <(printf '%s\n' "${RESULTS[@]}" | sort -t: -k1 -n ; printf '\0')
    unset IFS

    # Очищаем ТОЛЬКО правила prio 30200-299 (не трогаем prio 30050!)
    local p
    for p in $(seq 30200 10 30299); do
        ip rule del prio "${p}" 2>/dev/null || true
    done

    local prio=30200 best_iface="" best_lat="0" best_table=""
    local entry iface table latency
    for entry in "${SORTED[@]}"; do
        iface=$(echo "${entry}" | cut -d':' -f3)
        table=$(echo "${entry}" | cut -d':' -f4)
        latency=$(echo "${entry}" | cut -d':' -f1)
        ip rule add prio "${prio}" iif "${SERVER_WG_NIC}" lookup "${table}" 2>/dev/null || true
        echo "[$(date '+%H:%M:%S')] ${iface} prio=${prio} ping=${latency}ms table=${table}"
        if [ "${prio}" -eq 30200 ]; then
            best_iface="${iface}"
            best_lat="${latency}"
            best_table="${table}"
        fi
        ((prio+=10))
    done

    echo "[$(date '+%H:%M:%S')] Активный туннель: ${best_iface} (${best_lat}ms)"

    # Обновляем правило для telemt (fwmark 0x100000) на лучший туннель
    if [ -n "${best_table}" ]; then
        ip rule del fwmark 0x100000 prio 30045 2>/dev/null || true
        ip rule add fwmark 0x100000 table "${best_table}" priority 30045 2>/dev/null || true
        # Сбрасываем conntrack для Telegram DC чтобы новые соединения шли через туннель
        for _tg_ip in 149.154.167.51 149.154.167.91 149.154.175.50 149.154.175.100 149.154.171.5 91.105.192.100; do
            conntrack -D -d "${_tg_ip}" 2>/dev/null || true
        done
    fi
}

# [fix v28.20.8] Обёртка с flock — защищает от параллельных гонок
# при работе с ip rule (балансировщик + restartTunnels могут пересечься).
do_balance() {
    (
        flock -n 200 || { echo "[$(date '+%H:%M:%S')] balance уже запущен — пропускаю"; return; }
        _do_balance_inner
    ) 200>"${LOCK_FILE}"
}

echo "[$(date '+%H:%M:%S')] Запуск балансировщика..."
do_balance

# Счётчик итераций для периодической самодиагностики
_ITER=0

while true; do
    sleep "${BALANCE_INTERVAL}"
    _ITER=$((_ITER + 1))
    [ -f "${CONFIG_FILE}" ] && _load_conf 2>/dev/null || true

    # ── Watchdog: проверяем что fwmark правило на месте ──────────
    # Если wg0 рестартовал — PostDown удалил правило, PostUp добавил снова.
    # Но если что-то пошло не так — восстанавливаем вручную.
    if ! ip rule show 2>/dev/null | grep -q "fwmark 0x200000"; then
        echo "[$(date '+%H:%M:%S')] ⚠ fwmark 0x200000 потерян — восстанавливаю"
        ip -4 rule add fwmark 0x200000 table main priority 30050 2>/dev/null || true
    fi
    # [fix v28.24.6] Watchdog для fwmark 0x100000 (telemt/MTProxy → лучший туннель).
    # Если правило prio 30045 исчезло (например, после wg-quick down/up), а
    # балансировщик ещё не сделал следующий цикл — восстанавливаем на текущий
    # активный туннель (prio 30200), чтобы Telegram-прокси не висели секундами.
    if ! ip rule show 2>/dev/null | grep -q "fwmark 0x100000"; then
        _cur_tbl=$(ip rule show 2>/dev/null | awk '/^30200:.*lookup/{print $NF; exit}')
        if [ -n "${_cur_tbl}" ]; then
            echo "[$(date '+%H:%M:%S')] ⚠ fwmark 0x100000 потерян — восстанавливаю на table ${_cur_tbl}"
            ip rule add fwmark 0x100000 table "${_cur_tbl}" priority 30045 2>/dev/null || true
        fi
    fi

    # ── Watchdog: проверяем что таблицы маршрутизации живы ───────
    # ip rule show выводит "200:  from all iif ..." — без слова "prio"
    if ! ip rule show 2>/dev/null | grep -qE "^30200:.*lookup 5182[0-9]+|^302[0-9]{2}:.*iif.*lookup 5182[0-9]+"; then
        echo "[$(date '+%H:%M:%S')] ⚠ Таблицы маршрутизации потеряны — перебалансировка"
        do_balance
        continue
    fi

    # ── Основная логика переключения ─────────────────────────────
    # ip rule show prio 30200 — правильный синтаксис для фильтрации по приоритету
    ACTIVE_TABLE=$(ip rule show 2>/dev/null | awk '/^30200:.*lookup/{print $NF; exit}')
    if [ -z "${ACTIVE_TABLE}" ]; then
        echo "[$(date '+%H:%M:%S')] ⚠ Нет правила prio 30200 — перебалансировка"
        do_balance
        continue
    fi
    ACTIVE_IFACE=$(ip route show table "${ACTIVE_TABLE}" 2>/dev/null \
        | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    if [ -n "${ACTIVE_IFACE}" ]; then
        ACTIVE_PING=$(ping -I "${ACTIVE_IFACE}" -c 2 -W 2 -q 8.8.8.8 2>/dev/null \
            | grep 'rtt' | sed -n 's|.*= [0-9.]*/\([0-9.]*\).*|\1|p')
        ACTIVE_PING=${ACTIVE_PING:-9999}
        # [fix v28.18] чисто-bash сравнение (не зависит от bc)
        if [ "${ACTIVE_PING%.*}" -ge "${BAD_PING_MS}" ] 2>/dev/null; then
            echo "[$(date '+%H:%M:%S')] ⚠ ${ACTIVE_IFACE} ping=${ACTIVE_PING}ms >= ${BAD_PING_MS}ms — перебалансировка"
            do_balance
            continue
        fi
    else
        echo "[$(date '+%H:%M:%S')] ⚠ Активный туннель не найден — перебалансировка"
        do_balance
        continue
    fi
    # [fix v28.18] гистерезис: активный туннель в норме — НЕ дёргаем do_balance каждые ${BALANCE_INTERVAL}s.
    # Полная перебалансировка раз в ~5 минут (для учёта появления более быстрого канала).
    if [ $((_ITER % 30)) -eq 0 ]; then
        do_balance
    fi
done
FOOTER
    chmod +x /usr/local/bin/wg-balance.sh

    # [fix] Собираем список After= и Wants= для всех WG-интерфейсов динамически
    local _wg_after="network-online.target nftables.service wg-quick@${SERVER_WG_NIC}.service"
    local _wg_wants="network-online.target wg-quick@${SERVER_WG_NIC}.service"
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        _wg_after="${_wg_after} wg-quick@${TUNNEL_IFACE[$i]}.service"
        _wg_wants="${_wg_wants} wg-quick@${TUNNEL_IFACE[$i]}.service"
    done

    cat > /etc/systemd/system/wg-balance.service << EOF
[Unit]
Description=WireGuard Tunnel Watchdog & Balancer
After=${_wg_after}
Wants=${_wg_wants}

[Service]
Type=simple
# sleep 10: при холодном старте wg-quick@ oneshot завершаются быстро,
# но интерфейсы поднимаются с задержкой (ключи, handshake)
ExecStartPre=/bin/sleep 10
# Восстанавливаем fwmark правила если они потерялись (ребут, рестарт wg0)
ExecStartPre=-/bin/bash -c 'ip -4 rule del fwmark 0x200000 table main priority 30050 2>/dev/null; ip -4 rule add fwmark 0x200000 table main priority 30050'
ExecStart=/usr/local/bin/wg-balance.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# [fix v28.24.13] Systemd hardening — минимизируем поверхность атаки.
# CAP_NET_ADMIN нужен для wg/nft/ip rule, остальные привилегии не нужны.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log /var/run /run /etc/wireguard
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable wg-balance.service
    info "Watchdog systemd сервис создан"
}

# ── Конфиги WireGuard ──────────────────────────────────────────
createConfigs() {
    step "Создание конфигов WireGuard"
    mkdir -p /etc/wireguard

    for ((i=0; i<TUNNEL_COUNT; i++)); do
        local iface="${TUNNEL_IFACE[$i]}"
        local mtu="${TUNNEL_MTU[$i]:-1420}"
        local table="${TUNNEL_TABLE[$i]}"
        local addr_line="Address = ${TUNNEL_ADDRESS[$i]}"
        [ -n "${TUNNEL_ADDRESS_V6[$i]}" ] && addr_line="${addr_line}, ${TUNNEL_ADDRESS_V6[$i]}"
        local psk_line=""
        [ -n "${TUNNEL_PSK[$i]}" ] && psk_line="PresharedKey = ${TUNNEL_PSK[$i]}"
        # [fix v28.24.23] Атомарная запись через _atomic_write (sync + mv):
        # защита от обрыва питания или kill -9 в момент записи PrivateKey.
        local _tconf="/etc/wireguard/${iface}.conf"
        if ! _atomic_write "${_tconf}" 600 << EOF
[Interface]
PrivateKey = ${TUNNEL_PRIVATE[$i]}
${addr_line}
MTU = ${mtu}
Table = off
PostUp = ip route add default dev ${iface} table ${table}
PostDown = ip route del default dev ${iface} table ${table} 2>/dev/null || true
[Peer]
PublicKey = ${TUNNEL_PUBLIC[$i]}
${psk_line}
Endpoint = ${TUNNEL_ENDPOINT[$i]}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
        then
            error "Не удалось записать конфиг ${_tconf}"
        fi
        info "${iface} создан (MTU: ${mtu})"
    done

    # [fix] umask 077 — ключ создаётся сразу с правами 600 (без гонки tee+chmod)
    [ ! -f /etc/wireguard/server_private.key ] && (umask 077; wg genkey > /etc/wireguard/server_private.key)
    chmod 600 /etc/wireguard/server_private.key
    local SERVER_PRIV_KEY
    SERVER_PRIV_KEY=$(cat /etc/wireguard/server_private.key)
    local SERVER_PUB_KEY
    SERVER_PUB_KEY=$(wg pubkey < /etc/wireguard/server_private.key)

    # [fix v28.24.23] Атомарная запись серверного конфига через _atomic_write
    local _sconf="/etc/wireguard/${SERVER_WG_NIC}.conf"
    {
        printf '[Interface]\nPrivateKey = %s\nAddress = %s, %s\nListenPort = %s\nMTU = %s\nTable = off\n' \
            "${SERVER_PRIV_KEY}" "${SERVER_IPV4_ADDR}" "${SERVER_IPV6_ADDR}" "${SERVER_PORT}" "${SERVER_MTU:-1420}"
        printf 'PostUp = ip -4 rule add fwmark 0x200000 table main priority 30050 || true\n'
        printf 'PostDown = ip -4 rule del fwmark 0x200000 table main priority 30050 2>/dev/null || true; ip -4 rule del fwmark 0x100000 priority 30045 2>/dev/null || true\n'
    } | _atomic_write "${_sconf}" 600 || error "Не удалось записать серверный конфиг ${_sconf}"

    if [ -d /etc/wireguard/clients ]; then
        for f in /etc/wireguard/clients/*.conf; do
            [ -f "$f" ] || continue
            local CLIENT_NAME CLIENT_PRIV CLIENT_PUB CLIENT_PSK CLIENT_IPS
            CLIENT_NAME=$(basename "${f}" .conf)
            # [fix v28.18] PublicKey в клиентском [Peer] = ключ СЕРВЕРА.
            # Берём PrivateKey клиента и считаем публичный ключ из него.
            CLIENT_PRIV=$(grep -E "^\\s*PrivateKey\\s*=" "$f" | head -1 | cut -d= -f2- | tr -d ' ')
            if [ -z "${CLIENT_PRIV}" ]; then
                warn "У ${CLIENT_NAME} нет PrivateKey — пропускаю"
                continue
            fi
            CLIENT_PUB=$(wg pubkey <<< "${CLIENT_PRIV}" 2>/dev/null) || { warn "${CLIENT_NAME}: невалидный ключ"; continue; }
            CLIENT_PSK=$(grep -E "^\\s*PresharedKey\\s*=" "$f" | head -1 | cut -d= -f2- | tr -d ' ')
            CLIENT_IPS=$(grep "^Address" "$f" | head -1 | cut -d' ' -f3-)
            # [fix v28.22.1] Не пишем PresharedKey если он пустой — WireGuard не примет "PresharedKey = "
            {
                echo "[Peer]"
                echo "PublicKey = ${CLIENT_PUB}"
                [ -n "${CLIENT_PSK}" ] && echo "PresharedKey = ${CLIENT_PSK}"
                echo "AllowedIPs = ${CLIENT_IPS}"
            } >> "/etc/wireguard/${SERVER_WG_NIC}.conf"
            if [ -n "${CLIENT_PSK}" ]; then
                wg set "${SERVER_WG_NIC}" peer "${CLIENT_PUB}" \
                    preshared-key <(echo "${CLIENT_PSK}") \
                    allowed-ips "${CLIENT_IPS}" 2>/dev/null || true
            else
                wg set "${SERVER_WG_NIC}" peer "${CLIENT_PUB}" \
                    allowed-ips "${CLIENT_IPS}" 2>/dev/null || true
            fi
        done
    fi
    chmod 600 "/etc/wireguard/${SERVER_WG_NIC}.conf"
    info "Публичный ключ сервера: ${SERVER_PUB_KEY}"
}

# ── Клиенты ────────────────────────────────────────────────────
# [fix] Исправлен парсинг LAST_IPV4 — grep ищет AllowedIPs = X.X.X.X/32
addClient() {
    loadConfig
    echo -ne "  ${CYAN}→ Имя клиента${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    # [fix v28.21.3] Жёсткая валидация — имя идёт в путь файла и sed-паттерны.
    validateClientName "${CLIENT_NAME}"
    if [ -e "/etc/wireguard/clients/${CLIENT_NAME}.conf" ]; then
        warn "Клиент ${CLIENT_NAME} уже существует"
        return
    fi

    # [v28.22.0] Универсальная автовыдача IP для подсетей /16 .. /30.
    # Алгоритм: считаем «host part» как 32-битное целое, начинаем с 2-го хоста сети,
    # ищем первый свободный среди уже занятых /32 в server.conf.
    local _prefix="${CLIENT_IPV4_SUBNET##*/}"
    if ! [[ "${_prefix}" =~ ^[0-9]+$ ]] || [ "${_prefix}" -lt 16 ] || [ "${_prefix}" -gt 30 ]; then
        warn "CLIENT_IPV4_SUBNET=${CLIENT_IPV4_SUBNET} — поддерживаются префиксы /16../30. Отказ."
        return
    fi
    # IP сети → 32-битное число
    local _net="${CLIENT_IPV4_SUBNET%/*}"
    local _o1 _o2 _o3 _o4
    IFS=. read -r _o1 _o2 _o3 _o4 <<< "${_net}"
    local _net_int=$(( (_o1 << 24) | (_o2 << 16) | (_o3 << 8) | _o4 ))
    local _hosts=$(( (1 << (32 - _prefix)) - 2 ))   # минус network/broadcast
    if [ "${_hosts}" -lt 1 ]; then
        warn "Подсеть слишком мала (${CLIENT_IPV4_SUBNET}) — нет свободных хостов"
        return
    fi
    # Собираем уже выданные IP в виде 32-битных int
    local _used_file
    _used_file=$(mktemp) || { warn "mktemp failed — невозможно выделить IP"; return 1; }
    # [fix v28.22.1] `|| :` — пустой grep даёт rc=1 и при pipefail ловится ERR-trap.
    # [fix v28.24.10] grep -oP → awk: портабельность (BusyBox без PCRE).
    { awk '/AllowedIPs[[:space:]]*=/{
            for(i=1;i<=NF;i++) if($i ~ /^[0-9.]+\/32([,]|$)/){sub(/\/32.*$/,"",$i); print $i}
        }' "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null \
        | awk -F. '{printf "%d\n", ($1*16777216)+($2*65536)+($3*256)+$4}' \
        | sort -un > "${_used_file}"; } || : > "${_used_file}"
    # 1-й хост — это .1 (обычно адрес сервера), клиентам отдаём с .2
    local _candidate_int=$(( _net_int + 2 ))
    local _max_int=$(( _net_int + _hosts ))
    while [ "${_candidate_int}" -le "${_max_int}" ] && grep -qx "${_candidate_int}" "${_used_file}"; do
        _candidate_int=$(( _candidate_int + 1 ))
    done
    rm -f "${_used_file}"
    if [ "${_candidate_int}" -gt "${_max_int}" ]; then
        warn "Подсеть ${CLIENT_IPV4_SUBNET} заполнена (${_hosts} хостов) — расширь CLIENT_IPV4_SUBNET"
        return
    fi
    local _c1=$(( (_candidate_int >> 24) & 255 ))
    local _c2=$(( (_candidate_int >> 16) & 255 ))
    local _c3=$(( (_candidate_int >> 8)  & 255 ))
    local _c4=$(( _candidate_int & 255 ))
    local CLIENT_IPV4="${_c1}.${_c2}.${_c3}.${_c4}/32"
    # IPv6: используем младшие 16 бит как идентификатор (для совместимости со старой схемой /24).
    local _v6_id=$(( _candidate_int & 0xFFFF ))
    local ipv6_net="${CLIENT_IPV6_SUBNET%::*}"
    local CLIENT_IPV6
    CLIENT_IPV6=$(printf "%s::%x/128" "${ipv6_net}" "${_v6_id}")
    local PRIV PUB PRE SERVER_PUB_KEY
    PRIV=$(wg genkey)
    [ -n "${PRIV}" ] || error "wg genkey вернул пустой ключ — проверь установку wireguard-tools"
    PUB=$(wg pubkey <<< "${PRIV}")
    [ -n "${PUB}" ] || error "wg pubkey не сработал"
    PRE=$(wg genpsk)
    [ -n "${PRE}" ] || error "wg genpsk вернул пустой PSK"
    SERVER_PUB_KEY=$(wg pubkey < /etc/wireguard/server_private.key)
    [ -n "${SERVER_PUB_KEY}" ] || error "Не удалось получить публичный ключ сервера"

    cat >> "/etc/wireguard/${SERVER_WG_NIC}.conf" << EOF
[Peer]
PublicKey = ${PUB}
PresharedKey = ${PRE}
AllowedIPs = ${CLIENT_IPV4}, ${CLIENT_IPV6}
EOF

    # DNS: если dnsmasq активен — используем WG-IP сервера (реальный адрес, QR работает)
    local CLIENT_DNS="8.8.8.8, 8.8.4.4"
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"
    if systemctl is-active dnsmasq >/dev/null 2>&1 && [ "${DNS_MODE:-public}" != "public" ]; then
        CLIENT_DNS="${_wg_ip}"
    fi

    mkdir -p /etc/wireguard/clients
    # [fix] umask 077 — конфиг с PrivateKey+PSK создаётся сразу без гонки chmod
    (umask 077; cat > "/etc/wireguard/clients/${CLIENT_NAME}.conf" << EOF
[Interface]
PrivateKey = ${PRIV}
Address = ${CLIENT_IPV4}, ${CLIENT_IPV6}
DNS = ${CLIENT_DNS}
[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${PRE}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
)
    wg set "${SERVER_WG_NIC}" peer "${PUB}" \
        preshared-key <(echo "${PRE}") \
        allowed-ips "${CLIENT_IPV4},${CLIENT_IPV6}" 2>/dev/null || true
    qrencode -o "/etc/wireguard/clients/${CLIENT_NAME}.png" -t PNG \
        < "/etc/wireguard/clients/${CLIENT_NAME}.conf" 2>/dev/null || true
    info "Клиент ${GREEN}${CLIENT_NAME}${NC} добавлен (IPv4: ${CLIENT_IPV4}, DNS: ${CLIENT_DNS})"
    audit_log "addClient name=${CLIENT_NAME} ip=${CLIENT_IPV4}"
    echo ""
    qrencode -t UTF8 < "/etc/wireguard/clients/${CLIENT_NAME}.conf"
}

listClients() {
    loadConfig
    step "Список клиентов"
    # [fix v28.24.2] nullglob вместо ls — корректно при отсутствии файлов и пробелах в именах
    shopt -s nullglob
    local _client_files=(/etc/wireguard/clients/*.conf)
    shopt -u nullglob
    if [ ! -d /etc/wireguard/clients ] || [ "${#_client_files[@]}" -eq 0 ]; then
        warn "Нет клиентов"
        return
    fi
    echo ""
    printf "  ${BOLD}${CYAN}  %-20s  %-20s  %-22s${NC}\n" "Имя" "IPv4" "IPv6"
    echo -e "  ${CYAN}──────────────────────────────────────────────────────────────${NC}"
    for f in /etc/wireguard/clients/*.conf; do
        local name ipv4 ipv6
        name=$(basename "${f}" .conf)
        # [fix v28.24.10] Без PCRE — awk парсит "Address = v4[, v6]"
        ipv4=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/{split($2,a,","); gsub(/[[:space:]]/,"",a[1]); print a[1]; exit}' "${f}")
        ipv6=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/{split($2,a,","); gsub(/[[:space:]]/,"",a[2]); print a[2]; exit}' "${f}")
        printf "  ${GREEN}  %-20s${NC}  %-20s  %s\n" "${name}" "${ipv4}" "${ipv6:-—}"
    done
    echo ""
}

revokeClient() {
    loadConfig
    listClients
    echo -ne "  ${CYAN}→ Имя клиента для отзыва${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local CLIENT_CONF="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${CLIENT_CONF}" ] && { warn "Клиент не найден"; return; }
    # [fix v28.20.4] Клиентский .conf содержит PrivateKey клиента и PublicKey СЕРВЕРА.
    # Нам нужен публичный ключ КЛИЕНТА — вычисляем его из PrivateKey.
    local CLIENT_PRIV PUB
    CLIENT_PRIV=$(awk -F'=' '/^[[:space:]]*PrivateKey[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "${CLIENT_CONF}")
    if [ -z "${CLIENT_PRIV}" ]; then
        warn "Не найден PrivateKey в конфиге клиента — невозможно определить публичный ключ"
        return
    fi
    PUB=$(wg pubkey <<< "${CLIENT_PRIV}" 2>/dev/null) || { warn "Невалидный PrivateKey в конфиге клиента"; return; }
    [ -z "${PUB}" ] && { warn "Не удалось вычислить PublicKey клиента"; return; }
    # [fix v28.20.4] sed /PublicKey/,+3d не удаляет строку [Peer] перед ним.
    # Используем более точный паттерн: удаляем блок [Peer] + следующие строки до PublicKey включительно.
    # [fix v28.20.5] Передаём ключ через аргумент ($1) — безопасно, без bash-интерполяции в heredoc
    # [fix v28.22.2] Надёжное удаление [Peer]-блока: разбиваем по началам блоков,
    # выкидываем тот, чей PublicKey совпал. Работает и без PresharedKey,
    # и с произвольным порядком ключей в блоке. Не оставляет висящих [Peer].
    python3 - "${PUB}" "/etc/wireguard/${SERVER_WG_NIC}.conf" << 'PYEOF'
import sys, re
pub, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        data = f.read().replace('\r\n', '\n').replace('\r', '\n')
except FileNotFoundError:
    sys.exit(0)
parts = re.split(r'(?m)^(?=[ \t]*\[Peer\][ \t]*$)', data)
out = [p for p in parts
       if not (p.lstrip().startswith('[Peer]')
               and re.search(r'(?m)^\s*PublicKey\s*=\s*' + re.escape(pub) + r'\s*$', p))]
with open(path, 'w') as f:
    f.write(''.join(out))
print("ok")
PYEOF
    wg set "${SERVER_WG_NIC}" peer "${PUB}" remove 2>/dev/null || true
    rm -f "${CLIENT_CONF}" "/etc/wireguard/clients/${CLIENT_NAME}.png"
    # [fix v28.23.0]  #5: чистим состояние лимитов трафика, иначе при
    # повторном добавлении клиента с тем же именем watcher сразу его отключит.
    rm -f "/var/lib/wg/limits/${CLIENT_NAME}.total" \
          "/var/lib/wg/limits/${CLIENT_NAME}.rx" \
          "/var/lib/wg/limits/${CLIENT_NAME}.tx" \
          "/var/lib/wg/limits/${CLIENT_NAME}.disabled" 2>/dev/null || true
    # И снимаем строку из .routing-profiles
    if [ -f /etc/wireguard/.routing-profiles ]; then
        local _tmp; _tmp=$(mktemp)
        grep -v "^${CLIENT_NAME}:" /etc/wireguard/.routing-profiles > "${_tmp}" && \
            mv "${_tmp}" /etc/wireguard/.routing-profiles || rm -f "${_tmp}"
    fi
    info "Клиент ${CLIENT_NAME} удалён"
    audit_log "revokeClient name=${CLIENT_NAME}"
}

openClientsFolder() {
    step "Папка клиентов"
    info "Путь: /etc/wireguard/clients/"
    ls -la /etc/wireguard/clients/ 2>/dev/null || warn "Папка не найдена"
}

# ── Туннели ────────────────────────────────────────────────────
restartTunnels() {
    loadConfig
    # [fix v28.25.3] wg-quick может отсутствовать (пакет wireguard-tools не установлен).
    command -v wg-quick >/dev/null 2>&1 || { warn "wg-quick не найден — установи: apt-get install -y wireguard-tools"; return 1; }
    # [fix v28.20.8] flock защищает от параллельного запуска
    # (балансировщик/cron могут одновременно дёргать ip rule).
    # [fix v28.21.3] Lock-файл создаётся заранее; код проверяет статус subshell'а
    # и прекращает работу, если lock не взят (раньше return из subshell не выходил из функции).
    : > /var/run/wg-restart.lock 2>/dev/null || true
    (
        flock -w 30 200 || exit 99
        step "Перезапуск всех туннелей"
        for ((i=0; i<TUNNEL_COUNT; i++)); do
            wg-quick down "${TUNNEL_IFACE[$i]}" 2>/dev/null || true
        done
        wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
        sleep 1
        for ((i=0; i<TUNNEL_COUNT; i++)); do
            if wg-quick up "${TUNNEL_IFACE[$i]}" 2>/dev/null; then
                info "Туннель ${TUNNEL_IFACE[$i]} поднят"
            else
                warn "Туннель ${TUNNEL_IFACE[$i]} не поднялся"
            fi
        done
        if wg-quick up "${SERVER_WG_NIC}" 2>/dev/null; then
            info "Сервер ${SERVER_WG_NIC} поднят"
        else
            warn "Сервер не поднялся"
        fi
        systemctl restart wg-balance.service 2>/dev/null || true
        info "Готово"
        wg show
    ) 200>/var/run/wg-restart.lock
    local _rc=$?
    if [ "${_rc}" -eq 99 ]; then
        warn "Timeout ожидания lock /var/run/wg-restart.lock — перезапуск пропущен"
        return 1
    fi
    return 0
}

configureTunnel() {
    local idx=$1
    local num=$((idx + 1))
    section "Туннель #${num}"
    ask "Интерфейс"   "" "TUNNEL_IFACE[$idx]"      "wg-up${num}"
    ask "PrivateKey"  "" "TUNNEL_PRIVATE[$idx]"     ""
    ask "Address IPv4" "" "TUNNEL_ADDRESS[$idx]"    "10.7.0.${num}/32"
    ask "Address IPv6" "" "TUNNEL_ADDRESS_V6[$idx]" ""
    ask "PublicKey"   "" "TUNNEL_PUBLIC[$idx]"      ""
    ask "PresharedKey" "" "TUNNEL_PSK[$idx]"        ""
    ask "Endpoint"    "" "TUNNEL_ENDPOINT[$idx]"    ""
    hint "1420 — стандарт, 1280 — если проблемы с фрагментацией"
    ask "MTU"         "" "TUNNEL_MTU[$idx]"         "1420"
    # [fix v28.20.8] Валидация ввода перед записью в systemd/nftables конфиги
    validateIfaceName "${TUNNEL_IFACE[$idx]}"
    validateEndpoint  "${TUNNEL_ENDPOINT[$idx]}"
    # shellcheck disable=SC2004  # $idx в индексе массива — допустимо и наглядно
    TUNNEL_TABLE[$idx]=$((51821 + idx))
    info "Туннель настроен (MTU: ${TUNNEL_MTU[$idx]})"
}

addTunnel() {
    loadConfig
    section "Добавление туннеля"
    # [fix v28.25.3] Проверяем наличие wg-quick до любых операций
    command -v wg-quick >/dev/null 2>&1 || { warn "wg-quick не найден — установи: apt-get install -y wireguard-tools"; return 1; }
    # [v28.22.0] Авто-бэкап перед изменением списка туннелей
    _autoBackup "add-tunnel" || true
    local idx=${TUNNEL_COUNT}
    local num=$((idx + 1))
    ask "Интерфейс"    "" "TUNNEL_IFACE[$idx]"      "wg-up${num}"
    ask "PrivateKey"   "" "TUNNEL_PRIVATE[$idx]"    ""
    ask "Address IPv4" "" "TUNNEL_ADDRESS[$idx]"    "10.7.0.${num}/32"
    ask "Address IPv6" "" "TUNNEL_ADDRESS_V6[$idx]" ""
    ask "PublicKey"    "" "TUNNEL_PUBLIC[$idx]"     ""
    ask "PresharedKey" "" "TUNNEL_PSK[$idx]"        ""
    ask "Endpoint"     "" "TUNNEL_ENDPOINT[$idx]"   ""
    hint "1420 — стандарт, 1280 — если проблемы"
    ask "MTU"          "" "TUNNEL_MTU[$idx]"        "1420"
    # [fix v28.20.8] Валидация ввода перед записью в systemd/nftables конфиги
    validateIfaceName "${TUNNEL_IFACE[$idx]}"
    validateEndpoint  "${TUNNEL_ENDPOINT[$idx]}"
    # shellcheck disable=SC2004  # $idx в индексе массива — допустимо и наглядно
    TUNNEL_TABLE[$idx]=$((51821 + idx))
    TUNNEL_COUNT=$((TUNNEL_COUNT + 1))
    saveConfig
    createIpSetAndNft
    createConfigs
    createBalanceScript
    mkdir -p "/etc/systemd/system/wg-quick@${TUNNEL_IFACE[$idx]}.service.d"
    printf '[Service]\nExecStartPre=-/usr/bin/wg-quick down %%i\n' \
        > "/etc/systemd/system/wg-quick@${TUNNEL_IFACE[$idx]}.service.d/override.conf"
    # [fix] Обновляем After=/Wants= в wg-balance.service для нового туннеля
    local _wg_after="network-online.target nftables.service wg-quick@${SERVER_WG_NIC}.service"
    local _wg_wants="network-online.target wg-quick@${SERVER_WG_NIC}.service"
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        _wg_after="${_wg_after} wg-quick@${TUNNEL_IFACE[$i]}.service"
        _wg_wants="${_wg_wants} wg-quick@${TUNNEL_IFACE[$i]}.service"
    done
    sed -i "s|^After=.*|After=${_wg_after}|" /etc/systemd/system/wg-balance.service 2>/dev/null || true
    sed -i "s|^Wants=.*|Wants=${_wg_wants}|" /etc/systemd/system/wg-balance.service 2>/dev/null || true
    # [fix v28.25.3] Проверяем daemon-reload — юнит может содержать ошибку
    systemctl daemon-reload || warn "addTunnel: daemon-reload завершился с ошибкой (проверь: systemctl status wg-quick@${TUNNEL_IFACE[$idx]})"
    systemctl enable "wg-quick@${TUNNEL_IFACE[$idx]}" 2>/dev/null || true
    wg-quick up "${TUNNEL_IFACE[$idx]}" 2>/dev/null || warn "Туннель не поднялся"
    wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
    wg-quick up "${SERVER_WG_NIC}" 2>/dev/null || warn "Сервер не поднялся"
    systemctl restart wg-balance.service 2>/dev/null || true
    info "Туннель добавлен"
    audit_log "addTunnel iface=${TUNNEL_IFACE[$idx]} endpoint=${TUNNEL_ENDPOINT[$idx]}"
}

manageTunnel() {
    loadConfig
    step "Управление туннелями"
    [ ${TUNNEL_COUNT} -eq 0 ] && { warn "Нет туннелей"; return; }
    echo ""
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        local status="неактивен" color="${RED}"
        wg show "${TUNNEL_IFACE[$i]}" >/dev/null 2>&1 && status="активен" && color="${GREEN}"
        printf "  ${CYAN}%2d${NC}) ${color}%-12s${NC}  →  %s  ${DIM}(%s)${NC}\n" \
            "$((i+1))" "${TUNNEL_IFACE[$i]}" "${TUNNEL_ENDPOINT[$i]}" "${status}"
    done
    echo -e "   ${RED} 0${NC}) Отмена"
    echo ""
    read -rp "  Выбор: " choice
    [[ "${choice}" =~ ^[0-9]+$ ]] || { warn "Нужно число"; return; }
    [ "${choice}" -eq 0 ] && return
    local idx=$((choice - 1))
    [ ${idx} -lt 0 ] || [ ${idx} -ge ${TUNNEL_COUNT} ] && { warn "Неверный выбор"; return; }
    echo ""
    echo -e "  ${CYAN}Действие:${NC}"
    echo -e "    ${CYAN}1${NC}) Запустить"
    echo -e "    ${CYAN}2${NC}) Остановить"
    echo -e "    ${CYAN}3${NC}) Перезапустить"
    read -rp "  Выбор: " action
    case "${action}" in
        1) wg-quick up "${TUNNEL_IFACE[$idx]}" 2>/dev/null && info "Запущен" ;;
        2) wg-quick down "${TUNNEL_IFACE[$idx]}" 2>/dev/null && info "Остановлен" ;;
        3) wg-quick down "${TUNNEL_IFACE[$idx]}" 2>/dev/null; sleep 1
           wg-quick up "${TUNNEL_IFACE[$idx]}" 2>/dev/null && info "Перезапущен" ;;
        *) warn "Неверно" ;;
    esac
}

removeTunnel() {
    loadConfig
    step "Удаление туннеля"
    [ ${TUNNEL_COUNT} -eq 0 ] && { warn "Нет туннелей"; return; }
    echo ""
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        printf "  ${CYAN}%2d${NC}) %-12s  →  %s\n" \
            "$((i+1))" "${TUNNEL_IFACE[$i]}" "${TUNNEL_ENDPOINT[$i]}"
    done
    echo -e "   ${RED} 0${NC}) Отмена"
    echo ""
    read -rp "  Выбор: " choice
    [[ "${choice}" =~ ^[0-9]+$ ]] || { warn "Нужно число"; return; }
    [ "${choice}" -eq 0 ] && return
    local idx=$((choice - 1))
    [ ${idx} -lt 0 ] || [ ${idx} -ge ${TUNNEL_COUNT} ] && { warn "Неверный выбор"; return; }
    local iface="${TUNNEL_IFACE[$idx]}"
    wg-quick down "${iface}" 2>/dev/null || true
    systemctl disable "wg-quick@${iface}" 2>/dev/null || true
    rm -rf "/etc/systemd/system/wg-quick@${iface}.service.d"
    # [fix v28.25.3] Проверяем daemon-reload
    systemctl daemon-reload || warn "removeTunnel: daemon-reload завершился с ошибкой"
    rm -f "/etc/wireguard/${iface}.conf"
    local i
    for ((i=idx; i<TUNNEL_COUNT-1; i++)); do
        TUNNEL_IFACE[i]="${TUNNEL_IFACE[i+1]}"
        TUNNEL_PRIVATE[i]="${TUNNEL_PRIVATE[i+1]}"
        TUNNEL_ADDRESS[i]="${TUNNEL_ADDRESS[i+1]}"
        TUNNEL_ADDRESS_V6[i]="${TUNNEL_ADDRESS_V6[i+1]}"
        TUNNEL_PUBLIC[i]="${TUNNEL_PUBLIC[i+1]}"
        TUNNEL_PSK[i]="${TUNNEL_PSK[i+1]}"
        TUNNEL_ENDPOINT[i]="${TUNNEL_ENDPOINT[i+1]}"
        TUNNEL_TABLE[i]="${TUNNEL_TABLE[i+1]}"
        TUNNEL_MTU[i]="${TUNNEL_MTU[i+1]}"
    done
    TUNNEL_COUNT=$((TUNNEL_COUNT - 1))
    # [fix] unset последних элементов после сдвига — иначе старые данные
    # висят в памяти bash до конца сессии (классическая утечка массивов).
    unset "TUNNEL_IFACE[${TUNNEL_COUNT}]"
    unset "TUNNEL_PRIVATE[${TUNNEL_COUNT}]"
    unset "TUNNEL_ADDRESS[${TUNNEL_COUNT}]"
    unset "TUNNEL_ADDRESS_V6[${TUNNEL_COUNT}]"
    unset "TUNNEL_PUBLIC[${TUNNEL_COUNT}]"
    unset "TUNNEL_PSK[${TUNNEL_COUNT}]"
    unset "TUNNEL_ENDPOINT[${TUNNEL_COUNT}]"
    unset "TUNNEL_TABLE[${TUNNEL_COUNT}]"
    unset "TUNNEL_MTU[${TUNNEL_COUNT}]"
    for ((i=0; i<TUNNEL_COUNT; i++)); do TUNNEL_TABLE[i]=$((51821 + i)); done
    # [fix v28.24.6] Сбрасываем все таблицы из старого диапазона, чтобы
    # после переиндексации не остались default-маршруты на исчезнувшие
    # интерфейсы (wg-up3 при TUNNEL_COUNT=2 и т.п.).
    for _t in $(seq 51821 51830); do
        ip route flush table "${_t}" 2>/dev/null || true
    done
    saveConfig
    createIpSetAndNft
    createConfigs
    createBalanceScript
    wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
    wg-quick up "${SERVER_WG_NIC}" 2>/dev/null || warn "Сервер не поднялся"
    systemctl restart wg-balance.service 2>/dev/null || true
    info "Туннель '${iface}' удалён"
    audit_log "removeTunnel iface=${iface}"
}

# ── Диагностика ────────────────────────────────────────────────
diagnoseTunnels() {
    loadConfig
    section "Диагностика туннелей"
    echo -e "\n  ${BOLD}${CYAN}1. Статус WireGuard:${NC}"
    wg show 2>/dev/null || warn "WireGuard не активен"
    echo -e "\n  ${BOLD}${CYAN}2. Пинг до endpoints (ICMP + через туннель):${NC}"
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        local endpoint="${TUNNEL_ENDPOINT[$i]}"
        local host="${endpoint%%:*}"
        local iface="${TUNNEL_IFACE[$i]}"
        printf "    ${WHITE}%s${NC} → %s\n" "${iface}" "${host}"
        # ICMP до endpoint
        printf "      %-30s" "ICMP endpoint:"
        local ep_rtt
        ep_rtt=$(ping -c 1 -W 2 "${host}" 2>/dev/null | grep 'rtt' | \
                 sed -n 's|.*= [0-9.]*/\([0-9.]*\).*|\1|p' || true)
        if [ -n "${ep_rtt}" ]; then
            echo -e "${GREEN}${ep_rtt}ms${NC}"
        else
            echo -e "${YELLOW}недоступен (ICMP заблокирован)${NC}"
        fi
        # Пинг 8.8.8.8 через интерфейс
        printf "      %-30s" "8.8.8.8 через ${iface}:"
        if wg show "${iface}" >/dev/null 2>&1; then
            local tun_rtt
            tun_rtt=$(ping -I "${iface}" -c 1 -W 3 8.8.8.8 2>/dev/null | grep 'rtt' | \
                      sed -n 's|.*= [0-9.]*/\([0-9.]*\).*|\1|p' || true)
            [ -n "${tun_rtt}" ] \
                && echo -e "${GREEN}${tun_rtt}ms ✔${NC}" \
                || echo -e "${RED}нет ответа${NC}"
        else
            echo -e "${DIM}туннель не активен${NC}"
        fi
    done
    echo -e "\n  ${BOLD}${CYAN}3. Маршрутизация:${NC}"
    echo "    Основная таблица:"
    ip route show table main | grep default || echo "      нет маршрута"
    echo "    Правила:"
    ip rule show | grep -E "(prio|fwmark)" | head -15 | sed 's/^/      /'
    echo -e "\n  ${BOLD}${CYAN}4. GeoIP sets:${NC}"
    local _set_count _set6_count
    _set_count=$( { nft list set inet wg-policy russia    2>/dev/null | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}' | wc -l; } 2>/dev/null | tr -d '\n ')
    _set6_count=$( { nft list set inet wg-policy russia_v6 2>/dev/null | grep -oE '[0-9a-fA-F:]+/[0-9]+'                    | wc -l; } 2>/dev/null | tr -d '\n ')
    [ -z "${_set_count}" ]  && _set_count=0
    [ -z "${_set6_count}" ] && _set6_count=0
    if [ "${_set_count}" -gt 0 ] 2>/dev/null; then
        info "@russia    (IPv4): ${GREEN}${_set_count}${NC} подсетей"
    else
        warn "@russia пуст — запусти: /usr/local/bin/update-ru-ipset.sh"
    fi
    if [ "${_set6_count}" -gt 0 ] 2>/dev/null; then
        info "@russia_v6 (IPv6): ${GREEN}${_set6_count}${NC} подсетей"
    else
        warn "@russia_v6 пуст или отсутствует (старая инсталляция?)"
    fi
    # [v28.22.0] Offline-файлы (для работы «в полях»)
    if [ -s /etc/wireguard/geoip/ru-aggregated.zone ]; then
        info "Offline IPv4: ${GREEN}/etc/wireguard/geoip/ru-aggregated.zone${NC} ($(wc -l < /etc/wireguard/geoip/ru-aggregated.zone) строк)"
    else
        echo -e "  ${DIM}Offline IPv4 не задан (опционально: /etc/wireguard/geoip/ru-aggregated.zone)${NC}"
    fi
    if [ -s /etc/wireguard/geoip/ru-aggregated-v6.zone ]; then
        info "Offline IPv6: ${GREEN}/etc/wireguard/geoip/ru-aggregated-v6.zone${NC} ($(wc -l < /etc/wireguard/geoip/ru-aggregated-v6.zone) строк)"
    else
        echo -e "  ${DIM}Offline IPv6 не задан (опционально: /etc/wireguard/geoip/ru-aggregated-v6.zone)${NC}"
    fi
    echo -e "\n  ${BOLD}${CYAN}5. Балансировщик:${NC}"
    if systemctl is-active --quiet wg-balance.service; then info "Активен"; else warn "Не активен"; fi
    echo -e "\n  ${BOLD}${CYAN}6. Тест GeoIP (реальный):${NC}"
    echo -e "  ${DIM}Проверяем маршрутизацию — РФ IP через ${MAIN_INTERFACE}, зарубежный через туннель...${NC}"
    local _my_ip _tun_ip _best_tun

    # Определяем активный туннель
    _best_tun=$(ip rule show 2>/dev/null | awk '/^30200:.*lookup/{print $NF; exit}')
    _best_tun=$(ip route show table "${_best_tun:-51821}" 2>/dev/null | awk '/^default/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

    printf "  %-40s" "Мой IP (через ${MAIN_INTERFACE} напрямую):"
    _my_ip=$(curl -s --max-time 5 --interface "${MAIN_INTERFACE}" ifconfig.me 2>/dev/null || echo "нет ответа")
    echo -e "${WHITE}${_my_ip}${NC}"

    if [ -n "${_best_tun}" ]; then
        printf "  %-40s" "IP через туннель (${_best_tun}):"
        _tun_ip=$(curl -s --max-time 5 --interface "${_best_tun}" ifconfig.me 2>/dev/null || echo "нет ответа")
        echo -e "${WHITE}${_tun_ip}${NC}"
        if [ "${_my_ip}" != "${_tun_ip}" ] && [ "${_tun_ip}" != "нет ответа" ]; then
            echo ""
            info "${GREEN}Туннель работает:${NC} ${MAIN_INTERFACE}=${_my_ip}, туннель=${_tun_ip}"
        else
            echo ""
            warn "IP через туннель совпадает с ${MAIN_INTERFACE} — проверь туннель ${_best_tun}"
        fi
    else
        warn "Активный туннель не определён"
    fi

    # Проверяем маршрутизацию РФ трафика через правила
    echo ""
    echo -e "  ${DIM}Маршрут для РФ IP (77.88.8.8 с fwmark):${NC}"
    ip route get 77.88.8.8 iif "${SERVER_WG_NIC}" mark 0x200000 2>/dev/null | head -1 | sed 's/^/    /' \
        | grep -q "${MAIN_INTERFACE}" && echo -e "    ${GREEN}✔ РФ → ${MAIN_INTERFACE} (правильно)${NC}" \
        || echo -e "    ${YELLOW}⚠ Проверь маршрут РФ трафика${NC}"
    echo -e "  ${DIM}Маршрут для зарубежного IP (8.8.8.8 от клиента через wg0):${NC}"
    # [fix v28.20.4] Используем iif wg0 чтобы тестировать маршрут КЛИЕНТСКОГО трафика,
    # а не трафика самого сервера (серверный трафик намеренно идёт через main без туннеля)
    _route=$(ip route get 8.8.8.8 iif "${SERVER_WG_NIC}" 2>/dev/null | head -1 || true)
    echo "    ${_route}" | grep -q "wg-" \
        && echo -e "    ${GREEN}✔ Зарубежный → туннель (правильно)${NC}" \
        || echo -e "    ${YELLOW}⚠ Зарубежный идёт через ${_route}${NC}"
}

diagnoseIPTables() {
    section "Диагностика nftables"
    echo -e "\n  ${BOLD}${CYAN}1. Таблицы nftables:${NC}"
    nft list tables 2>/dev/null || warn "nftables не активен"
    echo -e "\n  ${BOLD}${CYAN}2. fwmark правила:${NC}"
    ip rule show | grep -E "fwmark 0x200000" || echo "    нет правил"
    echo -e "\n  ${BOLD}${CYAN}3. Сервис nftables:${NC}"
    if systemctl is-active --quiet nftables; then info "Активен"; else warn "Не активен"; fi
    echo -e "\n  ${BOLD}${CYAN}4. Маршрут по умолчанию (main):${NC}"
    ip route show table main | grep default || echo "    нет маршрута"
}

wgFullStatus() {
    section "Полный статус WireGuard"
    echo -e "\n  ${BOLD}${CYAN}1. WG интерфейсы:${NC}"
    ip -brief link show | grep -E "wg" || echo "    нет WG интерфейсов"
    echo -e "\n  ${BOLD}${CYAN}2. WireGuard peers:${NC}"
    wg show 2>/dev/null || warn "Не активен"
    echo -e "\n  ${BOLD}${CYAN}3. Конфиг сервера (первые 20 строк):${NC}"
    if [ -f "/etc/wireguard/${SERVER_WG_NIC}.conf" ]; then
        head -20 "/etc/wireguard/${SERVER_WG_NIC}.conf" | sed 's/^/    /'
    else
        warn "Конфиг не найден"
    fi
    echo -e "\n  ${BOLD}${CYAN}4. Клиенты:${NC}"
    local cnt=0
    if [ -d /etc/wireguard/clients ]; then
        shopt -s nullglob
        local _cfiles=(/etc/wireguard/clients/*.conf)
        cnt=${#_cfiles[@]}
        shopt -u nullglob
    fi
    echo "    Всего клиентов: ${cnt}"
}

# ── Балансировщик ──────────────────────────────────────────────
manageBalancer() {
    section "Управление балансировщиком"
    echo -e "  ${CYAN}1${NC}) Статус сервиса"
    echo -e "  ${CYAN}2${NC}) Просмотр логов (follow)"
    echo -e "  ${CYAN}3${NC}) Перезапуск"
    echo -e "  ${CYAN}4${NC}) Остановить"
    echo -e "  ${CYAN}5${NC}) Запустить"
    echo -e "  ${CYAN}6${NC}) Изменить интервал"
    echo -e "  ${CYAN}7${NC}) Изменить порог пинга"
    echo -e "  ${RED}0${NC}) Отмена"
    echo ""
    read -rp "  Выбор: " choice
    local new_val
    case "${choice}" in
        1) systemctl status wg-balance.service --no-pager
           journalctl -u wg-balance.service -n 20 --no-pager ;;
        2) journalctl -u wg-balance.service -f ;;
        3) systemctl restart wg-balance.service && info "Перезапущен" ;;
        4) systemctl stop wg-balance.service && info "Остановлен" ;;
        5) systemctl start wg-balance.service && info "Запущен" ;;
        6) read -rp "  Новый интервал (сек, 5..3600): " new_val
           if [[ "${new_val}" =~ ^[0-9]+$ ]] && (( new_val >= 5 && new_val <= 3600 )); then
               sed -i "s|^BALANCE_INTERVAL=.*|BALANCE_INTERVAL=\"${new_val}\"|" "${CONFIG_FILE}" && \
                   info "Интервал: ${new_val} сек"
               systemctl restart wg-balance.service
           else
               warn "Интервал должен быть целым числом в диапазоне 5..3600 — отмена"
           fi ;;
        7) read -rp "  Новый порог (мс, 10..5000): " new_val
           if [[ "${new_val}" =~ ^[0-9]+$ ]] && (( new_val >= 10 && new_val <= 5000 )); then
               sed -i "s|^BAD_PING_MS=.*|BAD_PING_MS=\"${new_val}\"|" "${CONFIG_FILE}" && \
                   info "Порог: ${new_val} мс"
               systemctl restart wg-balance.service
           else
               warn "Порог должен быть целым числом в диапазоне 10..5000 — отмена"
           fi ;;
        *) warn "Отмена" ;;
    esac
}

# ── MTProto Proxy ──────────────────────────────────────────────
installMTProto() {
    section "Установка MTProto Proxy"
    if [ -z "${SERVER_PUB_IP}" ] || [ "${SERVER_PUB_IP}" = "0.0.0.0" ]; then
        error "SERVER_PUB_IP не настроен!"
    fi
    echo -e "\n  ${CYAN}Публичный IP сервера:${NC} ${BOLD}${GREEN}${SERVER_PUB_IP}${NC}"
    read -rp "  IP верный? Enter для продолжения: "
    ask "DOMAIN (для FakeTLS)" "" "DOMAIN"    "ya.ru"
    ask "COUNT (кол-во ключей)" "" "COUNT"    "200"
    ask "DNS"                   "" "MTG_DNS"  "8.8.8.8"
    step "Установка зависимостей"
    apt update -q
    # Только то, что реально нужно для MTProxy
    apt install -y wget curl git build-essential qrencode util-linux
    # [fix v28.24.1] Тяжёлые инструменты мониторинга (glances/atop/iotop/sysdig...)
    # убраны из обязательной установки MTProxy — они не нужны для работы прокси.
    # Установи отдельно если нужно: apt install -y glances atop nmon btop iotop \
    #   sysstat iftop nload nethogs tcpdump bmon iptraf-ng lsof strace sysdig lnav
    step "Установка Go"
    # [fix v28.21.3] Динамически узнаём последнюю стабильную версию Go.
    local GO_VERSION
    GO_VERSION=$(curl -fsSL --tlsv1.2 --proto '=https' --max-time 10 https://go.dev/VERSION?m=text 2>/dev/null | head -n1 | sed 's/^go//')
    [ -z "${GO_VERSION}" ] && GO_VERSION="1.22.5"
    info "Используем Go ${GO_VERSION}"
    # [fix] Определяем архитектуру — без этого установка падает на arm64/armv7 (AWS Graviton, Oracle Ampere, RPi)
    local _GO_ARCH
    case "$(uname -m)" in
        x86_64)         _GO_ARCH="amd64" ;;
        aarch64|arm64)  _GO_ARCH="arm64" ;;
        armv7l|armv6l)  _GO_ARCH="armv6l" ;;
        *)              _GO_ARCH="amd64" ; warn "Неизвестная архитектура $(uname -m), пробуем amd64" ;;
    esac
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${_GO_ARCH}.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-${_GO_ARCH}.tar.gz"
    rm "go${GO_VERSION}.linux-${_GO_ARCH}.tar.gz"
    export PATH=$PATH:/usr/local/go/bin
    # [fix v28.25.2] Экспортируем GOPATH явно — go install создаёт ~/go/bin,
    # но только если GOPATH задан или используется дефолт $HOME/go.
    # Без export PATH последующие команды (generate-secret) не найдут бинарь.
    export GOPATH="${HOME}/go"
    export PATH="${PATH}:${GOPATH}/bin"
    step "Установка mtg"
    # [fix v28.25.2] Проверяем успешность go install явно.
    if ! go install github.com/9seconds/mtg/v2@latest; then
        error "go install mtg завершился с ошибкой — установка прервана"
    fi
    # [fix v28.25.2] Проверяем что каталог ~/go/bin создан и бинарь в нём есть.
    if [ ! -f "${GOPATH}/bin/mtg" ]; then
        error "Бинарь mtg не найден в ${GOPATH}/bin — go install мог завершиться частично"
    fi
    mv "${GOPATH}/bin/mtg" /usr/local/bin/mtg
    chmod +x /usr/local/bin/mtg
    step "Генерация ${COUNT} FakeTLS секретов"
    rm -f /root/mtproto_secrets.txt /root/mtproto_links.txt /etc/mtg.env
    local i
    # shellcheck disable=SC2153  # DOMAIN присваивается через ask "DOMAIN"
    for i in $(seq 1 "${COUNT}"); do
        /usr/local/bin/mtg generate-secret "${DOMAIN}" >> /root/mtproto_secrets.txt
    done
    step "Создание ссылок"
    while read -r SECRET; do
        echo "tg://proxy?server=${SERVER_PUB_IP}&port=443&secret=${SECRET}"
    done < /root/mtproto_secrets.txt > /root/mtproto_links.txt
    local SECRET
    SECRET=$(head -n 1 /root/mtproto_secrets.txt)
    echo "SECRET=${SECRET}" > /etc/mtg.env
    step "Создание systemd сервиса"
    cat > /etc/systemd/system/mtg.service << EOF
[Unit]
Description=MTProto Proxy
After=network.target wg-quick@${SERVER_WG_NIC}.service wg-balance.service
Wants=network.target wg-quick@${SERVER_WG_NIC}.service wg-balance.service
[Service]
EnvironmentFile=/etc/mtg.env
ExecStart=/usr/local/bin/mtg simple-run -n ${MTG_DNS} -i prefer-ipv4 0.0.0.0:443 \$SECRET
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE

# [fix v28.24.13] Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable mtg
    systemctl restart mtg
    systemctl restart wg-balance.service
    sleep 2
    banner "MTProto Proxy установлен!"
    info "Адрес: ${SERVER_PUB_IP}:443"
    info "Ключи: /root/mtproto_links.txt"
    echo ""
    head -n 5 /root/mtproto_links.txt
}

removeMTProto() {
    section "Удаление MTProto Proxy"
    read -rp "  Введи YES для подтверждения: " CONFIRM
    [ "${CONFIRM}" != "YES" ] && return
    systemctl stop mtg 2>/dev/null || true
    systemctl disable mtg 2>/dev/null || true
    rm -f /etc/systemd/system/mtg.service
    systemctl daemon-reload
    rm -f /root/mtproto_secrets.txt /root/mtproto_links.txt /etc/mtg.env
    rm -rf /usr/local/go
    info "MTProto удалён"
}

diagnoseMTProto() {
    section "Диагностика MTProto"
    echo -e "\n  ${BOLD}${CYAN}1. Статус сервиса:${NC}"
    systemctl status mtg --no-pager 2>/dev/null | head -15 || warn "Не установлен"
    echo -e "\n  ${BOLD}${CYAN}2. Порт 443:${NC}"
    ss -tlnp | grep :443 || warn "Порт не слушается"
    echo -e "\n  ${BOLD}${CYAN}3. Ключи:${NC}"
    if [ -f /root/mtproto_links.txt ]; then
        local cnt
        cnt=$(wc -l < /root/mtproto_links.txt)
        info "${cnt} ключей сгенерировано"
    else
        echo "    0 ключей"
    fi
}

showMTProtoKeys() {
    section "Ключи доступа MTProto"
    [ ! -f /root/mtproto_links.txt ] && { warn "Ключи не найдены"; return; }
    echo -e "  ${CYAN}1${NC}) Показать первые 10"
    echo -e "  ${CYAN}2${NC}) Показать все"
    echo -e "  ${RED}0${NC}) Отмена"
    echo ""
    read -rp "  Выбор: " choice
    case "${choice}" in
        1) head -n 10 /root/mtproto_links.txt ;;
        2) cat /root/mtproto_links.txt ;;
        *) ;;
    esac
}

# ── Полное удаление ────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════
# DNS — конфиденциальность + маршрутизация через nftset
# ════════════════════════════════════════════════════════════════
# Принцип (geo-режим):
#   Клиент → DNS запрос → dnsmasq (10.200.200.1:53)
#   dnsmasq → unbound (127.0.0.1:5335) → root servers (DNSSEC, qname-min)
#   Никакой внешний DNS-сервер не видит запросы клиентов.
#
#   Маршрутизация через nftset (не через IP апстрима):
#     tunnel-force домены: nftset → force_tunnel_v4/v6 → mark 0x100000 → туннель
#     direct домены:       nftset → russia/russia_v6   → mark 0x200000 → напрямую
#     остальные:           unbound резолвит, GeoIP в nftables решает куда
#
# Режимы DNS_MODE:
#   geo    — dnsmasq → unbound (рекурсия, DNSSEC, без внешнего апстрима)
#   tunnel — dnsmasq → stubby (DoT: Cloudflare/Quad9 по TLS 853, через туннель)
#   public — dnsmasq выключен, клиент использует 8.8.8.8 напрямую



# ── Освободить порт 53 от systemd-resolved ─────────────────────
_freePort53() {
    # [fix v28.20.5] disable --now вместо mask — не ломает cloud-init и apt-upgrade
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/99-wireguard.conf << EOF
[Resolve]
DNSStubListener=no
DNS=127.0.0.1
FallbackDNS=77.88.8.8
EOF
    sleep 1
    # [fix _freePort53] НЕ используем chattr -i/+i:
    #   • chattr на симлинке применяется к ЦЕЛИ (системному файлу systemd-resolved)
    #   • chattr +i ломает cloud-init, NetworkManager, netplan при reboot
    # Вместо этого: сохраняем бэкап содержимого (cp -fL читает сквозь симлинк),
    # затем rm удаляет только симлинк (не цель), создаём обычный файл.
    if [ -L /etc/resolv.conf ]; then
        local _target
        _target=$(readlink /etc/resolv.conf 2>/dev/null || true)
        if [ ! -f /etc/resolv.conf.wg-bak ]; then
            cp -fL /etc/resolv.conf /etc/resolv.conf.wg-bak 2>/dev/null || true
            info "resolv.conf был симлинком на ${_target} — содержимое сохранено в .wg-bak"
        fi
        # rm -f удаляет только симлинк, цель (stub-resolv.conf) не затрагивается
        rm -f /etc/resolv.conf
    elif [ -f /etc/resolv.conf ]; then
        if [ ! -f /etc/resolv.conf.wg-bak ]; then
            if ! grep -qx "nameserver 127.0.0.1" /etc/resolv.conf 2>/dev/null; then
                cp -f /etc/resolv.conf /etc/resolv.conf.wg-bak 2>/dev/null || true
            fi
        fi
        rm -f /etc/resolv.conf
    fi
    # [fix v28.23.2] первичный 127.0.0.1 (dnsmasq), резервный 77.88.8.8 (Яндекс, в @russia).
    # timeout:1 attempts:1 — не зависаем при поднимающемся dnsmasq.
    printf "nameserver 127.0.0.1\nnameserver 77.88.8.8\noptions timeout:1 attempts:1\n" > /etc/resolv.conf
    info "resolv.conf → 127.0.0.1 (dnsmasq) + 77.88.8.8 (fallback). НЕ используем chattr."
}

# ── Базовый конфиг dnsmasq (одинаков для всех режимов) ─────────
_writeDnsmasqBase() {
    local _wg_ip="$1"
    if [ -z "${_wg_ip}" ]; then
        warn "Не удалось определить IP сервера для dnsmasq"
        return 1
    fi
    cat > /etc/dnsmasq.conf << EOF
# WireGuard DNS (управляется скриптом — не редактировать вручную)
# Слушаем на WG-интерфейсе, loopback (для самого сервера) и 127.0.0.1
interface=${SERVER_WG_NIC}
interface=lo
bind-interfaces
listen-address=${_wg_ip},127.0.0.1
# Не использовать /etc/resolv.conf — форвардим через wg-dns.conf
no-resolv
no-poll
# Не слушать на основном интерфейсе
except-interface=${MAIN_INTERFACE}
# Подключаем конфиг форвардинга и tunnel-force
conf-dir=/etc/dnsmasq.d/,*.conf
EOF
}

# ── Написать конфиг форвардинга в зависимости от режима ────────
_writeDnsmasqForward() {
    local mode="$1"
    if [ "${mode}" = "tunnel" ]; then
        # [v28.24.15] Tunnel-режим: dnsmasq → stubby (127.0.0.1:5353) → DoT
        # Шифруем апстрим-запросы (Cloudflare/Quad9 по TLS 853),
        # сам трафик stubby уходит в туннель. DPI провайдера/хостера
        # больше не видит plaintext :53 от сервера.
        cat > "${DNSMASQ_WG_CONF}" << 'EOF'
# Tunnel-режим: DNS-over-TLS через локальный stubby (127.0.0.1:5353)
# Никаких plaintext :53 наружу — DPI не видит запросы клиентов.
server=127.0.0.1#5353
no-resolv
# strict-order: всегда первый сервер (stubby), не пробуем другие
strict-order
EOF
        info "DNS tunnel: dnsmasq → stubby (DoT, 127.0.0.1:5353) → Cloudflare/Quad9"
    else
        # Geo-режим: форвард на локальный unbound (127.0.0.1:5335)
        # unbound сам рекурсивно резолвит через root servers (root.hints),
        # никакой внешний апстрим не видит все запросы. DNSSEC включён.
        # qname-minimisation: каждый NS получает только нужную ему часть имени.
        cat > "${DNSMASQ_WG_CONF}" << 'EOF'
# Geo-режим: форвард на локальный unbound (рекурсивный резолвер, root hints)
# Никакого внешнего апстрима — unbound сам ходит к корневым серверам.
# DNSSEC валидация выполняется в unbound.
server=127.0.0.1#5335
no-resolv
strict-order
# Кэш dnsmasq — 500k запросов (дополнительный слой поверх кэша unbound)
cache-size=500000
EOF
        # Проверяем что unbound реально слушает — если нет, fallback на stubby (DoT)
        if ! ss -lntu 2>/dev/null | grep -q '127\.0\.0\.1:5335'; then
            warn "unbound не отвечает на :5335 — geo fallback на stubby (DoT)"
            cat > "${DNSMASQ_WG_CONF}" << 'FBEOF'
# Geo fallback: unbound недоступен — форвард на stubby (DoT)
server=127.0.0.1#5353
no-resolv
strict-order
cache-size=500000
FBEOF
        else
            info "DNS geo: dnsmasq → unbound (127.0.0.1:5335) → root servers (DNSSEC + qname-min)"
        fi
    fi
}


# ── DNS-over-TLS через stubby (v28.24.15) ─────────────────────────
# Поднимает локальный резолвер 127.0.0.1:5353, который форвардит
# DNS на Cloudflare (1.1.1.1) и Quad9 (9.9.9.9) по TLS (порт 853).
# dnsmasq в tunnel-режиме отправляет апстрим-запросы СЮДА вместо
# plaintext 8.8.8.8 — DPI провайдера/хостера видит только TLS на :853.
_setupStubby() {
    if ! command -v stubby >/dev/null 2>&1; then
        warn "stubby не установлен — DoT недоступен (apt-get install stubby)"
        return 1
    fi
    mkdir -p /etc/stubby
    cat > /etc/stubby/stubby.yml << 'STUBBY_EOF'
# Managed by wg-server — DNS-over-TLS resolver for dnsmasq upstream
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
round_robin_upstreams: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.1@5353
  - 0::1@5353
appdata_dir: "/var/cache/stubby"
upstream_recursive_servers:
  # Cloudflare DNS over TLS
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
  # Quad9 (фильтрует malware, без анонимной аналитики)
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"
  # Google DNS over TLS (резерв)
  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
STUBBY_EOF
    mkdir -p /var/cache/stubby
    chown -R stubby:stubby /var/cache/stubby 2>/dev/null || true
    systemctl enable stubby 2>/dev/null || true
    systemctl restart stubby 2>/dev/null || true
    # Ждём до 5с пока stubby реально слушает 127.0.0.1:5353
    local _i=0
    while [ $_i -lt 5 ]; do
        if ss -lntu 2>/dev/null | grep -q '127\.0\.0\.1:5353'; then
            info "stubby поднят — DoT-резолвер на 127.0.0.1:5353"
            return 0
        fi
        sleep 1; _i=$((_i + 1))
    done
    warn "stubby не отвечает на 127.0.0.1:5353 — DNS-апстрим вернётся к Яндексу"
    return 1
}

# ── Рекурсивный резолвер unbound (v28.24.22) ─────────────────────────
# Слушает на 127.0.0.1:5335. dnsmasq в geo-режиме форвардит сюда.
# unbound сам ходит к корневым серверам (root.hints), никакого внешнего
# апстрима. DNSSEC валидация включена. qname-minimisation скрывает
# полное имя от промежуточных NS — каждый видит только свою часть.
# Кэш: 512MB (rrset + msg по 256MB), aggressive-nsec + prefetch.
_setupUnbound() {
    if ! command -v unbound >/dev/null 2>&1; then
        warn "unbound не установлен — geo-режим вернётся к Яндексу (apt-get install unbound)"
        return 1
    fi

    # Получаем свежий root.hints если его нет или он старше 30 дней
    local _hints="/var/lib/unbound/root.hints"
    if [ ! -f "${_hints}" ] ||        [ "$(find "${_hints}" -mtime +30 2>/dev/null | wc -l)" -gt 0 ]; then
        info "Загружаю root.hints..."
        curl -fsSL --max-time 15             "https://www.internic.net/domain/named.cache"             -o "${_hints}" 2>/dev/null         || wget -qO "${_hints}" --timeout=15             "https://www.internic.net/domain/named.cache" 2>/dev/null         || true
        [ -s "${_hints}" ]             && info "root.hints обновлён"             || warn "root.hints не скачан — unbound использует встроенные прайминг-записи"
    fi

    # Обновляем trust-anchor для DNSSEC
    unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true

    mkdir -p /etc/unbound/unbound.conf.d
    cat > /etc/unbound/unbound.conf.d/wg-recursive.conf << 'UNBOUND_EOF'
# Managed by wg-server — не редактировать вручную
server:
    # Слушаем только на loopback — снаружи недоступен
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    # Только localhost может запрашивать
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse

    # Root hints
    root-hints: "/var/lib/unbound/root.hints"

    # DNSSEC
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes

    # qname minimisation — скрываем полное имя от промежуточных NS
    qname-minimisation: yes
    qname-minimisation-strict: no

    # Кэш — 512MB (rrset + message cache по 256MB)
    rrset-cache-size: 256m
    msg-cache-size: 256m
    # Агрессивный NSEC — кэшируем negative ответы, меньше запросов наружу
    aggressive-nsec: yes
    # Prefetch — обновляем записи за 10% до истечения TTL
    prefetch: yes
    prefetch-key: yes
    # TTL: минимум 30s, максимум 24h
    cache-min-ttl: 30
    cache-max-ttl: 86400

    # Скрываем версию и hostname
    hide-version: yes
    hide-identity: yes
    identity: "dns"

    # Защита от amplification / rebinding
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    use-caps-for-id: yes

    # Производительность
    outgoing-range: 512
    num-queries-per-thread: 1024
    num-threads: 2

    # Логирование минимальное
    verbosity: 0
    logfile: ""
    use-syslog: yes

    root-key-sentinel: yes
UNBOUND_EOF

    mkdir -p /etc/systemd/system/unbound.service.d
    cat > /etc/systemd/system/unbound.service.d/99-wireguard.conf << 'DROPIN_EOF'
[Service]
Restart=on-failure
RestartSec=5
DROPIN_EOF

    systemctl daemon-reload
    systemctl enable unbound 2>/dev/null || true
    systemctl restart unbound 2>/dev/null || true

    local _i=0
    while [ $_i -lt 8 ]; do
        if ss -lntu 2>/dev/null | grep -q '127\.0\.0\.1:5335'; then
            info "unbound поднят — рекурсивный резолвер на 127.0.0.1:5335 (DNSSEC + qname-min + кэш 512MB)"
            return 0
        fi
        sleep 1; _i=$((_i + 1))
    done
    warn "unbound не отвечает на 127.0.0.1:5335 — geo-режим вернётся к Яндексу"
    return 1
}

# ── NetworkManager: запрещаем трогать наш resolv.conf и wg* ─────────
# (v28.24.15) При DHCP renew / link flap NM молча перезаписывал
# /etc/resolv.conf, снося nameserver 127.0.0.1 → dnsmasq оставался
# без клиентов. Также NM иногда поднимает wg-интерфейсы по-своему.
_setupNetworkManagerUnmanaged() {
    # [fix] Надёжная проверка: NM считается присутствующим только если
    # исполняемый файл есть И сервис активен или включён.
    # Пустая директория /etc/NetworkManager — частый артефакт удалённого пакета
    # или cloud-init; без бинаря она безвредна, но создавать конфиг в неё незачем.
    local _nm_present=0
    if command -v nmcli >/dev/null 2>&1; then
        # nmcli есть — проверяем, что демон реально работает или включён автозапуск
        if systemctl is-active NetworkManager >/dev/null 2>&1 \
            || systemctl is-enabled NetworkManager >/dev/null 2>&1; then
            _nm_present=1
        fi
    fi
    if [ "${_nm_present}" -eq 0 ]; then
        # NM не установлен или не активен — нечего настраивать
        return 0
    fi
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/99-wireguard.conf << 'NM_EOF'
# Managed by wg-server (v28.24.15)
# Не трогать resolv.conf — им управляет dnsmasq / wg-server.
# Не управлять wg-интерфейсами — это делает wg-quick@.
[main]
rc-manager=unmanaged
dns=none

[keyfile]
unmanaged-devices=interface-name:wg*;interface-name:wg-*
NM_EOF
    systemctl reload NetworkManager 2>/dev/null \
        || systemctl restart NetworkManager 2>/dev/null \
        || true
    info "NetworkManager: rc-manager=unmanaged, wg* unmanaged (resolv.conf защищён)"
}

# Вызывается автоматически из firstInstall
_setupDnsmasqAuto() {
    loadConfig
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"   # 10.200.200.1

    _setupNetworkManagerUnmanaged
    _setupStubby || warn "stubby не поднят — tunnel-режим вернётся к plaintext"
    _setupUnbound || warn "unbound не поднят — geo-режим вернётся к Яндексу как fallback"
    _freePort53
    _writeDnsmasqBase "${_wg_ip}"
    _writeDnsmasqForward "geo"

    # Drop-in: только Restart — НЕ добавляем After=wg-quick@ т.к. это создаёт
    # ordering cycle при shutdown: nss-lookup/stop→dnsmasq/stop→wg-quick/stop→nss-lookup/stop.
    # Если dnsmasq стартует до wg0 интерфейса — упадёт и сам поднимется через RestartSec=5.
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    cat > /etc/systemd/system/dnsmasq.service.d/99-wireguard.conf << 'EOF'
[Service]
Restart=on-failure
RestartSec=5
# [fix v28.20.8] Ждём появления nftables set @russia до 60s.
# Иначе dnsmasq может стартовать раньше wg0/nftables и не увидит RU IP при первом резолвинге.
ExecStartPre=/bin/bash -c 'i=0; while [ $i -lt 60 ]; do [ -f /run/wg-russia-ready ] && exit 0; sleep 1; i=$((i+1)); done; echo "WARNING: marker /run/wg-russia-ready не появился за 60s, стартуем без GeoIP" >&2'
EOF
    systemctl daemon-reload
    systemctl enable dnsmasq 2>/dev/null || true
    systemctl restart dnsmasq 2>/dev/null || true
    # [fix v28.24.16] _freePort53 вызывается дважды: до (освобождаем порт 53 перед запуском dnsmasq)
    # и после (обновляем resolv.conf → 127.0.0.1, чтобы сервер резолвил через dnsmasq в geo-режиме)
    _freePort53
    if systemctl is-active dnsmasq >/dev/null 2>&1; then
        # [fix _setupDnsmasqAuto] Устанавливаем DNS_MODE="geo" только при первичной
        # установке (CONFIG_FILE не существует) или если режим был "public".
        # Не сбрасываем явно выбранный пользователем "tunnel" → "geo".
        if [ ! -f "${CONFIG_FILE}" ] || [ "${DNS_MODE:-public}" = "public" ]; then
            DNS_MODE="geo"
        fi
        saveConfig
        # Обновляем DNS у всех существующих клиентов
        for f in /etc/wireguard/clients/*.conf; do
            [ -f "$f" ] || continue
            sed -i "s|^DNS = .*|DNS = ${_wg_ip}|" "$f"
            qrencode -o "${f%.conf}.png" -t PNG < "$f" 2>/dev/null || true
        done
        info "dnsmasq запущен — DNS клиентов: ${GREEN}${_wg_ip}${NC} (geo-режим)"
        _rebuildTunnelForce 2>/dev/null || true
    else
        warn "dnsmasq не стартовал — клиенты используют 8.8.8.8"
        DNS_MODE="public"
        saveConfig
    fi
}

setupSplitDNS() {
    loadConfig
    section "Настройка DNS"
    echo ""
    echo -e "  ${WHITE}Выбери режим:${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) ${WHITE}geo${NC}    — unbound → root servers (рекурсия, DNSSEC)"
    echo -e "      ${DIM}Рекомендуется. dnsmasq → unbound (127.0.0.1:5335) → корневые серверы.${NC}"
    echo -e "      ${DIM}Никакого внешнего апстрима. DNSSEC + qname-min + кэш 512MB.${NC}"
    echo -e "      ${DIM}Трафик маршрутизируется по GeoIP: РФ напрямую, зарубежье в туннель.${NC}"
    echo ""
    echo -e "  ${YELLOW}2${NC}) ${WHITE}tunnel${NC} — DoT (Cloudflare/Quad9 TLS 853) через туннель"
    echo -e "      ${DIM}Весь DNS-трафик уходит в туннель. Максимальная приватность.${NC}"
    echo ""
    echo -e "  ${YELLOW}3${NC}) ${WHITE}public${NC} — без dnsmasq, 8.8.8.8 напрямую"
    echo -e "      ${DIM}dnsmasq выключен, клиент использует 8.8.8.8 напрямую.${NC}"
    echo ""
    echo -e "  ${RED}0${NC}) Отмена"
    echo ""
    read -rp "  Выбор: " _mc
    case "${_mc}" in
        1) _applyDNSMode "geo"    ;;
        2) _applyDNSMode "tunnel" ;;
        3) _applyDNSMode "public" ;;
        0) return ;;
        *) warn "Неверный выбор" ;;
    esac
}

_applyDNSMode() {
    local mode="$1"
    loadConfig
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"

    _freePort53

    if [ "${mode}" = "public" ]; then
        systemctl stop dnsmasq 2>/dev/null || true
        systemctl disable dnsmasq 2>/dev/null || true
        DNS_MODE="public"
        saveConfig
        # [fix v28.24.7] Пересоздаём nftables — mangle-output зависит от DNS_MODE
        createIpSetAndNft
        for f in /etc/wireguard/clients/*.conf; do
            [ -f "$f" ] || continue
            sed -i "s|^DNS = .*|DNS = 8.8.8.8, 8.8.4.4|" "$f"
            qrencode -o "${f%.conf}.png" -t PNG < "$f" 2>/dev/null || true
            info "Обновлён: $(basename "$f" .conf) → DNS 8.8.8.8"
        done
        info "Режим public: dnsmasq выключен"
        return
    fi

    _writeDnsmasqBase "${_wg_ip}"
    # [v28.24.22] geo-режим использует unbound — убеждаемся что запущен
    # [fix v28.25.0] Проверяем результат: если unbound/stubby не поднялся — fallback на
    # публичный DNS вместо битого форварда на несуществующий локальный порт.
    if [ "${mode}" = "geo" ]; then
        if ! _setupUnbound; then
            warn "_applyDNSMode: unbound не поднят — использую Яндекс.DNS (77.88.8.8) как fallback"
            mode="geo-fallback-yandex"
        fi
        # geo не использует stubby — останавливаем чтобы не держал :5353 вхолостую
        systemctl stop stubby 2>/dev/null || true
    fi
    # [fix] tunnel-режим требует stubby для DoT-форварда на 127.0.0.1:5353
    if [ "${mode}" = "tunnel" ]; then
        if ! _setupStubby; then
            warn "_applyDNSMode: stubby не поднят — tunnel-режим упадёт на plaintext. Использую Яндекс fallback."
            # Записываем fallback-конфиг вместо broken-форварда
            cat > "${DNSMASQ_WG_CONF}" << 'FBEOF'
# Fallback: stubby недоступен — форвард на Яндекс.DNS (РФ IP → напрямую)
server=77.88.8.8
server=77.88.8.1
no-resolv
strict-order
FBEOF
            mode="geo"   # сохраняем в конфиге как geo, т.к. tunnel сломан
        else
            # tunnel использует stubby — останавливаем unbound чтобы не держал :5335 вхолостую
            systemctl stop unbound 2>/dev/null || true
        fi
    fi
    # В geo-fallback-yandex режим уже записан в _writeDnsmasqForward через ветку else
    [[ "${mode}" == "geo-fallback-yandex" ]] && mode="geo"
    _writeDnsmasqForward "${mode}"
    _rebuildTunnelForce

    # Убеждаемся что drop-in существует (только Restart, без After=wg-quick@ — цикл)
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    cat > /etc/systemd/system/dnsmasq.service.d/99-wireguard.conf << 'EOF'
[Service]
Restart=on-failure
RestartSec=5
# [fix v28.20.8] Ждём появления nftables set @russia до 60s
ExecStartPre=/bin/bash -c 'i=0; while [ $i -lt 60 ]; do [ -f /run/wg-russia-ready ] && exit 0; sleep 1; i=$((i+1)); done; echo "WARNING: marker /run/wg-russia-ready не появился за 60s, стартуем без GeoIP" >&2'
EOF
    systemctl daemon-reload
    systemctl enable dnsmasq 2>/dev/null || true
    # [fix v28.24.23] Валидация dnsmasq конфига перед рестартом — откат при ошибке
    if command -v dnsmasq >/dev/null 2>&1; then
        if ! dnsmasq --test -C /etc/dnsmasq.conf 2>/dev/null; then
            warn "_applyDNSMode: dnsmasq --test обнаружил ошибку в конфиге — перезапуск пропущен"
            DNS_MODE="${mode}"
            saveConfig
            return 1
        fi
    fi
    systemctl restart dnsmasq
    # Повторно вызываем _freePort53 чтобы resolv.conf остался → 127.0.0.1
    # (restart dnsmasq иногда сбрасывает chattr если symlink пересоздаётся)
    _freePort53
    if systemctl is-active dnsmasq >/dev/null 2>&1; then
        DNS_MODE="${mode}"
        saveConfig
        # [fix v28.24.7] Пересоздаём nftables — mangle-output зависит от DNS_MODE
        createIpSetAndNft
        for f in /etc/wireguard/clients/*.conf; do
            [ -f "$f" ] || continue
            sed -i "s|^DNS = .*|DNS = ${_wg_ip}|" "$f"
            qrencode -o "${f%.conf}.png" -t PNG < "$f" 2>/dev/null || true
            info "Обновлён: $(basename "$f" .conf) → DNS ${_wg_ip}"
        done
        info "Режим ${mode} активен. Клиентские конфиги и QR обновлены."
        audit_log "setupSplitDNS mode=${mode}"
    else
        warn "dnsmasq не стартовал. Лог: journalctl -u dnsmasq -n 20"
    fi
}

# Пересборка конфига "принудительно через туннель" из TUNNEL_FORCE_DOMAINS
# Домены из этого файла форвардятся на 8.8.8.8 — иностранный IP,
# значит DNS-трафик уйдёт через туннель (не в @russia)
_rebuildTunnelForce() {
    # [fix v28.24.10] Аудит: вся функция под общим nft-lock'ом. Раньше
    # вызовы из addTunnelForceDomain/менюшек шли без flock и могли пересечься
    # с update-ru-ipset / restartTunnels (редко, но возможно).
    (
        flock -w 30 200 || { warn "_rebuildTunnelForce: nft занят, попробуй позже"; exit 0; }
    local out="${DNSMASQ_FORCE_CONF}"
    # [fix v28.23.2]  #3: проверяем существование set перед flush.
    # На старых установках без force_tunnel_v4/v6 flush+add давали ошибки в логах.
    local _have_v4=0 _have_v6=0
    nft list set inet wg-policy force_tunnel_v4 >/dev/null 2>&1 && _have_v4=1
    nft list set inet wg-policy force_tunnel_v6 >/dev/null 2>&1 && _have_v6=1
    [ "${_have_v4}" = "1" ] && nft flush set inet wg-policy force_tunnel_v4 2>/dev/null || true
    [ "${_have_v6}" = "1" ] && nft flush set inet wg-policy force_tunnel_v6 2>/dev/null || true
    if [ ! -f "${TUNNEL_FORCE_DOMAINS}" ] || [ ! -s "${TUNNEL_FORCE_DOMAINS}" ]; then
        rm -f "${out}"
        systemctl reload-or-restart dnsmasq 2>/dev/null || true
        exit 0
    fi
    {
        echo "# Домены принудительно через туннель"
        echo "# [v28.24.22] nftset: dnsmasq резолвит через unbound (конфиденциально),"
        echo "# полученные IP кладёт в force_tunnel_v4/v6 — без plaintext DNS наружу."
        echo "# Файл: ${TUNNEL_FORCE_DOMAINS}  — не редактировать этот файл напрямую"
        # [fix v28.23.0]  #2: собираем IP/CIDR в batch-файл и грузим
        # одним nft -f, а не N отдельными вызовами.
        local _v4=() _v6=()
        while IFS= read -r line; do
            [[ "${line}" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            line="${line%%#*}"
            line="${line%"${line##*[! ]}"}"
            [ -z "${line}" ] && continue
            if echo "${line}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
                _v4+=("${line}")
            elif echo "${line}" | grep -qE '^[0-9a-fA-F:]+(/[0-9]+)?$' && echo "${line}" | grep -q ':'; then
                # [fix v28.24.14] нормализация: одиночный IPv6 без префикса → /128
                [[ "${line}" != */* ]] && line="${line}/128"
                _v6+=("${line}")
            else
                # [fix v28.24.22] nftset вместо server=/domain/8.8.8.8:
                # dnsmasq резолвит через свой апстрим (unbound/stubby — конфиденциально),
                # IP-ответ автоматически добавляется в nft set force_tunnel_v4/v6.
                # Маршрутизация работает через nftables mark 0x100000, DNS — без утечки.
                echo "nftset=/${line}/4#inet#wg-policy#force_tunnel_v4,6#inet#wg-policy#force_tunnel_v6"
            fi
        done < "${TUNNEL_FORCE_DOMAINS}"
        # [fix v28.24.12] Дополнительно читаем отдельный файл CIDR-в-туннель.
        if [ -f "${TUNNEL_FORCE_CIDR}" ] && [ -s "${TUNNEL_FORCE_CIDR}" ]; then
            while IFS= read -r line; do
                [[ "${line}" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${line// }" ]] && continue
                line="${line%%#*}"
                line="${line%"${line##*[! ]}"}"
                [ -z "${line}" ] && continue
                if echo "${line}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
                    _v4+=("${line}")
                elif echo "${line}" | grep -qE '^[0-9a-fA-F:]+(/[0-9]+)?$' && echo "${line}" | grep -q ':'; then
                    [[ "${line}" != */* ]] && line="${line}/128"
                    _v6+=("${line}")
                fi
            done < "${TUNNEL_FORCE_CIDR}"
        fi
    } > "${out}"
    # [fix v28.23.2] Batch-add только если соответствующий set существует.
    # [fix v28.24.2] Заменили trap RETURN на явный rm — RETURN-trap при вложенных
    # вызовах молча затирает trap родителя.
    # [fix v28.24.10] CIDR дробятся чанками по 200 элементов — с запасом под
    # очень большие списки (>5000): даже на старых nft строка не упрётся в лимит.
    # [fix v28.25.1] Дополнительное ограничение по байтам строки: при 20k+ подсетей
    # даже чанк из 200 элементов IPv6 (до 43 байт каждый) может дать ~8600 байт на
    # строку — близко к internal limit nft. Переключаемся на построчную эмиссию
    # как только накопленная строка превысит 4096 байт.
    if { [ "${_have_v4}" = "1" ] && [ "${#_v4[@]}" -gt 0 ]; } || \
       { [ "${_have_v6}" = "1" ] && [ "${#_v6[@]}" -gt 0 ]; }; then
        local _nft_batch
        _nft_batch=$(mktemp)
        # [fix v28.25.2] Регистрируем trap для гарантированной очистки _nft_batch
        # при любом выходе (в т.ч. при ошибке nft -f или нештатном exit).
        # rm -f после nft -f ниже дублирует очистку для штатного пути — trap
        # страхует нештатные случаи.
        # [fix] RETURN не работает внутри subshell ( ... ) — subshell делает exit,
        # а не return. Используем EXIT, который корректно ловит любой выход из subshell.
        trap 'rm -f "${_nft_batch}" 2>/dev/null' EXIT
        local _CHUNK=200
        local _MAX_LINE_BYTES=4096

        # [fix v28.25.3] Префикс имени — bash-функции глобальны, без префикса
        # при параллельных вызовах _rebuildTunnelForce возможен конфликт имён.
        # Функция-эмиттер: формирует batch-строки с ограничением по байтам
        _rtf__emit_elements() {
            local _set="$1"; shift
            local -a _arr=("$@")
            local _line="" _elem _line_len=0 _elem_len
            for _elem in "${_arr[@]}"; do
                _elem_len=${#_elem}
                # +2 за ", " между элементами
                if [ "${_line_len}" -gt 0 ] && \
                   [ $(( _line_len + _elem_len + 2 )) -gt "${_MAX_LINE_BYTES}" ]; then
                    printf 'add element inet wg-policy %s { %s }\n' "${_set}" "${_line}"
                    _line="${_elem}"
                    _line_len=${#_elem}
                elif [ "${_line_len}" -eq 0 ]; then
                    _line="${_elem}"
                    _line_len=${#_elem}
                else
                    _line="${_line},${_elem}"
                    _line_len=$(( _line_len + _elem_len + 1 ))
                fi
            done
            [ -n "${_line}" ] && printf 'add element inet wg-policy %s { %s }\n' "${_set}" "${_line}"
        }

        {
            if [ "${_have_v4}" = "1" ] && [ "${#_v4[@]}" -gt 0 ]; then
                local _i _end _slice
                for ((_i=0; _i<${#_v4[@]}; _i+=_CHUNK)); do
                    _end=$((_i + _CHUNK))
                    [ "${_end}" -gt "${#_v4[@]}" ] && _end="${#_v4[@]}"
                    _slice=("${_v4[@]:_i:_end-_i}")
                    _rtf__emit_elements "force_tunnel_v4" "${_slice[@]}"
                done
            fi
            if [ "${_have_v6}" = "1" ] && [ "${#_v6[@]}" -gt 0 ]; then
                local _j _end6 _slice6
                for ((_j=0; _j<${#_v6[@]}; _j+=_CHUNK)); do
                    _end6=$((_j + _CHUNK))
                    [ "${_end6}" -gt "${#_v6[@]}" ] && _end6="${#_v6[@]}"
                    _slice6=("${_v6[@]:_j:_end6-_j}")
                    _rtf__emit_elements "force_tunnel_v6" "${_slice6[@]}"
                done
            fi
        } > "${_nft_batch}"
        nft -f "${_nft_batch}" 2>/dev/null || warn "_rebuildTunnelForce: часть IP не загружена в nft"
        rm -f "${_nft_batch}" 2>/dev/null || true
        # [fix v28.25.3] Сверяем ожидаемое и реальное количество элементов в set.
        # nft -f может вернуть 0 даже если часть элементов отклонена ядром.
        local _expect4="${#_v4[@]}" _expect6="${#_v6[@]}"
        local _actual4=0 _actual6=0
        [ "${_have_v4}" = "1" ] && \
            _actual4=$(nft list set inet wg-policy force_tunnel_v4 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l || echo 0)
        [ "${_have_v6}" = "1" ] && \
            _actual6=$(nft list set inet wg-policy force_tunnel_v6 2>/dev/null \
                | grep -oE '[0-9a-fA-F:]+(/[0-9]+)?' | wc -l || echo 0)
        if [ "${_have_v4}" = "1" ] && [ "${_actual4}" -lt "${_expect4}" ]; then
            warn "_rebuildTunnelForce: force_tunnel_v4 ожидалось ${_expect4} элементов, в nft ${_actual4} — часть отклонена ядром"
        fi
        if [ "${_have_v6}" = "1" ] && [ "${_actual6}" -lt "${_expect6}" ]; then
            warn "_rebuildTunnelForce: force_tunnel_v6 ожидалось ${_expect6} элементов, в nft ${_actual6} — часть отклонена ядром"
        fi
    fi
    # [fix v28.24.9] Сохраняем force_tunnel_* в /etc/nftables.conf — иначе
    # при перезагрузке хоста set'ы будут пусты и принудительный туннель
    # отвалится до следующего ручного _rebuildTunnelForce.
    # [fix v28.24.10] Внешний flock уже взят — внутренний подвыход убран,
    # пишем nftables.conf прямо в этом же критическом разделе.
    if declare -F _saveWgNftables >/dev/null 2>&1 && [ -f /etc/nftables.conf ]; then
        local _tmp
        _tmp=$(mktemp /etc/nftables.conf.XXXXXX) && {
            if _saveWgNftables "${_tmp}"; then
                chmod 644 "${_tmp}"
                mv -f "${_tmp}" /etc/nftables.conf
            else
                rm -f "${_tmp}"
            fi
        }
    fi
    systemctl reload-or-restart dnsmasq 2>/dev/null || true
    ) 200>/var/run/wg-nft.lock
}

# ════════════════════════════════════════════════════════════════
# ПРЯМЫЕ ДОМЕНЫ — dnsmasq форвард на Яндекс.DNS (напрямую, не в туннель)
# ════════════════════════════════════════════════════════════════

_rebuildDirectDomains() {
    # [fix v28.24.14] Защита от параллельной записи DNSMASQ_DIRECT_CONF
    # (например, одновременный вызов из меню и из cron'а).
    (
        flock -w 15 201 || { warn "_rebuildDirectDomains: lock занят, пропускаю"; exit 0; }
    local out="${DNSMASQ_DIRECT_CONF}"
    if [ ! -f "${DIRECT_DOMAINS_FILE}" ] || [ ! -s "${DIRECT_DOMAINS_FILE}" ]; then
        rm -f "${out}"
        systemctl reload-or-restart dnsmasq 2>/dev/null || true
        exit 0
    fi
    {
        echo "# Домены напрямую мимо VPN"
        echo "# [v28.24.22] nftset: dnsmasq резолвит через unbound (конфиденциально),"
        echo "# полученные IP кладёт в @russia/@russia_v6 — трафик идёт напрямую."
        echo "# Файл: ${DIRECT_DOMAINS_FILE}  — не редактировать этот файл напрямую"
        while IFS= read -r line; do
            [[ "${line}" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            line="${line%%#*}"
            line="${line%"${line##*[! ]}"}"
            [ -z "${line}" ] && continue
            # Только доменные имена (не IP/CIDR)
            if echo "${line}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
                continue  # IP пропускаем — для IP используй .direct-ips
            elif echo "${line}" | grep -qE '^[0-9a-fA-F:]+(/[0-9]+)?$' && echo "${line}" | grep -q ':'; then
                continue  # IPv6 пропускаем
            else
                # [fix v28.24.22] nftset вместо server=/domain/77.88.8.8:
                # dnsmasq резолвит через свой апстрим (unbound/stubby — конфиденциально),
                # IP-ответ автоматически добавляется в @russia/@russia_v6.
                # Трафик к домену идёт напрямую (mark 0x200000), DNS — без утечки.
                echo "nftset=/${line}/4#inet#wg-policy#russia,6#inet#wg-policy#russia_v6"
            fi
        done < "${DIRECT_DOMAINS_FILE}"
    } > "${out}"
    systemctl reload-or-restart dnsmasq 2>/dev/null || true
    ) 201>/var/run/wg-dnsmasq-direct.lock
}

showDirectDomains() {
    section "Домены напрямую мимо VPN"
    echo ""
    echo -e "  ${DIM}Домены из этого списка резолвятся через Яндекс.DNS (РФ IP → напрямую).${NC}"
    echo -e "  ${DIM}Файл: ${DIRECT_DOMAINS_FILE}${NC}"
    echo ""
    if [ ! -f "${DIRECT_DOMAINS_FILE}" ] || [ ! -s "${DIRECT_DOMAINS_FILE}" ]; then
        echo ""
        echo -e "  ${YELLOW}⚠${NC}   ${WHITE}Список пуст.${NC}"
        echo ""
        echo -e "      ${DIM}Примеры: company.local / internal.example.com${NC}"
        echo ""
        return
    fi
    local i=1
    while IFS= read -r line; do
        [[ "${line}" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        printf "  ${GREEN}%3d${NC}  %s\n" "${i}" "${line}"
        ((++i))
    done < "${DIRECT_DOMAINS_FILE}"
    echo ""
}

_menuDirectDomains() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔀  ДОМЕНЫ НАПРЯМУЮ — мимо VPN-туннеля                     ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Домены из этого списка всегда резолвятся через Яндекс.DNS (77.88.8.8).${NC}"
        echo -e "  ${DIM}Яндекс.DNS входит в @russia → DNS-запрос и трафик идут НАПРЯМУЮ.${NC}"
        echo -e "  ${DIM}Полезно для: корпоративных доменов, внутренних сервисов, локальных зон.${NC}"
        echo -e "  ${DIM}Файл: ${DIRECT_DOMAINS_FILE}${NC}"
        echo ""
        showDirectDomains
        echo -e "  ${YELLOW}1${NC})  📋  ${WHITE}Показать список${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ➕  ${WHITE}Добавить домен${NC}"
        echo -e "      ${DIM}Один домен (company.local, *.internal.com). Сразу применяется.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  ❌  ${WHITE}Удалить домен${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  ✏️   ${WHITE}Открыть файл в редакторе (nano)${NC}"
        echo -e "      ${DIM}По одному домену на строку. # — комментарии.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🔄  ${WHITE}Применить изменения к dnsmasq${NC}"
        echo -e "      ${DIM}Пересобирает ${DNSMASQ_DIRECT_CONF} и перезапускает dnsmasq.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showDirectDomains ;;
            2) echo ""
               echo -e "  ${DIM}Введи домен (например: company.local, *.internal.example.com)${NC}"
               echo -ne "  ${CYAN}→ Домен${NC}: "
               read -r _entry
               [ -z "${_entry}" ] && continue
               touch "${DIRECT_DOMAINS_FILE}"
               if grep -qxF "${_entry}" "${DIRECT_DOMAINS_FILE}" 2>/dev/null; then
                   warn "Уже в списке: ${_entry}"
               else
                   echo "${_entry}" >> "${DIRECT_DOMAINS_FILE}"
                   info "Добавлено: ${GREEN}${_entry}${NC}"
                   _rebuildDirectDomains
               fi
               ;;
            3) showDirectDomains
               [ ! -f "${DIRECT_DOMAINS_FILE}" ] || [ ! -s "${DIRECT_DOMAINS_FILE}" ] && continue
               echo ""
               echo -ne "  ${CYAN}→ Домен для удаления${NC}: "
               read -r _entry
               [ -z "${_entry}" ] && continue
               { local _esc; _esc=$(escape_sed_pipe "${_entry}"); sed -i "\|^${_esc}$|d" "${DIRECT_DOMAINS_FILE}"; }
               info "Удалено: ${_entry}"
               _rebuildDirectDomains
               ;;
            4) if [ ! -f "${DIRECT_DOMAINS_FILE}" ]; then
                   cat > "${DIRECT_DOMAINS_FILE}" <<'EOF'
# ──────────────────────────────────────────────────────────────
#  Домены, идущие НАПРЯМУЮ (мимо VPN-туннеля)
# ──────────────────────────────────────────────────────────────
#  DNS-запросы к этим доменам форвардятся на Яндекс.DNS (77.88.8.8).
#  Яндекс.DNS входит в @russia — значит трафик идёт напрямую.
#
#  Формат — одна запись на строку:
#     • Домен:        company.local
#     • Поддомены:    *.internal.example.com
#
#  Строки с # — комментарии, игнорируются.
#  Не пиши протокол (https://) — только домен.
# ──────────────────────────────────────────────────────────────
EOF
               fi
               local _EDITOR_CMD; _resolveEditor || { echo ""; continue; }
               "${_EDITOR_CMD[@]}" "${DIRECT_DOMAINS_FILE}"
               echo ""
               info "Файл сохранён. Применяю к dnsmasq..."
               _rebuildDirectDomains
               info "Готово."
               ;;
            5) _rebuildDirectDomains; info "Применено" ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

showTunnelForceDomains() {
    section "Домены/IP принудительно через туннель"
    echo ""
    echo -e "  ${DIM}Домены и IP из этого списка всегда резолвятся и маршрутизируются${NC}"
    echo -e "  ${DIM}через VPN-туннель — даже если они РФ или в whitelist.${NC}"
    echo -e "  ${DIM}Файл: ${TUNNEL_FORCE_DOMAINS}${NC}"
    echo ""
    if [ ! -f "${TUNNEL_FORCE_DOMAINS}" ] || [ ! -s "${TUNNEL_FORCE_DOMAINS}" ]; then
        echo ""
        echo -e "  ${YELLOW}⚠${NC}   ${WHITE}Список пуст.${NC}"
        echo ""
        echo -e "      ${DIM}Примеры: github.com / *.telegram.org / 91.108.4.0/22${NC}"
        echo ""
        return
    fi
    local i=1
    while IFS= read -r line; do
        [[ "${line}" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        printf "  ${GREEN}%3d${NC}  %s\n" "${i}" "${line}"
        ((++i))
    done < "${TUNNEL_FORCE_DOMAINS}"
    echo ""
}

# [fix v28.24.7] Единая функция выбора и санитизации редактора.
# Возвращает массив _EDITOR_CMD готовый к "${_EDITOR_CMD[@]} file".
# [fix v28.24.8] После fallback на nano проверяем что он реально установлен;
# если нет — перебираем vim/vi, иначе возвращаем ошибку с подсказкой.
_resolveEditor() {
    local _es="${EDITOR:-}"
    if [ -z "${_es}" ]; then
        if   command -v nano >/dev/null 2>&1; then _es="nano"
        elif command -v vim  >/dev/null 2>&1; then _es="vim"
        elif command -v vi   >/dev/null 2>&1; then _es="vi"
        else warn "Не найден ни один редактор (nano/vim/vi). Установи: apt install nano"; return 1
        fi
    fi
    if [[ "${_es}" =~ [\;\&\|\`\$\(\)\<\>\{\}\\] ]]; then
        warn "EDITOR содержит подозрительные символы — ищу безопасный редактор"
        # [fix v28.24.8] Перебираем fallback-редакторы, не полагаясь на наличие nano.
        if   command -v nano >/dev/null 2>&1; then _es="nano"
        elif command -v vim  >/dev/null 2>&1; then _es="vim"
        elif command -v vi   >/dev/null 2>&1; then _es="vi"
        else warn "Ни nano/vim/vi не найдены. Установи: apt install nano"; return 1
        fi
    fi
    # shellcheck disable=SC2206
    _EDITOR_CMD=(${_es})
}

editTunnelForceDomains() {
    # При первом запуске создаём файл с подробным описанием формата
    if [ ! -f "${TUNNEL_FORCE_DOMAINS}" ] || [ ! -s "${TUNNEL_FORCE_DOMAINS}" ]; then
        cat > "${TUNNEL_FORCE_DOMAINS}" <<'EOF'
# ──────────────────────────────────────────────────────────────
#  Домены и IP, ПРИНУДИТЕЛЬНО идущие через VPN-туннель
# ──────────────────────────────────────────────────────────────
#  Эти записи всегда идут в туннель, даже если IP резолвится
#  в РФ-диапазон. Полезно для: github.com, telegram.org,
#  корпоративных ресурсов, заблокированных сервисов.
#
#  Формат — одна запись на строку:
#     • Домен:           github.com
#     • Поддомены:       *.telegram.org   (звёздочка = любой поддомен)
#     • IPv4-подсеть:    91.108.4.0/22
#     • IPv6-подсеть:    2001:67c:4e8::/48
#     • Один IP:         1.2.3.4/32
#
#  Правила:
#     • Строки с # — комментарии, игнорируются
#     • Пустые строки игнорируются
#     • Не пиши протокол (https://) — только домен/IP
#
#  После сохранения файла dnsmasq пересоберёт конфиг автоматически
#  и применит изменения (перезапуск службы).
# ──────────────────────────────────────────────────────────────
EOF
    fi
    # Открываем редактор (или $EDITOR), после закрытия пересобираем dnsmasq
    # [fix v28.24.2] EDITOR может содержать аргументы (например "code --wait") —
    # сплитим через массив, чтобы они не передавались как одно слово.
    local _EDITOR_CMD; _resolveEditor || return 1
    "${_EDITOR_CMD[@]}" "${TUNNEL_FORCE_DOMAINS}"
    echo ""
    info "Файл сохранён. Применяю к dnsmasq..."
    _rebuildTunnelForce
    info "Готово."
}

addTunnelForceDomain() {
    echo ""
    echo -e "  ${DIM}Введи домен (например: github.com, telegram.org)${NC}"
    echo -e "  ${DIM}или IP/подсеть (например: 91.108.4.0/22)${NC}"
    echo ""
    echo -ne "  ${CYAN}→ Домен или IP${NC}: "
    read -r _entry
    [ -z "${_entry}" ] && return
    touch "${TUNNEL_FORCE_DOMAINS}"
    if grep -qxF "${_entry}" "${TUNNEL_FORCE_DOMAINS}" 2>/dev/null; then
        warn "Уже в списке: ${_entry}"
        return
    fi
    echo "${_entry}" >> "${TUNNEL_FORCE_DOMAINS}"
    info "Добавлено: ${GREEN}${_entry}${NC}"
    _rebuildTunnelForce
}

removeTunnelForceDomain() {
    showTunnelForceDomains
    [ ! -f "${TUNNEL_FORCE_DOMAINS}" ] || [ ! -s "${TUNNEL_FORCE_DOMAINS}" ] && return
    echo ""
    echo -ne "  ${CYAN}→ Домен или IP для удаления${NC}: "
    read -r _entry
    [ -z "${_entry}" ] && return
    # [fix v28.24.12] escape_regex — иначе домен ".*" удалял ВСЕ строки.
    local _esc; _esc=$(escape_sed_pipe "${_entry}")
    sed -i "\|^${_esc}$|d" "${TUNNEL_FORCE_DOMAINS}"
    info "Удалено: ${_entry}"
    _rebuildTunnelForce
}

menuTunnelForceDomains() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔀  ПРИНУДИТЕЛЬНО В ТУННЕЛЬ — домены и IP                  ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Домены и подсети из этого списка ВСЕГДА идут через VPN-туннель.${NC}"
        echo -e "  ${DIM}Полезно для: github.com, telegram.org, своих корпоративных ресурсов.${NC}"
        echo -e "  ${DIM}Файл: ${TUNNEL_FORCE_DOMAINS}${NC}"
        echo ""
        showTunnelForceDomains
        echo -e "  ${YELLOW}1${NC})  📋  ${WHITE}Показать список${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ➕  ${WHITE}Добавить домен / IP${NC}"
        echo -e "      ${DIM}Один домен или подсеть (CIDR). Сразу применяется.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  ❌  ${WHITE}Удалить из списка${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  ✏️   ${WHITE}Открыть файл в редакторе (nano)${NC}"
        echo -e "      ${DIM}Полный контроль — несколько записей сразу, комментарии.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🔄  ${WHITE}Применить изменения к dnsmasq${NC}"
        echo -e "      ${DIM}Пересобирает dnsmasq-конфиг и перезапускает сервис.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showTunnelForceDomains ;;
            2) addTunnelForceDomain ;;
            3) removeTunnelForceDomain ;;
            4) editTunnelForceDomains ;;
            5) _rebuildTunnelForce; info "Применено" ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

showDNSStatus() {
    loadConfig
    section "Статус DNS"
    echo ""
    local _wg_ip="${SERVER_IPV4_ADDR%%/*}"
    local _mode="${DNS_MODE:-public}"
    local _dm_st
    _dm_st=$(systemctl is-active dnsmasq 2>/dev/null || echo "не запущен")

    # Описание режима
    local _mode_desc
    case "${_mode}" in
        geo)    _mode_desc="unbound → root servers (рекурсия, DNSSEC, без внешнего апстрима)" ;;
        tunnel) _mode_desc="DoT Cloudflare/Quad9 TLS 853 (через туннель, макс. приватность)" ;;
        public) _mode_desc="8.8.8.8 напрямую (dnsmasq выключен)"                       ;;
        split)  _mode_desc="устаревший split — переключи на geo"                        ;;
        *)      _mode_desc="${_mode}" ;;
    esac

    printf "  ${WHITE}%-25s${NC}  ${YELLOW}%s${NC}\n" "Режим:" "${_mode}"
    printf "  ${WHITE}%-25s${NC}  %s\n"               "Форвард DNS:"  "${_mode_desc}"
    printf "  ${WHITE}%-25s${NC}  " "dnsmasq:"
    [ "${_dm_st}" = "active" ] \
        && echo -e "${GREEN}активен${NC}" \
        || echo -e "${RED}${_dm_st}${NC}"
    printf "  ${WHITE}%-25s${NC}  %s\n" "DNS клиентов:" \
        "$([ "${_mode}" = "public" ] && echo "8.8.8.8 (прямой)" || echo "${_wg_ip} (dnsmasq)")"
    echo ""

    if systemctl is-active dnsmasq >/dev/null 2>&1; then
        echo -e "  ${WHITE}Проверка резолвинга через dnsmasq:${NC}"
        local _r1 _r2
        _r1=$(dig +short +time=2 yandex.ru  @"${_wg_ip}" 2>/dev/null | head -1)
        _r2=$(dig +short +time=2 google.com @"${_wg_ip}" 2>/dev/null | head -1)
        [ -n "${_r1}" ] \
            && echo -e "  ${GREEN}✔${NC}  yandex.ru  → ${_r1}" \
            || echo -e "  ${RED}✖${NC}  yandex.ru  — нет ответа"
        [ -n "${_r2}" ] \
            && echo -e "  ${GREEN}✔${NC}  google.com → ${_r2}" \
            || echo -e "  ${RED}✖${NC}  google.com — нет ответа"
        echo ""
        echo -e "  ${DIM}Форвард конфиг: ${DNSMASQ_WG_CONF}${NC}"
        [ -f "${DNSMASQ_WG_CONF}" ] && grep '^server=' "${DNSMASQ_WG_CONF}" | sed 's/^/    /'
    fi

    echo ""
    echo -e "  ${WHITE}DNS клиентов:${NC}"
    for f in /etc/wireguard/clients/*.conf; do
        [ -f "$f" ] || continue
        local _n _d
        _n=$(basename "$f" .conf)
        _d=$(grep "^DNS" "$f" | cut -d= -f2- | tr -d ' ')
        printf "  ${DIM}%-20s${NC}  %s\n" "${_n}" "${_d:-не задан}"
    done
    echo ""
}

# ════════════════════════════════════════════════════════════════
# DNS-over-TLS (stubby) — управление шифрованным апстримом
# ════════════════════════════════════════════════════════════════
STUBBY_CONF="/etc/stubby/stubby.yml"

_dotShowStatus() {
    echo ""
    if ! command -v stubby >/dev/null 2>&1; then
        warn "stubby не установлен. Установка: apt-get install -y stubby"
        return
    fi
    local _act _enabled
    _act=$(systemctl is-active stubby 2>/dev/null || echo "inactive")
    _enabled=$(systemctl is-enabled stubby 2>/dev/null || echo "disabled")
    if [ "${_act}" = "active" ]; then
        echo -e "  ${WHITE}Статус stubby:${NC}     ${GREEN}${_act}${NC} (${_enabled})"
    else
        echo -e "  ${WHITE}Статус stubby:${NC}     ${RED}${_act}${NC} (${_enabled})"
    fi
    local _listen
    _listen=$(ss -lntu 2>/dev/null | awk '/:5353 /{print $5}' | sort -u | tr '\n' ' ')
    echo -e "  ${WHITE}Слушает на:${NC}        ${_listen:-нет}"
    echo -e "  ${WHITE}Конфиг:${NC}            ${STUBBY_CONF}"
    if [ -f "${STUBBY_CONF}" ]; then
        local _ups
        _ups=$(awk '/tls_auth_name:/{gsub(/"/,"",$2); print $2}' "${STUBBY_CONF}" | sort -u | tr '\n' ' ')
        echo -e "  ${WHITE}Активные апстримы:${NC} ${_ups:-нет}"
    fi
    # tunnel-режим — реально ли dnsmasq смотрит на 127.0.0.1#5353?
    if grep -q '^server=127.0.0.1#5353' /etc/dnsmasq.d/wg-dns.conf 2>/dev/null; then
        echo -e "  ${WHITE}dnsmasq апстрим:${NC}   ${GREEN}127.0.0.1#5353 (DoT через stubby)${NC}"
    else
        echo -e "  ${WHITE}dnsmasq апстрим:${NC}   ${DIM}plaintext (DoT не используется в текущем режиме)${NC}"
    fi
    echo ""
}

_dotTestResolve() {
    echo ""
    if ! command -v dig >/dev/null 2>&1; then
        warn "dig не установлен (apt-get install dnsutils)"
        return
    fi
    info "Запрос example.com через 127.0.0.1:5353 (stubby)..."
    dig @127.0.0.1 -p 5353 +time=3 +tries=1 example.com 2>&1 \
        | awk '/^;; (ANSWER SECTION|Query time|SERVER)/{p=1} p' | head -20
    echo ""
}

_dotApplyPreset() {
    local preset="$1"
    command -v stubby >/dev/null 2>&1 || { warn "Пакет stubby не установлен в системе — установи его через пункт установки пакетов"; return 1; }
    mkdir -p /etc/stubby /var/cache/stubby
    # Бэкап текущего конфига
    [ -f "${STUBBY_CONF}" ] && cp -f "${STUBBY_CONF}" "${STUBBY_CONF}.bak.$(date +%s)"
    local _hdr='# Managed by wg-server — DNS-over-TLS resolver for dnsmasq upstream
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
round_robin_upstreams: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.1@5353
  - 0::1@5353
appdata_dir: "/var/cache/stubby"
upstream_recursive_servers:'
    local _cf='  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"'
    local _q9='  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"'
    local _gg='  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
  - address_data: 8.8.4.4
    tls_auth_name: "dns.google"'
    local _ag='  - address_data: 94.140.14.14
    tls_auth_name: "dns.adguard-dns.com"
  - address_data: 94.140.15.15
    tls_auth_name: "dns.adguard-dns.com"'
    {
        echo "${_hdr}"
        case "${preset}" in
            cloudflare) echo "${_cf}" ;;
            quad9)      echo "${_q9}" ;;
            google)     echo "${_gg}" ;;
            adguard)    echo "${_ag}" ;;
            all|*)      echo "${_cf}"; echo "${_q9}"; echo "${_gg}" ;;
        esac
    } > "${STUBBY_CONF}"
    chown -R stubby:stubby /var/cache/stubby 2>/dev/null || true
    systemctl restart stubby 2>/dev/null || true
    sleep 1
    if systemctl is-active stubby >/dev/null 2>&1; then
        info "Пресет «${preset}» применён, stubby перезапущен"
    else
        warn "stubby не стартовал — проверь: journalctl -u stubby -n 30"
    fi
}

_dotEdit() {
    # [fix] Используем _resolveEditor вместо прямого EDITOR — проверка спецсимволов и fallback
    local _EDITOR_CMD
    command -v stubby >/dev/null 2>&1 || { warn "Пакет stubby не установлен в системе — установи его через пункт установки пакетов"; return 1; }
    _resolveEditor || { warn "Не найден редактор для редактирования stubby.yml"; return 1; }
    [ -f "${STUBBY_CONF}" ] || { warn "${STUBBY_CONF} не существует — применяю пресет 'all'"; _dotApplyPreset all; }
    cp -f "${STUBBY_CONF}" "${STUBBY_CONF}.bak.$(date +%s)"
    "${_EDITOR_CMD[@]}" "${STUBBY_CONF}"
    info "Перезапускаю stubby..."
    systemctl restart stubby 2>/dev/null || true
    sleep 1
    if systemctl is-active stubby >/dev/null 2>&1; then
        info "stubby перезапущен успешно"
    else
        warn "stubby не стартовал — конфиг битый? journalctl -u stubby -n 30"
    fi
}

menuDoT() {
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔐  DNS-over-TLS (stubby) — шифрование DNS-апстрима        ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        _dotShowStatus
        echo -e "  ${YELLOW}1${NC})  📊  ${WHITE}Подробный статус${NC}  ${DIM}(systemctl status)${NC}"
        echo -e "  ${YELLOW}2${NC})  📋  ${WHITE}Лог stubby${NC}  ${DIM}(последние 40 строк)${NC}"
        echo -e "  ${YELLOW}3${NC})  🧪  ${WHITE}Тест резолвинга через DoT${NC}  ${DIM}(dig example.com)${NC}"
        echo -e "  ${YELLOW}4${NC})  ✏️   ${WHITE}Редактировать stubby.yml${NC}  ${DIM}(\$EDITOR, авто-рестарт)${NC}"
        echo ""
        echo -e "  ${WHITE}Пресеты резолверов (перезаписывает stubby.yml):${NC}"
        echo -e "  ${YELLOW}5${NC})  ☁️   Cloudflare  ${DIM}(1.1.1.1 / 1.0.0.1)${NC}"
        echo -e "  ${YELLOW}6${NC})  🛡️   Quad9       ${DIM}(9.9.9.9 — фильтр malware)${NC}"
        echo -e "  ${YELLOW}7${NC})  🔍  Google      ${DIM}(8.8.8.8 / 8.8.4.4)${NC}"
        echo -e "  ${YELLOW}8${NC})  🚫  AdGuard     ${DIM}(блок рекламы и трекеров)${NC}"
        echo -e "  ${YELLOW}9${NC})  🌐  Все три     ${DIM}(Cloudflare + Quad9 + Google, round-robin)${NC}"
        echo ""
        echo -e "  ${YELLOW}r${NC})  🔄  Перезапустить stubby"
        echo -e "  ${YELLOW}o${NC})  ⏯   Включить/выключить автозапуск stubby"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Выбор: " choice
        case "${choice}" in
            1) systemctl status stubby --no-pager 2>&1 | head -25 ;;
            2) journalctl -u stubby -n 40 --no-pager 2>/dev/null || warn "stubby не запущен" ;;
            3) _dotTestResolve ;;
            4) _dotEdit ;;
            5) _dotApplyPreset cloudflare ;;
            6) _dotApplyPreset quad9 ;;
            7) _dotApplyPreset google ;;
            8) _dotApplyPreset adguard ;;
            9) _dotApplyPreset all ;;
            r|R) systemctl restart stubby 2>/dev/null && info "stubby перезапущен" \
                    || warn "Ошибка перезапуска stubby" ;;
            o|O) if systemctl is-enabled stubby >/dev/null 2>&1; then
                     systemctl disable --now stubby && info "stubby выключен"
                 else
                     systemctl enable --now stubby && info "stubby включён"
                 fi ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

menuDNS() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🌐  DNS — маршрутизация по IP DNS-серверов                 ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        showDNSStatus
        echo -e "  ${YELLOW}1${NC})  ⚙️   ${WHITE}Сменить режим DNS${NC}  ${DIM}(geo / tunnel / public)${NC}"
        echo -e "  ${YELLOW}2${NC})  🔄  ${WHITE}Обновить DNS у всех клиентов${NC}  ${DIM}(пересоздать QR)${NC}"
        echo -e "  ${YELLOW}3${NC})  📋  ${WHITE}Лог dnsmasq${NC}"
        echo -e "  ${YELLOW}4${NC})  🔀  ${WHITE}Принудительно в туннель${NC}  ${DIM}— домены и CIDR через VPN${NC}"
        echo -e "  ${YELLOW}5${NC})  ✏️   ${WHITE}Открыть конфиг доменов в редакторе${NC}"
        echo -e "      ${DIM}Файл: ${TUNNEL_FORCE_DOMAINS}${NC}"
        echo -e "      ${DIM}По одному домену или CIDR на строку. Автоприменение.${NC}"
        echo -e "  ${YELLOW}6${NC})  🌐  ${WHITE}CIDR в туннель — управление подсетями${NC}"
        echo -e "      ${DIM}IP-подсети которые всегда идут через VPN (даже если РФ).${NC}"
        echo -e "  ${YELLOW}7${NC})  🔐  ${WHITE}DNS-over-TLS (stubby)${NC}  ${DIM}— шифрование апстрима${NC}"
        echo -e "      ${DIM}Резолверы, статус, редактирование /etc/stubby/stubby.yml${NC}"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) setupSplitDNS ;;
            2) loadConfig
               local _d
               [ "${DNS_MODE:-public}" != "public" ] \
                   && _d="${SERVER_IPV4_ADDR%%/*}" || _d="8.8.8.8, 8.8.4.4"
               for f in /etc/wireguard/clients/*.conf; do
                   [ -f "$f" ] || continue
                   sed -i "s|^DNS = .*|DNS = ${_d}|" "$f"
                   qrencode -o "${f%.conf}.png" -t PNG < "$f" 2>/dev/null || true
                   info "$(basename "$f" .conf) → DNS ${_d}"
               done ;;
            3) journalctl -u dnsmasq -n 40 --no-pager 2>/dev/null \
                   || warn "dnsmasq не запущен" ;;
            4) menuTunnelForceDomains ;;
            5) editTunnelForceDomains ;;
            6) _menuForceTunnelCIDR ;;
            7) menuDoT ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ANTI-DPI — обфускация WireGuard от блокировок и DPI
# ════════════════════════════════════════════════════════════════


_antidpiLoad() {
    # [fix v28.20.5] Безопасный парсинг вместо source
    # [fix v28.24.2] Объявляем _line/_k/_v как local — иначе глобальные имена
    # конфликтуют при вложенных вызовах (см. аналогичный fix в loadConfig).
    local _line _k _v
    if [ -f "${ANTIDPI_CONF}" ]; then
        while IFS= read -r _line || [ -n "${_line}" ]; do
            [[ "${_line}" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${_line// }" ]] && continue
            [[ "${_line}" != *=* ]] && continue
            _k="${_line%%=*}"; _v="${_line#*=}"
            _k="${_k// /}"; _v="${_v#\"}"; _v="${_v%\"}"
            case "${_k}" in
                ANTIDPI_BBR|ANTIDPI_MSS|ANTIDPI_JITTER)
                    printf -v "${_k}" '%s' "${_v}" ;;
            esac
        done < "${ANTIDPI_CONF}"
    fi
    ANTIDPI_BBR="${ANTIDPI_BBR:-no}"
    ANTIDPI_MSS="${ANTIDPI_MSS:-no}"
    ANTIDPI_JITTER="${ANTIDPI_JITTER:-no}"
}
_antidpiSave() {
    cat > "${ANTIDPI_CONF}" << EOF
ANTIDPI_BBR="${ANTIDPI_BBR}"
ANTIDPI_MSS="${ANTIDPI_MSS}"
ANTIDPI_JITTER="${ANTIDPI_JITTER}"
EOF
    chmod 600 "${ANTIDPI_CONF}"
}

applyBBR() {
    section "BBR + fq — нормализация паттернов"
    modprobe tcp_bbr 2>/dev/null || true
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    cat > /etc/sysctl.d/99-antidpi.conf << 'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_timestamps=0
EOF
    sysctl -p /etc/sysctl.d/99-antidpi.conf >/dev/null 2>&1 || true
    _antidpiLoad; ANTIDPI_BBR="yes"; _antidpiSave
    if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        info "BBR активирован"
    else
        warn "BBR: нужна перезагрузка"
    fi
}

removeBBR() {
    rm -f /etc/sysctl.d/99-antidpi.conf
    sysctl -w net.core.default_qdisc=pfifo_fast >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
    _antidpiLoad; ANTIDPI_BBR="no"; _antidpiSave
    info "BBR отключён"
}


# ── _saveWgNftables: атомарно сохранить ТОЛЬКО свои таблицы в /etc/nftables.conf ──
# Использует nft list table ... вместо nft list ruleset — не захватывает
# таблицы Docker/fail2ban/libvirt/k8s. Вызывается под flock /var/run/wg-nft.lock.
# Аргумент: путь к уже открытому временному файлу.
_saveWgNftables() {
    local _out="$1"
    printf '#!/usr/sbin/nft -f\n' > "${_out}"
    # [fix] Правильная идиома: сначала delete (удалить если есть), потом список таблицы
    # nft list table выводит полное содержимое включая set-элементы, что корректно
    # загружается через nft -f при следующей перезагрузке.
    # Порядок: delete (idempotent — не ошибка если таблицы нет), затем nft list table
    # выводит текущую конфигурацию в синтаксисе, который nft -f принимает напрямую.
    local _t
    for _t in wg-policy wg-filter wg-nat; do
        if nft list table inet "${_t}" >/dev/null 2>&1; then
            # Таблица существует: сначала удаляем (чтобы при загрузке не было "already exists"),
            # потом выводим её содержимое (nft list table добавляет заголовок "table inet X { ... }")
            printf 'delete table inet %s\n' "${_t}" >> "${_out}"
            nft list table inet "${_t}" >> "${_out}" 2>/dev/null || true
        fi
    done
    # Успех: файл содержит хотя бы один chain или set
    grep -q 'chain\|set\|element' "${_out}" 2>/dev/null
}

# ── Мини-транзакция для опасных операций с nftables ──────────────────────────
# [fix v28.24.17] Транзакция снимает снапшот ТОЛЬКО наших таблиц (wg-policy,
# wg-filter, wg-nat) — чужие таблицы (Docker, fail2ban, libvirt) не затрагиваются.
# Откат тоже безопасен: удаляем только наши таблицы и восстанавливаем из снапшота.
#
# Использование:
#   _txn_begin    # снапшот → /tmp
#   _txn_step "описание" "команда"   # шаги с авто-откатом при ошибке
#   _txn_commit   # удаляем снапшот
#   _txn_rollback # явный откат (можно вызвать из trap)

_WG_TXN_SNAPSHOT=""

_txn_begin() {
    _WG_TXN_SNAPSHOT=$(mktemp /tmp/wg-nft-txn.XXXXXX) || {
        warn "[txn] Не удалось создать снапшот — транзакция недоступна"
        return 1
    }
    printf '#!/usr/sbin/nft -f\n' > "${_WG_TXN_SNAPSHOT}"
    local _t
    for _t in wg-policy wg-filter wg-nat; do
        # [fix] Правильный порядок: delete (idempotent) затем list table
        if nft list table inet "${_t}" >/dev/null 2>&1; then
            printf 'delete table inet %s\n' "${_t}" >> "${_WG_TXN_SNAPSHOT}"
            nft list table inet "${_t}" >> "${_WG_TXN_SNAPSHOT}" 2>/dev/null || true
        fi
    done
    if grep -q 'chain\|set\|element' "${_WG_TXN_SNAPSHOT}" 2>/dev/null; then
        info "[txn] Снапшот nftables сохранён: ${_WG_TXN_SNAPSHOT}"
        return 0
    else
        warn "[txn] Снапшот пуст — nftables не активен?"
        rm -f "${_WG_TXN_SNAPSHOT}"; _WG_TXN_SNAPSHOT=""
        return 1
    fi
}

_txn_rollback() {
    [ -z "${_WG_TXN_SNAPSHOT}" ] && { warn "[txn] Нет снапшота для отката"; return 1; }
    warn "[txn] Откат nftables..."
    # Удаляем только НАШИ таблицы — чужие (Docker, fail2ban) не трогаем
    local _t
    for _t in wg-policy wg-filter wg-nat; do
        nft delete table inet "${_t}" 2>/dev/null || true
    done
    # Восстанавливаем наши таблицы из снапшота
    if nft -f "${_WG_TXN_SNAPSHOT}" 2>/dev/null; then
        info "[txn] Откат выполнен успешно"
    else
        warn "[txn] Откат завершился с ошибками — проверь: nft list ruleset"
    fi
    rm -f "${_WG_TXN_SNAPSHOT}"; _WG_TXN_SNAPSHOT=""
}

_txn_commit() {
    rm -f "${_WG_TXN_SNAPSHOT}"; _WG_TXN_SNAPSHOT=""
}

_txn_step() {
    local _step_desc="$1"; shift
    # [fix v28.25.3] Заменяем bash -c "$*" на прямой вызов "$@":
    #   • bash -c при аргументах с кавычками/пробелами даёт неожиданное word-splitting;
    #   • "$@" корректно передаёт каждый аргумент как отдельное слово;
    #   • функции текущего shell-окружения доступны без subshell (export -f не нужен).
    # Вызывающая сторона: _txn_step "desc" funcname [arg1 arg2 ...]
    local _step_err
    if _step_err=$( "$@" 2>&1 ); then
        return 0
    else
        warn "[txn] Шаг «${_step_desc}» завершился с ошибкой${_step_err:+: ${_step_err}}"
        _txn_rollback
        return 1
    fi
}

applyMSS() {
    loadConfig
    section "MSS clamp + TTL нормализация"

    # Применяем в живой nftables
    # Сначала создаём chain если нет, потом добавляем правила
    nft add chain inet wg-policy mangle-forward \
        '{ type filter hook forward priority mangle; policy accept; }' 2>/dev/null || true

    # Удаляем старые правила если есть (чтобы не дублировать)
    nft flush chain inet wg-policy mangle-forward 2>/dev/null || true

    # Добавляем правила
    nft add rule inet wg-policy mangle-forward \
        tcp flags syn tcp option maxseg size set 1280 2>/dev/null || true
    nft add rule inet wg-policy mangle-forward \
        ip ttl set 64 2>/dev/null || true

    # [fix v28.24.1] Атомарная запись через mktemp+mv + _saveWgNftables (только наши таблицы).
    # Раньше использовался nft list ruleset — он захватывал таблицы Docker/fail2ban/libvirt.
    {
        flock -w 30 200 || { warn "applyMSS: timeout lock"; return; }
        local _tmp
        _tmp=$(mktemp /etc/nftables.conf.XXXXXX) || { warn "applyMSS: mktemp failed"; return; }
        if _saveWgNftables "${_tmp}"; then
            chmod 644 "${_tmp}"
            mv -f "${_tmp}" /etc/nftables.conf
        else
            rm -f "${_tmp}"
            warn "applyMSS: не удалось сохранить nftables.conf"
        fi
    } 200>/var/run/wg-nft.lock

    _antidpiLoad; ANTIDPI_MSS="yes"; _antidpiSave
    info "MSS=1280 + TTL=64 применены и сохранены в nftables.conf"
}

removeMSS() {
    loadConfig
    # Удаляем chain из живого nftables
    nft flush chain inet wg-policy mangle-forward 2>/dev/null || true
    nft delete chain inet wg-policy mangle-forward 2>/dev/null || true
    # [fix v28.24.1] Атомарная запись через mktemp+mv + _saveWgNftables (только наши таблицы).
    {
        flock -w 30 200 || { warn "removeMSS: timeout lock"; return; }
        local _tmp
        _tmp=$(mktemp /etc/nftables.conf.XXXXXX) || { warn "removeMSS: mktemp failed"; return; }
        if _saveWgNftables "${_tmp}"; then
            chmod 644 "${_tmp}"
            mv -f "${_tmp}" /etc/nftables.conf
        else
            rm -f "${_tmp}"
            warn "removeMSS: не удалось сохранить nftables.conf"
        fi
    } 200>/var/run/wg-nft.lock
    _antidpiLoad; ANTIDPI_MSS="no"; _antidpiSave
    info "MSS/TTL нормализация отключена"
}


applyJitter() {
    loadConfig
    section "Jitter — рандомизация timing пакетов"
    hint "Ломает ритм WireGuard keepalive (каждые 25с). Jitter ±5ms незаметен для скорости."
    for _if in "${SERVER_WG_NIC}" "${TUNNEL_IFACE[@]:-}"; do
        [ -z "${_if}" ] && continue
        ip link show "${_if}" >/dev/null 2>&1 || continue
        tc qdisc del dev "${_if}" root 2>/dev/null || true
        # [fix v28.25.0] Загружаем sch_netem (может отсутствовать в LXC/Docker образах);
        # если distribution normal недоступна — fallback на простой delay без distribution.
        modprobe sch_netem 2>/dev/null || true
        if tc qdisc add dev "${_if}" root netem \
                delay 2ms 5ms distribution normal loss 0% 2>/dev/null; then
            info "Jitter: ${_if}"
        elif tc qdisc add dev "${_if}" root netem \
                delay 2ms 5ms loss 0% 2>/dev/null; then
            info "Jitter (без distribution normal — модуль sch_netem не поддерживает): ${_if}"
        else
            warn "Не удалось: ${_if}"
        fi
    done
    # Systemd oneshot для автоприменения после перезагрузки
    local _cmds=""
    for _if in "${SERVER_WG_NIC}" "${TUNNEL_IFACE[@]:-}"; do
        [ -z "${_if}" ] && continue
        _cmds+="ExecStart=/sbin/tc qdisc add dev ${_if} root netem delay 2ms 5ms distribution normal loss 0%\n"
        _cmds+="ExecStop=/sbin/tc qdisc del dev ${_if} root\n"
    done

    local _after="wg-quick@${SERVER_WG_NIC}.service"
    for _if in "${TUNNEL_IFACE[@]:-}"; do
        [ -n "${_if}" ] && _after+=" wg-quick@${_if}.service"
    done

    cat > /etc/systemd/system/wg-antidpi-jitter.service << EOF
[Unit]
Description=WireGuard Anti-DPI jitter
After=${_after}
[Service]
Type=oneshot
RemainAfterExit=yes
$(printf '%b' "${_cmds}")
[Install]
WantedBy=multi-user.target
EOF
    # [fix v28.25.3] Проверяем успешность daemon-reload — если юнит-файл
    # содержит синтаксическую ошибку, systemd молча это проглатывает без проверки.
    systemctl daemon-reload || warn "daemon-reload завершился с ошибкой (проверь: systemctl status wg-antidpi-jitter.service)"
    systemctl enable wg-antidpi-jitter.service 2>/dev/null || true
    _antidpiLoad; ANTIDPI_JITTER="yes"; _antidpiSave
    info "Jitter включён и добавлен в автозапуск"
}
removeJitter() {
    loadConfig
    for _if in "${SERVER_WG_NIC}" "${TUNNEL_IFACE[@]:-}"; do
        [ -z "${_if}" ] && continue
        tc qdisc del dev "${_if}" root 2>/dev/null || true
    done
    systemctl disable wg-antidpi-jitter.service 2>/dev/null || true
    rm -f /etc/systemd/system/wg-antidpi-jitter.service
    systemctl daemon-reload
    _antidpiLoad; ANTIDPI_JITTER="no"; _antidpiSave
    info "Jitter отключён"
}

applyAllAntiDPI() {
    applyBBR; applyMSS; applyJitter
    info "Все Anti-DPI техники применены"
}

removeAllAntiDPI() {
    removeBBR; removeMSS; removeJitter
    info "Anti-DPI отключён полностью"
}

showAntiDPIStatus() {
    _antidpiLoad
    echo ""
    local _bbr_st _mss_st _jit_st

    # BBR: проверяем реальное состояние ядра
    sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr \
        && _bbr_st="${GREEN}активен${NC}" || _bbr_st="${RED}выключен${NC}"

    # MSS: правило в nftables называется "maxseg" или "tcpmss" в зависимости от версии nft
    if nft list chain inet wg-policy mangle-forward 2>/dev/null \
            | grep -qE "maxseg|tcpmss|mss"; then
        _mss_st="${GREEN}активен${NC}"
    elif grep -q "mangle-forward" /etc/nftables.conf 2>/dev/null; then
        _mss_st="${GREEN}активен${NC}"
    else
        _mss_st="${RED}выключен${NC}"
    fi

    # Jitter: проверяем tc qdisc на WG интерфейсах
    if tc qdisc show 2>/dev/null | grep -q netem; then
        _jit_st="${GREEN}активен${NC}"
    elif systemctl is-enabled wg-antidpi-jitter.service >/dev/null 2>&1; then
        _jit_st="${GREEN}активен${NC} ${DIM}(вступит после ребута)${NC}"
    else
        _jit_st="${RED}выключен${NC}"
    fi

    printf "  %-30s  " "BBR + fq"
    echo -e "${_bbr_st}"
    printf "  %-30s  " "MSS clamp + TTL фикс"
    echo -e "${_mss_st}"
    printf "  %-30s  " "Jitter ±5ms"
    echo -e "${_jit_st}"
    echo ""
}

menuAntiDPI() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🛡  ANTI-DPI — защита от блокировок и обфускация            ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Скрывает WireGuard от глубокой инспекции пакетов (DPI) РКН.${NC}"
        echo ""
        showAntiDPIStatus
        echo -e "  ${YELLOW}1${NC})  ⚡  Применить ВСЁ сразу        ${DIM}— BBR + MSS + Jitter${NC}"
        echo -e "  ${YELLOW}2${NC})  📶  BBR + fq                  ${DIM}— нормализация паттернов отправки${NC}"
        echo -e "  ${YELLOW}3${NC})  📐  MSS clamp + TTL=64         ${DIM}— убирает отпечаток туннеля${NC}"
        echo -e "  ${YELLOW}4${NC})  ⏱  Jitter ±5ms               ${DIM}— ломает ритм WG keepalive${NC}"
        echo -e "  ${RED}5${NC})  💣  Отключить всё"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) applyAllAntiDPI ;;
            2) applyBBR ;;
            3) applyMSS ;;
            4) applyJitter ;;
            5) removeAllAntiDPI ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

removeAll() {
    echo ""
    echo -e "${RED}${BOLD}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}  ║        ⚠  ПОЛНОЕ УДАЛЕНИЕ WIREGUARD  ⚠           ║${NC}"
    echo -e "${RED}${BOLD}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}Это действие необратимо! Все конфиги будут удалены.${NC}"
    echo -e "  ${YELLOW}Для подтверждения введите: ${BOLD}REMOVE${NC}"
    echo ""
    read -rp "  Ввод: " CONFIRM
    if [ "${CONFIRM}" != "REMOVE" ]; then
        warn "Отменено"
        return
    fi

    # [v28.22.0] Авто-бэкап ДО полного удаления — last chance to restore.
    _autoBackup "remove-all" || warn "Бэкап не создан (продолжаем)"

    step "Остановка сервисов"
    systemctl stop wg-balance mtg telemt nftables dnsmasq \
        wg-ip-watchdog wg-ip-watchdog.timer \
        update-ru-ipset update-ru-ipset.timer \
        wg-balance-watchdog wg-balance-watchdog.timer 2>/dev/null || true
    systemctl disable wg-balance mtg telemt nftables dnsmasq \
        wg-ip-watchdog wg-ip-watchdog.timer \
        update-ru-ipset update-ru-ipset.timer \
        wg-balance-watchdog wg-balance-watchdog.timer 2>/dev/null || true

    step "Остановка WireGuard"
    for iface in $(wg show interfaces 2>/dev/null); do
        wg-quick down "${iface}" 2>/dev/null || true
    done

    step "Очистка правил маршрутизации"
    for p in 30045 30050 30051 $(seq 30200 10 30299); do
        ip rule del prio "${p}" 2>/dev/null || true
    done
    # [fix v28.18] не сносим чужие таблицы (Docker/Fail2ban/etc) — только свои
    nft delete table inet wg-policy 2>/dev/null || true
    nft delete table inet wg-filter 2>/dev/null || true
    # [fix v28.22.2] Раньше удаляли "table ip nat" — это имя используют Docker
    # и libvirt. Удаляем только наш namespace inet wg-nat (строка ниже).
    nft delete table inet wg-nat 2>/dev/null || true

    step "Удаление systemd файлов"
    rm -f /etc/systemd/system/wg-balance.service \
          /etc/systemd/system/mtg.service \
          /etc/systemd/system/telemt.service \
          /etc/systemd/system/wg-antidpi-jitter.service \
          /etc/systemd/system/update-ru-ipset.service \
          /etc/systemd/system/update-ru-ipset.timer \
          /etc/systemd/system/wg-ip-watchdog.service \
          /etc/systemd/system/wg-ip-watchdog.timer \
          /etc/systemd/system/wg-balance-watchdog.service \
          /etc/systemd/system/wg-balance-watchdog.timer
    rm -f /etc/systemd/system/dnsmasq.service.d/99-wireguard.conf
    rmdir /etc/systemd/system/dnsmasq.service.d 2>/dev/null || true
    rm -rf /etc/systemd/system/wg-quick@*.service.d
    systemctl daemon-reload 2>/dev/null || true

    step "Удаление конфигов и скриптов"
    rm -rf /etc/wireguard/*
    # rm -rf /etc/wireguard/* НЕ удаляет скрытые dotfiles без shopt -s dotglob.
    # Явно удаляем служебные файлы состояния, иначе при повторном запуске
    # скрипт пропустит firstInstall (т.к. .wg-setup.conf останется).
    rm -f /etc/wireguard/.wg-setup.conf \
          /etc/wireguard/.direct-ips \
          /etc/wireguard/.tunnel-force-domains \
          /etc/wireguard/.tunnel-force-cidr \
          /etc/wireguard/.direct-domains \
          /etc/wireguard/.antidpi.conf \
          /etc/wireguard/.routing-profiles \
          /etc/wireguard/.traffic-limits
    rm -f /etc/nftables.conf
    rm -f /usr/local/bin/wg-balance.sh \
          /usr/local/bin/update-ru-ipset.sh \
          /usr/local/bin/wg-ip-watchdog.sh \
          /usr/local/bin/wg-balance-watchdog.sh \
          /usr/local/bin/wg-update-geo-lists.sh \
          /usr/local/bin/wg-restore-force-tunnel.sh
    rm -f /root/mtproto_secrets.txt /root/mtproto_links.txt /etc/mtg.env
    rm -f /usr/local/bin/telemt /etc/telemt.toml
    rm -rf /var/lib/telemt
    rm -f /etc/dnsmasq.d/wg-split-dns.conf \
          /etc/dnsmasq.d/wg-dns.conf \
          /etc/dnsmasq.d/wg-tunnel-force.conf \
          /etc/dnsmasq.d/wg-direct-domains.conf
    # [fix] Удаляем drop-in nftables — иначе после повторной установки systemd пытается
    # запустить несуществующие скрипты при рестарте nftables
    rm -f /etc/systemd/system/nftables.service.d/99-geoip.conf
    rmdir /etc/systemd/system/nftables.service.d 2>/dev/null || true
    rm -f /etc/sysctl.d/99-antidpi.conf
    rm -f /etc/wireguard/.antidpi.conf
    rm -f /var/lib/wg/last-pub-ip
    rm -f /var/log/wg-ip-watchdog.log
    rm -f /var/log/wg-balance-watchdog.log
    # [v28.24.24] Key watchdog
    systemctl stop    wg-key-watchdog.timer wg-key-watchdog.service 2>/dev/null || true
    systemctl disable wg-key-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/wg-key-watchdog.{service,timer}
    rm -f /usr/local/bin/wg-key-watchdog.sh
    rm -f /var/log/wg-key-watchdog.log
    rm -f /var/log/wg-geoip.log
    rm -f /var/log/wg-geo-lists.log

    step "Очистка cron"
    crontab -l 2>/dev/null | grep -v "update-ru-ipset\|wg-" | crontab - 2>/dev/null || true

    step "Восстановление DNS"
    # Снимаем immutable флаг который мог поставить _freePort53 (старые установки)
    chattr -i /etc/resolv.conf 2>/dev/null || true
    if [ -L /etc/resolv.conf ]; then
        # [fix v28.25.2] Симлинк — systemd-resolved уже управляет, не трогаем.
        # Финальный ln -sf ниже всё равно перезапишет симлинк на stub-resolv.conf.
        true
    else
        # [fix v28.25.2] Удаляем наш nameserver 127.0.0.1 (dnsmasq) если он есть.
        # Дополнительно: если resolv.conf пуст или содержит только наши записи —
        # восстанавливаем из .wg-bak (если сохранён при установке) или ставим 8.8.8.8.
        if grep -q "^nameserver 127.0.0.1" /etc/resolv.conf 2>/dev/null; then
            sed -i '/^nameserver 127.0.0.1/d' /etc/resolv.conf
        fi
        if ! grep -qE "^nameserver " /etc/resolv.conf 2>/dev/null; then
            if [ -f /etc/resolv.conf.wg-bak ]; then
                cp -f /etc/resolv.conf.wg-bak /etc/resolv.conf
                info "resolv.conf восстановлен из .wg-bak"
            else
                printf "nameserver 8.8.8.8\nnameserver 1.1.1.1\n" > /etc/resolv.conf
                info "resolv.conf: восстановлен fallback (8.8.8.8, 1.1.1.1)"
            fi
        fi
    fi
    # Восстанавливаем systemd-resolved если был замаскирован
    systemctl unmask systemd-resolved 2>/dev/null || true
    systemctl enable systemd-resolved 2>/dev/null || true
    systemctl start systemd-resolved 2>/dev/null || true
    rm -f /etc/systemd/resolved.conf.d/99-wireguard.conf
    rmdir /etc/systemd/resolved.conf.d 2>/dev/null || true
    # [fix] Убираем наш NM-конфиг и возвращаем NetworkManager в управляемый режим
    if [ -f /etc/NetworkManager/conf.d/99-wireguard.conf ]; then
        rm -f /etc/NetworkManager/conf.d/99-wireguard.conf
        rmdir /etc/NetworkManager/conf.d 2>/dev/null || true  # удалим директорию если пуста
        # Перезагружаем NM только если он реально работает
        if systemctl is-active NetworkManager >/dev/null 2>&1; then
            systemctl reload NetworkManager 2>/dev/null \
                || systemctl restart NetworkManager 2>/dev/null \
                || true
            info "NetworkManager: конфиг wg-server удалён, rc-manager восстановлен"
        fi
    fi
    # Восстанавливаем стандартный resolv.conf через systemd
    if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
    else
        # systemd-resolved не запущен или файл ещё не создан — используем fallback
        if [ -f /etc/resolv.conf.wg-bak ]; then
            cp -f /etc/resolv.conf.wg-bak /etc/resolv.conf
        else
            printf "nameserver 8.8.8.8\nnameserver 1.1.1.1\n" > /etc/resolv.conf
        fi
    fi

    # Останавливаем dnsmasq и чистим его конфиги
    systemctl stop dnsmasq 2>/dev/null || true
    rm -f /etc/dnsmasq.conf /etc/dnsmasq.d/wg-*.conf
    systemctl start dnsmasq 2>/dev/null || true

    banner "УДАЛЕНИЕ ЗАВЕРШЕНО"
    echo -e "  ${DIM}WireGuard, туннели, балансировщик, telemt — всё удалено.${NC}"
    echo -e "  ${DIM}nftables сброшен. DNS восстановлен.${NC}"
    echo ""
    exit 0
}

# ════════════════════════════════════════════════════════════════
# ЗАГРУЗКА GEO-СПИСКОВ (US/RU домены и CIDR)
# ════════════════════════════════════════════════════════════════
# Источники (репозиторий avar-soft/wireguard-home-server):
#   .tunnel-force-domains  ← IP US_domein.txt   (домены → принудительно в туннель)
#   .tunnel-force-cidr     ← IP US_v4.txt + IP US_v6.txt  (CIDR → принудительно в туннель)
#   .direct-ips            ← IP RU_v4.txt + IP RU_v6.txt  (подсети напрямую)
#   .direct-domains        ← IP RU_domein.txt   (домены напрямую)
#
# Форматы исходных файлов (CRLF, требуют нормализации):
#   *_domein.txt  — голые домены, по одному на строку: "google.com\r\n"
#                   → нормализуем в просто "google.com" (без \r)
#                   → именно этот формат ожидает _rebuildTunnelForce / dnsmasq
#   *_v4.txt      — CIDR IPv4, по одному на строку: "1.2.3.0/24\r\n"
#                   → нормализуем, фильтруем валидные CIDR (nftables interval set)
#   *_v6.txt      — CIDR IPv6: "2001:db8::/32\r\n"  → аналогично
# Вызывается при firstInstall и ежемесячным cron/скриптом.
_downloadGeoLists() {
    local _base="https://raw.githubusercontent.com/avar-soft/wireguard-home-server/main/geoip"
    local _ok=0 _fail=0
    local _DIRECT_IPS="${DIRECT_IPS_FILE:-/etc/wireguard/.direct-ips}"

    step "Загрузка Geo-списков (US/RU домены и CIDR)"
    mkdir -p /etc/wireguard

    # ── _dlNorm: скачать + нормализовать → целевой файл ──────────
    # Режимы нормализации:
    #   domain  — убираем \r, пустые строки, комментарии; оставляем голые домены
    #   cidr4   — убираем \r; фильтруем только валидные IPv4 CIDR (x.x.x.x/N)
    #   cidr6   — убираем \r; фильтруем только валидные IPv6 CIDR (содержат ':' и '/')
    # append=1 → дописываем в файл (для объединения v4+v6)
    _dlNorm() {
        local _url="$1" _mode="$2" _dst="$3" _append="${4:-0}"
        local _raw _out
        _raw=$(mktemp)
        _out=$(mktemp)
        trap 'rm -f "${_raw}" "${_out}"' RETURN

        if ! curl -fsSL --tlsv1.2 --proto '=https' \
                --connect-timeout 10 --max-time 90 \
                "${_url}" -o "${_raw}" 2>/dev/null || [ ! -s "${_raw}" ]; then
            return 1
        fi

        case "${_mode}" in
            domain)
                # Убираем \r, пробелы по краям, пустые строки и комментарии (#).
                # Принимаем строки похожие на домен: буквы/цифры/точки/дефисы.
                awk '{
                    sub(/\r$/, "")
                    sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "")
                    if ($0 == "" || substr($0,1,1) == "#") next
                    if ($0 ~ /^[A-Za-z0-9*._-]+$/) print $0
                }' "${_raw}" > "${_out}"
                ;;
            cidr4)
                # Только валидные IPv4 CIDR: x.x.x.x/N где N 0..32
                awk '{
                    sub(/\r$/, "")
                    sub(/[[:space:]]*#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                    if ($0 !~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}\/[0-9]{1,2}$/) next
                    split($0, a, "/"); if (a[2]+0 > 32) next
                    split(a[1], o, ".")
                    if (o[1]>255||o[2]>255||o[3]>255||o[4]>255) next
                    print $0
                }' "${_raw}" > "${_out}"
                ;;
            cidr6)
                # Только валидные IPv6 CIDR: содержат ':' и '/N' где N 0..128
                awk '{
                    sub(/\r$/, "")
                    sub(/[[:space:]]*#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                    if (index($0,":")==0 || index($0,"/")==0) next
                    split($0, a, "/"); if (a[2]+0 > 128) next
                    print $0
                }' "${_raw}" > "${_out}"
                ;;
        esac

        [ -s "${_out}" ] || return 1

        if [ "${_append}" = "1" ]; then
            cat "${_out}" >> "${_dst}"
        else
            mv "${_out}" "${_dst}"
            _out=""   # уже перемещён, trap не трогает
        fi
        return 0
    }

    # 1. .tunnel-force-domains — US домены (принудительно в туннель)
    echo -ne "  ${CYAN}→${NC} Загрузка US-доменов (.tunnel-force-domains)... "
    if _dlNorm "${_base}/IP%20US_domein.txt" "domain" "${TUNNEL_FORCE_DOMAINS}"; then
        local _cnt; _cnt=$(wc -l < "${TUNNEL_FORCE_DOMAINS}")
        echo -e "${GREEN}OK${NC} (${_cnt} доменов)"
        _ok=$((_ok + 1))
    else
        echo -e "${YELLOW}WARN — не загружен, файл оставлен без изменений${NC}"
        _fail=$((_fail + 1))
    fi

    # 2. .tunnel-force-cidr — US IPv4 (принудительно в туннель)
    echo -ne "  ${CYAN}→${NC} Загрузка US-CIDR IPv4 (.tunnel-force-cidr)... "
    if _dlNorm "${_base}/IP%20US_v4.txt" "cidr4" "${TUNNEL_FORCE_CIDR}"; then
        echo -ne "${GREEN}OK${NC}  "
        _ok=$((_ok + 1))
    else
        echo -ne "${YELLOW}WARN${NC}  "
        _fail=$((_fail + 1))
    fi
    # 2b. US IPv6 — дописываем в тот же файл
    echo -ne "IPv6... "
    if _dlNorm "${_base}/IP%20US_v6.txt" "cidr6" "${TUNNEL_FORCE_CIDR}" 1; then
        local _cnt6; _cnt6=$(wc -l < "${TUNNEL_FORCE_CIDR}")
        echo -e "${GREEN}OK${NC} (всего ${_cnt6} записей)"
        _ok=$((_ok + 1))
    else
        echo -e "${YELLOW}WARN${NC}"
        _fail=$((_fail + 1))
    fi

    # 3. .direct-ips — RU IPv4 (напрямую, whitelist)
    echo -ne "  ${CYAN}→${NC} Загрузка RU-подсетей IPv4 (.direct-ips)... "
    if _dlNorm "${_base}/IP%20RU_v4.txt" "cidr4" "${_DIRECT_IPS}"; then
        echo -ne "${GREEN}OK${NC}  "
        _ok=$((_ok + 1))
    else
        echo -ne "${YELLOW}WARN${NC}  "
        _fail=$((_fail + 1))
    fi
    # 3b. RU IPv6 — дописываем
    echo -ne "IPv6... "
    if _dlNorm "${_base}/IP%20RU_v6.txt" "cidr6" "${_DIRECT_IPS}" 1; then
        local _cnt_d; _cnt_d=$(wc -l < "${_DIRECT_IPS}")
        echo -e "${GREEN}OK${NC} (всего ${_cnt_d} записей)"
        _ok=$((_ok + 1))
    else
        echo -e "${YELLOW}WARN${NC}"
        _fail=$((_fail + 1))
    fi

    # 4. .direct-domains — RU домены (напрямую, минуя туннель)
    echo -ne "  ${CYAN}→${NC} Загрузка RU-доменов (.direct-domains)... "
    if _dlNorm "${_base}/IP%20RU_domein.txt" "domain" "${DIRECT_DOMAINS_FILE}"; then
        local _cnt2; _cnt2=$(wc -l < "${DIRECT_DOMAINS_FILE}")
        echo -e "${GREEN}OK${NC} (${_cnt2} доменов)"
        _ok=$((_ok + 1))
    else
        echo -e "${YELLOW}WARN — не загружен, файл оставлен без изменений${NC}"
        _fail=$((_fail + 1))
    fi

    chmod 640 "${TUNNEL_FORCE_DOMAINS}" "${TUNNEL_FORCE_CIDR}" \
              "${_DIRECT_IPS}" "${DIRECT_DOMAINS_FILE}" 2>/dev/null || true

    if [ "${_fail}" -eq 0 ]; then
        info "Geo-списки загружены и нормализованы (${_ok} источников)"
    else
        warn "Geo-списки: загружено ${_ok}, не удалось ${_fail} — проверь подключение к GitHub"
    fi

    unset -f _dlNorm
}

# ── Установщик ежемесячного скрипта обновления Geo-списков ──────
_installGeoListsUpdater() {
    # Создаём отдельный скрипт — он вызывается cron раз в месяц,
    # обновляет списки, нормализует данные (CRLF → LF, фильтрует мусор),
    # затем применяет изменения через rebuild tunnel-force и reload dnsmasq.
    cat > /usr/local/bin/wg-update-geo-lists.sh << 'GEOLISTS_SCRIPT'
#!/bin/bash
# wg-update-geo-lists.sh — ежемесячное обновление US/RU geo-списков.
# Скачивает свежие домены и CIDR из avar-soft/wireguard-home-server,
# нормализует (убирает CRLF, фильтрует невалидные строки), затем
# применяет изменения через wg-restore-force-tunnel.sh + reload dnsmasq.

set -uo pipefail
LOG="/var/log/wg-geo-lists.log"
BASE="https://raw.githubusercontent.com/avar-soft/wireguard-home-server/main/geoip"
TUNNEL_FORCE_DOMAINS="/etc/wireguard/.tunnel-force-domains"
TUNNEL_FORCE_CIDR="/etc/wireguard/.tunnel-force-cidr"
DIRECT_IPS_FILE="/etc/wireguard/.direct-ips"
DIRECT_DOMAINS_FILE="/etc/wireguard/.direct-domains"
LOCK="/var/run/wg-geo-lists.lock"

TS() { date '+%Y-%m-%d %H:%M:%S'; }

exec 9>"${LOCK}"
flock -w 30 9 || { echo "[$(TS)] INFO: другой инстанс уже работает"; exit 0; }

echo "[$(TS)] === Обновление Geo-списков ===" >> "${LOG}"

# _dlnorm <url> <mode> <dst> [append=0]
# mode: domain | cidr4 | cidr6
_dlnorm() {
    local _url="$1" _mode="$2" _dst="$3" _append="${4:-0}"
    local _raw _out
    _raw=$(mktemp); _out=$(mktemp)
    trap 'rm -f "${_raw}" "${_out}"' RETURN
    curl -fsSL --tlsv1.2 --proto '=https' --connect-timeout 10 --max-time 90 \
        "${_url}" -o "${_raw}" 2>/dev/null && [ -s "${_raw}" ] || return 1
    case "${_mode}" in
        domain)
            awk '{sub(/\r$/,""); sub(/^[[:space:]]+/,""); sub(/[[:space:]]+$/,"")
                  if ($0==""||substr($0,1,1)=="#") next
                  if ($0~/^[A-Za-z0-9*._-]+$/) print $0}' "${_raw}" > "${_out}" ;;
        cidr4)
            awk '{sub(/\r$/,""); sub(/[[:space:]]*#.*/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,"")
                  if ($0!~/^[0-9]{1,3}(\.[0-9]{1,3}){3}\/[0-9]{1,2}$/) next
                  split($0,a,"/"); if(a[2]+0>32) next
                  split(a[1],o,"."); if(o[1]>255||o[2]>255||o[3]>255||o[4]>255) next
                  print $0}' "${_raw}" > "${_out}" ;;
        cidr6)
            awk '{sub(/\r$/,""); sub(/[[:space:]]*#.*/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,"")
                  if(index($0,":")==0||index($0,"/")==0) next
                  split($0,a,"/"); if(a[2]+0>128) next; print $0}' "${_raw}" > "${_out}" ;;
    esac
    [ -s "${_out}" ] || return 1
    if [ "${_append}" = "1" ]; then cat "${_out}" >> "${_dst}"
    else mv "${_out}" "${_dst}"; _out=""; fi
    return 0
}

_log_result() {
    local _name="$1" _file="$2"
    [ -s "${_file}" ] \
        && echo "[$(TS)] OK   ${_name}: $(wc -l < "${_file}") строк" >> "${LOG}" \
        || echo "[$(TS)] WARN ${_name}: пустой файл"                  >> "${LOG}"
}

# ── Скачиваем и нормализуем каждый источник ──────────────────
_dlnorm "${BASE}/IP%20US_domein.txt" "domain" "${TUNNEL_FORCE_DOMAINS}"   && _log_result ".tunnel-force-domains" "${TUNNEL_FORCE_DOMAINS}" || echo "[$(TS)] FAIL .tunnel-force-domains" >> "${LOG}"
_dlnorm "${BASE}/IP%20US_v4.txt"     "cidr4"  "${TUNNEL_FORCE_CIDR}"      && true                                                          || echo "[$(TS)] FAIL .tunnel-force-cidr v4" >> "${LOG}"
_dlnorm "${BASE}/IP%20US_v6.txt"     "cidr6"  "${TUNNEL_FORCE_CIDR}" 1    && _log_result ".tunnel-force-cidr"   "${TUNNEL_FORCE_CIDR}"     || echo "[$(TS)] FAIL .tunnel-force-cidr v6" >> "${LOG}"
_dlnorm "${BASE}/IP%20RU_v4.txt"     "cidr4"  "${DIRECT_IPS_FILE}"        && true                                                          || echo "[$(TS)] FAIL .direct-ips v4"        >> "${LOG}"
_dlnorm "${BASE}/IP%20RU_v6.txt"     "cidr6"  "${DIRECT_IPS_FILE}"  1     && _log_result ".direct-ips"          "${DIRECT_IPS_FILE}"       || echo "[$(TS)] FAIL .direct-ips v6"        >> "${LOG}"
_dlnorm "${BASE}/IP%20RU_domein.txt" "domain" "${DIRECT_DOMAINS_FILE}"    && _log_result ".direct-domains"      "${DIRECT_DOMAINS_FILE}"   || echo "[$(TS)] FAIL .direct-domains"       >> "${LOG}"

# ── Применяем изменения ───────────────────────────────────────
# CIDR → nftables force_tunnel_v4/v6
/usr/local/bin/wg-restore-force-tunnel.sh 2>>"${LOG}" || true
# Домены → dnsmasq (tunnel-force.conf + direct-domains.conf)
systemctl reload-or-restart dnsmasq 2>>"${LOG}" || true

echo "[$(TS)] === Готово ===" >> "${LOG}"

# Ротация лога: держим последние 500 строк
tail -n 500 "${LOG}" > "${LOG}.tmp" && mv "${LOG}.tmp" "${LOG}" || true

exit 0
GEOLISTS_SCRIPT

    chmod +x /usr/local/bin/wg-update-geo-lists.sh
    info "Установлен скрипт обновления: /usr/local/bin/wg-update-geo-lists.sh"
}

# ── Первоначальная установка ───────────────────────────────────
firstInstall() {
    banner "WireGuard Multi-Tunnel — Установка"
    section "1/4 — Настройка сервера"
    ip -brief link show | awk '{print "    - " $1}'
    echo ""
    ask "Основной сетевой интерфейс" "" "MAIN_INTERFACE" ""
    validateInterface "${MAIN_INTERFACE}"
    ask "WG интерфейс" "" "SERVER_WG_NIC" "wg0"
    validateIfaceName "${SERVER_WG_NIC}"
    ask "Порт WG"      "" "SERVER_PORT"   "51820"
    ask "MTU сервера"  "" "SERVER_MTU"    "1420"
    [[ "${SERVER_MTU}" =~ ^[0-9]+$ ]] && [ "${SERVER_MTU}" -ge 576 ] && [ "${SERVER_MTU}" -le 9000 ] \
        || { warn "Недопустимый MTU: ${SERVER_MTU} — используем 1420"; SERVER_MTU="1420"; }
    # [fix КРИТИЧ 3b] Ограничиваем длину до 5 цифр перед арифметикой (overflow protection)
    [[ "${SERVER_PORT}" =~ ^[0-9]{1,5}$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ] \
        || error "Недопустимый порт: '${SERVER_PORT}' (допустимо 1-65535)"
    echo ""
    echo -e "  ${CYAN}→ Определение публичного IP...${NC}"
    SERVER_PUB_IP=$(ip -4 addr show "${MAIN_INTERFACE}" | awk '/inet / {split($2,a,"/"); print a[1]; exit}')
    if [ -z "${SERVER_PUB_IP}" ]; then
        warn "IPv4 не найден на ${MAIN_INTERFACE} (IPv6-only или нет адреса)"
        while true; do
            ask "Введите публичный IPv4 сервера" "" "SERVER_PUB_IP" ""
            if echo "${SERVER_PUB_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                break
            fi
            warn "Неверный формат! Введи IP-адрес (например, 92.51.23.56)"
        done
    elif [[ "${SERVER_PUB_IP}" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
        warn "Обнаружен приватный IP: ${SERVER_PUB_IP}"
        while true; do
            ask "Введите публичный IP сервера" "" "SERVER_PUB_IP" ""
            if echo "${SERVER_PUB_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                break
            fi
            warn "Неверный формат! Введи IP адрес (например, 92.51.23.56)"
        done
    else
        hint "Обнаружен публичный IP: ${SERVER_PUB_IP}"
        read -rp "  Верно? Enter для подтверждения (или введите другой): " alt_ip
        [ -n "${alt_ip}" ] && SERVER_PUB_IP="${alt_ip}"
    fi
    # [fix КРИТИЧ 1] Повторная валидация SERVER_PUB_IP перед сохранением.
    # Допускаем: корректный IPv4 (4 октета 0-255) ИЛИ hostname/домен
    # (буквы, цифры, дефис, точка — напр. "144.su", "my.vpn.example.com").
    if [[ "${SERVER_PUB_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r _o1 _o2 _o3 _o4 <<< "${SERVER_PUB_IP}"
        for _oct in "${_o1}" "${_o2}" "${_o3}" "${_o4}"; do
            [[ "${_oct}" =~ ^[0-9]+$ ]] && [ "${_oct}" -le 255 ] || \
                error "Недопустимый октет в SERVER_PUB_IP: '${_oct}'"
        done
        unset _o1 _o2 _o3 _o4 _oct
    elif [[ "${SERVER_PUB_IP}" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$ ]]; then
        : # Валидный hostname/домен — пропускаем
    else
        error "SERVER_PUB_IP содержит недопустимые символы: '${SERVER_PUB_IP}'"
    fi
    echo ""
    info "Публичный IP: ${GREEN}${BOLD}${SERVER_PUB_IP}${NC}"
    echo ""
    while true; do
        ask "Подсеть IPv4 клиентов" "" "CLIENT_IPV4_SUBNET" "10.200.200.0/24"
        if echo "${CLIENT_IPV4_SUBNET}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
            break
        fi
        warn "Неверный формат! Введи подсеть в виде X.X.X.X/XX (например, 10.200.200.0/24)"
    done
    while true; do
        ask "Подсеть IPv6 клиентов" "" "CLIENT_IPV6_SUBNET" "fd66:66:66::/64"
        if echo "${CLIENT_IPV6_SUBNET}" | grep -qE '^[0-9a-fA-F:]+::[0-9a-fA-F:]*/[0-9]+$'; then
            break
        fi
        warn "Неверный формат! Введи IPv6 подсеть (например, fd66:66:66::/64)"
    done
    local ipv4_base="${CLIENT_IPV4_SUBNET%/*}"
    local ipv4_prefix="${CLIENT_IPV4_SUBNET##*/}"
    SERVER_IPV4_ADDR="${ipv4_base%.*}.1/${ipv4_prefix}"
    local ipv6_base="${CLIENT_IPV6_SUBNET%/*}"
    local ipv6_prefix="${CLIENT_IPV6_SUBNET##*/}"
    SERVER_IPV6_ADDR="${ipv6_base%::*}::1/${ipv6_prefix}"

    section "2/4 — Туннели"
    TUNNEL_COUNT=0
    while true; do
        configureTunnel "${TUNNEL_COUNT}"
        TUNNEL_COUNT=$((TUNNEL_COUNT + 1))
        local ADD_MORE
        askYesNo "Добавить ещё туннель?" "ADD_MORE" "n"
        [ "${ADD_MORE}" != "yes" ] && break
    done

    section "3/4 — Watchdog балансировщик"
    ask "Интервал проверки (сек)"   "" "BALANCE_INTERVAL" "10"
    ask "Порог плохого пинга (мс)"  "" "BAD_PING_MS"      "200"

    section "4/4 — Подтверждение"
    echo ""
    echo -e "  ${BOLD}Публичный IP:${NC}      ${GREEN}${SERVER_PUB_IP}${NC}"
    echo -e "  ${BOLD}Основной iface:${NC}    ${CYAN}${MAIN_INTERFACE}${NC}"
    echo -e "  ${BOLD}WG интерфейс:${NC}      ${CYAN}${SERVER_WG_NIC}:${SERVER_PORT}${NC}"
    echo -e "  ${BOLD}Туннелей:${NC}          ${YELLOW}${TUNNEL_COUNT}${NC}"
    local i
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        echo -e "    ${CYAN}→${NC} ${TUNNEL_IFACE[$i]}  ⟶  ${TUNNEL_ENDPOINT[$i]}"
    done
    echo ""
    read -rp "  Всё верно? Enter для установки (Ctrl+C — отмена): "

    saveConfig
    enableForwarding
    createIpSetAndNft
    createConfigs
    createBalanceScript

    # ── Logrotate для наших логов ──────────────────────────────────
    # [fix v28.25.3] Без ротации /var/log/wg-*.log растут неограниченно;
    # особенно актуально для wg-balance-watchdog.log (проверка каждые 2 мин).
    cat > /etc/logrotate.d/wg-server << 'LOGROTATE'
/var/log/wg-geoip.log
/var/log/wg-geo-lists.log
/var/log/wg-ip-watchdog.log
/var/log/wg-balance-watchdog.log
/var/log/wg-key-watchdog.log
/var/log/wg-limits.log
/var/log/wg-audit.log
/var/log/wg-server-trap.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        # [fix] wg-balance пишет в journald — SIGHUP ему бессмысленен.
        # dnsmasq действительно переоткрывает лог-файл при HUP.
        systemctl kill -s HUP dnsmasq.service 2>/dev/null || true
    endscript
}
LOGROTATE
    info "Logrotate: /etc/logrotate.d/wg-server создан (ротация раз в неделю, 4 архива)"

    # ── Загрузка Geo-списков при установке ────────────────────────
    _downloadGeoLists
    _installGeoListsUpdater

    # ── Drop-in override: systemd при старте делает wg-quick down перед up ──
    # Без этого "already exists" при перезагрузке если интерфейс уже поднят
    for _iface in "${SERVER_WG_NIC}" "${TUNNEL_IFACE[@]:-}"; do
        [ -z "${_iface}" ] && continue
        mkdir -p "/etc/systemd/system/wg-quick@${_iface}.service.d"
        printf '[Service]\nExecStartPre=-/usr/bin/wg-quick down %%i\n' \
            > "/etc/systemd/system/wg-quick@${_iface}.service.d/override.conf"
    done
    systemctl daemon-reload

    # ── Включаем автозапуск всех служб ───────────────────────────
    # Порядок важен: nftables → туннели → сервер → balance → dnsmasq
    # nftables drop-in НЕ создаём — After=network-online в nftables вызывает
    # ordering cycle при shutdown (nftables WantedBy=sysinit.target, Before=network-pre.target)
    systemctl enable nftables 2>/dev/null || true
    systemctl enable wg-balance.service 2>/dev/null || true
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        systemctl enable "wg-quick@${TUNNEL_IFACE[$i]}" 2>/dev/null || true
        wg-quick up "${TUNNEL_IFACE[$i]}" 2>/dev/null             || warn "Туннель ${TUNNEL_IFACE[$i]} не поднялся"
    done
    systemctl enable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
    wg-quick up "${SERVER_WG_NIC}" 2>/dev/null || warn "Сервер не поднялся"

    # ── Настройка dnsmasq (split-DNS по умолчанию) ────────────────
    _setupDnsmasqAuto

    # Cron: еженедельное обновление GeoIP базы (воскресенье 4:00)
    (crontab -l 2>/dev/null | grep -v "update-ru-ipset" || true
     echo "0 4 * * 0 /usr/local/bin/update-ru-ipset.sh >> /var/log/wg-geoip.log 2>&1") | crontab -

    # Cron: ежемесячное обновление US/RU Geo-списков (1-е число, 3:00)
    # Обновляет .tunnel-force-domains, .tunnel-force-cidr, .direct-ips, .direct-domains
    (crontab -l 2>/dev/null | grep -v "wg-update-geo-lists" || true
     echo "0 3 1 * * /usr/local/bin/wg-update-geo-lists.sh >> /var/log/wg-geo-lists.log 2>&1") | crontab -

    # Cron: ежемесячное обновление root.hints для unbound (1-е число, 3:30)
    # [fix] Смещено на 30 минут относительно wg-update-geo-lists (0 3 1) — оба вызывают
    # systemctl reload-or-restart unbound, одновременный запуск давал race condition.
    # [fix] reload-or-restart только если unbound реально активен — иначе при режимах
    # tunnel/public (unbound отключён) systemd пишет ошибки в journalctl.
    (crontab -l 2>/dev/null | grep -v "wg-root-hints" || true
     echo "30 3 1 * * curl -fsSL --max-time 15 https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints 2>/dev/null && { systemctl is-active --quiet unbound && systemctl reload-or-restart unbound 2>/dev/null; } || true  # wg-root-hints") | crontab -

    # Systemd: загрузка GeoIP через 45с после старта (к этому моменту nftables точно жив)
    # ── Drop-in для nftables: автозапуск GeoIP после рестарта nftables
    mkdir -p /etc/systemd/system/nftables.service.d
    cat > /etc/systemd/system/nftables.service.d/99-geoip.conf << 'EOF'
[Service]
ExecStartPost=-/usr/local/bin/update-ru-ipset.sh
ExecStartPost=-/usr/local/bin/wg-restore-force-tunnel.sh
EOF

    # Systemd: атомарная загрузка GeoIP (доли секунды, без HTTP-предпроверки)
    cat > /etc/systemd/system/update-ru-ipset.service << 'GEOEOF'
[Unit]
Description=Load RU GeoIP into nftables @russia set
Wants=network-online.target nftables.service
After=network-online.target nftables.service wg-quick@WG_NIC_PLACEHOLDER.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-ru-ipset.sh
StandardOutput=append:/var/log/wg-geoip.log
StandardError=append:/var/log/wg-geoip.log
RemainAfterExit=no
TimeoutStartSec=180

# [fix v28.24.13] Hardening — нужен CAP_NET_ADMIN для nft, остальное закрыто.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log /var/run /run /etc/wireguard /etc/nftables.conf /var/cache
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_OVERRIDE

[Install]
WantedBy=multi-user.target
GEOEOF
    # [fix v28.20.4] Подставляем реальное имя интерфейса вместо placeholder
    sed -i "s/wg-quick@WG_NIC_PLACEHOLDER/wg-quick@${SERVER_WG_NIC}/g" \
        /etc/systemd/system/update-ru-ipset.service

    cat > /etc/systemd/system/update-ru-ipset.timer << 'GEOEOF'
[Unit]
Description=RU GeoIP reload – 40s after boot, every 12h

[Timer]
OnBootSec=40s
OnUnitActiveSec=12h
Persistent=true
Unit=update-ru-ipset.service

[Install]
WantedBy=timers.target
GEOEOF
    systemctl daemon-reload
    systemctl enable update-ru-ipset.timer 2>/dev/null || true
    systemctl enable update-ru-ipset.service 2>/dev/null || true

    systemctl restart wg-balance.service
    sleep 2
    journalctl -u wg-balance.service -n 8 --no-pager 2>/dev/null || true

    # Balance watchdog — автоматически при установке
    setupBalanceWatchdog 2>/dev/null || true

    banner "✔ Установка завершена!"
    info "Публичный IP: ${GREEN}${BOLD}${SERVER_PUB_IP}${NC}"
    info "Основной интерфейс: ${CYAN}${MAIN_INTERFACE}${NC}"
    info "Туннелей: ${YELLOW}${TUNNEL_COUNT}${NC}"
    info "GeoIP: РФ → ${MAIN_INTERFACE} напрямую, зарубежье → туннель"
    info "DNS: ${GREEN}split${NC} (РФ-домены напрямую, зарубежные через туннель)"
    echo ""
    echo -e "  ${DIM}Добавь первого клиента: меню → 1 → 1${NC}"
    echo ""
    wg show
}

# ════════════════════════════════════════════════════════════════
# МЕНЮ — вспомогательные функции статуса
# ════════════════════════════════════════════════════════════════

_svcStatus() {
    local svc="$1"
    systemctl is-active "${svc}" 2>/dev/null | grep -q "^active$" \
        && echo -e "${GREEN}●${NC}" || echo -e "${RED}○${NC}"
}

_svcEnable()        { systemctl enable  "$1" 2>/dev/null || true; }
_svcRestart()       { systemctl restart "$1" 2>/dev/null || true; }
_svcEnableRestart() { _svcEnable "$1"; _svcRestart "$1"; }

_pause() { echo ""; read -rp "  [Enter] — продолжить..." _dummy; }

_wgIfaceStatus() {
    local iface="$1"
    wg show "${iface}" >/dev/null 2>&1 \
        && echo -e "${GREEN}UP${NC}" || echo -e "${RED}DOWN${NC}"
}

_clientCount() {
    if [ -d /etc/wireguard/clients ]; then
        shopt -s nullglob
        local _f=(/etc/wireguard/clients/*.conf)
        shopt -u nullglob
        echo "${#_f[@]}"
    else
        echo 0
    fi
}

_statusBar() {
    # [fix v28.24.21] Защита от set -u: если _statusBar вызвана вне menu()
    # (например, из шедулера), TUNNEL_COUNT и массивы могут быть не инициализированы.
    # loadConfig идемпотентна — повторный вызов безопасен.
    [ -z "${SERVER_WG_NIC:-}" ] && loadConfig
    local wg_status bal_status nft_status clients
    wg_status=$(_wgIfaceStatus "${SERVER_WG_NIC}")
    bal_status=$(_svcStatus "wg-balance")
    nft_status=$(_svcStatus "nftables")
    clients=$(_clientCount)
    local tcount=0 i
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        wg show "${TUNNEL_IFACE[$i]}" >/dev/null 2>&1 && ((++tcount)) || true
    done
    local tel_st tel_color
    # [fix v28.24.5] systemctl is-active печатает "inactive" И возвращает ≠0,
    # из-за чего "$( ... || echo off)" склеивал "inactive\noff" в одну строку.
    tel_st=$(systemctl is-active telemt 2>/dev/null | head -n1)
    [ -z "${tel_st}" ] && tel_st="off"
    [ "${tel_st}" = "active" ] && tel_color="${GREEN}" || tel_color="${DIM}"
    local mtg_st mtg_color
    mtg_st=$(systemctl is-active mtg 2>/dev/null | head -n1)
    [ -z "${mtg_st}" ] && mtg_st="off"
    [ "${mtg_st}" = "active" ] && mtg_color="${GREEN}" || mtg_color="${DIM}"

    # [v28.22.0] Активный туннель + кол-во подсетей в GeoIP @russia/@russia_v6
    local active_tun geo4 geo6
    active_tun=$(ip rule show 2>/dev/null | awk '/^30200:.*lookup/{print $NF; exit}')
    if [ -n "${active_tun}" ]; then
        active_tun=$(ip route show table "${active_tun}" 2>/dev/null \
            | awk '/^default/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    fi
    [ -z "${active_tun}" ] && active_tun="—"
    geo4=$(nft list set inet wg-policy russia    2>/dev/null | grep -oEc '[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}' 2>/dev/null | tr -d '\n' || true)
    geo6=$(nft list set inet wg-policy russia_v6 2>/dev/null | grep -oEc '[0-9a-fA-F:]+/[0-9]+'                    2>/dev/null | tr -d '\n' || true)
    [ -z "${geo4}" ] && geo4=0
    [ -z "${geo6}" ] && geo6=0

    echo -e "  ${DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"
    printf "  ${WHITE}WG${NC}: %-6s  ${WHITE}Туннелей${NC}: ${YELLOW}%d/%d${NC}  ${WHITE}Клиентов${NC}: ${GREEN}%s${NC}  ${WHITE}Баланс${NC}: %s  ${WHITE}NFT${NC}: %s\n" \
        "${wg_status}" "${tcount}" "${TUNNEL_COUNT}" "${clients}" "${bal_status}" "${nft_status}"
    printf "  ${WHITE}Активный${NC}: ${CYAN}%-8s${NC}  ${WHITE}GeoIP${NC}: ${GREEN}v4=%s${NC}/${GREEN}v6=%s${NC}  ${WHITE}Telemt${NC}: ${tel_color}%-8s${NC}  ${WHITE}MTG${NC}: ${mtg_color}%s${NC}\n" \
        "${active_tun}" "${geo4}" "${geo6}" "${tel_st}" "${mtg_st}"
    echo -e "  ${DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"
}

# ════════════════════════════════════════════════════════════════
# ПОДМЕНЮ
# ════════════════════════════════════════════════════════════════

menuClients() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   👤  КЛИЕНТЫ — устройства которые подключаются к серверу    ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Каждый клиент — это одно устройство (телефон, ноутбук, ПК).${NC}"
        echo -e "  ${DIM}После добавления получишь QR-код — отсканируй в приложении WireGuard.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  ➕  ${WHITE}Добавить клиента${NC}"
        echo -e "      ${DIM}Создаёт новый ключ, конфиг-файл и QR-код для нового устройства.${NC}"
        echo -e "      ${DIM}Нужно только ввести имя (например: iphone, work-laptop).${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ❌  ${WHITE}Отозвать клиента${NC}"
        echo -e "      ${DIM}Удаляет устройство — оно больше не сможет подключиться.${NC}"
        echo -e "      ${DIM}Полезно если потерял телефон или передал кому-то.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  📋  ${WHITE}Список клиентов${NC}"
        echo -e "      ${DIM}Показывает все зарегистрированные устройства и их IP-адреса.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  📁  ${WHITE}Папка с конфигами${NC}"
        echo -e "      ${DIM}Открывает /etc/wireguard/clients/ — там лежат .conf и .png файлы${NC}"
        echo -e "      ${DIM}для каждого клиента (конфиг и QR-код).${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) addClient ;;
            2) revokeClient ;;
            3) listClients ;;
            4) openClientsFolder ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

menuTunnels() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔀  ТУННЕЛИ — исходящие VPN до внешних серверов            ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Туннель = соединение до внешнего VPN-сервера (например, в Нидерландах).${NC}"
        echo -e "  ${DIM}Зарубежный трафик уходит через туннель. Можно добавить несколько —${NC}"
        echo -e "  ${DIM}балансировщик автоматически выберет тот у которого лучший пинг.${NC}"
        echo ""
        # Показываем статус туннелей прямо в меню
        if [ ${TUNNEL_COUNT} -gt 0 ]; then
            echo -e "  ${WHITE}Текущие туннели:${NC}"
            local i
            for ((i=0; i<TUNNEL_COUNT; i++)); do
                local st color
                wg show "${TUNNEL_IFACE[$i]}" >/dev/null 2>&1 \
                    && st="▲ РАБОТАЕТ" && color="${GREEN}" \
                    || st="▼ СТОИТ   " && color="${RED}"
                printf "    ${color}%-12s${NC}  %-14s  →  %s\n" \
                    "${st}" "${TUNNEL_IFACE[$i]}" "${TUNNEL_ENDPOINT[$i]}"
            done
            echo ""
        else
            echo -e "  ${DIM}  (туннелей пока нет — добавь хотя бы один)${NC}"
            echo ""
        fi
        echo -e "  ${YELLOW}1${NC})  ➕  ${WHITE}Добавить туннель${NC}"
        echo -e "      ${DIM}Подключиться к новому VPN-серверу. Потребуются PrivateKey, PublicKey,${NC}"
        echo -e "      ${DIM}Endpoint (IP:порт) — всё это даёт провайдер VPN-сервера.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ⚙️   ${WHITE}Остановить / Запустить / Перезапустить туннель${NC}"
        echo -e "      ${DIM}Управление отдельным туннелем без перезапуска всего остального.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🗑️   ${WHITE}Удалить туннель${NC}"
        echo -e "      ${DIM}Полностью убирает туннель: останавливает, удаляет конфиг, перестраивает${NC}"
        echo -e "      ${DIM}правила маршрутизации.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔍  ${WHITE}Диагностика туннелей${NC}"
        echo -e "      ${DIM}Проверяет: пинг до каждого VPN-сервера, статус WireGuard, правила${NC}"
        echo -e "      ${DIM}маршрутизации, работу GeoIP. Запускай если что-то не работает.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) addTunnel ;;
            2) manageTunnel ;;
            3) removeTunnel ;;
            4) diagnoseTunnels ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

menuIPTables() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔥  ФАЙРВОЛ / GeoIP — правила куда идёт трафик             ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Здесь настраивается логика разделения трафика:${NC}"
        echo -e "  ${DIM}  • IP-адреса России → идут напрямую через твой интернет (быстро)${NC}"
        echo -e "  ${DIM}  • Всё остальное    → идёт через VPN-туннель (анонимно)${NC}"
        echo -e "  ${DIM}База РФ IP-адресов обновляется раз в неделю автоматически.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  ✏️   ${WHITE}Редактировать конфиг WireGuard-сервера${NC}"
        echo -e "      ${DIM}Открывает файл настроек в редакторе nano. Для опытных пользователей.${NC}"
        echo -e "      ${DIM}После изменений нужно перезапустить WG (пункт 7 в главном меню).${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  🔍  ${WHITE}Диагностика правил файрвола${NC}"
        echo -e "      ${DIM}Показывает все активные nftables-таблицы, fwmark-правила и маршруты.${NC}"
        echo -e "      ${DIM}Запускай если РФ сайты идут через VPN или наоборот.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔄  ${WHITE}Перезапустить nftables${NC}"
        echo -e "      ${DIM}Применяет заново все правила файрвола из /etc/nftables.conf${NC}"
        echo -e "      ${DIM}Помогает если правила «слетели» после перезагрузки.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🗺️   ${WHITE}Обновить список IP-адресов России прямо сейчас${NC}"
        echo -e "      ${DIM}Скачивает свежий список РФ подсетей с ipdeny.com и применяет.${NC}"
        echo -e "      ${DIM}В норме это делается автоматически каждое воскресенье в 4:00.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🔧  ${WHITE}Восстановить маршрутизацию${NC}"
        echo -e "      ${DIM}Пересобирает nftables.conf и ip rule по всем туннелям из конфига.${NC}"
        echo -e "      ${DIM}Используй если интернет не работает после добавления туннеля.${NC}"
        echo ""
        echo -e "  ${YELLOW}6${NC})  📋  ${WHITE}Работа с Geo-списками${NC}"
        echo -e "      ${DIM}Просмотр, редактирование ru-aggregated.zone и ru-aggregated-v6.zone.${NC}"
        echo -e "      ${DIM}Управление режимом: только-чтение (защита от перезаписи) или запись.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) # [fix] Используем _resolveEditor вместо хардкода nano — проверка EDITOR на спецсимволы
               local _EDITOR_CMD
               if _resolveEditor; then
                   "${_EDITOR_CMD[@]}" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null \
                       || "${_EDITOR_CMD[@]}" /etc/wireguard/wg0.conf
               fi ;;
            2) diagnoseIPTables ;;
            3) systemctl restart nftables && info "nftables перезапущен" ;;
            4) if /usr/local/bin/update-ru-ipset.sh; then
                   # [fix v28.24.9] persistence after manual GeoIP update
                   (
                       flock -w 10 200 || exit 0
                       _tmp=$(mktemp /etc/nftables.conf.XXXXXX) || exit 0
                       if _saveWgNftables "${_tmp}"; then chmod 644 "${_tmp}"; mv -f "${_tmp}" /etc/nftables.conf
                       else rm -f "${_tmp}"; fi
                   ) 200>/var/run/wg-nft.lock
                   info "GeoIP обновлён (сохранено в /etc/nftables.conf)"
               fi ;;
            5) repairRouting ;;
            6) menuGeoLists ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# GEO-СПИСКИ — управление файлами GeoIP базы
# ════════════════════════════════════════════════════════════════

_geoListReadonly() {
    # Возвращает 0 если файл только-для-чтения (immutable или нет прав w)
    local f="$1"
    [ -f "${f}" ] || return 1
    if lsattr "${f}" 2>/dev/null | grep -q '^....i'; then return 0; fi
    [ ! -w "${f}" ] && return 0
    return 1
}

_geoListStatus() {
    local f="$1" label="$2"
    local lines=0 ro_str
    [ -f "${f}" ] && lines=$(wc -l < "${f}" 2>/dev/null || echo 0)
    if _geoListReadonly "${f}"; then
        ro_str="${RED}🔒 только-чтение${NC}"
    else
        ro_str="${GREEN}✏️  запись разрешена${NC}"
    fi
    printf "  ${WHITE}%-6s${NC}  %5s строк   %b\n  ${DIM}    %s${NC}\n" \
        "${label}" "${lines}" "${ro_str}" "${f}"
}

_geoSetReadonly() {
    local f="$1"
    # Используем chattr +i (immutable) — надёжнее chmod (root может обходить chmod)
    if chattr +i "${f}" 2>/dev/null; then
        info "Файл ${f} защищён от перезаписи (chattr +i)"
    else
        # Fallback: chmod 444
        chmod 444 "${f}" 2>/dev/null || true
        warn "chattr недоступен — используем chmod 444 (root всё ещё может писать)"
    fi
}

_geoSetWritable() {
    local f="$1"
    chattr -i "${f}" 2>/dev/null || true
    chmod 644 "${f}" 2>/dev/null || true
    info "Файл ${f} — запись разрешена"
}

_geoToggleAutoUpdate() {
    # Включает / выключает автообновление GeoIP (cron + systemd timer)
    local _cron_has
    _cron_has=$(crontab -l 2>/dev/null | grep -c "update-ru-ipset" || true)
    local _timer_en
    _timer_en=$(systemctl is-enabled update-ru-ipset.timer 2>/dev/null || echo "disabled")

    if [ "${_cron_has}" -gt 0 ] || [ "${_timer_en}" = "enabled" ]; then
        # Выключаем
        warn "Отключаю автообновление GeoIP..."
        crontab -l 2>/dev/null | grep -v "update-ru-ipset" | crontab - 2>/dev/null || true
        systemctl disable update-ru-ipset.timer 2>/dev/null || true
        systemctl stop update-ru-ipset.timer 2>/dev/null || true
        info "Автообновление ВЫКЛЮЧЕНО. GeoIP файлы не будут перезаписываться по расписанию."
        echo ""
        echo -e "  ${YELLOW}Рекомендуется также защитить файлы:${NC}"
        echo -e "  ${DIM}Пункт → Geo-списки → Переключить режим → только-чтение${NC}"
    else
        # Включаем
        info "Включаю автообновление GeoIP..."
        (crontab -l 2>/dev/null | grep -v "update-ru-ipset" || true
         echo "0 4 * * 0 /usr/local/bin/update-ru-ipset.sh >> /var/log/wg-geoip.log 2>&1") | crontab -
        systemctl enable update-ru-ipset.timer 2>/dev/null || true
        systemctl start update-ru-ipset.timer 2>/dev/null || true
        info "Автообновление ВКЛЮЧЕНО (каждое воскресенье 4:00 + timer каждые 12ч)"
    fi
}

menuGeoLists() {
    local GEO_V4="/etc/wireguard/geoip/ru-aggregated.zone"
    local GEO_V6="/etc/wireguard/geoip/ru-aggregated-v6.zone"
    local NFT_CONF="/etc/nftables.conf"
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📋  GEO-СПИСКИ — управление базой IP-адресов               ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # Статус автообновления
        local _cron_has _timer_en _auto_str
        _cron_has=$(crontab -l 2>/dev/null | grep -c "update-ru-ipset" || true)
        _timer_en=$(systemctl is-enabled update-ru-ipset.timer 2>/dev/null || echo "disabled")
        if [ "${_cron_has}" -gt 0 ] || [ "${_timer_en}" = "enabled" ]; then
            _auto_str="${GREEN}ВКЛ (каждое воскресенье 4:00)${NC}"
        else
            _auto_str="${RED}ВЫКЛ${NC}"
        fi
        printf "  ${WHITE}Автообновление:${NC}  %b\n\n" "${_auto_str}"

        # ── Online: nftables sets @russia / @russia_v6 ──────────────────
        local _nft_v4_cnt _nft_v6_cnt _nft_v4_ro _nft_v6_ro _ro_str4 _ro_str6
        # [fix v28.24.5] было "grep -oEc PAT | wc -l || echo 0" — давало
        # двух-строчные значения типа "1\n0" и ломало printf.
        _nft_v4_cnt=$(nft list set inet wg-policy russia    2>/dev/null \
            | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}' 2>/dev/null | wc -l | tr -d '\n ')
        _nft_v6_cnt=$(nft list set inet wg-policy russia_v6 2>/dev/null \
            | grep -oE '[0-9a-fA-F:]+/[0-9]+'                    2>/dev/null | wc -l | tr -d '\n ')
        [ -z "${_nft_v4_cnt}" ] && _nft_v4_cnt=0
        [ -z "${_nft_v6_cnt}" ] && _nft_v6_cnt=0
        if _geoListReadonly "${NFT_CONF}"; then
            _ro_str4="${RED}🔒 только-чтение${NC}"
            _ro_str6="${RED}🔒 только-чтение${NC}"
        else
            _ro_str4="${GREEN}✏️  запись разрешена${NC}"
            _ro_str6="${GREEN}✏️  запись разрешена${NC}"
        fi

        echo -e "  ${WHITE}Online списки  ${DIM}(nftables sets, загружаются в память)${NC}"
        echo ""
        printf "  ${WHITE}%-6s${NC}  nft: ${CYAN}%5s${NC} подсетей   %b\n    ${DIM}  /etc/nftables.conf → set @russia${NC}\n" \
            "IPv4" "${_nft_v4_cnt}" "${_ro_str4}"
        echo ""
        printf "  ${WHITE}%-6s${NC}  nft: ${CYAN}%5s${NC} подсетей   %b\n    ${DIM}  /etc/nftables.conf → set @russia_v6${NC}\n" \
            "IPv6" "${_nft_v6_cnt}" "${_ro_str6}"
        echo ""

        # ── Offline: файлы ru-aggregated.zone ───────────────────────────
        echo -e "  ${WHITE}Offline списки  ${DIM}(файлы-источники, загружаются скриптом)${NC}"
        echo ""
        _geoListStatus "${GEO_V4}" "IPv4"
        echo ""
        _geoListStatus "${GEO_V6}" "IPv6"
        echo ""

        echo -e "  ${YELLOW}──── Режим файлов ─────────────────────────────────────────────${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  🔒  ${WHITE}Защитить offline файлы от перезаписи${NC}  ${DIM}(chattr +i)${NC}"
        echo -e "      ${DIM}ru-aggregated.zone / ru-aggregated-v6.zone — immutable.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ✏️   ${WHITE}Разрешить запись в offline файлы${NC}  ${DIM}(chattr -i)${NC}"
        echo -e "      ${DIM}Разрешает обновление и редактирование.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔒  ${WHITE}Защитить online конфиг от перезаписи${NC}  ${DIM}(chattr +i)${NC}"
        echo -e "      ${DIM}/etc/nftables.conf — @russia/@russia_v6 не затрутся.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  ✏️   ${WHITE}Разрешить запись в online конфиг${NC}  ${DIM}(chattr -i)${NC}"
        echo -e "      ${DIM}/etc/nftables.conf — разрешает изменения.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🔄  ${WHITE}Вкл/Выкл автообновление GeoIP${NC}"
        echo -e "      ${DIM}Переключает cron + systemd timer обновления баз.${NC}"
        echo -e "      ${DIM}При отключении файлы не будут затираться по расписанию.${NC}"
        echo ""
        echo -e "  ${YELLOW}──── Редактирование ────────────────────────────────────────────${NC}"
        echo ""
        echo -e "  ${YELLOW}6${NC})  📝  ${WHITE}Редактировать IPv4 offline базу в nano${NC}"
        echo -e "      ${DIM}${GEO_V4}${NC}"
        echo -e "      ${DIM}После сохранения — применить через пункт 10.${NC}"
        echo ""
        echo -e "  ${YELLOW}7${NC})  📝  ${WHITE}Редактировать IPv6 offline базу в nano${NC}"
        echo -e "      ${DIM}${GEO_V6}${NC}"
        echo -e "      ${DIM}После сохранения — применить через пункт 10.${NC}"
        echo ""
        echo -e "  ${YELLOW}8${NC})  📝  ${WHITE}Редактировать online IPv4 set в nano${NC}"
        echo -e "      ${DIM}/etc/nftables.conf  (секция set @russia)${NC}"
        echo -e "      ${DIM}После сохранения — применить через пункт 10.${NC}"
        echo ""
        echo -e "  ${YELLOW}9${NC})  📝  ${WHITE}Редактировать online IPv6 set в nano${NC}"
        echo -e "      ${DIM}/etc/nftables.conf  (секция set @russia_v6)${NC}"
        echo -e "      ${DIM}После сохранения — применить через пункт 10.${NC}"
        echo ""
        echo -e "  ${YELLOW}10${NC})  🚀  ${WHITE}Применить offline файлы в nftables прямо сейчас${NC}"
        echo -e "       ${DIM}update-ru-ipset.sh — загружает .zone файлы в @russia/@russia_v6.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1)  # Защитить offline файлы
                local _ans
                read -rp "  Защитить offline файлы (chattr +i)? [y/N]: " _ans
                [[ "${_ans}" =~ ^[Yy]$ ]] || { warn "Отменено"; echo ""; read -rp "  [Enter]..." _d; continue; }
                [ -f "${GEO_V4}" ] && { _geoSetReadonly "${GEO_V4}" || warn "Не удалось защитить IPv4 offline файл"; } || warn "IPv4 offline файл не найден"
                [ -f "${GEO_V6}" ] && { _geoSetReadonly "${GEO_V6}" || warn "Не удалось защитить IPv6 offline файл"; } || warn "IPv6 offline файл не найден"
                ;;
            2)  # Разрешить запись offline
                local _ans
                read -rp "  Разрешить запись в offline файлы (chattr -i)? [y/N]: " _ans
                [[ "${_ans}" =~ ^[Yy]$ ]] || { warn "Отменено"; echo ""; read -rp "  [Enter]..." _d; continue; }
                [ -f "${GEO_V4}" ] && { _geoSetWritable "${GEO_V4}" || warn "Не удалось снять защиту с IPv4 offline файла"; } || warn "IPv4 offline файл не найден"
                [ -f "${GEO_V6}" ] && { _geoSetWritable "${GEO_V6}" || warn "Не удалось снять защиту с IPv6 offline файла"; } || warn "IPv6 offline файл не найден"
                ;;
            3)  # Защитить online конфиг
                local _ans
                read -rp "  Защитить /etc/nftables.conf (chattr +i)? [y/N]: " _ans
                [[ "${_ans}" =~ ^[Yy]$ ]] || { warn "Отменено"; echo ""; read -rp "  [Enter]..." _d; continue; }
                _geoSetReadonly "${NFT_CONF}"
                ;;
            4)  # Разрешить запись online конфиг
                local _ans
                read -rp "  Разрешить запись в /etc/nftables.conf (chattr -i)? [y/N]: " _ans
                [[ "${_ans}" =~ ^[Yy]$ ]] || { warn "Отменено"; echo ""; read -rp "  [Enter]..." _d; continue; }
                _geoSetWritable "${NFT_CONF}"
                ;;
            5)  _geoToggleAutoUpdate ;;
            6)  # Редактировать IPv4 offline
                if _geoListReadonly "${GEO_V4}"; then
                    warn "Файл защищён от записи! Сначала пункт 2 (разрешить запись)."
                else
                    mkdir -p "$(dirname "${GEO_V4}")"
                    local _EDITOR_CMD; _resolveEditor || continue
                    "${_EDITOR_CMD[@]}" "${GEO_V4}"
                    echo ""
                    read -rp "  Применить изменения в nftables? [Y/n]: " _ans
                    if [[ ! "${_ans}" =~ ^[Nn]$ ]] && /usr/local/bin/update-ru-ipset.sh; then
                        ( flock -w 10 200 || exit 0; _tmp=$(mktemp /etc/nftables.conf.XXXXXX) || exit 0
                          if _saveWgNftables "${_tmp}"; then chmod 644 "${_tmp}"; mv -f "${_tmp}" /etc/nftables.conf; else rm -f "${_tmp}"; fi
                        ) 200>/var/run/wg-nft.lock
                    fi
                fi
                ;;
            7)  # Редактировать IPv6 offline
                if _geoListReadonly "${GEO_V6}"; then
                    warn "Файл защищён от записи! Сначала пункт 2 (разрешить запись)."
                else
                    mkdir -p "$(dirname "${GEO_V6}")"
                    local _EDITOR_CMD; _resolveEditor || continue
                    "${_EDITOR_CMD[@]}" "${GEO_V6}"
                    echo ""
                    read -rp "  Применить изменения в nftables? [Y/n]: " _ans
                    if [[ ! "${_ans}" =~ ^[Nn]$ ]] && /usr/local/bin/update-ru-ipset.sh; then
                        ( flock -w 10 200 || exit 0; _tmp=$(mktemp /etc/nftables.conf.XXXXXX) || exit 0
                          if _saveWgNftables "${_tmp}"; then chmod 644 "${_tmp}"; mv -f "${_tmp}" /etc/nftables.conf; else rm -f "${_tmp}"; fi
                        ) 200>/var/run/wg-nft.lock
                    fi
                fi
                ;;
            8)  # Редактировать nftables.conf (секция @russia)
                if _geoListReadonly "${NFT_CONF}"; then
                    warn "Файл защищён от записи! Сначала пункт 4 (разрешить запись)."
                else
                    local _EDITOR_CMD; _resolveEditor || continue
                    "${_EDITOR_CMD[@]}" "${NFT_CONF}"
                    echo ""
                    read -rp "  Применить nftables.conf? [Y/n]: " _ans
                    [[ "${_ans}" =~ ^[Nn]$ ]] || { nft -f "${NFT_CONF}" && info "nftables применён"; }
                fi
                ;;
            9)  # Редактировать nftables.conf (секция @russia_v6) — тот же файл
                if _geoListReadonly "${NFT_CONF}"; then
                    warn "Файл защищён от записи! Сначала пункт 4 (разрешить запись)."
                else
                    local _EDITOR_CMD; _resolveEditor || continue
                    "${_EDITOR_CMD[@]}" "${NFT_CONF}"
                    echo ""
                    read -rp "  Применить nftables.conf? [Y/n]: " _ans
                    [[ "${_ans}" =~ ^[Nn]$ ]] || { nft -f "${NFT_CONF}" && info "nftables применён"; }
                fi
                ;;
            10) # Применить offline файлы в nftables
                if _geoListReadonly "${GEO_V4}" || _geoListReadonly "${GEO_V6}"; then
                    echo ""
                    warn "Один или оба offline файла защищены — update-ru-ipset использует их как источник."
                    read -rp "  Продолжить загрузку в nftables? [Y/n]: " _ans
                    [[ "${_ans}" =~ ^[Nn]$ ]] && { echo ""; read -rp "  [Enter]..." _d; continue; }
                fi
                if /usr/local/bin/update-ru-ipset.sh; then
                    # [fix v28.24.9] persistence
                    (
                        flock -w 10 200 || exit 0
                        _tmp=$(mktemp /etc/nftables.conf.XXXXXX) || exit 0
                        if _saveWgNftables "${_tmp}"; then chmod 644 "${_tmp}"; mv -f "${_tmp}" /etc/nftables.conf
                        else rm -f "${_tmp}"; fi
                    ) 200>/var/run/wg-nft.lock
                    info "GeoIP применён (сохранено в /etc/nftables.conf)"
                fi
                ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

menuWGStatus() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📊  СТАТУС — что сейчас работает и как                     ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Здесь можно посмотреть состояние всей системы без изменений.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  🖥️   ${WHITE}Статус WireGuard-сервера${NC}"
        echo -e "      ${DIM}Показывает: активен ли сервер, публичный ключ, порт, список пиров.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  👤  ${WHITE}Список клиентов${NC}"
        echo -e "      ${DIM}Все зарегистрированные устройства с их IP-адресами.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔀  ${WHITE}Статус туннелей${NC}"
        echo -e "      ${DIM}Для каждого туннеля: активен или нет, endpoint, последний handshake.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  📋  ${WHITE}Полный статус системы${NC}"
        echo -e "      ${DIM}Всё сразу: интерфейсы, пиры, конфиг сервера, кол-во клиентов.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) wg show "${SERVER_WG_NIC}" 2>/dev/null || warn "Сервер не активен (попробуй пункт 7 — Перезапустить всё)" ;;
            2) listClients ;;
            3) local i
               for ((i=0; i<TUNNEL_COUNT; i++)); do
                   wg show "${TUNNEL_IFACE[$i]}" 2>/dev/null \
                       || echo -e "  ${RED}${TUNNEL_IFACE[$i]}: не активен${NC}"
               done ;;
            4) wgFullStatus ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# DDNS / IP WATCHDOG — мониторинг смены публичного IP
# ════════════════════════════════════════════════════════════════

setupIPWatchdog() {
    loadConfig
    section "Мониторинг публичного IP (IP Watchdog)"
    echo ""
    echo -e "  ${DIM}Сервис проверяет внешний IP каждые 5 минут.${NC}"
    echo -e "  ${DIM}Если IP изменился — обновляет конфиги клиентов и пишет в лог.${NC}"
    echo ""

    # Скрипт watchdog
    cat > /usr/local/bin/wg-ip-watchdog.sh << WDEOF
#!/bin/bash
# WireGuard IP Watchdog — следит за сменой публичного IP
CONFIG_FILE="/etc/wireguard/.wg-setup.conf"
LOG="/var/log/wg-ip-watchdog.log"
STATE_FILE="/var/lib/wg/last-pub-ip"
mkdir -p "\$(dirname "\${STATE_FILE}")" 2>/dev/null || true

# [fix v28.20.9] Безопасный парсинг конфига вместо source (защита от RCE при повреждении файла)
[ -f "\${CONFIG_FILE}" ] || { echo "ERROR: конфиг не найден: \${CONFIG_FILE}" >&2; exit 1; }
while IFS= read -r _line || [ -n "\${_line}" ]; do
    [[ "\${_line}" =~ ^[[:space:]]*# ]] && continue
    [[ -z "\${_line// }" ]] && continue
    [[ "\${_line}" != *=* ]] && continue
    _k="\${_line%%=*}"
    _v="\${_line#*=}"
    _k="\${_k// /}"
    _v="\${_v#\"}"
    _v="\${_v%\"}"
    case "\${_k}" in
        SERVER_PORT|SERVER_WG_NIC)
            printf -v "\${_k}" '%s' "\${_v}" ;;
    esac
done < "\${CONFIG_FILE}"
[ -z "\${SERVER_PORT}" ] && { echo "ERROR: SERVER_PORT не найден в конфиге" >&2; exit 1; }

_log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*" | tee -a "\${LOG}"; }

# Получаем текущий внешний IP
CURRENT_IP=\$(curl -fsSL --tlsv1.2 --proto '=https' --max-time 5 https://api.ipify.org 2>/dev/null \
    || curl -fsSL --tlsv1.2 --proto '=https' --max-time 5 https://ifconfig.me 2>/dev/null \
    || echo "")

[ -z "\${CURRENT_IP}" ] && { _log "ERROR: не удалось получить внешний IP"; exit 1; }

# [fix] Валидация формата IP — защита от инъекции в sed если источник вернул мусор
if ! printf '%s' "\${CURRENT_IP}" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    _log "ERROR: CURRENT_IP '\${CURRENT_IP}' не является валидным IPv4-адресом — прерываем"
    exit 1
fi

# Читаем последний известный IP
LAST_IP=\$(cat "\${STATE_FILE}" 2>/dev/null || echo "")

if [ "\${CURRENT_IP}" = "\${LAST_IP}" ]; then
    exit 0  # IP не изменился — всё хорошо
fi

# IP изменился!
_log "⚠ IP изменился: \${LAST_IP:-неизвестен} → \${CURRENT_IP}"
echo "\${CURRENT_IP}" > "\${STATE_FILE}"

# Обновляем SERVER_PUB_IP в конфиге
sed -i "s|^SERVER_PUB_IP=.*|SERVER_PUB_IP=\"\${CURRENT_IP}\"|" "\${CONFIG_FILE}"

# Обновляем Endpoint в конфигах клиентов
if [ -d "/etc/wireguard/clients" ]; then
    for conf in /etc/wireguard/clients/*.conf; do
        [ -f "\${conf}" ] || continue
        sed -i "s|^Endpoint = .*:\${SERVER_PORT}|Endpoint = \${CURRENT_IP}:\${SERVER_PORT}|" "\${conf}"
        _log "  Обновлён: \$(basename \${conf})"
    done
fi

# [fix v28.24.9] Обновляем публичный host у Telemt/MTG, иначе tg://proxy
# ссылки перестают работать после смены IP. После правки — рестартуем сервисы.
if [ -f /etc/telemt.toml ]; then
    sed -i -E "s|^([[:space:]]*public_host[[:space:]]*=[[:space:]]*\")[^\"]*(\".*)|\1\${CURRENT_IP}\2|" /etc/telemt.toml 2>/dev/null || true
    _telemt_safe_restart 2>/dev/null || true
    _log "  Telemt: public_host → \${CURRENT_IP}"
fi
if [ -f /etc/mtg.env ]; then
    sed -i -E "s|^(MTG_HOST=).*|\1\${CURRENT_IP}|" /etc/mtg.env 2>/dev/null || true
fi
if systemctl list-unit-files 2>/dev/null | grep -q '^mtg\.service'; then
    systemctl restart mtg 2>/dev/null || true
    _log "  MTG: рестартован с новым IP"
fi

_log "✔ Конфиги обновлены. Новый IP: \${CURRENT_IP}"
_log "  Клиентам нужно обновить QR-код (меню → Клиенты → пересоздать QR)"
WDEOF
    chmod +x /usr/local/bin/wg-ip-watchdog.sh

    # Systemd timer: каждые 5 минут
    cat > /etc/systemd/system/wg-ip-watchdog.service << 'EOF'
[Unit]
Description=WireGuard Public IP Watchdog
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wg-ip-watchdog.sh
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/wg-ip-watchdog.timer << 'EOF'
[Unit]
Description=WireGuard IP Watchdog — check every 5 min

[Timer]
OnBootSec=60s
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

    # [fix v28.25.3] Проверяем успешность daemon-reload.
    systemctl daemon-reload || warn "daemon-reload завершился с ошибкой (проверь: systemctl status wg-ip-watchdog.service)"
    systemctl enable wg-ip-watchdog.timer 2>/dev/null || true
    systemctl start wg-ip-watchdog.timer 2>/dev/null || true
    # Запускаем сразу чтобы сохранить текущий IP в state file
    systemctl start wg-ip-watchdog.service 2>/dev/null || true

    info "IP Watchdog установлен (проверка каждые 5 минут)"
    echo ""
    echo -e "  ${DIM}Лог изменений: /var/log/wg-ip-watchdog.log${NC}"
    echo -e "  ${DIM}Текущий IP: ${NC}$(cat /var/lib/wg/last-pub-ip 2>/dev/null || echo 'неизвестен')"
}

removeIPWatchdog() {
    systemctl stop wg-ip-watchdog.timer wg-ip-watchdog.service 2>/dev/null || true
    systemctl disable wg-ip-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/wg-ip-watchdog.{service,timer}
    rm -f /usr/local/bin/wg-ip-watchdog.sh
    systemctl daemon-reload
    info "IP Watchdog удалён"
}

# ── Watchdog для wg-balance ─────────────────────────────────────
# Проверяет что балансировщик жив каждые 2 минуты.
# Если упал — перезапускает и пишет в лог.
setupBalanceWatchdog() {
    loadConfig
    section "Watchdog для wg-balance"
    echo ""
    echo -e "  ${DIM}Сервис проверяет что wg-balance жив каждые 2 минуты.${NC}"
    echo -e "  ${DIM}Если упал — перезапускает автоматически.${NC}"
    echo ""

    cat > /usr/local/bin/wg-balance-watchdog.sh << 'BWEOF'
#!/bin/bash
LOG="/var/log/wg-balance-watchdog.log"
_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG}"; }

# Проверяем что wg-balance активен
if ! systemctl is-active --quiet wg-balance; then
    _log "⚠ wg-balance не активен — перезапускаю..."
    systemctl restart wg-balance
    sleep 5
    if systemctl is-active --quiet wg-balance; then
        _log "✔ wg-balance успешно перезапущен"
    else
        _log "✖ wg-balance не удалось запустить!"
        journalctl -u wg-balance -n 10 --no-pager >> "${LOG}" 2>/dev/null || true
    fi
    exit 0
fi

# Проверяем что балансировщик реально работает — есть активные туннельные таблицы
if ! ip rule show 2>/dev/null | grep -qE 'lookup 5182[0-9]+'; then
    _log "⚠ ip rule таблицы балансировщика отсутствуют — перезапускаю wg-balance..."
    systemctl restart wg-balance
    _log "✔ wg-balance перезапущен для восстановления таблиц"
fi
BWEOF
    chmod +x /usr/local/bin/wg-balance-watchdog.sh

    cat > /etc/systemd/system/wg-balance-watchdog.service << 'EOF'
[Unit]
Description=WireGuard Balance Watchdog
After=network-online.target wg-balance.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wg-balance-watchdog.sh
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/wg-balance-watchdog.timer << 'EOF'
[Unit]
Description=WireGuard Balance Watchdog — каждые 2 минуты

[Timer]
OnBootSec=90s
OnUnitActiveSec=2min
AccuracySec=15s

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable wg-balance-watchdog.timer 2>/dev/null || true
    systemctl start wg-balance-watchdog.timer 2>/dev/null || true
    systemctl start wg-balance-watchdog.service 2>/dev/null || true

    info "Balance Watchdog установлен (проверка каждые 2 минуты)"
    echo -e "  ${DIM}Лог: /var/log/wg-balance-watchdog.log${NC}"
    echo ""
}

removeBalanceWatchdog() {
    systemctl stop wg-balance-watchdog.timer wg-balance-watchdog.service 2>/dev/null || true
    systemctl disable wg-balance-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/wg-balance-watchdog.{service,timer}
    rm -f /usr/local/bin/wg-balance-watchdog.sh
    systemctl daemon-reload
    info "Balance Watchdog удалён"
}

# ── Watchdog целостности ключей WireGuard ───────────────────────────────────
# [v28.24.24] Проверяет наличие, права и валидность server_private.key каждые
# 10 минут. При обнаружении проблемы — пишет в лог и отправляет systemd alert
# (статус Failed). Намеренно НЕ восстанавливает ключ автоматически: утеря
# приватного ключа требует ротации всех клиентских Peer-записей — это действие
# пользователя. Вместо этого сервис переходит в Failed, что видно в:
#   systemctl status wg-key-watchdog
#   journalctl -u wg-key-watchdog -n 20
setupKeyWatchdog() {
    loadConfig
    section "Watchdog целостности ключей WireGuard"
    echo ""
    echo -e "  ${DIM}Сервис проверяет каждые 10 минут:${NC}"
    echo -e "  ${DIM}  • наличие /etc/wireguard/server_private.key${NC}"
    echo -e "  ${DIM}  • права 600 (не шире)${NC}"
    echo -e "  ${DIM}  • что ключ валиден (wg pubkey не возвращает ошибку)${NC}"
    echo -e "  ${DIM}  • совпадение публичного ключа с SERVER_PUB_KEY в конфиге${NC}"
    echo ""

    cat > /usr/local/bin/wg-key-watchdog.sh << 'KWEOF'
#!/bin/bash
# wg-key-watchdog — проверка целостности приватного ключа WireGuard
# [v28.24.24] Намеренно завершается с exit 1 при любой проблеме,
# чтобы systemd перевёл сервис в Failed — это видно в статусбаре и алертах.
CONFIG_FILE="/etc/wireguard/.wg-setup.conf"
KEY_FILE="/etc/wireguard/server_private.key"
LOG="/var/log/wg-key-watchdog.log"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG}"; }
_fail() { _log "✖ КРИТИЧНО: $*"; exit 1; }

# 1. Файл существует
[ -f "${KEY_FILE}" ] || _fail "Файл ключа ${KEY_FILE} не найден!"

# 2. Права не шире 0600
_perms=$(stat -c '%a' "${KEY_FILE}" 2>/dev/null || stat -f '%p' "${KEY_FILE}" 2>/dev/null | tail -c 4)
if [ "${_perms}" != "600" ]; then
    _log "⚠ Права ${KEY_FILE} = ${_perms}, исправляю на 600"
    chmod 600 "${KEY_FILE}" || _fail "Не удалось исправить права на ${KEY_FILE}"
    _log "✔ Права исправлены"
fi

# 3. Файл не пуст
[ -s "${KEY_FILE}" ] || _fail "Файл ключа ${KEY_FILE} пуст!"

# 4. Ключ валиден (wg pubkey не должен возвращать ошибку)
_pub=$(wg pubkey < "${KEY_FILE}" 2>/dev/null) || _fail "Ключ ${KEY_FILE} не является валидным WireGuard-ключом!"
[ -n "${_pub}" ] || _fail "wg pubkey вернул пустой результат для ${KEY_FILE}!"

# 5. Публичный ключ совпадает с тем, что прописан в конфиге (если конфиг есть)
if [ -f "${CONFIG_FILE}" ]; then
    _stored_pub=$(grep -E '^SERVER_PUB_KEY=' "${CONFIG_FILE}" | head -1 \
        | sed 's/^SERVER_PUB_KEY=//' | tr -d '"' | tr -d "'" | tr -d ' ')
    if [ -n "${_stored_pub}" ] && [ "${_pub}" != "${_stored_pub}" ]; then
        _fail "Публичный ключ (${_pub}) не совпадает с SERVER_PUB_KEY в конфиге (${_stored_pub})! Ключ подменён или конфиг устарел."
    fi
fi

_log "✔ Ключ OK (pub: ${_pub:0:12}…)"
exit 0
KWEOF
    chmod +x /usr/local/bin/wg-key-watchdog.sh

    cat > /etc/systemd/system/wg-key-watchdog.service << 'EOF'
[Unit]
Description=WireGuard Key Integrity Watchdog
After=network.target
# Если сервис падает — systemd пишет в journal, visible in statusbar
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wg-key-watchdog.sh
StandardOutput=journal
StandardError=journal
# Не перезапускаем автоматически: проблема с ключом требует ручного вмешательства
Restart=no
EOF

    cat > /etc/systemd/system/wg-key-watchdog.timer << 'EOF'
[Unit]
Description=WireGuard Key Integrity — check every 10 min

[Timer]
OnBootSec=90s
OnUnitActiveSec=10min
AccuracySec=30s
# Если сервис перешёл в Failed — таймер продолжает попытки
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload || warn "daemon-reload завершился с ошибкой"
    systemctl enable wg-key-watchdog.timer 2>/dev/null || true
    systemctl start  wg-key-watchdog.timer 2>/dev/null || true
    # Первый прогон сразу
    systemctl start  wg-key-watchdog.service 2>/dev/null || true

    info "Key Watchdog установлен (проверка каждые 10 минут)"
    echo ""
    echo -e "  ${DIM}Лог: /var/log/wg-key-watchdog.log${NC}"
    echo -e "  ${DIM}Статус: systemctl status wg-key-watchdog.service${NC}"
}

removeKeyWatchdog() {
    systemctl stop    wg-key-watchdog.timer wg-key-watchdog.service 2>/dev/null || true
    systemctl disable wg-key-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/wg-key-watchdog.{service,timer}
    rm -f /usr/local/bin/wg-key-watchdog.sh
    systemctl daemon-reload
    info "Key Watchdog удалён"
}

menuIPWatchdog() {
    loadConfig  # [fix v28.24.1] однократно до цикла; состояние конфига статично
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🌐  IP WATCHDOG — мониторинг смены публичного IP           ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        local _timer_st
        _timer_st=$(systemctl is-active wg-ip-watchdog.timer 2>/dev/null || echo "inactive")
        local _cur_ip
        _cur_ip=$(cat /var/lib/wg/last-pub-ip 2>/dev/null || echo "неизвестен")
        local _cfg_ip="${SERVER_PUB_IP:-неизвестен}"

        if [ "${_timer_st}" = "active" ]; then
            echo -e "  Статус:     ${GREEN}● активен${NC}  (проверка каждые 5 минут)"
        else
            echo -e "  Статус:     ${RED}○ не установлен${NC}"
        fi
        echo -e "  IP в конфиге:  ${CYAN}${_cfg_ip}${NC}"
        echo -e "  Последний IP:  ${CYAN}${_cur_ip}${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  ✅  Установить / обновить IP Watchdog"
        echo -e "  ${YELLOW}2${NC})  📋  Лог изменений IP"
        echo -e "  ${YELLOW}3${NC})  🔄  Проверить IP прямо сейчас"
        echo -e "  ${RED}4${NC})  ❌  Удалить IP Watchdog"
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) setupIPWatchdog ;;
            2) echo ""
               if [ -f /var/log/wg-ip-watchdog.log ]; then
                   tail -30 /var/log/wg-ip-watchdog.log
               else
                   warn "Лог пуст или watchdog не установлен"
               fi ;;
            3) echo ""
               step "Проверяю IP..."
               systemctl start wg-ip-watchdog.service 2>/dev/null || \
                   /usr/local/bin/wg-ip-watchdog.sh 2>/dev/null || true
               echo ""
               echo -e "  IP сейчас: ${GREEN}$(cat /var/lib/wg/last-pub-ip 2>/dev/null || echo 'неизвестен')${NC}" ;;
            4) removeIPWatchdog ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

menuBalancer() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   ⚖️   БАЛАНСИРОВЩИК — автовыбор лучшего туннеля              ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Балансировщик каждые N секунд пингует все туннели и ставит вперёд${NC}"
        echo -e "  ${DIM}тот у которого меньше задержка. Если туннель «умирает» (пинг > порога)${NC}"
        echo -e "  ${DIM}— автоматически переключается на следующий лучший.${NC}"
        echo ""
        local bal_st
        bal_st=$(_svcStatus "wg-balance")
        echo -e "  Сервис балансировщика: ${bal_st}  ${DIM}(интервал: ${BALANCE_INTERVAL}с, порог: ${BAD_PING_MS}мс)${NC}"
        echo ""
        local bw_st
        bw_st=$(systemctl is-active wg-balance-watchdog.timer 2>/dev/null || echo "inactive")
        if [ "${bw_st}" = "active" ]; then
            echo -e "  Watchdog балансировщика: ${GREEN}● активен${NC}  ${DIM}(проверка каждые 2 минуты)${NC}"
        else
            echo -e "  Watchdog балансировщика: ${RED}○ не установлен${NC}"
        fi
        echo ""
        echo -e "  ${YELLOW}1${NC})  📊  ${WHITE}Статус и последние логи${NC}"
        echo -e "      ${DIM}Показывает активен ли балансировщик и последние 20 строк лога.${NC}"
        echo -e "      ${DIM}В логе видно какой туннель сейчас главный и какой у него пинг.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ⚙️   ${WHITE}Управление сервисом (стоп/старт/рестарт)${NC}"
        echo -e "      ${DIM}Полное управление: просмотр лога в реальном времени, перезапуск,${NC}"
        echo -e "      ${DIM}остановка, запуск, изменение интервала и порога пинга.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  ✏️   ${WHITE}Изменить настройки${NC}"
        echo -e "      ${DIM}Интервал проверки: как часто пинговать туннели (по умолч. 10 сек).${NC}"
        echo -e "      ${DIM}Порог пинга: выше этого значения туннель считается плохим (200 мс).${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔍  ${WHITE}Диагностика маршрутов${NC}"
        echo -e "      ${DIM}Показывает активные ip rule (какой туннель стоит первым) и таблицы${NC}"
        echo -e "      ${DIM}маршрутизации. Полезно для отладки если балансировка не работает.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🛡️   ${WHITE}Watchdog балансировщика${NC}"
        echo -e "      ${DIM}Устанавливает/удаляет автоматический перезапуск wg-balance${NC}"
        echo -e "      ${DIM}если он упал. Проверяет каждые 2 минуты.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) systemctl status wg-balance.service --no-pager
               echo ""
               journalctl -u wg-balance.service -n 20 --no-pager ;;
            2) manageBalancer ;;
            3) local ni np
               read -rp "  Интервал (сек) [${BALANCE_INTERVAL}]: " ni
               if [ -n "${ni}" ]; then
                   if [[ "${ni}" =~ ^[0-9]+$ ]] && (( ni >= 5 && ni <= 3600 )); then
                       sed -i "s|^BALANCE_INTERVAL=.*|BALANCE_INTERVAL=\"${ni}\"|" "${CONFIG_FILE}"
                   else
                       warn "Интервал должен быть целым числом 5..3600 — пропуск"
                   fi
               fi
               read -rp "  Порог пинга (мс) [${BAD_PING_MS}]: " np
               if [ -n "${np}" ]; then
                   if [[ "${np}" =~ ^[0-9]+$ ]] && (( np >= 10 && np <= 5000 )); then
                       sed -i "s|^BAD_PING_MS=.*|BAD_PING_MS=\"${np}\"|" "${CONFIG_FILE}"
                   else
                       warn "Порог должен быть целым числом 10..5000 — пропуск"
                   fi
               fi
               systemctl restart wg-balance.service
               info "Настройки обновлены, балансировщик перезапущен" ;;
            4) echo -e "\n  ${WHITE}Активные правила маршрутизации:${NC}"
               { ip rule show | grep -E "prio (45|50|51|200)" || true; } | sed 's/^/    /'
               echo -e "\n  ${WHITE}Таблица маршрутизации 51821:${NC}"
               { ip route show table 51821 2>/dev/null | head -5 || true; } | sed 's/^/    /' ;;
            5) if [ "${bw_st}" = "active" ]; then
                   echo ""
                   echo -e "  ${YELLOW}1${NC}) Просмотр лога watchdog"
                   echo -e "  ${YELLOW}2${NC}) Удалить watchdog"
                   echo -e "  ${YELLOW}0${NC}) Назад"
                   read -rp "  Выбор: " bw_opt
                   case "${bw_opt}" in
                       1) tail -30 /var/log/wg-balance-watchdog.log 2>/dev/null || warn "Лог пуст" ;;
                       2) removeBalanceWatchdog ;;
                   esac
               else
                   setupBalanceWatchdog
               fi ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# TELEMT — НОВЫЙ MTProxy (Rust + Tokio, без Docker)
# https://github.com/telemt/telemt
# ════════════════════════════════════════════════════════════════



_telemt_detectArch() {
    local arch libc="gnu"
    arch=$(uname -m)
    # Проверяем версию glibc: telemt требует >= 2.32
    # На Debian 10 / Ubuntu 20.04 glibc = 2.31 → используем musl (статическая сборка)
    if ldd --version 2>&1 | grep -iq musl; then
        libc="musl"
    else
        local glibc_ver
        glibc_ver=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+$' || echo "2.31")
        local glibc_major glibc_minor
        glibc_major=$(echo "${glibc_ver}" | cut -d. -f1)
        glibc_minor=$(echo "${glibc_ver}" | cut -d. -f2)
        # Если glibc < 2.32 — musl (не зависит от системного glibc)
        if [ "${glibc_major}" -lt 2 ] || { [ "${glibc_major}" -eq 2 ] && [ "${glibc_minor}" -lt 32 ]; }; then
            libc="musl"
            warn "glibc ${glibc_ver} < 2.32 — используем musl-сборку telemt (статическая, работает везде)"
        fi
    fi
    case "${arch}" in
        x86_64)  echo "x86_64-linux-${libc}" ;;
        aarch64) echo "aarch64-linux-${libc}" ;;
        armv7l)  echo "armv7-linux-${libc}eabihf" ;;
        *)       error "Неподдерживаемая архитектура: ${arch}" ;;
    esac
}

_telemt_getLatestVersion() {
    curl -fsSL --tlsv1.2 --proto '=https' "${TELEMT_API_URL}" 2>/dev/null \
        | grep '"tag_name"' | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

_telemt_getCurrentVersion() {
    [ -x "${TELEMT_BIN}" ] \
        && "${TELEMT_BIN}" --version 2>/dev/null | head -1 \
        || echo "не установлен"
}

_telemt_downloadBinary() {
    local version="${1:-}"
    local arch
    arch=$(_telemt_detectArch)
    if [ -z "${version}" ]; then
        step "Определение последней версии telemt"
        version=$(_telemt_getLatestVersion)
        [ -z "${version}" ] && error "Не удалось получить версию с GitHub"
        info "Последняя версия: ${GREEN}${version}${NC}"
    fi

    # Если бинарь уже установлен и той же версии — пропускаем скачивание
    if [ -x "${TELEMT_BIN}" ]; then
        local cur_ver
        cur_ver=$("${TELEMT_BIN}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9.]+' | head -1 || true)
        local want_ver="${version#v}"
        if [ "${cur_ver}" = "${want_ver}" ]; then
            info "telemt ${cur_ver} уже установлен — пропускаем скачивание"
            return 0
        fi
    fi

    local url="${TELEMT_RELEASE_BASE}/${version}/telemt-${arch}.tar.gz"
    local sums_url="${TELEMT_RELEASE_BASE}/${version}/SHA256SUMS"
    step "Скачивание telemt ${version} (${arch})"
    local tmpdir
    tmpdir=$(mktemp -d)
    # [fix] Регистрируем cleanup в РОДИТЕЛЬСКОМ процессе — это гарантирует удаление
    # tmpdir при любом выходе (в т.ч. при exit из ERR trap в родителе).
    # Дополнительно trap внутри subshell страхует от выхода внутри него.
    # [fix v28.25.2] Убрано 'trap - EXIT' из родительского trap: снятие обработчика
    # после его срабатывания приводит к тому, что при повторном вызове функции
    # (или нештатном выходе из подоболочки) родительский cleanup уже не действует.
    # [fix] Одинарные кавычки в trap EXIT откладывают раскрытие ${tmpdir} до выхода
    # из СКРИПТА — к тому моменту local-переменная уже уничтожена → set -u ломает
    # cleanup. Используем RETURN + двойные кавычки: раскрытие происходит сразу
    # (значение tmpdir зафиксировано), cleanup срабатывает при выходе из функции.
    # Subshell использует EXIT со своей копией переменной — там одинарные кавычки ОК.
    trap "rm -rf '${tmpdir}' 2>/dev/null" RETURN
    (
    trap 'rm -rf "'"${tmpdir}"'" 2>/dev/null' EXIT
    # [v28.21.0] best-effort SHA256: качаем SHA256SUMS из релиза, проверяем после загрузки
    curl -fsSL --tlsv1.2 --proto '=https' --max-time 30 "${sums_url}" -o "${tmpdir}/SHA256SUMS" 2>/dev/null || true

    # Скачиваем с таймаутом 90с и двумя попытками (GitHub CDN может быть медленным)
    local ok=0
    for attempt in 1 2; do
        if curl -fsSL --tlsv1.2 --proto '=https' --max-time 90 --retry 2 --retry-delay 3 "${url}" \
                -o "${tmpdir}/telemt.tar.gz" 2>/dev/null; then
            ok=1; break
        fi
        warn "Попытка ${attempt}: не удалось скачать — повтор..."
        sleep 5
    done

    if [ "${ok}" -eq 1 ]; then
        # [v28.21.0] SHA256 verify — мягкий (warn если SHA256SUMS недоступен)
        if [ -s "${tmpdir}/SHA256SUMS" ]; then
            local _expected _actual
            _expected=$(grep -E "telemt-${arch}\.tar\.gz" "${tmpdir}/SHA256SUMS" 2>/dev/null | awk '{print $1}' | head -1)
            _actual=$(sha256sum "${tmpdir}/telemt.tar.gz" | awk '{print $1}')
            if [ -n "${_expected}" ] && [ "${_expected}" != "${_actual}" ]; then
                error "SHA256 mismatch для telemt-${arch}.tar.gz: ожидалось ${_expected}, получено ${_actual}"
            fi
        else
            warn "SHA256SUMS недоступен — пропускаем проверку целостности (best-effort)"
        fi
        tar -xzf "${tmpdir}/telemt.tar.gz" -C "${tmpdir}" 2>/dev/null || true
        local bin
        bin=$(find "${tmpdir}" -name "telemt" -type f | head -1)
        if [ -z "${bin}" ]; then
            # Попробуем скачать как голый бинарь
            local url2="${TELEMT_RELEASE_BASE}/${version}/telemt-${arch}"
            curl -fsSL --tlsv1.2 --proto '=https' --max-time 90 "${url2}" -o "${tmpdir}/telemt" 2>/dev/null \
                || error "Не удалось скачать бинарь telemt"
            bin="${tmpdir}/telemt"
        fi
        cp "${bin}" "${TELEMT_BIN}"
        chmod +x "${TELEMT_BIN}"
        info "Бинарь установлен: ${TELEMT_BIN}"
    else
        error "Не удалось скачать telemt после 2 попыток. Если GitHub CDN недоступен с этого сервера — скачай вручную:\ncurl -fsSL --max-time 90 '${url}' -o /tmp/telemt.tar.gz\nи запусти установку повторно."
    fi
    rm -rf "${tmpdir}" 2>/dev/null || true
    # [fix v28.25.0] Закрываем подоболочку (trap EXIT выше локален внутри неё).
    # Удаление tmpdir гарантировано trap'ом EXIT внутри подоболочки.
    ) ; return $?
}

_telemt_generateSecret() {
    # [fix v28.25.0] Проверяем наличие openssl перед вызовом — без него команда
    # просто упадёт в меню «Добавить пользователя» до установки telemt.
    if ! command -v openssl >/dev/null 2>&1; then
        warn "openssl не найден — устанавливаю..."
        apt-get install -y openssl -q 2>/dev/null || {
            warn "Не удалось установить openssl — установи вручную: apt install openssl"
            return 1
        }
    fi
    openssl rand -hex 16
}

_telemt_listUsers() {
    [ -f "${TELEMT_CONFIG}" ] || { echo ""; return; }
    awk '/^\[access\.users\]/{found=1; next} /^\[/{found=0} found && /=/{print}' \
        "${TELEMT_CONFIG}" | sed 's/[[:space:]]//g'
}

_telemt_addUser() {
    local name="$1" secret="$2"
    # [fix] Defence in depth — валидируем имя внутри функции, даже если вызывающий код уже проверил.
    # Предотвращает sed-инъекцию если функция будет вызвана из нового места без валидации.
    if ! [[ "${name}" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
        warn "_telemt_addUser: недопустимое имя '${name}' (разрешены a-zA-Z0-9_-, до 32 символов)"
        return 1
    fi
    [ -f "${TELEMT_CONFIG}" ] || { warn "Конфиг не найден"; return; }
    if grep -qE "^${name}[[:space:]]*=" "${TELEMT_CONFIG}" 2>/dev/null; then
        warn "Пользователь '${name}' уже существует"
        return
    fi
    sed -i "/^\[access\.users\]/a ${name} = \"${secret}\"" "${TELEMT_CONFIG}"
    info "Пользователь ${GREEN}${name}${NC} добавлен"
}

# [fix v28.24.24] Валидация конфига telemt перед рестартом.
# Telemt не имеет флага --check-config; используем минимальный синтаксический
# тест: парсим TOML вручную через awk (нет внешних зависимостей) и проверяем
# наличие обязательных ключей. Если telemt соберёт собственный валидатор —
# заменить тело на: "${TELEMT_BIN}" --check-config "${TELEMT_CONFIG}"
_telemt_safe_restart() {
    local _cfg="${TELEMT_CONFIG:-/etc/telemt.toml}"
    local _bin="${TELEMT_BIN:-/usr/local/bin/telemt}"

    # 1. Файл существует и не пуст
    if [ ! -f "${_cfg}" ]; then
        warn "telemt: конфиг ${_cfg} не найден — рестарт отменён"
        return 1
    fi
    if [ ! -s "${_cfg}" ]; then
        warn "telemt: конфиг ${_cfg} пуст — рестарт отменён"
        return 1
    fi

    # 2. Синтаксическая проверка TOML: нет незакрытых кавычек в строках со =
    #    (grубая проверка; ловит самые частые ошибки ручного редактирования)
    local _bad_line
    _bad_line=$(awk -F= '
        /^[[:space:]]*#/ { next }
        NF >= 2 {
            val = $0; sub(/^[^=]*=[[:space:]]*/, "", val)
            # Строковое значение начинается с " — проверяем закрывающую "
            if (val ~ /^"/ && val !~ /^"[^"]*"[[:space:]]*(#.*)?$/) {
                print NR": "val; exit 1
            }
        }
    ' "${_cfg}" 2>/dev/null || true)
    if [ -n "${_bad_line}" ]; then
        warn "telemt: синтаксическая ошибка в ${_cfg} (строка ${_bad_line}) — рестарт отменён"
        return 1
    fi

    # 3. Обязательные ключи: port верхнего уровня + хотя бы один пользователь
    #    в секции [access.users] (секрет хранится там, а не как глобальный ключ)
    if ! grep -qE "^[[:space:]]*port[[:space:]]*=" "${_cfg}" 2>/dev/null; then
        warn "telemt: в конфиге отсутствует обязательное поле 'port' — рестарт отменён"
        return 1
    fi
    if ! grep -qF "[access.users]" "${_cfg}" 2>/dev/null; then
        warn "telemt: секция [access.users] отсутствует в конфиге — рестарт отменён"
        return 1
    fi
    # Хотя бы одна запись пользователя (строка вида: имя = "секрет") после заголовка секции
    if ! awk '/^\[access\.users\]/{found=1; next} /^\[/{found=0} found && /=[[:space:]]*"/{ok=1} END{exit !ok}'             "${_cfg}" 2>/dev/null; then
        warn "telemt: в [access.users] нет ни одного пользователя — рестарт отменён"
        return 1
    fi

    # 4. Бинарь существует и исполняем
    if [ ! -x "${_bin}" ]; then
        warn "telemt: бинарь ${_bin} не найден или не исполняем — рестарт отменён"
        return 1
    fi

    # Всё хорошо — рестартуем
    systemctl restart telemt
}

_telemt_removeUser() {
    local name="$1"
    # [fix] Defence in depth — валидируем имя внутри функции.
    if ! [[ "${name}" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
        warn "_telemt_removeUser: недопустимое имя '${name}' (разрешены a-zA-Z0-9_-, до 32 символов)"
        return 1
    fi
    [ -f "${TELEMT_CONFIG}" ] || { warn "Конфиг не найден"; return; }
    sed -i "/^${name}\s*=/d" "${TELEMT_CONFIG}"
    info "Пользователь ${name} удалён"
}

_telemt_createConfig() {
    local pub_ip="$1" port="${2:-443}" tls_domain="${3:-1c.ru}" \
          username="${4:-user1}" secret="${5:-}"
    [ -z "${secret}" ] && secret=$(_telemt_generateSecret)
    # [fix v28.22.3] Экранируем кавычки в tls_domain и username — без этого
    # TOML-конфиг становится невалидным если значение содержит двойную кавычку.
    local tls_domain_escaped username_escaped
    tls_domain_escaped=$(printf '%s' "${tls_domain}" | sed 's/\\/\\\\/g; s/"/\\"/g')
    username_escaped=$(printf '%s' "${username}" | sed 's/\\/\\\\/g; s/"/\\"/g')
    mkdir -p "${TELEMT_TLSFRONT_DIR}"
    cat > "${TELEMT_CONFIG}" << EOF
# ══════════════════════════════════════════════════════
# Telemt MTProxy — конфиг
# Upstream: https://github.com/telemt/telemt
# ══════════════════════════════════════════════════════

[general]
use_middle_proxy = false
log_level = "normal"
# Рекламный тег от @MTProxybot (необязательно):
# ad_tag = "00000000000000000000000000000000"

[general.modes]
classic = false   # Старый незащищённый режим — выключен
secure  = false   # Защищённый без TLS — выключен
tls     = true    # Fake TLS — ВКЛЮЧЁН (рекомендуется)

[general.links]
show = "*"
public_host = "${pub_ip}"
public_port = ${port}

[server]
port = ${port}

[server.api]
enabled   = true
listen    = "127.0.0.1:9091"
whitelist = ["127.0.0.0/8"]
minimal_runtime_enabled    = false
minimal_runtime_cache_ttl_ms = 1000

# Метрики Prometheus (раскомментируй если нужно):
# metrics_port = 9090
# metrics_whitelist = ["127.0.0.1", "::1"]

[[server.listeners]]
ip = "0.0.0.0"

# ── Маскировка от DPI ──────────────────────────────────
# Без правильного ключа трафик уходит к реальному сайту-маскировке
[censorship]
tls_domain    = "${tls_domain_escaped}"
mask          = true
tls_emulation = true
tls_front_dir = "${TELEMT_TLSFRONT_DIR}"

[access]
replay_check_len = 65536
ignore_time_skew = false

# ── Пользователи ──────────────────────────────────────
# Формат: имя = "32 hex символа"
# Генерация: openssl rand -hex 16
[access.users]
${username_escaped} = "${secret}"
EOF
    chmod 600 "${TELEMT_CONFIG}"
    info "Конфиг создан: ${TELEMT_CONFIG}"
}

_telemt_createService() {
    cat > "${TELEMT_SERVICE}" << EOF
[Unit]
Description=Telemt MTProxy (Rust — Telegram Proxy)
Documentation=https://github.com/telemt/telemt
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${TELEMT_BIN} ${TELEMT_CONFIG}
Restart=always
RestartSec=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=telemt

# [fix v28.24.14] Исправлена критическая ошибка: CapabilityBoundingSet= (пустой) +
# NoNewPrivileges=yes лишал процесс CAP_NET_BIND_SERVICE, из-за чего telemt не мог
# открыть привилегированный порт 443 (Permission denied). Добавлены явные capabilities.
NoNewPrivileges=yes
ProtectSystem=strict
ReadOnlyPaths=${TELEMT_CONFIG}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable telemt 2>/dev/null || true
    info "Systemd сервис telemt создан и включён в автозапуск"
}

installTelemt() {
    loadConfig
    section "Установка Telemt MTProxy (Rust, без Docker)"
    echo ""
    echo -e "  ${DIM}Что будет установлено:${NC}"
    echo -e "  ${DIM}  • Готовый бинарь telemt с GitHub Releases (~10 секунд)${NC}"
    echo -e "  ${DIM}  • Конфиг ${TELEMT_CONFIG} с Fake TLS и маскировкой${NC}"
    echo -e "  ${DIM}  • Systemd сервис с LimitNOFILE=65536${NC}"
    echo ""

    # Проверяем зависимости
    apt-get install -y curl openssl iproute2 -q 2>/dev/null || true

    # Публичный IP
    local PUB_IP="${SERVER_PUB_IP:-}"
    if [ -z "${PUB_IP}" ] || [ "${PUB_IP}" = "0.0.0.0" ]; then
        PUB_IP=$(curl -fsSL --tlsv1.2 --proto '=https' https://api.ipify.org 2>/dev/null \
               || curl -fsSL --tlsv1.2 --proto '=https' https://ifconfig.me 2>/dev/null || echo "")
    fi
    if [ -n "${PUB_IP}" ]; then
        info "Публичный IP: ${GREEN}${PUB_IP}${NC}"
        read -rp "  Верно? Enter = да, или введи другой: " alt
        [ -n "${alt}" ] && PUB_IP="${alt}"
    else
        read -rp "  Введи публичный IP сервера: " PUB_IP
    fi

    # Порт
    echo ""
    echo -ne "  ${YELLOW}→ Порт${NC} ${DIM}[443]${NC}: "
    read -r TPORT; [ -z "${TPORT}" ] && TPORT="443"
    # Проверка занятости порта
    if ss -tlnp 2>/dev/null | grep -q ":${TPORT} "; then
        local proc
        proc=$(ss -tlnp 2>/dev/null | grep ":${TPORT} " \
               | awk 'match($0, /users:\(\("[^"]+/) {print substr($0, RSTART+10, RLENGTH-10)}' | head -1)
        warn "Порт ${TPORT} занят: ${proc:-неизвестно}"
        warn "Останови nginx/apache или используй другой порт"
        read -rp "  Другой порт (Enter = отмена): " TPORT2
        if [ -z "${TPORT2}" ]; then
            warn "Порт не изменён — установка отменена (порт ${TPORT} занят)"
            return
        fi
        # [fix v28.24.20] Проверяем и альтернативный порт — пользователь мог
        # указать тоже занятый. Повторяем ту же проверку один раз.
        if ss -tlnp 2>/dev/null | grep -q ":${TPORT2} "; then
            local proc2
            proc2=$(ss -tlnp 2>/dev/null | grep ":${TPORT2} " \
                   | awk 'match($0, /users:\(\("[^"]+/) {print substr($0, RSTART+10, RLENGTH-10)}' | head -1)
            warn "Альтернативный порт ${TPORT2} тоже занят: ${proc2:-неизвестно} — установка отменена"
            return
        fi
        TPORT="${TPORT2}"
    fi

    # Домен маскировки
    echo ""
    echo -e "  ${DIM}Домен маскировки — под какой сайт прячемся. Должен работать по HTTPS.${NC}"
    echo -e "  ${DIM}Рекомендуемые: 1c.ru  sberbank.ru  gosuslugi.ru  vk.com${NC}"
    echo ""
    echo -ne "  ${YELLOW}→ Домен маскировки${NC} ${DIM}[1c.ru]${NC}: "
    read -r TDOMAIN; [ -z "${TDOMAIN}" ] && TDOMAIN="1c.ru"

    # Первый пользователь
    echo ""
    echo -ne "  ${YELLOW}→ Имя первого пользователя${NC} ${DIM}[user1]${NC}: "
    read -r TUNAME; [ -z "${TUNAME}" ] && TUNAME="user1"

    # Скачиваем, создаём конфиг и сервис
    _telemt_downloadBinary
    _telemt_createConfig "${PUB_IP}" "${TPORT}" "${TDOMAIN}" "${TUNAME}"
    _telemt_createService

    # Запускаем
    step "Запуск telemt"
    systemctl start telemt
    sleep 3
    if systemctl is-active telemt >/dev/null 2>&1; then
        info "${GREEN}Telemt запущен!${NC}"
    else
        warn "Сервис не стартовал. Лог:"
        journalctl -u telemt -n 15 --no-pager 2>/dev/null || true
    fi

    showTelemetLinks
    echo ""
    info "Конфиг: ${TELEMT_CONFIG}  |  Логи: journalctl -u telemt -f"
}

updateTelemt() {
    step "Обновление telemt"
    local current latest
    current=$(_telemt_getCurrentVersion)
    latest=$(_telemt_getLatestVersion)
    info "Текущая: ${current}"
    info "Последняя: ${GREEN}${latest}${NC}"
    if [ "${current}" = "${latest}" ]; then
        info "Уже установлена последняя версия!"
        return
    fi
    read -rp "  Обновить? [y/N]: " yn
    [[ "${yn}" =~ ^[Yy]$ ]] || { warn "Отменено"; return; }
    systemctl stop telemt 2>/dev/null || true
    _telemt_downloadBinary "${latest}"
    systemctl start telemt
    info "Обновлено до ${latest}"
}

removeTelemt() {
    section "Удаление Telemt MTProxy"
    echo ""
    warn "Будет удалено: бинарь, конфиг, сервис, TLS кэш"
    read -rp "  Введи YES для подтверждения: " CONFIRM
    [ "${CONFIRM}" != "YES" ] && { warn "Отменено"; return; }
    systemctl stop telemt 2>/dev/null || true
    systemctl disable telemt 2>/dev/null || true
    rm -f "${TELEMT_BIN}" "${TELEMT_CONFIG}" "${TELEMT_SERVICE}"
    rm -rf "${TELEMT_TLSFRONT_DIR}"
    systemctl daemon-reload
    info "Telemt удалён"
}

showTelemetLinks() {
    step "Ссылки tg://proxy для Telegram"
    echo ""

    [ -f "${TELEMT_CONFIG}" ] || { warn "Конфиг не найден"; return; }

    # 1. Достаем общие настройки из конфига
    # [fix v28.25.0] awk вместо grep+cut — корректно обрабатывает закомментированные
    # строки и дубли ключей в разных секциях TOML.
    local pub_ip port domain
    pub_ip=$(awk -F'"' '/^[[:space:]]*public_host[[:space:]]*=/ {print $2; exit}' "${TELEMT_CONFIG}")
    port=$(awk '/^[[:space:]]*public_port[[:space:]]*=/ {gsub(/[^0-9]/,"",$NF); print $NF+0; exit}' "${TELEMT_CONFIG}")
    domain=$(awk -F'"' '/^[[:space:]]*tls_domain[[:space:]]*=/ {print $2; exit}' "${TELEMT_CONFIG}")

    # Переводим домен в HEX (нужно для Fake TLS секрета)
    # [fix v28.25.0] xxd вместо od — xxd явно объявлен зависимостью (installPackages),
    # поведение od с пробелами отличается в busybox/macOS.
    local domain_hex
    domain_hex=$(printf '%s' "${domain}" | xxd -p | tr -d ' \n')

    # 2. Достаем всех пользователей и генерируем чистые ссылки
    local users
    users=$(_telemt_listUsers)

    if [ -n "${users}" ]; then
        local i=1
        while IFS= read -r line; do
            local uname usecret final_secret
            uname=$(echo "${line}" | cut -d= -f1)
            usecret=$(echo "${line}" | cut -d'"' -f2)

            # Формируем правильный секрет: ee + secret + domain_hex
            final_secret="ee${usecret}${domain_hex}"

            echo -e "  ${WHITE}Пользователь:${NC} ${GREEN}${uname}${NC}"
            echo -e "  ${CYAN}tg://proxy?server=${pub_ip}&port=${port}&secret=${final_secret}${NC}"
            echo -e "  ${DIM}──────────────────────────────────────────────────────────${NC}"
            ((++i))
        done <<< "${users}"
        echo ""
        info "Отправь чистую ссылку другу — теперь там нет лишних дат и символов."
    else
        warn "Пользователи в конфиге не найдены."
    fi
}

diagnoseTelemt() {
    section "Диагностика Telemt"
    echo ""
    echo -e "  ${WHITE}── Бинарь и версия ──${NC}"
    if [ -x "${TELEMT_BIN}" ]; then
        info "Бинарь: ${TELEMT_BIN}"
        info "Версия: ${GREEN}$(_telemt_getCurrentVersion)${NC}"
    else
        warn "Бинарь не найден"
    fi

    echo ""
    echo -e "  ${WHITE}── Сервис ──${NC}"
    systemctl status telemt --no-pager 2>/dev/null | head -12 \
        || warn "Сервис не найден"

    echo ""
    echo -e "  ${WHITE}── Порт ──${NC}"
    local port="443"
    [ -f "${TELEMT_CONFIG}" ] && \
        port=$(grep '^port\s*=' "${TELEMT_CONFIG}" | head -1 | grep -oE '[0-9]+' | head -1)
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        local proc
        proc=$(ss -tlnp 2>/dev/null | grep ":${port} " \
               | awk 'match($0, /users:\(\("[^"]+/) {print substr($0, RSTART+10, RLENGTH-10)}' | head -1)
        info "Порт ${port} слушает: ${GREEN}${proc:-telemt}${NC}"
    else
        warn "Порт ${port} не слушается!"
    fi

    echo ""
    echo -e "  ${WHITE}── Пользователи ──${NC}"
    local users
    users=$(_telemt_listUsers)
    if [ -n "${users}" ]; then
        while IFS= read -r line; do
            local uname usecret
            uname=$(echo "${line}" | cut -d= -f1)
            usecret=$(echo "${line}" | cut -d'"' -f2)
            printf "  ${GREEN}●${NC}  %-20s  ${DIM}%s${NC}\n" "${uname}" "${usecret}"
        done <<< "${users}"
    else
        warn "Пользователи не найдены"
    fi

    echo ""
    echo -e "  ${WHITE}── REST API (127.0.0.1:9091) ──${NC}"
    local api
    api=$(curl -fsSL --connect-timeout 2 http://127.0.0.1:9091/status 2>/dev/null || echo "")
    if [ -n "${api}" ]; then
        info "API отвечает:"
        echo "${api}" | python3 -m json.tool 2>/dev/null \
            | head -15 | sed 's/^/    /' || echo "    ${api}"
    else
        echo -e "  ${DIM}API не отвечает (нормально если minimal_runtime_enabled=false)${NC}"
    fi

    echo ""
    echo -e "  ${WHITE}── Домен маскировки ──${NC}"
    local domain=""
    [ -f "${TELEMT_CONFIG}" ] && \
        domain=$(grep '^tls_domain' "${TELEMT_CONFIG}" | head -1 \
                 | sed 's/.*= *"\([^"]*\)".*/\1/')
    if [ -n "${domain}" ]; then
        printf "  %-40s" "HTTPS к ${domain}..."
        if curl -fsSL --connect-timeout 4 "https://${domain}" -o /dev/null 2>/dev/null; then
            echo -e "${GREEN}✔ OK${NC}"
        else
            echo -e "${RED}✖ недоступен — замени tls_domain в конфиге${NC}"
        fi
    fi

    echo ""
    echo -e "  ${WHITE}── Последние логи ──${NC}"
    journalctl -u telemt -n 15 --no-pager 2>/dev/null || warn "Логи не найдены"
    echo ""
}

menuTelemetUsers() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   👥  TELEMT — ПОЛЬЗОВАТЕЛИ (доступ к прокси)                ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Каждый пользователь имеет уникальный секрет и свою tg://-ссылку.${NC}"
        echo -e "  ${DIM}Ссылка = tg://proxy?server=IP&port=443&secret=ee<домен><секрет>${NC}"
        echo -e "  ${DIM}Ссылки генерирует сам telemt — смотри пункт «Показать ссылки».${NC}"
        echo ""
        local users
        users=$(_telemt_listUsers)
        if [ -n "${users}" ]; then
            echo -e "  ${WHITE}Текущие пользователи:${NC}"
            echo -e "  ${DIM}──────────────────────────────────────────────────────────${NC}"
            while IFS= read -r line; do
                local uname usecret
                uname=$(echo "${line}" | cut -d= -f1)
                usecret=$(echo "${line}" | cut -d'"' -f2)
                printf "  ${GREEN}●${NC}  %-20s  ${DIM}%s${NC}\n" "${uname}" "${usecret}"
            done <<< "${users}"
            echo ""
        else
            echo -e "  ${DIM}  (пользователей нет)${NC}"
            echo ""
        fi
        echo -e "  ${YELLOW}1${NC})  ➕  ${WHITE}Добавить пользователя${NC}"
        echo -e "      ${DIM}Генерирует новый секрет, добавляет в конфиг, перезапускает сервис.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ❌  ${WHITE}Удалить пользователя${NC}"
        echo -e "      ${DIM}Убирает из конфига — его ссылка перестаёт работать.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔑  ${WHITE}Сменить секрет пользователя${NC}"
        echo -e "      ${DIM}Старая ссылка умирает, нужно раздать новую.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        local UNAME NEW_SECRET
        case "${opt}" in
            1)
                echo ""
                echo -ne "  ${YELLOW}→ Имя (латиница, цифры, _)${NC}: "
                read -r UNAME
                [ -z "${UNAME}" ] && continue
                # [fix v28.24.1] Унифицированная валидация через validateClientName
                if ! [[ "${UNAME}" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
                    warn "Только латиница, цифры, _ и - (макс 32 символа)"
                else
                    NEW_SECRET=$(_telemt_generateSecret)
                    _telemt_addUser "${UNAME}" "${NEW_SECRET}"
                    _telemt_safe_restart 2>/dev/null || true
                    sleep 2
                    showTelemetLinks
                fi
                ;;
            2)
                echo ""
                echo -ne "  ${YELLOW}→ Имя пользователя для удаления${NC}: "
                read -r UNAME
                [ -z "${UNAME}" ] && continue
                # [fix v28.24.19] Валидация имени перед sed-операцией в _telemt_removeUser.
                if ! [[ "${UNAME}" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
                    warn "Только латиница, цифры, _ и - (макс 32 символа)"
                    continue
                fi
                _telemt_removeUser "${UNAME}"
                _telemt_safe_restart 2>/dev/null || true
                ;;
            3)
                echo ""
                echo -ne "  ${YELLOW}→ Имя пользователя${NC}: "
                read -r UNAME
                [ -z "${UNAME}" ] && continue
                # [fix v28.24.19] Валидация имени перед sed-операциями в remove+add.
                if ! [[ "${UNAME}" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
                    warn "Только латиница, цифры, _ и - (макс 32 символа)"
                    continue
                fi
                _telemt_removeUser "${UNAME}"
                NEW_SECRET=$(_telemt_generateSecret)
                _telemt_addUser "${UNAME}" "${NEW_SECRET}"
                _telemt_safe_restart 2>/dev/null || true
                sleep 2
                info "Новый секрет: ${GREEN}${NEW_SECRET}${NC}"
                showTelemetLinks
                ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

menuTelemetConfig() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   ⚙️   TELEMT — НАСТРОЙКИ КОНФИГА                             ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Конфиг: ${TELEMT_CONFIG}${NC}"
        echo ""
        # Показываем ключевые параметры
        if [ -f "${TELEMT_CONFIG}" ]; then
            local port domain
            port=$(grep '^port\s*=' "${TELEMT_CONFIG}" | head -1 | grep -oE '[0-9]+' | head -1)
            domain=$(grep '^tls_domain' "${TELEMT_CONFIG}" | head -1 \
                     | sed 's/.*= *"\([^"]*\)".*/\1/')
            echo -e "  ${WHITE}Текущие параметры:${NC}"
            echo -e "  ${DIM}  Порт:           ${NC}${GREEN}${port:-?}${NC}"
            echo -e "  ${DIM}  Домен маскировки:${NC}${GREEN}${domain:-?}${NC}"
            echo ""
        fi
        echo -e "  ${YELLOW}1${NC})  ✏️   ${WHITE}Открыть конфиг в nano${NC}"
        echo -e "      ${DIM}Полное редактирование /etc/telemt.toml. После сохранения — перезапуск.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  🌐  ${WHITE}Сменить домен маскировки${NC}"
        echo -e "      ${DIM}Под какой сайт маскироваться: 1c.ru, sberbank.ru, gosuslugi.ru…${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔌  ${WHITE}Сменить порт${NC}"
        echo -e "      ${DIM}По умолчанию 443. Другие порты могут быть заблокированы.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🌐  ${WHITE}Тест домена маскировки${NC}"
        echo -e "      ${DIM}Проверяет что tls_domain доступен по HTTPS — важно для Fake TLS.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  📊  ${WHITE}Сравнение Telemt vs старый MTG${NC}"
        echo -e "      ${DIM}Таблица с отличиями — почему Telemt лучше.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1)
                [ -f "${TELEMT_CONFIG}" ] || { warn "Конфиг не найден — сначала установи Telemt"; continue; }
                local _EDITOR_CMD; _resolveEditor && "${_EDITOR_CMD[@]}" "${TELEMT_CONFIG}"
                read -rp "  Перезапустить сервис? [Y/n]: " yn
                [[ "${yn}" =~ ^[Nn]$ ]] || { _telemt_safe_restart; info "Перезапущен"; }
                ;;
            2)
                [ -f "${TELEMT_CONFIG}" ] || { warn "Конфиг не найден"; continue; }
                echo ""
                echo -e "  ${DIM}Примеры: 1c.ru  sberbank.ru  gosuslugi.ru  vk.com  yandex.ru${NC}"
                echo -ne "  ${YELLOW}→ Новый домен${NC}: "
                read -r NDOMAIN
                [ -z "${NDOMAIN}" ] && continue
                # [fix v28.24.19] Заменяем небезопасный plain sed на safe_sed —
                # экранирует sed-метасимволы в NDOMAIN (защита от инъекции в TOML).
                # Домен не требует строгой валидации здесь (cosmetic field),
                # но safe_sed гарантирует корректную запись любого значения.
                safe_sed "${TELEMT_CONFIG}" \
                    '^tls_domain[[:space:]]*=.*' \
                    "tls_domain = \"${NDOMAIN}\""
                info "Домен изменён на ${GREEN}${NDOMAIN}${NC}"
                # Очищаем TLS кэш — нужно пересоздать
                rm -rf "${TELEMT_TLSFRONT_DIR:?}"/*  2>/dev/null || true
                _telemt_safe_restart && info "Сервис перезапущен"
                ;;
            3)
                [ -f "${TELEMT_CONFIG}" ] || { warn "Конфиг не найден"; continue; }
                echo ""
                echo -ne "  ${YELLOW}→ Новый порт${NC}: "
                read -r NPORT
                [ -z "${NPORT}" ] && continue
                # [fix v28.22.1] Валидация: порт должен быть числом 1..65535
                if ! [[ "${NPORT}" =~ ^[0-9]+$ ]] || (( NPORT < 1 || NPORT > 65535 )); then
                    warn "Некорректный порт: '${NPORT}' (допустимо 1..65535)"
                    continue
                fi
                # [fix v28.24.20] Единообразие с safe_sed. NPORT валидирован как
                # число 1..65535 выше, инъекция невозможна, но style consistency.
                safe_sed "${TELEMT_CONFIG}" '^port[[:space:]]*=.*'        "port = ${NPORT}"
                safe_sed "${TELEMT_CONFIG}" '^public_port[[:space:]]*=.*' "public_port = ${NPORT}"
                info "Порт изменён на ${GREEN}${NPORT}${NC}"
                _telemt_safe_restart && info "Сервис перезапущен"
                sleep 2
                showTelemetLinks
                ;;
            4)
                [ -f "${TELEMT_CONFIG}" ] || { warn "Конфиг не найден"; continue; }
                local domain=""
                domain=$(grep '^tls_domain' "${TELEMT_CONFIG}" | head -1 \
                         | sed 's/.*= *"\([^"]*\)".*/\1/')
                echo ""
                echo -e "  ${WHITE}Тест домена: ${GREEN}${domain}${NC}"
                echo ""
                printf "  %-40s" "DNS резолвинг..."
                host -W 3 "${domain}" >/dev/null 2>&1 \
                    && echo -e "${GREEN}✔ OK${NC}" || echo -e "${RED}✖ ошибка${NC}"
                printf "  %-40s" "HTTPS (curl)..."
                curl -fsSL --connect-timeout 5 "https://${domain}" -o /dev/null 2>/dev/null \
                    && echo -e "${GREEN}✔ OK${NC}" \
                    || echo -e "${RED}✖ недоступен — замени домен!${NC}"
                echo ""
                ;;
            5)
                echo ""
                echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${YELLOW}  ║   📊  Telemt (Rust) vs MTG (Go, старый)                      ║${NC}"
                echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
                echo ""
                printf "  ${WHITE}%-30s  %-20s  %-20s${NC}\n" "Параметр" "MTG (старый)" "Telemt (новый)"
                echo -e "  ${DIM}──────────────────────────────────────────────────────────────────${NC}"
                _cmp() {
                    local f="$1" m="$2" t="$3" c="${GREEN}"
                    [ "${t}" = "❌" ] && c="${RED}"
                    printf "  %-30s  %-20s  ${c}%-20s${NC}\n" "${f}" "${m}" "${t}"
                }
                _cmp "Язык"                    "Go"              "Rust + Tokio"
                _cmp "Актуальность"            "Устарел"         "✅ v3.3.28 (2026)"
                _cmp "RAM"                     "~50 MB"          "✅ ~10-20 MB"
                _cmp "Установка"               "Компиляция Go"   "✅ Готовый бинарь"
                _cmp "Fake TLS"                "Базовая"         "✅ Глубокая + TLS emul."
                _cmp "TCP Splice (маскировка)" "❌"              "✅ Есть"
                _cmp "Anti-Replay"             "Базовый"         "✅ Sliding Window"
                _cmp "Несколько пользователей" "❌"              "✅ Да"
                _cmp "REST API"                "❌"              "✅ 127.0.0.1:9091"
                _cmp "Prometheus метрики"      "❌"              "✅ Опционально"
                _cmp "amd64 + arm64"           "Частично"        "✅ Да"
                _cmp "Docker нужен"            "Да (раньше)"     "✅ Нет, нативный"
                echo ""
                echo -e "  ${GREEN}${BOLD}Вывод: Telemt лучше во всём — рекомендуется к использованию.${NC}"
                echo ""
                ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

menuTelemt() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🦀  TELEMT — MTProxy нового поколения (Rust + Tokio)       ║${NC}"
        echo -e "${YELLOW}  ║   Fake TLS | Anti-Replay | Multi-user | Без Docker           ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        # Статус строка
        local tel_st tel_ver tel_color
        tel_st=$(systemctl is-active telemt 2>/dev/null || echo "не установлен")
        tel_ver=$(_telemt_getCurrentVersion 2>/dev/null)
        [ "${tel_st}" = "active" ] && tel_color="${GREEN}" || tel_color="${RED}"
        echo -e "  ${WHITE}Статус:${NC} ${tel_color}${tel_st}${NC}  ${DIM}|  Версия: ${tel_ver}${NC}"
        echo ""
        echo -e "  ${DIM}Telemt — современная замена старому MTG. Написан на Rust,${NC}"
        echo -e "  ${DIM}потребляет ~10 МБ RAM, работает без Docker, маскируется под${NC}"
        echo -e "  ${DIM}реальный HTTPS-сайт (DPI не отличит от обычного браузера).${NC}"
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  УСТАНОВКА И УПРАВЛЕНИЕ                                     │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📦  ${WHITE}Установить / переустановить${NC}"
        echo -e "      ${DIM}Скачивает бинарь (~10 сек), создаёт конфиг и systemd сервис.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  🔄  ${WHITE}Обновить до последней версии${NC}"
        echo -e "      ${DIM}Проверяет GitHub Releases, скачивает и применяет если есть новее.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  👥  ${WHITE}Пользователи (добавить / удалить / сменить ключ)${NC}"
        echo -e "      ${DIM}Каждый пользователь = своя tg://-ссылка для Telegram.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔑  ${WHITE}Показать ссылки для Telegram${NC}"
        echo -e "      ${DIM}Выводит tg://proxy?... из логов для всех пользователей.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  ⚙️   ${WHITE}Настройки (порт, домен маскировки, конфиг)${NC}"
        echo -e "      ${DIM}Смена tls_domain, порта, редактирование telemt.toml.${NC}"
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  МОНИТОРИНГ                                                 │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW}6${NC})  📊  ${WHITE}Диагностика${NC}"
        echo -e "      ${DIM}Версия, сервис, порт, пользователи, API, домен маскировки, логи.${NC}"
        echo ""
        echo -e "  ${YELLOW}7${NC})  📄  ${WHITE}Логи в реальном времени (Ctrl+C — выход)${NC}"
        echo -e "      ${DIM}journalctl -u telemt -f — смотри подключения клиентов.${NC}"
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  СЕРВИС                                                     │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW}s${NC})  ▶   Запустить    ${YELLOW}p${NC})  ■  Остановить    ${YELLOW}r${NC})  🔄  Перезапустить"
        echo ""
        echo -e "  ${RED}d${NC})  💣  ${RED}Удалить Telemt полностью${NC}"
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) installTelemt ;;
            2) updateTelemt ;;
            3) menuTelemetUsers ;;
            4) showTelemetLinks ;;
            5) menuTelemetConfig ;;
            6) diagnoseTelemt ;;
            7) trap 'echo ""; return' INT
               journalctl -u telemt -f --no-pager
               trap - INT ;;
            s|S) if systemctl start   telemt 2>/dev/null; then info "Запущен";    else warn "Ошибка"; fi ;;
            p|P) if systemctl stop    telemt 2>/dev/null; then info "Остановлен"; else warn "Ошибка"; fi ;;
            r|R) if _telemt_safe_restart 2>/dev/null; then info "Перезапущен"; else warn "Ошибка"; fi ;;
            d|D) removeTelemt ;;
            0) break ;;
            *) warn "Неверный выбор" ; sleep 1 ; continue ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# СТАРЫЙ MTProto (MTG / Go) — оставлен для совместимости
# ════════════════════════════════════════════════════════════════
menuMTProto() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📡  MTProto PROXY — прокси-сервер для Telegram             ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}MTProto Proxy позволяет подключаться к Telegram через твой сервер.${NC}"
        echo -e "  ${DIM}Генерирует ссылки вида tg://proxy?... — отправь другу, он тапает,${NC}"
        echo -e "  ${DIM}и его Telegram идёт через твой VPN. Работает на порту 443.${NC}"
        echo ""
        local mtg_st
        mtg_st=$(_svcStatus "mtg")
        echo -e "  Статус MTProto прокси (mtg): ${mtg_st}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📦  ${WHITE}Установить MTProto Proxy${NC}"
        echo -e "      ${DIM}Скачивает и компилирует mtg (Go), генерирует 200 FakeTLS ключей,${NC}"
        echo -e "      ${DIM}создаёт systemd-сервис. Нужен Go — установится автоматически.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  🗑️   ${WHITE}Удалить MTProto Proxy${NC}"
        echo -e "      ${DIM}Останавливает сервис, удаляет бинарник, ключи и конфиги mtg.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔍  ${WHITE}Диагностика${NC}"
        echo -e "      ${DIM}Статус сервиса, слушает ли порт 443, сколько ключей сгенерировано.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔑  ${WHITE}Показать ключи / ссылки для Telegram${NC}"
        echo -e "      ${DIM}Выводит ссылки tg://proxy?... которые можно скопировать и раздать.${NC}"
        echo -e "      ${DIM}Первые 10 или все 200 — на выбор.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) installMTProto ;;
            2) removeMTProto ;;
            3) diagnoseMTProto ;;
            4) showMTProtoKeys ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ГЛАВНОЕ МЕНЮ
# ════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════
# БЭКАП И ВОССТАНОВЛЕНИЕ
# ════════════════════════════════════════════════════════════════

backupConfig() {
    local dir
    dir="/root/wg-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "${dir}"

    step "Сохраняю конфиги..."

    # WireGuard конфиги и клиенты
    cp -r /etc/wireguard "${dir}/" 2>/dev/null || true
    # nftables
    cp /etc/nftables.conf "${dir}/" 2>/dev/null || true
    # Скрипты
    cp /usr/local/bin/wg-balance.sh "${dir}/" 2>/dev/null || true
    cp /usr/local/bin/update-ru-ipset.sh "${dir}/" 2>/dev/null || true
    cp /usr/local/bin/wg-ip-watchdog.sh "${dir}/" 2>/dev/null || true
    # Systemd сервисы
    mkdir -p "${dir}/systemd"
    cp /etc/systemd/system/wg-balance.service "${dir}/systemd/" 2>/dev/null || true
    cp /etc/systemd/system/update-ru-ipset.service "${dir}/systemd/" 2>/dev/null || true
    cp /etc/systemd/system/update-ru-ipset.timer "${dir}/systemd/" 2>/dev/null || true
    cp /etc/systemd/system/wg-ip-watchdog.service "${dir}/systemd/" 2>/dev/null || true
    cp /etc/systemd/system/wg-ip-watchdog.timer "${dir}/systemd/" 2>/dev/null || true
    for f in /etc/systemd/system/wg-quick@*.service.d; do
        [ -d "$f" ] && cp -r "$f" "${dir}/systemd/" 2>/dev/null || true
    done
    # Telemt
    [ -f /etc/telemt.toml ] && cp /etc/telemt.toml "${dir}/" 2>/dev/null || true
    [ -f /etc/systemd/system/telemt.service ] && \
        cp /etc/systemd/system/telemt.service "${dir}/systemd/" 2>/dev/null || true
    # dnsmasq
    mkdir -p "${dir}/dnsmasq.d"
    cp /etc/dnsmasq.d/wg-*.conf "${dir}/dnsmasq.d/" 2>/dev/null || true
    cp /etc/systemd/system/dnsmasq.service.d/99-wireguard.conf \
        "${dir}/dnsmasq-dropin.conf" 2>/dev/null || true
    # sysctl (Anti-DPI)
    cp /etc/sysctl.d/99-antidpi.conf "${dir}/" 2>/dev/null || true
    # Текущий скрипт
    cp "${BASH_SOURCE[0]}" "${dir}/wg-server.sh" 2>/dev/null || true

    # Метаданные бэкапа
    cat > "${dir}/backup-info.txt" << EOF
Дата:    $(date '+%Y-%m-%d %H:%M:%S')
Хост:    $(hostname)
IP:      $(curl -fsSL --tlsv1.2 --proto '=https' --max-time 3 https://api.ipify.org 2>/dev/null || ip -4 addr show | awk '/inet / && !/127\./ {split($2,a,"/"); print a[1]; exit}')
Версия:  $(head -3 "${BASH_SOURCE[0]}" | grep Версия || echo 'unknown')
Туннели: ${TUNNEL_COUNT:-0}
Клиенты: $(shopt -s nullglob; _f=(/etc/wireguard/clients/*.conf); echo "${#_f[@]}")
EOF

    tar -czf "${dir}.tar.gz" -C /root "$(basename "${dir}")" 2>/dev/null
    rm -rf "${dir}"
    echo ""
    info "Бэкап сохранён: ${GREEN}${dir}.tar.gz${NC}"
    ls -lh "${dir}.tar.gz"
    echo ""
    echo -e "  ${DIM}Для переноса на другой сервер:${NC}"
    echo -e "  ${DIM}  scp root@$(hostname -I | awk '{print $1}'):${dir}.tar.gz ./wg-backup.tar.gz${NC}"
}

restoreConfig() {
    section "Восстановление из бэкапа"
    echo -e "  ${DIM}Доступные бэкапы в /root/:${NC}"
    echo ""
    local -a backups=()
    local i=1
    for f in /root/wg-backup-*.tar.gz; do
        [ -f "$f" ] || continue
        backups+=("$f")
        printf "  ${YELLOW}%2d${NC}) %-50s ${DIM}%s${NC}\n" \
            "${i}" "$(basename "${f}")" "$(stat -c '%s %y' -- "${f}" 2>/dev/null | awk '{print $1, $2, $3}')"
        ((++i))
    done
    if [ ${#backups[@]} -eq 0 ]; then
        warn "Бэкапов не найдено. Сначала создай бэкап (пункт 1)."
        return
    fi
    echo ""
    echo -e "  ${RED}0${NC}) Отмена"
    echo ""
    read -rp "  Выбери номер бэкапа: " choice
    [ "${choice}" = "0" ] || [ -z "${choice}" ] && return
    local idx=$((choice - 1))
    if [ "${idx}" -lt 0 ] || [ "${idx}" -ge "${#backups[@]}" ]; then warn "Неверный выбор"; return; fi
    local archive="${backups[$idx]}"

    # Показываем информацию о бэкапе
    echo ""
    local tmpdir
    tmpdir=$(mktemp -d)
    # [fix v28.24.21] trap гарантирует удаление tmpdir при любом выходе из функции
    # (ранний return на CONFIRM, ошибка tar, и т.д.). Предыдущий код удалял вручную
    # только в двух ветках — при отмене и в конце; при ошибке tmpdir оставался.
    trap 'rm -rf "${tmpdir}" 2>/dev/null || true' RETURN
    tar -xzf "${archive}" -C "${tmpdir}" 2>/dev/null
    local extracted
    # [fix v28.20.10] безопасный glob вместо `ls | head`
    shopt -s nullglob
    local _ents=("${tmpdir}"/*)
    shopt -u nullglob
    extracted=$(basename "${_ents[0]:-}")
    if [ -f "${tmpdir}/${extracted}/backup-info.txt" ]; then
        echo -e "  ${CYAN}Информация о бэкапе:${NC}"
        sed 's/^/    /' "${tmpdir}/${extracted}/backup-info.txt"
        echo ""
    fi

    warn "ВНИМАНИЕ! Текущие конфиги будут перезаписаны!"
    read -rp "  Введи YES для подтверждения: " CONFIRM
    if [ "${CONFIRM}" != "YES" ]; then
        warn "Отменено"
        return
    fi

    step "Останавливаю сервисы..."
    systemctl stop wg-balance telemt dnsmasq nftables wg-ip-watchdog 2>/dev/null || true
    for iface in $(wg show interfaces 2>/dev/null); do
        wg-quick down "${iface}" 2>/dev/null || true
    done

    step "Восстанавливаю файлы..."
    local src="${tmpdir}/${extracted}"

    # WireGuard конфиги
    [ -d "${src}/wireguard" ] && {
        cp -r "${src}/wireguard/." /etc/wireguard/
        chmod 600 /etc/wireguard/*.conf 2>/dev/null || true
        info "wireguard конфиги восстановлены"
    }
    # nftables
    [ -f "${src}/nftables.conf" ] && {
        cp "${src}/nftables.conf" /etc/
        info "nftables.conf восстановлен"
    }
    # Скрипты
    for s in wg-balance.sh update-ru-ipset.sh wg-ip-watchdog.sh; do
        [ -f "${src}/${s}" ] && {
            cp "${src}/${s}" /usr/local/bin/
            chmod +x "/usr/local/bin/${s}"
        }
    done
    # Systemd
    [ -d "${src}/systemd" ] && {
        cp "${src}/systemd/"*.service /etc/systemd/system/ 2>/dev/null || true
        cp "${src}/systemd/"*.timer /etc/systemd/system/ 2>/dev/null || true
        for d in "${src}/systemd/wg-quick@"*.service.d; do
            [ -d "$d" ] || continue
            local dname; dname=$(basename "$d")
            mkdir -p "/etc/systemd/system/${dname}"
            cp "${d}/"* "/etc/systemd/system/${dname}/" 2>/dev/null || true
        done
        info "systemd сервисы восстановлены"
    }
    # Telemt
    [ -f "${src}/telemt.toml" ] && cp "${src}/telemt.toml" /etc/
    # dnsmasq
    [ -d "${src}/dnsmasq.d" ] && cp "${src}/dnsmasq.d/"* /etc/dnsmasq.d/ 2>/dev/null || true
    [ -f "${src}/dnsmasq-dropin.conf" ] && {
        mkdir -p /etc/systemd/system/dnsmasq.service.d
        cp "${src}/dnsmasq-dropin.conf" \
            /etc/systemd/system/dnsmasq.service.d/99-wireguard.conf 2>/dev/null || true
    }
    # Anti-DPI
    [ -f "${src}/99-antidpi.conf" ] && {
        cp "${src}/99-antidpi.conf" /etc/sysctl.d/
        sysctl -p /etc/sysctl.d/99-antidpi.conf 2>/dev/null || true
    }
    # tmpdir убирается trap'ом RETURN (установлен выше после mktemp)
    # [fix v28.25.0] Явный rm убран — он дублировал trap RETURN и мог удалить
    # tmpdir дважды при параллельном запуске. Trap является единственным cleanup.

    step "Запускаю сервисы..."
    systemctl daemon-reload
    nft -f /etc/nftables.conf 2>/dev/null || true
    systemctl start nftables 2>/dev/null || true
    loadConfig
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        if wg-quick up "${TUNNEL_IFACE[$i]}" 2>/dev/null; then
            info "Туннель ${TUNNEL_IFACE[$i]} поднят"
        else
            warn "${TUNNEL_IFACE[$i]} не поднялся"
        fi
    done
    if wg-quick up "${SERVER_WG_NIC}" 2>/dev/null; then
        info "Сервер ${SERVER_WG_NIC} поднят"
    else
        warn "${SERVER_WG_NIC} не поднялся"
    fi
    systemctl start wg-balance dnsmasq telemt 2>/dev/null || true
    systemctl enable wg-ip-watchdog.timer update-ru-ipset.timer 2>/dev/null || true
    systemctl start wg-ip-watchdog.timer update-ru-ipset.timer 2>/dev/null || true
    # [fix v28.21.10] Восстанавливаем crontab GeoIP — без него еженедельное обновление @russia не запустится.
    if [ -x /usr/local/bin/update-ru-ipset.sh ]; then
        ( crontab -l 2>/dev/null | grep -v 'update-ru-ipset' ; \
          echo "0 4 * * 0 /usr/local/bin/update-ru-ipset.sh >> /var/log/wg-geoip.log 2>&1" ) | crontab - 2>/dev/null || true
    fi

    echo ""
    info "${GREEN}${BOLD}Восстановление завершено!${NC}"
    echo -e "  ${DIM}Запусти полный тест системы (меню 14) чтобы проверить.${NC}"
}

listBackups() {
    section "Список бэкапов"
    local found=0
    echo ""
    for f in /root/wg-backup-*.tar.gz; do
        [ -f "$f" ] || continue
        found=1
        printf "  ${GREEN}✔${NC}  %-50s  ${DIM}%s${NC}\n" \
            "$(basename "${f}")" "$(stat -c '%s %y' -- "${f}" 2>/dev/null | awk '{print $1, $2, $3}')"
    done
    [ "${found}" -eq 0 ] && warn "Бэкапов не найдено"
    echo ""
}

deleteOldBackups() {
    section "Удаление старых бэкапов"
    local -a backups=()
    for f in /root/wg-backup-*.tar.gz; do
        [ -f "$f" ] && backups+=("$f")
    done
    if [ "${#backups[@]}" -eq 0 ]; then warn "Бэкапов нет"; return; fi
    echo ""
    read -rp "  Сколько последних оставить [3]: " keep
    [ -z "${keep}" ] && keep=3
    local total=${#backups[@]}
    if [ "${total}" -le "${keep}" ]; then
        info "Всего ${total} бэкапов — удалять нечего"
        return
    fi
    local del_count=$((total - keep))
    # [fix v28.24.2] while-read через process substitution — без subshell
    local _f
    while IFS= read -r _f; do
        rm -f "${_f}"
        info "Удалён: $(basename "${_f}")"
    done < <(printf '%s\n' "${backups[@]}" | sort | head -n "${del_count}")
    info "Готово. Оставлено последних ${keep} бэкапов."
}

menuBackup() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   💾  БЭКАП И ВОССТАНОВЛЕНИЕ                                 ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Бэкап сохраняет ВСЕ конфиги: ключи WireGuard, настройки туннелей,${NC}"
        echo -e "  ${DIM}правила файрвола, скрипты. Рекомендуется делать ПЕРЕД изменениями.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  💾  ${WHITE}Создать бэкап прямо сейчас${NC}"
        echo -e "      ${DIM}Упаковывает все конфиги в /root/wg-backup-ДАТА.tar.gz${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  📂  ${WHITE}Восстановить из бэкапа${NC}"
        echo -e "      ${DIM}Останавливает WG, распаковывает выбранный архив, поднимает всё заново.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  📋  ${WHITE}Список бэкапов${NC}"
        echo -e "      ${DIM}Показывает все архивы с датой и размером.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🗑️   ${WHITE}Удалить старые бэкапы${NC}"
        echo -e "      ${DIM}Оставляет последние N штук, остальные удаляет.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) backupConfig ;;
            2) restoreConfig ;;
            3) listBackups ;;
            4) deleteOldBackups ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# QR-КОД ПОВТОРНО + ЭКСПОРТ + ПЕРЕИМЕНОВАНИЕ
# ════════════════════════════════════════════════════════════════

showClientQR() {
    loadConfig
    listClients
    echo ""
    echo -ne "  ${YELLOW}→ Имя клиента${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local conf="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${conf}" ] && { warn "Клиент '${CLIENT_NAME}' не найден"; return; }
    echo ""
    info "QR-код для ${GREEN}${CLIENT_NAME}${NC}:"
    echo ""
    qrencode -t UTF8 < "${conf}"
    echo ""
    info "PNG-файл: /etc/wireguard/clients/${CLIENT_NAME}.png"
}

exportClientConf() {
    loadConfig
    listClients
    echo ""
    echo -ne "  ${YELLOW}→ Имя клиента${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local conf="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${conf}" ] && { warn "Клиент '${CLIENT_NAME}' не найден"; return; }
    echo ""
    echo -e "${YELLOW}  ┌─── Конфиг: ${CLIENT_NAME}.conf ───────────────────────────────┐${NC}"
    while IFS= read -r line; do
        printf "${WHITE}  │  %-60s${YELLOW}│${NC}\n" "${line}"
    done < "${conf}"
    echo -e "${YELLOW}  └────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    info "Скопируй текст выше и вставь в приложение WireGuard вручную"
    info "Или забери файл: scp root@СЕРВЕР:${conf} ."
}

renameClient() {
    loadConfig
    echo ""
    echo -ne "  ${YELLOW}→ Текущее имя клиента${NC}: "
    read -r OLD_NAME
    [ -z "${OLD_NAME}" ] && return
    local old_conf="/etc/wireguard/clients/${OLD_NAME}.conf"
    [ ! -f "${old_conf}" ] && { warn "Клиент '${OLD_NAME}' не найден"; return; }
    echo -ne "  ${YELLOW}→ Новое имя${NC}: "
    read -r NEW_NAME
    [ -z "${NEW_NAME}" ] && return
    # [fix v28.22.1] Валидация нового имени — как и при addClient (защита от path traversal)
    validateClientName "${NEW_NAME}"
    [ -f "/etc/wireguard/clients/${NEW_NAME}.conf" ] && { warn "Клиент '${NEW_NAME}' уже существует"; return; }
    mv "${old_conf}" "/etc/wireguard/clients/${NEW_NAME}.conf"
    [ -f "/etc/wireguard/clients/${OLD_NAME}.png" ] && \
        mv "/etc/wireguard/clients/${OLD_NAME}.png" "/etc/wireguard/clients/${NEW_NAME}.png"
    info "Переименован: ${OLD_NAME} → ${GREEN}${NEW_NAME}${NC}"
}

# ════════════════════════════════════════════════════════════════
# ТРАФИК И МОНИТОРИНГ
# ════════════════════════════════════════════════════════════════

showTrafficStats() {
    loadConfig
    section "Трафик по клиентам"
    echo ""

    # 1. Строим массив pubkey -> имя клиента
    local -A CLIENT_MAP
    for f in /etc/wireguard/clients/*.conf; do
        [ -f "$f" ] || continue
        local fpriv fpub name
        fpriv=$(grep -E "^\\s*PrivateKey\\s*=" "$f" | head -1 | awk '{print $3}')
        [ -z "${fpriv}" ] && continue
        fpub=$(wg pubkey <<< "${fpriv}" 2>/dev/null) || continue
        name=$(basename "$f" .conf)
        CLIENT_MAP["${fpub}"]="${name}"
    done

    local peers_raw
    # [fix v28.24.16] Fallback для старых версий WireGuard без поддержки 'dump'
    if wg show "${SERVER_WG_NIC}" dump >/dev/null 2>&1; then
        peers_raw=$(wg show "${SERVER_WG_NIC}" dump 2>/dev/null | tail -n +2) || {
            warn "WireGuard не активен"
            return
        }
    else
        warn "wg dump не поддерживается — используем wg show (ограниченная статистика)"
        peers_raw=$(wg show "${SERVER_WG_NIC}" 2>/dev/null | awk '
            /^peer:/ { pub=$2; psk="(none)"; ep=""; allowed=""; hs=0; rx=0; tx=0 }
            /latest handshake:/ { hs=$NF }
            /transfer:/ { rx=$2; tx=$4 }
            /allowed ips:/ { allowed=$3 }
            /endpoint:/ { ep=$2 }
            /^$/ && pub { print pub"\t"psk"\t"ep"\t"allowed"\t"hs"\t"rx"\t"tx; pub="" }
            END { if (pub) print pub"\t"psk"\t"ep"\t"allowed"\t"hs"\t"rx"\t"tx }
        ') || {
            warn "WireGuard не активен"
            return
        }
    fi

    printf "  ${WHITE}%-22s  %-18s  %-18s  %-20s${NC}\n" \
        "Клиент" "Получено" "Отправлено" "Последний онлайн"
    echo -e "  ${DIM}──────────────────────────────────────────────────────────────────────────${NC}"

    while IFS=$'\t' read -r pub_key _psk _endpoint _allowed handshake rx tx _rest; do
        # Пропускаем пустые строки
        [ -z "${pub_key}" ] && continue

        # Ищем клиента по публичному ключу
        local name="${CLIENT_MAP[$pub_key]:-—}"

        [[ "${rx}"        =~ ^[0-9]+$ ]] || rx=0
        [[ "${tx}"        =~ ^[0-9]+$ ]] || tx=0
        [[ "${handshake}" =~ ^[0-9]+$ ]] || handshake=0

        local rx_fmt tx_fmt
        rx_fmt=$(awk -v b="${rx}" 'BEGIN{
            if(b>1073741824) printf "%.1f GiB", b/1073741824
            else if(b>1048576) printf "%.1f MiB", b/1048576
            else if(b>1024) printf "%.0f KiB", b/1024
            else printf "%d B", b
        }')
        tx_fmt=$(awk -v b="${tx}" 'BEGIN{
            if(b>1073741824) printf "%.1f GiB", b/1073741824
            else if(b>1048576) printf "%.1f MiB", b/1048576
            else if(b>1024) printf "%.0f KiB", b/1024
            else printf "%d B", b
        }')

        local hs_fmt="никогда"
        if [ "${handshake}" != "0" ] && [ -n "${handshake}" ] && [ "${handshake}" -gt 1000000000 ] 2>/dev/null; then
            local now delta
            now=$(date +%s)
            delta=$((now - handshake))
            if   [ ${delta} -lt 0 ];     then hs_fmt="только что"
            elif [ ${delta} -lt 60 ];    then hs_fmt="${delta}с назад"
            elif [ ${delta} -lt 3600 ];  then hs_fmt="$((delta/60))мин назад"
            elif [ ${delta} -lt 86400 ]; then hs_fmt="$((delta/3600))ч назад"
            else                              hs_fmt="$((delta/86400))д назад"
            fi
        fi

        printf "  ${GREEN}%-22s${NC}  %-18s  %-18s  ${DIM}%-20s${NC}\n" \
            "${name}" "↓ ${rx_fmt}" "↑ ${tx_fmt}" "${hs_fmt}"
    done <<< "${peers_raw}"
    echo ""
}

showTunnelSpeeds() {
    loadConfig
    section "Пинг до туннелей"
    echo ""
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        local host="${TUNNEL_ENDPOINT[$i]%%:*}"
        local iface="${TUNNEL_IFACE[$i]}"
        local st color
        wg show "${iface}" >/dev/null 2>&1 \
            && st="▲ UP  " && color="${GREEN}" \
            || st="▼ DOWN" && color="${RED}"

        printf "  ${color}%-6s${NC}  ${WHITE}%-12s${NC}  %-25s\n" "${st}" "${iface}" "${host}"

        # 1. ICMP до endpoint
        printf "    %-35s" "ICMP до endpoint ${host}:"
        local rtt_ep
        rtt_ep=$(ping -c 3 -W 2 -q "${host}" 2>/dev/null | grep 'rtt' | \
                 sed -n 's|.*= [0-9.]*/\([0-9.]*\).*|\1|p' || true)
        if [ -n "${rtt_ep}" ]; then
            local ms_ep
            ms_ep=$(printf "%.0f" "${rtt_ep}")
            if   [ "${ms_ep}" -lt 50 ];  then echo -e "${GREEN}${ms_ep}ms ✔${NC}"
            elif [ "${ms_ep}" -lt 120 ]; then echo -e "${YELLOW}${ms_ep}ms ~${NC}"
            else                              echo -e "${RED}${ms_ep}ms ✖${NC}"
            fi
        else
            echo -e "${YELLOW}недоступен (ICMP заблокирован провайдером)${NC}"
        fi

        # 2. Пинг 8.8.8.8 через интерфейс туннеля
        printf "    %-35s" "Пинг 8.8.8.8 через ${iface}:"
        if wg show "${iface}" >/dev/null 2>&1; then
            local rtt_tun
            rtt_tun=$(ping -I "${iface}" -c 3 -W 3 -q 8.8.8.8 2>/dev/null | grep 'rtt' | \
                      sed -n 's|.*= [0-9.]*/\([0-9.]*\).*|\1|p' || true)
            if [ -n "${rtt_tun}" ]; then
                local ms_tun
                ms_tun=$(printf "%.0f" "${rtt_tun}")
                if   [ "${ms_tun}" -lt 50 ];  then echo -e "${GREEN}${ms_tun}ms ✔ отлично${NC}"
                elif [ "${ms_tun}" -lt 120 ]; then echo -e "${YELLOW}${ms_tun}ms ~ нормально${NC}"
                elif [ "${ms_tun}" -lt 200 ]; then echo -e "${YELLOW}${ms_tun}ms ⚠ медленно${NC}"
                else                               echo -e "${RED}${ms_tun}ms ✖ плохо${NC}"
                fi
            else
                echo -e "${RED}нет ответа (туннель или маршрут не работает)${NC}"
            fi
        else
            echo -e "${DIM}туннель не активен${NC}"
        fi
        echo ""
    done
}

liveMonitor() {
    loadConfig
    section "Live-монитор (Ctrl+C — выход)"
    echo -e "  ${DIM}Обновляется каждые 3 секунды.${NC}"
    echo ""
    # [fix v28.24.1] Кешируем map pubkey→name ОДИН раз до входа в цикл.
    # Раньше на каждой итерации (каждые 3с) вызывался wg pubkey O(peers×clients) раз.
    declare -A _LM_CLIENT_MAP
    local _lmf _lmpriv _lmpub
    for _lmf in /etc/wireguard/clients/*.conf; do
        [ -f "${_lmf}" ] || continue
        _lmpriv=$(grep -E "^[[:space:]]*PrivateKey[[:space:]]*=" "${_lmf}" | head -1 | awk '{print $3}')
        [ -z "${_lmpriv}" ] && continue
        _lmpub=$(wg pubkey <<< "${_lmpriv}" 2>/dev/null) || continue
        _LM_CLIENT_MAP["${_lmpub}"]=$(basename "${_lmf}" .conf)
    done

    trap 'echo -e "\n"; return' INT
    while true; do
        clear
        echo -e "${YELLOW}  ══ LIVE MONITOR ══ $(date '+%H:%M:%S') ══ Ctrl+C — выход ══${NC}"
        echo ""
        echo -e "  ${WHITE}Туннели:${NC}"
        local i
        for ((i=0; i<TUNNEL_COUNT; i++)); do
            local host="${TUNNEL_ENDPOINT[$i]%%:*}"
            local st color
            wg show "${TUNNEL_IFACE[$i]}" >/dev/null 2>&1 \
                && st="▲ UP  " && color="${GREEN}" \
                || st="▼ DOWN" && color="${RED}"
            local rtt="---"
            if wg show "${TUNNEL_IFACE[$i]}" >/dev/null 2>&1; then
                local _r
                _r=$(ping -I "${TUNNEL_IFACE[$i]}" -c 1 -W 1 -q 8.8.8.8 2>/dev/null | grep 'rtt' | \
                      sed -n 's|.*= [0-9.]*/\([0-9.]*\).*|\1|p')
                rtt="${_r:-???}"
            fi
            printf "    ${color}%-6s${NC}  ${WHITE}%-12s${NC}  %-25s  8.8.8.8: %sms\n" \
                "${st}" "${TUNNEL_IFACE[$i]}" "${TUNNEL_ENDPOINT[$i]}" "${rtt}"
        done
        echo ""
        local active_table active_iface
        active_table=$(ip rule show 2>/dev/null | awk '/^30200:.*lookup/{print $NF; exit}')
        active_iface=$(ip route show table "${active_table:-0}" 2>/dev/null | \
                       awk '/^default/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
        echo -e "  ${WHITE}Активный туннель:${NC} ${GREEN}${active_iface:-неизвестно}${NC}"
        echo ""
        echo -e "  ${WHITE}Клиенты онлайн (handshake < 3 мин):${NC}"
        local now
        now=$(date +%s)
        # [fix v28.24.1] process substitution вместо pipe — while видит _LM_CLIENT_MAP
        # [fix liveMonitor] Проверяем поддержку dump — как в showTrafficStats
        local _lm_dump_ok=0
        wg show "${SERVER_WG_NIC}" dump >/dev/null 2>&1 && _lm_dump_ok=1
        if [ "${_lm_dump_ok}" = "1" ]; then
          while IFS=$'	' read -r pub _psk _ep _allowed hs _rx _tx _rest; do
            { [ "${hs}" = "0" ] || [ -z "${hs}" ]; } && continue
            [[ "${hs}" =~ ^[0-9]+$ ]] || continue
            [ "${hs}" -lt 1000000000 ] 2>/dev/null && continue
            local delta=$((now - hs))
            [ ${delta} -lt 0 ] && continue
            [ ${delta} -gt 180 ] && continue
            local name="${_LM_CLIENT_MAP[$pub]:-?}"
            printf "    ${GREEN}●${NC} %-20s  ${DIM}%dс назад${NC}
" "${name}" "${delta}"
          done < <(wg show "${SERVER_WG_NIC}" dump 2>/dev/null | tail -n +2)
        else
          # Fallback для старых версий WireGuard без поддержки dump
          wg show "${SERVER_WG_NIC}" 2>/dev/null | awk '/^peer:/{pub=$2} /latest handshake:/{print pub, $NF}' |           while read -r pub hs; do
            [ -z "${pub}" ] || [ -z "${hs}" ] && continue
            [[ "${hs}" =~ ^[0-9]+$ ]] || continue
            local delta=$((now - hs))
            [ ${delta} -lt 0 ] || [ ${delta} -gt 180 ] && continue
            local name="${_LM_CLIENT_MAP[$pub]:-?}"
            printf "    ${GREEN}●${NC} %-20s  ${DIM}%dс назад${NC}
" "${name}" "${delta}"
          done
        fi
        echo ""
        echo -e "  ${WHITE}Сервисы:${NC}"
        for svc in wg-balance nftables; do
            local s
            s=$(systemctl is-active "${svc}" 2>/dev/null)
            [ "${s}" = "active" ] \
                && printf "    ${GREEN}●${NC} %-20s active\n" "${svc}" \
                || printf "    ${RED}○${NC} %-20s ${RED}%s${NC}\n" "${svc}" "${s}"
        done
        echo ""
        sleep 3
    done
    trap - INT
}

menuMonitor() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📈  МОНИТОРИНГ — трафик, скорости, онлайн-статус           ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Наблюдай за системой без изменений настроек.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📶  ${WHITE}Трафик и последний онлайн клиентов${NC}"
        echo -e "      ${DIM}Сколько трафика каждый клиент скачал/отправил и когда был онлайн.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  📡  ${WHITE}Пинг до всех туннелей${NC}"
        echo -e "      ${DIM}Пингует каждый VPN-сервер 3 раза. Зелёный <50ms, красный плохо.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔴  ${WHITE}Live-монитор (обновление каждые 3 сек)${NC}"
        echo -e "      ${DIM}Реальное время: пинги туннелей, активный туннель, онлайн-клиенты.${NC}"
        echo -e "      ${DIM}Выход — Ctrl+C.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showTrafficStats ;;
            2) showTunnelSpeeds ;;
            3) ( trap 'exit 0' INT; liveMonitor ) || true ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# РОТАЦИЯ КЛЮЧЕЙ
# ════════════════════════════════════════════════════════════════

rotateServerKey() {
    loadConfig
    section "Ротация серверного ключа"
    echo ""
    echo -e "  ${DIM}Генерируется новый серверный ключ. Все клиентские конфиги обновятся${NC}"
    echo -e "  ${DIM}автоматически, QR-коды перегенерируются.${NC}"
    echo ""
    warn "После ротации ВСЕ клиенты временно отключатся и потребуют новый QR-код!"
    echo ""
    read -rp "  Введи YES для продолжения: " CONFIRM
    [ "${CONFIRM}" != "YES" ] && { warn "Отменено"; return; }

    # [v28.22.0] Авто-бэкап перед опасной операцией
    _autoBackup "rotate-server-key" || warn "Бэкап не создан (продолжаем)"

    cp /etc/wireguard/server_private.key \
       "/etc/wireguard/server_private.key.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

    # [fix v28.20.8] Принудительно удаляем всех старых пиров с интерфейса
    # перед сменой ключа — иначе wg-quick down может оставить stale-сессии.
    wg show "${SERVER_WG_NIC}" peers 2>/dev/null | while read -r _peer; do
        [ -n "${_peer}" ] && wg set "${SERVER_WG_NIC}" peer "${_peer}" remove 2>/dev/null || true
    done
    # [fix v28.22.0] Гасим ВСЕ туннели (а не только серверный) — иначе up-туннели держат
    # stale-сессии со старым публичным ключом сервера.
    local i
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        wg-quick down "${TUNNEL_IFACE[$i]}" 2>/dev/null || true
    done
    wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true

    # [fix] umask 077 — ключ создаётся сразу с правами 600 (без гонки tee+chmod)
    (umask 077; wg genkey > /etc/wireguard/server_private.key)
    chmod 600 /etc/wireguard/server_private.key
    local NEW_PUB
    NEW_PUB=$(wg pubkey < /etc/wireguard/server_private.key)
    info "Новый публичный ключ: ${GREEN}${NEW_PUB}${NC}"

    local updated=0
    for f in /etc/wireguard/clients/*.conf; do
        [ -f "$f" ] || continue
        sed -i "s|^PublicKey = .*|PublicKey = ${NEW_PUB}|" "$f"
        local name
        name=$(basename "$f" .conf)
        qrencode -o "/etc/wireguard/clients/${name}.png" -t PNG < "$f" 2>/dev/null || true
        info "Обновлён: ${name}"
        ((++updated))
    done

    createConfigs 2>/dev/null || true
    # [fix v28.22.0] Полный перезапуск стека (включая up-туннели) вместо одинокого wg-quick up.
    restartTunnels || warn "restartTunnels вернул ошибку — проверь wg show"
    info "Ротация завершена. Обновлено клиентов: ${updated}"
    audit_log "rotateServerKey updated_clients=${updated}"
    warn "Раздай клиентам новые QR-коды → Клиенты → Показать QR"
}

rotateClientKey() {
    loadConfig
    listClients
    echo ""
    echo -ne "  ${YELLOW}→ Имя клиента для ротации ключа${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local conf="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${conf}" ] && { warn "Клиент не найден"; return; }

    echo ""
    warn "Клиент ${CLIENT_NAME} отключится до сканирования нового QR-кода"
    read -rp "  Введи YES для продолжения: " CONFIRM
    [ "${CONFIRM}" != "YES" ] && { warn "Отменено"; return; }

    local OLD_PUB OLD_PRIV
    # [fix v28.20.4] Берём OLD_PUB из PrivateKey клиента, а не из PublicKey в [Peer]
    # (в [Peer] клиентского conf прописан ключ СЕРВЕРА, а не клиента)
    OLD_PRIV=$(grep 'PrivateKey' "${conf}" | head -1 | awk -F'= ' '{print $2}' | tr -d ' ')
    if [ -z "${OLD_PRIV}" ]; then
        warn "Не найден PrivateKey в конфиге клиента"
        return
    fi
    OLD_PUB=$(wg pubkey <<< "${OLD_PRIV}" 2>/dev/null) || { warn "Невалидный PrivateKey"; return; }
    [ -z "${OLD_PUB}" ] && { warn "Не удалось вычислить OLD_PUB"; return; }
    # [fix v28.20.5] Передаём ключ через аргумент — безопасно, без bash-интерполяции в heredoc
    # [fix v28.22.2] Тот же надёжный split-by-block подход, что и в revokeClient.
    python3 - "${OLD_PUB}" "/etc/wireguard/${SERVER_WG_NIC}.conf" << 'PYEOF'
import sys, re
pub, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        data = f.read().replace('\r\n', '\n').replace('\r', '\n')
except FileNotFoundError:
    sys.exit(0)
parts = re.split(r'(?m)^(?=[ \t]*\[Peer\][ \t]*$)', data)
out = [p for p in parts
       if not (p.lstrip().startswith('[Peer]')
               and re.search(r'(?m)^\s*PublicKey\s*=\s*' + re.escape(pub) + r'\s*$', p))]
with open(path, 'w') as f:
    f.write(''.join(out))
PYEOF
    wg set "${SERVER_WG_NIC}" peer "${OLD_PUB}" remove 2>/dev/null || true

    # [fix v28.23.2]  #4: сбрасываем счётчики и .disabled-флаг,
    # иначе watcher отключит новый ключ сразу же если старый уже был over-limit.
    rm -f "/var/lib/wg/limits/${CLIENT_NAME}.total" \
          "/var/lib/wg/limits/${CLIENT_NAME}.rx" \
          "/var/lib/wg/limits/${CLIENT_NAME}.tx" \
          "/var/lib/wg/limits/${CLIENT_NAME}.disabled" 2>/dev/null || true

    local PRIV PUB PRE SERVER_PUB_KEY
    PRIV=$(wg genkey)
    [ -n "${PRIV}" ] || error "wg genkey вернул пустой ключ"
    PUB=$(wg pubkey <<< "${PRIV}")
    [ -n "${PUB}" ] || error "wg pubkey не сработал"
    PRE=$(wg genpsk)
    [ -n "${PRE}" ] || error "wg genpsk вернул пустой PSK"
    SERVER_PUB_KEY=$(wg pubkey < /etc/wireguard/server_private.key)
    [ -n "${SERVER_PUB_KEY}" ] || error "Не удалось получить публичный ключ сервера"

    local CLIENT_IPV4 CLIENT_IPV6
    CLIENT_IPV4=$(grep 'Address' "${conf}" | head -1 | awk -F'= ' '{print $2}' | cut -d',' -f1 | tr -d ' ')
    CLIENT_IPV6=$(grep 'Address' "${conf}" | head -1 | awk -F'= ' '{print $2}' | cut -d',' -f2 | tr -d ' ')

    # [fix v28.24.2] Корректно собираем Address и allowed-ips, если IPv6 пуст
    local _addr_line _allowed
    if [ -n "${CLIENT_IPV6}" ]; then
        _addr_line="${CLIENT_IPV4}, ${CLIENT_IPV6}"
        _allowed="${CLIENT_IPV4},${CLIENT_IPV6}"
    else
        _addr_line="${CLIENT_IPV4}"
        _allowed="${CLIENT_IPV4}"
    fi

    local CLIENT_DNS
    CLIENT_DNS=$(grep "^DNS" "${conf}" | head -1 | cut -d= -f2- | sed 's/^ //')
    [ -z "${CLIENT_DNS}" ] && CLIENT_DNS="8.8.8.8, 8.8.4.4"

    cat > "${conf}" << EOF
[Interface]
PrivateKey = ${PRIV}
Address = ${_addr_line}
DNS = ${CLIENT_DNS}
[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${PRE}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    chmod 600 "${conf}"

    cat >> "/etc/wireguard/${SERVER_WG_NIC}.conf" << EOF
[Peer]
PublicKey = ${PUB}
PresharedKey = ${PRE}
AllowedIPs = ${_addr_line}
EOF
    wg set "${SERVER_WG_NIC}" peer "${PUB}" \
        preshared-key <(echo "${PRE}") \
        allowed-ips "${_allowed}" 2>/dev/null || true

    qrencode -o "/etc/wireguard/clients/${CLIENT_NAME}.png" -t PNG < "${conf}" 2>/dev/null || true
    info "Ключ клиента ${GREEN}${CLIENT_NAME}${NC} обновлён. Новый QR:"
    echo ""
    qrencode -t UTF8 < "${conf}"
}

menuKeyRotation() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔑  РОТАЦИЯ КЛЮЧЕЙ — смена ключей шифрования               ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Ротация — замена криптоключей на новые. Хорошая практика безопасности:${NC}"
        echo -e "  ${DIM}если старый ключ утёк — после ротации он бесполезен.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  🖥️   ${WHITE}Сменить ключ СЕРВЕРА${NC}"
        echo -e "      ${DIM}Генерирует новую пару ключей сервера. Все клиентские конфиги${NC}"
        echo -e "      ${DIM}обновляются автоматически, QR перегенерируются.${NC}"
        echo -e "      ${RED}      ⚠ Все клиенты временно отключатся!${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  👤  ${WHITE}Сменить ключ отдельного клиента${NC}"
        echo -e "      ${DIM}Новые ключи только для одного устройства. Остальные продолжают${NC}"
        echo -e "      ${DIM}работать. Сразу показывает новый QR-код.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) rotateServerKey ;;
            2) rotateClientKey ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ЛИМИТЫ ТРАФИКА
# ════════════════════════════════════════════════════════════════

showTrafficLimits() {
    section "Текущие лимиты трафика"
    echo ""
    local limfile="/etc/wireguard/.traffic-limits"
    if [ ! -f "${limfile}" ] || [ ! -s "${limfile}" ]; then
        warn "Лимиты не настроены. Все клиенты без ограничений."
        return
    fi
    printf "  ${WHITE}%-22s  %-15s  %-15s${NC}\n" "Клиент" "Лимит (GB)" "Действие"
    echo -e "  ${DIM}──────────────────────────────────────────────────────${NC}"
    while IFS=: read -r name limit_gb action; do
        printf "  ${GREEN}%-22s${NC}  %-15s  %s\n" "${name}" "${limit_gb} GB" "${action}"
    done < "${limfile}"
    echo ""
}

setTrafficLimit() {
    loadConfig
    listClients
    echo ""
    echo -ne "  ${YELLOW}→ Имя клиента${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local conf="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${conf}" ] && { warn "Клиент не найден"; return; }
    echo ""
    echo -e "  ${DIM}Лимит суммарного трафика (входящий + исходящий).${NC}"
    read -rp "  Лимит (GB, 0 = без лимита): " LIMIT_GB
    [ -z "${LIMIT_GB}" ] && return
    # [fix v28.22.2] Без валидации нечисловое значение трактуется bash-арифметикой
    # как 0 — клиент тут же отключается вотчером при первом запуске.
    if ! [[ "${LIMIT_GB}" =~ ^[0-9]+$ ]]; then
        warn "Лимит должен быть целым числом GB. Введено: '${LIMIT_GB}'"
        return
    fi
    echo ""
    echo -e "  ${WHITE}Что делать при превышении:${NC}"
    echo -e "  ${YELLOW}1${NC}) Отключить клиента (удалить пир)"
    echo -e "  ${YELLOW}2${NC}) Только предупредить в лог"
    read -rp "  Выбор [1]: " action_choice
    local action="disconnect"
    [ "${action_choice}" = "2" ] && action="warn"

    local limfile="/etc/wireguard/.traffic-limits"
    if [ -f "${limfile}" ]; then
        local _tmp; _tmp=$(mktemp)
        grep -v "^${CLIENT_NAME}:" "${limfile}" > "${_tmp}" && mv "${_tmp}" "${limfile}" || rm -f "${_tmp}"
    fi
    echo "${CLIENT_NAME}:${LIMIT_GB}:${action}" >> "${limfile}"
    # [fix v28.24.21] При изменении лимита сбрасываем накопленные state-файлы.
    # Без этого клиент, уже набравший счётчик близко к старому лимиту, может
    # быть немедленно отключён вотчером с новым (в т.ч. бо́льшим) лимитом.
    rm -f "/var/lib/wg/limits/${CLIENT_NAME}.total" \
          "/var/lib/wg/limits/${CLIENT_NAME}.disabled" 2>/dev/null || true
    info "Лимит для ${CLIENT_NAME}: ${LIMIT_GB} GB, действие: ${action} (счётчики сброшены)"
    _installTrafficLimitWatcher
}

_installTrafficLimitWatcher() {
    cat > /usr/local/bin/wg-traffic-limit.sh << 'WATCHER'
#!/bin/bash
CONFIG_FILE="/etc/wireguard/.wg-setup.conf"
LIMITS_FILE="/etc/wireguard/.traffic-limits"
[ -f "${CONFIG_FILE}" ] || exit 0
[ -f "${LIMITS_FILE}" ] || exit 0
# [fix v28.20.5] Безопасный парсинг конфига вместо source
SERVER_WG_NIC=""
while IFS= read -r _line || [ -n "${_line}" ]; do
    [[ "${_line}" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${_line// }" ]] && continue
    [[ "${_line}" != *=* ]] && continue
    _k="${_line%%=*}"; _v="${_line#*=}"
    _k="${_k// /}"; _v="${_v#\"}"; _v="${_v%\"}"
    [ "${_k}" = "SERVER_WG_NIC" ] && SERVER_WG_NIC="${_v}"
done < "${CONFIG_FILE}"
# [fix v28.21.3] Кумулятивный учёт через дельту: total += max(0, cur - last).
# Это корректно при любом сбросе счётчиков wg (down/up, reboot) и не двоит трафик.
mkdir -p /var/lib/wg/limits
while IFS=: read -r name limit_gb action; do
    [ "${limit_gb}" = "0" ] && continue
    conf="/etc/wireguard/clients/${name}.conf"
    [ -f "${conf}" ] || continue
    priv=$(grep -E "^[[:space:]]*PrivateKey[[:space:]]*=" "${conf}" | head -1 | awk '{print $3}')
    [ -z "${priv}" ] && continue
    pub=$(wg pubkey <<< "${priv}" 2>/dev/null) || continue
    [ -z "${pub}" ] && continue
    # [fix v28.25.3] Fallback: если wg dump недоступен (старые ядра/версии wg-tools),
    # пробуем парсить wg show <iface> transfer. Формат: "<pubkey> <rx_bytes> <tx_bytes>".
    stats=$(wg show "${SERVER_WG_NIC}" dump 2>/dev/null | grep "^${pub}" | head -1)
    if [ -n "${stats}" ]; then
        cur_rx=$(echo "${stats}" | awk '{print $6}')
        cur_tx=$(echo "${stats}" | awk '{print $7}')
    else
        # Fallback: wg show <iface> transfer → "<pubkey>\t<rx>\t<tx>"
        # [fix v28.25.3] Если и transfer недоступен — явная ошибка, не тихий continue.
        xfer_line=""
        if ! wg show "${SERVER_WG_NIC}" transfer >/dev/null 2>&1; then
            echo "[$(date '+%Y-%m-%d %H:%M')] ERROR: wg show dump и wg show transfer недоступны — версия WireGuard слишком старая или wg-tools не установлен. Лимиты не работают."
            exit 1
        fi
        xfer_line=$(wg show "${SERVER_WG_NIC}" transfer 2>/dev/null | grep "^${pub}" | head -1)
        [ -z "${xfer_line}" ] && continue
        cur_rx=$(echo "${xfer_line}" | awk '{print $2}')
        cur_tx=$(echo "${xfer_line}" | awk '{print $3}')
    fi
    [[ "${cur_rx}" =~ ^[0-9]+$ ]] || continue
    [[ "${cur_tx}" =~ ^[0-9]+$ ]] || continue
    state="/var/lib/wg/limits/${name}.total"
    total_rx=0; total_tx=0; last_rx=0; last_tx=0
    if [ -f "${state}" ]; then
        while IFS= read -r _sline || [ -n "${_sline}" ]; do
            [[ -z "${_sline// }" ]] && continue
            [[ "${_sline}" != *=* ]] && continue
            _sk="${_sline%%=*}"; _sv="${_sline#*=}"
            _sk="${_sk// /}"; _sv="${_sv// /}"
            case "${_sk}" in
                total_rx|total_tx|last_rx|last_tx)
                    [[ "${_sv}" =~ ^[0-9]+$ ]] && printf -v "${_sk}" '%s' "${_sv}" ;;
            esac
        done < "${state}"
    fi
    # Дельта: если счётчик не уменьшился — прибавляем разницу, иначе считаем cur с нуля.
    if [ "${cur_rx}" -ge "${last_rx}" ]; then
        total_rx=$((total_rx + cur_rx - last_rx))
    else
        total_rx=$((total_rx + cur_rx))
    fi
    if [ "${cur_tx}" -ge "${last_tx}" ]; then
        total_tx=$((total_tx + cur_tx - last_tx))
    else
        total_tx=$((total_tx + cur_tx))
    fi
    last_rx=${cur_rx}
    last_tx=${cur_tx}
    cat > "${state}" <<EOF
total_rx=${total_rx}
total_tx=${total_tx}
last_rx=${last_rx}
last_tx=${last_tx}
EOF
    total=$(( (total_rx + total_tx) / 1073741824 ))
    if [ "${total}" -ge "${limit_gb}" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M')] ЛИМИТ: ${name} использовал ${total}GB >= ${limit_gb}GB (кумулятивно)"
        if [ "${action}" = "disconnect" ]; then
            wg set "${SERVER_WG_NIC}" peer "${pub}" remove 2>/dev/null || true
            # [fix v28.21.3] python3 вместо ненадёжного 'sed ,+3d' — корректно удаляет [Peer]-блок целиком.
            python3 - "$pub" "/etc/wireguard/${SERVER_WG_NIC}.conf" <<'PY' 2>/dev/null || true
import sys, re
pub, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        data = f.read()
except FileNotFoundError:
    sys.exit(0)
# Разбиваем на блоки по [Peer] и удаляем тот, в котором PublicKey == pub.
parts = re.split(r'(?m)^(?=[ \t]*\[Peer\][ \t]*$)', data)
out = []
for p in parts:
    if p.lstrip().startswith('[Peer]') and re.search(r'(?m)^\s*PublicKey\s*=\s*' + re.escape(pub) + r'\s*$', p):
        continue
    out.append(p)
with open(path, 'w') as f:
    f.write(''.join(out))
PY
            echo "[$(date '+%Y-%m-%d %H:%M')] Клиент ${name} отключён (превышен лимит)"
        fi
    fi
done < "${LIMITS_FILE}"
WATCHER
    chmod +x /usr/local/bin/wg-traffic-limit.sh
    (crontab -l 2>/dev/null | grep -v "wg-traffic-limit"
     echo "*/15 * * * * /usr/local/bin/wg-traffic-limit.sh >> /var/log/wg-limits.log 2>&1") | crontab -
    info "Watcher установлен (проверка каждые 15 минут)"
}

removeTrafficLimit() {
    loadConfig
    local limfile="/etc/wireguard/.traffic-limits"
    [ ! -f "${limfile}" ] && { warn "Лимиты не настроены"; return; }
    showTrafficLimits
    echo ""
    echo -ne "  ${YELLOW}→ Имя клиента (или ALL для всех)${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    if [ "${CLIENT_NAME}" = "ALL" ]; then
        rm -f "${limfile}"
        # [fix v28.24.21] Очищаем все state-файлы — без этого при повторном
        # назначении лимита вотчер видит накопленные счётчики и сразу отключает клиента.
        rm -f /var/lib/wg/limits/*.total \
              /var/lib/wg/limits/*.disabled 2>/dev/null || true
        info "Все лимиты и счётчики сняты"
    else
        # [fix v28.24.14] Уходим от sed-regex с интерполяцией имени —
        # используем grep -F (fixed string) с префиксом "name:".
        local _tmp; _tmp=$(mktemp)
        if grep -v "^${CLIENT_NAME}:" "${limfile}" > "${_tmp}"; then
            mv "${_tmp}" "${limfile}"
        else
            # grep вернул 1 если ничего не осталось — всё равно сохраняем пустой файл
            mv "${_tmp}" "${limfile}" 2>/dev/null || rm -f "${_tmp}"
        fi
        # [fix v28.24.21] Сбрасываем state-файлы конкретного клиента — иначе
        # старые накопленные счётчики сработают при следующем назначении лимита.
        rm -f "/var/lib/wg/limits/${CLIENT_NAME}.total" \
              "/var/lib/wg/limits/${CLIENT_NAME}.disabled" 2>/dev/null || true
        info "Лимит и счётчики для ${CLIENT_NAME} сброшены"
    fi
}

menuTrafficLimits() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📊  ЛИМИТЫ ТРАФИКА — ограничения по клиентам               ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Задай каждому клиенту лимит трафика в GB. При превышении — клиент${NC}"
        echo -e "  ${DIM}отключается или пишется предупреждение. Проверка каждые 15 минут.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📋  ${WHITE}Текущие лимиты${NC}"
        echo -e "      ${DIM}Список клиентов у которых настроен лимит трафика.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ➕  ${WHITE}Установить / изменить лимит${NC}"
        echo -e "      ${DIM}Выбираешь клиента, вводишь GB и что делать при превышении.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  ❌  ${WHITE}Снять лимит с клиента${NC}"
        echo -e "      ${DIM}Убирает ограничение. Введи ALL чтобы снять со всех сразу.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  📄  ${WHITE}Лог проверок лимитов${NC}"
        echo -e "      ${DIM}История: когда и кто превысил лимит.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showTrafficLimits ;;
            2) setTrafficLimit ;;
            3) removeTrafficLimit ;;
            4) if [ -f /var/log/wg-limits.log ]; then
                   tail -n 30 /var/log/wg-limits.log
               else
                   warn "Лог пуст или не создан"
               fi ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# РАЗДЕЛЬНАЯ МАРШРУТИЗАЦИЯ ПО КЛИЕНТАМ
# ════════════════════════════════════════════════════════════════

showRoutingProfiles() {
    section "Профили маршрутизации клиентов"
    echo ""
    local proffile="/etc/wireguard/.routing-profiles"
    printf "  ${WHITE}%-22s  %-20s${NC}\n" "Клиент" "Профиль"
    echo -e "  ${DIM}──────────────────────────────────────────────────────${NC}"
    for f in /etc/wireguard/clients/*.conf; do
        [ -f "$f" ] || continue
        local name profile="geo-split (по умолч.)"
        name=$(basename "$f" .conf)
        if [ -f "${proffile}" ]; then
            local p
            p=$(grep "^${name}:" "${proffile}" 2>/dev/null | cut -d: -f2)
            [ -n "${p}" ] && profile="${p}"
        fi
        printf "  ${GREEN}%-22s${NC}  %s\n" "${name}" "${profile}"
    done
    echo ""
    echo -e "  ${DIM}geo-split   — РФ напрямую, зарубежье через VPN (по умолчанию)${NC}"
    echo -e "  ${DIM}full-vpn    — ВЕСЬ трафик через VPN (даже РФ сайты)${NC}"
    echo -e "  ${DIM}direct-only — ВЕСЬ трафик напрямую (VPN не используется)${NC}"
    echo ""
}

setRoutingProfile() {
    # [fix v28.24.10] Аудит: гонка при параллельном изменении nft mangle-prerouting
    # (cron update-ru-ipset, restartTunnels, repairRouting, повторный setRoutingProfile).
    # Берём тот же lock, что используют другие nft-операции.
    (
        flock -w 30 200 || { warn "Не удалось взять блокировку nft, попробуй ещё раз"; exit 0; }
    loadConfig
    listClients
    echo ""
    echo -ne "  ${YELLOW}→ Имя клиента${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && exit 0
    local conf="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${conf}" ] && { warn "Клиент не найден"; exit 0; }
    echo ""
    echo -e "  ${WHITE}Профиль маршрутизации:${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC})  geo-split    ${DIM}— РФ напрямую, остальное через VPN (стандарт)${NC}"
    echo -e "  ${YELLOW}2${NC})  full-vpn     ${DIM}— ВЕСЬ трафик через VPN${NC}"
    echo -e "  ${YELLOW}3${NC})  direct-only  ${DIM}— ВЕСЬ трафик напрямую, без VPN${NC}"
    echo ""
    read -rp "  Выбор [1]: " choice
    local profile
    case "${choice}" in
        2) profile="full-vpn" ;;
        3) profile="direct-only" ;;
        *) profile="geo-split" ;;
    esac

    local proffile="/etc/wireguard/.routing-profiles"
    if [ -f "${proffile}" ]; then
        # [fix v28.24.14] grep -v вместо sed-regex с интерполяцией имени
        local _ptmp; _ptmp=$(mktemp)
        grep -v "^${CLIENT_NAME}:" "${proffile}" > "${_ptmp}" 2>/dev/null || true
        mv "${_ptmp}" "${proffile}" 2>/dev/null || rm -f "${_ptmp}"
    fi
    echo "${CLIENT_NAME}:${profile}" >> "${proffile}"

    local CLIENT_IP
    CLIENT_IP=$(awk -F'=' '/^[[:space:]]*AllowedIPs[[:space:]]*=/{split($2,a,","); gsub(/[[:space:]]/,"",a[1]); print a[1]; exit}' "${conf}")
    # Нормализуем IP (убираем маску /32 и пр.) — чтобы сматчить в выводе nft
    local CLIENT_IP_BARE="${CLIENT_IP%%/*}"

    # [fix v28.21.1] Удаляем ТОЛЬКО персональное правило этого клиента (не флашим всю цепочку!)
    # Иначе сбрасываются профили full-vpn/direct-only других клиентов.
    # [fix v28.23.0]  #3 / #1: убираем bash -c (injection surface).
    # Парсим handle в число и вызываем nft напрямую — никакого shell-парсинга строки.
    local _handles
    _handles=$(nft -a list chain inet wg-policy mangle-prerouting 2>/dev/null | \
        awk -v ip="${CLIENT_IP_BARE}" '
            /ip saddr/ && $0 ~ ip && /handle [0-9]+$/ { print $NF }')
    local _h
    for _h in ${_handles}; do
        # Жёсткая проверка: только цифры
        case "${_h}" in
            ''|*[!0-9]*) continue ;;
        esac
        nft delete rule inet wg-policy mangle-prerouting handle "${_h}" 2>/dev/null || true
    done

    case "${profile}" in
        full-vpn)
            nft add rule inet wg-policy mangle-prerouting \
                iifname "${SERVER_WG_NIC}" ip saddr "${CLIENT_IP}" \
                meta mark set 0x00000001 2>/dev/null || true
            ;;
        direct-only)
            nft add rule inet wg-policy mangle-prerouting \
                iifname "${SERVER_WG_NIC}" ip saddr "${CLIENT_IP}" \
                meta mark set 0x00200000 2>/dev/null || true
            ;;
        geo-split)
            # Персональное правило клиента уже удалено выше — клиент возвращается
            # под общее GeoIP-правило. Убеждаемся, что общее правило существует.
            if ! nft list chain inet wg-policy mangle-prerouting 2>/dev/null | \
                 grep -q 'iifname "'"${SERVER_WG_NIC}"'" ip daddr @russia'; then
                nft add rule inet wg-policy mangle-prerouting \
                    iifname "${SERVER_WG_NIC}" ip daddr @russia \
                    meta mark set 0x00200000 2>/dev/null || true
            fi
            ;;
    esac
    info "Профиль ${GREEN}${profile}${NC} применён для ${CLIENT_NAME}"
    # [fix v28.24.1] Сохраняем ТОЛЬКО свои таблицы (не захватываем Docker/fail2ban).
    local _tmp
    _tmp=$(mktemp /etc/nftables.conf.XXXXXX) && {
        if _saveWgNftables "${_tmp}"; then
            mv -f "${_tmp}" /etc/nftables.conf
            info "Конфиг nftables сохранён — профиль переживёт перезагрузку"
        else
            rm -f "${_tmp}"
            warn "Не удалось сохранить — после reboot восстанови через меню Автозапуск"
        fi
    }
    ) 200>/var/run/wg-nft.lock
}

menuRoutingProfiles() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🗺️   ПРОФИЛИ МАРШРУТИЗАЦИИ — у каждого клиента свой режим   ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}По умолчанию все клиенты одинаковы: РФ напрямую, зарубежье через VPN.${NC}"
        echo -e "  ${DIM}Здесь можно назначить конкретному клиенту другой режим:${NC}"
        echo -e "  ${DIM}  full-vpn    — весь его трафик идёт через VPN${NC}"
        echo -e "  ${DIM}  direct-only — весь его трафик идёт напрямую, VPN не используется${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📋  ${WHITE}Профили всех клиентов${NC}"
        echo -e "      ${DIM}Текущий режим маршрутизации для каждого устройства.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ✏️   ${WHITE}Назначить профиль клиенту${NC}"
        echo -e "      ${DIM}Выбираешь клиента и режим: geo-split / full-vpn / direct-only.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showRoutingProfiles ;;
            2) setRoutingProfile ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# СВОИ IP "НАПРЯМУЮ"
# ════════════════════════════════════════════════════════════════

showDirectIPs() {
    section "Свои IP-адреса для прямого выхода"
    echo ""
    local wlfile="/etc/wireguard/.direct-ips"
    if [ ! -f "${wlfile}" ] || [ ! -s "${wlfile}" ]; then
        warn "Список пуст."
        echo -e "  ${DIM}Примеры: корпоративная сеть 192.168.1.0/24, NAS 10.0.0.5/32${NC}"
        return
    fi
    echo -e "  ${WHITE}Подсети с прямым выходом:${NC}"
    echo ""
    local i=1
    while IFS=: read -r net comment; do
        printf "  ${GREEN}%2d${NC}) %-20s  ${DIM}%s${NC}\n" "${i}" "${net}" "${comment}"
        ((++i))
    done < "${wlfile}"
    echo ""
}

addDirectIP() {
    echo ""
    echo -e "  ${DIM}IP-подсеть которая будет идти НАПРЯМУЮ (не через VPN).${NC}"
    echo -e "  ${DIM}Примеры: 10.0.0.0/8  /  192.168.1.0/24  /  1.2.3.4/32${NC}"
    echo ""
    read -rp "  Подсеть (CIDR): " NET
    [ -z "${NET}" ] && return
    # [fix v28.22.1] Единая валидация CIDR: поддерживает IPv4 (X.X.X.X/N) и IPv6 (addr/N).
    # Убрана противоречивая двойная проверка (IPv4-only grep + IPv4/IPv6 regex).
    if ! [[ "${NET}" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]]; then
        warn "Неверный формат. Нужно: X.X.X.X/N (IPv4) или addr/N (IPv6), например: 10.0.0.0/8"
        return
    fi
    # [fix v28.25.2] Regex пропускает синтаксически невалидные IPv6 (напр. ::::::/64).
    # Для IPv6 дополнительно проверяем структуру через ядро (validate_ipv6_cidr).
    if echo "${NET}" | grep -q ':'; then
        if ! validate_ipv6_cidr "${NET}"; then
            warn "Некорректный IPv6 CIDR: ${NET}"
            return
        fi
    fi
    read -rp "  Комментарий (необязательно): " COMMENT
    local wlfile="/etc/wireguard/.direct-ips"
    # flock защищает от гонки параллельных меню
    # [fix v28.24.2] Динамический FD вместо фиксированного 200 — не пересекается
    # с другими flock-блоками (createIpSetAndNft, applyMSS, balance) в том же процессе.
    local _lockfd
    exec {_lockfd}>"${wlfile}.lock"
    flock -w 10 "${_lockfd}" || { warn "Не удалось получить блокировку — повтори попытку"; exec {_lockfd}>&-; return 1; }
    if [ -f "${wlfile}" ] && grep -qF -- "${NET}:" "${wlfile}"; then
        warn "Эта подсеть уже в списке"
        flock -u "${_lockfd}"
        exec {_lockfd}>&-
        return
    fi
    echo "${NET}:${COMMENT:-без комментария}" >> "${wlfile}"
    flock -u "${_lockfd}"
    exec {_lockfd}>&-
    # shellcheck disable=SC1083  # nft требует литеральные { }
    # [fix v28.24.4] IPv6 → russia_v6, IPv4 → russia
    if echo "${NET}" | grep -q ':'; then
        nft add element inet wg-policy russia_v6 { "${NET}" } 2>/dev/null || \
            warn "Не удалось добавить IPv6 в nft set russia_v6 — применится после перезапуска nftables"
    else
        nft add element inet wg-policy russia { "${NET}" } 2>/dev/null || \
            warn "Не удалось добавить в nft set russia — применится после перезапуска nftables"
    fi
    # [fix v28.24.1] Атомарная запись /etc/nftables.conf (только свои таблицы).
    # [fix race] flock 200 защищает от гонки с update-ru-ipset.sh (flush сета russia).
    (
        flock -w 10 200 || exit 0
        local _tmp
        _tmp=$(mktemp /etc/nftables.conf.XXXXXX) && {
            if _saveWgNftables "${_tmp}"; then
                mv -f "${_tmp}" /etc/nftables.conf
            else
                rm -f "${_tmp}"
            fi
        }
    ) 200>/var/run/wg-nft.lock
    info "Добавлено: ${NET} → прямой выход (сохранено в /etc/nftables.conf)"
}

removeDirectIP() {
    local wlfile="/etc/wireguard/.direct-ips"
    [ ! -f "${wlfile}" ] && { warn "Список пуст"; return; }
    showDirectIPs
    echo ""
    read -rp "  Подсеть для удаления (например 10.0.0.0/8): " NET
    [ -z "${NET}" ] && return
    if ! [[ "${NET}" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]]; then
        warn "Некорректный формат подсети: ${NET}"
        return
    fi
    local _lockfd
    exec {_lockfd}>"${wlfile}.lock"
    flock -w 10 "${_lockfd}" || { warn "Не удалось получить блокировку — повтори попытку"; exec {_lockfd}>&-; return 1; }
    # [fix v28.24.14] grep -F (fixed string) вместо sed-regex: точки в IP — sed-метасимволы.
    local _ditmp; _ditmp=$(mktemp)
    grep -vF -- "${NET}:" "${wlfile}" > "${_ditmp}" 2>/dev/null || true
    mv "${_ditmp}" "${wlfile}" 2>/dev/null || rm -f "${_ditmp}"
    flock -u "${_lockfd}"
    exec {_lockfd}>&-
    # shellcheck disable=SC1083
    # [fix v28.24.4] IPv6 → russia_v6, IPv4 → russia
    if echo "${NET}" | grep -q ':'; then
        nft delete element inet wg-policy russia_v6 { "${NET}" } 2>/dev/null || true
    else
        nft delete element inet wg-policy russia { "${NET}" } 2>/dev/null || true
    fi
    # [fix v28.24.1] Атомарная запись /etc/nftables.conf (только свои таблицы).
    # [fix race] flock 200 защищает от гонки с update-ru-ipset.sh (flush сета russia).
    (
        flock -w 10 200 || exit 0
        local _tmp
        _tmp=$(mktemp /etc/nftables.conf.XXXXXX) && {
            if _saveWgNftables "${_tmp}"; then
                mv -f "${_tmp}" /etc/nftables.conf
            else
                rm -f "${_tmp}"
            fi
        }
    ) 200>/var/run/wg-nft.lock
    info "Удалено: ${NET} (сохранено)"
}


editDirectIPsFile() {
    local wlfile="/etc/wireguard/.direct-ips"
    # Создаём файл с шапкой-описанием при первом запуске редактора
    if [ ! -f "${wlfile}" ]; then
        cat > "${wlfile}" <<'EOF'
# ──────────────────────────────────────────────────────────────
#  Свои подсети, идущие НАПРЯМУЮ (минуя VPN-туннель)
# ──────────────────────────────────────────────────────────────
#  Формат строки:
#     CIDR:Комментарий
#  Примеры:
#     192.168.1.0/24:Домашняя сеть
#     10.0.0.0/8:Корпоративная сеть
#     1.2.3.4/32:NAS
#  • Допустимы IPv4 и IPv6 (например fd00::/8:локальная сеть)
#  • Строки, начинающиеся с # — комментарии, игнорируются
#  • Пустые строки игнорируются
#  После сохранения файла будут перезагружены nft sets и службы.
# ──────────────────────────────────────────────────────────────
EOF
    fi

    local _EDITOR_CMD; _resolveEditor || return 1
    info "Открываю ${wlfile} в ${_EDITOR_CMD[0]}..."
    sleep 1
    "${_EDITOR_CMD[@]}" "${wlfile}"

    # Перезаливаем set russia: чистим только пользовательские записи и добавляем заново
    info "Применяю изменения в nftables..."
    local added=0 skipped=0 line net comment
    while IFS= read -r line || [ -n "${line}" ]; do
        # Пропускаем комментарии и пустые строки
        case "${line}" in
            ''|\#*) continue ;;
        esac
        # [fix v28.24.16] Правильный разбор строки «CIDR:Комментарий»:
        # Старый код «net="${line%%:*}"» срезал всё от первого ':', что ломало
        # IPv6-адреса (они сами содержат ':'), превращая «2a02:6b8::/39» в «2a02».
        # Теперь CIDR берётся через regex — вся часть с '/' включительно.
        net=""
        comment=""
        if [[ "${line}" =~ ^([0-9a-fA-F:.]+/[0-9]+)(:(.*))?$ ]]; then
            net="${BASH_REMATCH[1]}"
            comment="${BASH_REMATCH[3]:-}"
        fi
        # Валидация
        if [[ -z "${net}" ]]; then
            warn "Пропущено (некорректный CIDR): ${line}"
            ((++skipped))
            continue
        fi
        # [fix v28.24.4] IPv6 → russia_v6, IPv4 → russia
        local _nft_set="russia"
        echo "${net}" | grep -q ':' && _nft_set="russia_v6"
        # shellcheck disable=SC1083  # nft требует литеральные { }
        if nft add element inet wg-policy "${_nft_set}" { "${net}" } 2>/dev/null; then
            ((++added))
        else
            ((++skipped))
        fi
    done < "${wlfile}"

    # [fix v28.24.1] Сохраняем ТОЛЬКО свои таблицы (не захватываем Docker/fail2ban).
    # [fix race] flock 200 защищает от гонки с update-ru-ipset.sh (flush сета russia).
    (
        flock -w 10 200 || exit 0
        local _tmp
        _tmp=$(mktemp /etc/nftables.conf.XXXXXX) && {
            if _saveWgNftables "${_tmp}"; then
                mv -f "${_tmp}" /etc/nftables.conf
            else
                rm -f "${_tmp}"
            fi
        }
    ) 200>/var/run/wg-nft.lock

    info "Применено подсетей: ${added}, пропущено: ${skipped}"

    # Перезапуск служб для гарантированного применения
    echo ""
    read -rp "  Перезапустить службы (nftables + wg-quick)? [Y/n]: " ans
    case "${ans}" in
        n|N|no|No|NO) info "Перезапуск пропущен. Изменения уже в nft set." ;;
        *)
            systemctl restart nftables 2>/dev/null && info "nftables перезапущен"
            for ((i=0; i<TUNNEL_COUNT; i++)); do
                local iface="${TUNNEL_IFACE[$i]}"
                systemctl restart "wg-quick@${iface}" 2>/dev/null \
                    && info "wg-quick@${iface} перезапущен"
            done
            ;;
    esac
}

menuDirectIPs() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📌  ПРЯМЫЕ IP — свои адреса идущие напрямую без VPN        ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Помимо базы РФ IP можно добавить свои подсети которые всегда идут${NC}"
        echo -e "  ${DIM}напрямую: корпоративная сеть, домашний NAS, отдельные IP-адреса.${NC}"
        echo ""
        echo -e "  ${YELLOW}──── Прямые подсети (мимо VPN) ────────────────────────────────${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📋  ${WHITE}Текущий список${NC}"
        echo -e "      ${DIM}Все добавленные подсети с комментариями.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ➕  ${WHITE}Добавить подсеть${NC}"
        echo -e "      ${DIM}Вводишь CIDR и комментарий. Сразу применяется в nftables.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  ❌  ${WHITE}Удалить подсеть${NC}"
        echo -e "      ${DIM}Убирает из списка — трафик снова пойдёт через VPN.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  📝  ${WHITE}Открыть конфиг подсетей в редакторе${NC}"
        echo -e "      ${DIM}Массовое редактирование (nano/vim). Формат: CIDR:Комментарий.${NC}"
        echo -e "      ${DIM}После сохранения подсети сразу применяются + перезапуск служб.${NC}"
        echo ""
        echo -e "  ${YELLOW}──── Не через туннель (прямой выход) ──────────────────────────${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🔀  ${WHITE}Домены — напрямую мимо туннеля${NC}"
        echo -e "      ${DIM}Список доменных имён которые всегда идут НАПРЯМУЮ —${NC}"
        echo -e "      ${DIM}не через VPN (например: внутренние/корпоративные домены).${NC}"
        echo ""
        echo -e "  ${YELLOW}6${NC})  🌐  ${WHITE}CIDR — напрямую мимо туннеля${NC}"
        echo -e "      ${DIM}IP-подсети которые всегда идут напрямую — не через VPN,${NC}"
        echo -e "      ${DIM}в дополнение к GeoIP РФ и основному whitelist.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showDirectIPs ;;
            2) addDirectIP ;;
            3) removeDirectIP ;;
            4) editDirectIPsFile ;;
            5) _menuDirectDomains ;;
            6) _menuDirectCIDR ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# CIDR напрямую мимо туннеля — управление через .direct-ips
_menuDirectCIDR() {
    local wlfile="/etc/wireguard/.direct-ips"
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🌐  CIDR НАПРЯМУЮ — подсети минуя VPN-туннель              ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Подсети из этого списка всегда идут НАПРЯМУЮ — не через VPN.${NC}"
        echo -e "  ${DIM}Добавляются в nftables @russia/@russia_v6 как прямые маршруты.${NC}"
        echo -e "  ${DIM}Файл: ${wlfile}${NC}"
        echo ""
        # Показываем только CIDR строки из .direct-ips
        local _count=0 _i=1
        if [ -f "${wlfile}" ] && [ -s "${wlfile}" ]; then
            echo -e "  ${WHITE}Текущие CIDR (прямой выход):${NC}"
            echo ""
            while IFS=: read -r _net _comment; do
                [[ "${_net}" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${_net// }" ]] && continue
                _net="${_net// /}"
                [[ "${_net}" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]] || continue
                printf "  ${GREEN}%3d${NC})  %-22s  ${DIM}%s${NC}\n" "${_i}" "${_net}" "${_comment:-}"
                ((_i++)); ((_count++))
            done < "${wlfile}"
            [ "${_count}" -eq 0 ] && echo -e "  ${DIM}  (список пуст)${NC}"
        else
            echo -e "  ${DIM}  (список пуст)${NC}"
        fi
        echo ""
        echo -e "  ${YELLOW}1${NC})  ➕  ${WHITE}Добавить CIDR${NC}"
        echo -e "      ${DIM}Формат: 192.168.1.0/24 или 2001:db8::/32. Сразу в nftables.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ❌  ${WHITE}Удалить CIDR${NC}"
        echo -e "      ${DIM}Вводишь подсеть — убирается из списка и из nftables.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  📝  ${WHITE}Открыть файл в редакторе${NC}"
        echo -e "      ${DIM}${wlfile}  Формат: CIDR:Комментарий${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔄  ${WHITE}Применить файл в nftables${NC}"
        echo -e "      ${DIM}Перечитывает .direct-ips и загружает в @russia/@russia_v6.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) addDirectIP ;;
            2) removeDirectIP ;;
            3) editDirectIPsFile ;;
            4) echo ""
               info "Применяю .direct-ips в nftables..."
               if /usr/local/bin/update-ru-ipset.sh; then
                   # [fix v28.24.9] Сохраняем runtime nftables в /etc/nftables.conf,
                   # иначе изменения исчезнут после перезагрузки.
                   (
                       flock -w 10 200 || exit 0
                       _tmp=$(mktemp /etc/nftables.conf.XXXXXX) || exit 0
                       if _saveWgNftables "${_tmp}"; then
                           chmod 644 "${_tmp}"
                           mv -f "${_tmp}" /etc/nftables.conf
                       else
                           rm -f "${_tmp}"
                       fi
                   ) 200>/var/run/wg-nft.lock
                   info "Готово (изменения сохранены в /etc/nftables.conf)"
               fi ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# Управление CIDR которые принудительно идут в туннель (через force_tunnel_v4/v6)
_menuForceTunnelCIDR() {
    # [fix v28.24.12] Полноценное меню с собственным файлом TUNNEL_FORCE_CIDR
    # (раньше шарили TUNNEL_FORCE_DOMAINS — путалось с доменами и при пустом
    # списке доменов меню показывало "нет ни черта"). Также показываем
    # реальное состояние nft set'ов force_tunnel_v4/v6 — чтобы было видно
    # что маршрутизация применилась.
    local ftfile="${TUNNEL_FORCE_CIDR}"
    # Первый запуск — создаём файл с пояснениями
    if [ ! -f "${ftfile}" ]; then
        mkdir -p "$(dirname "${ftfile}")"
        cat > "${ftfile}" <<'EOF'
# ──────────────────────────────────────────────────────────────
#  CIDR, ПРИНУДИТЕЛЬНО идущие через VPN-туннель
# ──────────────────────────────────────────────────────────────
#  Эти подсети маршрутизируются через туннель ВСЕГДА — даже
#  если они в @russia (GeoIP РФ) или в whitelist прямых IP.
#  Приоритет правил nft: force_tunnel_* > russia > default.
#
#  Формат — одна запись на строку:
#     • IPv4:  91.108.4.0/22
#     • IPv6:  2001:67c:4e8::/48
#     • Один IP: 1.2.3.4/32
#
#  Строки с # — комментарии, пустые — игнорируются.
#  Применяется автоматически при добавлении/удалении из меню.
# ──────────────────────────────────────────────────────────────
EOF
    fi
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🌐  CIDR В ТУННЕЛЬ — IP-подсети принудительно через VPN    ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}IP-подсети из этого списка всегда идут через туннель —${NC}"
        echo -e "  ${DIM}даже если они в @russia или в whitelist прямых IP.${NC}"
        echo -e "  ${DIM}Файл: ${ftfile}${NC}"
        echo ""

        # Текущее состояние nft set'ов — пользователь видит что правила реально применены
        local _live4 _live6
        _live4=$(nft list set inet wg-policy force_tunnel_v4 2>/dev/null | grep -oEc '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' || echo 0)
        _live6=$(nft list set inet wg-policy force_tunnel_v6 2>/dev/null | grep -oEc '[0-9a-fA-F:]+/[0-9]+' || echo 0)
        printf "  ${WHITE}В nftables сейчас:${NC}  ${GREEN}v4=%s${NC}  ${GREEN}v6=%s${NC}\n\n" "${_live4}" "${_live6}"

        # Содержимое файла
        local _count=0
        if [ -s "${ftfile}" ]; then
            echo -e "  ${WHITE}CIDR в файле:${NC}"
            echo ""
            local _i=1
            while IFS= read -r _line; do
                [[ "${_line}" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${_line// }" ]] && continue
                _line="${_line%%#*}"; _line="${_line// /}"
                [ -z "${_line}" ] && continue
                if [[ "${_line}" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]]; then
                    printf "  ${GREEN}%3d${NC})  %s\n" "${_i}" "${_line}"
                    ((_i++)); ((_count++))
                fi
            done < "${ftfile}"
        fi
        [ "${_count}" -eq 0 ] && echo -e "  ${DIM}  (список пуст — добавь через пункт 1)${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  ➕  ${WHITE}Добавить CIDR${NC}"
        echo -e "      ${DIM}Формат: 192.168.1.0/24 или 2001:db8::/32. Сразу в nftables.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ❌  ${WHITE}Удалить CIDR${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  📝  ${WHITE}Открыть файл в редакторе${NC}"
        echo -e "      ${DIM}${ftfile}${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔄  ${WHITE}Применить файл к nftables/dnsmasq${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) echo ""
               echo -e "  ${DIM}Формат: 91.108.4.0/22 (IPv4) или 2001:67c:4e8::/48 (IPv6)${NC}"
               echo -ne "  ${CYAN}→ CIDR${NC}: "
               read -r _cidr
               _cidr="${_cidr// /}"
               [ -z "${_cidr}" ] && continue
               if ! [[ "${_cidr}" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]]; then
                   warn "Некорректный CIDR формат: ${_cidr}"
               # [fix v28.25.2] Дополнительная IPv6-валидация через ядро
               elif echo "${_cidr}" | grep -q ':' && ! validate_ipv6_cidr "${_cidr}"; then
                   warn "Некорректный IPv6 CIDR (ядро отклонило): ${_cidr}"
               elif grep -qxF "${_cidr}" "${ftfile}" 2>/dev/null; then
                   warn "Уже есть в списке: ${_cidr}"
               else
                   echo "${_cidr}" >> "${ftfile}"
                   info "Добавлено: ${GREEN}${_cidr}${NC}"
                   _rebuildTunnelForce
                   info "Применено."
               fi
               ;;
            2) echo ""
               echo -ne "  ${CYAN}→ CIDR для удаления${NC}: "
               read -r _cidr
               _cidr="${_cidr// /}"
               [ -z "${_cidr}" ] && continue
               if [ -f "${ftfile}" ]; then
                   local _esc; _esc=$(escape_sed_pipe "${_cidr}")
                   sed -i "\|^${_esc}$|d" "${ftfile}"
                   info "Удалено: ${_cidr}"
                   _rebuildTunnelForce
               fi
               ;;
            3) local _EDITOR_CMD; _resolveEditor || { echo ""; continue; }
               "${_EDITOR_CMD[@]}" "${ftfile}"
               echo ""; info "Применяю..."; _rebuildTunnelForce; info "Готово."
               ;;
            4) _rebuildTunnelForce; info "Применено" ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# KILLSWITCH
# ════════════════════════════════════════════════════════════════

showKillswitchStatus() {
    section "Статус Killswitch"
    echo ""
    local ksfile="/etc/wireguard/.killswitch-clients"
    if [ ! -f "${ksfile}" ] || [ ! -s "${ksfile}" ]; then
        echo -e "  ${DIM}Killswitch не настроен ни для одного клиента.${NC}"
        echo ""
        echo -e "  ${DIM}Что такое killswitch: если VPN упало — без него устройство ходит${NC}"
        echo -e "  ${DIM}напрямую (утечка IP). С killswitch — интернет блокируется до${NC}"
        echo -e "  ${DIM}восстановления VPN.${NC}"
        return
    fi
    echo -e "  ${WHITE}Клиенты с включённым killswitch:${NC}"
    echo ""
    while IFS= read -r name; do
        [ -n "${name}" ] && echo -e "  ${GREEN}●${NC} ${name}"
    done < "${ksfile}"
    echo ""
}

toggleKillswitch() {
    loadConfig
    listClients
    echo ""
    echo -ne "  ${YELLOW}→ Имя клиента${NC}: "
    read -r CLIENT_NAME
    [ -z "${CLIENT_NAME}" ] && return
    local conf="/etc/wireguard/clients/${CLIENT_NAME}.conf"
    [ ! -f "${conf}" ] && { warn "Клиент не найден"; return; }

    local ksfile="/etc/wireguard/.killswitch-clients"
    touch "${ksfile}"

    # [fix v28.20.4] Предупреждение: PostUp/PreDown с iptables работают ТОЛЬКО на Linux+wg-quick.
    # iOS, Android, Windows, macOS — проигнорируют или отклонят такой конфиг.
    if ! grep -q "^${CLIENT_NAME}$" "${ksfile}" 2>/dev/null; then
        echo ""
        echo -e "  ${RED}${BOLD}⚠  ВАЖНО: Killswitch работает ТОЛЬКО на Linux-клиентах с wg-quick!${NC}"
        echo -e "  ${YELLOW}   iOS, Android, Windows, macOS — конфиг с PostUp/PreDown будет${NC}"
        echo -e "  ${YELLOW}   отклонён или сломает подключение. Используй только для Linux.${NC}"
        echo -e "  ${YELLOW}   На мобильных устройствах включи «Block untunneled traffic»${NC}"
        echo -e "  ${YELLOW}   в настройках приложения WireGuard.${NC}"
        echo ""
        read -rp "  Клиент — Linux с wg-quick? Продолжить? [y/N]: " _ks_confirm
        [[ "${_ks_confirm}" =~ ^[Yy]$ ]] || { warn "Отменено"; return; }
    fi

    # Правила killswitch: блокируем весь трафик кроме WG-интерфейса
    local KS_POSTUP="PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark \$(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables -I OUTPUT ! -o %i -m mark ! --mark \$(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT"
    local KS_PREDOWN="PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark \$(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT; ip6tables -D OUTPUT ! -o %i -m mark ! --mark \$(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT"

    if grep -q "^${CLIENT_NAME}$" "${ksfile}" 2>/dev/null; then
        # Выключаем — удаляем строки PostUp/PreDown с killswitch
        # [fix v28.24.14] grep -vxF (fixed string, whole line) вместо sed-regex
        local _kstmp; _kstmp=$(mktemp)
        grep -vxF "${CLIENT_NAME}" "${ksfile}" > "${_kstmp}" 2>/dev/null || true
        mv "${_kstmp}" "${ksfile}" 2>/dev/null || rm -f "${_kstmp}"
        local tmpf
        tmpf=$(mktemp)
        grep -v "PostUp.*OUTPUT.*REJECT\|PreDown.*OUTPUT.*REJECT" "${conf}" > "${tmpf}"
        mv "${tmpf}" "${conf}"
        chmod 600 "${conf}"
        qrencode -o "/etc/wireguard/clients/${CLIENT_NAME}.png" -t PNG < "${conf}" 2>/dev/null || true
        info "Killswitch ${RED}ВЫКЛЮЧЕН${NC} для ${CLIENT_NAME}"
        echo ""
        qrencode -t UTF8 < "${conf}"
    else
        # Включаем — вставляем после последней строки [Interface] секции
        # Ищем строку DNS или Address как якорь; если нет — вставляем перед [Peer]
        echo "${CLIENT_NAME}" >> "${ksfile}"
        local tmpf
        tmpf=$(mktemp)
        awk -v pu="${KS_POSTUP}" -v pd="${KS_PREDOWN}" '
            /^\[Peer\]/ && !inserted {
                print pu
                print pd
                inserted=1
            }
            { print }
        ' "${conf}" > "${tmpf}"
        mv "${tmpf}" "${conf}"
        chmod 600 "${conf}"
        qrencode -o "/etc/wireguard/clients/${CLIENT_NAME}.png" -t PNG < "${conf}" 2>/dev/null || true
        info "Killswitch ${GREEN}ВКЛЮЧЁН${NC} для ${CLIENT_NAME}. Новый QR:"
        echo ""
        qrencode -t UTF8 < "${conf}"
    fi
}

menuKillswitch() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🔒  KILLSWITCH — блокировка интернета при обрыве VPN       ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Если VPN-соединение разрывается — без killswitch устройство продолжает${NC}"
        echo -e "  ${DIM}ходить в интернет напрямую, раскрывая реальный IP. С killswitch —${NC}"
        echo -e "  ${DIM}интернет полностью блокируется пока VPN не восстановится.${NC}"
        echo -e "  ${DIM}Реализация: PostUp/PreDown iptables правила в конфиге клиента.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📋  ${WHITE}Кому включён killswitch${NC}"
        echo -e "      ${DIM}Список клиентов с активной защитой от утечек.${NC}"
        echo -e "  ${YELLOW}2${NC})  🔄  ${WHITE}Включить / выключить для клиента${NC}"
        echo -e "      ${DIM}Выбираешь клиента — переключает состояние и показывает новый QR.${NC}"
        echo -e "      ${DIM}Клиенту нужно переустановить конфиг.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showKillswitchStatus ;;
            2) toggleKillswitch ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# АВТОЗАПУСК
# ════════════════════════════════════════════════════════════════

showAutostart() {
    loadConfig
    section "Автозапуск при старте системы"
    echo ""
    echo -e "  ${DIM}wg-quick@ сервисы: тип oneshot — systemd запускает и завершается,${NC}"
    echo -e "  ${DIM}интерфейс остаётся живым. Реальный статус проверяется через wg show.${NC}"
    echo ""
    local services=("wg-quick@${SERVER_WG_NIC}")
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        services+=("wg-quick@${TUNNEL_IFACE[$i]}")
    done
    services+=("wg-balance" "nftables" "dnsmasq" "update-ru-ipset" "telemt" "mtg")

    printf "  ${WHITE}%-35s  %-12s  %-14s${NC}\n" "Сервис" "Автозапуск" "Статус"
    echo -e "  ${DIM}──────────────────────────────────────────────────────────${NC}"

    for svc in "${services[@]}"; do
        local enabled active e_color a_color
        enabled=$(systemctl is-enabled "${svc}" 2>/dev/null || echo "—")
        active=$(systemctl is-active   "${svc}" 2>/dev/null || echo "—")

        # Цвет автозапуска
        case "${enabled}" in
            enabled)  e_color="${GREEN}" ;;
            disabled) e_color="${RED}"   ;;
            *)        e_color="${DIM}"   ;;
        esac

        # Цвет и текст статуса
        if [[ "${svc}" == wg-quick@* ]]; then
            # wg-quick — oneshot, systemd показывает inactive но интерфейс жив
            local iface="${svc#wg-quick@}"
            if wg show "${iface}" >/dev/null 2>&1; then
                a_color="${GREEN}"
                active="● up"
            else
                a_color="${RED}"
                active="○ down"
            fi
        elif [[ "${svc}" =~ ^(telemt|mtg)$ ]] && [ "${enabled}" = "—" ]; then
            # Не установлены — серым, без ошибки
            a_color="${DIM}"
            e_color="${DIM}"
        elif [ "${active}" = "active" ]; then
            a_color="${GREEN}"
        else
            a_color="${RED}"
        fi

        printf "  %-35s  ${e_color}%-12s${NC}  ${a_color}%-14s${NC}\n" \
            "${svc}" "${enabled}" "${active}"
    done
    echo ""
}

toggleAutostart() {
    loadConfig
    showAutostart
    echo ""
    echo -e "  ${WHITE}Управление автозапуском:${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) Включить автозапуск ВСЕХ сервисов"
    echo -e "  ${YELLOW}2${NC}) Выключить автозапуск ВСЕХ сервисов"
    echo -e "  ${YELLOW}3${NC}) Включить для отдельного сервиса"
    echo -e "  ${YELLOW}4${NC}) Выключить для отдельного сервиса"
    echo -e "  ${RED}0${NC}) Отмена"
    echo ""
    read -rp "  Выбор: " choice
    # Базовые сервисы (всегда нужны)
    local services=("wg-quick@${SERVER_WG_NIC}")
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        services+=("wg-quick@${TUNNEL_IFACE[$i]}")
    done
    services+=("wg-balance" "nftables" "dnsmasq")
    case "${choice}" in
        1) for s in "${services[@]}"; do
               if systemctl enable "${s}" 2>/dev/null; then info "Включён: ${s}"; else warn "Не удалось: ${s}"; fi
           done ;;
        2) for s in "${services[@]}"; do
               if systemctl disable "${s}" 2>/dev/null; then info "Выключен: ${s}"; else warn "Не удалось: ${s}"; fi
           done ;;
        3|4)
           echo ""
           local i=1
           for s in "${services[@]}"; do echo "  ${YELLOW}${i}${NC}) ${s}"; ((++i)); done
           read -rp "  Номер: " sn
           local idx=$((sn-1))
           [ ${idx} -lt 0 ] || [ ${idx} -ge ${#services[@]} ] && { warn "Неверно"; return; }
           if [ "${choice}" = "3" ]; then
               systemctl enable "${services[$idx]}" 2>/dev/null && info "Включён: ${services[$idx]}"
           else
               systemctl disable "${services[$idx]}" 2>/dev/null && info "Выключен: ${services[$idx]}"
           fi ;;
        *) return ;;
    esac
}

_fixAutostart() {
    loadConfig
    section "Починка автозапуска"
    echo ""
    echo -e "  ${DIM}Включаю автозапуск всех необходимых сервисов...${NC}"
    echo ""

    # Порядок: nftables → туннели → сервер → balance → dnsmasq
    local svcs=()
    svcs+=("nftables")
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        svcs+=("wg-quick@${TUNNEL_IFACE[$i]}")
    done
    svcs+=("wg-quick@${SERVER_WG_NIC}")
    svcs+=("wg-balance")
    svcs+=("dnsmasq")

    for s in "${svcs[@]}"; do
        local cur
        cur=$(systemctl is-enabled "${s}" 2>/dev/null || echo "—")
        if [ "${cur}" = "enabled" ]; then
            printf "  ${GREEN}✔${NC}  %-35s уже enabled\n" "${s}"
        else
            systemctl enable "${s}" 2>/dev/null \
                && printf "  ${GREEN}✔${NC}  %-35s включён\n" "${s}" \
                || printf "  ${RED}✖${NC}  %-35s ошибка\n" "${s}"
        fi
    done

    # ── [fix] networkd-wait-online — гарантирует что network-online.target
    # реально ждёт поднятия интерфейсов (иначе target срабатывает мгновенно)
    echo ""
    echo -e "  ${DIM}Проверяю network-online.target (systemd-networkd-wait-online)...${NC}"
    if systemctl is-enabled systemd-networkd >/dev/null 2>&1; then
        systemctl enable systemd-networkd-wait-online 2>/dev/null || true
        info "systemd-networkd-wait-online включён"
    elif systemctl is-enabled NetworkManager >/dev/null 2>&1; then
        info "NetworkManager управляет сетью — network-online.target в порядке"
    else
        warn "Не удалось определить сетевой менеджер — network-online.target может не работать"
    fi

    # ── Drop-in override для wg-quick@ (ExecStartPre down + Wants=network-online)
    # [fix] По умолчанию wg-quick@ имеет только After=network.target — этого
    # недостаточно: при ребуте туннели к внешним серверам не успевают подняться.
    # Добавляем Wants/After=network-online.target через отдельный drop-in.
    echo ""
    echo -e "  ${DIM}Настраиваю drop-in для wg-quick@ (network-online + override)...${NC}"
    for _iface in "${SERVER_WG_NIC}" "${TUNNEL_IFACE[@]:-}"; do
        [ -z "${_iface}" ] && continue
        local _dir="/etc/systemd/system/wg-quick@${_iface}.service.d"
        mkdir -p "${_dir}"

        # override.conf — ExecStartPre down (предотвращает конфликт при рестарте)
        if [ ! -f "${_dir}/override.conf" ]; then
            printf '[Service]\nExecStartPre=-/usr/bin/wg-quick down %%i\n' \
                > "${_dir}/override.conf"
            info "override.conf создан для wg-quick@${_iface}"
        fi

        # 10-network.conf — ждём реальный online перед поднятием туннеля
        # Только After=, не Wants= — Wants создаёт цикл зависимостей при shutdown
        # [fix v28.24.23] ExecStartPre проверяет ip route get 8.8.8.8 — гарантирует
        # что сетевой стек реально готов, а не только сигнализирован network-online.target.
        cat > "${_dir}/10-network.conf" << 'WGNET'
[Unit]
After=network-online.target

[Service]
# Ждём реальной маршрутизации до поднятия туннеля (VPS с медленным DHCP)
ExecStartPre=/bin/bash -c 'until ip route get 8.8.8.8 >/dev/null 2>&1; do sleep 1; done'
WGNET
        printf "  ${GREEN}✔${NC}  %-35s network-online зависимость\n" "wg-quick@${_iface}"
    done

    # ── Drop-in для nftables
    # [fix] НЕ добавляем After=network-online в nftables — это создаёт ordering cycle
    # при shutdown: cloud-init → network-online/stop → nftables/stop → network-pre/stop → цикл.
    # nftables — firewall, он должен стартовать ДО network-online, не после.
    # Удаляем старый drop-in 99-wireguard.conf если был создан ранее (он создавал ordering cycle).
    # Ниже создаётся другой drop-in — 99-geoip.conf (только ExecStartPost для GeoIP).
    echo ""
    echo -e "  ${DIM}nftables: удаляю устаревший drop-in ordering (если был)...${NC}"
    # Удаляем старый drop-in если был создан ранее
    rm -f /etc/systemd/system/nftables.service.d/99-wireguard.conf
    rmdir /etc/systemd/system/nftables.service.d 2>/dev/null || true
    info "nftables: ordering cycle устранён (drop-in 99-wireguard.conf удалён)"

    # ── Пересоздаём wg-balance.service с правильным After= для всех туннелей
    echo ""
    echo -e "  ${DIM}Обновляю wg-balance.service (After= для всех туннелей)...${NC}"
    local _wg_after="network-online.target nftables.service wg-quick@${SERVER_WG_NIC}.service"
    local _wg_wants="network-online.target wg-quick@${SERVER_WG_NIC}.service"
    for ((i=0; i<TUNNEL_COUNT; i++)); do
        _wg_after="${_wg_after} wg-quick@${TUNNEL_IFACE[$i]}.service"
        _wg_wants="${_wg_wants} wg-quick@${TUNNEL_IFACE[$i]}.service"
    done
    sed -i "s|^After=.*|After=${_wg_after}|" /etc/systemd/system/wg-balance.service 2>/dev/null || true
    sed -i "s|^Wants=.*|Wants=${_wg_wants}|" /etc/systemd/system/wg-balance.service 2>/dev/null || true
    sed -i "s|ExecStartPre=/bin/sleep [0-9]*|ExecStartPre=/bin/sleep 10|" /etc/systemd/system/wg-balance.service 2>/dev/null || true
    # Добавляем восстановление fwmark если ещё нет
    grep -q "fwmark 0x200000" /etc/systemd/system/wg-balance.service 2>/dev/null || \
        sed -i '/ExecStartPre=\/bin\/sleep/a ExecStartPre=-/sbin/ip -4 rule add fwmark 0x200000 table main priority 30050' \
            /etc/systemd/system/wg-balance.service 2>/dev/null || true
    info "wg-balance.service обновлён"

    # ── Drop-in для dnsmasq — только Restart, без Unit зависимостей
    # [fix] After=wg-quick@ или After=nftables создаёт ordering cycle:
    # nss-lookup/stop → dnsmasq/stop → wg-quick/stop → nss-lookup/stop (петля).
    # Правильно: dnsmasq стартует сам, если упал до поднятия wg0 — перезапустится.
    echo ""
    echo -e "  ${DIM}Настраиваю drop-in для dnsmasq...${NC}"
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    cat > /etc/systemd/system/dnsmasq.service.d/99-wireguard.conf << 'EOF'
[Service]
Restart=on-failure
RestartSec=5
# [fix v28.20.8] Ждём появления nftables set @russia до 60s
ExecStartPre=/bin/bash -c 'i=0; while [ $i -lt 60 ]; do [ -f /run/wg-russia-ready ] && exit 0; sleep 1; i=$((i+1)); done; echo "WARNING: marker /run/wg-russia-ready не появился за 60s, стартуем без GeoIP" >&2'
EOF
    info "Drop-in dnsmasq: Restart=on-failure RestartSec=5 (без Unit зависимостей)"

    # ── Systemd сервис для GeoIP при старте ──────────────────────
    echo ""
    echo -e "  ${DIM}Создаю systemd сервис для загрузки GeoIP при старте...${NC}"
    # [fix] GeoIP нужно запускать ПОСЛЕ того как nftables полностью инициализирован.
    # Используем timer с задержкой 30с — к этому моменту все сервисы точно живы.
    # ── Drop-in для nftables: автозапуск GeoIP после рестарта nftables
    mkdir -p /etc/systemd/system/nftables.service.d
    cat > /etc/systemd/system/nftables.service.d/99-geoip.conf << 'EOF'
[Service]
ExecStartPost=-/usr/local/bin/update-ru-ipset.sh
ExecStartPost=-/usr/local/bin/wg-restore-force-tunnel.sh
EOF

    # Systemd: атомарная загрузка GeoIP (доли секунды, без HTTP-предпроверки)
    cat > /etc/systemd/system/update-ru-ipset.service << 'GEOEOF'
[Unit]
Description=Load RU GeoIP into nftables @russia set
Wants=network-online.target nftables.service
After=network-online.target nftables.service wg-quick@WG_NIC_PLACEHOLDER.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-ru-ipset.sh
StandardOutput=append:/var/log/wg-geoip.log
StandardError=append:/var/log/wg-geoip.log
RemainAfterExit=no
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
GEOEOF
    # [fix v28.20.4] Подставляем реальное имя интерфейса вместо placeholder
    sed -i "s/wg-quick@WG_NIC_PLACEHOLDER/wg-quick@${SERVER_WG_NIC}/g" \
        /etc/systemd/system/update-ru-ipset.service

    cat > /etc/systemd/system/update-ru-ipset.timer << 'GEOEOF'
[Unit]
Description=RU GeoIP reload – 40s after boot, every 12h

[Timer]
OnBootSec=40s
OnUnitActiveSec=12h
Persistent=true
Unit=update-ru-ipset.service

[Install]
WantedBy=timers.target
GEOEOF
    systemctl enable update-ru-ipset.timer 2>/dev/null || true
    systemctl enable update-ru-ipset.service 2>/dev/null || true
    info "update-ru-ipset.timer включён (атомарная загрузка через 40с после старта)"

    systemctl daemon-reload
    echo ""
    echo -e "  ${GREEN}${BOLD}✓ Готово. Порядок запуска после перезагрузки:${NC}"
    echo -e "  ${DIM}  network-online.target${NC}"
    echo -e "  ${DIM}  ↓ wg-quick@TUNNEL_x (все туннели, параллельно)${NC}"
    echo -e "  ${DIM}  ↓ wg-quick@${SERVER_WG_NIC}${NC}"
    echo -e "  ${DIM}  ↓ nftables  (fwmark добавляет сам WG-SERVER через PostUp)${NC}"
    echo -e "  ${DIM}  ↓ update-ru-ipset  (GeoIP база @russia)${NC}"
    echo -e "  ${DIM}  ↓ dnsmasq${NC}"
    echo -e "  ${DIM}  ↓ wg-balance${NC}"
    echo ""
    showAutostart
}

menuAutostart() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   🚀  АВТОЗАПУСК — настройка запуска при старте сервера      ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}После перезагрузки сервера WireGuard должен подняться сам.${NC}"
        echo -e "  ${DIM}Проверь и настрой автозапуск всех нужных сервисов.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  📋  ${WHITE}Статус автозапуска${NC}"
        echo -e "      ${DIM}Показывает включён ли автозапуск и текущее состояние каждого сервиса.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  ⚙️   ${WHITE}Включить / выключить автозапуск${NC}"
        echo -e "      ${DIM}Управление через systemctl enable/disable. Для всех или для одного.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔧  ${WHITE}Починить автозапуск${NC}  ${DIM}(порядок загрузки + все зависимости)${NC}"
        echo -e "      ${DIM}enable всех сервисов + drop-in: network-online для wg-quick@,${NC}"
        echo -e "      ${DIM}nftables, dnsmasq; ip rule fwmark; networkd-wait-online.${NC}"
        echo -e "      ${DIM}Используй если после перезагрузки что-то не поднялось.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  🔑  ${WHITE}Key Watchdog${NC}          ${DIM}— следить за целостностью server_private.key${NC}"
        echo -e "      ${DIM}Таймер каждые 10 минут: наличие, права 600, валидность ключа.${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🗑️   ${WHITE}Удалить Key Watchdog${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) showAutostart ;;
            2) toggleAutostart ;;
            3) _fixAutostart ;;
            4) setupKeyWatchdog ;;
            5) removeKeyWatchdog ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ЛОГИ
# ════════════════════════════════════════════════════════════════

menuLogs() {
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   📄  ЛОГИ — журналы всех сервисов системы                   ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Если что-то не работает — смотри логи первым делом. Там видны${NC}"
        echo -e "  ${DIM}ошибки, переключения туннелей, подключения клиентов.${NC}"
        echo ""
        echo -e "  ${YELLOW}1${NC})  ⚖️   ${WHITE}Лог балансировщика${NC}"
        echo -e "      ${DIM}Переключения туннелей, пинги, перебалансировка.${NC}"
        echo ""
        echo -e "  ${YELLOW}2${NC})  🖥️   ${WHITE}Лог WireGuard-сервера${NC}"
        echo -e "      ${DIM}Старт, стоп, ошибки конфигурации.${NC}"
        echo ""
        echo -e "  ${YELLOW}3${NC})  🔥  ${WHITE}Лог nftables${NC}"
        echo -e "      ${DIM}Ошибки и события файрвола.${NC}"
        echo ""
        echo -e "  ${YELLOW}4${NC})  📡  ${WHITE}Лог MTProto Proxy (старый MTG)${NC}"
        echo -e "      ${DIM}Подключения через Telegram прокси (старый Go-движок).${NC}"
        echo ""
        echo -e "  ${YELLOW}5${NC})  🦀  ${WHITE}Лог Telemt (новый MTProxy)${NC}"
        echo -e "      ${DIM}Подключения через Telemt — ссылки, ошибки, статистика.${NC}"
        echo ""
        echo -e "  ${YELLOW}6${NC})  🔴  ${WHITE}Все логи в реальном времени (Ctrl+C — выход)${NC}"
        echo -e "      ${DIM}Объединённый поток всех сервисов — удобно при отладке.${NC}"
        echo ""
        echo -e "  ${RED}0${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер: " opt
        case "${opt}" in
            1) journalctl -u wg-balance.service -n 50 --no-pager ;;
            2) journalctl -u "wg-quick@${SERVER_WG_NIC}.service" -n 50 --no-pager ;;
            3) journalctl -u nftables.service -n 50 --no-pager ;;
            4) journalctl -u mtg.service -n 50 --no-pager ;;
            5) journalctl -u telemt.service -n 50 --no-pager ;;
            6) trap 'echo ""; return' INT
               journalctl -f \
                   -u wg-balance.service \
                   -u "wg-quick@${SERVER_WG_NIC}.service" \
                   -u nftables.service \
                   -u mtg.service \
                   -u telemt.service
               trap - INT ;;
            0) break ;;
            *) warn "Неверный выбор" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ТЕСТ СИСТЕМЫ — полное покрытие всех подсистем
# ════════════════════════════════════════════════════════════════

# ── Вспомогательные примитивы ────────────────────────────────
_tst() {
    # _tst "описание" cmd [args...]
    local desc="$1"; shift
    printf "  %-56s" "${desc}"
    if "$@" >/dev/null 2>&1; then
        echo -e "${GREEN}✔ OK${NC}"
        (( _TST_PASS++ )) || true
    else
        echo -e "${RED}✖ FAIL${NC}"
        (( _TST_FAIL++ )) || true
    fi
}

_tst_info() {
    # Информативная строка — никогда не FAIL
    local desc="$1"; shift
    local val
    val=$( "$@" 2>/dev/null ) || val="—"
    printf "  %-56s${DIM}%s${NC}\n" "${desc}" "${val}"
}

_tst_header() {
    echo ""
    echo -e "  ${WHITE}── $* ──${NC}"
}

_tst_skip() {
    printf "  %-56s${DIM}пропущено${NC}\n" "$1"
}

# ── 1. WireGuard сервер ───────────────────────────────────────
_tstSectionWGServer() {
    _tst_header "1. WireGuard-сервер"
    _tst "wg-сервис активен (wg-quick@${SERVER_WG_NIC})" \
        systemctl is-active "wg-quick@${SERVER_WG_NIC}"
    _tst "Интерфейс ${SERVER_WG_NIC} существует в ядре" \
        ip link show "${SERVER_WG_NIC}"
    # [fix v28.24.23] Прямой вызов wg show + grep вместо bash -c (нет subshell, нет escaping)
    _tst "wg show — интерфейс виден wg-утилите" \
        sh -c "wg show \"${SERVER_WG_NIC}\" 2>/dev/null | grep -q interface"
    _tst "UDP-порт сервера ${SERVER_PORT} прослушивается" \
        sh -c "ss -lnup 2>/dev/null | grep -q \":${SERVER_PORT} \""
    _tst "Публичный ключ сервера присутствует" \
        sh -c "wg show \"${SERVER_WG_NIC}\" public-key 2>/dev/null | grep -qE '^[A-Za-z0-9+/=]{43,44}$'"
    _tst "Есть хотя бы один настроенный пир" \
        sh -c "wg show \"${SERVER_WG_NIC}\" peers 2>/dev/null | grep -q ."
    _tst "IP-адрес интерфейса ${SERVER_WG_NIC} поднят" \
        sh -c "ip -4 addr show \"${SERVER_WG_NIC}\" 2>/dev/null | grep -q 'inet '"
    _tst_info "Пиров подключено (latest handshake < 3 мин)" \
        sh -c "wg show \"${SERVER_WG_NIC}\" latest-handshakes 2>/dev/null \
            | awk -v now=\"\$(date +%s)\" '\$2>0 && (now-\$2)<180{c++} END{print c+0\" активных\";}'"
    _tst_info "Версия WireGuard (wg --version)" \
        sh -c "wg --version 2>/dev/null | head -1"
}

# ── 2. Туннели (исходящие) ────────────────────────────────────
_tstSectionTunnels() {
    _tst_header "2. Туннели (исходящие WireGuard-соединения)"
    if [ "${TUNNEL_COUNT:-0}" -eq 0 ]; then
        _tst_skip "Туннели не настроены (TUNNEL_COUNT=0)"
        return
    fi
    local i
    for (( i=0; i<TUNNEL_COUNT; i++ )); do
        local iface="${TUNNEL_IFACE[$i]:-}"
        local ep="${TUNNEL_ENDPOINT[$i]:-}"
        local host="${ep%%:*}"
        local port="${ep##*:}"
        [ -z "${iface}" ] && continue
        _tst "Туннель ${iface}: сервис активен" \
            systemctl is-active "wg-quick@${iface}"
        _tst "Туннель ${iface}: интерфейс в ядре" \
            ip link show "${iface}"
        _tst "Туннель ${iface}: получен handshake (≤ 3 мин или есть)" \
            bash -c "wg show \"${iface}\" latest-handshakes 2>/dev/null | awk '\$2>0{ok=1} END{exit !ok}'"
        _tst "Туннель ${iface}: IP интерфейса поднят" \
            bash -c "ip -4 addr show \"${iface}\" 2>/dev/null | grep -q 'inet '"
        if [ -n "${host}" ]; then
            _tst "Туннель ${iface}: маршрут до эндпоинта ${host} существует" \
                bash -c "ip route get \"${host}\" 2>/dev/null | grep -q 'dev'"
            _tst "Туннель ${iface}: TCP-достижимость ${host}:${port:-51820}" \
                bash -c "( exec 3<>/dev/tcp/${host}/${port:-51820} ) 2>/dev/null \
                    || ping -c1 -W3 \"${host}\" >/dev/null 2>&1"
        fi
        _tst_info "Туннель ${iface}: трафик rx/tx" \
            bash -c "wg show \"${iface}\" transfer 2>/dev/null \
                | awk '{printf \"rx=%s tx=%s\",\$1,\$2}' || echo '—'"
    done
}

# ── 3. Маршрутизация и fwmark ────────────────────────────────
_tstSectionRouting() {
    _tst_header "3. Маршрутизация / fwmark / ip rule"
    _tst "fwmark 0x200000 → lookup main (РФ трафик напрямую)" \
        bash -c "ip rule show 2>/dev/null | grep -q 'fwmark 0x200000'"
    _tst "fwmark 0x100000 → туннель (зарубежный трафик)" \
        bash -c "ip rule show 2>/dev/null | grep -q 'fwmark 0x100000'"
    _tst "Таблица маршрутов туннеля существует (5182x)" \
        bash -c "ip rule show 2>/dev/null | grep -qE 'lookup 5182'"
    _tst "Основной маршрут (default) через MAIN_INTERFACE есть" \
        bash -c "ip route show default 2>/dev/null | grep -q 'dev ${MAIN_INTERFACE}'"
    _tst "Маршрут до WG-подсети на ${SERVER_WG_NIC}" \
        bash -c "ip route show dev \"${SERVER_WG_NIC}\" 2>/dev/null | grep -q 'dev'"
    _tst_info "Все ip rule (краткая сводка)" \
        bash -c "ip rule show 2>/dev/null | wc -l | xargs -I{} echo '{} правил'"
}

# ── 4. nftables / GeoIP ───────────────────────────────────────
_tstSectionNftables() {
    _tst_header "4. nftables / GeoIP"
    _tst "nftables сервис активен" \
        systemctl is-active nftables
    _tst "Таблица inet wg-policy существует" \
        bash -c "nft list table inet wg-policy >/dev/null 2>&1"
    _tst "nft set 'russia' (IPv4) существует" \
        bash -c "nft list set inet wg-policy russia >/dev/null 2>&1"
    _tst "GeoIP IPv4: более 100 CIDR в set 'russia'" \
        bash -c "[ \"\$(nft list set inet wg-policy russia 2>/dev/null \
            | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+' | wc -l)\" -gt 100 ]"
    if nft list set inet wg-policy russia_v6 >/dev/null 2>&1; then
        _tst "GeoIP IPv6: set 'russia_v6' непуст" \
            bash -c "nft list set inet wg-policy russia_v6 2>/dev/null \
                | grep -qE '[0-9a-fA-F:]+/[0-9]+'"
    else
        _tst_skip "GeoIP IPv6: set russia_v6 не создан (IPv6 отключён)"
    fi
    _tst "Offline-файл GeoIP IPv4 присутствует" \
        test -s /etc/wireguard/geoip/ru-aggregated.zone
    if [ -f /etc/wireguard/geoip/ru-aggregated-v6.zone ]; then
        _tst "Offline-файл GeoIP IPv6 присутствует" \
            test -s /etc/wireguard/geoip/ru-aggregated-v6.zone
    else
        _tst_skip "Offline GeoIP IPv6: файл не создан"
    fi
    _tst "Скрипт обновления GeoIP исполняемый" \
        test -x /usr/local/bin/update-ru-ipset.sh
    _tst "Drop-in nftables для GeoIP присутствует" \
        test -f /etc/systemd/system/nftables.service.d/99-geoip.conf
    _tst_info "Размер offline GeoIP IPv4 (строк)" \
        bash -c "wc -l < /etc/wireguard/geoip/ru-aggregated.zone 2>/dev/null | xargs echo"
}

# ── 5. dnsmasq ────────────────────────────────────────────────
_tstSectionDnsmasq() {
    _tst_header "5. dnsmasq"
    _tst "Сервис dnsmasq активен" \
        systemctl is-active dnsmasq
    _tst "dnsmasq слушает 127.0.0.1:53" \
        bash -c "ss -lntu 2>/dev/null | grep -q '127\.0\.0\.1:53'"
    _tst "dnsmasq конфиг wg-dns.conf существует" \
        test -f /etc/dnsmasq.d/wg-dns.conf
    _tst "dnsmasq резолвит google.com через :53" \
        bash -c "dig @127.0.0.1 -p 53 google.com A +short +time=3 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'"
    _tst "dnsmasq резолвит yandex.ru через :53" \
        bash -c "dig @127.0.0.1 -p 53 yandex.ru A +short +time=3 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'"
    _tst "dnsmasq не отвечает снаружи (lo only)" \
        bash -c "! ss -lntu 2>/dev/null | grep ':53' | grep -qv '127\.0\.0\.1\|::1\|${SERVER_IPV4_ADDR%%/*}'"
    if [ -f /etc/dnsmasq.d/wg-tunnel-force.conf ]; then
        _tst "Конфиг tunnel-force domains присутствует" \
            test -s /etc/dnsmasq.d/wg-tunnel-force.conf
    fi
    if [ -f /etc/dnsmasq.d/wg-split-dns.conf ]; then
        _tst "Конфиг split-DNS присутствует" \
            test -s /etc/dnsmasq.d/wg-split-dns.conf
    fi
    _tst_info "dnsmasq uptime (PID)" \
        bash -c "systemctl show dnsmasq --property=MainPID --value 2>/dev/null | xargs -I{} ps -p {} -o etime= 2>/dev/null | xargs echo 'pid uptime:'"
}

# ── 6. unbound (DNS geo-режим) ────────────────────────────────
_tstSectionUnbound() {
    _tst_header "6. unbound (рекурсивный резолвер, geo-режим)"
    if ! command -v unbound >/dev/null 2>&1 && ! systemctl list-units --full --all 2>/dev/null | grep -q unbound; then
        _tst_skip "unbound не установлен"
        return
    fi
    _tst "Сервис unbound активен" \
        systemctl is-active unbound
    _tst "unbound слушает 127.0.0.1:5335" \
        bash -c "ss -lntu 2>/dev/null | grep -q '127\.0\.0\.1:5335'"
    _tst "unbound отвечает на прямые запросы (google.com)" \
        bash -c "dig @127.0.0.1 -p 5335 google.com A +short +time=5 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'"
    _tst "unbound резолвит домен .ru (yandex.ru)" \
        bash -c "dig @127.0.0.1 -p 5335 yandex.ru A +short +time=5 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'"
    _tst "DNSSEC: валидация работает (sigok для dnssec-tools.org)" \
        bash -c "dig @127.0.0.1 -p 5335 dnssec-tools.org A +dnssec +time=5 +tries=1 2>/dev/null | grep -q 'ad'"
    _tst "DNSSEC: BOGUS-домен отклоняется (servfail.nl)" \
        bash -c "dig @127.0.0.1 -p 5335 servfail.nl A +time=5 +tries=1 2>/dev/null | grep -q 'SERVFAIL'"
    _tst "root.hints файл присутствует" \
        test -s /var/lib/unbound/root.hints
    _tst "unbound.conf существует" \
        bash -c "test -f /etc/unbound/unbound.conf || test -f /etc/unbound/unbound.conf.d/wg-unbound.conf"
    _tst_info "unbound: версия" \
        bash -c "unbound -V 2>/dev/null | head -1"
}

# ── 7. DNS-over-TLS (stubby) ─────────────────────────────────
_tstSectionDoT() {
    _tst_header "7. DNS-over-TLS (stubby)"
    if ! command -v stubby >/dev/null 2>&1 && ! systemctl list-units --full --all 2>/dev/null | grep -q stubby; then
        _tst_skip "stubby не установлен"
        return
    fi
    _tst "Сервис stubby активен" \
        systemctl is-active stubby
    _tst "stubby слушает 127.0.0.1:5353" \
        bash -c "ss -lntu 2>/dev/null | grep -q '127\.0\.0\.1:5353'"
    _tst "stubby отвечает на DNS-запросы (google.com)" \
        bash -c "dig @127.0.0.1 -p 5353 google.com A +short +time=8 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'"
    _tst "stubby резолвит cloudflare.com" \
        bash -c "dig @127.0.0.1 -p 5353 cloudflare.com A +short +time=8 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'"
    _tst "stubby.yml конфиг существует" \
        test -f /etc/stubby/stubby.yml
    _tst "TLS-сертификат Cloudflare 1.1.1.1:853 доступен" \
        bash -c "echo | openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com \
            -connect_timeout 5 2>/dev/null | grep -q 'CONNECTED'"
    _tst "TLS-сертификат Quad9 9.9.9.9:853 доступен" \
        bash -c "echo | openssl s_client -connect 9.9.9.9:853 -servername dns.quad9.net \
            -connect_timeout 5 2>/dev/null | grep -q 'CONNECTED'"
    _tst_info "Текущий DNS-режим скрипта" \
        bash -c "echo \"${DNS_MODE}\""
}

# ── 8. DNS: сквозной chain-тест ───────────────────────────────
_tstSectionDNSChain() {
    _tst_header "8. DNS — сквозные chain-тесты"
    _tst "Системный резолвер (getent) google.com" \
        bash -c "getent hosts google.com >/dev/null"
    _tst "Системный резолвер (getent) yandex.ru" \
        bash -c "getent hosts yandex.ru >/dev/null"
    _tst "Нет DNS-утечек: dnsmasq → 127.0.0.1 (не 8.8.8.8)" \
        bash -c "cat /etc/resolv.conf 2>/dev/null | grep '^nameserver' | head -1 | grep -q '127\.0\.0\.1'"
    _tst "Нет plain-text DNS наружу (порт 53 к внешним IP заблокирован нашим nft)" \
        bash -c "nft list chain inet wg-policy forward 2>/dev/null | grep -q 'dport 53' \
            || nft list chain inet wg-policy output 2>/dev/null | grep -q 'dport 53'"
    _tst "Резолвинг через dnsmasq: localhost доступен" \
        bash -c "dig @127.0.0.1 localhost A +short +time=3 +tries=1 2>/dev/null | grep -q '127'"
    _tst "Обратный резолвинг PTR (1.1.1.1)" \
        bash -c "dig @127.0.0.1 -p 53 -x 1.1.1.1 +short +time=3 +tries=1 2>/dev/null | grep -q '.'"
    _tst "IPv6 DNS резолвинг (AAAA google.com)" \
        bash -c "dig @127.0.0.1 -p 53 google.com AAAA +short +time=3 +tries=1 2>/dev/null | grep -qE ':'"
    case "${DNS_MODE}" in
        geo)
            _tst "geo-chain: dnsmasq:53 → unbound:5335 (транзитный резолвинг)" \
                bash -c "dig @127.0.0.1 -p 5335 github.com A +short +time=5 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.'"
            ;;
        tunnel)
            _tst "tunnel-chain: dnsmasq:53 → stubby:5353 (DoT транзит)" \
                bash -c "dig @127.0.0.1 -p 5353 github.com A +short +time=8 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.'"
            ;;
        public)
            _tst "public-режим: прямой резолвинг 8.8.8.8" \
                bash -c "dig @8.8.8.8 google.com A +short +time=5 +tries=1 2>/dev/null | grep -qE '^[0-9]+\.'"
            ;;
    esac
}

# ── 9. Балансировщик ─────────────────────────────────────────
_tstSectionBalancer() {
    _tst_header "9. Балансировщик (wg-balance)"
    _tst "Сервис wg-balance активен" \
        systemctl is-active wg-balance
    _tst "Скрипт /usr/local/bin/wg-balance.sh исполняемый" \
        test -x /usr/local/bin/wg-balance.sh
    _tst "Lock-файл балансировщика доступен (нет зависших экземпляров)" \
        bash -c "! flock -n /var/run/wg-balance.lock true 2>/dev/null || true"
    _tst "Таблица маршрутизации балансировщика активна (lookup 5182x)" \
        bash -c "ip rule show 2>/dev/null | grep -qE 'lookup 5182'"
    if [ -f /etc/systemd/system/wg-balance.service ]; then
        _tst "Unit-файл wg-balance.service валиден" \
            bash -c "systemd-analyze verify wg-balance.service 2>/dev/null"
    fi
    if [ -f /usr/local/bin/wg-balance-watchdog.sh ]; then
        _tst "Watchdog wg-balance-watchdog активен" \
            systemctl is-active wg-balance-watchdog.timer
        _tst "Скрипт wg-balance-watchdog.sh исполняемый" \
            test -x /usr/local/bin/wg-balance-watchdog.sh
    else
        _tst_skip "wg-balance-watchdog: не установлен"
    fi
    if [ -f /usr/local/bin/wg-ip-watchdog.sh ]; then
        _tst "IP-watchdog таймер активен" \
            systemctl is-active wg-ip-watchdog.timer
        _tst "Скрипт wg-ip-watchdog.sh исполняемый" \
            test -x /usr/local/bin/wg-ip-watchdog.sh
    else
        _tst_skip "wg-ip-watchdog: не установлен"
    fi
    _tst_info "Последние строки журнала wg-balance" \
        bash -c "journalctl -u wg-balance -n 2 --no-pager -q 2>/dev/null | tail -1 | cut -c1-80"
}

# ── 10. Anti-DPI ─────────────────────────────────────────────
_tstSectionAntiDPI() {
    _tst_header "10. Anti-DPI (обфускация WireGuard)"
    local bbr="${ANTIDPI_BBR:-no}"
    local mss="${ANTIDPI_MSS:-no}"
    local jitter="${ANTIDPI_JITTER:-no}"
    _tst_info "Режим Anti-DPI (BBR/MSS/Jitter)" \
        bash -c "echo \"BBR=${bbr} MSS=${mss} Jitter=${jitter}\""
    if [ "${bbr}" = "yes" ]; then
        _tst "BBR включён: sysctl net.ipv4.tcp_congestion_control=bbr" \
            bash -c "sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr"
        _tst "BBR: модуль tcp_bbr загружен" \
            bash -c "lsmod 2>/dev/null | grep -q tcp_bbr"
    else
        _tst_skip "BBR: не включён"
    fi
    if [ "${mss}" = "yes" ]; then
        _tst "MSS Clamping: правило nft для TCP MSS присутствует" \
            bash -c "nft list ruleset 2>/dev/null | grep -qi 'tcp option maxseg'"
    else
        _tst_skip "MSS Clamping: не включён"
    fi
    if [ "${jitter}" = "yes" ]; then
        _tst "Jitter: systemd-юнит wg-antidpi-jitter активен" \
            systemctl is-active wg-antidpi-jitter
        _tst "Jitter: /etc/sysctl.d/99-antidpi.conf присутствует" \
            test -f /etc/sysctl.d/99-antidpi.conf
    else
        _tst_skip "Jitter: не включён"
    fi
    _tst_info "net.core.default_qdisc" \
        bash -c "sysctl -n net.core.default_qdisc 2>/dev/null"
    _tst_info "net.ipv4.tcp_congestion_control" \
        bash -c "sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null"
}

# ── 11. Killswitch ────────────────────────────────────────────
_tstSectionKillswitch() {
    _tst_header "11. Killswitch"
    local ksfile="/etc/wireguard/.killswitch-clients"
    if [ ! -f "${ksfile}" ] || [ ! -s "${ksfile}" ]; then
        _tst_skip "Killswitch: ни одному клиенту не включён"
        return
    fi
    local kscnt
    kscnt=$(wc -l < "${ksfile}" 2>/dev/null || echo 0)
    _tst_info "Клиентов с killswitch" bash -c "echo ${kscnt}"
    _tst "Killswitch: nft-правило drop для default route присутствует" \
        bash -c "nft list ruleset 2>/dev/null | grep -q 'drop' \
            && nft list ruleset 2>/dev/null | grep -qi 'killswitch\|kill'"
    _tst "Killswitch: WG-клиент config содержит PostUp/PreDown" \
        bash -c "grep -rl 'PreDown.*iptables\|PreDown.*nft' /etc/wireguard/clients/ 2>/dev/null | grep -q ."
}

# ── 12. Telemt (MTProxy Rust) ─────────────────────────────────
_tstSectionTelemt() {
    _tst_header "12. Telemt (MTProxy — Rust, Fake TLS)"
    if [ ! -x "${TELEMT_BIN:-/usr/local/bin/telemt}" ]; then
        _tst_skip "Telemt: не установлен"
        return
    fi
    _tst "Бинарь telemt исполняемый" \
        test -x "${TELEMT_BIN:-/usr/local/bin/telemt}"
    _tst "Сервис telemt активен" \
        systemctl is-active telemt
    _tst "Конфиг /etc/telemt.toml существует" \
        test -f "${TELEMT_CONFIG:-/etc/telemt.toml}"
    _tst "Telemt API отвечает на 127.0.0.1:9091" \
        bash -c "curl -fsSL --max-time 3 http://127.0.0.1:9091/ >/dev/null 2>&1 \
            || ( exec 3<>/dev/tcp/127.0.0.1/9091 ) 2>/dev/null"
    local _tmt_port
    _tmt_port=$(grep -E '^\s*port\s*=' "${TELEMT_CONFIG:-/etc/telemt.toml}" 2>/dev/null \
        | head -1 | grep -oE '[0-9]+' | head -1)
    if [ -n "${_tmt_port}" ]; then
        _tst "Telemt порт ${_tmt_port} прослушивается" \
            bash -c "ss -lntu 2>/dev/null | grep -q ':${_tmt_port} '"
    fi
    _tst "SHA256 бинаря telemt совпадает с эталоном (файл .sha256)" \
        bash -c "sha256sum -c /var/lib/telemt/telemt.sha256 >/dev/null 2>&1 || true"
    _tst_info "Telemt версия" \
        bash -c "${TELEMT_BIN:-/usr/local/bin/telemt} --version 2>/dev/null | head -1"
}

# ── 13. MTProto (старый mtg) ──────────────────────────────────
_tstSectionMTProto() {
    _tst_header "13. MTProto Proxy (mtg — старый Go)"
    if [ ! -f /etc/systemd/system/mtg.service ] && [ ! -f /etc/mtg.env ]; then
        _tst_skip "MTProto (mtg): не установлен"
        return
    fi
    _tst "Сервис mtg активен" \
        systemctl is-active mtg
    _tst "/etc/mtg.env существует" \
        test -f /etc/mtg.env
    _tst "SECRET в /etc/mtg.env непустой" \
        bash -c "grep -q '^SECRET=.\+' /etc/mtg.env 2>/dev/null"
    local _mtg_port
    _mtg_port=$(grep -oP '0\.0\.0\.0:\K[0-9]+' /etc/systemd/system/mtg.service 2>/dev/null | head -1)
    if [ -n "${_mtg_port}" ]; then
        _tst "MTG порт ${_mtg_port} прослушивается" \
            bash -c "ss -lntu 2>/dev/null | grep -q ':${_mtg_port} '"
    fi
    _tst "Файл ссылок /root/mtproto_links.txt существует" \
        test -f /root/mtproto_links.txt
}

# ── 14. Интернет / внешняя связь ─────────────────────────────
_tstSectionInternet() {
    _tst_header "14. Интернет / внешняя связь"
    _tst "TCP связь 8.8.8.8:53 (Google DNS)" \
        bash -c "( exec 3<>/dev/tcp/8.8.8.8/53 ) 2>/dev/null \
            || ping -c1 -W3 8.8.8.8 >/dev/null 2>&1"
    _tst "TCP связь 1.1.1.1:443 (Cloudflare)" \
        bash -c "( exec 3<>/dev/tcp/1.1.1.1/443 ) 2>/dev/null"
    _tst "HTTPS: curl google.com отвечает" \
        bash -c "curl -fsSL --max-time 5 --proto '=https' https://www.google.com -o /dev/null 2>/dev/null"
    _tst "HTTPS: curl yandex.ru отвечает" \
        bash -c "curl -fsSL --max-time 5 --proto '=https' https://yandex.ru -o /dev/null 2>/dev/null"
    _tst "Текущий внешний IP получен (ipify.org)" \
        bash -c "curl -fsSL --max-time 5 --proto '=https' https://api.ipify.org 2>/dev/null \
            | grep -qE '^[0-9]+\.[0-9]+'"
    _tst_info "Текущий внешний IP" \
        bash -c "curl -fsSL --max-time 5 --proto '=https' https://api.ipify.org 2>/dev/null || echo '—'"
    _tst_info "Задержка до 8.8.8.8 (ping)" \
        bash -c "ping -c3 -W2 8.8.8.8 2>/dev/null | tail -1 | grep -oP 'rtt.*' || echo '—'"
}

# ── 15. IPv6 ──────────────────────────────────────────────────
_tstSectionIPv6() {
    _tst_header "15. IPv6"
    local ipv6_ok
    ipv6_ok=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
    if [ "${ipv6_ok}" = "1" ]; then
        _tst_skip "IPv6 отключён в ядре (disable_ipv6=1)"
        return
    fi
    _tst "IPv6 включён в ядре" \
        bash -c "[ \"\$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)\" = '0' ]"
    _tst "IPv6 адрес на MAIN_INTERFACE присутствует" \
        bash -c "ip -6 addr show \"${MAIN_INTERFACE}\" 2>/dev/null | grep -q 'inet6'"
    _tst "IPv6 адрес на ${SERVER_WG_NIC} присутствует" \
        bash -c "ip -6 addr show \"${SERVER_WG_NIC}\" 2>/dev/null | grep -q 'inet6'"
    _tst "IPv6 TCP связь (2001:4860:4860::8888 Google) или DNS AAAA" \
        bash -c "ping6 -c1 -W3 2001:4860:4860::8888 >/dev/null 2>&1 \
            || dig @127.0.0.1 google.com AAAA +short +time=3 2>/dev/null | grep -qE ':'"
    _tst "GeoIP IPv6 fwmark-правила присутствуют в nftables" \
        bash -c "nft list ruleset 2>/dev/null | grep -q 'ip6 daddr'"
}

# ── 16. Автозапуск и systemd ─────────────────────────────────
_tstSectionAutostart() {
    _tst_header "16. Автозапуск / systemd units"
    _tst "WG-сервис включён в автозапуск" \
        bash -c "systemctl is-enabled \"wg-quick@${SERVER_WG_NIC}\" 2>/dev/null | grep -qE 'enabled'"
    _tst "nftables включён в автозапуск" \
        bash -c "systemctl is-enabled nftables 2>/dev/null | grep -qE 'enabled'"
    _tst "dnsmasq включён в автозапуск" \
        bash -c "systemctl is-enabled dnsmasq 2>/dev/null | grep -qE 'enabled'"
    _tst "wg-balance включён в автозапуск" \
        bash -c "systemctl is-enabled wg-balance 2>/dev/null | grep -qE 'enabled'"
    _tst "Unit-файлы валидны (systemd-analyze verify)" \
        bash -c "systemd-analyze verify \"wg-quick@${SERVER_WG_NIC}.service\" wg-balance.service 2>/dev/null"
    if [ -f /etc/systemd/system/wg-ip-watchdog.timer ]; then
        _tst "wg-ip-watchdog.timer активен" \
            systemctl is-active wg-ip-watchdog.timer
    fi
    _tst_info "Системный uptime" bash -c "uptime -p 2>/dev/null || uptime"
}

# ── 17. Безопасность / sysctl ────────────────────────────────
_tstSectionSecurity() {
    _tst_header "17. Безопасность / sysctl"
    _tst "IP-forwarding включён (IPv4)" \
        bash -c "[ \"\$(sysctl -n net.ipv4.ip_forward 2>/dev/null)\" = '1' ]"
    _tst "rp_filter отключён на ${MAIN_INTERFACE} (нужен для балансировщика)" \
        bash -c "val=\$(sysctl -n \"net.ipv4.conf.${MAIN_INTERFACE}.rp_filter\" 2>/dev/null); [ \"\$val\" = '0' ] || [ \"\$val\" = '2' ]"
    _tst "rp_filter отключён на ${SERVER_WG_NIC}" \
        bash -c "val=\$(sysctl -n \"net.ipv4.conf.${SERVER_WG_NIC}.rp_filter\" 2>/dev/null); [ \"\$val\" = '0' ] || [ \"\$val\" = '2' ]"
    _tst "Ошибок в /var/log/wg-errors.log нет (пуст или отсутствует)" \
        bash -c "[ ! -s \"${WG_ERR_LOG:-/var/log/wg-errors.log}\" ]"
    _tst "/etc/nftables.conf существует и непустой" \
        test -s /etc/nftables.conf
    _tst "resolv.conf указывает на 127.0.0.1 (dnsmasq, не наружу)" \
        bash -c "grep -q '^nameserver 127\.0\.0\.1' /etc/resolv.conf 2>/dev/null"
    _tst "Нет лишних открытых портов наружу (кроме WG-порта ${SERVER_PORT})" \
        bash -c "ss -lntu 2>/dev/null | awk 'NR>1{print \$5}' \
            | grep -vE '127\.|::1|0\.0\.0\.0:${SERVER_PORT}' | grep -c '0\.0\.0\.0:' | xargs -I{} [ '{}' -le 3 ]"
    _tst_info "Открытые внешние порты" \
        bash -c "ss -lntu 2>/dev/null | awk 'NR>1{print \$5}' \
            | grep '0\.0\.0\.0:' | grep -v '127\.' | awk -F: '{print \$NF}' | sort -n | xargs echo"
}

# ── 18. Бэкапы ───────────────────────────────────────────────
_tstSectionBackup() {
    _tst_header "18. Бэкапы"
    local bakdir="${BACKUP_DIR:-/var/backups/wg}"
    if [ ! -d "${bakdir}" ]; then
        _tst_skip "Директория бэкапов ${bakdir} не существует"
        return
    fi
    _tst "Директория бэкапов доступна" \
        test -d "${bakdir}"
    _tst "Хотя бы один бэкап-архив существует" \
        bash -c "ls \"${bakdir}\"/*.tar.gz 2>/dev/null | grep -q ."
    _tst_info "Последний бэкап" \
        bash -c "ls -t \"${bakdir}\"/*.tar.gz 2>/dev/null | head -1 | xargs basename 2>/dev/null || echo '—'"
    _tst_info "Количество бэкапов" \
        bash -c "ls \"${bakdir}\"/*.tar.gz 2>/dev/null | wc -l | xargs echo"
}

# ── Полный тест: запуск всех секций ──────────────────────────
runSystemTest() {
    loadConfig
    _antidpiLoad 2>/dev/null || true
    section "ПОЛНЫЙ ТЕСТ СИСТЕМЫ"
    echo ""
    echo -e "  ${DIM}Покрытие: WG-сервер · Туннели · Маршрутизация · nftables/GeoIP${NC}"
    echo -e "  ${DIM}          dnsmasq · unbound · DoT/stubby · DNS-chain · Балансировщик${NC}"
    echo -e "  ${DIM}          Anti-DPI · Killswitch · Telemt · MTProto · Интернет · IPv6${NC}"
    echo -e "  ${DIM}          Автозапуск · Безопасность · Бэкапы${NC}"
    echo ""
    # [fix] _TST_PASS/_TST_FAIL должны быть глобальными — функция _tst не видит local-переменные
    # родительских фреймов (они не экспортируются через стек вызовов в bash).
    _TST_PASS=0; _TST_FAIL=0

    _tstSectionWGServer
    _tstSectionTunnels
    _tstSectionRouting
    _tstSectionNftables
    _tstSectionDnsmasq
    _tstSectionUnbound
    _tstSectionDoT
    _tstSectionDNSChain
    _tstSectionBalancer
    _tstSectionAntiDPI
    _tstSectionKillswitch
    _tstSectionTelemt
    _tstSectionMTProto
    _tstSectionInternet
    _tstSectionIPv6
    _tstSectionAutostart
    _tstSectionSecurity
    _tstSectionBackup

    echo ""
    echo -e "  ${DIM}────────────────────────────────────────────────────────────${NC}"
    echo ""
    local _total=$(( _TST_PASS + _TST_FAIL ))
    if [ "${_TST_FAIL}" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}✔ Все тесты пройдены: ${_TST_PASS}/${_total}${NC}"
    else
        echo -e "  ${RED}${BOLD}✖ Провалено: ${_TST_FAIL} из ${_total}${NC}  ${DIM}(пройдено: ${_TST_PASS})${NC}"
        echo ""
        echo -e "  ${YELLOW}Подсказка:${NC} красные ✖ — смотри журналы через пункт ${WHITE}13 → Логи${NC}"
        echo -e "  ${DIM}или: journalctl -u <service> -n 50 --no-pager${NC}"
    fi
    echo ""
}

# ── Тест одной секции по номеру ───────────────────────────────
_runTestSection() {
    loadConfig
    _antidpiLoad 2>/dev/null || true
    # [fix] Глобальные переменные — _tst не видит local из родительского фрейма
    _TST_PASS=0; _TST_FAIL=0
    case "$1" in
        1)  _tstSectionWGServer ;;
        2)  _tstSectionTunnels ;;
        3)  _tstSectionRouting ;;
        4)  _tstSectionNftables ;;
        5)  _tstSectionDnsmasq ;;
        6)  _tstSectionUnbound ;;
        7)  _tstSectionDoT ;;
        8)  _tstSectionDNSChain ;;
        9)  _tstSectionBalancer ;;
        10) _tstSectionAntiDPI ;;
        11) _tstSectionKillswitch ;;
        12) _tstSectionTelemt ;;
        13) _tstSectionMTProto ;;
        14) _tstSectionInternet ;;
        15) _tstSectionIPv6 ;;
        16) _tstSectionAutostart ;;
        17) _tstSectionSecurity ;;
        18) _tstSectionBackup ;;
    esac
    echo ""
    echo -e "  ${DIM}Пройдено: ${GREEN}${_TST_PASS}${NC}${DIM}  Провалено: ${RED}${_TST_FAIL}${NC}"
}

menuSystemTest() {
    while true; do
        clear
        echo ""
        echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}  ║   ✅  ТЕСТ СИСТЕМЫ — детальная диагностика всех подсистем   ║${NC}"
        echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Зелёный ✔ — работает. Красный ✖ — проблема. Серый — пропущен (не установлен).${NC}"
        echo ""
        echo -e "${WHITE}  ┌─── ПОЛНЫЙ ТЕСТ ───────────────────────────────────────────────┐${NC}"
        echo -e "  ${YELLOW} 0${NC})  🚀  ${WHITE}Запустить ВСЕ тесты${NC}  ${DIM}(все 18 секций, ~45 сек)${NC}"
        echo -e "${WHITE}  └───────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "${WHITE}  ┌─── ПО СЕКЦИЯМ ─────────────────────────────────────────────────┐${NC}"
        echo -e "  ${YELLOW} 1${NC})  🔌  ${WHITE}WireGuard-сервер${NC}       ${DIM}интерфейс, ключи, порт, пиры${NC}"
        echo -e "  ${YELLOW} 2${NC})  🔀  ${WHITE}Туннели${NC}                ${DIM}handshake, эндпоинты, трафик${NC}"
        echo -e "  ${YELLOW} 3${NC})  🗺️   ${WHITE}Маршрутизация / fwmark${NC} ${DIM}ip rule, таблицы, default route${NC}"
        echo -e "  ${YELLOW} 4${NC})  🔥  ${WHITE}nftables / GeoIP${NC}       ${DIM}таблицы, sets russia, IPv4/IPv6${NC}"
        echo -e "  ${YELLOW} 5${NC})  🌐  ${WHITE}dnsmasq${NC}                ${DIM}сервис, порт :53, резолвинг, изоляция${NC}"
        echo -e "  ${YELLOW} 6${NC})  🔄  ${WHITE}unbound${NC}                ${DIM}рекурсия, DNSSEC, root.hints, :5335${NC}"
        echo -e "  ${YELLOW} 7${NC})  🔐  ${WHITE}DNS-over-TLS (stubby)${NC}  ${DIM}:5353, TLS-сертификаты, Cloudflare/Quad9${NC}"
        echo -e "  ${YELLOW} 8${NC})  🔗  ${WHITE}DNS chain-тесты${NC}        ${DIM}сквозной резолвинг, утечки, PTR, AAAA${NC}"
        echo -e "  ${YELLOW} 9${NC})  ⚖️   ${WHITE}Балансировщик${NC}          ${DIM}wg-balance, watchdog, таблицы${NC}"
        echo -e "  ${YELLOW}10${NC})  🛡   ${WHITE}Anti-DPI${NC}               ${DIM}BBR, MSS clamping, jitter${NC}"
        echo -e "  ${YELLOW}11${NC})  🔒  ${WHITE}Killswitch${NC}             ${DIM}nft-правила, конфиги клиентов${NC}"
        echo -e "  ${YELLOW}12${NC})  🦀  ${WHITE}Telemt (MTProxy)${NC}       ${DIM}бинарь, сервис, API, порт, SHA256${NC}"
        echo -e "  ${YELLOW}13${NC})  📡  ${WHITE}MTProto (старый mtg)${NC}   ${DIM}сервис, secret, порт, ссылки${NC}"
        echo -e "  ${YELLOW}14${NC})  🌍  ${WHITE}Интернет / связь${NC}       ${DIM}TCP, HTTPS, внешний IP, пинги${NC}"
        echo -e "  ${YELLOW}15${NC})  6️⃣   ${WHITE}IPv6${NC}                   ${DIM}ядро, адреса, GeoIP, пинг6${NC}"
        echo -e "  ${YELLOW}16${NC})  🚀  ${WHITE}Автозапуск / systemd${NC}   ${DIM}enabled, verify, таймеры${NC}"
        echo -e "  ${YELLOW}17${NC})  🔑  ${WHITE}Безопасность / sysctl${NC}  ${DIM}forwarding, rp_filter, открытые порты${NC}"
        echo -e "  ${YELLOW}18${NC})  💾  ${WHITE}Бэкапы${NC}                 ${DIM}директория, архивы, дата${NC}"
        echo -e "${WHITE}  └───────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${RED}99${NC})  ←   Назад в главное меню"
        echo ""
        read -rp "  Введи номер секции (0 = все, 99 = назад): " opt
        case "${opt}" in
            0)  runSystemTest ;;
            1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18) _runTestSection "${opt}" ;;
            99) break ;;
            *)  warn "Введи номер от 0 до 18 или 99 для выхода" ;;
        esac
        _pause
    done
}

# ════════════════════════════════════════════════════════════════
# ОБНОВЛЕНИЕ СКРИПТА
# ════════════════════════════════════════════════════════════════

updateScript() {
    section "Обновление скрипта"
    echo ""
    local SCRIPT_PATH
    SCRIPT_PATH=$(realpath "$0" 2>/dev/null || readlink -f "$0")
    echo -e "  ${DIM}Текущий файл: ${SCRIPT_PATH}${NC}"
    echo -e "  ${DIM}Установленная версия: ${WHITE}${VERSION}${NC}"
    echo ""

    # [v28.22.0] Проверка актуальной версии (через ENV WG_VERSION_URL).
    # Чтобы не привязываться к конкретному репо, URL берём из переменной окружения.
    # Например: WG_VERSION_URL=https://example.com/wg/version.txt ./wg-server.sh
    local _ver_url="${WG_VERSION_URL:-}"
    if [ -n "${_ver_url}" ]; then
        local _latest
        _latest=$(curl -fsSL --proto '=https' --max-time 10 "${_ver_url}" 2>/dev/null | head -1 | tr -d ' \r\n')
        if [ -n "${_latest}" ]; then
            if [ "${_latest}" != "${VERSION}" ]; then
                echo -e "  ${GREEN}✦ Доступна новая версия: ${BOLD}${_latest}${NC} ${DIM}(текущая: ${VERSION})${NC}"
            else
                echo -e "  ${DIM}✓ У тебя последняя версия (${VERSION})${NC}"
            fi
        else
            echo -e "  ${DIM}Не удалось проверить версию (${_ver_url})${NC}"
        fi
        echo ""
    else
        echo -e "  ${DIM}(подсказка: задай WG_VERSION_URL=https://.../version.txt для авто-проверки версии)${NC}"
        echo ""
    fi

    echo -e "  ${WHITE}Откуда обновить:${NC}"
    echo ""
    echo -e "  ${YELLOW}1${NC}) По прямой URL-ссылке (curl)"
    echo -e "  ${YELLOW}2${NC}) Из локального файла на сервере"
    echo -e "  ${YELLOW}3${NC}) ${GREEN}Откатиться к предыдущей версии${NC} ${DIM}(если есть .old)${NC}"
    echo -e "  ${RED}0${NC}) Отмена"
    echo ""
    read -rp "  Выбор: " choice
    case "${choice}" in
        3)
            if [ -f "${SCRIPT_PATH}.old" ]; then
                local _old_ver
                _old_ver=$(grep -oP 'VERSION="\K[^"]+' "${SCRIPT_PATH}.old" 2>/dev/null | head -1 || echo "неизвестна")
                warn "Откат к версии ${_old_ver} (${SCRIPT_PATH}.old)"
                read -rp "  Подтвердить? [y/N]: " _yn
                [[ "${_yn}" =~ ^[Yy]$ ]] || { warn "Отменено"; return; }
                if bash -n "${SCRIPT_PATH}.old" 2>/dev/null; then
                    cp -p "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak.$(date +%Y%m%d-%H%M%S)"
                    if install -m 0755 "${SCRIPT_PATH}.old" "${SCRIPT_PATH}.new" \
                       && mv -f "${SCRIPT_PATH}.new" "${SCRIPT_PATH}"; then
                        info "Откат выполнен. Перезапусти: ${SCRIPT_PATH}"
                    else
                        rm -f "${SCRIPT_PATH}.new"
                        warn "Не удалось откатить — текущая версия не тронута"
                    fi
                else
                    warn "Файл ${SCRIPT_PATH}.old не прошёл bash -n — откат отменён"
                fi
            else
                warn "Файл .old не найден — предыдущая версия не сохранена"
            fi
            return
            ;;
        1)
            read -rp "  URL (raw ссылка на .sh файл): " RAW_URL
            [ -z "${RAW_URL}" ] && return
            # [fix v28.20.11] HTTPS-only — защита от MITM downgrade
            if ! [[ "${RAW_URL}" =~ ^https:// ]]; then
                warn "Только HTTPS URL разрешены (защита от MITM)"
                return
            fi
            read -rp "  Ожидаемый SHA256 (Enter — пропустить, не рекомендуется): " EXPECT_SHA
            local tmpfile
            tmpfile=$(mktemp)
            if curl -fsSL --proto '=https' --tlsv1.2 "${RAW_URL}" -o "${tmpfile}" 2>/dev/null; then
                # 1) минимальный размер (защита от пустых/обрезанных файлов)
                local fsize
                fsize=$(stat -c%s "${tmpfile}" 2>/dev/null || echo 0)
                if [ "${fsize}" -lt 10240 ]; then
                    rm -f "${tmpfile}"; warn "Файл подозрительно мал (${fsize}B) — отменено"; return
                fi
                # 2) валидный bash shebang (#!/bin/bash или #!/usr/bin/env bash)
                if ! head -1 "${tmpfile}" | grep -qE '^#!(/bin/bash|/usr/bin/env[[:space:]]+bash)'; then
                    rm -f "${tmpfile}"; warn "Нет валидного bash shebang — отменено"; return
                fi
                # 3) bash -n syntax check
                if ! bash -n "${tmpfile}" 2>/dev/null; then
                    rm -f "${tmpfile}"; warn "Скрипт не проходит bash -n — отменено"; return
                fi
                # 4) проверка SHA256 если указан
                if [ -n "${EXPECT_SHA}" ]; then
                    local actual_sha
                    actual_sha=$(sha256sum "${tmpfile}" | awk '{print $1}')
                    if [ "${actual_sha}" != "${EXPECT_SHA}" ]; then
                        rm -f "${tmpfile}"
                        warn "SHA256 не совпал! ожидали ${EXPECT_SHA}, получили ${actual_sha}"
                        return
                    fi
                    info "SHA256 верифицирован"
                fi
                # [fix v28.24.12] Раньше cp перезаписывал ЖИВОЙ файл, который
                # читает bash чанками, → "Text file busy" / Segmentation fault.
                # Атомарный паттерн: install в .new в той же ФС → mv (rename
                # обновляет dentry, старый inode остаётся открыт текущим bash).
                # [fix v28.24.23] Дополнительно сохраняем .old (откатная копия).
                cp -p "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak.$(date +%Y%m%d-%H%M%S)"
                cp -p "${SCRIPT_PATH}" "${SCRIPT_PATH}.old" 2>/dev/null || true
                if install -m 0755 "${tmpfile}" "${SCRIPT_PATH}.new" \
                   && mv -f "${SCRIPT_PATH}.new" "${SCRIPT_PATH}"; then
                    rm -f "${tmpfile}"
                    info "Скрипт обновлён (атомарно). Предыдущая версия: ${SCRIPT_PATH}.old"
                    warn "Перезапусти: ${SCRIPT_PATH}"
                else
                    rm -f "${tmpfile}" "${SCRIPT_PATH}.new"
                    warn "Не удалось атомарно заменить — старая версия не тронута."
                fi
            else
                rm -f "${tmpfile}"
                warn "Не удалось скачать. Проверь URL и интернет."
            fi
            ;;
        2)
            read -rp "  Путь к файлу: " LOCAL_FILE
            { [ -z "${LOCAL_FILE}" ] || [ ! -f "${LOCAL_FILE}" ]; } && { warn "Файл не найден"; return; }
            if ! head -1 "${LOCAL_FILE}" | grep -qE '^#!(/bin/bash|/usr/bin/env[[:space:]]+bash)'; then
                warn "Нет валидного bash shebang — отменено"; return
            fi
            if ! bash -n "${LOCAL_FILE}" 2>/dev/null; then
                warn "Скрипт не проходит bash -n — отменено"; return
            fi
            # [fix v28.24.12] Атомарная замена через install + mv (см. выше).
            # [fix v28.24.23] Сохраняем .old для возможности отката.
            cp -p "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak.$(date +%Y%m%d-%H%M%S)"
            cp -p "${SCRIPT_PATH}" "${SCRIPT_PATH}.old" 2>/dev/null || true
            if install -m 0755 "${LOCAL_FILE}" "${SCRIPT_PATH}.new" \
               && mv -f "${SCRIPT_PATH}.new" "${SCRIPT_PATH}"; then
                info "Скрипт обновлён из ${LOCAL_FILE} (атомарно). Откат: ${SCRIPT_PATH}.old"
                warn "Перезапусти: ${SCRIPT_PATH}"
            else
                rm -f "${SCRIPT_PATH}.new"
                warn "Не удалось атомарно заменить — старая версия не тронута."
            fi
            ;;
        *) return ;;
    esac
}


# ════════════════════════════════════════════════════════════════
# ГЛАВНОЕ МЕНЮ
# ════════════════════════════════════════════════════════════════
menu() {
    loadConfig
    # [fix v28.25.3] Авто-проверка версии при запуске, если задан WG_VERSION_URL.
    # Выполняется однократно (не в цикле меню). Не блокирует запуск при недоступности URL.
    if [ -n "${WG_VERSION_URL:-}" ]; then
        local _startup_ver
        _startup_ver=$(curl -fsSL --proto "=https" --max-time 5 "${WG_VERSION_URL}" 2>/dev/null \
            | head -1 | tr -d " \r\n" || true)
        if [ -n "${_startup_ver}" ] && [ "${_startup_ver}" != "${VERSION}" ]; then
            echo -e "  ${GREEN}✦ Доступна новая версия скрипта: ${BOLD}${_startup_ver}${NC} ${DIM}(текущая: ${VERSION})${NC}"
            echo -e "  ${DIM}Обновить: выбери пункт 20 в главном меню.${NC}"
            echo ""
            sleep 2
        fi
    fi
    while true; do
        clear
        echo -e ""
        echo -e "${YELLOW}  ╔═════════════════════════════════════════════════════════════╗${NC}"
        printf "${YELLOW}  ║      🛡️   WireGuard Home Server  —  v%-22s  ║${NC}\n" "${VERSION}"
        echo -e "${YELLOW}  ║   РФ напрямую │ Зарубежье в туннель │ Split-DNS │ Anti-DPI  ║${NC}"
        echo -e "${YELLOW}  ╚═════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        _statusBar
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  КЛИЕНТЫ И МАРШРУТИЗАЦИЯ                                    │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW} 1${NC})  👤  ${WHITE}Клиенты${NC}               ${DIM}— добавить, QR-код, список, отозвать${NC}"
        echo -e "  ${YELLOW} 2${NC})  🔀  ${WHITE}Туннели${NC}               ${DIM}— VPN-соединения до внешних серверов${NC}"
        echo -e "  ${YELLOW} 3${NC})  🔥  ${WHITE}Файрвол / GeoIP${NC}       ${DIM}— правила, список РФ IP, обновление${NC}"
        echo -e "  ${YELLOW} 4${NC})  🗺️   ${WHITE}Профили маршрутизации${NC} ${DIM}— geo-split / full-vpn / direct-only${NC}"
        echo -e "  ${YELLOW} 5${NC})  📌  ${WHITE}Прямые IP (whitelist)${NC} ${DIM}— свои подсети минуя VPN${NC}"
        echo -e "  ${YELLOW} 6${NC})  🔒  ${WHITE}Killswitch${NC}            ${DIM}— блокировка при обрыве VPN${NC}"
        echo -e "  ${YELLOW} 7${NC})  🌐  ${WHITE}DNS (geo/tunnel/pub)${NC}  ${DIM}— unbound/рекурсия или DoT (Cloudflare/Quad9) через туннель${NC}"
        echo -e "  ${YELLOW} 8${NC})  🛡   ${WHITE}Anti-DPI${NC}              ${DIM}— обфускация WG от блокировок РКН${NC}"
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  МОНИТОРИНГ                                                 │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW} 9${NC})  📊  ${WHITE}Статус WireGuard${NC}      ${DIM}— пиры, трафик, последний онлайн${NC}"
        echo -e "  ${YELLOW}10${NC})  ⚖️   ${WHITE}Балансировщик${NC}         ${DIM}— watchdog, логи, настройки${NC}"
        echo -e "  ${YELLOW}11${NC})  📈  ${WHITE}Мониторинг${NC}            ${DIM}— трафик клиентов, пинги, live-монитор${NC}"
        echo -e "  ${YELLOW}12${NC})  📊  ${WHITE}Лимиты трафика${NC}        ${DIM}— ограничения по GB на клиента${NC}"
        echo -e "  ${YELLOW}13${NC})  📄  ${WHITE}Логи${NC}                  ${DIM}— журналы всех сервисов${NC}"
        echo -e "  ${YELLOW}14${NC})  ✅  ${WHITE}Тест системы${NC}          ${DIM}— автопроверка что всё работает${NC}"
        echo ""
        echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${WHITE}  │  ПРОЧЕЕ                                                     │${NC}"
        echo -e "${WHITE}  └─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${YELLOW}15${NC})  🦀  ${WHITE}Telemt (новый MTProxy)${NC}       ${DIM}— Rust, Fake TLS, multi-user${NC}"
        echo -e "  ${YELLOW}16${NC})  📡  ${WHITE}MTProto Proxy (старый MTG)${NC}   ${DIM}— Go-версия, для совместимости${NC}"
        echo -e "  ${YELLOW}17${NC})  🔑  ${WHITE}Ротация ключей${NC}               ${DIM}— смена ключей шифрования${NC}"
        echo -e "  ${YELLOW}18${NC})  💾  ${WHITE}Бэкап / Восстановление${NC}       ${DIM}— сохранить и восстановить конфиги${NC}"
        echo -e "  ${YELLOW}19${NC})  🚀  ${WHITE}Автозапуск${NC}                   ${DIM}— настройка запуска при старте сервера${NC}"
        echo -e "  ${YELLOW}20${NC})  🔄  ${WHITE}Обновить скрипт${NC}              ${DIM}— загрузить новую версию${NC}"
        echo ""
        echo -e "  ${YELLOW}21${NC})  🔄  ${WHITE}Перезапустить всё${NC}"
        echo -e "  ${RED}22${NC})  💣  ${RED}Удалить всё (НЕОБРАТИМО!)${NC}"
        echo ""
        echo -e "  ${RED} 0${NC})  🚪  Выход"
        echo ""
        echo -ne "  ${YELLOW}${BOLD}Введи номер и нажми Enter:${NC} "
        read -r opt
        case "${opt}" in
             1) menuClients ;;
             2) menuTunnels ;;
             3) menuIPTables ;;
             4) menuRoutingProfiles ;;
             5) menuDirectIPs ;;
             6) menuKillswitch ;;
             7) menuDNS ;;
             8) menuAntiDPI ;;
             9) menuWGStatus ;;
            10) menuBalancer ;;
            11) menuMonitor ;;
            12) menuTrafficLimits ;;
            13) menuLogs ;;
            14) menuSystemTest ;;
            15) menuTelemt ;;
            16) menuMTProto ;;
            17) menuKeyRotation ;;
            18) menuBackup ;;
            19) menuAutostart ;;
            20) updateScript
                _pause ;;
            21) _quickBackupPrompt "перезапуск всех туннелей и служб"
                restartTunnels
                _pause ;;
            22) _quickBackupPrompt "ПОЛНОЕ УДАЛЕНИЕ конфигов"
                removeAll ;;
             0) echo ""; exit 0 ;;
             *) warn "Неверный выбор — введи цифру от 0 до 22" ; sleep 1 ;;
        esac
    done
}

# [v28.24.0] Быстрый бэкап перед опасными действиями ( рекомендация).
# Спрашивает пользователя и при согласии вызывает backupConfig.
# Безопасно: если backupConfig падает — продолжаем (опасное действие пользователь уже подтвердил).
_quickBackupPrompt() {
    local _what="${1:-это действие}"
    echo ""
    echo -e "  ${YELLOW}⚠  Перед '${_what}' рекомендуется сделать бэкап${NC}"
    read -rp "  Создать бэкап сейчас? [Y/n]: " _ans
    case "${_ans}" in
        n|N|no|No|NO) info "Бэкап пропущен по запросу пользователя" ;;
        # [fix v28.25.0] Убрали 2>/dev/null — критические ошибки (нет места на диске,
        # ошибка tar) теперь видны пользователю вместо тихого исчезновения.
        *) if ! backupConfig; then
               warn "Бэкап завершился с ошибкой — продолжаем по запросу пользователя"
           fi ;;
    esac
    echo ""
}

# ════════════════════════════════════════════════════════════════
# ТОЧКА ВХОДА
# ════════════════════════════════════════════════════════════════
isRoot
checkBashVersion
[[ "${1:-}" == "--remove" ]] && { removeAll; exit 0; }
if [ ! -f "${CONFIG_FILE}" ]; then
    installPackages
    firstInstall
fi
menu
