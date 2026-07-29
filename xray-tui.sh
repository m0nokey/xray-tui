#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COUNTRIES_FILE="$ROOT_DIR/data/countries.tsv"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"
VAULT_FILE="$STATE_DIR/vault.json"
HOST_STATE_DIR="${XRAY_TUI_HOST_STATE_DIR:-$STATE_DIR}"
HOST_VAULT_FILE="$HOST_STATE_DIR/vault.json"
BACKUPS_DIR="$STATE_DIR/backups"
USER_BACKUP_DIR="$BACKUPS_DIR/user"
SYSTEM_BACKUP_DIR="$BACKUPS_DIR/system"
RUNTIME_TMP_DIR="${TMPDIR:-/tmp}/xray-tui-${BASHPID}"
readonly VAULT_BACKUP_KEEP_COUNT=20
DEBUG_MODE=0
PIPELINE_ACTIVE=0
PIPELINE_TITLE=''
PIPELINE_OPERATION=''
PIPELINE_PERCENT=0
PIPELINE_LABEL=''
PIPELINE_FRAME=0
PIPELINE_TTY_ACTIVE=0
PIPELINE_TTY_STATE=''
MENU_NUMERIC_OPTIONS=''
CURRENT_INPUT_HINT=''
VAULT_PASSWORD_FILE=""
MAIN_MENU_REQUESTED=0
LAST_ANSIBLE_OUTPUT=""
for argument in "$@"; do
    [[ "$argument" == "--debug" ]] && DEBUG_MODE=1
done
# Internal status used to distinguish missing saved SSH access from deployment errors.
readonly NO_SAVED_SSH_ACCESS=125
# Internal status used to return to the VPS password prompt after auth failure.
readonly INVALID_BOOTSTRAP_CREDENTIALS=126
# Internal status used when the VPS cannot be reached over SSH.
readonly UNAVAILABLE_BOOTSTRAP_CONNECTION=127
# Internal status used for other preflight failures.
readonly BOOTSTRAP_PREFLIGHT_FAILED=128
# Internal status used to refresh the server list after successful removal.
readonly NODE_REMOVED_STATUS=124
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
rm -f "$STATE_DIR"/.vault.* 2>/dev/null || true
mkdir -p "$RUNTIME_TMP_DIR"
chmod 700 "$RUNTIME_TMP_DIR"
export TMPDIR="$RUNTIME_TMP_DIR"
export ANSIBLE_LOCAL_TEMP=/tmp/ansible-local
export ANSIBLE_SSH_CONTROL_PATH_DIR=/tmp/ansible-cp
export ANSIBLE_CONFIG="$ROOT_DIR/ansible/ansible.cfg"
export ANSIBLE_FORCE_COLOR=true
mkdir -p "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_SSH_CONTROL_PATH_DIR"

if [[ -t 1 ]]; then
    COLOR_RESET=$'\033[0m'
    COLOR_TEXT=$'\033[97m'
    COLOR_LINE=$'\033[38;5;117m'
    COLOR_INFO=$'\033[38;5;117m'
    COLOR_WARN=$'\033[38;5;221m'
    COLOR_SUCCESS=$'\033[32m'
    COLOR_MUTED=$'\033[38;5;245m'
    COLOR_MUTED_ITALIC=$'\033[3;38;5;245m'
else
    COLOR_RESET=''
    COLOR_TEXT=''
    COLOR_LINE=''
    COLOR_INFO=''
    COLOR_WARN=''
    COLOR_SUCCESS=''
    COLOR_MUTED=''
    COLOR_MUTED_ITALIC=''
fi

source "$ROOT_DIR/lib/ui.sh"
source "$ROOT_DIR/lib/pipeline.sh"
source "$ROOT_DIR/lib/vault.sh"
source "$ROOT_DIR/lib/info.sh"
source "$ROOT_DIR/lib/dns.sh"
source "$ROOT_DIR/lib/ansible.sh"
source "$ROOT_DIR/lib/deployment.sh"
source "$ROOT_DIR/lib/access_keys.sh"
source "$ROOT_DIR/lib/security.sh"
source "$ROOT_DIR/lib/nodes.sh"

cleanup() {
    declare -F pipeline_restore_terminal >/dev/null 2>&1 && pipeline_restore_terminal || true
    [[ -n "$VAULT_PASSWORD_FILE" ]] && rm -f "$VAULT_PASSWORD_FILE"
    rm -f "$STATE_DIR"/.vault.* 2>/dev/null || true
    declare -F prune_vault_backups >/dev/null 2>&1 && prune_vault_backups
    rm -rf "$RUNTIME_TMP_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

add_node_ip_prompt() {
    local ip_value error=''
    while true; do
        clear_screen
        menu_heading "Add VPN server"
        printf '%s\n' "Enter the public IPv4 address of the VPS."
        [[ -n "$error" ]] && printf '%s\n' "$error"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice ip_value 'Enter VPS IP: ' 'a public IPv4 address, or b, m, i, x'; then
            continue
        fi
        case "$ip_value" in
            b|B) return 1 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 1 ;;
            i|I) show_info general; error='' ;;
            x|X) exit_tui ;;
            *)
                if valid_ipv4 "$ip_value"; then
                    ADD_NODE_HOST="$ip_value"
                    return 0
                fi
                error="Invalid VPS IP address. Enter an IPv4 address."
                ;;
        esac
    done
}

add_node_user_prompt() {
    local user_value error=''
    while true; do
        clear_screen
        menu_heading "Add VPN server"
        printf '%s\n' "Enter the SSH user used for the first VPS connection."
        [[ -n "$error" ]] && printf '%s\n' "$error"
        echo
        printf '%b%s%b\n' "$COLOR_MUTED_ITALIC" "[!] Press Enter to use the default value shown in [brackets]." "$COLOR_RESET"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read -r -e -p 'Enter VPS user [root]: ' user_value; then
            return 1
        fi
        case "$user_value" in
            b|B) return 1 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 1 ;;
            i|I) show_info general; error='' ;;
            x|X) exit_tui ;;
            '') ADD_NODE_USER=root; return 0 ;;
            *)
                if [[ "$user_value" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]]; then
                    ADD_NODE_USER="$user_value"
                    return 0
                fi
                error="Invalid SSH user. Enter a valid Linux user name."
                ;;
        esac
    done
}

add_node_port_prompt() {
    local port_value error=''
    while true; do
        clear_screen
        menu_heading "Add VPN server"
        printf '%s\n' "Enter the SSH port used for the first VPS connection."
        [[ -n "$error" ]] && printf '%s\n' "$error"
        echo
        printf '%b%s%b\n' "$COLOR_MUTED_ITALIC" "[!] Press Enter to use the default value shown in [brackets]." "$COLOR_RESET"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read -r -e -p 'Enter VPS port [22]: ' port_value; then
            return 1
        fi
        case "$port_value" in
            b|B) return 1 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 1 ;;
            i|I) show_info general; error='' ;;
            x|X) exit_tui ;;
            '') ADD_NODE_PORT=22; return 0 ;;
            *)
                if [[ "$port_value" =~ ^[0-9]+$ ]] && ((10#$port_value >= 1 && 10#$port_value <= 65535)); then
                    ADD_NODE_PORT="$port_value"
                    return 0
                fi
                error="Invalid VPS port. Enter a number from 1 to 65535."
                ;;
        esac
    done
}

add_node_password_prompt() {
    clear_screen
    menu_heading "Add VPN server"
    printf '%s\n' "Enter the password for the first VPS connection."
    printf '%b%s%b\n' "$COLOR_MUTED_ITALIC" "The password is used only to verify access and start deployment." "$COLOR_RESET"
    echo
    if ! read_secret 'Enter VPS password: '; then
        return 1
    fi
    ADD_NODE_PASSWORD="$REPLY"
}

add_node_domain_prompt() {
    local domain_value error=''
    while true; do
        clear_screen
        menu_heading "Add VPN server"
        printf '%b%s%b\n' "$COLOR_MUTED_ITALIC" "This domain helps the VPN connection look like normal HTTPS traffic." "$COLOR_RESET"
        printf '%b%s%b\n' "$COLOR_MUTED_ITALIC" "Use a real HTTPS website that supports TLS 1.3." "$COLOR_RESET"
        printf '%b%s%b\n' "$COLOR_MUTED_ITALIC" "Press Enter to use the default value shown in [brackets]." "$COLOR_RESET"
        [[ -n "$error" ]] && printf '%s\n' "$error"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read -r -e -p 'Enter domain [github.com]: ' domain_value; then
            return 1
        fi
        case "$domain_value" in
            b|B) return 1 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 1 ;;
            i|I) show_info general; error='' ;;
            x|X) exit_tui ;;
            '') domain_value=github.com ;;
        esac
        if [[ "$domain_value" == b || "$domain_value" == B || "$domain_value" == m || "$domain_value" == M || "$domain_value" == i || "$domain_value" == I || "$domain_value" == x || "$domain_value" == X ]]; then
            continue
        fi
        if valid_server_name "$domain_value"; then
            ADD_NODE_SERVER_NAME="${domain_value,,}"
            return 0
        fi
        error="Invalid domain. Use an HTTPS hostname such as github.com."
    done
}

review_node_connection() {
    local choice
    while true; do
        clear_screen
        menu_heading "Review VPS connection"
        echo
        printf '%-16s %s\n' "IP address:" "$1"
        printf '%-16s %s\n' "User:" "$2"
        printf '%-16s %s\n' "Port:" "$3"
        printf '%-16s %s\n' "Password:" "entered"
        echo
        menu_option 1 Continue
        menu_option 2 Edit
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice choice '?: ' '1 or 2, or b, m, i, x'; then
            continue
        fi
        case "$choice" in
            1) return 0 ;;
            2) return 1 ;;
            b|B) return 2 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 2 ;;
            i|I) show_info general ;;
            x|X) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

bootstrap_auth_failure_menu() {
    local choice
    while true; do
        clear_screen
        printf '%s\n' "VPS authentication failed. The user or password was rejected."
        printf '%s\n' "Choose what to do next."
        echo
        menu_option 1 "Enter password again"
        menu_option 2 "Edit VPS connection"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice choice '?: ' '1 or 2, or b, m, i, x'; then
            continue
        fi
        case "$choice" in
            1) return 0 ;;
            2) return 1 ;;
            b|B) return 2 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 2 ;;
            i|I) show_info general ;;
            x|X) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

bootstrap_connection_failure_menu() {
    local host="$1" port="$2" choice
    while true; do
        clear_screen
        printf '%s\n' "VPS SSH connection unavailable"
        printf '%s\n' "The VPS did not accept an SSH connection."
        printf '%-16s %s\n' "IP address:" "$host"
        printf '%-16s %s\n' "Port:" "$port"
        printf '%s\n' "Check the IP address and SSH port."
        echo
        menu_option 1 "Edit VPS connection"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice choice '?: ' '1, or b, m, i, x'; then
            continue
        fi
        case "$choice" in
            1) return 0 ;;
            b|B) return 2 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 2 ;;
            i|I) show_info general ;;
            x|X) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

local_internet_failure_menu() {
    local choice
    while true; do
        clear_screen
        printf '%s\n' "Internet connection unavailable"
        printf '%s\n' "The computer running Xray TUI cannot reach the Internet."
        printf '%s\n' "Check the local network, proxy, or firewall settings."
        echo
        menu_option 1 "Try again"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice choice '?: ' '1, or b, m, i, x'; then
            continue
        fi
        case "$choice" in
            1) return 0 ;;
            b|B) return 2 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 2 ;;
            i|I) show_info general ;;
            x|X) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

bootstrap_preflight_failure_menu() {
    local choice
    while true; do
        clear_screen
        printf '%s\n' "VPS preflight failed"
        printf '%s\n' "The VPS did not pass the initial checks."
        printf '%s\n' "Deployment was not started."
        printf '%s\n' "Check the VPS operating system, SSH access, and system configuration."
        echo
        menu_option 1 "Edit VPS connection"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice choice '?: ' '1, or b, m, i, x'; then
            continue
        fi
        case "$choice" in
            1) return 0 ;;
            b|B) return 2 ;;
            m|M) MAIN_MENU_REQUESTED=1; return 2 ;;
            i|I) show_info general ;;
            x|X) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}


while true; do
    clear_screen
    echo
    menu_option 1 "VPN servers"
    menu_option 2 "Add VPN server"
    menu_option 3 Vault
    echo
    menu_control i info
    menu_control x exit
    echo
    if ! read_required_choice choice '?: ' '1, 2, 3, i, or x'; then continue; fi
    MAIN_MENU_REQUESTED=0
    case "$choice" in
        1) vpn_servers || true ;;
        2) add_node || true ;;
        3) secure_state || true ;;
        i) show_info general ;;
        x) exit_tui ;;
        *) invalid_choice ;;
    esac
done
