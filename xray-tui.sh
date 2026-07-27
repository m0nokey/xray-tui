#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COUNTRIES_FILE="$ROOT_DIR/data/countries.tsv"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"
VAULT_FILE="$STATE_DIR/vault.json"
HOST_STATE_DIR="${XRAY_TUI_HOST_STATE_DIR:-$STATE_DIR}"
HOST_VAULT_FILE="$HOST_STATE_DIR/vault.json"
VAULT_PASSWORD_FILE=""
MAIN_MENU_REQUESTED=0
LAST_ANSIBLE_OUTPUT=""
# Internal status used to distinguish missing saved SSH access from deployment errors.
readonly NO_SAVED_SSH_ACCESS=125
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
export ANSIBLE_LOCAL_TEMP=/tmp/ansible-local
export ANSIBLE_SSH_CONTROL_PATH_DIR=/tmp/ansible-cp
export ANSIBLE_CONFIG="$ROOT_DIR/ansible/ansible.cfg"
export ANSIBLE_FORCE_COLOR=true
mkdir -p "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_SSH_CONTROL_PATH_DIR"

if [[ -t 1 ]]; then
    COLOR_RESET=$'\033[0m'
    COLOR_TEXT=$'\033[97m'
    COLOR_HEADER=$'\033[38;5;183m'
    COLOR_LINE=$'\033[38;5;117m'
    COLOR_INFO=$'\033[38;5;117m'
    COLOR_WARN=$'\033[38;5;221m'
    COLOR_ERROR=$'\033[38;5;203m'
    COLOR_MUTED=$'\033[38;5;245m'
else
    COLOR_RESET=''
    COLOR_TEXT=''
    COLOR_HEADER=''
    COLOR_LINE=''
    COLOR_INFO=''
    COLOR_WARN=''
    COLOR_ERROR=''
    COLOR_MUTED=''
fi

cleanup() {
    [[ -n "$VAULT_PASSWORD_FILE" ]] && rm -f "$VAULT_PASSWORD_FILE"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

read_ascii_secret() {
    local prompt="$1" value read_status
    printf '%s' "$prompt" >&2
    read -r -s value
    read_status=$?
    printf '\n' >&2
    if ((read_status != 0)); then
        unset value
        return 1
    fi
    if (export LC_ALL=C; [[ -n "$value" && "$value" =~ ^[[:print:]]+$ ]]); then
        REPLY="$value"
        unset value
        return 0
    fi
    unset value
    printf '%s\n' "Invalid password. Use printable ASCII characters with the English keyboard layout." >&2
    sleep 1
    clear_screen
    return 1
}

create_vault_password_file() {
    local password password_confirm attempt
    attempt=0
    while ((attempt < 3)); do
        attempt=$((attempt + 1))
        clear_screen
        printf '%s\n' "An encrypted Vault will be created on this computer." >&2
        printf '%s\n' "It will store your VPS access data and VPN keys." >&2
        printf '%s\n' "Create and remember a strong Vault password." >&2
        printf '\n' >&2
        if ! read_ascii_secret "Create Vault password (attempt ${attempt}/3): "; then
            continue
        fi
        password="$REPLY"
        if ! read_ascii_secret "Confirm Vault password (attempt ${attempt}/3): "; then
            unset password
            continue
        fi
        password_confirm="$REPLY"
        if [[ "$password" != "$password_confirm" ]]; then
            unset password password_confirm
            clear_screen
            printf '%s\n' "Vault passwords do not match. Please try again." >&2
            sleep 1.5
            continue
        fi
        VAULT_PASSWORD_FILE="$(mktemp /tmp/xray-vault-password.XXXXXX)"
        chmod 600 "$VAULT_PASSWORD_FILE"
        printf '%s\n' "$password" >"$VAULT_PASSWORD_FILE"
        unset password password_confirm
        return 0
    done
    printf '%s\n' "Vault password setup failed after 3 attempts." >&2
    sleep 2.5
    return 1
}

ensure_vault_password_file() {
    local password attempt checked_state vault_view_status
    [[ -n "$VAULT_PASSWORD_FILE" && -f "$VAULT_PASSWORD_FILE" ]] && return 0

    if [[ ! -f "$VAULT_FILE" ]]; then
        create_vault_password_file || return 1
        clear_screen
        return 0
    fi

    if ! vault_ciphertext_valid; then
        rm -f "$VAULT_FILE" "$VAULT_PASSWORD_FILE"
        VAULT_PASSWORD_FILE=""
        clear_screen
        printf '%s\n' "The existing Vault is damaged and was removed." >&2
        printf '%s\n' "A new encrypted Vault will be created now." >&2
        sleep 2.5
        create_vault_password_file || return 1
        clear_screen
        return 0
    fi

    attempt=0
    while ((attempt < 3)); do
        attempt=$((attempt + 1))
        clear_screen
        printf '%s\n' "An encrypted Vault was found on this computer." >&2
        printf '%s\n' "It contains saved VPS access data and VPN keys." >&2
        printf '%s\n' "Enter the Vault password to unlock it." >&2
        printf '\n' >&2
        VAULT_PASSWORD_FILE="$(mktemp /tmp/xray-vault-password.XXXXXX)"
        chmod 600 "$VAULT_PASSWORD_FILE"
        if ! read_ascii_secret "Vault password (attempt ${attempt}/3): "; then
            rm -f "$VAULT_PASSWORD_FILE"
            VAULT_PASSWORD_FILE=""
            continue
        fi
        password="$REPLY"
        printf '%s\n' "$password" >"$VAULT_PASSWORD_FILE"
        unset password
        checked_state="$(mktemp /tmp/xray-vault-check.XXXXXX)"
        vault_view_status=0
        ansible-vault view --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE" >"$checked_state" 2>/dev/null || vault_view_status=$?
        if [[ "$vault_view_status" == 0 ]]; then
            if json_file_valid "$checked_state"; then
                rm -f "$checked_state"
                clear_screen
                return 0
            fi
            rm -f "$checked_state"
            rm -f "$VAULT_PASSWORD_FILE"
            VAULT_PASSWORD_FILE=""
            rm -f "$VAULT_FILE"
            clear_screen
            printf '%s\n' "The existing Vault state is damaged and was removed." >&2
            printf '%s\n' "A new encrypted Vault will be created now." >&2
            sleep 2.5
            create_vault_password_file || return 1
            clear_screen
            return 0
        fi
        rm -f "$checked_state"
        rm -f "$VAULT_PASSWORD_FILE"
        VAULT_PASSWORD_FILE=""
        clear_screen
        if [[ "$attempt" -lt 3 ]]; then
            printf '%s\n' "The Vault password is incorrect. Please try again." >&2
            sleep 1.5
            clear_screen
        fi
    done
    printf '%s\n' "Vault password verification failed after 3 attempts." >&2
    sleep 2.5
    return 1
}

valid_ipv4() {
    local address="$1" part
    local -a octets
    IFS=. read -r -a octets <<<"$address"
    [[ "${#octets[@]}" == 4 ]] || return 1
    for part in "${octets[@]}"; do
        [[ "$part" =~ ^[0-9]+$ ]] || return 1
        ((10#$part <= 255)) || return 1
    done
}

valid_server_name() {
    local value="$1" label
    local -a labels
    [[ -n "$value" && ${#value} -le 253 ]] || return 1
    [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] || return 1
    IFS=. read -r -a labels <<<"$value"
    for label in "${labels[@]}"; do
        (( ${#label} <= 63 )) || return 1
    done
}

json_file_valid() {
    python3 - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        state = json.load(stream)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)

if not isinstance(state, dict) or not isinstance(state.get("nodes"), dict):
    raise SystemExit(1)
PY
}

vault_ciphertext_valid() {
    [[ -s "$VAULT_FILE" ]] || return 1
    awk '
        NR == 1 {
            fields = split($0, header, ";")
            if (fields != 3 || header[1] != "$ANSIBLE_VAULT" ||
                header[2] !~ /^[0-9]+[.][0-9]+$/ ||
                header[3] !~ /^[A-Za-z0-9_-]+$/) bad = 1
            next
        }
        {
            if ($0 !~ /^[0-9A-Fa-f]+$/ || length($0) % 2 != 0) bad = 1
            payload = 1
        }
        END { exit (bad || !payload) ? 1 : 0 }
    ' "$VAULT_FILE"
}

vault_view() {
    if [[ -f "$VAULT_FILE" ]]; then
        local output
        if ! ensure_vault_password_file; then
            return 1
        fi
        if [[ ! -f "$VAULT_FILE" ]]; then
            printf '{"nodes":{}}\n'
            return 0
        fi
        output="$(mktemp "$STATE_DIR/.view.XXXXXX")"
        if ! ansible-vault view --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE" >"$output"; then
            rm -f "$output"
            return 1
        fi
        if ! json_file_valid "$output"; then
            rm -f "$output"
            printf '%s\n' "The encrypted Vault contains invalid state and was not changed." >&2
            return 1
        fi
        cat "$output"
        rm -f "$output"
    else
        printf '{"nodes":{}}\n'
    fi
}

read_vault_state() {
    local output="$1"
    if ! vault_view >"$output"; then
        rm -f "$output"
        clear_screen
        printf '%s\n' "Unable to read the encrypted Vault state."
        printf '%s\n' "Restore a valid backup or delete the invalid Vault before continuing."
        printf '%s\n' "The Vault was not changed."
        read -r -p "Press Enter to continue" _
        return 1
    fi
}

vault_state_command() {
    local state command_status
    state="$(mktemp "$STATE_DIR/.read.XXXXXX")"
    if ! read_vault_state "$state"; then
        rm -f "$state"
        return 1
    fi
    if "$@" <"$state"; then
        command_status=0
    else
        command_status=$?
    fi
    rm -f "$state"
    return "$command_status"
}

vault_save() {
    local input="$1" encrypted checked
    if ! ensure_vault_password_file; then
        return 1
    fi
    if ! json_file_valid "$input"; then
        printf '%s\n' "Refusing to save invalid Vault state." >&2
        return 1
    fi
    encrypted="$(mktemp "$STATE_DIR/.vault.XXXXXX")"
    checked="$(mktemp "$STATE_DIR/.decrypted.XXXXXX")"
    chmod 600 "$encrypted" "$checked"
    if ! ansible-vault encrypt "$input" --output "$encrypted" --vault-password-file "$VAULT_PASSWORD_FILE"; then
        rm -f "$encrypted" "$checked"
        return 1
    fi
    if ! ansible-vault view --vault-password-file "$VAULT_PASSWORD_FILE" "$encrypted" >"$checked" || ! json_file_valid "$checked"; then
        rm -f "$encrypted" "$checked"
        printf '%s\n' "Refusing to install an invalid encrypted Vault." >&2
        return 1
    fi
    mv -f "$encrypted" "$VAULT_FILE"
    chmod 600 "$VAULT_FILE"
    rm -f "$checked"
}

state_mutate() {
    local action="$1"; shift
    local before after
    before="$(mktemp "$STATE_DIR/.before.XXXXXX")"
    after="$(mktemp "$STATE_DIR/.after.XXXXXX")"
    read_vault_state "$before" || { rm -f "$before" "$after"; return 1; }
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" "$action" "$@" <"$before" >"$after"; then
        rm -f "$before" "$after"
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        clear_screen
        printf '%s\n' "The Vault was not changed."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    rm -f "$before" "$after"
}

initialize_vault() {
    local temp
    temp="$(mktemp "$STATE_DIR/.initial-state.XXXXXX")"
    printf '{"nodes":{}}\n' >"$temp"
    if ! vault_save "$temp"; then
        rm -f "$temp"
        printf '%s\n' "Vault creation failed."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    rm -f "$temp"
    printf '%s\n' "Vault created."
    read -r -p "Press Enter to continue" _
}

delete_vault() {
    local confirm
    while true; do
        clear_screen
        echo
        menu_heading "Delete Vault:"
        echo
        printf '%s\n' "This will delete the Vault, its backups, and all saved VPS/VPN access data."
        echo
        printf '%s\n' "Are you sure you want to delete the Vault? (y/n)"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice confirm '?: '; then continue; fi
        case "$confirm" in
            [Yy]) break ;;
            [Nn]|b) return 0 ;;
            m) MAIN_MENU_REQUESTED=1; return 0 ;;
            i) show_info vault ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
    rm -f "$VAULT_FILE" "$STATE_DIR/vault.json.backup" "$VAULT_PASSWORD_FILE"
    rm -rf "$STATE_DIR/backups"
    rm -f "$STATE_DIR"/vault.json.restore.*
    VAULT_PASSWORD_FILE=""
    printf '%s\n' "Vault deleted."
    read -r -p "Press Enter to continue" _
}

has_vault_backups() {
    compgen -G "$STATE_DIR/backups/vault-*.tar.gz" >/dev/null
}

backup_vault() {
    local backup_dir backup_file
    backup_dir="$STATE_DIR/backups"
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    backup_file="$backup_dir/vault-$(date -u '+%Y%m%dT%H%M%SZ').tar.gz"
    if ! tar -C "$STATE_DIR" -czf "$backup_file" "$(basename "$VAULT_FILE")"; then
        rm -f "$backup_file"
        printf '%s\n' "Could not create the encrypted Vault backup."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    chmod 600 "$backup_file"
    printf '%s\n' "Encrypted Vault backup created:"
    printf '%s\n' "$backup_file"
    read -r -p "Press Enter to continue" _
}

restore_vault() {
    local archive tmpdir entry restored current_backup
    read -r -e -p 'Encrypted Vault backup path: ' archive
    if [[ ! -f "$archive" ]]; then
        printf '%s\n' "Backup file not found."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    entry="$(tar -tzf "$archive" 2>/dev/null | awk '$0 == "vault.json" { print; exit }')"
    if [[ -z "$entry" ]]; then
        printf '%s\n' "Invalid backup: vault.json was not found."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    tmpdir="$(mktemp -d /tmp/xray-vault-restore.XXXXXX)"
    if ! tar -xzf "$archive" -C "$tmpdir" "$entry"; then
        rm -rf "$tmpdir"
        printf '%s\n' "Could not extract the encrypted Vault backup."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    restored="$tmpdir/$entry"
    if [[ ! -s "$restored" ]]; then
        rm -rf "$tmpdir"
        printf '%s\n' "Invalid backup: the encrypted Vault is empty."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    if [[ -f "$VAULT_FILE" ]]; then
        current_backup="$STATE_DIR/vault.json.restore.$(date -u '+%Y%m%dT%H%M%SZ')"
        mv "$VAULT_FILE" "$current_backup"
        chmod 600 "$current_backup"
    fi
    mv "$restored" "$VAULT_FILE"
    chmod 600 "$VAULT_FILE"
    rm -rf "$tmpdir"
    rm -f "$VAULT_PASSWORD_FILE"
    VAULT_PASSWORD_FILE=""
    printf '%s\n' "Encrypted Vault restored."
    read -r -p "Press Enter to continue" _
}

read_required_choice() {
    local variable="$1" prompt="$2" value=''
    if ! read -r -e -p "$prompt" value; then
        return 1
    fi
    if [[ -z "$value" ]]; then
        invalid_choice
        clear_screen
        return 2
    fi
    printf -v "$variable" '%s' "$value"
}

prompt_nav() {
    echo
    menu_control b back
    menu_control m main
    menu_control i info
    menu_control x exit
    echo
    read_required_choice REPLY '?: '
}

menu_heading() {
    printf '%s%s%s\n' "$COLOR_LINE" "$1" "$COLOR_RESET"
}

menu_option() {
    printf '%s%s.%s %s%s%s\n' "$COLOR_LINE" "$1" "$COLOR_RESET" "$COLOR_TEXT" "$2" "$COLOR_RESET"
}

menu_control() {
    printf '%s%s.%s %s%s%s\n' "$COLOR_LINE" "$1" "$COLOR_RESET" "$COLOR_TEXT" "$2" "$COLOR_RESET"
}

show_dns_profile_matrix() {
    local separator
    separator="    $(printf '%*s' 103 '' | tr ' ' '-')"
    printf '%s\n' "PROFILE LIST MATRIX"
    printf '%s\n' ""
    printf '    %-45s %9s %9s %9s %9s %17s\n' \
        "List" "Minimal" "Optimal" "Full" "Maximum" "Approx. entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "URLhaus" "ON" "ON" "ON" "ON" "~611 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "HaGeZi Threat Intelligence Feeds Mini" "-" "ON" "-" "-" "160,610 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "HaGeZi Encrypted DNS" "-" "-" "ON" "-" "3,423 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "HaGeZi Encrypted DNS/VPN/Proxy Bypass" "-" "-" "-" "ON" "17,591 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "AdGuard CNAME Trackers" "-" "-" "ON" "ON" "~100,087 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "AdGuard Mail Trackers" "-" "-" "ON" "ON" "~98,595 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "ThreatFox" "-" "-" "ON" "ON" "~45,617 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "HaGeZi Pro++" "-" "-" "ON" "-" "272,267 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "HaGeZi Ultimate" "-" "-" "-" "ON" "294,364 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "HaGeZi Threat Intelligence Feeds Medium" "-" "-" "-" "ON" "417,094 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Threat Intelligence IPs" "-" "-" "-" "ON" "~54,609 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Dynamic DNS Threats" "-" "-" "optional" "ON" "1,524 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Suspicious Spam TLDs" "-" "-" "-" "optional" "~129 entries"
    printf '%s\n' "$separator"
    printf '%s\n' ""
    printf '%s\n' "    Custom-only sources"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Pop-up Ads" "-" "optional" "included" "included" "56,598 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Adult Content" "-" "optional" "optional" "optional" "110,004 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Gambling Mini" "-" "optional" "optional" "optional" "94,060 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Gambling Medium" "-" "-" "optional" "optional" "155,276 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Gambling Full" "-" "-" "optional" "optional" "357,251 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Social Networks" "-" "-" "optional" "optional" "898 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "SafeSearch" "-" "-" "optional" "optional" "206 entries"
    printf '%s\n' "$separator"
    printf '    %-45s %9s %9s %9s %9s %17s\n' "Anti Piracy" "-" "-" "optional" "optional" "36,844 entries"
    printf '%s\n' "$separator"
    printf '%s\n' ""
    printf '%s\n' "    Counts are upstream list values and may change when sources update."
}

show_info() {
    local topic="${1:-general}"
    local reset="$COLOR_RESET" blue="$COLOR_LINE" gray="$COLOR_MUTED"
    local green=$'\033[92m' yellow=$'\033[93m' red=$'\033[91m'

    if [[ ! -t 1 ]]; then
        reset=''
        blue=''
        gray=''
        green=''
        yellow=''
        red=''
    fi

    info_desc() {
        printf '    %b%s%b\n' "$gray" "$1" "$reset"
    }

    clear_screen
    echo
    case "$topic" in
        status)
            printf '%b  Status:%b\n' "$blue" "$reset"
            printf '    %bActive%b           %bXray is running and both VPN ports are reachable.%b\n' "$green" "$reset" "$gray" "$reset"
            printf '    %bPartial%b          %bXray is running and only one VPN port is reachable.%b\n' "$yellow" "$reset" "$gray" "$reset"
            printf '    %bVPN unavailable%b  %bThe VPS responded, but Xray is not confirmed running.%b\n' "$red" "$reset" "$gray" "$reset"
            printf '    %bUnreachable%b      %bNo VPN or management port responded; DPI or a provider firewall may be involved.%b\n' "$red" "$reset" "$gray" "$reset"
            echo
            printf '%b  Selected server menu:%b\n' "$blue" "$reset"
            printf '%s\n' "    1. Manage VPN server"
            info_desc "       Open server operations, ad and threat blocking, country blocking, or removal."
            printf '%s\n' "    2. Manage access keys"
            info_desc "       Show, add, or remove the VPN client keys for this server."
            ;;
        access_keys)
            printf '%b  Access keys:%b\n' "$blue" "$reset"
            info_desc "Each access key contains one Vision UUID and one XHTTP UUID."
            info_desc "Both UUIDs are deployed together and removed together."
            info_desc "You can add up to 50 access keys at once."
            info_desc "In the remove screen, enter a key number or the last number to remove all keys."
            echo
            printf '%b  Manage access keys menu:%b\n' "$blue" "$reset"
            printf '%s\n' "    1. Show"
            info_desc "       Display the Vision and XHTTP connection links for each key."
            printf '%s\n' "    2. Add"
            info_desc "       Generate 1 to 50 new access keys and deploy them to the VPS."
            printf '%s\n' "    3. Remove"
            info_desc "       Remove one key, or choose the final number to remove all keys."
            echo
            printf '%b  Access-key screens:%b\n' "$blue" "$reset"
            info_desc "Add: enter the number of keys to generate, from 1 to 50."
            info_desc "Remove: select a key number, then confirm with y or cancel with n."
            info_desc "Remove all: confirm that every Vision and XHTTP key should be deleted."
            ;;
        dns)
            printf '%b  Block ads and threats:%b\n' "$blue" "$reset"
            printf '    %-7s - %s\n' "Minimal" "malware and malicious websites."
            printf '    %-7s - %s\n' "Optimal" "malware, phishing, scams and selected trackers."
            printf '    %-7s - %s\n' "Full" "ads, tracking, telemetry and malware."
            printf '    %-7s - %s\n' "Maximum" "broad threat protection and known DNS bypass services."
            printf '    %-7s - %s\n' "Custom" "choose extra categories within the VPS resource limit."
            info_desc "Full includes Encrypted DNS protection; Custom can disable it for TV compatibility."
            info_desc "Blocked domains return NXDOMAIN. DNS filtering does not replace a firewall."
            echo
            printf '%b  Block ads and threats menu:%b\n' "$blue" "$reset"
            printf '%s\n' "    1. Disabled"
            info_desc "       Remove DNS blocklists from the VPS."
            printf '%s\n' "    2. Minimal"
            info_desc "       Enable malware and malicious website protection."
            printf '%s\n' "    3. Optimal"
            info_desc "       Add phishing, scams, and selected tracker protection."
            printf '%s\n' "    4. Full"
            info_desc "       Add advertising, tracking, telemetry, and broader threat protection."
            printf '%s\n' "    5. Maximum"
            info_desc "       Add broad threat feeds and known DNS bypass service domains."
            printf '%s\n' "    6. Custom"
            info_desc "       Toggle individual lists and apply a resource-checked combination."
            echo
            show_dns_profile_matrix
            echo
            printf '%b  List descriptions:%b\n' "$blue" "$reset"
            printf '    %-32s - %s\n' "URLhaus" "malware delivery and malicious website domains."
            printf '    %-32s - %s\n' "Threat Intelligence Feeds Mini" "malware, phishing, scams and attacker infrastructure."
            printf '    %-32s - %s\n' "Encrypted DNS" "known DoH and DoT resolver domains."
            printf '    %-32s - %s\n' "DNS/VPN/Proxy Bypass" "known DoH, VPN and proxy service domains; not all exit-node IPs."
            printf '    %-32s - %s\n' "CNAME Trackers" "trackers hidden behind CNAME DNS records."
            printf '    %-32s - %s\n' "Mail Trackers" "tracking pixels and link-tracking domains in emails."
            printf '    %-32s - %s\n' "ThreatFox" "malware indicators and command-and-control domains."
            printf '    %-32s - %s\n' "Pro++" "ads, trackers, telemetry, malware, phishing and scams."
            printf '    %-32s - %s\n' "Ultimate" "aggressive privacy and security filtering with higher false positives."
            printf '    %-32s - %s\n' "Threat Intelligence Feeds Medium" "a larger malware, phishing, scam and attacker infrastructure feed."
            printf '    %-32s - %s\n' "Threat Intelligence IPs" "IP-related threat indicators in RPZ form; not an IP firewall."
            printf '    %-32s - %s\n' "Dynamic DNS Threats" "suspicious dynamic DNS used by malware and phishing."
            printf '    %-32s - %s\n' "Suspicious Spam TLDs" "selected high-abuse TLDs; legitimate sites may be blocked."
            printf '    %-32s - %s\n' "Pop-up Ads" "known pop-up and aggressive advertising domains."
            printf '    %-32s - %s\n' "Adult Content" "adult and NSFW domains; not a complete parental-control system."
            printf '    %-32s - %s\n' "Gambling Mini" "selected betting, casino and gambling domains."
            printf '    %-32s - %s\n' "Gambling Medium" "a broader betting, casino and gambling domain list."
            printf '    %-32s - %s\n' "Gambling Full" "the broadest betting, casino and gambling domain list."
            printf '    %-32s - %s\n' "Social Networks" "selected social media domains."
            printf '    %-32s - %s\n' "SafeSearch" "helps enforce safer search endpoints."
            printf '    %-32s - %s\n' "Anti Piracy" "torrent, warez and known piracy domains."
            printf '    %-32s : %s\n' "Source repository" "https://github.com/hagezi/dns-blocklists"
            echo
            printf '%b  Custom selection:%b\n' "$blue" "$reset"
            info_desc "Select a number to toggle a list. [ON] means it will be deployed."
            info_desc "The selected lists are checked against the detected VPS CPU and RAM."
            info_desc "Large alternatives are mutually exclusive: Pro++/Ultimate, TIF Mini/Medium, and Gambling sizes."
            info_desc "Apply saves the selected lists in the Vault only after the VPS deployment succeeds."
            ;;
        local_region)
            printf '%b  Block countries:%b\n' "$blue" "$reset"
            info_desc "Select one or more countries whose destinations should be blocked on the VPS."
            info_desc "This is a fallback policy for clients that cannot route local traffic directly."
            info_desc "Xray blocks IP ranges assigned to the selected countries."
            info_desc "For Russia, .ru and .рф domains are also matched when RU is selected."
            info_desc "Other country domains may use foreign CDNs and are not a complete domain-zone block."
            info_desc "This does not route traffic directly and does not guarantee that a VPN will be undetectable."
            info_desc "Shared hosting, CDNs, geolocation databases, and country domains can cause false positives."
            info_desc "The policy is stored for this VPN node and applies to all its access keys."
            echo
            printf '%b  Block countries menu:%b\n' "$blue" "$reset"
            printf '%s\n' "    1. Select countries"
            info_desc "       Search by country name or ISO code and toggle multiple checkboxes."
            printf '%s\n' "    2. Disable policy"
            info_desc "       Remove all country blocking rules from this VPN node."
            info_desc "Use Apply after selecting countries; the Vault changes only after deployment succeeds."
            ;;
        server)
            printf '%b  Manage VPN server:%b\n' "$blue" "$reset"
            printf '%s\n' "    1. Check VPN status"
            info_desc "       Test management SSH, the Xray container, and both VPN ports."
            printf '%s\n' "    2. Restart VPN server"
            info_desc "       Restart the Xray Docker stack without changing keys or profiles."
            printf '%s\n' "    3. Block ads and threats"
            info_desc "       Choose protection against ads, trackers, malware, phishing, and other known threats."
            printf '%s\n' "    4. Block countries"
            info_desc "       Stop connections to selected countries when direct bypass is unavailable."
            printf '%s\n' "    5. Rotate SSH key"
            info_desc "       Generate a new management key, verify it, then revoke the old key."
            printf '%s\n' "    6. Remove VPN server"
            info_desc "       Clean Xray and Docker from the VPS before removing its Vault entry."
            printf '%s\n' "    7. Open SSH session"
            info_desc "       Connect as the saved management user using the saved SSH key and port."
            ;;
        vault)
            printf '%b  Vault:%b\n' "$blue" "$reset"
            info_desc "The Vault is encrypted local storage for VPS access data and VPN keys."
            info_desc "It is unlocked only when an operation needs the saved data."
            info_desc "Keep the Vault password safe: it cannot be recovered from the file."
            echo
            printf '%b  Vault menu:%b\n' "$blue" "$reset"
            printf '%s\n' "    1. Change encryption password"
            info_desc "       Re-encrypt the Vault with a new local password."
            printf '%s\n' "    2. Backup encrypted state"
            info_desc "       Create a copy of the encrypted Vault for recovery."
            printf '%s\n' "    3. Restore encrypted state"
            info_desc "       Replace the current Vault with a selected encrypted backup."
            printf '%s\n' "    4. Delete Vault"
            info_desc "       Delete local Vault data, backups, VPS credentials, and VPN keys."
            info_desc "When no Vault exists, option 1 creates it and option 2 restores a backup."
            ;;
        removal)
            printf '%b  Remote cleanup:%b\n' "$blue" "$reset"
            info_desc "Confirm with y to remove the VPN server from the VPS."
            info_desc "Cancel with n or b to leave the VPS and Vault unchanged."
            info_desc "Xray, Docker, updater services, and the deploy user are removed from the VPS."
            info_desc "The original SSH configuration is restored from its backup."
            info_desc "The server stays in the Vault if remote cleanup fails."
            info_desc "After a failed cleanup, r retries with the initial SSH credentials."
            info_desc "You can remove only the local Vault entry with y after a failed cleanup; verify the VPS separately."
            ;;
        *)
            printf '%b  Xray TUI:%b\n' "$blue" "$reset"
            info_desc "This tool installs and manages your Xray VPN servers."
            info_desc "VPS access data and VPN keys are kept in the encrypted Vault."
            echo
            printf '%b  Main menu:%b\n' "$blue" "$reset"
            echo
            printf '%s\n' "  1. VPN servers"
            info_desc " - View the VPN servers saved in the Vault."
            info_desc " - Check the VPS, SSH, Xray, and VPN port status."
            info_desc " - Select a server to manage it."
            info_desc " - If there are no servers, add one with option 2 first."
            echo
            printf '%s\n' "     Selected server menu:"
            printf '%s\n' "     1. Manage VPN server"
            info_desc "        Check status, restart Xray, manage DNS and country policy, rotate the SSH key, or remove the server."
            printf '%s\n' "     2. Manage access keys"
            info_desc "        Show, add, or remove VPN access keys for this server."
            echo
            printf '%s\n' "  2. Add VPN server"
            info_desc " - Enter the VPS IP address, SSH user, SSH port, and password."
            info_desc " - Enter a Reality camouflage domain, or use github.com by default."
            info_desc " - Choose a profile to block ads, trackers, malware, phishing, and other threats."
            info_desc "   The menu checks VPS resources before allowing a profile."
            info_desc " - Install Docker, Xray, automatic updates, and SSH hardening."
            info_desc " - Generate VPN access keys and save all connection data in the Vault."
            info_desc " - Repeating setup for the same VPS is safe and idempotent."
            echo
            printf '%s\n' "  3. Vault"
            printf '%s\n' "     1. Change encryption password"
            info_desc "        Change the password protecting the local Vault."
            printf '%s\n' "     2. Backup encrypted state"
            info_desc "        Create a backup containing the encrypted Vault file."
            printf '%s\n' "     3. Restore encrypted state"
            info_desc "        Replace the current Vault with a selected encrypted backup."
            printf '%s\n' "     4. Delete Vault"
            info_desc "        Delete local VPS access data, VPN keys, and Vault backups."
            echo
            printf '%s\n' "  Manage VPN server"
            printf '%s\n' "     1. Check VPN status"
            info_desc "        Test SSH access, the Xray container, and both VPN ports."
            printf '%s\n' "     2. Restart VPN server"
            info_desc "        Restart the Xray Docker stack without changing access keys."
            printf '%s\n' "     3. Block ads and threats"
            info_desc "        Enable, disable, or change protection against ads and known threats."
            printf '%s\n' "     4. Block countries"
            info_desc "        Stop connections to selected countries when client bypass is unavailable."
            printf '%s\n' "     5. Rotate SSH key"
            info_desc "        Generate a new deploy SSH key and revoke the old one."
            printf '%s\n' "     6. Remove VPN server"
            info_desc "        Remove the Xray installation and clean up the VPS."
            info_desc "        The Vault is changed only after remote cleanup succeeds."
            echo
            printf '%s\n' "  Manage access keys"
            printf '%s\n' "     1. Show"
            info_desc "        Display the Vision and XHTTP connection links for each key."
            printf '%s\n' "     2. Add"
            info_desc "        Add from 1 to 50 access keys and deploy them to the VPS."
            printf '%s\n' "     3. Remove"
            info_desc "        Select a key by number and remove both protocol UUIDs together."
            info_desc "        Choose the last number to remove every access key at once."
            ;;
    esac
    echo
    read -r -e -p "Press Enter to return" _
}

clear_screen() {
    printf '\033[H\033[2J\033[3J' >&2
}

wait_action_return() {
    local key
    [[ -t 0 ]] || return 0
    while true; do
        printf '\n\033[90mPress Enter or Space to return to the menu.\033[0m'
        IFS= read -r -s -n 1 key || return 0
        case "$key" in
            ""|" ")
                echo
                return 0
                ;;
            x|X)
                exit_tui
                ;;
        esac
    done
}

exit_tui() {
    clear_screen
    exit 0
}

invalid_choice() {
    printf '%s\n' "Invalid input. Enter a menu option using the English keyboard layout."
    sleep 1
}

show_nodes() {
    local state
    state="$(mktemp "$STATE_DIR/.nodes.XXXXXX")"
    if materialize_vault_state "$state"; then
        python3 "$ROOT_DIR/scripts/render_nodes.py" --check <"$state"
    fi
    rm -f "$state"
}

materialize_vault_state() {
    local state="$1" normalized
    normalized="$(mktemp "$STATE_DIR/.normalized.XXXXXX")"
    if ! read_vault_state "$state"; then
        rm -f "$normalized"
        return 1
    fi
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" normalize <"$state" >"$normalized"; then
        rm -f "$normalized"
        printf '%s\n' "Unable to normalize the encrypted Vault state." >&2
        return 1
    fi
    if ! cmp -s "$state" "$normalized"; then
        if ! vault_save "$normalized"; then
            rm -f "$normalized"
            printf '%s\n' "The encrypted Vault could not be updated." >&2
            return 1
        fi
    fi
    mv -f "$normalized" "$state"
}

show_node_status() {
    local node="$1" state
    state="$(mktemp "$STATE_DIR/.node.XXXXXX")"
    if materialize_vault_state "$state"; then
        python3 "$ROOT_DIR/scripts/render_nodes.py" --check --node "$node" <"$state"
    fi
    rm -f "$state"
}

open_node_ssh_session() {
    local node="$1" state host user port private_key key_file ssh_status
    state="$(mktemp "$STATE_DIR/.ssh-session.XXXXXX")"
    if ! read_vault_state "$state"; then
        rm -f "$state"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$state")"
    user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_user", node.get("deploy_user", "deploy")))' "$node" <"$state")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node.get("ssh_port", 22))))' "$node" <"$state")"
    private_key="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$state")"
    rm -f "$state"

    if [[ -z "$host" || -z "$user" || -z "$port" || -z "$private_key" ]]; then
        clear_screen
        printf '%s\n' "Saved SSH management credentials are incomplete for this VPN server."
        wait_action_return
        return 1
    fi

    key_file="$(mktemp /tmp/xray-ssh-session.XXXXXX)"
    chmod 600 "$key_file"
    printf '%s\n' "$private_key" >"$key_file"
    unset private_key

    clear_screen
    printf '%s\n' "Opening SSH session to ${user}@${host}:${port}."
    printf '%s\n' "Exit the remote shell to return to Xray TUI."
    echo
    if ssh -tt -i "$key_file" -p "$port" \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=8 \
        -o ConnectionAttempts=1 \
        "$user@$host"; then
        ssh_status=0
    else
        ssh_status=$?
    fi
    rm -f "$key_file"
    echo
    if ((ssh_status != 0)); then
        printf '%s\n' "SSH session ended with exit code ${ssh_status}."
    else
        printf '%s\n' "SSH session closed."
    fi
    wait_action_return
    return 0
}

yaml_scalar() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

probe_vps_resources() {
    local host="$1" user="$2" port="$3" password="$4"
    local inventory_dir inventory log password_yaml facts_line
    inventory_dir="$(mktemp -d /tmp/xray-preflight.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    log="$inventory_dir/ansible.log"
    password_yaml="$(yaml_scalar "$password")"
    printf '%s\n' \
        "---" \
        "all:" \
        "  children:" \
        "    xray_nodes:" \
        "      hosts:" \
        "        preflight:" \
        "          ansible_host: $host" \
        "          ansible_user: $user" \
        "          ansible_port: $port" \
        "          ansible_password: $password_yaml" \
        "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password'" \
        >"$inventory"
    chmod 600 "$inventory"
    unset password password_yaml

    clear_screen
    printf '%s\n' "Checking VPS resources..."
    if ! ansible-playbook -i "$inventory" "$ROOT_DIR/ansible/preflight.yml" >"$log" 2>&1; then
        cat "$log"
        rm -rf "$inventory_dir"
        printf '%s\n' "The VPS resources could not be checked. Deployment was not started."
        wait_action_return
        return 1
    fi
    facts_line="$(grep -o 'XRAY_RESOURCE_FACTS vcpus=[0-9][0-9]* ram_mb=[0-9][0-9]*' "$log" | tail -n 1 || true)"
    if [[ ! "$facts_line" =~ vcpus=([0-9]+)[[:space:]]ram_mb=([0-9]+) ]]; then
        cat "$log"
        rm -rf "$inventory_dir"
        printf '%s\n' "The VPS resource report was invalid. Deployment was not started."
        wait_action_return
        return 1
    fi
    VPS_VCPUS="${BASH_REMATCH[1]}"
    VPS_RAM_MB="${BASH_REMATCH[2]}"
    rm -rf "$inventory_dir"
    return 0
}

probe_vps_resources_with_key() {
    local host="$1" user="$2" port="$3" private_key="$4"
    local inventory_dir inventory key_file log facts_line
    inventory_dir="$(mktemp -d /tmp/xray-preflight.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    key_file="$inventory_dir/id_ed25519"
    log="$inventory_dir/ansible.log"
    printf '%s\n' "$private_key" >"$key_file"
    chmod 600 "$key_file"
    printf '%s\n' \
        "---" \
        "all:" \
        "  children:" \
        "    xray_nodes:" \
        "      hosts:" \
        "        preflight:" \
        "          ansible_host: $host" \
        "          ansible_user: $user" \
        "          ansible_port: $port" \
        "          ansible_ssh_private_key_file: $key_file" \
        "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" \
        >"$inventory"
    chmod 600 "$inventory"

    clear_screen
    printf '%s\n' "Checking VPS resources..."
    if ! ansible-playbook -i "$inventory" "$ROOT_DIR/ansible/preflight.yml" >"$log" 2>&1; then
        cat "$log"
        rm -rf "$inventory_dir"
        printf '%s\n' "The VPS resources could not be checked. The DNS profile was not changed."
        wait_action_return
        return 1
    fi
    facts_line="$(grep -o 'XRAY_RESOURCE_FACTS vcpus=[0-9][0-9]* ram_mb=[0-9][0-9]*' "$log" | tail -n 1 || true)"
    if [[ ! "$facts_line" =~ vcpus=([0-9]+)[[:space:]]ram_mb=([0-9]+) ]]; then
        cat "$log"
        rm -rf "$inventory_dir"
        printf '%s\n' "The VPS resource report was invalid. The DNS profile was not changed."
        wait_action_return
        return 1
    fi
    VPS_VCPUS="${BASH_REMATCH[1]}"
    VPS_RAM_MB="${BASH_REMATCH[2]}"
    rm -rf "$inventory_dir"
    return 0
}

dns_source_label() {
    case "$1" in
        urlhaus) printf '%s' "URLhaus" ;;
        hagezi-tif-mini) printf '%s' "HaGeZi Threat Intelligence Feeds Mini" ;;
        hagezi-doh) printf '%s' "HaGeZi Encrypted DNS" ;;
        hagezi-bypass) printf '%s' "HaGeZi Encrypted DNS/VPN/Proxy Bypass" ;;
        adguard-cname-trackers) printf '%s' "AdGuard CNAME Trackers" ;;
        adguard-cname-mail) printf '%s' "AdGuard Mail Trackers" ;;
        threatfox) printf '%s' "ThreatFox" ;;
        hagezi-pro-plus) printf '%s' "HaGeZi Pro++" ;;
        hagezi-ultimate) printf '%s' "HaGeZi Ultimate" ;;
        hagezi-tif-medium) printf '%s' "HaGeZi Threat Intelligence Feeds Medium" ;;
        hagezi-tif-ips) printf '%s' "Threat Intelligence IPs" ;;
        hagezi-dyndns) printf '%s' "Dynamic DNS Threats" ;;
        hagezi-spam-tlds) printf '%s' "Suspicious Spam TLDs" ;;
        hagezi-popup-ads) printf '%s' "Pop-up Ads" ;;
        hagezi-nsfw) printf '%s' "Adult Content" ;;
        hagezi-gambling-mini) printf '%s' "Gambling Mini" ;;
        hagezi-gambling-medium) printf '%s' "Gambling Medium" ;;
        hagezi-gambling-full) printf '%s' "Gambling Full" ;;
        hagezi-social) printf '%s' "Social Networks" ;;
        hagezi-safesearch) printf '%s' "SafeSearch" ;;
        hagezi-anti-piracy) printf '%s' "Anti Piracy" ;;
        *) printf '%s' "$1" ;;
    esac
}

dns_source_entries() {
    case "$1" in
        urlhaus) printf '%s' 611 ;;
        hagezi-tif-mini) printf '%s' 160610 ;;
        hagezi-doh) printf '%s' 3423 ;;
        hagezi-bypass) printf '%s' 17591 ;;
        adguard-cname-trackers) printf '%s' 100087 ;;
        adguard-cname-mail) printf '%s' 98595 ;;
        threatfox) printf '%s' 45617 ;;
        hagezi-pro-plus) printf '%s' 272267 ;;
        hagezi-ultimate) printf '%s' 294364 ;;
        hagezi-tif-medium) printf '%s' 417094 ;;
        hagezi-tif-ips) printf '%s' 54609 ;;
        hagezi-dyndns) printf '%s' 1524 ;;
        hagezi-spam-tlds) printf '%s' 129 ;;
        hagezi-popup-ads) printf '%s' 56598 ;;
        hagezi-nsfw) printf '%s' 110004 ;;
        hagezi-gambling-mini) printf '%s' 94060 ;;
        hagezi-gambling-medium) printf '%s' 155276 ;;
        hagezi-gambling-full) printf '%s' 357251 ;;
        hagezi-social) printf '%s' 898 ;;
        hagezi-safesearch) printf '%s' 206 ;;
        hagezi-anti-piracy) printf '%s' 36844 ;;
        *) printf '%s' 0 ;;
    esac
}

dns_profile_min_vcpus() {
    case "$1" in
        disabled) printf '%s' 0 ;;
        minimal|optimal|custom) printf '%s' 1 ;;
        full|maximum) printf '%s' 2 ;;
        *) printf '%s' 99 ;;
    esac
}

dns_profile_min_memory() {
    case "$1" in
        disabled) printf '%s' 0 ;;
        minimal) printf '%s' 1280 ;;
        optimal) printf '%s' 1280 ;;
        full) printf '%s' 1792 ;;
        maximum) printf '%s' 2304 ;;
        custom) printf '%s' 768 ;;
        *) printf '%s' 999999 ;;
    esac
}

dns_profile_is_available() {
    local profile="$1"
    if [[ "$profile" == "custom" && -n "${DNS_FILTER_LISTS:-}" ]]; then
        ((VPS_VCPUS >= $(dns_profile_min_vcpus "$profile") && VPS_RAM_MB >= $(dns_custom_memory_floor)))
    else
        ((VPS_VCPUS >= $(dns_profile_min_vcpus "$profile") && VPS_RAM_MB >= $(dns_profile_min_memory "$profile")))
    fi
}

dns_custom_has_source() {
    [[ ",${DNS_FILTER_LISTS:-}," == *",$1,"* ]]
}

dns_custom_toggle_source() {
    local source="$1" current="${DNS_FILTER_LISTS:-}" updated
    if dns_custom_has_source "$source"; then
        updated=",${current},"
        updated="${updated/,${source},/,}"
        updated="${updated#,}"
        updated="${updated%,}"
        DNS_FILTER_LISTS="$updated"
    else
        DNS_FILTER_LISTS="${current:+$current,}$source"
    fi
}

dns_custom_validate() {
    local gambling_count=0 source
    dns_custom_has_source hagezi-pro-plus && dns_custom_has_source hagezi-ultimate && {
        printf '%s\n' "Choose either HaGeZi Pro++ or HaGeZi Ultimate, not both."
        return 1
    }
    dns_custom_has_source hagezi-tif-mini && dns_custom_has_source hagezi-tif-medium && {
        printf '%s\n' "Choose either TIF Mini or TIF Medium, not both."
        return 1
    }
    for source in hagezi-gambling-mini hagezi-gambling-medium hagezi-gambling-full; do
        dns_custom_has_source "$source" && gambling_count=$((gambling_count + 1))
    done
    if ((gambling_count > 1)); then
        printf '%s\n' "Choose one Gambling list size."
        return 1
    fi
    return 0
}

dns_custom_entries() {
    local total=0 source
    IFS=',' read -r -a selected <<<"${DNS_FILTER_LISTS:-}"
    for source in "${selected[@]}"; do
        [[ -n "$source" ]] || continue
        total=$((total + $(dns_source_entries "$source")))
    done
    printf '%s' "$total"
}

dns_custom_reference_entries() {
    printf '%s' 520600
}

dns_custom_reference_memory_mb() {
    printf '%s' 600
}

dns_custom_memory_headroom_mb() {
    printf '%s' 1024
}

dns_custom_memory_round_mb() {
    printf '%s' 256
}

dns_custom_estimated_rpz_memory() {
    local entries="$(dns_custom_entries)"
    local reference_entries="$(dns_custom_reference_entries)"
    local reference_memory="$(dns_custom_reference_memory_mb)"
    local estimate=$(( (entries * reference_memory + reference_entries - 1) / reference_entries ))
    ((estimate < 1)) && estimate=1
    printf '%s' "$estimate"
}

dns_custom_memory_floor() {
    local estimated="$(dns_custom_estimated_rpz_memory)"
    local headroom="$(dns_custom_memory_headroom_mb)"
    local round="$(dns_custom_memory_round_mb)"
    local required=$((estimated + headroom))
    local floor=$(( ((required + round - 1) / round) * round ))
    ((floor < 768)) && floor=768
    printf '%s' "$floor"
}

country_name_for_code() {
    local code="${1^^}"
    awk -F '\t' -v code="$code" '$1 == code { print $2; exit }' "$COUNTRIES_FILE"
}

country_matches() {
    local query="${1,,}"
    awk -F '\t' -v query="$query" '
        BEGIN { IGNORECASE = 1 }
        $0 !~ /^#/ && (query == "*" || tolower($1) == query || index(tolower($2), query) > 0) { print }
    ' "$COUNTRIES_FILE"
}

local_region_has_country() {
    [[ ",${LOCAL_REGION_COUNTRIES:-}," == *",$1,"* ]]
}

local_region_toggle_country() {
    local code="$1" current="${LOCAL_REGION_COUNTRIES:-}" updated
    if local_region_has_country "$code"; then
        updated=",${current},"
        updated="${updated/,${code},/,}"
        updated="${updated#,}"
        updated="${updated%,}"
        LOCAL_REGION_COUNTRIES="$updated"
    else
        LOCAL_REGION_COUNTRIES="${current:+$current,}$code"
    fi
}

local_region_selected_summary() {
    local code name
    local -a selected=() labels=()
    IFS=',' read -r -a selected <<<"${LOCAL_REGION_COUNTRIES:-}"
    for code in "${selected[@]}"; do
        [[ -n "$code" ]] || continue
        name="$(country_name_for_code "$code")"
        labels+=("${name:-Unknown} (${code^^})")
    done
    if ((${#labels[@]} == 0)); then
        printf '%s' "Disabled"
    else
        local joined
        (IFS=', '; joined="${labels[*]}"; printf '%s' "$joined")
    fi
}

select_local_region_countries() {
    local query="" choice index code name status page=0 page_size=20 page_count start end
    local -a matches=()
    while true; do
        clear_screen
        printf '%s\n' "Block countries"
        printf '%s\n' "Select one or more countries to block on the VPN server."
        printf '%s\n' "Current selection: $(local_region_selected_summary)"
        echo
        if [[ -z "$query" ]]; then
            mapfile -t matches < <(country_matches "*")
            page_count=$(( (${#matches[@]} + page_size - 1) / page_size ))
            ((page_count > 0)) || page_count=1
            ((page < 0)) && page=0
            ((page >= page_count)) && page=$((page_count - 1))
            start=$((page * page_size))
            end=$((start + page_size))
            ((end > ${#matches[@]})) && end=${#matches[@]}
            printf 'Countries (page %d/%d)\n' "$((page + 1))" "$page_count"
            printf '%s\n' "Select a number to toggle a country. [ON] means it will be blocked."
            echo
            for ((index = start; index < end; index++)); do
                IFS=$'\t' read -r code name <<<"${matches[$index]}"
                if local_region_has_country "${code,,}"; then status="ON"; else status="-"; fi
                printf '  %2d. %-42s [%s] (%s)\n' "$((index - start + 1))" "$name" "$status" "${code^^}"
            done
            echo
            menu_control s "search country"
            if ((page < page_count - 1)); then menu_control n "next page"; fi
            if ((page > 0)); then menu_control p "previous page"; fi
        else
            mapfile -t matches < <(country_matches "$query")
            page=0
            if ((${#matches[@]} == 0)); then
                printf '%s\n' "No country or territory matched: $query"
            else
                printf '%s\n' "Matches for: $query"
                printf '%s\n' "Select a number to toggle a country; selections are kept while you search."
                echo
                start=0
                end=${#matches[@]}
                ((end > 30)) && end=30
                for ((index = start; index < end; index++)); do
                    IFS=$'\t' read -r code name <<<"${matches[$index]}"
                    if local_region_has_country "${code,,}"; then status="ON"; else status="-"; fi
                    printf '  %2d. %-42s [%s] (%s)\n' "$((index + 1))" "$name" "$status" "${code^^}"
                done
                if ((${#matches[@]} > 30)); then printf '%s\n' "      More matches exist; refine the search."; fi
            fi
            echo
            menu_control s "new search"
        fi
        menu_control a "apply selection"
        if ! prompt_nav; then continue; fi
        choice="$REPLY"
        case "$choice" in
            s|S)
                if ! read_required_choice query "Country name or ISO code: "; then continue; fi
                ;;
            n|N)
                [[ -z "$query" ]] && page=$((page + 1)) || invalid_choice
                ;;
            p|P)
                [[ -z "$query" ]] && page=$((page - 1)) || invalid_choice
                ;;
            a|A)
                return 0
                ;;
            b) return 1 ;;
            m) MAIN_MENU_REQUESTED=1; return 1 ;;
            i) show_info local_region ;;
            x) exit_tui ;;
            ''|*[!0-9]*) invalid_choice ;;
            *)
                if ((${#matches[@]} == 0)) || ((choice < 1 || choice > end - start)); then
                    invalid_choice
                    continue
                fi
                IFS=$'\t' read -r code name <<<"${matches[$((start + choice - 1))]}"
                local_region_toggle_country "${code,,}"
                ;;
        esac
    done
}

select_custom_dns_profile() {
    local choice source index status entries memory rpz_memory
    local -a sources=(
        urlhaus hagezi-tif-mini hagezi-doh hagezi-bypass
        adguard-cname-trackers adguard-cname-mail threatfox hagezi-pro-plus
        hagezi-ultimate hagezi-tif-medium hagezi-tif-ips hagezi-dyndns
        hagezi-spam-tlds hagezi-popup-ads hagezi-nsfw hagezi-gambling-mini
        hagezi-gambling-medium hagezi-gambling-full hagezi-social
        hagezi-safesearch hagezi-anti-piracy
    )
    if [[ "${DNS_FILTER_CURRENT_PROFILE:-}" == "custom" && -n "${DNS_FILTER_CURRENT_LISTS:-}" ]]; then
        DNS_FILTER_LISTS="$DNS_FILTER_CURRENT_LISTS"
    else
        DNS_FILTER_LISTS=""
    fi
    while true; do
        clear_screen
        printf '%s\n' "Custom ad and threat blocking"
        printf '%s\n' "Choose any lists you need. Select at least one list."
        printf '%s\n' "Large threat feeds are mutually exclusive in practice."
        echo
        for index in "${!sources[@]}"; do
            source="${sources[$index]}"
            if dns_custom_has_source "$source"; then status="ON"; else status="-"; fi
            printf '  %2d. %-48s [%s] %s entries\n' \
                "$((index + 1))" "$(dns_source_label "$source")" "$status" "$(dns_source_entries "$source")"
        done
        entries="$(dns_custom_entries)"
        rpz_memory="$(dns_custom_estimated_rpz_memory)"
        memory="$(dns_custom_memory_floor)"
        echo
        printf '%s\n' "Approx. selected entries: ${entries}"
        printf '%s\n' "Estimated RPZ memory: ~${rpz_memory} MB"
        printf '%s\n' "VPS memory: ${VPS_RAM_MB} MB RAM | Required: ${memory} MB RAM"
        if ((VPS_RAM_MB < memory)); then
            printf '%s\n' "Status: NOT AVAILABLE on this VPS"
        else
            printf '%s\n' "Status: available"
        fi
        if dns_custom_has_source hagezi-doh || dns_custom_has_source hagezi-bypass; then
            printf '%s\n' "Warning: encrypted DNS/bypass protection may affect Smart TVs and Hiddify."
        fi
        echo
        menu_control a "apply custom profile"
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            a|A)
                if [[ -z "${DNS_FILTER_LISTS:-}" ]]; then
                    printf '%s\n' "Select at least one list, or use Disabled for no lists."
                    wait_action_return
                    continue
                fi
                if ! dns_custom_validate; then
                    wait_action_return
                    continue
                fi
                if ((VPS_VCPUS < $(dns_profile_min_vcpus custom) || VPS_RAM_MB < memory)); then
                    printf '%s\n' "This Custom profile exceeds the VPS resource limit."
                    wait_action_return
                    continue
                fi
                DNS_FILTER_PROFILE=custom
                return 0
                ;;
            i) show_info dns ;;
            b) return 1 ;;
            m) MAIN_MENU_REQUESTED=1; return 1 ;;
            x) exit_tui ;;
            ''|[!0-9]*) invalid_choice ;;
            *)
                index=$((REPLY - 1))
                if ((index >= 0 && index < ${#sources[@]})); then
                    source="${sources[$index]}"
                    dns_custom_toggle_source "$source"
                else
                    invalid_choice
                fi
                ;;
        esac
    done
}

select_dns_profile() {
    local profile
    while true; do
        clear_screen
        printf '%s\n' "Block ads and threats"
        printf '%s\n' "Current: ${DNS_FILTER_CURRENT_PROFILE:-disabled} | VPS: ${VPS_VCPUS} vCPU, $(((VPS_RAM_MB + 512) / 1024)) GB RAM"
        printf '%s\n' "Select a profile. Press i for list details."
        echo
        printf '  %s1.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Disabled" "No DNS blocklists" "available"
        printf '  %s2.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Minimal" "Malware protection" "$(dns_profile_is_available minimal && printf available || printf 'not available')"
        printf '  %s3.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Optimal" "Malware, phishing and scams" "$(dns_profile_is_available optimal && printf available || printf 'not available')"
        printf '  %s4.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Full" "Malware, ads and tracking" "$(dns_profile_is_available full && printf available || printf 'not available')"
        printf '  %s5.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Maximum" "Broad protection and DNS bypass" "$(dns_profile_is_available maximum && printf available || printf 'not available')"
        printf '  %s6.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Custom" "Choose protection categories" "$(dns_profile_is_available custom && printf available || printf 'not available')"
        echo
        if ! dns_profile_is_available maximum; then
            printf '%s\n' "  Maximum requires at least 2 vCPU and $(dns_profile_min_memory maximum) MB RAM."
        fi
        printf '%s\n' "  4 GB RAM is recommended for large feeds; Custom can disable encrypted DNS for TVs."
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1) DNS_FILTER_PROFILE=disabled; DNS_FILTER_LISTS=""; return 0 ;;
            2|3|4|5)
                case "$REPLY" in 2) profile=minimal ;; 3) profile=optimal ;; 4) profile=full ;; 5) profile=maximum ;; esac
                if dns_profile_is_available "$profile"; then
                    DNS_FILTER_PROFILE="$profile"
                    DNS_FILTER_LISTS=""
                    return 0
                fi
                printf '%s\n' "This profile does not fit the detected VPS resources."
                wait_action_return
                ;;
            6)
                if select_custom_dns_profile; then
                    return 0
                fi
                [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return 1
                ;;
            i) show_info dns ;;
            b) return 1 ;;
            m) MAIN_MENU_REQUESTED=1; return 1 ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

run_ansible_playbook() {
    local log rc
    LAST_ANSIBLE_OUTPUT=""
    log="$(mktemp "$STATE_DIR/.ansible.XXXXXX")"
    if ansible-playbook "$@" 2>&1 | tee "$log"; then
        rc=0
    else
        rc="${PIPESTATUS[0]}"
    fi
    if ((rc != 0)); then
        LAST_ANSIBLE_OUTPUT="$(tail -n 24 "$log")"
        echo
        printf '%s\n' "Ansible failed with exit code ${rc}. Last output:"
        printf '%s\n' "$LAST_ANSIBLE_OUTPUT"
    fi
    rm -f "$log"
    return "$rc"
}

find_node_by_connection() {
    local state_file="$1" host="$2" port="$3"
    python3 - "$state_file" "$host" "$port" <<'PY'
import json
import sys

state = json.load(open(sys.argv[1], encoding="utf-8"))
host, port = sys.argv[2:]
for name, node in state.get("nodes", {}).items():
    saved_host = str(node.get("host", ""))
    saved_ports = {
        str(node.get("management_port", "")),
        str(node.get("ssh_port", "")),
        str(node.get("bootstrap_ssh_port", "")),
    }
    if not node.get("bootstrap_ssh_port"):
        saved_ports.add("22")
    if saved_host == host and port in saved_ports:
        print(name)
        break
PY
}

retry_existing_node_with_bootstrap() {
    local node="$1" state_file="$2" host="$3" user="$4" port="$5" use_saved_password="${6:-0}"
    local password retry_state saved_password

    clear_screen
    printf '%s\n' "Ansible will verify the VPS address, SSH port, user, and password."
    echo
    saved_password="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_password", ""), end="")' "$node" <"$state_file")"
    if [[ "$use_saved_password" == 1 && -n "$saved_password" ]]; then
        password="$saved_password"
        printf '%s\n' "Using the encrypted initial SSH password from the Vault."
        sleep 1
    else
        if ! read_ascii_secret 'VPS password: '; then
            return 1
        fi
        password="$REPLY"
    fi
    retry_state="$(mktemp "$STATE_DIR/.retry.XXXXXX")"
    if ! XRAY_BOOTSTRAP_PASSWORD="$password" python3 "$ROOT_DIR/scripts/state_cli.py" set-bootstrap "$node" "$user" "$port" <"$state_file" >"$retry_state"; then
        unset password
        rm -f "$retry_state"
        return 1
    fi
    unset password
    if ! deploy_node "$node" "$retry_state" "" 1; then
        rm -f "$retry_state"
        return 1
    fi
    if ! vault_save "$retry_state"; then
        rm -f "$retry_state"
        return 1
    fi
    rm -f "$retry_state"
    return 0
}

retry_existing_node_with_saved_key() {
    local node="$1" state_file="$2" connect_port="$3" recovery_state key_file host user target_port management_port bootstrap_port probe_port recovery_rc
    recovery_state="$(mktemp "$STATE_DIR/.recovery.XXXXXX")"
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" ensure-ssh-port "$node" "$connect_port" <"$state_file" >"$recovery_state"; then
        rm -f "$recovery_state"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$recovery_state")"
    user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_user", node.get("deploy_user", "deploy")))' "$node" <"$recovery_state")"
    target_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$recovery_state")"
    management_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("management_port", ""))' "$node" <"$recovery_state")"
    bootstrap_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_ssh_port", ""))' "$node" <"$recovery_state")"
    key_file="$(mktemp "$STATE_DIR/.probe.XXXXXX")"
    python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$recovery_state" >"$key_file"
    chmod 600 "$key_file"

    if [[ ! -s "$key_file" ]]; then
        rm -f "$recovery_state" "$key_file"
        return "$NO_SAVED_SSH_ACCESS"
    fi

    for probe_port in "$management_port" "$target_port" "$connect_port" "$bootstrap_port"; do
        [[ -n "$probe_port" ]] || continue
        if ssh -i "$key_file" -p "$probe_port" \
            -o IdentitiesOnly=yes \
            -o BatchMode=yes \
            -o ConnectTimeout=5 \
            -o ConnectionAttempts=1 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$user@$host" true; then
            if deploy_node "$node" "$recovery_state" "$probe_port"; then
                rm -f "$key_file"
                if vault_save "$recovery_state"; then
                    rm -f "$recovery_state"
                    return 0
                fi
                rm -f "$recovery_state"
                return 1
            else
                recovery_rc=$?
                rm -f "$recovery_state" "$key_file"
                return "$recovery_rc"
            fi
        fi
    done
    rm -f "$recovery_state" "$key_file"
    return "$NO_SAVED_SSH_ACCESS"
}

add_node() {
    local name host server_name dns_profile dns_lists bootstrap_user bootstrap_password bootstrap_port before after existing_node recovery_rc saved_bootstrap_user saved_bootstrap_port
    clear_screen
    read -r -e -p 'VPS IP address: ' host
    if ! valid_ipv4 "$host"; then
        printf '%s\n' "Invalid VPS IP address. Enter an IPv4 address."
        sleep 1.5
        return 1
    fi
    read -r -e -p 'VPS user (press Enter to use root): ' bootstrap_user
    bootstrap_user="${bootstrap_user:-root}"
    read -r -e -p 'VPS SSH port (press Enter to use 22): ' bootstrap_port
    bootstrap_port="${bootstrap_port:-22}"
    if [[ ! "$bootstrap_port" =~ ^[0-9]+$ ]] || ((10#$bootstrap_port < 1 || 10#$bootstrap_port > 65535)); then
        printf '%s\n' "Invalid VPS SSH port. Enter a number from 1 to 65535."
        sleep 1.5
        return 1
    fi
    before="$(mktemp "$STATE_DIR/.before.XXXXXX")"
    after="$(mktemp "$STATE_DIR/.after.XXXXXX")"
    if ! read_vault_state "$before"; then
        rm -f "$before" "$after"
        return 1
    fi

    existing_node="$(find_node_by_connection "$before" "$host" "$bootstrap_port")"
    if [[ -n "$existing_node" ]]; then
        saved_bootstrap_user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("bootstrap_user", "root"), end="")' "$existing_node" <"$before")"
        saved_bootstrap_port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("bootstrap_ssh_port", 22), end="")' "$existing_node" <"$before")"
        if [[ "$bootstrap_user" != "$saved_bootstrap_user" || "$bootstrap_port" != "$saved_bootstrap_port" ]]; then
            clear_screen
            printf '%s\n' "A VPN server for this IP address and SSH port already exists in the Vault."
            printf '%s\n' "The saved server uses SSH user ${saved_bootstrap_user} on port ${saved_bootstrap_port}."
            printf '%s\n' "The entered user and port will be used to recover or redeploy this server."
            echo
            if retry_existing_node_with_bootstrap "$existing_node" "$before" "$host" "$bootstrap_user" "$bootstrap_port"; then
                rm -f "$before" "$after"
                printf '%s\n' "VPN server already exists in Vault. Bootstrap deployment completed idempotently."
            else
                rm -f "$before" "$after"
                printf '%s\n' "Deployment failed. The existing Vault was not changed."
            fi
            wait_action_return
            return 0
        fi
        if deploy_node "$existing_node" "$before"; then
            if vault_save "$before"; then
                rm -f "$before" "$after"
                printf '%s\n' "VPN server already exists in Vault. Deployment completed idempotently."
            else
                rm -f "$before" "$after"
                printf '%s\n' "The VPN server was deployed, but the encrypted Vault could not be updated."
            fi
        elif retry_existing_node_with_saved_key "$existing_node" "$before" "$bootstrap_port"; then
            rm -f "$before" "$after"
            printf '%s\n' "VPN server already exists in Vault. SSH access recovered on the bootstrap port."
        else
            recovery_rc=$?
            if ((recovery_rc == NO_SAVED_SSH_ACCESS)) && retry_existing_node_with_bootstrap "$existing_node" "$before" "$host" "$bootstrap_user" "$bootstrap_port" 1; then
                rm -f "$before" "$after"
                printf '%s\n' "VPN server already exists in Vault. Bootstrap deployment completed idempotently."
            else
                rm -f "$before" "$after"
                printf '%s\n' "Deployment failed. The existing Vault was not changed."
            fi
        fi
        wait_action_return
        return 0
    fi

    clear_screen
    printf '%s\n' "Reality camouflage domain (SNI)"
    printf '%s\n' "Enter a public HTTPS domain without https:// or a path."
    printf '%s\n' "Press Enter to use github.com, or type another domain."
    echo
    read -r -e -p 'Domain: ' server_name
    server_name="${server_name:-github.com}"
    if ! valid_server_name "$server_name"; then
        printf '%s\n' "Invalid domain. Use an ASCII HTTPS hostname such as github.com."
        sleep 1.5
        rm -f "$before" "$after"
        wait_action_return
        return 1
    fi
    server_name="${server_name,,}"

    clear_screen
    printf '%s\n' "Ansible will verify the VPS address, SSH port, user, and password."
    echo
    if ! read_ascii_secret 'VPS password: '; then
        rm -f "$before" "$after"
        wait_action_return
        return 1
    fi
    bootstrap_password="$REPLY"

    if ! probe_vps_resources "$host" "$bootstrap_user" "$bootstrap_port" "$bootstrap_password"; then
        unset bootstrap_password
        rm -f "$before" "$after"
        return 1
    fi
    unset DNS_FILTER_CURRENT_PROFILE
    unset DNS_FILTER_LISTS
    if ! select_dns_profile; then
        unset bootstrap_password
        rm -f "$before" "$after"
        return 1
    fi
    dns_profile="$DNS_FILTER_PROFILE"
    dns_lists="${DNS_FILTER_LISTS:-}"

    name="auto"
    if ! XRAY_BOOTSTRAP_USER="$bootstrap_user" XRAY_BOOTSTRAP_PASSWORD="$bootstrap_password" XRAY_BOOTSTRAP_PORT="$bootstrap_port" python3 "$ROOT_DIR/scripts/state_cli.py" --server-name "$server_name" --dns-profile "$dns_profile" --dns-lists "$dns_lists" add-node "$name" "$host" <"$before" >"$after"; then
        rm -f "$before" "$after"
        return 1
    fi
    unset bootstrap_password
    name="$(python3 - "$before" "$after" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
print(next(name for name in after["nodes"] if name not in before.get("nodes", {})))
PY
)"
    rm -f "$before"
    if ! deploy_node "$name" "$after" "" 1; then
        rm -f "$after"
        printf '%s\n' "Initial deployment failed. The VPN server was not added."
        wait_action_return
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$after"
        printf '%s\n' "The VPN server was deployed, but the encrypted Vault could not be saved."
        printf '%s\n' "The server was not added to the local menu."
        wait_action_return
        return 1
    fi
    rm -f "$after"
    printf '%s\n' "VPN server installed and added to the encrypted Vault."
    wait_action_return
}

deploy_node() {
    local node="$1" state_file="${2:-}" connect_port="${3:-}" bootstrap_mode="${4:-0}" before extra inventory inventory_dir key_file user host port target_port management_port legacy_port bootstrap_port bootstrap bootstrap_password bootstrap_user rc marked migrated_state
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    if [[ -n "$state_file" ]]; then
        cp "$state_file" "$before"
    else
        read_vault_state "$before" || { rm -f "$before" "$extra"; rm -rf "$inventory_dir"; return 1; }
    fi
    legacy_port="$(python3 -c 'import json,sys; value=json.load(sys.stdin)["nodes"][sys.argv[1]].get("ssh_port"); print(value if value is not None else "")' "$node" <"$before")"
    bootstrap_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_ssh_port", 22))' "$node" <"$before")"
    if [[ -z "$legacy_port" || "$legacy_port" == "22" || "$legacy_port" == "$bootstrap_port" ]]; then
        migrated_state="$(mktemp "$STATE_DIR/.migrated.XXXXXX")"
        if ! python3 "$ROOT_DIR/scripts/state_cli.py" ensure-ssh-port "$node" "$bootstrap_port" <"$before" >"$migrated_state"; then
            rm -f "$before" "$extra" "$migrated_state"; rm -rf "$inventory_dir"
            return 1
        fi
        mv -f "$migrated_state" "$before"
        connect_port="${connect_port:-$bootstrap_port}"
    fi
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    target_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$before")"
    management_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("management_port", ""))' "$node" <"$before")"
    port="${connect_port:-${management_port:-$target_port}}"
    key_file="$(mktemp)"
    bootstrap="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_private_key", ""), end="")' "$node" <"$before")"
    bootstrap_password="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_password", ""), end="")' "$node" <"$before")"
    if [[ "$bootstrap_mode" != 1 ]]; then
        bootstrap_password=""
    fi
    bootstrap_user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_user", "root"), end="")' "$node" <"$before")"
    if [[ -n "$bootstrap_password" ]]; then
        user="$bootstrap_user"
        port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_ssh_port", 22))' "$node" <"$before")"
        bootstrap_password="$(yaml_scalar "$bootstrap_password")"
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_password: $bootstrap_password" "          ansible_become_password: $bootstrap_password" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password'" >"$inventory"
    elif [[ -n "$bootstrap" ]]; then
        user="$bootstrap_user"
        printf '%s' "$bootstrap" >"$key_file"
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    else
        user=deploy
        python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before" >"$key_file"
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    fi
    chmod 600 "$key_file"
    if [[ -n "$bootstrap_password" ]]; then
        if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/bootstrap.yml"; then
            :
        else
            rc=$?
            rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
            return "$rc"
        fi
    else
        if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/bootstrap.yml" --private-key "$key_file"; then
            :
        else
            rc=$?
            rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
            return "$rc"
        fi
    fi
    if [[ -n "$bootstrap_password" || -n "$bootstrap" ]]; then
        python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before" >"$key_file"
        chmod 600 "$key_file"
    fi

    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/harden_ssh.yml" --private-key "$key_file"; then
        :
    else
        rc=$?
        rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
        return "$rc"
    fi

    local verify_attempt
    for verify_attempt in {1..12}; do
        if ssh -i "$key_file" -p "$target_port" \
            -o IdentitiesOnly=yes \
            -o BatchMode=yes \
            -o ConnectTimeout=8 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            deploy@"$host" true; then
            break
        fi
        if ((verify_attempt < 12)); then
            sleep 5
        fi
    done
    if ((verify_attempt == 12)); then
        printf '%s\n' "Deployment completed, but the generated SSH port could not be verified: $target_port."
        rm -f "$before" "$extra" "$key_file"
        rm -rf "$inventory_dir"
        return 1
    fi
    ssh -i "$key_file" -p "$target_port" \
        -o IdentitiesOnly=yes \
        -o BatchMode=yes \
        -o ConnectTimeout=8 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        deploy@"$host" \
        'sudo -n sh -c "systemctl stop xray-tui-ssh-rollback.timer xray-tui-ssh-rollback.service 2>/dev/null || true; systemctl reset-failed xray-tui-ssh-rollback.timer xray-tui-ssh-rollback.service 2>/dev/null || true"' \
        || true

    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $target_port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/site.yml" --private-key "$key_file"; then
        :
    else
        rc=$?
        rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
        return "$rc"
    fi

    if [[ -n "$state_file" || "$user" == root || -n "$bootstrap" || -n "$bootstrap_password" ]]; then
        marked="$(mktemp "$STATE_DIR/.marked.XXXXXX")"
        if ! python3 "$ROOT_DIR/scripts/state_cli.py" mark-deployed "$node" <"$before" >"$marked"; then
            rm -f "$before" "$extra" "$key_file" "$marked"; rm -rf "$inventory_dir"
            return 1
        fi
        mv -f "$marked" "$before"
        if [[ -n "$state_file" ]]; then
            cp "$before" "$state_file"
        else
            if ! vault_save "$before"; then
                rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
                return 1
            fi
        fi
    fi
    rm -f "$before" "$extra" "$key_file"
    rm -rf "$inventory_dir"
}

run_node_playbook() {
    local node="$1" playbook="$2" state_file="${3:-}" before extra inventory inventory_dir key_file host port rc
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    key_file="$(mktemp)"
    if [[ -n "$state_file" ]]; then
        cp "$state_file" "$before"
    else
        read_vault_state "$before" || { rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"; return 1; }
    fi
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node["ssh_port"])))' "$node" <"$before")"
    python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before" >"$key_file"
    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    chmod 600 "$key_file"
    if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/$playbook" --private-key "$key_file"; then
        rc=0
    else
        rc=$?
    fi
    rm -f "$before" "$extra" "$key_file"
    rm -rf "$inventory_dir"
    return "$rc"
}

run_remove_with_bootstrap() {
    local node="$1" before extra inventory inventory_dir host user port password password_yaml rc
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    if ! read_vault_state "$before"; then
        rm -f "$before" "$extra"
        rm -rf "$inventory_dir"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_user", "root"))' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("bootstrap_ssh_port", node.get("initial_port", 22)))' "$node" <"$before")"
    password="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_password", ""), end="")' "$node" <"$before")"
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"

    clear_screen
    printf '%s\n' "Remote cleanup needs the initial SSH credentials."
    printf '%s\n' "VPS address: ${host}"
    printf '%s\n' "SSH user: ${user}"
    printf '%s\n' "SSH port: ${port}"
    echo
    if [[ -n "$password" ]]; then
        printf '%s\n' "Using the encrypted initial SSH password from the Vault."
    else
        if ! read_ascii_secret 'Initial SSH password: '; then
            rm -f "$before" "$extra"
            rm -rf "$inventory_dir"
            return 1
        fi
        password="$REPLY"
    fi
    password_yaml="$(yaml_scalar "$password")"
    unset password
    printf '%s\n' \
        "---" \
        "all:" \
        "  children:" \
        "    xray_nodes:" \
        "      hosts:" \
        "        $node:" \
        "          ansible_host: $host" \
        "          ansible_user: $user" \
        "          ansible_port: $port" \
        "          ansible_password: $password_yaml" \
        "          ansible_become_password: $password_yaml" \
        "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password'" \
        >"$inventory"
    unset password_yaml
    chmod 600 "$inventory"

    if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/remove.yml"; then
        rc=0
    else
        rc=$?
    fi
    rm -f "$before" "$extra"
    rm -rf "$inventory_dir"
    return "$rc"
}

mutate_access_keys_and_deploy() {
    local node="$1" action="$2" key_id="${3:-}" before after
    before="$(mktemp)"
    after="$(mktemp)"
    if ! read_vault_state "$before"; then
        rm -f "$before" "$after"
        return 1
    fi
    if [[ "$action" == "remove-key" || "$action" == "add-keys" ]]; then
        python3 "$ROOT_DIR/scripts/state_cli.py" "$action" "$node" "$key_id" <"$before" >"$after" || {
            rm -f "$before" "$after"
            return 1
        }
    else
        python3 "$ROOT_DIR/scripts/state_cli.py" "$action" "$node" <"$before" >"$after" || {
            rm -f "$before" "$after"
            return 1
        }
    fi
    if ! run_node_playbook "$node" site.yml "$after"; then
        rm -f "$before" "$after"
        printf '%s\n' "Access key change failed. The existing Vault was not changed."
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        printf '%s\n' "The VPN was updated, but the encrypted Vault could not be saved."
        printf '%s\n' "The existing Vault was not changed."
        return 1
    fi
    rm -f "$before" "$after"
    return 0
}

add_access_keys_menu() {
    local node="$1" count
    while true; do
        clear_screen
        echo
        menu_heading "Add access keys:"
        echo
        printf '%s\n' "How many access keys do you want to add?"
        printf '%s\n' "Enter a number from 1 to 50."
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice count '?: '; then continue; fi
        case "$count" in
            b) return 0 ;;
            m) MAIN_MENU_REQUESTED=1; return 0 ;;
            i) show_info access_keys ;;
            x) exit_tui ;;
            ''|*[!0-9]*)
                printf '%s\n' "Invalid number. Enter a whole number from 1 to 50."
                sleep 1
                clear_screen
                ;;
            *)
                if ((10#$count < 1 || 10#$count > 50)); then
                    printf '%s\n' "Invalid number. Enter a whole number from 1 to 50."
                    sleep 1
                    clear_screen
                    continue
                fi
                clear_screen
                if mutate_access_keys_and_deploy "$node" add-keys "$count"; then
                    printf '%s\n' "Access keys added: $count."
                fi
                read -r -p "Press Enter to continue" _
                return 0
                ;;
        esac
    done
}

remove_access_key_menu() {
    local node="$1" state key_list selection key_id vision_id xhttp_id confirm key_count remove_all_selection
    state="$(mktemp "$STATE_DIR/.keys.XXXXXX")"
    if ! read_vault_state "$state"; then
        rm -f "$state"
        return 1
    fi

    while true; do
        clear_screen
        echo
        menu_heading "Remove access key:"
        echo
        key_list="$(python3 - "$node" "$state" <<'PY'
import json
import sys

node = json.load(open(sys.argv[2], encoding="utf-8")).get("nodes", {}).get(sys.argv[1])
if node is None:
    raise SystemExit("node not found")
for index, key in enumerate(node.get("xray", {}).get("access_keys", []), 1):
    print(f"{index}\t{key['key_id']}\t{key['vision_uuid']}\t{key['xhttp_uuid']}")
PY
)"
        if [[ -z "$key_list" ]]; then
            key_count=0
            remove_all_selection=1
            printf '%s\n' "  No access keys configured."
        else
            key_count="$(printf '%s\n' "$key_list" | awk 'END {print NR}')"
            remove_all_selection=$((key_count + 1))
            while IFS=$'\t' read -r selection key_id vision_id xhttp_id; do
                printf '  %s%s.%s %sKey id:%s %s\n' "$COLOR_LINE" "$selection" "$COLOR_RESET" "$COLOR_TEXT" "$COLOR_RESET" "$key_id"
                printf '     Vision ID: %s\n' "$vision_id"
                printf '     XHTTP ID: %s\n' "$xhttp_id"
            done <<<"$key_list"
            echo
            printf '  %s%s.%s %sremove all access keys%s\n' "$COLOR_LINE" "$remove_all_selection" "$COLOR_RESET" "$COLOR_TEXT" "$COLOR_RESET"
        fi
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            i) show_info access_keys ;;
            "$remove_all_selection")
                if [[ -z "$key_list" ]]; then
                    invalid_choice
                    continue
                fi
                while true; do
                    clear_screen
                    echo
                    menu_heading "Remove all access keys:"
                    echo
                    printf '%s\n' "This will remove every Vision and XHTTP access key from the VPS."
                    printf '%s\n' "Are you sure you want to remove all access keys? (y/n)"
                    echo
                    menu_control b back
                    menu_control m main
                    menu_control i info
                    menu_control x exit
                    echo
                    if ! read_required_choice confirm '?: '; then continue; fi
                    case "$confirm" in
                        [Yy])
                            clear_screen
                            if mutate_access_keys_and_deploy "$node" remove-all-keys; then
                                printf '%s\n' "All access keys removed."
                            fi
                            read -r -p "Press Enter to continue" _
                            rm -f "$state"
                            return 0
                            ;;
                        [Nn]|b) break ;;
                        m) rm -f "$state"; MAIN_MENU_REQUESTED=1; return 0 ;;
                        i) show_info access_keys ;;
                        x) exit_tui ;;
                        *) invalid_choice ;;
                    esac
                done
                ;;
            b) rm -f "$state"; return 0 ;;
            m) rm -f "$state"; MAIN_MENU_REQUESTED=1; return 0 ;;
            x) rm -f "$state"; exit_tui ;;
            ''|*[!0-9]*) invalid_choice ;;
            *)
                if [[ -z "$key_list" ]]; then
                    invalid_choice
                    continue
                fi
                key_list="$(python3 - "$node" "$REPLY" "$state" <<'PY'
import json
import sys

node = json.load(open(sys.argv[3], encoding="utf-8")).get("nodes", {}).get(sys.argv[1])
index = int(sys.argv[2])
keys = node.get("xray", {}).get("access_keys", []) if node else []
if 1 <= index <= len(keys):
    key = keys[index - 1]
    print(f"{key['key_id']}\t{key['vision_uuid']}\t{key['xhttp_uuid']}")
PY
)"
                if [[ -z "$key_list" ]]; then
                    invalid_choice
                    continue
                fi
                IFS=$'\t' read -r key_id vision_id xhttp_id <<<"$key_list"
                while true; do
                    clear_screen
                    echo
                    menu_heading "Remove access key:"
                    echo
                    printf '%s\n' "  Key id: $key_id"
                    printf '%s\n' "  Vision ID: $vision_id"
                    printf '%s\n' "  XHTTP ID: $xhttp_id"
                    echo
                    printf '%s\n' "  Are you sure you want to remove this access key? (y/n)"
                    echo
                    menu_control b back
                    menu_control m main
                    menu_control i info
                    menu_control x exit
                    echo
                    if ! read_required_choice confirm '  ?: '; then continue; fi
                    case "$confirm" in
                        [Yy])
                            clear_screen
                            if mutate_access_keys_and_deploy "$node" remove-key "$key_id"; then
                                printf '%s\n' "Access key removed."
                            fi
                            read -r -p "Press Enter to continue" _
                            rm -f "$state"
                            return 0
                            ;;
                        [Nn]|b) break ;;
                        m) rm -f "$state"; MAIN_MENU_REQUESTED=1; return 0 ;;
                        i) show_info access_keys ;;
                        x) rm -f "$state"; exit_tui ;;
                        *) invalid_choice ;;
                    esac
                done
                ;;
        esac
    done
}

rotate_ssh_key() {
    local node="$1" before extra inventory inventory_dir key_dir old_key new_key new_pub rotated_state host old_pub port rc
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    key_dir="$(mktemp -d "$STATE_DIR/.ssh-rotate.XXXXXX")"
    old_key="$key_dir/old"
    new_key="$key_dir/new"
    new_pub="${new_key}.pub"
    rotated_state="$(mktemp "$STATE_DIR/.rotated-state.XXXXXX")"
    read_vault_state "$before" || { rm -f "$before" "$extra" "$rotated_state"; rm -rf "$inventory_dir" "$key_dir"; return 1; }
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node["ssh_port"])))' "$node" <"$before")"
    old_pub="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_authorized_key", node.get("deploy_authorized_key", "")), end="")' "$node" <"$before")"
    python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before" >"$old_key"
    chmod 600 "$old_key"
    ssh-keygen -q -t ed25519 -N "" -f "$new_key"

    python3 - "$before" "$node" "$new_pub" "$old_pub" >"$extra" <<'PY'
import json
import sys

state = json.load(open(sys.argv[1], encoding="utf-8"))
node = state["nodes"][sys.argv[2]]
data = {
    "xray_state": node["xray"],
    "xray_public_host": node["host"],
    "deploy_user": "deploy",
    "deploy_authorized_key": node.get("management_authorized_key", node.get("deploy_authorized_key", "")),
    "old_deploy_authorized_key": sys.argv[4],
    "new_deploy_authorized_key": open(sys.argv[3], encoding="utf-8").read().strip(),
}
json.dump(data, sys.stdout, indent=2)
print()
PY
    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    if ! run_ansible_playbook -i "$inventory" -e "@$extra" -e rotate_remove_old_key=false "$ROOT_DIR/ansible/rotate-ssh.yml" --private-key "$old_key"; then
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    if ! ssh -i "$new_key" -p "$port" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR deploy@"$host" true; then
        printf '%s\n' "The new SSH key could not be verified. The old key remains active."
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" set-deploy-key "$node" "$new_key" "$new_pub" <"$before" >"$rotated_state"; then
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    if ! vault_save "$rotated_state"; then
        printf '%s\n' "The new SSH key is active, but the encrypted Vault was not changed. The old key remains active."
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi

    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_private_key_file: $new_key" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    if ! run_ansible_playbook -i "$inventory" -e "@$extra" -e rotate_remove_old_key=true "$ROOT_DIR/ansible/rotate-ssh.yml" --private-key "$new_key"; then
        printf '%s\n' "The new SSH key is stored in the Vault, but the old key could not be revoked."
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    if ! ssh -i "$new_key" -p "$port" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR deploy@"$host" true; then
        printf '%s\n' "The old key was revoked, but the new SSH key could not be verified afterward."
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    rm -f "$before" "$extra" "$rotated_state"
    rm -rf "$inventory_dir" "$key_dir"
    printf '%s\n' "SSH key rotated."
}

manage_dns_protection() {
    local node="$1" before after host user port private_key current_profile current_lists selected_profile selected_lists
    before="$(mktemp)"
    if ! read_vault_state "$before"; then
        rm -f "$before"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_user", node.get("deploy_user", "deploy")))' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node.get("ssh_port", 22))))' "$node" <"$before")"
    private_key="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before")"
    current_profile="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("xray", {}).get("dns_filter_profile", "disabled"), end="")' "$node" <"$before")"
    current_lists="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(",".join(node.get("xray", {}).get("dns_filter_lists", [])), end="")' "$node" <"$before")"
    if [[ -z "$private_key" ]]; then
        rm -f "$before"
        clear_screen
        printf '%s\n' "No management SSH key is available for this VPN server."
        wait_action_return
        return 1
    fi
    if ! probe_vps_resources_with_key "$host" "$user" "$port" "$private_key"; then
        rm -f "$before"
        return 1
    fi

    DNS_FILTER_CURRENT_PROFILE="$current_profile"
    DNS_FILTER_CURRENT_LISTS="$current_lists"
    if ! select_dns_profile; then
        unset DNS_FILTER_CURRENT_PROFILE
        unset DNS_FILTER_CURRENT_LISTS
        rm -f "$before"
        return 0
    fi
    selected_profile="$DNS_FILTER_PROFILE"
    selected_lists="${DNS_FILTER_LISTS:-}"
    unset DNS_FILTER_CURRENT_PROFILE
    unset DNS_FILTER_CURRENT_LISTS
    if [[ "$selected_profile" == "$current_profile" && "$selected_profile" != "custom" ]] || \
       [[ "$selected_profile" == "custom" && "$current_profile" == "custom" && "$selected_lists" == "$current_lists" ]]; then
        clear_screen
        printf '%s\n' "DNS protection profile was not changed."
        wait_action_return
        rm -f "$before"
        return 0
    fi

    after="$(mktemp)"
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" --dns-lists "$selected_lists" set-dns-profile "$node" "$selected_profile" <"$before" >"$after"; then
        rm -f "$before" "$after"
        return 1
    fi
    clear_screen
    printf '%s\n' "Applying DNS protection profile: ${selected_profile}"
    if ! run_node_playbook "$node" site.yml "$after"; then
        rm -f "$before" "$after"
        printf '%s\n' "DNS protection change failed. The existing Vault was not changed."
        wait_action_return
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        printf '%s\n' "The VPN was updated, but the encrypted Vault could not be saved."
        printf '%s\n' "The existing DNS profile remains recorded in the Vault."
        wait_action_return
        return 1
    fi
    rm -f "$before" "$after"
    printf '%s\n' "DNS protection profile updated: ${selected_profile}."
    wait_action_return
}

manage_local_region_policy() {
    local node="$1" before after current_countries selected_countries policy
    before="$(mktemp)"
    if ! read_vault_state "$before"; then
        rm -f "$before"
        return 1
    fi
    current_countries="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(",".join(node.get("xray", {}).get("local_region_countries", [])), end="")' "$node" <"$before")"
    LOCAL_REGION_COUNTRIES="$current_countries"
    while true; do
        clear_screen
        printf '%s\n' "Block countries"
        printf '%s\n' "Selected countries are blocked when the client cannot bypass them directly."
        printf '%s\n' "Current selection: $(local_region_selected_summary)"
        echo
        menu_option 1 "Select countries"
        menu_option 2 "Disable policy"
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1)
                if ! select_local_region_countries; then
                    [[ "$MAIN_MENU_REQUESTED" == 1 ]] && { unset LOCAL_REGION_COUNTRIES; rm -f "$before"; return; }
                    continue
                fi
                ;;
            2) LOCAL_REGION_COUNTRIES="" ;;
            i) show_info local_region; continue ;;
            b) unset LOCAL_REGION_COUNTRIES; rm -f "$before"; return ;;
            m) MAIN_MENU_REQUESTED=1; unset LOCAL_REGION_COUNTRIES; rm -f "$before"; return ;;
            x) exit_tui ;;
            *) invalid_choice; continue ;;
        esac
        selected_countries="${LOCAL_REGION_COUNTRIES:-}"
        if [[ "$selected_countries" == "$current_countries" ]]; then
            clear_screen
            printf '%s\n' "Country blocking settings were not changed."
            wait_action_return
            unset LOCAL_REGION_COUNTRIES
            rm -f "$before"
            return 0
        fi
        if [[ -n "$selected_countries" ]]; then policy=enabled; else policy=disabled; fi
        after="$(mktemp)"
        if ! python3 "$ROOT_DIR/scripts/state_cli.py" --local-region-countries "$selected_countries" set-local-region "$node" "$policy" <"$before" >"$after"; then
            rm -f "$before" "$after"
            unset LOCAL_REGION_COUNTRIES
            return 1
        fi
        clear_screen
        if [[ -n "$selected_countries" ]]; then
            printf '%s\n' "Applying country blocking: $(local_region_selected_summary)"
        else
            printf '%s\n' "Disabling country blocking."
        fi
        if ! run_node_playbook "$node" site.yml "$after"; then
            rm -f "$before" "$after"
            unset LOCAL_REGION_COUNTRIES
            printf '%s\n' "Country blocking change failed. The existing Vault was not changed."
            wait_action_return
            return 1
        fi
        if ! vault_save "$after"; then
            rm -f "$before" "$after"
            unset LOCAL_REGION_COUNTRIES
            printf '%s\n' "The VPN was updated, but the encrypted Vault could not be saved."
            printf '%s\n' "The previous country blocking settings remain recorded in the Vault."
            wait_action_return
            return 1
        fi
        rm -f "$before" "$after"
        unset LOCAL_REGION_COUNTRIES
        printf '%s\n' "Country blocking settings updated."
        wait_action_return
        return 0
    done
}

manage_keys() {
    local node="$1"
    while true; do
        clear_screen
        echo
        menu_heading "Manage access keys:"
        echo
        menu_option 1 Show
        menu_option 2 Add
        menu_option 3 Remove
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1) clear_screen; vault_state_command python3 "$ROOT_DIR/scripts/render_keys.py" "$node"; read -r -p "Press Enter to continue" _ ;;
            2) add_access_keys_menu "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            3) remove_access_key_menu "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            i) show_info access_keys ;;
            b) return ;;
            m) MAIN_MENU_REQUESTED=1; return ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

manage_node() {
    local node="$1"
    while true; do
        clear_screen
        echo
        show_node_status "$node"
        echo
        menu_option 1 "Manage VPN server"
        menu_option 2 "Manage access keys"
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1) manage_server "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            2) manage_keys "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            i) show_info status ;;
            b) return ;;
            m) MAIN_MENU_REQUESTED=1; return ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

manage_server() {
    local node="$1"
    while true; do
        clear_screen
        echo
        menu_heading "Manage VPN server:"
        echo
        menu_option 1 "Check VPN status"
        menu_option 2 "Restart VPN server"
        menu_option 3 "Block ads and threats"
        menu_option 4 "Block countries"
        menu_option 5 "Rotate SSH key"
        menu_option 6 "Remove VPN server"
        menu_option 7 "Open SSH session"
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1) clear_screen; show_node_status "$node"; read -r -p "Press Enter" _ ;;
            2) clear_screen; run_node_playbook "$node" restart.yml; read -r -p "Press Enter" _ ;;
            3) manage_dns_protection "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            4) manage_local_region_policy "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            5) clear_screen; rotate_ssh_key "$node"; read -r -p "Press Enter" _ ;;
            6) clear_screen; remove_node "$node"; return ;;
            7) open_node_ssh_session "$node" ;;
            i) show_info server ;;
            b) return ;;
            m) MAIN_MENU_REQUESTED=1; return ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

remove_remote_node() {
    local node="$1"
    if ! run_node_playbook "$node" remove.yml; then
        printf '%s\n' "The management cleanup phase failed; trying the original SSH credentials."
    fi
    run_remove_with_bootstrap "$node"
}

remove_node() {
    local node="$1" confirm local_confirm
    clear_screen
    while true; do
        clear_screen
        echo
        menu_heading "Remove VPN server:"
        echo
        printf '%s\n' "Are you sure you want to remove this VPN server? (y/n)"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice confirm '?: '; then continue; fi
        case "$confirm" in
            [Yy]) break ;;
            [Nn]|b) return 0 ;;
            m) MAIN_MENU_REQUESTED=1; return 0 ;;
            i) show_info removal ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done

    if remove_remote_node "$node"; then
        state_mutate remove-node "$node"
        printf '%s\n' "VPN server removed from the VPS and Vault."
        return 0
    fi

    while true; do
        clear_screen
        echo
        printf '%s\n' "Remote cleanup failed; the VPN server was not removed from the Vault."
        printf '%s\n' "The VPS may be unreachable, or the cleanup playbook may have failed."
        echo
        if [[ -n "$LAST_ANSIBLE_OUTPUT" ]]; then
            printf '%s\n' "Last Ansible output:"
            printf '%s\n' "$LAST_ANSIBLE_OUTPUT"
            echo
        fi
        printf '%s\n' "Remove this VPN server from the local Vault anyway? (y/n)"
        echo
        menu_control r "retry remote cleanup with the initial SSH credentials"
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice local_confirm '?: '; then continue; fi
        case "$local_confirm" in
            [Yy])
                state_mutate remove-node "$node"
                printf '%s\n' "VPN server removed from the local Vault."
                break
                ;;
            r)
                if remove_remote_node "$node"; then
                    state_mutate remove-node "$node"
                    printf '%s\n' "VPN server removed from the VPS and Vault."
                    break
                fi
                ;;
            i) show_info removal ;;
            [Nn]|b) break ;;
            m) MAIN_MENU_REQUESTED=1; break ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
    read -r -p "Press Enter" _
}

vpn_servers() {
    local count names choice node state
    while true; do
        clear_screen
        state="$(mktemp "$STATE_DIR/.servers.XXXXXX")"
        if ! materialize_vault_state "$state"; then
            rm -f "$state"
            return 1
        fi
        if ! count="$(python3 "$ROOT_DIR/scripts/state_cli.py" count <"$state")"; then
            rm -f "$state"
            return 1
        fi
        if [[ "$count" == 0 ]]; then
            echo
            menu_heading "VPN servers:"
            echo
            printf '%s\n' "  No VPN servers configured."
            echo
            menu_option 1 "Add VPN server"
            echo
            if ! prompt_nav; then continue; fi
            case "$REPLY" in
                1) rm -f "$state"; add_node; return ;;
                i) show_info status; rm -f "$state"; continue ;;
                b) rm -f "$state"; return ;;
                m) rm -f "$state"; MAIN_MENU_REQUESTED=1; return ;;
                x) rm -f "$state"; exit_tui ;;
                *) invalid_choice; rm -f "$state"; continue ;;
            esac
        fi
        if [[ "$count" == 1 ]]; then
            if ! node="$(python3 "$ROOT_DIR/scripts/state_cli.py" names <"$state")"; then
                rm -f "$state"
                return 1
            fi
            rm -f "$state"
            manage_node "$node"
            return
        fi
        python3 "$ROOT_DIR/scripts/render_nodes.py" --check <"$state"
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            i) show_info status; rm -f "$state"; continue ;;
            b) rm -f "$state"; return ;;
            m) rm -f "$state"; MAIN_MENU_REQUESTED=1; return ;;
            x) rm -f "$state"; exit_tui ;;
            *[!0-9]*) invalid_choice; rm -f "$state"; continue ;;
            *)
                if ! names="$(python3 "$ROOT_DIR/scripts/state_cli.py" names <"$state")"; then
                    rm -f "$state"
                    return 1
                fi
                node="$(printf '%s\n' "$names" | sed -n "${REPLY}p")"
                rm -f "$state"
                if [[ -n "$node" ]]; then
                    manage_node "$node"
                    return
                fi
                invalid_choice
                ;;
        esac
    done
}

secure_state() {
    while true; do
        clear_screen
        echo
        menu_heading "Vault:"
        if [[ -f "$VAULT_FILE" ]]; then
            printf '  %sStatus:%s %sAvailable%s\n' "$COLOR_TEXT" "$COLOR_RESET" "$COLOR_INFO" "$COLOR_RESET"
            printf '  %sEncrypted storage for VPS access and VPN keys.%s\n' "$COLOR_TEXT" "$COLOR_RESET"
            printf '  %sLocation:%s %s%s%s\n' "$COLOR_TEXT" "$COLOR_RESET" "$COLOR_TEXT" "$HOST_VAULT_FILE" "$COLOR_RESET"
            echo
            menu_option 1 "Change encryption password"
            menu_option 2 "Backup encrypted state"
            menu_option 3 "Restore encrypted state"
            menu_option 4 "Delete Vault"
        else
            printf '  %sStatus:%s %sNot initialized%s\n' "$COLOR_TEXT" "$COLOR_RESET" "$COLOR_WARN" "$COLOR_RESET"
            printf '  %sNo encrypted Vault exists on this computer.%s\n' "$COLOR_TEXT" "$COLOR_RESET"
            printf '  %sExpected location:%s %s%s%s\n' "$COLOR_TEXT" "$COLOR_RESET" "$COLOR_TEXT" "$HOST_VAULT_FILE" "$COLOR_RESET"
            echo
            menu_option 1 "Create Vault"
            has_vault_backups && menu_option 2 "Restore encrypted state"
        fi
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    if ensure_vault_password_file && [[ -f "$VAULT_FILE" ]]; then
                        ansible-vault rekey --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE"
                        rm -f "$VAULT_PASSWORD_FILE"
                        VAULT_PASSWORD_FILE=""
                    fi
                else
                    initialize_vault
                fi
                ;;
            2)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    backup_vault
                elif has_vault_backups; then
                    restore_vault
                else
                    invalid_choice
                fi
                ;;
            3)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    restore_vault
                else
                    invalid_choice
                fi
                ;;
            4)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    delete_vault
                    [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return
                else
                    invalid_choice
                fi
                ;;
            i) show_info vault ;;
            b) return ;;
            m) MAIN_MENU_REQUESTED=1; return ;;
            x) exit_tui ;;
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
    if ! read_required_choice choice '?: '; then continue; fi
    MAIN_MENU_REQUESTED=0
    case "$choice" in
        1) vpn_servers ;;
        2) add_node ;;
        3) secure_state ;;
        i) show_info general ;;
        x) exit_tui ;;
        *) invalid_choice ;;
    esac
done
