#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COUNTRIES_FILE="$ROOT_DIR/data/countries.tsv"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"
VAULT_FILE="$STATE_DIR/vault.json"
HOST_STATE_DIR="${XRAY_TUI_HOST_STATE_DIR:-$STATE_DIR}"
HOST_VAULT_FILE="$HOST_STATE_DIR/vault.json"
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
    COLOR_HEADER=$'\033[38;5;183m'
    COLOR_LINE=$'\033[38;5;117m'
    COLOR_INFO=$'\033[38;5;117m'
    COLOR_WARN=$'\033[38;5;221m'
    COLOR_ERROR=$'\033[38;5;203m'
    COLOR_MUTED=$'\033[38;5;245m'
    COLOR_MUTED_ITALIC=$'\033[3;38;5;245m'
else
    COLOR_RESET=''
    COLOR_TEXT=''
    COLOR_HEADER=''
    COLOR_LINE=''
    COLOR_INFO=''
    COLOR_WARN=''
    COLOR_ERROR=''
    COLOR_MUTED=''
    COLOR_MUTED_ITALIC=''
fi

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

read_secret() {
    local prompt="$1" value read_status
    printf '%s' "$prompt" >&2
    IFS= read -r -s value
    read_status=$?
    printf '\n' >&2
    if ((read_status != 0)); then
        unset value
        return 1
    fi
    if [[ -n "$value" ]]; then
        REPLY="$value"
        unset value
        return 0
    fi
    unset value
    printf '%s\n' "Password cannot be empty." >&2
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
        if ! read_secret "Create Vault password (attempt ${attempt}/3): "; then
            continue
        fi
        password="$REPLY"
        if ! read_secret "Confirm Vault password (attempt ${attempt}/3): "; then
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
        if ! read_secret "Vault password (attempt ${attempt}/3): "; then
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
        output="$(mktemp "$RUNTIME_TMP_DIR/.view.XXXXXX")"
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
        show_result_screen \
            "Unable to read the encrypted Vault state." \
            "Restore a valid backup or delete the invalid Vault before continuing." \
            "The Vault was not changed."
        return 1
    fi
}

vault_state_command() {
    local state command_status
    state="$(mktemp "$RUNTIME_TMP_DIR/.read.XXXXXX")"
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
    checked="$(mktemp "$RUNTIME_TMP_DIR/.decrypted.XXXXXX")"
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
    if ! install_encrypted_vault "$encrypted"; then
        rm -f "$encrypted" "$checked"
        return 1
    fi
    rm -f "$checked"
}

state_mutate() {
    local action="$1"; shift
    local before after
    before="$(mktemp "$RUNTIME_TMP_DIR/.before.XXXXXX")"
    after="$(mktemp "$RUNTIME_TMP_DIR/.after.XXXXXX")"
    read_vault_state "$before" || { rm -f "$before" "$after"; return 1; }
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" "$action" "$@" <"$before" >"$after"; then
        rm -f "$before" "$after"
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        show_result_screen "The Vault was not changed."
        return 1
    fi
    rm -f "$before" "$after"
}

initialize_vault() {
    local temp
    temp="$(mktemp "$RUNTIME_TMP_DIR/.initial-state.XXXXXX")"
    printf '{"nodes":{}}\n' >"$temp"
    if ! vault_save "$temp"; then
        rm -f "$temp"
        show_result_screen "Vault creation failed."
        return 1
    fi
    rm -f "$temp"
    show_result_screen "Vault created."
}

delete_vault() {
    local confirm
    while true; do
        clear_screen
        menu_heading "Delete Vault:"
        echo
        printf '%s\n' "This permanently deletes the Vault, all automatic and manual backups, saved VPS access credentials, SSH keys, and VPN access keys."
        echo
        menu_option 1 "Delete the Vault"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice confirm '?: '; then continue; fi
        case "$confirm" in
            1) break ;;
            b) return 0 ;;
            m) MAIN_MENU_REQUESTED=1; return 0 ;;
            i) show_info vault ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
    while true; do
        clear_screen
        menu_heading "Confirm Vault deletion:"
        echo
        printf '%s\n' "This action cannot be undone."
        printf '%s\n' "Are you sure you want to delete the Vault and all backups? (y/n)"
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
    rm -f "$VAULT_FILE".bak.*
    rm -rf "$STATE_DIR/backups"
    rm -f "$STATE_DIR"/vault.json.restore.*
    VAULT_PASSWORD_FILE=""
    while true; do
        clear_screen
        menu_heading "Vault deleted:"
        echo
        printf '%s\n' "The Vault, all backups, saved VPS access credentials, SSH keys, and VPN access keys were deleted."
        echo
        menu_option 1 "Create new Vault"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1) initialize_vault || true; return 0 ;;
            b) return 0 ;;
            m) MAIN_MENU_REQUESTED=1; return 0 ;;
            i) show_info vault ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

vault_backup_paths() {
    local backup_path
    shopt -s nullglob
    for backup_path in "$STATE_DIR"/backups/vault-*.tar.gz; do
        [[ -f "$backup_path" ]] && printf '%s\n' "$backup_path"
    done
    shopt -u nullglob
}

has_vault_backups() {
    local backup_path
    while IFS= read -r backup_path; do
        [[ -n "$backup_path" ]] && return 0
    done < <(vault_backup_paths)
    return 1
}

vault_backup_timestamp() {
    local backup_path="$1" backup_name date_part time_part
    backup_name="${backup_path##*/}"
    backup_name="${backup_name#vault-}"
    backup_name="${backup_name%.tar.gz}"
    if [[ "$backup_name" =~ ^([0-9]{8})T([0-9]{6})Z$ ]]; then
        date_part="${BASH_REMATCH[1]}"
        time_part="${BASH_REMATCH[2]}"
        printf '%s-%s-%s %s:%s:%s UTC\n' \
            "${date_part:0:4}" "${date_part:4:2}" "${date_part:6:2}" \
            "${time_part:0:2}" "${time_part:2:2}" "${time_part:4:2}"
        return 0
    fi
    printf '%s\n' "$backup_name"
}

vault_backup_display_path() {
    local backup_path="$1"
    if [[ "$backup_path" == "$STATE_DIR"/* ]]; then
        printf '%s/%s\n' "${HOST_STATE_DIR%/}" "${backup_path#"$STATE_DIR"/}"
    else
        printf '%s\n' "$backup_path"
    fi
}

print_vault_backups() {
    local index=1 backup_path
    local -a backups=()

    mapfile -t backups < <(vault_backup_paths | LC_ALL=C sort -r)
    if ((${#backups[@]} == 0)); then
        printf '%s\n' "No Vault backups found."
        return 1
    fi

    for backup_path in "${backups[@]}"; do
        printf '%d. Manual backup | %s\n' \
            "$index" \
            "$(vault_backup_timestamp "$backup_path")"
        printf '   Path: %s\n' "$(vault_backup_display_path "$backup_path")"
        index=$((index + 1))
    done
}

show_vault_backups() {
    while true; do
        clear_screen
        menu_heading "Vault backups:"
        echo
        print_vault_backups || true
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            b) return 0 ;;
            m) MAIN_MENU_REQUESTED=1; return 0 ;;
            i) show_info vault ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

select_vault_backup() {
    local choice backup_path index
    local -a backups=()

    mapfile -t backups < <(vault_backup_paths | LC_ALL=C sort -r)
    ((${#backups[@]} > 0)) || {
        show_result_screen "No Vault backups found."
        return 1
    }

    while true; do
        clear_screen
        menu_heading "Restore encrypted state"
        echo
        printf '%s\n' "Choose a Vault backup to restore."
        echo
        index=1
        for backup_path in "${backups[@]}"; do
            printf '%d. Manual backup | %s\n' \
                "$index" \
                "$(vault_backup_timestamp "$backup_path")"
            printf '   Path: %s\n' "$(vault_backup_display_path "$backup_path")"
            index=$((index + 1))
        done
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            b) return 1 ;;
            m) MAIN_MENU_REQUESTED=1; return 1 ;;
            i) show_info vault ;;
            x) exit_tui ;;
            ''|*[!0-9]*) invalid_choice ;;
            *)
                choice=$((10#$REPLY))
                if ((choice >= 1 && choice <= ${#backups[@]})); then
                    SELECTED_VAULT_BACKUP="${backups[choice - 1]}"
                    return 0
                fi
                invalid_choice
                ;;
        esac
    done
}

next_vault_backup_path() {
    local timestamp candidate suffix=0
    timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
    candidate="$VAULT_FILE.bak.$timestamp"
    while [[ -e "$candidate" ]]; do
        suffix=$((suffix + 1))
        candidate="$VAULT_FILE.bak.$timestamp.$suffix"
    done
    printf '%s\n' "$candidate"
}

prune_vault_backups() {
    local backup_file
    local -a backups=() sorted_backups=()

    shopt -s nullglob
    backups=( "$VAULT_FILE".bak.* )
    shopt -u nullglob

    for backup_file in "${backups[@]}"; do
        [[ -f "$backup_file" ]] && sorted_backups+=("$backup_file")
    done
    ((${#sorted_backups[@]} > VAULT_BACKUP_KEEP_COUNT)) || return 0

    mapfile -t sorted_backups < <(printf '%s\n' "${sorted_backups[@]}" | LC_ALL=C sort -r)
    for backup_file in "${sorted_backups[@]:VAULT_BACKUP_KEEP_COUNT}"; do
        rm -f -- "$backup_file"
    done
}

install_encrypted_vault() {
    local encrypted_tmp="$1" backup_path

    [[ -s "$encrypted_tmp" ]] || {
        printf '%s\n' "Encrypted Vault output is empty; keeping the existing Vault." >&2
        return 1
    }

    if ! chmod 600 "$encrypted_tmp"; then
        printf '%s\n' "Could not secure the encrypted Vault before installation." >&2
        return 1
    fi

    if [[ -f "$VAULT_FILE" ]]; then
        backup_path="$(next_vault_backup_path)"
        if ! cp -p -- "$VAULT_FILE" "$backup_path" || ! chmod 600 "$backup_path"; then
            rm -f -- "$backup_path"
            printf '%s\n' "Could not back up the current encrypted Vault." >&2
            return 1
        fi
    fi

    if ! mv -f -- "$encrypted_tmp" "$VAULT_FILE"; then
        printf '%s\n' "Could not replace the encrypted Vault." >&2
        return 1
    fi
    prune_vault_backups
}

backup_vault() {
    local backup_dir backup_file
    backup_dir="$STATE_DIR/backups"
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    backup_file="$backup_dir/vault-$(date -u '+%Y%m%dT%H%M%SZ').tar.gz"
    if ! tar -C "$STATE_DIR" -czf "$backup_file" "$(basename "$VAULT_FILE")"; then
        rm -f "$backup_file"
        show_result_screen "Could not create the encrypted Vault backup."
        return 1
    fi
    chmod 600 "$backup_file"
    show_result_screen "Encrypted Vault backup created:" "$backup_file"
}

restore_vault() {
    local archive tmpdir entry restored staged
    if ! select_vault_backup; then
        return 0
    fi
    archive="$SELECTED_VAULT_BACKUP"
    entry="$(tar -tzf "$archive" 2>/dev/null | awk '$0 == "vault.json" { print; exit }')"
    if [[ -z "$entry" ]]; then
        show_result_screen "Invalid backup: vault.json was not found."
        return 0
    fi
    tmpdir="$(mktemp -d "$RUNTIME_TMP_DIR/restore.XXXXXX")"
    if ! tar -xzf "$archive" -C "$tmpdir" "$entry"; then
        rm -rf "$tmpdir"
        show_result_screen "Could not extract the encrypted Vault backup."
        return 0
    fi
    restored="$tmpdir/$entry"
    if [[ ! -s "$restored" ]]; then
        rm -rf "$tmpdir"
        show_result_screen "Invalid backup: the encrypted Vault is empty."
        return 0
    fi
    staged="$(mktemp "$STATE_DIR/.vault.XXXXXX")"
    if ! cp -- "$restored" "$staged" || ! chmod 600 "$staged"; then
        rm -f "$staged"
        rm -rf "$tmpdir"
        show_result_screen "Could not stage the restored encrypted Vault."
        return 0
    fi
    if ! install_encrypted_vault "$staged"; then
        rm -f "$staged"
        [[ -n "${tmpdir:-}" ]] && rm -rf "$tmpdir"
        show_result_screen "The current Vault was kept unchanged."
        return 0
    fi
    [[ -n "${tmpdir:-}" ]] && rm -rf "$tmpdir"
    prune_vault_backups
    rm -f "$VAULT_PASSWORD_FILE"
    VAULT_PASSWORD_FILE=""
    show_result_screen "Encrypted Vault restored."
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

add_node_ip_prompt() {
    local ip_value error=''
    while true; do
        clear_screen
        printf '%s\n' "Add VPN server"
        printf '%s\n' "Enter the public IPv4 address of the VPS."
        [[ -n "$error" ]] && printf '%s\n' "$error"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice ip_value 'Enter VPS IP: '; then
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
        printf '%s\n' "Add VPN server"
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
        printf '%s\n' "Add VPN server"
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
    printf '%s\n' "Add VPN server"
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
        printf '%s\n' "Add VPN server"
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
        printf '%s\n' "Review VPS connection"
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
        if ! read_required_choice choice '?: '; then
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
        if ! read_required_choice choice '?: '; then
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
        if ! read_required_choice choice '?: '; then
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
        if ! read_required_choice choice '?: '; then
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
        if ! read_required_choice choice '?: '; then
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
            info_desc "       Open server operations, ad and threat blocking, country blocking, or deletion."
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
            info_desc "Resource floors: Minimal/Optimal 1 vCPU and 1280 MB RAM; Full 2 vCPU and 1792 MB RAM."
            info_desc "Maximum requires 2 vCPU and 2304 MB RAM. Custom is calculated from the selected lists."
            info_desc "Large feeds work best with 4 GB RAM."
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
            printf '%s\n' "    2. Open SSH session"
            info_desc "       Connect as the saved management user using the saved SSH key and port."
            printf '%s\n' "    3. Restart VPN server"
            info_desc "       Restart the Xray Docker stack without changing keys or profiles."
            printf '%s\n' "    4. Block ads and threats"
            info_desc "       Choose protection against ads, trackers, malware, phishing, and other known threats."
            printf '%s\n' "    5. Block countries"
            info_desc "       Stop connections to selected countries when direct bypass is unavailable."
            printf '%s\n' "    6. Rotate SSH key"
            info_desc "       Generate a new SSH key for secure access to this VPS and disable the old key."
            printf '%s\n' "    7. Delete VPN server"
            info_desc "       Clean Xray and Docker from the VPS before deleting its Vault entry."
            ;;
        vault)
            printf '%b  Vault:%b\n' "$blue" "$reset"
            info_desc "The Vault is encrypted local storage for VPS access data and VPN keys."
            info_desc "It is unlocked only when an operation needs the saved data."
            info_desc "Keep the Vault password safe: it cannot be recovered from the file."
            info_desc "Before each successful Vault replacement, the previous encrypted file is saved as a recovery copy."
            info_desc "The newest 20 automatic recovery copies are kept; older copies are removed automatically."
            info_desc "Automatic recovery copies are internal and are not shown in the backup browser."
            info_desc "Backup encrypted state creates a manual tar.gz archive for user recovery and migration."
            echo
            printf '%b  Vault menu:%b\n' "$blue" "$reset"
            printf '%s\n' "    1. Change encryption password"
            info_desc "       Re-encrypt the Vault with a new local password."
            printf '%s\n' "    2. Backup encrypted state"
            info_desc "       Create a copy of the encrypted Vault for recovery."
            printf '%s\n' "    3. Restore encrypted state"
            info_desc "       Replace the current Vault with a selected encrypted backup."
            printf '%s\n' "    4. View backups"
            info_desc "       Show manual encrypted archives with their paths and timestamps."
            printf '%s\n' "    5. Delete Vault"
            info_desc "       Delete local Vault data, backups, VPS credentials, and VPN keys."
            info_desc "When no Vault exists, option 1 creates it, option 2 restores a backup, and option 3 lists backups."
            ;;
        removal)
            printf '%b  VPN server deletion:%b\n' "$blue" "$reset"
            info_desc "Confirm with y to delete the VPN server from the VPS."
            info_desc "Cancel with n or b to leave the VPS and Vault unchanged."
            info_desc "Xray, Docker, updater services, and the deploy user are removed from the VPS."
            info_desc "The original SSH configuration is restored from its backup."
            info_desc "The server stays in the Vault if remote deletion fails."
            info_desc "After a failed cleanup, choose 1 to retry or 2 to delete only the local Vault entry."
            info_desc "Press b to keep the server in the Vault and return."
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
            info_desc " - Enter the VPS IP address, SSH user, SSH port, and password on separate screens."
            info_desc " - Review the connection details, then let the manager check SSH access and VPS resources."
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
            printf '%s\n' "     4. View backups"
            info_desc "        List automatic recovery copies and manual encrypted archives with their paths and timestamps."
            printf '%s\n' "     5. Delete Vault"
            info_desc "        Delete local VPS access data, VPN keys, and Vault backups."
            echo
            printf '%s\n' "  Manage VPN server"
            printf '%s\n' "     1. Check VPN status"
            info_desc "        Test SSH access, the Xray container, and both VPN ports."
            printf '%s\n' "     2. Open SSH session"
            info_desc "        Connect using the saved management key and port."
            printf '%s\n' "     3. Restart VPN server"
            info_desc "        Restart the Xray Docker stack without changing access keys."
            printf '%s\n' "     4. Block ads and threats"
            info_desc "        Enable, disable, or change protection against ads and known threats."
            printf '%s\n' "     5. Block countries"
            info_desc "        Stop connections to selected countries when client bypass is unavailable."
            printf '%s\n' "     6. Rotate SSH key"
            info_desc "        Generate a new SSH key for secure access to this VPS and disable the old key."
            printf '%s\n' "     7. Delete VPN server"
            info_desc "        Remove the Xray installation and clean up the VPS."
            info_desc "        The Vault is changed only after remote deletion succeeds."
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

pipeline_start() {
    ((DEBUG_MODE)) && return 0
    PIPELINE_ACTIVE=1
    PIPELINE_TITLE="$1"
    PIPELINE_OPERATION="${2:-}"
    PIPELINE_PERCENT=0
    PIPELINE_LABEL="Preparing..."
    PIPELINE_FRAME=0
    if [[ -t 0 && -t 1 ]]; then
        PIPELINE_TTY_STATE="$(stty -g 2>/dev/null || true)"
        if [[ -n "$PIPELINE_TTY_STATE" ]] && stty -echo -icanon -isig 2>/dev/null; then
            printf '\033[?25l'
            PIPELINE_TTY_ACTIVE=1
        fi
    fi
    clear_screen
    printf '%s\n\n' "$PIPELINE_TITLE"
    pipeline_render
}

pipeline_render() {
    local frame
    ((DEBUG_MODE || !PIPELINE_ACTIVE)) && return 0
    pipeline_drain_input
    frame='|'
    case "$((PIPELINE_FRAME % 4))" in
        1) frame='/' ;;
        2) frame='-' ;;
        3) frame='\\' ;;
    esac
    if [[ -t 1 ]]; then
        printf '\r\033[K  [%3d%%] %-44s %s' "$PIPELINE_PERCENT" "$PIPELINE_LABEL" "$frame"
    else
        printf '  [%3d%%] %s\n' "$PIPELINE_PERCENT" "$PIPELINE_LABEL"
    fi
    PIPELINE_FRAME=$((PIPELINE_FRAME + 1))
}

pipeline_drain_input() {
    ((PIPELINE_TTY_ACTIVE)) || return 0
    local pipeline_input=''
    while IFS= read -r -t 0 -n 10000 pipeline_input 2>/dev/null; do
        :
    done
    unset pipeline_input
}

pipeline_restore_terminal() {
    if ((PIPELINE_TTY_ACTIVE)); then
        pipeline_drain_input
        if [[ -n "$PIPELINE_TTY_STATE" ]]; then
            stty "$PIPELINE_TTY_STATE" 2>/dev/null || stty sane 2>/dev/null || true
        else
            stty sane 2>/dev/null || true
        fi
        printf '\033[?25h'
    fi
    PIPELINE_TTY_ACTIVE=0
    PIPELINE_TTY_STATE=''
}

pipeline_stage() {
    ((DEBUG_MODE)) && return 0
    if ((PIPELINE_ACTIVE == 0)); then
        pipeline_start "Working on VPN server"
    fi
    if [[ -n "$PIPELINE_LABEL" && "$PIPELINE_LABEL" != 'Preparing...' && -t 1 ]]; then
        printf '\r\033[K  [%3d%%] %-44s done\n' "$PIPELINE_PERCENT" "$PIPELINE_LABEL"
    fi
    PIPELINE_PERCENT="$1"
    PIPELINE_LABEL="$2"
    PIPELINE_FRAME=0
}

pipeline_complete() {
    ((DEBUG_MODE || !PIPELINE_ACTIVE)) && return 0
    if [[ -t 1 ]]; then
        printf '\r\033[K  [100%%] Done\n'
    else
        printf '  [100%%] Done\n'
    fi
    sleep 1.5
    pipeline_restore_terminal
    PIPELINE_ACTIVE=0
    PIPELINE_TITLE=''
    PIPELINE_OPERATION=''
    PIPELINE_LABEL=''
    PIPELINE_FRAME=0
}

pipeline_abort() {
    ((DEBUG_MODE || !PIPELINE_ACTIVE)) && return 0
    if [[ -t 1 ]]; then
        printf '\r\033[K  [%3d%%] %-44s failed\n' "$PIPELINE_PERCENT" "$PIPELINE_LABEL"
    else
        printf '  [%3d%%] %s failed\n' "$PIPELINE_PERCENT" "$PIPELINE_LABEL"
    fi
    pipeline_restore_terminal
    PIPELINE_ACTIVE=0
    PIPELINE_TITLE=''
    PIPELINE_OPERATION=''
    PIPELINE_LABEL=''
    PIPELINE_FRAME=0
}

pipeline_stage_for_playbook() {
    local argument playbook=''
    for argument in "$@"; do
        case "$argument" in
            *.yml) playbook="${argument##*/}" ;;
        esac
    done
    case "$playbook" in
        bootstrap.yml) pipeline_stage 25 'Preparing the VPS' ;;
        harden_ssh.yml) pipeline_stage 50 'Hardening SSH access' ;;
        site.yml)
            case "$PIPELINE_OPERATION" in
                access_keys) pipeline_stage 80 'Applying access key changes' ;;
                dns) pipeline_stage 80 'Applying DNS protection' ;;
                countries) pipeline_stage 80 'Applying country blocking' ;;
                *) pipeline_stage 85 'Installing Xray and Docker' ;;
            esac
            ;;
        restart.yml) pipeline_stage 80 'Restarting the VPN service' ;;
        rotate-ssh.yml)
            [[ "$PIPELINE_OPERATION" == rotate ]] || pipeline_stage 70 'Rotating the SSH key'
            ;;
        remove.yml) pipeline_stage 80 'Deleting the VPN service' ;;
    esac
}

local_internet_available() {
    local url
    command -v curl >/dev/null 2>&1 || return 1
    for url in \
        https://www.gstatic.com/generate_204 \
        https://deb.debian.org/ \
        https://github.com/; do
        if curl -fsSL --connect-timeout 3 --max-time 6 -o /dev/null "$url" 2>/dev/null; then
            return 0
        fi
    done
    return 1
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

show_result_screen() {
    if ((DEBUG_MODE)); then
        printf '\n%s\n' "$@"
        printf '%s\n' "Press Enter to continue."
        read -r _ || true
        return 0
    fi
    clear_screen
    printf '%s\n' "$@"
    echo
    printf '%s\n' "Press Enter to continue."
    read -r _ || true
}

pause_result_screen() {
    echo
    printf '%s\n' "Press Enter to continue."
    read -r _ || true
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
    state="$(mktemp "$RUNTIME_TMP_DIR/.nodes.XXXXXX")"
    if materialize_vault_state "$state"; then
        python3 "$ROOT_DIR/scripts/render_nodes.py" --check <"$state"
    fi
    rm -f "$state"
}

materialize_vault_state() {
    local state="$1" normalized
    normalized="$(mktemp "$RUNTIME_TMP_DIR/.normalized.XXXXXX")"
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
    state="$(mktemp "$RUNTIME_TMP_DIR/.node.XXXXXX")"
    if materialize_vault_state "$state"; then
        python3 "$ROOT_DIR/scripts/render_nodes.py" --check --node "$node" <"$state"
    fi
    rm -f "$state"
}

open_node_ssh_session() {
    local node="$1" state host user port private_key key_file known_hosts_file ssh_status
    state="$(mktemp "$RUNTIME_TMP_DIR/.ssh-session.XXXXXX")"
    if ! read_vault_state "$state"; then
        rm -f "$state"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$state")"
    user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_user", node.get("deploy_user", "deploy")))' "$node" <"$state")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node.get("ssh_port", 22))))' "$node" <"$state")"
    private_key="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$state")"
    known_hosts_file="$(mktemp /tmp/xray-known-hosts.XXXXXX)"
    if ! write_node_known_hosts "$state" "$node" "$known_hosts_file"; then
        rm -f "$state" "$known_hosts_file"
        clear_screen
        printf '%s\n' "The SSH host key is not pinned for this VPN server. Redeploy it before opening an SSH session."
        wait_action_return
        return 1
    fi
    rm -f "$state"

    if [[ -z "$host" || -z "$user" || -z "$port" || -z "$private_key" ]]; then
        rm -f "$known_hosts_file"
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
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$known_hosts_file" \
        -o ConnectTimeout=8 \
        -o ConnectionAttempts=1 \
        "$user@$host"; then
        ssh_status=0
    else
        ssh_status=$?
    fi
    rm -f "$key_file" "$known_hosts_file"
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
    local inventory_dir inventory log password_yaml facts_line auth_output auth_rc preflight_pid preflight_rc=0
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

    if ((PIPELINE_ACTIVE)); then
        pipeline_stage 10 'Checking the VPS connection'
    fi
    # Reject bad credentials before Ansible starts its retry loop.
    if command -v sshpass >/dev/null 2>&1; then
        auth_rc=0
        auth_output="$(SSHPASS="$password" sshpass -e ssh \
            -p "$port" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=8 \
            -o ConnectionAttempts=1 \
            -o NumberOfPasswordPrompts=1 \
            -o PubkeyAuthentication=no \
            -o PreferredAuthentications=password \
            -o LogLevel=ERROR \
            "$user@$host" true 2>&1)" || auth_rc=$?
        if ((auth_rc != 0)); then
            if grep -Eiq 'permission denied|authentication failed|authentication refused' <<<"$auth_output"; then
                rm -rf "$inventory_dir"
                unset password password_yaml auth_output
                return "$INVALID_BOOTSTRAP_CREDENTIALS"
            fi
            if grep -Eiq 'connection closed|connection timed out|timed out|connection refused|no route to host|network is unreachable|could not resolve hostname' <<<"$auth_output"; then
                rm -rf "$inventory_dir"
                unset password password_yaml auth_output
                return "$UNAVAILABLE_BOOTSTRAP_CONNECTION"
            fi
        fi
    fi
    unset password password_yaml

    if ((PIPELINE_ACTIVE)); then
        pipeline_stage 15 'Checking VPS access and resources'
    else
        clear_screen
        printf '%s\n' "Checking VPS resources..."
    fi
    ansible-playbook -i "$inventory" "$ROOT_DIR/ansible/preflight.yml" >"$log" 2>&1 &
    preflight_pid=$!
    while kill -0 "$preflight_pid" 2>/dev/null; do
        pipeline_render
        sleep 0.1
    done
    wait "$preflight_pid" || preflight_rc=$?
    if ((preflight_rc != 0)); then
        if grep -Eiq 'permission denied|authentication failed|authentication refused|failed password' "$log"; then
            rm -rf "$inventory_dir"
            return "$INVALID_BOOTSTRAP_CREDENTIALS"
        fi
        if grep -Eiq 'connection closed|connection timed out|timed out waiting|connection refused|no route to host|network is unreachable|could not resolve hostname' "$log"; then
            rm -rf "$inventory_dir"
            return "$UNAVAILABLE_BOOTSTRAP_CONNECTION"
        fi
        rm -rf "$inventory_dir"
        return "$BOOTSTRAP_PREFLIGHT_FAILED"
    fi
    facts_line="$(grep -o 'XRAY_RESOURCE_FACTS vcpus=[0-9][0-9]* ram_mb=[0-9][0-9]*' "$log" | tail -n 1 || true)"
    if [[ ! "$facts_line" =~ vcpus=([0-9]+)[[:space:]]ram_mb=([0-9]+) ]]; then
        rm -rf "$inventory_dir"
        return "$BOOTSTRAP_PREFLIGHT_FAILED"
    fi
    VPS_VCPUS="${BASH_REMATCH[1]}"
    VPS_RAM_MB="${BASH_REMATCH[2]}"
    rm -rf "$inventory_dir"
    return 0
}

probe_vps_resources_with_key() {
    local host="$1" user="$2" port="$3" private_key="$4" known_hosts_file="${5:-}"
    local inventory_dir inventory key_file log facts_line ssh_common_args preflight_pid preflight_rc=0 pipeline_owned=0
    inventory_dir="$(mktemp -d /tmp/xray-preflight.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    key_file="$inventory_dir/id_ed25519"
    log="$inventory_dir/ansible.log"
    if [[ -n "$known_hosts_file" ]]; then
        ssh_common_args="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
    else
        ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
    fi
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
        "          ansible_ssh_common_args: '$ssh_common_args'" \
        >"$inventory"
    chmod 600 "$inventory"

    if ((DEBUG_MODE)); then
        if ansible-playbook -i "$inventory" "$ROOT_DIR/ansible/preflight.yml" 2>&1 | tee "$log"; then
            preflight_rc=0
        else
            preflight_rc="${PIPESTATUS[0]}"
        fi
    else
        pipeline_start "Checking VPN server resources" preflight
        pipeline_owned=1
        pipeline_stage 15 'Checking VPN access and resources'
        ansible-playbook -i "$inventory" "$ROOT_DIR/ansible/preflight.yml" >"$log" 2>&1 &
        preflight_pid=$!
        while kill -0 "$preflight_pid" 2>/dev/null; do
            pipeline_render
            sleep 0.1
        done
        wait "$preflight_pid" || preflight_rc=$?
    fi
    if ((preflight_rc != 0)); then
        ((pipeline_owned)) && pipeline_abort
        rm -rf "$inventory_dir"
        printf '%s\n' "The VPS resources could not be checked. The DNS profile was not changed."
        if ((DEBUG_MODE)); then
            printf '%s\n' "The raw Ansible output is shown above."
        fi
        wait_action_return
        return 1
    fi
    facts_line="$(grep -o 'XRAY_RESOURCE_FACTS vcpus=[0-9][0-9]* ram_mb=[0-9][0-9]*' "$log" | tail -n 1 || true)"
    if [[ ! "$facts_line" =~ vcpus=([0-9]+)[[:space:]]ram_mb=([0-9]+) ]]; then
        ((pipeline_owned)) && pipeline_abort
        rm -rf "$inventory_dir"
        printf '%s\n' "The VPS resource report was invalid. The DNS profile was not changed."
        if ((DEBUG_MODE)); then
            printf '%s\n' "The raw Ansible output is shown above."
        fi
        wait_action_return
        return 1
    fi
    VPS_VCPUS="${BASH_REMATCH[1]}"
    VPS_RAM_MB="${BASH_REMATCH[2]}"
    rm -rf "$inventory_dir"
    ((pipeline_owned)) && pipeline_complete "VPS resources available"
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
    local search_action next_action previous_action apply_action action_base
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
                printf '%d. %-42s [%s] (%s)\n' "$((index - start + 1))" "$name" "$status" "${code^^}"
            done
            echo
            action_base=$page_size
            search_action=$((action_base + 1))
            next_action=$((action_base + 2))
            previous_action=$((action_base + 3))
            apply_action=$((action_base + 4))
            menu_option "$search_action" "Search country"
            if ((page < page_count - 1)); then menu_option "$next_action" "Next page"; fi
            if ((page > 0)); then menu_option "$previous_action" "Previous page"; fi
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
                    printf '%d. %-42s [%s] (%s)\n' "$((index + 1))" "$name" "$status" "${code^^}"
                done
                if ((${#matches[@]} > 30)); then printf '%s\n' "      More matches exist; refine the search."; fi
            fi
            echo
            action_base=30
            search_action=$((action_base + 1))
            apply_action=$((action_base + 2))
            menu_option "$search_action" "New search"
        fi
        menu_option "$apply_action" "Apply selection"
        if ! prompt_nav; then continue; fi
        choice="$REPLY"
        case "$choice" in
            "$search_action")
                if ! read_required_choice query "Country name or ISO code: "; then continue; fi
                ;;
            "$next_action")
                [[ -z "$query" ]] && page=$((page + 1)) || invalid_choice
                ;;
            "$previous_action")
                [[ -z "$query" ]] && page=$((page - 1)) || invalid_choice
                ;;
            "$apply_action")
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
    local choice source index status entries memory rpz_memory apply_action
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
            printf '%d. %-48s [%s] %s entries\n' \
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
        apply_action=$((${#sources[@]} + 1))
        menu_option "$apply_action" "Apply custom profile"
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            "$apply_action")
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
    local profile mode="${1:-manage}"
    while true; do
        clear_screen
        if [[ "$mode" == "initial" ]]; then
            printf '%s\n' "Block ads and threats"
        else
            printf '%s\n' "Current profile: Block ads and threats"
        fi
        printf '%s\n' "Optional. Blocks malware, phishing, scams, ads, trackers, and telemetry."
        printf '%s\n' "Current: ${DNS_FILTER_CURRENT_PROFILE:-disabled}"
        echo
        printf '%s1.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Disabled" "No blocking" "available"
        printf '%s2.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Minimal" "Malware protection" "$(dns_profile_is_available minimal && printf available || printf 'not available')"
        printf '%s3.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Optimal" "Malware, phishing and scams" "$(dns_profile_is_available optimal && printf available || printf 'not available')"
        printf '%s4.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Full" "Malware, ads and tracking" "$(dns_profile_is_available full && printf available || printf 'not available')"
        printf '%s5.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Maximum" "Broad protection and DNS bypass" "$(dns_profile_is_available maximum && printf available || printf 'not available')"
        printf '%s6.%s %-9s %-43s [%s]\n' "$COLOR_LINE" "$COLOR_RESET" "Custom" "Choose protection categories" "$(dns_profile_is_available custom && printf available || printf 'not available')"
        echo
        if [[ "$mode" == "initial" ]]; then
            printf '%s\n' "Not sure what to choose? Press Enter to keep it disabled."
            printf '%s\n' "You can enable it later from the VPN management menu."
        fi
        echo
        if [[ "$mode" == "initial" ]]; then
            menu_control b back
            menu_control m main
            menu_control i info
            menu_control x exit
            echo
            if ! read -r -e -p '?: ' REPLY; then return 1; fi
            [[ -z "$REPLY" ]] && REPLY=1
        else
            if ! prompt_nav; then continue; fi
        fi
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
    local log rc quiet=0 debug_output='' ansible_pid pipeline_owned=0
    if [[ "${1:-}" == "--quiet" ]]; then
        quiet=1
        shift
    fi
    LAST_ANSIBLE_OUTPUT=""
    if ((DEBUG_MODE)); then
        if debug_output="$(set -o pipefail; ansible-playbook "$@" 2>&1 | tee /dev/stderr)"; then
            rc=0
        else
            rc=$?
        fi
        LAST_ANSIBLE_OUTPUT="$debug_output"
    else
        if ((PIPELINE_ACTIVE == 0)); then
            pipeline_start "Working on VPN server"
            pipeline_owned=1
        fi
        pipeline_stage_for_playbook "$@"
        log="$(mktemp "$RUNTIME_TMP_DIR/.ansible.XXXXXX")"
        ansible-playbook "$@" >"$log" 2>&1 &
        ansible_pid=$!
        while kill -0 "$ansible_pid" 2>/dev/null; do
            pipeline_render
            sleep 0.1
        done
        if wait "$ansible_pid"; then
            rc=0
        else
            rc=$?
        fi
        if ((rc != 0)); then
            LAST_ANSIBLE_OUTPUT="$(tail -n 24 "$log")"
        else
            LAST_ANSIBLE_OUTPUT="$(tail -n 80 "$log")"
        fi
        rm -f "$log"
    fi
    if ((rc != 0)); then
        if ((DEBUG_MODE)); then
            printf '\n%s\n' "Ansible failed with exit code ${rc}."
        elif (( ! quiet )); then
            printf '%s\n' "Ansible failed with exit code ${rc}."
        fi
    fi
    if ((pipeline_owned)); then
        if ((rc == 0)); then
            pipeline_complete
        else
            pipeline_abort
        fi
    fi
    return "$rc"
}

write_node_known_hosts() {
    local state_file="$1" node="$2" output="$3" port_override="${4:-}" host port public_key
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$state_file")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node.get("ssh_port", ""))))' "$node" <"$state_file")"
    if [[ -n "$port_override" ]]; then
        port="$port_override"
    fi
    public_key="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("ssh_host_public_key", ""), end="")' "$node" <"$state_file")"
    [[ -n "$host" && -n "$port" && -n "$public_key" ]] || return 1
    printf '[%s]:%s %s\n' "$host" "$port" "$public_key" >"$output"
    chmod 600 "$output"
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
        if ! read_secret 'VPS password: '; then
            return 1
        fi
        password="$REPLY"
    fi
    retry_state="$(mktemp "$RUNTIME_TMP_DIR/.retry.XXXXXX")"
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
    local node="$1" state_file="$2" connect_port="$3" recovery_state key_file known_hosts_file probe_known_hosts host user target_port management_port bootstrap_port probe_port recovery_rc
    recovery_state="$(mktemp "$RUNTIME_TMP_DIR/.recovery.XXXXXX")"
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" ensure-ssh-port "$node" "$connect_port" <"$state_file" >"$recovery_state"; then
        rm -f "$recovery_state"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$recovery_state")"
    user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_user", node.get("deploy_user", "deploy")))' "$node" <"$recovery_state")"
    target_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$recovery_state")"
    management_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("management_port", ""))' "$node" <"$recovery_state")"
    bootstrap_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_ssh_port", ""))' "$node" <"$recovery_state")"
    key_file="$(mktemp "$RUNTIME_TMP_DIR/.probe.XXXXXX")"
    known_hosts_file="$(mktemp /tmp/xray-known-hosts.XXXXXX)"
    probe_known_hosts="$(mktemp /tmp/xray-known-hosts.XXXXXX)"
    : >"$known_hosts_file"
    for probe_port in "$management_port" "$target_port" "$connect_port" "$bootstrap_port"; do
        [[ -n "$probe_port" ]] || continue
        if ! write_node_known_hosts "$recovery_state" "$node" "$probe_known_hosts" "$probe_port"; then
            rm -f "$recovery_state" "$key_file" "$known_hosts_file" "$probe_known_hosts"
            return "$NO_SAVED_SSH_ACCESS"
        fi
        cat "$probe_known_hosts" >>"$known_hosts_file"
    done
    rm -f "$probe_known_hosts"
    python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$recovery_state" >"$key_file"
    chmod 600 "$key_file"

    if [[ ! -s "$key_file" ]]; then
        rm -f "$recovery_state" "$key_file" "$known_hosts_file"
        return "$NO_SAVED_SSH_ACCESS"
    fi

    for probe_port in "$management_port" "$target_port" "$connect_port" "$bootstrap_port"; do
        [[ -n "$probe_port" ]] || continue
        if ssh -i "$key_file" -p "$probe_port" \
            -o IdentitiesOnly=yes \
            -o BatchMode=yes \
            -o ConnectTimeout=5 \
            -o ConnectionAttempts=1 \
            -o StrictHostKeyChecking=yes \
            -o UserKnownHostsFile="$known_hosts_file" \
            -o LogLevel=ERROR \
            "$user@$host" true; then
            if deploy_node "$node" "$recovery_state" "$probe_port"; then
                rm -f "$key_file" "$known_hosts_file"
                if vault_save "$recovery_state"; then
                    rm -f "$recovery_state"
                    return 0
                fi
                rm -f "$recovery_state"
                return 1
            else
                recovery_rc=$?
                rm -f "$recovery_state" "$key_file" "$known_hosts_file"
                return "$recovery_rc"
            fi
        fi
    done
    rm -f "$recovery_state" "$key_file" "$known_hosts_file"
    return "$NO_SAVED_SSH_ACCESS"
}

add_node() {
    local name host server_name dns_profile dns_lists bootstrap_user bootstrap_password bootstrap_port before after existing_node recovery_rc saved_bootstrap_user saved_bootstrap_port review_status probe_rc auth_action internet_action
    while true; do
        clear_screen
        printf '%s\n' "Checking local Internet connection..."
        if ! local_internet_available; then
            if local_internet_failure_menu; then
                internet_action=0
            else
                internet_action=$?
            fi
            if ((internet_action == 0)); then
                continue
            fi
            return 0
        fi
        if ! add_node_ip_prompt; then
            return 0
        fi
        host="$ADD_NODE_HOST"
        unset ADD_NODE_HOST
        if ! add_node_user_prompt; then
            return 0
        fi
        bootstrap_user="$ADD_NODE_USER"
        unset ADD_NODE_USER
        if ! add_node_port_prompt; then
            return 0
        fi
        bootstrap_port="$ADD_NODE_PORT"
        unset ADD_NODE_PORT
        before="$(mktemp "$RUNTIME_TMP_DIR/.before.XXXXXX")"
        after="$(mktemp "$RUNTIME_TMP_DIR/.after.XXXXXX")"
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
                show_result_screen "VPN server already exists in Vault. Bootstrap deployment completed idempotently."
            else
                rm -f "$before" "$after"
                show_result_screen "Deployment failed. The existing Vault was not changed."
            fi
            return 0
        fi
        if deploy_node "$existing_node" "$before"; then
            if vault_save "$before"; then
                rm -f "$before" "$after"
                show_result_screen "VPN server already exists in Vault. Deployment completed idempotently."
            else
                rm -f "$before" "$after"
                show_result_screen "The VPN server was deployed, but the encrypted Vault could not be updated."
            fi
        elif retry_existing_node_with_saved_key "$existing_node" "$before" "$bootstrap_port"; then
            rm -f "$before" "$after"
            show_result_screen "VPN server already exists in Vault. SSH access recovered on the bootstrap port."
        else
            recovery_rc=$?
            if ((recovery_rc == NO_SAVED_SSH_ACCESS)) && retry_existing_node_with_bootstrap "$existing_node" "$before" "$host" "$bootstrap_user" "$bootstrap_port" 1; then
                rm -f "$before" "$after"
                show_result_screen "VPN server already exists in Vault. Bootstrap deployment completed idempotently."
            else
                rm -f "$before" "$after"
                show_result_screen "Deployment failed. The existing Vault was not changed."
            fi
        fi
            return 0
        fi

        while true; do
            if ! add_node_password_prompt; then
                rm -f "$before" "$after"
                return 0
            fi
            bootstrap_password="$ADD_NODE_PASSWORD"
            unset ADD_NODE_PASSWORD
            if review_node_connection "$host" "$bootstrap_user" "$bootstrap_port"; then
                review_status=0
            else
                review_status=$?
            fi
            case "$review_status" in
                0) ;;
                1)
                    unset bootstrap_password
                    rm -f "$before" "$after"
                    continue 2
                    ;;
                *) rm -f "$before" "$after"; return 0 ;;
            esac

            pipeline_start "Checking VPS resources"
            if probe_vps_resources "$host" "$bootstrap_user" "$bootstrap_port" "$bootstrap_password"; then
                pipeline_complete "VPS resources available"
                break 2
            else
                probe_rc=$?
                pipeline_abort
            fi
            if ((probe_rc == UNAVAILABLE_BOOTSTRAP_CONNECTION)); then
                if bootstrap_connection_failure_menu "$host" "$bootstrap_port"; then
                    auth_action=0
                else
                    auth_action=$?
                fi
                unset bootstrap_password
                rm -f "$before" "$after"
                if ((auth_action == 0)); then
                    continue 2
                fi
                return 0
            fi
            if ((probe_rc == BOOTSTRAP_PREFLIGHT_FAILED)); then
                if bootstrap_preflight_failure_menu; then
                    auth_action=0
                else
                    auth_action=$?
                fi
                unset bootstrap_password
                rm -f "$before" "$after"
                if ((auth_action == 0)); then
                    continue 2
                fi
                return 0
            fi
            if ((probe_rc != INVALID_BOOTSTRAP_CREDENTIALS)); then
                unset bootstrap_password
                rm -f "$before" "$after"
                return 1
            fi
            if bootstrap_auth_failure_menu; then
                continue
            else
                auth_action=$?
            fi
            unset bootstrap_password
            rm -f "$before" "$after"
            if ((auth_action == 1)); then
                continue 2
            fi
            return 0
        done
    done
    if ! add_node_domain_prompt; then
        unset bootstrap_password
        rm -f "$before" "$after"
        return 0
    fi
    server_name="$ADD_NODE_SERVER_NAME"
    unset ADD_NODE_SERVER_NAME
    unset DNS_FILTER_CURRENT_PROFILE
    unset DNS_FILTER_LISTS
    if ! select_dns_profile initial; then
        unset bootstrap_password
        rm -f "$before" "$after"
        return 0
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
    pipeline_start "Installing VPN server"
    if ! deploy_node "$name" "$after" "" 1; then
        pipeline_abort
        rm -f "$after"
        show_result_screen "Initial deployment failed. The VPN server was not added."
        return 1
    fi
    if ! vault_save "$after"; then
        pipeline_abort
        rm -f "$after"
        show_result_screen \
            "The VPN server was deployed, but the encrypted Vault could not be saved." \
            "The server was not added to the local menu."
        return 1
    fi
    rm -f "$after"
    pipeline_complete "Installation complete"
    show_result_screen "VPN server installed and added to the encrypted Vault."
}

deploy_node() {
    local node="$1" state_file="${2:-}" connect_port="${3:-}" bootstrap_mode="${4:-0}" before extra inventory inventory_dir key_file known_hosts_file host_key_file user host port target_port management_port legacy_port bootstrap_port bootstrap bootstrap_password bootstrap_user host_public_key ssh_common_args rc marked migrated_state hardened_state ssh_host_public_key ssh_host_fingerprint actual_fingerprint
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    known_hosts_file="$inventory_dir/known_hosts"
    host_key_file="$inventory_dir/ssh_host_ed25519_key.pub"
    if [[ -n "$state_file" ]]; then
        cp "$state_file" "$before"
    else
        read_vault_state "$before" || { rm -f "$before" "$extra"; rm -rf "$inventory_dir"; return 1; }
    fi
    legacy_port="$(python3 -c 'import json,sys; value=json.load(sys.stdin)["nodes"][sys.argv[1]].get("ssh_port"); print(value if value is not None else "")' "$node" <"$before")"
    bootstrap_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_ssh_port", 22))' "$node" <"$before")"
    if [[ -z "$legacy_port" || "$legacy_port" == "22" || "$legacy_port" == "$bootstrap_port" ]]; then
        migrated_state="$(mktemp "$RUNTIME_TMP_DIR/.migrated.XXXXXX")"
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
    host_public_key="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("ssh_host_public_key", ""), end="")' "$node" <"$before")"
    if [[ -n "$bootstrap_password" ]]; then
        user="$bootstrap_user"
        port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_ssh_port", 22))' "$node" <"$before")"
        bootstrap_password="$(yaml_scalar "$bootstrap_password")"
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_password: $bootstrap_password" "          ansible_become_password: $bootstrap_password" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password'" >"$inventory"
    elif [[ -n "$bootstrap" ]]; then
        user="$bootstrap_user"
        printf '%s' "$bootstrap" >"$key_file"
        if [[ -n "$host_public_key" ]]; then
            if ! write_node_known_hosts "$before" "$node" "$known_hosts_file" "$port"; then
                rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
                return 1
            fi
            ssh_common_args="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
        else
            ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
        fi
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '$ssh_common_args'" >"$inventory"
    else
        user=deploy
        python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before" >"$key_file"
        if [[ -n "$host_public_key" ]]; then
            if ! write_node_known_hosts "$before" "$node" "$known_hosts_file" "$port"; then
                rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
                return 1
            fi
            ssh_common_args="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
        else
            ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
        fi
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '$ssh_common_args'" >"$inventory"
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

    if [[ -n "$host_public_key" ]]; then
        if ! write_node_known_hosts "$before" "$node" "$known_hosts_file" "$port"; then
            rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
            return 1
        fi
        ssh_common_args="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
    else
        ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes"
    fi
    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '$ssh_common_args'" >"$inventory"
    if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/harden_ssh.yml" --private-key "$key_file"; then
        :
    else
        rc=$?
        rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
        return "$rc"
    fi

    ssh_host_public_key="$(printf '%s\n' "$LAST_ANSIBLE_OUTPUT" | sed -n 's/.*XRAY_SSH_HOST_PUBLIC_KEY=\(ssh-ed25519 [A-Za-z0-9+/=]*\).*/\1/p' | tail -n 1)"
    ssh_host_fingerprint="$(printf '%s\n' "$LAST_ANSIBLE_OUTPUT" | sed -n 's/.*XRAY_SSH_HOST_FINGERPRINT=\(SHA256:[A-Za-z0-9+/=]*\).*/\1/p' | tail -n 1)"
    if [[ -z "$ssh_host_public_key" || -z "$ssh_host_fingerprint" ]]; then
        printf '%s\n' "SSH hardening completed, but the VPS host key could not be returned to the client."
        rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
        return 1
    fi
    printf '%s\n' "$ssh_host_public_key" >"$host_key_file"
    actual_fingerprint="$(ssh-keygen -lf "$host_key_file" -E sha256 2>/dev/null | awk '{print $2}')"
    if [[ "$actual_fingerprint" != "$ssh_host_fingerprint" ]]; then
        printf '%s\n' "The returned SSH host key fingerprint is invalid."
        rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
        return 1
    fi
    hardened_state="$(mktemp)"
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" set-ssh-host-key "$node" "$host_key_file" "$actual_fingerprint" <"$before" >"$hardened_state"; then
        rm -f "$before" "$extra" "$key_file" "$hardened_state"; rm -rf "$inventory_dir"
        return 1
    fi
    mv -f "$hardened_state" "$before"
    printf '[%s]:%s %s\n' "$host" "$target_port" "$ssh_host_public_key" >"$known_hosts_file"
    chmod 600 "$known_hosts_file"

    pipeline_stage 70 'Verifying hardened SSH access'
    pipeline_render
    local verify_attempt verified=0
    for verify_attempt in {1..12}; do
        if ssh -i "$key_file" -p "$target_port" \
            -o IdentitiesOnly=yes \
            -o BatchMode=yes \
            -o ConnectTimeout=8 \
            -o StrictHostKeyChecking=yes \
            -o UserKnownHostsFile="$known_hosts_file" \
            -o LogLevel=ERROR \
            deploy@"$host" true; then
            verified=1
            break
        fi
        if ((verify_attempt < 12)); then
            sleep 5
        fi
    done
    if ((verified == 0)); then
        printf '%s\n' "Deployment completed, but the generated SSH port could not be verified: $target_port."
        rm -f "$before" "$extra" "$key_file" "$host_key_file" "$known_hosts_file"
        rm -rf "$inventory_dir"
        return 1
    fi
    ssh -i "$key_file" -p "$target_port" \
        -o IdentitiesOnly=yes \
        -o BatchMode=yes \
        -o ConnectTimeout=8 \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$known_hosts_file" \
        -o LogLevel=ERROR \
        deploy@"$host" \
        'sudo -n sh -c "systemctl stop xray-tui-ssh-rollback.timer xray-tui-ssh-rollback.service 2>/dev/null || true; systemctl reset-failed xray-tui-ssh-rollback.timer xray-tui-ssh-rollback.service 2>/dev/null || true"' \
        || true

    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $target_port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/site.yml" --private-key "$key_file"; then
        :
    else
        rc=$?
            rm -f "$before" "$extra" "$key_file" "$host_key_file" "$known_hosts_file"; rm -rf "$inventory_dir"
        return "$rc"
    fi

    if [[ -n "$state_file" || "$user" == root || -n "$bootstrap" || -n "$bootstrap_password" ]]; then
        marked="$(mktemp "$RUNTIME_TMP_DIR/.marked.XXXXXX")"
        if ! python3 "$ROOT_DIR/scripts/state_cli.py" mark-deployed "$node" <"$before" >"$marked"; then
            rm -f "$before" "$extra" "$key_file" "$marked"; rm -rf "$inventory_dir"
            return 1
        fi
        mv -f "$marked" "$before"
        if [[ -n "$state_file" ]]; then
            cp "$before" "$state_file"
        else
            if ! vault_save "$before"; then
                rm -f "$before" "$extra" "$key_file" "$host_key_file" "$known_hosts_file"; rm -rf "$inventory_dir"
                return 1
            fi
        fi
    fi
    rm -f "$before" "$extra" "$key_file" "$host_key_file" "$known_hosts_file"
    rm -rf "$inventory_dir"
}

run_node_playbook() {
    local node="$1" playbook="$2" state_file="${3:-}" operation_title="${4:-Updating VPN server}" operation="${5:-}" before extra inventory inventory_dir key_file known_hosts_file host port rc pipeline_owned=0
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    key_file="$(mktemp)"
    known_hosts_file="$inventory_dir/known_hosts"
    if [[ -n "$state_file" ]]; then
        cp "$state_file" "$before"
    else
        read_vault_state "$before" || { rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"; return 1; }
    fi
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
    if ! write_node_known_hosts "$before" "$node" "$known_hosts_file"; then
        printf '%s\n' "The SSH host key is not pinned for this VPN server. Redeploy it before changing settings."
        rm -f "$before" "$extra" "$key_file"
        rm -rf "$inventory_dir"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node["ssh_port"])))' "$node" <"$before")"
    python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before" >"$key_file"
    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    chmod 600 "$key_file"
    if ((DEBUG_MODE == 0 && PIPELINE_ACTIVE == 0)); then
        pipeline_start "$operation_title" "$operation"
        pipeline_owned=1
    fi
    if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/$playbook" --private-key "$key_file"; then
        rc=0
    else
        rc=$?
    fi
    rm -f "$before" "$extra" "$key_file"
    rm -rf "$inventory_dir"
    if ((pipeline_owned)); then
        if ((rc == 0)); then
            pipeline_complete "Operation complete"
        else
            pipeline_abort
        fi
    fi
    return "$rc"
}

run_remove_with_management_key() {
    local node="$1" before extra inventory inventory_dir key_file host user port private_key rc pipeline_owned=0
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    key_file="$inventory_dir/id_ed25519"
    if ! read_vault_state "$before"; then
        rm -f "$before" "$extra" "$key_file"
        rm -rf "$inventory_dir"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_user", node.get("deploy_user", "deploy")))' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node.get("ssh_port", ""))))' "$node" <"$before")"
    private_key="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before")"
    if [[ -z "$host" || -z "$port" || -z "$private_key" ]]; then
        rm -f "$before" "$extra" "$key_file"
        rm -rf "$inventory_dir"
        return 1
    fi
    printf '%s\n' "$private_key" >"$key_file"
    chmod 600 "$key_file"
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
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
        "          ansible_ssh_private_key_file: $key_file" \
        "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" \
        >"$inventory"
    chmod 600 "$inventory"

    if ((DEBUG_MODE == 0 && PIPELINE_ACTIVE == 0)); then
        pipeline_start "Deleting VPN server" remove
        pipeline_owned=1
    fi
    if run_ansible_playbook --quiet -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/remove.yml" --private-key "$key_file"; then
        rc=0
    else
        rc=$?
    fi
    rm -f "$before" "$extra" "$key_file"
    rm -rf "$inventory_dir"
    if ((pipeline_owned)); then
        if ((rc == 0)); then pipeline_complete "VPN server deleted"; else pipeline_abort; fi
    fi
    return "$rc"
}

run_remove_with_bootstrap() {
    local node="$1" before extra inventory inventory_dir host user port password password_yaml rc pipeline_owned=0
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

    if [[ -n "$password" ]]; then
        :
    else
        clear_screen
        printf '%s\n' "Remote deletion needs the initial SSH password."
        printf '%s\n' "VPS address: ${host}"
        printf '%s\n' "SSH user: ${user}"
        printf '%s\n' "SSH port: ${port}"
        echo
        if ! read_secret 'Initial SSH password: '; then
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

    if ((DEBUG_MODE == 0 && PIPELINE_ACTIVE == 0)); then
        pipeline_start "Deleting VPN server" remove
        pipeline_owned=1
    fi
    if run_ansible_playbook --quiet -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/remove.yml"; then
        rc=0
    else
        rc=$?
    fi
    rm -f "$before" "$extra"
    rm -rf "$inventory_dir"
    if ((pipeline_owned)); then
        if ((rc == 0)); then pipeline_complete "VPN server deleted"; else pipeline_abort; fi
    fi
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
    if ! run_node_playbook "$node" site.yml "$after" "Updating access keys" access_keys; then
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
                    show_result_screen "Access keys added: $count."
                else
                    show_result_screen "Access key change failed. The existing Vault was not changed."
                fi
                return 0
                ;;
        esac
    done
}

remove_access_key_menu() {
    local node="$1" state key_list selection key_id vision_id xhttp_id confirm key_count remove_all_selection
    state="$(mktemp "$RUNTIME_TMP_DIR/.keys.XXXXXX")"
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
            printf '%s\n' "No access keys configured."
        else
            key_count="$(printf '%s\n' "$key_list" | awk 'END {print NR}')"
            remove_all_selection=$((key_count + 1))
            while IFS=$'\t' read -r selection key_id vision_id xhttp_id; do
                printf '%s%s.%s %sKey id:%s %s\n' "$COLOR_LINE" "$selection" "$COLOR_RESET" "$COLOR_TEXT" "$COLOR_RESET" "$key_id"
                printf '     Vision ID: %s\n' "$vision_id"
                printf '     XHTTP ID: %s\n' "$xhttp_id"
            done <<<"$key_list"
            echo
            printf '%s%s.%s %sRemove all access keys%s\n' "$COLOR_LINE" "$remove_all_selection" "$COLOR_RESET" "$COLOR_TEXT" "$COLOR_RESET"
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
                                show_result_screen "All access keys removed."
                            else
                                show_result_screen "Access key change failed. The existing Vault was not changed."
                            fi
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
                    if ! read_required_choice confirm '?: '; then continue; fi
                    case "$confirm" in
                        [Yy])
                            clear_screen
                            if mutate_access_keys_and_deploy "$node" remove-key "$key_id"; then
                                show_result_screen "Access key removed."
                            else
                                show_result_screen "Access key change failed. The existing Vault was not changed."
                            fi
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
    local node="$1" before extra inventory inventory_dir key_dir old_key new_key new_pub rotated_state known_hosts_file host old_pub port rc
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    known_hosts_file="$inventory_dir/known_hosts"
    key_dir="$(mktemp -d "$RUNTIME_TMP_DIR/.ssh-rotate.XXXXXX")"
    old_key="$key_dir/old"
    new_key="$key_dir/new"
    new_pub="${new_key}.pub"
    rotated_state="$(mktemp "$RUNTIME_TMP_DIR/.rotated-state.XXXXXX")"
    read_vault_state "$before" || { rm -f "$before" "$extra" "$rotated_state"; rm -rf "$inventory_dir" "$key_dir"; return 1; }
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node["ssh_port"])))' "$node" <"$before")"
    old_pub="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_authorized_key", node.get("deploy_authorized_key", "")), end="")' "$node" <"$before")"
    if ! write_node_known_hosts "$before" "$node" "$known_hosts_file" "$port"; then
        printf '%s\n' "The SSH host key is not pinned for this VPN server. Redeploy it before rotating the SSH key."
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
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
    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    pipeline_start "Rotating SSH key" rotate
    pipeline_stage 25 'Adding the new SSH key'
    if ! run_ansible_playbook -i "$inventory" -e "@$extra" -e rotate_remove_old_key=false "$ROOT_DIR/ansible/rotate-ssh.yml" --private-key "$old_key"; then
        pipeline_abort
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    pipeline_stage 50 'Verifying the new SSH key'
    pipeline_render
    if ! ssh -i "$new_key" -p "$port" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o LogLevel=ERROR deploy@"$host" true; then
        printf '%s\n' "The new SSH key could not be verified. The old key remains active."
        pipeline_abort
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" set-deploy-key "$node" "$new_key" "$new_pub" <"$before" >"$rotated_state"; then
        pipeline_abort
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    if ! vault_save "$rotated_state"; then
        printf '%s\n' "The new SSH key is active, but the encrypted Vault was not changed. The old key remains active."
        pipeline_abort
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi

    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_private_key_file: $new_key" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts_file -o ConnectTimeout=8 -o ConnectionAttempts=1 -o IdentitiesOnly=yes'" >"$inventory"
    pipeline_stage 75 'Removing the old SSH key'
    if ! run_ansible_playbook -i "$inventory" -e "@$extra" -e rotate_remove_old_key=true "$ROOT_DIR/ansible/rotate-ssh.yml" --private-key "$new_key"; then
        printf '%s\n' "The new SSH key is stored in the Vault, but the old key could not be revoked."
        pipeline_abort
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    if ! ssh -i "$new_key" -p "$port" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o LogLevel=ERROR deploy@"$host" true; then
        printf '%s\n' "The old key was revoked, but the new SSH key could not be verified afterward."
        pipeline_abort
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    rm -f "$before" "$extra" "$rotated_state"
    rm -rf "$inventory_dir" "$key_dir"
    pipeline_complete "SSH key rotation complete"
    printf '%s\n' "SSH key rotated."
}

manage_dns_protection() {
    local node="$1" before after host user port private_key known_hosts_file current_profile current_lists selected_profile selected_lists
    before="$(mktemp)"
    if ! read_vault_state "$before"; then
        rm -f "$before"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    user="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_user", node.get("deploy_user", "deploy")))' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node.get("ssh_port", 22))))' "$node" <"$before")"
    private_key="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_private_key", node.get("deploy_private_key", "")), end="")' "$node" <"$before")"
    known_hosts_file="$(mktemp /tmp/xray-known-hosts.XXXXXX)"
    if ! write_node_known_hosts "$before" "$node" "$known_hosts_file"; then
        rm -f "$before" "$known_hosts_file"
        clear_screen
        printf '%s\n' "The SSH host key is not pinned for this VPN server. Redeploy it before changing settings."
        wait_action_return
        return 1
    fi
    current_profile="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("xray", {}).get("dns_filter_profile", "disabled"), end="")' "$node" <"$before")"
    current_lists="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(",".join(node.get("xray", {}).get("dns_filter_lists", [])), end="")' "$node" <"$before")"
    if [[ -z "$private_key" ]]; then
        rm -f "$before" "$known_hosts_file"
        clear_screen
        printf '%s\n' "No management SSH key is available for this VPN server."
        wait_action_return
        return 1
    fi
    if ! probe_vps_resources_with_key "$host" "$user" "$port" "$private_key" "$known_hosts_file"; then
        rm -f "$before" "$known_hosts_file"
        return 1
    fi

    DNS_FILTER_CURRENT_PROFILE="$current_profile"
    DNS_FILTER_CURRENT_LISTS="$current_lists"
    if ! select_dns_profile manage; then
        unset DNS_FILTER_CURRENT_PROFILE
        unset DNS_FILTER_CURRENT_LISTS
        rm -f "$before" "$known_hosts_file"
        return 0
    fi
    selected_profile="$DNS_FILTER_PROFILE"
    selected_lists="${DNS_FILTER_LISTS:-}"
    unset DNS_FILTER_CURRENT_PROFILE
    unset DNS_FILTER_CURRENT_LISTS
    if [[ "$selected_profile" == "$current_profile" && "$selected_profile" != "custom" ]] || \
       [[ "$selected_profile" == "custom" && "$current_profile" == "custom" && "$selected_lists" == "$current_lists" ]]; then
        show_result_screen "DNS protection profile was not changed."
        rm -f "$before" "$known_hosts_file"
        return 0
    fi

    after="$(mktemp)"
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" --dns-lists "$selected_lists" set-dns-profile "$node" "$selected_profile" <"$before" >"$after"; then
        rm -f "$before" "$after" "$known_hosts_file"
        return 1
    fi
    clear_screen
    printf '%s\n' "Applying DNS protection profile: ${selected_profile}"
    if ! run_node_playbook "$node" site.yml "$after" "Applying DNS protection" dns; then
        rm -f "$before" "$after" "$known_hosts_file"
        show_result_screen "DNS protection change failed. The existing Vault was not changed."
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        show_result_screen \
            "The VPN was updated, but the encrypted Vault could not be saved." \
            "The existing DNS profile remains recorded in the Vault."
        return 1
    fi
    rm -f "$before" "$after" "$known_hosts_file"
    show_result_screen "DNS protection profile updated: ${selected_profile}."
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
            show_result_screen "Country blocking settings were not changed."
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
        if ! run_node_playbook "$node" site.yml "$after" "Applying country blocking" countries; then
            rm -f "$before" "$after"
            unset LOCAL_REGION_COUNTRIES
            show_result_screen "Country blocking change failed. The existing Vault was not changed."
            return 1
        fi
        if ! vault_save "$after"; then
            rm -f "$before" "$after"
            unset LOCAL_REGION_COUNTRIES
            show_result_screen \
                "The VPN was updated, but the encrypted Vault could not be saved." \
                "The previous country blocking settings remain recorded in the Vault."
            return 1
        fi
        rm -f "$before" "$after"
        unset LOCAL_REGION_COUNTRIES
        show_result_screen "Country blocking settings updated."
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
            1) clear_screen; vault_state_command python3 "$ROOT_DIR/scripts/render_keys.py" "$node" || true; pause_result_screen ;;
            2) add_access_keys_menu "$node" || true; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            3) remove_access_key_menu "$node" || true; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            i) show_info access_keys ;;
            b) return ;;
            m) MAIN_MENU_REQUESTED=1; return ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
        [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return
    done
}

manage_node() {
    local node="$1" node_status
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
            1)
                if manage_server "$node"; then
                    :
                else
                    node_status=$?
                    if ((node_status == NODE_REMOVED_STATUS)); then
                        return "$NODE_REMOVED_STATUS"
                    fi
                fi
                [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return
                ;;
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
    local node="$1" removal_status
    while true; do
        clear_screen
        echo
        menu_heading "Manage VPN server:"
        echo
        menu_option 1 "Check VPN status"
        menu_option 2 "Open SSH session"
        menu_option 3 "Restart VPN server"
        menu_option 4 "Block ads and threats"
        menu_option 5 "Block countries"
        menu_option 6 "Rotate SSH key"
        menu_option 7 "Delete VPN server"
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1) clear_screen; show_node_status "$node" || true; pause_result_screen ;;
            2) open_node_ssh_session "$node" || true ;;
            3) clear_screen; run_node_playbook "$node" restart.yml "" "Restarting VPN service" restart || true; pause_result_screen ;;
            4) manage_dns_protection "$node" || true; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            5) manage_local_region_policy "$node" || true; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            6) clear_screen; rotate_ssh_key "$node" || true; pause_result_screen ;;
            7)
                clear_screen
                if remove_node "$node"; then
                    return
                else
                    removal_status=$?
                fi
                if ((removal_status == NODE_REMOVED_STATUS)); then
                    return "$NODE_REMOVED_STATUS"
                fi
                return
                ;;
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
    # Removal remains independent of the pinned management host key.
    if run_remove_with_management_key "$node"; then
        # The deploy user cannot remove itself while it is the Ansible user.
        # The first pass restores the original SSH access; the second pass
        # removes the deploy account and the remaining Xray TUI state as root.
        run_remove_with_bootstrap "$node"
        return $?
    fi
    run_remove_with_bootstrap "$node"
}

remove_node() {
    local node="$1" confirm local_confirm removed=0 host management_port bootstrap_port state
    clear_screen
    while true; do
        clear_screen
        echo
        menu_heading "Delete VPN server:"
        echo
        printf '%s\n' "Are you sure you want to delete this VPN server? (y/n)"
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

    state="$(mktemp)"
    if read_vault_state "$state"; then
        host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$state")"
        management_port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("management_port", node.get("sshd_port", node.get("ssh_port", ""))))' "$node" <"$state")"
        bootstrap_port="$(python3 -c 'import json,sys; node=json.load(sys.stdin)["nodes"][sys.argv[1]]; print(node.get("bootstrap_ssh_port", node.get("initial_port", 22)))' "$node" <"$state")"
    fi
    rm -f "$state"

    clear_screen
    menu_heading "Deleting VPN server:"
    echo
    printf '%s\n' "VPS address: ${host:-unknown}"
    printf '%s\n' "Deleting the remote VPN server."
    echo
    if remove_remote_node "$node"; then
        if state_mutate remove-node "$node"; then
            show_result_screen "VPN server deleted from the VPS and Vault."
            return "$NODE_REMOVED_STATUS"
        fi
        show_result_screen "The VPS was cleaned, but the local Vault could not be updated."
        return 0
    fi

    while true; do
        clear_screen
        menu_heading "VPN server was not deleted:"
        echo
        printf '%s\n' "VPS address: ${host:-unknown}"
        printf '%s\n' "Management SSH port: ${management_port:-unknown}"
        printf '%s\n' "Initial SSH port: ${bootstrap_port:-22}"
        echo
        printf '%s\n' "Remote deletion did not complete."
        printf '%s\n' "The VPS may be unreachable or its SSH service may be unavailable."
        printf '%s\n' "The VPN server is still saved in the local Vault."
        echo
        menu_option 1 "Try delete again"
        menu_option 2 "Delete from local Vault only"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice local_confirm '?: '; then continue; fi
        case "$local_confirm" in
            2)
                if state_mutate remove-node "$node"; then
                    show_result_screen "VPN server deleted from the local Vault."
                    removed=1
                fi
                break
                ;;
            1)
                if remove_remote_node "$node"; then
                    if state_mutate remove-node "$node"; then
                        show_result_screen "VPN server deleted from the VPS and Vault."
                        removed=1
                    fi
                    break
                fi
                ;;
            i) show_info removal ;;
            b) break ;;
            m) MAIN_MENU_REQUESTED=1; break ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
    if ((removed)); then
        return "$NODE_REMOVED_STATUS"
    fi
    return 0
}

vpn_servers() {
    local count names choice node state node_status
    while true; do
        clear_screen
        state="$(mktemp "$RUNTIME_TMP_DIR/.servers.XXXXXX")"
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
                1) rm -f "$state"; add_node || true; return ;;
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
            node_status=0
            if manage_node "$node"; then
                :
            else
                node_status=$?
            fi
            if ((node_status == NODE_REMOVED_STATUS)); then
                continue
            fi
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
                    node_status=0
                    if manage_node "$node"; then
                        :
                    else
                        node_status=$?
                    fi
                    if ((node_status == NODE_REMOVED_STATUS)); then
                        continue
                    fi
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
            menu_option 4 "View backups"
            menu_option 5 "Delete Vault"
        else
            printf '  %sStatus:%s %sNot initialized%s\n' "$COLOR_TEXT" "$COLOR_RESET" "$COLOR_WARN" "$COLOR_RESET"
            printf '  %sNo encrypted Vault exists on this computer.%s\n' "$COLOR_TEXT" "$COLOR_RESET"
            printf '  %sExpected location:%s %s%s%s\n' "$COLOR_TEXT" "$COLOR_RESET" "$COLOR_TEXT" "$HOST_VAULT_FILE" "$COLOR_RESET"
            echo
            menu_option 1 "Create Vault"
            if has_vault_backups; then
                menu_option 2 "Restore encrypted state"
                menu_option 3 "View backups"
            fi
        fi
        echo
        if ! prompt_nav; then continue; fi
        case "$REPLY" in
            1)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    if ensure_vault_password_file && [[ -f "$VAULT_FILE" ]]; then
                        ansible-vault rekey --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE" || true
                        rm -f "$VAULT_PASSWORD_FILE"
                        VAULT_PASSWORD_FILE=""
                    fi
                else
                    initialize_vault || true
                fi
                ;;
            2)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    backup_vault || true
                elif has_vault_backups; then
                    restore_vault || true
                else
                    invalid_choice
                fi
                ;;
            3)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    restore_vault || true
                elif has_vault_backups; then
                    show_vault_backups || true
                else
                    invalid_choice
                fi
                ;;
            5)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    delete_vault
                    [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return
                else
                    invalid_choice
                fi
                ;;
            4)
                clear_screen
                if [[ -f "$VAULT_FILE" ]]; then
                    show_vault_backups || true
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
        [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return
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
        1) vpn_servers || true ;;
        2) add_node || true ;;
        3) secure_state || true ;;
        i) show_info general ;;
        x) exit_tui ;;
        *) invalid_choice ;;
    esac
done
