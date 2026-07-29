#!/usr/bin/env bash

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
        printf '%s\n' "The existing Vault is damaged and was deleted." >&2
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
            printf '%s\n' "The existing Vault state is damaged and was deleted." >&2
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
    local input="$1" encrypted checked vault_output
    if ! ensure_vault_password_file; then
        return 1
    fi
    if ! json_file_valid "$input"; then
        printf '%s\n' "Refusing to save invalid Vault state." >&2
        return 1
    fi
    encrypted="$(mktemp "$STATE_DIR/.vault.XXXXXX")"
    checked="$(mktemp "$RUNTIME_TMP_DIR/.decrypted.XXXXXX")"
    vault_output="$(mktemp "$RUNTIME_TMP_DIR/.vault-output.XXXXXX")"
    chmod 600 "$encrypted" "$checked"
    if ! ansible-vault encrypt "$input" --output "$encrypted" --vault-password-file "$VAULT_PASSWORD_FILE" >"$vault_output" 2>&1; then
        cat "$vault_output" >&2
        rm -f "$encrypted" "$checked" "$vault_output"
        return 1
    fi
    rm -f "$vault_output"
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
        printf '%s\n' "This permanently deletes the Vault, all system and user backups, saved VPS access credentials, SSH keys, and VPN access keys."
        echo
        menu_option 1 "Delete the Vault"
        echo
        menu_control b back
        menu_control m main
        menu_control i info
        menu_control x exit
        echo
        if ! read_required_choice confirm '?: ' '1, or b, m, i, x'; then continue; fi
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
        if ! read_required_choice confirm '?: ' 'y or n, or b, m, i, x'; then continue; fi
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
    rm -rf "$BACKUPS_DIR"
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
    for backup_path in "$USER_BACKUP_DIR"/vault-*.tar.gz; do
        [[ -f "$backup_path" ]] && printf '%s\n' "$backup_path"
    done
    shopt -u nullglob
}

ensure_backup_directories() {
    mkdir -p "$USER_BACKUP_DIR" "$SYSTEM_BACKUP_DIR"
    chmod 700 "$USER_BACKUP_DIR" "$SYSTEM_BACKUP_DIR"
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
        printf '%d. User backup | %s\n' \
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
            printf '%d. User backup | %s\n' \
                "$index" \
                "$(vault_backup_timestamp "$backup_path")"
            printf '   Path: %s\n' "$(vault_backup_display_path "$backup_path")"
            index=$((index + 1))
        done
        if ! prompt_nav "1-${#backups[@]}"; then continue; fi
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
    ensure_backup_directories
    timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
    candidate="$SYSTEM_BACKUP_DIR/vault.json.bak.$timestamp"
    while [[ -e "$candidate" ]]; do
        suffix=$((suffix + 1))
        candidate="$SYSTEM_BACKUP_DIR/vault.json.bak.$timestamp.$suffix"
    done
    printf '%s\n' "$candidate"
}

prune_vault_backups() {
    local backup_file
    local -a backups=() sorted_backups=()

    shopt -s nullglob
    backups=( "$SYSTEM_BACKUP_DIR"/vault.json.bak.* )
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
    backup_dir="$USER_BACKUP_DIR"
    ensure_backup_directories
    backup_file="$backup_dir/vault-$(date -u '+%Y%m%dT%H%M%SZ').tar.gz"
    if ! tar -C "$STATE_DIR" -czf "$backup_file" "$(basename "$VAULT_FILE")"; then
        rm -f "$backup_file"
        show_result_screen "Could not create the encrypted Vault backup."
        return 1
    fi
    chmod 600 "$backup_file"
    show_result_screen "Encrypted Vault backup created:" "$(vault_backup_display_path "$backup_file")"
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
