#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"
VAULT_FILE="$STATE_DIR/vault.json"
VAULT_PASSWORD_FILE=""
MAIN_MENU_REQUESTED=0
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
export ANSIBLE_LOCAL_TEMP=/tmp/ansible-local
export ANSIBLE_REMOTE_TEMP=/tmp/ansible-remote
export ANSIBLE_SSH_CONTROL_PATH_DIR=/tmp/ansible-cp
export ANSIBLE_CONFIG="$ROOT_DIR/ansible/ansible.cfg"
mkdir -p "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_REMOTE_TEMP" "$ANSIBLE_SSH_CONTROL_PATH_DIR"

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
    echo "Invalid password. Use printable ASCII characters with the English keyboard layout." >&2
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
        echo "An encrypted Vault will be created on this computer." >&2
        echo "It will store your VPS access data and VPN keys." >&2
        echo "Create and remember a strong Vault password." >&2
        echo >&2
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
            echo "Vault passwords do not match. Please try again." >&2
            sleep 1.5
            continue
        fi
        VAULT_PASSWORD_FILE="$(mktemp /tmp/xray-vault-password.XXXXXX)"
        chmod 600 "$VAULT_PASSWORD_FILE"
        printf '%s\n' "$password" >"$VAULT_PASSWORD_FILE"
        unset password password_confirm
        return 0
    done
    echo "Vault password setup failed after 3 attempts." >&2
    sleep 2.5
    return 1
}

ensure_vault_password_file() {
    local password attempt checked_state vault_view_status
    [[ -n "$VAULT_PASSWORD_FILE" && -f "$VAULT_PASSWORD_FILE" ]] && return 0

    if [[ ! -f "$VAULT_FILE" ]]; then
        create_vault_password_file || return 1
        return 0
    fi

    if ! vault_ciphertext_valid; then
        rm -f "$VAULT_FILE" "$VAULT_PASSWORD_FILE"
        VAULT_PASSWORD_FILE=""
        clear_screen
        echo "The existing Vault is damaged and was removed." >&2
        echo "A new encrypted Vault will be created now." >&2
        sleep 2.5
        create_vault_password_file || return 1
        return 0
    fi

    attempt=0
    while ((attempt < 3)); do
        attempt=$((attempt + 1))
        clear_screen
        echo "An encrypted Vault was found on this computer." >&2
        echo "It contains saved VPS access data and VPN keys." >&2
        echo "Enter the Vault password to unlock it." >&2
        echo >&2
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
                return 0
            fi
            rm -f "$checked_state"
            rm -f "$VAULT_PASSWORD_FILE"
            VAULT_PASSWORD_FILE=""
            rm -f "$VAULT_FILE"
            clear_screen
            echo "The existing Vault state is damaged and was removed." >&2
            echo "A new encrypted Vault will be created now." >&2
            sleep 2.5
            create_vault_password_file || return 1
            return 0
        fi
        rm -f "$checked_state"
        rm -f "$VAULT_PASSWORD_FILE"
        VAULT_PASSWORD_FILE=""
        clear_screen
        if [[ "$attempt" -lt 3 ]]; then
            echo "The Vault password is incorrect. Please try again." >&2
            sleep 1.5
            clear_screen
        fi
    done
    echo "Vault password verification failed after 3 attempts." >&2
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
            echo "The encrypted Vault contains invalid state and was not changed." >&2
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
        echo "Unable to read the encrypted Vault state."
        echo "Restore a valid backup or delete the invalid Vault before continuing."
        echo "The Vault was not changed."
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
        echo "Refusing to save invalid Vault state." >&2
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
        echo "Refusing to install an invalid encrypted Vault." >&2
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
        echo "The Vault was not changed."
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
        echo "Vault initialization failed."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    rm -f "$temp"
    echo "Vault initialized."
    read -r -p "Press Enter to continue" _
}

delete_vault() {
    local confirm
    echo "This will delete the Vault, its backup, and all saved VPS/VPN access data."
    printf "Delete Vault permanently? (y/N): "
    read -r -e confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return 0
    rm -f "$VAULT_FILE" "$STATE_DIR/vault.json.backup" "$VAULT_PASSWORD_FILE"
    rm -rf "$STATE_DIR/backups"
    rm -f "$STATE_DIR"/vault.json.restore.*
    VAULT_PASSWORD_FILE=""
    echo "Vault deleted."
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
        echo "Could not create the encrypted Vault backup."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    chmod 600 "$backup_file"
    echo "Encrypted Vault backup created:"
    echo "$backup_file"
    read -r -p "Press Enter to continue" _
}

restore_vault() {
    local archive tmpdir entry restored current_backup
    read -r -e -p 'Encrypted Vault backup path: ' archive
    if [[ ! -f "$archive" ]]; then
        echo "Backup file not found."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    entry="$(tar -tzf "$archive" 2>/dev/null | awk '$0 == "vault.json" { print; exit }')"
    if [[ -z "$entry" ]]; then
        echo "Invalid backup: vault.json was not found."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    tmpdir="$(mktemp -d /tmp/xray-vault-restore.XXXXXX)"
    if ! tar -xzf "$archive" -C "$tmpdir" "$entry"; then
        rm -rf "$tmpdir"
        echo "Could not extract the encrypted Vault backup."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    restored="$tmpdir/$entry"
    if [[ ! -s "$restored" ]]; then
        rm -rf "$tmpdir"
        echo "Invalid backup: the encrypted Vault is empty."
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
    echo "Encrypted Vault restored."
    read -r -p "Press Enter to continue" _
}

prompt_nav() {
    echo "b. back"
    echo "m. main"
    echo "x. exit"
    read -r -e -p '?: ' REPLY
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
                printf '\n'
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
    echo "Invalid input. Use the English keyboard layout."
    sleep 1
    clear_screen
}

show_nodes() {
    vault_state_command python3 "$ROOT_DIR/scripts/render_nodes.py" --check
}

yaml_scalar() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

run_ansible_playbook() {
    local log rc
    log="$(mktemp "$STATE_DIR/.ansible.XXXXXX")"
    if ansible-playbook "$@" 2>&1 | tee "$log"; then
        rc=0
    else
        rc="${PIPESTATUS[0]}"
    fi
    if ((rc != 0)); then
        echo
        echo "Ansible failed with exit code ${rc}. Last output:"
        tail -n 120 "$log"
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
    saved_port = str(node.get("ssh_port", node.get("bootstrap_ssh_port", "")))
    if saved_host == host and saved_port == port:
        print(name)
        break
PY
}

retry_existing_node_with_bootstrap() {
    local node="$1" state_file="$2" host="$3" user="$4" port="$5"
    local password retry_state

    clear_screen
    echo "Ansible will verify the VPS address, SSH port, user, and password."
    echo
    if ! read_ascii_secret 'VPS password: '; then
        return 1
    fi
    password="$REPLY"
    retry_state="$(mktemp "$STATE_DIR/.retry.XXXXXX")"
    if ! XRAY_BOOTSTRAP_PASSWORD="$password" python3 "$ROOT_DIR/scripts/state_cli.py" set-bootstrap "$node" "$user" "$port" <"$state_file" >"$retry_state"; then
        unset password
        rm -f "$retry_state"
        return 1
    fi
    unset password
    if ! deploy_node "$node" "$retry_state"; then
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

add_node() {
    local name host bootstrap_user bootstrap_password bootstrap_port before after existing_node
    clear_screen
    read -r -e -p 'VPS IP address: ' host
    if ! valid_ipv4 "$host"; then
        echo "Invalid VPS IP address. Enter an IPv4 address."
        sleep 1.5
        return 1
    fi
    read -r -e -p 'VPS user [root]: ' bootstrap_user
    bootstrap_user="${bootstrap_user:-root}"
    read -r -e -p 'VPS SSH port [22]: ' bootstrap_port
    bootstrap_port="${bootstrap_port:-22}"
    if [[ ! "$bootstrap_port" =~ ^[0-9]+$ ]] || ((10#$bootstrap_port < 1 || 10#$bootstrap_port > 65535)); then
        echo "Invalid VPS SSH port. Enter a number from 1 to 65535."
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
        if deploy_node "$existing_node" "$before"; then
            rm -f "$before" "$after"
            echo "VPN server already exists in Vault. Deployment completed idempotently."
        elif retry_existing_node_with_bootstrap "$existing_node" "$before" "$host" "$bootstrap_user" "$bootstrap_port"; then
            rm -f "$before" "$after"
            echo "VPN server already exists in Vault. Bootstrap deployment completed idempotently."
        else
            rm -f "$before" "$after"
            echo "Deployment failed. The existing Vault was not changed."
        fi
        wait_action_return
        return 0
    fi

    clear_screen
    echo "Ansible will verify the VPS address, SSH port, user, and password."
    echo
    if ! read_ascii_secret 'VPS password: '; then
        rm -f "$before" "$after"
        wait_action_return
        return 1
    fi
    bootstrap_password="$REPLY"

    name="auto"
    if ! XRAY_BOOTSTRAP_USER="$bootstrap_user" XRAY_BOOTSTRAP_PASSWORD="$bootstrap_password" XRAY_BOOTSTRAP_PORT="$bootstrap_port" python3 "$ROOT_DIR/scripts/state_cli.py" add-node "$name" "$host" <"$before" >"$after"; then
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
    if ! deploy_node "$name" "$after"; then
        rm -f "$after"
        echo "Initial deployment failed. The VPN server was not added."
        wait_action_return
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$after"
        echo "The VPN server was deployed, but the encrypted Vault could not be saved."
        echo "The server was not added to the local menu."
        wait_action_return
        return 1
    fi
    rm -f "$after"
    echo "VPN server installed and added to the encrypted Vault."
    wait_action_return
}

deploy_node() {
    local node="$1" state_file="${2:-}" before extra inventory inventory_dir key_file user host port bootstrap bootstrap_password bootstrap_user rc marked
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    if [[ -n "$state_file" ]]; then
        cp "$state_file" "$before"
    else
        read_vault_state "$before" || { rm -f "$before" "$extra"; rm -rf "$inventory_dir"; return 1; }
    fi
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$before")"
    key_file="$(mktemp)"
    bootstrap="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_private_key", ""), end="")' "$node" <"$before")"
    bootstrap_password="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_password", ""), end="")' "$node" <"$before")"
    bootstrap_user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_user", "root"), end="")' "$node" <"$before")"
    if [[ -n "$bootstrap_password" ]]; then
        user="$bootstrap_user"
        port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_ssh_port", 22))' "$node" <"$before")"
        bootstrap_password="$(yaml_scalar "$bootstrap_password")"
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_password: $bootstrap_password" "          ansible_become_password: $bootstrap_password" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1'" >"$inventory"
    elif [[ -n "$bootstrap" ]]; then
        user="$bootstrap_user"
        printf '%s' "$bootstrap" >"$key_file"
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1'" >"$inventory"
    else
        user=deploy
        python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["deploy_private_key"], end="")' "$node" <"$before" >"$key_file"
        printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: $user" "          ansible_port: $port" "          ansible_ssh_private_key_file: $key_file" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1'" >"$inventory"
    fi
    chmod 600 "$key_file"
    if [[ -n "$bootstrap_password" ]]; then
        if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/site.yml"; then
            :
        else
            rc=$?
            rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
            return "$rc"
        fi
    else
        if run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/site.yml" --private-key "$key_file"; then
            :
        else
            rc=$?
            rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"
            return "$rc"
        fi
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
    local node="$1" playbook="$2" before extra inventory inventory_dir key_file host port
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    key_file="$(mktemp)"
    read_vault_state "$before" || { rm -f "$before" "$extra" "$key_file"; rm -rf "$inventory_dir"; return 1; }
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$before")"
    python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["deploy_private_key"], end="")' "$node" <"$before" >"$key_file"
    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1'" >"$inventory"
    chmod 600 "$key_file"
    run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/$playbook" --private-key "$key_file"
    rm -f "$before" "$extra" "$key_file"
    rm -rf "$inventory_dir"
}

mutate_access_keys_and_deploy() {
    local node="$1" action="$2" key_id="${3:-}" before after
    before="$(mktemp)"
    after="$(mktemp)"
    if ! read_vault_state "$before"; then
        rm -f "$before" "$after"
        return 1
    fi
    if [[ "$action" == "remove-key" ]]; then
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
    if ! deploy_node "$node" "$after"; then
        rm -f "$before" "$after"
        echo "Access key change failed. The existing Vault was not changed."
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        echo "The VPN was updated, but the encrypted Vault could not be saved."
        echo "The existing Vault was not changed."
        return 1
    fi
    rm -f "$before" "$after"
    return 0
}

rotate_ssh_key() {
    local node="$1" before extra inventory inventory_dir old_key new_key new_pub host old_pub port
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory_dir="$(mktemp -d /tmp/xray-inventory.XXXXXX)"
    inventory="$inventory_dir/hosts.yml"
    old_key="$(mktemp)"
    new_key="$(mktemp)"
    new_pub="${new_key}.pub"
    read_vault_state "$before" || { rm -f "$before" "$extra" "$old_key" "$new_key" "$new_pub"; rm -rf "$inventory_dir"; return 1; }
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$before")"
    old_pub="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["deploy_authorized_key"], end="")' "$node" <"$before")"
    python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["deploy_private_key"], end="")' "$node" <"$before" >"$old_key"
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
    "deploy_authorized_key": node["deploy_authorized_key"],
    "old_deploy_authorized_key": sys.argv[4],
    "new_deploy_authorized_key": open(sys.argv[3], encoding="utf-8").read().strip(),
}
json.dump(data, sys.stdout, indent=2)
print()
PY
    printf '%s\n' "---" "all:" "  children:" "    xray_nodes:" "      hosts:" "        $node:" "          ansible_host: $host" "          ansible_user: deploy" "          ansible_port: $port" "          ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o ConnectionAttempts=1'" >"$inventory"
    run_ansible_playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/rotate-ssh.yml" --private-key "$old_key"
    ssh -i "$new_key" -p "$port" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR deploy@"$host" true
    state_mutate set-deploy-key "$node" "$new_key" "$new_pub"
    rm -f "$before" "$extra" "$old_key" "$new_key" "$new_pub"
    rm -rf "$inventory_dir"
    echo "SSH key rotated."
}

manage_keys() {
    local node="$1"
    while true; do
        clear_screen
        echo
        echo "Manage access keys:"
        echo
        echo "1. Show keys"
        echo "2. Add key"
        echo "3. Remove key"
        echo
        prompt_nav
        case "$REPLY" in
            1) clear_screen; vault_state_command python3 "$ROOT_DIR/scripts/render_keys.py" "$node"; read -r -p "Press Enter to continue" _ ;;
            2) clear_screen; if mutate_access_keys_and_deploy "$node" add-key; then echo "Access key added."; fi; read -r -p "Press Enter" _ ;;
            3) clear_screen; read -r -e -p 'Key id: ' key_id; if mutate_access_keys_and_deploy "$node" remove-key "$key_id"; then echo "Access key removed."; fi; read -r -p "Press Enter" _ ;;
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
        vault_state_command python3 "$ROOT_DIR/scripts/render_nodes.py" --check --node "$node"
        echo
        echo "1. Manage VPN server"
        echo "2. Manage access keys"
        echo
        prompt_nav
        case "$REPLY" in
            1) manage_server "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            2) manage_keys "$node"; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
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
        echo "Manage VPN server:"
        echo
        echo "1. Check VPN status"
        echo "2. Restart VPN server"
        echo "3. Rotate SSH key"
        echo "4. Remove VPN server"
        echo
        prompt_nav
        case "$REPLY" in
            1) clear_screen; vault_state_command python3 "$ROOT_DIR/scripts/render_nodes.py" --check --node "$node"; read -r -p "Press Enter" _ ;;
            2) clear_screen; run_node_playbook "$node" restart.yml; read -r -p "Press Enter" _ ;;
            3) clear_screen; rotate_ssh_key "$node"; read -r -p "Press Enter" _ ;;
            4) clear_screen; remove_node "$node"; return ;;
            b) return ;;
            m) MAIN_MENU_REQUESTED=1; return ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
    done
}

remove_node() {
    local node="$1" confirm local_confirm
    clear_screen
    printf 'Remove this VPN server? (y/N): '
    read -r -e confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return 0

    if run_node_playbook "$node" remove.yml; then
        state_mutate remove-node "$node"
        echo "VPN server removed from the VPS and Vault."
        return 0
    fi

    echo "The VPS could not be reached; its remote cleanup was not completed."
    printf 'Remove the unavailable server from the local Vault anyway? (y/N): '
    read -r -e local_confirm
    if [[ "$local_confirm" =~ ^[Yy]$ ]]; then
        state_mutate remove-node "$node"
        echo "VPN server removed from the local Vault."
    fi
    read -r -p "Press Enter" _
}

vpn_servers() {
    local count names choice node state
    clear_screen
    state="$(mktemp "$STATE_DIR/.servers.XXXXXX")"
    if ! read_vault_state "$state"; then
        rm -f "$state"
        return 1
    fi
    if ! count="$(python3 "$ROOT_DIR/scripts/state_cli.py" count <"$state")"; then
        rm -f "$state"
        return 1
    fi
    if [[ "$count" == 0 ]]; then
        echo
        echo "VPN servers:"
        echo
        echo "  No VPN servers configured."
        echo
        echo "  1. Add VPN server"
        echo
        prompt_nav
        case "$REPLY" in
            1) rm -f "$state"; add_node ;;
            b) rm -f "$state"; return ;;
            m) rm -f "$state"; MAIN_MENU_REQUESTED=1; return ;;
            x) rm -f "$state"; exit_tui ;;
            *) invalid_choice ;;
        esac
        rm -f "$state"
        return
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
    prompt_nav
    case "$REPLY" in
        b) rm -f "$state"; return ;;
        m) rm -f "$state"; MAIN_MENU_REQUESTED=1; return ;;
        x) rm -f "$state"; exit_tui ;;
        *[!0-9]*) invalid_choice ;;
        *)
            if ! names="$(python3 "$ROOT_DIR/scripts/state_cli.py" names <"$state")"; then
                rm -f "$state"
                return 1
            fi
            node="$(printf '%s\n' "$names" | sed -n "${REPLY}p")"
            rm -f "$state"
            [[ -n "$node" ]] && manage_node "$node" || invalid_choice
            ;;
    esac
    rm -f "$state"
}

secure_state() {
    while true; do
        clear_screen
        echo
        echo "Vault:"
        echo
        if [[ -f "$VAULT_FILE" ]]; then
            echo "Encrypted storage for VPS access and VPN keys."
            echo
            echo "1. Change encryption password"
            echo "2. Backup encrypted state"
            echo "3. Restore encrypted state"
            echo "4. Delete Vault"
        else
            echo "Vault is not initialized."
            echo
            echo "1. Initialize Vault"
            has_vault_backups && echo "2. Restore encrypted state"
        fi
        echo
        prompt_nav
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
                else
                    invalid_choice
                fi
                ;;
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
    echo "1. VPN servers"
    echo "2. Add VPN server"
    echo "3. Vault"
    echo
    echo "x. exit"
    read -r -e -p '?: ' choice
    MAIN_MENU_REQUESTED=0
    case "$choice" in
        1) vpn_servers ;;
        2) add_node ;;
        3) secure_state ;;
        x) exit_tui ;;
        *) invalid_choice ;;
    esac
done
