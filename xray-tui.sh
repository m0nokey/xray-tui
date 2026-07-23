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
mkdir -p "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_REMOTE_TEMP"

cleanup() {
    [[ -n "$VAULT_PASSWORD_FILE" ]] && rm -f "$VAULT_PASSWORD_FILE"
}
trap cleanup EXIT INT TERM

read_ascii_secret() {
    local prompt="$1" value
    read -r -s -e -p "$prompt" value
    printf '\n'
    if (export LC_ALL=C; [[ -n "$value" && "$value" =~ ^[[:print:]]+$ ]]); then
        REPLY="$value"
        unset value
        return 0
    fi
    unset value
    echo "Invalid password. Use printable ASCII characters with the English keyboard layout."
    sleep 1
    clear_screen
    return 1
}

ensure_vault_password_file() {
    local password password_confirm attempt
    [[ -n "$VAULT_PASSWORD_FILE" && -f "$VAULT_PASSWORD_FILE" ]] && return 0

    if [[ ! -f "$VAULT_FILE" ]]; then
        for attempt in 1 2 3; do
            clear_screen
            echo "An encrypted Vault will be created on this computer."
            echo "It will store your VPS access data and VPN keys."
            echo "Create and remember a strong Vault password."
            echo
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
                echo "Vault passwords do not match. Please try again."
                sleep 1.5
                continue
            fi
            VAULT_PASSWORD_FILE="$(mktemp /tmp/xray-vault-password.XXXXXX)"
            chmod 600 "$VAULT_PASSWORD_FILE"
            printf '%s\n' "$password" >"$VAULT_PASSWORD_FILE"
            unset password password_confirm
            return 0
        done
        echo "Vault password setup failed after 3 attempts."
        sleep 2.5
        exit 1
    fi

    for attempt in 1 2 3; do
        clear_screen
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
        if ansible-vault view --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE" >/dev/null 2>&1; then
            return 0
        fi
        rm -f "$VAULT_PASSWORD_FILE"
        VAULT_PASSWORD_FILE=""
        clear_screen
        if [[ "$attempt" -lt 3 ]]; then
            echo "The Vault password is incorrect. Please try again."
            sleep 1.5
            clear_screen
        fi
    done
    echo "Vault password verification failed after 3 attempts."
    sleep 2.5
    exit 1
}

verify_bootstrap_ssh() {
    local host="$1" user="$2" port="$3" attempt password rc
    for attempt in 1 2 3; do
        if ! read_ascii_secret "VPS password (attempt ${attempt}/3): "; then
            continue
        fi
        password="$REPLY"
        if SSHPASS="$password" sshpass -e ssh \
            -p "$port" \
            -o BatchMode=no \
            -o ConnectTimeout=8 \
            -o ConnectionAttempts=1 \
            -o LogLevel=ERROR \
            -o NumberOfPasswordPrompts=1 \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$user@$host" true >/dev/null 2>&1; then
            rc=0
        else
            rc=$?
        fi
        if [[ "$rc" == 0 ]]; then
            REPLY="$password"
            unset password
            clear_screen
            echo "SSH access verified successfully."
            sleep 2.5
            clear_screen
            return 0
        fi
        unset password
        clear_screen
        if [[ "$rc" != 5 ]]; then
            echo "The VPS address, SSH port, or user is invalid, or SSH is unavailable."
            echo "Please enter the VPS connection details again."
            sleep 2.5
            clear_screen
            return 2
        fi
        if [[ "$attempt" -lt 3 ]]; then
            echo "The VPS password is incorrect."
            echo "Please try again."
            sleep 1.5
            clear_screen
        fi
    done
    echo "SSH authentication failed after 3 password attempts."
    echo "The VPS password is incorrect."
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

vault_view() {
    if [[ -f "$VAULT_FILE" ]]; then
        local output
        ensure_vault_password_file
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
        echo "Restore a valid backup or delete the damaged Vault before continuing."
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
    ensure_vault_password_file
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
    printf '\033[H\033[2J\033[3J'
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

add_node() {
    local name host bootstrap_user bootstrap_password bootstrap_port before after
    local ssh_result
    while true; do
        clear_screen
        read -r -e -p 'VPS IP address: ' host
        if ! valid_ipv4 "$host"; then
            echo "Invalid VPS IP address. Enter an IPv4 address."
            sleep 1.5
            continue
        fi
        name="auto"
        read -r -e -p 'VPS user [root]: ' bootstrap_user
        bootstrap_user="${bootstrap_user:-root}"
        read -r -e -p 'VPS SSH port [22]: ' bootstrap_port
        bootstrap_port="${bootstrap_port:-22}"
        if [[ ! "$bootstrap_port" =~ ^[0-9]+$ ]] || ((10#$bootstrap_port < 1 || 10#$bootstrap_port > 65535)); then
            echo "Invalid VPS SSH port. Enter a number from 1 to 65535."
            sleep 1.5
            continue
        fi
        if verify_bootstrap_ssh "$host" "$bootstrap_user" "$bootstrap_port"; then
            bootstrap_password="$REPLY"
            break
        else
            ssh_result=$?
            [[ "$ssh_result" == 2 ]] && continue
            exit 1
        fi
    done
    before="$(mktemp "$STATE_DIR/.before.XXXXXX")"
    after="$(mktemp "$STATE_DIR/.after.XXXXXX")"
    read_vault_state "$before" || { rm -f "$before" "$after"; return 1; }
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
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        clear_screen
        echo "The VPN server was not added. The Vault was not changed."
        read -r -p "Press Enter to continue" _
        return 1
    fi
    rm -f "$before" "$after"
    echo "VPN server added to encrypted state."
    if ! deploy_node "$name"; then
        echo "Initial deployment failed. The node remains in Vault and can be retried."
    fi
    read -r -p "Press Enter to continue" _
}

deploy_node() {
    local node="$1" before extra inventory key_file user host port bootstrap bootstrap_password bootstrap_user
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory="$(mktemp /tmp/xray-inventory.XXXXXX.yml)"
    read_vault_state "$before" || { rm -f "$before" "$extra" "$inventory"; return 1; }
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
        printf '%s\n' "all:" "  hosts:" "    $node:" "      ansible_host: $host" "      ansible_user: $user" "      ansible_port: $port" "      ansible_password: $bootstrap_password" "      ansible_become_password: $bootstrap_password" >"$inventory"
    elif [[ -n "$bootstrap" ]]; then
        user="$bootstrap_user"
        printf '%s' "$bootstrap" >"$key_file"
        printf '%s\n' "all:" "  hosts:" "    $node:" "      ansible_host: $host" "      ansible_user: $user" "      ansible_port: $port" "      ansible_ssh_private_key_file: $key_file" >"$inventory"
    else
        user=deploy
        python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["deploy_private_key"], end="")' "$node" <"$before" >"$key_file"
        printf '%s\n' "all:" "  hosts:" "    $node:" "      ansible_host: $host" "      ansible_user: $user" "      ansible_port: $port" "      ansible_ssh_private_key_file: $key_file" >"$inventory"
    fi
    chmod 600 "$key_file"
    if [[ -n "$bootstrap_password" ]]; then
        ansible-playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/site.yml"
    else
        ansible-playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/site.yml" --private-key "$key_file"
    fi
    if [[ "$user" == root ]]; then
        state_mutate mark-deployed "$node"
    fi
    rm -f "$before" "$extra" "$inventory" "$key_file"
}

run_node_playbook() {
    local node="$1" playbook="$2" before extra inventory key_file host port
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory="$(mktemp /tmp/xray-inventory.XXXXXX.yml)"
    key_file="$(mktemp)"
    read_vault_state "$before" || { rm -f "$before" "$extra" "$inventory" "$key_file"; return 1; }
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$before")"
    python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["deploy_private_key"], end="")' "$node" <"$before" >"$key_file"
    printf '%s\n' "all:" "  hosts:" "    $node:" "      ansible_host: $host" "      ansible_user: deploy" "      ansible_port: $port" >"$inventory"
    chmod 600 "$key_file"
    ansible-playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/$playbook" --private-key "$key_file"
    rm -f "$before" "$extra" "$inventory" "$key_file"
}

rotate_ssh_key() {
    local node="$1" before extra inventory old_key new_key new_pub host old_pub port
    before="$(mktemp)"
    extra="$(mktemp)"
    inventory="$(mktemp /tmp/xray-inventory.XXXXXX.yml)"
    old_key="$(mktemp)"
    new_key="$(mktemp)"
    new_pub="${new_key}.pub"
    read_vault_state "$before" || { rm -f "$before" "$extra" "$inventory" "$old_key" "$new_key" "$new_pub"; return 1; }
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
    printf '%s\n' "all:" "  hosts:" "    $node:" "      ansible_host: $host" "      ansible_user: deploy" "      ansible_port: $port" >"$inventory"
    ansible-playbook -i "$inventory" -e "@$extra" "$ROOT_DIR/ansible/rotate-ssh.yml" --private-key "$old_key"
    ssh -i "$new_key" -p "$port" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new deploy@"$host" true
    state_mutate set-deploy-key "$node" "$new_key" "$new_pub"
    rm -f "$before" "$extra" "$inventory" "$old_key" "$new_key" "$new_pub"
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
            2) clear_screen; if state_mutate add-key "$node"; then deploy_node "$node"; echo "Access key added."; fi; read -r -p "Press Enter" _ ;;
            3) clear_screen; read -r -e -p 'Key id: ' key_id; if state_mutate remove-key "$node" "$key_id"; then deploy_node "$node"; echo "Access key removed."; fi; read -r -p "Press Enter" _ ;;
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
    local count names choice node
    clear_screen
    if ! count="$(vault_state_command python3 "$ROOT_DIR/scripts/state_cli.py" count)"; then
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
            1) add_node ;;
            b) return ;;
            m) MAIN_MENU_REQUESTED=1; return ;;
            x) exit_tui ;;
            *) invalid_choice ;;
        esac
        return
    fi
    if [[ "$count" == 1 ]]; then
        if ! node="$(vault_state_command python3 "$ROOT_DIR/scripts/state_cli.py" names)"; then
            return 1
        fi
        manage_node "$node"
        return
    fi
    show_nodes
    prompt_nav
    case "$REPLY" in
        b) return ;;
        m) MAIN_MENU_REQUESTED=1; return ;;
        x) exit_tui ;;
        *[!0-9]*) invalid_choice ;;
        *)
            if ! names="$(vault_state_command python3 "$ROOT_DIR/scripts/state_cli.py" names)"; then
                return 1
            fi
            node="$(printf '%s\n' "$names" | sed -n "${REPLY}p")"
            [[ -n "$node" ]] && manage_node "$node" || invalid_choice
            ;;
    esac
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
                    ensure_vault_password_file
                    ansible-vault rekey --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE"
                    rm -f "$VAULT_PASSWORD_FILE"
                    VAULT_PASSWORD_FILE=""
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
