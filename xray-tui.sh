#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"
VAULT_FILE="$STATE_DIR/vault.json"
VAULT_PASSWORD_FILE=""
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

cleanup() {
    [[ -n "$VAULT_PASSWORD_FILE" ]] && rm -f "$VAULT_PASSWORD_FILE"
}
trap cleanup EXIT INT TERM

ensure_vault_password_file() {
    local password
    [[ -n "$VAULT_PASSWORD_FILE" && -f "$VAULT_PASSWORD_FILE" ]] && return 0
    VAULT_PASSWORD_FILE="$(mktemp /tmp/xray-vault-password.XXXXXX)"
    chmod 600 "$VAULT_PASSWORD_FILE"
    printf 'Vault password: '
    read -r -s password
    printf '\n'
    printf '%s\n' "$password" >"$VAULT_PASSWORD_FILE"
    unset password
}

vault_view() {
    if [[ -f "$VAULT_FILE" ]]; then
        ensure_vault_password_file
        ansible-vault view --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE"
    else
        printf '{"nodes":{}}\n'
    fi
}

vault_save() {
    local input="$1" temp
    ensure_vault_password_file
    temp="$(mktemp "$STATE_DIR/.state.XXXXXX")"
    chmod 600 "$temp"
    cat >"$temp" <"$input"
    ansible-vault encrypt "$temp" --output "$VAULT_FILE" --vault-password-file "$VAULT_PASSWORD_FILE"
    chmod 600 "$VAULT_FILE"
    rm -f "$temp"
}

state_mutate() {
    local action="$1"; shift
    local before after
    before="$(mktemp "$STATE_DIR/.before.XXXXXX")"
    after="$(mktemp "$STATE_DIR/.after.XXXXXX")"
    vault_view >"$before"
    python3 "$ROOT_DIR/scripts/state_cli.py" "$action" "$@" <"$before" >"$after"
    vault_save "$after"
    rm -f "$before" "$after"
}

prompt_nav() {
    echo "b. back"
    echo "m. main"
    echo "x. exit"
    printf '?: '
    read -r REPLY
}

show_nodes() {
    vault_view | python3 "$ROOT_DIR/scripts/render_nodes.py" --check
}

yaml_scalar() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

add_node() {
    local name host bootstrap_user bootstrap_password bootstrap_port before after
    printf 'Node name: '; read -r name
    printf 'IP address or hostname: '; read -r host
    printf 'Initial SSH user [root]: '
    read -r bootstrap_user
    bootstrap_user="${bootstrap_user:-root}"
    printf 'Initial SSH port [22]: '
    read -r bootstrap_port
    bootstrap_port="${bootstrap_port:-22}"
    [[ "$bootstrap_port" =~ ^[0-9]+$ ]] || { echo "SSH port must be numeric."; read -r -p "Press Enter" _; return 1; }
    printf 'Initial root SSH password: '
    read -r -s bootstrap_password
    printf '\n'
    [[ -n "$bootstrap_password" ]] || { echo "SSH password cannot be empty."; read -r -p "Press Enter" _; return 1; }
    before="$(mktemp "$STATE_DIR/.before.XXXXXX")"
    after="$(mktemp "$STATE_DIR/.after.XXXXXX")"
    vault_view >"$before"
    XRAY_BOOTSTRAP_USER="$bootstrap_user" XRAY_BOOTSTRAP_PASSWORD="$bootstrap_password" XRAY_BOOTSTRAP_PORT="$bootstrap_port" python3 "$ROOT_DIR/scripts/state_cli.py" add-node "$name" "$host" <"$before" >"$after"
    unset bootstrap_password
    vault_save "$after"
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
    inventory="$(mktemp)"
    vault_view >"$before"
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
    inventory="$(mktemp)"
    key_file="$(mktemp)"
    vault_view >"$before"
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
    inventory="$(mktemp)"
    old_key="$(mktemp)"
    new_key="$(mktemp)"
    new_pub="${new_key}.pub"
    vault_view >"$before"
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
        echo
        echo "Manage access keys:"
        echo
        echo "1. Show keys"
        echo "2. Add key"
        echo "3. Remove key"
        echo
        prompt_nav
        case "$REPLY" in
            1) vault_view | python3 "$ROOT_DIR/scripts/render_keys.py" "$node"; prompt_nav >/dev/null ;;
            2) state_mutate add-key "$node"; deploy_node "$node"; echo "Access key added."; read -r -p "Press Enter" _ ;;
            3) printf 'Key id: '; read -r key_id; state_mutate remove-key "$node" "$key_id"; deploy_node "$node"; echo "Access key removed."; read -r -p "Press Enter" _ ;;
            b|m|x) return ;;
        esac
    done
}

manage_node() {
    local node="$1"
    while true; do
        echo
        vault_view | python3 "$ROOT_DIR/scripts/render_nodes.py" --check --node "$node"
        echo
        echo "1. Manage VPN server"
        echo "2. Manage access keys"
        echo
        prompt_nav
        case "$REPLY" in
            1) manage_server "$node" ;;
            2) manage_keys "$node" ;;
            b|m|x) return ;;
        esac
    done
}

manage_server() {
    local node="$1"
    while true; do
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
            1) vault_view | python3 "$ROOT_DIR/scripts/render_nodes.py" --check --node "$node"; read -r -p "Press Enter" _ ;;
            2) run_node_playbook "$node" restart.yml; read -r -p "Press Enter" _ ;;
            3) rotate_ssh_key "$node"; read -r -p "Press Enter" _ ;;
            4) remove_node "$node"; return ;;
            b|m|x) return ;;
        esac
    done
}

remove_node() {
    local node="$1" confirm local_confirm
    printf 'Remove this VPN server? (y/N): '
    read -r confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return 0

    if run_node_playbook "$node" remove.yml; then
        state_mutate remove-node "$node"
        echo "VPN server removed from the VPS and Vault."
        return 0
    fi

    echo "The VPS could not be reached; its remote cleanup was not completed."
    printf 'Remove the unavailable server from the local Vault anyway? (y/N): '
    read -r local_confirm
    if [[ "$local_confirm" =~ ^[Yy]$ ]]; then
        state_mutate remove-node "$node"
        echo "VPN server removed from the local Vault."
    fi
    read -r -p "Press Enter" _
}

vpn_servers() {
    local count names choice node
    count="$(vault_view | python3 "$ROOT_DIR/scripts/state_cli.py" count)"
    if [[ "$count" == 0 ]]; then
        echo
        echo "VPN servers:"
        echo
        echo "  No VPN servers configured."
        echo
        echo "  1. Add VPN server"
        echo
        prompt_nav
        [[ "$REPLY" == 1 ]] && add_node
        return
    fi
    if [[ "$count" == 1 ]]; then
        node="$(vault_view | python3 "$ROOT_DIR/scripts/state_cli.py" names)"
        manage_node "$node"
        return
    fi
    show_nodes
    prompt_nav
    if [[ "$REPLY" =~ ^[0-9]+$ ]]; then
        node="$(vault_view | python3 "$ROOT_DIR/scripts/state_cli.py" names | sed -n "${REPLY}p")"
        [[ -n "$node" ]] && manage_node "$node"
    fi
}

secure_state() {
    while true; do
        echo
        echo "Vault:"
        echo
        echo "Encrypted storage for VPS access and VPN keys."
        echo
        echo "1. Change encryption password"
        echo "2. Backup encrypted state"
        echo "3. Restore encrypted state"
        echo
        prompt_nav
        case "$REPLY" in
            1) ensure_vault_password_file; ansible-vault rekey --vault-password-file "$VAULT_PASSWORD_FILE" "$VAULT_FILE"; rm -f "$VAULT_PASSWORD_FILE"; VAULT_PASSWORD_FILE="" ;;
            2) cp -p "$VAULT_FILE" "$STATE_DIR/vault.json.backup" ;;
            3) cp -p "$STATE_DIR/vault.json.backup" "$VAULT_FILE"; rm -f "$VAULT_PASSWORD_FILE"; VAULT_PASSWORD_FILE="" ;;
            b|m|x) return ;;
        esac
    done
}

while true; do
    echo
    echo "1. VPN servers"
    echo "2. Add VPN server"
    echo "3. Vault"
    echo
    echo "x. exit"
    printf '?: '
    read -r choice
    case "$choice" in
        1) vpn_servers ;;
        2) add_node ;;
        3) secure_state ;;
        x) exit 0 ;;
    esac
done
