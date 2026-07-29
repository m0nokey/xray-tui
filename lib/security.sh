#!/usr/bin/env bash

rotate_ssh_key() {
    local node="$1" before extra inventory inventory_dir key_dir old_key new_key new_pub rotated_state known_hosts_file host old_pub port
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
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$before")"
    old_pub="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_authorized_key"], end="")' "$node" <"$before")"
    if ! write_node_known_hosts "$before" "$node" "$known_hosts_file" "$port"; then
        printf '%s\n' "The SSH host key is not pinned for this VPN server. Redeploy it before rotating the SSH key."
        rm -f "$before" "$extra" "$rotated_state"
        rm -rf "$inventory_dir" "$key_dir"
        return 1
    fi
    python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$before" >"$old_key"
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
    "deploy_authorized_key": node["management_authorized_key"],
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
    if ! python3 "$ROOT_DIR/scripts/state_cli.py" set-management-key "$node" "$new_key" "$new_pub" <"$before" >"$rotated_state"; then
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
    pipeline_stage 75 'Deleting the old SSH key'
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
    pipeline_complete "Management SSH key rotated successfully." 1
}
