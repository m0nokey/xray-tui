#!/usr/bin/env bash

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

            pipeline_start "Checking VPS resources" preflight
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
    pipeline_start "Installing VPN server" install
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
    pipeline_complete "VPN server added successfully." 1
}

deploy_node() {
    local node="$1" state_file="${2:-}" connect_port="${3:-}" bootstrap_mode="${4:-0}" before extra inventory inventory_dir key_file known_hosts_file host_key_file user host port target_port management_port bootstrap bootstrap_password bootstrap_user host_public_key ssh_common_args rc marked hardened_state ssh_host_public_key ssh_host_fingerprint actual_fingerprint
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
    python3 "$ROOT_DIR/scripts/state_cli.py" extract "$node" <"$before" >"$extra"
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    target_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$before")"
    management_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$before")"
    port="${connect_port:-${management_port:-$target_port}}"
    key_file="$(mktemp)"
    bootstrap="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_private_key", ""), end="")' "$node" <"$before")"
    bootstrap_password="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]].get("bootstrap_password", ""), end="")' "$node" <"$before")"
    if [[ "$bootstrap_mode" != 1 ]]; then
        bootstrap_password=""
    fi
    bootstrap_user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["bootstrap_user"], end="")' "$node" <"$before")"
    host_public_key="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_host_public_key"], end="")' "$node" <"$before")"
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
        python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$before" >"$key_file"
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
        python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$before" >"$key_file"
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
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$before")"
    python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$before" >"$key_file"
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
        ((rc != 0)) && pipeline_abort
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
    user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_user"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$before")"
    private_key="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$before")"
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
        if ((rc != 0)); then pipeline_abort; fi
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
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["bootstrap_ssh_port"])' "$node" <"$before")"
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
        if ((rc != 0)); then pipeline_abort; fi
    fi
    return "$rc"
}
