#!/usr/bin/env bash

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
        pipeline_stage 20 'Checking VPS resources'
    else
        clear_screen
        printf '%s\n' "Checking VPS resources..."
    fi
    ansible-playbook -i "$inventory" "$ROOT_DIR/ansible/preflight.yml" >"$log" 2>&1 &
    preflight_pid=$!
    while kill -0 "$preflight_pid" 2>/dev/null; do
        pipeline_stage_from_ansible_log "$log"
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
    # These facts are consumed by the sourced DNS module after probing.
    # shellcheck disable=SC2034
    VPS_VCPUS="${BASH_REMATCH[1]}"
    # shellcheck disable=SC2034
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
        pipeline_stage 20 'Checking VPS resources'
        ansible-playbook -i "$inventory" "$ROOT_DIR/ansible/preflight.yml" >"$log" 2>&1 &
        preflight_pid=$!
        while kill -0 "$preflight_pid" 2>/dev/null; do
            pipeline_stage_from_ansible_log "$log"
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
    # These facts are consumed by the sourced DNS module after probing.
    # shellcheck disable=SC2034
    VPS_VCPUS="${BASH_REMATCH[1]}"
    # shellcheck disable=SC2034
    VPS_RAM_MB="${BASH_REMATCH[2]}"
    rm -rf "$inventory_dir"
    ((pipeline_owned)) && pipeline_complete "VPS resources available"
    return 0
}

run_ansible_playbook() {
    local log rc quiet=0 debug_output='' ansible_pid pipeline_owned=0
    if [[ "${1:-}" == "--quiet" ]]; then
        quiet=1
        shift
    fi
    # Deployment code reads this captured output to extract generated SSH data.
    # shellcheck disable=SC2034
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
            pipeline_stage_from_ansible_log "$log"
            pipeline_render
            sleep 0.1
        done
        if wait "$ansible_pid"; then
            rc=0
        else
            rc=$?
        fi
        if ((rc != 0)); then
            # shellcheck disable=SC2034
            LAST_ANSIBLE_OUTPUT="$(tail -n 24 "$log")"
        else
            # shellcheck disable=SC2034
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
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$state_file")"
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
        str(node["management_port"]),
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
    if ! cp "$state_file" "$recovery_state"; then
        rm -f "$recovery_state"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$recovery_state")"
    user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_user"])' "$node" <"$recovery_state")"
    target_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["ssh_port"])' "$node" <"$recovery_state")"
    management_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$recovery_state")"
    bootstrap_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["bootstrap_ssh_port"])' "$node" <"$recovery_state")"
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
    python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$recovery_state" >"$key_file"
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
