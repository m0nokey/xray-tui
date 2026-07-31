#!/usr/bin/env bash

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

show_nodes() {
    local state
    state="$(mktemp "$RUNTIME_TMP_DIR/.nodes.XXXXXX")"
    if read_vault_state "$state"; then
        python3 "$ROOT_DIR/scripts/render_nodes.py" --check <"$state"
    fi
    rm -f "$state"
}

show_node_status() {
    local node="$1" state
    state="$(mktemp "$RUNTIME_TMP_DIR/.node.XXXXXX")"
    if read_vault_state "$state"; then
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
    user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_user"])' "$node" <"$state")"
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$state")"
    private_key="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$state")"
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
            3)
                clear_screen
                if run_node_playbook "$node" restart.yml "" "Restarting VPN service" restart; then
                    pipeline_complete "VPN server restarted successfully." 1
                else
                    pause_result_screen
                fi
                ;;
            4) manage_dns_protection "$node" || true; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            5) manage_local_region_policy "$node" || true; [[ "$MAIN_MENU_REQUESTED" == 1 ]] && return ;;
            6) clear_screen; rotate_ssh_key "$node" || true ;;
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
        if ! read_required_choice confirm '?: ' 'y or n, or b, m, i, x'; then continue; fi
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
        management_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$state")"
        bootstrap_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["bootstrap_ssh_port"])' "$node" <"$state")"
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
            pipeline_complete "VPN server deleted from VPS and Vault." 1
            return "$NODE_REMOVED_STATUS"
        fi
        pipeline_abort
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
        if ! read_required_choice local_confirm '?: ' '1 or 2, or b, m, i, x'; then continue; fi
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
                        pipeline_complete "VPN server deleted from VPS and Vault." 1
                        removed=1
                    else
                        pipeline_abort
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
    local count names node state node_status
    while true; do
        clear_screen
        state="$(mktemp "$RUNTIME_TMP_DIR/.servers.XXXXXX")"
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
            menu_heading "VPN servers:"
            echo
            printf '%s\n' "  No VPN servers configured."
            echo
            menu_option 1 "Add VPN server"
            echo
            if ! prompt_nav; then continue; fi
            case "$REPLY" in
                1) rm -f "$state"; add_node || true; return ;;
                i) show_info add-node; rm -f "$state"; continue ;;
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
        if ! prompt_nav "1-$count"; then continue; fi
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
