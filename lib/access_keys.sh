#!/usr/bin/env bash

mutate_access_keys_and_deploy() {
    local node="$1" action="$2" key_id="${3:-}" before after success_message
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
        pipeline_abort
        printf '%s\n' "The VPN was updated, but the encrypted Vault could not be saved."
        printf '%s\n' "The existing Vault was not changed."
        return 1
    fi
    rm -f "$before" "$after"
    case "$action" in
        add-keys)
            if ((10#$key_id == 1)); then
                success_message='Access key added successfully.'
            else
                success_message="${key_id} access keys added successfully."
            fi
            ;;
        remove-all-keys) success_message='All access keys deleted successfully.' ;;
        remove-key) success_message='Access key deleted successfully.' ;;
    esac
    pipeline_complete "$success_message" 1
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
        if ! read_required_choice count '?: ' 'a number from 1 to 50, or b, m, i, x'; then continue; fi
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
                    :
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
        menu_heading "Delete access key:"
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
            printf '%s%s.%s %sDelete all access keys%s\n' "$COLOR_LINE" "$remove_all_selection" "$COLOR_RESET" "$COLOR_TEXT" "$COLOR_RESET"
        fi
        echo
        if ! prompt_nav "1-$remove_all_selection"; then continue; fi
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
                    menu_heading "Delete all access keys:"
                    echo
                    printf '%s\n' "This will delete every Vision and XHTTP access key from the VPS."
                    printf '%s\n' "Are you sure you want to delete all access keys? (y/n)"
                    echo
                    menu_control b back
                    menu_control m main
                    menu_control i info
                    menu_control x exit
                    echo
                    if ! read_required_choice confirm '?: ' 'y or n, or b, m, i, x'; then continue; fi
                    case "$confirm" in
                        [Yy])
                            clear_screen
                            if mutate_access_keys_and_deploy "$node" remove-all-keys; then
                                :
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
                    menu_heading "Delete access key:"
                    echo
                    printf '%s\n' "  Key id: $key_id"
                    printf '%s\n' "  Vision ID: $vision_id"
                    printf '%s\n' "  XHTTP ID: $xhttp_id"
                    echo
                    printf '%s\n' "  Are you sure you want to delete this access key? (y/n)"
                    echo
                    menu_control b back
                    menu_control m main
                    menu_control i info
                    menu_control x exit
                    echo
                    if ! read_required_choice confirm '?: ' 'y or n, or b, m, i, x'; then continue; fi
                    case "$confirm" in
                        [Yy])
                            clear_screen
                            if mutate_access_keys_and_deploy "$node" remove-key "$key_id"; then
                                :
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
manage_keys() {
    local node="$1"
    while true; do
        clear_screen
        echo
        menu_heading "Manage access keys:"
        echo
        menu_option 1 Show
        menu_option 2 Add
        menu_option 3 Delete
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
