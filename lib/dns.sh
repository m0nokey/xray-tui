#!/usr/bin/env bash

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
    local entries reference_entries reference_memory
    entries="$(dns_custom_entries)"
    reference_entries="$(dns_custom_reference_entries)"
    reference_memory="$(dns_custom_reference_memory_mb)"
    local estimate=$(( (entries * reference_memory + reference_entries - 1) / reference_entries ))
    ((estimate < 1)) && estimate=1
    printf '%s' "$estimate"
}

dns_custom_memory_floor() {
    local estimated headroom round
    estimated="$(dns_custom_estimated_rpz_memory)"
    headroom="$(dns_custom_memory_headroom_mb)"
    round="$(dns_custom_memory_round_mb)"
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
    local query="" choice index code name status page=0 page_size=20 page_count start end input_options
    local search_action next_action previous_action apply_action action_base
    local -a matches=()
    while true; do
        clear_screen
        menu_heading "Block countries"
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
        input_options=""
        if ((end > start)); then input_options="1-$((end - start))"; fi
        input_options="${input_options:+$input_options }$search_action"
        if [[ -z "$query" && $page -lt $((page_count - 1)) ]]; then input_options="$input_options $next_action"; fi
        if [[ -z "$query" && $page -gt 0 ]]; then input_options="$input_options $previous_action"; fi
        input_options="$input_options $apply_action"
        if ! prompt_nav "$input_options"; then continue; fi
        choice="$REPLY"
        case "$choice" in
            "$search_action")
                if ! read_required_choice query "Country name or ISO code: " 'a country name or ISO code, or b, m, i, x'; then continue; fi
                ;;
            "$next_action")
                if [[ -z "$query" ]]; then
                    page=$((page + 1))
                else
                    invalid_choice
                fi
                ;;
            "$previous_action")
                if [[ -z "$query" ]]; then
                    page=$((page - 1))
                else
                    invalid_choice
                fi
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
        if ! prompt_nav "1-${#sources[@]} $apply_action"; then continue; fi
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
            menu_heading "Block ads and threats"
        else
            menu_heading "Current profile: Block ads and threats"
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
            # The shared invalid-input renderer reads this sourced global.
            # shellcheck disable=SC2034
            CURRENT_INPUT_HINT='Enter 1, 2, 3, 4, 5, 6, b, m, i, or x. Press Enter for Disabled.'
            if ! read -r -e -p '?: ' REPLY; then return 1; fi
            [[ -z "$REPLY" ]] && REPLY=1
        else
            if ! prompt_nav '1 2 3 4 5 6'; then continue; fi
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
manage_dns_protection() {
    local node="$1" before after host user port private_key known_hosts_file current_profile current_lists selected_profile selected_lists
    before="$(mktemp)"
    if ! read_vault_state "$before"; then
        rm -f "$before"
        return 1
    fi
    host="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["host"])' "$node" <"$before")"
    user="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_user"])' "$node" <"$before")"
    port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_port"])' "$node" <"$before")"
    private_key="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["nodes"][sys.argv[1]]["management_private_key"], end="")' "$node" <"$before")"
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
    if [[ "$selected_profile" == 'disabled' ]]; then
        printf '%s\n' "Disabling DNS protection."
    else
        printf '%s\n' "Enabling ${selected_profile^} DNS protection."
    fi
    if ! run_node_playbook "$node" site.yml "$after" "Updating DNS protection" dns; then
        rm -f "$before" "$after" "$known_hosts_file"
        show_result_screen "DNS protection change failed. The existing Vault was not changed."
        return 1
    fi
    if ! vault_save "$after"; then
        rm -f "$before" "$after"
        pipeline_abort
        show_result_screen \
            "The VPN was updated, but the encrypted Vault could not be saved." \
            "The existing DNS profile remains recorded in the Vault."
        return 1
    fi
    rm -f "$before" "$after" "$known_hosts_file"
    if [[ "$selected_profile" == 'disabled' ]]; then
        pipeline_complete "DNS protection is now disabled." 1
    else
        pipeline_complete "${selected_profile^} DNS protection is now enabled." 1
    fi
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
        menu_heading "Block countries"
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
            printf '%s\n' "Applying country blocking."
        else
            printf '%s\n' "Disabling country blocking."
        fi
        if ! run_node_playbook "$node" site.yml "$after" "Updating country blocking" countries; then
            rm -f "$before" "$after"
            unset LOCAL_REGION_COUNTRIES
            show_result_screen "Country blocking change failed. The existing Vault was not changed."
            return 1
        fi
        if ! vault_save "$after"; then
            rm -f "$before" "$after"
            unset LOCAL_REGION_COUNTRIES
            pipeline_abort
            show_result_screen \
                "The VPN was updated, but the encrypted Vault could not be saved." \
                "The previous country blocking settings remain recorded in the Vault."
            return 1
        fi
        rm -f "$before" "$after"
        unset LOCAL_REGION_COUNTRIES
        if [[ -n "$selected_countries" ]]; then
            pipeline_complete "Country blocking is now enabled." 1
        else
            pipeline_complete "Country blocking is now disabled." 1
        fi
        return 0
    done
}
