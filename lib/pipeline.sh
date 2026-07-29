#!/usr/bin/env bash

pipeline_start() {
    ((DEBUG_MODE)) && return 0
    PIPELINE_ACTIVE=1
    PIPELINE_TITLE="$1"
    PIPELINE_OPERATION="${2:-}"
    case "$PIPELINE_OPERATION" in
        preflight) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking the VPS connection' ;;
        install) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking the VPS connection' ;;
        access_keys) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking SSH access' ;;
        dns) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking SSH access' ;;
        countries) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking SSH access' ;;
        restart) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking SSH access' ;;
        rotate) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking SSH access' ;;
        remove) PIPELINE_PERCENT=10; PIPELINE_LABEL='Checking SSH access' ;;
        *) PIPELINE_PERCENT=10; PIPELINE_LABEL='Preparing the operation' ;;
    esac
    PIPELINE_FRAME=0
    if [[ -t 0 && -t 1 ]]; then
        PIPELINE_TTY_STATE="$(stty -g 2>/dev/null || true)"
        if [[ -n "$PIPELINE_TTY_STATE" ]] && stty -echo -icanon -isig 2>/dev/null; then
            printf '\033[?25l'
            PIPELINE_TTY_ACTIVE=1
        fi
    fi
    clear_screen
    printf '%s%s%s\n\n' "$COLOR_LINE" "$PIPELINE_TITLE" "$COLOR_RESET"
    pipeline_render
}

pipeline_render() {
    local frames=$'|/-\\' frame
    ((DEBUG_MODE || !PIPELINE_ACTIVE)) && return 0
    pipeline_drain_input
    frame="${frames:PIPELINE_FRAME%4:1}"
    if [[ -t 1 ]]; then
        printf '\r\033[K  %b[%3d%%]%b %-44s %s' \
            "$COLOR_LINE" "$PIPELINE_PERCENT" "$COLOR_RESET" "$PIPELINE_LABEL" "$frame"
    else
        printf '  [%3d%%] %-44s\n' "$PIPELINE_PERCENT" "$PIPELINE_LABEL"
    fi
    PIPELINE_FRAME=$((PIPELINE_FRAME + 1))
}

pipeline_drain_input() {
    ((PIPELINE_TTY_ACTIVE)) || return 0
    local pipeline_input=''
    while IFS= read -r -t 0 -n 10000 pipeline_input 2>/dev/null; do
        :
    done
    : "$pipeline_input"
    unset pipeline_input
}

pipeline_restore_terminal() {
    if ((PIPELINE_TTY_ACTIVE)); then
        pipeline_drain_input
        if [[ -n "$PIPELINE_TTY_STATE" ]]; then
            stty "$PIPELINE_TTY_STATE" 2>/dev/null || stty sane 2>/dev/null || true
        else
            stty sane 2>/dev/null || true
        fi
        printf '\033[?25h'
    fi
    PIPELINE_TTY_ACTIVE=0
    PIPELINE_TTY_STATE=''
}

pipeline_stage() {
    ((DEBUG_MODE)) && return 0
    if ((PIPELINE_ACTIVE == 0)); then
        pipeline_start "Working on VPN server"
    fi
    if [[ "$PIPELINE_LABEL" == "$2" ]]; then
        return 0
    fi
    if (( $1 < PIPELINE_PERCENT )); then
        return 0
    fi
    if [[ -n "$PIPELINE_LABEL" && "$PIPELINE_LABEL" != 'Preparing...' && -t 1 ]]; then
        printf '\r\033[K  %b[%3d%%]%b %-44s %b%s%b\n' \
            "$COLOR_LINE" "$PIPELINE_PERCENT" "$COLOR_RESET" "$PIPELINE_LABEL" \
            "$COLOR_SUCCESS" "done" "$COLOR_RESET"
    fi
    PIPELINE_PERCENT="$1"
    PIPELINE_LABEL="$2"
    PIPELINE_FRAME=0
}

pipeline_stage_from_ansible_log() {
    local log="$1" task task_name
    [[ -s "$log" ]] || return 0
    task="$(grep '^TASK \[' "$log" | tail -n 1 | sed -E 's/^TASK \[(.*)\] .*/\1/' || true)"
    [[ -n "$task" ]] || return 0
    task_name="$task"
    [[ "$task_name" == *': '* ]] && task_name="${task_name#*: }"

    case "$PIPELINE_OPERATION:$task_name" in
        preflight:Wait\ for\ VPS\ SSH\ access|preflight:Gather\ VPS\ facts\ after\ SSH\ is\ available)
            pipeline_stage 20 'Checking VPS access' ;;
        preflight:Require\ Debian|preflight:Report\ VPS\ resources)
            pipeline_stage 80 'Checking VPS resources' ;;
        install:Wait\ for\ initial\ SSH\ access)
            pipeline_stage 10 'Checking the VPS connection' ;;
        install:Gather\ VPS\ facts\ after\ SSH\ is\ available)
            pipeline_stage 20 'Checking VPS system' ;;
        install:Bootstrap\ deploy\ access|install:Create\ deploy\ group|install:Create\ deploy\ user|install:Install\ deploy\ authorized\ key|install:Install\ passwordless\ deploy\ sudoers\ file)
            pipeline_stage 30 'Preparing VPS access' ;;
        install:Wait\ for\ deploy\ SSH\ access\ after\ bootstrap)
            pipeline_stage 35 'Reconnecting after bootstrap' ;;
        install:Check\ whether\ Xray\ TUI\ host\ key\ was\ initialized|install:Install\ complete\ hardened\ sshd_config|install:Reload\ SSH\ daemon\ after\ hardening)
            pipeline_stage 40 'Hardening SSH access' ;;
        install:Verify\ effective\ hardened\ SSH\ port|install:Report\ generated\ SSH\ host\ key)
            pipeline_stage 50 'Verifying hardened SSH access' ;;
        install:Install\ base\ packages|install:Install\ Docker\ and\ Compose\ plugin|install:Enable\ Docker|install:Install\ Xray\ TUI\ OS\ updater*|install:Install\ Xray\ TUI\ Docker\ updater*)
            pipeline_stage 60 'Installing Docker and system packages' ;;
        install:Render\ Unbound\ configuration|install:Render\ Unbound\ Dockerfile|install:Render\ Docker\ Compose\ file|install:Render\ Xray\ configuration)
            pipeline_stage 70 'Rendering VPN configuration' ;;
        install:Validate\ Unbound*|install:Validate\ Xray\ configuration*|install:Validate\ REALITY\ target)
            pipeline_stage 80 'Validating Xray and DNS configuration' ;;
        install:Ensure\ Xray\ stack\ is\ running)
            pipeline_stage 90 'Starting and checking VPN stack' ;;
        access_keys:*|dns:*|countries:*)
            pipeline_stage_from_xray_task "$task_name" ;;
        restart:Wait\ for\ SSH\ access)
            pipeline_stage 10 'Checking SSH access' ;;
        restart:Restart\ Xray\ Compose\ service)
            pipeline_stage 80 'Restarting the Xray container' ;;
        rotate:Wait\ for\ SSH\ access)
            pipeline_stage 10 'Checking SSH access' ;;
        rotate:Ensure\ deploy\ SSH\ directory\ permissions|rotate:Install\ the\ new\ deploy\ key)
            pipeline_stage 30 'Installing the new SSH key' ;;
        rotate:Remove\ the\ old\ deploy\ key)
            pipeline_stage 70 'Deleting the old SSH key' ;;
        remove:Wait\ for\ SSH\ access)
            pipeline_stage 10 'Checking SSH access' ;;
        remove:Check\ whether\ *|remove:Detect\ a\ previously\ interrupted\ cleanup|remove:Select\ the\ original\ SSH\ configuration\ backup)
            pipeline_stage 20 'Checking installed VPN components' ;;
        remove:Remove\ the\ Xray\ Compose\ project|remove:Remove\ Xray\ files)
            pipeline_stage 35 'Stopping the VPN stack' ;;
        remove:Stop\ Xray\ TUI\ updater\ services|remove:Remove\ Xray\ TUI\ updater\ files|remove:Remove\ updater\ configuration*)
            pipeline_stage 50 'Deleting Xray and updater files' ;;
        remove:Restore\ the\ original\ sshd_config|remove:Restore\ original\ SSH\ host\ keys|remove:Reload\ SSH\ after\ restoring*)
            pipeline_stage 70 'Restoring SSH configuration' ;;
        remove:Remove\ Docker\ packages*|remove:Remove\ Docker\ runtime*|remove:Remove\ deploy\ user*)
            pipeline_stage 80 'Deleting Docker and deploy access' ;;
        remove:Remove\ Xray\ TUI\ state\ directory*)
            pipeline_stage 90 'Verifying VPS cleanup' ;;
    esac
}

pipeline_stage_from_xray_task() {
    local task="$1"
    case "$task" in
        Wait\ for\ initial\ SSH\ access|Gather\ VPS\ facts\ after\ SSH\ is\ available)
            pipeline_stage 10 'Checking SSH access' ;;
        Gather\ package\ facts|Set\ Debian\ codename)
            pipeline_stage 15 'Checking VPS system' ;;
        Validate\ local\ encrypted\ runtime\ state|Select\ DNS\ protection\ profile|Select\ local-region\ traffic\ policy|Validate\ DNS\ protection\ profile|Validate\ local-region\ traffic\ policy|Validate\ custom\ DNS\ protection\ sources|Calculate\ selected\ DNS\ protection\ entries|Calculate\ DNS\ runtime\ memory|Validate\ VPS\ resources\ for\ DNS\ protection)
            pipeline_stage 20 'Preparing selected settings' ;;
        Render\ Unbound\ configuration|Render\ Unbound\ Dockerfile|Render\ Docker\ Compose\ file|Render\ Xray\ configuration)
            pipeline_stage 40 'Rendering VPN configuration' ;;
        Build\ Unbound\ image*|Inspect\ Unbound\ container|Select\ Unbound\ container\ state|Validate\ running\ Unbound\ configuration|Validate\ Unbound\ configuration*)
            pipeline_stage 55 'Validating DNS configuration' ;;
        Validate\ Xray\ configuration*|Validate\ REALITY\ target)
            pipeline_stage 65 'Validating Xray configuration' ;;
        Restart\ Unbound\ after\ configuration\ validation|Ensure\ Xray\ stack\ is\ running)
            pipeline_stage 90 'Starting and checking VPN stack' ;;
    esac
}

pipeline_default_success_message() {
    case "$PIPELINE_OPERATION" in
        preflight) printf '%s' 'VPS resources are available.' ;;
        install) printf '%s' 'VPN server added successfully.' ;;
        access_keys) printf '%s' 'Access keys updated successfully.' ;;
        dns) printf '%s' 'DNS protection updated successfully.' ;;
        countries) printf '%s' 'Country blocking updated successfully.' ;;
        restart) printf '%s' 'VPN server restarted successfully.' ;;
        rotate) printf '%s' 'Management SSH key rotated successfully.' ;;
        remove) printf '%s' 'VPN server deleted successfully.' ;;
        *) printf '%s' 'Operation completed successfully.' ;;
    esac
}

pipeline_complete() {
    local final_message="${1:-$(pipeline_default_success_message)}" pause="${2:-0}"
    if ((DEBUG_MODE)); then
        printf '\n%s\n' "$final_message"
        ((pause)) && wait_action_return
        return 0
    fi
    ((PIPELINE_ACTIVE)) || return 0
    if [[ -t 1 ]]; then
        if [[ -n "$PIPELINE_LABEL" && "$PIPELINE_LABEL" != 'Preparing...' ]]; then
            printf '\r\033[K  %b[%3d%%]%b %-44s %b%s%b\n' \
                "$COLOR_LINE" "$PIPELINE_PERCENT" "$COLOR_RESET" "$PIPELINE_LABEL" \
                "$COLOR_SUCCESS" "done" "$COLOR_RESET"
        fi
        printf '\r\033[K  %b[100%%]%b %-44s %b%s%b\n' \
            "$COLOR_LINE" "$COLOR_RESET" "$final_message" \
            "$COLOR_SUCCESS" "done" "$COLOR_RESET"
    else
        if [[ -n "$PIPELINE_LABEL" && "$PIPELINE_LABEL" != 'Preparing...' ]]; then
            printf '  [%3d%%] %-44s %b%s%b\n' \
                "$PIPELINE_PERCENT" "$PIPELINE_LABEL" "$COLOR_SUCCESS" "done" "$COLOR_RESET"
        fi
        printf '  [100%%] %-44s %b%s%b\n' \
            "$final_message" "$COLOR_SUCCESS" "done" "$COLOR_RESET"
    fi
    sleep 1.5
    pipeline_restore_terminal
    PIPELINE_ACTIVE=0
    PIPELINE_TITLE=''
    PIPELINE_OPERATION=''
    PIPELINE_LABEL=''
    PIPELINE_FRAME=0
    ((pause)) && wait_action_return
}

pipeline_abort() {
    ((DEBUG_MODE || !PIPELINE_ACTIVE)) && return 0
    if [[ -t 1 ]]; then
        printf '\r\033[K  %b[%3d%%]%b %-44s failed\n' \
            "$COLOR_LINE" "$PIPELINE_PERCENT" "$COLOR_RESET" "$PIPELINE_LABEL"
    else
        printf '  [%3d%%] %-44s failed\n' "$PIPELINE_PERCENT" "$PIPELINE_LABEL"
    fi
    pipeline_restore_terminal
    PIPELINE_ACTIVE=0
    PIPELINE_TITLE=''
    PIPELINE_OPERATION=''
    PIPELINE_LABEL=''
    PIPELINE_FRAME=0
}

pipeline_stage_for_playbook() {
    local argument playbook=''
    for argument in "$@"; do
        case "$argument" in
            *.yml) playbook="${argument##*/}" ;;
        esac
    done
    case "$playbook" in
        bootstrap.yml) pipeline_stage 30 'Preparing VPS access' ;;
        harden_ssh.yml) pipeline_stage 40 'Hardening SSH access' ;;
        site.yml)
            case "$PIPELINE_OPERATION" in
                access_keys|dns|countries) pipeline_stage 10 'Checking SSH access' ;;
                *) pipeline_stage 60 'Installing Docker and system packages' ;;
            esac
            ;;
        restart.yml) pipeline_stage 20 'Checking SSH access' ;;
        rotate-ssh.yml)
            [[ "$PIPELINE_OPERATION" == rotate ]] || pipeline_stage 70 'Rotating the SSH key'
            ;;
        remove.yml) pipeline_stage 20 'Checking installed VPN components' ;;
    esac
}
