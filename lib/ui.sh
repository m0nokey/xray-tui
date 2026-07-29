#!/usr/bin/env bash

menu_heading() {
    printf '%s%s%s\n' "$COLOR_LINE" "$1" "$COLOR_RESET"
}

menu_option() {
    if [[ "$1" =~ ^[0-9]+$ ]] && [[ " $MENU_NUMERIC_OPTIONS " != *" $1 "* ]]; then
        MENU_NUMERIC_OPTIONS="${MENU_NUMERIC_OPTIONS:+$MENU_NUMERIC_OPTIONS }$1"
    fi
    printf '%s%s.%s %s%s%s\n' "$COLOR_LINE" "$1" "$COLOR_RESET" "$COLOR_TEXT" "$2" "$COLOR_RESET"
}

menu_control() {
    printf '%s%s.%s %s%s%s\n' "$COLOR_LINE" "$1" "$COLOR_RESET" "$COLOR_TEXT" "$2" "$COLOR_RESET"
}

clear_screen() {
    MENU_NUMERIC_OPTIONS=''
    CURRENT_INPUT_HINT=''
    printf '\033[H\033[2J\033[3J' >&2
}

read_required_choice() {
    local variable="$1" prompt="$2" allowed="${3:-}" value=''
    if [[ -n "$allowed" ]]; then
        CURRENT_INPUT_HINT="Enter ${allowed}."
    fi
    if ! read -r -e -p "$prompt" value; then
        return 1
    fi
    if [[ -z "$value" ]]; then
        invalid_choice
        clear_screen
        return 2
    fi
    printf -v "$variable" '%s' "$value"
}

prompt_nav() {
    local option options_text='' numeric_options="${1:-$MENU_NUMERIC_OPTIONS}"
    echo
    menu_control b back
    menu_control m main
    menu_control i info
    menu_control x exit
    echo
    if [[ -n "$numeric_options" ]]; then
        for option in $numeric_options; do
            if [[ -z "$options_text" ]]; then
                options_text="$option"
            else
                options_text="${options_text}, ${option}"
            fi
        done
        CURRENT_INPUT_HINT="Enter ${options_text}, b, m, i, or x."
    else
        CURRENT_INPUT_HINT='Enter b, m, i, or x.'
    fi
    read_required_choice REPLY '?: '
}

wait_action_return() {
    local key
    [[ -t 0 ]] || return 0
    while true; do
        printf '\n\033[90mPress Enter or Space to return to the menu.\033[0m'
        IFS= read -r -s -n 1 key || return 0
        case "$key" in
            ""|" ")
                echo
                return 0
                ;;
            x|X)
                exit_tui
                ;;
        esac
    done
}

show_result_screen() {
    if ((DEBUG_MODE)); then
        printf '\n%s\n' "$@"
        printf '%s\n' "Press Enter to continue."
        read -r _ || true
        return 0
    fi
    clear_screen
    printf '%s\n' "$@"
    echo
    printf '%s\n' "Press Enter to continue."
    read -r _ || true
}

pause_result_screen() {
    echo
    printf '%s\n' "Press Enter to continue."
    read -r _ || true
}

exit_tui() {
    clear_screen
    exit 0
}

invalid_choice() {
    local message
    if [[ -n "$CURRENT_INPUT_HINT" ]]; then
        message="Invalid input. $CURRENT_INPUT_HINT"
    else
        message='Invalid input. Enter a valid menu option.'
    fi
    if [[ -t 1 ]]; then
        printf '\033[1A\r\033[2K?:    %s\n' "$message"
    else
        printf '%s\n' "?:    $message"
    fi
    sleep 2
}
