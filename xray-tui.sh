#!/bin/bash
set -euo pipefail

workdir="$(mktemp -d -t xray.XXXXXX 2>/dev/null || mktemp -d -t xray)"
build_id="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || date +%s%N)"
builder="xray.${build_id}"

cleanup() {
    docker ps -aq --filter "ancestor=xray-admin:${build_id}" | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker images -q "xray-admin:${build_id}" | xargs -r docker rmi -f >/dev/null 2>&1 || true
    docker buildx rm -f "$builder" >/dev/null 2>&1 || true
    docker ps -aq -f "name=buildx_buildkit_" | xargs -r docker rm -f >/dev/null 2>&1 || true
    for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 'moby/buildkit'); do
        if [ -z "$(docker ps -aq --filter ancestor="$img" 2>/dev/null)" ]; then
            docker image rm -f "$img" >/dev/null 2>&1 || true
        fi
    done
    rm -rf "$workdir"
    clear; printf '\e[3J'
}
trap cleanup EXIT INT TERM

cat <<'EOF' > "${workdir}/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG APP_UID=10000
ARG APP_GID=10000
RUN groupadd -g $APP_GID app \
 && useradd -u $APP_UID -g $APP_GID -M -s /usr/sbin/nologin app 

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates jq openssh-client sshpass python3 python3-nacl openssl \
 && rm -rf /var/lib/apt/lists/*

RUN passwd -l root \
 && usermod -s /usr/sbin/nologin root

RUN cat <<'EOW' > /usr/local/bin/xray.sh
#!/bin/bash
set -Eeuo pipefail

# ─────────────────────────────── helpers ───────────────────────────────

indent() {
    local arg="${1:-}"
    local mode
    local num
    if [[ "$arg" =~ ^([+-])([0-9]+)$ ]]; then
        mode="${BASH_REMATCH[1]}"
        num="${BASH_REMATCH[2]}"
    else
        mode="$arg"
        num="${2:-0}"
    fi
    case "$mode" in
        +) sed "s/^/$(printf '%*s' "$num")/";;
        -) sed -E "s/^ {0,$num}//";;
        0) awk '{ $1=$1; print }';;
        *) return 1;;
    esac
}

cls() { clear; printf '\e[3J'; }
hr() { printf '%s\n' "____________________"; }
header() { cls; echo "$1"; hr; }

ui_lock() {
    local msg="${*:-working...}"
    _ui_depth=${_ui_depth:-0}
    if (( _ui_depth == 0 )); then
        _ui_lock_active=1
        _ui_msg_stack=()
        _ui_msg="$msg"

        stty -echo -icanon -isig 2>/dev/null || true
        printf '\e[?25l' 2>/dev/null || true

        { 
          while [[ "${_ui_lock_active:-}" = "1" ]]; do
              read -r -t "${UI_DRAIN_INTERVAL:-0.05}" -n 10000 _junk || true
          done
        } &
        _ui_drain_pid=$!

        { 
          # quiet spinner
          set +x
          i=0; frames='|/-\'
          while [[ "${_ui_lock_active:-}" = "1" ]]; do
              printf "\r%s %s" "$_ui_msg" "${frames:i++%4:1}"
              sleep 0.1
          done
          printf "\r\033[K"
        } &
        _ui_spin_pid=$!
    else
        _ui_msg_stack+=("$_ui_msg")
        _ui_msg="$msg"
    fi

    _ui_depth=$((_ui_depth + 1))
}

ui_set() {
    local msg="${*:-working...}"
    [[ "${_ui_depth:-0}" -gt 0 ]] && _ui_msg="$msg"
}

ui_unlock() {
    _ui_depth=${_ui_depth:-0}
    (( _ui_depth > 0 )) || return 0

    _ui_depth=$((_ui_depth - 1))
    if (( _ui_depth > 0 )); then
        local n=${#_ui_msg_stack[@]}
        if (( n > 0 )); then
            _ui_msg="${_ui_msg_stack[$((n-1))]}"
            unset "_ui_msg_stack[$((n-1))]"
        fi
        return 0
    fi

    _ui_lock_active=0
    kill "${_ui_drain_pid:-}" "${_ui_spin_pid:-}" 2>/dev/null || true
    wait "${_ui_drain_pid:-}" 2>/dev/null || true
    wait "${_ui_spin_pid:-}" 2>/dev/null || true
    printf "\r\033[K"

    stty sane 2>/dev/null || true
    printf '\e[?25h' 2>/dev/null || true
    read -r -t 0.01 -n 10000 _junk 2>/dev/null || true
    unset _ui_drain_pid _ui_spin_pid _ui_msg _ui_msg_stack _ui_lock_active
}
trap 'ui_unlock >/dev/null 2>&1 || true' EXIT

drain() { read -r -t 0 -n 10000 _junk 2>/dev/null || true; }

first_token_lower() {
    local s="$1"
    # trim leading spaces
    s="${s#"${s%%[!$' \t\r\n']*}"}"
    # take first token
    s="${s%%[ $'\t\r\n']*}"
    # to lower (bash 4+)
    printf '%s' "${s,,}"
}

nav_print() {
    drain
    printf 'b.   back\n'
    printf 'x.   exit\n'
    printf '?:   '
}

nav_invalid_inline() {
    printf '\033[1A\r\033[K?:   no valid entry!'
    sleep 0.5
    printf '\r\033[K?:   '
}

nav_wait_bx_redraw() {
    local render_fn="$1"; shift
    while :; do
        IFS= read -r _nav_ans
        local key; key="$(first_token_lower "$_nav_ans")"
        case "$key" in
            b) return 0 ;;
            x) echo "Bye."; exit 0 ;;
            *) nav_invalid_inline
               "$render_fn" "$@"
               nav_print
               ;;
        esac
    done
}

actions_block() {
    printf "b.   back\n"
    printf "x.   exit\n"
    printf "?:   "
}

# ─────────────────────────────── config ───────────────────────────────

remote_dir="/opt/xray"
remote_cfg="${remote_dir}/config.json"
remote_dc="${remote_dir}/docker-compose.yaml"
vless_sni_default="api.github.com"
vless_spider_x_default="/"
vless_port_default="443"
ssh_opts='-o LogLevel=error -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o UserKnownHostsFile=/tmp/known_hosts -o StrictHostKeyChecking=accept-new'
base_mark="/tmp/.base_install_done"

# ───────────────────────────── ssh helpers ─────────────────────────────

test_login() {
  local host="$1" port="$2" password="$3"
  ( set +x
    printf '%s' "$password" | /usr/bin/sshpass -d 0 \
      ssh -p "$port" $ssh_opts "root@${host}" exit
  ) >/dev/null 2>&1
}

ssh_run() {
  local cmd="$1"
  ( set +x
    printf '%s' "$password" | /usr/bin/sshpass -d 0 \
      ssh -p "$port" $ssh_opts "root@${host}" "$cmd"
  ) </dev/null 2>/dev/null || return $?
}

ssh_pipe() {
  local cmd="$1"
  ( set +x
    exec 9<<<"$password"
    cat | /usr/bin/sshpass -d 9 \
      ssh -p "$port" $ssh_opts "root@${host}" "$cmd"
    exec 9<&-
  ) 2>/dev/null
}
ssh_cat() { ssh_run "cat '$1'"; }
jq_docker() { jq "$@"; }

# ───────────────────────── key & id utilities ─────────────────────────

uuid() { cat /proc/sys/kernel/random/uuid; }

short_id_from_uuid() {
    local u="$1"
    u="${u//-/}"
    printf '%s' "$u" | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n' | cut -c1-16
}

xray_keys() {
    local out
    out="$(
        cat <<'EOL' | indent -4 | python3 -
    import base64
    from nacl.public import PrivateKey

    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    sk = PrivateKey.generate()
    pk = sk.public_key
    print(b64url(sk.encode()))
    print(b64url(pk.encode()))
EOL
    )"
    priv_key="$(printf '%s\n' "$out" | sed -n '1p')"
    pub_key="$(printf '%s\n' "$out" | sed -n '2p')"
}

derive_pbk() {
    local priv="$1"
    [[ -z "$priv" ]] && { echo ""; return; }
    cat <<'EOL' | indent -4 | python3 - "$priv"
    import sys, base64
    from nacl.public import PrivateKey

    p = sys.argv[1].strip()
    pad = '=' * ((4 - len(p) % 4) % 4)
    raw = base64.urlsafe_b64decode(p + pad)
    sk  = PrivateKey(raw)
    pk  = sk.public_key.encode()
    print(base64.urlsafe_b64encode(pk).decode().rstrip('='))
EOL
}

# Update shortIds to match clients deterministically (stdin json → stdout json)
sync_shortids_with_clients() {
    local json; json="$(cat)"
    mapfile -t _uuids < <(printf '%s' "$json" \
        | jq -r '(.inbounds[]?|select(.protocol=="vless")|.settings.clients // [])[].id')
    local _sids=() u
    for u in "${_uuids[@]}"; do _sids+=( "$(short_id_from_uuid "$u")" ); done
    local sids_json
    sids_json="$(printf '%s\n' "${_sids[@]}" | jq -R . | jq -s '
        reduce .[] as $x ([]; if index($x) then . else . + [$x] end)
    ')"
    printf '%s' "$json" | jq --argjson sids "$sids_json" '
        .inbounds |= (
            map(if .protocol=="vless"
                then (.streamSettings.realitySettings.shortIds = $sids)
                else . end)
        )'
}

# ────────────────────────────── base vps ──────────────────────────────

base_install_prepare_local() {
    install_file="$(mktemp)"
    cat <<-'EOS' | indent -4 > $install_file
    #!/bin/bash 

    indent() {
        local arg="${1:-}"
        local mode
        local num
        if [[ "$arg" =~ ^([+-])([0-9]+)$ ]]; then
            mode="${BASH_REMATCH[1]}"
            num="${BASH_REMATCH[2]}"
        else
            mode="$arg"
            num="${2:-0}"
        fi
        case "$mode" in
            +) sed "s/^/$(printf '%*s' "$num")/";;
            -) sed -E "s/^ {0,$num}//";;
            0) awk '{ $1=$1; print }';;
            *) return 1;;
        esac
    }
    codename() {
        local codename=""
        declare -A codename_count
        tmp_names=()
        add_to_temp() { [ -n "$1" ] && tmp_names+=("$1"); }
        [ -f /etc/os-release ] && add_to_temp "$(grep -oP '(?<=VERSION_CODENAME=)\w+' /etc/os-release 2>/dev/null)"
        [ -f /boot/grub/grub.cfg ] && add_to_temp "$(grep -oP '(?<=menuentry '\''Debian GNU/Linux )[^ ]+' /boot/grub/grub.cfg | head -n 1 2>/dev/null)"
        [ -f /etc/apt/sources.list ] && add_to_temp "$(grep -m1 -Po '(?<=/debian/)\w+' /etc/apt/sources.list 2>/dev/null)"
        [ -f /etc/default/grub ] && add_to_temp "$(grep -oP '(?<=GRUB_DISTRIBUTOR=")[^"]+' /etc/default/grub 2>/dev/null)"
        add_to_temp "$(grep -oP 'debian[^ ]+' /proc/cmdline 2>/dev/null)"
        [ -f /boot/config-$(uname -r) ] && add_to_temp "$(grep -oP 'debian[^-]*' /boot/config-$(uname -r) 2>/dev/null)"
        [ -f /etc/motd ] && add_to_temp "$(grep -oP '(Debian GNU/Linux \K[^ ]+)' /etc/motd 2>/dev/null)"
        ls /var/lib/apt/lists/*_InRelease >/dev/null 2>&1 && add_to_temp "$(grep -oP '(?<=dists/)[^/ ]+' /var/lib/apt/lists/*_InRelease | head -n 1 2>/dev/null)"
        for name in "${tmp_names[@]}"; do [ -n "$name" ] && codename_count["$name"]=$((codename_count["$name"]+1)); done
        for name in "${!codename_count[@]}"; do [ -z "$codename" ] || [ "${codename_count[$name]}" -gt "${codename_count[$codename]}" ] && codename=$name; done
        [ -z "$codename" ] && { echo "Failed to detect Debian codename";return 1; }
        echo "$codename"
    }
    configure_repo() {
        local codename="$(codename)"
        rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
        cat <<-EOL | indent -4 > /etc/apt/sources.list.d/debian.sources
        Types: deb deb-src
        URIs: https://deb.debian.org/debian
        Suites: ${codename} ${codename}-updates
        Components: main
        Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
        
        Types: deb deb-src
        URIs: https://security.debian.org/debian-security
        Suites: ${codename}-security
        Components: main
        Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
    EOL
    }
    install_packages() {
        export DEBIAN_FRONTEND=noninteractive
        rm -rf /var/lib/apt/lists/*
        apt-get update >/dev/null 2>&1 && apt-get -o Dpkg::Options::="--force-confold" upgrade -y --allow-downgrades --allow-remove-essential --allow-change-held-packages >/dev/null 2>&1
        local packages=("lsb-release" "apt-transport-https" "ca-certificates" "gnupg2" "curl")
        for pkg in "${packages[@]}"; do apt-get install --no-install-recommends -y $pkg >/dev/null 2>&1; done
    }
    install_docker() {
        install -d -m0755 /etc/apt/keyrings
        local arch="$(dpkg --print-architecture)"
        local codename="$(lsb_release -cs 2>/dev/null)"
        curl -fsSL --proto '=https' --tlsv1.3 https://download.docker.com/linux/debian/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
        printf "Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.gpg\n" "$codename" "$arch" > /etc/apt/sources.list.d/docker.sources
        printf "Package: *\nPin: origin download.docker.com\nPin-Priority: 900\n" > /etc/apt/preferences.d/docker
        apt-get update 2>/dev/null
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null
    }
    install_docker_compose() {
        local ver=$(curl -sf --tlsv1.3 --proto '=https' https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        curl -sfLS --tlsv1.3 --proto '=https' -o /usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/${ver}/docker-compose-$(uname -s)-$(uname -m)"
        chmod +x /usr/local/bin/docker-compose
    }
    install_xray() {
        mkdir -p /opt/xray/
        /usr/bin/docker pull ghcr.io/xtls/xray-core:latest
    }
    configure_timezone() {
        timedatectl set-timezone UTC
    }
    configure_path() {
        echo -e "export LC_CTYPE=en_US.UTF-8\nexport LC_ALL=en_US.UTF-8\nexport PATH=$PATH:/usr/sbin" >> /root/.bashrc
        PATH=/usr/local/bin:/usr/bin:/bin
    }
    configure_locales() {
        echo -e "LANGUAGE=en_US.UTF-8\nLANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8" > /etc/default/locale
        grep -q "^en_US\.UTF-8 UTF-8" /etc/locale.gen || { grep -q "^# *en_US\.UTF-8 UTF-8" /etc/locale.gen && sed -i 's/^# *\(en_US\.UTF-8 UTF-8\)/\1/' /etc/locale.gen || echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen; }
        locale-gen >/dev/null 2>&1
        update-locale LANG=en_US.UTF-8 LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8 >/dev/null 2>&1
        source /root/.bashrc >/dev/null 2>&1
        source /etc/default/locale >/dev/null 2>&1  
    }
    setup_security_update() {
        apt-get update >/dev/null 2>&1; apt-get install --no-install-recommends -y unattended-upgrades apt-listchanges >/dev/null 2>&1
        cat <<-'EOL' | indent -4 > /etc/apt/apt.conf.d/50unattended-upgrades
        Unattended-Upgrade::Origins-Pattern {
            "origin=Debian,codename=${distro_codename},label=Debian-Security";
            "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        };
        Unattended-Upgrade::Remove-Unused-Dependencies "false";
        Dpkg::Options {
            "--force-confdef";
            "--force-confold";
        };
    EOL
        cat <<-'EOL' | indent 0 > /etc/apt/apt.conf.d/20auto-upgrades
        APT::Periodic::Update-Package-Lists "1";
        APT::Periodic::Download-Upgradeable-Packages "1";
        APT::Periodic::AutocleanInterval "7";
        APT::Periodic::Unattended-Upgrade "1";
    EOL
    }
    configure_os_updater() {
        cat <<-'EOL' | indent -4 > /usr/local/sbin/os-updater
        #!/bin/bash
        set -Eeuo pipefail
    
        export DEBIAN_FRONTEND=noninteractive
        export APT_LISTCHANGES_FRONTEND=none
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
        LOG=/var/log/apt-auto-upgrade.log
        exec > >(tee -a "$LOG") 2>&1
    
        exec 9>/run/apt-maint.lock
        if ! flock -n 9; then
            echo "[INFO] another apt run in progress, exiting"
            exit 0
        fi
    
        trap 'echo "[ERROR] failed at line $LINENO (exit=$?)"' ERR
    
        retry() {
            local attempts="$1" 
            local pause="$2" 
            shift 2
            local n=1
            until "$@"; do
                if (( n >= attempts )); then
                    echo "[ERROR] after ${attempts} attempts: $*"
                    return 1
                fi
                echo "[WARN] attempt $n failed; retrying in ${pause}s: $*"
                sleep "$pause"
                ((n++))
            done
        }
    
        echo "[INFO] === $(date -Is) start ==="
    
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    
        install -m0755 -d /etc/apt/keyrings || true
        curl -fsSL --tlsv1.3 --http2 --proto '=https' "https://download.docker.com/linux/debian/gpg" | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg || true
    
        retry 5 10 apt-get -qq -o Acquire::Retries=3 update
        retry 3 20 apt-get -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o DPkg::Lock::Timeout=600 -y dist-upgrade
    
        apt-get -y autoremove --purge || true
        apt-get clean || true
    
        need_reboot=false
        reason=""
    
        current_kernel="$(uname -r || true)"
        latest_installed_kernel="$(ls -1 /lib/modules 2>/dev/null | sort -V | tail -1 || true)"
        if [ -n "$latest_installed_kernel" ] && [ "$current_kernel" != "$latest_installed_kernel" ]; then
            need_reboot=true
            reason="kernel $current_kernel -> $latest_installed_kernel"
        fi
    
        if [ -f /run/reboot-required ] || [ -f /var/run/reboot-required ]; then
            need_reboot=true
            if [ -z "$reason" ]; then
                reason="reboot-required flag"
            else
                reason="$reason + reboot-required flag"
            fi
        fi
    
        if $need_reboot; then
            echo "[INFO] rebooting: $reason"
            if command -v systemctl >/dev/null 2>&1; then
                systemctl reboot || /sbin/reboot
            else
                /sbin/reboot
            fi
        else
            echo "[INFO] reboot not required"
        fi
    
        echo "[INFO] === $(date -Is) end ==="
    EOL
    
        chmod 0755 /usr/local/sbin/os-updater
        chown root:root /usr/local/sbin/os-updater
    
        cat <<-'EOL' | indent -4 > /etc/systemd/system/os-updater.service
        [Unit]
        Description=Safe unattended apt dist-upgrade (kernel-aware)
        Documentation=man:apt-get(8)
        After=network-online.target
        Wants=network-online.target
    
        [Service]
        Type=oneshot
        ExecStart=/bin/bash /usr/local/sbin/os-updater
        Nice=10
        TimeoutStartSec=2h
        Environment=DEBIAN_FRONTEND=noninteractive
        Environment=APT_LISTCHANGES_FRONTEND=none
    
        [Install]
        WantedBy=multi-user.target
    EOL
    
        cat <<-'EOL' | indent -4 > /etc/systemd/system/os-updater.timer
        [Unit]
        Description=Run os_updater nightly
    
        [Timer]
        OnCalendar=*-*-* 01:00
        RandomizedDelaySec=13m
        Persistent=true
        AccuracySec=1h
    
        [Install]
        WantedBy=timers.target
    EOL
    
        cat <<-'EOL' | indent -4 > /etc/logrotate.d/os_updater
        /var/log/apt-auto-upgrade.log {
          daily
          rotate 8
          size 512k
          compress
          delaycompress
          dateext
          missingok
          notifempty
          create 0640 root adm
          su root adm
        }
    EOL
    
        systemctl daemon-reload
        systemctl enable --now os-updater.timer
    }
    configure_docker_compose_updater() {
        cat <<-'EOL' | indent -4 > /usr/local/sbin/docker-compose-updater
        #!/bin/bash
        set -Eeuo pipefail
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    
        compose_file="/opt/xray/docker-compose.yaml"
        attempt=0
        max_attempts=3
        tmp_folder="$(mktemp -d)"
        binary_name="docker-compose-linux-$(uname -m)"
        tmp_compose="$tmp_folder/$binary_name"
        current_version=$(/usr/local/bin/docker-compose -v | grep -o 'v[0-9]*\.[0-9]*\.[0-9]*' || true)
    
        trap "rm -rf \"$tmp_folder\"" EXIT
    
        latest_version=""
        until [[ "$latest_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $((++attempt)) -ge $max_attempts ]]; do
            latest_version=$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://api.github.com/repos/docker/compose/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            [[ "$latest_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || sleep 5
        done
    
        [[ "$latest_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 0
        [[ "$current_version" == "$latest_version" ]] && exit 0
    
        download_url="https://github.com/docker/compose/releases/download/${latest_version}"
    
        attempt=0
        until curl --tlsv1.3 --http2 --proto '=https' -sfLC - -o "$tmp_compose" "${download_url}/${binary_name}"; do
            [[ $((attempt++)) -ge $max_attempts ]] && exit 1
            sleep 5
        done
    
        attempt=0
        until curl --tlsv1.3 --http2 --proto '=https' -sfLC - -o "$tmp_folder/checksum" "${download_url}/${binary_name}.sha256"; do
            [[ $((attempt++)) -ge $max_attempts ]] && exit 1
            sleep 5
        done
    
        (cd "${tmp_folder}" && echo "$(cat checksum)" | sha256sum -c --status) || { echo "Checksum verification failed"; exit 1; }
        chmod +x "$tmp_compose"
    
        /usr/local/bin/docker-compose -f "$compose_file" down || true
        mv "$tmp_compose" "/usr/local/bin/docker-compose"
        /usr/local/bin/docker-compose -f "$compose_file" up -d
    EOL
    
        chmod 0755 /usr/local/sbin/docker-compose-updater
        chown root:root /usr/local/sbin/docker-compose-updater
    
        cat <<-'EOL' | indent -4 > /etc/systemd/system/docker-compose-updater.service
        [Unit]
        Description=Update docker-compose binary and restart stack
        After=network-online.target docker.service
        Wants=network-online.target docker.service
        ConditionPathExists=/opt/xray/docker-compose.yaml
    
        [Service]
        Type=oneshot
        ExecStart=/bin/bash /usr/local/sbin/docker-compose-updater
        Nice=10
        TimeoutStartSec=30m
    
        [Install]
        WantedBy=multi-user.target
    EOL
    
        cat <<-'EOL' | indent -4 > /etc/systemd/system/docker-compose-updater.timer
        [Unit]
        Description=Run docker-compose updater nightly at 01:45
    
        [Timer]
        OnCalendar=*-*-* 01:45
        Persistent=true
        AccuracySec=1min
    
        [Install]
        WantedBy=timers.target
    EOL
    
        systemctl daemon-reload
        systemctl enable --now docker-compose-updater.timer
    }
    configure_docker_updater() {
        cat <<-'EOL' | indent -4 > /usr/local/sbin/docker-updater
        #!/bin/bash
        set -Eeuo pipefail
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
        compose_file="/opt/xray/docker-compose.yaml"

        exec 9>/run/docker-updater.lock
        if ! flock -n 9; then
            echo "[INFO] another docker_updater run is in progress, exiting"
            exit 0
        fi
    
        docker pull ghcr.io/xtls/xray-core:latest
        #docker-compose -f "$compose_file" build --no-cache
        docker-compose -f "$compose_file" down
        docker-compose -f "$compose_file" up -d --force-recreate
    
        docker image prune -f || true
        docker builder prune -f || true
    EOL
    
        chmod 0755 /usr/local/sbin/docker-updater
        chown root:root /usr/local/sbin/docker-updater
    
        cat <<-'EOL' | indent -4 > /etc/systemd/system/docker-updater.service
        [Unit]
        Description=Update xray-core image and restart docker stack
        After=network-online.target docker.service
        Wants=network-online.target docker.service
        ConditionPathExists=/opt/xray/docker-compose.yaml
    
        [Service]
        Type=oneshot
        ExecStart=/bin/bash /usr/local/sbin/docker-updater
        TimeoutStartSec=30m
        Nice=10
    
        [Install]
        WantedBy=multi-user.target
    EOL
    
        cat <<-'EOL' | indent -4 > /etc/systemd/system/docker-updater.timer
        [Unit]
        Description=Run docker_updater nightly at 01:30
    
        [Timer]
        OnCalendar=*-*-* 02:00
        Persistent=true
        AccuracySec=1min
    
        [Install]
        WantedBy=timers.target
    EOL
    
        systemctl daemon-reload
        systemctl enable --now docker-updater.timer
    }
    
    configure_repo
    install_packages
    install_docker
    install_docker_compose
    install_xray
    configure_timezone
    configure_path
    configure_locales
    setup_security_update
    configure_os_updater
    configure_docker_updater
    configure_docker_compose_updater
    touch /tmp/.base_install_done
EOS
}

base_install_push_and_start() {
    cat "${install_file}" | ssh_pipe \
      'cat > /tmp/install.sh; sleep 3; nohup bash /tmp/install.sh >/dev/null 2>&1 & echo $! > /tmp/install.pid; sleep 3; ps -p $(cat /tmp/install.pid) >/dev/null'
}

wait_for_base_install() {
    local deadline=$((SECONDS + 1800))
    while (( SECONDS < deadline )); do
        if ssh_run "test -f '${base_mark}'"; then
            return 0
        fi
        if ssh_run "command -v docker >/dev/null 2>&1 && (docker compose version >/dev/null 2>&1 || docker-compose -v >/dev/null 2>&1)"; then
            return 0
        fi
        sleep 20
    done
    return 1
}

ensure_bootstrap_remote() {
    local need_bootstrap=1
    ssh_run '
        ok=0
        # 1) Docker + compose
        if command -v docker >/dev/null 2>&1 && ( docker compose version >/dev/null 2>&1 || docker-compose -v >/dev/null 2>&1 ); then
            if [ -d "/opt/xray" ]; then
                if systemctl list-unit-files --no-legend | awk "{print \$1}" | grep -qx os-updater.timer \
                   && systemctl list-unit-files --no-legend | awk "{print \$1}" | grep -qx docker-updater.timer \
                   && systemctl list-unit-files --no-legend | awk "{print \$1}" | grep -qx docker-compose-updater.timer; then
                    ok=1
                fi
            fi
        fi
        exit $(( ok ? 0 : 1 ))
    ' && need_bootstrap=0 || need_bootstrap=1

    if (( need_bootstrap )); then
        base_install_prepare_local
        ui_lock "/ installing..."
        base_install_push_and_start || true
        wait_for_base_install || true
        ui_unlock
    fi
}

# ─────────────────────────── remote file writers ───────────────────────────

write_remote_dc_with_port() {
    local p="$1"
    ssh_run "mkdir -p '${remote_dir}'"
    cat <<'EOL' | indent -4 | ssh_pipe "cat > '${remote_dc}'"
    services:
      xray:
        image: ghcr.io/xtls/xray-core:latest
        container_name: xray
        sysctls:
          net.ipv4.ip_unprivileged_port_start: __PORT__
        cap_drop: [ "ALL" ]
        security_opt:
          - no-new-privileges:true
        read_only: true
        tmpfs:
          - /tmp:rw,nosuid,nodev,noexec,mode=1777
        pids_limit: 512
        mem_limit: 512m
        ulimits:
          nofile: 262144
        volumes:
          - ./config.json:/etc/xray/config.json:ro
        command: ["run", "-c", "/etc/xray/config.json"]
        restart: unless-stopped
        ports:
          - "__PORT__:__PORT__/tcp"
        logging:
          driver: none
EOL
    ssh_run "sed -i 's/__PORT__/${p}/g' '${remote_dc}'"
}

get_remote_json_or_empty() {
    if ssh_run "test -f '${remote_cfg}'"; then
        ssh_cat "${remote_cfg}"
    else
        echo '{}'
    fi
}

send_config_and_restart() {
    set +e
    local remote_cmd="cat > '${remote_cfg}' && (docker compose -f '${remote_dc}' up -d && docker compose -f '${remote_dc}' restart xray || docker-compose -f '${remote_dc}' restart) >/dev/null 2>&1 || true"
    cat config.json | ssh_pipe "${remote_cmd}" || true
    set -e
}

# ─────────────────────────────── cache (in-mem) ───────────────────────────────
_json_cache=''
_json_cache_valid=0

cache_set_json() {
    _json_cache="$1"
    _json_cache_valid=1
}

cache_invalidate() {
    _json_cache=''
    _json_cache_valid=0
}

get_remote_json_cached() {
    if (( _json_cache_valid )); then
        printf '%s' "$_json_cache"
    else
        local j; j="$(get_remote_json_or_empty)"
        _json_cache="$j"
        _json_cache_valid=1
        printf '%s' "$j"
    fi
}

server_exists() { ssh_run "test -f '${remote_cfg}'"; }
server_exists_cached() {
    if (( _json_cache_valid )); then
        [[ "$_json_cache" != '{}' ]]
        return
    fi
    server_exists
}

# ─────────────────────────────── ui screens ───────────────────────────────

# Build VLESS links; SID is derived per-client via short_id_from_uuid(UUID).
build_links_array() {
    local json="$1"
    local vless_sni vless_port priv_key pbk
    vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0] // empty' | head -n1)"
    vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port // empty' | head -n1)"
    priv_key="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.privateKey // empty' | head -n1)"
    [[ -z "$vless_sni" || -z "$vless_port" || -z "$priv_key" ]] && { echo "(none)"; return; }
    pbk="$(derive_pbk "$priv_key")"
    [[ -z "$pbk" && -n "${pub_key-}" ]] && pbk="$pub_key"
    mapfile -t ids < <(printf '%s' "$json" \
        | jq -r '(.inbounds[]?|select(.protocol=="vless")|.settings.clients // [])[] | .id')
    ((${#ids[@]}==0)) && { echo "(none)"; return; }
    local u sid
    for u in "${ids[@]}"; do
        sid="$(short_id_from_uuid "$u")"
        echo "vless://${u}@${host}:${vless_port}?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&sni=${vless_sni}&fp=chrome&pbk=${pbk}&sid=${sid}#vless-vision-reality"
    done
}

# ── server info ──
render_server_info_screen() {
    header "xray › server › info"
    ui_lock "loading..."
    local json; json="$(get_remote_json_cached)"
    ui_unlock
    if [[ "$json" == '{}' ]]; then
        echo "none"
        echo
        return 0
    fi
    local vless_sni vless_port
    vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0] // empty' | head -n1)"
    vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port // empty' | head -n1)"
    printf '%-12s %s\n' "Protocol:"    "xtls-rprx-vision"
    printf '%-12s %s\n' "Server Name:" "${vless_sni}:${vless_port}"
    echo
}
print_server_info_screen() {
    render_server_info_screen
    nav_print
    nav_wait_bx_redraw render_server_info_screen
}

# ── server create ──
server_create_interactive() {
    header "xray › server › create"

    local exists=1; if server_exists_cached; then exists=0; fi
    if (( exists == 0 )); then
        ui_lock "loading..."
        local json; json="$(get_remote_json_cached)"
        ui_unlock

        local vless_sni vless_port
        vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0] // empty' | head -n1)"
        vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port // empty' | head -n1)"

        printf '%-12s %s\n' "Protocol:"    "xtls-rprx-vision"
        printf '%-12s %s\n' "Server Name:" "${vless_sni}:${vless_port}"
        echo
        echo "You already have an Xray Server created."
        echo
        nav_print
        nav_wait_bx_redraw server_create_interactive
        return 0
    fi

    printf "Enter SNI (default %s): " "$vless_sni_default"; read -r sni; [[ -z "${sni:-}" ]] && sni="$vless_sni_default"
    printf "Enter spider path (default %s): " "$vless_spider_x_default"; read -r spx; [[ -z "${spx:-}" ]] && spx="$vless_spider_x_default"
    printf "Enter listen port (default %s): " "$vless_port_default"; read -r port_in; [[ -z "${port_in:-}" ]] && port_in="$vless_port_default"

    ui_lock "creating server..."
    ensure_bootstrap_remote
    ui_set "creating server..."

    xray_keys
    local sid; sid="$(short_id_from_uuid "$(uuid)")"
    local json
    json="$(cat <<'EOL'
    {
        "log": { "loglevel": "none" },
        "inbounds": [
            {
                "port": __PORT__,
                "protocol": "vless",
                "settings": { "clients": [], "decryption": "none" },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "__SNI__:443",
                        "serverNames": ["__SNI__"],
                        "privateKey": "__PRIV__",
                        "shortIds": ["__SID__"]
                    }
                },
                "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"], "routeOnly": true }
            }
        ],
        "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
    }
EOL
)"
    json="${json/__PORT__/$port_in}"
    json="${json//__SNI__/$sni}"
    json="${json/__PRIV__/$priv_key}"
    json="${json/__SID__/$sid}"

    write_remote_dc_with_port "$port_in"
    printf '%s' "$json" > config.json
    cache_set_json "$json"

    ui_set "applying..."
    send_config_and_restart
    ui_unlock

    render_server_create_result() {
        header "xray › server › create"
        printf '%-12s %s\n' "Protocol:"    "xtls-rprx-vision"
        printf '%-12s %s\n' "Server Name:" "${sni}:${port_in}"
        echo
    }
    render_server_create_result
    nav_print
    nav_wait_bx_redraw render_server_create_result
}

# ── server restart ──
render_server_restart_done() {
    header "xray › server › restart"
    echo "done"
    echo
}
server_restart() {
    header "xray › server › restart"
    ui_lock "restarting..."
    set +e
    ssh_run "(docker compose -f '${remote_dc}' restart xray || docker-compose -f '${remote_dc}' restart) >/dev/null 2>&1" || true
    set -e
    ui_unlock
    render_server_restart_done
    nav_print
    nav_wait_bx_redraw render_server_restart_done
}

# ── server remove ──
render_server_remove_none() {
    header "xray › server › remove"
    echo "none"
    echo
}

render_server_remove_done() {
    header "xray › server › remove"
    echo "done"
    echo
}

render_server_remove_confirm() {
    header "xray › server › remove"
    ui_lock "loading..."
    local json; json="$(get_remote_json_cached)"
    ui_unlock

    if [[ "$json" == '{}' ]]; then
        echo "none"
        echo
        return 1
    fi

    local vless_sni vless_port
    vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0] // empty' | head -n1)"
    vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port // empty' | head -n1)"

    printf '%-12s %s\n' "Protocol:"    "xtls-rprx-vision"
    printf '%-12s %s\n' "Server Name:" "${vless_sni}:${vless_port}"
    echo
    echo "Do you want to remove this Xray server (y/n)?"
    echo
    return 0
}

server_remove() {
    if ! server_exists_cached; then
        render_server_remove_none
        nav_print
        nav_wait_bx_redraw render_server_remove_none
        return
    fi

    while :; do
        if ! render_server_remove_confirm; then
            nav_print
            nav_wait_bx_redraw render_server_remove_none
            return
        fi
        nav_print
        read -r ans
        case "$(first_token_lower "$ans")" in
            b) return 0 ;;
            x) echo "Bye."; exit 0 ;;
            y)
                ui_lock "removing..."
                ssh_run "(docker compose -f '${remote_dc}' down -v --remove-orphans || docker-compose -f '${remote_dc}' down -v) >/dev/null 2>&1" || true
                ssh_run '
                    for unit in os-updater docker-compose-updater docker-updater; do
                        systemctl disable --now "${unit}.timer" >/dev/null 2>&1 || true
                        systemctl disable --now "${unit}.service" >/dev/null 2>&1 || true
                    done
                    systemctl daemon-reload >/dev/null 2>&1 || true
                ' || true

                ssh_run '
                    rm -f /etc/systemd/system/os-updater.service \
                          /etc/systemd/system/os-updater.timer \
                          /etc/systemd/system/docker-compose-updater.service \
                          /etc/systemd/system/docker-compose-updater.timer \
                          /etc/systemd/system/docker-updater.service \
                          /etc/systemd/system/docker-updater.timer
                    rm -f /usr/local/sbin/os-updater \
                          /usr/local/sbin/docker-compose-updater \
                          /usr/local/sbin/docker-updater \
                          /var/log/apt-auto-upgrade.log
                    systemctl daemon-reload >/dev/null 2>&1 || true
                ' || true

                ssh_run "rm -f '${remote_cfg}' '${remote_dc}'" || true
                ssh_run "rm -rf '${remote_dir}'" || true
                ui_unlock
                cache_set_json '{}'
                render_server_remove_done
                nav_print
                nav_wait_bx_redraw render_server_remove_done
                return
                ;;
            n)
                return 0
                ;;
            *)
                nav_invalid_inline
                ;;
        esac
    done
}

# ── keys list ──
render_keys_list_screen() {
    header "xray › access › list"
    ui_lock "loading..."
    local json; json="$(get_remote_json_cached)"
    json="$(printf '%s' "$json" | sync_shortids_with_clients)"
    local links=()
    mapfile -t links < <(build_links_array "$json" || true)
    ui_unlock

    if ((${#links[@]} == 0)) || [[ "${links[0]-}" == "(none)" ]]; then
        echo "none"
        echo
    else
        local l
        for l in "${links[@]}"; do
            printf '%s\n\n' "$l"
        done
    fi
}
keys_list_screen() {
    render_keys_list_screen
    nav_print
    nav_wait_bx_redraw render_keys_list_screen
}

# ── keys add ──
render_keys_add_prompt() {
    header "xray › access › add"
    echo "How many access links do you need?"
    echo "Enter a number (e.g., 1–100)."
    echo
}
keys_add_screen() {
    local count
    while :; do
        render_keys_add_prompt
        nav_print
        IFS= read -r ans
        # allow whitespace around number
        if [[ "$(first_token_lower "$ans")" == "b" ]]; then return 0; fi
        if [[ "$(first_token_lower "$ans")" == "x" ]]; then echo "Bye."; exit 0; fi
        if [[ "$ans" =~ ^[[:space:]]*([0-9]+)[[:space:]]*$ ]]; then
            count="${BASH_REMATCH[1]}"
            if (( count >= 1 && count <= 100 )); then
                break
            fi
        fi
        nav_invalid_inline
    done

    ui_lock "preparing..."
    local json; json="$(get_remote_json_cached)"
    if [[ "$json" == '{}' ]]; then
        ensure_bootstrap_remote
        xray_keys
        local sni="$vless_sni_default"
        local port_in="$vless_port_default"
        local sid_boot="$(short_id_from_uuid "$(uuid)")"
        json="$(cat <<'EOL' | indent -4
        {
            "log": { "loglevel": "none" },
            "inbounds": [
                {
                    "port": __PORT__,
                    "protocol": "vless",
                    "settings": { "clients": [], "decryption": "none" },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "__SNI__:443",
                            "serverNames": ["__SNI__"],
                            "privateKey": "__PRIV__",
                            "shortIds": ["__SID__"]
                        }
                    },
                    "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"], "routeOnly": true }
                }
            ],
            "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
        }
EOL
)"
        json="${json/__PORT__/$port_in}"
        json="${json//__SNI__/$sni}"
        json="${json/__PRIV__/$priv_key}"
        json="${json/__SID__/$sid_boot}"
        write_remote_dc_with_port "$port_in"
    fi

    declare -a new_uuids=()
    local i
    for i in $(seq 1 "$count"); do new_uuids+=( "$(uuid)" ); done
    local u
    for u in "${new_uuids[@]}"; do
        json="$(printf '%s' "$json" | jq --arg uuid "$u" '
            (.inbounds[]|select(.protocol=="vless")|.settings.clients) += [{"id":$uuid,"flow":"xtls-rprx-vision"}]
        ')"
    done

    json="$(printf '%s' "$json" | sync_shortids_with_clients)"

    printf '%s' "$json" > config.json
    cache_set_json "$json"
    ui_unlock
    ui_lock "applying..."
    send_config_and_restart
    ui_unlock

    render_keys_add_result() {
        header "xray › access › add"
        local vless_sni vless_port priv_key_local pbk
        vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0]' | head -n1)"
        vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port' | head -n1)"
        priv_key_local="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.privateKey' | head -n1)"
        pbk="$(derive_pbk "$priv_key_local")"
        [[ -z "$pbk" && -n "${pub_key-}" ]] && pbk="$pub_key"
        local uu
        for uu in "${new_uuids[@]}"; do
            sid="$(short_id_from_uuid "$uu")"
            echo "vless://${uu}@${host}:${vless_port}?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&sni=${vless_sni}&fp=chrome&pbk=${pbk}&sid=${sid}#vless-vision-reality"
            echo
        done
    }
    render_keys_add_result
    nav_print
    nav_wait_bx_redraw render_keys_add_result
}

# ── keys remove menu ──
render_keys_remove_menu() {
    header "xray › access › remove"
    echo "1.   Remove all access links"
    echo "2.   Remove a single access link"
    echo
}
keys_remove_menu() {
    while :; do
        render_keys_remove_menu
        nav_print
        read -r ans
        case "$(first_token_lower "$ans")" in
            1) keys_remove_all ;;
            2) keys_remove_one ;;
            b) return 0 ;;
            x) echo "Bye."; exit 0 ;;
            *) nav_invalid_inline ;;
        esac
    done
}

# ── keys remove all ──
render_keys_remove_all_confirm() {
    header "xray › access › remove › all"
    echo "Do you want to remove all access links (y/n)?"
    echo
}
keys_remove_all() {
    while :; do
        render_keys_remove_all_confirm
        nav_print
        read -r ans
        case "$(first_token_lower "$ans")" in
            b) return 0 ;;
            x) echo "Bye."; exit 0 ;;
            y)
                ui_lock "removing..."
                local json; json="$(get_remote_json_cached)"
                json="$(
                    jq '
                      .inbounds |= map(
                        if .protocol=="vless"
                        then (.settings.clients = []
                              | .streamSettings.realitySettings.shortIds = [])
                        else .
                        end
                      )
                    ' <<< "$json"
                )"
                printf '%s' "$json" > config.json
                cache_set_json "$json"
                send_config_and_restart
                ui_unlock

                header "xray › access › remove › all"
                echo "none"
                echo
                nav_print
                nav_wait_bx_redraw render_keys_remove_all_confirm
                return 0
                ;;
            n) return 0 ;;
            *) nav_invalid_inline ;;
        esac
    done
}

# ── keys remove one ──
render_keys_remove_one_pick() {
    header "xray › access › remove › one"
    ui_lock "loading..."
    local json; json="$(get_remote_json_cached)"
    mapfile -t uuids < <(printf '%s' "$json" \
        | jq -r '(.inbounds[]?|select(.protocol=="vless")|.settings.clients // [])[] | .id')
    ui_unlock

    if ((${#uuids[@]}==0)); then
        echo "none"
        echo
        return 1
    fi

    local i
    for i in "${!uuids[@]}"; do
        printf '%d.   %s\n' "$((i+1))" "${uuids[$i]}"
    done
    echo
    return 0
}
keys_remove_one() {
    while :; do
        if render_keys_remove_one_pick; then
            nav_print
            read -r pick_raw
            local pick="$(first_token_lower "$pick_raw")"
            case "$pick" in
                b) return 0 ;;
                x) echo "Bye."; exit 0 ;;
                *)
                    if [[ "$pick_raw" =~ ^[[:space:]]*([0-9]+)[[:space:]]*$ ]]; then
                        local idx=$((BASH_REMATCH[1]-1))
                        ui_lock "loading..."
                        local json; json="$(get_remote_json_cached)"
                        mapfile -t uuids < <(printf '%s' "$json" \
                            | jq -r '(.inbounds[]?|select(.protocol=="vless")|.settings.clients // [])[] | .id')
                        ui_unlock
                        (( idx<0 || idx>=${#uuids[@]} )) && { nav_invalid_inline; continue; }
                        local target="${uuids[$idx]}"

                        render_keys_remove_one_confirm() {
                            header "xray › access › remove › one"
                            echo "$target"
                            echo "Do you want to remove this access link (y/n)?"
                            echo
                        }
                        while :; do
                            render_keys_remove_one_confirm
                            nav_print
                            read -r yn
                            case "$(first_token_lower "$yn")" in
                                b) break ;;
                                x) echo "Bye."; exit 0 ;;
                                y)
                                    ui_lock "removing..."
                                    local json2; json2="$(get_remote_json_cached)"
                                    json2="$(printf '%s' "$json2" \
                                        | jq --arg uuid "$target" '
                                            (.inbounds[]|select(.protocol=="vless")|.settings.clients)
                                            |= map(select(.id != $uuid))
                                        ')"
                                    json2="$(printf '%s' "$json2" | sync_shortids_with_clients)"
                                    printf '%s' "$json2" > config.json
                                    cache_set_json "$json2"
                                    send_config_and_restart
                                    ui_unlock
                                    break
                                    ;;
                                n) break ;;
                                *) nav_invalid_inline ;;
                            esac
                        done
                    else
                        nav_invalid_inline
                        continue
                    fi
                    ;;
            esac
        else
            nav_print
            nav_wait_bx_redraw render_keys_remove_one_pick
            return 0
        fi
    done
}

# ─────────────────────────────── menus ───────────────────────────────

render_home() {
    header "xray › home"

    echo "Server"
    echo "1.   Show installed Xray (what’s installed and running)"
    echo "2.   Install / Reinstall Xray (deploy from scratch)"
    echo "3.   Restart Xray (soft restart of container)"
    echo "4.   Remove Xray (container and config)"
    echo
    echo "Access"
    echo "5.   Show access links (all active xray keys)"
    echo "6.   Issue new access links (create N new keys)"
    echo "7.   Remove access links (all or one keys)"
    echo
}
menu_xray() {
    while :; do
        render_home
        nav_print
        read -r ans
        case "$(first_token_lower "$ans")" in
            1) print_server_info_screen ;;
            2) server_create_interactive ;;
            3) server_restart ;;
            4) server_remove ;;
            5) keys_list_screen ;;
            6) keys_add_screen ;;
            7) keys_remove_menu ;;
            b) : ;;
            x) echo "Bye."; exit 0 ;;
            *) nav_invalid_inline ;;
        esac
    done
}

# ──────────────────────── bootstrap: auth & run ────────────────────────

print_attempt() { header "[Check VPS]"; }

mkdir -p /tmp && : > /tmp/known_hosts

for i in {1..3}; do
    print_attempt "$i"
    while :; do
        printf "%-22s" "Enter VPS IP address: " >&2
        read -r host
        [[ -z "$host" ]] && { echo "IP address can't be empty." >&2; continue; }
        break
    done
    printf "%-22s" "Enter VPS port (default 22): " >&2
    read -r port; [[ -z "$port" ]] && port=22
    while :; do
        printf "%-22s" "Enter VPS password: " >&2
        read -rs password; printf "\n"
        [[ -z "$password" ]] && { echo "Password can't be empty." >&2; continue; }
        break
    done
    if test_login "$host" "$port" "$password"; then
        header "[ok]"
        sleep 0.8
        break
    else
        printf "Incorrect IP, port or password. Try again.\n" >&2
        sleep 1
    fi
    [[ $i -eq 3 ]] && { printf "The maximum number of attempts has been reached.\nPlease try again later\n" >&2; exit 1; }
done

menu_xray
EOW
RUN chmod +x /usr/local/bin/xray.sh
WORKDIR /app
USER $APP_UID:$APP_GID
ENTRYPOINT ["/usr/local/bin/xray.sh"]
EOF

docker buildx create --name "$builder" --use --driver docker-container --driver-opt image=moby/buildkit:latest --bootstrap >/dev/null
docker buildx build --builder "$builder" --load --pull --label "temp.build.id=${build_id}" -t "xray-admin:${build_id}" -t xray-admin "$workdir"
docker run --rm -it --user 10000:10000 --read-only --workdir /tmp --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777 --cap-drop=ALL --security-opt no-new-privileges --pids-limit 256 --memory 512m --cpus 1 xray-admin:${build_id}
