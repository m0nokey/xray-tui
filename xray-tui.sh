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

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates jq openssh-client sshpass python3 python3-nacl \
 && rm -rf /var/lib/apt/lists/*

RUN printf '%s\n' '#!/bin/sh' \
    'if [ "$1" = "-p" ] || [ "$1" = "-P" ]; then exec /usr/bin/sshpass "$@"; fi' \
    'pass="$1"; shift' \
    'exec /usr/bin/sshpass -p "$pass" "$@"' > /usr/local/bin/sshpass \
 && chmod +x /usr/local/bin/sshpass

RUN cat <<'EOW' > /usr/local/bin/xray.sh
#!/bin/bash
set -euo pipefail

# ─────────────────────────────── helpers ───────────────────────────────

indent() {
    local mode="$1"
    local num="$2"
    case "$mode" in
        +) sed "s/^/$(printf '%*s' "$num")/";;
        -) sed -E "s/^ {0,$num}//";;
        0) awk '{ $1=$1; print }';;
        *) return 1;;
    esac
}

cls() { clear; printf '\e[3J'; }
hr()  { printf '%s\n' "____________________"; }
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

        { while [[ "${_ui_lock_active:-}" = "1" ]]; do
              read -r -t 0.05 -n 10000 _junk || true
          done
        } &
        _ui_drain_pid=$!

        { i=0; frames='|/-\'; while [[ "${_ui_lock_active:-}" = "1" ]]; do
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
    # update message while locked
    local msg="${*:-working...}"
    [[ "${_ui_depth:-0}" -gt 0 ]] && _ui_msg="$msg"
}

ui_unlock() {
    _ui_depth=${_ui_depth:-0}
    (( _ui_depth > 0 )) || return 0

    _ui_depth=$((_ui_depth - 1))
    if (( _ui_depth > 0 )); then
        # restore previous message if any
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

actions_block() {
    printf "b.   back\n"
    printf "x.   exit\n"
    printf "?:   "
}

# ─────────────────────────────── config ───────────────────────────────

remote_dir="/root/xray"
remote_cfg="${remote_dir}/config.json"
remote_dc="${remote_dir}/docker-compose.yaml"

vless_sni_default="api.github.com"
vless_spider_x_default="/"
vless_port_default="443"

ssh_opts='-o LogLevel=error -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

base_mark="/tmp/.base_install_done"

# ───────────────────────────── ssh helpers ─────────────────────────────

test_login() {
    local host="$1" port="$2" password="$3"
    sshpass "$password" ssh -p "$port" $ssh_opts "root@${host}" 'exit' 2>/dev/null
}
ssh_run()  { sshpass "$password" ssh -p "$port" $ssh_opts "root@${host}" "$1" </dev/null 2>/dev/null || return $?; }
ssh_pipe() { cat | sshpass "$password" ssh -p "$port" $ssh_opts "root@${host}" "$1" 2>/dev/null; }
ssh_cat()  { ssh_run "cat '$1'"; }
jq_docker(){ jq "$@"; }

# ───────────────────────── key & id utilities ─────────────────────────

uuid() { cat /proc/sys/kernel/random/uuid; }

# shortId derived deterministically from UUID (first 16 hex of sha256(uuid-without-dashes))
short_id_from_uuid() {
    local u="$1"
    u="${u//-/}"
    printf '%s' "$u" | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n' | cut -c1-16
}

xray_keys() {
    local out
    out="$(
        cat <<'EOL' | indent - 4 | python3 -
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
    cat <<'EOL' | indent - 4 | python3 - "$priv"
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
# For each client UUID, compute shortId = short_id_from_uuid(UUID).
# Deduplicate, keep order as in clients, and never keep empty strings.
sync_shortids_with_clients() {
    local json; json="$(cat)"

    # extract client UUIDs as bash array
    mapfile -t _uuids < <(printf '%s' "$json" \
        | jq -r '(.inbounds[]?|select(.protocol=="vless")|.settings.clients // [])[].id')

    # build SIDs from UUIDs
    local _sids=() u
    for u in "${_uuids[@]}"; do
        _sids+=( "$(short_id_from_uuid "$u")" )
    done

    # make a unique JSON array preserving order
    # (jq 'unique' loses order, so we do it in jq with an order-preserving fold)
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
    cat <<-'EOS' | indent - 4 > $install_file
    #!/bin/bash 

    indent() {
        local mode="$1"
        local num="$2"
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
        cat <<EOL | indent - 4 > /etc/apt/sources.list.d/debian.sources
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
        local packages=("lsb-release" "apt-transport-https" "ca-certificates" "gnupg2" "cron" "curl")
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
        curl -sfLC - --tlsv1.3 --proto '=https' -o /usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/${ver}/docker-compose-$(uname -s)-$(uname -m)"
        chmod +x /usr/local/bin/docker-compose
    }
    install_xray() {
        mkdir -p /root/xray/
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
        locale-gen en_US.UTF-8 >/dev/null 2>&1
        source /root/.bashrc >/dev/null 2>&1
        source /etc/default/locale >/dev/null 2>&1  
    }
    setup_security_update() {
        export DEBIAN_FRONTEND=noninteractive
        apt-get update >/dev/null 2>&1
        apt-get install --no-install-recommends -y unattended-upgrades >/dev/null 2>&1
    
        cat <<'EOL' | indent - 4 > /etc/apt/apt.conf.d/50unattended-upgrades
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
        cat <<'EOL' | indent 0 > /etc/apt/apt.conf.d/20auto-upgrades
        APT::Periodic::Update-Package-Lists "1";
        APT::Periodic::Download-Upgradeable-Packages "1";
        APT::Periodic::AutocleanInterval "7";
        APT::Periodic::Unattended-Upgrade "1";
    EOL
    }
    configure_os_updater() {
        [ ! -d /root/.tools ] && mkdir /root/.tools
        cat <<-'EOL' | indent - 4 > /root/.tools/os_updater
        #!/bin/bash
        set -e
        export DEBIAN_FRONTEND=noninteractive
        export APT_LISTCHANGES_FRONTEND=none
        curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://download.docker.com/linux/debian/gpg" | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
        /usr/bin/apt-get clean
        /usr/bin/rm -rf /var/lib/apt/lists/*
        /usr/bin/apt update
        if [ $? -eq 0 ]; then
            /usr/bin/apt-get -o Dpkg::Options::="--force-confold" upgrade -y
            kernel=$(apt list --upgradable 2>/dev/null | grep -E 'linux-(headers|image|modules)-[0-9]+')
            /usr/bin/apt-get -o Dpkg::Options::="--force-confold" dist-upgrade -y
            /usr/bin/apt-get autoremove --purge -y
            /usr/bin/apt-get clean
            if [ ! -z "$kernel" ]; then
                /sbin/reboot
            fi
        fi
    EOL
        chmod +x /root/.tools/os_updater
        local tmp_cron=$(mktemp)
        crontab -l -u root 2>/dev/null > "$tmp_cron"
        echo '0 3 * * * /bin/bash /root/.tools/os_updater' >> "$tmp_cron"
        crontab -u root "$tmp_cron"
        rm "$tmp_cron"
    }
    configure_docker_compose_updater() {
        [ ! -d /root/.tools ] && mkdir /root/.tools
        cat <<-'EOL' | indent - 4 > /root/.tools/docker_compose_updater
        #!/bin/bash
        set -e
        tmp_folder=$(mktemp -d)
        compose_file="/root/xray/docker-compose.yaml"
        latest_version=$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://api.github.com/repos/docker/compose/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        current_version=$(/usr/local/bin/docker-compose -v | grep -o 'v[0-9]*\.[0-9]*\.[0-9]*')
        
        if [[ "$current_version" != "$latest_version" ]]; then
            /usr/local/bin/docker-compose -f $compose_file down
            attempt=0
            max_attempts=3
            until curl --tlsv1.3 --http2 --proto '=https' -sfLC - -o "$tmp_folder/docker-compose" "https://github.com/docker/compose/releases/download/${latest_version}/docker-compose-$(uname -s)-$(uname -m)"; do
                ((attempt++))
                [[ $attempt -ge $max_attempts ]] && exit 1
                sleep 2
            done
            chmod +x "${tmp_folder}/docker-compose"
            mv "${tmp_folder}/docker-compose" /usr/local/bin/docker-compose
            /usr/local/bin/docker-compose -f $compose_file up
        fi
        rm -rf "$tmp_folder"
    EOL
        chmod +x /root/.tools/docker_compose_updater
        local tmp_cron=$(mktemp)
        crontab -l -u root 2>/dev/null > "$tmp_cron"
        echo '30 3 * * * /bin/bash /root/.tools/docker_compose_updater' >> "$tmp_cron"
        crontab -u root "$tmp_cron"
        rm "$tmp_cron"
    }
    configure_docker_updater() {
        [ ! -d /root/.tools ] && mkdir /root/.tools
        cat <<-'EOL' | indent 0 > /root/.tools/docker_updater
        #!/bin/bash
        set -e
        compose_file="/root/xray/docker-compose.yaml"
        /usr/bin/docker pull ghcr.io/xtls/xray-core:latest
        #/usr/local/bin/docker-compose -f $compose_file build --no-cache
        /usr/local/bin/docker-compose -f $compose_file down
        /usr/local/bin/docker-compose -f $compose_file up -d --force-recreate
        /usr/bin/docker system prune -a -f
    EOL
        chmod +x /root/.tools/docker_updater
        local tmp_cron=$(mktemp)
        crontab -l -u root 2>/dev/null > "$tmp_cron"
        echo '45 3 * * * /bin/bash /root/.tools/docker_updater' >> "$tmp_cron"
        crontab -u root "$tmp_cron"
        rm "$tmp_cron"
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
    cat "${install_file}" | sshpass "$password" ssh -p "$port" -o LogLevel=error -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${host}" \
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

ensure_docker_remote() {
    if ssh_run 'command -v docker >/dev/null 2>&1'; then
        if ssh_run 'docker compose version >/dev/null 2>&1 || docker-compose -v >/dev/null 2>&1'; then
            return 0
        fi
    fi
    base_install_prepare_local
    ui_lock "/ installing..."
    base_install_push_and_start || true
    wait_for_base_install || true
    ui_unlock
}

# ─────────────────────────── remote file writers ───────────────────────────

write_remote_dc_with_port() {
    local p="$1"
    ssh_run "mkdir -p '${remote_dir}'"
    cat <<'EOL' | indent - 4 | ssh_pipe "cat > '${remote_dc}'"
    services:
        xray:
            image: ghcr.io/xtls/xray-core:latest
            container_name: xray
            cap_add:
                - NET_BIND_SERVICE
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

server_exists() { ssh_run "test -f '${remote_cfg}'"; }

print_server_info_screen() {
    header "xray › server › info"
    ui_lock "loading..."
    local json; json="$(get_remote_json_or_empty)"
    ui_unlock

    if [[ "$json" == '{}' ]]; then
        echo "none"
        echo
        printf 'b.   back\nx.   exit\n?:   '
        read -r ans
        [[ "$ans" =~ ^[xX]$ ]] && { echo "Bye."; exit 0; }
        return 0
    fi

    local vless_sni vless_port
    vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0] // empty' | head -n1)"
    vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port // empty' | head -n1)"

    printf '%-12s %s\n' "Protocol:"    "xtls-rprx-vision"
    printf '%-12s %s\n' "Server Name:" "${vless_sni}:${vless_port}"
    echo
    printf 'b.   back\nx.   exit\n?:   '
    read -r ans
    [[ "$ans" =~ ^[xX]$ ]] && { echo "Bye."; exit 0; }
    return 0
}

server_create_interactive() {
    header "xray › server › create"

    local exists=1; if server_exists; then exists=0; fi
    if (( exists == 0 )); then
        ui_lock "loading..."
        local json; json="$(get_remote_json_or_empty)"
        ui_unlock

        local vless_sni vless_port
        vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0] // empty' | head -n1)"
        vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port // empty' | head -n1)"

        printf '%-12s %s\n' "Protocol:"    "xtls-rprx-vision"
        printf '%-12s %s\n' "Server Name:" "${vless_sni}:${vless_port}"
        echo
        echo "You already have an Xray Server created."
        echo
        printf 'b.   back\nx.   exit\n?:   '
        read -r ans
        case "$ans" in x|X) echo "Bye."; exit 0 ;; *) return 0 ;; esac
        return 0
    fi

    printf "Enter SNI (default %s): " "$vless_sni_default"; read -r sni; [[ -z "${sni:-}" ]] && sni="$vless_sni_default"
    printf "Enter spider path (default %s): " "$vless_spider_x_default"; read -r spx; [[ -z "${spx:-}" ]] && spx="$vless_spider_x_default"
    printf "Enter listen port (default %s): " "$vless_port_default"; read -r port_in; [[ -z "${port_in:-}" ]] && port_in="$vless_port_default"

    ui_lock "creating server..."
    ensure_docker_remote
    ui_set "creating server..."

    xray_keys
    local sid; sid="$(short_id)"
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

    ui_set "applying..."
    send_config_and_restart
    ui_unlock

    header "xray › server › create"
    printf '%-12s %s\n' "Protocol:"    "xtls-rprx-vision"
    printf '%-12s %s\n' "Server Name:" "${sni}:${port_in}"
    echo
    printf 'b.   back\nx.   exit\n?:   '
    read -r _
}

server_restart() {
    header "xray › server › restart"
    ui_lock "restarting..."
    set +e
    ssh_run "(docker compose -f '${remote_dc}' restart xray || docker-compose -f '${remote_dc}' restart) >/dev/null 2>&1" || true
    set -e
    ui_unlock
    echo "done"
    echo
    printf 'b.   back\nx.   exit\n?:   '
    read -r _
}

server_remove() {
    header "xray › server › remove"
    ui_lock "checking..."
    local exists=1; if server_exists; then exists=0; fi
    ui_unlock

    if (( exists != 0 )); then
        echo "none"
        echo
        printf 'b.   back\nx.   exit\n?:   '
        read -r _
        return
    fi

    ui_lock "removing..."
    ssh_run "(docker compose -f '${remote_dc}' down || docker-compose -f '${remote_dc}' down) >/dev/null 2>&1" || true
    ssh_run "rm -f '${remote_cfg}'" || true
    ui_unlock
    echo "done"
    echo
    printf 'b.   back\nx.   exit\n?:   '
    read -r _
}

keys_list_screen() {
    header "xray › access › list"
    ui_lock "loading..."
    local json; json="$(get_remote_json_or_empty)"
    # keep shortIds in sync with current clients
    json="$(printf '%s' "$json" | sync_shortids_with_clients)"
    # show links
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

    printf 'b.   back\nx.   exit\n?:   '
    read -r ans
    case "$ans" in
        b|B) return 0 ;;
        x|X) echo "Bye."; exit 0 ;;
        *)   return 0 ;;
    esac
}

keys_add_screen() {
    header "xray › access › add"
    echo "How many access links do you need?"
    echo "Enter a number (e.g., 1–100)."
    echo
    printf 'b.   back\nx.   exit\n?:   '
    read -r ans
    case "$ans" in
        b|B) return 0 ;;
        x|X) echo "Bye."; exit 0 ;;
    esac
    if ! [[ "$ans" =~ ^[0-9]+$ ]] || (( ans < 1 || ans > 100 )); then
        return 0
    fi

    local count="$ans"

    ui_lock "preparing..."
    local json; json="$(get_remote_json_or_empty)"
    if [[ "$json" == '{}' ]]; then
        # fresh server bootstrap
        ensure_docker_remote
        xray_keys
        local sni="$vless_sni_default"
        local port_in="$vless_port_default"
        local sid_boot="$(short_id_from_uuid "$(uuid)")"   # placeholder SID; will be replaced by sync
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
        json="${json/__SID__/$sid_boot}"
        write_remote_dc_with_port "$port_in"
    fi

    # add N clients
    declare -a new_uuids=()
    local i
    for i in $(seq 1 "$count"); do
        new_uuids+=( "$(uuid)" )
    done
    local u
    for u in "${new_uuids[@]}"; do
        json="$(printf '%s' "$json" | jq --arg uuid "$u" '
            (.inbounds[]|select(.protocol=="vless")|.settings.clients) += [{"id":$uuid,"flow":"xtls-rprx-vision"}]
        ')"
    done

    # sync shortIds to match clients
    json="$(printf '%s' "$json" | sync_shortids_with_clients)"

    # persist & restart
    printf '%s' "$json" > config.json
    ui_unlock
    ui_lock "applying..."
    send_config_and_restart
    ui_unlock

    # show generated links
    header "xray › access › add"
    local vless_sni vless_port priv_key pbk
    vless_sni="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.serverNames[0]' | head -n1)"
    vless_port="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.port' | head -n1)"
    priv_key="$(printf '%s' "$json" | jq -r '.inbounds[]?|select(.protocol=="vless")|.streamSettings.realitySettings.privateKey' | head -n1)"
    pbk="$(derive_pbk "$priv_key")"
    [[ -z "$pbk" && -n "${pub_key-}" ]] && pbk="$pub_key"

    for u in "${new_uuids[@]}"; do
        sid="$(short_id_from_uuid "$u")"
        echo "vless://${u}@${host}:${vless_port}?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&sni=${vless_sni}&fp=chrome&pbk=${pbk}&sid=${sid}#vless-vision-reality"
        echo
    done

    printf 'b.   back\nx.   exit\n?:   '
    read -r ans2
    case "$ans2" in
        b|B) return 0 ;;
        x|X) echo "Bye."; exit 0 ;;
        *)   return 0 ;;
    esac
}

keys_remove_menu() {
    while :; do
        header "xray › access › remove"
        echo "1.   Remove all access links"
        echo "2.   Remove a single access link"
        echo
        printf 'b.   back\nx.   exit\n?:   '
        read -r ans
        case "$ans" in
            1) keys_remove_all ;;
            2) keys_remove_one ;;
            b|B) return 0 ;;
            x|X) echo "Bye."; exit 0 ;;
            *) ;;
        esac
    done
}

keys_remove_all() {
    header "xray › access › remove › all"
    echo "Do you want to remove all access links (y/n)?"
    echo
    printf 'b.   back\nx.   exit\n?:   '
    read -r ans
    case "$ans" in
        b|B) return 0 ;;
        x|X) echo "Bye."; exit 0 ;;
        y|Y)
            ui_lock "removing..."
            local json; json="$(get_remote_json_or_empty)"

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
            send_config_and_restart
            ui_unlock
            ;;
        *) return 0 ;;
    esac

    header "xray › access › remove › all"
    echo "none"
    echo
    printf 'b.   back\nx.   exit\n?:   '
    read -r _
}

keys_remove_one() {
    while :; do
        header "xray › access › remove › one"
        ui_lock "loading..."
        local json; json="$(get_remote_json_or_empty)"
        mapfile -t uuids < <(printf '%s' "$json" \
            | jq -r '(.inbounds[]?|select(.protocol=="vless")|.settings.clients // [])[] | .id')
        ui_unlock

        if ((${#uuids[@]}==0)); then
            echo "none"
            echo
            printf 'b.   back\nx.   exit\n?:   '
            read -r ans
            [[ "$ans" =~ ^[xX]$ ]] && { echo "Bye."; exit 0; }
            return 0
        fi

        local i
        for i in "${!uuids[@]}"; do
            printf '%d.   %s\n' "$((i+1))" "${uuids[$i]}"
        done
        echo
        printf 'b.   back\nx.   exit\n?:   '
        read -r pick
        case "$pick" in
            b|B) return 0 ;;
            x|X) echo "Bye."; exit 0 ;;
        esac
        if ! [[ "$pick" =~ ^[0-9]+$ ]]; then
            continue
        fi
        local idx=$((pick-1))
        (( idx<0 || idx>=${#uuids[@]} )) && continue
        local target="${uuids[$idx]}"

        header "xray › access › remove › one"
        echo "$target"
        echo "Do you want to remove this access link (y/n)?"
        echo
        printf 'b.   back\nx.   exit\n?:   '
        read -r yn
        case "$yn" in
            b|B) continue ;;
            x|X) echo "Bye."; exit 0 ;;
            y|Y)
                ui_lock "removing..."
                local json2; json2="$(get_remote_json_or_empty)"
                # remove client
                json2="$(printf '%s' "$json2" \
                    | jq --arg uuid "$target" '
                        (.inbounds[]|select(.protocol=="vless")|.settings.clients)
                        |= map(select(.id != $uuid))
                    ')"
                # resync shortIds to remaining clients
                json2="$(printf '%s' "$json2" | sync_shortids_with_clients)"
                printf '%s' "$json2" > config.json
                send_config_and_restart
                ui_unlock
                ;;
            *) continue ;;
        esac
    done
}

# ─────────────────────────────── menus ───────────────────────────────

menu_xray() {
    while :; do
        header "xray › home"

        echo "Server"
        echo "1.   Show installed Xray (what’s installed and running)"
        echo "2.   Install / Reinstall Xray (deploy from scratch)"
        echo "3.   Restart Xray (soft restart of container)"
        echo "4.   Remove Xray (container and config)"
        echo
        echo "Access"
        echo "5.   Show access links (all active xray keys)"
        echo "6.   Issue new access links (create N new links)"
        echo "7.   Remove access links (all or one)"
        echo
        printf 'b.   back\nx.   exit\n?:   '
        read -r ans

        case "$ans" in
            1) print_server_info_screen ;;   # xray › server › info
            2) server_create_interactive ;;  # xray › server › create
            3) server_restart ;;             # xray › server › restart
            4) server_remove ;;              # xray › server › remove
            5) keys_list_screen ;;           # xray › access › list
            6) keys_add_screen ;;            # xray › access › add
            7) keys_remove_menu ;;           # xray › access › remove
            b|B) : ;;
            x|X) echo "Bye."; exit 0 ;;
            *)  : ;;
        esac
    done
}

# ──────────────────────── bootstrap: auth & run ────────────────────────

print_attempt() { header "[Check VPS]"; }

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
ENTRYPOINT ["/usr/local/bin/xray.sh"]
EOF

docker buildx create --name "$builder" --use --driver docker-container --driver-opt image=moby/buildkit:latest --bootstrap >/dev/null
docker buildx build --builder "$builder" --load --pull --label "temp.build.id=${build_id}" -t "xray-admin:${build_id}" -t xray-admin "$workdir"
docker run --rm -it "xray-admin:${build_id}"
