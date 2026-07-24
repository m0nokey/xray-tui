# xray-tui Legacy

This folder contains the original, lightweight Xray TUI.

The legacy version connects to the VPS directly over SSH and manages one Xray
Docker stack. It does **not** use the current Ansible deployment flow and does
not install the current VPS SSH hardening. Use it only when you specifically
need the old approach.

For the current Ansible-based manager with VPS hardening, encrypted local Vault
state, node management, SSH-key rotation, and per-key management, use the
[main project README](../README.md).

## Quick Start

Run the legacy script directly from GitHub:

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/m0nokey/xray-tui/refs/heads/main/legacy/xray-tui.sh')"
```

Or clone the repository and run the local copy:

```bash
git clone https://github.com/m0nokey/xray-tui.git
cd xray-tui
bash legacy/xray-tui.sh
```

The local computer needs macOS or Linux, Bash, `curl`, and Docker with Compose.
The legacy script builds a temporary Alpine administration container and
removes it when the script exits.

## Supported VPS

The legacy script expects a Debian-based VPS with `apt`, systemd, root SSH
access, and a public IPv4 address or DNS name. It does not provide the current
project's Debian 12+ validation or VPS hardening. Review the script and the
remote changes before using it.

## Menu

```text
1. Server
2. Keys

x. exit
?:

Server:

1. Install
2. Remove
3. Restart
4. Status

b. back
m. main
x. exit
?:

Keys:

1. List
2. Add
3. Remove

b. back
m. main
x. exit
?:
```

### Server Actions

`Status` reads the remote Xray configuration and displays the configured SNI,
TCP Vision port, XHTTP port, and XHTTP path. It does not perform an active
connectivity test.

`Install` creates a server only when `/opt/xray/config.json` does not already
exist. It is not an in-place reinstall operation. The script asks for an SNI,
default `api.github.com`, and an XHTTP path, default `/`.

The two client-facing ports are generated randomly in the range `30000-60000`.
They are different and are not entered manually.

`Restart` restarts the remote Xray service through Docker Compose.

`Remove` stops and removes the Xray Compose stack, Xray files, update timers,
helper scripts, and `/opt/xray`. It does not uninstall Docker or restore the
VPS to a hardened configuration because this legacy version does not install
that hardening in the first place.

### Key Actions

`List` prints all generated VLESS links. Each client normally has two links:
one for TCP Vision and one for XHTTP.

`Add` accepts from 1 to 100 new keys. If no server exists, it bootstraps one
with the default SNI and path before adding the keys.

`Remove` can remove all keys or a single key. Removing keys changes only the
VLESS client lists and REALITY short IDs; it does not remove the server.

The navigation keys are:

- `b` to go back;
- `m` to return to the main menu;
- `x` to exit the TUI.

## Remote Layout

After installation, the main files are:

```text
/opt/xray/config.json
/opt/xray/docker-compose.yaml
```

The Compose service uses `ghcr.io/xtls/xray-core:latest` and publishes the two
generated TCP ports. The container uses a read-only root filesystem, no Linux
capabilities, `no-new-privileges`, resource limits, and an `unless-stopped`
restart policy.

## VLESS Links

The legacy TUI generates links similar to:

```text
vless://UUID@SERVER:PORT?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&sni=api.github.com&fp=chrome&pbk=PUBLIC_KEY&sid=SHORT_ID#vless-vision-reality
```

```text
vless://UUID@SERVER:PORT?type=xhttp&encryption=none&security=reality&sni=api.github.com&fp=chrome&pbk=PUBLIC_KEY&sid=SHORT_ID&path=%2F#vless-xhttp-reality
```

Treat complete links and UUIDs as secrets. Anyone with a link can use the
server as that client.

## Automatic Updates

The legacy installation creates systemd timers for Debian package updates and
the Xray Docker image. The Xray configuration is preserved when the image is
updated.

## License

MIT. See [LICENSE](../LICENSE).
