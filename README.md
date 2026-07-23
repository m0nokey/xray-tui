# xray-tui

`xray-tui` is a terminal UI for installing and managing an Xray server on a remote Debian VPS over SSH.

It creates one Docker stack with two VLESS inbounds:

- VLESS over TCP with XTLS Vision and REALITY;
- VLESS over XHTTP with REALITY.

The tool generates complete VLESS links for both transports and lets you manage client UUIDs from the menu.

> **Security notice:** review the script before running it. It connects to the VPS as `root`, installs Docker, changes APT sources, and creates systemd update timers.

## Requirements

### Local machine

- macOS or Linux;
- Bash;
- `curl` for the one-line launcher;
- Docker Desktop on macOS or Docker Engine with Compose on Linux.

The launcher builds a temporary Alpine-based admin image and runs the TUI inside it. The temporary container and image are removed when the script exits.

### Remote VPS

- Debian with `apt` and systemd;
- root SSH access;
- an SSH server reachable on the selected port;
- a public IPv4 address or DNS name reachable by clients.

The first connection uses a root password. The script accepts up to three login attempts. The SSH host key is accepted into a temporary `known_hosts` file for that run.

## Quick start

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/m0nokey/xray-tui/refs/heads/main/xray-tui.sh')"
```

The script builds the local admin image, starts the TUI, and asks for:

```text
Enter VPS IP address:
Enter VPS port (default 22):
Enter VPS password:
```

The launcher does not install Xray on the local machine. Server-side installation is performed over SSH.

## Main menu

```text
xray › menu
____________________
Server
1. Status
2. Install
3. Restart
4. Remove

Keys
5. List
6. Add
7. Remove

b.   back
x.   exit
?:
```

### Server actions

**1. Status** reads the remote Xray configuration and displays the configured SNI, TCP Vision port, XHTTP port, and XHTTP path. It does not perform an active connectivity test.

**2. Install** creates a new server only when `/opt/xray/config.json` does not already exist. It is not an in-place reinstall operation. If a server already exists, the TUI reports that it has already been created.

The TUI asks for:

- SNI, default: `api.github.com`;
- XHTTP path, default: `/`.

The two client-facing ports are generated randomly in the range `30000-60000`. They are different and are not entered manually.

**3. Restart** restarts the remote `xray` service through Docker Compose.

**4. Remove** asks for confirmation and then:

- stops and removes the Xray Compose stack;
- removes the Xray configuration and Compose file;
- removes the OS and Docker update timers and helper scripts;
- removes `/opt/xray`.

It does not uninstall Docker or modify the rest of the operating system.

### Key actions

**5. List** prints all generated VLESS links for every configured client. Each client normally has two links: one for TCP Vision and one for XHTTP.

**6. Add** accepts between `1` and `100` new keys. If no server exists yet, this action bootstraps one with the default SNI and path before adding the keys.

**7. Remove** opens a submenu:

```text
1.   Remove all keys
2.   Remove a single key
```

Removing keys changes only the VLESS client lists and REALITY short IDs. It does not remove the server.

The following commands are available on every screen:

- `b` goes back;
- `x` exits the TUI.

## Remote layout

After installation, the main files are:

```text
/opt/xray/config.json
/opt/xray/docker-compose.yaml
```

The Compose service uses:

```text
ghcr.io/xtls/xray-core:latest
```

The generated container has these relevant constraints:

- read-only root filesystem;
- `/tmp` mounted as a temporary filesystem;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- `pids_limit: 512`;
- `mem_limit: 512m`;
- `nofile: 262144`;
- restart policy: `unless-stopped`;
- only the two generated ports are published as TCP ports.

## Generated Xray configuration

The configuration contains two VLESS inbounds that share one REALITY key pair and server name.

### TCP Vision

```text
network: tcp
security: reality
flow: xtls-rprx-vision
```

The generated link contains `type=tcp` and `flow=xtls-rprx-vision`.

### XHTTP

```text
network: xhttp
security: reality
path: <the path entered during installation>
```

The generated link contains `type=xhttp` and the URL-encoded XHTTP path.

Both inbounds use VLESS with `decryption: none`, REALITY, and Xray sniffing with HTTP, TLS, and QUIC destination overrides. The Docker Compose stack publishes TCP ports only; this project does not create a UDP listener.

## VLESS links

For every client UUID, the TUI generates links similar to:

```text
vless://UUID@SERVER:PORT?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&sni=api.github.com&fp=chrome&pbk=PUBLIC_KEY&sid=SHORT_ID#vless-vision-reality
```

```text
vless://UUID@SERVER:PORT?type=xhttp&encryption=none&security=reality&sni=api.github.com&fp=chrome&pbk=PUBLIC_KEY&sid=SHORT_ID&path=%2F#vless-xhttp-reality
```

The `sid` value is deterministically derived from the client UUID. The `pbk` value is derived from the REALITY private key and is distributed as part of the client link. Treat complete links and UUIDs as secrets because anyone who has one can use the server as that client.

Clients must support the selected VLESS transport and REALITY. Examples include Shadowrocket, v2rayNG, and v2rayN, subject to their support for the exact Xray transport options.

## Automatic updates on the VPS

The first installation creates two systemd timers.

### Operating system updates

`os-updater.timer` runs daily around `01:00` with a randomized delay of up to 13 minutes. It updates Debian packages, performs cleanup, and reboots the VPS when a kernel or package update requires it.

### Xray image updates

`docker-updater.timer` runs daily at `02:00`. It:

1. pulls `ghcr.io/xtls/xray-core:latest`;
2. stops the existing Compose stack;
3. recreates it with the existing `/opt/xray/config.json`;
4. prunes unused Docker images and build cache.

The Xray configuration is preserved during this update.

## Security considerations

- The tool operates as `root` on the remote VPS.
- The generated VLESS links are credentials; do not publish them.
- Use SSH keys and disable SSH password authentication after the initial setup.
- Choose an SNI that is a real TLS-capable hostname and reachable from the VPS.
- Keep generated client links private and remove keys that are no longer needed.
- Review the downloaded script before executing a one-line installer.

## License

MIT. See [LICENSE](./LICENSE).
