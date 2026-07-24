# xray-tui

`xray-tui` is a simple console manager for Xray VPN servers and access keys.
It runs on your computer and lets you install, check, restart, update, and
remove Xray VPN servers through a menu. Access keys can be added or removed
individually without changing keys that are already in use.

The VPS runs Xray in Docker with two protocols:

- VLESS TCP with Vision and REALITY;
- VLESS XHTTP with REALITY.

## Supported VPS

Any VPS provider is supported when the target VPS runs **Debian 12 or newer**.

Ubuntu and other operating systems are not supported. The VPS must have:

- SSH access;
- an initial user with `sudo` access, usually `root`;
- password authentication available for the first installation;
- a public IP address or resolvable hostname.

The controller installs Docker, Xray, automatic updates, and SSH hardening on
the VPS. The initial SSH password is used only during Ansible operations and is
stored locally only inside the encrypted Vault.

## Requirements On Your Computer

You need:

- Docker with Docker Compose;
- Bash;
- an interactive terminal;
- `curl` for checking the Docker base image version.

You do not need to install Ansible, Python, SSH tools, or Xray on your
computer. They run inside the local Alpine-based controller container.

## Quick Start

```sh
git clone https://github.com/m0nokey/xray-tui.git
cd xray-tui
bash run.sh
```

On the first start, the controller builds its local container and asks you to
create a Vault password. Then choose `2. Add VPN server`.

The setup asks for:

1. VPS IP address or hostname;
2. initial SSH user, default `root`;
3. initial SSH port, default `22`;
4. initial SSH password;
5. Reality camouflage domain, default `github.com`.

After a successful deployment, the controller generates the VPN ports, REALITY
keys, paired access keys, and a new deploy SSH key. All sensitive connection
data is saved in the encrypted local Vault.

## Main Menu

```text
1. VPN servers
2. Add VPN server
3. Vault

i. info
x. exit
?:
```

Press `i` on any menu to see help for that screen. Press `Enter` after the
help text to return to the same menu. `b` goes back, `m` returns to the main
menu, and `x` exits the controller.

## Managing A Server

When a server is selected, the controller shows its IP address, status,
country, creation date, and provider.

```text
1. Manage VPN server
2. Manage access keys

b. back
m. main
i. info
x. exit
?:
```

### Manage VPN Server

```text
1. Check VPN status
2. Restart VPN server
3. Rotate SSH key
4. Remove VPN server
```

The status check tests management SSH access, the Xray container, and both VPN
ports:

```text
Active           Xray is running and both VPN ports are reachable.
Partial          Xray is running and only one VPN port is reachable.
VPN unavailable  The VPS responded, but Xray is not confirmed running.
Unreachable      No VPN or management port responded; DPI or a provider firewall may be involved.
```

`Rotate SSH key` creates a new deploy key, verifies it, and then revokes the
old key. The VPN access keys are not changed.

`Remove VPN server` removes the Xray installation, Docker stack, automatic
updaters, and the deploy account from the VPS. It restores the original SSH
configuration and removes the server from the Vault only after remote cleanup
has completed successfully.

### Manage Access Keys

```text
1. Show
2. Add
3. Remove
```

One access-key profile contains two UUIDs:

- one Vision UUID;
- one XHTTP UUID.

The `Show` action displays both client links. `Add` creates from 1 to 50 new
profiles in one operation. `Remove` shows the key numbers and both protocol
UUIDs, then removes the selected pair together. The last number removes all
access keys after confirmation.

## Vault

The Vault is a local encrypted file containing VPS access data, SSH keys, VPN
ports, REALITY material, and access-key UUIDs. It is created on the first
setup or through `Vault > Create Vault`.

The file is stored on your computer at:

```text
$HOME/.local/state/xray/vault.json
```

The Vault menu provides:

```text
1. Change encryption password
2. Backup encrypted state
3. Restore encrypted state
4. Delete Vault
```

The Vault password is never stored in the repository or on the VPS. Keep the
password and encrypted backups safe: the password cannot be recovered from the
Vault file.

## Security And Updates

Ansible configures the VPS through SSH and applies the following management
steps:

- creates the `deploy` management user with a generated SSH key;
- enables passwordless sudo for that management user;
- disables root and password SSH login after installation;
- generates a random non-default SSH management port;
- applies hardened SSH settings and rotates the SSH host key;
- runs Xray in Docker;
- installs automatic Debian security updates;
- installs a scheduled Docker image updater for Xray.

The Xray configuration is rendered on the VPS from the state supplied by the
local controller. The local Vault is the source of truth for managing nodes
and keys; no separate key database is created by the controller.

## Repository Layout

```text
xray-tui.sh                      interactive console manager
run.sh                           local launcher and image freshness check
tui/Dockerfile                    Alpine controller image
tui/compose.yml                  local hardened controller container
ansible/                          VPS playbooks, roles, and templates
scripts/state_cli.py              encrypted state operations
scripts/render_nodes.py           server table and status output
scripts/render_keys.py            paired VLESS link output
```

## License

MIT. See [LICENSE](./LICENSE).
