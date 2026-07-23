# xray-tui

An Alpine-based local controller for deploying and managing a small Xray VPN
server through SSH and Ansible. The VPS runs one hardened Xray container. The
controller does not require Docker on the VPS beyond the Docker runtime used
by that container and does not create a server-side key database.

## What it does

- deploys VLESS TCP Vision and VLESS XHTTP with REALITY;
- generates ports, REALITY material, and paired access keys locally;
- stores all sensitive data in an encrypted Ansible Vault;
- adds or revokes one access-key pair without changing other users;
- checks and restarts a VPN server over SSH;
- rotates the deploy SSH key;
- applies baseline VPS SSH and Docker hardening through Ansible.

The Vault contains VPS access data, deploy keys, VPN ports, REALITY keys, and
paired client UUIDs. It is stored under `$HOME/.local/state/xray`, encrypted at
rest, and never committed to Git or copied to the VPS as a database.

## Requirements

The host needs Bash and Docker Compose. The local `xray-tui` image is built from
Alpine and contains only the controller runtime: `ansible-playbook`,
`ansible-vault`, `ssh`, `ssh-keygen`, `curl`, Python, and PyNaCl. It has a
read-only root filesystem, no Docker socket, no Linux capabilities, a
non-privileged security profile, process and resource limits, and a small
`tmpfs` for temporary files.

The VPS must be a Debian-based system with root SSH access for its first
deployment. The controller asks for the current root SSH password and passes
it to Ansible only inside the container. Ansible creates the `deploy` user, installs its generated public
key, disables root and password SSH login, and starts the Docker service.

## Start

```sh
./run.sh
```

The first run creates the local Vault password. Add a VPS from the menu, enter
its address and the initial root SSH password, and the controller will
generate the local state and deploy the server automatically.

## Menu

```text
1. VPN servers
2. Add VPN server
3. Vault

x. exit
?:
```

For a selected server:

```text
VPN Server:

           IP               STATUS   COUNTRY   CREATED      PROVIDER

           203.0.113.10     Active   DE        2026-07-23   Example Provider

  1. Manage VPN server
  2. Manage access keys

  b. back
  m. main
  x. exit
  ?:
```

Server management:

```text
Manage VPN server:

  1. Check VPN status
  2. Restart VPN server
  3. Rotate SSH key
  4. Remove VPN server

  b. back
  m. main
  x. exit
  ?:
```

Access-key management:

```text
Manage access keys:

  1. Show keys
  2. Add key
  3. Remove key

  b. back
  m. main
  x. exit
  ?:
```

Each access-key profile contains two links, one for Vision and one for XHTTP.
Removing a profile revokes both UUIDs together.

## Layout

```text
tui/Dockerfile                   Alpine xray-tui image
tui/compose.yml                  hardened local container
ansible/                         VPS roles and templates
scripts/state_cli.py             local Vault state operations
scripts/render_nodes.py          aligned node/status table
scripts/render_keys.py           paired VLESS link output
xray-tui.sh                      interactive controller
run.sh                            local entrypoint
```

The generated Vault and private keys are outside the repository. The bootstrap
password is cleared from the Vault after the deploy user is verified. Back them up
only as encrypted Vault data.

## License

MIT. See [LICENSE](./LICENSE).
