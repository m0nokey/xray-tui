# Ansible deployment

This branch deploys the simple two-transport Xray stack through Ansible.
Ansible connects over SSH without an agent on the VPS. The Xray deployment
uses one Docker container; no management container or server-side key state is
created.

The local `xray-tui` container is Alpine-based and contains Ansible, OpenSSH, curl,
Python, and PyNaCl. It does not contain Docker or a Docker socket. Its root
filesystem is read-only, all Linux capabilities are dropped, and it has strict
process, memory, CPU, and temporary-filesystem limits. REALITY keys are
generated locally with PyNaCl, using the same method as the original
`xray-tui` implementation.

An access key is a management profile, not an operating-system user and not a
separate Xray server account. Each profile contains two independent Xray
clients:

- `vision_uuid` for VLESS TCP Vision;
- `xhttp_uuid` for VLESS XHTTP in `packet-up` mode.

Both entries carry the same `key_id` in Xray's `email` field. That field pairs
the two credentials so a revoke operation removes exactly one profile from
both inbounds. Other profiles are unchanged.

The intended list output is:

```text
1.
vless://...vision...
vless://...xhttp...

2.
vless://...vision...
vless://...xhttp...
```

There are no legacy `xray › ...` headers in the new interface.

## Controller menu

```text
1. VPN servers
2. Add VPN server
3. Vault

x. exit
?:
```

For a selected server:

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

Access keys are managed separately:

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

The `Vault` menu manages the local encrypted storage containing VPS access
credentials, deploy SSH keys, REALITY keys, VPN ports, and access-key pairs.
The Vault is encrypted at rest and its password is created on the first run.
If the computer is stolen, the stored data cannot be used without that Vault
password.

```text
Vault:

1. Change encryption password
2. Backup encrypted state
3. Restore encrypted state

b. back
m. main
x. exit
?:
```

## Local setup

```sh
./run.sh
```

The `xray-tui` container mounts the repository read-only and mounts only
`$HOME/.local/state/xray` as writable state. It communicates with VPS nodes
over SSH.

The `./run.sh` entrypoint starts the interactive controller. It creates the
Vault on first use, asks for the initial SSH user, port, and password when a node is added,
generates all Xray material locally, and runs the Ansible deployment. The
controller is the only supported way to change access keys or deploy state;
there is no plaintext `state.json` or manual inventory step.

The local `xray-tui` controller keeps the generated ports, REALITY key pair, short ID, access
key pairs, the deploy SSH key, and encrypted initial SSH credentials under `$HOME/.local/state/xray/`. The
directory is protected locally and never belongs to the Git worktree. Ansible transfers only the
rendered files over SSH and does not create a second access-key database on
the VPS.

The controller asks for the Reality camouflage hostname (SNI) when a new node
is added. It stores that value in the encrypted node state and uses it for the
Xray `serverNames`, Reality destination, and both generated client links.
Before the stack starts, Ansible validates the hostname with the Xray TLS
probe. Xray runs from `ghcr.io/xtls/xray-core:latest`; the scheduled updater
pulls that tag and refreshes the Xray container.
The initial SSH address, port, user, and password remain encrypted in the
Vault for bootstrap recovery, reinstall, and removal fallback, then disappear
when the node record is deleted.

Restart and removal are also Ansible operations. The controller invokes
`restart.yml` or `remove.yml`; it does not run Docker commands or delete VPS
files directly over SSH. Before hardening, the original SSH configuration,
host keys, and managed APT source file are backed up under
`/var/lib/xray-tui/`. Removal stops and removes the Xray Compose project,
updater timers, Docker packages, and Xray TUI files; restores the original
SSH and APT files; removes the Xray TUI-created `deploy` user; and leaves the
timezone at UTC. Cleanup refuses to proceed when the original SSH
configuration backup is missing.
