# xray-tui

`xray-tui` is a simple console manager for Xray VPN servers and access keys.
It runs on your computer and lets you install, check, restart, update, and
remove Xray VPN servers through a menu. Access keys can be added or removed
individually without changing keys that are already in use.

> **Legacy version:** the old direct-SSH approach is preserved in the
> [`legacy/`](./legacy/) folder. It does not include the current VPS hardening
> and Ansible management flow. Use it only if you specifically need the old
> lightweight approach. The current project is the manager described below.

The VPS runs Xray in Docker with two protocols:

- VLESS TCP with Vision and REALITY;
- VLESS XHTTP with REALITY in `packet-up` mode.

The XHTTP server configuration and generated client links use the same
`packet-up` transport mode.

## Requirements

### Local computer

- Docker;
- Docker Compose;
- Bash;
- `curl`;
- `git` (or `tar` for an archive download);
- Internet connection;
- interactive terminal.

### VPS

- Root or `sudo` access for package installation;
- Debian 12 or newer;
- public IPv4 address or resolvable hostname;
- SSH password access for the first installation;
- at least 1 vCPU and 1 GB RAM for the VPN.

The VPS provider does not matter.

### Optional DNS protection

Disabled by default. It can block malware, phishing, scams, ads, trackers,
telemetry, and known DNS/VPN/proxy bypass domains. Some legitimate domains or
devices with their own encrypted DNS may be affected.

The manager checks VPS resources before deployment:

- `Minimal`: 1 vCPU, 1280 MB RAM;
- `Optimal`: 1 vCPU, 1280 MB RAM;
- `Full`: 2 vCPU, 1792 MB RAM;
- `Maximum`: 2 vCPU, 2304 MB RAM;
- `Custom`: calculated from the selected lists.

4 GB RAM is recommended for large profiles. These values are planning floors,
not hard memory limits.

## Install In 3 Steps

```sh
git clone https://github.com/m0nokey/xray-tui.git
cd xray-tui
bash run.sh
```

If Git is not installed, download the repository archive with `curl` and
extract it with `tar`:

```sh
curl -fsSL https://github.com/m0nokey/xray-tui/archive/refs/heads/main.tar.gz \
  | tar -xz
mv xray-tui-main xray-tui
cd xray-tui
bash run.sh
```

On the first start, the controller builds its local container and asks you to
create a Vault password.

### Step 1: choose `2. Add VPN server`

The setup asks for:

1. VPS IP address or hostname;
2. initial SSH user, default `root`;
3. initial SSH port, default `22`;
4. initial SSH password;
5. Reality camouflage domain, default `github.com`;
6. DNS protection profile, selected from the profiles supported by the VPS.

### Step 2: choose the protection

Select a DNS profile or leave protection disabled. You can also configure
country blocking later from the server menu.

### Step 3: wait for deployment

The manager installs Docker, Xray, SSH hardening, automatic updates, and VPN
access keys. After a successful deployment it saves the VPN ports, REALITY
keys, SSH key, and access-key pairs in the encrypted local Vault.

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
3. Block ads and threats
4. Block countries
5. Rotate SSH key
6. Remove VPN server
7. Open SSH session

b. back
m. main
i. info
x. exit
?:
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

`Block ads and threats` checks the VPS resources and lets you enable, disable,
or change the DNS protection profile later. The change is applied through
Ansible and saved to the Vault only after a successful deployment.

`Block countries` lets you select one or more countries to block on the VPS.
This is useful when a client cannot bypass local traffic directly. The policy
applies to all access keys on the node.

`Remove VPN server` removes the Xray installation, Docker stack, automatic
updaters, and the deploy account from the VPS. It restores the original SSH
configuration and removes the server from the Vault only after remote cleanup
has completed successfully.

`Open SSH session` connects to the VPS with the saved management user, SSH key,
and SSH port.

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
- optionally runs Unbound in a separate hardened Docker container with RPZ
  blocklists and DNS-over-TLS upstreams;
- installs automatic Debian security updates;
- installs a scheduled updater for the Xray `:latest` image and the optional
  Unbound image;
- validates the REALITY camouflage hostname before starting the Xray stack.

The Xray configuration is rendered on the VPS from the state supplied by the
local controller. The local Vault is the source of truth for managing nodes
and keys; no separate key database is created by the controller.

### DNS Protection

When enabled, Xray sends DNS queries through the private Unbound container.
Unbound uses DNS-over-TLS upstreams and RPZ blocklists. The Xray container has
no direct DNS fallback, and direct outbound DNS ports are blocked by routing.

Profiles:

- `Disabled`: no blocklists and the lowest resource usage;
- `Minimal`: URLhaus malware-delivery domains;
- `Optimal`: URLhaus plus HaGeZi TIF Mini for malware, phishing, scams,
  cryptojacking, and command-and-control domains;
- `Full`: URLhaus, HaGeZi Encrypted DNS, AdGuard CNAME tracker lists,
  AdGuard Mail Trackers, ThreatFox, and HaGeZi Pro++;
- `Maximum`: broad threat feeds, bypass protection, tracker protection,
  dynamic DNS threats, suspicious spam TLDs, and threat-intelligence IPs;
- `Custom`: URLhaus plus selected additional sources, with resource and
  compatibility checks before deployment.

`HaGeZi Encrypted DNS` is included in Full and can be disabled through
Custom because some Smart TVs and VPN clients use their own encrypted DNS.
The Xray tunnel itself is not affected, but an application may lose DNS
resolution if its resolver is listed.

The `Full` profile can run on a 2 GB VPS, but 4 GB RAM is recommended because
large RPZ lists consume more memory while loading and updating. Blocked names
return `NXDOMAIN`, and aggressive lists can occasionally block legitimate
domains.

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
