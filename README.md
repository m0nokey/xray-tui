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

## Supported VPS

The VPS provider does not matter. The target VPS must run **Debian 12 or
newer**. Only Debian 12+ VPS are supported.

The target VPS must also meet all of these requirements:

- a public IPv4 address or resolvable hostname;
- an initial SSH user with `sudo` access, usually `root`;
- password authentication available for the first installation;
- at least 1 vCPU and 1 GB RAM for the VPN itself.

Optional DNS protection is disabled by default. When enabled, it can block DNS
requests to malicious domains, phishing sites, trackers, advertising,
telemetry, and command-and-control servers. It uses additional VPS resources
and may block some legitimate domains. The profile can be enabled or changed
later.

Available DNS protection profiles have these requirements:

- `Minimal`: at least 1 vCPU and 768 MB RAM;
- `Optimal`: at least 1 vCPU and 1536 MB RAM;
- `Full`: at least 2 vCPU and 1800 MB RAM; 4 GB RAM is recommended;
- `Maximum`: at least 2 vCPU and 3072 MB RAM; 4 GB RAM is recommended;
- `Custom`: starts with URLhaus and checks every selected source against the
  detected VPS resource floor.

The installer checks the VPS resources before deployment and marks profiles
that do not fit. DNS protection is optional and can be disabled.

During deployment, the controller:

- installs Docker and Xray;
- configures automatic operating-system and Docker updates;
- applies VPS SSH hardening;
- generates VPN ports, REALITY keys, access keys, and a management SSH key;
- stores sensitive VPS and VPN data locally inside the encrypted Vault.

The initial SSH password is used only during Ansible operations. It is not
stored on the VPS.

## Requirements On Your Computer

You need:

- Docker with Docker Compose;
- Bash;
- an interactive terminal;
- `git` to clone the repository, or `curl` and `tar` to download it without Git.

Debian 12+ is required for the VPS, not for the local computer. The local
computer can be macOS or Linux.

You do not need to install Ansible, Python, SSH tools, or Xray on your
computer. They run inside the local Alpine-based controller container.

## Quick Start

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
create a Vault password. Then choose `2. Add VPN server`.

The setup asks for:

1. VPS IP address or hostname;
2. initial SSH user, default `root`;
3. initial SSH port, default `22`;
4. initial SSH password;
5. Reality camouflage domain, default `github.com`;
6. DNS protection profile, selected from the profiles supported by the VPS.

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
3. DNS protection
4. Rotate SSH key
5. Remove VPN server
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

`DNS protection` checks the VPS resources and lets you enable, disable, or
change the DNS protection profile later. The change is applied through Ansible
and saved to the Vault only after a successful deployment.

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
