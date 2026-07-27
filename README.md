# xray-tui

`xray-tui` is a console manager for Xray VPN servers.

It runs on your computer and helps you:

```text
- install an Xray VPN on a VPS
- create and manage VPN access keys
- block ads, trackers, and known threats
- block selected countries on the VPS
- open an SSH session without remembering the port or password
- update or remove the VPN server
```

The connection data is stored in an encrypted local Vault.

> ⚠️ **Security Notice:**<br>
> Always review any script from the internet before running it on your system!

## Requirements

### Local computer

```text
- Docker
- Docker Compose
- Bash
- curl
- git
```

### VPS

```text
- Root/sudo access
- Supported OS: Debian 12+
- Public IPv4 address
- SSH password access for the first installation
- At least 1 vCPU and 1 GB RAM
```

## Quick Start

```sh
git clone https://github.com/m0nokey/xray-tui.git
cd xray-tui
bash run.sh
```

Without Git:

```sh
curl -fsSL https://github.com/m0nokey/xray-tui/archive/refs/heads/main.tar.gz | tar -xz
mv xray-tui-main xray-tui
cd xray-tui
bash run.sh
```

On the first run, create a password for the local encrypted Vault.

In the main menu choose:

```text
2. Add VPN server
```

Each input is shown on a separate screen. The previous screen is cleared.

```text
Enter VPS IP:
Enter VPS user [root]:
Enter VPS port [22]:
Enter VPS password:
```

```text
[!] Press Enter to use the default value shown in [brackets].
```

Before connecting, the manager shows the entered IP, user, port, and the
password status. Use `e. edit` if something is wrong.

Choose `a. continue`. The manager then checks:

```text
- SSH access
- VPS resources
```

If the check succeeds, choose a camouflage domain and protection profile:

```text
This domain helps the VPN connection look like normal HTTPS traffic.
Use a real HTTPS website that supports TLS 1.3.

Enter domain [github.com]:
Block ads and threats (optional):
Blocks malware, phishing, scams, ads, trackers, and telemetry.

Select a profile:
```

The default domain is `github.com`. You can change it according to your
country and camouflage strategy.

Choose a profile or press Enter for `Disabled`. You can enable blocking later
from `Manage VPN server`. Wait for the deployment to finish.

After a successful deployment, the manager saves the VPN ports, keys, and
connection data in the encrypted Vault.

## Main Menu

```text
1. VPN servers
2. Add VPN server
3. Vault

i. info
x. exit
?:
```

Use `i` to see help for the current screen. Use `b` to go back, `m` to return
to the main menu, and `x` to exit.

## Server Menu

The VPS list shows the important information at a glance:

```text
  Node Management:

     IP              STATUS   COUNTRY   CREATED      PROVIDER

  1. 203.0.113.42   Active   DE        2026-07-27   Example VPS
```

The terminal uses color for quick scanning: `Active` is green, `Partial` is
yellow, and unavailable states are red.

After selecting a VPS:

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
```

`Open SSH session` uses the saved management key and port from the Vault.

### VPN Status

```text
Active           Xray is running and both VPN ports are reachable.
Partial          Xray is running and only one VPN port is reachable.
VPN unavailable  The VPS responded, but Xray is not confirmed running.
Unreachable      No VPN or management port responded.
```

## Optional Protection

### Block Ads And Threats

Disabled by default. You can enable lists that block known domain names used
for:

```text
- malware and dangerous websites
- phishing and scams
- ads and pop-ups
- trackers and email tracking
```

The selected lists are loaded on the VPS. Larger profiles need more VPS CPU
and RAM, so the manager checks resources before deployment.

```text
- Minimal: 1 vCPU / 1 GB RAM
- Optimal: 1 vCPU / 1 GB RAM
- Full: 2 vCPU / about 2 GB RAM
- Maximum: 2 vCPU / about 2.5 GB RAM
- Custom: depends on the selected lists
```

```text
- Disabled - no blocking
- Minimal - malware and dangerous websites
- Optimal - malware, phishing, and scams
- Full - malware, ads, trackers, and telemetry
- Maximum - broad protection and known DNS bypass services
- Custom - choose additional categories
```

Some legitimate websites or Smart TVs may be affected. You can change or
disable protection later from the server menu.

The lists are provided by the
[HaGeZi DNS Blocklists project](https://github.com/hagezi/dns-blocklists).

### Block Countries

Select one or more countries to block on the VPS. This is useful when a VPN
client cannot configure local traffic bypass directly.

The policy applies to all access keys on that VPS. It blocks destination IP
ranges assigned to the selected countries. For Russia, selecting `RU` also
matches `.ru` and `.рф` domains.

This is not a VPN detection guarantee. CDNs, shared hosting, and geolocation
data can cause false positives.

## Access Keys

```text
1. Show
2. Add
3. Remove
```

Each access key contains two paired client links:

```text
- VLESS TCP Vision
- VLESS XHTTP
```

Removing a key removes both links together. Other keys are not changed.

## Vault

The Vault is a local encrypted file containing VPS access data, SSH keys, VPN
ports, REALITY keys, and access-key pairs.

```text
1. Change encryption password
2. Backup encrypted state
3. Restore encrypted state
4. Delete Vault
```

The Vault is stored at:

```text
$HOME/.local/state/xray/vault.json
```

The Vault password is not stored on the VPS and cannot be recovered from the
encrypted file.

## Remove A VPN Server

`Remove VPN server` cleans the VPS before deleting its Vault record.

```text
- stops and removes the Xray Docker stack
- removes updater services and Xray files
- removes the management user created by xray-tui
- restores the original SSH configuration
- removes the server from the local Vault after successful cleanup
```

If remote cleanup fails, the Vault entry is kept so the operation can be
retried.

## Technical Overview

```text
Your computer
    |
    | xray-tui
    | encrypted Vault
    | SSH / Ansible
    v
VPS
    |
    +-- Docker
    |     |
    |     +-- Xray VPN
    |     |
    |     +-- optional Unbound DNS protection
    |
    +-- hardened SSH management
    +-- automatic OS and Docker updates
```

The VPS runs:

```text
- VLESS TCP with Vision and REALITY
- VLESS XHTTP with REALITY in packet-up mode
```

When protection is enabled, Xray sends DNS requests through the private
Unbound container. Unbound uses DNS-over-TLS upstreams and blocklists. Blocked
domain names return `NXDOMAIN`.

The local Vault is the source of truth for VPS access and VPN keys. No
separate key database is created on the VPS.

## Repository Layout

```text
xray-tui.sh       interactive console manager
run.sh            local launcher
tui/              local controller container
ansible/          VPS playbooks and roles
scripts/          encrypted state and output helpers
```

## Legacy Version

The previous direct-SSH version is still available for reference and
compatibility.

Run it directly from GitHub:

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/m0nokey/xray-tui/refs/heads/main/legacy/xray-tui.sh')"
```

Or run the local copy:

```bash
bash legacy/xray-tui.sh
```

The legacy version does not include the current Vault, Ansible deployment, or
current server management flow. It will be removed in a future release.

## License

MIT. See [LICENSE](./LICENSE).
