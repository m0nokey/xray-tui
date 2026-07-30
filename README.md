# xray-tui

`xray-tui` is a simple terminal-based (TUI) manager for your own Xray VPN
infrastructure.

It provides centralized management of deployed VPN servers and their access
from one interface. You can add VPS nodes, configure them, check their status,
and issue or revoke VPN access keys without manually editing configuration
files.

`xray-tui` is not a VPN client. It manages the servers that user devices
connect to.

The program runs on your macOS or Linux computer inside a Docker container.
Server data, SSH access, and VPN keys are stored only on your computer in a
local encrypted Vault. They are not sent to a cloud service and are not stored
in the project repository.

After the initial deployment, each VPS works autonomously. It runs Xray,
performs scheduled updates, checks the VPN stack, and recovers from a failed
Xray update.

It helps you:

```text
- install an Xray VPN on a VPS
- create and manage VPN access keys
- block ads, trackers, and known threats
- block selected countries on the VPS
- open an SSH session without remembering the port or password
- update or delete the VPN server
```

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

### Linux Docker access

`xray-tui` does not need to be started with `sudo`.

On Linux, the current user must have permission to access the Docker daemon.
If Docker reports a permission error for `/var/run/docker.sock`, configure
Docker access once:

```sh
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

If the Docker service is not running:

```sh
sudo systemctl enable --now docker
```

Do not run `sudo bash run.sh`, because this can make the local Vault and
controller files owned by `root`.

### VPS

```text
- Root/sudo access
- Supported OS: Debian 12+
- Public IPv4 address
- SSH password access for the first installation
- At least 1 vCPU and 1 GB RAM
```

## Quick Start

For normal use, download the latest stable release from the
[GitHub Releases page](https://github.com/m0nokey/xray-tui/releases/latest).
Release archives include a SHA-256 checksum and are the recommended way to run
`xray-tui`.

```sh
curl -fsSL --proto '=https' -O "https://github.com/m0nokey/xray-tui/releases/latest/download/xray-tui-latest.tar.gz" \
&& curl -fsSL --proto '=https' -O "https://github.com/m0nokey/xray-tui/releases/latest/download/SHA256SUMS" \
&& grep -F "xray-tui-latest.tar.gz" SHA256SUMS | sha256sum -c - \
&& tar -xzf xray-tui-latest.tar.gz \
&& cd "$(tar -tzf xray-tui-latest.tar.gz | sed -n '1s#/.*##p')" \
&& bash run.sh
```

The `releases/latest` link always points to the newest stable release. The
README does not need to be changed for every patch release.

For development and testing, use the `main` branch instead:

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
password status. Choose `2. Edit` if something is wrong.

Choose `1. Continue`. The manager then checks:

```text
- SSH access
- VPS resources
```

If the check succeeds, the manager asks for a camouflage domain:

```text
Add VPN server

This domain helps the VPN connection look like normal HTTPS traffic.
Use a real HTTPS website that supports TLS 1.3.
Press Enter to use the default value shown in [brackets].

Enter domain [github.com]:
```

After the domain screen, choose an optional DNS protection profile:

```text
Block ads and threats

Optional. Blocks malware, phishing, scams, ads, trackers, and telemetry.
Current: disabled

1. Disabled  No blocking
2. Minimal   Malware protection
3. Optimal   Malware, phishing and scams
4. Full      Malware, ads and tracking
5. Maximum   Broad protection and DNS bypass
6. Custom    Choose protection categories

Not sure what to choose? Press Enter to keep it disabled.
You can enable it later from the VPN management menu.

?:
```

The default domain is `github.com`. You can change it according to your
country and camouflage strategy. The availability of DNS profiles depends on
the detected VPS CPU and memory resources.

After selecting a profile, wait for the deployment to finish.

During deployment, normal mode shows a short stage-based progress screen:

```text
Installing VPN server

  [ 10%] Checking the VPS connection                  done
  [ 20%] Checking VPS system                          done
  [ 30%] Preparing VPS access                         done
  [ 35%] Reconnecting after bootstrap                 done
  [ 40%] Hardening SSH access                         done
  [ 50%] Verifying hardened SSH access                done
  [ 60%] Installing Docker and system packages        done
  [ 70%] Rendering VPN configuration                  done
  [ 80%] Validating Xray and DNS configuration        done
  [ 90%] Starting and checking VPN stack              done
  [100%] VPN server added successfully.               done
```

The percentages represent deployment stages, not individual Ansible tasks.
They are intended to show what the manager is doing while the remote operation
is running.

After a successful deployment, the manager saves the VPN ports, keys, and
connection data in the encrypted Vault.

### Debug mode

If an operation fails and you need the technical output for an issue, run:

```sh
bash run.sh --debug
```

Debug mode shows the raw Ansible output in the terminal and keeps it visible
until you press Enter. This makes it possible to copy the failure details into
an issue. It does not create a permanent log file on the host. The normal mode
shows only the user-facing progress and result messages.

## Managing Multiple Nodes

One instance of `xray-tui` running in Docker can manage multiple VPS nodes.

Each node has its own connection settings, SSH access, VPN ports, access keys,
DNS protection settings, and server status.

When the server list is checked, up to 16 nodes are checked concurrently. If
there are more nodes, the remaining checks wait for an available slot and run
automatically in the same refresh cycle.

Deployment, configuration changes, and removal are currently performed for one
selected node at a time. Autonomous updates run independently on every VPS.

The server list and status display are shown in the Server Menu below.

## How It Works

`xray-tui` runs in Docker on the user's computer and connects to VPS nodes over
SSH. Ansible performs the initial server configuration. After deployment, each
node continues to operate independently.

```text
                              CONTROL PLANE

  +-------------------------+       SSH / Ansible       +-------------------------+
  | User's computer         | ------------------------> | VPS node                |
  |                         |                           |                         |
  | xray-tui in Docker      |                           | Debian + Docker Compose |
  | encrypted local Vault   |                           |                         |
  +-------------------------+                           |  +-------------------+  |
                                                        |  | Xray              |  |
  +-------------------------+       VPN connection      |  | Vision + REALITY  |  |
  | VPN client devices      | ------------------------> |  | XHTTP + REALITY   |  |
  | phone / laptop / tablet |                           |  | packet-up         |  |
  +-------------------------+                           |  +---------+---------+  |
                                                        |            |            |
                                                        |            | DNS        |
                                                        |            v            |
                                                        |  +-------------------+  |
                                                        |  | Unbound           |  |
                                                        |  | RPZ blocklists    |  |
                                                        |  | NXDOMAIN          |  |
                                                        |  +---------+---------+  |
                                                        +------------|------------+
                                                                     |
                                                                 DNS-over-TLS
                                                          Cloudflare / AdGuard DNS
                                                                     |
                                                                     v
                                                                  Internet
```

Xray and Unbound run as separate services in the same Docker Compose stack.
Xray handles VPN connections. When DNS protection is enabled, Xray sends DNS
queries to the private Unbound service. Unbound applies RPZ blocklists and
forwards allowed queries over DNS-over-TLS.

The user's computer does not need to stay powered on. After deployment, the VPS
continues to run and maintain itself.

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

  Fleet status: 4 Active, 1 Partial

     IP              STATUS   COUNTRY   CREATED      PROVIDER

  1. 203.0.113.42   Active   DE        2026-07-27   Hetzner Online GmbH
  2. 198.51.100.17  Active   US        2026-07-26   Amazon Technologies Inc.
  3. 192.0.2.24     Active   NL        2026-07-25   DigitalOcean, LLC
  4. 203.0.113.88   Active   GB        2026-07-24   Google LLC
  5. 198.51.100.64  Partial  SG        2026-07-23   Vultr Holdings LLC
```

The terminal uses color for quick scanning: `Active` is green, `Partial` is
yellow, and unavailable states are red. In this example, four nodes are fully
operational and the Singapore node has a degraded VPN status: Xray is running,
but only one of its VPN ports is reachable. The IP addresses above use
documentation-only ranges and are examples rather than real servers.

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
2. Open SSH session
3. Restart VPN server
4. Block ads and threats
5. Block countries
6. Rotate SSH key
7. Delete VPN server
```

`Open SSH session` uses the saved management key and port from the Vault.

### VPN Status

```text
Active           Xray is running and both VPN ports are reachable.
Partial          Xray is running and only one VPN port is reachable.
VPN unavailable  The VPS responded, but Xray is not confirmed running.
Unreachable      No VPN or management port responded.
```

## Autonomous Operation And Updates

After deployment, independent system services are installed on the VPS. They:

- update Debian and the Docker/Xray stack every night;
- reboot the VPS when a kernel update requires it;
- check the stack after an update;
- restore the previous working Xray version if an update fails.

Both the server and client parts of Xray should be kept up to date. New versions
fix vulnerabilities, improve compatibility, and reduce the chance that outdated
protocol characteristics will be recognized and blocked by DPI.

For this reason, client applications on user devices should also be updated
after a server update. This does not guarantee that a connection will never be
blocked, but it is the safest and most reliable way to operate Xray.

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
3. Delete
```

Each access key contains two paired client links:

```text
- VLESS TCP Vision
- VLESS XHTTP
```

Deleting a key deletes both links together. Other keys are not changed.

## Vault

The Vault is a local encrypted file containing VPS access data, SSH keys, VPN
ports, REALITY keys, and access-key pairs.

The Vault is encrypted using the standard Ansible Vault format:

```text
$ANSIBLE_VAULT;1.1;AES256
```

The format uses:

- AES-256 in CTR mode;
- PBKDF2-HMAC-SHA256 for password-based key derivation;
- 10,000 PBKDF2 iterations;
- HMAC-SHA256 for ciphertext integrity;
- a salt stored in the encrypted Vault.

The Vault password is not stored on the user's computer or on any VPS. If the
password is lost, the Vault cannot be recovered.

Ansible Vault protects data at rest. SSH protects the connection while the
controller communicates with a VPS.

```text
1. Change encryption password
2. Backup encrypted state
3. Restore encrypted state
4. View backups
5. Delete Vault
```

The Vault is stored at:

```text
$HOME/.local/state/xray/vault.json
```

The Vault password is not stored on the VPS and cannot be recovered from the
encrypted file.

Before each successful Vault replacement, the previous encrypted file is saved
as an automatic recovery copy in `backups/system/`. The newest 20 copies are
kept and older copies are deleted automatically. `Backup encrypted state`
creates a separate user-created `tar.gz` archive in `backups/user/`; user archives
are not part of the automatic rotation. `View backups` lists user archives
with their UTC timestamp and full path. Automatic recovery copies are internal
and are not shown. `Restore encrypted state` lets you select a user archive
by number, so you do not need to enter a path manually.

If the Vault file is damaged or decrypts to invalid state, xray-tui does not
delete it or create an empty replacement. It moves the original to a timestamped
`.corrupt.*` file, keeps it protected with owner-only permissions, and stops
until a valid backup is restored.

The complete local structure is:

```text
$HOME/.local/state/xray/
├── vault.json
└── backups/
    ├── user/     user-created encrypted archives
    └── system/   automatic recovery copies
```

### Restore On Another Computer

Use a user backup when moving the Vault to another computer.

1. On the old computer, choose `Vault` and `Backup encrypted state`.
2. Copy the created `vault-*.tar.gz` file to this directory on the new computer:

```text
$HOME/.local/state/xray/backups/user/
```

3. Start xray-tui and choose `Vault` and `Restore encrypted state`.
4. Select the backup by number and enter the Vault password when requested.

Create the `backups/user` directory first if it does not exist. The Vault does not
need to be initialized before restoring a backup. With the Docker launcher,
`/state/xray` is the path inside the container; the host path above is the
directory to use for copying files. The password is not included in the
backup and must be remembered separately.

The `.local` directory is hidden in most file managers. Use the terminal to
copy the backup to a visible folder before transferring it:

```bash
ls -lh "$HOME/.local/state/xray/backups/user/"
cp "$HOME/.local/state/xray/backups/user"/vault-*.tar.gz "$HOME/Downloads/"
```

After copying the file to the new computer, place it into the Vault backup
directory:

```bash
mkdir -p "$HOME/.local/state/xray/backups/user"
cp "$HOME/Downloads"/vault-*.tar.gz "$HOME/.local/state/xray/backups/user/"
chmod 600 "$HOME/.local/state/xray/backups/user"/vault-*.tar.gz
```

Then start xray-tui, open `Vault`, choose `Restore encrypted state`, and select
the user backup by number.

Automatic files in `backups/system/` are intended for internal local recovery.
They are not part of the user backup browser; use a user `tar.gz` backup for
recovery and migration.

### Repeatable Use Without Keeping The Repository

After a VPS has been deployed, it does not depend on the local project directory
or the local `xray-tui` Docker image. You may remove the cloned repository and
the local image without interrupting the VPN on the VPS.

Do not delete the local state directory:

```text
$HOME/.local/state/xray/
```

This directory contains the encrypted Vault with the infrastructure state.

When you need to issue new keys, change settings, or remove a VPS, download the
latest stable release archive and run it again. You do not need to keep the
repository or the local controller image between runs.

Use the same verified Release installation commands from `Quick Start` above.

`xray-tui` finds the existing Vault on the computer and asks for its password.
After unlocking it, your VPS nodes, SSH access, VPN keys, and infrastructure
settings become available again.

## Delete A VPN Server

`Delete VPN server` cleans the VPS before deleting its Vault record.

```text
- stops and deletes the Xray Docker stack
- deletes updater services and Xray files
- deletes the management user created by xray-tui
- restores the original SSH configuration
- deletes the server from the local Vault after successful cleanup
```

If remote deletion fails, the Vault entry is kept so the operation can be
retried.

## Software Sources And Supply Chain

The project uses official repositories and upstream project sources instead of
arbitrary binaries or unverified installation scripts.

- The local controller runs from the official `alpine:3.23` image.
- Ansible, OpenSSH, Python, and supporting tools are installed from Alpine
  repositories.
- VPS system packages are installed from the official Debian and Debian
  Security repositories.
- Docker Engine, Docker CLI, and the Compose plugin are installed from Docker's
  official Debian APT repository and verified with Docker's GPG key.
- Xray runs from the upstream image `ghcr.io/xtls/xray-core:latest`.
- Unbound is built on the VPS from the official `alpine:3.23` base image, with
  the Unbound package installed from Alpine repositories.
- DNS protection lists are downloaded from their upstream projects, including
  HaGeZi, AdGuard, URLhaus, and ThreatFox.

Repository sources and signatures are configured by Ansible during deployment
and are used again during automatic updates.

Every release is published only after the full CI pipeline succeeds. Release
assets include an SPDX SBOM, and GitHub artifact attestations record the build
provenance of the archives and checksum manifest.

### Floating Runtime Dependencies

Runtime dependencies intentionally track supported upstream versions instead
of being permanently pinned. This allows installations to continue receiving
compatibility and security updates if maintenance of `xray-tui` stops.

The current runtime model includes the upstream Xray image tag, current Alpine
packages, the `community.docker` Ansible collection, Debian packages, and
upstream DNS protection lists. CI vulnerability scanning, image smoke tests,
VPN health checks, and automatic rollback reduce the risks of upstream changes.

This is a deliberate supply-chain trade-off: floating dependencies improve
long-term compatibility and unattended security updates, but reduce
reproducibility and depend on upstream release quality. See
[`SECURITY.md`](SECURITY.md) and the [threat model](docs/THREAT_MODEL.md) for
the detailed assumptions and accepted risks.

## Technical Overview

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
lib/              focused Bash runtime modules
run.sh            local launcher
tui/              local controller container
ansible/          VPS playbooks and roles
scripts/          encrypted state and output helpers
```

## License

MIT. See [LICENSE](./LICENSE).
