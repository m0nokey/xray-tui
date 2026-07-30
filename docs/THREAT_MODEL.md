# xray-tui threat model

This document describes the security boundaries of `xray-tui` as a local
control plane for independently operated Xray VPS nodes.

## Architecture and trust boundaries

```text
  User's computer
  +----------------------------+
  | Docker controller          |
  | xray-tui + Ansible         |
  | encrypted local Vault      |
  +-------------+--------------+
                |
                | SSH
                v
  VPS node
  +----------------------------+
  | Debian + Docker Compose    |
  | Xray + optional Unbound    |
  | systemd update services    |
  +-------------+--------------+
                |
                | upstream registries,
                | packages and DNS lists
                v
           External services
```

The main trust boundaries are:

1. The local host and the controller container.
2. The controller and each VPS over SSH.
3. Each VPS and external package, container, DNS, and blocklist providers.
4. VPN client devices and the Xray service exposed by a VPS.

## Protected assets

- the encrypted local Vault;
- the Vault password;
- initial SSH passwords retained for recovery and removal;
- deploy SSH private keys;
- Xray REALITY private keys;
- VPN access UUIDs and share links;
- VPS addresses, ports, host keys, and configuration;
- the availability and integrity of each VPN node.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Vault theft | Ansible Vault, AES-256, `0600`, local-only storage | Endpoint compromise or password leak |
| Temporary secret theft | Private tmpfs, restrictive permissions, cleanup | Local privileged attacker may observe a running process |
| SSH interception | Host keys, SSH hardening, rollback timer | VPS provider and recovery path must be trusted |
| SSH lockout | Configuration backup and emergency rollback | Recovery is harder without provider console access |
| Bad upstream update | Health checks, smoke tests, rollback | A bad release can still pass automated checks |
| Compromised source | Official repositories and release checksums | Upstream compromise is outside project control |
| Leaked VPN key | Per-user keys, revoke and rotation operations | A copied active key works until revoked |
| Bad DNS or blocklist update | TLS transport, validation, health checks | Lists may be stale, unavailable, or overblocking |
| Controller compromise | No Docker socket, read-only root, dropped capabilities | Controller still handles Vault and SSH secrets |
| VPS compromise | SSH hardening, minimal packages, automated updates | `xray-tui` cannot recover a compromised host |
| Blocking or denial of service | Multiple transports and optional DNS filtering | No protocol guarantees reachability |

## Accepted design decisions

### Floating runtime dependencies

The VPS runtime intentionally follows supported upstream versions. Xray uses the
upstream `latest` image tag, the controller uses current supported Alpine
packages, and the Ansible collection is installed from its upstream source.
This keeps unattended installations receiving compatibility and security fixes
even if `xray-tui` is no longer maintained.

The trade-off is reduced reproducibility and a dependency on upstream release
quality. CI scanning, smoke tests, health checks, and rollback reduce but do
not eliminate this risk.

### Local-only Vault

There is no cloud backup or server-side key database. This reduces the impact
of a central service compromise, but users must protect their computer, Vault
password, and encrypted backups.

### Initial SSH password retention

The initial SSH password remains encrypted in the Vault so that recovery,
reinstallation, and complete VPS removal can work without requiring a second
manual credential workflow. This increases the consequences of a compromised
Vault and is an explicit trade-off.

## Out of scope

This model does not cover:

- security of the user's operating system or endpoint applications;
- security of the VPS provider, datacenter, or network;
- vulnerabilities in Xray, Debian, Docker, Alpine, DNS providers, or blocklist
  projects beyond the controls described above;
- a formal cryptographic review of Ansible Vault, Xray, or REALITY;
- availability guarantees against censorship, filtering, or denial of service.
