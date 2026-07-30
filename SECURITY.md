# Security

`xray-tui` manages VPN infrastructure and stores sensitive access material on
the user's computer. It is not a hosted control plane and does not send Vault
contents or VPN keys to the project maintainers.

## Reporting a vulnerability

Please do not include passwords, Vault files, private keys, server credentials,
or working exploit details in a public issue.

For a vulnerability that is not publicly known, use GitHub's private security
reporting feature for this repository when available. If private reporting is
unavailable, contact the maintainers through the repository before publishing
technical details.

Public dependency-scan results may be reported in a normal issue when they do
not contain private infrastructure data. Include the exact image, release or
commit, scanner version, and a short reproducible result.

## Security model

- The controller runs locally inside a Docker container on macOS or Linux.
- The controller does not receive the local Docker socket.
- The controller image uses a read-only root filesystem, drops Linux
  capabilities, enables `no-new-privileges`, and writes persistent state only
  to the local state directory.
- The local Vault is encrypted with Ansible Vault. The current Vault format
  uses AES-256 encryption; the Vault password is not stored in the repository
  or in plaintext state files.
- VPS access data, deploy SSH keys, REALITY keys, and VPN access keys are kept
  in the encrypted local Vault.
- Keys are generated locally and transferred to the VPS over SSH during
  deployment.
- The VPS runs autonomously after deployment. It updates the operating system
  and VPN stack, checks service health, and can roll back a failed Xray stack
  update.

The detailed assets, trust boundaries, threats, controls, and residual risks
are documented in [the threat model](docs/THREAT_MODEL.md).

## Supply-chain policy

The project uses official repositories and upstream project sources. Runtime
dependencies intentionally track supported upstream versions instead of being
permanently pinned. This allows installations to continue receiving
compatibility and security updates if maintenance of `xray-tui` stops.

CI vulnerability scans, image smoke tests, service health checks, and rollback
logic reduce the risk of upstream changes, but they cannot guarantee that an
upstream release is safe or compatible.

This is a deliberate residual supply-chain risk. The current project does not
promise reproducible runtime images for every upstream component.

## User responsibilities

Users are responsible for:

- protecting the Vault password and the computer that stores the Vault;
- using a VPS provider with a working emergency or console recovery path;
- reviewing release notes and CI results before production use;
- keeping Xray-compatible client applications updated;
- downloading normal installations from a tagged GitHub Release and checking
  its SHA-256 checksum.

`xray-tui` cannot protect a Vault after the user's computer is compromised,
cannot protect a VPS after its operating system or provider is compromised,
and cannot guarantee availability against network blocking or denial of
service.

## Scope

This document describes the intended security architecture and accepted risks.
It is not a formal independent security audit, penetration test, or guarantee
that every upstream dependency or configuration is free of vulnerabilities.
