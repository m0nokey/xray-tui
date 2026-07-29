## User-visible changes

- Added a clear stage-based progress pipeline for VPN installation, restart,
  access-key changes, DNS protection, country blocking, SSH rotation, and
  server deletion.
- Added a final 100% completion state with an operation-specific success
  message instead of leaving the user on an unfinished spinner.
- Improved menu input hints. Empty or invalid choices now explain the valid
  numbers and navigation keys for the current screen.
- Kept numeric actions separate from letter-based navigation throughout the
  TUI and aligned the menu spacing and prompts with the existing interface.
- Improved Vault backup, restore, deletion, and return-to-menu flows.
- Added a debug mode for troubleshooting Ansible operations while keeping the
  regular interface focused on progress instead of raw task output.
- Improved user-facing wording and ordering for destructive server and access
  key actions.

## Notes

- This is a patch release for the `v0.2` series.
- Existing VPN nodes do not need to be redeployed for these interface and
  troubleshooting improvements.
- The password-based first-install flow remains unchanged.
