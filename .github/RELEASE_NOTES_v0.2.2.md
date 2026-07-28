## User-visible changes

- Fixed the first VPS connection flow after a successful resource check. The
  setup no longer returns to the IP address screen after the VPS is accepted.
- Invalid SSH passwords are detected before Ansible starts its long connection
  retry cycle. You can enter the password again or edit the VPS connection.
- Improved removal of hardened VPN servers. Cleanup first uses the saved
  management key on the current SSH port, then reconnects with the original
  bootstrap credentials to restore SSH and remove the deploy account.
- Remote cleanup and local Vault removal remain separate. The server is removed
  from the Vault only after remote cleanup succeeds, unless the user explicitly
  chooses local removal after a failed cleanup.
- Fixed SSH host-key reporting during hardening. The generated public key and
  fingerprint are now returned reliably and cannot be shadowed by extracted
  Vault variables.

## Notes

- This is a patch release. The existing password-based first-install flow is
  unchanged.
- Existing VPN nodes do not need to be redeployed for these fixes.
