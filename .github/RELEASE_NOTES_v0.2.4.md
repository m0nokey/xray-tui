## User-visible changes

- Fixed DNS protection updates when an Xray node already has a running
  Unbound container. Configuration validation now checks the running
  container directly instead of starting a disposable container with the
  same static network address.
- Kept validation safe for a first deployment. If Unbound is not running,
  the configuration is checked in a disposable container before the service
  is started.
- Fixed access-key management after enabling or changing DNS protection.
  Adding and removing access keys no longer fails because the Unbound
  validation container cannot claim the service network address.
- Moved Xray configuration rendering and service restart ordering so the
  Unbound configuration is validated before the updated DNS service is
  recreated.
- Fixed the confirmation prompt alignment on the Remove access key screen.
  The prompt now uses the same `?:` layout as the other TUI screens.

## Notes

- This is a patch release for the `v0.2` series.
- Existing VPN nodes do not need to be redeployed unless you want to apply a
  DNS protection change or manage access keys after upgrading.
- The password-based first-install flow remains unchanged.
