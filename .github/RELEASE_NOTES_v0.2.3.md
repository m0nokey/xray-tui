## User-visible changes

- Added a local Internet connectivity check before the VPS setup starts. The
  TUI checks outbound HTTPS from the computer running Xray TUI and shows a
  short retry screen when the local network is unavailable.
- Improved the VPS connection flow for unavailable SSH endpoints. Timeout,
  connection refused, connection closed, and routing errors now show the VPS
  address and port with an option to edit the connection. The TUI no longer
  retries an unavailable VPS automatically.
- Kept authentication failures separate from connection failures. When the
  VPS rejects the user or password, the TUI offers password retry or full
  connection editing.
- Fixed the `Review VPS connection` edit action. Editing now returns to the IP,
  SSH user, and port screens instead of reopening only the password prompt.
- Added a clear screen for unexpected VPS preflight failures instead of
  returning silently after the technical Ansible output is hidden.
- Reduced the VPS preflight SSH wait to a two-second delay and a nine-second
  timeout, making failed connections return faster.
- Fixed cleanup of temporary state when editing the connection during the
  review step.
- Fixed SSH port verification so a successful connection on the final retry
  is accepted correctly.

## Notes

- This is a patch release for the `v0.2` series.
- The password-based first-install flow remains unchanged.
- Existing VPN nodes do not need to be redeployed for these fixes.
