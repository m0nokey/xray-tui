## Controller and deployment fixes

- Use Alpine 3.24 consistently for the controller Dockerfile and the launcher.
- Keep the controller SSH KEX query unprivileged while retaining root access
  for remote VPS hardening tasks.
- Use the controller's writable temporary directory for delegated SSH queries
  instead of trying to create files under its read-only home directory.
- Bootstrap directly when connecting as root, and use sudo when connecting
  as a non-root SSH user. Subsequent management continues through `deploy`.
- Fix Ruff FURB162 and UP017 without changing UTC timestamp storage or the
  displayed creation date for ISO timestamps ending in `Z`.
- Add regression coverage for controller privilege isolation and creation dates.
- Validate the selected release tag in CI, including manually dispatched releases.
- Set XHTTP server mode to `auto` so clients can select `packet-up`, `stream-up`,
  or `stream-one`. New connection links default to `mode=auto`; existing
  `packet-up` profiles remain compatible after the server configuration is updated.
