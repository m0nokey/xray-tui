## Configurable VPN ports

- New nodes use randomly generated high TCP ports by default, preserving the
  original behavior.
- During setup, users can choose TCP port 443 for VLESS TCP Vision with REALITY
  and a generated high port for VLESS XHTTP.
- During setup, users can also enter both VPN ports manually.
- Manual ports must be different and must not overlap the generated SSH port.
- Existing nodes keep their current ports and are not changed automatically.
