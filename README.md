# xray-tui

A minimal, Dockerized TUI to install and manage **Xray (VLESS-TCP-XTLS-Vision-REALITY)** on your VPS over SSH — without installing tools on your local macOS/Linux host.

> ⚠️ **Security Notice:**  
> Always review any script from the internet before running it on your system!

---

## Requirements

- **Local (your computer):** Docker installed (Docker Desktop on macOS, Docker Engine on Linux). The manager runs **inside a container**, keeping your host clean.
- **Remote VPS:** **Debian 12+ only** (root SSH access).

---

## Nightly auto-updates on the VPS

Every night, your VPS will automatically update:
- the **OS** (security/regular updates),
- **Docker**,
- **docker-compose**,
- the **Xray** image (`ghcr.io/xtls/xray-core:latest`).

No manual maintenance required.

---

## Fastest path to your own VLESS‑REALITY‑Vision server

1) **Run the script on your macOS/Linux host**

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/m0nokey/xray-tui/refs/heads/main/xray-tui.sh')"
```

This pulls and runs the Dockerized TUI client. Nothing is installed on your host system.

2) **Enter your VPS credentials**

Example (TUI prompts):
```
Enter VPS IP address: 1.2.3.4
Enter VPS port (default 22): 22
Enter VPS password:
```

3) **Install Xray on the VPS (if not present yet)**

From the home screen:
```
xray › home
____________________
Server

2.   Install / Reinstall Xray (deploy from scratch)
```

This installs Docker (if missing), writes the Xray config and compose file, and starts the official Xray container.

4) **Issue one or many access links**

From the home screen:
```
xray › home
____________________
Access

6.   Issue new access links (create N new links)
```

Choose how many links you want (e.g., 1–100). The TUI will print ready-to-use **VLESS‑REALITY** URLs.

**Done.** Share the links with your devices and connect.

---

## Notes

- The manager prints links in full (including `uuid`, `sid`, `pbk`, `sni`, port, etc.).
- You can list existing links, remove one, or remove all at any time.
- After the initial setup, consider switching your VPS to **SSH key-based auth**.

---

## Security Notice

**Always review scripts before running them.**  
This tool connects to your VPS as **root** to provision and manage Docker/Xray. Keep your credentials safe and rotate them if needed.

---

## license

licensed under the mit license. see [license](./LICENSE) for details.
