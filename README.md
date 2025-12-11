# xray-tui

A small text UI (TUI) tool to install and manage **Xray (VLESS-XHTTP-REALITY)** on your Debian VPS over SSH — without installing anything on your local machine except Docker.

You run **one command** on your laptop/PC, then use a simple menu to:

- Install Xray on a fresh VPS
- Generate ready-to-use VLESS links
- List / add / remove access keys

> ⚠️ Security Notice  
> Always review scripts from the internet before running them on your system.

---

## What it does

On your **remote VPS (Debian 12+)**, the tool will:

- Install **Docker** if it is not installed
- Pull the official Xray image: `ghcr.io/xtls/xray-core:latest`
- Create a **VLESS-XHTTP-REALITY** server:
  - Protocol: VLESS
  - Transport: `network: xhttp`
  - Security: REALITY (TLS camouflage to a real site)
- Set up nightly auto-updates for:
  - Debian OS (security and regular updates)
  - Docker and docker-compose plugin
  - Xray image

You end up with:

- `/opt/xray/config.json` – Xray configuration
- `/opt/xray/docker-compose.yaml` – Docker stack
- A running `xray` container managed entirely from the TUI

---

## Requirements

### Local machine (your laptop/PC)

- macOS or Linux
- **Docker** installed:
  - macOS → Docker Desktop
  - Linux → Docker Engine

The TUI runs **inside a Docker container**. It does not install Python, Go, Node, or anything else on your host.

### Remote VPS

- Debian **12 or newer**
- Root SSH access (password is fine for the first run)

---

## Auto-updates on the VPS

Once installed, the VPS will automatically:

- Update Debian packages daily
- Keep Docker and docker-compose plugin up to date
- Pull the latest `ghcr.io/xtls/xray-core:latest`
- Restart the Xray stack with the same configuration

You do not need to log in regularly just to update Xray.

---

## Quick start

### 1. Run the TUI from your local machine

On macOS or Linux:

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/m0nokey/xray-tui/refs/heads/main/xray-tui.sh')"
```

This:

- Pulls a small Docker image
- Starts **xray-tui** inside Docker
- Opens a text menu in your terminal

Nothing is permanently installed on your local system (only a Docker image).

---

### 2. Connect to your VPS

The TUI will ask:

```text
Enter VPS IP address: 1.2.3.4
Enter VPS port (default 22): 22
Enter VPS password:
```

Provide:

- VPS IP address
- SSH port (default: 22)
- Root password

If the login succeeds, you will see the main menu.

---

### 3. Main menu

Home screen:

```text
xray › menu
____________________
Server
1. Status
2. Install
3. Restart
4. Remove

Keys
5. List
6. Add
7. Remove

b.   back
x.   exit
?:   _
```

Meaning:

- **1. Status** – show current protocol, domain (SNI) and port
- **2. Install** – install or reinstall the Xray stack on the VPS
- **3. Restart** – restart the Xray Docker container
- **4. Remove** – stop and remove Xray plus its config (Docker and OS stay)
- **5. List** – print all existing VLESS active keys
- **6. Add** – generate new VLESS keys
- **7. Remove** – delete all keys or a single key

---

### 4. First install

From the menu, choose:

```text
2
```

You will be prompted for:

- **SNI** – domain used for REALITY camouflage (for example `api.github.com`)
- **Path** – HTTP path for xhttp (for example `/` or `/api`)
- **Listen port** – default `443` or try any from 20000 to 60000

The script will then:

- Install Docker if needed
- Create `/opt/xray/config.json` with **VLESS-XHTTP-REALITY** inbound
- Create `/opt/xray/docker-compose.yaml`
- Start the `xray` container

You can verify with:

```text
1
```

Example output:

```text
Protocol:    vless-xhttp-reality
Server Name: api.github.com:443
```

(Values depend on your choices.)

---

### 5. Generate keys

From the menu, choose:

```text
6
```

The TUI asks:

```text
How many keys do you need?
Enter a number (e.g., 1–100).
```

Example: enter `3`.

The tool will generate 3 unique UUIDs and print 3 full VLESS URLs, for example:

```text
vless://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@1.2.3.4:443?type=xhttp&encryption=none&security=reality&sni=api.github.com&fp=chrome&pbk=...&sid=...&path=%2F#vless-xhttp-reality
```

You can copy these URLs into:

- **Shadowrocket** (iOS/Mac)
- **v2rayNG** (Android)
- **v2rayN** (Windows)
- Any other VLESS client that supports REALITY + xhttp

---

### 6. Manage keys

- To **list** all existing links: choose menu item `5` (List).
- To **remove**:
  - choose menu item `7` (Remove)
  - then select:
    - remove all keys, or
    - remove one key by number

Only client entries in `config.json` are deleted.  
The server itself keeps running unless you choose **4. Remove** in the Server section.

---

## Protocol overview (VLESS-XHTTP-REALITY)

Short summary:

- **VLESS** – lightweight protocol (no built-in TLS layer)
- **REALITY** – makes traffic look like a real HTTPS connection to a real host (for example `api.github.com`)
- **XHTTP** – HTTP-like transport that looks similar to normal HTTP/2 traffic and is friendly to proxies and DPI

Your traffic:

- Looks like a normal HTTPS session to the configured SNI
- Does not require a real TLS certificate on your VPS
- Uses a different stack than old VLESS-TCP-XTLS-Vision

---

## Notes

- All Xray files live under `/opt/xray/` on the VPS
- You can always:
  - **3. Restart** – restart the container if something is stuck
  - **2. Install** – reinstall the stack (config and compose are recreated)
- Generated links include all required parameters: `uuid`, `pbk`, `sid`, `sni`, port, path, and so on

For better security after the initial setup:

- Switch VPS SSH to **key-based auth**
- Disable password login
- Treat generated VLESS links as secrets (like passwords)

---

## Security Notice

This tool connects to your VPS as **root** over SSH to install and manage Docker/Xray.  
Keep your VPS credentials and VLESS links private and rotate them if needed.

---

## License

Licensed under the MIT license. See [LICENSE](./LICENSE) for details.
