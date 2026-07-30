#!/usr/bin/env python3
import argparse
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from nacl.public import PrivateKey
from state_logic import generated_port, generated_vpn_ports

COUNTRIES_FILE = Path(__file__).resolve().parent.parent / "data" / "countries.tsv"


def country_codes():
    try:
        with COUNTRIES_FILE.open(encoding="utf-8") as handle:
            return {
                line.split("\t", 1)[0].strip().lower()
                for line in handle
                if line.strip() and not line.startswith("#")
            }
    except OSError as exc:
        raise SystemExit(f"country code table is unavailable: {COUNTRIES_FILE}") from exc


def read_state():
    raw = sys.stdin.read()
    if not raw.strip():
        raise SystemExit("encrypted Vault state is empty; refusing to modify it")
    try:
        state = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"encrypted Vault state is invalid JSON: {exc.msg}") from exc
    if not isinstance(state, dict) or not isinstance(state.get("nodes"), dict):
        raise SystemExit("encrypted Vault state has an invalid structure; expected an object with nodes")
    return state


def ip_info(host):
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["curl", "-sSfL", "--tlsv1.3", "--http2", "--proto", "=https",
                 f"https://ipinfo.io/{host}"], capture_output=True, text=True, timeout=10,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                org = data.get("org", "N/A")
                return data.get("country", "N/A"), org.split(" ", 1)[1] if " " in org else org
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            pass
        if attempt < 2:
            import time
            time.sleep(3)
    raise SystemExit("Failed to get IP info")


def reality_keys():
    key = PrivateKey.generate()
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    return encode(key.encode()), encode(key.public_key.encode())


def deploy_key():
    fd, path = tempfile.mkstemp(prefix="xray-deploy-")
    os.close(fd)
    os.unlink(path)
    try:
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True)
        private = Path(path).read_text(encoding="utf-8")
        public = Path(path + ".pub").read_text(encoding="utf-8").strip()
        return private, public
    finally:
        for filename in (path, path + ".pub"):
            try:
                os.unlink(filename)
            except FileNotFoundError:
                pass


parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("count", "names", "extract", "mark-deployed", "set-management-key", "set-ssh-host-key", "set-bootstrap", "set-dns-profile", "set-local-region", "remove-node", "add-node", "add-key", "add-keys", "remove-key", "remove-all-keys"))
parser.add_argument("args", nargs="*")
parser.add_argument("--bootstrap-key")
parser.add_argument("--server-name", default="github.com")
parser.add_argument(
    "--port-mode",
    choices=("random", "vision-443", "xhttp-443", "manual"),
    default="random",
)
parser.add_argument("--vision-port", type=int)
parser.add_argument("--xhttp-port", type=int)
parser.add_argument(
    "--dns-profile",
    choices=("disabled", "minimal", "optimal", "full", "maximum", "custom"),
    default="disabled",
)
parser.add_argument(
    "--dns-lists",
    default="",
    help="comma-separated DNS source names for the custom profile",
)
parser.add_argument(
    "--local-region-countries",
    default="",
    help="comma-separated ISO alpha-2 country codes",
)
opts = parser.parse_args()
state = read_state()
nodes = state.setdefault("nodes", {})

if opts.action == "count":
    print(len(nodes))
    raise SystemExit(0)
elif opts.action == "names":
    print("\n".join(nodes))
    raise SystemExit(0)
elif opts.action == "extract":
    if len(opts.args) != 1 or opts.args[0] not in nodes:
        raise SystemExit("extract requires NODE")
    node = nodes[opts.args[0]]
    output = {
        "xray_state": node["xray"],
        "xray_server_name": node["xray"].get("server_name", "github.com"),
        "xray_dns_profile": node["xray"].get("dns_filter_profile", "disabled"),
        "xray_dns_lists": node["xray"].get("dns_filter_lists", []),
        "xray_local_region_countries": node["xray"].get("local_region_countries", []),
        "xray_public_host": node["host"],
        "management_user": node["management_user"],
        "management_authorized_key": node["management_authorized_key"],
        "system_base_deploy_user": node["management_user"],
        "system_base_deploy_authorized_key": node["management_authorized_key"],
        "management_private_key": node["management_private_key"],
        "system_base_harden_ssh_initial_user": node.get("bootstrap_user", "root"),
        "ssh_port": node["ssh_port"],
        "management_port": node["management_port"],
        "system_base_ssh_host_public_key": node.get("ssh_host_public_key", ""),
        "system_base_ssh_host_fingerprint": node.get("ssh_host_fingerprint", ""),
    }
    json.dump(output, sys.stdout, indent=2)
    print()
    raise SystemExit(0)
elif opts.action == "mark-deployed":
    if len(opts.args) != 1 or opts.args[0] not in nodes:
        raise SystemExit("mark-deployed requires NODE")
    node = nodes[opts.args[0]]
    node["bootstrap_private_key"] = ""
    node["management_port"] = node["ssh_port"]
elif opts.action == "set-management-key":
    if len(opts.args) != 3 or opts.args[0] not in nodes:
        raise SystemExit("set-management-key requires NODE PRIVATE_KEY PUBLIC_KEY")
    node = nodes[opts.args[0]]
    node["management_private_key"] = Path(opts.args[1]).read_text(encoding="utf-8")
    node["management_authorized_key"] = Path(opts.args[2]).read_text(encoding="utf-8").strip()
elif opts.action == "set-ssh-host-key":
    if len(opts.args) != 3 or opts.args[0] not in nodes:
        raise SystemExit("set-ssh-host-key requires NODE PUBLIC_KEY_FILE FINGERPRINT")
    public_key = Path(opts.args[1]).read_text(encoding="utf-8").strip()
    fingerprint = opts.args[2].strip()
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?", public_key):
        raise SystemExit("invalid SSH host public key")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/=]+", fingerprint):
        raise SystemExit("invalid SSH host fingerprint")
    node = nodes[opts.args[0]]
    node["ssh_host_public_key"] = public_key
    node["ssh_host_fingerprint"] = fingerprint
elif opts.action == "set-bootstrap":
    if len(opts.args) != 3 or opts.args[0] not in nodes:
        raise SystemExit("set-bootstrap requires NODE USER PORT")
    password = os.environ.get("XRAY_BOOTSTRAP_PASSWORD", "")
    if not password:
        raise SystemExit("set-bootstrap requires XRAY_BOOTSTRAP_PASSWORD")
    node = nodes[opts.args[0]]
    node["bootstrap_user"] = opts.args[1]
    node["bootstrap_ssh_port"] = int(opts.args[2])
    node["bootstrap_password"] = password
    node["management_port"] = node["bootstrap_ssh_port"]
elif opts.action == "set-dns-profile":
    if len(opts.args) != 2 or opts.args[0] not in nodes:
        raise SystemExit("set-dns-profile requires NODE PROFILE")
    profile = opts.args[1]
    if profile not in ("disabled", "minimal", "optimal", "full", "maximum", "custom"):
        raise SystemExit("unsupported DNS protection profile")
    node_xray = nodes[opts.args[0]].setdefault("xray", {})
    node_xray["dns_filter_profile"] = profile
    if profile == "custom":
        node_xray["dns_filter_lists"] = [item for item in opts.dns_lists.split(",") if item]
    else:
        node_xray.pop("dns_filter_lists", None)
elif opts.action == "set-local-region":
    if len(opts.args) != 2 or opts.args[0] not in nodes:
        raise SystemExit("set-local-region requires NODE ENABLED_OR_DISABLED")
    if opts.args[1] not in ("enabled", "disabled"):
        raise SystemExit("set-local-region requires enabled or disabled")
    countries = []
    if opts.args[1] == "enabled":
        countries = list(dict.fromkeys(
            item.strip().lower()
            for item in opts.local_region_countries.split(",")
            if item.strip()
        ))
        invalid = [item for item in countries if not re.fullmatch(r"[a-z]{2}", item)]
        invalid.extend(item for item in countries if item not in country_codes() and item not in invalid)
        if invalid:
            raise SystemExit(f"unsupported country code: {', '.join(invalid)}")
        if not countries:
            raise SystemExit("enabled local-region policy requires at least one country")
    nodes[opts.args[0]].setdefault("xray", {})["local_region_countries"] = countries
elif opts.action == "remove-node":
    if len(opts.args) != 1 or opts.args[0] not in nodes:
        raise SystemExit("remove-node requires NODE")
    del nodes[opts.args[0]]
elif opts.action == "add-node":
    if len(opts.args) != 2:
        raise SystemExit("add-node requires NAME HOST")
    name, host = opts.args
    if name == "auto":
        base = re.sub(r"[^A-Za-z0-9]+", "-", host).strip("-").lower() or "server"
        name = "vpn-" + base[:48]
        suffix = 2
        original = name
        while name in nodes:
            name = f"{original}-{suffix}"
            suffix += 1
    if name in nodes:
        raise SystemExit(f"node already exists: {name}")
    country, provider = ip_info(host)
    private, public = deploy_key()
    bootstrap_private = ""
    if opts.bootstrap_key:
        bootstrap_private = Path(opts.bootstrap_key).read_text(encoding="utf-8")
    bootstrap_password = os.environ.get("XRAY_BOOTSTRAP_PASSWORD", "")
    bootstrap_port = int(os.environ.get("XRAY_BOOTSTRAP_PORT", "22"))
    bootstrap_user = os.environ.get("XRAY_BOOTSTRAP_USER", "root")
    reality_private, reality_public = reality_keys()
    server_name = opts.server_name.strip().lower()
    if (
        len(server_name) > 253
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+", server_name)
        or any(len(label) > 63 for label in server_name.split("."))
    ):
        raise SystemExit("server name must be a valid ASCII hostname")
    used_ports = set()
    ssh_port = generated_port(used_ports)
    manual_ports = None
    if opts.port_mode == "manual":
        manual_ports = (opts.vision_port, opts.xhttp_port)
    try:
        vision_port, xhttp_port = generated_vpn_ports(used_ports, opts.port_mode, manual_ports)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    vision_uuid = str(uuid.uuid4())
    nodes[name] = {
        "name": name,
        "host": host,
        "country": country,
        "provider": provider,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "management_user": "deploy",
        "management_private_key": private,
        "management_authorized_key": public,
        "bootstrap_private_key": bootstrap_private,
        "bootstrap_password": bootstrap_password,
        "bootstrap_user": bootstrap_user,
        "bootstrap_ssh_port": bootstrap_port,
        "ssh_port": ssh_port,
        "management_port": bootstrap_port,
        "ssh_host_public_key": "",
        "ssh_host_fingerprint": "",
        "xray": {
            "vision_port": vision_port, "xhttp_port": xhttp_port,
            "port_mode": opts.port_mode,
            "reality_private_key": reality_private,
            "reality_public_key": reality_public,
            "reality_short_id": secrets.token_hex(8),
            "server_name": server_name,
            "dns_filter_profile": opts.dns_profile,
            "dns_filter_lists": [item for item in opts.dns_lists.split(",") if item],
            "local_region_countries": [],
            "access_keys": [{
                "key_id": "key-" + vision_uuid.replace("-", "")[:8],
                "vision_uuid": vision_uuid,
                "xhttp_uuid": str(uuid.uuid4()),
            }],
        },
    }
elif opts.action in ("add-key", "add-keys", "remove-key", "remove-all-keys"):
    if len(opts.args) < 1:
        raise SystemExit(f"{opts.action} requires NODE")
    node = nodes.get(opts.args[0])
    if node is None:
        raise SystemExit(f"node not found: {opts.args[0]}")
    keys = node.setdefault("xray", {}).setdefault("access_keys", [])
    if opts.action in ("add-key", "add-keys"):
        if opts.action == "add-key":
            count = 1
        else:
            if len(opts.args) != 2 or not opts.args[1].isdigit():
                raise SystemExit("add-keys requires NODE COUNT")
            count = int(opts.args[1])
            if not 1 <= count <= 50:
                raise SystemExit("access key count must be between 1 and 50")
        for _ in range(count):
            vision_uuid = str(uuid.uuid4())
            keys.append({
                "key_id": "key-" + vision_uuid.replace("-", "")[:8],
                "vision_uuid": vision_uuid,
                "xhttp_uuid": str(uuid.uuid4()),
            })
    elif opts.action == "remove-all-keys":
        node["xray"]["access_keys"] = []
    else:
        if len(opts.args) != 2:
            raise SystemExit("remove-key requires NODE KEY_ID")
        key_id = opts.args[1]
        node["xray"]["access_keys"] = [key for key in keys if key["key_id"] != key_id]
        if len(node["xray"]["access_keys"]) == len(keys):
            raise SystemExit(f"key not found: {key_id}")

json.dump(state, sys.stdout, indent=2)
print()
