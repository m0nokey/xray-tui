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
from nacl.public import PrivateKey


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
        private = open(path, encoding="utf-8").read()
        public = open(path + ".pub", encoding="utf-8").read().strip()
        return private, public
    finally:
        for filename in (path, path + ".pub"):
            try:
                os.unlink(filename)
            except FileNotFoundError:
                pass


def _bot_port_pattern(port):
    value = str(port)
    if any(value[index] == value[index + 1] for index in range(len(value) - 1)):
        return True
    if any(sequence in value for sequence in ("01234", "12345", "23456", "34567", "45678", "56789")):
        return True
    if len(value) >= 5 and any(
        value[index] == value[index + 2] == value[index + 4]
        for index in range(len(value) - 4)
    ):
        return True
    if len(value) == 5:
        if value[0] == value[4] and value[1] == value[3]:
            return True
        if value[0] == value[3] and value[1] == value[4]:
            return True
    if len(value) >= 4 and any(
        value[index] == value[index + 2]
        and value[index + 1] == value[index + 3]
        for index in range(len(value) - 3)
    ):
        return True
    return False


def generated_port(used):
    while True:
        port = secrets.randbelow(40001) + 20000
        value = str(port)
        if port in used or _bot_port_pattern(port):
            continue
        if any(
            abs(int(value[index]) - int(value[index + 1])) < 2
            for index in range(len(value) - 1)
        ):
            continue
        used.add(port)
        return port


def port_number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("count", "names", "normalize", "extract", "mark-deployed", "set-deploy-key", "ensure-ssh-port", "set-bootstrap", "remove-node", "add-node", "add-key", "add-keys", "remove-key", "remove-all-keys"))
parser.add_argument("args", nargs="*")
parser.add_argument("--bootstrap-key")
parser.add_argument("--server-name", default="github.com")
opts = parser.parse_args()
state = read_state()
nodes = state.setdefault("nodes", {})

if opts.action == "count":
    print(len(nodes))
    raise SystemExit(0)
elif opts.action == "names":
    print("\n".join(nodes))
    raise SystemExit(0)
elif opts.action == "normalize":
    for node in nodes.values():
        node.setdefault("xray", {}).setdefault("server_name", "github.com")
        bootstrap_port = int(node.get("bootstrap_ssh_port", node.get("initial_port", 22)))
        target_port = int(
            node.get(
                "sshd_port",
                node.get("harden_ssh_port", node.get("target_ssh_port", node.get("ssh_port", bootstrap_port))),
            )
        )
        node.setdefault("bootstrap_ssh_port", bootstrap_port)
        node.setdefault("initial_port", bootstrap_port)
        node.setdefault("ssh_port", target_port)
        node.setdefault("sshd_port", target_port)
        if "management_port" not in node:
            if node.get("bootstrap_private_key") or node.get("bootstrap_password"):
                node["management_port"] = bootstrap_port
            else:
                node["management_port"] = target_port
        management_user = node.get("management_user", node.get("deploy_user", "deploy"))
        management_private_key = node.get(
            "management_private_key", node.get("deploy_private_key", "")
        )
        management_authorized_key = node.get(
            "management_authorized_key", node.get("deploy_authorized_key", "")
        )
        node.setdefault("management_user", management_user)
        node.setdefault("management_private_key", management_private_key)
        node.setdefault("management_authorized_key", management_authorized_key)
        node.setdefault("deploy_user", management_user)
        node.setdefault("deploy_private_key", management_private_key)
        node.setdefault("deploy_authorized_key", management_authorized_key)
elif opts.action == "extract":
    if len(opts.args) != 1 or opts.args[0] not in nodes:
        raise SystemExit("extract requires NODE")
    node = nodes[opts.args[0]]
    target_port = node.get(
        "sshd_port",
        node.get("harden_ssh_port", node.get("target_ssh_port", node.get("ssh_port", node.get("bootstrap_ssh_port", 22)))),
    )
    initial_port = node.get("initial_port", node.get("bootstrap_ssh_port", 22))
    output = {
        "xray_state": node["xray"],
        "xray_server_name": node["xray"].get("server_name", "github.com"),
        "xray_public_host": node["host"],
        "management_user": node.get("management_user", node.get("deploy_user", "deploy")),
        "management_authorized_key": node.get(
            "management_authorized_key", node.get("deploy_authorized_key", "")
        ),
        "deploy_user": node.get("deploy_user", node.get("management_user", "deploy")),
        "deploy_authorized_key": node.get(
            "deploy_authorized_key", node.get("management_authorized_key", "")
        ),
        "management_private_key": node.get(
            "management_private_key", node.get("deploy_private_key", "")
        ),
        "harden_ssh_initial_user": node.get("bootstrap_user", "root"),
        "initial_port": initial_port,
        "ssh_port": target_port,
        "sshd_port": target_port,
        "management_port": node.get("management_port", initial_port),
    }
    json.dump(output, sys.stdout, indent=2)
    print()
    raise SystemExit(0)
elif opts.action == "mark-deployed":
    if len(opts.args) != 1 or opts.args[0] not in nodes:
        raise SystemExit("mark-deployed requires NODE")
    node = nodes[opts.args[0]]
    node["bootstrap_private_key"] = ""
    target_port = int(
        node.get("sshd_port", node.get("harden_ssh_port", node.get("target_ssh_port", node.get("ssh_port", node.get("bootstrap_ssh_port", 22)))))
    )
    node["ssh_port"] = target_port
    node["sshd_port"] = target_port
    node["initial_port"] = int(node.get("initial_port", node.get("bootstrap_ssh_port", 22)))
    node["management_port"] = target_port
elif opts.action == "set-deploy-key":
    if len(opts.args) != 3 or opts.args[0] not in nodes:
        raise SystemExit("set-deploy-key requires NODE PRIVATE_KEY PUBLIC_KEY")
    node = nodes[opts.args[0]]
    node["deploy_private_key"] = open(opts.args[1], encoding="utf-8").read()
    node["deploy_authorized_key"] = open(opts.args[2], encoding="utf-8").read().strip()
    node["management_private_key"] = node["deploy_private_key"]
    node["management_authorized_key"] = node["deploy_authorized_key"]
elif opts.action == "ensure-ssh-port":
    if len(opts.args) != 2 or opts.args[0] not in nodes:
        raise SystemExit("ensure-ssh-port requires NODE BOOTSTRAP_PORT")
    node = nodes[opts.args[0]]
    bootstrap_port = int(opts.args[1])
    node["bootstrap_ssh_port"] = bootstrap_port
    node.setdefault("initial_port", bootstrap_port)
    node.setdefault("management_port", bootstrap_port)
    current_ssh_port = port_number(node.get("sshd_port", node.get("harden_ssh_port", node.get("target_ssh_port", node.get("ssh_port")))))
    if current_ssh_port in (None, 22, bootstrap_port):
        used_ports = {
            int(node["xray"].get("vision_port")),
            int(node["xray"].get("xhttp_port")),
        }
        node["sshd_port"] = generated_port(used_ports)
        node["ssh_port"] = node["sshd_port"]
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
    node["initial_port"] = node.get("initial_port", node["bootstrap_ssh_port"])
    node["management_port"] = node.get("management_port", node["bootstrap_ssh_port"])
    current_ssh_port = port_number(node.get("sshd_port", node.get("harden_ssh_port", node.get("target_ssh_port", node.get("ssh_port")))))
    if current_ssh_port in (None, 22, node["bootstrap_ssh_port"]):
        used_ports = {
            int(node["xray"].get("vision_port")),
            int(node["xray"].get("xhttp_port")),
        }
        node["sshd_port"] = generated_port(used_ports)
        node["ssh_port"] = node["sshd_port"]
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
        bootstrap_private = open(opts.bootstrap_key, encoding="utf-8").read()
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
    ports = [generated_port(used_ports) for _ in range(2)]
    vision_uuid = str(uuid.uuid4())
    nodes[name] = {
        "name": name,
        "host": host,
        "country": country,
        "provider": provider,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "deploy_user": "deploy",
        "deploy_private_key": private,
        "deploy_authorized_key": public,
        "management_user": "deploy",
        "management_private_key": private,
        "management_authorized_key": public,
        "bootstrap_private_key": bootstrap_private,
        "bootstrap_password": bootstrap_password,
        "bootstrap_user": bootstrap_user,
        "bootstrap_ssh_port": bootstrap_port,
        "initial_port": bootstrap_port,
        "ssh_port": ssh_port,
        "sshd_port": ssh_port,
        "management_port": bootstrap_port,
        "xray": {
            "vision_port": ports[0], "xhttp_port": ports[1],
            "reality_private_key": reality_private,
            "reality_public_key": reality_public,
            "reality_short_id": secrets.token_hex(8),
            "server_name": server_name,
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
