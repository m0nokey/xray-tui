#!/usr/bin/env python3
import argparse
import base64
import json
import os
import random
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
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"encrypted Vault state is invalid JSON: {exc.msg}") from exc


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


parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("count", "names", "extract", "mark-deployed", "set-deploy-key", "remove-node", "add-node", "add-key", "remove-key"))
parser.add_argument("args", nargs="*")
parser.add_argument("--bootstrap-key")
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
        "xray_public_host": node["host"],
        "deploy_user": node.get("deploy_user", "deploy"),
        "deploy_authorized_key": node.get("deploy_authorized_key", ""),
    }
    json.dump(output, sys.stdout, indent=2)
    print()
    raise SystemExit(0)
elif opts.action == "mark-deployed":
    if len(opts.args) != 1 or opts.args[0] not in nodes:
        raise SystemExit("mark-deployed requires NODE")
    nodes[opts.args[0]]["bootstrap_private_key"] = ""
    nodes[opts.args[0]]["bootstrap_password"] = ""
elif opts.action == "set-deploy-key":
    if len(opts.args) != 3 or opts.args[0] not in nodes:
        raise SystemExit("set-deploy-key requires NODE PRIVATE_KEY PUBLIC_KEY")
    node = nodes[opts.args[0]]
    node["deploy_private_key"] = open(opts.args[1], encoding="utf-8").read()
    node["deploy_authorized_key"] = open(opts.args[2], encoding="utf-8").read().strip()
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
    ports = random.SystemRandom().sample(range(30000, 60001), 2)
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
        "bootstrap_private_key": bootstrap_private,
        "bootstrap_password": bootstrap_password,
        "bootstrap_user": bootstrap_user,
        "bootstrap_ssh_port": bootstrap_port,
        "ssh_port": bootstrap_port,
        "xray": {
            "vision_port": ports[0], "xhttp_port": ports[1],
            "reality_private_key": reality_private,
            "reality_public_key": reality_public,
            "reality_short_id": secrets.token_hex(8),
            "access_keys": [{
                "key_id": "key-" + vision_uuid.replace("-", "")[:8],
                "vision_uuid": vision_uuid,
                "xhttp_uuid": str(uuid.uuid4()),
            }],
        },
    }
elif opts.action in ("add-key", "remove-key"):
    if len(opts.args) < 1:
        raise SystemExit(f"{opts.action} requires NODE")
    node = nodes.get(opts.args[0])
    if node is None:
        raise SystemExit(f"node not found: {opts.args[0]}")
    keys = node.setdefault("xray", {}).setdefault("access_keys", [])
    if opts.action == "add-key":
        vision_uuid = str(uuid.uuid4())
        keys.append({
            "key_id": "key-" + vision_uuid.replace("-", "")[:8],
            "vision_uuid": vision_uuid,
            "xhttp_uuid": str(uuid.uuid4()),
        })
    else:
        if len(opts.args) != 2:
            raise SystemExit("remove-key requires NODE KEY_ID")
        key_id = opts.args[1]
        node["xray"]["access_keys"] = [key for key in keys if key["key_id"] != key_id]
        if len(node["xray"]["access_keys"]) == len(keys):
            raise SystemExit(f"key not found: {key_id}")

json.dump(state, sys.stdout, indent=2)
print()
