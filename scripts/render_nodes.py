#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone


def node_status(node):
    key = node.get("deploy_private_key", "")
    if not key:
        return "Unknown"
    fd, path = tempfile.mkstemp(prefix="xray-node-key-")
    try:
        os.write(fd, key.encode())
        os.close(fd)
        os.chmod(path, 0o600)
        port = str(node.get("ssh_port", 22))
        command = (
            "docker inspect --format "
            "'{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' xray"
        )
        result = subprocess.run(
            ["ssh", "-i", path, "-p", port,
             "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
             "-o", "StrictHostKeyChecking=accept-new",
             f"{node.get('deploy_user', 'deploy')}@{node['host']}", command],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode != 0:
            return "Offline"
        state = result.stdout.strip().split()
        if state and state[0] == "running" and (len(state) < 2 or state[1] in ("", "healthy")):
            return "Active"
        if state and state[0] == "running":
            return "Starting"
        return "Stopped"
    except (OSError, subprocess.SubprocessError):
        return "Offline"
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
parser.add_argument("--node")
args = parser.parse_args()
data = json.load(__import__("sys").stdin)
nodes = data.get("nodes", {})
if args.node:
    nodes = {args.node: nodes[args.node]} if args.node in nodes else {}

print()
print("  Node Management:")
print()
if not nodes:
    print("  No VPN nodes installed.")
else:
    rows = []
    for name, node in nodes.items():
        created = node.get("created_at", "N/A")
        try:
            created = datetime.fromisoformat(created.replace("Z", "+00:00")).strftime("%Y-%m-%d")
        except (AttributeError, ValueError):
            pass
        provider = node.get("provider", "N/A")
        rows.append((node.get("host", "N/A"), node.get("country", "N/A"), created,
                     node_status(node) if args.check else node.get("status", "Unknown"),
                     provider, name))

    headers = ("IP", "STATUS", "COUNTRY", "CREATED", "PROVIDER")
    values = [(host, status, country, created, provider)
              for host, country, created, status, provider, _ in rows]
    widths = [max(len(headers[i]), *(len(row[i]) for row in values)) for i in range(5)]
    number_width = len(str(len(rows)))
    row_prefix = lambda number: f"  {number:>{number_width}}.   "
    print(" " * len(row_prefix(1)) + "   ".join(headers[i].ljust(widths[i]) for i in range(5)).rstrip())
    print()
    for index, (host, country, created, status, provider, _) in enumerate(rows, 1):
        values = (host, status, country, created, provider)
        print(row_prefix(index) + "   ".join(values[i].ljust(widths[i]) for i in range(5)).rstrip())
print()
