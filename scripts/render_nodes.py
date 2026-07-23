#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import socket
from datetime import datetime, timezone


def port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def node_status(node):
    host = node.get("host", "")
    xray = node.get("xray", {})
    vpn_ports = (xray.get("vision_port"), xray.get("xhttp_port"))
    ports = [port for port in vpn_ports if port]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(port_open, host, port) for port in ports]
        ssh_port = node.get("ssh_port")
        ssh_future = pool.submit(port_open, host, ssh_port) if ssh_port else None
        probes = [future.result() for future in futures]
        ssh_reachable = ssh_future.result() if ssh_future else False

    if len(probes) == 2 and all(probes):
        return "Active"
    if any(probes):
        return "Partial"
    if ssh_reachable:
        return "VPN unavailable"
    return "Unreachable"


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
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(nodes)))) as pool:
        statuses = {}
        if args.check:
            futures = {pool.submit(node_status, node): name for name, node in nodes.items()}
            statuses = {futures[future]: future.result() for future in concurrent.futures.as_completed(futures)}
        for name, node in nodes.items():
            created = node.get("created_at", "N/A")
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except (AttributeError, ValueError):
                pass
            provider = node.get("provider", "N/A")
            rows.append((node.get("host", "N/A"), node.get("country", "N/A"), created,
                         statuses.get(name, node.get("status", "Unknown")),
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
    if args.check:
        print()
        print("  Status:")
        print("    Active           Both VPN ports are reachable.")
        print("    Partial          Only one VPN port is reachable.")
        print("    VPN unavailable  Management SSH is reachable, but VPN ports are not.")
        print("    Unreachable      No VPN or management port responded; DPI or a provider firewall may be involved.")
print()
