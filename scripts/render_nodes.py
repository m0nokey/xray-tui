#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import os
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


RESET = "\033[0m"
BLUE = "\033[38;5;117m"
GRAY = "\033[38;5;245m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
USE_COLOR = sys.stdout.isatty()


def color(text, value):
    return f"{value}{text}{RESET}" if USE_COLOR else text


def status_color(status):
    return {
        "Active": GREEN,
        "Partial": YELLOW,
        "VPN unavailable": RED,
        "Unreachable": RED,
    }.get(status, GRAY)


def port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def management_ports(node):
    """Return known SSH ports, preserving compatibility with older Vaults."""
    ports = []
    for value in (
        node.get("management_port"),
        node.get("sshd_port"),
        node.get("harden_ssh_port"),
        node.get("target_ssh_port"),
        node.get("ssh_port"),
        node.get("bootstrap_ssh_port"),
        node.get("initial_port"),
        22,
    ):
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def management_state(node, timeout=5.0):
    """Probe management access and return details without exposing credentials."""
    host = node.get("host", "")
    user = node.get("management_user") or node.get("deploy_user", "deploy")
    private_key = node.get("management_private_key") or node.get("deploy_private_key", "")
    ports = management_ports(node)
    details = {
        "ports": ports,
        "initial_port": node.get("initial_port", node.get("bootstrap_ssh_port", 22)),
        "management_port": node.get("management_port"),
        "sshd_port": node.get("sshd_port", node.get("ssh_port")),
        "tcp_ports": [],
        "ssh_port": None,
        "ssh": "not checked",
        "ssh_error": "",
        "xray": "not checked",
    }
    if not host or not ports:
        details["ssh"] = "no management port in Vault"
        return details

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as pool:
        port_futures = {
            pool.submit(port_open, host, port, 0.8): port for port in ports
        }
        reachable_ports = [
            port for future, port in port_futures.items() if future.result()
        ]
    details["tcp_ports"] = reachable_ports
    if not private_key:
        details["ssh"] = "management private key missing in Vault"
        return details

    key_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=".xray-status-", delete=False
        ) as key_file:
            key_file.write(private_key)
            key_path = key_file.name
        os.chmod(key_path, 0o600)

        for ssh_port in reachable_ports:
            result = subprocess.run(
                [
                    "ssh",
                    "-i",
                    key_path,
                    "-p",
                    str(ssh_port),
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=3",
                    "-o",
                    "ConnectionAttempts=1",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    f"{user}@{host}",
                    "status=\"$(sudo -n docker inspect --format '{{.State.Status}}' xray 2>/dev/null || "
                    "docker inspect --format '{{.State.Status}}' xray 2>/dev/null || true)\"; "
                    "case \"$status\" in running) printf xray-running;; "
                    "'') printf xray-not-found;; *) printf 'xray-%s' \"$status\";; esac",
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode == 0:
                details["ssh_port"] = ssh_port
                details["ssh"] = "connected"
                details["xray"] = result.stdout.strip() or "empty response"
                return details
            error = (result.stderr or "").lower()
            details["ssh_error"] = " ".join((result.stderr or "").split())[:240]
            if "permission denied" in error:
                details["ssh"] = "authentication failed"
            elif "timed out" in error or "timeout" in error:
                details["ssh"] = "connection timeout"
            elif "connection refused" in error:
                details["ssh"] = "connection refused"
            elif "no route" in error or "unreachable" in error:
                details["ssh"] = "network unreachable"
            else:
                details["ssh"] = f"connection failed (exit {result.returncode})"
    except subprocess.TimeoutExpired:
        details["ssh"] = "SSH command timeout"
    except (OSError, subprocess.SubprocessError):
        details["ssh"] = "SSH client error"
    finally:
        if key_path:
            try:
                os.unlink(key_path)
            except FileNotFoundError:
                pass

    return details


def node_diagnostics(node):
    host = node.get("host", "")
    xray = node.get("xray", {})
    vpn_ports = (xray.get("vision_port"), xray.get("xhttp_port"))
    ports = [port for port in vpn_ports if port]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(port_open, host, port) for port in ports]
        management_future = pool.submit(management_state, node)
        probes = [future.result() for future in futures]
        management = management_future.result()

    ssh_reachable = bool(management["tcp_ports"] or management["ssh_port"])
    xray_running = management["xray"] == "xray-running"

    if not ssh_reachable and not any(probes):
        status = "Unreachable"
    elif not ssh_reachable:
        status = "VPN unavailable"
    elif xray_running and len(probes) == 2 and all(probes):
        status = "Active"
    elif xray_running and any(probes):
        status = "Partial"
    else:
        status = "VPN unavailable"

    return {
        "status": status,
        "management": management,
        "vpn": list(zip(ports, probes)),
    }


def node_status(node):
    return node_diagnostics(node)["status"]


parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
parser.add_argument("--node")
args = parser.parse_args()
data = json.load(__import__("sys").stdin)
nodes = data.get("nodes", {})
if args.node:
    nodes = {args.node: nodes[args.node]} if args.node in nodes else {}

print()
print(color("  Node Management:", BLUE))
print()
if not nodes:
    print("  No VPN nodes installed.")
else:
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(nodes)))) as pool:
        statuses = {}
        if args.check:
            futures = {pool.submit(node_diagnostics, node): name for name, node in nodes.items()}
            statuses = {
                futures[future]: future.result()
                for future in concurrent.futures.as_completed(futures)
            }
        for name, node in nodes.items():
            created = node.get("created_at", "N/A")
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except (AttributeError, ValueError):
                pass
            provider = node.get("provider", "N/A")
            rows.append((node.get("host", "N/A"), node.get("country", "N/A"), created,
                         statuses.get(name, {}).get("status", node.get("status", "Unknown")),
                         provider, name))

    headers = ("IP", "STATUS", "COUNTRY", "CREATED", "PROVIDER")
    values = [(host, status, country, created, provider)
              for host, country, created, status, provider, _ in rows]
    widths = [max(len(headers[i]), *(len(row[i]) for row in values)) for i in range(5)]
    number_width = len(str(len(rows)))
    row_prefix = lambda number: f"  {number:>{number_width}}.   "
    print(color(" " * len(row_prefix(1)) + "   ".join(headers[i].ljust(widths[i]) for i in range(5)).rstrip(), BLUE))
    print()
    for index, (host, country, created, status, provider, _) in enumerate(rows, 1):
        values = (host, status, country, created, provider)
        row = "   ".join(values[i].ljust(widths[i]) for i in range(5)).rstrip()
        status_start = row.find(status)
        status_end = status_start + len(status)
        colored_row = (
            row[:status_start]
            + color(row[status_start:status_end], status_color(status))
            + row[status_end:]
        )
        print(row_prefix(index) + colored_row)
print()
