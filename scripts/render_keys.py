#!/usr/bin/env python3
import argparse
import json
import sys
from urllib.parse import quote

RESET = "\033[0m"
BLUE = "\033[38;5;117m"
USE_COLOR = sys.stdout.isatty()


def color(text, value):
    return f"{value}{text}{RESET}" if USE_COLOR else text


parser = argparse.ArgumentParser()
parser.add_argument("node")
args = parser.parse_args()
state = json.load(sys.stdin)
node = state.get("nodes", {}).get(args.node)
if node is None:
    raise SystemExit("node not found")
xray = node.get("xray", {})
keys = xray.get("access_keys", [])
server_name = xray.get("server_name", "github.com")
if not keys:
    print()
    print(color("Manage access keys:", BLUE))
    print("\n  No access keys configured.\n")
    print(f"  {color('1.', BLUE)} Add key")
    raise SystemExit(0)

for index, key in enumerate(keys, 1):
    print(color(f"{index}.", BLUE))
    print(
        f"vless://{key['vision_uuid']}@{node['host']}:{xray['vision_port']}"
        f"?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality"
        f"&sni={server_name}&fp=chrome"
        f"&pbk={xray['reality_public_key']}&sid={xray['reality_short_id']}#vless-vision-reality"
    )
    print()
    print(
        f"vless://{key['xhttp_uuid']}@{node['host']}:{xray['xhttp_port']}"
        f"?type=xhttp&encryption=none&security=reality"
        f"&sni={server_name}&fp=chrome"
        f"&pbk={xray['reality_public_key']}&sid={xray['reality_short_id']}"
        f"&path={quote(xray.get('xhttp_path', '/'), safe='')}&mode=packet-up#vless-xhttp-reality"
    )
    if index != len(keys):
        print()
        print()
        print()
    else:
        print()
        print()
