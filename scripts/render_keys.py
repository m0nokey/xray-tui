#!/usr/bin/env python3
import argparse
import json
import sys
from urllib.parse import quote

parser = argparse.ArgumentParser()
parser.add_argument("node")
args = parser.parse_args()
state = json.load(sys.stdin)
node = state.get("nodes", {}).get(args.node)
if node is None:
    raise SystemExit("node not found")
xray = node.get("xray", {})
keys = xray.get("access_keys", [])
if not keys:
    print("\nManage access keys:\n\n  No access keys configured.\n\n  1. Add key")
    raise SystemExit(0)

for index, key in enumerate(keys, 1):
    print(f"{index}.")
    print(
        f"vless://{key['vision_uuid']}@{node['host']}:{xray['vision_port']}"
        f"?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality"
        f"&sni={xray.get('server_name', 'api.github.com')}&fp=chrome"
        f"&pbk={xray['reality_public_key']}&sid={xray['reality_short_id']}#vless-vision-reality"
    )
    print(
        f"vless://{key['xhttp_uuid']}@{node['host']}:{xray['xhttp_port']}"
        f"?type=xhttp&encryption=none&security=reality"
        f"&sni={xray.get('server_name', 'api.github.com')}&fp=chrome"
        f"&pbk={xray['reality_public_key']}&sid={xray['reality_short_id']}"
        f"&path={quote(xray.get('xhttp_path', '/'), safe='')}#vless-xhttp-reality"
    )
    if index != len(keys):
        print()
