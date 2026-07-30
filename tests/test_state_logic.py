import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.state_logic import bot_port_pattern, generated_port, generated_vpn_ports


ROOT_DIR = Path(__file__).resolve().parent.parent
STATE_CLI = ROOT_DIR / "scripts" / "state_cli.py"


class PortGenerationTests(unittest.TestCase):
    def test_known_obvious_patterns_are_rejected(self):
        for port in (20000, 23456, 1212, 12321, 12312, 20202):
            with self.subTest(port=port):
                self.assertTrue(bot_port_pattern(port))

    def test_less_obvious_values_are_not_rejected_by_pattern_filter(self):
        for port in (24680, 13579, 31415):
            with self.subTest(port=port):
                self.assertFalse(bot_port_pattern(port))

    def test_generated_ports_meet_all_generation_constraints(self):
        used = set()
        ports = [generated_port(used) for _ in range(250)]

        self.assertEqual(len(ports), len(set(ports)))
        for port in ports:
            self.assertGreaterEqual(port, 20000)
            self.assertLessEqual(port, 60000)
            self.assertFalse(bot_port_pattern(port))
            digits = str(port)
            self.assertTrue(all(
                abs(int(left) - int(right)) >= 2
                for left, right in zip(digits, digits[1:])
            ))

    def test_default_mode_generates_both_ports(self):
        used = set()

        vision_port, xhttp_port = generated_vpn_ports(used)

        self.assertGreaterEqual(vision_port, 20000)
        self.assertLessEqual(vision_port, 60000)
        self.assertGreaterEqual(xhttp_port, 20000)
        self.assertLessEqual(xhttp_port, 60000)
        self.assertEqual(used, {vision_port, xhttp_port})

    def test_vision_443_mode_uses_https_port_and_generates_xhttp(self):
        used = set()

        vision_port, xhttp_port = generated_vpn_ports(used, "vision-443")

        self.assertEqual(vision_port, 443)
        self.assertGreaterEqual(xhttp_port, 20000)
        self.assertLessEqual(xhttp_port, 60000)
        self.assertEqual(used, {xhttp_port})

    def test_manual_mode_uses_the_requested_ports(self):
        used = {42137}

        ports = generated_vpn_ports(used, "manual", (443, 8443))

        self.assertEqual(ports, (443, 8443))
        self.assertEqual(used, {42137, 443, 8443})

    def test_manual_mode_rejects_invalid_port_pairs(self):
        for ports in ((443, 443), (0, 8443), (443, 65536), (42137, 8443)):
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    generated_vpn_ports({42137}, "manual", ports)


class StateCliTests(unittest.TestCase):
    def run_cli(self, state, *arguments):
        result = subprocess.run(
            [sys.executable, str(STATE_CLI), *arguments],
            cwd=ROOT_DIR,
            input=json.dumps(state),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def fixture_state():
        return {
            "nodes": {
                "node-a": {
                    "name": "node-a",
                    "host": "192.0.2.10",
                    "management_user": "deploy",
                    "management_authorized_key": "ssh-ed25519 AAAA old",
                    "management_private_key": "private-key",
                    "bootstrap_private_key": "bootstrap-key",
                    "bootstrap_password": "bootstrap-password",
                    "bootstrap_ssh_port": 22,
                    "ssh_port": 42137,
                    "management_port": 22,
                    "xray": {
                        "vision_port": 38642,
                        "xhttp_port": 49753,
                        "access_keys": [{
                            "key_id": "key-initial",
                            "vision_uuid": "11111111-1111-4111-8111-111111111111",
                            "xhttp_uuid": "22222222-2222-4222-8222-222222222222",
                        }],
                    },
                },
            }
        }

    def test_key_lifecycle_and_dns_profile(self):
        state = self.fixture_state()
        state = self.run_cli(state, "add-keys", "node-a", "2")
        keys = state["nodes"]["node-a"]["xray"]["access_keys"]
        self.assertEqual(len(keys), 3)
        self.assertEqual(len({key["key_id"] for key in keys}), 3)

        state = self.run_cli(state, "remove-key", "node-a", keys[1]["key_id"])
        self.assertEqual(len(state["nodes"]["node-a"]["xray"]["access_keys"]), 2)

        state = self.run_cli(
            state,
            "set-dns-profile",
            "node-a",
            "custom",
            "--dns-lists",
            "ads,malware",
        )
        xray = state["nodes"]["node-a"]["xray"]
        self.assertEqual(xray["dns_filter_profile"], "custom")
        self.assertEqual(xray["dns_filter_lists"], ["ads", "malware"])

        state = self.run_cli(state, "remove-all-keys", "node-a")
        self.assertEqual(state["nodes"]["node-a"]["xray"]["access_keys"], [])

    def test_deployment_state_moves_to_management_port(self):
        state = self.run_cli(self.fixture_state(), "mark-deployed", "node-a")
        node = state["nodes"]["node-a"]
        self.assertEqual(node["bootstrap_private_key"], "")
        self.assertEqual(node["management_port"], node["ssh_port"])

    def test_invalid_local_region_is_rejected(self):
        result = subprocess.run(
            [
                sys.executable,
                str(STATE_CLI),
                "set-local-region",
                "node-a",
                "enabled",
                "--local-region-countries",
                "xx",
            ],
            cwd=ROOT_DIR,
            input=json.dumps(self.fixture_state()),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported country code", result.stderr)


if __name__ == "__main__":
    unittest.main()
