import contextlib
import io
import json
import sys
import unittest
from unittest.mock import patch

from scripts.render_nodes import connectivity_lines, firewall_hint, main


class NodeConnectivityTests(unittest.TestCase):
    NODE = {
        "xray": {
            "vision_port": 38642,
            "xhttp_port": 49753,
        },
    }

    @staticmethod
    def diagnostics(vpn):
        return {
            "management": {
                "management_port": 22,
                "ssh_port": 22,
                "ssh": "connected",
                "xray": "xray-running",
            },
            "vpn": vpn,
        }

    def test_firewall_hint_for_running_xray_with_both_vpn_ports_blocked(self):
        diagnostics = self.diagnostics([(38642, False), (49753, False)])

        self.assertTrue(firewall_hint(diagnostics))
        lines = connectivity_lines(self.NODE, diagnostics)
        self.assertIn("OpenSSH", lines[0])
        self.assertIn("TCP 22", lines[0])
        self.assertIn("TCP 38642", lines[1])
        self.assertIn("TCP 49753", lines[2])
        self.assertTrue(all("unavailable" in line for line in lines[1:]))

    def test_firewall_hint_is_not_shown_when_a_vpn_port_is_reachable(self):
        diagnostics = self.diagnostics([(38642, True), (49753, False)])

        self.assertFalse(firewall_hint(diagnostics))


class NodeCreationDateTests(unittest.TestCase):
    def test_iso_dates_and_invalid_date_fallback(self):
        for created, expected in (
            ("2026-11-02T00:15:00Z", "2026-11-02"),
            ("2026-11-02T00:15:00+00:00", "2026-11-02"),
            ("2026-11-02T00:15:00+03:00", "2026-11-02"),
            ("N/A", "N/A"),
        ):
            with self.subTest(created=created):
                state = {"nodes": {"node-a": {"created_at": created}}}
                output = io.StringIO()
                with (
                    patch.object(sys, "argv", ["render_nodes.py"]),
                    patch.object(sys, "stdin", io.StringIO(json.dumps(state))),
                    contextlib.redirect_stdout(output),
                ):
                    main()
                self.assertIn(expected, output.getvalue())


if __name__ == "__main__":
    unittest.main()
