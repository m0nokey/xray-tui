import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT_DIR = Path(__file__).resolve().parent.parent


class ControllerPrivilegeTests(unittest.TestCase):
    def test_kex_query_does_not_inherit_vps_privilege_escalation(self):
        role = ROOT_DIR / "ansible/roles/system_base/tasks/harden_ssh.yml"
        tasks = yaml.safe_load(role.read_text(encoding="utf-8"))
        query = next(
            task for task in tasks
            if task["name"] == "Detect controller SSH KEX algorithms"
        )
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            # Keep the target user distinct even when tests run as root, so
            # losing become: false always attempts privilege escalation.
            play = [{
                "name": "Check controller privileges under a privileged VPS play",
                "hosts": "vps",
                "gather_facts": False,
                "become": True,
                "become_user": "nobody" if os.geteuid() == 0 else "root",
                "become_exe": str(temporary / "sudo-must-not-be-used"),
                "tasks": [query, {
                    "name": "Require successful read-only controller query",
                    "ansible.builtin.assert": {
                        "that": [
                            "system_base_harden_ssh_controller_kex_cmd.rc == 0",
                            "system_base_harden_ssh_controller_kex_cmd.stdout_lines | length > 0",
                            "not system_base_harden_ssh_controller_kex_cmd.changed",
                        ],
                    },
                }],
            }]
            playbook = temporary / "check.yml"
            playbook.write_text(yaml.safe_dump(play), encoding="utf-8")
            environment = os.environ.copy()
            environment["ANSIBLE_LOCAL_TEMP"] = str(temporary / "ansible-local")
            result = subprocess.run(
                ["ansible-playbook", "-i", "vps,", str(playbook)],
                cwd=ROOT_DIR,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
