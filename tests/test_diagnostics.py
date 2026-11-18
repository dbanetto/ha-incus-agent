"""Exercise host inspection using temporary fixtures, never the real host."""

import errno
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "diagnostics", Path(__file__).parents[1] / "incus_agent/diagnostics.py"
)
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "host"
        self.proc = self.base / "proc"
        self.write(self.proc / "1/comm", "systemd\n")
        self.write(self.root / "etc/os-release", 'ID=haos\nVERSION_ID="17.0"\n')
        self.write(self.proc / "filesystems", "nodev\t9p\nnodev\tvirtiofs\n")
        self.write(self.proc / "1/mountinfo", "")
        self.subject = diagnostics.Diagnostics(self.root, self.proc)

    @staticmethod
    def write(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def states(self):
        return {item["name"]: item["status"] for item in self.subject.run()["checks"]}

    def test_missing_native_agent(self):
        states = self.states()
        self.assertEqual(states["host_scope"], "present")
        self.assertEqual(states["lxd-agent_unit"], "absent")
        self.assertEqual(states["agent_processes"], "absent")
        self.assertEqual(states["mounted_agent_shares"], "unknown")
        self.assertEqual(states["driver_vsock"], "unknown")

    def test_native_service_and_process(self):
        self.write(self.root / "usr/lib/systemd/system/lxd-agent.service", "[Service]\n")
        self.write(self.proc / "42/comm", "incus-agent\n")
        report = self.subject.run()
        states = {item["name"]: item["status"] for item in report["checks"]}
        self.assertEqual(states["lxd-agent_unit"], "present")
        self.assertEqual(states["agent_processes"], "present")
        self.assertIn("Do not start a second agent", report["conclusion"])

    def test_container_pid_namespace_is_not_host(self):
        self.write(self.proc / "1/comm", "python3\n")
        self.assertEqual(self.states(), {"host_scope": "unknown"})

    def test_non_haos_host_is_not_probed(self):
        self.write(self.root / "etc/os-release", "ID=alpine\n")
        self.assertEqual(self.states(), {"host_scope": "unknown"})

    def test_permission_denied_is_not_absence(self):
        with patch.object(Path, "lstat", side_effect=PermissionError(errno.EACCES, "denied")):
            self.assertEqual(self.subject.probe("dev/vsock"), "unknown")

    def test_incomplete_process_scan_is_unknown(self):
        self.write(self.proc / "42/comm", "other\n")
        original = Path.read_text

        def read_text(path, *args, **kwargs):
            if path == self.proc / "42/comm":
                raise PermissionError(errno.EACCES, "denied")
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_text):
            self.subject.processes()
        self.assertEqual(self.subject.checks[0]["status"], "unknown")

    def test_os_release_absolute_symlink_and_board(self):
        (self.root / "etc/os-release").unlink()
        self.write(self.root / "usr/lib/os-release", "ID=haos\nVARIANT_ID=generic-aarch64\n")
        (self.root / "etc/os-release").symlink_to("/usr/lib/os-release")
        report = self.subject.run()
        identity = next(check["identity"] for check in report["checks"] if check["name"] == "host_os")
        self.assertEqual(identity["VARIANT_ID"], "generic-aarch64")

    def test_absolute_symlinks_resolve_in_host(self):
        self.write(self.root / "usr/lib/systemd/system/incus-agent.service", "[Service]\n")
        (self.root / "lib").symlink_to("/usr/lib")
        self.assertEqual(self.subject.probe("lib/systemd/system/incus-agent.service"), "present")

    def test_symlink_loop_is_unknown(self):
        (self.root / "loop").symlink_to("/loop")
        self.assertEqual(self.subject.probe("loop"), "unknown")

    def test_registered_filesystems_and_mounted_share(self):
        self.write(self.proc / "1/mountinfo", "31 20 0:30 / /mnt/config ro - 9p config ro\n")
        states = self.states()
        self.assertEqual(states["9p_registered"], "present")
        self.assertEqual(states["virtiofs_registered"], "present")
        self.assertEqual(states["mounted_agent_shares"], "present")

    def test_unregistered_filesystem_is_unknown(self):
        self.write(self.proc / "filesystems", "nodev\tproc\n")
        self.assertEqual(self.states()["9p_registered"], "unknown")

    def test_default_does_not_run_source_check(self):
        source = Mock()
        with patch.dict("sys.modules", {"source_check": source}):
            self.subject.run()
        source.run_source_check.assert_not_called()

    def test_opt_in_runs_source_check(self):
        source = Mock()
        source.run_source_check.return_value = {
            "status": "present", "detail": "Source inspection only.", "attempts": [],
        }
        with patch.dict("sys.modules", {"source_check": source}):
            report = self.subject.run("source_check")
        source.run_source_check.assert_called_once_with(self.subject)
        self.assertEqual(report["mode"], "source_check")
        self.assertIn("At least one source share", report["conclusion"])

    def test_unknown_host_never_runs_source_check(self):
        self.write(self.proc / "1/comm", "python3\n")
        source = Mock()
        with patch.dict("sys.modules", {"source_check": source}):
            self.subject.run("source_check")
        source.run_source_check.assert_not_called()

    def test_options_default_and_opt_in(self):
        options = self.base / "options.json"
        self.assertEqual(diagnostics.load_mode(options), "diagnose")
        options.write_text('{"mode": "source_check"}')
        self.assertEqual(diagnostics.load_mode(options), "source_check")
        options.write_text('{"mode": "manage"}')
        with self.assertRaises(ValueError):
            diagnostics.load_mode(options)


if __name__ == "__main__":
    unittest.main()
