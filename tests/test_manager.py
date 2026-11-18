"""Managed-agent tests use fixtures/mocks; never execute an agent or enter namespaces."""

import importlib
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch


with patch.object(sys, "path", [str(Path(__file__).parents[1] / "incus_agent"), *sys.path]):
    manager = importlib.import_module("manager")


def elf(machine=183):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = machine.to_bytes(2, "little")
    return header


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.runtime = self.base / "ha-incus-agent-test"
        self.source.mkdir()
        self.runtime.mkdir(mode=0o700)
        (self.source / "incus-agent").write_bytes(elf())
        for name in manager.CREDENTIALS:
            (self.source / name).write_text("PRIVATE_CONNECTION_MATERIAL")

    @staticmethod
    def inspector(**overrides):
        states = {"host_scope": "present", "agent_processes": "absent",
                  "incus-agent_unit": "absent", "lxd-agent_unit": "absent",
                  "vsock_device": "present", "incus_serial_symlink": "present"}
        states.update(overrides)
        inspector = Mock()
        inspector.run.return_value = {"checks": [{"name": key, "status": value} for key, value in states.items()]}
        return inspector

    def test_preflight_accepts_only_complete_prerequisites(self):
        manager.preflight(self.inspector())
        for override in ({"agent_processes": "present"}, {"agent_processes": "unknown"},
                         {"lxd-agent_unit": "present"}, {"vsock_device": "unknown"},
                         {"host_scope": "unknown"}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                manager.preflight(self.inspector(**override))

    def test_stages_allowlist_with_private_permissions(self):
        (self.source / "install.sh").write_text("DO NOT RUN")
        (self.source / "agent-mounts.json").write_text("DO NOT COPY")
        (self.source / "nics").mkdir()
        self.assertTrue(manager.stage_files(self.source, self.runtime, "aarch64"))
        self.assertEqual({path.name for path in self.runtime.iterdir()}, set(manager.FILES))
        self.assertEqual(stat.S_IMODE((self.runtime / "incus-agent").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.runtime / "agent.key").stat().st_mode), 0o600)

    def test_rejects_loader_scripts_and_wrong_architecture(self):
        for content in (b"#!/bin/sh\nDO_NOT_EXECUTE\n", elf(62)):
            with self.subTest(content=content[:6]):
                (self.source / "incus-agent").write_bytes(content)
                with self.assertRaises(ValueError):
                    manager.stage_files(self.source, self.runtime, "aarch64")
                self.assertEqual(list(self.runtime.iterdir()), [])

    def test_does_not_follow_credential_symlinks(self):
        (self.source / "agent.key").unlink()
        (self.source / "agent.key").symlink_to(self.source / "agent.crt")
        with self.assertRaises(OSError):
            manager.stage_files(self.source, self.runtime, "aarch64")

    def test_copy_rejects_oversized_and_empty_files(self):
        for content in (b"", b"12345"):
            (self.source / "test").write_bytes(content)
            with self.assertRaises(ValueError):
                manager.copy_regular(self.source / "test", self.runtime / "out", 0o600, 4)
            self.assertFalse((self.runtime / "out").exists())

    def test_copy_does_not_overwrite_existing_files(self):
        (self.runtime / "incus-agent").write_text("existing")
        with self.assertRaises(FileExistsError):
            manager.stage_files(self.source, self.runtime, "aarch64")
        self.assertEqual((self.runtime / "incus-agent").read_text(), "existing")

    def test_launch_enters_host_root_and_all_required_namespaces(self):
        args = manager.launch_args(self.runtime)
        for flag in ("--mount", "--net", "--uts", "--ipc", "--cgroup", "--no-fork", "--root=/proc/1/root"):
            self.assertIn(flag, args)
        self.assertIn(f"--wd=/proc/1/root/run/{self.runtime.name}", args)
        self.assertEqual(args[-1], f"/run/{self.runtime.name}/incus-agent")
        self.assertNotIn("SUPERVISOR_TOKEN", manager.ENVIRONMENT)
        self.assertNotIn("NOTIFY_SOCKET", manager.ENVIRONMENT)

    def test_graceful_stop_forwards_signal(self):
        process = Mock(pid=321)
        stop = threading.Event()
        stop.set()
        with patch.object(manager.os, "killpg") as kill:
            self.assertEqual(manager.supervise(process, stop), 0)
        kill.assert_called_once_with(321, signal.SIGTERM)

    def test_stop_escalates_to_kill(self):
        process = Mock(pid=321)
        process.wait.side_effect = [subprocess.TimeoutExpired("agent", 10), 0]
        stop = threading.Event()
        stop.set()
        with patch.object(manager.os, "killpg") as kill:
            self.assertEqual(manager.supervise(process, stop), 0)
        self.assertEqual([call.args[1] for call in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])

    def test_unexpected_exit_does_not_restart(self):
        process = Mock(pid=321)
        process.wait.return_value = 0
        self.assertEqual(manager.supervise(process, threading.Event()), 1)
        process.wait.assert_called_once()

    def test_failed_staging_cleans_only_owned_runtime(self):
        inspector = self.inspector()
        inspector.host_path.return_value = self.base
        keep = self.base / "unrelated"
        keep.write_text("user data")
        with patch.object(manager, "acquire_lock", return_value=None), \
             patch.object(manager, "stage_runtime", return_value=False), \
             patch.object(manager.subprocess, "Popen") as launch:
            self.assertEqual(manager.manage(inspector), 1)
        launch.assert_not_called()
        self.assertEqual(keep.read_text(), "user data")
        # The fixture directory is unrelated to the invocation's random runtime.
        self.assertEqual(list(self.base.glob("ha-incus-agent-*")), [self.runtime])

    def test_manage_launches_only_after_staging_and_repeat_preflight(self):
        inspector = self.inspector()
        inspector.host_path.return_value = self.base
        process = Mock(pid=321)
        process.poll.return_value = 0
        with patch.object(manager, "acquire_lock", return_value=None), \
             patch.object(manager, "stage_runtime", return_value=True) as stage, \
             patch.object(manager, "Diagnostics", return_value=inspector), \
             patch.object(manager.subprocess, "Popen", return_value=process) as launch, \
             patch.object(manager, "supervise", return_value=0):
            self.assertEqual(manager.manage(inspector), 0)
        self.assertEqual(inspector.run.call_count, 2)
        stage.assert_called_once()
        launch.assert_called_once()
        self.assertEqual(launch.call_args.kwargs["env"], manager.ENVIRONMENT)
        self.assertTrue(launch.call_args.kwargs["start_new_session"])
        self.assertEqual(list(self.base.glob("ha-incus-agent-*")), [self.runtime])

    def test_new_native_agent_after_staging_prevents_launch(self):
        inspector = self.inspector()
        inspector.host_path.return_value = self.base
        conflict = self.inspector(agent_processes="present")
        with patch.object(manager, "acquire_lock", return_value=None), \
             patch.object(manager, "stage_runtime", return_value=True), \
             patch.object(manager, "Diagnostics", return_value=conflict), \
             patch.object(manager.subprocess, "Popen") as launch:
            self.assertEqual(manager.manage(inspector), 1)
        launch.assert_not_called()
        self.assertEqual(list(self.base.glob("ha-incus-agent-*")), [self.runtime])

    def test_failed_namespace_isolation_never_stages(self):
        with patch.object(manager, "verify_isolation", return_value="not isolated"), \
             patch.object(manager, "check_candidate") as check:
            result = manager.stage_worker({"parent_mount_namespace": 1})
        self.assertFalse(result["ready"])
        check.assert_not_called()

    def test_cannot_confirm_stop_preserves_runtime(self):
        process = Mock(pid=321)
        process.poll.return_value = None
        with patch.object(manager.os, "killpg", side_effect=PermissionError):
            self.assertFalse(manager.ensure_stopped(process))


if __name__ == "__main__":
    unittest.main()
