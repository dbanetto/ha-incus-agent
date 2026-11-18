"""Source-check unit tests; mounts and subprocesses are mocked, never real."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "source_check", Path(__file__).parents[1] / "incus_agent/source_check.py"
)
source_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_check)


def elf(machine=183):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = machine.to_bytes(2, "little")
    return header


class SourceCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_aarch64_elf_and_connection_metadata(self):
        (self.root / "incus-agent").write_bytes(elf())
        for name in source_check.CREDENTIALS:
            (self.root / name).write_text("SECRET_MUST_NOT_BE_REPORTED")
        result = source_check.inspect_share(self.root, "config", "aarch64")
        self.assertTrue(result["binaries"]["incus-agent"]["architecture_matches"])
        self.assertTrue(all(value == "present" for value in result["connection_files"].values()))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_wrong_architecture(self):
        (self.root / "incus-agent").write_bytes(elf(62))
        self.assertFalse(source_check.inspect_share(self.root, "config", "aarch64")
                         ["binaries"]["incus-agent"]["architecture_matches"])

    def test_owned_header_inspection_does_not_resolve_magic_links(self):
        (self.root / "incus-agent").write_bytes(elf())
        with patch.object(Path, "resolve", side_effect=AssertionError("must preserve kernel magic links")):
            result = source_check.regular_binary_header(self.root / "incus-agent", "aarch64")
        self.assertTrue(result["architecture_matches"])

    def test_loader_script_and_split_agent_share(self):
        (self.root / "incus-agent").write_text("#!/bin/sh\nDO_NOT_EXECUTE\n")
        self.assertEqual(source_check.inspect_share(self.root, "config", "aarch64")
                         ["binaries"]["incus-agent"]["format"], "script")
        (self.root / "incus-agent.linux.aarch64").write_bytes(elf())
        result = source_check.inspect_share(self.root, "agent", "aarch64")
        self.assertTrue(result["binaries"]["incus-agent.linux.aarch64"]["architecture_matches"])
        self.assertEqual(result["connection_files"], {})

    def test_symlink_cannot_escape_share(self):
        outside = self.root / "outside"
        outside.write_bytes(elf())
        share = self.root / "share"
        share.mkdir()
        (share / "incus-agent").symlink_to(outside)
        self.assertEqual(source_check.inspect_share(share, "config", "aarch64")
                         ["binaries"]["incus-agent"]["format"], "outside_share_symlink")

    def test_relative_legacy_binary_symlink(self):
        (self.root / "incus-agent").write_bytes(elf())
        (self.root / "lxd-agent").symlink_to("incus-agent")
        result = source_check.inspect_share(self.root, "config", "aarch64")
        self.assertTrue(result["binaries"]["lxd-agent"]["architecture_matches"])

    def test_credential_symlink_not_followed(self):
        (self.root / "agent.key").symlink_to("/unreadable/secret")
        self.assertEqual(source_check.inspect_share(self.root, "config", "aarch64")
                         ["connection_files"]["agent.key"], "unknown")

    def test_binary_symlink_cannot_open_credential(self):
        (self.root / "agent.key").write_text("SECRET")
        (self.root / "incus-agent").symlink_to("agent.key")
        with patch.object(source_check.os, "open") as open_file:
            result = source_check.binary_header(self.root / "incus-agent", self.root, "aarch64")
        open_file.assert_not_called()
        self.assertEqual(result["format"], "unexpected_binary_target")

    def test_mount_is_read_only_and_always_unmounted(self):
        with patch.object(source_check, "command", return_value=0) as command, \
             patch.object(source_check, "mount_flags", return_value=source_check.REQUIRED_FLAGS), \
             patch.object(source_check, "inspect_share", return_value={"binaries": {}}):
            result = source_check.check_candidate({"filesystem": "9p", "tag": "config"}, "aarch64")
        self.assertEqual(result["status"], "present")
        self.assertEqual(result["cleanup"], "unmounted")
        args = command.call_args_list[0].args[0]
        self.assertIn("ro,nosuid,nodev,noexec,trans=virtio,access=0,version=9p2000.L", args)
        self.assertEqual(command.call_args_list[1].args[0][:2], ["umount", "-n"])

    def test_unsafe_mount_is_not_inspected(self):
        with patch.object(source_check, "command", return_value=0), \
             patch.object(source_check, "mount_flags", return_value={"rw"}), \
             patch.object(source_check, "inspect_share") as inspect:
            result = source_check.check_candidate({"filesystem": "virtiofs", "tag": "config"}, "aarch64")
        inspect.assert_not_called()
        self.assertEqual(result["status"], "unknown")

    def test_failed_mount_not_claimed_absent(self):
        with patch.object(source_check, "command", return_value=32), \
             patch.object(source_check, "mount_flags", return_value=set()), \
             patch.object(source_check, "inspect_share") as inspect:
            result = source_check.check_candidate({"filesystem": "9p", "tag": "config"}, "aarch64")
        inspect.assert_not_called()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["mount_exit_code"], 32)

    def test_inspection_failure_still_unmounts(self):
        with patch.object(source_check, "command", return_value=0) as command, \
             patch.object(source_check, "mount_flags", return_value=source_check.REQUIRED_FLAGS), \
             patch.object(source_check, "inspect_share", side_effect=OSError):
            result = source_check.check_candidate({"filesystem": "9p", "tag": "config"}, "aarch64")
        self.assertEqual(result["cleanup"], "unmounted")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(command.call_count, 2)

    def test_mountinfo_failure_still_unmounts(self):
        with patch.object(source_check, "command", return_value=0) as command, \
             patch.object(source_check, "mount_flags", side_effect=PermissionError):
            result = source_check.check_candidate({"filesystem": "9p", "tag": "config"}, "aarch64")
        self.assertEqual(result["cleanup"], "unmounted")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(command.call_count, 2)

    def test_discovery_prefers_advertised_known_tags(self):
        device = self.root / "sys/bus/virtio/devices/virtio3"
        device.mkdir(parents=True)
        (device / "mount_tag").write_text("agent\x00\n")
        inspector = Mock()
        inspector.host_path.side_effect = lambda relative: self.root / relative
        result = source_check.discover(inspector)
        self.assertEqual(result[0], {"filesystem": "9p", "tag": "agent", "advertised": True})
        self.assertEqual(len(result), 4)
        (device / "mount_tag").write_text("unrelated-secret-share")
        self.assertFalse(any(item["advertised"] for item in source_check.discover(inspector)))

    def test_unmount_failure_uses_lazy_detach(self):
        with patch.object(source_check, "command", side_effect=[0, 32, 0]), \
             patch.object(source_check, "mount_flags", return_value=source_check.REQUIRED_FLAGS), \
             patch.object(source_check, "inspect_share", return_value={}):
            result = source_check.check_candidate({"filesystem": "9p", "tag": "config"}, "aarch64")
        self.assertEqual(result["cleanup"], "lazy_detached")
        self.assertEqual(result["status"], "unknown")

    def test_arbitrary_mount_sources_rejected(self):
        with self.assertRaises(ValueError):
            source_check.check_candidate({"filesystem": "ext4", "tag": "/dev/sda"}, "aarch64")

    def test_worker_refuses_parent_namespace(self):
        with patch.object(source_check.os, "stat", return_value=Mock(st_ino=42)), \
             patch.object(source_check, "check_candidate") as check:
            result = source_check.worker({"parent_mount_namespace": 42, "candidates": []})
        check.assert_not_called()
        self.assertEqual(result["status"], "unknown")

    def test_worker_refuses_shared_propagation(self):
        with patch.object(source_check.os, "stat", side_effect=[Mock(st_ino=3), Mock(st_ino=1)]), \
             patch.object(Path, "read_text", return_value="1 0 0:1 / / rw shared:1 - ext4 root rw\n"), \
             patch.object(source_check, "check_candidate") as check:
            result = source_check.worker({"parent_mount_namespace": 2, "candidates": []})
        check.assert_not_called()
        self.assertEqual(result["status"], "unknown")

    def test_timeout_kills_worker_process_group(self):
        process = Mock(pid=1234)
        process.communicate.side_effect = [subprocess.TimeoutExpired("unshare", 150), ("", None)]
        with patch.object(source_check, "discover", return_value=[]), \
             patch.object(source_check.os, "stat", return_value=Mock(st_ino=1)), \
             patch.object(source_check.subprocess, "Popen", return_value=process), \
             patch.object(source_check.os, "killpg") as kill:
            result = source_check.run_source_check(Mock())
        kill.assert_called_once_with(1234, source_check.signal.SIGKILL)
        self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
