"""Opt-in, isolated read-only inspection. Never execute files from a share."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import tempfile


FILESYSTEMS = ("virtiofs", "9p")
TAGS = ("config", "agent")
CREDENTIALS = ("server.crt", "agent.crt", "agent.key")
ARCHITECTURES = {"aarch64": 183, "x86_64": 62}
REQUIRED_FLAGS = {"ro", "nosuid", "nodev", "noexec"}


def discover(inspector) -> list[dict]:
    """Use advertised tags when visible; fixed fallback probes are still needed."""
    advertised = set()
    try:
        entries = list(inspector.host_path("sys/bus/virtio/devices").iterdir())
    except OSError:
        entries = []
    for entry in entries:
        for attribute, filesystem in (("mount_tag", "9p"), ("tag", "virtiofs")):
            try:
                path = inspector.host_path(f"sys/bus/virtio/devices/{entry.name}/{attribute}")
                tag = path.read_text().strip("\x00\n ")
                if tag in TAGS:
                    advertised.add((filesystem, tag))
            except OSError:
                continue
    # Older virtio drivers may not expose tags in sysfs. Only probe these two
    # known tags; never use arbitrary options or sources supplied by a user/share.
    all_pairs = [(filesystem, tag) for tag in TAGS for filesystem in FILESYSTEMS]
    all_pairs.sort(key=lambda pair: pair not in advertised)
    return [{"filesystem": fs, "tag": tag, "advertised": (fs, tag) in advertised}
            for fs, tag in all_pairs]


def binary_header(path: Path, root: Path, architecture: str) -> dict:
    """Read at most 64 bytes; never run the binary or print header contents."""
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root.resolve(strict=True)):
            return {"status": "unknown", "format": "outside_share_symlink"}
        allowed = {"incus-agent", "lxd-agent", f"incus-agent.linux.{architecture}"}
        if resolved.parent != root.resolve(strict=True) or resolved.name not in allowed:
            return {"status": "unknown", "format": "unexpected_binary_target"}
        fd = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return {"status": "unknown", "format": "not_regular"}
            header = os.read(fd, 64)
        finally:
            os.close(fd)
    except FileNotFoundError:
        return {"status": "absent"}
    except (OSError, RuntimeError):
        return {"status": "unknown"}
    if header.startswith(b"#!"):
        return {"status": "present", "format": "script", "architecture_matches": None}
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[5] not in (1, 2):
        return {"status": "unknown", "format": "unrecognised"}
    machine = int.from_bytes(header[18:20], "little" if header[5] == 1 else "big")
    expected = ARCHITECTURES.get(architecture)
    return {"status": "present", "format": "ELF", "elf_machine": machine,
            "architecture_matches": (header[4] == 2 and header[5] == 1 and machine == expected) if expected else None}


def inspect_share(root: Path, tag: str, architecture: str) -> dict:
    names = ("incus-agent", "lxd-agent") if tag == "config" else (
        "incus-agent", f"incus-agent.linux.{architecture}",
    )
    binaries = {name: binary_header(root / name, root, architecture) for name in names}
    credentials = {}
    if tag == "config":
        for name in CREDENTIALS:
            try:
                # Only metadata is read. Never follow credential symlinks.
                info = (root / name).lstat()
                credentials[name] = "present" if stat.S_ISREG(info.st_mode) and info.st_size > 0 else "unknown"
            except FileNotFoundError:
                credentials[name] = "absent"
            except OSError:
                credentials[name] = "unknown"
    return {"binaries": binaries, "connection_files": credentials}


def mount_flags(target: Path) -> set[str]:
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 5 and fields[4] == str(target):
            return set(fields[5].split(","))
    return set()


def command(args: list[str]) -> int:
    """Do not surface external command output; it is not part of our report."""
    try:
        return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=15, check=False).returncode
    except subprocess.TimeoutExpired:
        return 124
    except OSError:
        return 127


def check_candidate(candidate: dict, architecture: str) -> dict:
    filesystem, tag = candidate["filesystem"], candidate["tag"]
    if filesystem not in FILESYSTEMS or tag not in TAGS:
        raise ValueError("Unsupported share candidate")
    target = Path(tempfile.mkdtemp(prefix="incus-source-"))
    result = dict(candidate, status="unknown")
    mounted = False
    try:
        options = "ro,nosuid,nodev,noexec"
        if filesystem == "9p":
            options += ",trans=virtio,access=0,version=9p2000.L"
        # -i prevents invoking filesystem mount helpers; -n avoids mtab writes.
        code = command(["mount", "-i", "-n", "-t", filesystem, "-o", options, tag, str(target)])
        mounted = code == 0
        # Inspect actual mount state even if the command timed out or failed.
        flags = mount_flags(target)
        mounted = mounted or bool(flags)
        if code != 0:
            result.update(detail="Mount failed or timed out; share availability is inconclusive.", mount_exit_code=code)
        elif not REQUIRED_FLAGS.issubset(flags):
            result["detail"] = "Required read-only/noexec mount flags were not verified; contents not inspected."
        else:
            result.update(status="present", detail="Share mounted read-only and inspected without executing files.")
            result.update(inspect_share(target, tag, architecture))
    except (OSError, ValueError):
        result.update(status="unknown", detail="Share inspection failed; no external error output included.")
    finally:
        if mounted:
            code = command(["umount", "-n", str(target)])
            if code != 0:
                # Namespace destruction is the final backstop; never recurse
                # into or delete files beneath a mount that might still exist.
                detached = command(["umount", "-n", "-l", str(target)]) == 0
                result["cleanup"] = "lazy_detached" if detached else "namespace_exit_required"
                result["status"] = "unknown"
            else:
                result["cleanup"] = "unmounted"
        try:
            target.rmdir()
        except OSError:
            pass
    return result


def worker(payload: dict) -> dict:
    # The unshare wrapper must create a NEW namespace, never enter the host's.
    own = os.stat("/proc/self/ns/mnt").st_ino
    if own in {payload["parent_mount_namespace"], os.stat("/proc/1/ns/mnt").st_ino}:
        return {"status": "unknown", "detail": "Mount namespace isolation was not established."}
    # Refuse to mount anything until recursive propagation is known private.
    # unshare --propagation private performs this before launching the worker.
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        optional = line.partition(" - ")[0].split()[6:]
        if any(field.startswith(("shared:", "master:", "propagate_from:")) for field in optional):
            return {"status": "unknown", "detail": "Mount propagation is not private; no shares mounted."}
    architecture = platform.machine()
    if architecture not in ARCHITECTURES:
        return {"status": "unknown", "detail": "Unsupported inspection architecture."}
    results = [check_candidate(candidate, architecture) for candidate in payload["candidates"]]
    return {"status": "present" if any(r["status"] == "present" for r in results) else "unknown",
            "detail": "Source inspection only; no agent installed or executed.", "attempts": results}


def run_source_check(inspector) -> dict:
    candidates = discover(inspector)
    try:
        payload = json.dumps({"candidates": candidates,
                              "parent_mount_namespace": os.stat("/proc/self/ns/mnt").st_ino})
        args = ["unshare", "--mount", "--propagation", "private", "--",
                sys.executable, str(Path(__file__).resolve()), "--worker"]
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        try:
            output, _ = process.communicate(payload, timeout=150)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            return {"status": "unknown", "detail": "Source-check timed out; isolated worker terminated."}
        if process.returncode != 0:
            return {"status": "unknown", "detail": "Isolated worker could not run. Check SYS_ADMIN and Supervisor security restrictions."}
        return json.loads(output)
    except (OSError, ValueError):
        return {"status": "unknown", "detail": "Cannot launch or read isolated source-check worker."}


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("This helper is only called by the diagnostic collector.")
    try:
        print(json.dumps(worker(json.load(sys.stdin))))
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"status": "unknown", "detail": "Source-check worker failed safely."}))
