"""Experimental, opt-in Incus agent lifecycle. No persistent host installation."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading

from diagnostics import Diagnostics
from source_check import (
    CREDENTIALS, binary_header, check_candidate, discover, regular_binary_header, verify_isolation,
)


PREFIX = "ha-incus-agent-"
FILES = ("incus-agent", *CREDENTIALS)
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
               "USER": "root", "LOGNAME": "root", "LANG": "C.UTF-8"}

# Fixed script, not interpolated input. nsenter opens the working/root directories
# before changing namespaces; the executable path is passed as a positional arg.
HOST_EXEC = r'''
set -eu
grep -Eq '^ID="?(haos|hassos)"?$' /etc/os-release || exit 70
for ns in mnt net uts ipc cgroup; do
    current=$(readlink /proc/self/ns/$ns) || exit 71
    target=$(readlink /proc/1/ns/$ns) || exit 71
    [ -n "$current" ] && [ "$current" = "$target" ] || exit 71
done
printf '%s\n' 'Host namespace/root verification passed; executing Incus agent.'
exec "$1" --verbose
'''


def preflight(inspector: Diagnostics) -> None:
    """Fail closed on native agents, inaccessible checks, and missing transports."""
    report = inspector.run()
    states = {check["name"]: check["status"] for check in report["checks"]}
    required = {"host_scope": "present", "agent_processes": "absent",
                "incus-agent_unit": "absent", "lxd-agent_unit": "absent",
                "vsock_device": "present", "incus_serial_symlink": "present"}
    for name, expected in required.items():
        if states.get(name) != expected:
            raise ValueError(f"Startup refused: {name} must be {expected}, got {states.get(name, 'unknown')}.")


def acquire_lock(inspector: Diagnostics) -> int:
    path = inspector.host_path("run") / "ha-incus-agent.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("Startup refused: unsafe host runtime lock.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def copy_regular(source: Path, destination: Path, mode: int, limit: int) -> None:
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("Source is not a nonempty regular file within the size limit.")
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(destination_fd, "wb") as output:
                total = 0
                while chunk := os.read(source_fd, min(1024 * 1024, limit + 1 - total)):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError("Source exceeded its size limit during copy.")
                    output.write(chunk)
                if total == 0:
                    raise ValueError("Source became empty during copy.")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    finally:
        os.close(source_fd)


def stage_files(source: Path, runtime: Path, architecture: str) -> bool:
    # Initial manage mode deliberately supports the inline ELF layout confirmed
    # on the test VM, not execution of loader scripts or generic installers.
    header = binary_header(source / "incus-agent", source, architecture)
    if header.get("format") != "ELF" or header.get("architecture_matches") is not True:
        raise ValueError("Manage mode requires a matching inline incus-agent ELF on config.")
    resolved = (source / "incus-agent").resolve(strict=True)
    copy_regular(resolved, runtime / "incus-agent", 0o700, 128 * 1024 * 1024)
    for name in CREDENTIALS:
        copy_regular(source / name, runtime / name, 0o600, 1024 * 1024)
    staged = regular_binary_header(runtime / "incus-agent", architecture)
    if staged.get("architecture_matches") is not True:
        raise ValueError("Staged binary architecture check failed.")
    return True


def stage_worker(payload: dict) -> dict:
    problem = verify_isolation(payload["parent_mount_namespace"])
    if problem:
        return {"ready": False, "detail": problem}
    name = payload["runtime_name"]
    if not isinstance(name, str) or not re.fullmatch(r"ha-incus-agent-[a-zA-Z0-9_-]+", name):
        raise ValueError("Invalid managed runtime name")
    runtime = Path("/proc/1/root/run") / name
    info = runtime.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Unsafe managed runtime directory")
    architecture = platform.machine()
    attempts = []
    for candidate in payload["candidates"]:
        if candidate["tag"] != "config":
            continue
        # Only remove the fixed files this worker may have partially staged.
        for filename in FILES:
            (runtime / filename).unlink(missing_ok=True)
        result = check_candidate(candidate, architecture,
                                 visitor=lambda source: stage_files(source, runtime, architecture))
        attempts.append(result)
        if result.get("staged") is True and result.get("cleanup") == "unmounted" and result["status"] == "present":
            return {"ready": True, "detail": "Inline agent and connection files staged; source unmounted.",
                    "attempts": attempts}
        if result.get("cleanup") in {"lazy_detached", "namespace_exit_required"}:
            break
    return {"ready": False,
            "detail": "Staging failed. A matching inline ELF and all connection files on config are required.",
            "attempts": attempts}


def stage_runtime(inspector: Diagnostics, runtime: Path) -> bool:
    payload = {"runtime_name": runtime.name, "candidates": discover(inspector),
               "parent_mount_namespace": os.stat("/proc/self/ns/mnt").st_ino}
    process = subprocess.Popen(
        ["unshare", "--mount", "--propagation", "private", "--", sys.executable,
         str(Path(__file__).resolve()), "--stage-worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, start_new_session=True,
    )
    try:
        output, _ = process.communicate(json.dumps(payload), timeout=150)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        print("Staging timed out; isolated worker terminated.", flush=True)
        return False
    if process.returncode != 0:
        print("Staging worker failed; check mount namespace permissions.", flush=True)
        return False
    try:
        result = json.loads(output)
        print(f"Staging: {result['detail']}", flush=True)
        for attempt in result.get("attempts", []):
            print(f"  {json.dumps(attempt, sort_keys=True)}", flush=True)
        return result.get("ready") is True
    except (ValueError, KeyError, TypeError):
        print("Staging worker returned an invalid report.", flush=True)
        return False


def launch_args(runtime: Path) -> list[str]:
    guest = f"/run/{runtime.name}"
    return ["nsenter", "--target", "1", "--mount", "--net", "--uts", "--ipc", "--cgroup",
            "--no-fork", "--root=/proc/1/root", f"--wd=/proc/1/root{guest}",
            "--", "/bin/sh", "-c", HOST_EXEC, "ha-incus-agent", f"{guest}/incus-agent"]


def supervise(process, stop: threading.Event) -> int:
    try:
        while not stop.is_set():
            try:
                code = process.wait(timeout=1)
                print(f"Managed agent exited with status {code}; not restarting automatically.", flush=True)
                return code if code > 0 else 1
            except subprocess.TimeoutExpired:
                pass
        print("Stopping managed agent...", flush=True)
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        return 0
    except ProcessLookupError:
        process.wait()
        return 0 if stop.is_set() else 1


def ensure_stopped(process) -> bool:
    """Never remove credentials while a launched process could still use them."""
    if process is None or process.poll() is not None:
        return True
    try:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        return True
    except ProcessLookupError:
        return process.poll() is not None
    except (OSError, subprocess.TimeoutExpired):
        return False


def manage(inspector: Diagnostics | None = None) -> int:
    inspector = inspector or Diagnostics()
    stop = threading.Event()
    handlers = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
    runtime = None
    lock = None
    process = None
    try:
        print("MANAGE MODE: Incus will have root command/file access to the HAOS VM.", flush=True)
        preflight(inspector)
        lock = acquire_lock(inspector)
        runtime = Path(tempfile.mkdtemp(prefix=PREFIX, dir=inspector.host_path("run")))
        print("Staging fresh Incus-supplied runtime files; no persistent service will be installed.", flush=True)
        if not stage_runtime(inspector, runtime):
            return 1
        if stop.is_set():
            return 0
        # Repeat checks immediately before launch to narrow native-agent races.
        preflight(Diagnostics())
        process = subprocess.Popen(launch_args(runtime), env=ENVIRONMENT, stdin=subprocess.DEVNULL,
                                   start_new_session=True)
        print(f"Managed agent process launched (PID {process.pid}); verify connectivity from Incus.", flush=True)
        return supervise(process, stop)
    except (OSError, ValueError):
        # Never include arbitrary exception text: it can contain source details.
        print("Managed startup refused or failed. Check native-agent conflicts, privileges, and staging results.", flush=True)
        return 1
    finally:
        stopped = ensure_stopped(process)
        if runtime is not None and stopped:
            try:
                # Only this invocation's mkdtemp directory, never a shared path.
                shutil.rmtree(runtime)
                print("Managed runtime files removed.", flush=True)
            except OSError:
                print("WARNING: runtime cleanup failed; private files may remain in host /run until reboot.", flush=True)
        elif runtime is not None:
            print("WARNING: process termination could not be confirmed; runtime retained until container shutdown/reboot.", flush=True)
        if lock is not None:
            os.close(lock)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    if sys.argv[1:] != ["--stage-worker"]:
        raise SystemExit("Use the add-on's explicit manage mode.")
    try:
        print(json.dumps(stage_worker(json.load(sys.stdin))))
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"ready": False, "detail": "Staging worker failed safely."}))
