"""Read-only HAOS host inspection; never execute or install a guest agent."""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import platform
import stat
import sys


AGENTS = {"incus-agent", "lxd-agent"}
UNIT_DIRS = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")


def failure_status(error: OSError) -> str:
    """Only a genuine missing path is evidence of absence."""
    return "absent" if error.errno in (errno.ENOENT, errno.ENOTDIR) else "unknown"


class Diagnostics:
    def __init__(self, host_root: Path = Path("/proc/1/root"), proc: Path = Path("/proc")):
        self.root = host_root
        self.proc = proc
        self.checks: list[dict] = []

    def add(self, name: str, status: str, detail: str, **extra) -> None:
        self.checks.append(dict(name=name, status=status, detail=detail, **extra))

    def host_path(self, relative: str) -> Path:
        """Resolve absolute symlinks inside the host, not the add-on's root."""
        pending = relative.split("/")
        parts: list[str] = []
        links = 0
        while pending:
            part = pending.pop(0)
            if part in {"", "."}:
                continue
            if part == "..":
                parts = parts[:-1]
                continue
            path = self.root.joinpath(*parts, part)
            if stat.S_ISLNK(path.lstat().st_mode):
                links += 1
                if links > 40:
                    raise OSError(errno.ELOOP, "Host symlink limit exceeded")
                target = os.readlink(path)
                if target.startswith("/"):
                    parts = []
                pending = target.split("/") + pending
            else:
                parts.append(part)
        return self.root.joinpath(*parts)

    def probe(self, relative: str) -> str:
        try:
            self.host_path(relative).stat()
            return "present"
        except OSError as error:
            return failure_status(error)

    def host_identity(self) -> bool:
        try:
            init = (self.proc / "1/comm").read_text().strip()
        except OSError:
            self.add("host_scope", "unknown", "Cannot inspect PID 1; host PID access is required.")
            return False
        if init != "systemd":
            self.add("host_scope", "unknown", "PID 1 is not systemd; refusing to treat this view as HAOS.")
            return False
        try:
            values = {}
            for line in self.host_path("etc/os-release").read_text().splitlines():
                key, sep, value = line.partition("=")
                if sep and key in {
                    "ID", "NAME", "VERSION_ID", "PRETTY_NAME", "VARIANT_ID",
                    "SUPERVISOR_MACHINE", "SUPERVISOR_ARCH",
                }:
                    values[key] = value.strip('"\'')
        except OSError:
            self.add("host_scope", "unknown", "Cannot read host os-release; check protection mode and privileges.")
            return False
        if values.get("ID") not in {"haos", "hassos"}:
            self.add("host_scope", "unknown", "Host OS is not identified as HAOS; no further host probes performed.")
            return False
        self.add("host_scope", "present", "Host PID namespace and HAOS root are visible.")
        self.add("host_os", "info", "HAOS identity from the host filesystem.", identity=values)
        return True

    def services(self) -> None:
        for agent in sorted(AGENTS):
            paths = [f"{directory}/{agent}.service" for directory in UNIT_DIRS]
            states = [self.probe(path) for path in paths]
            status = "present" if "present" in states else "unknown" if "unknown" in states else "absent"
            self.add(f"{agent}_unit", status, "Unit-file presence only; service active/failed state is not queried.")

    def processes(self) -> None:
        found = []
        incomplete = False
        try:
            entries = list(self.proc.iterdir())
        except OSError:
            self.add("agent_processes", "unknown", "Cannot enumerate host processes.")
            return
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                # Do not read command-line arguments: these can contain secrets.
                name = (entry / "comm").read_text().strip()
                if name in AGENTS:
                    found.append({"pid": int(entry.name), "name": name})
            except OSError as error:
                # Processes can disappear during the scan; permission errors are different.
                if failure_status(error) != "absent":
                    incomplete = True
        status = "present" if found else "unknown" if incomplete else "absent"
        self.add("agent_processes", status,
                 "Process-name matches only; presence does not prove host connectivity or native ownership.",
                 processes=found, scan_complete=not incomplete)

    def devices(self) -> None:
        for label, relative in (
            ("vsock_device", "dev/vsock"),
            ("incus_serial_symlink", "dev/virtio-ports/org.linuxcontainers.incus"),
            ("lxd_serial_symlink", "dev/virtio-ports/org.linuxcontainers.lxd"),
            ("agent_config_cdrom", "dev/disk/by-label/incus-agent"),
        ):
            self.add(label, self.probe(relative), f"Host path /{relative} (existence, not an access/transport test).")
        try:
            names = []
            for entry in self.host_path("sys/class/virtio-ports").iterdir():
                name = self.host_path(f"sys/class/virtio-ports/{entry.name}/name").read_text().strip()
                if name in {"org.linuxcontainers.incus", "org.linuxcontainers.lxd"}:
                    names.append(name)
            self.add("agent_serial_ports", "present" if names else "absent",
                     "Port names from host sysfs; no device is opened or written.", ports=sorted(names))
        except OSError as error:
            self.add("agent_serial_ports", failure_status(error), "Could not inspect virtio port names.")

    def kernel(self) -> None:
        try:
            filesystems = (self.proc / "filesystems").read_text().split()
            for filesystem in ("9p", "virtiofs"):
                self.add(f"{filesystem}_registered", "present" if filesystem in filesystems else "unknown",
                         "Registered filesystem support; an unregistered driver may still be loadable.")
        except OSError:
            self.add("registered_filesystems", "unknown", "Cannot read kernel filesystem registrations.")
        for module in ("vsock", "vmw_vsock_virtio_transport", "9pnet_virtio", "virtio_console"):
            status = self.probe(f"sys/module/{module}")
            self.add(f"driver_{module}", "present" if status == "present" else "unknown",
                     "Sysfs driver entry only; absence does not prove missing kernel support.")

    def agent_source(self) -> None:
        for agent in sorted(AGENTS):
            states = [self.probe(f"run/{directory}/{agent}") for directory in ("incus_agent", "lxd_agent")]
            status = "present" if "present" in states else "unknown" if "unknown" in states else "absent"
            self.add(f"runtime_{agent}", status, "Existing runtime binary path; credentials and binary contents are not read.")
        try:
            lines = (self.proc / "1/mountinfo").read_text().splitlines()
            shares = []
            for line in lines:
                left, sep, right = line.partition(" - ")
                fields, mount = left.split(), right.split()
                if sep and len(fields) >= 5 and len(mount) >= 2:
                    if mount[0] in {"9p", "virtiofs"} and mount[1] in {"config", "agent"}:
                        shares.append({"filesystem": mount[0], "tag": mount[1], "mountpoint": fields[4]})
            self.add("mounted_agent_shares", "present" if shares else "unknown",
                     "Host mounts only; an available but unmounted share cannot be detected here.", shares=shares)
        except OSError:
            self.add("mounted_agent_shares", "unknown", "Cannot read host mount information.")

    def run(self) -> dict:
        if self.host_identity():
            self.services()
            self.processes()
            self.devices()
            self.kernel()
            self.agent_source()
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "diagnose",
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "checks": self.checks,
            "conclusion": self.conclusion(),
        }

    def conclusion(self) -> str:
        states = {check["name"]: check["status"] for check in self.checks}
        if states.get("host_scope") != "present":
            return "Host inspection unavailable. Check protection mode and add-on privileges. No changes made."
        if states.get("agent_processes") == "present":
            return "Agent-named process detected. Do not start a second agent; verify connectivity from Incus."
        if any(states.get(f"{agent}_unit") == "present" for agent in AGENTS):
            return "Native launcher found. Inspect service state before considering a replacement."
        return "No managed agent was started. Review individual checks; runtime feasibility is not yet established."


def main() -> int:
    report = Diagnostics().run()
    print("Incus guest agent diagnostics — read-only, no installation or startup")
    for check in report["checks"]:
        print(f"[{check['status'].upper()}] {check['name']}: {check['detail']}")
        for key in ("identity", "processes", "ports", "shares"):
            if check.get(key):
                print(f"  {key}: {json.dumps(check[key], sort_keys=True)}")
    print(f"\nConclusion: {report['conclusion']}")
    try:
        # /data belongs to this add-on. No host paths are written.
        Path("/data/report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Report saved to the add-on's private /data/report.json.")
    except OSError:
        print("Could not save private report; diagnostic results remain in these logs.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
