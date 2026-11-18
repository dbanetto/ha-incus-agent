# Incus Guest Agent for Home Assistant OS

Experimental Supervisor add-on for investigating Incus guest-agent support in
Home Assistant OS VMs, initially targeting ARM64. This is **not a HACS integration**.

## Current status: experimental opt-in agent supervision

Version 0.3.0 has three explicit modes:

| Mode | Behavior |
| --- | --- |
| `diagnose` (default) | Inspect host prerequisites and exit; no mounts or agent startup. |
| `source_check` | Inspect read-only Incus shares in a private namespace, then exit. |
| `manage` | Stage and supervise the Incus-supplied agent against the HAOS host. |

No mode installs a package or persistent systemd service. HAOS has no supported
runtime host package manager. Managed runtime operation is experimental and needs
validation on your VM; process startup is not proof of correct guest metrics.

### Install without a shell

1. Publish this repository to a GitHub URL accessible to your Supervisor.
2. In Home Assistant, open **Settings → Add-ons → Add-on Store → ⋮ → Repositories**
   (called Apps in newer versions), and add that repository URL.
3. Refresh the store and install **Incus Agent Diagnostics**. The first install
   builds the container on your HAOS machine and needs Internet access.
4. Open the add-on's **Info** page and turn **Protection mode off**. You may need
   **Advanced mode** enabled in your Home Assistant user profile to see this control.
5. Start the add-on, then open **Logs**. Copy the report for troubleshooting.

The diagnostic modes exit after reporting, so **Stopped** is expected for those
modes. `manage` stays running while its agent runs. Leave **Start on boot** off
until managed operation has been verified on your VM.

No shell, host SSH setup, network port, or Incus server credentials are needed.
Do not install this on a non-HAOS host or expose it as a general host-inspection service.

### Check the Incus-supplied agent source

Open the add-on's **Configuration** tab and select:

```yaml
mode: source_check
```

Save, start the add-on, and open **Logs**. Allow up to approximately three minutes.
The source-check result includes an `attempts` list for the `config` and `agent`
shares over virtiofs/9p. Advertised virtio tags are preferred; fixed known-tag
probes are used as fallback. No arbitrary devices or user-specified shares are mounted.

The worker creates a new mount namespace, makes propagation recursively private,
and refuses to proceed if that isolation cannot be verified. Mounts use
`ro,nosuid,nodev,noexec`; their flags are verified before files are inspected.
Normal unmount is attempted in a `finally` block, with lazy detach and namespace
destruction as cleanup backstops. The worker has bounded subprocess timeouts.
An uninterruptible kernel operation can still exceed those timeouts.

Only expected agent filenames are inspected, reading at most 64 bytes per binary
to distinguish ELF headers from loader scripts and compare ELF architecture.
Modern Incus may supply a script on `config` and a separate architecture-specific
binary on `agent`; a script is reported, **never executed**. Connection files
(`server.crt`, `agent.crt`, `agent.key`) are checked only for nonempty regular-file
metadata. Their contents are never opened, copied, or printed.

Successful mounting is not proof of a complete, usable agent installation. Check
binary `architecture_matches`, connection-file presence, and cleanup results.
Mount failures remain **UNKNOWN**, not evidence that a share is absent. Raw mount
error output is suppressed; reports include exit codes instead.

Switch back to `mode: diagnose` for passive checks. The container's broad
permissions apply to every mode because Supervisor permissions cannot vary by option.

### Run the agent (experimental)

**This gives the Incus host authenticated root command and file access to your
HAOS VM, not just metrics. Trust your Incus host and this add-on before enabling.**
Take a VM backup/snapshot before testing. Update to 0.3.0, keep Protection mode
off, select the following configuration, save, then start the add-on:

```yaml
mode: manage
```

Startup refuses to proceed unless the HAOS host is visible, no native agent unit
or process is detected, the process scan is complete, and Incus serial/vsock
devices exist. A host `/run` lock prevents concurrent managers from this project;
native launchers do not honour that lock, so checks are repeated before launch.

The first implementation supports **a matching inline `incus-agent` ELF on the
`config` share**, as confirmed on our ARM64 test VM. Split-share loader scripts
are recognised by source-check mode but are not yet supported in manage mode.
The binary and exactly three connection files are freshly copied into a random,
root-owned mode-0700 directory under host `/run/ha-incus-agent-*`. Credential
files are mode 0600; no credentials are saved to the add-on's persistent data.
Source shares must unmount successfully before execution is allowed.

Generic installers, templates, NIC configuration, mount recipes, and loader
scripts are not copied or run. The staged agent uses host mount, network, UTS,
IPC and cgroup namespace views and host root/cwd via `nsenter`; host PID access is
already enabled. A fixed host-side check verifies namespace equality and HAOS
identity before executing it. The agent stays in the add-on's resource cgroup;
joining the host cgroup namespace does not move its resource-group membership.
Its environment is allowlisted, excluding Supervisor tokens and notify sockets.

Look for `Host namespace/root verification passed` and the agent's own startup
logs, then verify from the **Incus host**:

```sh
incus exec ha -- uname -a
incus exec ha -- cat /etc/os-release
incus info ha
```

The OS must be HAOS, not Alpine. Compare guest memory, networking and filesystem
metrics with HAOS observations before relying on them. This version does not
automatically certify connectivity or metric correctness.

Stopping the add-on forwards SIGTERM to its agent process group, escalating to
SIGKILL if needed, then removes only its own runtime directory. Unexpected agent
exit fails the add-on without an automatic restart loop. Unclean shutdown can
leave private runtime files until reboot; host `/run` is volatile. An empty lock
file is deliberately retained until reboot to avoid lock-file unlink races.
If termination cannot be confirmed, runtime files are retained and a warning is
logged. Changing modes requires stopping/restarting the add-on.

The agent itself can create guest-API sockets and act on authenticated host
requests. Stopping it does **not** roll back host file changes, mounts, or other
actions requested through Incus, nor does the add-on delete arbitrary agent-created
host paths. Active exec sessions may be interrupted when the add-on stops.

## Security

**The container has effectively root-level host access in every mode**:

- `host_pid` exposes host processes and `/proc/1/root`.
- `SYS_PTRACE` and `DAC_READ_SEARCH` allow the host-root inspection needed here.
- `SYS_ADMIN` permits the isolated mount namespace and temporary source mounts.
- `full_access` enables privileged hardware access for virtio serial/vsock and
  host-level agent operations. This is much broader than just mapping two devices.
- AppArmor confinement is disabled for this experimental image.
- Protection mode must be off for host PID access.

A compromise of this add-on could compromise the HAOS host. These are prototype
permissions, **not a proven minimum**. The configuration does not separately map
the Docker socket or host D-Bus, but a privileged process with host-root access
can reach them anyway. Turning off protection mode is a meaningful security
tradeoff, not a way to safely sandbox an untrusted agent. Passive modes do not
explicitly load modules; mounts can trigger autoloading, and the managed upstream
agent can load drivers or perform other host actions as part of normal operation.

Passive modes do not read agent credentials, process arguments, or journal
contents. Source-check mode reads binary headers only, never executing them.
Manage mode copies credentials privately and executes the binary supplied by the
Incus host; neither source credential contents nor Supervisor tokens are logged. It
prints selected OS identity, driver/device presence, service-file presence,
agent-named PIDs, relevant mounted share paths, and source-check metadata.
Review logs before sharing them. A JSON copy is written only to this add-on's
private `/data/report.json`; it is not directly downloadable from the UI.

## Interpreting the report

- **PRESENT**: the specific file, process name, or kernel registration was observed.
- **ABSENT**: the specific inspected item was missing, with no access failure.
- **UNKNOWN**: permissions, incomplete visibility, or the probe's limitations mean
  absence cannot safely be inferred.
- **INFO**: environment metadata.

A service file does not establish whether the service is active or failed. A
process-name match does not establish which container or service owns it, or
whether the agent works. An unregistered filesystem or missing module entry does
not establish that a driver is unavailable. An unmounted share cannot be detected
by inspecting mount information. Passive diagnostics do not test vsock communication.

Native agent processes or launcher files are reasons to investigate before
starting a replacement. From the Incus host, connectivity can be tested with:

```sh
incus exec ha -- /bin/sh -c 'uname -a'
```

## Remaining validation

Validate managed startup, VM-wide metrics, stop/restart, reboot, snapshot restore,
and HAOS/Incus upgrades on real machines. Runtime namespace checks are safeguards,
not evidence that the whole lifecycle works. Missing kernel features may require
HAOS changes rather than an add-on workaround. Split-share binary staging and
tighter hardware/capability permissions remain future work.

## Development

The collector uses only Python's standard library. Run fixture-based tests with:

```sh
python3 -m unittest discover -s tests -v
```

Build locally with Docker (optional):

```sh
docker build --build-arg BUILD_ARCH=aarch64 -t ha-incus-diagnostics incus_agent
```

Building does not test HAOS host access. Running the image normally on your laptop
should report an unknown host scope, not treat the container as the host. A real
Supervisor/HAOS test is still required, especially for permissions and ARM64.
