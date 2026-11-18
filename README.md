# Incus Guest Agent for Home Assistant OS

Experimental Supervisor add-on for investigating Incus guest-agent support in
Home Assistant OS VMs, initially targeting ARM64. This is **not a HACS integration**.

## Current status: diagnostics and opt-in source inspection

Version 0.2.0 inspects the HAOS host and prints a report in the add-on's **Logs**
tab. Default `diagnose` mode does not mount shares. Opt-in `source_check` mode
temporarily mounts known Incus shares read-only in a new private mount namespace.
Neither mode installs packages, executes an agent or installer, modifies services,
or fixes guest connectivity. HAOS has no supported runtime host package manager;
provisioning an agent is a future, separate milestone.

### Install without a shell

1. Publish this repository to a GitHub URL accessible to your Supervisor.
2. In Home Assistant, open **Settings → Add-ons → Add-on Store → ⋮ → Repositories**
   (called Apps in newer versions), and add that repository URL.
3. Refresh the store and install **Incus Agent Diagnostics**. The first install
   builds the container on your HAOS machine and needs Internet access.
4. Open the add-on's **Info** page and turn **Protection mode off**. You may need
   **Advanced mode** enabled in your Home Assistant user profile to see this control.
5. Start the add-on, then open **Logs**. Copy the report for troubleshooting.

This is a one-shot tool: it exits after reporting, so **Stopped** after a run is
expected. Leave **Start on boot** off. Start it again to refresh the report.

No shell, host SSH setup, network port, or Incus server credentials are needed.
Do not install this on a non-HAOS host or expose it as a general host-inspection service.

### Check the Incus-supplied agent source

After updating to 0.2.0, open the add-on's **Configuration** tab and select:

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

Switch back to `mode: diagnose` for passive checks. `SYS_ADMIN` is still granted
to the image in either mode because Supervisor permissions cannot vary by option.

## Security

Although the code only reads host state, **the container has powerful host access**:

- `host_pid` exposes host processes and `/proc/1/root`.
- `SYS_PTRACE` and `DAC_READ_SEARCH` allow the host-root inspection needed here.
- `SYS_ADMIN` permits the isolated mount namespace and temporary source mounts.
- AppArmor confinement is disabled for this experimental diagnostic image.
- Protection mode must be off for host PID access.

A compromise of this add-on could compromise the HAOS host. These are prototype
permissions, **not a proven minimum**. Run it only when needed and uninstall it
after collecting diagnostics if you do not need it. It does not request the Docker
socket, host D-Bus, host networking, or `SYS_MODULE`. No explicit module-loading
commands are run; source-check mounts may cause normal kernel driver autoloading.

The diagnostic code does not read agent credentials, process arguments, or journal
contents. Source-check mode reads binary headers only, never executing them. It
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
by inspecting mount information. This version does not test vsock communication.

Native agent processes or launcher files are reasons to investigate before
starting a replacement. From the Incus host, connectivity can be tested with:

```sh
incus exec ha -- /bin/sh -c 'uname -a'
```

## Next milestone

Use the diagnostic results to design opt-in agent supervision using the binary
and per-VM connection material supplied by Incus. Validate namespace/root access,
VM-wide metrics, native-agent conflict avoidance, lifecycle, and upgrade behavior
before claiming a working guest agent. Missing kernel features may require HAOS
changes rather than an add-on workaround.

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
