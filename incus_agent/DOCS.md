# Incus Agent Diagnostics

This experimental add-on only checks guest-agent prerequisites. It does not
install or run an agent and does not change the HAOS host.

1. Disable **Protection mode** on the add-on's Info page.
2. Start the add-on.
3. Open **Logs** and copy the report.

The add-on exits when done. A stopped state is expected. Start it again to rerun.
Leave Start on boot off. The default configuration is:

```yaml
mode: diagnose
```

## Opt-in source check

To test access to the agent supplied by Incus, select and save:

```yaml
mode: source_check
```

Start the add-on again and inspect its Logs (allow approximately three minutes).
This mode temporarily mounts the known `config` and `agent` virtiofs/9p shares
read-only, with `nosuid,nodev,noexec`, in a separate private mount namespace.
It checks expected agent binary headers and connection-file metadata, then
unmounts the shares. No share files are executed or copied and credential
contents are never read. Default diagnostics do not mount anything.

Look for `architecture_matches: true` on an ELF binary and `present` connection
files on `config`. A loader script may require the separate `agent` share.
A mount failure is inconclusive, and a successful source check does not establish
working agent connectivity. Cleanup issues are reported in the attempts list.

**Security:** host PID access, `SYS_PTRACE`, `DAC_READ_SEARCH`, `SYS_ADMIN`, and disabled
AppArmor confinement provide powerful host access. Read-only behavior is a
property of this collector, not a sandbox guarantee. Run only a trusted build.
These permissions apply even in default diagnostic mode. Source mounts can
trigger normal kernel driver autoloading; no module-loading commands are run.

`UNKNOWN` does not mean missing. Service-file presence is not service status;
agent process presence is not proof of connectivity. Do not start a competing
agent based only on this report.
