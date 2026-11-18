# Incus Agent Diagnostics

This experimental add-on defaults to diagnostics. An explicit `manage` mode can
run the Incus-supplied guest agent with HAOS host access. No persistent service
or host package is installed.

1. Disable **Protection mode** on the add-on's Info page.
2. Start the add-on.
3. Open **Logs** and copy the report.

Diagnostic modes exit when done; a stopped state is expected. `manage` stays
running. Leave Start on boot off until verified. The default configuration is:

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

## Run the agent (0.3.0, experimental)

**Incus will gain authenticated root command/file access to the whole HAOS VM.**
Take a backup/snapshot and trust the Incus host before enabling:

```yaml
mode: manage
```

Save, start, and inspect Logs. Only the inline ELF layout on `config` is supported
for now; loader-script/split-share layouts fail closed. Native agent units,
running agent processes or inconclusive prerequisites block managed startup.
The agent and three connection files are staged privately in host `/run` with
restrictive permissions, then the source is unmounted before execution. No
templates, NIC configuration, mount recipes or installers are copied.

Host namespace/root verification runs before execution. The agent environment
does not include Supervisor tokens. From your Incus host, verify:

```sh
incus exec ha -- uname -a
incus exec ha -- cat /etc/os-release
incus info ha
```

Confirm HAOS, not Alpine, and validate VM-wide metrics. A running add-on is not
proof of connectivity. Stop the add-on to terminate the agent and remove its
runtime directory. Unexpected agent exit is not automatically retried. Unclean
shutdown can leave private runtime files until reboot; an empty lock file is
retained until reboot intentionally. The add-on does not undo authenticated
Incus operations or delete arbitrary host paths created by the upstream agent.

**Security:** host PID access, `full_access` privileged hardware access,
`SYS_PTRACE`, `DAC_READ_SEARCH`, `SYS_ADMIN`, and disabled AppArmor confinement
provide effectively root-level host access in **every mode**. Passive read-only
behavior is not a sandbox guarantee. Source mounts may autoload drivers, and
the managed upstream agent can load modules and perform host operations.

`UNKNOWN` does not mean missing. Service-file presence is not service status;
agent process presence is not proof of connectivity. Do not start a competing
agent based only on this report.
