# Incus Agent Diagnostics

This experimental add-on only checks guest-agent prerequisites. It does not
install or run an agent and does not change the HAOS host.

1. Disable **Protection mode** on the add-on's Info page.
2. Start the add-on.
3. Open **Logs** and copy the report.

The add-on exits when done. A stopped state is expected. Start it again to rerun.
No configuration options are required. Leave Start on boot off.

**Security:** host PID access, `SYS_PTRACE`, `DAC_READ_SEARCH`, and disabled
AppArmor confinement provide powerful host access. Read-only behavior is a
property of this collector, not a sandbox guarantee. Run only a trusted build.

`UNKNOWN` does not mean missing. Service-file presence is not service status;
agent process presence is not proof of connectivity. Do not start a competing
agent based only on this report.
