# Changelog

## 0.3.0

- Add explicit `mode: manage` for the inline ELF-on-config layout.
- Stage only the architecture-matching agent and three connection files in a
  private, temporary host `/run` directory; never run installers or loader scripts.
- Require successful source unmount before launch.
- Refuse native agent/service conflicts and inconclusive prerequisites; hold a
  host runtime lock and repeat checks before launch.
- Enter and verify host namespace/root views; exclude Supervisor credentials
  from the managed process environment.
- Forward stop signals, escalate if needed, and remove owned runtime files.
- Enable privileged hardware access (`full_access`) for host-level operations;
  these broad permissions apply in every mode. Keep diagnose as the default.
- Keep start-on-boot manual; no automatic agent restart loop or GitHub tests.

## 0.2.0

- Keep passive diagnostics as the default; add opt-in `mode: source_check`.
- Discover advertised virtio tags and probe known config/agent shares read-only
  inside a separate, recursively private mount namespace.
- Inspect agent ELF architecture or loader-script headers without execution.
- Check connection-file metadata without opening credentials.
- Add bounded mount/worker timeouts and unmount cleanup reporting.
- Request `SYS_ADMIN` and include util-linux for namespace and mount operations.
- Still no agent installation, startup, or persistent host changes.

## 0.1.0

- Initial diagnostic-only Supervisor add-on for aarch64 and amd64.
- Inspect host identity, native agent launchers/processes, virtio devices, kernel
  registrations, existing runtime binaries, and mounted configuration shares.
- Report inconclusive or inaccessible checks as unknown.
- No installation, agent startup, or host modifications.
