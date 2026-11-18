# Changelog

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
