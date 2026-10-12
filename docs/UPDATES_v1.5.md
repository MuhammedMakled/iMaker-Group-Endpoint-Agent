# v1.5: Remote self-update (upgrade-agent)

The IT Command Center can push a new agent build to a PC. The service
downloads and verifies the bundle, hands off to a short-lived updater, and the
updater installs it or rolls back. The result is reported as `UPGRADE_SUCCESS`
or `UPGRADE_FAILED`.

## Bundle format

`download_url` points to a `.zip` containing exactly two files at the top level:

- `ImakerAgentService.exe`
- `ImakerTrayApp.exe`

Any other entry, a folder, a duplicate, or a path separator is refused before
anything is written. `sha256_hash` is the SHA-256 of the zip itself.

## Configuration (agent.json)

| Key | Default | Meaning |
|---|---|---|
| `update_allowed_hosts` | `[]` | Exact hostnames the bundle may come from. Empty disables upgrades. |
| `update_require_signature` | `true` | Both binaries must carry a valid Authenticode signature. |
| `update_signer_subject` | `""` | Substring that must appear in the signer certificate subject. Required when signatures are required. |
| `update_report_url` | `""` | HTTPS endpoint for outcome reports. Until it is set, results wait in `updates\state.json`. |

## Flow

1. `upgrade-agent` is a privileged RPC. It needs an elevated admin and a
   global-admin session. The session token travels in the RPC envelope's
   `auth` field, not in the parameters.
2. The service validates the request (https, allowed host, 64-hex hash, newer
   version, no in-progress or unreported upgrade).
3. The zip is downloaded to `%ProgramData%\Imaker\updates\incoming`, capped at
   200 MB, and the SHA-256 is checked before the zip is opened.
4. The bundle is extracted to `updates\staged\<version>` and both binaries are
   Authenticode-checked.
5. The current binaries are backed up to `updates\backup`, and the service
   binary is copied to `updates\updater.exe`.
6. The updater (`updater.exe apply-update`) stops the tray and the service,
   copies the new binaries, and starts the service.
7. The new service writes `updates\health.json`. If the target version does not
   report healthy within 15 seconds, the updater restores the backups, starts
   the old service, and records `UPGRADE_FAILED`.
8. The outcome is posted to `update_report_url` once and marked reported.

Logs: `ProgramData\Imaker\logs\updater.log` and the service log.

## Known limits

- The tray is stopped for the update and restarts at the next logon (its Run
  key). It is not relaunched in the active session.
- Report authentication is not defined yet. It depends on the gateway contract.
- The updater is not yet verified on a Windows PC. Unit tests cover validation,
  hashing, bundle safety, download limits, and the apply/rollback sequence. The
  Windows SCM, file-replace, Authenticode and detached-spawn paths need a lab
  test before any fleet use.
