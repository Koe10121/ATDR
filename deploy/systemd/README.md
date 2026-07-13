# ATDR Managed Services

These files are deployment examples for an approved Linux shared-lab host. They do not change the normal Windows SQLite commands and do not start workers from the API process.

1. Install ATDR under `/opt/atdr` and create the unprivileged `atdr` service account.
2. Mount shared staging at `/srv/atdr/shared` on every worker host.
3. Store real settings in `/etc/atdr/atdr.env` with mode `0600`.
4. Run Alembic once before starting the API or workers.
5. Install the examples without the `.example` suffix under `/etc/systemd/system/`.
6. Start one API and the approved worker count, for example `atdr-worker@1` and `atdr-worker@2`.

Workers use `SIGTERM` and a 150-second stop window. Resumable imports release at a committed chunk boundary; non-resumable jobs drain before process exit. PostgreSQL and the shared staging mount are required for multi-worker use.

The API example disables Uvicorn's generic proxy-header handling. ATDR accepts forwarded protocol/client values only when `TRUST_PROXY_HEADERS=true` and the direct peer matches `TRUSTED_PROXY_CIDRS`; the Nginx reference uses loopback only.

Optional report/verification timers are also provided for readiness, audit-retention preview, staged-input cleanup preview, and backup checksum/freshness verification. None of the scheduled services contains `--apply` or `--execute`. Enable them only after reviewing paths and private environment settings:

```bash
sudo systemctl enable --now atdr-readiness-check.timer
sudo systemctl enable --now atdr-audit-retention-report.timer
sudo systemctl enable --now atdr-staging-cleanup-report.timer
sudo systemctl enable --now atdr-backup-verify.timer
```

Backup creation remains a separate approved operator policy. The verification timer never creates, restores, or deletes a backup.
