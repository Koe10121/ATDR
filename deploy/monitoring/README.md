# ATDR Monitoring Groundwork

The Prometheus example scrapes ATDR's low-cardinality `/metrics` endpoint and loads alert rules for service/database readiness, database-pool saturation, backup freshness, configuration safety, response simulation, queue backlog, stale workers, recent operation/ingestion/detection failures, and staging pressure.

The metrics contract deliberately excludes request IDs, route paths, actors, usernames, email addresses, IP addresses, file paths, raw logs, tokens, and secrets. Keep the endpoint private. The Nginx example allows only loopback access.

Validate configuration on the deployment host:

```bash
promtool check config /etc/prometheus/prometheus.yml
promtool check rules /etc/prometheus/rules/atdr-alerts.yml
```

Alert delivery, paging recipients, retention, and high-availability Prometheus remain deployment-owner decisions. These examples do not create automatic response actions.

`atdr_database_pool_observable=0` is expected for SQLite; pool capacity claims require PostgreSQL. Backup metrics perform only manifest/checksum/freshness verification and never create, restore, or delete a backup. Use `docs/V3_96_OPERATIONAL_ACCEPTANCE_CHECKLIST.md` before accepting a shared environment.
