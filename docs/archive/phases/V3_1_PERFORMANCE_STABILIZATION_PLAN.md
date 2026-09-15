# ATDR v3.1 Performance Stabilization Plan

v3.1 stabilizes the production-readiness track by checking the large local SQLite performance warnings without changing ATDR's normal local workflow.

## Source Evidence

| Area | Source |
| --- | --- |
| Overview summary implementation | `atdr/app/services/dashboard_service.py` |
| ML Governance summary implementation | `atdr/app/services/ml_service.py` |
| Performance smoke command | `atdr/scripts/performance_smoke.py` |
| Existing performance indexes | `migrations/versions/a7c9d2e4f6b1_add_summary_performance_indexes.py` |
| Dashboard API route | `atdr/app/routers/dashboard.py` |
| Production-readiness doctor | `atdr/scripts/production_readiness_doctor.py` |

## Observed Warning

The earlier v3.0 smoke run reported:

- Overview uncached summary: about `10.385s`
- ML Governance lightweight summary: about `2.6904s`

A focused rerun against the same local database measured:

- Overview uncached summary: about `0.37s`
- Overview cached summary: about `0.006s`
- ML Governance lightweight summary: about `1.07s`

## Root Cause Assessment

The slow result did not reproduce during focused profiling. The likely cause is cold SQLite and operating-system file cache pressure after heavy verification runs, not a persistent query regression.

Evidence:

- `build_dashboard_summary()` uses aggregate SQL queries and the existing summary cache.
- The parser-error path avoids JSON scans for datasets above `EXACT_JSON_QUALITY_LIMIT`.
- Existing indexes cover common alert, anomaly, ML label, and run-history queries.
- Focused timing of individual Overview and ML Governance query groups stayed under local lab budgets.

## Query Hotspots To Watch

These are the areas most likely to become expensive as the database grows:

- Overview quality aggregates over `normalized_logs`.
- Top distribution group-bys over `action`, `protocol`, `app_risk`, and country fields.
- Alert occurrence metadata derived from alert JSON metadata.
- ML Governance dataset profile, baseline drift profile, and data-quality profile.
- Cold uncached SQLite reads after large imports, tests, or OS cache eviction.

## Current Stabilization Decision

No new Alembic index migration is added in v3.1 because the current large local database is under budget after focused rerun. Adding indexes without a reproducible slow query would risk migration churn without clear benefit.

## Guardrails Added

- Production-readiness doctor now reminds operators to run `performance_smoke` and validate PostgreSQL for larger shared labs.
- Tests cover Overview summary cache hit and invalidation after ingestion.
- Existing performance smoke remains read-only and still reports warnings when budgets are exceeded.

## Local Lab Performance Budget

- Overview cached: target under `0.05s`.
- Overview uncached: target under `2s` for the current local SQLite dataset when warm.
- ML Governance lightweight: target under `2s`.
- Alert list and case summary: target under `1s`.

## When To Treat This As A Blocker

Treat performance as a v3.x blocker if:

- Overview uncached repeatedly exceeds `2s` after two focused reruns.
- Overview cached exceeds `0.5s`.
- ML Governance lightweight repeatedly exceeds `2s`.
- Alert list or case summary exceeds `1s`.
- Frontend calls heavy endpoints repeatedly without user action.

## Recommended Next Step

Run PostgreSQL lab validation on a Docker/PostgreSQL-capable host before any shared-lab or production-like claim. SQLite remains the normal local development database, but PostgreSQL is the correct validation path for larger concurrent datasets.

