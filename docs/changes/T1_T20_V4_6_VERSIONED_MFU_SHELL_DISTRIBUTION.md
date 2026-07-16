# T1-T20: v4.6 Versioned MFU Shell Distribution

## T1 Change Title

v4.6 Versioned MFU Shell Distribution and Teammate Runtime Acceptance.

## T2 Requirement

Replace machine-specific supervisor-folder onboarding with an approved, sanitized, checksum-locked companion archive while preserving mandatory shell entry, fail-closed authentication, and ATDR runtime behavior.

## T3 Source Evidence

`config/mfu-shell-contract.json`, lifecycle PowerShell scripts, external approved shell source structure, v4.3-v4.5 tests/docs, Git status, and clean-room acceptance output.

## T4 Current Behavior

Before v4.6, setup recorded an absolute path to an unversioned external shell. Teammates could not obtain the exact reviewed shell from the ATDR repository, and drift or private-file inclusion was not governed by an archive checksum.

## T5 Impacted Areas / Agents

Release/operations, security/IAM boundary, Windows onboarding, QA/UAT, repository hygiene, and documentation.

## T6 Scope

Deterministic package creation, safety scanning, manifest/checksum verification, versioned installation, lifecycle integration, clean-clone acceptance, tests, and documentation. Provider credentials and live university authentication remain out of scope.

## T7 Functional Requirements

- Build one deterministic sanitized ZIP from the reviewed shell source.
- Refuse secrets, private config, generated content, traversal paths, and source drift.
- Install and verify by release version and checksum.
- Support Windows paths with spaces and broken/missing venv recovery.
- Report installation and provider readiness separately.
- Fail closed with one provider blocker when private OAuth configuration is absent.

## T8 Acceptance Criteria

A clean Windows clone installs from the archive, reaches Alembic head on a new disposable SQLite database, reports verified package integrity, reuses the release idempotently, fails startup safely without provider config, and stops idempotently. No forbidden artifact enters Git.

## T9 API Contract

No ATDR HTTP API change.

## T10 Data Model / Migration

No schema change. Clean-room setup applies existing migrations to a disposable database; the configured user database is untouched.

## T11 Backend Plan / Changes

Add deterministic package build/verify/install services and CLI with contract locking, safety scans, archive-path validation, installed-source verification, quarantine on drift, and explicit confirmations.

## T12 Frontend Plan / Changes

No React or MFU shell UI behavior change.

## T13 Security / Response / AI Safety

No credential is copied into the archive. No auth bypass, raw-provider secret output, model activation, automatic response, or real firewall action is introduced.

## T14 Test Plan

Package determinism/exclusions, secret rejection, tamper/traversal rejection, idempotent install, source-drift detection, path-with-spaces setup, lifecycle integrity enforcement, clean clone, full backend/frontend/release verification, and Git hygiene.

## T15 Implementation Summary

Implemented contract v2, release `1.4.0-atdr.1`, deterministic sanitized archive generation, package verification/install CLI, versioned ignored runtime installation, package-aware setup/start/check, concise provider blocking, and teammate documentation.

## T16 Tests Run / Evidence

Package/auth/portability regression suite passed `23` tests; package-specific suite passed `6` tests. The disposable clean-clone setup passed in `554.8s`, reported installation ready/package verified/provider not ready/secrets not exposed, and a repeat setup passed in `3.2s`. Start failed closed with one provider blocker and stop passed twice. Taskboard checks, Ruff, compileall, PowerShell parsing, full backend `595 passed, 1 skipped`, Alembic no drift, React lint/build, Playwright `25 passed, 1 skipped`, replay dry-run, read-only performance smoke, and release gate `ok: true` passed. The known cold large-SQLite Overview warning remains documented.

## T17 PRD / Docs Updated

v4.6 status, hygiene, allowlist, quickstart, one-command start, PRD, traceability, compliance checklist, docs index, task board, README, and this record.

## T18 Risks / Blockers / Assumptions / Decisions

Live MFU OAuth acceptance remains university-controlled. The legacy Vue shell dependency tree has deprecation/engine warnings. Windows clones should use a reasonably short path unless long-path support is enabled. The package archive is an approved release artifact, not a tracked source file.

## T19 Release / Rollback

No commit or push is performed without explicit approval of `docs/V4_6_COMMIT_ALLOWLIST.md`. Rollback is a normal source revert. Runtime releases are ignored and may be reinstalled from the approved archive; setup does not reset data.

## T20 Final Handoff

The locally controllable v4.6 distribution scope is complete once the full verification matrix passes. Provider-backed sign-in remains a separate acceptance gate; production readiness is not claimed.
