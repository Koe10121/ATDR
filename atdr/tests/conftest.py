from __future__ import annotations

import os


# Test clients exercise local credentials intentionally. Runtime defaults stay
# fail-closed on the mandatory shell profile; tests must opt into recovery.
os.environ.setdefault("ATDR_AUTH_MODE", "local_recovery")
# Tests never call a real language model, whatever .env enables for the
# running system; agent tests inject a scripted engine instead.
os.environ["ASSISTANT_AGENT_ENGINE"] = "off"
# Tests never load this machine's MFU behaviour model to raise alerts; model-alert
# tests pass a model of their own.
os.environ["ATDR_MODEL_ALERTS"] = "false"
# Tests never use this machine's backup folder, its backup schedule or a drive connected to it, whatever .env
# sets for the running system: a test that resets a database would leave its backup among the real ones. The
# backup tests name a folder, a schedule and a drive of their own.
os.environ["ATDR_BACKUP_DIRECTORY"] = ""
os.environ["ATDR_BACKUP_SCHEDULE_HOURS"] = "0"
os.environ["ATDR_BACKUP_OFFSITE_FOLDER"] = ""
# Tests never show a Windows notification, send email or post to a chat group, whatever .env sets up for the
# running system. The notification tests pass senders of their own.
os.environ["ATDR_NOTIFY_WINDOWS"] = "false"
os.environ["ATDR_NOTIFY_EMAIL_TO"] = ""
os.environ["ATDR_NOTIFY_CHAT_WEBHOOK_URL"] = ""

# Nor do they open the database of the system running on this machine: see own_database_guard.py. The import
# brings its check after every test with it.
from atdr.tests.own_database_guard import install as _guard_own_database  # noqa: E402
from atdr.tests.own_database_guard import no_test_opens_the_projects_own_database  # noqa: E402, F401

_guard_own_database()
