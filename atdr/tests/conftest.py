from __future__ import annotations

import os


# Test clients exercise local credentials intentionally. Runtime defaults stay
# fail-closed on the mandatory shell profile; tests must opt into recovery.
os.environ.setdefault("ATDR_AUTH_MODE", "local_recovery")
# Tests never call a real language model, whatever .env enables for the
# running system; agent tests inject a scripted engine instead.
os.environ["ASSISTANT_AGENT_ENGINE"] = "off"
