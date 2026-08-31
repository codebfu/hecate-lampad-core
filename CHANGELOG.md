# Changelog

## 1.0.3 — 2026-08-31

- Auto-repair pull sessions: reload config/key from disk after enroll or re-enroll without a manual service restart.
- Reset HTTP client and heartbeat thread after sustained pull/heartbeat failures or when no pull succeeds within the startup grace window.

## 1.0.1 — 2026-08-31

- Sync local `agent_state` from the server after operator approval (service pull loop and `status` command).

## 1.0.0 — 2026-08-31

Initial public release.

- Add `forget` command to clear local agent enrollment (config, key, runtime status).
