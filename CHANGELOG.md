# Changelog

## 1.0.5 — 2026-09-22

- Distinguish permission-denied vs missing config in agent readiness (clearer status when `/etc/hecate-lampad` ownership is wrong).

## 1.0.4 — 2026-09-21

- After a successful Linux desktop package install, re-run session activation so `/run/hecate-lampad` is ready and live GUI sessions get the helper started.

## 1.0.3 — 2026-08-31

- Auto-repair pull sessions: reload config/key from disk after enroll or re-enroll without a manual service restart.
- Reset HTTP client and heartbeat thread after sustained pull/heartbeat failures or when no pull succeeds within the startup grace window.

## 1.0.1 — 2026-08-31

- Sync local `agent_state` from the server after operator approval (service pull loop and `status` command).

## 1.0.0 — 2026-08-31

Initial public release.

- Add `forget` command to clear local agent enrollment (config, key, runtime status).
