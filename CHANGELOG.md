# Changelog

## 1.0.7 — 2026-09-22

- Re-validate `desktop.app.launch` against the signed task `shell_policy` before forwarding to the desktop helper (defense in depth for the §11 sandbox escape).

## 1.0.6 — 2026-09-22

- Auto-repair `desktop.sock` / `ipc.token` group to `hecate-ipc` when the helper recreates them without group write access (fixes sticky `gui:none` after helper restart / agent update).

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
