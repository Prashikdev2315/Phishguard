# PhishGuard — Spike Results (FR-09 / E2E-10)

**PRD reference:** §4 MV3 engineering notes, FR-09, E2E-10, risk R-03
**Harness:** `tools/spike/race_harness.py`

---

## Purpose

> "There is no webRequestBlocking. The interstitial is applied with
> `tabs.update` to an extension page right after the verdict. The request
> may already be in flight, so the guarantee is measured, not assumed
> (FR-09, M0 spike)."  — PRD §4

This file is auto-written by the race harness. Do not edit manually.

---

## Gate

| Metric                          | Required | Consequence if below             |
|---------------------------------|----------|----------------------------------|
| `interstitial_rate` (all runs)  | ≥ 0.99   | FAIL — enforcement unreliable    |
| `interstitial_rate` (all runs)  | ≥ 0.90   | WARN — document residual; consider DNR session rules or warn-only |
| `cold_interstitial_rate`        | reported | Informs whether lazy model-load impacts blocking |

---

## Latest run

```
NOT YET RUN
Run the harness: python tools/spike/race_harness.py --extension extension --runs 200
Results will overwrite this section automatically.
```

---

## Setup requirements

The harness uses a **mapped fake domain** (`phishguard-spike.test`) served
from the machine's LAN IP so that:

1. The URL passes the extension's pre-filter (not loopback / not `127.0.0.1`).
2. We control the server and can count per-run hits to detect target-committed races.

**One-time setup (run once as Administrator / with sudo):**

```
# Windows (PowerShell, elevated):
Add-Content C:\Windows\System32\drivers\etc\hosts "`n10.17.8.107  phishguard-spike.test"

# macOS / Linux:
echo "10.17.8.107  phishguard-spike.test" | sudo tee -a /etc/hosts
```

Replace `10.17.8.107` with the output of:
```python
python -c "import socket; s=socket.socket(); s.connect(('8.8.8.8',80)); print(s.getsockname()[0])"
```

The harness will verify DNS resolution before running and exit with a clear
error message if the mapping is missing.

---

## Measurement design

```
For each run i in 1..N:
  ┌─ Playwright navigates to http://phishguard-spike.test/run-{i}/
  │
  ├─ Extension fires onBeforeNavigate
  │   → tabs.update(tabId, {url: warning.html?token=T})
  │
  ├─ Race outcome (measured two ways):
  │   [Browser-side]  page.url after framenavigated settle:
  │                   - warning.html URL  → extension won  (interstitial_shown)
  │                   - /run-{i}/ URL     → target committed (target_committed)
  │
  │   [Server-side]   HTTP server hit counter for /run-{i}/:
  │                   - 0 hits → target never fetched  (consistent with extension win)
  │                   - ≥1 hit → target fetched        (may still show interstitial if
  │                              tabs.update fired before DOM committed)
  │
  └─ Cold runs: CDP Target.closeTarget on the SW target before navigation
                to simulate ephemeral service-worker wake (PRD §4).
```

---

## Assumption logged

See `docs/ASSUMPTIONS.md` A-03: `tabs.update` does not require the `tabs`
permission on Chrome 120+ MV3. If the spike shows permission errors, add
`"tabs"` to the approved list and update SC-01.

---

*Template created Chunk 1 follow-up. Overwritten by harness on each run.*
