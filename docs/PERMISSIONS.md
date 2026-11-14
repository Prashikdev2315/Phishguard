# PhishGuard — Frozen Permission List

**Status:** Frozen in Chunk 1 (Spike and scaffold)
**PRD reference:** §8.1, SEC-02, SC-01

Any change to this list requires a PRD revision **before** the code change.
SC-01 (`tests/security/test_sc01_manifest.py`) fails the CI build
if `extension/manifest.json` deviates from this document.

---

## Approved permissions (`permissions`)

| Permission      | Justification                                                      |
|-----------------|--------------------------------------------------------------------|
| `storage`       | Local verdict cache, user allowlist, settings, history (§8.3)     |
| `webNavigation` | `onBeforeNavigate` trigger for top-level navigations (§4, FR-01)  |
| `alarms`        | Daily history purge, hourly cache sweep (§8.5)                    |

## Approved optional permissions (`optional_permissions`)

| Permission  | Justification                                                             | When requested          |
|-------------|---------------------------------------------------------------------------|-------------------------|
| `scripting` | Inject the in-page banner into the target page (FR-11); closed Shadow DOM | Only after user grants host access |

## Core host permissions (`host_permissions`)

**(empty)** — PhishGuard requests **no broad host access** in its core manifest.
The service worker reads the navigated URL from `webNavigation` event details;
it never injects content or makes host requests without explicit user consent.

## Optional host permissions (`optional_host_permissions`)

| Entry        | Justification                                            | When requested |
|--------------|----------------------------------------------------------|----------------|
| `<all_urls>` | Required by `scripting` to inject the banner (FR-11)     | Only after user opts in to in-page banner in Settings |

## What is NOT permitted (and why)

| Capability                    | Reason excluded                                           |
|-------------------------------|-----------------------------------------------------------|
| `webRequest` / blocking       | MV3 has no `webRequestBlocking`; interstitial uses `tabs.update` (PRD §4) |
| `declarativeNetRequest`       | Evaluated in spike; adopted only if it helps (§8.1)      |
| `tabs`                        | Spike must confirm whether `tabs.update` needs it; default: not in core list |
| `cookies`, `history`, etc.    | Not needed; excluded for minimum-privilege (SEC-02)       |
| Remote network requests       | Zero outbound requests in v1 (G5, SEC-06)                |
| `externally_connectable`      | Excluded so web pages cannot message the worker (SEC-03)  |
| `web_accessible_resources`    | Empty so web pages cannot frame `warning.html` (SEC-03)   |

---

## Open item from M0 spike

> **Spike question:** Does `tabs.update` require the `tabs` permission
> under MV3 on Chrome 120+?
>
> If yes, `"tabs"` is added to `permissions` here and in `manifest.json`,
> and SC-01 is updated in the same commit.
> Current assumption: **not required** (see `docs/ASSUMPTIONS.md` A-03).
>
> Spike result recorded in: `docs/SPIKE_RESULTS.md`

---

*Last updated: Chunk 1*
