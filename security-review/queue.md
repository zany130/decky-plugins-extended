# Security Review Queue

Pending artifacts: **6** — critical 2, high 4, normal 0.
Generated: `2026-08-09T01:07:41.070060Z`
Source audit run: https://github.com/zany130/decky-plugins-extended/actions/runs/31286922055

| Priority | Plugin | Candidate | Baseline | Classification | Why |
| --- | --- | --- | --- | --- | --- |
| **CRITICAL** | Muon | 0.5.0.1 / `3ed4c4629013` | unavailable | BLOCK | blocked by policy, baseline unavailable |
| **CRITICAL** | Decky-Framegen | v0.17 / `3300b617e3d9` | v0.17 / `3300b617e3d9` | AUDIT\_ERROR | audit error, security delta, same artifact analysis drift |
| **HIGH** | DeckyClash | v0.1.2 / `7ebadc4bfd0e` | unavailable | MANUAL\_REVIEW | baseline unavailable |
| **HIGH** | MoonDeck | nightly / `e37fe1f709be` | unavailable | MANUAL\_REVIEW | baseline unavailable |
| **HIGH** | Unifideck | Release-0.7.3 / `dd9943ce6b0c` | Release-0.7.2 / `a313be924cab` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Decky Notifications | 1.0 / `c48de9ce7a8b` | unavailable | PASS\_WITH\_WARNINGS | baseline unavailable |

## Muon

- Repository: `https://github.com/wtlnetwork/muon`
- Candidate: `0.5.0.1` — `3ed4c4629013d94fc1486943a47e5044fbda7f2488d0e5c75976b9c29068de81`
- Classification: **BLOCK** (risk 1362)
- Comparison: `baseline\_not\_found`; reviewer-attention changes: 0
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.

## Decky-Framegen

- Repository: `https://github.com/xXJSONDeruloXx/Decky-Framegen`
- Candidate: `v0.17` — `3300b617e3d979b483d03f995c75c829d6d54beaa4ac8dfae300c2560e4fc60f`
- Classification: **AUDIT\_ERROR** (risk 0)
- Comparison: `compared`; reviewer-attention changes: 4
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: `v0.17` — `3300b617e3d979b483d03f995c75c829d6d54beaa4ac8dfae300c2560e4fc60f`
- Artifact bytes are unchanged; differences may reflect scanner/rule/coverage drift.
- Scanner coverage issues: clamav: `failed`
- Capability changes:
  - **Malware detection:** not\_observed -\> unknown — **review**
  - **Persistence and automatic startup:** not\_observed -\> unknown — **review**
  - **Privileged and system-level access:** not\_observed -\> unknown — **review**
  - **Credentials and sensitive data:** not\_observed -\> unknown — **review**

## DeckyClash

- Repository: `https://github.com/chenx-dust/DeckyClash`
- Candidate: `v0.1.2` — `7ebadc4bfd0eeec84b9d4d39dfcae39f893fe05e80521caf431a8f4fafde54de`
- Classification: **MANUAL\_REVIEW** (risk 162)
- Comparison: `baseline\_not\_found`; reviewer-attention changes: 0
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.

## MoonDeck

- Repository: `https://github.com/FrogTheFrog/moondeck`
- Candidate: `nightly` — `e37fe1f709be38ad1247402faee5ea1a9770eae28250570119bb64a2502da03a`
- Classification: **MANUAL\_REVIEW** (risk 7799)
- Comparison: `baseline\_not\_found`; reviewer-attention changes: 0
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.

## Unifideck

- Repository: `https://github.com/mubaraknumann/unifideck`
- Candidate: `Release-0.7.3` — `dd9943ce6b0c2be3a68644727046f1693ad537b6085c5adaf16b29cf436a0bf7`
- Classification: **MANUAL\_REVIEW** (risk 2396)
- Comparison: `compared`; reviewer-attention changes: 2
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: `Release-0.7.2` — `a313be924cabe15255d222742a402cd98cb510a35dfe4b2d06cf1e59366936de`
- Capability changes:
  - **Network communication:** network destinations +1/-1 — **review**
  - **Published release versus source:** source/release difference profile changed — **review**

## Decky Notifications

- Repository: `https://github.com/zany130/decky-notifications`
- Candidate: `1.0` — `c48de9ce7a8b8d5fedf97c9b8d1062b77d1868a798e5e307f6092c9097006b93`
- Classification: **PASS\_WITH\_WARNINGS** (risk 4)
- Comparison: `baseline\_not\_found`; reviewer-attention changes: 0
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.
