# Security Review Queue

Pending artifacts: **16** — critical 3, high 10, normal 3.
Generated: `2026-08-17T12:21:34.103744Z`
Source audit run: https://github.com/zany130/decky-plugins-extended/actions/runs/32029220843

| Priority | Plugin | Candidate | Baseline | Classification | Why |
| --- | --- | --- | --- | --- | --- |
| **CRITICAL** | Muon | 0.5.0.2 / `229ae50f12c4` | unavailable | BLOCK | blocked by policy, baseline unavailable |
| **CRITICAL** | https://github.com/xXJSONDeruloXx/Decky-bionic-fg |  / `unavailable` | v0.1.6 / `d3758997fc9b` | AUDIT\_ERROR | audit error, artifact identity unavailable, security delta |
| **CRITICAL** | Decky-Framegen | v0.17 / `3300b617e3d9` | v0.17 / `3300b617e3d9` | AUDIT\_ERROR | audit error, security delta, same artifact analysis drift |
| **HIGH** | DeckyClash | v0.1.2 / `7ebadc4bfd0e` | unavailable | MANUAL\_REVIEW | baseline unavailable |
| **HIGH** | Tender | tender-v0.31.0 / `74ba2fe0775e` | decky-romm-sync-v0.30.1 / `254a911f01e6` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | MoonDeck | nightly / `05225f387478` | unavailable | MANUAL\_REVIEW | baseline unavailable |
| **HIGH** | Unifideck | Release-0.7.3 / `dd9943ce6b0c` | Release-0.7.2 / `a313be924cab` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Steamcord | v1.22.0 / `7fb27ec9829e` | v1.21.1 / `4c0ca32204c2` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Achievement Companion | v0.3.3 / `8aa1bb619bad` | v0.3.2 / `3f0260c0a552` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Decky Vibrance HDR | 1.0.1 / `8bbf5601ea5b` | 1.0.0 / `c5fbde7be36a` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | LeGoTDP | 1.6.1 / `2bccb912292b` | 1.6.0 / `4b04b2e1bb98` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | RetroDECKY | v1.2.0 / `070d8850fcac` | v1.1.0 / `344fb7a08202` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Decky Notifications | 1.0 / `c48de9ce7a8b` | unavailable | PASS\_WITH\_WARNINGS | baseline unavailable |
| **NORMAL** | SDH-Ludusavi | v0.4.4 / `71b609181c55` | v0.4.3 / `28171f4a1039` | MANUAL\_REVIEW | new artifact |
| **NORMAL** | Panel de Control | panel-de-control-v0.37.4 / `6ff6350f519e` | panel-de-control-v0.37.1 / `e20cce88c57d` | MANUAL\_REVIEW | new artifact |
| **NORMAL** | Deck Shelves | v3.2.1 / `0f14447ea693` | v3.1.0 / `71a7c6d4f53e` | MANUAL\_REVIEW | new artifact |

## Muon

- Repository: `https://github.com/wtlnetwork/muon`
- Candidate: `0.5.0.2` — `229ae50f12c45e693813d496bad547680c75966405684460200a14fce050fe9a`
- Classification: **BLOCK** (risk 1362)
- Comparison: `baseline_not_found`; reviewer-attention changes: 0
- First seen: `2026-08-15T18:14:21.149471Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.

## https://github.com/xXJSONDeruloXx/Decky-bionic-fg

- Repository: `https://github.com/xXJSONDeruloXx/Decky-bionic-fg`
- Candidate: `` — `artifact SHA unavailable`
- Classification: **AUDIT\_ERROR** (risk 0)
- Comparison: `compared`; reviewer-attention changes: 9
- First seen: `2026-08-12T00:59:11.100677Z`
- Accepted baseline: `v0.1.6` — `d3758997fc9ba41b1441e82d3b7c2a67d283d247a09b9796065113f0525b335a`
- Report errors: 1 (see the full audit artifact/logs for details)
- Capability changes:
  - **Command and process execution:** not\_observed -\> unknown — **review**
  - **Known vulnerabilities:** not\_observed -\> unknown — **review**
  - **Malware detection:** not\_observed -\> unknown — **review**
  - **Native executable code:** observed -\> unknown; native binaries +0/-3; rule profile +0/-2 — **review**
  - **Network communication:** observed -\> unknown; network destinations +0/-2 — **review**
  - **Persistence and automatic startup:** not\_observed -\> unknown — **review**
  - **Privileged and system-level access:** not\_observed -\> unknown — **review**
  - **Credentials and sensitive data:** not\_observed -\> unknown — **review**
  - **Published release versus source:** observed -\> unknown; source/release difference profile changed; rule profile +0/-1 — **review**

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
- Comparison: `baseline_not_found`; reviewer-attention changes: 0
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.

## Tender

- Repository: `https://github.com/danielcopper/decky-romm-sync`
- Candidate: `tender-v0.31.0` — `74ba2fe0775e39495db180bb7303390ebf7123ccd1de08b55c11386c75e847f2`
- Classification: **MANUAL\_REVIEW** (risk 147)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-08-17T00:36:14.187561Z`
- Accepted baseline: `decky-romm-sync-v0.30.1` — `254a911f01e6c8d1c01deddbcfab4c0ee437e1bca3e28bf92d3b41ae0ab002db`
- Capability changes:
  - **Native executable code:** native binaries +1/-1 — **review**

## MoonDeck

- Repository: `https://github.com/FrogTheFrog/moondeck`
- Candidate: `nightly` — `05225f387478d5684c5c1b10bcd607c199c96528b671ffd2e55ad3a974f9d8d1`
- Classification: **MANUAL\_REVIEW** (risk 7799)
- Comparison: `baseline_not_found`; reviewer-attention changes: 0
- First seen: `2026-08-12T00:59:11.100677Z`
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

## Steamcord

- Repository: `https://github.com/Necrosiak/Steamcord`
- Candidate: `v1.22.0` — `7fb27ec9829ed74715d80bdc36d8fe0bb70a1e36fcdd65d4f4c4df2a0c9ae67a`
- Classification: **MANUAL\_REVIEW** (risk 757)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-08-12T12:45:55.406552Z`
- Accepted baseline: `v1.21.1` — `4c0ca32204c25c741d03736199622d8ee6ed63fbca5c67ff7f321b7593348f38`
- Capability changes:
  - **Published release versus source:** source/release difference profile changed (1 count change(s)) — **review**

## Achievement Companion

- Repository: `https://github.com/parvagans/achievement-companion`
- Candidate: `v0.3.3` — `8aa1bb619bad34badb7e8dc2a45a583e3080f2d05253c677c44482d90991a0b3`
- Classification: **MANUAL\_REVIEW** (risk 34)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-08-15T12:16:35.411907Z`
- Accepted baseline: `v0.3.2` — `3f0260c0a5526a5d921e35c3cf0ca6e2d5a15d098ae1c0d9f6991711662a70ed`
- Capability changes:
  - **Published release versus source:** source/release difference profile changed (1 count change(s)); rule profile +1/-0 — **review**

## Decky Vibrance HDR

- Repository: `https://github.com/Rayekkk/DeckyVibranceHDR`
- Candidate: `1.0.1` — `8bbf5601ea5b9e9865329773f05e7a9a8e8496303a6bb447a7da5a00c61407de`
- Classification: **MANUAL\_REVIEW** (risk 92)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-08-10T00:51:45.065594Z`
- Accepted baseline: `1.0.0` — `c5fbde7be36a9212b85b8db87e495217b174b617a433385bd43ffec5a9aef159`
- Capability changes:
  - **Published release versus source:** source/release difference profile changed (2 count change(s)) — **review**

## LeGoTDP

- Repository: `https://github.com/Rayekkk/LeGoTDP`
- Candidate: `1.6.1` — `2bccb912292b5d6caffcce17b2009b463fd7828aede88ce0f1af51adae4042b8`
- Classification: **MANUAL\_REVIEW** (risk 52)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-08-10T00:51:45.065594Z`
- Accepted baseline: `1.6.0` — `4b04b2e1bb980b312eb482f7a6da8af3c5cbcb7124b4d3c4322ba7cea9b8a805`
- Capability changes:
  - **Published release versus source:** source/release difference profile changed (1 count change(s)) — **review**

## RetroDECKY

- Repository: `https://github.com/Teppichseite/RetroDECKY`
- Candidate: `v1.2.0` — `070d8850fcacd98db20cf45c09810f9d43898b00fa464673db5664530877daed`
- Classification: **MANUAL\_REVIEW** (risk 404)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-08-16T00:36:25.880142Z`
- Accepted baseline: `v1.1.0` — `344fb7a082022f492ff2fe8db243e5363e8a2be3757c5ea9fb99e55264d9b25d`
- Capability changes:
  - **Network communication:** network destinations +3/-0 — **review**

## Decky Notifications

- Repository: `https://github.com/zany130/decky-notifications`
- Candidate: `1.0` — `c48de9ce7a8b8d5fedf97c9b8d1062b77d1868a798e5e307f6092c9097006b93`
- Classification: **PASS\_WITH\_WARNINGS** (risk 4)
- Comparison: `baseline_not_found`; reviewer-attention changes: 0
- First seen: `2026-08-09T01:07:41.070060Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.

## SDH-Ludusavi

- Repository: `https://github.com/beallio/SDH-Ludusavi`
- Candidate: `v0.4.4` — `71b609181c55a2c7fc6002ccefb93b25c55dabae3bfd9cc83f245a740399457e`
- Classification: **MANUAL\_REVIEW** (risk 32)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-08-13T00:59:58.219898Z`
- Accepted baseline: `v0.4.3` — `28171f4a10398c75f228112aa607529691804547e8c85eb518e7f015f3a26355`
- Capability changes: none observed in the comparison model.

## Panel de Control

- Repository: `https://github.com/Hooandee/panel-de-control`
- Candidate: `panel-de-control-v0.37.4` — `6ff6350f519ed52887d1aeab1974bf4add941c629dc3ef3441e012a85db841ce`
- Classification: **MANUAL\_REVIEW** (risk 327)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-08-17T12:21:34.103744Z`
- Accepted baseline: `panel-de-control-v0.37.1` — `e20cce88c57d2d4e4793c6b759d7bc4fdc6b51060469764e31e62b7ae05fdb07`
- Capability changes: none observed in the comparison model.

## Deck Shelves

- Repository: `https://github.com/santojon/Deck-Shelves`
- Candidate: `v3.2.1` — `0f14447ea6930103fff7235d3e45c7892f70afe38d95b84a07c90ca372eb95c5`
- Classification: **MANUAL\_REVIEW** (risk 87)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-08-15T18:14:21.149471Z`
- Accepted baseline: `v3.1.0` — `71a7c6d4f53eebbcd86d2d0e7563945bb4154b92edcc68e33af8caa7fde2e8d9`
- Capability changes: none observed in the comparison model.
