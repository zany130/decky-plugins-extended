# Security Review Queue

Pending artifacts: **19** — critical 3, high 11, normal 5.
Generated: `2026-09-04T20:02:19.703989Z`
Source audit run: https://github.com/zany130/decky-plugins-extended/actions/runs/33913924158

| Priority | Plugin | Candidate | Baseline | Classification | Why |
| --- | --- | --- | --- | --- | --- |
| **CRITICAL** | Muon | 0.5.0.2 / `229ae50f12c4` | unavailable | BLOCK | blocked by policy, baseline unavailable |
| **CRITICAL** | https://github.com/xXJSONDeruloXx/Decky-bionic-fg |  / `unavailable` | v0.1.6 / `d3758997fc9b` | AUDIT\_ERROR | audit error, artifact identity unavailable, security delta |
| **CRITICAL** | Decky-Framegen | v0.17 / `3300b617e3d9` | v0.17 / `3300b617e3d9` | AUDIT\_ERROR | audit error, security delta, same artifact analysis drift |
| **HIGH** | steam-achievements | v1.2.5 / `522346503007` | v1.2.3 / `4a698f9f7bf0` | PASS\_WITH\_WARNINGS | new artifact, security delta |
| **HIGH** | DeckyClash | v0.1.2 / `7ebadc4bfd0e` | unavailable | MANUAL\_REVIEW | baseline unavailable |
| **HIGH** | Tender | tender-v0.31.0 / `74ba2fe0775e` | decky-romm-sync-v0.30.1 / `254a911f01e6` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | MoonDeck | nightly / `8ceb60a12e02` | unavailable | MANUAL\_REVIEW | baseline unavailable |
| **HIGH** | Panel de Control | panel-de-control-v0.38.0 / `ee7028d8da07` | panel-de-control-v0.37.1 / `e20cce88c57d` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Unifideck | Release-0.7.4 / `86b264f4e143` | Release-0.7.3 / `dd9943ce6b0c` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Achievement Companion | v0.3.3 / `8aa1bb619bad` | v0.3.2 / `3f0260c0a552` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Decky Vibrance HDR | 1.0.1 / `8bbf5601ea5b` | 1.0.0 / `c5fbde7be36a` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | LeGoTDP | 1.7.0 / `05ec1d51456b` | 1.6.1 / `2bccb912292b` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | RetroDECKY | v1.2.0 / `070d8850fcac` | v1.1.0 / `344fb7a08202` | MANUAL\_REVIEW | new artifact, security delta |
| **HIGH** | Decky Notifications | 1.0 / `c48de9ce7a8b` | unavailable | PASS\_WITH\_WARNINGS | baseline unavailable |
| **NORMAL** | Decky Metadata | v0.3.12 / `0a9555f9dd87` | v0.3.6 / `0d856632d8a4` | PASS | new artifact |
| **NORMAL** | Decky UI Restored | v0.2.3 / `e06302ed068e` | v0.2.0 / `0c5e9cda3953` | PASS\_WITH\_WARNINGS | new artifact |
| **NORMAL** | SDH-Ludusavi | v0.4.7 / `439fe36d33c9` | v0.4.3 / `28171f4a1039` | MANUAL\_REVIEW | new artifact |
| **NORMAL** | Steamcord | v1.30.0 / `7c7f2baf1f3f` | v1.21.1 / `4c0ca32204c2` | MANUAL\_REVIEW | new artifact |
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

## steam-achievements

- Repository: `https://github.com/AG69075/steamOS_plugin_achievements`
- Candidate: `v1.2.5` — `522346503007e6bb6243d8bdde072c46ec45f19eb7a3a8011e7edc33e704fee1`
- Classification: **PASS\_WITH\_WARNINGS** (risk 2)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-08-26T12:27:53.973839Z`
- Accepted baseline: `v1.2.3` — `4a698f9f7bf08e8f4e78c341009ac7003830ad43e071aaef770c1af61ee443e0`
- Capability changes:
  - **Published release versus source:** source/release difference profile changed; rule profile +0/-1 — **review**

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
- Candidate: `nightly` — `8ceb60a12e02a281fe37d1f80e8d456108842e626b229d656590207f2415a2b4`
- Classification: **MANUAL\_REVIEW** (risk 7799)
- Comparison: `baseline_not_found`; reviewer-attention changes: 0
- First seen: `2026-08-23T00:38:26.656868Z`
- Accepted baseline: unavailable
- Capability changes: none observed in the comparison model.

## Panel de Control

- Repository: `https://github.com/Hooandee/panel-de-control`
- Candidate: `panel-de-control-v0.38.0` — `ee7028d8da07b8416303bbc1d31dcb4752a2ca10742b3b2b5138bdac9a6ce73a`
- Classification: **MANUAL\_REVIEW** (risk 362)
- Comparison: `compared`; reviewer-attention changes: 2
- First seen: `2026-09-02T20:16:27.729655Z`
- Accepted baseline: `panel-de-control-v0.37.1` — `e20cce88c57d2d4e4793c6b759d7bc4fdc6b51060469764e31e62b7ae05fdb07`
- Capability changes:
  - **Command and process execution:** rule profile +3/-0 — **review**
  - **Network communication:** network destinations +2/-0 — **review**

## Unifideck

- Repository: `https://github.com/mubaraknumann/unifideck`
- Candidate: `Release-0.7.4` — `86b264f4e143b5e13499fb8812fde93801320a082af3106d515acfdfb1cf6ba9`
- Classification: **MANUAL\_REVIEW** (risk 2396)
- Comparison: `compared`; reviewer-attention changes: 2
- First seen: `2026-08-23T12:19:52.936768Z`
- Accepted baseline: `Release-0.7.3` — `dd9943ce6b0c2be3a68644727046f1693ad537b6085c5adaf16b29cf436a0bf7`
- Capability changes:
  - **Network communication:** network destinations +3/-0 — **review**
  - **Published release versus source:** source/release difference profile changed; rule profile +1/-0 — **review**

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
- Candidate: `1.7.0` — `05ec1d51456b7719286349b570d6679a53ba6482828a0ba67388df280f054ba7`
- Classification: **MANUAL\_REVIEW** (risk 52)
- Comparison: `compared`; reviewer-attention changes: 1
- First seen: `2026-09-02T20:16:27.729655Z`
- Accepted baseline: `1.6.1` — `2bccb912292b5d6caffcce17b2009b463fd7828aede88ce0f1af51adae4042b8`
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

## Decky Metadata

- Repository: `https://github.com/beallio/Decky-Metadata`
- Candidate: `v0.3.12` — `0a9555f9dd87781b43083ce2e860674f0d76bfb0bdde8b19174d88b64a34accb`
- Classification: **PASS** (risk 0)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-09-04T20:02:19.703989Z`
- Accepted baseline: `v0.3.6` — `0d856632d8a48a93f9886bb4f4bc7270bf64f21d1dce23c208a978e45d94fda5`
- Capability changes: none observed in the comparison model.

## Decky UI Restored

- Repository: `https://github.com/beallio/Decky-SteamAchievements`
- Candidate: `v0.2.3` — `e06302ed068e0d2a5a5805beca8cb9ef5c48a019f0b79f5f147e9108b1fd1d13`
- Classification: **PASS\_WITH\_WARNINGS** (risk 4)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-09-04T20:02:19.703989Z`
- Accepted baseline: `v0.2.0` — `0c5e9cda3953aa0c563f8ec614f0b342a90762643cb935da42d8688c77c02b3a`
- Capability changes: none observed in the comparison model.

## SDH-Ludusavi

- Repository: `https://github.com/beallio/SDH-Ludusavi`
- Candidate: `v0.4.7` — `439fe36d33c949b265242f2a984ea2b2700db36246a483495c2dfcb26ab91f69`
- Classification: **MANUAL\_REVIEW** (risk 42)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-09-02T20:16:27.729655Z`
- Accepted baseline: `v0.4.3` — `28171f4a10398c75f228112aa607529691804547e8c85eb518e7f015f3a26355`
- Capability changes: none observed in the comparison model.

## Steamcord

- Repository: `https://github.com/Necrosiak/Steamcord`
- Candidate: `v1.30.0` — `7c7f2baf1f3f9072d74ba7a475a75b9fcd4f7dfa34e800f6bc2a2952fca7ac99`
- Classification: **MANUAL\_REVIEW** (risk 742)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-09-01T10:42:16.601755Z`
- Accepted baseline: `v1.21.1` — `4c0ca32204c25c741d03736199622d8ee6ed63fbca5c67ff7f321b7593348f38`
- Capability changes: none observed in the comparison model.

## Deck Shelves

- Repository: `https://github.com/santojon/Deck-Shelves`
- Candidate: `v3.2.1` — `0f14447ea6930103fff7235d3e45c7892f70afe38d95b84a07c90ca372eb95c5`
- Classification: **MANUAL\_REVIEW** (risk 87)
- Comparison: `compared`; reviewer-attention changes: 0
- First seen: `2026-08-15T18:14:21.149471Z`
- Accepted baseline: `v3.1.0` — `71a7c6d4f53eebbcd86d2d0e7563945bb4154b92edcc68e33af8caa7fde2e8d9`
- Capability changes: none observed in the comparison model.
