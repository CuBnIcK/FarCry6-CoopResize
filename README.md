# Far Cry 6 Co-op Resize: 3–4 player campaign

Far Cry 6 limits campaign co-op to **two players**. This patcher lifts that limit so **three or more players** can play the campaign together.

This is a Far Cry 6 fork of [zooloo-01/FarCry5-CoopUnlock](https://github.com/zooloo-01/FarCry5-CoopUnlock), the 3-player patch for Far Cry 5.

**Works with the latest Far Cry 6 on Steam and on Ubisoft Connect (Uplay).** The patcher detects the version automatically.

| Players | Status |
| --- | --- |
| 3 | **Tested.** Three players play the campaign together in one world |
| 4 | Works, but **at your own risk.** Not tested as thoroughly as 3 |
| 5+ | The patch opens 4 slots. More is theoretically possible, but would need further changes and is entirely at your own risk |

## ⚠️ Every player must install the patch

If you plan to play with more than two people, **the host and every guest install the patch**, not only the host.

Without the patch on every PC, the game falls out of sync: players stand in an A-pose without animations, cars don't move for others, and transitions can hang on a black screen.

## How to use

1. Download **`FC6CoopPatcher.exe`** from the [latest release](../../releases/latest).
2. **Close Far Cry 6 completely.**
3. Run the patcher. It finds the game in Steam or Ubisoft Connect by itself, otherwise click **Browse...** and choose the Far Cry 6 folder (the one that contains `bin`).
4. Click **Install co-op patch**. It takes up to a minute, the game DLL is about 500 MB.
5. Start the game, host the campaign and invite your friends. Every friend does steps 1–4 too.

The patcher shows what is installed: original game, co-op patch, or an unsupported version.

### Undo the patch

Close the game, run the patcher and click **Restore original**. Verifying the game files in Steam or Ubisoft Connect also brings back the original.

## Known issues

- **Cutscenes:** the third (and fourth) player is not attached to the cutscene camera. During cutscenes that player keeps playing on their own while the first two watch the scene.
- **Game updates:** a game update or "Verify integrity of game files" replaces the patched DLL. Run the patcher again. If it reports an unsupported version, the game was updated and the patch needs an update too.
- Not every story mission has been played with three players. Back up your saves before experimenting.

## Good to know

- The patcher changes one file, `bin\FC_m64d3d12.dll`, and keeps a verified copy of the original next to it as `FC_m64d3d12.dll.bak`.
- It works only with the exact game versions it knows, checked by SHA-256. An unknown DLL is never touched.
- Every file is written to a temporary copy, checked against the expected SHA-256, and only then moved into place.
- This is an unofficial community project. **No game files are included.** You need your own copy of Far Cry 6.

## Disclaimer

**Use entirely at your own risk.** This is an unofficial modification, not supported by Ubisoft. Modifying game files may conflict with the game's terms of service.

- It may be incompatible with other mods. A mod that replaces `FC_m64d3d12.dll` makes the patcher refuse to work, and other mods may break the game in combination with this patch.
- Crashes, desyncs, lost progress or other problems are possible. Back up your saves.
- The authors take no responsibility for any consequences of using it.

This project was made with the help of AI tools (neural networks): reverse engineering, code and documentation. Everything was checked by tests and by playing the game, but keep that in mind.

## How it works

Far Cry 6 limits co-op to two players in several layers. The patch lifts all of them:

| Layer | Limit in the original game | Without this fix |
| --- | --- | --- |
| Game mode configuration and local session slots | `maxTeamSize = 2` | The game refuses a third player |
| Ubisoft sessions API quota | `2` | Joins fail with `Aoraki-4D82D34C` |
| Storm peer-to-peer session | `maxPeers = 2`, `maxPeersId = 2` | `Bookworm` or `Trapper` errors |
| P2P object replica table | peer ids 0 and 1 only | The third player waits for the world forever (`Trapper-B2FE5BAD`) |
| P2P object owner checks | peer id below 2 | The third player never spawns |

## For developers

The patcher is plain Python 3.11+ with no dependencies. Code lives in [src/fc6](src/fc6).

```bash
python src/fc6_coop_patcher.py                       # the window
python src/fc6_coop_patcher.py --status              # the same from a terminal
python src/fc6_coop_patcher.py --install "D:\Games\Far Cry 6"
python src/fc6_coop_patcher.py --restore
```

Research tools:

- `python src/patch_fc6.py --list` lists every experimental variant. `python src/patch_fc6.py <original DLL> --output-dir <new folder> [--variant <name>]` builds a package next to a pristine backup without installing anything.
- `python src/observe_fc6_runtime.py` reads a running game (read-only, Steam build) and reports the loaded variant and session limits.
- `python src/collect_fc6_join_diagnostics.py --duration 120` records join-state changes as JSONL. It omits account names, session IDs, addresses and network payloads.

Tests: `python -m pip install -r requirements.txt`, then `python -m unittest discover -s tests`. Tests that need the game DLL read `FC6_ORIGINAL_DLL` (Steam) and `FC6_UBISOFT_DLL`, or the backups under `local/far-cry-6/`, and are skipped otherwise.

Build the exe with `./build_exe.ps1`. Pushing a `v*` tag builds it on GitHub Actions and attaches it to a release.

## Credits

- [zooloo-01](https://github.com/zooloo-01) for the original [Far Cry 5 co-op unlock](https://github.com/zooloo-01/FarCry5-CoopUnlock).
- Many thanks to **YuRaNnNzZZ**, **Horpsel** and **Dayfing** for testing, all the black screens, A-poses and reconnects that made three-player co-op work.

Found a bug? [Open an issue](../../issues).

**License:** [MIT](LICENSE).
