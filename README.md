# Far Cry 5: 3-Player Campaign Co-op

Far Cry 5 normally limits campaign co-op to **two players**. This small Windows patcher lets you **host a campaign with three players total** (with experimental support for 4–16 players), and includes an optional **Cutscene Camera Fix** for additional players.

We've tested three-player sessions on two different host PCs. Players could see and interact with each other, ride in the same vehicle, fast-travel together, and receive campaign mission objectives.

## How to use

### If you are the Host:
1. Download **`FC5CampaignCoopPatcher.exe`** from the [latest release](https://github.com/zooloo-01/FarCry5-CoopUnlock/releases/latest).
2. **Close Far Cry 5 completely.**
3. Run the patcher on the PC that will host the game.
4. Select your installation (or browse to `Far Cry 5\bin\FC_m64.dll`).
5. Choose **3 Players** (or 4 Players).
6. *(Optional)* Check **Fix Cutscene Cameras (Experimental)**.
7. Click **Apply Co-op Patch**.
8. Launch the campaign and invite your friends.

### If you are a Guest (Players 2, 3, or 4 on Windows PC):
1. Download **`FC5CampaignCoopPatcher.exe`**.
2. **Close Far Cry 5 completely.**
3. Run the patcher on your PC.
4. Select your installation (`Far Cry 5\bin\FC_m64.dll`).
5. Choose **2 Players [Pristine / Guest Only]** (or keep your capacity as-is).
6. Check **Fix Cutscene Cameras (Experimental)**.
7. Click **Apply Co-op Patch**.

### Important Notes:
- **GeForce NOW Guests:** Players connecting via NVIDIA GeForce NOW cannot install local DLL patches because the game runs on cloud virtual machines without local file access. GeForce NOW players can join and play the 3P/4P campaign normally and will hear cutscene dialogue and audio, but their view camera will remain in 1st-person gameplay mode during cinematics.
- **Experimental Status:** While 3-player co-op campaign gameplay is fully verified and proven in live gameplay, the cutscene camera fix for additional players remains an experimental feature until extensive live testing confirms stability across all campaign sequences and outpost liberations.
- **Both Host and Guests:** The host may install both the capacity patch and camera fix. Guest players on Windows PCs only need to install the camera fix.

## Undo the patch

Close the game, open the patcher, and click **Restore Original Game**.

## Good to know

- **The patcher automatically backs up the original game DLL** (`FC_m64.dll.bak`).
- **3 players is the tested option.** The 4–16 player settings are experimental and haven't been verified in live gameplay.
- The patcher only supports compatible game builds. If it reports an unsupported DLL, don't force it.
- Not every story mission or multiplayer scenario has been tested. Back up your save before experimenting.
- This is an unofficial community project. **No game files are included.** You'll need your own copy of Far Cry 5.

Found a bug? [Open an issue](https://github.com/zooloo-01/FarCry5-CoopUnlock/issues).

**License:** MIT for this patcher.
