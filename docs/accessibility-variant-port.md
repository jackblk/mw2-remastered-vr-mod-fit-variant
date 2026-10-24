# Accessibility variant fork (MW2CR 1.1.2.1279292)

This fork of Overlord runs on a modified ("accessibility") `MW2CR.exe`, build
1.1.2.1279292, and keeps the official build working. The variant is itself a
modded, rebuilt executable. Its code layout matches the official binary, but
everything from `.data` onward is mapped `0x1000` lower, so every official
data address in the mod must be relocated at run time.

Status: the client starts, native VR stereo renders, the tutorial (The Pit,
`trainer`) was played in VR and Team Player (`roadkill`) loads. Open issue:
Steam Link disconnects during play (see Known issues).

## Start here

1. Read this file. If `tmp/handover.md` exists (git-ignored, the user's
   machine), read it next: it has the local paths and where the last session
   stopped.
2. Set `OVERLORD_GAME_DIR` to the game folder (with `MW2CR.exe`). Build
   prerequisites are in `docs/development.md` (run `generate.bat` again after
   a merge adds source files).
3. For `tools/variant_tool.py`, use a Python venv with
   `pip install capstone numpy minidump`. `python tools/variant_tool.py -h`
   lists the commands.
4. Ask the user what to do next: sync upstream, test, or fix a reported
   problem. Then follow the matching loop below.

Roles: the agent edits, builds, deploys and reads logs and dumps. Only the
user can run the game in VR; ask them to report what they did, when, and
what they saw, and to keep the game folder's files from that run.

## Branches and remotes

- `upstream` is Aeka0/Overlord (fetch only; it accepts no pull requests).
  `origin` is the fork.
- `main` mirrors `upstream/main`. Never commit to it.
- `build-1279292-variant` is `main` plus the port. It merges `main`; it is
  not rebased or force-pushed. `git diff main...build-1279292-variant` is the
  whole port. Keep that diff small: no new files or docs unless needed.

## Porting loop (sync with upstream)

```bash
python tools/variant_tool.py hook-bytes      # note the counts
git fetch upstream
git switch main && git merge --ff-only upstream/main
git switch build-1279292-variant && git merge main
python tools/variant_tool.py unwrapped
```

1. Resolve merge conflicts. They are usually upstream edits next to a
   relocated address; keep upstream's change and the relocation.
2. `unwrapped` lists raw official data addresses (`>= 0x140BE8000`) in
   `src/client` and checks each against the binary. Port each one:
   - a literal at its use: `game::build::relocate(0x14...)`;
   - a named constant: `constexpr game::build::data_address name{0x14...};`
     and read it with `name.get()`;
   - `game::symbol` and `vr::h2::read_only_global` relocate by themselves;
   - an address that must stay official: add `// variant-keep`.

   The verdict must be `shifted`: variant code references the address at
   `-0x1000`. Any other verdict means the uniform shift is not proven there;
   find the variant's real address with `refs`, `disasm` and `strings`.
3. Read the upstream diff (`git diff ORIG_HEAD.. -- src` right after the
   merge) for what no literal scan finds:
   - data addresses computed as `site + displacement` from an instruction:
     decode the live instruction instead (see `native_hud_capture.cpp`);
   - code that writes captured or official bytes back over instructions:
     write the loaded image's bytes, not the official ones;
   - exact byte comparisons outside `utils::hook_validation::verify_masked_bytes`.
4. Run `hook-bytes` again: a rise in `unmatched` means a new hook's expected
   bytes do not fit the variant; list them with `-v`.
5. Build and deploy (Test loop), have the user test, then commit and push:
   `git push origin main build-1279292-variant`.

## Test loop

```bash
python tools/deploy_local.py --build
```

This builds RelWithDebInfo, copies only changed files (with the PDB) into
`OVERLORD_GAME_DIR` and backs up replaced files to
`output/deployments/<UTC time>/`. The Release configuration currently fails on
an upstream warning in `ladder_scene.cpp`; use the default.

After the user's run:

```bash
python tools/variant_tool.py logs
```

It shows matching lines from `overlord.log` (rewritten each run, flushed per
line, no timestamps on ordinary lines), the key status-report lines and the
newest minidumps.

- `diagnose/overlord-status-latest.txt`: `strict_preflight=ready` means native
  stereo may run; `openxr_frame_submission` counts world and menu-only
  frames. The user refreshes it with `vr_diagnose` or Ctrl+Shift+F8 while a
  problem is visible (`docs/vr-diagnostics-workflow.md`).
- Normal on the variant: `[ARXAN] DbgBreakPoint changed` and
  `LUI WARNING: Anim State pool full`.

## Debugging crashes and errors

- **Crash** (`minidumps/*.dmp`): `python tools/variant_tool.py crash` takes the
  newest dump and prints the exception, the registers and the unwound stack,
  with overlord frames named from the PDB. If the dump is older than the
  deployed `overlord.exe`, the tool uses the build in the first deployment
  backup after the crash; override with `--overlord`. `--scan` adds a raw
  stack scan; `mem <dmp> <addr>:<len>` reads captured memory.
- **Com_Error** (error dialog, no dump): `overlord.log` has
  `[VR diag] Com_Error frame N: h2 0x...` / `overlord+0x...` lines; name the
  overlord frames with `sym <offset>...`.
- **Headset stops receiving frames**: `[VR diag] hh:mm:ss.mmm Present gap N ms`
  lines mark Present gaps and blocking Presents of 250 ms or more (OpenXR
  frames are submitted only inside H2's Present). Compare their times with
  SteamVR's timestamped logs (`driver_vrlink.txt`, `vrserver.txt`,
  `vrcompositor.txt`, `xrclient_overlord.txt` in Steam's `logs` folder).
- **A native address**: `disasm <addr> --function`, `refs <addr>` (who reads
  or writes it), `callers <function>`, `strings <text>`, `data-refs <addr>`,
  `disp <value>` (image-relative operands), `sections`.

## Variant facts

| | Official (upstream target) | Accessibility variant |
| --- | --- | --- |
| `MW2CR.exe` size | `0xE1E0C8` | `0xE1E248` |
| DWORD at `0x140123456` | `0xE465E151` | `0x0FE4158D` |
| `.data` starts at | `0x140BE8000` | `0x140BE7000` |
| Authenticode | valid | `HashMismatch` (modified after signing) |
| PE timestamp | `0x6023ED08` (2021-02-10) | `0x5EAB60CD` (2020-04-30) |
| PE image size | `0x11E6BC00` | `0x11E6B200` |

Variant SHA-256: `b0b9909199051ecf1e24a56f6a6f93f47364549f32164f7698db789d271d8c57`.
No official binary was available; official facts come from the source.

- **Code layout matches.** 501 of 1587 source code addresses land exactly on
  `.pdata` function starts, and 688 expected byte arrays in the source matched
  the variant exactly at their addresses in the first audit.
- **`.data` is shifted.** Every official data address the mod uses is
  referenced by variant code at `address - 0x1000` and never at `address`.
  RIP- and image-relative displacements to data differ by `-0x1000`, for
  example `mov eax,[rip+0x0EC4991B]` vs `[rip+0x0EC4891B]` at `0x14029737B`.
- **It is a rebuilt image, not a pure shift.** Every section's raw size equals
  its virtual size, every section is marked executable, and a rebuilt
  `.idata` and a second `.text` (`0x151E3E000`, `0x2D200`) follow `.reloc`.
  The image size does not fit a pure shift either. Only `.data` is evidenced
  to be uniformly shifted, which is why each new address is checked.
- **The code is stored decrypted** (the official file is Arxan-encrypted on
  disk), so code pages stay `PAGE_EXECUTE_WRITECOPY` until patched.
- The CRT still resolves `InitializeCriticalSectionEx` through
  `GetProcAddress`, so the `post_unpack` trigger in `main.cpp` fires.

## Where the port lives

- `src/client/game/build.hpp`, `game.cpp`: `game::build::id`,
  `relocate(address)` (identity on the official build) and `data_address`.
- `main.cpp` `verify_version()` picks the build from the probe DWORD;
  `game_data.hpp` accepts both file sizes.
- `game::symbol::get()` and `vr::h2::read_only_global::get()` relocate.
- `utils::hook_validation::verify_masked_bytes` accepts a mismatched 4-byte
  window only when it encodes the same RIP- or image-relative data target
  moved by the build's delta (`set_data_relocation`).
- Sites that write original bytes keep the loaded image's encoding:
  `scene_surface_storage.cpp`, `native_post_aa.cpp` and the rollback in
  `engine_stereo_renderer.cpp`.
- `engine_stereo_renderer.cpp`: `effective_protection()` treats copy-on-write
  as writable; patch transactions report the first failing step.
- `native_hud_capture.cpp`: the UI end marker decodes the live displacement at
  `0x14079A1D2` instead of replaying the official one.
- `engine_stereo_probe.cpp`: the native stereo fingerprint is selected per
  build.
- `loadscreen.cpp`: `clear()` skips unregistered dvars, so an early
  `Com_Error` surfaces instead of `Dvar_Reset(nullptr)`.
- Diagnostics: `console.cpp` mirrors console output to `overlord.log`;
  `main.cpp` logs fatal startup errors; `logger.cpp` logs the Com_Error call
  stack; `d3d11.cpp` logs Present gaps.
- Tools: `tools/deploy_local.py` (test deploys), `tools/variant_tool.py`
  (porting checks, binary queries, crash triage).

## Known issues and gaps

- **Steam Link (`vrlink`) disconnects.** In a 28-minute run the game held about
  86-89 fps with no Present gap of 250 ms or more before each disconnect. In
  `driver_vrlink.txt` the link degraded first (bad-link events, rising ping,
  stream-reset requests, `THROTTLE EVENT`, packet timeouts), then
  `Connection inactive`; Present gaps appeared only afterwards. So the
  disconnects do not look caused by load stalls; network or Steam Link
  settings (fixed 350 Mbit/s, auto bitrate off) are the next suspects. A
  keep-alive frame submitted from a mod thread is on hold without evidence.
- Both controllers' grip channels report `calibration_invalid`; probably a
  SteamVR setup issue, not investigated.
- Only `verify_masked_bytes` tolerates the shift. An exact comparison of code
  bytes that covers a data displacement elsewhere would still reject the
  variant; none are known.
- Binary fingerprints other than the startup probe could gate features per
  build; none besides the native stereo one were found.
- Base H2-Mod fastfiles come from the Beta 1 release, so some localized text
  may be stale.
- Signature scanning (resolving every address at run time) is deferred until
  a build with a different code layout needs support.

## History

1. Copy-on-write code pages failed the backend patch transaction; fixed by
   `effective_protection()`.
2. `Dvar_Reset(nullptr)` crashed in `loadscreen::clear()` during an early
   `Com_Error`; the real error was `Tried to use 'feedbackSampler' when it
   isn't valid`.
3. `feedbackSampler`: the UI end marker replayed the blit gate's load from the
   official address, so the variant compared an unrelated global and always
   blitted render target 1. Fixed by decoding the live displacement. A literal
   scan had missed it because the address was `site + displacement`.
4. The headset showed only "waiting": the native stereo fingerprint accepted
   only the official binary (`strict_preflight=blocked reason=target_identity`).
   Fixed by the per-build fingerprint.
5. Upstream sync to `6892500`: five new data addresses relocated.
