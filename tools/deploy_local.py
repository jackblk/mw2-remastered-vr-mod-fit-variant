"""Install a built client overlay into a game directory for local testing.

Copies the same file set as tools/package_client.py (executable, OpenXR loader,
SteamVR manifest/artwork, input bindings, h2-mod scripts and sound zone,
notices), plus the matching PDB, into the game root. Every replaced file is
backed up first and a failed copy rolls back. Original game files and user
profiles are never touched.

The client build does not produce the base H2-Mod fastfiles. Pass --base-data
once (for example a previous release's h2-mod directory) to install them.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import package_client  # noqa: E402  Release file selection and artifact audit.
from deploy_client_pair import digest  # noqa: E402

ROOT = package_client.ROOT
GAME_BINARIES = ("MW2CR.exe", "h2_sp64_bnet_ship.exe")


def build(configuration: str) -> None:
    subprocess.run(["msbuild", str(ROOT / "build/overlord.sln"), "/t:client", "/m:2",
                    f"/p:Configuration={configuration}", "/p:Platform=x64",
                    "/p:PreferredToolArchitecture=x64", "/p:CL_MPCount=4",
                    "/v:minimal", "/nologo"], cwd=ROOT, check=True)


def collect(configuration: str, base_data: Path | None, symbols: bool) -> dict[str, Path]:
    files = package_client.collect(configuration, base_data)
    if symbols:
        binary = "overlord-debug" if configuration == "Debug" else "overlord"
        pdb = ROOT / "build/bin/x64" / configuration / f"{binary}.pdb"
        if not pdb.is_file() or not pdb.stat().st_size:
            raise ValueError(f"Missing symbols from the selected build: {pdb.name}")
        files[pdb.name] = pdb
    return files


def deploy(files: dict[str, Path], destination: Path, backup_root: Path, dry_run: bool) -> dict:
    destination, backup_root = destination.resolve(), backup_root.resolve()
    if not destination.is_dir():
        raise NotADirectoryError(destination)
    if not any((destination / name).is_file() for name in GAME_BINARIES):
        raise ValueError(f"Not a game directory (no {' or '.join(GAME_BINARIES)}): {destination}")
    # Validate every destination before changing any installed file.
    changes = {}
    for name, source in sorted(files.items()):
        target = destination / name
        if not target.resolve().is_relative_to(destination) or target.resolve() == source.resolve():
            raise ValueError(f"Unsafe deployment destination: {name}")
        expected = digest(source)
        previous = digest(target) if target.is_file() else None
        if previous != expected:
            changes[name] = (source, previous, expected)
    token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    backup = backup_root / token
    record = {"time_utc": datetime.now(timezone.utc).isoformat(), "destination": str(destination),
              "backup": str(backup), "deployed": False, "unchanged": len(files) - len(changes),
              "files": {name: {"source": str(source), "before": previous, "after": expected}
                        for name, (source, previous, expected) in changes.items()}}
    if dry_run or not changes:
        record["deployed"] = not changes
        return record
    backup.mkdir(parents=True, exist_ok=False)
    staged, replaced = {}, []
    try:
        for name, (source, previous, expected) in changes.items():
            target = destination / name
            if previous is not None:
                (backup / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup / name)
                if digest(backup / name) != previous:
                    raise OSError(f"Backup verification failed: {name}")
            stage = destination / (name + ".staging-" + token)
            stage.parent.mkdir(parents=True, exist_ok=True)
            staged[name] = stage
            shutil.copy2(source, stage)
            if digest(stage) != expected:
                raise OSError(f"Stage verification failed: {name}")
        for name in changes:
            # A running overlord.exe cannot be replaced; that rolls back the set.
            os.replace(staged[name], destination / name)
            replaced.append(name)
        for name, (_, _, expected) in changes.items():
            if digest(destination / name) != expected:
                raise OSError(f"Deployment verification failed: {name}")
        record["deployed"] = True
    except Exception:
        for name in reversed(replaced):
            if changes[name][1] is None:
                (destination / name).unlink()
            else:
                shutil.copy2(backup / name, staged[name])
                os.replace(staged[name], destination / name)
        raise
    finally:
        for stage in staged.values():
            if stage.exists():
                stage.unlink()
        (backup / "deployment.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("game_directory", type=Path, nargs="?",
                        default=os.environ.get("OVERLORD_GAME_DIR"),
                        help="Game root containing MW2CR.exe (default: %%OVERLORD_GAME_DIR%%)")
    parser.add_argument("--configuration", choices=["RelWithDebInfo", "Release", "Debug"],
                        default="RelWithDebInfo")
    parser.add_argument("--build", action="store_true", help="Build the client with msbuild first")
    parser.add_argument("--base-data", type=Path,
                        help="Directory with base H2-Mod fastfiles under zone/ (e.g. a release's h2-mod)")
    parser.add_argument("--no-symbols", action="store_true", help="Do not install the PDB")
    parser.add_argument("--backup-root", type=Path, default=ROOT / "output/deployments")
    parser.add_argument("--dry-run", action="store_true", help="List changes without copying")
    args = parser.parse_args()
    if args.game_directory is None:
        parser.error("game_directory is required (or set OVERLORD_GAME_DIR)")
    try:
        if args.build:
            build(args.configuration)
        files = collect(args.configuration, args.base_data, not args.no_symbols)
        record = deploy(files, Path(args.game_directory), args.backup_root, args.dry_run)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Deploy failed: {error}\n")
    for name in record["files"]:
        print(("would copy " if args.dry_run else "copied ") + name)
    state = "dry run" if args.dry_run else ("deployed" if record["deployed"] else "not deployed")
    print(f"{state}: {len(record['files'])} changed, {record['unchanged']} unchanged -> {record['destination']}")
    if record["files"] and not args.dry_run:
        print(f"backup: {record['backup']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
