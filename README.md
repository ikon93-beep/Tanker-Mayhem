# Tanker Mayhem — Explosive Tanker Trucks

Source code for TrailerImpactMod 3.3b for Need for Speed: Most Wanted (2005), PC v1.3.

A strong collision with a TRAILERA fuel tanker triggers an explosion and sound, disables nearby police vehicles, stops the attached SEMIA, and activates the damaged tanker body. Recycled tanker instances return to their normal appearance.

This is the source snapshot used for the working 3.3b release. The four source files are unchanged from the development package. Runtime success was confirmed by the author during in-game testing on their installation; compatibility with every executable or mod combination is not guaranteed.

## Build

Requires Python and the Zig compiler provided by the `ziglang` Python package. Run from this repository root:

```sh
python -m pip install ziglang
python -c "from pathlib import Path; Path('scripts').mkdir(exist_ok=True)"
python -m ziglang c++ -target x86-windows-msvc -O2 -fno-exceptions -fno-rtti -fno-stack-protector -fno-builtin -nostdlib -shared -Wl,-e,DllMain@12 source/TrailerImpactMod_3.3b.cpp -o scripts/TrailerImpactMod.asi
```

The historical compiler package version was not pinned; byte-for-byte reproducibility is not claimed.

## Installation

Use a compatible ASI Loader and place the built ASI in the game's `scripts` folder. The sound files and TRAILERA geometry from the Tanker Mayhem release are also required. Keep only one TrailerImpactMod ASI installed.

This repository contains source only. It does not include speed.exe, game assets, sound files, compiled plugins, logs, or historical test versions.

## Compatibility and limitations

- Targets the supported v1.3 executable layout; fixed native addresses are used.
- Unlimiter and SpeedReflect are not required. Only specifically recognized native/mod code patterns are accepted for the body rebuild.
- The visual swap pool has 64 records per process. When exhausted, further visual swaps are skipped until the game restarts.
- Diagnostic logging remains in the release code to help investigate compatibility problems.

No open-source license has been selected for this publication.
