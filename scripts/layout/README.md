# Layout comparison: our build against the shipped binary

Four small tools that compare `main.exe` with `bin/2025.7.1/ForgedAlliance.exe`
directly, image to image. No C++ is parsed, which is the point: the earlier
source-side attempt at this (counting `virtual` declarations in headers) reported
210 mismatches of 680 and every large family among them was a parser artifact —
implicit overrides, unresolved bases. Reading the two images instead has no such
failure mode, and in one pass it found four real defects that per-function audits
had missed for months.

All four need only a compile (`-t:ClCompile`) plus whatever `main.exe`/`main.pdb`
were last linked; none of them need a link of their own.

| script | question it answers |
|---|---|
| `vtcompare.py` | which classes have a different **number** of vtable slots |
| `vtorder.py` | which classes hold a **different method in a given slot** |
| `ourvt.py <Class>` | dump one of our vtables with names resolved from `main.pdb` |
| `rttibases.py` | which classes have a different **base-class list or base offset** |

## How the vtable walk works, and why it terminates

Each vftable head comes from a symbol — the IDA callgraph index for the shipped
side, `main.pdb`'s public symbol stream (scanned raw for `S_PUB32` records) for
ours. Slots are then counted by walking dwords forward while each one points
into `.text`. That stops on its own because MSVC places the `??_R4`
complete-object-locator pointer immediately *before* every vftable, and that is
an `.rdata` address. Independently validated against TerrainCommon 15,
UserEntity 17, CTesselator 12, CDecalManager 30, CWldTerrainRes 77,
CameraImpl 44.

It can still over-run where two sibling tables sit adjacent with no locator
between them — `PausedChildThread` reads as 12 slots against a real 6 — and the
tail it invents shows up as slots IDA never named, which is how the filters
recognise it.

## Reading the output without chasing ghosts

Three sources of noise account for nearly all raw hits. Filter or check them
before acting:

- **IDA's placeholder names.** `sub_XXXXXXXX`, `FuncN`, `nullsub_N` carry no
  information; a row reading `shipped Func1 | ours GetLodThreshold` is the same
  function under two names. Equally, IDA's name is not authoritative where ours
  came from a mangled symbol: `IWinApp` slot 1 reads `AppExit` against our
  `AppGetHelpText`, and both are 0x008CD460.
- **ICF.** `/OPT:ICF` folds identical bodies, so a trivial accessor of ours
  resolves to whichever public won at that address — `capacity`, `swap`,
  `_Get_scary`, a wx function. `Unit` looked permuted at slot 17 for exactly
  this reason; slots 16 and 17 are both `GetAttributes`, the const and non-const
  overloads.
- **Empty bases.** `noncopyable`, `InstanceCounter<T>` and `WeakObject` are
  empty, and MSVC may place an empty base anywhere, so their RTTI offsets are
  not layout. `UserEntity` reads as having `WeakObject` at +8 against our +4 and
  is *correct*: the engine's weak-link head is at +0x30, zeroed by the
  constructor at 0x008B85E0 and drained by the destructor.

The durable rule this produced: **verify any candidate against the constructor
or destructor disassembly before touching the source.** That test rejected
`UserEntity` and confirmed `CameraImpl`.

## Verifying a fix without linking

The vtable is a COMDAT in the `.obj`. Its slot count is the section size minus
the symbol's value, over four, and the section's relocations give the slots in
order. That is how every fix in this family was checked — see the commits for
SkyDome/WaterSurface, CMauiControl, CameraImpl and the virtual-destructor pass.

## What it found

- `SkyDome`, `WaterSurface`, `HighFidelityWater`, `LowFidelityWater` — a missing
  slot each (commit d2de354f).
- `CMauiControl` and its twelve subclasses — the whole 25-slot table permuted,
  plus two members declared virtual that the engine does not (commit 4393556f).
- `CameraImpl` — all 44 slots permuted, a hand-written scalar-deleting
  destructor holding a slot of its own, and `CameraSetViewport` missing from the
  table (commit f5c5a54a).
- Five base classes carrying a virtual destructor the engine has no slot for,
  displacing every method under it in them and in everything deriving from them
  (commit b5fb4a97).
- `gpg::gal::DeviceD3D9` — 19 slots still not overridden; see
  `decomp/recovery/reports/by-source/src/sdk/gpg/gal/Device.reconstruction.md`.
