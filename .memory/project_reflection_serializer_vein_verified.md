---
name: project-reflection-serializer-vein-verified
description: The RType Init / serializer vein is systematically verified clean as of 2026-08-17 - size, version, both callbacks, class presence, and member-pair completeness all check out. Do not re-sweep it.
metadata:
  type: project
---

After fixing nine defects in this area during the 2026-08-17 run, I swept the
whole reflection/serialization layer against the binary and it now checks out on
every axis I could mechanise. **Do not spend another batch re-sweeping this** -
re-read this note instead.

## The oracle

391 `::Init` emissions of 3-14 instructions exist below 0x00A00000. Of those,
**84 install serializers, and not one is one-sided** - every emission that sets
`serLoadFunc_` also sets `serSaveFunc_`. That makes any *source* `Init` which
installs only one side unambiguously a defect, not a judgement call.

Field offsets on `RType` (vptr at +0x00): `size_` +0x08, `version_` +0x0C,
`serSaveConstructArgsFunc_` +0x10, `serSaveFunc_` +0x14, `serConstructFunc_`
+0x18, `serLoadFunc_` +0x1C. So in a decompile, `*(this+2)`/`this[2]` is size,
`+3` version, `+5` **save**, `+7` **load**. Getting 5 and 7 backwards is the
easy mistake.

## Sweeps run, all clean

| Check | Result |
|---|---|
| src `Init` bodies installing only one of the two callbacks | 0 |
| literal `size_` in src disagreeing with the emission's `mSize` | 0 |
| emissions setting `mVersion` where src `Init` omits `version_` | 0 (of 91) |
| serializer-installing emission whose class name is absent from src | 0 |
| `MemberSerialize`/`MemberDeserialize` pairs with exactly one half recovered | 0 |

## What was fixed getting there

- **One-sided installs** (type could load but not save, or vice versa):
  formation broadcaster `80f3753`, weapon-pointer vector `1c84b4f`,
  threat vector `86965ed`.
- **Wrong reflected size**: `RVectorType_SThreat` declared `0x0C` where the
  emission sets `0x10` - `msvc8::vector` is 0x10 and `0x0C` omits the proxy
  word, so reflected reads ran a pointer short of the object (`86965ed`).
- **Missing version stamps**: five of six broadcaster `Init`s (`4cb9352`,
  `80f3753`).
- **Whole missing subsystem**: `CFormationInstance` save/load - see
  [[project-formation-serializer-decoded]] and
  [[project-cformationinstance-split-blocks-saveload]].
- **Descriptor caches**: see [[project-descriptor-cache-defect-class]].

## Caveat on name matching

Mapping an emission's class to source needs more than `_P` -> `Ptr`. A sweep
that reports "SRC-INIT-NOT-FOUND" in bulk is usually a name-mapping failure, not
missing code - I confirmed 0 genuinely-absent classes by searching for the bare
class name anywhere in `src/sdk` rather than for `Class::Init()`.
