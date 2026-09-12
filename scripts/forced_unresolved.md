# Forced-unresolved symbol allowlist

Symbols this recovery does not define yet. `main.vcxproj` links with `/FORCE`,
so each is a warning rather than an error - but the linker still needs an
address for the call site and uses RVA 0, which the loader relocates to the
module base. Calling one jumps to `imagebase + 0`.

`scripts/linkcheck.py` reads this list and fails a build that produces any
unresolved symbol not in it. Remove an entry when it is recovered; never add
one to silence a build.

## Sofdec frame converters

`mwsffrm_CallbackAnalyzeSofdecHeader` is address-taken into the Sofdec
platform callback table at `SofdecAdxPlatformRuntime.cpp:2506`. (The two
ARGB converters that used to sit beside it, `CFT_Ycc420plnToArgb8888Prg`
and `_Int`, are recovered, along with their `cft_c_` / `cft_sse_` leaves.)

## The list

```
_mwsffrm_CallbackAnalyzeSofdecHeader
```
