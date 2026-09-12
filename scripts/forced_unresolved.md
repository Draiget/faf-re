# Forced-unresolved symbol allowlist

Symbols this recovery does not define yet. `main.vcxproj` links with `/FORCE`,
so each is a warning rather than an error - but the linker still needs an
address for the call site and uses RVA 0, which the loader relocates to the
module base. Calling one jumps to `imagebase + 0`.

`scripts/linkcheck.py` reads this list and fails a build that produces any
unresolved symbol not in it. Remove an entry when it is recovered; never add
one to silence a build.

## Sofdec frame converters

`CFT_Ycc420plnToArgb8888Prg` / `_Int` are the CRI Sofdec ARGB converters,
address-taken at `SofdecSfxRuntime.cpp:2394` and selected during movie playback
when the stream's chroma flags call for them. Their bodies are at `0x00AEEB40`
and `0x00AEE960`, with the `cft_c_` / `cft_sse_` leaf tier underneath.
`mwsffrm_CallbackAnalyzeSofdecHeader` is address-taken into the Sofdec platform
callback table at `SofdecAdxPlatformRuntime.cpp:2506`.

## The list

```
_CFT_Ycc420plnToArgb8888Int
_CFT_Ycc420plnToArgb8888Prg
_mwsffrm_CallbackAnalyzeSofdecHeader
```
