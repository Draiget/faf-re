---
name: project_main_exe_not_large_address_aware
description: main.exe is NOT LARGE_ADDRESS_AWARE (PE characteristics 0x102) while retail ForgedAlliance.exe IS (0x123), so we are capped at 2GB of user address space where retail gets 4GB on a 64-bit host. Retail also reserves a 1.9MB stack against our 1MB. Both are one-line project settings.
metadata:
  type: project
---

## The two PE-header gaps

`dumpbin /HEADERS` on the staged pair, same directory:

| | characteristics | stack reserve |
|---|---|---|
| retail `ForgedAlliance.exe` | **`0x123`** | **`0x1E8480`** (2,000,000) |
| our `main.exe` | `0x102` | `0x100000` (1,048,576) |

`0x123` = `RELOCS_STRIPPED(0x01) | EXECUTABLE_IMAGE(0x02) |
IMAGE_FILE_LARGE_ADDRESS_AWARE(0x20) | 32BIT_MACHINE(0x100)`.
`0x102` is missing the `0x20`.

**Consequence:** our 32-bit process is limited to a **2 GB** user address space;
retail gets **4 GB** on a 64-bit host. That matters directly, because the crash
in [[project_commander_crash_is_memory_exhaustion]] is an access violation on a
reserved-but-uncommitted page handed back by `AllocateFreeRegion` after a
`VirtualAlloc(MEM_COMMIT)` failed -- and the faulting address was `0x592B5600`,
i.e. **1.49 GB in**, already close to the 2 GB ceiling. Retail would not have
been anywhere near its limit at the same footprint.

The stack reserve is the second gap: `2000000` is a round decimal, so the
original link was `/STACK:2000000`. Ours is the MSVC default 1 MB. Relevant
given how deep the Lua interpreter recurses (`luaV_execute` frames are large).

## The fix

In `src/sdk/main.vcxproj`, both **Win32** `<Link>` blocks (`Debug|Win32` and
`Release|Win32`; the x64 configurations do not need it):

```xml
<LargeAddressAware>true</LargeAddressAware>
<StackReserveSize>2000000</StackReserveSize>
```

`gAllocationType` was checked while chasing this and is a red herring: it is `0`
in our tree and only ever OR'd into the `VirtualAlloc` flags, so commits are
plain `MEM_COMMIT`. The commit failures are genuine address-space pressure, not
a bad flag word.

## How this was found

By diffing the two executables rather than reading code -- see
[[reference_retail_engine_ab_oracle]]. `dumpbin /HEADERS` on retail beside ours
is a cheap check that had never been run, and it is worth repeating for any
other link-level property (subsystem version, section alignment, TLS, safe SEH).
