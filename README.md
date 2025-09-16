# FAF-RE

Reverse engineering project of Supreme Commander: Forged Alliance.

## Path

1. IDA Disassemble;
2. vtable + RTTI dump & analysis;
3. Engine structure build;
4. ReClass.NET + Custom hooks for more analysis;
5. Complete game/engine SDK;
6. Graphics wrappers;
7. ???
8. No profit, just curiosity and waisting time;

## Projects

### inspect-injector

With a single build + run you should be able to attach to running FA process, enable detours 
and start analysis journey.

### inspect

DLL that will be injected by `inspect-injector` since it can't attach injector itself with
`DllMain` execution.

### main

Wrapper of a FA with original SDK/classes.

### sdk

As much as possible, based on class structure, strings and comments/log messages -
recreation of a game/engine structure that could be used to build up custom FA-wrapper.
Probably will be never finished, but why not start at least.


### What we know about FA binary

- Binary format: PE32 (x86), Subsystem: Windows GUI.
- Compiler/Linker: MSVC v8.0 (Linker 8.00, Visual Studio 2005).
- Base address: 0x400000 (RELOCS STRIPPED, no ASLR).
- RVA: 0x0068EF5E (.text section).
- CRT: no MSVCR* import, probably /MT (static CRT).

Dependencies:
- Boost 1.34.X (it's either 1.34.0 or 1.34.1)
- LuaPlus 5.0 build 1081 (with slight modifications to Lua threads)
- WX Widgets 2.4.2 (MSW version, though using the portable build)
- Wild Magic 3.8 (a physics library now called Geometric Tools)
- zlib 1.2.3 (also included in WX but seems to be included separately as well)
- BugSplat
- CRI Middleware (Sofdec and ADX) - proprietary
- DirectX 9 & 10 (including XACT audio engine) - DX10 is not fully enabled and does not work

### Big thanks to

For disassembling initial binary and hard-work around building game structure:
- Hdt80bro
- 4z0t 

And other folks in FAForever community.

## Defines

- `USE_X87_COMPATIBILITY` - Uses x87 floating-point-related subset of the x86 architecture instruction set.
