# FAF SDL 3.4.18 patch

Baseline: the SDL 3.4.18 release archive (`dependencies/SDL3`, pinned by SHA256 in `cmake/FafDependencies.cmake`). `cmake/FafDependencies.cmake` applies the patch at configure time.

## Patch scope

| File | Change | Load-bearing? |
|---|---|---|
| `src/video/windows/SDL_windowsclipboard.c` | `WIN_OpenClipboard` takes the first window in the list that has its Windows data, instead of reading the head window's data unchecked | **Yes** on Windows: without it the game can crash while a window is being created |

## Why

`SDL_CreateWindowWithProperties` links a new window at the head of `_this->windows` (`src/video/SDL_video.c`, before `CreateSDLWindow`) while its `internal` data is still null. When another SDL window gains focus during that time, `WIN_UpdateFocus` calls `WIN_CheckClipboardUpdate` (`src/video/windows/SDL_windowsevents.c`), which opens the clipboard through `_this->windows->internal->hwnd`: a read at address 0x8.

Seen once on 2026-11-23 on Vulkan while a skirmish loaded: `EXCEPTION_ACCESS_VIOLATION`, "attempted to read memory at 0000000000000008", at `WIN_OpenClipboard` inlined into `GetMimeTypes` and `WIN_CheckClipboardUpdate` (llvm-symbolizer on the exe's own PDB). The same test ran clean on the next try, as a race would.

Not reported upstream yet.
