#pragma once

/**
 * `FAF_RETAIL_LAYOUT` decides whether the legacy containers keep the word the
 * 2007 binary reserves at their start.
 *
 * VS2005 builds with `_SECURE_SCL=1`, so every shipped `std::vector`, `list`,
 * `map`, `set` and `deque` opens with a `_Container_proxy*` and every
 * `std::string` with an allocator word. The binary never reads either one.
 *
 * - 1: the containers have the binary's exact sizes, so every layout
 *   `static_assert` and `+0x..` field comment in `src/` holds. CMake preset
 *   `clang-x86-retail-layout` builds this form to check them. Standalone tools
 *   that compile engine sources without CMake (`tools/difffuzz`) get it too.
 * - 0: the game's builds, on every platform. The words are gone, and
 *   `platform/LayoutAsserts.h` switches those asserts off, because their numbers
 *   describe the form above.
 */
#ifndef FAF_RETAIL_LAYOUT
#define FAF_RETAIL_LAYOUT 1
#endif
