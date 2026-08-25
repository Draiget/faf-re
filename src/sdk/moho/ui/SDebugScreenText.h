#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "Wm3Vector3.h"

namespace moho
{
  /**
   * Address: 0x004516C0 (FUN_004516C0 payload in Moho::CDebugCanvas::Render)
   * Address: 0x0064EC50 (FUN_0064EC50, the compiler-generated copy
   * constructor -- memberwise-copies the three `Wm3::Vec3f` members
   * (9 floats, offsets 0x00-0x24), default-constructs then `assign`s
   * `text` (the standard VC8 SSO construct-then-assign idiom: capacity
   * field set to 15, size set to 0, first inline byte set to 0, then
   * `msvc8::string::assign` copies the real content), and copies
   * `pointSize`/`color`. This struct has no user-declared special
   * member, so this out-of-line body is pure compiler-emitted glue for
   * the implicit copy constructor, not hand-written source (CLAUDE.md's
   * "compiler-emitted glue is not source at all" applies directly).
   * Reached from `msvc8::vector<SDebugScreenText>`'s `_Insert_n`
   * (`FUN_0064E490`), `uninit_fill_n` (`FUN_0064F910`), and
   * `uninit_move_n` (`FUN_00650160`) instantiations, all cited on their
   * respective template members in `legacy/containers/Vector.h` --
   * VC8/2007 predates C++ move semantics, so `uninit_move_n`'s
   * "move" of the live range during grow/insert is this same copy
   * constructor, matching the binary exactly (see that member's own
   * citation for the `T(src[i])`-from-lvalue detail).
   *
   * What it does:
   * Carries one oriented world-space text draw command for debug rendering.
   */
  struct SDebugScreenText
  {
    Wm3::Vec3f origin;        // +0x00
    Wm3::Vec3f xAxis;         // +0x0C
    Wm3::Vec3f yAxis;         // +0x18
    msvc8::string text;       // +0x24
    std::int32_t pointSize;   // +0x40
    std::uint32_t color;      // +0x44
  };

  static_assert(offsetof(SDebugScreenText, origin) == 0x00, "SDebugScreenText::origin offset must be 0x00");
  static_assert(offsetof(SDebugScreenText, xAxis) == 0x0C, "SDebugScreenText::xAxis offset must be 0x0C");
  static_assert(offsetof(SDebugScreenText, yAxis) == 0x18, "SDebugScreenText::yAxis offset must be 0x18");
  static_assert(offsetof(SDebugScreenText, text) == 0x24, "SDebugScreenText::text offset must be 0x24");
  static_assert(
    offsetof(SDebugScreenText, pointSize) == 0x40,
    "SDebugScreenText::pointSize offset must be 0x40"
  );
  static_assert(offsetof(SDebugScreenText, color) == 0x44, "SDebugScreenText::color offset must be 0x44");
  static_assert(sizeof(SDebugScreenText) == 0x48, "SDebugScreenText size must be 0x48");
} // namespace moho
