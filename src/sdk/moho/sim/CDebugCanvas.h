#pragma once

#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/math/Vector3f.h"
#include "moho/ui/SDebugLine.h"
#include "moho/ui/SDebugWorldText.h"

namespace moho
{
  class CDebugCanvas
  {
  public:
    /**
     * Address: 0x00450030 (FUN_00450030, ?AddWireCircle@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MII@Z)
     *
     * What it does:
     * Appends a polyline circle in world space to the debug line buffer.
     */
    void AddWireCircle(
      const Wm3::Vector3f& normal,
      const Wm3::Vector3f& center,
      float radius,
      std::uint32_t depth,
      std::uint32_t precision
    );

    /**
     * Address: 0x00452070 (FUN_00452070, Moho::CDebugCanvas::DebugDrawLine)
     *
     * What it does:
     * Appends one line segment to the debug line buffer.
     */
    void DebugDrawLine(const SDebugLine& line);

    /**
     * Address: 0x006531D0 (FUN_006531D0, helper used by Moho::RDebugWeapons::OnTick)
     *
     * What it does:
     * Appends one world-space text label to the debug text buffer.
     */
    void AddWorldText(const SDebugWorldText& text);

  public:
    msvc8::vector<SDebugLine> lines;
    msvc8::vector<SDebugWorldText> worldText;
    msvc8::vector<void*> screenText;
    msvc8::vector<void*> decals;
  };

  static_assert(sizeof(CDebugCanvas) == 0x40, "CDebugCanvas size must be 0x40");
} // namespace moho
