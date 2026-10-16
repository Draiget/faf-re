#include "moho/console/CVarAccess.h"

#include <cstdint>

#include "moho/app/WinApp.h"

namespace moho
{
  extern bool ren_FogOfWar;

  namespace console
  {
    namespace
    {
      // Two adjacent bytes at 0x010A63EC/0x010A63ED, both .bss so both start
      // false in the shipped image.
      bool gSimDebugCheats = false;
      bool gSimReportCheats = false;
    } // namespace

    // 0x010A63EC and 0x010A63ED are two adjacent single bytes, so they are
    // plain global flags rather than convar objects (a `TSimConVar` is 0x14
    // bytes). Both live in .bss, so the image's initial value for each is
    // false.
    bool SimDebugCheatsEnabled()
    {
      return gSimDebugCheats;
    }

    bool SimReportCheatsEnabled()
    {
      return gSimReportCheats;
    }

    int PlatformGetCallStack(std::uintptr_t* outFrames, unsigned int maxFrames)
    {
      if (!outFrames || maxFrames == 0u) {
        return 0;
      }

      return static_cast<int>(moho::PLAT_GetCallStack(nullptr, maxFrames, outFrames));
    }

    void PlatformFormatCallstack(msvc8::string* outText, const int frameCount, const std::uintptr_t* frames)
    {
      if (!outText || !frames) {
        return;
      }

      if (frameCount <= 0) {
        outText->assign_owned("");
        return;
      }

      const msvc8::string formatted = moho::PLAT_FormatCallstack(0, frameCount, frames);
      outText->assign_owned(formatted.c_str());
    }

    // 0x00F57DC3 is the one `ren_FogOfWar` byte: `CWldSession::DoBeat` writes
    // it every beat, and the renderer, `UserUnit::Tick` (0x008C0B9C) and
    // `UserArmy::CanSeePoint` (0x008B22BA) all read that same byte.
    bool RenderFogOfWarEnabled()
    {
      return moho::ren_FogOfWar;
    }
  } // namespace console
} // namespace moho
