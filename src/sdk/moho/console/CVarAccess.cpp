#include "moho/console/CVarAccess.h"

#include <cstdint>

#include "moho/app/WinApp.h"

namespace moho
{
  namespace console
  {
    namespace
    {
      // Two adjacent bytes at 0x010A63EC/0x010A63ED, both .bss so both start
      // false in the shipped image.
      bool gSimDebugCheats = false;
      bool gSimReportCheats = false;

      // 0x00F57DC3, a .data byte whose stored value is 1.
      bool gRenderFogOfWar = true;
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

    int PlatformGetCallStack(unsigned int* outFrames, unsigned int maxFrames)
    {
      if (!outFrames || maxFrames == 0u) {
        return 0;
      }

      return static_cast<int>(moho::PLAT_GetCallStack(nullptr, maxFrames, outFrames));
    }

    void PlatformFormatCallstack(msvc8::string* outText, const int frameCount, const unsigned int* frames)
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

    bool RenderFogOfWarEnabled()
    {
      return gRenderFogOfWar;
    }
  } // namespace console
} // namespace moho
