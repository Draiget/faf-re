#pragma once

#include "legacy/containers/String.h"

namespace moho
{
  namespace console
  {

    [[nodiscard]] bool SimDebugCheatsEnabled();
    [[nodiscard]] bool SimReportCheatsEnabled();

    [[nodiscard]] int PlatformGetCallStack(unsigned int* outFrames, unsigned int maxFrames);
    void PlatformFormatCallstack(msvc8::string* outText, int frameCount, const unsigned int* frames);

    [[nodiscard]] bool RenderFogOfWarEnabled();
  } // namespace console
} // namespace moho
