#pragma once

#include "legacy/containers/String.h"

namespace moho
{
  namespace console
  {

    [[nodiscard]] bool SimDebugCheatsEnabled();
    [[nodiscard]] bool SimReportCheatsEnabled();

    [[nodiscard]] int PlatformGetCallStack(std::uintptr_t* outFrames, unsigned int maxFrames);
    void PlatformFormatCallstack(msvc8::string* outText, int frameCount, const std::uintptr_t* frames);

    [[nodiscard]] bool RenderFogOfWarEnabled();
  } // namespace console
} // namespace moho
