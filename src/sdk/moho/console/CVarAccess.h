#pragma once

#include "legacy/containers/String.h"

namespace moho
{
  class CSimConVarBase;

  namespace console
  {
    [[nodiscard]] CSimConVarBase* SimPathBackgroundUpdateConVar();
    [[nodiscard]] CSimConVarBase* SimPathBackgroundBudgetConVar();
    [[nodiscard]] CSimConVarBase* SimPathTimeoutPreviewConVar();
    [[nodiscard]] CSimConVarBase* SimChecksumPeriodConVar();
    [[nodiscard]] CSimConVarBase* SimSteeringAirToleranceConVar();

    [[nodiscard]] bool SimDebugCheatsEnabled();
    [[nodiscard]] bool SimReportCheatsEnabled();

    [[nodiscard]] int PlatformGetCallStack(unsigned int* outFrames, unsigned int maxFrames);
    void PlatformFormatCallstack(msvc8::string* outText, int frameCount, const unsigned int* frames);

    [[nodiscard]] bool RenderFogOfWarEnabled();
  } // namespace console
} // namespace moho
