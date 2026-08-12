#include "moho/console/CVarAccess.h"

#include <cstdint>

#include "moho/app/WinApp.h"
#include "moho/sim/CSimConVarBase.h"

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

    // These are the engine's sim console variables. Each is a dynamically
    // initialised static in the binary's .bss - `path_BackgroundUpdate` at
    // 0x010BA530, `path_BackgroundBudget` at 0x010BA404, `path_TimeoutPreview`
    // at 0x010BB0AC, `sim_ChecksumPeriod` at 0x010BA5E0 and
    // `ai_SteeringAirTolerance` at 0x010AFE14 (IDA names the last one
    // `SimConVar_ai_SteeringAirTolerance` at its `Sim::GetSimVar` call site in
    // CAiSteeringImpl::FlyToNextWaypoint). The names come from the image's
    // string table; the `DoSimCommand path_BackgroundUpdate` /
    // `DoSimCommand sim_ChecksumPeriod` literals confirm the console spelling.
    //
    // They used to be handed out as raw addresses cast to `CSimConVarBase*`.
    // Those addresses are uninitialised storage in this build, so
    // `Sim::GetSimVar` read a garbage `mIndex` and resized `mSimVars` to it -
    // which threw out of the sim thread and terminated the process on the
    // first beat. Constructing them here as ordinary sim convars gives them
    // real indices from the shared counter.
    //
    // The defaults are the fallbacks the recovered readers already apply when
    // an instance is missing, not values read out of the binary's static
    // initialisers - those initialisers are not in the export set, so the
    // stored defaults remain unconfirmed.
    CSimConVarBase* SimPathBackgroundUpdateConVar()
    {
      static TSimConVar<bool> sVar(false, "path_BackgroundUpdate", false);
      return &sVar;
    }

    CSimConVarBase* SimPathBackgroundBudgetConVar()
    {
      static TSimConVar<int> sVar(false, "path_BackgroundBudget", 0);
      return &sVar;
    }

    CSimConVarBase* SimPathTimeoutPreviewConVar()
    {
      static TSimConVar<int> sVar(false, "path_TimeoutPreview", 0);
      return &sVar;
    }

    CSimConVarBase* SimChecksumPeriodConVar()
    {
      static TSimConVar<int> sVar(false, "sim_ChecksumPeriod", 1);
      return &sVar;
    }

    CSimConVarBase* SimSteeringAirToleranceConVar()
    {
      static TSimConVar<float> sVar(false, "ai_SteeringAirTolerance", 1.0f);
      return &sVar;
    }

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
