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
      constexpr std::uintptr_t kPathBackgroundUpdateConVarEa = 0x010BA530u;
      constexpr std::uintptr_t kPathBackgroundBudgetConVarEa = 0x010BA404u;
      constexpr std::uintptr_t kPathTimeoutPreviewConVarEa = 0x010BB0ACu;
      constexpr std::uintptr_t kChecksumPeriodConVarEa = 0x010BA5E0u;
      constexpr std::uintptr_t kSteeringAirToleranceConVarEa = 0x010AFE14u;

      constexpr std::uintptr_t kSimDebugCheatsEa = 0x010A63ECu;
      constexpr std::uintptr_t kSimReportCheatsEa = 0x010A63EDu;

      constexpr std::uintptr_t kRenderFogOfWarEa = 0x00F57DC3u;
    } // namespace

    CSimConVarBase* SimPathBackgroundUpdateConVar()
    {
      return reinterpret_cast<CSimConVarBase*>(kPathBackgroundUpdateConVarEa);
    }

    CSimConVarBase* SimPathBackgroundBudgetConVar()
    {
      return reinterpret_cast<CSimConVarBase*>(kPathBackgroundBudgetConVarEa);
    }

    CSimConVarBase* SimPathTimeoutPreviewConVar()
    {
      return reinterpret_cast<CSimConVarBase*>(kPathTimeoutPreviewConVarEa);
    }

    CSimConVarBase* SimChecksumPeriodConVar()
    {
      return reinterpret_cast<CSimConVarBase*>(kChecksumPeriodConVarEa);
    }

    CSimConVarBase* SimSteeringAirToleranceConVar()
    {
      return reinterpret_cast<CSimConVarBase*>(kSteeringAirToleranceConVarEa);
    }

    bool SimDebugCheatsEnabled()
    {
      const auto* const flag = reinterpret_cast<const std::uint8_t*>(kSimDebugCheatsEa);
      return flag && (*flag != 0u);
    }

    bool SimReportCheatsEnabled()
    {
      const auto* const flag = reinterpret_cast<const std::uint8_t*>(kSimReportCheatsEa);
      return flag && (*flag != 0u);
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
      const auto* const flag = reinterpret_cast<const std::uint8_t*>(kRenderFogOfWarEa);
      return flag && (*flag != 0u);
    }
  } // namespace console
} // namespace moho
