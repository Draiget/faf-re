#include "moho/console/CVarAccess.h"

#include <cstdint>

#include "moho/sim/CSimConVarBase.h"

namespace moho
{
  namespace console
  {
    namespace
    {
      constexpr std::uintptr_t kPathBackgroundUpdateConVarEa = 0x010BA530u;
      constexpr std::uintptr_t kPathBackgroundBudgetConVarEa = 0x010BA404u;
      constexpr std::uintptr_t kChecksumPeriodConVarEa = 0x010BA5E0u;

      constexpr std::uintptr_t kSimDebugCheatsEa = 0x010A63ECu;
      constexpr std::uintptr_t kSimReportCheatsEa = 0x010A63EDu;

      constexpr std::uintptr_t kGetCallStackEa = 0x004A22B0u;
      constexpr std::uintptr_t kFormatCallStackEa = 0x004A26E0u;

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

    CSimConVarBase* SimChecksumPeriodConVar()
    {
      return reinterpret_cast<CSimConVarBase*>(kChecksumPeriodConVarEa);
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

      using GetCallStackFn = unsigned int(__cdecl*)(void*, unsigned int, unsigned int*);
      const auto getCallStack = reinterpret_cast<GetCallStackFn>(kGetCallStackEa);
      if (!getCallStack) {
        return 0;
      }

      return static_cast<int>(getCallStack(nullptr, maxFrames, outFrames));
    }

    void PlatformFormatCallstack(msvc8::string* outText, const int frameCount, const unsigned int* frames)
    {
      if (!outText || !frames) {
        return;
      }

      using FormatCallStackFn = msvc8::string*(__cdecl*)(msvc8::string*, int, int, const unsigned int*);
      const auto formatCallStack = reinterpret_cast<FormatCallStackFn>(kFormatCallStackEa);
      if (!formatCallStack) {
        return;
      }

      formatCallStack(outText, 0, frameCount, frames);
    }

    bool RenderFogOfWarEnabled()
    {
      const auto* const flag = reinterpret_cast<const std::uint8_t*>(kRenderFogOfWarEa);
      return flag && (*flag != 0u);
    }
  } // namespace console
} // namespace moho
