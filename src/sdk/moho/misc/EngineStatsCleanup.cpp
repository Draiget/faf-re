#include "moho/misc/EngineStatsCleanup.h"

#include <cstdint>
#include <cstdlib>
#include <new>

#include "moho/misc/Stats.h"

namespace
{
  template <std::uintptr_t SlotAddress>
  struct EngineStatsSlot;

  template <>
  struct EngineStatsSlot<0x10B185Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B185Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B199Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B199Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B1A78u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B1A78u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B1B2Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B1B2Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B1BF4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B1BF4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B1C2Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B1C2Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B1D44u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B1D44u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B1F4Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B1F4Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B2014u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B2014u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B2258u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B2258u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B2368u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B2368u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B24B4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B24B4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B25A0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B25A0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B26F0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B26F0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B2848u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B2848u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B2B10u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B2B10u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B2CD0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B2CD0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B2DC4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B2DC4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3000u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3000u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B0318u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B0318u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B054Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B054Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B0878u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B0878u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B09B8u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B09B8u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B306Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B306Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B313Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B313Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3268u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3268u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B32D8u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B32D8u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3438u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3438u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3640u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3640u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B375Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B375Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B384Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B384Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3A58u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3A58u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3AF0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3AF0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3BECu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3BECu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3C84u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3C84u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B3D68u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B3D68u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B440Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B440Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B4534u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B4534u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B4D0Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B4D0Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7464u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7464u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7494u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7494u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A74C0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A74C0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A765Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A765Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A766Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A766Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A767Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A767Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A77A4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A77A4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A67B8u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A67B8u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A66C4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A66C4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A9B54u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A9B54u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A9B74u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A9B74u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A9BE8u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A9BE8u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A9BFCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A9BFCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7804u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7804u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B4F74u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B4F74u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7820u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7820u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7830u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7830u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7918u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7918u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7930u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7930u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A79A4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A79A4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7A28u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7A28u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7AD0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7AD0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AF0ACu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AF0ACu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AFE28u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AFE28u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AFADCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AFADCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AFD24u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AFD24u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B51F4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B51F4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B5304u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B5304u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B53BCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B53BCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B53CCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B53CCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B55E0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B55E0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B5680u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B5680u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B5A38u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B5A38u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B5CC0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B5CC0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B5C54u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B5C54u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B5F7Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B5F7Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B61C0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B61C0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B6224u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B6224u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B72BCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B72BCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B764Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B764Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B7C20u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B7C20u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B7E60u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B7E60u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B7E80u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B7E80u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B7E90u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B7E90u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B7EA0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B7EA0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B7F3Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B7F3Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B8618u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B8618u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B8768u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B8768u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B89DCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B89DCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B8844u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B8844u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B8E90u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B8E90u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B88C0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B88C0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10B90B4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10B90B4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AD404u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AD404u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AD414u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AD414u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AD6E4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AD6E4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ACB44u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ACB44u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ACDFCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ACDFCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ACEE8u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ACEE8u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AD100u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AD100u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AD110u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AD110u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AD300u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AD300u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ACA98u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ACA98u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AC654u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AC654u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AC77Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AC77Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AC8A4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AC8A4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AC644u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AC644u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AC454u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AC454u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AC2CCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AC2CCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AC054u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AC054u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ABDECu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ABDECu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ABA84u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ABA84u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ABB4Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ABB4Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ABCF0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ABCF0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10ABD00u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10ABD00u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AB2B4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AB2B4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AAE1Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AAE1Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AACDCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AACDCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AAB5Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AAB5Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AA8BCu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AA8BCu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AA8ACu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AA8ACu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AA7B4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AA7B4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AA62Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AA62Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AA5B8u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AA5B8u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10AA3C0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10AA3C0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7AE0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7AE0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7AF0u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7AF0u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7BB4u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7BB4u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7BE8u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7BE8u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7C00u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7C00u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7C24u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7C24u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7CACu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7CACu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7D34u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7D34u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7D44u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7D44u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7D54u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7D54u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7D5Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7D5Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A7E74u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A7E74u>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A809Cu>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A809Cu>::value = nullptr;

  template <>
  struct EngineStatsSlot<0x10A8710u>
  {
    static moho::EngineStats* value;
  };
  moho::EngineStats* EngineStatsSlot<0x10A8710u>::value = nullptr;

  template <typename T>
  void DestroySingletonSlot(T*& slot) noexcept
  {
    T* const value = slot;
    if (value == nullptr) {
      return;
    }

    value->~T();
    ::operator delete(value);
  }

  template <void (*Cleanup)()>
  [[nodiscard]] int RegisterExitCleanup() noexcept
  {
    return std::atexit(Cleanup);
  }

  template <std::uintptr_t SlotAddress>
  void CleanupEngineStatsSlot() noexcept
  {
    DestroySingletonSlot(EngineStatsSlot<SlotAddress>::value);
  }

  struct EngineStatsCleanupBootstrapEarly
  {
    EngineStatsCleanupBootstrapEarly()
    {
      (void)moho::register_EngineStatsCleanupSlotVariant70();
      (void)moho::register_EngineStatsCleanupSlotVariant71();
      (void)moho::register_EngineStatsCleanupSlotVariant72();
      (void)moho::register_EngineStatsCleanupSlotVariant73();
      (void)moho::register_EngineStatsCleanupSlotVariant74();
      (void)moho::register_EngineStatsCleanupSlotVariant75();
      (void)moho::register_EngineStatsCleanupSlotVariant76();
      (void)moho::register_EngineStatsCleanupSlotVariant77();
      (void)moho::register_EngineStatsCleanupSlotVariant78();
      (void)moho::register_EngineStatsCleanupSlotVariant79();
      (void)moho::register_EngineStatsCleanupSlotVariant80();
      (void)moho::register_EngineStatsCleanupSlotVariant81();
      (void)moho::register_EngineStatsCleanupSlotVariant82();
      (void)moho::register_EngineStatsCleanupSlotVariant83();
      (void)moho::register_EngineStatsCleanupSlotVariant84();
      (void)moho::register_EngineStatsCleanupSlotVariant85();
      (void)moho::register_EngineStatsCleanupSlotVariant86();
      (void)moho::register_EngineStatsCleanupSlotVariant87();
      (void)moho::register_EngineStatsCleanupSlotVariant88();
      (void)moho::register_EngineStatsCleanupSlotVariant89();
      (void)moho::register_EngineStatsCleanupSlotVariant90();
      (void)moho::register_EngineStatsCleanupSlotVariant91();
      (void)moho::register_EngineStatsCleanupSlotVariant92();
      (void)moho::register_EngineStatsCleanupSlotVariant93();
      (void)moho::register_EngineStatsCleanupSlotVariant94();
      (void)moho::register_EngineStatsCleanupSlotVariant95();
      (void)moho::register_EngineStatsCleanupSlotVariant96();
      (void)moho::register_EngineStatsCleanupSlotVariant97();
      (void)moho::register_EngineStatsCleanupSlotVariant98();
      (void)moho::register_EngineStatsCleanupSlotVariant99();
      (void)moho::register_EngineStatsCleanupSlotVariant100();
      (void)moho::register_EngineStatsCleanupSlotVariant101();
      (void)moho::register_EngineStatsCleanupSlotVariant102();
      (void)moho::register_EngineStatsCleanupSlotVariant103();
      (void)moho::register_EngineStatsCleanupSlotVariant104();
      (void)moho::register_EngineStatsCleanupSlotVariant105();
      (void)moho::register_EngineStatsCleanupSlotVariant106();
      (void)moho::register_EngineStatsCleanupSlotVariant107();
      (void)moho::register_EngineStatsCleanupSlotVariant108();
      (void)moho::register_EngineStatsCleanupSlotVariant109();
      (void)moho::register_EngineStatsCleanupSlotVariant110();
      (void)moho::register_EngineStatsCleanupSlotVariant111();
      (void)moho::register_EngineStatsCleanupSlotVariant112();
      (void)moho::register_EngineStatsCleanupSlotVariant113();
      (void)moho::register_EngineStatsCleanupSlotVariant114();
      (void)moho::register_EngineStatsCleanupSlotVariant115();
      (void)moho::register_EngineStatsCleanupSlotVariant116();
      (void)moho::register_EngineStatsCleanupSlotVariant117();
      (void)moho::register_EngineStatsCleanupSlotVariant118();
      (void)moho::register_EngineStatsCleanupSlotVariant119();
      (void)moho::register_EngineStatsCleanupSlotVariant120();
      (void)moho::register_EngineStatsCleanupSlotVariant121();
      (void)moho::register_EngineStatsCleanupSlotVariant122();
      (void)moho::register_EngineStatsCleanupSlotVariant123();
      (void)moho::register_EngineStatsCleanupSlotVariant124();
      (void)moho::register_EngineStatsCleanupSlotVariant125();
      (void)moho::register_EngineStatsCleanupSlotVariant126();
      (void)moho::register_EngineStatsCleanupSlotVariant127();
      (void)moho::register_EngineStatsCleanupSlotVariant128();
      (void)moho::register_EngineStatsCleanupSlotVariant129();
      (void)moho::register_EngineStatsCleanupSlotVariant130();
      (void)moho::register_EngineStatsCleanupSlotVariant131();
      (void)moho::register_EngineStatsCleanupSlotVariant132();
      (void)moho::register_EngineStatsCleanupSlotVariant11();
      (void)moho::register_EngineStatsCleanupSlotVariant12();
      (void)moho::register_EngineStatsCleanupSlotVariant13();
      (void)moho::register_EngineStatsCleanupSlotVariant67();
      (void)moho::register_EngineStatsCleanupSlotVariant14();
      (void)moho::register_EngineStatsCleanupSlotVariant15();
      (void)moho::register_EngineStatsCleanupSlotVariant16();
      (void)moho::register_EngineStatsCleanupSlotVariant17();
      (void)moho::register_EngineStatsCleanupSlotVariant18();
      (void)moho::register_EngineStatsCleanupSlotVariant19();
      (void)moho::register_EngineStatsCleanupSlotVariant20();
      (void)moho::register_EngineStatsCleanupSlotVariant21();
      (void)moho::register_EngineStatsCleanupSlotVariant9();
      (void)moho::register_EngineStatsCleanupSlotVariant10();
      (void)moho::register_EngineStatsCleanupSlotVariant66();
      (void)moho::register_EngineStatsCleanupSlotVariant68();
      (void)moho::register_EngineStatsCleanupSlotVariant69();
      (void)moho::register_EngineStatsCleanupSlotVariant22();
      (void)moho::register_EngineStatsCleanupSlotVariant23();
      (void)moho::register_EngineStatsCleanupSlotVariant24();
      (void)moho::register_EngineStatsCleanupSlotVariant25();
      (void)moho::register_EngineStatsCleanupSlotVariant26();
      (void)moho::register_EngineStatsCleanupSlotVariant27();
      (void)moho::register_EngineStatsCleanupSlotVariant28();
      (void)moho::register_EngineStatsCleanupSlotVariant29();
      (void)moho::register_EngineStatsCleanupSlotVariant30();
    }
  };

  [[maybe_unused]] EngineStatsCleanupBootstrapEarly gEngineStatsCleanupBootstrapEarly;

  struct EngineStatsCleanupBootstrapPreEffects
  {
    EngineStatsCleanupBootstrapPreEffects()
    {
      (void)moho::register_EngineStatsCleanupSlotVariant31();
      (void)moho::register_EngineStatsCleanupSlotVariant32();
      (void)moho::register_EngineStatsCleanupSlotVariant33();
      (void)moho::register_EngineStatsCleanupSlotVariant34();
    }
  };

  [[maybe_unused]] EngineStatsCleanupBootstrapPreEffects gEngineStatsCleanupBootstrapPreEffects;

  struct EngineStatsCleanupLegacyBootstrap
  {
    EngineStatsCleanupLegacyBootstrap()
    {
      (void)moho::register_EngineStatsCleanupSlotVariant1();
      (void)moho::register_EngineStatsCleanupSlotVariant2();
      (void)moho::register_EngineStatsCleanupSlotVariant3();
      (void)moho::register_EngineStatsCleanupSlotVariant4();
      moho::register_EngineStatsCleanupSlotVariant5();
      moho::register_EngineStatsCleanupSlotVariant6();
      moho::register_EngineStatsCleanupSlotVariant7();
      (void)moho::register_EngineStatsCleanupSlotVariant8();
    }
  };

  [[maybe_unused]] EngineStatsCleanupLegacyBootstrap gEngineStatsCleanupLegacyBootstrap;

  struct EngineStatsCleanupBootstrap0
  {
    EngineStatsCleanupBootstrap0()
    {
      (void)moho::register_EngineStatsCleanupSlotVariant35();
      (void)moho::register_EngineStatsCleanupSlotVariant36();
      (void)moho::register_EngineStatsCleanupSlotVariant37();
      (void)moho::register_EngineStatsCleanupSlotVariant38();
      (void)moho::register_EngineStatsCleanupSlotVariant39();
      (void)moho::register_EngineStatsCleanupSlotVariant40();
      (void)moho::register_EngineStatsCleanupSlotVariant41();
      (void)moho::register_EngineStatsCleanupSlotVariant42();
      (void)moho::register_EngineStatsCleanupSlotVariant43();
      (void)moho::register_EngineStatsCleanupSlotVariant44();
      (void)moho::register_EngineStatsCleanupSlotVariant45();
      (void)moho::register_EngineStatsCleanupSlotVariant46();
    }
  };

  [[maybe_unused]] EngineStatsCleanupBootstrap0 gEngineStatsCleanupBootstrap0;

  struct EngineStatsCleanupBootstrapA
  {
    EngineStatsCleanupBootstrapA()
    {
      (void)moho::register_EngineStatsCleanupSlotVariant47();
      (void)moho::register_EngineStatsCleanupSlotVariant48();
      (void)moho::register_EngineStatsCleanupSlotVariant49();
      (void)moho::register_EngineStatsCleanupSlotVariant50();
      (void)moho::register_EngineStatsCleanupSlotVariant51();
      (void)moho::register_EngineStatsCleanupSlotVariant52();
      (void)moho::register_EngineStatsCleanupSlotVariant53();
      (void)moho::register_EngineStatsCleanupSlotVariant54();
      (void)moho::register_EngineStatsCleanupSlotVariant55();
      (void)moho::register_EngineStatsCleanupSlotVariant56();
      (void)moho::register_EngineStatsCleanupSlotVariant57();
      (void)moho::register_EngineStatsCleanupSlotVariant58();
      (void)moho::register_EngineStatsCleanupSlotVariant59();
      (void)moho::register_EngineStatsCleanupSlotVariant60();
    }
  };

  [[maybe_unused]] EngineStatsCleanupBootstrapA gEngineStatsCleanupBootstrapA;

  struct EngineStatsCleanupBootstrap
  {
    EngineStatsCleanupBootstrap()
    {
      (void)moho::register_EngineStatsCleanupSlotVariant63();
      (void)moho::register_EngineStatsCleanupSlotVariant64();
      (void)moho::register_EngineStatsCleanupSlotVariant65();
    }
  };

  [[maybe_unused]] EngineStatsCleanupBootstrap gEngineStatsCleanupBootstrap;

  struct EngineStatsCleanupBootstrapB
  {
    EngineStatsCleanupBootstrapB()
    {
      (void)moho::register_EngineStatsCleanupSlotVariant61();
      (void)moho::register_EngineStatsCleanupSlotVariant62();
    }
  };

  [[maybe_unused]] EngineStatsCleanupBootstrapB gEngineStatsCleanupBootstrapB;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BFA4A0 (FUN_00BFA4A0, cleanup_EngineStatsSlotVariant11)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B1F4C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant11()
  {
    CleanupEngineStatsSlot<0x10B1F4Cu>();
  }

  /**
   * Address: 0x00BFA700 (FUN_00BFA700, cleanup_EngineStatsSlotVariant12)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2014`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant12()
  {
    CleanupEngineStatsSlot<0x10B2014u>();
  }

  /**
   * Address: 0x00BFA8B0 (FUN_00BFA8B0, cleanup_EngineStatsSlotVariant13)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2258`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant13()
  {
    CleanupEngineStatsSlot<0x10B2258u>();
  }

  /**
   * Address: 0x00BD1AA0 (FUN_00BD1AA0, register_EngineStatsCleanupSlotVariant11)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B1F4C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant11()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant11>();
  }

  /**
   * Address: 0x00BD1DD0 (FUN_00BD1DD0, register_EngineStatsCleanupSlotVariant12)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2014`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant12()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant12>();
  }

  /**
   * Address: 0x00BD2180 (FUN_00BD2180, register_EngineStatsCleanupSlotVariant13)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2258`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant13()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant13>();
  }

  /**
   * Address: 0x00BFAA40 (FUN_00BFAA40, cleanup_EngineStatsSlotVariant14)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B24B4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant14()
  {
    CleanupEngineStatsSlot<0x10B24B4u>();
  }

  /**
   * Address: 0x00BD2540 (FUN_00BD2540, register_EngineStatsCleanupSlotVariant14)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B24B4`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant14()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant14>();
  }

  /**
   * Address: 0x00BFAAF0 (FUN_00BFAAF0, cleanup_EngineStatsSlotVariant15)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B25A0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant15()
  {
    CleanupEngineStatsSlot<0x10B25A0u>();
  }

  /**
   * Address: 0x00BD26B0 (FUN_00BD26B0, register_EngineStatsCleanupSlotVariant15)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B25A0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant15()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant15>();
  }

  /**
   * Address: 0x00BFABA0 (FUN_00BFABA0, cleanup_EngineStatsSlotVariant16)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B26F0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant16()
  {
    CleanupEngineStatsSlot<0x10B26F0u>();
  }

  /**
   * Address: 0x00BD2830 (FUN_00BD2830, register_EngineStatsCleanupSlotVariant16)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B26F0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant16()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant16>();
  }

  /**
   * Address: 0x00BFAC50 (FUN_00BFAC50, cleanup_EngineStatsSlotVariant17)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2848`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant17()
  {
    CleanupEngineStatsSlot<0x10B2848u>();
  }

  /**
   * Address: 0x00BD2AF0 (FUN_00BD2AF0, register_EngineStatsCleanupSlotVariant17)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2848`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant17()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant17>();
  }

  /**
   * Address: 0x00BFAF70 (FUN_00BFAF70, cleanup_EngineStatsSlotVariant18)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2B10`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant18()
  {
    CleanupEngineStatsSlot<0x10B2B10u>();
  }

  /**
   * Address: 0x00BD2D40 (FUN_00BD2D40, register_EngineStatsCleanupSlotVariant18)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2B10`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant18()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant18>();
  }

  /**
   * Address: 0x00BFB0E0 (FUN_00BFB0E0, cleanup_EngineStatsSlotVariant19)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2CD0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant19()
  {
    CleanupEngineStatsSlot<0x10B2CD0u>();
  }

  /**
   * Address: 0x00BD2FA0 (FUN_00BD2FA0, register_EngineStatsCleanupSlotVariant19)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2CD0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant19()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant19>();
  }

  /**
   * Address: 0x00BFB190 (FUN_00BFB190, cleanup_EngineStatsSlotVariant20)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2DC4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant20()
  {
    CleanupEngineStatsSlot<0x10B2DC4u>();
  }

  /**
   * Address: 0x00BD3180 (FUN_00BD3180, register_EngineStatsCleanupSlotVariant20)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2DC4`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant20()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant20>();
  }

  /**
   * Address: 0x00BFB240 (FUN_00BFB240, cleanup_EngineStatsSlotVariant21)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3000`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant21()
  {
    CleanupEngineStatsSlot<0x10B3000u>();
  }

  /**
   * Address: 0x00BD32D0 (FUN_00BD32D0, register_EngineStatsCleanupSlotVariant21)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3000`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant21()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant21>();
  }

  /**
   * Address: 0x00BF81C0 (FUN_00BF81C0, cleanup_EngineStatsSlotVariant9)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B0318`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant9()
  {
    CleanupEngineStatsSlot<0x10B0318u>();
  }

  /**
   * Address: 0x00BF8850 (FUN_00BF8850, cleanup_EngineStatsSlotVariant10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B054C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant10()
  {
    CleanupEngineStatsSlot<0x10B054Cu>();
  }

  /**
   * Address: 0x00BCE4E0 (FUN_00BCE4E0, register_EngineStatsCleanupSlotVariant9)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B0318`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant9()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant9>();
  }

  /**
   * Address: 0x00BCEB60 (FUN_00BCEB60, register_EngineStatsCleanupSlotVariant10)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B054C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant10()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant10>();
  }

  /**
   * Address: 0x00BF8940 (FUN_00BF8940, cleanup_EngineStatsSlotVariant66)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B0878`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant66()
  {
    CleanupEngineStatsSlot<0x10B0878u>();
  }

  /**
   * Address: 0x00BCECA0 (FUN_00BCECA0, register_EngineStatsCleanupSlotVariant66)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B0878`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant66()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant66>();
  }

  /**
   * Address: 0x00BF8F70 (FUN_00BF8F70, cleanup_EngineStatsSlotVariant68)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B09B8`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant68()
  {
    CleanupEngineStatsSlot<0x10B09B8u>();
  }

  /**
   * Address: 0x00BCF0C0 (FUN_00BCF0C0, register_EngineStatsCleanupSlotVariant68)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B09B8`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant68()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant68>();
  }

  /**
   * Address: 0x00BF8020 (FUN_00BF8020, cleanup_EngineStatsSlotVariant69)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10AFE28`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant69()
  {
    CleanupEngineStatsSlot<0x10AFE28u>();
  }

  /**
   * Address: 0x00BCE1B0 (FUN_00BCE1B0, register_EngineStatsCleanupSlotVariant69)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10AFE28`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant69()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant69>();
  }

  /**
   * Address: 0x00BFA990 (FUN_00BFA990, cleanup_EngineStatsSlotVariant67)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2368`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant67()
  {
    CleanupEngineStatsSlot<0x10B2368u>();
  }

  /**
   * Address: 0x00BD23F0 (FUN_00BD23F0, register_EngineStatsCleanupSlotVariant67)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2368`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant67()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant67>();
  }

  /**
   * Address: 0x00BFB2F0 (FUN_00BFB2F0, cleanup_EngineStatsSlotVariant22)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B306C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant22()
  {
    CleanupEngineStatsSlot<0x10B306Cu>();
  }

  /**
   * Address: 0x00BD35F0 (FUN_00BD35F0, register_EngineStatsCleanupSlotVariant22)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B306C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant22()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant22>();
  }

  /**
   * Address: 0x00BFB3A0 (FUN_00BFB3A0, cleanup_EngineStatsSlotVariant23)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B313C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant23()
  {
    CleanupEngineStatsSlot<0x10B313Cu>();
  }

  /**
   * Address: 0x00BD3730 (FUN_00BD3730, register_EngineStatsCleanupSlotVariant23)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B313C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant23()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant23>();
  }

  /**
   * Address: 0x00BFB450 (FUN_00BFB450, cleanup_EngineStatsSlotVariant24)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3268`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant24()
  {
    CleanupEngineStatsSlot<0x10B3268u>();
  }

  /**
   * Address: 0x00BD3820 (FUN_00BD3820, register_EngineStatsCleanupSlotVariant24)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3268`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant24()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant24>();
  }

  /**
   * Address: 0x00BFB650 (FUN_00BFB650, cleanup_EngineStatsSlotVariant25)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B32D8`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant25()
  {
    CleanupEngineStatsSlot<0x10B32D8u>();
  }

  /**
   * Address: 0x00BD3AC0 (FUN_00BD3AC0, register_EngineStatsCleanupSlotVariant25)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B32D8`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant25()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant25>();
  }

  /**
   * Address: 0x00BFB680 (FUN_00BFB680, cleanup_EngineStatsSlotVariant26)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3438`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant26()
  {
    CleanupEngineStatsSlot<0x10B3438u>();
  }

  /**
   * Address: 0x00BD3BB0 (FUN_00BD3BB0, register_EngineStatsCleanupSlotVariant26)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3438`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant26()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant26>();
  }

  /**
   * Address: 0x00BFB6C0 (FUN_00BFB6C0, cleanup_EngineStatsSlotVariant27)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3640`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant27()
  {
    CleanupEngineStatsSlot<0x10B3640u>();
  }

  /**
   * Address: 0x00BD3C00 (FUN_00BD3C00, register_EngineStatsCleanupSlotVariant27)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3640`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant27()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant27>();
  }

  /**
   * Address: 0x00BFB710 (FUN_00BFB710, cleanup_EngineStatsSlotVariant28)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B375C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant28()
  {
    CleanupEngineStatsSlot<0x10B375Cu>();
  }

  /**
   * Address: 0x00BD3D30 (FUN_00BD3D30, register_EngineStatsCleanupSlotVariant28)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B375C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant28()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant28>();
  }

  /**
   * Address: 0x00BFB830 (FUN_00BFB830, cleanup_EngineStatsSlotVariant29)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B384C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant29()
  {
    CleanupEngineStatsSlot<0x10B384Cu>();
  }

  /**
   * Address: 0x00BD3DF0 (FUN_00BD3DF0, register_EngineStatsCleanupSlotVariant29)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B384C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant29()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant29>();
  }

  /**
   * Address: 0x00BFB860 (FUN_00BFB860, cleanup_EngineStatsSlotVariant30)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3A58`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant30()
  {
    CleanupEngineStatsSlot<0x10B3A58u>();
  }

  /**
   * Address: 0x00BD3EE0 (FUN_00BD3EE0, register_EngineStatsCleanupSlotVariant30)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3A58`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant30()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant30>();
  }

  /**
   * Address: 0x00BFB9A0 (FUN_00BFB9A0, cleanup_EngineStatsSlotVariant31)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3AF0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant31()
  {
    CleanupEngineStatsSlot<0x10B3AF0u>();
  }

  /**
   * Address: 0x00BD40B0 (FUN_00BD40B0, register_EngineStatsCleanupSlotVariant31)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3AF0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant31()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant31>();
  }

  /**
   * Address: 0x00BFBC90 (FUN_00BFBC90, cleanup_EngineStatsSlotVariant32)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3BEC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant32()
  {
    CleanupEngineStatsSlot<0x10B3BECu>();
  }

  /**
   * Address: 0x00BD41A0 (FUN_00BD41A0, register_EngineStatsCleanupSlotVariant32)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3BEC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant32()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant32>();
  }

  /**
   * Address: 0x00BFBF30 (FUN_00BFBF30, cleanup_EngineStatsSlotVariant33)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3C84`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant33()
  {
    CleanupEngineStatsSlot<0x10B3C84u>();
  }

  /**
   * Address: 0x00BD4450 (FUN_00BD4450, register_EngineStatsCleanupSlotVariant33)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3C84`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant33()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant33>();
  }

  /**
   * Address: 0x00BFBF80 (FUN_00BFBF80, cleanup_EngineStatsSlotVariant34)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3D68`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant34()
  {
    CleanupEngineStatsSlot<0x10B3D68u>();
  }

  /**
   * Address: 0x00BD4500 (FUN_00BD4500, register_EngineStatsCleanupSlotVariant34)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3D68`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant34()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant34>();
  }

  /**
   * Address: 0x00BFC610 (FUN_00BFC610, cleanup_EngineStatsSlotVariant35)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B440C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant35()
  {
    CleanupEngineStatsSlot<0x10B440Cu>();
  }

  /**
   * Address: 0x00BD4E10 (FUN_00BD4E10, register_EngineStatsCleanupSlotVariant35)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B440C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant35()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant35>();
  }

  /**
   * Address: 0x00BFCA50 (FUN_00BFCA50, sub_BFCA50)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B4534`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant36()
  {
    CleanupEngineStatsSlot<0x10B4534u>();
  }

  /**
   * Address: 0x00BD5170 (FUN_00BD5170, sub_BD5170)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B4534`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant36()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant36>();
  }

  /**
   * Address: 0x00BFCC80 (FUN_00BFCC80, sub_BFCC80)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B4D0C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant37()
  {
    CleanupEngineStatsSlot<0x10B4D0Cu>();
  }

  /**
   * Address: 0x00BD5290 (FUN_00BD5290, sub_BD5290)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B4D0C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant37()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant37>();
  }

  /**
   * Address: 0x00BFCCA0 (FUN_00BFCCA0, sub_BFCCA0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B4F74`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant38()
  {
    CleanupEngineStatsSlot<0x10B4F74u>();
  }

  /**
   * Address: 0x00BD5760 (FUN_00BD5760, sub_BD5760)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B4F74`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant38()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant38>();
  }

  /**
   * Address: 0x00BEEE50 (FUN_00BEEE50, sub_BEEE50)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_7`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant1()
  {
    CleanupEngineStatsSlot<0x10A7804u>();
  }

  /**
   * Address: 0x00BC3B30 (FUN_00BC3B30, register_engine_stats_7)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `engine_stats_7`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant1()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant1>();
  }

  /**
   * Address: 0x00BEEEB0 (FUN_00BEEEB0, sub_BEEEB0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_8`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant2()
  {
    CleanupEngineStatsSlot<0x10A7820u>();
  }

  /**
   * Address: 0x00BC3C40 (FUN_00BC3C40, register_engine_stats_8)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `engine_stats_8`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant2()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant2>();
  }

  /**
   * Address: 0x00BEEF10 (FUN_00BEEF10, sub_BEEF10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_9`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant3()
  {
    CleanupEngineStatsSlot<0x10A7830u>();
  }

  /**
   * Address: 0x00BC3C90 (FUN_00BC3C90, register_engine_stats_9)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `engine_stats_9`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant3()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant3>();
  }

  /**
   * Address: 0x00BEF120 (FUN_00BEF120, sub_BEF120)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7918`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant4()
  {
    CleanupEngineStatsSlot<0x10A7918u>();
  }

  /**
   * Address: 0x00BC3FE0 (FUN_00BC3FE0, sub_BC3FE0)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7918`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant4()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant4>();
  }

  /**
   * Address: 0x00BEF170 (FUN_00BEF170, cleanup_EngineStatsSlotVariant5)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7930`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant5()
  {
    CleanupEngineStatsSlot<0x10A7930u>();
  }

  /**
   * Address: 0x00BC4050 (FUN_00BC4050, register_EngineStatsCleanupSlotVariant5)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7930`
   * with `atexit`.
   */
  void register_EngineStatsCleanupSlotVariant5()
  {
    (void)RegisterExitCleanup<&cleanup_EngineStatsSlotVariant5>();
  }

  /**
   * Address: 0x00BEF1D0 (FUN_00BEF1D0, cleanup_EngineStatsSlotVariant6)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A79A4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant6()
  {
    CleanupEngineStatsSlot<0x10A79A4u>();
  }

  /**
   * Address: 0x00BC40E0 (FUN_00BC40E0, register_EngineStatsCleanupSlotVariant6)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A79A4`
   * with `atexit`.
   */
  void register_EngineStatsCleanupSlotVariant6()
  {
    (void)RegisterExitCleanup<&cleanup_EngineStatsSlotVariant6>();
  }

  /**
   * Address: 0x00BEF350 (FUN_00BEF350, cleanup_EngineStatsSlotVariant7)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7A28`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant7()
  {
    CleanupEngineStatsSlot<0x10A7A28u>();
  }

  /**
   * Address: 0x00BC4260 (FUN_00BC4260, register_EngineStatsCleanupSlotVariant7)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7A28`
   * with `atexit`.
   */
  void register_EngineStatsCleanupSlotVariant7()
  {
    (void)RegisterExitCleanup<&cleanup_EngineStatsSlotVariant7>();
  }

  /**
   * Address: 0x00BEF370 (FUN_00BEF370, cleanup_EngineStatsSlotVariant8)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7AD0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant8()
  {
    CleanupEngineStatsSlot<0x10A7AD0u>();
  }

  /**
   * Address: 0x00BC42D0 (FUN_00BC42D0, register_EngineStatsCleanupSlotVariant8)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7AD0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant8()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant8>();
  }

  /**
   * Address: 0x00BFCF90 (FUN_00BFCF90, cleanup_EngineStatsSlotVariant39)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B51F4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant39()
  {
    CleanupEngineStatsSlot<0x10B51F4u>();
  }

  /**
   * Address: 0x00BD59D0 (FUN_00BD59D0, register_EngineStatsCleanupSlotVariant39)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B51F4`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant39()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant39>();
  }

  /**
   * Address: 0x00BFD1F0 (FUN_00BFD1F0, cleanup_EngineStatsSlotVariant40)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B5304`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant40()
  {
    CleanupEngineStatsSlot<0x10B5304u>();
  }

  /**
   * Address: 0x00BD5D40 (FUN_00BD5D40, register_EngineStatsCleanupSlotVariant40)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B5304`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant40()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant40>();
  }

  /**
   * Address: 0x00BFD3C0 (FUN_00BFD3C0, cleanup_EngineStatsSlotVariant41)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B53BC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant41()
  {
    CleanupEngineStatsSlot<0x10B53BCu>();
  }

  /**
   * Address: 0x00BD5F50 (FUN_00BD5F50, register_EngineStatsCleanupSlotVariant41)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B53BC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant41()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant41>();
  }

  /**
   * Address: 0x00BFD3E0 (FUN_00BFD3E0, cleanup_EngineStatsSlotVariant42)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B53CC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant42()
  {
    CleanupEngineStatsSlot<0x10B53CCu>();
  }

  /**
   * Address: 0x00BD5FC0 (FUN_00BD5FC0, register_EngineStatsCleanupSlotVariant42)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B53CC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant42()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant42>();
  }

  /**
   * Address: 0x00BFD4F0 (FUN_00BFD4F0, cleanup_EngineStatsSlotVariant43)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B55E0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant43()
  {
    CleanupEngineStatsSlot<0x10B55E0u>();
  }

  /**
   * Address: 0x00BD6100 (FUN_00BD6100, register_EngineStatsCleanupSlotVariant43)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B55E0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant43()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant43>();
  }

  /**
   * Address: 0x00BFD820 (FUN_00BFD820, cleanup_EngineStatsSlotVariant44)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B5680`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant44()
  {
    CleanupEngineStatsSlot<0x10B5680u>();
  }

  /**
   * Address: 0x00BD6500 (FUN_00BD6500, register_EngineStatsCleanupSlotVariant44)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B5680`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant44()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant44>();
  }

  /**
   * Address: 0x00BFD840 (FUN_00BFD840, cleanup_EngineStatsSlotVariant45)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B5A38`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant45()
  {
    CleanupEngineStatsSlot<0x10B5A38u>();
  }

  /**
   * Address: 0x00BD65D0 (FUN_00BD65D0, register_EngineStatsCleanupSlotVariant45)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B5A38`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant45()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant45>();
  }

  /**
   * Address: 0x00BFD860 (FUN_00BFD860, cleanup_EngineStatsSlotVariant46)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B5C54`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant46()
  {
    CleanupEngineStatsSlot<0x10B5C54u>();
  }

  /**
   * Address: 0x00BD6800 (FUN_00BD6800, register_EngineStatsCleanupSlotVariant46)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B5C54`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant46()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant46>();
  }

  /**
   * Address: 0x00BFDD30 (FUN_00BFDD30, cleanup_EngineStatsSlotVariant47)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B5CC0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant47()
  {
    CleanupEngineStatsSlot<0x10B5CC0u>();
  }

  /**
   * Address: 0x00BD6C80 (FUN_00BD6C80, register_EngineStatsCleanupSlotVariant47)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B5CC0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant47()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant47>();
  }

  /**
   * Address: 0x00BFDE10 (FUN_00BFDE10, cleanup_EngineStatsSlotVariant48)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B5F7C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant48()
  {
    CleanupEngineStatsSlot<0x10B5F7Cu>();
  }

  /**
   * Address: 0x00BD6D70 (FUN_00BD6D70, register_EngineStatsCleanupSlotVariant48)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B5F7C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant48()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant48>();
  }

  /**
   * Address: 0x00BFE0D0 (FUN_00BFE0D0, cleanup_EngineStatsSlotVariant49)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B61C0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant49()
  {
    CleanupEngineStatsSlot<0x10B61C0u>();
  }

  /**
   * Address: 0x00BD72C0 (FUN_00BD72C0, register_EngineStatsCleanupSlotVariant49)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B61C0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant49()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant49>();
  }

  /**
   * Address: 0x00BFE150 (FUN_00BFE150, sub_BFE150)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B6224`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant50()
  {
    CleanupEngineStatsSlot<0x10B6224u>();
  }

  /**
   * Address: 0x00BD7530 (FUN_00BD7530, sub_BD7530)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B6224`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant50()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant50>();
  }

  /**
   * Address: 0x00BFE170 (FUN_00BFE170, sub_BFE170)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B72BC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant51()
  {
    CleanupEngineStatsSlot<0x10B72BCu>();
  }

  /**
   * Address: 0x00BD7780 (FUN_00BD7780, sub_BD7780)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B72BC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant51()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant51>();
  }

  /**
   * Address: 0x00BFE3D0 (FUN_00BFE3D0, sub_BFE3D0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B764C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant52()
  {
    CleanupEngineStatsSlot<0x10B764Cu>();
  }

  /**
   * Address: 0x00BFE510 (FUN_00BFE510, sub_BFE510)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7C20`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant53()
  {
    CleanupEngineStatsSlot<0x10B7C20u>();
  }

  /**
   * Address: 0x00BD8450 (FUN_00BD8450, sub_BD8450)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B764C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant52()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant52>();
  }

  /**
   * Address: 0x00BD8520 (FUN_00BD8520, sub_BD8520)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7C20`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant53()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant53>();
  }

  /**
   * Address: 0x00BFE920 (FUN_00BFE920, sub_BFE920)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7E60`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant54()
  {
    CleanupEngineStatsSlot<0x10B7E60u>();
  }

  /**
   * Address: 0x00BFEAC0 (FUN_00BFEAC0, sub_BFEAC0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7E80`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant55()
  {
    CleanupEngineStatsSlot<0x10B7E80u>();
  }

  /**
   * Address: 0x00BFEAE0 (FUN_00BFEAE0, sub_BFEAE0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7E90`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant56()
  {
    CleanupEngineStatsSlot<0x10B7E90u>();
  }

  /**
   * Address: 0x00BFEB00 (FUN_00BFEB00, sub_BFEB00)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7EA0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant57()
  {
    CleanupEngineStatsSlot<0x10B7EA0u>();
  }

  /**
   * Address: 0x00BFEB20 (FUN_00BFEB20, sub_BFEB20)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7F3C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant58()
  {
    CleanupEngineStatsSlot<0x10B7F3Cu>();
  }

  /**
   * Address: 0x00BFEE80 (FUN_00BFEE80, sub_BFEE80)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B8618`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant59()
  {
    CleanupEngineStatsSlot<0x10B8618u>();
  }

  /**
   * Address: 0x00BFF0C0 (FUN_00BFF0C0, sub_BFF0C0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B8768`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant60()
  {
    CleanupEngineStatsSlot<0x10B8768u>();
  }

  /**
   * Address: 0x00BD8C30 (FUN_00BD8C30, sub_BD8C30)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7E60`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant54()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant54>();
  }

  /**
   * Address: 0x00BD8D70 (FUN_00BD8D70, sub_BD8D70)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7E80`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant55()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant55>();
  }

  /**
   * Address: 0x00BD8DE0 (FUN_00BD8DE0, sub_BD8DE0)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7E90`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant56()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant56>();
  }

  /**
   * Address: 0x00BD8E50 (FUN_00BD8E50, sub_BD8E50)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7EA0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant57()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant57>();
  }

  /**
   * Address: 0x00BD8E60 (FUN_00BD8E60, sub_BD8E60)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7F3C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant58()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant58>();
  }

  /**
   * Address: 0x00BD9070 (FUN_00BD9070, sub_BD9070)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B8618`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant59()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant59>();
  }

  /**
   * Address: 0x00BD9610 (FUN_00BD9610, sub_BD9610)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B8768`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant60()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant60>();
  }

  /**
   * Address: 0x00BFF2A0 (FUN_00BFF2A0, sub_BFF2A0)
   *
   * What it does:
   * Tears down the first recovered `EngineStats` singleton slot at process exit.
   */
  void cleanup_EngineStatsSlotVariant63()
  {
    CleanupEngineStatsSlot<0x10B89DCu>();
  }

  /**
   * Address: 0x00BFF260 (FUN_00BFF260, sub_BFF260)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B8844`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant61()
  {
    CleanupEngineStatsSlot<0x10B8844u>();
  }

  /**
   * Address: 0x00BFF4D0 (FUN_00BFF4D0, sub_BFF4D0)
   *
   * What it does:
   * Tears down the second recovered `EngineStats` singleton slot at process exit.
   */
  void cleanup_EngineStatsSlotVariant64()
  {
    CleanupEngineStatsSlot<0x10B8E90u>();
  }

  /**
   * Address: 0x00BFF280 (FUN_00BFF280, sub_BFF280)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B88C0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant62()
  {
    CleanupEngineStatsSlot<0x10B88C0u>();
  }

  /**
   * Address: 0x00BFF550 (FUN_00BFF550, sub_BFF550)
   *
   * What it does:
   * Tears down the third recovered `EngineStats` singleton slot at process exit.
   */
  void cleanup_EngineStatsSlotVariant65()
  {
    CleanupEngineStatsSlot<0x10B90B4u>();
  }

  /**
   * Address: 0x00BD9AB0 (FUN_00BD9AB0, sub_BD9AB0)
   *
   * What it does:
   * Registers the first `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant63()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant63>();
  }

  /**
   * Address: 0x00BD9950 (FUN_00BD9950, sub_BD9950)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B8844`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant61()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant61>();
  }

  /**
   * Address: 0x00BD9C80 (FUN_00BD9C80, sub_BD9C80)
   *
   * What it does:
   * Registers the second `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant64()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant64>();
  }

  /**
   * Address: 0x00BD99C0 (FUN_00BD99C0, sub_BD99C0)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B88C0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant62()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant62>();
  }

  /**
   * Address: 0x00BD9FD0 (FUN_00BD9FD0, sub_BD9FD0)
   *
   * What it does:
   * Registers the third `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant65()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant65>();
  }

  /**
   * Address: 0x00BF9F10 (FUN_00BF9F10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B185C`.
   */
  void cleanup_EngineStatsSlotVariant70()
  {
    CleanupEngineStatsSlot<0x10B185Cu>();
  }

  /**
   * Address: 0x00BF9FC0 (FUN_00BF9FC0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B199C`.
   */
  void cleanup_EngineStatsSlotVariant71()
  {
    CleanupEngineStatsSlot<0x10B199Cu>();
  }

  /**
   * Address: 0x00BFA100 (FUN_00BFA100)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1A78`.
   */
  void cleanup_EngineStatsSlotVariant72()
  {
    CleanupEngineStatsSlot<0x10B1A78u>();
  }

  /**
   * Address: 0x00BFA1E0 (FUN_00BFA1E0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1B2C`.
   */
  void cleanup_EngineStatsSlotVariant73()
  {
    CleanupEngineStatsSlot<0x10B1B2Cu>();
  }

  /**
   * Address: 0x00BFA290 (FUN_00BFA290)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1BF4`.
   */
  void cleanup_EngineStatsSlotVariant74()
  {
    CleanupEngineStatsSlot<0x10B1BF4u>();
  }

  /**
   * Address: 0x00BFA340 (FUN_00BFA340)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1C2C`.
   */
  void cleanup_EngineStatsSlotVariant75()
  {
    CleanupEngineStatsSlot<0x10B1C2Cu>();
  }

  /**
   * Address: 0x00BFA3F0 (FUN_00BFA3F0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1D44`.
   */
  void cleanup_EngineStatsSlotVariant76()
  {
    CleanupEngineStatsSlot<0x10B1D44u>();
  }

  /**
   * Address: 0x00BF7790 (FUN_00BF7790, sub_BF7790)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AFADC`.
   */
  void cleanup_EngineStatsSlotVariant77()
  {
    CleanupEngineStatsSlot<0x10AFADCu>();
  }

  /**
   * Address: 0x00BF7D80 (FUN_00BF7D80, sub_BF7D80)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AFD24`.
   */
  void cleanup_EngineStatsSlotVariant78()
  {
    CleanupEngineStatsSlot<0x10AFD24u>();
  }

  /**
   * Address: 0x00BF73F0 (FUN_00BF73F0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AF0AC`.
   */
  void cleanup_EngineStatsSlotVariant79()
  {
    CleanupEngineStatsSlot<0x10AF0ACu>();
  }

  /**
   * Address: 0x00BD0C50 (FUN_00BD0C50)
   *
   * What it does:
   * Registers the `dword_10B185C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant70()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant70>();
  }

  /**
   * Address: 0x00BD0EA0 (FUN_00BD0EA0)
   *
   * What it does:
   * Registers the `dword_10B199C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant71()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant71>();
  }

  /**
   * Address: 0x00BD1150 (FUN_00BD1150)
   *
   * What it does:
   * Registers the `dword_10B1A78` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant72()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant72>();
  }

  /**
   * Address: 0x00BD1380 (FUN_00BD1380)
   *
   * What it does:
   * Registers the `dword_10B1B2C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant73()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant73>();
  }

  /**
   * Address: 0x00BD1630 (FUN_00BD1630)
   *
   * What it does:
   * Registers the `dword_10B1BF4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant74()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant74>();
  }

  /**
   * Address: 0x00BD1880 (FUN_00BD1880)
   *
   * What it does:
   * Registers the `dword_10B1C2C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant75()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant75>();
  }

  /**
   * Address: 0x00BD1950 (FUN_00BD1950)
   *
   * What it does:
   * Registers the `dword_10B1D44` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant76()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant76>();
  }

  /**
   * Address: 0x00BCD980 (FUN_00BCD980, sub_BCD980)
   *
   * What it does:
   * Registers the `dword_10AFADC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant77()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant77>();
  }

  /**
   * Address: 0x00BCDFA0 (FUN_00BCDFA0, sub_BCDFA0)
   *
   * What it does:
   * Registers the `dword_10AFD24` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant78()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant78>();
  }

  /**
   * Address: 0x00BCD080 (FUN_00BCD080)
   *
   * What it does:
   * Registers the `dword_10AF0AC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant79()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant79>();
  }

  /**
   * Address: 0x00BF5EC0 (FUN_00BF5EC0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD404`.
   */
  void cleanup_EngineStatsSlotVariant80()
  {
    CleanupEngineStatsSlot<0x10AD404u>();
  }

  /**
   * Address: 0x00BF5EE0 (FUN_00BF5EE0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD414`.
   */
  void cleanup_EngineStatsSlotVariant81()
  {
    CleanupEngineStatsSlot<0x10AD414u>();
  }

  /**
   * Address: 0x00BF5F60 (FUN_00BF5F60)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD6E4`.
   */
  void cleanup_EngineStatsSlotVariant82()
  {
    CleanupEngineStatsSlot<0x10AD6E4u>();
  }

  /**
   * Address: 0x00BCAD60 (FUN_00BCAD60)
   *
   * What it does:
   * Registers the `dword_10AD404` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant80()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant80>();
  }

  /**
   * Address: 0x00BCADD0 (FUN_00BCADD0)
   *
   * What it does:
   * Registers the `dword_10AD414` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant81()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant81>();
  }

  /**
   * Address: 0x00BCAE60 (FUN_00BCAE60)
   *
   * What it does:
   * Registers the `dword_10AD6E4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant82()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant82>();
  }

  /**
   * Address: 0x00BF51A0 (FUN_00BF51A0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACB44`.
   */
  void cleanup_EngineStatsSlotVariant83()
  {
    CleanupEngineStatsSlot<0x10ACB44u>();
  }

  /**
   * Address: 0x00BF51C0 (FUN_00BF51C0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACDFC`.
   */
  void cleanup_EngineStatsSlotVariant84()
  {
    CleanupEngineStatsSlot<0x10ACDFCu>();
  }

  /**
   * Address: 0x00BF5600 (FUN_00BF5600)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACEE8`.
   */
  void cleanup_EngineStatsSlotVariant85()
  {
    CleanupEngineStatsSlot<0x10ACEE8u>();
  }

  /**
   * Address: 0x00BF5790 (FUN_00BF5790)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD100`.
   */
  void cleanup_EngineStatsSlotVariant86()
  {
    CleanupEngineStatsSlot<0x10AD100u>();
  }

  /**
   * Address: 0x00BF57B0 (FUN_00BF57B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD110`.
   */
  void cleanup_EngineStatsSlotVariant87()
  {
    CleanupEngineStatsSlot<0x10AD110u>();
  }

  /**
   * Address: 0x00BF57D0 (FUN_00BF57D0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD300`.
   */
  void cleanup_EngineStatsSlotVariant88()
  {
    CleanupEngineStatsSlot<0x10AD300u>();
  }

  /**
   * Address: 0x00BCA3B0 (FUN_00BCA3B0)
   *
   * What it does:
   * Registers the `dword_10ACB44` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant83()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant83>();
  }

  /**
   * Address: 0x00BCA430 (FUN_00BCA430)
   *
   * What it does:
   * Registers the `dword_10ACDFC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant84()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant84>();
  }

  /**
   * Address: 0x00BCA780 (FUN_00BCA780)
   *
   * What it does:
   * Registers the `dword_10ACEE8` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant85()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant85>();
  }

  /**
   * Address: 0x00BCA990 (FUN_00BCA990)
   *
   * What it does:
   * Registers the `dword_10AD100` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant86()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant86>();
  }

  /**
   * Address: 0x00BCA9A0 (FUN_00BCA9A0)
   *
   * What it does:
   * Registers the `dword_10AD110` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant87()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant87>();
  }

  /**
   * Address: 0x00BCAA10 (FUN_00BCAA10)
   *
   * What it does:
   * Registers the `dword_10AD300` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant88()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant88>();
  }

  /**
   * Address: 0x00BF50B0 (FUN_00BF50B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACA98`.
   */
  void cleanup_EngineStatsSlotVariant89()
  {
    CleanupEngineStatsSlot<0x10ACA98u>();
  }

  /**
   * Address: 0x00BCA280 (FUN_00BCA280)
   *
   * What it does:
   * Registers the `dword_10ACA98` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant89()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant89>();
  }

  /**
   * Address: 0x00BF4BD0 (FUN_00BF4BD0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC654`.
   */
  void cleanup_EngineStatsSlotVariant90()
  {
    CleanupEngineStatsSlot<0x10AC654u>();
  }

  /**
   * Address: 0x00BC9DE0 (FUN_00BC9DE0)
   *
   * What it does:
   * Registers the `dword_10AC654` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant90()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant90>();
  }

  /**
   * Address: 0x00BF4BF0 (FUN_00BF4BF0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC77C`.
   */
  void cleanup_EngineStatsSlotVariant91()
  {
    CleanupEngineStatsSlot<0x10AC77Cu>();
  }

  /**
   * Address: 0x00BC9DF0 (FUN_00BC9DF0)
   *
   * What it does:
   * Registers the `dword_10AC77C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant91()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant91>();
  }

  /**
   * Address: 0x00BF4D30 (FUN_00BF4D30)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC8A4`.
   */
  void cleanup_EngineStatsSlotVariant92()
  {
    CleanupEngineStatsSlot<0x10AC8A4u>();
  }

  /**
   * Address: 0x00BC9F50 (FUN_00BC9F50)
   *
   * What it does:
   * Registers the `dword_10AC8A4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant92()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant92>();
  }

  /**
   * Address: 0x00BF4930 (FUN_00BF4930)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC644`.
   */
  void cleanup_EngineStatsSlotVariant93()
  {
    CleanupEngineStatsSlot<0x10AC644u>();
  }

  /**
   * Address: 0x00BC9C10 (FUN_00BC9C10)
   *
   * What it does:
   * Registers the `dword_10AC644` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant93()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant93>();
  }

  /**
   * Address: 0x00BF4760 (FUN_00BF4760)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC454`.
   */
  void cleanup_EngineStatsSlotVariant94()
  {
    CleanupEngineStatsSlot<0x10AC454u>();
  }

  /**
   * Address: 0x00BC9A20 (FUN_00BC9A20)
   *
   * What it does:
   * Registers the `dword_10AC454` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant94()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant94>();
  }

  /**
   * Address: 0x00BF4460 (FUN_00BF4460)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC2CC`.
   */
  void cleanup_EngineStatsSlotVariant95()
  {
    CleanupEngineStatsSlot<0x10AC2CCu>();
  }

  /**
   * Address: 0x00BC9880 (FUN_00BC9880)
   *
   * What it does:
   * Registers the `dword_10AC2CC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant95()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant95>();
  }

  /**
   * Address: 0x00BF4170 (FUN_00BF4170)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC054`.
   */
  void cleanup_EngineStatsSlotVariant96()
  {
    CleanupEngineStatsSlot<0x10AC054u>();
  }

  /**
   * Address: 0x00BC9580 (FUN_00BC9580)
   *
   * What it does:
   * Registers the `dword_10AC054` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant96()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant96>();
  }

  /**
   * Address: 0x00BF3F10 (FUN_00BF3F10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABDEC`.
   */
  void cleanup_EngineStatsSlotVariant97()
  {
    CleanupEngineStatsSlot<0x10ABDECu>();
  }

  /**
   * Address: 0x00BC9430 (FUN_00BC9430)
   *
   * What it does:
   * Registers the `dword_10ABDEC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant97()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant97>();
  }

  /**
   * Address: 0x00BF3930 (FUN_00BF3930)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABA84`.
   */
  void cleanup_EngineStatsSlotVariant98()
  {
    CleanupEngineStatsSlot<0x10ABA84u>();
  }

  /**
   * Address: 0x00BC8D50 (FUN_00BC8D50)
   *
   * What it does:
   * Registers the `dword_10ABA84` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant98()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant98>();
  }

  /**
   * Address: 0x00BF3B00 (FUN_00BF3B00)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABB4C`.
   */
  void cleanup_EngineStatsSlotVariant99()
  {
    CleanupEngineStatsSlot<0x10ABB4Cu>();
  }

  /**
   * Address: 0x00BC9050 (FUN_00BC9050)
   *
   * What it does:
   * Registers the `dword_10ABB4C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant99()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant99>();
  }

  /**
   * Address: 0x00BF3DE0 (FUN_00BF3DE0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABCF0`.
   */
  void cleanup_EngineStatsSlotVariant100()
  {
    CleanupEngineStatsSlot<0x10ABCF0u>();
  }

  /**
   * Address: 0x00BC9310 (FUN_00BC9310)
   *
   * What it does:
   * Registers the `dword_10ABCF0` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant100()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant100>();
  }

  /**
   * Address: 0x00BF3E00 (FUN_00BF3E00)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABD00`.
   */
  void cleanup_EngineStatsSlotVariant101()
  {
    CleanupEngineStatsSlot<0x10ABD00u>();
  }

  /**
   * Address: 0x00BC9380 (FUN_00BC9380)
   *
   * What it does:
   * Registers the `dword_10ABD00` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant101()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant101>();
  }

  /**
   * Address: 0x00BF31B0 (FUN_00BF31B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AB2B4`.
   */
  void cleanup_EngineStatsSlotVariant102()
  {
    CleanupEngineStatsSlot<0x10AB2B4u>();
  }

  /**
   * Address: 0x00BC88A0 (FUN_00BC88A0)
   *
   * What it does:
   * Registers the `dword_10AB2B4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant102()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant102>();
  }

  /**
   * Address: 0x00BF2FB0 (FUN_00BF2FB0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AAE1C`.
   */
  void cleanup_EngineStatsSlotVariant103()
  {
    CleanupEngineStatsSlot<0x10AAE1Cu>();
  }

  /**
   * Address: 0x00BC8740 (FUN_00BC8740)
   *
   * What it does:
   * Registers the `dword_10AAE1C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant103()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant103>();
  }

  /**
   * Address: 0x00BF2DB0 (FUN_00BF2DB0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AACDC`.
   */
  void cleanup_EngineStatsSlotVariant104()
  {
    CleanupEngineStatsSlot<0x10AACDCu>();
  }

  /**
   * Address: 0x00BC85E0 (FUN_00BC85E0)
   *
   * What it does:
   * Registers the `dword_10AACDC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant104()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant104>();
  }

  /**
   * Address: 0x00BF2BE0 (FUN_00BF2BE0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AAB5C`.
   */
  void cleanup_EngineStatsSlotVariant105()
  {
    CleanupEngineStatsSlot<0x10AAB5Cu>();
  }

  /**
   * Address: 0x00BC8500 (FUN_00BC8500)
   *
   * What it does:
   * Registers the `dword_10AAB5C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant105()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant105>();
  }

  /**
   * Address: 0x00BF27F0 (FUN_00BF27F0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA8BC`.
   */
  void cleanup_EngineStatsSlotVariant106()
  {
    CleanupEngineStatsSlot<0x10AA8BCu>();
  }

  /**
   * Address: 0x00BC82D0 (FUN_00BC82D0)
   *
   * What it does:
   * Registers the `dword_10AA8BC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant106()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant106>();
  }

  /**
   * Address: 0x00BF26E0 (FUN_00BF26E0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA8AC`.
   */
  void cleanup_EngineStatsSlotVariant107()
  {
    CleanupEngineStatsSlot<0x10AA8ACu>();
  }

  /**
   * Address: 0x00BC8220 (FUN_00BC8220)
   *
   * What it does:
   * Registers the `dword_10AA8AC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant107()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant107>();
  }

  /**
   * Address: 0x00BF2420 (FUN_00BF2420)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA7B4`.
   */
  void cleanup_EngineStatsSlotVariant108()
  {
    CleanupEngineStatsSlot<0x10AA7B4u>();
  }

  /**
   * Address: 0x00BC8040 (FUN_00BC8040)
   *
   * What it does:
   * Registers the `dword_10AA7B4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant108()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant108>();
  }

  /**
   * Address: 0x00BF23A0 (FUN_00BF23A0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA62C`.
   */
  void cleanup_EngineStatsSlotVariant109()
  {
    CleanupEngineStatsSlot<0x10AA62Cu>();
  }

  /**
   * Address: 0x00BC7F50 (FUN_00BC7F50)
   *
   * What it does:
   * Registers the `dword_10AA62C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant109()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant109>();
  }

  /**
   * Address: 0x00BF2380 (FUN_00BF2380)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA5B8`.
   */
  void cleanup_EngineStatsSlotVariant110()
  {
    CleanupEngineStatsSlot<0x10AA5B8u>();
  }

  /**
   * Address: 0x00BC7EA0 (FUN_00BC7EA0)
   *
   * What it does:
   * Registers the `dword_10AA5B8` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant110()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant110>();
  }

  /**
   * Address: 0x00BF2050 (FUN_00BF2050)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA3C0`.
   */
  void cleanup_EngineStatsSlotVariant111()
  {
    CleanupEngineStatsSlot<0x10AA3C0u>();
  }

  /**
   * Address: 0x00BC7BF0 (FUN_00BC7BF0)
   *
   * What it does:
   * Registers the `dword_10AA3C0` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant111()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant111>();
  }

  /**
   * Address: 0x00BEF600 (FUN_00BEF600)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7C00`.
   */
  void cleanup_EngineStatsSlotVariant112()
  {
    CleanupEngineStatsSlot<0x10A7C00u>();
  }

  /**
   * Address: 0x00BC46A0 (FUN_00BC46A0)
   *
   * What it does:
   * Registers the `dword_10A7C00` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant112()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant112>();
  }

  /**
   * Address: 0x00BEF620 (FUN_00BEF620)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7C24`.
   */
  void cleanup_EngineStatsSlotVariant113()
  {
    CleanupEngineStatsSlot<0x10A7C24u>();
  }

  /**
   * Address: 0x00BC4770 (FUN_00BC4770)
   *
   * What it does:
   * Registers the `dword_10A7C24` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant113()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant113>();
  }

  /**
   * Address: 0x00BEF700 (FUN_00BEF700)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7CAC`.
   */
  void cleanup_EngineStatsSlotVariant114()
  {
    CleanupEngineStatsSlot<0x10A7CACu>();
  }

  /**
   * Address: 0x00BC48E0 (FUN_00BC48E0)
   *
   * What it does:
   * Registers the `dword_10A7CAC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant114()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant114>();
  }

  /**
   * Address: 0x00BEF7B0 (FUN_00BEF7B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7D34`.
   */
  void cleanup_EngineStatsSlotVariant115()
  {
    CleanupEngineStatsSlot<0x10A7D34u>();
  }

  /**
   * Address: 0x00BC49B0 (FUN_00BC49B0)
   *
   * What it does:
   * Registers the `dword_10A7D34` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant115()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant115>();
  }

  /**
   * Address: 0x00BEF860 (FUN_00BEF860)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7D44`.
   */
  void cleanup_EngineStatsSlotVariant116()
  {
    CleanupEngineStatsSlot<0x10A7D44u>();
  }

  /**
   * Address: 0x00BC4A80 (FUN_00BC4A80)
   *
   * What it does:
   * Registers the `dword_10A7D44` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant116()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant116>();
  }

  /**
   * Address: 0x00BEF880 (FUN_00BEF880)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7D54`.
   */
  void cleanup_EngineStatsSlotVariant117()
  {
    CleanupEngineStatsSlot<0x10A7D54u>();
  }

  /**
   * Address: 0x00BC4B50 (FUN_00BC4B50)
   *
   * What it does:
   * Registers the `dword_10A7D54` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant117()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant117>();
  }

  /**
   * Address: 0x00BEF8A0 (FUN_00BEF8A0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7D5C`.
   */
  void cleanup_EngineStatsSlotVariant118()
  {
    CleanupEngineStatsSlot<0x10A7D5Cu>();
  }

  /**
   * Address: 0x00BC4B60 (FUN_00BC4B60)
   *
   * What it does:
   * Registers the `dword_10A7D5C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant118()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant118>();
  }

  /**
   * Address: 0x00BEFD30 (FUN_00BEFD30)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7E74`.
   */
  void cleanup_EngineStatsSlotVariant119()
  {
    CleanupEngineStatsSlot<0x10A7E74u>();
  }

  /**
   * Address: 0x00BC5170 (FUN_00BC5170)
   *
   * What it does:
   * Registers the `dword_10A7E74` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant119()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant119>();
  }

  /**
   * Address: 0x00BEFD50 (FUN_00BEFD50)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A809C`.
   */
  void cleanup_EngineStatsSlotVariant120()
  {
    CleanupEngineStatsSlot<0x10A809Cu>();
  }

  /**
   * Address: 0x00BC5240 (FUN_00BC5240)
   *
   * What it does:
   * Registers the `dword_10A809C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant120()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant120>();
  }

  /**
   * Address: 0x00BF0010 (FUN_00BF0010)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A8710`.
   */
  void cleanup_EngineStatsSlotVariant121()
  {
    CleanupEngineStatsSlot<0x10A8710u>();
  }

  /**
   * Address: 0x00BC5520 (FUN_00BC5520)
   *
   * What it does:
   * Registers the `dword_10A8710` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant121()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant121>();
  }

  /**
   * Address: 0x00BEF520 (FUN_00BEF520)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7AE0`.
   */
  void cleanup_EngineStatsSlotVariant122()
  {
    CleanupEngineStatsSlot<0x10A7AE0u>();
  }

  /**
   * Address: 0x00BC44D0 (FUN_00BC44D0)
   *
   * What it does:
   * Registers the `dword_10A7AE0` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant122()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant122>();
  }

  /**
   * Address: 0x00BEF540 (FUN_00BEF540)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7AF0`.
   */
  void cleanup_EngineStatsSlotVariant123()
  {
    CleanupEngineStatsSlot<0x10A7AF0u>();
  }

  /**
   * Address: 0x00BC44E0 (FUN_00BC44E0)
   *
   * What it does:
   * Registers the `dword_10A7AF0` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant123()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant123>();
  }

  /**
   * Address: 0x00BEF560 (FUN_00BEF560)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7BB4`.
   */
  void cleanup_EngineStatsSlotVariant124()
  {
    CleanupEngineStatsSlot<0x10A7BB4u>();
  }

  /**
   * Address: 0x00BC45B0 (FUN_00BC45B0)
   *
   * What it does:
   * Registers the `dword_10A7BB4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant124()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant124>();
  }

  /**
   * Address: 0x00BEF580 (FUN_00BEF580)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7BE8`.
   */
  void cleanup_EngineStatsSlotVariant125()
  {
    CleanupEngineStatsSlot<0x10A7BE8u>();
  }

  /**
   * Address: 0x00BC4680 (FUN_00BC4680)
   *
   * What it does:
   * Registers the `dword_10A7BE8` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant125()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant125>();
  }

  /**
   * Address: 0x00BEE7B0 (FUN_00BEE7B0, sub_BEE7B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_0`
   * (`dword_10A7464`).
   */
  void cleanup_EngineStatsCleanupSlotVariant126()
  {
    CleanupEngineStatsSlot<0x10A7464u>();
  }

  /**
   * Address: 0x00BC33C0 (FUN_00BC33C0, register_engine_stats_0)
   *
   * What it does:
   * Registers the `engine_stats_0` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant126()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant126>();
  }

  /**
   * Address: 0x00BEE7D0 (FUN_00BEE7D0, sub_BEE7D0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_1`
   * (`dword_10A7494`).
   */
  void cleanup_EngineStatsCleanupSlotVariant127()
  {
    CleanupEngineStatsSlot<0x10A7494u>();
  }

  /**
   * Address: 0x00BC33D0 (FUN_00BC33D0, register_engine_stats_1)
   *
   * What it does:
   * Registers the `engine_stats_1` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant127()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant127>();
  }

  /**
   * Address: 0x00BEE8B0 (FUN_00BEE8B0, sub_BEE8B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_2`
   * (`dword_10A74C0`).
   */
  void cleanup_EngineStatsCleanupSlotVariant128()
  {
    CleanupEngineStatsSlot<0x10A74C0u>();
  }

  /**
   * Address: 0x00BC3560 (FUN_00BC3560, register_engine_stats_2)
   *
   * What it does:
   * Registers the `engine_stats_2` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant128()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant128>();
  }

  /**
   * Address: 0x00BEE8D0 (FUN_00BEE8D0, sub_BEE8D0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_3`
   * (`dword_10A765C`).
   */
  void cleanup_EngineStatsCleanupSlotVariant129()
  {
    CleanupEngineStatsSlot<0x10A765Cu>();
  }

  /**
   * Address: 0x00BC35D0 (FUN_00BC35D0, register_engine_stats_3)
   *
   * What it does:
   * Registers the `engine_stats_3` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant129()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant129>();
  }

  /**
   * Address: 0x00BEEA90 (FUN_00BEEA90, sub_BEEA90)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_4`
   * (`dword_10A766C`).
   */
  void cleanup_EngineStatsCleanupSlotVariant130()
  {
    CleanupEngineStatsSlot<0x10A766Cu>();
  }

  /**
   * Address: 0x00BC3780 (FUN_00BC3780, register_engine_stats_4)
   *
   * What it does:
   * Registers the `engine_stats_4` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant130()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant130>();
  }

  /**
   * Address: 0x00BEEAB0 (FUN_00BEEAB0, sub_BEEAB0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_5`
   * (`dword_10A767C`).
   */
  void cleanup_EngineStatsCleanupSlotVariant131()
  {
    CleanupEngineStatsSlot<0x10A767Cu>();
  }

  /**
   * Address: 0x00BC37F0 (FUN_00BC37F0, register_engine_stats_5)
   *
   * What it does:
   * Registers the `engine_stats_5` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant131()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant131>();
  }

  /**
   * Address: 0x00BEEAD0 (FUN_00BEEAD0, sub_BEEAD0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_6`
   * (`dword_10A77A4`).
   */
  void cleanup_EngineStatsCleanupSlotVariant132()
  {
    CleanupEngineStatsSlot<0x10A77A4u>();
  }

  /**
   * Address: 0x00BC3880 (FUN_00BC3880, register_engine_stats_6)
   *
   * What it does:
   * Registers the `engine_stats_6` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant132()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant132>();
  }

  /**
   * Address: 0x00BEE290 (FUN_00BEE290, sub_BEE290)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `sEngineStats`
   * (`dword_10A67B8`).
   */
  void cleanup_EngineStatsCleanupSlotVariant133()
  {
    CleanupEngineStatsSlot<0x10A67B8u>();
  }

  /**
   * Address: 0x00BC2FB0 (FUN_00BC2FB0, register_engine_stats)
   *
   * What it does:
   * Registers the `sEngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant133()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant133>();
  }

  /**
   * Address: 0x00BEE0C0 (FUN_00BEE0C0, sub_BEE0C0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `enginestats`
   * (`dword_10A66C4`).
   */
  void cleanup_EngineStatsCleanupSlotVariant134()
  {
    CleanupEngineStatsSlot<0x10A66C4u>();
  }

  /**
   * Address: 0x00BC2EC0 (FUN_00BC2EC0, register_enginestats)
   *
   * What it does:
   * Registers the `enginestats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant134()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsCleanupSlotVariant134>();
  }

  /**
   * Address: 0x00BF1800 (FUN_00BF1800, sub_BF1800)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A9B54`.
   */
  void cleanup_EngineStatsSlotVariant135()
  {
    CleanupEngineStatsSlot<0x10A9B54u>();
  }

  /**
   * Address: 0x00BC71B0 (FUN_00BC71B0, sub_BC71B0)
   *
   * What it does:
   * Registers the `dword_10A9B54` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant135()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant135>();
  }

  /**
   * Address: 0x00BF1820 (FUN_00BF1820, sub_BF1820)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A9B74`.
   */
  void cleanup_EngineStatsSlotVariant136()
  {
    CleanupEngineStatsSlot<0x10A9B74u>();
  }

  /**
   * Address: 0x00BC71C0 (FUN_00BC71C0, sub_BC71C0)
   *
   * What it does:
   * Registers the `dword_10A9B74` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant136()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant136>();
  }

  /**
   * Address: 0x00BF1890 (FUN_00BF1890, sub_BF1890)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A9BE8`.
   */
  void cleanup_EngineStatsSlotVariant137()
  {
    CleanupEngineStatsSlot<0x10A9BE8u>();
  }

  /**
   * Address: 0x00BC7300 (FUN_00BC7300, sub_BC7300)
   *
   * What it does:
   * Registers the `dword_10A9BE8` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant137()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant137>();
  }

  /**
   * Address: 0x00BF1990 (FUN_00BF1990, sub_BF1990)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A9BFC`.
   */
  void cleanup_EngineStatsSlotVariant138()
  {
    CleanupEngineStatsSlot<0x10A9BFCu>();
  }

  /**
   * Address: 0x00BC7430 (FUN_00BC7430, sub_BC7430)
   *
   * What it does:
   * Registers the `dword_10A9BFC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant138()
  {
    return RegisterExitCleanup<&cleanup_EngineStatsSlotVariant138>();
  }
} // namespace moho
