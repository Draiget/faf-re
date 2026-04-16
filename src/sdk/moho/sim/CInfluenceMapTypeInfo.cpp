#include "moho/sim/CInfluenceMapTypeInfo.h"

#include <typeinfo>

#include "moho/sim/CInfluenceMap.h"

namespace
{
  moho::CInfluenceMapTypeInfo gCInfluenceMapTypeInfo;
  moho::EThreatTypeTypeInfo gEThreatTypeTypeInfo;
}

namespace moho
{
  /**
   * Address: 0x00717490 (FUN_00717490, sub_717490)
   *
   * IDA signature:
   * gpg::RType *sub_717490();
   */
  CInfluenceMapTypeInfo::CInfluenceMapTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CInfluenceMap), this);
  }

  /**
   * Address: 0x00BDA660 (FUN_00BDA660, sub_BDA660)
   *
   * What it does:
   * Forces CInfluenceMap RTTI preregistration bootstrap.
   */
  void register_CInfluenceMapTypeInfo()
  {
    (void)gCInfluenceMapTypeInfo;
  }

  /**
   * What it does:
   * Forces EThreatType enum-type reflection preregistration storage.
   */
  void register_EThreatTypeTypeInfo()
  {
    (void)gEThreatTypeTypeInfo;
  }

  /**
   * Address: 0x00717520 (FUN_00717520, Moho::CInfluenceMapTypeInfo::dtr)
   */
  CInfluenceMapTypeInfo::~CInfluenceMapTypeInfo() = default;

  /**
   * Address: 0x00717510 (FUN_00717510, Moho::CInfluenceMapTypeInfo::GetName)
   */
  const char* CInfluenceMapTypeInfo::GetName() const
  {
    return "CInfluenceMap";
  }

  /**
   * Address: 0x007174F0 (FUN_007174F0, Moho::CInfluenceMapTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CInfluenceMapTypeInfo::Init(gpg::RType *this);
   */
  void CInfluenceMapTypeInfo::Init()
  {
    size_ = sizeof(CInfluenceMap);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x007154D0 (FUN_007154D0, Moho::EThreatTypeTypeInfo::EThreatTypeTypeInfo)
   */
  EThreatTypeTypeInfo::EThreatTypeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EThreatType), this);
  }

  /**
   * Address: 0x00715580 (FUN_00715580, j_??1REnumType@gpg@@QAE@@Z_48)
   */
  EThreatTypeTypeInfo::~EThreatTypeTypeInfo() = default;

  /**
   * Address: 0x00715550 (FUN_00715550, Moho::EThreatTypeTypeInfo::GetName)
   */
  const char* EThreatTypeTypeInfo::GetName() const
  {
    return "EThreatType";
  }

  /**
   * Address: 0x00715530 (FUN_00715530, Moho::EThreatTypeTypeInfo::Init)
   */
  void EThreatTypeTypeInfo::Init()
  {
    size_ = sizeof(EThreatType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00715590 (FUN_00715590, Moho::EThreatTypeTypeInfo::AddEnums)
   */
  void EThreatTypeTypeInfo::AddEnums()
  {
    mPrefix = "THREATTYPE_";
    AddEnum(StripPrefix("THREATTYPE_Overall"), static_cast<std::int32_t>(THREATTYPE_Overall));
    AddEnum(StripPrefix("THREATTYPE_OverallNotAssigned"), static_cast<std::int32_t>(THREATTYPE_OverallNotAssigned));
    AddEnum(StripPrefix("THREATTYPE_StructuresNotMex"), static_cast<std::int32_t>(THREATTYPE_StructuresNotMex));
    AddEnum(StripPrefix("THREATTYPE_Structures"), static_cast<std::int32_t>(THREATTYPE_Structures));
    AddEnum(StripPrefix("THREATTYPE_Naval"), static_cast<std::int32_t>(THREATTYPE_Naval));
    AddEnum(StripPrefix("THREATTYPE_Air"), static_cast<std::int32_t>(THREATTYPE_Air));
    AddEnum(StripPrefix("THREATTYPE_Land"), static_cast<std::int32_t>(THREATTYPE_Land));
    AddEnum(StripPrefix("THREATTYPE_Experimental"), static_cast<std::int32_t>(THREATTYPE_Experimental));
    AddEnum(StripPrefix("THREATTYPE_Commander"), static_cast<std::int32_t>(THREATTYPE_Commander));
    AddEnum(StripPrefix("THREATTYPE_Artillery"), static_cast<std::int32_t>(THREATTYPE_Artillery));
    AddEnum(StripPrefix("THREATTYPE_AntiAir"), static_cast<std::int32_t>(THREATTYPE_AntiAir));
    AddEnum(StripPrefix("THREATTYPE_AntiSurface"), static_cast<std::int32_t>(THREATTYPE_AntiSurface));
    AddEnum(StripPrefix("THREATTYPE_AntiSub"), static_cast<std::int32_t>(THREATTYPE_AntiSub));
    AddEnum(StripPrefix("THREATTYPE_Economy"), static_cast<std::int32_t>(THREATTYPE_Economy));
    AddEnum(StripPrefix("THREATTYPE_Unknown"), static_cast<std::int32_t>(THREATTYPE_Unknown));
  }
} // namespace moho

namespace
{
  struct CInfluenceMapTypeInfoBootstrap
  {
    CInfluenceMapTypeInfoBootstrap()
    {
      moho::register_CInfluenceMapTypeInfo();
      moho::register_EThreatTypeTypeInfo();
    }
  };

  CInfluenceMapTypeInfoBootstrap gCInfluenceMapTypeInfoBootstrap;
} // namespace
