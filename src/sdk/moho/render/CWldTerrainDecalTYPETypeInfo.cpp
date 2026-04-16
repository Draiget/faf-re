#include "moho/render/CWldTerrainDecalTYPETypeInfo.h"

#include <typeinfo>

namespace moho
{
  /**
   * Address: 0x0089C8A0 (FUN_0089C8A0, Moho::CWldTerrainDecalTYPETypeInfo::ctor)
   *
   * What it does:
   * Preregisters the reflected `EWldTerrainDecalType` enum metadata.
   */
  CWldTerrainDecalTYPETypeInfo::CWldTerrainDecalTYPETypeInfo()
  {
    gpg::PreRegisterRType(typeid(EWldTerrainDecalType), this);
  }

  /**
   * Address: 0x0089C930 (FUN_0089C930, Moho::CWldTerrainDecalTYPETypeInfo::dtr)
   */
  CWldTerrainDecalTYPETypeInfo::~CWldTerrainDecalTYPETypeInfo() = default;

  /**
   * Address: 0x0089C920 (FUN_0089C920, Moho::CWldTerrainDecalTYPETypeInfo::GetName)
   */
  const char* CWldTerrainDecalTYPETypeInfo::GetName() const
  {
    return "CWldTerrainDecal::TYPE";
  }

  /**
   * Address: 0x0089C900 (FUN_0089C900, Moho::CWldTerrainDecalTYPETypeInfo::Init)
   */
  void CWldTerrainDecalTYPETypeInfo::Init()
  {
    size_ = sizeof(EWldTerrainDecalType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0089C960 (FUN_0089C960, Moho::CWldTerrainDecalTYPETypeInfo::AddEnums)
   */
  void CWldTerrainDecalTYPETypeInfo::AddEnums()
  {
    mPrefix = "CWldTerrainDecal::TYPE_";

    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_UNDEFINED"), static_cast<int>(WldTerrainDecalType_Undefined));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_ALBEDO"), static_cast<int>(WldTerrainDecalType_Albedo));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_NORMALS"), static_cast<int>(WldTerrainDecalType_Normals));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_WATER_MASK"), static_cast<int>(WldTerrainDecalType_WaterMask));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_WATER_ALBEDO"), static_cast<int>(WldTerrainDecalType_WaterAlbedo));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_WATER_NORMALS"), static_cast<int>(WldTerrainDecalType_WaterNormals));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_GLOW"), static_cast<int>(WldTerrainDecalType_Glow));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_NORMALS_ALPHA"), static_cast<int>(WldTerrainDecalType_NormalsAlpha));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_GLOW_MASK"), static_cast<int>(WldTerrainDecalType_GlowMask));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_ALBEDOXP"), static_cast<int>(WldTerrainDecalType_AlbedoXp));
    AddEnum(StripPrefix("CWldTerrainDecal::TYPE_FORCE_DWORD"), static_cast<int>(WldTerrainDecalType_ForceDword));
  }
} // namespace moho
