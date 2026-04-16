#pragma once

#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Models one `CWldTerrainDecal::TYPE` enum lane used by terrain decal RTTI.
   */
  enum EWldTerrainDecalType : std::int32_t
  {
    WldTerrainDecalType_Undefined = 0,
    WldTerrainDecalType_Albedo = 1,
    WldTerrainDecalType_Normals = 2,
    WldTerrainDecalType_WaterMask = 3,
    WldTerrainDecalType_WaterAlbedo = 4,
    WldTerrainDecalType_WaterNormals = 5,
    WldTerrainDecalType_Glow = 6,
    WldTerrainDecalType_NormalsAlpha = 7,
    WldTerrainDecalType_GlowMask = 8,
    WldTerrainDecalType_AlbedoXp = 9,
    WldTerrainDecalType_ForceDword = 0x7FFFFFFF,
  };

  static_assert(sizeof(EWldTerrainDecalType) == 0x4, "EWldTerrainDecalType size must be 0x4");

  /**
   * Owns reflected metadata for `CWldTerrainDecal::TYPE`.
   */
  class CWldTerrainDecalTYPETypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0089C8A0 (FUN_0089C8A0, Moho::CWldTerrainDecalTYPETypeInfo::ctor)
     *
     * What it does:
     * Preregisters the reflected `EWldTerrainDecalType` enum metadata.
     */
    CWldTerrainDecalTYPETypeInfo();

    /**
     * Address: 0x0089C930 (FUN_0089C930, Moho::CWldTerrainDecalTYPETypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for terrain decal type metadata.
     */
    ~CWldTerrainDecalTYPETypeInfo() override;

    /**
     * Address: 0x0089C920 (FUN_0089C920, Moho::CWldTerrainDecalTYPETypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for terrain decal type values.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0089C900 (FUN_0089C900, Moho::CWldTerrainDecalTYPETypeInfo::Init)
     *
     * What it does:
     * Writes enum width, installs terrain decal type labels, and finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0089C960 (FUN_0089C960, Moho::CWldTerrainDecalTYPETypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `CWldTerrainDecal::TYPE_` name/value map in reflected enum metadata.
     */
    void AddEnums();
  };

  static_assert(sizeof(CWldTerrainDecalTYPETypeInfo) == 0x78, "CWldTerrainDecalTYPETypeInfo size must be 0x78");
} // namespace moho
