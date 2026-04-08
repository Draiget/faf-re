#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum ECollisionShape : int32_t
  {
    COLSHAPE_None = 0x0,
    COLSHAPE_Box = 0x1,
    COLSHAPE_Sphere = 0x2,
  };

  /**
   * VFTABLE: 0x00E0D420
   * COL: 0x00E66D6C
   */
  class ECollisionShapeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x004FE480 (FUN_004FE480, Moho::ECollisionShapeTypeInfo::dtr)
     */
    ~ECollisionShapeTypeInfo() override;

    /**
     * Address: 0x004FE470 (FUN_004FE470, Moho::ECollisionShapeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004FE450 (FUN_004FE450, Moho::ECollisionShapeTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x004FE4B0 (FUN_004FE4B0, Moho::ECollisionShapeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(ECollisionShapeTypeInfo) == 0x78, "ECollisionShapeTypeInfo size must be 0x78");
  static_assert(sizeof(ECollisionShape) == 0x04, "ECollisionShape size must be 0x04");

  /**
   * Address: 0x004FE3F0 (FUN_004FE3F0, preregister_ECollisionShapeTypeInfo)
   *
   * What it does:
   * Materializes/preregisters startup RTTI storage for `ECollisionShape`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ECollisionShapeTypeInfo();

  /**
   * Address: 0x00BC7510 (FUN_00BC7510, register_ECollisionShapeTypeInfo)
   *
   * What it does:
   * Runs `ECollisionShape` type preregistration and installs process-exit
   * cleanup.
   */
  int register_ECollisionShapeTypeInfo();
}
