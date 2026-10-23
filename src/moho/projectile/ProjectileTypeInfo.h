#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class ProjectileTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0069E190 (FUN_0069E190, Moho::ProjectileTypeInfo::ProjectileTypeInfo)
     */
    ProjectileTypeInfo();

    /**
     * Address: 0x0069E260 (FUN_0069E260, Moho::ProjectileTypeInfo::dtr)
     */
    ~ProjectileTypeInfo() override;

    /**
     * Address: 0x0069E250 (FUN_0069E250, Moho::ProjectileTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0069E1F0 (FUN_0069E1F0, Moho::ProjectileTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0069F820 (FUN_0069F820, Moho::ProjectileTypeInfo::AddBaseEntity)
     */
    static void AddBase_Entity(gpg::RType* typeInfo);
  };

  static_assert(sizeof(ProjectileTypeInfo) == 0x64, "ProjectileTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD63F0 (FUN_00BD63F0, register_ProjectileTypeInfo)
   *
   * What it does:
   * Constructs the startup `ProjectileTypeInfo` object.
   */
  void register_ProjectileTypeInfo();
} // namespace moho
