#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E2D53C
   * COL: 0x00E864D8
   */
  class EntitySetBaseTypeInfo final : public gpg::RType
  {
  public:
    /**
       * Address: 0x00693570 (FUN_00693570)
     *
     * What it does:
     * Constructs/preregisters RTTI metadata for `EntitySetBase`.
     */
    EntitySetBaseTypeInfo();

    /**
     * Address: 0x00693600 (FUN_00693600, Moho::EntitySetBaseTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `EntitySetBaseTypeInfo`.
     */
    ~EntitySetBaseTypeInfo() override;

    /**
     * Address: 0x006935F0 (FUN_006935F0, Moho::EntitySetBaseTypeInfo::GetName)
     *
     * What it does:
     * Returns `"EntitySetBase"` as the reflection type-name.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006935D0 (FUN_006935D0, Moho::EntitySetBaseTypeInfo::Init)
     *
     * What it does:
     * Sets size/version metadata and finalizes type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(EntitySetBaseTypeInfo) == 0x64, "EntitySetBaseTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E2D56C
   * COL: 0x00E86480
   */
  class EntitySetTypeInfo final : public gpg::RType
  {
  public:
    /**
       * Address: 0x00693760 (FUN_00693760)
     *
     * What it does:
     * Constructs/preregisters RTTI metadata for `EntitySetTemplate<Entity>`.
     */
    EntitySetTypeInfo();

    /**
     * Address: 0x006937F0 (FUN_006937F0, Moho::EntitySetTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `EntitySetTypeInfo`.
     */
    ~EntitySetTypeInfo() override;

    /**
     * Address: 0x006937E0 (FUN_006937E0, Moho::EntitySetTypeInfo::GetName)
     *
     * What it does:
     * Returns `"EntitySet"` as the reflection type-name.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006937C0 (FUN_006937C0, Moho::EntitySetTypeInfo::Init)
     *
     * What it does:
     * Sets size/version metadata, adds `EntitySetBase` as base, and finalizes type setup.
     */
    void Init() override;

  private:
    static void AddBase_EntitySetBaseVariant1(gpg::RType* typeInfo);
    friend void add_EntitySetBaseBase(gpg::RType* typeInfo);
  };

  static_assert(sizeof(EntitySetTypeInfo) == 0x64, "EntitySetTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E2D55C
   * COL: 0x00E86428
   */
  class WeakEntitySetTypeInfo final : public gpg::RType
  {
  public:
    /**
       * Address: 0x006939B0 (FUN_006939B0)
     *
     * What it does:
     * Constructs/preregisters RTTI metadata for `WeakEntitySetTemplate<Entity>`.
     */
    WeakEntitySetTypeInfo();

    /**
     * Address: 0x00693A40 (FUN_00693A40, Moho::WeakEntitySetTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `WeakEntitySetTypeInfo`.
     */
    ~WeakEntitySetTypeInfo() override;

    /**
     * Address: 0x00693A30 (FUN_00693A30, Moho::WeakEntitySetTypeInfo::GetName)
     *
     * What it does:
     * Returns `"WeakEntitySet"` as the reflection type-name.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00693A10 (FUN_00693A10, Moho::WeakEntitySetTypeInfo::Init)
     *
     * What it does:
     * Sets size/version metadata, adds `EntitySetTemplate<Entity>` as base, and finalizes type setup.
     */
    void Init() override;

  private:
    static void AddBase_EntitySet(gpg::RType* typeInfo);
    friend void add_EntitySetBaseWeakBase(gpg::RType* typeInfo);
  };

  static_assert(sizeof(WeakEntitySetTypeInfo) == 0x64, "WeakEntitySetTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD5770 (FUN_00BD5770, sub_BD5770)
   *
   * What it does:
   * Constructs global `EntitySetBaseTypeInfo` and registers process-exit cleanup.
   */
  void register_EntitySetBaseTypeInfo();



  /**
   * Address: 0x00BD57D0 (FUN_00BD57D0, sub_BD57D0)
   *
   * What it does:
   * Constructs global `EntitySetTypeInfo` and registers process-exit cleanup.
   */
  void register_EntitySetTypeInfo();

  /**
   * Address: 0x00BD5830 (FUN_00BD5830, sub_BD5830)
   *
   * What it does:
   * Constructs global `WeakEntitySetTypeInfo` and registers process-exit cleanup.
   */
  void register_WeakEntitySetTypeInfo();
} // namespace moho
