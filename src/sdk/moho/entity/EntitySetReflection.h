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
   * VFTABLE: 0x00E2D4EC
   * COL: 0x00E86568
   */
  class EntitySetBaseSerializer
  {
  public:
    /**
     * Address: 0x006936B0 (FUN_006936B0, Moho::EntitySetBaseSerializer::Deserialize)
     *
     * What it does:
     * Tracks one pre-created `EntitySetBase` object and deserializes its
     * `fastvector<Entity*>` payload.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006936C0 (FUN_006936C0, Moho::EntitySetBaseSerializer::Serialize)
     *
     * What it does:
     * Marks one pre-created `EntitySetBase` object and serializes its
     * `fastvector<Entity*>` payload.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006936A0 (FUN_006936A0, nullsub_1804)
     *
     * What it does:
     * No-op vtable lane for this serializer helper family.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EntitySetBaseSerializer, mHelperNext) == 0x04, "EntitySetBaseSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EntitySetBaseSerializer, mHelperPrev) == 0x08, "EntitySetBaseSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EntitySetBaseSerializer, mDeserialize) == 0x0C,
    "EntitySetBaseSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EntitySetBaseSerializer, mSerialize) == 0x10, "EntitySetBaseSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EntitySetBaseSerializer) == 0x14, "EntitySetBaseSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E2D4F4
   * COL: 0x00E86510
   */
  class EntitySetSerializer
  {
  public:
    /**
     * Address: 0x006938A0 (FUN_006938A0, Moho::EntitySetSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `EntitySetTemplate<Entity>` payload through `EntitySetBase` RTTI.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006938E0 (FUN_006938E0, Moho::EntitySetSerializer::Serialize)
     *
     * What it does:
     * Serializes one `EntitySetTemplate<Entity>` payload through `EntitySetBase` RTTI.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds `EntitySetTemplate<Entity>` RTTI serializer callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(EntitySetSerializer, mHelperNext) == 0x04, "EntitySetSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(EntitySetSerializer, mHelperPrev) == 0x08, "EntitySetSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(EntitySetSerializer, mDeserialize) == 0x0C, "EntitySetSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(offsetof(EntitySetSerializer, mSerialize) == 0x10, "EntitySetSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(EntitySetSerializer) == 0x14, "EntitySetSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E2D4FC
   * COL: 0x00E864B8
   */
  class WeakEntitySetSerializer
  {
  public:
    /**
     * Address: 0x00693AF0 (FUN_00693AF0, Moho::WeakEntitySetSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one weak entity-set payload through `EntitySetTemplate<Entity>` RTTI.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00693B30 (FUN_00693B30, Moho::WeakEntitySetSerializer::Serialize)
     *
     * What it does:
     * Serializes one weak entity-set payload through `EntitySetTemplate<Entity>` RTTI.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds `WeakEntitySetTemplate<Entity>` RTTI serializer callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(WeakEntitySetSerializer, mHelperNext) == 0x04, "WeakEntitySetSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(WeakEntitySetSerializer, mHelperPrev) == 0x08, "WeakEntitySetSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(WeakEntitySetSerializer, mDeserialize) == 0x0C,
    "WeakEntitySetSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(WeakEntitySetSerializer, mSerialize) == 0x10, "WeakEntitySetSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(WeakEntitySetSerializer) == 0x14, "WeakEntitySetSerializer size must be 0x14");

  /**
   * Address: 0x00BD5770 (FUN_00BD5770, sub_BD5770)
   *
   * What it does:
   * Constructs global `EntitySetBaseTypeInfo` and registers process-exit cleanup.
   */
  int register_EntitySetBaseTypeInfo();

  /**
   * Address: 0x00BD5790 (FUN_00BD5790, sub_BD5790)
   *
   * What it does:
   * Initializes `EntitySetBaseSerializer` callback lanes and registers exit cleanup.
   */
  void register_EntitySetBaseSerializer();

  /**
   * Address: 0x00BD57D0 (FUN_00BD57D0, sub_BD57D0)
   *
   * What it does:
   * Constructs global `EntitySetTypeInfo` and registers process-exit cleanup.
   */
  int register_EntitySetTypeInfo();

  /**
   * Address: 0x00BD57F0 (FUN_00BD57F0, register_EntitySetSerializer)
   *
   * What it does:
   * Initializes `EntitySetSerializer` callback lanes and registers exit cleanup.
   */
  void register_EntitySetSerializer();

  /**
   * Address: 0x00BD5830 (FUN_00BD5830, sub_BD5830)
   *
   * What it does:
   * Constructs global `WeakEntitySetTypeInfo` and registers process-exit cleanup.
   */
  int register_WeakEntitySetTypeInfo();

  /**
   * Address: 0x00BD5850 (FUN_00BD5850, register_WeakEntitySetSerializer)
   *
   * What it does:
   * Initializes `WeakEntitySetSerializer` callback lanes and registers exit cleanup.
   */
  void register_WeakEntitySetSerializer();
} // namespace moho
