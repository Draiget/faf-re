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
   *
   * `vtable_writers` for `EntitySetBaseSerializer@Moho` shows two writers:
   * `FUN_00BD5790` (real, `__xc_a`-reachable) and `FUN_006936D0` (zero
   * incoming xrefs, dead COMDAT twin -- marked `skip`, along with
   * `FUN_00693DB0`, a base-subobject ctor variant that writes the OTHER
   * emitted vtable head, `gpg::SerSaveLoadHelper<Moho::EntitySetBase>`'s,
   * and `FUN_00693700`/`FUN_00693730`, two byte-identical dead
   * unlink-then-self-link bodies superseded by `SerHelperBase::
   * ResetLinks()`).
   *
   * `Init()`'s real body is `FUN_00693DE0` (found via a vtable slot-0 data
   * xref search: both this class's own vtable AND the `SerSaveLoadHelper<
   * EntitySetBase>` intermediate vtable point at the same address, so this
   * class does not override `Init()` -- it is the plain generic body). A
   * prior recovery pass mis-cited this class's `Init()`/
   * `RegisterSerializeFunctions` as `FUN_006936A0` ("nullsub_1804"), a
   * genuinely unrelated 1-byte, zero-xref padding stub nowhere near this
   * class's vtable -- that citation is corrected here.
   */
  class EntitySetBaseSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD5790 (FUN_00BD5790, dynamic initializer for the global
     * `EntitySetBaseSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    EntitySetBaseSerializer();

    /**
     * Address: 0x00BFCD20 (FUN_00BFCD20, Moho::EntitySetBaseSerializer::~EntitySetBaseSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~EntitySetBaseSerializer();

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
     * Address: 0x00693DE0 (FUN_00693DE0, gpg::SerSaveLoadHelper<Moho::EntitySetBase>::Init lane)
     *
     * What it does:
     * Resolves `EntitySetBase` RTTI and installs this helper's load/save
     * callbacks onto that type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

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
   *
   * `vtable_writers` for `EntitySetSerializer@Moho` shows two writers:
   * `FUN_00BD57F0` (real, `__xc_a`-reachable) and `FUN_00693920` (zero
   * incoming xrefs, dead COMDAT twin -- marked `skip`, along with
   * `FUN_00693E50`, a base-subobject ctor variant that writes the OTHER
   * emitted vtable head, `gpg::SerSaveLoadHelper<Moho::EntitySetTemplate<
   * Moho::Entity>>`'s, and `FUN_00693950`/`FUN_00693980`, two
   * byte-identical dead unlink-then-self-link bodies superseded by
   * `SerHelperBase::ResetLinks()`).
   *
   * `Deserialize`/`Serialize` (0x006938A0/0x006938E0) do NOT call
   * `EntitySetTemplate<Entity>::MemberDeserialize`/`MemberSerialize` on
   * their own type -- confirmed from raw decompiler output, both resolve
   * `EntitySetBase::sType` (the BASE class's RTTI) and forward through
   * `gpg::ReadArchive::Read`/`WriteArchive::Write`'s generic type-driven
   * dispatch instead. `Init()`'s real body is `FUN_00693E80` (found via a
   * vtable slot-0 data xref search, same shape as `EntitySetBaseSerializer`
   * above: both this class's own vtable and the `SerSaveLoadHelper<
   * EntitySetTemplate<Entity>>` intermediate vtable point at the same
   * address) and resolves this class's OWN type (`EntitySetTemplate<
   * Entity>::sType`, not `EntitySetBase`) -- the cross-type delegation is
   * confined to the Deserialize/Serialize callback bodies, `Init()` itself
   * is the plain generic pattern.
   */
  class EntitySetSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD57F0 (FUN_00BD57F0, dynamic initializer for the global
     * `EntitySetSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    EntitySetSerializer();

    /**
     * Address: 0x00BFCDB0 (FUN_00BFCDB0, Moho::EntitySetSerializer::~EntitySetSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~EntitySetSerializer();

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
     * Address: 0x00693E80 (FUN_00693E80, gpg::SerSaveLoadHelper<Moho::EntitySetTemplate<Moho::Entity>>::Init lane)
     *
     * What it does:
     * Resolves `EntitySetTemplate<Entity>` RTTI and installs this helper's
     * load/save callbacks onto that type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(EntitySetSerializer, mDeserialize) == 0x0C, "EntitySetSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(offsetof(EntitySetSerializer, mSerialize) == 0x10, "EntitySetSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(EntitySetSerializer) == 0x14, "EntitySetSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E2D4FC
   * COL: 0x00E864B8
   *
   * `vtable_writers` for `WeakEntitySetSerializer@Moho` shows two writers:
   * `FUN_00BD5850` (real, `__xc_a`-reachable) and `FUN_00693B70` (zero
   * incoming xrefs, dead COMDAT twin -- marked `skip`, along with
   * `FUN_00693EF0`, a base-subobject ctor variant that writes the OTHER
   * emitted vtable head, `gpg::SerSaveLoadHelper<Moho::WeakEntitySetTemplate<
   * Moho::Entity>>`'s, and `FUN_00693BA0`/`FUN_00693BD0`, two
   * byte-identical dead unlink-then-self-link bodies superseded by
   * `SerHelperBase::ResetLinks()`).
   *
   * Unlike the other three classes in this file, the real ctor's `atexit`
   * target (`FUN_00BFCE40`) demangles to no meaningful/mangled symbol at
   * all (`sub_BFCE40`, zero-meaningful-name) -- decompiles to the exact
   * same unlink-then-self-link body as the other three classes' mangled
   * `~XSerializer` destructors, and is directly confirmed as this class's
   * real atexit target via `FUN_00BD5850`'s own disassembly (`push offset
   * sub_BFCE40; call _atexit`). Modeled as a real destructor calling
   * `ResetLinks()`, same as the mangled cases; only the binary's own
   * naming differs.
   *
   * `Deserialize`/`Serialize` (0x00693AF0/0x00693B30) resolve
   * `EntitySetTemplate<Entity>::sType` (this class's OWN base, i.e. one
   * level up the chain from `EntitySetBaseSerializer`'s target) and forward
   * through `gpg::ReadArchive::Read`/`WriteArchive::Write`'s generic
   * type-driven dispatch, confirmed from raw decompiler output. `Init()`'s
   * real body is `FUN_00693F20` (found via a vtable slot-0 data xref
   * search, same two-vtables-same-address shape as the other two classes)
   * and resolves this class's OWN type (`WeakEntitySetTemplate<
   * Entity>::sType`) -- again, the cross-type delegation is confined to
   * the Deserialize/Serialize callback bodies.
   */
  class WeakEntitySetSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD5850 (FUN_00BD5850, dynamic initializer for the global
     * `WeakEntitySetSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    WeakEntitySetSerializer();

    /**
     * Address: 0x00BFCE40 (FUN_00BFCE40)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~WeakEntitySetSerializer();

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
     * Address: 0x00693F20 (FUN_00693F20, gpg::SerSaveLoadHelper<Moho::WeakEntitySetTemplate<Moho::Entity>>::Init lane)
     *
     * What it does:
     * Resolves `WeakEntitySetTemplate<Entity>` RTTI and installs this
     * helper's load/save callbacks onto that type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

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
