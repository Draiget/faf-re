#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "Wm3Box3.h"

namespace moho
{
  /**
   * Address: 0x00BC4A20 (FUN_00BC4A20, register_Box3fTypeInfo)
   *
   * What it does:
   * Touches startup-owned Box3f typeinfo storage so process-lifetime static
   * teardown is retained by CRT registration.
   */
  void register_Box3fTypeInfo();

  /**
   * Owns reflected metadata for `CColPrimitive<Wm3::Box3<float>>`.
   */
  class DColPrimBoxTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004FEFF0 (FUN_004FEFF0, Moho::DColPrimBoxTypeInfo::DColPrimBoxTypeInfo)
     *
     * What it does:
     * Constructs the typeinfo object and pre-registers the
     * `CColPrimitive<Wm3::Box3f>` RTTI lane.
     */
    DColPrimBoxTypeInfo();

    /**
     * Address: 0x004FF080 (FUN_004FF080, Moho::DColPrimBoxTypeInfo::dtr)
     * Slot: 2
     */
    ~DColPrimBoxTypeInfo() override;

    /**
     * Address: 0x004FF070 (FUN_004FF070, Moho::DColPrimBoxTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `DColPrimBox`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004FF050 (FUN_004FF050, Moho::DColPrimBoxTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CColPrimitive<Wm3::Box3<float>>`
     * (`sizeof = 0x4C`) and adds the `CColPrimitiveBase` base lane.
     */
    void Init() override;

    /**
     * Address: 0x005004D0 (FUN_005004D0, Moho::DColPrimBoxTypeInfo::AddBase_CColPrimitiveBase)
     *
     * What it does:
     * Registers `CColPrimitiveBase` as this type's reflected base at offset 0.
     */
    static void AddBase_CColPrimitiveBase(gpg::RType* typeInfo);
  };

  static_assert(sizeof(DColPrimBoxTypeInfo) == 0x64, "DColPrimBoxTypeInfo size must be 0x64");

  /**
   * Serializer helper for `CColPrimitive<Wm3::Box3<float>>` archive lanes.
   */
  class DColPrimBoxSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC76B0 (FUN_00BC76B0, dynamic initializer for the global
     * `DColPrimBoxSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    DColPrimBoxSerializer();

    /**
     * Address: 0x00BF1BF0 (FUN_00BF1BF0, Moho::DColPrimBoxSerializer::~DColPrimBoxSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~DColPrimBoxSerializer();

    /**
     * Address: 0x004FF880 (FUN_004FF880, Moho::DColPrimBoxSerializer::Deserialize)
     *
     * What it does:
     * No-op serializer lane placeholder bound into the primitive reflection
     * helper table.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004FF890 (FUN_004FF890, Moho::DColPrimBoxSerializer::Serialize)
     *
     * What it does:
     * No-op serializer lane placeholder bound into the primitive reflection
     * helper table.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004FFD70 (FUN_004FFD70, Moho::DColPrimBoxSerializer::Init)
     *
     * What it does:
     * Binds load/save callbacks into `CColPrimitive<Wm3::Box3<float>>` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(DColPrimBoxSerializer, mDeserialize) == 0x0C, "DColPrimBoxSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(DColPrimBoxSerializer, mSerialize) == 0x10, "DColPrimBoxSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(DColPrimBoxSerializer) == 0x14, "DColPrimBoxSerializer size must be 0x14");

  /**
   * Address: 0x00BC7620 (FUN_00BC7620, register_DColPrimBoxTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `DColPrimBoxTypeInfo` instance.
   */
  void register_DColPrimBoxTypeInfo();

  /**
   * VFTABLE: 0x00E03914
   * COL: 0x00E600E4
   */
  class Box3fTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00474410 (FUN_00474410, Moho::Box3fTypeInfo::Box3fTypeInfo)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for `Wm3::Box3<float>`.
     */
    Box3fTypeInfo();

    /**
     * Address: 0x004744A0 (FUN_004744A0, Moho::Box3fTypeInfo::dtr)
     * Slot: 2
     */
    ~Box3fTypeInfo() override;

    /**
     * Address: 0x00474490 (FUN_00474490, Moho::Box3fTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for Box3f.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00474470 (FUN_00474470, Moho::Box3fTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected object size and finalizes RType initialization.
     */
    void Init() override;
  };

  static_assert(sizeof(Box3fTypeInfo) == 0x64, "Box3fTypeInfo size must be 0x64");

  template <class T>
  [[nodiscard]] const T& Invalid();

  /**
   * Address: 0x00474600 (FUN_00474600, Moho::Invalid<Wm3::Box3<float>>)
   *
   * What it does:
   * Returns process-lifetime singleton invalid Box3f (all coordinates/extents set to NaN).
   */
  template <>
  [[nodiscard]] const Wm3::Box3f& Invalid<Wm3::Box3f>();
} // namespace moho
