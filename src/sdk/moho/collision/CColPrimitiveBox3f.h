#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "wm3/Box3.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E03944
   * COL: 0x00E600B0
   */
  class Box3fSerializer
  {
  public:
    /**
     * Address: 0x004756D0 (FUN_004756D0, gpg::SerSaveLoadHelper<Wm3::Box3<float>>::Init)
     *
     * What it does:
     * Resolves Box3f RTTI and installs load/save callbacks for this helper.
     */
    virtual void RegisterSerializeFunctions();

    /**
     * Address: 0x00474770 (FUN_00474770, Moho::Box3fSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `Wm3::Box3f::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00474780 (FUN_00474780, Moho::Box3fSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `Wm3::Box3f::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(Box3fSerializer, mHelperNext) == 0x04, "Box3fSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Box3fSerializer, mHelperPrev) == 0x08, "Box3fSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(Box3fSerializer, mLoadCallback) == 0x0C, "Box3fSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(Box3fSerializer, mSaveCallback) == 0x10, "Box3fSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(Box3fSerializer) == 0x14, "Box3fSerializer size must be 0x14");

  /**
   * Address: 0x00BC4A40 (FUN_00BC4A40, register_Box3fSerializer)
   *
   * What it does:
   * Installs startup serializer callbacks for Box3f and registers shutdown
   * unlink/teardown.
   */
  void register_Box3fSerializer();

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
  };

  static_assert(sizeof(DColPrimBoxTypeInfo) == 0x64, "DColPrimBoxTypeInfo size must be 0x64");

  /**
   * Serializer helper for `CColPrimitive<Wm3::Box3<float>>` archive lanes.
   */
  class DColPrimBoxSerializer
  {
  public:
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
     * Address: 0x004FFD70 (FUN_004FFD70, Moho::DColPrimBoxSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds load/save callbacks into `CColPrimitive<Wm3::Box3<float>>` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(DColPrimBoxSerializer, mHelperNext) == 0x04, "DColPrimBoxSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(DColPrimBoxSerializer, mHelperPrev) == 0x08, "DColPrimBoxSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(DColPrimBoxSerializer, mDeserialize) == 0x0C, "DColPrimBoxSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(DColPrimBoxSerializer, mSerialize) == 0x10, "DColPrimBoxSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(DColPrimBoxSerializer) == 0x14, "DColPrimBoxSerializer size must be 0x14");

  /**
   * Construct helper for `CColPrimitive<Wm3::Box3<float>>`.
   */
  class DColPrimBoxConstruct
  {
  public:
    /**
     * Address: 0x004FFCF0 (FUN_004FFCF0, Moho::DColPrimBoxConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into `CColPrimitive<Wm3::Box3<float>>` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(DColPrimBoxConstruct, mHelperNext) == 0x04, "DColPrimBoxConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(DColPrimBoxConstruct, mHelperPrev) == 0x08, "DColPrimBoxConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(DColPrimBoxConstruct, mConstructCallback) == 0x0C,
    "DColPrimBoxConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(DColPrimBoxConstruct, mDeleteCallback) == 0x10,
    "DColPrimBoxConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(DColPrimBoxConstruct) == 0x14, "DColPrimBoxConstruct size must be 0x14");

  /**
   * Save-construct helper for `CColPrimitive<Wm3::Box3<float>>`.
   */
  class DColPrimBoxSaveConstruct
  {
  public:
    /**
     * Address: 0x004FFC70 (FUN_004FFC70, Moho::DColPrimBoxSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * What it does:
     * Binds save-construct-args callback into `CColPrimitive<Wm3::Box3<float>>` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(DColPrimBoxSaveConstruct, mHelperNext) == 0x04,
    "DColPrimBoxSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(DColPrimBoxSaveConstruct, mHelperPrev) == 0x08,
    "DColPrimBoxSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(DColPrimBoxSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "DColPrimBoxSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(DColPrimBoxSaveConstruct) == 0x10, "DColPrimBoxSaveConstruct size must be 0x10");

  /**
   * Address: 0x00BC7620 (FUN_00BC7620, register_DColPrimBoxTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `DColPrimBoxTypeInfo` instance and its
   * process-exit cleanup hook.
   */
  void register_DColPrimBoxTypeInfo();

  /**
   * Address: 0x00BC76B0 (FUN_00BC76B0, register_DColPrimBoxSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `DColPrimBox` and registers shutdown
   * unlink/destruction.
   */
  void register_DColPrimBoxSerializer();

  /**
   * Address: 0x00BC7670 (FUN_00BC7670, register_DColPrimBoxConstruct)
   *
   * What it does:
   * Installs construct/delete callbacks for `DColPrimBox` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimBoxConstruct();

  /**
   * Address: 0x00BC7640 (FUN_00BC7640, register_DColPrimBoxSaveConstruct)
   *
   * What it does:
   * Installs save-construct-args callbacks for `DColPrimBox` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimBoxSaveConstruct();

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
