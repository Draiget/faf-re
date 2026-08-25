#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "Wm3Box3.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E03944
   * COL: 0x00E600B0
   */
  class Box3fSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC4A40 (FUN_00BC4A40, register_Box3fSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed from raw disassembly: real
     * base ctor call, field sets, vtable install -- no eager `Init()`
     * call exists here, despite this address's own Doxygen citation
     * historically reading "SerSaveLoadHelper<Box3f>::Init" (that name
     * came from the demangled `Init()` slot 0 target below, not from
     * this ctor). The real class identity, per `vtable_writers`, is
     * `Box3fSerializer@Moho` specifically, not a `SerSaveLoadHelper<T>`
     * instantiation -- kept as its own concrete class, same precedent as
     * `Rect2iSerializer`/`Rect2fSerializer`.
     */
    Box3fSerializer();

    /**
     * Address: 0x00BEF830 (FUN_00BEF830, Moho::Box3fSerializer::~Box3fSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~Box3fSerializer();

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

    /**
     * Address: 0x004756D0 (FUN_004756D0, gpg::SerSaveLoadHelper<Wm3::Box3<float>>::Init lane)
     *
     * What it does:
     * Resolves Box3f RTTI and installs load/save callbacks for this helper.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(Box3fSerializer, mLoadCallback) == 0x0C, "Box3fSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(Box3fSerializer, mSaveCallback) == 0x10, "Box3fSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(Box3fSerializer) == 0x14, "Box3fSerializer size must be 0x14");

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
   * Construct helper for `CColPrimitive<Wm3::Box3<float>>`.
   */
  class DColPrimBoxConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC7670 (FUN_00BC7670, dynamic initializer for the global
     * `DColPrimBoxConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields. Confirmed from raw disassembly:
     * `mDeleteCallback` is the real global `operator delete(void*)`
     * directly (a `jmp ??3@YAXPAX@Z` thunk, not a per-type wrapper that
     * runs `~BoxCollisionPrimitive()` first) -- the ctor's own atexit
     * target is a plain unlink thunk, so it is modeled as the compiler's
     * implicit static-destructor registration rather than an explicit
     * call.
     */
    DColPrimBoxConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~DColPrimBoxConstruct();

    /**
     * Address: 0x004FFCF0 (FUN_004FFCF0, Moho::DColPrimBoxConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into `CColPrimitive<Wm3::Box3<float>>` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;         // +0x10
  };

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
  class DColPrimBoxSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC7640 (FUN_00BC7640, dynamic initializer for the global
     * `DColPrimBoxSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field. Plain unlink atexit target,
     * modeled as the compiler's implicit static-destructor registration.
     */
    DColPrimBoxSaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~DColPrimBoxSaveConstruct();

    /**
     * Address: 0x004FFC70 (FUN_004FFC70, Moho::DColPrimBoxSaveConstruct::Init)
     *
     * What it does:
     * Binds save-construct-args callback into `CColPrimitive<Wm3::Box3<float>>` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

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
