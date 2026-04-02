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
