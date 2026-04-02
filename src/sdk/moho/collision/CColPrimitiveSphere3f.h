#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "wm3/Sphere3.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E038FC
   * COL: 0x00E60048
   */
  class Sphere3fSerializer
  {
  public:
    /**
     * Address: 0x00473FF0 (FUN_00473FF0, gpg::SerSaveLoadHelper<Wm3::Sphere3<float>>::Init)
     *
     * What it does:
     * Resolves Sphere3f RTTI and installs load/save callbacks for this helper.
     */
    virtual void RegisterSerializeFunctions();

    /**
     * Address: 0x004730E0 (FUN_004730E0, Moho::Sphere3fSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `Wm3::Sphere3f::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004730F0 (FUN_004730F0, Moho::Sphere3fSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `Wm3::Sphere3f::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(Sphere3fSerializer, mHelperNext) == 0x04, "Sphere3fSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(Sphere3fSerializer, mHelperPrev) == 0x08, "Sphere3fSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(Sphere3fSerializer, mLoadCallback) == 0x0C, "Sphere3fSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(Sphere3fSerializer, mSaveCallback) == 0x10, "Sphere3fSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(Sphere3fSerializer) == 0x14, "Sphere3fSerializer size must be 0x14");

  template <class T>
  [[nodiscard]] const T& Invalid();

  /**
   * Address: 0x00473050 (FUN_00473050, Moho::Invalid<Wm3::Sphere3<float>>)
   *
   * What it does:
   * Returns process-lifetime singleton invalid Sphere3f (center/radius set to NaN).
   */
  template <>
  [[nodiscard]] const Wm3::Sphere3f& Invalid<Wm3::Sphere3f>();
} // namespace moho
