#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CUnitMotionSerializer
  {
  public:
    /**
     * Address: 0x006BA2E0 (FUN_006BA2E0, Moho::CUnitMotionSerializer::Deserialize)
     *
     * What it does:
     * Forwards one reflected load callback into `CUnitMotion::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006BA2F0 (FUN_006BA2F0, Moho::CUnitMotionSerializer::Serialize)
     *
     * What it does:
     * Forwards one reflected save callback into `CUnitMotion::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006BA870 (FUN_006BA870, gpg::SerSaveLoadHelper_CUnitMotion::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CUnitMotion RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CUnitMotionSerializer, mHelperNext) == 0x04, "CUnitMotionSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitMotionSerializer, mHelperPrev) == 0x08, "CUnitMotionSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitMotionSerializer, mLoadCallback) == 0x0C,
    "CUnitMotionSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitMotionSerializer, mSaveCallback) == 0x10,
    "CUnitMotionSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CUnitMotionSerializer) == 0x14, "CUnitMotionSerializer size must be 0x14");
} // namespace moho
