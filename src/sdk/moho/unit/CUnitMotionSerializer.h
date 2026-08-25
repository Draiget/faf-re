#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMotionSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD7280 (FUN_00BD7280, register_CUnitMotionSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitMotionSerializer();

    /**
     * Address: 0x00BFE0A0 (FUN_00BFE0A0, Moho::CUnitMotionSerializer::~CUnitMotionSerializer)
     *
     * What it does:
     * Unlinks the `CUnitMotionSerializer` helper from the intrusive
     * serializer helper list and rewires it as a self-linked singleton.
     */
    ~CUnitMotionSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

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
