#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3631C
   * COL:  0x00E8FF4C
   */
  class CIntelPosHandleSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDCCF0 (FUN_00BDCCF0, dynamic initializer for the global
     * `CIntelPosHandleSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields.
     */
    CIntelPosHandleSerializer();

    /**
     * Address: 0x00C01ED0 (FUN_00C01ED0, Moho::CIntelPosHandleSerializer::~CIntelPosHandleSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CIntelPosHandleSerializer();

    /**
     * Address: 0x0076F3D0 (FUN_0076F3D0, Moho::CIntelPosHandleSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CIntelPosHandle::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0076F3E0 (FUN_0076F3E0, Moho::CIntelPosHandleSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CIntelPosHandle::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0076FB00 (FUN_0076FB00, gpg::SerSaveLoadHelper_CIntelPosHandle::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CIntelPosHandle RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CIntelPosHandleSerializer, mLoadCallback) == 0x0C,
    "CIntelPosHandleSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelPosHandleSerializer, mSaveCallback) == 0x10,
    "CIntelPosHandleSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelPosHandleSerializer) == 0x14, "CIntelPosHandleSerializer size must be 0x14");
} // namespace moho
