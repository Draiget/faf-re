#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E3631C
   * COL:  0x00E8FF4C
   */
  class CIntelPosHandleSerializer
  {
  public:
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
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CIntelPosHandleSerializer, mHelperLinks) == 0x04, "CIntelPosHandleSerializer::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelPosHandleSerializer, mLoadCallback) == 0x0C,
    "CIntelPosHandleSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelPosHandleSerializer, mSaveCallback) == 0x10,
    "CIntelPosHandleSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelPosHandleSerializer) == 0x14, "CIntelPosHandleSerializer size must be 0x14");

  /**
   * Address: 0x00C01ED0 (FUN_00C01ED0, cleanup_CIntelPosHandleSerializer)
   *
   * What it does:
   * Unlinks startup `CIntelPosHandleSerializer` helper links and rewires
   * a self-linked sentinel lane.
   */
  gpg::SerHelperBase* cleanup_CIntelPosHandleSerializer();

  /**
   * Address: 0x00BDCCF0 (FUN_00BDCCF0, register_CIntelPosHandleSerializer)
   *
   * What it does:
   * Initializes startup serializer helper lanes for `CIntelPosHandle` and
   * installs process-exit cleanup.
   */
  void register_CIntelPosHandleSerializer();
} // namespace moho

