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
   * VFTABLE: 0x00E3636C
   * COL:  0x00E8FDA4
   */
  class CIntelCounterHandleSerializer
  {
  public:
    /**
     * Address: 0x0076F990 (FUN_0076F990, Moho::CIntelCounterHandleSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CIntelCounterHandle::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0076F9A0 (FUN_0076F9A0, Moho::CIntelCounterHandleSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CIntelCounterHandle::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0076FC20 (FUN_0076FC20, gpg::SerSaveLoadHelper_CIntelCounterHandle::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CIntelCounterHandle RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CIntelCounterHandleSerializer, mHelperLinks) == 0x04,
    "CIntelCounterHandleSerializer::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelCounterHandleSerializer, mLoadCallback) == 0x0C,
    "CIntelCounterHandleSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelCounterHandleSerializer, mSaveCallback) == 0x10,
    "CIntelCounterHandleSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelCounterHandleSerializer) == 0x14, "CIntelCounterHandleSerializer size must be 0x14");

  /**
   * Address: 0x00C01F90 (FUN_00C01F90, cleanup_CIntelCounterHandleSerializer)
   *
   * What it does:
   * Unlinks startup `CIntelCounterHandleSerializer` helper links and rewires
   * a self-linked sentinel lane.
   */
  gpg::SerHelperBase* cleanup_CIntelCounterHandleSerializer();

  /**
   * Address: 0x00BDCD90 (FUN_00BDCD90, register_CIntelCounterHandleSerializer)
   *
   * What it does:
   * Initializes startup serializer helper lanes for `CIntelCounterHandle` and
   * installs process-exit cleanup.
   */
  void register_CIntelCounterHandleSerializer();
} // namespace moho

