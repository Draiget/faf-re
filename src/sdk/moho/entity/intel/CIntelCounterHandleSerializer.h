#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3636C
   * COL:  0x00E8FDA4
   */
  class CIntelCounterHandleSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDCD90 (FUN_00BDCD90, dynamic initializer for the global
     * `CIntelCounterHandleSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields.
     */
    CIntelCounterHandleSerializer();

    /**
     * Address: 0x00C01F90 (FUN_00C01F90, Moho::CIntelCounterHandleSerializer::~CIntelCounterHandleSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CIntelCounterHandleSerializer();

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
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CIntelCounterHandleSerializer, mLoadCallback) == 0x0C,
    "CIntelCounterHandleSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelCounterHandleSerializer, mSaveCallback) == 0x10,
    "CIntelCounterHandleSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelCounterHandleSerializer) == 0x14, "CIntelCounterHandleSerializer size must be 0x14");
} // namespace moho
