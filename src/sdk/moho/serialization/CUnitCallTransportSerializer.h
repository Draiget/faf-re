#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallTransport;

  class CUnitCallTransportSerializer
  {
  public:
    /**
     * Address: 0x005FFAF0 (FUN_005FFAF0, Moho::CUnitCallTransportSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitCallTransport::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005FFB00 (FUN_005FFB00, Moho::CUnitCallTransportSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitCallTransport::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006023B0 (FUN_006023B0)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `CUnitCallTransport` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext; // +0x04
    gpg::SerHelperBase* mHelperPrev; // +0x08
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CUnitCallTransportSerializer, mHelperNext) == 0x04,
    "CUnitCallTransportSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCallTransportSerializer, mHelperPrev) == 0x08,
    "CUnitCallTransportSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitCallTransportSerializer, mDeserialize) == 0x0C,
    "CUnitCallTransportSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCallTransportSerializer, mSerialize) == 0x10,
    "CUnitCallTransportSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitCallTransportSerializer) == 0x14, "CUnitCallTransportSerializer size must be 0x14");

  /**
   * Address: 0x00BF9620 (FUN_00BF9620, cleanup_CUnitCallTransportSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallTransportSerializer();

  /**
   * Address: 0x00BCFC60 (FUN_00BCFC60, register_CUnitCallTransportSerializer)
   *
   * What it does:
   * Initializes `CUnitCallTransport` serializer callback pointers and schedules
   * process-exit helper unlink cleanup.
   */
  void register_CUnitCallTransportSerializer();
} // namespace moho

