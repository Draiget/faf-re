#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CPrefetchSet;

  class CPrefetchSetSerializer
  {
  public:
    /**
     * Address: 0x004A55F0 (FUN_004A55F0, Moho::CPrefetchSetSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004A5630 (FUN_004A5630, Moho::CPrefetchSetSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004A5F50 (FUN_004A5F50)
     *
     * What it does:
     * Binds `CPrefetchSet` type serializer callback lanes in reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(CPrefetchSetSerializer, mHelperNext) == 0x04, "CPrefetchSetSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CPrefetchSetSerializer, mHelperPrev) == 0x08, "CPrefetchSetSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CPrefetchSetSerializer, mDeserialize) == 0x0C, "CPrefetchSetSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CPrefetchSetSerializer, mSerialize) == 0x10, "CPrefetchSetSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CPrefetchSetSerializer) == 0x14, "CPrefetchSetSerializer size must be 0x14");

  /**
   * Address: 0x004A56A0 (FUN_004A56A0)
   */
  gpg::SerHelperBase* ResetCPrefetchSetSerializerLinksVariant1();

  /**
   * Address: 0x004A56D0 (FUN_004A56D0)
   */
  gpg::SerHelperBase* ResetCPrefetchSetSerializerLinksVariant2();

  /**
   * Address: 0x00BC5990 (FUN_00BC5990, register_CPrefetchSetSerializer)
   *
   * What it does:
   * Initializes the global serializer node for `CPrefetchSet`, binds archive
   * callback lanes, and schedules serializer-link cleanup at process exit.
   */
  void register_CPrefetchSetSerializer();
} // namespace moho
