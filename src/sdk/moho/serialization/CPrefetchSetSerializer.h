#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CPrefetchSet;

  /**
   * VFTABLE: 0x00E07324 (`??_7CPrefetchSetSerializer@Moho@@6B@`)
   */
  class CPrefetchSetSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC5990 (FUN_00BC5990, dynamic initializer for the global
     * `CPrefetchSetSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CPrefetchSetSerializer();

    /**
     * Address: 0x00BF03A0 (FUN_00BF03A0, Moho::CPrefetchSetSerializer::~CPrefetchSetSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CPrefetchSetSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(CPrefetchSetSerializer, mDeserialize) == 0x0C, "CPrefetchSetSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CPrefetchSetSerializer, mSerialize) == 0x10, "CPrefetchSetSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CPrefetchSetSerializer) == 0x14, "CPrefetchSetSerializer size must be 0x14");
} // namespace moho
