#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1AF4C
   */
  class SMassInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCB700 (FUN_00BCB700, dynamic initializer for the global
     * `SMassInfoSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SMassInfoSerializer();

    /**
     * Address: 0x00BF64C0 (FUN_00BF64C0, ??1SMassInfoSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SMassInfoSerializer();

    /**
     * Address: 0x00585E10 (FUN_00585E10, Moho::SMassInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SMassInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00585E20 (FUN_00585E20, Moho::SMassInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SMassInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00591B90 (FUN_00591B90)
     *
     * What it does:
     * Binds load/save serializer callbacks into SMassInfo RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(SMassInfoSerializer, mLoadCallback) == 0x0C, "SMassInfoSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(SMassInfoSerializer, mSaveCallback) == 0x10, "SMassInfoSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(SMassInfoSerializer) == 0x14, "SMassInfoSerializer size must be 0x14");
} // namespace moho
