#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00DFFFE8
   */
  class IdPoolSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC2DA0 (FUN_00BC2DA0, dynamic initializer for the global
     * `IdPoolSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    IdPoolSerializer();

    /**
     * Address: 0x00BEE060 (FUN_00BEE060, ??1IdPoolSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~IdPoolSerializer();

    /**
     * Address: 0x00403B90 (FUN_00403B90, Moho::IdPoolSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading to `IdPool::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00403BA0 (FUN_00403BA0, Moho::IdPoolSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving to `IdPool::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00403DC0 (FUN_00403DC0, gpg::SerSaveLoadHelper<class Moho::IdPool>::Init)
     *
     * What it does:
     * Resolves `IdPool` RTTI and binds the load/save reflection callbacks.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(IdPoolSerializer, mLoadCallback) == 0x0C, "IdPoolSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(IdPoolSerializer, mSaveCallback) == 0x10, "IdPoolSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(IdPoolSerializer) == 0x14, "IdPoolSerializer size must be 0x14");
} // namespace moho
