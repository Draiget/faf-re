#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2FC2C
   */
  class CArmyImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD9C20 (FUN_00BD9C20, dynamic initializer for the global
     * `CArmyImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CArmyImplSerializer();

    /**
     * Address: 0x00BFF410 (FUN_00BFF410, ??1CArmyImplSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CArmyImplSerializer();

    /**
     * Address: 0x00701000 (FUN_00701000, Moho::CArmyImplSerializer::Deserialize)
     *
     * What it does:
     * Reflection load callback that forwards to `CArmyImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00701010 (FUN_00701010, Moho::CArmyImplSerializer::Serialize)
     *
     * What it does:
     * Reflection save callback that forwards to `CArmyImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00701DD0 (FUN_00701DD0, gpg::SerSaveLoadHelper_CArmyImpl::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CArmyImpl RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CArmyImplSerializer, mLoadCallback) == 0x0C, "CArmyImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyImplSerializer, mSaveCallback) == 0x10, "CArmyImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyImplSerializer) == 0x14, "CArmyImplSerializer size must be 0x14");
} // namespace moho
