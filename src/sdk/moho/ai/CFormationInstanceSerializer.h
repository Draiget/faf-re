// Reconstructed from FA binary evidence (vtable + callsites + decomp).
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
   * VFTABLE: 0x00E19134
   *
   * Serializer helper for `CFormationInstance`. Same shape as
   * `CAiBrainSerializer`: an intrusive node in the global serializer chain plus
   * the load/save callbacks that `RegisterSerializeFunctions` installs into the
   * reflected type.
   */
  class CFormationInstanceSerializer
  {
  public:
    /**
     * Address: 0x0056A860 (FUN_0056A860, Moho::CFormationInstanceSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CFormationInstance::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0056A870 (FUN_0056A870, Moho::CFormationInstanceSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CFormationInstance::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds this helper's load/save callbacks into the `CFormationInstance`
     * type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    // Intrusive list links from gpg::DListItem<gpg::SerHelperBase>.
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    // Serializer callbacks consumed by the reflection registration flow.
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CFormationInstanceSerializer, mHelperNext) == 0x04,
    "CFormationInstanceSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CFormationInstanceSerializer, mHelperPrev) == 0x08,
    "CFormationInstanceSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CFormationInstanceSerializer, mLoadCallback) == 0x0C,
    "CFormationInstanceSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CFormationInstanceSerializer, mSaveCallback) == 0x10,
    "CFormationInstanceSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(CFormationInstanceSerializer) == 0x14, "CFormationInstanceSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCAC40 (FUN_00BCAC40, register_CFormationInstanceSerializer)
   *
   * What it does:
   * Initializes the global `CFormationInstance` serializer helper, binds its
   * load/save callbacks, and installs process-exit cleanup.
   */
  void register_CFormationInstanceSerializer();
} // namespace moho
