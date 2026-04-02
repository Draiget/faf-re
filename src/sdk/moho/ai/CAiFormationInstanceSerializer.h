#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CAiFormationInstanceSerializer
  {
  public:
    /**
     * Address: 0x0059BEE0 (FUN_0059BEE0, Moho::CAiFormationInstanceSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiFormationInstance::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059BEF0 (FUN_0059BEF0, Moho::CAiFormationInstanceSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiFormationInstance::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059C820 (FUN_0059C820)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiFormationInstance RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiFormationInstanceSerializer, mHelperNext) == 0x04,
    "CAiFormationInstanceSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiFormationInstanceSerializer, mHelperPrev) == 0x08,
    "CAiFormationInstanceSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiFormationInstanceSerializer, mLoadCallback) == 0x0C,
    "CAiFormationInstanceSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiFormationInstanceSerializer, mSaveCallback) == 0x10,
    "CAiFormationInstanceSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiFormationInstanceSerializer) == 0x14, "CAiFormationInstanceSerializer size must be 0x14");

  /**
   * Address: 0x00BCC150 (FUN_00BCC150, register_CAiFormationInstanceSerializer)
   *
   * What it does:
   * Initializes the global formation-instance serializer helper callbacks and
   * installs process-exit cleanup.
   */
  void register_CAiFormationInstanceSerializer();
} // namespace moho
