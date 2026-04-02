#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1DD94
   * COL:  0x00E749D0
   */
  class SSiloBuildInfoSerializer
  {
  public:
    /**
     * Address: 0x005CEC70 (FUN_005CEC70, Moho::SSiloBuildInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards one `SSiloBuildInfo` load callback into member deserialize
     * logic.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CEC80 (FUN_005CEC80, Moho::SSiloBuildInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards one `SSiloBuildInfo` save callback into member serialize logic.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CFB60 (FUN_005CFB60)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SSiloBuildInfo` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SSiloBuildInfoSerializer, mHelperNext) == 0x04,
    "SSiloBuildInfoSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SSiloBuildInfoSerializer, mHelperPrev) == 0x08,
    "SSiloBuildInfoSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SSiloBuildInfoSerializer, mLoadCallback) == 0x0C,
    "SSiloBuildInfoSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SSiloBuildInfoSerializer, mSaveCallback) == 0x10,
    "SSiloBuildInfoSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SSiloBuildInfoSerializer) == 0x14, "SSiloBuildInfoSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E1DE48
   * COL:  0x00E747F8
   */
  class CAiSiloBuildImplSerializer
  {
  public:
    /**
     * Address: 0x005CF8D0 (FUN_005CF8D0, Moho::CAiSiloBuildImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiSiloBuildImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CF8E0 (FUN_005CF8E0, Moho::CAiSiloBuildImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiSiloBuildImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CFF30 (FUN_005CFF30)
     *
     * void ()
     *
     * IDA signature:
     * void (__cdecl *__thiscall sub_5CFF30(_DWORD *this))(gpg::ReadArchive *, int, int, gpg::RRef *);
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiSiloBuildImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mHelperNext) == 0x04,
    "CAiSiloBuildImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mHelperPrev) == 0x08,
    "CAiSiloBuildImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mLoadCallback) == 0x0C,
    "CAiSiloBuildImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mSaveCallback) == 0x10,
    "CAiSiloBuildImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiSiloBuildImplSerializer) == 0x14, "CAiSiloBuildImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCE0B0 (FUN_00BCE0B0, register_SSiloBuildInfoSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `SSiloBuildInfo` and installs
   * process-exit cleanup.
   */
  int register_SSiloBuildInfoSerializer();

  /**
   * Address: 0x00BCE150 (FUN_00BCE150, register_CAiSiloBuildImplSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `CAiSiloBuildImpl` and installs
   * process-exit cleanup.
   */
  int register_CAiSiloBuildImplSerializer();
} // namespace moho
