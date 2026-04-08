#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CScriptObjectSerializer
  {
  public:
    /**
     * Address: 0x004C79E0 (FUN_004C79E0, Moho::CScriptObjectSerializer::Deserialize)
     *
     * What it does:
     * Serializer load thunk forwarding into `CScriptObject::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004C79F0 (FUN_004C79F0, Moho::CScriptObjectSerializer::Serialize)
     *
     * What it does:
     * Serializer save thunk forwarding into `CScriptObject::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004C7D50 (FUN_004C7D50, gpg::SerSaveLoadHelper_CSCriptObject::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CScriptObject RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CScriptObjectSerializer, mHelperNext) == 0x04,
    "CScriptObjectSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CScriptObjectSerializer, mHelperPrev) == 0x08,
    "CScriptObjectSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CScriptObjectSerializer, mLoadCallback) == 0x0C,
    "CScriptObjectSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CScriptObjectSerializer, mSaveCallback) == 0x10,
    "CScriptObjectSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CScriptObjectSerializer) == 0x14, "CScriptObjectSerializer size must be 0x14");

  /**
   * Address: 0x00BC6080 (FUN_00BC6080, register_CScriptObjectSerializer)
   *
   * What it does:
   * Initializes startup serializer callback lanes for `CScriptObject` and
   * schedules intrusive helper cleanup at process exit.
   */
  void register_CScriptObjectSerializer();

  /**
   * What it does:
   * Unlinks static serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CScriptObjectSerializer();
} // namespace moho
