#include "moho/script/CScriptObjectSerializer.h"

#include "moho/script/CScriptObject.h"

namespace moho
{
  /**
   * Address: 0x00BC6080 (FUN_00BC6080, dynamic initializer for the global
   * `CScriptObjectSerializer` singleton)
   */
  CScriptObjectSerializer::CScriptObjectSerializer()
    : mLoadCallback(&CScriptObjectSerializer::Deserialize)
    , mSaveCallback(&CScriptObjectSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF0980 (FUN_00BF0980, Moho::CScriptObjectSerializer::~CScriptObjectSerializer)
   */
  CScriptObjectSerializer::~CScriptObjectSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x004C79E0 (FUN_004C79E0, Moho::CScriptObjectSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load directly into `CScriptObject::MemberDeserialize`.
   */
  void CScriptObjectSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<CScriptObject*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004C79F0 (FUN_004C79F0, Moho::CScriptObjectSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save directly into `CScriptObject::MemberSerialize`.
   */
  void CScriptObjectSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<CScriptObject*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x004C7D50 (FUN_004C7D50, Moho::CScriptObjectSerializer::Init)
   *
   * IDA signature:
   * void __thiscall gpg::SerSaveLoadHelper_CSCriptObject::Init(gpg::ISerializer *this);
   *
   * What it does:
   * Binds load/save serializer callbacks into `CScriptObject` RTTI.
   */
  void CScriptObjectSerializer::Init()
  {
    gpg::RType* const type = CScriptObject::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010A8B1C -- process-global `CScriptObjectSerializer` singleton.
  moho::CScriptObjectSerializer gCScriptObjectSerializer;
} // namespace
