#include "moho/script/CScriptObjectSerializer.h"

#include "moho/script/CScriptObject.h"

namespace moho
{
  /**
   * Address: 0x004C79E0 (FUN_004C79E0, Moho::CScriptObjectSerializer::Deserialize)
   */
  void CScriptObjectSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<CScriptObject*>(objectPtr);
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004C79F0 (FUN_004C79F0, Moho::CScriptObjectSerializer::Serialize)
   */
  void CScriptObjectSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<CScriptObject*>(objectPtr);
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x004C7D50 (FUN_004C7D50, gpg::SerSaveLoadHelper_CSCriptObject::Init)
   *
   * IDA signature:
   * void __thiscall gpg::SerSaveLoadHelper_CSCriptObject::Init(gpg::ISerializer *this);
   */
  void CScriptObjectSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CScriptObject::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
