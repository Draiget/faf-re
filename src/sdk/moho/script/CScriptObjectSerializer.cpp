#include "moho/script/CScriptObjectSerializer.h"

#include "moho/script/CScriptObject.h"

namespace moho
{
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
