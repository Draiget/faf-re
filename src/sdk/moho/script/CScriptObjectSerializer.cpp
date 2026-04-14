#include "moho/script/CScriptObjectSerializer.h"

#include <cstdlib>

#include "moho/script/CScriptObject.h"

namespace
{
  moho::CScriptObjectSerializer gCScriptObjectSerializer{};

  /**
   * Address: 0x004C8340 (FUN_004C8340, j_Moho::CScriptObject::MemberDeserialize)
   *
   * What it does:
   * Thin forwarding thunk to `CScriptObject::MemberDeserialize`.
   */
  [[maybe_unused]] void CScriptObjectMemberDeserializeThunk(
    moho::CScriptObject* const object, gpg::ReadArchive* const archive
  )
  {
    if (object) {
      object->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x004C8440 (FUN_004C8440, j_Moho::CScriptObject::MemberDeserialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CScriptObject::MemberDeserialize`.
   */
  [[maybe_unused]] void CScriptObjectMemberDeserializeThunkSecondary(
    moho::CScriptObject* const object, gpg::ReadArchive* const archive
  )
  {
    if (object) {
      object->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x004C8350 (FUN_004C8350, j_Moho::CScriptObject::MemberSerialize)
   *
   * What it does:
   * Forwards serializer save callback with owner-ref lane into
   * `CScriptObject::MemberSerialize`.
   */
  [[maybe_unused]] void CScriptObjectMemberSerializeThunkWithOwner(
    moho::CScriptObject* const object, gpg::RRef* const /*ownerRef*/, gpg::WriteArchive* const archive
  )
  {
    if (object) {
      object->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x004C8450 (FUN_004C8450, j_Moho::CScriptObject::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CScriptObject::MemberSerialize`.
   */
  [[maybe_unused]] void CScriptObjectMemberSerializeThunkSecondary(
    moho::CScriptObject* const object, gpg::WriteArchive* const archive
  )
  {
    if (object) {
      object->MemberSerialize(archive);
    }
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  /**
   * Address: 0x004C7A30 (FUN_004C7A30)
   * Address: 0x004C7A60 (FUN_004C7A60)
   *
   * What it does:
   * Unlinks the CScriptObjectSerializer helper-node from its global
   * intrusive list and points its own next/prev lanes at itself so the
   * node becomes a self-loop sentinel. Emitted by the compiler twice for
   * the two static-destruction lanes that unlink `gCScriptObjectSerializer`
   * at process exit.
   */
  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  template <typename TSerializer>
  void ResetSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext == nullptr || serializer.mHelperPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mHelperPrev = self;
      serializer.mHelperNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
  }

  void InitializeCScriptObjectSerializer()
  {
    ResetSerializerNode(gCScriptObjectSerializer);
    gCScriptObjectSerializer.mLoadCallback = &moho::CScriptObjectSerializer::Deserialize;
    gCScriptObjectSerializer.mSaveCallback = &moho::CScriptObjectSerializer::Serialize;
  }

  void CleanupCScriptObjectSerializerAtExit()
  {
    (void)moho::cleanup_CScriptObjectSerializer();
  }
} // namespace

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
    CScriptObjectMemberDeserializeThunk(object, archive);
  }

  /**
   * Address: 0x004C79F0 (FUN_004C79F0, Moho::CScriptObjectSerializer::Serialize)
   */
  void CScriptObjectSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<CScriptObject*>(objectPtr);
    CScriptObjectMemberSerializeThunkWithOwner(object, ownerRef, archive);
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

  gpg::SerHelperBase* cleanup_CScriptObjectSerializer()
  {
    return UnlinkSerializerNode(gCScriptObjectSerializer);
  }

  /**
   * Address: 0x00BC6080 (FUN_00BC6080, register_CScriptObjectSerializer)
   *
   * What it does:
   * Initializes startup serializer callback lanes for `CScriptObject` and
   * schedules intrusive helper cleanup at process exit.
   */
  void register_CScriptObjectSerializer()
  {
    InitializeCScriptObjectSerializer();
    (void)std::atexit(&CleanupCScriptObjectSerializerAtExit);
  }
} // namespace moho
