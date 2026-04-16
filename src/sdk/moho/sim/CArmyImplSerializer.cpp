#include "moho/sim/CArmyImplSerializer.h"

#include "moho/sim/CArmyImpl.h"

namespace
{
  moho::CArmyImplSerializer gCArmyImplSerializer;

  [[nodiscard]] gpg::SerHelperBase* CArmyImplSerializerNodeSelf()
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gCArmyImplSerializer.mHelperNext);
  }

  /**
   * Address: 0x00701050 (FUN_00701050, sub_701050)
   *
   * What it does:
   * Unlinks CArmyImplSerializer helper node from the current intrusive list and
   * rewires it to a self-linked singleton.
   */
  [[nodiscard]] gpg::SerHelperBase* ResetCArmyImplSerializerHelperLinksA()
  {
    gpg::SerHelperBase* const next = gCArmyImplSerializer.mHelperNext;
    gpg::SerHelperBase* const prev = gCArmyImplSerializer.mHelperPrev;
    next->mPrev = prev;
    prev->mNext = next;

    gpg::SerHelperBase* const self = CArmyImplSerializerNodeSelf();
    gCArmyImplSerializer.mHelperPrev = self;
    gCArmyImplSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00701080 (FUN_00701080, sub_701080)
   *
   * What it does:
   * Alias duplicate of `FUN_00701050` with identical intrusive-list
   * unlink-and-self-link behavior.
   */
  [[nodiscard]] gpg::SerHelperBase* ResetCArmyImplSerializerHelperLinksB()
  {
    return ResetCArmyImplSerializerHelperLinksA();
  }
}

namespace moho
{
  /**
   * Address: 0x00701000 (FUN_00701000, Moho::CArmyImplSerializer::Deserialize)
   */
  void CArmyImplSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CArmyImpl*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00701010 (FUN_00701010, Moho::CArmyImplSerializer::Serialize)
   */
  void CArmyImplSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CArmyImpl*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BD9C20 (FUN_00BD9C20, register_CArmyImplSerializer)
   */
  void register_CArmyImplSerializer()
  {
    gCArmyImplSerializer.mHelperNext = nullptr;
    gCArmyImplSerializer.mHelperPrev = nullptr;
    gCArmyImplSerializer.mLoadCallback = &CArmyImplSerializer::Deserialize;
    gCArmyImplSerializer.mSaveCallback = &CArmyImplSerializer::Serialize;
  }

  /**
   * Address: 0x00701DD0 (FUN_00701DD0, gpg::SerSaveLoadHelper_CArmyImpl::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_701DD0(void (__cdecl **this)(...)))(...);
   */
  void CArmyImplSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CArmyImpl::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  struct CArmyImplSerializerBootstrap
  {
    CArmyImplSerializerBootstrap()
    {
      moho::register_CArmyImplSerializer();
    }
  };

  CArmyImplSerializerBootstrap gCArmyImplSerializerBootstrap;
} // namespace
