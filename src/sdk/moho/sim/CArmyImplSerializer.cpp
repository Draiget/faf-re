#include "moho/sim/CArmyImplSerializer.h"

#include "moho/sim/CArmyImpl.h"

namespace moho
{
  /**
   * Address: 0x00BD9C20 (FUN_00BD9C20, dynamic initializer for the global
   * `CArmyImplSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CArmyImplSerializer::CArmyImplSerializer()
    : mLoadCallback(&CArmyImplSerializer::Deserialize)
    , mSaveCallback(&CArmyImplSerializer::Serialize)
  {}

  CArmyImplSerializer::~CArmyImplSerializer()
  {
    ResetLinks();
  }

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
   * Address: 0x00701DD0 (FUN_00701DD0, gpg::SerSaveLoadHelper_CArmyImpl::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_701DD0(void (__cdecl **this)(...)))(...);
   */
  void CArmyImplSerializer::Init()
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
  // Address: 0x010B8964 -- process-global `CArmyImplSerializer` singleton.
  moho::CArmyImplSerializer gCArmyImplSerializer;
} // namespace
