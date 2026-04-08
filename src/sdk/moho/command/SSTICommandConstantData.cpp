#include "moho/command/SSTICommandConstantData.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"

namespace
{
  moho::SSTICommandConstantDataSerializer gSSTICommandConstantDataSerializer{};
  gpg::RType* gQuatfType = nullptr;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
    return self;
  }

  [[nodiscard]] gpg::RType* ResolveQuatfType()
  {
    if (gQuatfType == nullptr) {
      gQuatfType = gpg::LookupRType(typeid(Wm3::Quatf));
    }
    return gQuatfType;
  }

  void cleanup_SSTICommandConstantDataSerializer_Atexit()
  {
    (void)UnlinkHelperNode(gSSTICommandConstantDataSerializer);
  }

  void register_SSTICommandConstantDataSerializer()
  {
    InitializeHelperNode(gSSTICommandConstantDataSerializer);
    gSSTICommandConstantDataSerializer.mSerLoadFunc = &moho::SSTICommandConstantDataSerializer::Deserialize;
    gSSTICommandConstantDataSerializer.mSerSaveFunc = &moho::SSTICommandConstantDataSerializer::Serialize;
    gSSTICommandConstantDataSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_SSTICommandConstantDataSerializer_Atexit);
  }
} // namespace

namespace moho
{
  gpg::RType* SSTICommandConstantData::sType = nullptr;

  /**
   * Address: 0x00554630 (FUN_00554630, Moho::SSTICommandConstantData::MemberDeserialize)
   */
  void SSTICommandConstantData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->ReadInt(&cmd);

    gpg::RType* const quatType = ResolveQuatfType();
    GPG_ASSERT(quatType != nullptr);
    archive->Read(quatType, &origin, ownerRef);

    archive->ReadFloat(&unk1);
    (void)archive->ReadPointer_REntityBlueprint(&blueprint, &ownerRef);
    archive->ReadString(&unk2);
  }

  /**
   * Address: 0x005546C0 (FUN_005546C0, Moho::SSTICommandConstantData::MemberSerialize)
   */
  void SSTICommandConstantData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->WriteInt(cmd);

    gpg::RType* const quatType = ResolveQuatfType();
    GPG_ASSERT(quatType != nullptr);
    archive->Write(quatType, &origin, ownerRef);

    archive->WriteFloat(unk1);

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_REntityBlueprint(&blueprintRef, blueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->WriteString(const_cast<msvc8::string*>(&unk2));
  }

  /**
   * Address: 0x00552810 (FUN_00552810, Moho::SSTICommandConstantDataSerializer::Deserialize)
   */
  void SSTICommandConstantDataSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const data = reinterpret_cast<SSTICommandConstantData*>(objectPtr);
    if (!archive || !data) {
      return;
    }

    data->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00552820 (FUN_00552820, Moho::SSTICommandConstantDataSerializer::Serialize)
   */
  void SSTICommandConstantDataSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    const auto* const data = reinterpret_cast<const SSTICommandConstantData*>(objectPtr);
    if (!archive || !data) {
      return;
    }

    data->MemberSerialize(archive);
  }

  /**
   * Address: 0x00552E00 (FUN_00552E00, gpg::SerSaveLoadHelper_SSTICommandConstantData::Init)
   */
  void SSTICommandConstantDataSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = SSTICommandConstantData::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(SSTICommandConstantData));
      SSTICommandConstantData::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace moho

namespace
{
  struct SSTICommandConstantDataSerializerBootstrap
  {
    SSTICommandConstantDataSerializerBootstrap()
    {
      register_SSTICommandConstantDataSerializer();
    }
  };

  [[maybe_unused]] SSTICommandConstantDataSerializerBootstrap gSSTICommandConstantDataSerializerBootstrap;
} // namespace
