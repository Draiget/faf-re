#include "moho/command/SSTICommandConstantData.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  class SSTICommandConstantDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTICommandConstantData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTICommandConstantData);
      gpg::RType::Init();
      Finish();
    }
  };

  gpg::RType* gQuatfType = nullptr;

  [[nodiscard]] gpg::RType* ResolveQuatfType()
  {
    if (gQuatfType == nullptr) {
      gQuatfType = gpg::LookupRType(typeid(Wm3::Quatf));
    }
    return gQuatfType;
  }

} // namespace

namespace moho
{
  gpg::RType* SSTICommandConstantData::sType = nullptr;

  /**
   * Address: 0x00552630 (FUN_00552630, preregister_SSTICommandConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTICommandConstantData`.
   */
  gpg::RType* preregister_SSTICommandConstantDataTypeInfo()
  {
    static SSTICommandConstantDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTICommandConstantData), &typeInfo);
    return &typeInfo;
  }

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
   * Address: 0x00BC9CA0 (FUN_00BC9CA0, dynamic initializer for the global
   * `SSTICommandConstantDataSerializer` singleton)
   */
  SSTICommandConstantDataSerializer::SSTICommandConstantDataSerializer()
    : mSerLoadFunc(&SSTICommandConstantDataSerializer::Deserialize)
    , mSerSaveFunc(&SSTICommandConstantDataSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF49F0 (FUN_00BF49F0, Moho::SSTICommandConstantDataSerializer::~SSTICommandConstantDataSerializer)
   */
  SSTICommandConstantDataSerializer::~SSTICommandConstantDataSerializer()
  {
    ResetLinks();
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
   * Address: 0x00552E00 (FUN_00552E00, Moho::SSTICommandConstantDataSerializer::Init)
   */
  void SSTICommandConstantDataSerializer::Init()
  {
    gpg::RType* type = SSTICommandConstantData::sType;
    if (type == nullptr) {
      type = preregister_SSTICommandConstantDataTypeInfo();
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
  // Address: 0x010AC540 -- process-global `SSTICommandConstantDataSerializer` singleton.
  moho::SSTICommandConstantDataSerializer gSSTICommandConstantDataSerializer;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSTICommandConstantDataTypeInfo_0f3565, moho::preregister_SSTICommandConstantDataTypeInfo)
