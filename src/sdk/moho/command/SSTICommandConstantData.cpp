#include "moho/command/SSTICommandConstantData.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"

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

  [[nodiscard]] gpg::SerHelperBase* ResetSSTICommandConstantDataSerializerHelperLinks() noexcept
  {
    gSSTICommandConstantDataSerializer.mHelperNext->mPrev = gSSTICommandConstantDataSerializer.mHelperPrev;
    gSSTICommandConstantDataSerializer.mHelperPrev->mNext = gSSTICommandConstantDataSerializer.mHelperNext;
    gpg::SerHelperBase* const self = HelperSelfNode(gSSTICommandConstantDataSerializer);
    gSSTICommandConstantDataSerializer.mHelperNext = self;
    gSSTICommandConstantDataSerializer.mHelperPrev = self;
    return self;
  }

  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTICommandConstantDataSerializerHelperNodePrimary() noexcept;
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTICommandConstantDataSerializerHelperNodeSecondary() noexcept;

  [[nodiscard]] gpg::RType* ResolveQuatfType()
  {
    if (gQuatfType == nullptr) {
      gQuatfType = gpg::LookupRType(typeid(Wm3::Quatf));
    }
    return gQuatfType;
  }

  void cleanup_SSTICommandConstantDataSerializer_Atexit()
  {
    (void)CleanupSSTICommandConstantDataSerializerHelperNodePrimary();
  }

  /**
   * Address: 0x00552860 (FUN_00552860)
   *
   * What it does:
   * Unlinks `SSTICommandConstantDataSerializer` helper node from the intrusive
   * helper list and restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTICommandConstantDataSerializerHelperNodePrimary() noexcept
  {
    return ResetSSTICommandConstantDataSerializerHelperLinks();
  }

  /**
   * Address: 0x00552890 (FUN_00552890)
   *
   * What it does:
   * Secondary entrypoint for `SSTICommandConstantDataSerializer` helper-node
   * unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTICommandConstantDataSerializerHelperNodeSecondary() noexcept
  {
    return ResetSSTICommandConstantDataSerializerHelperLinks();
  }

  void register_SSTICommandConstantDataSerializer()
  {
    InitializeHelperNode(gSSTICommandConstantDataSerializer);
    gSSTICommandConstantDataSerializer.mSerLoadFunc = &moho::SSTICommandConstantDataSerializer::Deserialize;
    gSSTICommandConstantDataSerializer.mSerSaveFunc = &moho::SSTICommandConstantDataSerializer::Serialize;
    (void)std::atexit(&cleanup_SSTICommandConstantDataSerializer_Atexit);
  }

  /**
   * Address: 0x006EC800 (FUN_006EC800)
   * Address: 0x006EBB60 (FUN_006EBB60)
   *
   * What it does:
   * Fills one half-open destination range with repeated
   * `SSTICommandConstantData` values copied from `fillValue`.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* FillSSTICommandConstantDataRange(
    moho::SSTICommandConstantData* destinationBegin,
    moho::SSTICommandConstantData* const destinationEnd,
    const moho::SSTICommandConstantData& fillValue
  )
  {
    for (moho::SSTICommandConstantData* cursor = destinationBegin; cursor != destinationEnd; ++cursor) {
      cursor->cmd = fillValue.cmd;
      cursor->unk0 = fillValue.unk0;
      cursor->origin = fillValue.origin;
      cursor->unk1 = fillValue.unk1;
      cursor->blueprint = fillValue.blueprint;
      cursor->unk2.assign(fillValue.unk2, 0, msvc8::string::npos);
    }

    return destinationEnd;
  }

  /**
   * Address: 0x006EB7B0 (FUN_006EB7B0)
   *
   * What it does:
   * Count-based adapter lane that forwards repeated constant-data fill into the
   * canonical half-open range helper.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* FillSSTICommandConstantDataRangeCountedAdapter(
    const moho::SSTICommandConstantData* const fillValue,
    moho::SSTICommandConstantData* const destinationBegin,
    const std::uint32_t count
  )
  {
    if (fillValue == nullptr || destinationBegin == nullptr || count == 0u) {
      return destinationBegin;
    }

    return FillSSTICommandConstantDataRange(destinationBegin, destinationBegin + count, *fillValue);
  }

  /**
   * Address: 0x006ECB50 (FUN_006ECB50)
   *
   * What it does:
   * Clears one `SSTICommandConstantData` trailing string lane and returns 0.
   */
  [[maybe_unused]] int ResetSSTICommandConstantDataStringLane(moho::SSTICommandConstantData* const entry) noexcept
  {
    if (entry != nullptr) {
      entry->unk2.tidy(true, 0U);
    }

    return 0;
  }

  /**
   * Address: 0x006ED180 (FUN_006ED180)
   * Address: 0x006EC880 (FUN_006EC880)
   *
   * What it does:
   * Backward-copies one `SSTICommandConstantData` range into potentially
   * overlapping destination storage and returns the new destination begin.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* CopyBackwardSSTICommandConstantDataRange(
    moho::SSTICommandConstantData* sourceCurrent,
    const moho::SSTICommandConstantData* const sourceBegin,
    moho::SSTICommandConstantData* destinationCurrent
  )
  {
    while (sourceCurrent != sourceBegin) {
      --sourceCurrent;
      --destinationCurrent;

      destinationCurrent->cmd = sourceCurrent->cmd;
      destinationCurrent->unk0 = sourceCurrent->unk0;
      destinationCurrent->origin = sourceCurrent->origin;
      destinationCurrent->unk1 = sourceCurrent->unk1;
      destinationCurrent->blueprint = sourceCurrent->blueprint;
      destinationCurrent->unk2.assign(sourceCurrent->unk2, 0, msvc8::string::npos);
    }

    return destinationCurrent;
  }

  /**
   * Address: 0x006EC7D0 (FUN_006EC7D0)
   * Address: 0x006ED150 (FUN_006ED150)
   * Address: 0x006ED540 (FUN_006ED540)
   *
   * What it does:
   * Forward-copy adapter lane that clones one half-open constant-data range
   * from source storage into destination storage.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* CopyForwardSSTICommandConstantDataRangeAdapter(
    const moho::SSTICommandConstantData* sourceBegin,
    const moho::SSTICommandConstantData* sourceEnd,
    moho::SSTICommandConstantData* destinationBegin
  )
  {
    moho::SSTICommandConstantData* destination = destinationBegin;
    for (const moho::SSTICommandConstantData* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
      destination->cmd = source->cmd;
      destination->unk0 = source->unk0;
      destination->origin = source->origin;
      destination->unk1 = source->unk1;
      destination->blueprint = source->blueprint;
      destination->unk2.assign(source->unk2, 0, msvc8::string::npos);
    }
    return destination;
  }

  /**
   * Address: 0x006EBB70 (FUN_006EBB70)
   *
   * What it does:
   * Adapts one legacy call-convention lane into the canonical backward
   * `SSTICommandConstantData` copy helper.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* CopyBackwardSSTICommandConstantDataRangeAdapter(
    moho::SSTICommandConstantData* sourceCurrent,
    const moho::SSTICommandConstantData* const sourceBegin,
    moho::SSTICommandConstantData* destinationCurrent
  ) noexcept
  {
    return CopyBackwardSSTICommandConstantDataRange(sourceCurrent, sourceBegin, destinationCurrent);
  }

  /**
   * Address: 0x006EC980 (FUN_006EC980)
   * Address: 0x006EB490 (FUN_006EB490)
   * Address: 0x006EBC40 (FUN_006EBC40)
   *
   * What it does:
   * Resets the trailing string lane for each `SSTICommandConstantData` entry in
   * one half-open `[begin, end)` range.
   */
  [[maybe_unused]] void ResetSSTICommandConstantDataStringRange(
    moho::SSTICommandConstantData* begin,
    moho::SSTICommandConstantData* const end
  ) noexcept
  {
    while (begin != end) {
      begin->unk2.tidy(true, 0U);
      ++begin;
    }
  }

  /**
   * Address: 0x006ECA10 (FUN_006ECA10)
   * Address: 0x006ECA80 (FUN_006ECA80)
   *
   * What it does:
   * Copies one constant-data payload lane (`cmd` through trailing string) into
   * already-initialized destination storage.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* CopySSTICommandConstantDataLane(
    moho::SSTICommandConstantData* const destination,
    const moho::SSTICommandConstantData* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->cmd = source->cmd;
    destination->unk0 = source->unk0;
    destination->origin = source->origin;
    destination->unk1 = source->unk1;
    destination->blueprint = source->blueprint;
    destination->unk2.assign(source->unk2, 0, msvc8::string::npos);
    return destination;
  }

  /**
   * Address: 0x006ECB40 (FUN_006ECB40)
   *
   * What it does:
   * Null-guard adapter that copies one constant-data payload lane when
   * destination storage is present.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* CopySSTICommandConstantDataLaneIfPresent(
    moho::SSTICommandConstantData* const destination,
    const moho::SSTICommandConstantData* const source
  )
  {
    if (destination == nullptr) {
      return destination;
    }
    return CopySSTICommandConstantDataLane(destination, source);
  }

  /**
   * Address: 0x006ED2E0 (FUN_006ED2E0)
   *
   * What it does:
   * Clears one trailing constant-data string lane and returns zero.
   */
  [[maybe_unused]] int ResetSSTICommandConstantDataStringLaneReturnZero(
    moho::SSTICommandConstantData* const entry
  ) noexcept
  {
    return ResetSSTICommandConstantDataStringLane(entry);
  }

  /**
   * Address: 0x006ED310 (FUN_006ED310)
   *
   * What it does:
   * Clears one trailing constant-data string lane and returns destination
   * storage for chaining.
   */
  [[maybe_unused]] moho::SSTICommandConstantData* ResetSSTICommandConstantDataStringLaneReturnEntry(
    moho::SSTICommandConstantData* const entry
  ) noexcept
  {
    (void)ResetSSTICommandConstantDataStringLane(entry);
    return entry;
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
  struct SSTICommandConstantDataSerializerBootstrap
  {
    SSTICommandConstantDataSerializerBootstrap()
    {
      (void)moho::preregister_SSTICommandConstantDataTypeInfo();
      register_SSTICommandConstantDataSerializer();
    }
  };

  [[maybe_unused]] SSTICommandConstantDataSerializerBootstrap gSSTICommandConstantDataSerializerBootstrap;
} // namespace
