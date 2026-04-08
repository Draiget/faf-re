#include "moho/command/SSTICommandVariableData.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace
{
  moho::SSTICommandVariableDataSerializer gSSTICommandVariableDataSerializer{};

  gpg::RType* gEntIdVectorType = nullptr;
  gpg::RType* gUnitCommandType = nullptr;
  gpg::RType* gTargetType = nullptr;
  gpg::RType* gCellVectorType = nullptr;

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

  [[nodiscard]] gpg::RType* ResolveEntIdVectorType()
  {
    if (gEntIdVectorType == nullptr) {
      gEntIdVectorType = gpg::LookupRType(typeid(msvc8::vector<moho::EntId>));
    }
    return gEntIdVectorType;
  }

  [[nodiscard]] gpg::RType* ResolveEUnitCommandType()
  {
    if (gUnitCommandType == nullptr) {
      gUnitCommandType = gpg::LookupRType(typeid(moho::EUnitCommandType));
    }
    return gUnitCommandType;
  }

  [[nodiscard]] gpg::RType* ResolveSSTITargetType()
  {
    if (gTargetType == nullptr) {
      gTargetType = gpg::LookupRType(typeid(moho::SSTITarget));
    }
    return gTargetType;
  }

  [[nodiscard]] gpg::RType* ResolveSOCellPosVectorType()
  {
    if (gCellVectorType == nullptr) {
      gCellVectorType = gpg::LookupRType(typeid(msvc8::vector<moho::SOCellPos>));
    }
    return gCellVectorType;
  }

  void cleanup_SSTICommandVariableDataSerializer_Atexit()
  {
    (void)UnlinkHelperNode(gSSTICommandVariableDataSerializer);
  }

  void register_SSTICommandVariableDataSerializer()
  {
    InitializeHelperNode(gSSTICommandVariableDataSerializer);
    gSSTICommandVariableDataSerializer.mSerLoadFunc = &moho::SSTICommandVariableDataSerializer::Serialize;
    gSSTICommandVariableDataSerializer.mSerSaveFunc = &moho::SSTICommandVariableDataSerializer::Deserialize;
    gSSTICommandVariableDataSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_SSTICommandVariableDataSerializer_Atexit);
  }
} // namespace

namespace moho
{
  gpg::RType* SSTICommandVariableData::sType = nullptr;

  /**
   * Address: 0x005603E0 (FUN_005603E0, Moho::SSTICommandVariableData::~SSTICommandVariableData)
   *
   * What it does:
   * Releases command payload vectors (`mCells`, `mEntIds`) and restores their
   * inline-storage lanes.
   */
  SSTICommandVariableData::~SSTICommandVariableData() = default;

  /**
   * Address: 0x00554760 (FUN_00554760, Moho::SSTICommandVariableData::MemberDeserialize)
   */
  void SSTICommandVariableData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const entIdVectorType = ResolveEntIdVectorType();
    GPG_ASSERT(entIdVectorType != nullptr);
    archive->Read(entIdVectorType, &mEntIds, ownerRef);

    gpg::RType* const unitCommandType = ResolveEUnitCommandType();
    GPG_ASSERT(unitCommandType != nullptr);
    archive->Read(unitCommandType, &mCmdType, ownerRef);

    gpg::RType* const targetType = ResolveSSTITargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Read(targetType, &mTarget1, ownerRef);
    archive->Read(targetType, &mTarget2, ownerRef);

    gpg::RType* const cellVectorType = ResolveSOCellPosVectorType();
    GPG_ASSERT(cellVectorType != nullptr);
    archive->Read(cellVectorType, &mCells, ownerRef);

    archive->ReadInt(&mMaxCount);
    archive->ReadInt(&mCount);
    archive->ReadUInt(&v23);
  }

  /**
   * Address: 0x005548A0 (FUN_005548A0, Moho::SSTICommandVariableData::MemberSerialize)
   */
  void SSTICommandVariableData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const entIdVectorType = ResolveEntIdVectorType();
    GPG_ASSERT(entIdVectorType != nullptr);
    archive->Write(entIdVectorType, &mEntIds, ownerRef);

    gpg::RType* const unitCommandType = ResolveEUnitCommandType();
    GPG_ASSERT(unitCommandType != nullptr);
    archive->Write(unitCommandType, &mCmdType, ownerRef);

    gpg::RType* const targetType = ResolveSSTITargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Write(targetType, &mTarget1, ownerRef);
    archive->Write(targetType, &mTarget2, ownerRef);

    gpg::RType* const cellVectorType = ResolveSOCellPosVectorType();
    GPG_ASSERT(cellVectorType != nullptr);
    archive->Write(cellVectorType, &mCells, ownerRef);

    archive->WriteInt(mMaxCount);
    archive->WriteInt(mCount);
    archive->WriteUInt(v23);
  }

  /**
   * Address: 0x00552B20 (FUN_00552B20, Moho::SSTICommandVariableDataSerializer::Serialize)
   */
  void SSTICommandVariableDataSerializer::Serialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const data = reinterpret_cast<SSTICommandVariableData*>(objectPtr);
    if (!archive || !data) {
      return;
    }

    data->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00552B30 (FUN_00552B30, Moho::SSTICommandVariableDataSerializer::Deserialize)
   */
  void SSTICommandVariableDataSerializer::Deserialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    const auto* const data = reinterpret_cast<const SSTICommandVariableData*>(objectPtr);
    if (!archive || !data) {
      return;
    }

    data->MemberSerialize(archive);
  }

  /**
   * Address: 0x00553260 (FUN_00553260, gpg::SerSaveLoadHelper_SSTICommandVariableData::Init)
   */
  void SSTICommandVariableDataSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = SSTICommandVariableData::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(SSTICommandVariableData));
      SSTICommandVariableData::sType = type;
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
  struct SSTICommandVariableDataSerializerBootstrap
  {
    SSTICommandVariableDataSerializerBootstrap()
    {
      register_SSTICommandVariableDataSerializer();
    }
  };

  [[maybe_unused]] SSTICommandVariableDataSerializerBootstrap gSSTICommandVariableDataSerializerBootstrap;
} // namespace
