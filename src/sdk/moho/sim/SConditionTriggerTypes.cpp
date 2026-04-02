#include "moho/sim/SConditionTriggerTypes.h"

#include <cstdint>
#include <cstring>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/sim/CArmyStats.h"

namespace
{
  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gETriggerOperatorType = nullptr;
  gpg::RType* gSConditionCategorySetType = nullptr;
  gpg::RType* gFastVectorSConditionType = nullptr;

  constexpr std::size_t kTriggerInlineConditionCount = 2u;

  [[nodiscard]] moho::SCondition* InlineConditionBuffer(moho::STrigger* const trigger) noexcept
  {
    return reinterpret_cast<moho::SCondition*>(trigger->mPad30);
  }

  void DestroyConditionCategoryBits(moho::SCondition& condition)
  {
    // Address: 0x00711B80 (FUN_00711B80, sub_711B80) inner lane.
    condition.mCat.mBits.mWords.ResetStorageToInline();
  }

  void DestroyConditionRange(moho::SCondition* begin, moho::SCondition* end)
  {
    // Address: 0x00711B80 (FUN_00711B80, sub_711B80).
    while (begin && end && begin != end) {
      DestroyConditionCategoryBits(*begin);
      ++begin;
    }
  }

  void DestroySTriggerState(moho::STrigger* const trigger)
  {
    // Address: 0x00711A90 (FUN_00711A90, sub_711A90).
    if (!trigger) {
      return;
    }

    DestroyConditionRange(trigger->mConditions.begin, trigger->mConditions.end);

    moho::SCondition* const inlineBegin = reinterpret_cast<moho::SCondition*>(trigger->mConditions.metadata);
    if (trigger->mConditions.begin != inlineBegin) {
      delete[] trigger->mConditions.begin;
      trigger->mConditions.begin = inlineBegin;
      trigger->mConditions.capacityEnd = inlineBegin ? *reinterpret_cast<moho::SCondition* const*>(inlineBegin) : nullptr;
    }
    trigger->mConditions.end = trigger->mConditions.begin;
    trigger->mName.tidy(true, 0U);
  }
} // namespace

namespace moho
{
  gpg::RType* SCondition::sType = nullptr;
  gpg::RType* STrigger::sType = nullptr;

  gpg::RType* SCondition::StaticGetClass()
  {
    return CachedType<SCondition>(sType);
  }

  gpg::RType* STrigger::StaticGetClass()
  {
    return CachedType<STrigger>(sType);
  }

  /**
   * Address: 0x00712300 (FUN_00712300, Moho::SCondition::MemberDeserialize)
   */
  void SCondition::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (!tracked.object) {
      mItem = nullptr;
    } else {
      gpg::RRef sourceRef{};
      sourceRef.mObj = tracked.object;
      sourceRef.mType = tracked.type ? tracked.type : CArmyStatItem::StaticGetClass();
      const gpg::RRef upcastRef = gpg::REF_UpcastPtr(sourceRef, CArmyStatItem::StaticGetClass());
      mItem = static_cast<CArmyStatItem*>(upcastRef.mObj ? upcastRef.mObj : tracked.object);
    }

    archive->Read(CachedType<ETriggerOperator>(gETriggerOperatorType), &mOp, gpg::RRef{});
    archive->Read(CachedType<BVSet<const RBlueprint*, EntityCategoryHelper>>(gSConditionCategorySetType), &mCat, gpg::RRef{});
    archive->ReadFloat(&mVal);
  }

  /**
   * Address: 0x007123B0 (FUN_007123B0, Moho::SCondition::MemberSerialize)
   */
  void SCondition::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RRef itemRef{};
    itemRef.mObj = mItem;
    itemRef.mType = CArmyStatItem::StaticGetClass();
    gpg::WriteRawPointer(archive, itemRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    archive->Write(CachedType<ETriggerOperator>(gETriggerOperatorType), &mOp, gpg::RRef{});
    archive->Write(
      CachedType<BVSet<const RBlueprint*, EntityCategoryHelper>>(gSConditionCategorySetType), &mCat, gpg::RRef{}
    );
    archive->WriteFloat(mVal);
  }

  /**
   * Address: 0x00711030 / 0x007110F0 (FUN_00711030 / FUN_007110F0)
   */
  STrigger::STrigger()
    : mName()
    , mConditions{}
  {
    // Address: 0x00711030 / 0x007110F0 (FUN_00711030 / FUN_007110F0).
    SCondition* const inlineBegin = InlineConditionBuffer(this);
    mConditions.begin = inlineBegin;
    mConditions.end = inlineBegin;
    mConditions.capacityEnd = inlineBegin + kTriggerInlineConditionCount;
    mConditions.metadata = inlineBegin;
  }

  /**
   * Address: 0x00711A90 (FUN_00711A90, sub_711A90)
   */
  STrigger::~STrigger()
  {
    DestroySTriggerState(this);
  }

  /**
   * Address: 0x00712460 (FUN_00712460, Moho::STrigger::MemberDeserialize)
   */
  void STrigger::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->ReadString(&mName);
    archive->Read(CachedType<gpg::fastvector<SCondition>>(gFastVectorSConditionType), &mConditions, gpg::RRef{});
  }

  /**
   * Address: 0x007124B0 (FUN_007124B0, Moho::STrigger::MemberSerialize)
   */
  void STrigger::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->WriteString(const_cast<msvc8::string*>(&mName));
    archive->Write(CachedType<gpg::fastvector<SCondition>>(gFastVectorSConditionType), &mConditions, gpg::RRef{});
  }
} // namespace moho
