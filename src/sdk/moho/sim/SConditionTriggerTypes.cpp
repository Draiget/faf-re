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

  void DestroySTriggerState(moho::STrigger* const trigger)
  {
    // Alias of FUN_00711A90 (non-canonical helper lane).
    if (!trigger) {
      return;
    }

    // Destroys every live condition (`_Destroy_range`, 0x00711B80, cited on
    // FastVector.h's `DestroyRange`), releases a heap block the way the
    // vector allocated it and rebinds the inline window, then the name.
    trigger->mConditions.ResetStorageToInline();
    trigger->mName.tidy(true, 0U);
  }

  /**
   * Address: 0x00714850 (FUN_00714850)
   *
   * What it does:
   * Deleting-dtor thunk lane for `STrigger`: runs the canonical destructor
   * body and frees object storage when the pointer is non-null.
   */
  [[maybe_unused]] void DestroySTriggerAndFreeThunk(moho::STrigger* const trigger)
  {
    if (trigger == nullptr) {
      return;
    }

    trigger->~STrigger();
    ::operator delete(trigger);
  }

  // The `_Copy_backward` emissions for `SCondition` (0x00714850, 0x00713950)
  // and the jump thunks 0x00712840/0x00712870 are the tail-shift step of
  // `fastvector_n<SCondition, 2>::InsertAt` (0x0070FAD0); they are cited on
  // FastVector.h's `CopyBackwardAssign`, and `STrigger::mConditions` reaches
  // them through the template instead of a per-type copy here.
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
   * Address: 0x00711030 (FUN_00711030) / 0x007110F0 (FUN_00711030 / FUN_007110F0)
   */
  STrigger::STrigger()
    : mName()
    , mConditions()
  {
    // Address: 0x00711030 (FUN_00711030) / 0x007110F0 (FUN_00711030 / FUN_007110F0):
    // the empty name and the condition vector armed on its two inline slots,
    // which is `fastvector_n<SCondition, 2>`'s own constructor.
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
