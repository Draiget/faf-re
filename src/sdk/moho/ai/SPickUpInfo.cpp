#include "moho/ai/SPickUpInfo.h"

#include <cstddef>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  struct SPickUpInfoSerializerStartupNode
  {
    void* mVtable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoad = nullptr;   // +0x0C
    gpg::RType::save_func_t mSave = nullptr;   // +0x10
  };

  static_assert(
    offsetof(SPickUpInfoSerializerStartupNode, mHelperNext) == 0x04,
    "SPickUpInfoSerializerStartupNode::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SPickUpInfoSerializerStartupNode, mHelperPrev) == 0x08,
    "SPickUpInfoSerializerStartupNode::mHelperPrev offset must be 0x08"
  );
  static_assert(
    sizeof(SPickUpInfoSerializerStartupNode) == 0x14,
    "SPickUpInfoSerializerStartupNode size must be 0x14"
  );

  SPickUpInfoSerializerStartupNode gSPickUpInfoSerializerStartupNode{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(SPickUpInfoSerializerStartupNode& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(SPickUpInfoSerializerStartupNode& serializer) noexcept
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

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }
} // namespace

namespace moho
{
  gpg::RType* SPickUpInfo::sType = nullptr;

  SPickUpInfo::SPickUpInfo() noexcept
    : mUnit{}
    , mDistanceSq(0.0f)
  {}

  SPickUpInfo::SPickUpInfo(Unit* const unit, const float distanceSquared) noexcept
    : SPickUpInfo()
  {
    BindUnitAndDistanceSquared(unit, distanceSquared);
  }

  SPickUpInfo::SPickUpInfo(const SPickUpInfo& source) noexcept
    : SPickUpInfo()
  {
    mUnit.ResetFromOwnerLinkSlot(source.mUnit.ownerLinkSlot);
    mDistanceSq = source.mDistanceSq;
  }

  SPickUpInfo& SPickUpInfo::operator=(const SPickUpInfo& source) noexcept
  {
    if (this == &source) {
      return *this;
    }

    if (mUnit.ownerLinkSlot != source.mUnit.ownerLinkSlot) {
      mUnit.ResetFromOwnerLinkSlot(source.mUnit.ownerLinkSlot);
    }
    mDistanceSq = source.mDistanceSq;
    return *this;
  }

  SPickUpInfo::~SPickUpInfo()
  {
    UnlinkWeakUnitLane();
  }

  /**
   * Address: 0x006246A0 (FUN_006246A0)
   *
   * What it does:
   * Binds this entry's weak-unit link from `unit` and stores the provided
   * distance-squared lane.
   */
  void SPickUpInfo::BindUnitAndDistanceSquared(Unit* const unit, const float distanceSquared) noexcept
  {
    mUnit.BindObjectUnlinked(unit);
    (void)mUnit.LinkIntoOwnerChainHeadUnlinked();
    mDistanceSq = distanceSquared;
  }

  /**
   * Address: 0x00624AA0 (FUN_00624AA0)
   *
   * What it does:
   * Unlinks this entry from the current unit weak-owner intrusive chain.
   */
  void SPickUpInfo::UnlinkWeakUnitLane() noexcept
  {
    if (mUnit.IsLinkedInOwnerChain()) {
      (void)mUnit.ReplaceInOwnerChain(mUnit.nextInOwner);
    }
  }

  /**
   * Address: 0x00624870 (FUN_00624870, cleanup_SPickUpInfoSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the `SPickUpInfo` serializer helper
   * node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_SPickUpInfoSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gSPickUpInfoSerializerStartupNode);
  }

  /**
   * Address: 0x006248A0 (FUN_006248A0, cleanup_SPickUpInfoSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the `SPickUpInfo` serializer
   * helper node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_SPickUpInfoSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gSPickUpInfoSerializerStartupNode);
  }

  /**
   * Address: 0x00627EB0 (FUN_00627EB0)
   *
   * What it does:
   * Deserializes one pickup entry by reading weak-unit lane then distance.
   */
  void SPickUpInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
    GPG_ASSERT(weakUnitType != nullptr);

    const gpg::RRef ownerRef{};
    if (weakUnitType) {
      archive->Read(weakUnitType, &mUnit, ownerRef);
    }
    archive->ReadFloat(&mDistanceSq);
  }

  /**
   * Address: 0x00627F00 (FUN_00627F00)
   *
   * What it does:
   * Serializes one pickup entry by writing weak-unit lane then distance.
   */
  void SPickUpInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
    GPG_ASSERT(weakUnitType != nullptr);

    const gpg::RRef ownerRef{};
    if (weakUnitType) {
      archive->Write(weakUnitType, &mUnit, ownerRef);
    }
    archive->WriteFloat(mDistanceSq);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00628090 (FUN_00628090)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_SPickUpInfo` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignSPickUpInfoRef(gpg::RRef* const outRef, moho::SPickUpInfo* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)gpg::RRef_SPickUpInfo(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
