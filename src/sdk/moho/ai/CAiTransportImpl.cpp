#include "moho/ai/CAiTransportImpl.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniSkel.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CMersenneTwister.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

using namespace moho;

/**
 * Address: 0x005E43A0 (FUN_005E43A0, Moho::STransportPickUpInfo::STransportPickUpInfo)
 *
 * What it does:
 * Initializes fallback position/orientation lanes and resets pickup-unit set
 * storage to an empty inline-backed state.
 */
STransportPickUpInfo::STransportPickUpInfo()
  : mFallbackPos{0.0f, 0.0f}
  , mOri(0.0f, 0.0f, 0.0f, 0.0f)
  , mPos(0.0f, 0.0f, 0.0f)
  , mReserved24(0)
  , mUnits()
  , mHasSpace(0)
{
  mUnits.ListResetLinks();
  mUnits.Clear();
}

bool STransportPickUpInfo::HasUnit(const Unit* const unit) const noexcept
{
  return mUnits.ContainsUnit(unit);
}

/**
 * Address: 0x005E4480 (FUN_005E4480, Moho::STransportPickUpInfo::AddUnit)
 *
 * What it does:
 * Finds the first pickup-entry matching `unit`, removes that slot from the
 * contiguous vector storage, and clears `mHasSpace` when the set is empty.
 */
void STransportPickUpInfo::RemoveUnit(Unit* const unit) noexcept
{
  Entity** const begin = mUnits.mVec.begin();
  Entity** const end = mUnits.mVec.end();
  for (Entity** it = begin; it != end; ++it) {
    if (SEntitySetTemplateUnit::UnitFromEntry(*it) == unit) {
      (void)mUnits.mVec.erase(it);
      break;
    }
  }

  if (mUnits.mVec.begin() == mUnits.mVec.end()) {
    mHasSpace = 0u;
  }
}

/**
 * Address: 0x005EBA40 (FUN_005EBA40, Moho::STransportPickUpInfo::MemberDeserialize)
 *
 * What it does:
 * Reads the fallback position (SCoordsVec2), orientation (Quaternionf),
 * world position (Vector3f), unit set (EntitySetTemplate<Unit>), and
 * has-space flag from the archive via cached RType lookups.
 */
void STransportPickUpInfo::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  static gpg::RType* const coordsType = gpg::LookupRType(typeid(SCoordsVec2));
  static gpg::RType* const quatType = gpg::LookupRType(typeid(Wm3::Quaternion<float>));
  static gpg::RType* const vecType = gpg::LookupRType(typeid(Wm3::Vector3<float>));
  static gpg::RType* const unitsType = gpg::LookupRType(typeid(SEntitySetTemplateUnit));

  const gpg::RRef ownerRef{};
  archive->Read(coordsType, &mFallbackPos, ownerRef);
  archive->Read(quatType, &mOri, ownerRef);
  archive->Read(vecType, &mPos, ownerRef);
  archive->Read(unitsType, &mUnits, ownerRef);

  bool hasSpace = false;
  archive->ReadBool(&hasSpace);
  mHasSpace = static_cast<std::uint8_t>(hasSpace ? 1 : 0);
}

/**
 * Address: 0x005EBB30 (FUN_005EBB30, Moho::STransportPickUpInfo::MemberSerialize)
 *
 * What it does:
 * Writes fallback position (SCoordsVec2), orientation (Quaternionf),
 * world position (Vector3f), unit set (EntitySetTemplate<Unit>), and
 * has-space flag to the archive via cached RType lookups.
 */
void STransportPickUpInfo::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  static gpg::RType* const coordsType = gpg::LookupRType(typeid(SCoordsVec2));
  static gpg::RType* const quatType = gpg::LookupRType(typeid(Wm3::Quaternion<float>));
  static gpg::RType* const vecType = gpg::LookupRType(typeid(Wm3::Vector3<float>));
  static gpg::RType* const unitsType = gpg::LookupRType(typeid(SEntitySetTemplateUnit));

  const gpg::RRef ownerRef{};
  archive->Write(coordsType, &mFallbackPos, ownerRef);
  archive->Write(quatType, &mOri, ownerRef);
  archive->Write(vecType, &mPos, ownerRef);
  archive->Write(unitsType, &mUnits, ownerRef);
  archive->WriteBool(mHasSpace != 0u);
}

namespace
{
  gpg::RType* gIAiTransportType = nullptr;
  gpg::RType* gCAiTransportImplType = nullptr;
  gpg::RType* gUnitType = nullptr;
  gpg::RType* gWeakPtrUnitType = nullptr;
  gpg::RType* gEntitySetTemplateUnitType = nullptr;
  gpg::RType* gReservedBoneVectorType = nullptr;
  gpg::RType* gPickupInfoType = nullptr;
  gpg::RType* gFormationInstanceType = nullptr;
  gpg::RType* gVector3fType = nullptr;
  gpg::RType* gAttachPointVectorType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* ResolveIAiTransportType()
  {
    if (!IAiTransport::sType) {
      IAiTransport::sType = CachedType<IAiTransport>(gIAiTransportType);
    }
    return IAiTransport::sType;
  }

  [[nodiscard]] gpg::RType* ResolveCAiTransportImplType()
  {
    if (!CAiTransportImpl::sType) {
      CAiTransportImpl::sType = CachedType<CAiTransportImpl>(gCAiTransportImplType);
    }
    return CAiTransportImpl::sType;
  }

  [[nodiscard]] gpg::RType* ResolveUnitType()
  {
    return CachedType<Unit>(gUnitType);
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    return CachedType<WeakPtr<Unit>>(gWeakPtrUnitType);
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetTemplateUnitType()
  {
    return CachedType<SEntitySetTemplateUnit>(gEntitySetTemplateUnitType);
  }

  [[nodiscard]] gpg::RType* ResolveReservedBoneVectorType()
  {
    return CachedType<msvc8::vector<SAiReservedTransportBone>>(gReservedBoneVectorType);
  }

  [[nodiscard]] gpg::RType* ResolvePickupInfoType()
  {
    return CachedType<STransportPickUpInfo>(gPickupInfoType);
  }

  [[nodiscard]] gpg::RType* ResolveFormationInstanceType()
  {
    return CachedType<IFormationInstance>(gFormationInstanceType);
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    return CachedType<Wm3::Vector3<float>>(gVector3fType);
  }

  [[nodiscard]] gpg::RType* ResolveAttachPointVectorType()
  {
    return CachedType<msvc8::vector<SAttachPoint>>(gAttachPointVectorType);
  }

  [[nodiscard]] bool BlueprintBelongsToCategory(
    const RUnitBlueprint* const blueprint,
    const CategoryWordRangeView* const category
  ) noexcept
  {
    if (!blueprint || !category) {
      return false;
    }

    return category->ContainsBit(static_cast<std::uint32_t>(blueprint->mCategoryBitIndex));
  }

  template <class TObject>
  [[nodiscard]] TObject* DecodeTrackedPointer(const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType)
  {
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.type && expectedType) {
      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
      return static_cast<TObject*>(upcast.mObj);
    }

    return static_cast<TObject*>(tracked.object);
  }

  template <class TObject>
  [[nodiscard]] TObject* ReadPointerUnowned(
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef,
    gpg::RType* const expectedType
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    return DecodeTrackedPointer<TObject>(tracked, expectedType);
  }

  template <class TObject>
  void WritePointerUnowned(
    gpg::WriteArchive* const archive,
    const TObject* const object,
    gpg::RType* const objectType,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RRef objectRef{};
    objectRef.mObj = const_cast<TObject*>(object);
    objectRef.mType = object ? objectType : nullptr;
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  [[nodiscard]] float DistSq(const Wm3::Vec3f& lhs, const Wm3::Vec3f& rhs) noexcept
  {
    const float dx = lhs.x - rhs.x;
    const float dy = lhs.y - rhs.y;
    const float dz = lhs.z - rhs.z;
    return (dx * dx) + (dy * dy) + (dz * dz);
  }

  [[nodiscard]] SAttachPoint*
  CopyAttachPointRangeNullable(SAttachPoint* destination, const SAttachPoint* sourceBegin, const SAttachPoint* sourceEnd) noexcept;

  /**
   * Address: 0x005EE110 (FUN_005EE110, func_CopyAttachDataVector)
   *
   * What it does:
   * Copies one contiguous `SAttachPoint` range into destination storage and
   * returns the advanced destination cursor.
   */
  [[nodiscard]] SAttachPoint*
  CopyAttachPointRange(SAttachPoint* destination, const SAttachPoint* sourceBegin, const SAttachPoint* sourceEnd) noexcept
  {
    return CopyAttachPointRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EC510 (FUN_005EC510, func_SAttachPointPtr_memcpy)
   *
   * What it does:
   * Adapts the VC8 vector-copy calling lane `(end, start, dest)` into the
   * typed contiguous attach-point range copy helper call shape.
   */
  [[nodiscard]] SAttachPoint* CopyAttachPointRangeAdapter(
    const SAttachPoint* sourceEnd,
    const SAttachPoint* sourceBegin,
    SAttachPoint* destination
  ) noexcept
  {
    return CopyAttachPointRange(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EF610 (FUN_005EF610, std::vector_SAttachPoint::copy_helper)
   * Address: 0x005EF660 (FUN_005EF660, func_SAttachPointPtr::memcpy)
   *
   * What it does:
   * Copies one contiguous `SAttachPoint` range into destination storage when
   * destination is non-null; still advances and returns the destination cursor.
   */
  [[nodiscard]] SAttachPoint* CopyAttachPointRangeNullable(
    SAttachPoint* destination,
    const SAttachPoint* sourceBegin,
    const SAttachPoint* sourceEnd
  ) noexcept
  {
    const SAttachPoint* source = sourceBegin;
    while (source != sourceEnd) {
      if (destination != nullptr) {
        destination->index = source->index;
        destination->localPos.x = source->localPos.x;
        destination->localPos.y = source->localPos.y;
        destination->localPos.z = source->localPos.z;
        destination->distSq = source->distSq;
      }

      ++source;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x005EC4B0 (FUN_005EC4B0)
   * Address: 0x005EE0C0 (FUN_005EE0C0)
   *
   * What it does:
   * Adapter lane that forwards contiguous `SAttachPoint` range copy requests
   * into the canonical vector copy helper.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* CopyAttachPointRangeVectorCopyHelperAdapter(
    const SAttachPoint* sourceBegin,
    const SAttachPoint* sourceEnd,
    SAttachPoint* destination
  ) noexcept
  {
    return CopyAttachPointRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005F04B0 (FUN_005F04B0)
   *
   * What it does:
   * Copies one contiguous 32-bit lane range `[sourceBegin, sourceEnd)` into
   * destination storage and returns one-past the copied destination cursor.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullable(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (const std::uint32_t* source = sourceBegin; source != sourceEnd; ++source) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<std::uint32_t*>(destinationAddress) = *source;
      }
      destinationAddress += sizeof(std::uint32_t);
    }

    return reinterpret_cast<std::uint32_t*>(destinationAddress);
  }

  /**
   * Address: 0x005EC8E0 (FUN_005EC8E0)
   * Address: 0x005EE4A0 (FUN_005EE4A0)
   *
   * What it does:
   * Adapter lane that forwards contiguous dword range copy requests into the
   * canonical nullable dword-range helper.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableAdapter(
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd,
    std::uint32_t* destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EF720 (FUN_005EF720)
   *
   * What it does:
   * Source-first adapter lane for one nullable contiguous dword-range copy
   * dispatch.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableSourceFirstAdapter(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005F0590 (FUN_005F0590)
   *
   * What it does:
   * Alternate lane for contiguous `SAttachPoint` range copy used by transport
   * attach-point vector helpers.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* CopyAttachPointRangeNullableAlt(
    SAttachPoint* destination,
    const SAttachPoint* sourceBegin,
    const SAttachPoint* sourceEnd
  ) noexcept
  {
    return CopyAttachPointRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EC9B0 (FUN_005EC9B0)
   * Address: 0x005EE590 (FUN_005EE590)
   *
   * What it does:
   * Adapter lane that forwards contiguous attach-point range copy requests into
   * the alternate nullable attach-point helper.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* CopyAttachPointRangeNullableAltAdapter(
    const SAttachPoint* sourceBegin,
    const SAttachPoint* sourceEnd,
    SAttachPoint* destination
  ) noexcept
  {
    return CopyAttachPointRangeNullableAlt(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EF780 (FUN_005EF780)
   * Address: 0x005EFEA0 (FUN_005EFEA0)
   *
   * What it does:
   * Source-first adapter lane for contiguous nullable `SAttachPoint` range
   * copy dispatch into the alternate helper.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* CopyAttachPointRangeNullableAltSourceFirstAdapter(
    const SAttachPoint* const sourceBegin,
    const SAttachPoint* const sourceEnd,
    SAttachPoint* const destination
  ) noexcept
  {
    return CopyAttachPointRangeNullableAlt(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EF7B0 (FUN_005EF7B0)
   *
   * What it does:
   * Register-shape adapter lane that forwards one contiguous nullable
   * `SAttachPoint` range copy dispatch into `func_SAttachPointPtr::memcpy`.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* CopyAttachPointRangeNullableRegisterAdapter(
    SAttachPoint* const destination,
    const SAttachPoint* const sourceBegin,
    const SAttachPoint* const sourceEnd
  ) noexcept
  {
    return CopyAttachPointRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EE150 (FUN_005EE150)
   * Address: 0x005EE5C0 (FUN_005EE5C0)
   *
   * What it does:
   * Adapter lane that forwards contiguous attach-point range copy requests into
   * the canonical nullable attach-point helper.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* CopyAttachPointRangeNullableAdapter(
    const SAttachPoint* sourceBegin,
    const SAttachPoint* sourceEnd,
    SAttachPoint* destination
  ) noexcept
  {
    return CopyAttachPointRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005EC4E0 (FUN_005EC4E0)
   * Address: 0x005EC9E0 (FUN_005EC9E0)
   *
   * What it does:
   * Adapts one `(sourceEnd, sourceBegin, destination)` lane into the canonical
   * attach-point contiguous copy helper.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* CopyAttachPointRangeAdapterReversed(
    SAttachPoint* const sourceEnd,
    SAttachPoint* const sourceBegin,
    SAttachPoint* const destination
  ) noexcept
  {
    return CopyAttachPointRange(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005E9A90 (FUN_005E9A90)
   *
   * What it does:
   * Resets one `vector<SAttachPoint>` logical size to zero while preserving
   * allocated storage.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint* ResetAttachPointVectorUsedRange(msvc8::vector<SAttachPoint>& storage) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (view.begin != view.end) {
      view.end = CopyAttachPointRange(view.begin, view.end, view.end);
    }

    return view.end;
  }

  /**
   * Address: 0x005EA930 (FUN_005EA930)
   *
   * What it does:
   * Compacts one erased attach-point range by copying `[eraseEnd, end)` into
   * `eraseBegin`, updates vector end, and returns `outCursor`.
   */
  [[maybe_unused]] [[nodiscard]] SAttachPoint** EraseAttachPointRangeAndReturnCursor(
    SAttachPoint** const outCursor,
    msvc8::vector<SAttachPoint>& storage,
    SAttachPoint* const eraseBegin,
    SAttachPoint* const eraseEnd
  ) noexcept
  {
    if (eraseBegin != eraseEnd) {
      auto& view = msvc8::AsVectorRuntimeView(storage);
      view.end = CopyAttachPointRange(eraseBegin, eraseEnd, view.end);
    }

    *outCursor = eraseBegin;
    return outCursor;
  }

  /**
   * Address: 0x005E9CF0 (FUN_005E9CF0)
   *
   * What it does:
   * Removes one `int` lane at `erasePos` from contiguous vector storage,
   * compacts the tail with `memmove_s`, updates the active end lane, and
   * returns the erased-position cursor.
   */
  [[maybe_unused]] [[nodiscard]] int* EraseIntVectorElementAndReturnCursor(
    msvc8::vector<int>& storage,
    int* const erasePos
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    int* const activeEnd = view.end;

    if (erasePos != activeEnd) {
      int* const moveSource = erasePos + 1;
      const std::ptrdiff_t remaining = activeEnd - moveSource;
      if (remaining > 0) {
        const std::size_t bytes = static_cast<std::size_t>(remaining) * sizeof(int);
        (void)memmove_s(erasePos, bytes, moveSource, bytes);
      }

      view.end = erasePos + remaining;
    }

    return erasePos;
  }

  /**
   * Address: 0x005F05E0 (FUN_005F05E0, func_BinaryInsertAttachDataAtLowest)
   *
   * What it does:
   * Inserts one attach-point record into the heap window
   * `[lowerBoundIndex, upperSearchIndex]` by bubbling parent lanes downward
   * until `data.distSq` no longer exceeds the parent distance.
   */
  [[maybe_unused]] void InsertAttachPointIntoMaxHeapWindow(
    int upperSearchIndex,
    const int lowerBoundIndex,
    SAttachPoint* const vec,
    const SAttachPoint& data
  ) noexcept
  {
    int parentIndex = (upperSearchIndex - 1) / 2;
    while (lowerBoundIndex < upperSearchIndex) {
      SAttachPoint* const parent = &vec[parentIndex];
      if (data.distSq <= parent->distSq) {
        break;
      }

      vec[upperSearchIndex] = *parent;
      upperSearchIndex = parentIndex;
      parentIndex = (parentIndex - 1) / 2;
    }

    vec[upperSearchIndex] = data;
  }

  /**
   * Address: 0x005F0330 (FUN_005F0330, func_AttachDataInsert)
   *
   * What it does:
   * Sifts one attach-point heap lane downward from `lower` within `[0, upper)`,
   * then re-inserts `data` at the final position via parent-walk insertion.
   */
  [[maybe_unused]] void SiftDownAttachPointHeapAndInsert(
    int lower,
    const int upper,
    SAttachPoint* const vec,
    const SAttachPoint& data
  ) noexcept
  {
    int childIndex = (2 * lower) + 2;
    const int lowerStart = lower;
    bool childEqualsUpper = (childIndex == upper);

    while (childIndex < upper) {
      if (vec[childIndex - 1].distSq > vec[childIndex].distSq) {
        --childIndex;
      }

      vec[lower] = vec[childIndex];
      lower = childIndex;
      childIndex = (2 * childIndex) + 2;
      childEqualsUpper = (childIndex == upper);
    }

    if (childEqualsUpper) {
      vec[lower] = vec[upper - 1];
      lower = upper - 1;
    }

    InsertAttachPointIntoMaxHeapWindow(lower, lowerStart, vec, data);
  }

  /**
   * Address: 0x005F0810 (FUN_005F0810, sub_5F0810)
   *
   * What it does:
   * Copies the current heap-root attach-point into `poppedOut`, then restores
   * heap ordering by sifting `inserted` down across `[begin, end)`.
   */
  [[maybe_unused]] void PopAttachPointHeapRootAndInsert(
    SAttachPoint* const begin,
    SAttachPoint* const end,
    SAttachPoint* const poppedOut,
    const SAttachPoint& inserted
  ) noexcept
  {
    if (begin == nullptr || end == nullptr || poppedOut == nullptr || begin == end) {
      return;
    }

    *poppedOut = *begin;
    SiftDownAttachPointHeapAndInsert(0, static_cast<int>(end - begin), begin, inserted);
  }

  /**
   * Address: 0x005F0680 (FUN_005F0680)
   *
   * What it does:
   * Adapts one heap pop lane by using the last element (`end - 1`) as both
   * output slot and inserted replacement payload for
   * `PopAttachPointHeapRootAndInsert`.
   */
  [[maybe_unused]] void PopAttachPointHeapRootIntoTailSlotAdapter(
    SAttachPoint* const begin,
    SAttachPoint* const end
  ) noexcept
  {
    SAttachPoint* const tailSlot = end - 1;
    const SAttachPoint inserted = *tailSlot;
    PopAttachPointHeapRootAndInsert(begin, tailSlot, tailSlot, inserted);
  }

  /**
   * Address: 0x005EFB50 (FUN_005EFB50, sub_5EFB50)
   *
   * What it does:
   * Repeatedly pops the heap root into the shrinking tail lane of one
   * contiguous attach-point heap window until at most one element remains.
   */
  [[maybe_unused]] int PopAttachPointHeapRootsIntoSortedTail(
    SAttachPoint* const begin,
    SAttachPoint* end
  ) noexcept
  {
    int remaining = static_cast<int>(end - begin);
    while (remaining > 1) {
      SAttachPoint* const tailSlot = end - 1;
      const SAttachPoint inserted = *tailSlot;
      PopAttachPointHeapRootAndInsert(begin, tailSlot, tailSlot, inserted);
      end = tailSlot;
      remaining = static_cast<int>(end - begin);
    }
    return remaining;
  }

  /**
   * Address: 0x005EED90 (FUN_005EED90, sub_5EED90)
   *
   * What it does:
   * Tail-forwards one attach-point heap-sort thunk lane into
   * `PopAttachPointHeapRootsIntoSortedTail`.
   */
  [[maybe_unused]] int PopAttachPointHeapRootsIntoSortedTailThunk(
    SAttachPoint* const begin,
    SAttachPoint* const end
  ) noexcept
  {
    return PopAttachPointHeapRootsIntoSortedTail(begin, end);
  }

  /**
   * Address: 0x005EEDA0 (FUN_005EEDA0, func_CombSortAttachData_Small)
   *
   * What it does:
   * Sorts a small contiguous attach-point span by ascending `distSq` using the
   * same insertion-shift semantics as the binary small-range fallback lane.
   */
  [[maybe_unused]] void SortSmallAttachPointRangeByDistance(SAttachPoint* const start, SAttachPoint* const end) noexcept
  {
    if (start == nullptr || end == nullptr || start == end) {
      return;
    }

    for (SAttachPoint* current = start + 1; current != end; ++current) {
      const SAttachPoint value = *current;
      SAttachPoint* cursor = current;
      while (cursor != start && (cursor - 1)->distSq > value.distSq) {
        *cursor = *(cursor - 1);
        --cursor;
      }
      if (cursor != current) {
        *cursor = value;
      }
    }
  }

  /**
   * Address: 0x005EFAD0 (FUN_005EFAD0, func_SortAttachData2)
   *
   * What it does:
   * Heapifies the attach-point range by replaying every parent lane from the
   * middle of the range down to zero through `SiftDownAttachPointHeapAndInsert`.
   */
  [[maybe_unused]] void BuildAttachPointMaxHeap(SAttachPoint* const start, SAttachPoint* const end) noexcept
  {
    const int upper = static_cast<int>(end - start);
    int parentIndex = upper / 2;
    while (parentIndex > 0) {
      --parentIndex;
      const SAttachPoint node = start[parentIndex];
      SiftDownAttachPointHeapAndInsert(parentIndex, upper, start, node);
    }
  }

  /**
   * Address: 0x005EED50 (FUN_005EED50)
   *
   * What it does:
   * Calls the attach-point heap-build helper only when the source span holds
   * at least two elements.
   */
  [[maybe_unused]] void BuildAttachPointMaxHeapIfMultiElement(
    SAttachPoint* const start,
    SAttachPoint* const end
  ) noexcept
  {
    if ((end - start) > 1) {
      BuildAttachPointMaxHeap(start, end);
    }
  }

  /**
   * Address: 0x005F06C0 (FUN_005F06C0, func_CombSortAttachData)
   *
   * What it does:
   * Rotates one attach-point range `[start, end)` so `tooth` becomes the new
   * front, using the original cycle decomposition by `gcd(distance, shift)`.
   */
  [[maybe_unused]] void RotateAttachPointRangeByGcdCycles(
    SAttachPoint* const start,
    SAttachPoint* const tooth,
    SAttachPoint* const end
  ) noexcept
  {
    const int shift = static_cast<int>(tooth - start);
    const int distance = static_cast<int>(end - start);

    int cycleCount = distance;
    int remainder = shift;
    while (remainder != 0) {
      const int nextRemainder = cycleCount % remainder;
      cycleCount = remainder;
      remainder = nextRemainder;
    }

    if (!(cycleCount > 0 && cycleCount < distance)) {
      return;
    }

    SAttachPoint* cycleStart = start + cycleCount;
    for (int remainingCycles = cycleCount; remainingCycles > 0; --remainingCycles, --cycleStart) {
      const SAttachPoint carried = *cycleStart;
      SAttachPoint* current = cycleStart;
      SAttachPoint* next = (current + shift == end) ? start : (current + shift);

      while (next != cycleStart) {
        *current = *next;
        current = next;

        const int separationToEnd = static_cast<int>(end - current);
        if (shift >= separationToEnd) {
          next = start + (shift - separationToEnd);
        } else {
          next = current + shift;
        }
      }

      *current = carried;
    }
  }

  /**
   * Address: 0x005F0480 (FUN_005F0480)
   *
   * What it does:
   * Adapter lane that forwards one attach-point rotate dispatch into the
   * canonical gcd-cycle rotator.
   */
  [[maybe_unused]] void RotateAttachPointRangeByGcdCyclesAdapter(
    SAttachPoint* const start,
    SAttachPoint* const tooth,
    SAttachPoint* const end
  ) noexcept
  {
    RotateAttachPointRangeByGcdCycles(start, tooth, end);
  }

  /**
   * Address: 0x005EFBE0 (FUN_005EFBE0)
   *
   * What it does:
   * Guarded adapter lane for attach-point rotate dispatch; executes only when
   * `start != tooth` and `tooth != end`.
   */
  [[maybe_unused]] void RotateAttachPointRangeByGcdCyclesGuardedAdapter(
    SAttachPoint* const start,
    SAttachPoint* const tooth,
    SAttachPoint* const end
  ) noexcept
  {
    if (start == tooth || tooth == end) {
      return;
    }

    RotateAttachPointRangeByGcdCycles(start, tooth, end);
  }

  /**
   * Address: 0x00405050 (FUN_00405050, func_max)
   *
   * What it does:
   * Returns the greater integer value.
   */
  [[nodiscard]] int MaxInt(const int lhs, const int rhs) noexcept
  {
    if (lhs < rhs) {
      return rhs;
    }
    return lhs;
  }

  [[nodiscard]] Wm3::Vec3f ForwardFromOrientation(const Wm3::Quatf& orient) noexcept
  {
    return Wm3::Vec3f(
      ((orient.x * orient.z) + (orient.w * orient.y)) * 2.0f,
      ((orient.w * orient.z) - (orient.x * orient.y)) * 2.0f,
      1.0f - (((orient.z * orient.z) + (orient.y * orient.y)) * 2.0f)
    );
  }

  [[nodiscard]] Wm3::Vec3f NormalizeXZ(Wm3::Vec3f vec) noexcept
  {
    vec.y = 0.0f;
    const float lenSq = (vec.x * vec.x) + (vec.z * vec.z);
    if (lenSq <= 1.0e-6f) {
      return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    }
    const float invLen = 1.0f / std::sqrt(lenSq);
    vec.x *= invLen;
    vec.z *= invLen;
    return vec;
  }

  [[nodiscard]] Wm3::Quatf OrientationFromForward(const Wm3::Vec3f& forward) noexcept
  {
    const float lenSq = (forward.x * forward.x) + (forward.y * forward.y) + (forward.z * forward.z);
    if (lenSq <= 1.0e-6f) {
      return Wm3::Quatf(0.0f, 0.0f, 0.0f, 0.0f);
    }

    const float yaw = std::atan2(forward.x, forward.z);
    const float halfYaw = yaw * 0.5f;
    return Wm3::Quatf(std::cos(halfYaw), 0.0f, std::sin(halfYaw), 0.0f);
  }

  [[nodiscard]] SOCellPos InvalidCellPos() noexcept
  {
    SOCellPos out{};
    out.x = static_cast<std::int16_t>(0x8000);
    out.z = static_cast<std::int16_t>(0x8000);
    return out;
  }

  [[nodiscard]] SOCellPos CellPosFromWorldForUnit(const Wm3::Vec3f& worldPos, const Unit* const unit) noexcept
  {
    if (!unit) {
      return InvalidCellPos();
    }

    const SFootprint& footprint = unit->GetFootprint();
    const int x = static_cast<int>(worldPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    const int z = static_cast<int>(worldPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));

    SOCellPos out{};
    out.x = static_cast<std::int16_t>(x);
    out.z = static_cast<std::int16_t>(z);
    return out;
  }

  [[nodiscard]] const CAniSkel* ResolveUnitSkeleton(const Unit* const unit, boost::shared_ptr<const CAniSkel>& holdSkel)
  {
    holdSkel = {};
    if (!unit || !unit->AniActor) {
      return nullptr;
    }

    holdSkel = unit->AniActor->GetSkeleton();
    return holdSkel.get();
  }

  [[nodiscard]] const SAniSkelBone* ResolveUnitBoneByIndex(const Unit* const unit, const unsigned int boneIndex)
  {
    boost::shared_ptr<const CAniSkel> holdSkel{};
    const CAniSkel* const skeleton = ResolveUnitSkeleton(unit, holdSkel);
    if (!skeleton) {
      return nullptr;
    }

    return skeleton->GetBone(boneIndex);
  }

  /**
   * Address: 0x005E8A30 (sub_5E8A30)
   *
   * What it does:
   * Broadcasts one transport event to intrusive listeners while preserving
   * safe iteration semantics when listeners mutate registration.
   */
  void BroadcastTransportEvent(IAiTransport& transport, const EAiTransportEvent event)
  {
    Broadcaster* const head = static_cast<Broadcaster*>(&transport);
    if (!head || head->ListIsSingleton()) {
      return;
    }

    Broadcaster pending{};
    head->move_nodes_to(pending);

    while (auto* pendingNode = pending.pop_front()) {
      auto* const node = static_cast<Broadcaster*>(pendingNode);
      head->push_back(node);
      if (auto* const listener = IAiTransportEventListener::FromListenerLink(node)) {
        listener->OnTransportEvent(event);
      }
    }
  }

  /**
   * Address: 0x005EBD60 (sub_5EBD60)
   * Address: 0x005ED7D0 (func_LuaCallObjOObj_0 helper chain)
   *
   * What it does:
   * Invokes a transport script callback (`OnTransportAttach` / `OnTransportDetach`)
   * with bone-name string and optional payload unit Lua object.
   */
  void InvokeTransportBoneScriptCallback(
    Unit* const transportUnit,
    const char* const callbackName,
    const SAniSkelBone* const bone,
    Unit* const payloadUnit
  )
  {
    if (!transportUnit || !callbackName || !bone || !bone->mBoneName) {
      return;
    }

    const char* const boneName = bone->mBoneName;
    LuaPlus::LuaObject* const payloadObj = payloadUnit ? &payloadUnit->mLuaObj : nullptr;
    transportUnit->LuaPCall(callbackName, &boneName, payloadObj);
  }

  /**
   * Address: 0x005E3ED0 (FUN_005E3ED0, sub_5E3ED0)
   *
   * What it does:
   * Initializes one reserved-transport-bone payload from transport/attach
   * indices, links the weak-unit lane, copies one reserved-bone vector payload,
   * and returns the destination entry pointer.
   */
  [[maybe_unused]] SAiReservedTransportBone* InitReservedTransportBoneEntry(
    const unsigned int transportBoneIndex,
    const unsigned int attachBoneIndex,
    SAiReservedTransportBone* const destination,
    Unit* const reservedUnit,
    msvc8::vector<int> reservedBones
  )
  {
    destination->transportBoneIndex = transportBoneIndex;
    destination->attachBoneIndex = attachBoneIndex;
    destination->reservedUnit.ResetFromObject(reservedUnit);
    destination->reservedBones = reservedBones;
    return destination;
  }

} // namespace

gpg::RType* CAiTransportImpl::sType = nullptr;

/**
 * Address: 0x005E5300 (FUN_005E5300, Moho::CAiTransportImpl::CAiTransportImpl)
 * Address: 0x005E5670 (FUN_005E5670, Moho::CAiTransportImpl::CAiTransportImpl)
 * Mangled: ??0CAiTransportImpl@Moho@@AAE@XZ
 * Mangled: ??0CAiTransportImpl@Moho@@QAE@PAVUnit@1@@Z
 *
 * What it does:
 * Builds baseline transport state and, for unit-bound construction, resolves
 * staging/teleport category flags and links transport entity sets into the sim DB.
 */
CAiTransportImpl::CAiTransportImpl(Unit* const unit)
  : IAiTransport()
  , mUnit(unit)
  , mTeleportBeacon()
  , mStagingPlatform(0)
  , mTeleportation(0)
  , mUnknown1A{0, 0}
  , mAttachpoints(0)
  , mNextGeneric(0)
  , mLaunchAttachIndex(0)
  , mGenericOverflow(0)
  , mUnknown2C{0, 0, 0, 0}
  , mUnitSet30()
  , mStoredUnits()
  , mUnitSet80()
  , mReservedBones()
  , mPickupInfo()
  , mWaitingFormation(nullptr)
  , mPickupFacing(0.0f, 0.0f, 0.0f)
  , mGenericAttachPoints()
  , mClass1AttachPoints()
  , mClass2AttachPoints()
  , mClass3AttachPoints()
  , mClass4AttachPoints()
  , mClassSAttachPoints()
  , mLaunchAttachPoints()
{
  SetUpAttachPoints();

  if (!mUnit) {
    return;
  }

  Sim* const sim = mUnit->SimulationRef;
  if (!sim) {
    return;
  }

  if (sim->mRules) {
    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
    const CategoryWordRangeView* const airStagingCategory = sim->mRules->GetEntityCategory("AIRSTAGINGPLATFORM");
    const CategoryWordRangeView* const podStagingCategory = sim->mRules->GetEntityCategory("PODSTAGINGPLATFORM");
    const bool isStagingTransport =
      BlueprintBelongsToCategory(blueprint, airStagingCategory) ||
      BlueprintBelongsToCategory(blueprint, podStagingCategory);
    mStagingPlatform = static_cast<std::uint8_t>(isStagingTransport ? 1u : 0u);

    const CategoryWordRangeView* const teleportCategory = sim->mRules->GetEntityCategory("TELEPORTATION");
    mTeleportation = static_cast<std::uint8_t>(BlueprintBelongsToCategory(blueprint, teleportCategory) ? 1u : 0u);
  }

  if (sim->mEntityDB) {
    sim->mEntityDB->RegisterEntitySet(mPickupInfo.mUnits);
    sim->mEntityDB->RegisterEntitySet(mUnitSet30);
    sim->mEntityDB->RegisterEntitySet(mStoredUnits);
    sim->mEntityDB->RegisterEntitySet(mUnitSet80);
  }
}

/**
 * Address: 0x005E5C10 (FUN_005E5C10, core dtor)
 *
 * What it does:
 * Releases runtime waiting-formation state and destroys any still-live units
 * currently tracked in transport storage before normal member/base teardown.
 */
CAiTransportImpl::~CAiTransportImpl()
{
  TransportClearWaitingFormation();

  Entity* const* it = mStoredUnits.mVec.begin();
  Entity* const* const end = mStoredUnits.mVec.end();
  for (; it != end; ++it) {
    Unit* const storedUnit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!storedUnit || storedUnit->IsDead()) {
      continue;
    }

    static_cast<Entity*>(storedUnit)->Destroy();
  }
}

/**
 * Address: 0x005E8500 (FUN_005E8500, Moho::CAiTransportImpl::MemberConstruct)
 *
 * What it does:
 * Allocates one `CAiTransportImpl` object and publishes it via
 * `SerConstructResult::SetUnowned`.
 */
void CAiTransportImpl::MemberConstruct(gpg::SerConstructResult* const result)
{
  CAiTransportImpl* const object = new (std::nothrow) CAiTransportImpl{};
  if (!result) {
    return;
  }

  gpg::RRef objectRef{};
  objectRef.mObj = object;
  objectRef.mType = ResolveCAiTransportImplType();
  result->SetUnowned(objectRef, 0u);
}

/**
 * Address: 0x005EEE30 (FUN_005EEE30, Moho::CAiTransportImpl::MemberDeserialize)
 *
 * What it does:
 * Loads runtime transport state lanes from the read archive.
 */
void CAiTransportImpl::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const aiTransportType = ResolveIAiTransportType();
  GPG_ASSERT(aiTransportType != nullptr);
  archive->Read(aiTransportType, static_cast<IAiTransport*>(this), ownerRef);

  mUnit = ReadPointerUnowned<Unit>(archive, ownerRef, ResolveUnitType());

  gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
  GPG_ASSERT(weakUnitType != nullptr);
  archive->Read(weakUnitType, &mTeleportBeacon, ownerRef);

  bool boolValue = false;
  archive->ReadBool(&boolValue);
  mStagingPlatform = static_cast<std::uint8_t>(boolValue ? 1 : 0);
  archive->ReadBool(&boolValue);
  mTeleportation = static_cast<std::uint8_t>(boolValue ? 1 : 0);

  archive->ReadInt(&mAttachpoints);
  archive->ReadInt(&mNextGeneric);
  archive->ReadInt(&mLaunchAttachIndex);
  archive->ReadInt(&mGenericOverflow);

  gpg::RType* const entitySetType = ResolveEntitySetTemplateUnitType();
  GPG_ASSERT(entitySetType != nullptr);
  archive->Read(entitySetType, &mUnitSet30, ownerRef);
  archive->Read(entitySetType, &mStoredUnits, ownerRef);
  archive->Read(entitySetType, &mUnitSet80, ownerRef);

  gpg::RType* const reservedBoneVectorType = ResolveReservedBoneVectorType();
  GPG_ASSERT(reservedBoneVectorType != nullptr);
  archive->Read(reservedBoneVectorType, &mReservedBones, ownerRef);

  gpg::RType* const pickupInfoType = ResolvePickupInfoType();
  GPG_ASSERT(pickupInfoType != nullptr);
  archive->Read(pickupInfoType, &mPickupInfo, ownerRef);

  mWaitingFormation =
    ReadPointerUnowned<IFormationInstance>(archive, ownerRef, ResolveFormationInstanceType());

  gpg::RType* const vector3fType = ResolveVector3fType();
  GPG_ASSERT(vector3fType != nullptr);
  archive->Read(vector3fType, &mPickupFacing, ownerRef);

  gpg::RType* const attachPointVectorType = ResolveAttachPointVectorType();
  GPG_ASSERT(attachPointVectorType != nullptr);
  archive->Read(attachPointVectorType, &mGenericAttachPoints, ownerRef);
  archive->Read(attachPointVectorType, &mClass1AttachPoints, ownerRef);
  archive->Read(attachPointVectorType, &mClass2AttachPoints, ownerRef);
  archive->Read(attachPointVectorType, &mClass3AttachPoints, ownerRef);
  archive->Read(attachPointVectorType, &mClass4AttachPoints, ownerRef);
  archive->Read(attachPointVectorType, &mClassSAttachPoints, ownerRef);
  archive->Read(attachPointVectorType, &mLaunchAttachPoints, ownerRef);
}

/**
 * Address: 0x005EF1F0 (FUN_005EF1F0, Moho::CAiTransportImpl::MemberSerialize)
 *
 * What it does:
 * Saves runtime transport state lanes into the write archive.
 */
void CAiTransportImpl::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const aiTransportType = ResolveIAiTransportType();
  GPG_ASSERT(aiTransportType != nullptr);
  archive->Write(aiTransportType, static_cast<const IAiTransport*>(this), ownerRef);

  WritePointerUnowned(archive, mUnit, ResolveUnitType(), ownerRef);

  gpg::RType* const weakUnitType = ResolveWeakPtrUnitType();
  GPG_ASSERT(weakUnitType != nullptr);
  archive->Write(weakUnitType, &mTeleportBeacon, ownerRef);

  archive->WriteBool(mStagingPlatform != 0u);
  archive->WriteBool(mTeleportation != 0u);
  archive->WriteInt(mAttachpoints);
  archive->WriteInt(mNextGeneric);
  archive->WriteInt(mLaunchAttachIndex);
  archive->WriteInt(mGenericOverflow);

  gpg::RType* const entitySetType = ResolveEntitySetTemplateUnitType();
  GPG_ASSERT(entitySetType != nullptr);
  archive->Write(entitySetType, &mUnitSet30, ownerRef);
  archive->Write(entitySetType, &mStoredUnits, ownerRef);
  archive->Write(entitySetType, &mUnitSet80, ownerRef);

  gpg::RType* const reservedBoneVectorType = ResolveReservedBoneVectorType();
  GPG_ASSERT(reservedBoneVectorType != nullptr);
  archive->Write(reservedBoneVectorType, &mReservedBones, ownerRef);

  gpg::RType* const pickupInfoType = ResolvePickupInfoType();
  GPG_ASSERT(pickupInfoType != nullptr);
  archive->Write(pickupInfoType, &mPickupInfo, ownerRef);

  WritePointerUnowned(archive, mWaitingFormation, ResolveFormationInstanceType(), ownerRef);

  gpg::RType* const vector3fType = ResolveVector3fType();
  GPG_ASSERT(vector3fType != nullptr);
  archive->Write(vector3fType, &mPickupFacing, ownerRef);

  gpg::RType* const attachPointVectorType = ResolveAttachPointVectorType();
  GPG_ASSERT(attachPointVectorType != nullptr);
  archive->Write(attachPointVectorType, &mGenericAttachPoints, ownerRef);
  archive->Write(attachPointVectorType, &mClass1AttachPoints, ownerRef);
  archive->Write(attachPointVectorType, &mClass2AttachPoints, ownerRef);
  archive->Write(attachPointVectorType, &mClass3AttachPoints, ownerRef);
  archive->Write(attachPointVectorType, &mClass4AttachPoints, ownerRef);
  archive->Write(attachPointVectorType, &mClassSAttachPoints, ownerRef);
  archive->Write(attachPointVectorType, &mLaunchAttachPoints, ownerRef);
}

/**
 * Address: 0x005E60F0 (FUN_005E60F0)
 */
bool CAiTransportImpl::TransportIsAirStagingPlatform() const
{
  return mStagingPlatform != 0;
}

/**
 * Address: 0x005E6100 (FUN_005E6100)
 */
bool CAiTransportImpl::TransportIsTeleporter() const
{
  return mTeleportation != 0;
}

/**
 * Address: 0x005E6110 (FUN_005E6110)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetLoadedUnits(const bool includeFutureLoad) const
{
  EntitySetTemplate<Unit> out{};
  if (!mUnit) {
    return out;
  }

  const msvc8::vector<Entity*>& attached = mUnit->GetAttachedEntities();
  for (Entity* const* it = attached.begin(); it != attached.end(); ++it) {
    Unit* const attachedUnit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!attachedUnit) {
      continue;
    }

    if (attachedUnit->IsInCategory("UPGRADE")) {
      continue;
    }
    if (attachedUnit->IsUnitState(UNITSTATE_Refueling)) {
      continue;
    }
    if (includeFutureLoad && TransportIsStoredUnit(attachedUnit)) {
      continue;
    }

    (void)out.Add(attachedUnit);
  }

  return out;
}

/**
 * Address: 0x005E6260 (FUN_005E6260)
 */
void CAiTransportImpl::TransportAddPickupUnits(const EntitySetTemplate<Unit>& units, const SCoordsVec2 fallbackPos)
{
  for (Unit* const* it = units.begin(); it != units.end(); ++it) {
    Unit* const unit = *it;
    if (unit) {
      TransportRemovePickupUnit(unit, false);
    }
  }

  if (!mUnit) {
    return;
  }

  Wm3::Vec3f pickupFacing{};
  if (mAttachpoints == 1 && units.Size() == 1u) {
    Unit* const onlyUnit = SEntitySetTemplateUnit::UnitFromEntry(*units.begin());
    if (onlyUnit) {
      pickupFacing = ForwardFromOrientation(onlyUnit->GetTransform().orient_);
    }
  } else {
    const Wm3::Vec3f& transportPos = mUnit->GetPosition();
    pickupFacing = NormalizeXZ(Wm3::Vec3f(fallbackPos.x - transportPos.x, 0.0f, fallbackPos.z - transportPos.z));
  }

  mPickupFacing = pickupFacing;
  mPickupInfo.mFallbackPos = fallbackPos;
  mPickupInfo.mPos = Wm3::Vec3f(fallbackPos.x, mUnit->GetPosition().y, fallbackPos.z);
  mPickupInfo.mOri = OrientationFromForward(pickupFacing);
  mPickupInfo.mUnits.AddUnits(units);
  mPickupInfo.mHasSpace = 0;
}

/**
 * Address: 0x005E64A0 (FUN_005E64A0)
 */
void CAiTransportImpl::TransportRemovePickupUnit(Unit* const unit, const bool clearReservation)
{
  mPickupInfo.RemoveUnit(unit);
  if (clearReservation) {
    TransportRemoveUnitReservation(unit);
  }
}

namespace
{
  /**
   * Address: 0x005E9670 (FUN_005E9670)
   *
   * What it does:
   * Erases one reservation slot from `mReservedBones` and returns the next
   * iterator lane for erase-while-iterating loops.
   */
  [[nodiscard]] SAiReservedTransportBone* EraseReservedTransportBoneAndAdvance(
    msvc8::vector<SAiReservedTransportBone>& reservations,
    SAiReservedTransportBone* const it
  )
  {
    return reservations.erase(it);
  }
} // namespace

/**
 * Address: 0x005E64D0 (FUN_005E64D0)
 */
void CAiTransportImpl::TransportRemoveUnitReservation(Unit* const unit)
{
  for (SAiReservedTransportBone* it = mReservedBones.begin(); it != mReservedBones.end();) {
    Unit* const reserved = it->reservedUnit.GetObjectPtr();
    if (!reserved || reserved == unit) {
      it = EraseReservedTransportBoneAndAdvance(mReservedBones, it);
    } else {
      ++it;
    }
  }
}

/**
 * Address: 0x005E6530 (FUN_005E6530)
 */
void CAiTransportImpl::TransportUnreserveUnattachedSpots()
{
  for (SAiReservedTransportBone* it = mReservedBones.begin(); it != mReservedBones.end();) {
    Unit* const reserved = it->reservedUnit.GetObjectPtr();
    if (!reserved) {
      it = EraseReservedTransportBoneAndAdvance(mReservedBones, it);
      continue;
    }

    Unit* const transportedBy = reserved->TransportedByRef.ResolveObjectPtr<Unit>();
    if (transportedBy != mUnit) {
      it = EraseReservedTransportBoneAndAdvance(mReservedBones, it);
      continue;
    }

    ++it;
  }
}

/**
 * Address: 0x005E65A0 (FUN_005E65A0)
 */
unsigned int CAiTransportImpl::TransportGetPickupUnitCount() const
{
  return mPickupInfo.mUnits.CountLiveUnits();
}

/**
 * Address: 0x005E65F0 (FUN_005E65F0)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetPickupUnits()
{
  EntitySetTemplate<Unit> out{};
  mPickupInfo.mUnits.CopyTo(out);

  if (mWaitingFormation) {
    mUnitSet30.CopyLiveUnitsTo(out);
  }

  return out;
}

/**
 * Address: 0x005E6690 (FUN_005E6690)
 */
bool CAiTransportImpl::TransportIsUnitAssignedForPickup(Unit* const unit) const
{
  return mPickupInfo.HasUnit(unit);
}

/**
 * Address: 0x005E66B0 (FUN_005E66B0)
 */
SOCellPos CAiTransportImpl::TransportGetPickupUnitPos(Unit* const unit) const
{
  const SAiReservedTransportBone* const reservedBone = GetReservedBone(unit);
  if (!reservedBone || !mUnit) {
    return InvalidCellPos();
  }

  Wm3::Vec3f worldPos = mPickupInfo.mPos;
  if (mAttachpoints != 1) {
    const VTransform localTransform = mUnit->GetBoneLocalTransform(static_cast<int>(reservedBone->transportBoneIndex));
    const Wm3::Vec3f rotated = mPickupInfo.mOri.Rotate(localTransform.pos_);
    worldPos.x += rotated.x * 2.0f;
    worldPos.z += rotated.z * 2.0f;
  }

  return CellPosFromWorldForUnit(worldPos, unit);
}

/**
 * Address: 0x005E6870 (FUN_005E6870)
 */
bool CAiTransportImpl::TransportCanCarryUnit(Unit* const unit) const
{
  if (!unit || !unit->IsMobile()) {
    return false;
  }

  if (mStagingPlatform != 0) {
    if (!unit->mIsAir) {
      return false;
    }
  } else if (unit->mIsAir) {
    return false;
  }

  if (unit->IsInCategory("COMMAND") && (!mUnit || !mUnit->IsInCategory("CANTRANSPORTCOMMANDER"))) {
    return false;
  }

  if (!mUnit) {
    return false;
  }

  const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
  const RUnitBlueprint* const transportBlueprint = mUnit->GetBlueprint();
  if (!unitBlueprint || !transportBlueprint) {
    return false;
  }

  const int transportClass = unitBlueprint->Transport.TransportClass;
  if (transportBlueprint->Transport.ClassGenericUpTo >= transportClass && !mGenericAttachPoints.empty()) {
    return true;
  }

  const int attachCount = static_cast<int>(
    (transportBlueprint->Transport.ClassGenericUpTo != 0) ? mGenericAttachPoints.size() : mClass1AttachPoints.size()
  );

  switch (transportClass) {
    case 1:
      return attachCount > 0;
    case 2:
      return transportBlueprint->Transport.Class2AttachSize != 0 && attachCount >= transportBlueprint->Transport.Class2AttachSize;
    case 3:
      return transportBlueprint->Transport.Class3AttachSize != 0 && attachCount >= transportBlueprint->Transport.Class3AttachSize;
    case 4:
      return transportBlueprint->Transport.Class4AttachSize != 0 && attachCount > transportBlueprint->Transport.Class4AttachSize;
    default:
      return false;
  }
}

/**
 * Address: 0x005E5F10 (FUN_005E5F10)
 */
void CAiTransportImpl::TransportRemoveFromWaitingList(Unit* const unit)
{
  (void)mUnitSet30.RemoveUnit(unit);
}

/**
 * Address: 0x005E5EF0 (FUN_005E5EF0)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetUnitsWaitingForPickup() const
{
  EntitySetTemplate<Unit> out{};
  mUnitSet30.CopyTo(out);
  return out;
}

/**
 * Address: 0x005E5F30 (FUN_005E5F30)
 */
IFormationInstance* CAiTransportImpl::TransportGetWaitingFormation() const
{
  return mWaitingFormation;
}

/**
 * Address: 0x005E5F40 (FUN_005E5F40)
 */
void CAiTransportImpl::TransportGenerateWaitingFormationForUnits(const EntitySetTemplate<Unit>& units)
{
  mUnitSet30.AddUnits(units);
  if (!mUnit || !mUnit->SimulationRef || !mUnit->SimulationRef->mFormationDB) {
    return;
  }

  const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
  const char* const formationName = blueprint ? blueprint->AI.GuardFormationName.c_str() : nullptr;
  if (!formationName) {
    return;
  }

  SFormationUnitWeakRefSet weakSet{};
  for (Entity* const* it = mUnitSet30.mVec.begin(); it != mUnitSet30.mVec.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!unit) {
      continue;
    }

    const SFormationUnitWeakRef ref = SFormationUnitWeakRef::FromUnit(unit);
    weakSet.push_back(ref);
  }

  SCoordsVec2 center{};
  const Wm3::Vec3f& unitPos = mUnit->GetPosition();
  center.x = unitPos.x;
  center.z = unitPos.z;

  Wm3::Quatf orientation(0.0f, 0.0f, 0.0f, 0.0f);
  if (mUnit->IsMobile()) {
    orientation = mUnit->GetTransform().orient_;
  }

  CAiFormationDBImpl* const formationDB = mUnit->SimulationRef->mFormationDB;
  auto* const formation = formationDB->NewFormation(
    &weakSet,
    formationName,
    &center,
    orientation.x,
    orientation.y,
    orientation.z,
    orientation.w,
    2
  );
  mWaitingFormation = formation;
}

/**
 * Address: 0x005E60A0 (FUN_005E60A0)
 */
void CAiTransportImpl::TransportClearWaitingFormation()
{
  if (mWaitingFormation) {
    mWaitingFormation->operator_delete(1);
    mWaitingFormation = nullptr;
  }

  mUnitSet30.Clear();
}

/**
 * Address: 0x005E4930 (FUN_005E4930, Moho::CAiTransportImpl::SetUpAttachPoints)
 *
 * What it does:
 * Walks the transport skeleton and classifies attach bones by name token into
 * class-specific attach vectors used by transport slot assignment.
 */
void CAiTransportImpl::SetUpAttachPoints()
{
  if (!mUnit || !mUnit->AniActor) {
    return;
  }

  const boost::shared_ptr<const CAniSkel> skeletonHandle = mUnit->AniActor->GetSkeleton();
  const CAniSkel* const skeleton = skeletonHandle.get();
  if (!skeleton) {
    return;
  }

  const SAniSkelBone* const bonesBegin = skeleton->mBones.begin();
  const SAniSkelBone* const bonesEnd = skeleton->mBones.end();
  const unsigned int boneCount = static_cast<unsigned int>(bonesEnd - bonesBegin);

  for (unsigned int boneIndex = 0; boneIndex < boneCount; ++boneIndex) {
    const SAniSkelBone* const bone = skeleton->GetBone(boneIndex);
    if (!bone || !bone->mBoneName) {
      continue;
    }

    const VTransform localTransform = mUnit->GetBoneLocalTransform(static_cast<int>(boneIndex));
    SAttachPoint attachPoint{};
    attachPoint.index = boneIndex;
    attachPoint.localPos = localTransform.pos_;
    attachPoint.distSq = 0.0f;

    msvc8::vector<SAttachPoint>* targetList = nullptr;
    if (std::strstr(bone->mBoneName, "Launchpoint")) {
      targetList = &mLaunchAttachPoints;
    } else if (std::strstr(bone->mBoneName, "Attachpoint_Spr")) {
      ++mAttachpoints;
      if (mUnit->GetBlueprint()->Transport.ClassGenericUpTo < 4) {
        targetList = &mClass4AttachPoints;
      } else {
        targetList = &mGenericAttachPoints;
      }
    } else if (std::strstr(bone->mBoneName, "Attachpoint_Lrg")) {
      ++mAttachpoints;
      if (mUnit->GetBlueprint()->Transport.ClassGenericUpTo < 3) {
        targetList = &mClass3AttachPoints;
      } else {
        targetList = &mGenericAttachPoints;
      }
    } else if (std::strstr(bone->mBoneName, "Attachpoint_Med")) {
      ++mAttachpoints;
      if (mUnit->GetBlueprint()->Transport.ClassGenericUpTo < 2) {
        targetList = &mClass2AttachPoints;
      } else {
        targetList = &mGenericAttachPoints;
      }
    } else if (std::strstr(bone->mBoneName, "Attachpoint")) {
      ++mAttachpoints;
      if (mUnit->GetBlueprint()->Transport.ClassGenericUpTo < 1) {
        targetList = &mClass1AttachPoints;
      } else {
        targetList = &mGenericAttachPoints;
      }
    } else if (std::strstr(bone->mBoneName, "AttachSpecial")) {
      targetList = &mClassSAttachPoints;
    }

    if (targetList) {
      targetList->push_back(attachPoint);
    }
  }
}

/**
 * Address: 0x005E5120 (FUN_005E5120)
 */
const SAiReservedTransportBone* CAiTransportImpl::GetReservedBone(Unit* const unit) const
{
  for (const SAiReservedTransportBone* it = mReservedBones.begin(); it != mReservedBones.end(); ++it) {
    if (it->reservedUnit.GetObjectPtr() == unit) {
      return it;
    }
  }
  return nullptr;
}

/**
 * Address: 0x005E50A0 (FUN_005E50A0)
 */
unsigned int CAiTransportImpl::GetBestAttachPoint(Unit* const unit) const
{
  if (!unit) {
    return 0u;
  }

  boost::shared_ptr<const CAniSkel> holdSkel{};
  const CAniSkel* const skeleton = ResolveUnitSkeleton(mUnit, holdSkel);
  const int attachPointIndex = skeleton ? skeleton->FindBoneIndex("AttachPoint") : -1;
  if (attachPointIndex >= 0) {
    return static_cast<unsigned int>(attachPointIndex);
  }

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  if (blueprint && blueprint->Transport.AirClass != 0) {
    return 0u;
  }
  return static_cast<unsigned int>(attachPointIndex);
}

/**
 * Address: 0x005E6AC0 (FUN_005E6AC0)
 */
bool CAiTransportImpl::TransportValidateType(const RUnitBlueprint* const unitBlueprint) const
{
  if (!unitBlueprint || !mUnit) {
    return false;
  }

  const bool isAirClass = unitBlueprint->Transport.AirClass != 0;
  if (mStagingPlatform != 0 && !isAirClass) {
    return false;
  }
  if (mStagingPlatform != 0 || !isAirClass) {
    return true;
  }

  const Sim* const sim = mUnit->SimulationRef;
  if (!sim || !sim->mRules) {
    return false;
  }

  const CategoryWordRangeView* const category = sim->mRules->GetEntityCategory("TRANSPORTATION");
  if (!category) {
    return false;
  }

  const std::uint32_t ordinal = static_cast<std::uint32_t>(unitBlueprint->mCategoryBitIndex);
  const auto it = category->FindWord(ordinal >> 5u);
  if (it == category->cend()) {
    return false;
  }

  return (((*it) >> (ordinal & 0x1Fu)) & 1u) != 0u;
}

/**
 * Address: 0x005E9700 (FUN_005E9700, ??0vector_SAttachPoint@std@@QAE@@Z)
 * Mangled: ??0vector_SAttachPoint@std@@QAE@@Z
 *
 * What it does:
 * Rebuilds one destination attach-point vector from source lanes using the
 * same zero-init + resize + copy sequence as the VC8 helper constructor.
 */
msvc8::vector<SAttachPoint>* CAiTransportImpl::CopyAttachPointVector(
  const msvc8::vector<SAttachPoint>& source,
  msvc8::vector<SAttachPoint>& destination
)
{
  destination.clear();
  if (source.empty()) {
    return &destination;
  }

  destination.resize(source.size());
  SAttachPoint* const destinationBegin = destination.begin();
  const SAttachPoint* const sourceBegin = source.begin();
  const SAttachPoint* const sourceEnd = source.end();
  (void)CopyAttachPointRangeAdapter(sourceEnd, sourceBegin, destinationBegin);
  return &destination;
}

/**
 * Address: 0x005E6B30 (FUN_005E6B30)
 */
void CAiTransportImpl::TransportFindAttachList(
  const int unitClass,
  msvc8::vector<SAttachPoint>& attachPoints,
  msvc8::vector<SAttachPoint>& outAttachPoints,
  int& outAttachSize
)
{
  const RUnitBlueprint* const blueprint = (mUnit != nullptr) ? mUnit->GetBlueprint() : nullptr;
  if (!blueprint) {
    attachPoints.clear();
    outAttachPoints.clear();
    outAttachSize = 0;
    return;
  }

  if (unitClass > blueprint->Transport.ClassGenericUpTo) {
    switch (unitClass) {
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_1):
        (void)CopyAttachPointVector(mClass1AttachPoints, attachPoints);
        break;
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_2):
        (void)CopyAttachPointVector(mClass2AttachPoints, attachPoints);
        outAttachSize = blueprint->Transport.Class2AttachSize;
        break;
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_3):
        (void)CopyAttachPointVector(mClass3AttachPoints, attachPoints);
        outAttachSize = blueprint->Transport.Class3AttachSize;
        break;
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_4):
        (void)CopyAttachPointVector(mClass4AttachPoints, attachPoints);
        outAttachSize = blueprint->Transport.Class4AttachSize;
        [[fallthrough]];
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_SPECIAL):
        (void)CopyAttachPointVector(mClassSAttachPoints, attachPoints);
        outAttachSize = blueprint->Transport.ClassSAttachSize;
        break;
      default:
        break;
    }
  } else {
    (void)CopyAttachPointVector(mGenericAttachPoints, attachPoints);
  }

  if (outAttachSize == 0) {
    if (!mClass1AttachPoints.empty()) {
      (void)CopyAttachPointVector(mClass1AttachPoints, attachPoints);
    } else {
      (void)CopyAttachPointVector(mGenericAttachPoints, attachPoints);
    }
  }

  (void)CopyAttachPointVector(attachPoints, outAttachPoints);
}

/**
 * Address: 0x005E4D40 (FUN_005E4D40)
 */
msvc8::vector<int> CAiTransportImpl::GetClosestAttachPointsTo(
  msvc8::vector<SAttachPoint> attachPoints,
  const int hookIndex,
  int attachSize
)
{
  msvc8::vector<int> result{};
  if (attachSize <= 0) {
    return result;
  }

  if (attachSize == 1) {
    result.push_back(hookIndex);
    return result;
  }

  if (!mUnit || attachPoints.size() < static_cast<std::size_t>(attachSize)) {
    return result;
  }

  const VTransform hookTransform = mUnit->GetBoneLocalTransform(hookIndex);
  for (SAttachPoint* it = attachPoints.begin(); it != attachPoints.end(); ++it) {
    const VTransform attachTransform = mUnit->GetBoneLocalTransform(static_cast<int>(it->index));
    it->distSq = DistSq(attachTransform.pos_, hookTransform.pos_);
  }

  SAttachPoint* const sortBegin = attachPoints.begin();
  SAttachPoint* const sortEnd = attachPoints.end();
  if (sortBegin != nullptr && sortEnd != nullptr) {
    const std::size_t attachCount = attachPoints.size();
    if (attachCount <= 32u) {
      SortSmallAttachPointRangeByDistance(sortBegin, sortEnd);
    } else {
      std::sort(sortBegin, sortEnd, [](const SAttachPoint& lhs, const SAttachPoint& rhs) {
        return lhs.distSq < rhs.distSq;
      });
    }
  }

  for (const SAttachPoint* it = attachPoints.begin();
       it != attachPoints.end() && attachSize > 0;
       ++it, --attachSize) {
    result.push_back(static_cast<int>(it->index));
  }

  return result;
}

/**
 * Address: 0x005E4F00 (FUN_005E4F00)
 */
bool CAiTransportImpl::IsBoneReserved(msvc8::vector<int> boneIndices)
{
  for (const SAiReservedTransportBone* reserved = mReservedBones.begin(); reserved != mReservedBones.end(); ++reserved) {
    for (const int* candidate = boneIndices.begin(); candidate != boneIndices.end(); ++candidate) {
      for (const int* reservedBone = reserved->reservedBones.begin(); reservedBone != reserved->reservedBones.end(); ++reservedBone) {
        if (*candidate == *reservedBone) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Address: 0x005E4FA0 (FUN_005E4FA0)
 */
void CAiTransportImpl::ReserveBone(
  const unsigned int bestAttachBoneIndex,
  Unit* const unit,
  const unsigned int transportBoneIndex,
  msvc8::vector<int> boneIndices
)
{
  if (boneIndices.empty()) {
    return;
  }

  SAiReservedTransportBone reservation{};
  (void)InitReservedTransportBoneEntry(
    transportBoneIndex,
    bestAttachBoneIndex,
    &reservation,
    unit,
    boneIndices
  );
  mReservedBones.push_back(reservation);
}

/**
 * Address: 0x005E6C70 (FUN_005E6C70)
 */
bool CAiTransportImpl::TransportHasSpaceFor(const RUnitBlueprint* const unitBlueprint)
{
  if (!TransportValidateType(unitBlueprint)) {
    return false;
  }

  msvc8::vector<SAttachPoint> attachVec{};
  msvc8::vector<SAttachPoint> hookVec{};
  int attachSize = 1;
  TransportFindAttachList(unitBlueprint->Transport.TransportClass, attachVec, hookVec, attachSize);
  if (attachVec.empty()) {
    return false;
  }

  attachSize = MaxInt(1, attachSize);
  for (const SAttachPoint* it = attachVec.begin(); it != attachVec.end(); ++it) {
    msvc8::vector<int> candidate = GetClosestAttachPointsTo(hookVec, static_cast<int>(it->index), attachSize);
    if (!candidate.empty() && !IsBoneReserved(candidate)) {
      return true;
    }
  }

  return false;
}

/**
 * Address: 0x005E6E30 (FUN_005E6E30)
 */
bool CAiTransportImpl::TransportAssignSlot(Unit* const unit, const int hookIndex)
{
  if (!unit || !TransportValidateType(unit->GetBlueprint())) {
    return false;
  }

  const unsigned int bestAttachBoneIndex = GetBestAttachPoint(unit);
  msvc8::vector<SAttachPoint> attachVec{};
  msvc8::vector<SAttachPoint> hookVec{};
  int attachSize = 1;
  TransportFindAttachList(unit->GetBlueprint()->Transport.TransportClass, attachVec, hookVec, attachSize);

  if (hookIndex >= 0) {
    const int normalizedAttachSize = MaxInt(1, attachSize);
    msvc8::vector<int> candidate = GetClosestAttachPointsTo(hookVec, hookIndex, normalizedAttachSize);
    if (candidate.empty() || IsBoneReserved(candidate)) {
      return false;
    }
    ReserveBone(bestAttachBoneIndex, unit, static_cast<unsigned int>(hookIndex), candidate);
    return true;
  }

  if (attachVec.empty()) {
    return false;
  }

  attachSize = MaxInt(1, attachSize);
  for (const SAttachPoint* it = attachVec.begin(); it != attachVec.end(); ++it) {
    msvc8::vector<int> candidate = GetClosestAttachPointsTo(hookVec, static_cast<int>(it->index), attachSize);
    if (candidate.empty() || IsBoneReserved(candidate)) {
      continue;
    }

    ReserveBone(bestAttachBoneIndex, unit, it->index, candidate);
    return true;
  }

  return false;
}

/**
 * Address: 0x005E5150 (FUN_005E5150)
 */
void CAiTransportImpl::AttachUnitToBone(
  Unit* const unit,
  const unsigned int transportBoneIndex,
  const unsigned int attachBoneIndex
)
{
  if (!unit) {
    return;
  }

  SEntAttachInfo attachInfo = SEntAttachInfo::MakeDetached();
  attachInfo.mParentBoneIndex = static_cast<std::int32_t>(transportBoneIndex);
  attachInfo.mChildBoneIndex = static_cast<std::int32_t>(attachBoneIndex);
  attachInfo.TargetWeakLink().ResetFromObject(static_cast<Entity*>(mUnit));

  (void)unit->AttachTo(attachInfo);
  TransportRemovePickupUnit(unit, false);

  if (unit->AiNavigator) {
    unit->AiNavigator->AbortMove();
  }

  const SAniSkelBone* const transportBone = ResolveUnitBoneByIndex(mUnit, transportBoneIndex);
  InvokeTransportBoneScriptCallback(mUnit, "OnTransportAttach", transportBone, unit);
  BroadcastTransportEvent(*this, AITRANSPORTEVENT_Load);
}

/**
 * Address: 0x005E7100 (FUN_005E7100)
 */
bool CAiTransportImpl::TransportAttachUnit(Unit* const unit)
{
  if (!unit) {
    return false;
  }

  if (mTeleportation != 0) {
    TransportRemovePickupUnit(unit, true);
    return true;
  }

  const SAiReservedTransportBone* const reservedBone = GetReservedBone(unit);
  if (!reservedBone) {
    return false;
  }

  AttachUnitToBone(unit, reservedBone->transportBoneIndex, reservedBone->attachBoneIndex);
  unit->TransportedByRef.ResetObjectPtr<Unit>(mUnit);

  if (unit->AiNavigator) {
    unit->AiNavigator->AbortMove();
  }

  return true;
}

/**
 * Address: 0x005E7170 (FUN_005E7170)
 */
bool CAiTransportImpl::TransportDetachUnit(Unit* const unit)
{
  if (!unit || !mUnit) {
    return false;
  }

  Entity* const expectedParent = static_cast<Entity*>(mUnit);
  Entity* const actualParent = unit->mAttachInfo.GetAttachTargetEntity();
  if (actualParent != expectedParent) {
    gpg::Logf("Transport attemping to detach unit that is not attached");

    const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
    const RUnitBlueprint* const transportBlueprint = mUnit->GetBlueprint();
    const char* const unitName = unitBlueprint ? unitBlueprint->mBlueprintId.c_str() : "<unknown-unit>";
    const char* const transportName =
      transportBlueprint ? transportBlueprint->mBlueprintId.c_str() : "<unknown-transport>";
    gpg::Logf("Transport = %s, unit = %s", transportName, unitName);

    if (unit->IsDead()) {
      gpg::Logf("Attempted to detach a dead unit");
    }
  }

  if (mUnit->mCurrentLayer == LAYER_Air) {
    const Sim* const sim = mUnit->SimulationRef;
    if (!sim || !sim->mOGrid) {
      return false;
    }

    const SFootprint& footprint = unit->GetFootprint();
    const Wm3::Vec3f& worldPos = unit->GetPosition();
    const SCoordsVec2 worldPos2D{worldPos.x, worldPos.z};
    if (footprint.FitsAt(worldPos2D, *sim->mOGrid) == static_cast<EOccupancyCaps>(0u)) {
      return false;
    }
  }

  const int detachedBoneIndex = unit->mAttachInfo.mParentBoneIndex;
  (void)unit->DetachFrom(expectedParent, false);
  TransportRemovePickupUnit(unit, true);
  unit->TransportedByRef.ResetObjectPtr<Unit>(nullptr);

  const SAniSkelBone* detachedBone = nullptr;
  if (detachedBoneIndex >= 0) {
    detachedBone = ResolveUnitBoneByIndex(mUnit, static_cast<unsigned int>(detachedBoneIndex));
  }
  InvokeTransportBoneScriptCallback(mUnit, "OnTransportDetach", detachedBone, unit);
  BroadcastTransportEvent(*this, AITRANSPORTEVENT_Unload);

  if (unit->AiNavigator) {
    unit->AiNavigator->AbortMove();
  }

  return true;
}

/**
 * Address: 0x005E73E0 (FUN_005E73E0)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportDetachAllUnits(const bool clearReservations)
{
  EntitySetTemplate<Unit> detached{};
  EntitySetTemplate<Unit> storedToDestroy{};
  if (!mUnit) {
    return detached;
  }

  const bool requiresAirFitCheck = !clearReservations && (mUnit->mCurrentLayer == LAYER_Air);
  Sim* const sim = mUnit->SimulationRef;
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;

  const msvc8::vector<Entity*>& attachedCopy = mUnit->GetAttachedEntities();
  for (Entity* const* it = attachedCopy.begin(); it != attachedCopy.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!unit || unit->IsDead()) {
      continue;
    }

    if (requiresAirFitCheck) {
      if (!oGrid) {
        continue;
      }

      const Wm3::Vec3f& worldPos = unit->GetPosition();
      const SCoordsVec2 worldPos2D{worldPos.x, worldPos.z};
      const SFootprint& footprint = unit->GetFootprint();
      if (footprint.FitsAt(worldPos2D, *oGrid) == static_cast<EOccupancyCaps>(0u)) {
        continue;
      }
    }

    if (TransportIsStoredUnit(unit)) {
      (void)storedToDestroy.Add(unit);
    } else {
      (void)detached.Add(unit);
    }
  }

  CRandomStream* const random = sim ? sim->mRngState : nullptr;
  for (Unit* const* it = detached.mVec.begin(); it != detached.mVec.end(); ++it) {
    Unit* const unit = *it;
    if (!unit) {
      continue;
    }

    if (clearReservations) {
      const float roll = random ? CMersenneTwister::ToUnitFloat(random->twister.NextUInt32()) : 1.0f;
      if (roll < 0.99f) {
        if (unit->RunScriptUnitBool("CheckCanBeKilled", mUnit)) {
          unit->Kill(static_cast<Entity*>(mUnit), "Damage", 0.0f);
          continue;
        }

        if (unit->IsInCategory("COMMAND") && unit->RunScriptUnitBool("CheckCanTakeDamage", mUnit)) {
          unit->RunScriptUnitOnDamage(mUnit, 10000, false);
          continue;
        }
      }
    }

    (void)TransportDetachUnit(unit);
  }

  for (Unit* const* it = storedToDestroy.mVec.begin(); it != storedToDestroy.mVec.end(); ++it) {
    Unit* const unit = *it;
    if (!unit) {
      continue;
    }

    unit->RunScript("DestroyedOnTransport");
    unit->Destroy();
  }

  return detached;
}

/**
 * Address: 0x005E77B0 (FUN_005E77B0)
 */
void CAiTransportImpl::TransportAtPickupPosition()
{
  mPickupInfo.mHasSpace = 1;
}

/**
 * Address: 0x005E77C0 (FUN_005E77C0)
 */
bool CAiTransportImpl::TransportIsReadyForUnit(Unit* const unit) const
{
  return mPickupInfo.mHasSpace != 0 && mPickupInfo.HasUnit(unit);
}

/**
 * Address: 0x005E7930 (FUN_005E7930)
 */
int CAiTransportImpl::TransportGetAttachBone(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  return reserved ? static_cast<int>(reserved->transportBoneIndex) : -1;
}

/**
 * Address: 0x005E77F0 (FUN_005E77F0)
 */
SOCellPos CAiTransportImpl::TransportGetAttachPosition(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (!reserved || !mUnit) {
    return InvalidCellPos();
  }

  const VTransform localTransform = mUnit->GetBoneLocalTransform(static_cast<int>(reserved->transportBoneIndex));
  const Wm3::Vec3f rotated = mUnit->GetTransform().orient_.Rotate(localTransform.pos_);
  Wm3::Vec3f world = mUnit->GetPosition();
  world.x += rotated.x;
  world.z += rotated.z;
  return CellPosFromWorldForUnit(world, unit);
}

/**
 * Address: 0x005E7950 (FUN_005E7950)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetAttachBonePosition(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (!reserved || !mUnit) {
    return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
  }

  const VTransform localTransform = mUnit->GetBoneLocalTransform(static_cast<int>(reserved->transportBoneIndex));
  const Wm3::Vec3f rotated = mUnit->GetTransform().orient_.Rotate(localTransform.pos_);
  const Wm3::Vec3f base = mUnit->GetPosition();
  return Wm3::Vec3f(base.x + rotated.x, base.y + rotated.y, base.z + rotated.z);
}

/**
 * Address: 0x005E7A60 (FUN_005E7A60)
 */
VTransform CAiTransportImpl::TransportGetAttachBoneTransform(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (reserved && mUnit) {
    return mUnit->GetBoneWorldTransform(static_cast<int>(reserved->transportBoneIndex));
  }
  return mUnit ? mUnit->GetTransform() : VTransform{};
}

/**
 * Address: 0x005E7AD0 (FUN_005E7AD0)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetAttachFacing(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (!reserved || !mUnit) {
    return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
  }

  const VTransform localBone = mUnit->GetBoneLocalTransform(static_cast<int>(reserved->transportBoneIndex));
  Wm3::Vec3f localForward = localBone.orient_.Rotate(Wm3::Vec3f(0.0f, 0.0f, 1.0f));
  localForward.y = 0.0f;
  const Wm3::Vec3f worldForward = mUnit->GetTransform().orient_.Rotate(localForward);
  return Wm3::Vec3f::NormalizeOrZero(worldForward);
}

/**
 * Address: 0x005E7BB0 (FUN_005E7BB0)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetPickupFacing() const
{
  return mPickupFacing;
}

/**
 * Address: 0x005E7BE0 (FUN_005E7BE0)
 */
void CAiTransportImpl::TransportAddToStorage(Unit* const unit)
{
  if (!unit || !mUnit) {
    return;
  }

  unit->RunScript("OnAddToStorage", mUnit);
  TransportClearReservation(unit);

  SEntAttachInfo attachInfo = SEntAttachInfo::MakeDetached();
  attachInfo.mParentBoneIndex = -1;
  attachInfo.mChildBoneIndex = -1;
  attachInfo.TargetWeakLink().ResetFromObject(static_cast<Entity*>(mUnit));
  (void)unit->AttachTo(attachInfo);
  unit->TransportedByRef.ResetObjectPtr<Unit>(mUnit);
  (void)mStoredUnits.AddUnit(unit);
}

/**
 * Address: 0x005E7CF0 (FUN_005E7CF0)
 */
void CAiTransportImpl::TransportRemoveFromStorage(Unit* const unit, VTransform& outTransform)
{
  if (!mUnit) {
    outTransform = VTransform{};
    return;
  }

  outTransform = mUnit->GetTransform();
  if (!unit) {
    return;
  }

  unit->RunScript("OnRemoveFromStorage", mUnit);
  unit->TransportedByRef.ResetObjectPtr<Unit>(nullptr);
  (void)unit->DetachFrom(static_cast<Entity*>(mUnit), false);
  (void)mStoredUnits.RemoveUnit(unit);

  const msvc8::vector<SAttachPoint>* launchPoints = &mLaunchAttachPoints;
  if (launchPoints->empty()) {
    launchPoints = &mGenericAttachPoints;
  }
  if (launchPoints->empty()) {
    return;
  }

  const int count = static_cast<int>(launchPoints->size());
  if (count <= 0) {
    return;
  }

  mLaunchAttachIndex = (mLaunchAttachIndex + 1) % count;
  const SAttachPoint& point = (*launchPoints)[static_cast<std::size_t>(mLaunchAttachIndex)];
  outTransform = mUnit->GetBoneWorldTransform(static_cast<int>(point.index));
}

/**
 * Address: 0x005E7E60 (FUN_005E7E60)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetStoredUnits() const
{
  EntitySetTemplate<Unit> out{};
  mStoredUnits.CopyTo(out);
  return out;
}

/**
 * Address: 0x005E8050 (FUN_005E8050)
 */
bool CAiTransportImpl::TransportIsStoredUnit(Unit* const unit) const
{
  return mStoredUnits.ContainsUnit(unit);
}

/**
 * Address: 0x005E7E80 (FUN_005E7E80)
 */
bool CAiTransportImpl::TransportHasAvailableStorage() const
{
  if (!mUnit || !mUnit->GetBlueprint()) {
    return false;
  }

  const int reservedCount = static_cast<int>(mUnitSet80.Size());
  const int currentStoredCount = static_cast<int>(mStoredUnits.Size());
  return (currentStoredCount + reservedCount) < mUnit->GetBlueprint()->Transport.StorageSlots;
}

/**
 * Address: 0x005E7EC0 (FUN_005E7EC0)
 */
int CAiTransportImpl::TransportReserveStorage(
  Unit* const unit,
  Wm3::Vec3f& outPos,
  Wm3::Vec3f& outFacing,
  float& outDropDist
)
{
  const int previousOverflow = mGenericOverflow;
  if (!unit || !mUnit || mGenericAttachPoints.empty()) {
    outPos = Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    outFacing = Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    outDropDist = 0.0f;
    return previousOverflow;
  }

  (void)mUnitSet80.AddUnit(unit);
  const std::size_t index = static_cast<std::size_t>(mNextGeneric) % mGenericAttachPoints.size();
  const SAttachPoint& point = mGenericAttachPoints[index];
  const VTransform world = mUnit->GetBoneWorldTransform(static_cast<int>(point.index));
  outPos = world.pos_;
  outFacing = ForwardFromOrientation(world.orient_);
  outDropDist = world.pos_.y - mUnit->GetPosition().y;

  const int count = static_cast<int>(mGenericAttachPoints.size());
  if (count > 0) {
    mNextGeneric = (mNextGeneric + 1) % count;
    if (mNextGeneric == 0) {
      mGenericOverflow = (previousOverflow + 3) % 50;
    }
  }

  return previousOverflow;
}

/**
 * Address: 0x005E8020 (FUN_005E8020)
 */
void CAiTransportImpl::TransportClearReservation(Unit* const unit)
{
  (void)mUnitSet80.RemoveUnit(unit);
}

/**
 * Address: 0x005E8040 (FUN_005E8040)
 */
void CAiTransportImpl::TransportResetReservation()
{
  mNextGeneric = 0;
  mLaunchAttachIndex = 0;
  mGenericOverflow = 0;
}

/**
 * Address: 0x005E8080 (FUN_005E8080)
 */
void CAiTransportImpl::TranspotSetTeleportDest(Unit* const beaconUnit)
{
  if (beaconUnit && mUnit) {
    LuaPlus::LuaState* const state = mUnit->mLuaObj.GetActiveState();
    if (state) {
      const LuaPlus::LuaObject destination = moho::SCR_ToLua<Wm3::Vector3<float>>(state, beaconUnit->GetPosition());
      (void)mUnit->RunScript("OnSetTeleportDest", destination);
    }
  }

  mTeleportBeacon.ResetFromObject(beaconUnit);
}

/**
 * Address: 0x005E8120 (FUN_005E8120)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetTeleportDest() const
{
  Unit* const beacon = mTeleportBeacon.GetObjectPtr();
  if (!beacon || beacon->IsDead() || beacon->DestroyQueued()) {
    return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
  }

  return beacon->GetPosition();
}

/**
 * Address: 0x005E81C0 (FUN_005E81C0)
 */
Unit* CAiTransportImpl::TransportGetTeleportBeacon() const
{
  return mTeleportBeacon.GetObjectPtr();
}

/**
 * Address: 0x005E81D0 (FUN_005E81D0)
 */
bool CAiTransportImpl::TransportIsTeleportBeaconReady() const
{
  Unit* const beacon = mTeleportBeacon.GetObjectPtr();
  if (!beacon) {
    return false;
  }
  if (beacon->IsDead() || beacon->DestroyQueued()) {
    return false;
  }
  return beacon->IsNavigatorIdle();
}
