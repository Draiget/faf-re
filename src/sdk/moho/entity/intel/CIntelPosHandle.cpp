#include "CIntelPosHandle.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/CIntelGrid.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vec3f));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCIntelGridType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CIntelGrid));
    }
    return cached;
  }

  [[nodiscard]]
  gpg::RRef MakeSharedIntelGridRef(moho::CIntelGrid* const intelGrid)
  {
    gpg::RRef out{};
    out.mObj = intelGrid;
    out.mType = CachedCIntelGridType();
    return out;
  }

  /**
   * Address: 0x0076D8D0 (FUN_0076D8D0)
   *
   * What it does:
   * Rebuilds one position-watch entry's coverage when the requested position
   * or radius differs from the stored state by calling `SubViz`, updating the
   * cached fields, then calling `AddViz`.
   */
  [[maybe_unused]] void RebuildEntityPositionWatchCoverage(
    moho::EntityPositionWatchEntry* const entry,
    const Wm3::Vec3f& newPos,
    const std::uint32_t requestedRadius
  )
  {
    const int compareResult = Wm3::Vec3f::Compare(&newPos, &entry->mLastPos);
    if (compareResult != 0 || requestedRadius != entry->mRadius) {
      entry->SubViz();
      entry->mLastPos = newPos;
      entry->mRadius = requestedRadius;
      entry->AddViz();
    }
  }

  /**
   * Address: 0x0076E770 (FUN_0076E770, boost::shared_ptr_CIntelPosHandle::~shared_ptr_CIntelPosHandle)
   *
   * What it does:
   * Destroys one `CIntelPosHandle*` lane when present via virtual
   * `CIntelPosHandle::Destroy(1)` dispatch.
   */
  [[maybe_unused]] void DestroyIntelPosHandleViaDestroyIfPresent(
    moho::CIntelPosHandle* const* const handleSlot
  )
  {
    if (handleSlot == nullptr) {
      return;
    }

    moho::CIntelPosHandle* const handle = *handleSlot;
    if (handle != nullptr) {
      handle->Destroy(1);
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CIntelPosHandle::sType = nullptr;

  gpg::RType* CIntelPosHandle::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CIntelPosHandle));
    }
    return sType;
  }

  /**
   * Address: 0x0076D810 (FUN_0076D810, Moho::CIntelPosHandle::CIntelPosHandle)
   *
   * What it does:
   * Initializes intel-position handle state and retains one shared reference
   * to the bound intel-grid owner.
   */
  CIntelPosHandle::CIntelPosHandle(const std::uint32_t radius, const boost::SharedPtrRaw<CIntelGrid>& intelGrid)
    : mGrid{}
  {
    mLastPos = {};
    mRadius = radius;
    mLastTickUpdated = 0;
    mEnabled = 0;
    mGrid = intelGrid;
  }

  /**
   * Address: 0x0076D860 (FUN_0076D860, Moho::CIntelPosHandle::~CIntelPosHandle)
   *
   * What it does:
   * Removes active circle coverage from the bound grid and releases the
   * retained grid shared-pointer reference.
   */
  CIntelPosHandle::~CIntelPosHandle()
  {
    if (mEnabled != 0u && mRadius != 0u && mGrid.px != nullptr) {
      mGrid.px->SubtractCircle(mLastPos, mRadius);
    }
    mGrid.release();
  }

  /**
   * Address: 0x0076EFC0 (FUN_0076EFC0, Moho::CIntelPosHandle::Update)
   *
   * What it does:
   * Rebuilds grid coverage at a new world position when the value differs
   * from the cached position.
   */
  void CIntelPosHandle::Update(const Wm3::Vec3f& pos)
  {
    RebuildEntityPositionWatchCoverage(this, pos, mRadius);
  }

  /**
   * Address: 0x0076F1E0 (FUN_0076F1E0, Moho::CIntelPosHandle::UpdatePos)
   *
   * What it does:
   * Updates stored world position and refreshes grid coverage when movement
   * exceeds threshold or periodic refresh timeout is reached.
   */
  std::int32_t CIntelPosHandle::UpdatePos(const std::int32_t curTick, const Wm3::Vec3f& newPos)
  {
    if (mEnabled != 0u) {
      const float dx = newPos.x - mLastPos.x;
      const float dy = newPos.y - mLastPos.y;
      const float dz = newPos.z - mLastPos.z;
      const float distanceSquared = dx * dx + dy * dy + dz * dz;
      const float range = static_cast<float>(static_cast<double>(mRadius) * 0.333);
      const float rangeSquared = range * range;

      if (distanceSquared >= rangeSquared || (curTick - mLastTickUpdated) > 30) {
        mLastTickUpdated = curTick;
        Update(newPos);
      }

      return curTick;
    }

    mLastPos = newPos;
    return curTick;
  }

  /**
   * Address: 0x0076F280 (FUN_0076F280)
   *
   * What it does:
   * Updates visualized position immediately when enabled (or writes raw
   * position when disabled), then stores `curTick` as last-update tick.
   */
  void CIntelPosHandle::UpdatePosImmediate(const std::int32_t curTick, const Wm3::Vec3f& newPos)
  {
    if (mEnabled != 0u) {
      Update(newPos);
      mLastTickUpdated = curTick;
      return;
    }

    mLastPos = newPos;
    mLastTickUpdated = curTick;
  }

  /**
   * Address: 0x0076D980 (FUN_0076D980, Moho::CIntelPosHandle::ChangeRadius)
   *
   * What it does:
   * Rebuilds active grid coverage when the requested radius differs from the
   * current one, preserving the existing world position.
   */
  void CIntelPosHandle::ChangeRadius(const std::int32_t newRadius)
  {
    RebuildEntityPositionWatchCoverage(this, mLastPos, static_cast<std::uint32_t>(newRadius));
  }

  /**
   * Address: 0x00770000 (FUN_00770000, Moho::CIntelPosHandle::MemberDeserialize)
   *
   * gpg::ReadArchive *
   *
   * IDA signature:
   * void __usercall Moho::CIntelPosHandle::MemberDeserialize(
   *   Moho::CIntelPosHandle *this@<eax>, gpg::ReadArchive *archive@<esi>);
   *
   * What it does:
   * Deserializes base position-watch fields (`mLastPos`, `mRadius`,
   * `mEnabled`, `mGrid`, `mLastTickUpdated`) from archive payload.
   */
  void CIntelPosHandle::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedVector3fType(), &mLastPos, ownerRef);
    archive->ReadUInt(&mRadius);

    bool enabled = false;
    archive->ReadBool(&enabled);
    mEnabled = static_cast<std::uint8_t>(enabled ? 1u : 0u);

    mGrid.release();
    gpg::ReadPointerShared_CIntelGrid2(mGrid, archive, ownerRef);

    archive->ReadInt(&mLastTickUpdated);
  }

  /**
   * Address: 0x0076FD10 (FUN_0076FD10)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelPosHandle::MemberDeserialize`.
   */
  [[maybe_unused]] void CIntelPosHandleMemberDeserializeBridgeA(
    CIntelPosHandle* const handle,
    gpg::ReadArchive* const archive
  )
  {
    if (handle != nullptr) {
      handle->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00770090 (FUN_00770090, Moho::CIntelPosHandle::MemberSerialize)
   *
   * gpg::WriteArchive *
   *
   * IDA signature:
   * void __usercall Moho::CIntelPosHandle::MemberSerialize(
   *   Moho::CIntelPosHandle *this@<edi>, gpg::WriteArchive *archive@<esi>);
   *
   * What it does:
   * Serializes base position-watch fields (`mLastPos`, `mRadius`, `mEnabled`,
   * `mGrid`, `mLastTickUpdated`) into archive payload.
   */
  void CIntelPosHandle::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedVector3fType(), &mLastPos, ownerRef);
    archive->WriteUInt(mRadius);
    archive->WriteBool(mEnabled != 0u);

    const gpg::RRef gridRef = MakeSharedIntelGridRef(mGrid.px);
    gpg::WriteRawPointer(archive, gridRef, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WriteInt(mLastTickUpdated);
  }

  /**
   * Address: 0x0076FD20 (FUN_0076FD20)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelPosHandle::MemberSerialize`.
   */
  [[maybe_unused]] void CIntelPosHandleMemberSerializeBridgeA(
    const CIntelPosHandle* const handle,
    gpg::WriteArchive* const archive
  )
  {
    if (handle != nullptr) {
      handle->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0076FE10 (FUN_0076FE10)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelPosHandle::MemberDeserialize`.
   */
  [[maybe_unused]] void CIntelPosHandleMemberDeserializeBridgeB(
    CIntelPosHandle* const handle,
    gpg::ReadArchive* const archive
  )
  {
    if (handle != nullptr) {
      handle->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x0076FE20 (FUN_0076FE20)
   * Address: 0x00649B40 (FUN_00649B40)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelPosHandle::MemberSerialize`.
   */
  [[maybe_unused]] void CIntelPosHandleMemberSerializeBridgeB(
    const CIntelPosHandle* const handle,
    gpg::WriteArchive* const archive
  )
  {
    if (handle != nullptr) {
      handle->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0076F180 (FUN_0076F180)
   *
   * What it does:
   * Adds this handle's circular coverage into the bound intel grid.
   */
  void CIntelPosHandle::AddViz()
  {
    if (mEnabled == 0u || mRadius == 0u || mGrid.px == nullptr) {
      return;
    }

    mGrid.px->AddCircle(mLastPos, mRadius);
  }

  /**
   * Address: 0x0076F1B0 (FUN_0076F1B0)
   *
   * What it does:
   * Removes this handle's circular coverage from the bound intel grid
   * immediately.
   */
  void CIntelPosHandle::SubViz()
  {
    if (mEnabled == 0u || mRadius == 0u || mGrid.px == nullptr) {
      return;
    }

    mGrid.px->SubtractCircle(mLastPos, mRadius);
  }

  /**
   * Address: 0x0076D9D0 (FUN_0076D9D0, Moho::CIntelPosHandle::dtr)
   *
   * What it does:
   * Runs non-virtual destructor body and conditionally frees the object
   * allocation when `shouldDelete & 1` is set.
   */
  void CIntelPosHandle::Destroy(const int shouldDelete)
  {
    this->~CIntelPosHandle();
    if ((shouldDelete & 1) != 0) {
      ::operator delete(this);
    }
  }
} // namespace moho
