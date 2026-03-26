#include "CIntelPosHandle.h"

#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
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

  [[noreturn]] void ThrowPointerTypeMismatch(gpg::RType* const expectedType, const gpg::RRef& source)
  {
    const char* const expected = expectedType ? expectedType->GetName() : "null";
    const char* const actual = source.mType ? source.mType->GetName() : "null";
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected,
      actual
    );
    throw std::runtime_error(message.c_str());
  }

  [[nodiscard]]
  boost::SharedPtrRaw<moho::CIntelGrid> ReadSharedIntelGridPointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return {};
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    gpg::RType* const expectedType = CachedCIntelGridType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (!upcast.mObj) {
      ThrowPointerTypeMismatch(expectedType, source);
    }

    boost::SharedPtrRaw<moho::CIntelGrid> out{};
    out.px = static_cast<moho::CIntelGrid*>(upcast.mObj);
    out.pi = nullptr;
    return out;
  }

  void RefreshGridCoverageAtPosition(moho::CIntelPosHandle& handle, const Wm3::Vec3f& worldPos)
  {
    const std::uint32_t savedRadius = handle.mRadius;
    handle.SubViz();
    handle.mLastPos = worldPos;
    handle.mRadius = savedRadius;
    handle.AddViz();
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

      if (distanceSquared >= rangeSquared || (curTick - mLastTickUpdated) > 5) {
        mLastTickUpdated = curTick;
        RefreshGridCoverageAtPosition(*this, newPos);
      }

      return curTick;
    }

    mLastPos = newPos;
    return curTick;
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
    mGrid = ReadSharedIntelGridPointer(archive, ownerRef);

    archive->ReadInt(&mLastTickUpdated);
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
