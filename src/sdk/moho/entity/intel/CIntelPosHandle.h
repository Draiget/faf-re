#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "moho/entity/EntityPositionWatchEntry.h"

namespace gpg
{
  class ReadArchive;
  class RType;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CIntelGrid;

  /**
   * Recovered concrete viz handle used by Entity intel proximity updates.
   *
   * Constructor/layout evidence:
   * - FUN_0076D810 writes +0x1C/+0x20 and sets size-class to 0x24 (FUN_0076F0A0).
   */
  class CIntelPosHandle : public EntityPositionWatchEntry
  {
  public:
    [[nodiscard]] static gpg::RType* StaticGetClass();

    static gpg::RType* sType;

    /**
     * Address: 0x0076D810 (FUN_0076D810, Moho::CIntelPosHandle::CIntelPosHandle)
     *
     * What it does:
     * Initializes intel-position handle state and retains one shared reference
     * to the bound intel-grid owner.
     */
    CIntelPosHandle(std::uint32_t radius, const boost::SharedPtrRaw<CIntelGrid>& intelGrid);

    /**
     * Address: 0x0076D860 (FUN_0076D860, Moho::CIntelPosHandle::~CIntelPosHandle)
     *
     * What it does:
     * Removes active circle coverage from the bound grid and releases the
     * retained grid shared-pointer reference.
     */
    ~CIntelPosHandle();

    /**
     * Address: 0x0076EFC0 (FUN_0076EFC0, Moho::CIntelPosHandle::Update)
     *
     * What it does:
     * Rebuilds grid coverage at a new world position when the value differs
     * from the cached position.
     */
    void Update(const Wm3::Vec3f& pos);

    /**
     * Address: 0x0076F1E0 (FUN_0076F1E0, Moho::CIntelPosHandle::UpdatePos)
     *
     * What it does:
     * Updates stored world position and refreshes grid coverage when movement
     * exceeds threshold or periodic refresh timeout is reached.
     */
    std::int32_t UpdatePos(std::int32_t curTick, const Wm3::Vec3f& newPos);

    /**
     * Address: 0x0076D980 (FUN_0076D980, Moho::CIntelPosHandle::ChangeRadius)
     *
     * What it does:
     * Rebuilds active grid coverage when the requested radius differs from the
     * current one, preserving the existing world position.
     */
    void ChangeRadius(std::int32_t newRadius);

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
    void MemberDeserialize(gpg::ReadArchive* archive);

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
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0076F180 (FUN_0076F180)
     *
     * What it does:
     * Adds this handle's circular coverage into the bound intel grid.
     */
    void AddViz() override;

    /**
     * Address: 0x0076F1B0 (FUN_0076F1B0)
     *
     * What it does:
     * Removes this handle's circular coverage from the bound intel grid
     * immediately.
     */
    void SubViz() override;

    /**
     * Address: 0x0076D9D0 (FUN_0076D9D0, Moho::CIntelPosHandle::dtr)
     *
     * What it does:
     * Runs non-virtual destructor body and conditionally frees the object
     * allocation when `shouldDelete & 1` is set.
     */
    void Destroy(int shouldDelete) override;

    boost::SharedPtrRaw<CIntelGrid> mGrid; // +0x1C (px, pi)
  };

#if defined(_M_IX86)
  static_assert(sizeof(CIntelPosHandle) == 0x24, "CIntelPosHandle size must be 0x24");
  static_assert(offsetof(CIntelPosHandle, mGrid) == 0x1C, "CIntelPosHandle::mGrid offset must be 0x1C");
#endif
} // namespace moho
