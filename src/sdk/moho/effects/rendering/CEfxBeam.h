#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/particles/SWorldBeam.h"

namespace moho
{
  struct GeomCamera3;

  class CEfxBeam : public CEffectImpl
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x006546F0 (FUN_006546F0, Moho::CEfxBeam::CEfxBeam)
     *
     * What it does:
     * Initializes default effect, attachment, and beam payload state.
     */
    CEfxBeam();

    /**
     * Address: 0x00655B80 (FUN_00655B80, Moho::CEfxBeam::dtr)
     *
     * What it does:
     * Releases CEfxBeam-owned intrusive and reflected member state.
     */
    ~CEfxBeam() override;

    /**
     * Address: 0x00658A10 (FUN_00658A10, Moho::CEfxBeam::MemberDeserialize)
     *
     * What it does:
     * Loads CEfxBeam state from archive in the recovered binary field order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00658B10 (FUN_00658B10, Moho::CEfxBeam::MemberSerialize)
     *
     * What it does:
     * Saves CEfxBeam state to archive in the recovered binary field order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00655690 (FUN_00655690, Moho::CEfxBeam::CanSeeCam)
     *
     * What it does:
     * Applies camera-frustum and focused-army recon visibility tests for this
     * beam and updates cached `mVisible` state when re-evaluation is due.
     */
    [[nodiscard]] bool CanSeeCam(const GeomCamera3* camera);

    /**
     * Address: 0x00654D40 (FUN_00654D40, Moho::CEfxBeam::Reset)
     *
     * What it does:
     * Rebuilds beam render parameters from effect params, rebinding beam
     * textures and width/scroll/repeat lanes.
     */
    void Reset();

    /**
     * Address: 0x00654F30 (FUN_00654F30, Moho::CEfxBeam::Update)
     *
     * What it does:
     * Updates beam endpoint transforms from current attachment state and
     * handles detach/destroy paths for invalid source attachments.
     */
    [[nodiscard]] bool Update();

    /**
     * What it does:
     * Returns the cached reflection descriptor for `CEfxBeam`.
     */
    [[nodiscard]]
    static gpg::RType* StaticGetClass();

  public:
    std::int32_t mBlendMode;     // +0x190
    bool mVisible;               // +0x194
    std::uint8_t mPad195[0x03];  // +0x195
    std::uint32_t mLastUpdate;   // +0x198
    SEntAttachInfo mEnd;         // +0x19C
    SWorldBeam mBeam;            // +0x1C8
    bool mIsNew;                 // +0x294
    std::uint8_t mPad295[0x03];  // +0x295
  };

  static_assert(offsetof(CEfxBeam, mBlendMode) == 0x190, "CEfxBeam::mBlendMode offset must be 0x190");
  static_assert(offsetof(CEfxBeam, mVisible) == 0x194, "CEfxBeam::mVisible offset must be 0x194");
  static_assert(offsetof(CEfxBeam, mLastUpdate) == 0x198, "CEfxBeam::mLastUpdate offset must be 0x198");
  static_assert(offsetof(CEfxBeam, mEnd) == 0x19C, "CEfxBeam::mEnd offset must be 0x19C");
  static_assert(offsetof(CEfxBeam, mBeam) == 0x1C8, "CEfxBeam::mBeam offset must be 0x1C8");
  static_assert(offsetof(CEfxBeam, mIsNew) == 0x294, "CEfxBeam::mIsNew offset must be 0x294");
  static_assert(sizeof(CEfxBeam) == 0x298, "CEfxBeam size must be 0x298");
} // namespace moho
