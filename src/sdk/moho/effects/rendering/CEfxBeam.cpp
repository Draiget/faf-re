#include "moho/effects/rendering/CEfxBeam.h"

#include <cmath>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "Wm3Sphere3.h"

namespace
{
  template <typename TType>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& cached)
  {
    if (!cached) {
      cached = gpg::LookupRType(typeid(TType));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveCEffectImplType()
  {
    return ResolveCachedType<moho::CEffectImpl>(moho::CEffectImpl::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSEntAttachInfoType()
  {
    return ResolveCachedType<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldBeamType()
  {
    return ResolveCachedType<moho::SWorldBeam>(moho::SWorldBeam::sType);
  }

  [[nodiscard]] moho::IEffectManager* ResolveEffectManager(const moho::IEffect* const effect)
  {
    const std::uintptr_t raw = static_cast<std::uintptr_t>(effect->mUnknown3C);
    return reinterpret_cast<moho::IEffectManager*>(raw);
  }

  [[nodiscard]] float ProjectViewportDepthRow1(const moho::VMatrix4& viewport, const Wm3::Vec3f& point) noexcept
  {
    return (point.x * viewport.r[1].x) + (point.y * viewport.r[1].y) + (point.z * viewport.r[1].z) + viewport.r[1].w;
  }

  [[nodiscard]] Wm3::Sphere3f MakeSphere(const Wm3::Vec3f& center, const float radius) noexcept
  {
    Wm3::Sphere3f sphere{};
    sphere.Center = center;
    sphere.Radius = radius;
    return sphere;
  }

  [[nodiscard]] Wm3::Vec3f Midpoint(const Wm3::Vec3f& a, const Wm3::Vec3f& b) noexcept
  {
    return {
      (a.x + b.x) * 0.5f,
      (a.y + b.y) * 0.5f,
      (a.z + b.z) * 0.5f,
    };
  }

  [[nodiscard]] Wm3::Sphere3f BuildSegmentMidpointSphere(const Wm3::Vec3f& start, const Wm3::Vec3f& end) noexcept
  {
    const Wm3::Vec3f center = Midpoint(start, end);
    const float dx = end.x - center.x;
    const float dy = end.y - center.y;
    const float dz = end.z - center.z;
    return MakeSphere(center, std::sqrt((dx * dx) + (dy * dy) + (dz * dz)));
  }

  [[nodiscard]] moho::CArmyImpl* ResolveFocusArmy(moho::Sim* const sim) noexcept
  {
    if (!sim) {
      return nullptr;
    }

    moho::CArmyImpl** const armiesBegin = sim->mArmiesList.begin();
    if (!armiesBegin) {
      return nullptr;
    }

    const int focusArmyIndex = sim->mSyncFilter.focusArmy;
    if (focusArmyIndex < 0 || static_cast<std::size_t>(focusArmyIndex) >= sim->mArmiesList.size()) {
      return nullptr;
    }

    return armiesBegin[focusArmyIndex];
  }
} // namespace

namespace moho
{
  gpg::RType* CEfxBeam::sType = nullptr;

  /**
   * Address: 0x006546F0 (FUN_006546F0, Moho::CEfxBeam::CEfxBeam)
   */
  CEfxBeam::CEfxBeam()
    : CEffectImpl()
    , mBlendMode(0)
    , mVisible(false)
    , mPad195{0}
    , mLastUpdate(0)
    , mEnd(SEntAttachInfo::MakeDetached())
    , mBeam{}
    , mIsNew(true)
    , mPad295{0}
  {}

  /**
   * Address: 0x00655B80 (FUN_00655B80, Moho::CEfxBeam::dtr)
   */
  CEfxBeam::~CEfxBeam()
  {
    mEnd.TargetWeakLink().UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00658A10 (FUN_00658A10, Moho::CEfxBeam::MemberDeserialize)
   */
  void CEfxBeam::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveCEffectImplType(), static_cast<CEffectImpl*>(this), nullOwner);
    archive->ReadInt(&mBlendMode);
    archive->ReadBool(&mVisible);
    archive->ReadUInt(&mLastUpdate);
    archive->Read(ResolveSEntAttachInfoType(), &mEnd, nullOwner);
    archive->Read(ResolveSWorldBeamType(), &mBeam, nullOwner);
    archive->ReadBool(&mIsNew);
  }

  /**
   * Address: 0x00658B10 (FUN_00658B10, Moho::CEfxBeam::MemberSerialize)
   */
  void CEfxBeam::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveCEffectImplType(), static_cast<const CEffectImpl*>(this), nullOwner);
    archive->WriteInt(mBlendMode);
    archive->WriteBool(mVisible);
    archive->WriteUInt(mLastUpdate);
    archive->Write(ResolveSEntAttachInfoType(), &mEnd, nullOwner);
    archive->Write(ResolveSWorldBeamType(), &mBeam, nullOwner);
    archive->WriteBool(mIsNew);
  }

  /**
   * Address: 0x00655690 (FUN_00655690, Moho::CEfxBeam::CanSeeCam)
   *
   * What it does:
   * Performs frustum/depth rejection for beam endpoints and resolves focused
   * army LOS visibility through recon DB probes.
   */
  bool CEfxBeam::CanSeeCam(const GeomCamera3* const camera)
  {
    const float maxDepth = mParams.start_[20];

    if (!mNewAttachment) {
      if (maxDepth > 0.0f) {
        float projectedDepth = ProjectViewportDepthRow1(camera->viewport, mBeam.mEnd);
        const float startDepth = ProjectViewportDepthRow1(camera->viewport, mBeam.mStart);
        if (projectedDepth > startDepth) {
          projectedDepth = startDepth;
        }
        if (projectedDepth > maxDepth) {
          mLastUpdate = 0u;
          return false;
        }
      }

      if (!camera->solid2.Intersects(MakeSphere(mBeam.mStart, 15.0f))
          && !camera->solid2.Intersects(MakeSphere(mBeam.mEnd, 15.0f))) {
        mLastUpdate = 0u;
        return false;
      }
    } else {
      if (maxDepth > 0.0f) {
        float projectedDepth = ProjectViewportDepthRow1(camera->viewport, mBeam.mCurEnd.pos_);
        const float startDepth = ProjectViewportDepthRow1(camera->viewport, mBeam.mCurStart.pos_);
        if (projectedDepth > startDepth) {
          projectedDepth = startDepth;
        }
        if (projectedDepth > maxDepth) {
          mLastUpdate = 0u;
          return false;
        }
      }

      const Wm3::Sphere3f currentBeamSphere = BuildSegmentMidpointSphere(mBeam.mCurStart.pos_, mBeam.mCurEnd.pos_);
      if (!camera->solid2.Intersects(currentBeamSphere)) {
        const Wm3::Sphere3f lastBeamSphere = BuildSegmentMidpointSphere(mBeam.mLastStart.pos_, mBeam.mLastEnd.pos_);
        if (!camera->solid2.Intersects(lastBeamSphere)) {
          mLastUpdate = 0u;
          return false;
        }
      }
    }

    Sim* const sim = ResolveEffectManager(this)->GetSim();
    CArmyImpl* const focusArmy = ResolveFocusArmy(sim);
    if (!focusArmy) {
      return true;
    }

    if (mLastUpdate != 0u) {
      const std::uint32_t tickDelta = sim->mCurTick - mLastUpdate;
      if ((tickDelta % 5u) != 0u) {
        return mVisible;
      }
    } else {
      mLastUpdate = sim->mCurTick;
    }

    CAiReconDBImpl* const reconDb = focusArmy->GetReconDB();
    const bool startVisible = reconDb->ReconCanDetect(mBeam.mCurStart.pos_, static_cast<int>(RECON_LOSNow)) != RECON_None;
    mVisible = startVisible || reconDb->BeamIsVisible(mBeam);
    return mVisible;
  }

  /**
   * Address: 0x006585D0 (FUN_006585D0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards one CEfxBeam deserialize thunk alias into
   * `CEfxBeam::MemberDeserialize`.
   */
  void DeserializeCEfxBeamThunkVariantA(CEfxBeam* const object, gpg::ReadArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00658780 (FUN_00658780, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards a second CEfxBeam deserialize thunk alias into
   * `CEfxBeam::MemberDeserialize`.
   */
  void DeserializeCEfxBeamThunkVariantB(CEfxBeam* const object, gpg::ReadArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006585E0 (FUN_006585E0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CEfxBeam serialize thunk alias into
   * `CEfxBeam::MemberSerialize`.
   */
  void SerializeCEfxBeamThunkVariantA(const CEfxBeam* const object, gpg::WriteArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00658790 (FUN_00658790, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CEfxBeam serialize thunk alias into
   * `CEfxBeam::MemberSerialize`.
   */
  void SerializeCEfxBeamThunkVariantB(const CEfxBeam* const object, gpg::WriteArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * What it does:
   * Returns the cached reflection descriptor for `CEfxBeam`.
   */
  gpg::RType* CEfxBeam::StaticGetClass()
  {
    return ResolveCachedType<CEfxBeam>(sType);
  }
} // namespace moho
