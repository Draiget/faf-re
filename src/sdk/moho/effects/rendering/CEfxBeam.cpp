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
#include "moho/entity/Entity.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/render/EBeamParam.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/resource/CParticleTexture.h"
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

  [[nodiscard]] moho::Entity* ResolveAttachEntity(const moho::SEntAttachInfo& attachInfo) noexcept
  {
    return attachInfo.GetAttachTargetEntity();
  }

  [[nodiscard]] bool IsAttachmentInvalid(const moho::Entity* const entity) noexcept
  {
    return entity == nullptr || entity->DestroyQueuedFlag != 0u;
  }

  [[nodiscard]] moho::VTransform ReadCurrentTransform(const moho::Entity& entity) noexcept
  {
    return moho::BuildVTransformFromEntityTransformPayload(
      moho::ReadEntityTransformPayload(entity.Orientation, entity.Position)
    );
  }

  [[nodiscard]] moho::VTransform ReadPreviousTransform(const moho::Entity& entity) noexcept
  {
    return moho::BuildVTransformFromEntityTransformPayload(
      moho::ReadEntityTransformPayload(entity.PrevOrientation, entity.PrevPosition)
    );
  }

  [[nodiscard]] Wm3::Vec3f FetchVectorParam(moho::CEfxBeam& beam, const std::int32_t paramIndex)
  {
    Wm3::Vec3f value{};
    beam.GetVectorParam(&value, paramIndex);
    return value;
  }

  [[nodiscard]] Wm3::Vec3f ApplyPoint(const moho::VTransform& transform, const Wm3::Vec3f& point)
  {
    Wm3::Vec3f out{};
    transform.Apply(point, &out);
    return out;
  }

  void SetIdentityTransform(moho::VTransform& transform) noexcept
  {
    transform.orient_.x = 1.0f;
    transform.orient_.y = 0.0f;
    transform.orient_.z = 0.0f;
    transform.orient_.w = 0.0f;
    transform.pos_.x = 0.0f;
    transform.pos_.y = 0.0f;
    transform.pos_.z = 0.0f;
  }

  /**
   * Address: 0x00658EC0 (FUN_00658EC0)
   *
   * What it does:
   * Returns cached reflected type metadata for `SEntAttachInfo`, resolving it
   * through RTTI lookup on first use.
   */
  [[nodiscard]] gpg::RType* CachedSEntAttachInfoType()
  {
    gpg::RType* type = moho::SEntAttachInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SEntAttachInfo));
      moho::SEntAttachInfo::sType = type;
    }

    return type;
  }
} // namespace

namespace moho
{
  gpg::RType* CEfxBeam::sType = nullptr;

  /**
   * Address: 0x00658DA0 (FUN_00658DA0)
   *
   * What it does:
   * Reads one `CEffectImpl` base object through archive RTTI dispatch,
   * resolving and caching the `CEffectImpl` reflection type on first use.
   */
  void ReadCEfxBeamBaseEffectImplAdapter(
    gpg::ReadArchive* const archive, void* const object, const gpg::RRef& owner
  )
  {
    gpg::RType* type = CEffectImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CEffectImpl));
      CEffectImpl::sType = type;
    }
    archive->Read(type, object, owner);
  }

  /**
   * Address: 0x00658DD0 (FUN_00658DD0)
   *
   * What it does:
   * Writes one `CEffectImpl` base object through archive RTTI dispatch,
   * resolving and caching the `CEffectImpl` reflection type on first use.
   */
  void WriteCEfxBeamBaseEffectImplAdapter(
    gpg::WriteArchive* const archive, const void* const object, const gpg::RRef& owner
  )
  {
    gpg::RType* type = CEffectImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CEffectImpl));
      CEffectImpl::sType = type;
    }
    archive->Write(type, object, owner);
  }

  /**
   * Address: 0x00658E00 (FUN_00658E00)
   *
   * What it does:
   * Reads one `SEntAttachInfo` payload through archive RTTI dispatch,
   * resolving and caching the attach-info reflection type on first use.
   */
  void ReadCEfxBeamAttachInfoAdapter(
    gpg::ReadArchive* const archive, void* const object, const gpg::RRef& owner
  )
  {
    archive->Read(CachedSEntAttachInfoType(), object, owner);
  }

  /**
   * Address: 0x00658E30 (FUN_00658E30)
   *
   * What it does:
   * Writes one `SEntAttachInfo` payload through archive RTTI dispatch,
   * resolving and caching the attach-info reflection type on first use.
   */
  void WriteCEfxBeamAttachInfoAdapter(
    gpg::WriteArchive* const archive, const void* const object, const gpg::RRef& owner
  )
  {
    archive->Write(CachedSEntAttachInfoType(), object, owner);
  }

  /**
   * Address: 0x00658E60 (FUN_00658E60)
   *
   * What it does:
   * Reads one `SWorldBeam` payload through archive RTTI dispatch, resolving and
   * caching the beam-payload reflection type on first use.
   */
  void ReadCEfxBeamWorldBeamAdapter(
    gpg::ReadArchive* const archive, void* const object, const gpg::RRef& owner
  )
  {
    gpg::RType* type = SWorldBeam::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SWorldBeam));
      SWorldBeam::sType = type;
    }
    archive->Read(type, object, owner);
  }

  /**
   * Address: 0x00658E90 (FUN_00658E90)
   *
   * What it does:
   * Writes one `SWorldBeam` payload through archive RTTI dispatch, resolving and
   * caching the beam-payload reflection type on first use.
   */
  void WriteCEfxBeamWorldBeamAdapter(
    gpg::WriteArchive* const archive, const void* const object, const gpg::RRef& owner
  )
  {
    gpg::RType* type = SWorldBeam::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SWorldBeam));
      SWorldBeam::sType = type;
    }
    archive->Write(type, object, owner);
  }

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
   * Address: 0x00655D80 (FUN_00655D80, non-deleting destructor body)
   * Thunk entry: 0x00655B80 (FUN_00655B80, Moho::CEfxBeam::dtr)
   */
  CEfxBeam::~CEfxBeam()
  {
    ResetCountedParticleTexturePtr(mBeam.mTexture1);
    ResetCountedParticleTexturePtr(mBeam.mTexture2);
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
    ReadCEfxBeamBaseEffectImplAdapter(archive, static_cast<CEffectImpl*>(this), nullOwner);
    archive->ReadInt(&mBlendMode);
    archive->ReadBool(&mVisible);
    archive->ReadUInt(&mLastUpdate);
    ReadCEfxBeamAttachInfoAdapter(archive, &mEnd, nullOwner);
    ReadCEfxBeamWorldBeamAdapter(archive, &mBeam, nullOwner);
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
    WriteCEfxBeamBaseEffectImplAdapter(archive, static_cast<const CEffectImpl*>(this), nullOwner);
    archive->WriteInt(mBlendMode);
    archive->WriteBool(mVisible);
    archive->WriteUInt(mLastUpdate);
    WriteCEfxBeamAttachInfoAdapter(archive, &mEnd, nullOwner);
    WriteCEfxBeamWorldBeamAdapter(archive, &mBeam, nullOwner);
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
   * Address: 0x00654D40 (FUN_00654D40, Moho::CEfxBeam::Reset)
   *
   * What it does:
   * Rebuilds beam render parameters from effect params, rebinding beam
   * textures and width/scroll/repeat lanes.
   */
  void CEfxBeam::Reset()
  {
    Vector4f quatValue{};
    mBeam.mStartColor = *GetQuatParam(&quatValue, BEAM_STARTCOLOR);
    mBeam.mEndColor = *GetQuatParam(&quatValue, BEAM_ENDCOLOR);

    CParticleTexture* texture = nullptr;
    (void)GetTextureParam(&texture, 0);
    (void)AssignCountedParticleTexturePtr(&mBeam.mTexture1, texture);
    if (texture != nullptr) {
      (void)texture->ReleaseReferenceAtomic();
    }

    texture = nullptr;
    (void)GetTextureParam(&texture, 1);
    (void)AssignCountedParticleTexturePtr(&mBeam.mTexture2, texture);
    if (texture != nullptr) {
      (void)texture->ReleaseReferenceAtomic();
    }

    mBeam.mWidth = GetFloatParam(BEAM_THICKNESS);
    mBeam.mBlendMode = static_cast<SWorldBeam::BlendMode>(mBlendMode);
    mBeam.mRepeatRate = GetFloatParam(BEAM_REPEATRATE);
    mBeam.mUShift = GetFloatParam(BEAM_USHIFT);
    mBeam.mVShift = GetFloatParam(BEAM_VSHIFT);
  }

  /**
   * Address: 0x00654F30 (FUN_00654F30, Moho::CEfxBeam::Update)
   *
   * What it does:
   * Updates beam endpoint transforms from current attachment state and
   * handles detach/destroy paths for invalid source attachments.
   */
  bool CEfxBeam::Update()
  {
    if (mNewAttachment) {
      Entity* const sourceEntity = ResolveAttachEntity(mEntityInfo);
      if (IsAttachmentInvalid(sourceEntity)) {
        ResolveEffectManager(this)->DestroyEffect(this);
        return false;
      }

      Entity* const endEntity = ResolveAttachEntity(mEnd);
      if (endEntity == nullptr) {
        mBeam.mFromStart = false;
        mBeam.mCurStart = ReadCurrentTransform(*sourceEntity);
        mBeam.mLastStart = ReadPreviousTransform(*sourceEntity);
        mBeam.mStart = FetchVectorParam(*this, 0);

        const float beamLength = GetFloatParam(6);
        mBeam.mEnd.x = 0.0f;
        mBeam.mEnd.y = 0.0f;
        mBeam.mEnd.z = beamLength;
        mBeam.mLastInterpolation = sourceEntity->mVelocityScale;

        if (mEntityInfo.mParentBoneIndex != -1) {
          const VTransform sourceBoneTransform = sourceEntity->GetBoneLocalTransform(mEntityInfo.mParentBoneIndex);
          mBeam.mStart = ApplyPoint(sourceBoneTransform, mBeam.mStart);
          mBeam.mEnd = ApplyPoint(sourceBoneTransform, mBeam.mEnd);
        }

        mBeam.mCurEnd.pos_ = ApplyPoint(mBeam.mCurStart, mBeam.mEnd);
        mBeam.mLastEnd.pos_ = ApplyPoint(mBeam.mLastStart, mBeam.mEnd);
      } else {
        mBeam.mFromStart = true;
        mBeam.mCurStart = ReadCurrentTransform(*sourceEntity);
        mBeam.mLastStart = ReadPreviousTransform(*sourceEntity);
        mBeam.mCurEnd = ReadCurrentTransform(*endEntity);
        mBeam.mLastEnd = ReadPreviousTransform(*endEntity);

        const VTransform sourceBoneTransform = sourceEntity->GetBoneLocalTransform(mEntityInfo.mParentBoneIndex);
        const Wm3::Vec3f localStart = FetchVectorParam(*this, 0);
        mBeam.mStart = ApplyPoint(sourceBoneTransform, localStart);

        const VTransform endBoneTransform = endEntity->GetBoneLocalTransform(mEnd.mParentBoneIndex);
        const Wm3::Vec3f localEnd = FetchVectorParam(*this, 3);
        mBeam.mEnd = ApplyPoint(endBoneTransform, localEnd);

        mBeam.mLastInterpolation = sourceEntity->mVelocityScale;
      }

      if (mIsNew) {
        Entity* const classificationEntity = ResolveAttachEntity(mEntityInfo);
        if (classificationEntity != nullptr && !classificationEntity->IsCollisionBeam() &&
            !classificationEntity->IsProjectile() && !classificationEntity->IsUnit()) {
          mIsNew = false;
          return true;
        }
      }
    } else {
      mBeam.mFromStart = false;
      SetIdentityTransform(mBeam.mCurStart);
      SetIdentityTransform(mBeam.mLastStart);
      mBeam.mLastInterpolation = 1.0f;
      mBeam.mStart = FetchVectorParam(*this, 0);
      mBeam.mEnd = FetchVectorParam(*this, 3);
      mIsNew = false;
    }

    return true;
  }

  /**
   * Address: 0x00655B50 (FUN_00655B50, Moho::CEfxBeam::AttachEntityToEntity)
   *
   * What it does:
   * Sets source attachment lanes, stores one weak end-target entity pointer,
   * and clamps negative target-bone indices to zero.
   */
  void CEfxBeam::AttachEntityToEntity(
    Entity* const sourceEntity,
    const std::int32_t sourceBoneIndex,
    Entity* const targetEntity,
    const std::int32_t targetBoneIndex
  )
  {
    SetBone(sourceEntity, sourceBoneIndex);
    mEnd.mAttachTargetWeak.ResetFromObject(targetEntity);
    mEnd.mParentBoneIndex = targetBoneIndex < 0 ? 0 : targetBoneIndex;
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
   * Address: 0x0085ED60 (FUN_0085ED60)
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
