#include "moho/effects/rendering/CEfxEmitter.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>

#include "moho/ai/CAiReconDBImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/render/EEmitterParam.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "Wm3Sphere3.h"

namespace
{
  void RecomputeCurveYBoundsFromKeys(moho::SEfxCurve* const curve) noexcept
  {
    curve->mBoundsMin.y = std::numeric_limits<float>::infinity();
    curve->mBoundsMax.y = -std::numeric_limits<float>::infinity();

    for (Wm3::Vector3f* key = curve->mKeys.begin(); key != curve->mKeys.end(); ++key) {
      if (curve->mBoundsMin.y > key->y) {
        curve->mBoundsMin.y = key->y;
      }
      if (key->y > curve->mBoundsMax.y) {
        curve->mBoundsMax.y = key->y;
      }
    }
  }

  [[nodiscard]] moho::IEffectManager* ResolveEffectManager(const moho::IEffect* const effect) noexcept
  {
    const std::uintptr_t rawManager = static_cast<std::uintptr_t>(effect->mUnknown3C);
    return reinterpret_cast<moho::IEffectManager*>(rawManager);
  }

  [[nodiscard]] float ProjectViewportDepthRow1(const moho::VMatrix4& viewport, const Wm3::Vec3f& point) noexcept
  {
    return (point.x * viewport.r[1].x) + (point.y * viewport.r[1].y) + (point.z * viewport.r[1].z) + viewport.r[1].w;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0065C290 (FUN_0065C290, Moho::CEfxEmitter::UpdateCurveMask)
   *
   * What it does:
   * Rebuilds packed Z-curve mask bits by scanning every second emitter curve
   * lane and setting one bit when the lane has exactly one key and near-zero Z.
   */
  void CEfxEmitter::UpdateCurveMask()
  {
    mZCurveMask = 0u;

    SEfxCurve* const curves = mCurves.begin();
    for (std::uint32_t bitIndex = 0u; bitIndex < 21u; ++bitIndex) {
      SEfxCurve& curve = curves[bitIndex * 2u];
      if ((curve.mKeys.end() - curve.mKeys.begin()) != 1) {
        continue;
      }

      if (std::fabs(curve.mKeys.begin()->z) < std::fabs(0.001f)) {
        mZCurveMask |= (1u << bitIndex);
      }
    }
  }

  /**
   * Address: 0x0065C320 (FUN_0065C320, Moho::CEfxEmitter::SetCurveParam)
   *
   * What it does:
   * Copies one source curve bounds lane into the destination emitter slot,
   * recomputes source-curve Y bounds from key payload, and invalidates one
   * emitter parameter lane.
   */
  void CEfxEmitter::SetCurveParam(const std::int32_t paramIndex, const void* const curveData)
  {
    const auto* const sourceCurve = static_cast<const SEfxCurve*>(curveData);
    SEfxCurve& destinationCurve = mCurves.begin()[static_cast<std::size_t>(paramIndex) * 2u];
    destinationCurve.mBoundsMin = sourceCurve->mBoundsMin;
    destinationCurve.mBoundsMax = sourceCurve->mBoundsMax;

    RecomputeCurveYBoundsFromKeys(const_cast<SEfxCurve*>(sourceCurve));
    Invalidate2(paramIndex);
  }

  /**
   * Address: 0x0065C390 (FUN_0065C390, Moho::CEfxEmitter::Invalidate1)
   */
  void CEfxEmitter::Invalidate(const std::int32_t, const std::int32_t)
  {
    mValid = false;
  }

  /**
   * Address: 0x0065C3A0 (FUN_0065C3A0, Moho::CEfxEmitter::Invalidate2)
   */
  void CEfxEmitter::Invalidate2(const std::int32_t)
  {
    mValid = false;
  }

  /**
   * Address: 0x0065C420 (FUN_0065C420, Moho::CEfxEmitter::CanSeeCam)
   *
   * What it does:
   * Applies depth/frustum visibility checks and focused-army recon probes for
   * one camera.
   */
  bool CEfxEmitter::CanSeeCam(const GeomCamera3* const camera)
  {
    if (!camera) {
      mLastUpdate = 0u;
      return false;
    }

    const float lodCutoff = mParams.start_[EFFECT_LODCUTOFF];
    if (lodCutoff > 0.0f && ProjectViewportDepthRow1(camera->viewport, mPos) > lodCutoff) {
      mLastUpdate = 0u;
      return false;
    }

    Wm3::Sphere3f visibilitySphere{};
    visibilitySphere.Center = mPos;
    visibilitySphere.Radius = 5.0f;
    if (!camera->solid2.Intersects(visibilitySphere)) {
      mLastUpdate = 0u;
      return false;
    }

    Sim* const sim = ResolveEffectManager(this)->GetSim();
    if (!sim) {
      return true;
    }

    CArmyImpl** const armiesBegin = sim->mArmiesList.begin();
    if (!armiesBegin) {
      return true;
    }

    const int focusArmy = sim->mSyncFilter.focusArmy;
    if (focusArmy < 0 || static_cast<std::size_t>(focusArmy) >= sim->mArmiesList.size()) {
      return true;
    }

    CArmyImpl* const army = armiesBegin[focusArmy];
    if (!army) {
      return true;
    }

    if (mLastUpdate != 0u) {
      if (((sim->mCurTick - mLastUpdate) % 5u) != 0u) {
        return mVisible;
      }
    } else {
      mLastUpdate = sim->mCurTick;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    mVisible = reconDb->ReconCanDetect(mPos, static_cast<int>(RECON_LOSNow)) != RECON_None;
    return mVisible;
  }

  /**
   * Address: 0x0065C600 (FUN_0065C600, Moho::CEfxEmitter::IsVisible)
   *
   * What it does:
   * Scans sync cameras and returns whether this emitter should be processed
   * for the current tick.
   */
  bool CEfxEmitter::IsVisible()
  {
    if (mParams.start_[EFFECT_EMITIFVISIBLE] > 0.0f) {
      Sim* const sim = ResolveEffectManager(this)->GetSim();
      msvc8::vector<GeomCamera3>& cameras = sim->mSyncFilter.geoCams;
      GeomCamera3* const camerasEnd = cameras.end();
      GeomCamera3* camera = cameras.begin();

      if (camera == camerasEnd) {
        ++mLife;
        return false;
      }

      for (; camera != camerasEnd; ++camera) {
        if (!CanSeeCam(camera)) {
          continue;
        }

        if (!mNewAttachment) {
          break;
        }

        const float lodCutoff = mParams.start_[EFFECT_LODCUTOFF];
        if (lodCutoff <= 0.0f || ProjectViewportDepthRow1(camera->viewport, mPos) <= lodCutoff) {
          break;
        }
      }

      if (camera == camerasEnd) {
        ++mLife;
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x0065C700 (FUN_0065C700, Moho::CEfxEmitter::ProcessLifetime)
   *
   * What it does:
   * Applies lifetime/attachment visibility gates and destroys the effect
   * when one terminal condition is met.
   */
  bool CEfxEmitter::ProcessLifetime()
  {
    IEffectManager* const effectManager = ResolveEffectManager(this);
    const float* const params = mParams.start_;

    if (params[EFFECT_LIFETIME] >= 0.0f &&
        (static_cast<float>(static_cast<int>(mLife)) + params[EFFECT_TICKCOUNT]) >= params[EFFECT_LIFETIME]) {
      effectManager->DestroyEffect(this);
      return true;
    }

    if (mNewAttachment != 0u) {
      const Entity* const attachedEntity = mEntityInfo.GetAttachTargetEntity();
      if (attachedEntity == nullptr || attachedEntity->DestroyQueuedFlag != 0u) {
        effectManager->DestroyEffect(this);
        return true;
      }
    }

    if (mParams.start_[EFFECT_CREATEIFVISIBLE] > 0.0f) {
      msvc8::vector<GeomCamera3>& cameras = effectManager->GetSim()->mSyncFilter.geoCams;
      for (GeomCamera3* camera = cameras.begin(); camera != cameras.end(); ++camera) {
        if (!CanSeeCam(camera)) {
          continue;
        }

        mParams.start_[EFFECT_CREATEIFVISIBLE] = 0.0f;
        return false;
      }

      effectManager->DestroyEffect(this);
      return true;
    }

    return false;
  }
} // namespace moho
