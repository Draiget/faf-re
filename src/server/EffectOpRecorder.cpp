#include "server/EffectOpRecorder.h"

#include <atomic>
#include <mutex>

#include "moho/effects/rendering/IEffectManager.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/entity/Entity.h"

namespace faf::server
{
  namespace
  {
    std::mutex sLock;
    std::atomic<bool> sAttached{false};     // spares the copy and the lock when nothing records
    CEffectOpRecorder* sRecorder = nullptr; // under sLock
  } // namespace

  void FlattenEffectOpArgs(
    moho::SEffectOpArgs& args,
    std::vector<float>& floats
  )
  {
    if (const moho::SEfxCurve* const curve = args.curve; curve != nullptr) {
      floats = {curve->mBoundsMin.x, curve->mBoundsMin.y, curve->mBoundsMax.x, curve->mBoundsMax.y};
      for (const Wm3::Vector3f& key : curve->mKeys) {
        floats.insert(floats.end(), {key.x, key.y, key.z});
      }
      args.values = floats.data();
      args.valueCount = static_cast<std::uint32_t>(floats.size());
    }
    if (const moho::SCreateBeamParams* const beam = args.beam; beam != nullptr) {
      floats = {
        beam->mStart.x,
        beam->mStart.y,
        beam->mStart.z,
        beam->mEnd.x,
        beam->mEnd.y,
        beam->mEnd.z,
        beam->mLifetime,
        beam->mWidth,
        beam->mTextureScale,
        // Plan WP9.5: the colour (the beam's start and end colour, 0x00654A70) and the UV shifts and repeat rate.
        beam->mSpawnTransform.mOrientation[0],
        beam->mSpawnTransform.mOrientation[1],
        beam->mSpawnTransform.mOrientation[2],
        beam->mSpawnTransform.mOrientation[3],
        beam->mSpawnTransform.mPosition.x,
        beam->mSpawnTransform.mPosition.y,
        beam->mSpawnTransform.mPosition.z
      };
      args.entity = moho::EffectOpEntity(beam->mAttachEntity);
      args.bone = beam->mAttachBoneIndex;
      args.army = beam->mAttachArmyIndex;
      args.texture = beam->mTexture.c_str();
      args.param = beam->mBlendMode;
      args.values = floats.data();
      args.valueCount = static_cast<std::uint32_t>(floats.size());
    }
  }

  CEffectOpRecorder::~CEffectOpRecorder()
  {
    Detach();
  }

  void CEffectOpRecorder::Attach()
  {
    const std::lock_guard<std::mutex> lock(sLock);
    sRecorder = this;
    sAttached.store(true, std::memory_order_release);
  }

  void CEffectOpRecorder::Detach()
  {
    const std::lock_guard<std::mutex> lock(sLock);
    if (sRecorder == this) {
      sRecorder = nullptr;
      sAttached.store(false, std::memory_order_release);
    }
  }

  void CEffectOpRecorder::Hook(
    const moho::EEffectOp op,
    const moho::SEffectOpArgs& args
  )
  {
    if (!sAttached.load(std::memory_order_acquire)) {
      return;
    }
    // The pointers in `args` are valid only during the call: flatten before the lock, record under it.
    moho::SEffectOpArgs flat = args;
    thread_local std::vector<float> floats;
    FlattenEffectOpArgs(flat, floats);
    const std::lock_guard<std::mutex> lock(sLock);
    if (sRecorder != nullptr) {
      sRecorder->mEncoder.Record(op, flat);
    }
  }

  SEffectBeat CEffectOpRecorder::EndBeat(
    const bool ticked
  )
  {
    const std::lock_guard<std::mutex> lock(sLock);
    return mEncoder.EndBeat(ticked);
  }

  bool CEffectOpRecorder::IdOf(
    const moho::IEffect* const effect,
    std::uint32_t& id
  ) const
  {
    const std::lock_guard<std::mutex> lock(sLock);
    return mEncoder.IdOf(effect, id);
  }
} // namespace faf::server
