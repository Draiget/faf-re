#include "headless/EffectOpEncoder.h"

#include <cstring>

namespace faf::headless
{
  using moho::EEffectOp;

  namespace
  {
    [[nodiscard]] bool IsCreate(
      const EEffectOp op
    ) noexcept
    {
      return op <= EEffectOp::CreateLightParticle;
    }
  } // namespace

  void CEffectOpEncoder::AppendVarint(
    std::vector<std::uint8_t>& out,
    std::uint32_t value
  )
  {
    while (value >= 0x80u) {
      out.push_back(static_cast<std::uint8_t>((value & 0x7Fu) | 0x80u));
      value >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(value));
  }

  std::uint64_t CEffectOpEncoder::DroppedTotal() const noexcept
  {
    std::uint64_t total = 0;
    for (const std::uint64_t dropped : mDropped) {
      total += dropped;
    }
    return total;
  }

  CEffectOpEncoder::SNameRef CEffectOpEncoder::Resolve(
    SNameTable& table,
    const char* const name
  )
  {
    if (name == nullptr) {
      return {};
    }
    const auto [it, inserted] = table.indices.try_emplace(name, static_cast<std::uint32_t>(table.texts.size()));
    if (inserted) {
      table.texts.emplace_back(name);
    }
    return {it->second + 1u, inserted};
  }

  void CEffectOpEncoder::Record(
    const EEffectOp op,
    const moho::SEffectOpArgs& args
  )
  {
    SPending pending;
    pending.op = op;

    if (op == EEffectOp::Destroy || op == EEffectOp::DestroyByScript) {
      const auto it = mEffects.find(args.effect);
      if (it == mEffects.end()) {
        ++mDropped[Index(op)];
        return;
      }
      if (op == EEffectOp::Destroy) {
        // The engine's own destroy follows every `IEffect:Destroy()`; only the others are a client's to derive.
        if (!it->second.destroyedByScript) {
          ++mDerivedDestroys;
        }
        mEffects.erase(it);
        return;
      }
      if (it->second.destroyedByScript) {
        ++mDropped[Index(op)];
        return;
      }
      it->second.destroyedByScript = true;
      pending.id = it->second.id;
      mPending.push_back(pending);
      return;
    }

    if (IsCreate(op)) {
      if (op != EEffectOp::CreateLightParticle) {
        pending.id = mNextId++;
        mEffects[args.effect] = SEffectEntry{pending.id, false};
      }
    } else {
      const auto it = mEffects.find(args.effect);
      if (it == mEffects.end() || it->second.destroyedByScript) {
        ++mDropped[Index(op)];
        return;
      }
      pending.id = it->second.id;
    }

    pending.entity = args.entity;
    pending.bone = args.bone;
    pending.entity2 = args.entity2;
    pending.bone2 = args.bone2;
    pending.army = args.army;
    pending.param = args.param;
    pending.blueprint = Resolve(mBlueprints, args.blueprint);
    pending.texture = Resolve(mTextures, args.texture);
    pending.texture2 = Resolve(mTextures, args.texture2);
    pending.floatOffset = static_cast<std::uint32_t>(mFloats.size());
    pending.floatCount = args.values != nullptr ? args.valueCount : 0u;
    mFloats.insert(mFloats.end(), args.values, args.values + pending.floatCount);

    if (op == EEffectOp::SetFloat) {
      const std::uint64_t key =
        (static_cast<std::uint64_t>(pending.id) << 32) | static_cast<std::uint32_t>(pending.param);
      const auto [it, inserted] = mLastSetFloat.try_emplace(key, mPending.size());
      if (!inserted) {
        mPending[it->second].dead = true;
        it->second = mPending.size();
        ++mCoalesced;
      }
    }
    mPending.push_back(pending);
  }

  void CEffectOpEncoder::EncodeName(
    const SNameTable& table,
    const SNameRef ref
  )
  {
    AppendVarint(mBytes, ref.ref);
    if (ref.fresh) {
      const std::string& text = table.texts[ref.ref - 1u];
      AppendVarint(mBytes, static_cast<std::uint32_t>(text.size()));
      mBytes.insert(mBytes.end(), text.begin(), text.end());
    }
  }

  void CEffectOpEncoder::EncodeInt(
    const std::int32_t value
  )
  {
    AppendVarint(mBytes, static_cast<std::uint32_t>(value) + 1u);
  }

  void CEffectOpEncoder::EncodeFloats(
    const SPending& pending,
    const std::uint32_t fixedCount
  )
  {
    // fixedCount 0: a variable count, sent first. Otherwise exactly that many, missing ones as 0.
    const std::uint32_t count = fixedCount != 0u ? fixedCount : pending.floatCount;
    if (fixedCount == 0u) {
      AppendVarint(mBytes, count);
    }
    for (std::uint32_t i = 0; i < count; ++i) {
      const float value = i < pending.floatCount ? mFloats[pending.floatOffset + i] : 0.0f;
      std::uint32_t bits = 0;
      std::memcpy(&bits, &value, sizeof(bits));
      for (int shift = 0; shift < 32; shift += 8) {
        mBytes.push_back(static_cast<std::uint8_t>(bits >> shift));
      }
    }
  }

  CEffectOpEncoder::SBeat CEffectOpEncoder::EndBeat()
  {
    SBeat beat;
    mBytes.clear();
    for (const SPending& pending : mPending) {
      if (pending.dead) {
        continue;
      }
      const std::size_t start = mBytes.size();
      mBytes.push_back(static_cast<std::uint8_t>(pending.op));
      if (pending.op != EEffectOp::CreateLightParticle) {
        AppendVarint(mBytes, pending.id);
      }
      switch (pending.op) {
      case EEffectOp::CreateEmitter:
        EncodeName(mBlueprints, pending.blueprint);
        EncodeInt(pending.army);
        EncodeFloats(pending, 3u);
        break;
      case EEffectOp::CreateAttachedEmitter:
      case EEffectOp::CreateEmitterAtBone:
      case EEffectOp::CreateTrail:
        EncodeInt(pending.entity);
        EncodeInt(pending.bone);
        EncodeName(mBlueprints, pending.blueprint);
        EncodeInt(pending.army);
        break;
      case EEffectOp::CreateEmitterAtEntity:
      case EEffectOp::CreateEmitterOnEntity:
        EncodeInt(pending.entity);
        EncodeName(mBlueprints, pending.blueprint);
        EncodeInt(pending.army);
        break;
      case EEffectOp::CreateBeam:
        EncodeName(mBlueprints, pending.blueprint);
        if (pending.blueprint.ref == 0u) {
          // A beam from create parameters: attachment, texture, blend mode, then its floats.
          EncodeInt(pending.entity);
          EncodeInt(pending.bone);
          EncodeInt(pending.army);
          EncodeName(mTextures, pending.texture);
          EncodeInt(pending.param);
          EncodeFloats(pending, 0u);
        } else {
          EncodeInt(pending.army);
        }
        break;
      case EEffectOp::CreateBeamEntityToEntity:
      case EEffectOp::AttachBeamEntityToEntity:
        EncodeInt(pending.entity);
        EncodeInt(pending.bone);
        EncodeInt(pending.entity2);
        EncodeInt(pending.bone2);
        EncodeName(mBlueprints, pending.blueprint);
        EncodeInt(pending.army);
        break;
      case EEffectOp::CreateLightParticle:
        EncodeInt(pending.army);
        EncodeName(mTextures, pending.texture);
        EncodeName(mTextures, pending.texture2);
        EncodeFloats(pending, 5u);
        break;
      case EEffectOp::SetFloat:
        EncodeInt(pending.param);
        EncodeFloats(pending, 1u);
        break;
      case EEffectOp::SetVector:
      case EEffectOp::SetN:
      case EEffectOp::SetCurve:
        EncodeInt(pending.param);
        EncodeFloats(pending, 0u);
        break;
      case EEffectOp::SetEntity:
        EncodeInt(pending.entity);
        break;
      case EEffectOp::SetBone:
        EncodeInt(pending.entity);
        EncodeInt(pending.bone);
        break;
      case EEffectOp::DestroyByScript:
      case EEffectOp::Destroy:
      case EEffectOp::Count:
        break;
      }
      const auto bytes = static_cast<std::uint32_t>(mBytes.size() - start);
      ++mEncodedOps[Index(pending.op)];
      mEncodedBytes[Index(pending.op)] += bytes;
      ++beat.ops;
      beat.bytes += bytes;
    }
    mPending.clear();
    mFloats.clear();
    mLastSetFloat.clear();
    return beat;
  }
} // namespace faf::headless
