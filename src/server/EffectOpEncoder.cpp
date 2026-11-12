#include "server/EffectOpEncoder.h"

#include <cstring>

namespace faf::server
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

  std::uint32_t CEffectOpEncoder::Resolve(
    SNameTable& table,
    const char* const name
  )
  {
    if (name == nullptr) {
      return 0u;
    }
    const auto [it, inserted] = table.indices.try_emplace(name, static_cast<std::uint32_t>(table.texts.size()));
    if (inserted) {
      table.texts.emplace_back(name);
      table.beatUsed.push_back(0u);
    }
    return it->second + 1u;
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
    SEffectBeat& beat,
    SNameTable& table,
    const EEffectNameTable which,
    const std::uint32_t ref
  )
  {
    AppendVarint(beat.ops, ref);
    if (ref == 0u) {
      return;
    }
    const std::uint32_t entry = ref - 1u;
    if (table.beatUsed[entry] != mBeatSerial) {
      table.beatUsed[entry] = mBeatSerial;
      beat.names.push_back(SEffectBeatName{which, entry, &table.texts[entry]});
    }
  }

  void CEffectOpEncoder::EncodeInt(
    std::vector<std::uint8_t>& out,
    const std::int32_t value
  )
  {
    AppendVarint(out, static_cast<std::uint32_t>(value) + 1u);
  }

  void CEffectOpEncoder::EncodeFloats(
    std::vector<std::uint8_t>& out,
    const SPending& pending,
    const std::uint32_t fixedCount
  ) const
  {
    // fixedCount 0: a variable count, sent first. Otherwise exactly that many, missing ones as 0.
    const std::uint32_t count = fixedCount != 0u ? fixedCount : pending.floatCount;
    if (fixedCount == 0u) {
      AppendVarint(out, count);
    }
    for (std::uint32_t i = 0; i < count; ++i) {
      const float value = i < pending.floatCount ? mFloats[pending.floatOffset + i] : 0.0f;
      std::uint32_t bits = 0;
      std::memcpy(&bits, &value, sizeof(bits));
      for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::uint8_t>(bits >> shift));
      }
    }
  }

  SEffectBeat CEffectOpEncoder::EndBeat()
  {
    SEffectBeat beat;
    ++mBeatSerial;
    std::vector<std::uint8_t>& out = beat.ops;
    for (const SPending& pending : mPending) {
      if (pending.dead) {
        continue;
      }
      const std::size_t start = out.size();
      out.push_back(static_cast<std::uint8_t>(pending.op));
      if (pending.op != EEffectOp::CreateLightParticle) {
        AppendVarint(out, pending.id);
      }
      switch (pending.op) {
      case EEffectOp::CreateEmitter:
        EncodeName(beat, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        EncodeFloats(out, pending, 3u);
        break;
      case EEffectOp::CreateAttachedEmitter:
      case EEffectOp::CreateEmitterAtBone:
      case EEffectOp::CreateTrail:
        EncodeInt(out, pending.entity);
        EncodeInt(out, pending.bone);
        EncodeName(beat, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        break;
      case EEffectOp::CreateEmitterAtEntity:
      case EEffectOp::CreateEmitterOnEntity:
        EncodeInt(out, pending.entity);
        EncodeName(beat, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        break;
      case EEffectOp::CreateBeam:
        EncodeName(beat, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        if (pending.blueprint == 0u) {
          // A beam from create parameters: attachment, texture, blend mode, then its floats.
          EncodeInt(out, pending.entity);
          EncodeInt(out, pending.bone);
          EncodeInt(out, pending.army);
          EncodeName(beat, mTextures, EEffectNameTable::Textures, pending.texture);
          EncodeInt(out, pending.param);
          EncodeFloats(out, pending, 0u);
        } else {
          EncodeInt(out, pending.army);
        }
        break;
      case EEffectOp::CreateBeamEntityToEntity:
      case EEffectOp::AttachBeamEntityToEntity:
        EncodeInt(out, pending.entity);
        EncodeInt(out, pending.bone);
        EncodeInt(out, pending.entity2);
        EncodeInt(out, pending.bone2);
        EncodeName(beat, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        break;
      case EEffectOp::CreateLightParticle:
        EncodeInt(out, pending.army);
        EncodeName(beat, mTextures, EEffectNameTable::Textures, pending.texture);
        EncodeName(beat, mTextures, EEffectNameTable::Textures, pending.texture2);
        EncodeFloats(out, pending, 5u);
        break;
      case EEffectOp::SetFloat:
        EncodeInt(out, pending.param);
        EncodeFloats(out, pending, 1u);
        break;
      case EEffectOp::SetVector:
      case EEffectOp::SetN:
      case EEffectOp::SetCurve:
        EncodeInt(out, pending.param);
        EncodeFloats(out, pending, 0u);
        break;
      case EEffectOp::SetEntity:
        EncodeInt(out, pending.entity);
        break;
      case EEffectOp::SetBone:
        EncodeInt(out, pending.entity);
        EncodeInt(out, pending.bone);
        break;
      case EEffectOp::DestroyByScript:
      case EEffectOp::Destroy:
      case EEffectOp::Count:
        break;
      }
      const auto bytes = static_cast<std::uint32_t>(out.size() - start);
      ++mEncodedOps[Index(pending.op)];
      mEncodedBytes[Index(pending.op)] += bytes;
      ++beat.opCount;
    }
    mPending.clear();
    mFloats.clear();
    mLastSetFloat.clear();
    return beat;
  }

  void CEffectLaneNames::Write(
    const SEffectBeat& beat,
    std::vector<std::uint8_t>& lane
  )
  {
    lane.clear();
    if (beat.opCount == 0u) {
      return;
    }
    // Per table: the count of names new to this view, then each one's entry, length and text.
    for (const EEffectNameTable table : {EEffectNameTable::Blueprints, EEffectNameTable::Textures}) {
      std::vector<bool>& sent = mSent[static_cast<std::size_t>(table)];
      std::uint32_t fresh = 0;
      for (const SEffectBeatName& name : beat.names) {
        if (name.table == table && (name.entry >= sent.size() || !sent[name.entry])) {
          ++fresh;
        }
      }
      CEffectOpEncoder::AppendVarint(lane, fresh);
      if (fresh == 0u) {
        continue;
      }
      for (const SEffectBeatName& name : beat.names) {
        if (name.table != table || (name.entry < sent.size() && sent[name.entry])) {
          continue;
        }
        if (name.entry >= sent.size()) {
          sent.resize(static_cast<std::size_t>(name.entry) + 1u, false);
        }
        sent[name.entry] = true;
        CEffectOpEncoder::AppendVarint(lane, name.entry);
        CEffectOpEncoder::AppendVarint(lane, static_cast<std::uint32_t>(name.text->size()));
        lane.insert(lane.end(), name.text->begin(), name.text->end());
        ++mNamesSent;
      }
    }
    lane.insert(lane.end(), beat.ops.begin(), beat.ops.end());
  }
} // namespace faf::server
