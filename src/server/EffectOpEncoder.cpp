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
        mEnded.push_back(it->second.id);
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
    pending.armies = args.armies;
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
    SEffectBeatOp& op,
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
    const SEffectBeatName name{which, entry, &table.texts[entry]};
    if (table.beatUsed[entry] != mBeatSerial) {
      table.beatUsed[entry] = mBeatSerial;
      beat.names.push_back(name);
    }
    if (op.nameCount < op.names.size()) {
      op.names[op.nameCount++] = name;
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
      SEffectBeatOp entry;
      entry.offset = static_cast<std::uint32_t>(start);
      entry.op = pending.op;
      entry.id = pending.id;
      entry.param = pending.param;
      entry.armies = pending.armies;
      out.push_back(static_cast<std::uint8_t>(pending.op));
      if (pending.op != EEffectOp::CreateLightParticle) {
        AppendVarint(out, pending.id);
      }
      switch (pending.op) {
      case EEffectOp::CreateEmitter:
        EncodeName(beat, entry, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        EncodeFloats(out, pending, 3u);
        break;
      case EEffectOp::CreateAttachedEmitter:
      case EEffectOp::CreateEmitterAtBone:
      case EEffectOp::CreateTrail:
        EncodeInt(out, pending.entity);
        EncodeInt(out, pending.bone);
        EncodeName(beat, entry, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        break;
      case EEffectOp::CreateEmitterAtEntity:
      case EEffectOp::CreateEmitterOnEntity:
        EncodeInt(out, pending.entity);
        EncodeName(beat, entry, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        break;
      case EEffectOp::CreateBeam:
        EncodeName(beat, entry, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        if (pending.blueprint == 0u) {
          // A beam from create parameters: attachment, texture, blend mode, then its floats.
          EncodeInt(out, pending.entity);
          EncodeInt(out, pending.bone);
          EncodeInt(out, pending.army);
          EncodeName(beat, entry, mTextures, EEffectNameTable::Textures, pending.texture);
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
        EncodeName(beat, entry, mBlueprints, EEffectNameTable::Blueprints, pending.blueprint);
        EncodeInt(out, pending.army);
        break;
      case EEffectOp::CreateLightParticle:
        EncodeInt(out, pending.army);
        EncodeName(beat, entry, mTextures, EEffectNameTable::Textures, pending.texture);
        EncodeName(beat, entry, mTextures, EEffectNameTable::Textures, pending.texture2);
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
      // Plan WP9.2: what routing needs: the entities a create or an attach names, where a positioned one is.
      switch (pending.op) {
      case EEffectOp::CreateEmitter:
      case EEffectOp::CreateLightParticle:
        for (std::uint32_t i = 0; i < 3u && i < pending.floatCount; ++i) {
          entry.position[i] = mFloats[pending.floatOffset + i];
        }
        break;
      case EEffectOp::CreateAttachedEmitter:
      case EEffectOp::CreateEmitterAtBone:
      case EEffectOp::CreateEmitterAtEntity:
      case EEffectOp::CreateEmitterOnEntity:
      case EEffectOp::CreateTrail:
      case EEffectOp::CreateBeam:
      case EEffectOp::CreateBeamEntityToEntity:
      case EEffectOp::AttachBeamEntityToEntity:
      case EEffectOp::SetEntity:
      case EEffectOp::SetBone:
        entry.entity = pending.entity;
        entry.entity2 = pending.entity2;
        break;
      case EEffectOp::Destroy:
      case EEffectOp::SetFloat:
      case EEffectOp::SetVector:
      case EEffectOp::SetN:
      case EEffectOp::SetCurve:
      case EEffectOp::DestroyByScript:
      case EEffectOp::Count:
        break;
      }
      entry.size = bytes;
      beat.list.push_back(entry);
      ++mEncodedOps[Index(pending.op)];
      mEncodedBytes[Index(pending.op)] += bytes;
      ++beat.opCount;
    }
    beat.ended.swap(mEnded);
    mEnded.clear();
    mPending.clear();
    mFloats.clear();
    mLastSetFloat.clear();
    return beat;
  }

  void CEffectLaneNames::Need(
    const SEffectBeatName& name
  )
  {
    std::vector<bool>& sent = mSent[static_cast<std::size_t>(name.table)];
    if (name.entry < sent.size() && sent[name.entry]) {
      return;
    }
    if (name.entry >= sent.size()) {
      sent.resize(static_cast<std::size_t>(name.entry) + 1u, false);
    }
    sent[name.entry] = true;
    mNew.push_back(name);
  }

  void CEffectLaneNames::Finish(
    const std::span<const std::uint8_t> ops,
    const std::uint32_t opCount,
    std::vector<std::uint8_t>& lane
  )
  {
    lane.clear();
    if (opCount == 0u) {
      return;
    }
    // Per table: the count of names new to this view, then each one's entry, length and text.
    for (const EEffectNameTable table : {EEffectNameTable::Blueprints, EEffectNameTable::Textures}) {
      std::uint32_t fresh = 0;
      for (const SEffectBeatName& name : mNew) {
        fresh += name.table == table ? 1u : 0u;
      }
      CEffectOpEncoder::AppendVarint(lane, fresh);
      for (const SEffectBeatName& name : mNew) {
        if (name.table != table) {
          continue;
        }
        CEffectOpEncoder::AppendVarint(lane, name.entry);
        CEffectOpEncoder::AppendVarint(lane, static_cast<std::uint32_t>(name.text->size()));
        lane.insert(lane.end(), name.text->begin(), name.text->end());
        ++mNamesSent;
      }
    }
    mNew.clear();
    lane.insert(lane.end(), ops.begin(), ops.end());
  }

  void CEffectLaneNames::Write(
    const SEffectBeat& beat,
    std::vector<std::uint8_t>& lane
  )
  {
    Begin();
    if (beat.opCount != 0u) {
      for (const SEffectBeatName& name : beat.names) {
        Need(name);
      }
    }
    Finish(beat.ops, beat.opCount, lane);
  }
} // namespace faf::server
