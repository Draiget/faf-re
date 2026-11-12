#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "moho/effects/rendering/EffectOps.h"

namespace faf::headless
{
  /**
   * Plan WP9.1 step 2: encodes the sim's effect operations (moho/effects/rendering/EffectOps.h) as the server's
   * replication would send them, to measure their size. Not thread safe; the caller serialises `Record`/`EndBeat`.
   *
   * Each op is its `EEffectOp` byte, then (all but `CreateLightParticle`) the effect's id as an unsigned LEB128
   * varint, then its arguments in a fixed order per op:
   * - ints (entity, bone, army, parameter index, beam blend mode) as varints of the value plus one, so -1 is 0;
   * - floats as 4 little-endian bytes; a variable count (`SetVector`, `SetN`, `SetCurve`, parameter beams) goes
   *   first as a varint;
   * - blueprint ids and textures as a reference into a table of the names seen so far (0: none; n: entry n - 1).
   *   A name's first use takes the next free entry and sends its length (varint) and text after the reference;
   *   this stands in for the shared sorted blueprint list both sides would load.
   *
   * Effect ids are given at the create (counting up, never reused, so a client still drawing an effect whose end it
   * derives can't mistake a new one for it) and forgotten at any destroy. Ops on an effect never seen created are
   * dropped and counted. `Destroy` is never encoded: a client derives it (lifetime end, the entity's death,
   * fidelity), except after `DestroyByScript`, which is encoded instead. Several `SetFloat` to one (effect,
   * parameter) in a beat keep the last.
   *
   * Arguments are taken as flattened: `values` must hold a curve's bounds and keys and a parameter beam's floats
   * (`curve`/`beam` are ignored here; `ReplayEffectOps.cpp` flattens them).
   */
  class CEffectOpEncoder
  {
  public:
    static constexpr std::size_t kOps = static_cast<std::size_t>(moho::EEffectOp::Count);

    struct SBeat
    {
      std::uint32_t ops = 0;   // ops encoded
      std::uint32_t bytes = 0; // their bytes
    };

    void Record(moho::EEffectOp op, const moho::SEffectOpArgs& args);

    /** Encodes the ops recorded since the last call into `Bytes()`. */
    SBeat EndBeat();

    /** The last `EndBeat`'s encoding. */
    [[nodiscard]] const std::vector<std::uint8_t>& Bytes() const noexcept
    {
      return mBytes;
    }

    [[nodiscard]] std::uint64_t EncodedOps(
      moho::EEffectOp op
    ) const noexcept
    {
      return mEncodedOps[Index(op)];
    }
    [[nodiscard]] std::uint64_t EncodedBytes(
      moho::EEffectOp op
    ) const noexcept
    {
      return mEncodedBytes[Index(op)];
    }
    [[nodiscard]] std::uint64_t Dropped(
      moho::EEffectOp op
    ) const noexcept
    {
      return mDropped[Index(op)];
    }
    [[nodiscard]] std::uint64_t DroppedTotal() const noexcept;
    /** `Destroy`s left out: those not following a `DestroyByScript` of the same effect. */
    [[nodiscard]] std::uint64_t DerivedDestroys() const noexcept
    {
      return mDerivedDestroys;
    }
    /** `SetFloat`s replaced by a later one to the same (effect, parameter) in the same beat. */
    [[nodiscard]] std::uint64_t Coalesced() const noexcept
    {
      return mCoalesced;
    }
    [[nodiscard]] std::size_t BlueprintNames() const noexcept
    {
      return mBlueprints.texts.size();
    }
    [[nodiscard]] std::size_t TextureNames() const noexcept
    {
      return mTextures.texts.size();
    }
    [[nodiscard]] std::size_t LiveEffects() const noexcept
    {
      return mEffects.size();
    }

    static void AppendVarint(std::vector<std::uint8_t>& out, std::uint32_t value);

  private:
    struct SNameTable
    {
      std::unordered_map<std::string, std::uint32_t> indices;
      std::vector<std::string> texts;
    };

    // A name reference as recorded: 0 none, else entry + 1; `fresh` when this op is the name's first use.
    struct SNameRef
    {
      std::uint32_t ref = 0;
      bool fresh = false;
    };

    struct SPending
    {
      moho::EEffectOp op{};
      bool dead = false; // replaced by a later SetFloat
      std::uint32_t id = 0;
      std::int32_t entity = -1;
      std::int32_t bone = -1;
      std::int32_t entity2 = -1;
      std::int32_t bone2 = -1;
      std::int32_t army = -1;
      std::int32_t param = -1;
      SNameRef blueprint;
      SNameRef texture;
      SNameRef texture2;
      std::uint32_t floatOffset = 0;
      std::uint32_t floatCount = 0;
    };

    struct SEffectEntry
    {
      std::uint32_t id = 0;
      bool destroyedByScript = false;
    };

    [[nodiscard]] static std::size_t Index(
      moho::EEffectOp op
    ) noexcept
    {
      const auto index = static_cast<std::size_t>(op);
      return index < kOps ? index : kOps - 1u;
    }
    [[nodiscard]] static SNameRef Resolve(SNameTable& table, const char* name);
    void EncodeName(const SNameTable& table, SNameRef ref);
    void EncodeInt(std::int32_t value);
    void EncodeFloats(const SPending& pending, std::uint32_t fixedCount);

    std::unordered_map<const moho::IEffect*, SEffectEntry> mEffects;
    std::uint32_t mNextId = 0;
    SNameTable mBlueprints;
    SNameTable mTextures;

    std::vector<SPending> mPending;
    std::vector<float> mFloats;
    std::unordered_map<std::uint64_t, std::size_t> mLastSetFloat; // (id, param) -> mPending index, this beat
    std::vector<std::uint8_t> mBytes;

    std::array<std::uint64_t, kOps> mEncodedOps{};
    std::array<std::uint64_t, kOps> mEncodedBytes{};
    std::array<std::uint64_t, kOps> mDropped{};
    std::uint64_t mDerivedDestroys = 0;
    std::uint64_t mCoalesced = 0;
  };
} // namespace faf::headless
