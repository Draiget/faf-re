#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "moho/effects/rendering/EffectOps.h"

namespace faf::server
{
  /** Which name table a name is in. */
  enum class EEffectNameTable : std::uint8_t
  {
    Blueprints = 0,
    Textures = 1,
  };

  /** One name a beat's ops refer to. `text` stays valid as long as its encoder. */
  struct SEffectBeatName
  {
    EEffectNameTable table = EEffectNameTable::Blueprints;
    std::uint32_t entry = 0;
    const std::string* text = nullptr;
  };

  /** Plan WP9.2: one op of a beat, where its bytes are and what routing it to the views needs. */
  struct SEffectBeatOp
  {
    std::uint32_t offset = 0; // in `SEffectBeat::ops`
    std::uint32_t size = 0;
    moho::EEffectOp op = moho::EEffectOp::Count;
    std::uint8_t nameCount = 0;
    std::uint32_t id = 0;                   // the effect's (not for `CreateLightParticle`)
    std::int32_t entity = -1;               // the entities it names: creates, `SetEntity`, `SetBone`
    std::int32_t entity2 = -1;              // a beam's other end
    std::int32_t param = -1;                // a setter's parameter
    std::array<SEffectBeatName, 2> names{}; // the names it refers to (`nameCount` of them)
    std::array<float, 3> position{};        // `CreateEmitter`, `CreateLightParticle`: where it is
    std::uint32_t armies = ~0u; // `CreateLightParticle`: the armies whose intel shows it (all for a plain light)
    std::uint32_t views = 0;    // `CreateLightParticle`: the views it goes to, set by the server before the views
  };

  /** One beat's encoded ops, the same for every view (`CEffectLaneNames` makes each view's lane of it). */
  struct SEffectBeat
  {
    std::vector<std::uint8_t> ops; // the ops, names as references only
    std::uint32_t opCount = 0;
    std::vector<SEffectBeatName> names; // every name the ops refer to, once, in first-use order
    std::vector<SEffectBeatOp> list;    // plan WP9.2: each op of `ops`, in order
    std::vector<std::uint32_t> ended;   // plan WP9.2: effects destroyed this beat (any destroy, derived ones too)
  };

  /**
   * Plan WP9.1 steps 2 and 3: encodes the sim's effect operations (moho/effects/rendering/EffectOps.h) as the server's
   * effects lane sends them (remote/wire/EffectLane.h has the lane's layout and its reader). The server records every
   * beat's ops into one encoder and each view writes its lane from the beat's `SEffectBeat` (`CEffectLaneNames`);
   * headless's `--effect-record` measures the same bytes. Not thread safe; the caller serialises `Record`/`EndBeat`
   * (`CEffectOpRecorder` does).
   *
   * Each op is its `EEffectOp` byte, then (all but `CreateLightParticle`) the effect's id as an unsigned LEB128
   * varint, then its arguments in a fixed order per op:
   * - ints (entity, bone, army, parameter index, beam blend mode) as varints of the value plus one, so -1 is 0;
   * - floats as 4 little-endian bytes; a variable count (`SetVector`, `SetN`, `SetCurve`, parameter beams) goes
   *   first as a varint;
   * - blueprint ids and textures as a reference into a table of the names seen so far (0: none; n: entry n - 1). The
   *   texts go in each view's lane the first time that view needs them (`CEffectLaneNames`); entries never change.
   *
   * Effect ids are given at the create (counting up, never reused, so a client still drawing an effect whose end it
   * derives can't mistake a new one for it) and forgotten at any destroy. Ops on an effect never seen created are
   * dropped and counted. `Destroy` is never encoded: a client derives it (lifetime end, the entity's death,
   * fidelity), except after `DestroyByScript`, which is encoded instead. Several `SetFloat` to one (effect,
   * parameter) in a beat keep the last.
   *
   * Arguments are taken as flattened: `values` must hold a curve's bounds and keys and a parameter beam's floats
   * (`curve`/`beam` are ignored here; `FlattenEffectOpArgs` in EffectOpRecorder.h flattens them).
   */
  class CEffectOpEncoder
  {
  public:
    static constexpr std::size_t kOps = static_cast<std::size_t>(moho::EEffectOp::Count);

    void Record(moho::EEffectOp op, const moho::SEffectOpArgs& args);

    /** Encodes the ops recorded since the last call. */
    [[nodiscard]] SEffectBeat EndBeat();

    [[nodiscard]] std::uint64_t EncodedOps(
      moho::EEffectOp op
    ) const noexcept
    {
      return mEncodedOps[Index(op)];
    }
    /** The op's bytes in the beats' ops, without the name texts (those go once per view). */
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
      std::deque<std::string> texts;         // a deque: `SEffectBeatName::text` points into it
      std::vector<std::uint64_t> beatUsed{}; // per entry: the last beat (`mBeatSerial`) whose ops named it
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
      std::uint32_t blueprint = 0; // name references: 0 none, else entry + 1
      std::uint32_t texture = 0;
      std::uint32_t texture2 = 0;
      std::uint32_t floatOffset = 0;
      std::uint32_t floatCount = 0;
      std::uint32_t armies = ~0u;
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
    [[nodiscard]] static std::uint32_t Resolve(SNameTable& table, const char* name);
    void EncodeName(SEffectBeat& beat, SEffectBeatOp& op, SNameTable& table, EEffectNameTable which, std::uint32_t ref);
    static void EncodeInt(std::vector<std::uint8_t>& out, std::int32_t value);
    void EncodeFloats(std::vector<std::uint8_t>& out, const SPending& pending, std::uint32_t fixedCount) const;

    std::unordered_map<const moho::IEffect*, SEffectEntry> mEffects;
    std::uint32_t mNextId = 0;
    SNameTable mBlueprints;
    SNameTable mTextures;
    std::uint64_t mBeatSerial = 0; // counts `EndBeat`s, from 1

    std::vector<SPending> mPending;
    std::vector<std::uint32_t> mEnded; // this beat's destroyed effects
    std::vector<float> mFloats;
    std::unordered_map<std::uint64_t, std::size_t> mLastSetFloat; // (id, param) -> mPending index, this beat

    std::array<std::uint64_t, kOps> mEncodedOps{};
    std::array<std::uint64_t, kOps> mEncodedBytes{};
    std::array<std::uint64_t, kOps> mDropped{};
    std::uint64_t mDerivedDestroys = 0;
    std::uint64_t mCoalesced = 0;
  };

  /**
   * Plan WP9.3: ops name entities by the sim's ids, but a view's client holds some of them under ids of the view's own
   * (remote/ViewIdMap.h: other armies' projectiles and every recon blip), and another army's unit only as its blip.
   * Copies encoded ops (one, or several in a row: a beat's ops, a kept effect's create and setters) to the end of
   * `out`, each entity field (creates, `SetEntity`, `SetBone`) replaced by `toClient(entity)`: the id the view's client
   * holds that entity under, or -1 when it holds none. Other fields are copied byte for byte. False, with `out` as it
   * was, when the bytes don't parse as ops.
   */
  using EffectEntityToClient = std::function<std::int32_t(std::int32_t entity)>;
  [[nodiscard]] bool AppendWithClientEntities(
    std::span<const std::uint8_t> ops,
    const EffectEntityToClient& toClient,
    std::vector<std::uint8_t>& out
  );

  /**
   * Plan WP9.1 step 3: what one view's client was sent of the name tables. A name's text goes in the view's lane the
   * first time one of its ops refers to it; a view that joins late, or comes back holding nothing (`Reset`), gets the
   * names again as its ops need them. One per view, used by one thread at a time.
   */
  class CEffectLaneNames
  {
  public:
    /** The client holds no name: a new client, or one back from a lost connection. */
    void Reset() noexcept
    {
      mSent[0].clear();
      mSent[1].clear();
    }

    /**
     * This view's effects lane for `beat` (remote/wire/EffectLane.h), into `lane` (cleared first): empty when the beat
     * has no op; otherwise the names the view's client doesn't hold yet, then the beat's ops.
     */
    void Write(const SEffectBeat& beat, std::vector<std::uint8_t>& lane);

    /**
     * Plan WP9.2, a lane of some of the beat's ops (a routed view's): `Begin`, then `Need` for each name the chosen ops
     * refer to, then `Finish` with those ops' bytes. `Need` marks the name sent at once, so a name is listed once.
     */
    void Begin() noexcept
    {
      mNew.clear();
    }
    void Need(const SEffectBeatName& name);
    /** The lane (cleared first): empty without an op, else the names `Need` found new, then `ops`. */
    void Finish(std::span<const std::uint8_t> ops, std::uint32_t opCount, std::vector<std::uint8_t>& lane);

    /** Name texts this view was sent, over its whole life. */
    [[nodiscard]] std::uint64_t NamesSent() const noexcept
    {
      return mNamesSent;
    }

  private:
    std::vector<bool> mSent[2];        // per table, by entry
    std::vector<SEffectBeatName> mNew; // this lane's names new to the client, in first-use order
    std::uint64_t mNamesSent = 0;
  };
} // namespace faf::server
