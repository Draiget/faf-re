#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

#include "server/EffectOpEncoder.h"

namespace faf::server
{
  /**
   * Plan WP9.2: which of the beat's effect ops each view gets. An effect goes to a view only while that player's client
   * would draw where it is:
   *
   * - An effect on entities (every create but `CreateEmitter`, and a beam once attached) goes to the views whose client
   *   holds those entities this beat, both ends of a beam between two (the same records the view's entity frames hold:
   *   `CViewFrames::ViewHoldsEntityNow`). Another army's unit (allies' too) is published to a view only as its recon
   *   blip, so a view also holds a unit whose blip its client draws this beat (`ShownBy`, asked on the sim thread). A
   *   create a view can't place yet waits until it can; one that ends first never goes there.
   * - An emitter placed at an entity or a bone once (`CreateEmitterAtEntity`, `CreateEmitterAtBone`: it doesn't follow)
   *   goes to the views that hold the entity this beat or held it until this beat's frame removed it: a projectile's
   *   impact is made as the projectile goes, and the client places it from the entity's last state. Once sent it stays
   *   (like a point emitter); one held back goes later only if its entity is in the view then.
   * - A beam made without an attachment (`CreateBeam` from a blueprint) waits for its first `SetEntity`/`SetBone`.
   * - An emitter at a position (`CreateEmitter`) goes to the views whose sight covers the point at some beat while it
   *   lives (`ViewCanSeePoint`, asked on the sim thread), and stays with them.
   * - A light (`CreateLightParticle`, no effect id) goes once, at its beat: from `CreateLightParticleIntel` to the
   *   views of the armies whose intel detected it there (`SEffectBeatOp::armies`), otherwise to the views that see
   *   its point. A view that watches everything gets every light and sees every point.
   * - Setters and `DestroyByScript` follow the effect: a view gets them only while its client holds the effect (and,
   *   but for attaches and the destroy, while it can still place it this beat).
   * - When an attached effect's entity leaves a view (out of sight, or a lost connection), the view's client is taken
   *   to drop the effect with the entity (it derives that, as it derives the entity's death), and the effect is sent
   * again, whole, when the entity comes back.
   *
   * "Whole" is the create as it was made, then the last op per setter and parameter since (`SetEntity` and `SetBone`
   * count as one each). So the routes keep every live effect's create and its latest setters: memory goes with the
   * live effects, not with time, and an effect leaves at the beat after its destroy (any destroy, derived ones too).
   * Past `kMaxKept` live effects new ones aren't kept: they go to the views that can place them at their create, and
   * their setters follow, but they are never sent later.
   *
   * `CEffectRoutes` is the shared part, written on the sim thread (`TakeBeat`) between a beat's ops and its views;
   * each view's `CEffectViewRoute` reads it from the view's own job and marks its bit in each effect's `sent`.
   */
  class CEffectRoutes
  {
  public:
    static constexpr std::size_t kMaxKept = std::size_t{1} << 16;

    /** One op kept of a live effect: its bytes in `SLive::bytes`. */
    struct SPart
    {
      std::uint32_t offset = 0;
      std::uint32_t size = 0;
      moho::EEffectOp op = moho::EEffectOp::Count;
      std::int32_t param = -1;
    };

    struct SLive
    {
      std::int32_t entity = -1;  // what it is on (the last attachment); -1: none (unattached, or at a position)
      std::int32_t entity2 = -1; // a beam's other end
      std::array<float, 3> position{};
      bool positioned = false; // `CreateEmitter`: at a point
      bool placed = false;     // `CreateEmitterAtBone`/`AtEntity`: placed at its entity once, not following it
      bool ended = false;      // destroyed this beat; leaves at the next `TakeBeat`
      bool kept = false;       // its create and setters are kept, to send it later
      std::uint8_t nameCount = 0;
      std::array<SEffectBeatName, 2> names{}; // the create's names
      std::uint32_t seen = 0;                 // positioned: views whose sight covered its point at some beat
      std::uint32_t shown = 0;  // views whose client draws `entity` this beat through a blip (another army's unit)
      std::uint32_t shown2 = 0; // and `entity2`
      std::vector<std::uint8_t> bytes;        // the create, then the last op per (op, parameter)
      std::vector<SPart> parts;               // the ops in `bytes`; the create first
      std::atomic<std::uint32_t> sent{0};     // views whose client holds it now
      std::atomic<std::uint32_t> everSent{0}; // views it ever went to
    };

    /** Views (bits) that see a world point now. */
    using SeePoint = std::function<std::uint32_t(const std::array<float, 3>& position)>;
    /** Per view (by army index): the sim id of the blip it draws an entity through, -1 for none. */
    using SBlips = std::array<std::int32_t, 32>;
    /**
     * Views (bits) whose client draws the entity with this sim id now other than as its own record: another army's
     * unit, through its recon blip (`remote::ViewsShowingUnitBlips`); plan WP9.3: and, for each of them, that blip's
     * sim id in `blips` (filled with -1 before the call). May be empty: then only the frames' records count.
     */
    using ShownBy = std::function<std::uint32_t(std::int32_t entity, SBlips& blips)>;

    /**
     * On the sim thread, after the beat's `EndBeat` and before its views: last beat's ended effects leave, this beat's
     * ops update the live effects, and the beat's lights get their views (`SEffectBeatOp::views`). `views`: the
     * players' views; `watching`: those that see everything; `seePoint`: the others' sight; `shownBy`: who draws an
     * entity through a blip, asked once a beat per entity a live effect is on.
     */
    void TakeBeat(
      SEffectBeat& beat,
      std::uint32_t views,
      std::uint32_t watching,
      const SeePoint& seePoint,
      const ShownBy& shownBy = {}
    );

    [[nodiscard]] SLive* Find(
      const std::uint32_t id
    ) noexcept
    {
      const auto found = mLive.find(id);
      return found != mLive.end() ? &found->second : nullptr;
    }
    /** `visit(SLive&)` for each live effect (ended ones too). Any thread between `TakeBeat`s. */
    template <class Visit>
    void ForEachLive(
      Visit&& visit
    )
    {
      for (auto& [id, live] : mLive) {
        visit(live);
      }
    }

    /** `visit(id, const SLive&)` for each live effect (ended ones too). */
    template <class Visit>
    void ForEachLiveId(
      Visit&& visit
    ) const
    {
      for (const auto& [id, live] : mLive) {
        visit(id, live);
      }
    }

    [[nodiscard]] std::size_t Live() const noexcept
    {
      return mLive.size();
    }
    [[nodiscard]] std::size_t Kept() const noexcept
    {
      return mKept;
    }
    /** Bytes of creates and setters kept now. */
    [[nodiscard]] std::uint64_t KeptBytes() const noexcept
    {
      return mKeptBytes;
    }
    /** Effects ended, summed over the views of `TakeBeat`, that never reached that view. */
    [[nodiscard]] std::uint64_t Dropped() const noexcept
    {
      return mDropped;
    }
    /** Creates past `kMaxKept`. */
    [[nodiscard]] std::uint64_t NotKept() const noexcept
    {
      return mNotKept;
    }
    /**
     * Plan WP9.3: the sim id of the blip through which `view`'s client draws the entity this beat (`ShownBy`), -1 for
     * none. Only for entities a live effect is on; any thread between `TakeBeat`s.
     */
    [[nodiscard]] std::int32_t BlipShownTo(std::int32_t entity, std::size_t view) const noexcept;
    /** Plan WP9.3: live effects (not ended) whose bit `view` has in `sent`: those its client holds, as routing has it.
     */
    [[nodiscard]] std::size_t HeldBy(std::size_t view) const noexcept;

  private:
    void Keep(SLive& live, const SEffectBeat& beat, const SEffectBeatOp& op);

    struct SShown
    {
      std::uint32_t views = 0u;
      SBlips blips{};
    };

    std::unordered_map<std::uint32_t, SLive> mLive;
    std::vector<std::uint32_t> mEnding;                   // ended this beat; they leave at the next `TakeBeat`
    std::vector<std::uint32_t> mPositioned;               // live positioned effects not yet seen by every view
    std::unordered_map<std::int32_t, SShown> mShownCache; // this beat's `shownBy` answers
    std::size_t mKept = 0;
    std::uint64_t mKeptBytes = 0;
    std::uint64_t mDropped = 0;
    std::uint64_t mNotKept = 0;
  };

  /** Plan WP9.2: one view's end of the routes: its name table and what it was sent. One per view, used by its job. */
  class CEffectViewRoute
  {
  public:
    /** Whether the view's client holds the entity with this (sim) id this beat, or (`orLeft`) held it until this beat.
     */
    using Holds = std::function<bool(std::int32_t entity, bool orLeft)>;
    /**
     * Plan WP9.3: the id the view's client holds a sim entity under (its id map's, remote/ViewIdMap.h: the sim's own
     * for most entities, a view id for other armies' projectiles and for blips); false for one the view never got.
     */
    using ClientId = std::function<bool(std::int32_t entity, std::int32_t& clientId)>;

    /**
     * This view's effects lane for `beat` (into `lane`, cleared first): the beat's ops it gets, then live effects it
     * gets whole now. `fresh`: its client holds nothing (back from a lost connection), so its names and effects go
     * again. `view` must be under 32. With `clientId` (plan WP9.3) every entity an op names goes as the client holds
     * it: a record of its frames by that record's id, another army's unit by the id of the blip it draws
     * (`BlipShownTo`), and one it holds neither way as -1 (`Untranslated`). Without it ops keep the sim's ids.
     */
    void Write(
      const SEffectBeat& beat,
      CEffectRoutes& routes,
      std::size_t view,
      bool fresh,
      const Holds& holds,
      std::vector<std::uint8_t>& lane,
      const ClientId& clientId = {}
    );

    [[nodiscard]] const CEffectLaneNames& Names() const noexcept
    {
      return mNames;
    }
    /** Ops sent, wholes' ops included. */
    [[nodiscard]] std::uint64_t OpsSent() const noexcept
    {
      return mOpsSent;
    }
    /** Creates this view didn't get at their own beat. */
    [[nodiscard]] std::uint64_t Held() const noexcept
    {
      return mHeld;
    }
    /** Live effects sent whole later (a held create, an entity back in sight, a whole view). */
    [[nodiscard]] std::uint64_t Released() const noexcept
    {
      return mReleased;
    }
    /** Effects whose entity left the view, so its client dropped them. */
    [[nodiscard]] std::uint64_t Withdrawn() const noexcept
    {
      return mWithdrawn;
    }
    /** Lights it got. */
    [[nodiscard]] std::uint64_t Lights() const noexcept
    {
      return mLights;
    }
    /** Plan WP9.3: entity fields sent as the client's ids, and those of them it held under no id (sent as -1). */
    [[nodiscard]] std::uint64_t Translated() const noexcept
    {
      return mTranslated;
    }
    [[nodiscard]] std::uint64_t Untranslated() const noexcept
    {
      return mUntranslated;
    }

  private:
    CEffectLaneNames mNames;
    std::vector<std::uint8_t> mOps; // this beat's
    std::uint64_t mTranslated = 0;
    std::uint64_t mUntranslated = 0;
    std::uint64_t mOpsSent = 0;
    std::uint64_t mHeld = 0;
    std::uint64_t mReleased = 0;
    std::uint64_t mWithdrawn = 0;
    std::uint64_t mLights = 0;
  };
} // namespace faf::server
