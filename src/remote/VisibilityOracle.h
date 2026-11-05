#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/entity/SSTIEntityVariableData.h"
#include "Wm3Vector3.h"

// Engine addition, server mode (plan WP4.1, WP4.2): the reference visibility oracle. For any
// army it answers what a lockstep client focused on that army holds for one entity, from the
// sim alone and without writing anything, so the server can ask it for every view in turn
// while its own sim runs unfocused (-1).
//
// A lockstep client decides in two places:
//   1. The sim publishes the entity (`Entity::Sync`, 0x0067A0A0) only while it is not being
//      destroyed and `UpdateVisibility` set its flag under the client's focus army:
//      `Entity::UpdateVisibility` (0x00678A70) picks the visibility mode from the entity's
//      viz channel for that army, `Unit::UpdateVisibility` (0x006ABC30) publishes a unit to its
//      own army only, `ReconBlip::UpdateVisibility` (0x005BEE40) publishes a blip while the
//      army's recon record needs a flush. `Prop::Sync` (0x006FA2A0) never tests visibility.
//   2. The client draws a published entity's mesh by its visibility mode. A plain entity
//      (`UserEntity::UpdateVisibility` 0x008B9580) in mode ReconGrid shows only where its army
//      or an army that counts it as an ally can see the point (`UserArmy::CanSeePoint`
//      0x008B22B0, `UserArmy::CanSeeCell` 0x008B17F0; the grids are the sim's own, handed to
//      the client by shared pointer), and in mode MapPlayableRect only inside the playable
//      rect. Units and blips are `UserUnit`s on the client (`UserUnit::UpdateVisibility`
//      0x008C09B0): no grid and no rect; in mode ReconGrid a mobile one shows while its recon
//      flags say "seen now" (0x08), a structure once "seen ever" (0x10). A unit always sends
//      the flags 0x1C (`Unit::SyncInterface`), a blip its record for the focus army
//      (`ReconBlip::SyncInterface` 0x005BEFB0).
//
// Brute force on purpose: this is the reference the spatial oracle (WPR.44) is checked
// against (WPR.54). Two client-side inputs are not modelled: the client's fog-of-war console
// switch (`RenderFogOfWarEnabled`; a server view always has fog), and the timing of the
// client's grid reads (it reads the live grid when it draws, this answers at the beat).

namespace moho
{
  class CArmyImpl;
  class Entity;
  class ReconBlip;
  class Sim;
}

namespace faf::remote
{
  /** What a lockstep client focused on one army holds for one entity this beat. */
  struct SViewVisibility
  {
    bool published = false; // the client has the entity at all (`Entity::Sync` keeps its interface)
    moho::EUserEntityVisibilityMode mode = moho::EUserEntityVisibilityMode::Hidden; // how it shows it
  };

  /**
   * Plan WPR.35: everything stages 1 and 2 read from one entity, read once a beat for all views
   * instead of once per view. The entity-taking functions below read these first, so both
   * forms give the same answers.
   */
  struct SEntityFacts
  {
    enum class EKind : std::uint8_t
    {
      Plain,
      Prop,
      Unit,
      Blip
    };

    const moho::CArmyImpl* army = nullptr; // `Entity::ArmyRef`
    std::int32_t armyIndex = -1;           // `Entity::GetArmyIndex`
    std::int32_t vizToFocusPlayer = 0;
    std::int32_t vizToAllies = 0;
    std::int32_t vizToEnemies = 0;
    std::int32_t vizToNeutrals = 0;
    const moho::ReconBlip* blip = nullptr; // a blip's per-army records, for armies past 63
    std::uint64_t blipNeedsFlush = 0;      // a blip: bit n is army n's `mNeedsFlush`, armies 0..63
    Wm3::Vec3f pos{};                      // `mVarDat.mCurTransform.pos_`
    EKind kind = EKind::Plain;
    bool destroyed = false;  // `mOnDestroyDispatched`
    bool underwater = false; // `mVarDat.UsesUnderwaterReconGrid()`
  };

  /** Reads `entity`'s facts for this beat. */
  [[nodiscard]] SEntityFacts ReadEntityFacts(moho::Entity& entity);

  /**
   * Stage 1: the publication and visibility mode `Sim::Sync` would give `entity` with
   * `viewArmy` (0-based, or -1 for an observer) as its focus. Reads only.
   */
  [[nodiscard]] SViewVisibility ResolveViewVisibility(const moho::Sim& sim, std::int32_t viewArmy, moho::Entity& entity);
  /** Stage 1 from facts read this beat. */
  [[nodiscard]] SViewVisibility ResolveViewVisibility(const moho::Sim& sim, std::int32_t viewArmy, const SEntityFacts& facts);

  /**
   * `UserArmy::CanSeeCell` (0x008B17F0) on the sim's grids: whether `view` sees the cell through
   * its own vision (or, `underwater`, water) grid or the grid of an army that counts it as an
   * ally. `ViewCanSeePoint` maps the point to the cell; the spatial oracle tests cells directly.
   */
  [[nodiscard]] bool ViewCanSeeCell(
    const moho::Sim& sim, const moho::CArmyImpl& view, std::int32_t x, std::int32_t z, bool underwater
  );

  /**
   * Stage 2 (WP4.2): whether `viewArmy`'s client sees the world point `pos` through its own
   * recon grids or an ally's, mapped to cells as `UserArmy::CanSeePoint` maps them. An
   * underwater entity is tested against the water grids, everything else against the vision
   * grids. An observer (-1) sees everything.
   */
  [[nodiscard]] bool ViewCanSeePoint(const moho::Sim& sim, std::int32_t viewArmy, const Wm3::Vec3f& pos, bool underwater);

  /**
   * Whether the entity belongs in `viewArmy`'s view this beat: published, and for a plain
   * entity in mode ReconGrid inside the view's sight (plan §6). Units and blips are sent
   * whenever published: the client keeps a blip it does not draw (its radar icon), and never
   * tests them against the grid. Other modes are sent as published; the client hides or clips
   * them itself.
   */
  [[nodiscard]] bool CanViewSee(const moho::Sim& sim, std::int32_t viewArmy, moho::Entity& entity);
  /** `CanViewSee` from facts read this beat. */
  [[nodiscard]] bool CanViewSee(const moho::Sim& sim, std::int32_t viewArmy, const SEntityFacts& facts);
  /** `CanViewSee` for views 0 up to `viewCount` (at most 32), a bit each. */
  [[nodiscard]] std::uint32_t ViewsThatSee(const moho::Sim& sim, std::size_t viewCount, const SEntityFacts& facts);
  /** Whether `ViewsThatSee` reads nothing but `facts`: no grid, and no alliance between armies. */
  [[nodiscard]] bool ViewsFollowFactsAlone(const SEntityFacts& facts) noexcept;

  /**
   * Whether `viewArmy`'s lockstep client draws the entity's mesh this beat (stage 2 above,
   * `UserEntity::UpdateVisibility` or `UserUnit::UpdateVisibility`). What the golden test
   * (plan WP4.4) compares with a client's display.
   */
  [[nodiscard]] bool ViewShowsMesh(const moho::Sim& sim, std::int32_t viewArmy, moho::Entity& entity);
} // namespace faf::remote
