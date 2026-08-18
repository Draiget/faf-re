#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"
#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Map.h"

namespace moho
{
  class CD3DPrimBatcher;
  class CWldMap;
  class CWldSession;

  /**
   * Address: 0x010A645C (?UI_RenProjectileArcs@Moho@@3HA)
   *
   * Gates the whole arc pass from `CRenderWorldView::Render` (0x0086EEA3).
   * Zero-fill in the shipped image, so trails are off by default.
   */
  extern std::int32_t UI_RenProjectileArcs;
  struct GeomCamera3;

  /**
   * How many trail samples one projectile keeps inline before the vector spills
   * to the heap. `func_ImportEconOverlayParams`'s sibling staging block in
   * `FUN_00860E20` reserves 3072 bytes of inline storage at `+0x18` of the
   * sample vector, and every consumer strides it by 12 bytes.
   */
  inline constexpr std::size_t kProjectileArcInlineSamples = 256;

  /**
   * One projectile's screen trail, the mapped value of the arc table.
   *
   * Layout is pinned by three independent readings:
   *   - `FUN_00861D10` (the tree iterator increment) puts `_Isnil` at node
   *     `+0xC49` with `_Left`/`_Parent`/`_Right` at 0/4/8, so the node is the
   *     stock msvc8 `_Tree` node with `_Color` at `+0xC48`.
   *   - `FUN_00861320` (`find`) reads the key at node `+0x10` and
   *     `FUN_00860E20` (`operator[]`) returns node `+0x18`, so `_Myval` is a
   *     `pair<const int, ProjectileArcTrack>` placed at the first 8-aligned
   *     offset past the node header, with the key at `+0x10` and the track at
   *     `+0x18`. That fixes `sizeof(ProjectileArcTrack)` at `0xC48 - 0x18` and
   *     forces its alignment to 8 - which is also why `mSamples` starts at
   *     `+0x08` here rather than `+0x04`.
   *   - `FUN_00860D20` (the copy-assign) touches exactly `+0`, `+8`, `+3096`,
   *     `+3100`, `+3104`, `+3108` and `+3112`, matching the members below.
   */
  struct alignas(8) ProjectileArcTrack
  {
    /**
     * Set when the owning projectile was seen this frame. The draw pass clears
     * it after emitting the trail, and any track still clear at the end of the
     * pass has its key queued for erase.
     */
    bool mActive = false; // +0x0000

    /**
     * Screen-trail sample positions, oldest first.
     *
     * `alignas(8)` because the binary's `fastvector_n` is 8-aligned: the
     * track starts with a single byte yet the vector begins at `+0x08`, and
     * the tail pads from `0xC29` out to `0xC30`. The simplified
     * `gpg::fastvector_n` model in this tree is only 4-aligned, so the
     * alignment has to be restated here to reproduce the binary's layout.
     */
    alignas(8) gpg::fastvector_n<Wm3::Vector3f, kProjectileArcInlineSamples> mSamples{}; // +0x0008

    /** Frames since the last sample was appended. */
    std::int32_t mTicksSinceSample = 0; // +0x0C18

    /** The projectile's position this frame, drawn as the trail's leading end. */
    Wm3::Vector3f mLatestPosition{}; // +0x0C1C

    /** Whether the projectile is near enough to draw its trail at all. */
    bool mVisible = false; // +0x0C28

    ProjectileArcTrack() = default;

    /**
     * Address: 0x00860D20 (FUN_00860D20, ProjectileArcTrack copy)
     *
     * IDA signature:
     * int __usercall sub_860D20@<eax>(int src@<edi>, int dst@<esi>);
     *
     * What it does:
     * Copies one track field by field, rebinding the destination's sample
     * vector onto its own inline buffer before copying the elements across
     * (the binary calls the shared fastvector copy lane at 0x0065F240 for
     * exactly that). Spelled out because `gpg::fastvector_n` holds pointers
     * into its own inline storage, so the implicit copy would leave the
     * destination pointing at the source's buffer - and the map needs the
     * track copyable to build a node.
     */
    ProjectileArcTrack(const ProjectileArcTrack& other) { *this = other; }

    ProjectileArcTrack& operator=(const ProjectileArcTrack& other)
    {
      if (this != &other) {
        mActive = other.mActive;
        mSamples.InitInlineAndCopyFrom(other.mSamples);
        mTicksSinceSample = other.mTicksSinceSample;
        mLatestPosition = other.mLatestPosition;
        mVisible = other.mVisible;
      }
      return *this;
    }
  };

  static_assert(offsetof(ProjectileArcTrack, mActive) == 0x0000, "ProjectileArcTrack::mActive offset must be 0x0000");
  static_assert(
    offsetof(ProjectileArcTrack, mSamples) == 0x0008, "ProjectileArcTrack::mSamples offset must be 0x0008"
  );
  static_assert(
    offsetof(ProjectileArcTrack, mTicksSinceSample) == 0x0C18,
    "ProjectileArcTrack::mTicksSinceSample offset must be 0x0C18"
  );
  static_assert(
    offsetof(ProjectileArcTrack, mLatestPosition) == 0x0C1C,
    "ProjectileArcTrack::mLatestPosition offset must be 0x0C1C"
  );
  static_assert(
    offsetof(ProjectileArcTrack, mVisible) == 0x0C28, "ProjectileArcTrack::mVisible offset must be 0x0C28"
  );
  static_assert(sizeof(ProjectileArcTrack) == 0x0C30, "ProjectileArcTrack size must be 0x0C30");

  /** Arc tracks keyed by entity id. Head node at 0x010C4318, so the map object starts at 0x010C4314. */
  using ProjectileArcTable = msvc8::map<std::int32_t, ProjectileArcTrack>;

  /**
   * Address: 0x008600E0 (FUN_008600E0, Moho::CRenderWorldView::RenderProjectileArcs)
   *
   * IDA signature:
   * void __usercall Moho::CRenderWorldView::RenderProjectileArcs(
   *   CD3DPrimBatcher *batcher@<edi>, CRenderWorldView *view@<esi>,
   *   CWldSession *session, GeomCamera3 *cam);
   *
   * What it does:
   * Draws the screen-space trail behind every in-flight projectile, gated on
   * the `UI_RenProjectileArcs` CVar by the caller.
   *
   * Two passes. The first walks every projectile the session's spatial DB
   * holds, preloads its strategic-icon texture (bailing out of the whole pass
   * if one fails to load), and refreshes that projectile's track: position,
   * whether it is near enough to draw, and - once every
   * `UI_RenProjectileArcsSampleInterval` frames - one more trail sample.
   * The second walks the arc table and emits each track as a ribbon of
   * screen-space quads `UI_RenProectileTrailWidth` pixels either side of the
   * projected sample line, tinted `UI_RenProjectileTrailColor`, then erases
   * every track whose projectile was not seen this frame.
   *
   * Despite the IDA name the binary passes no `this`: `esi` arrives holding
   * the world view but is overwritten with `cam` at 0x00860113 before any read,
   * and the four real arguments are all on the stack. Recovered as a free
   * function accordingly.
   *
   * The fourth argument is the map, not a `float interpolant`. Its sole caller
   * `CRenderWorldView::Render` (0x0086EE00) stages `[ebp+10h]` into that slot at
   * 0x0086EEAC (`D9 45 10`) - the same parameter it hands to
   * `CWldSession::RenderProjectileIcons`, whose mangled name
   * (`...PAVCWldMap@2@M@Z`) types it `CWldMap*`. Every `fld` in `Render` reads
   * `[ebp+10h]`; `[ebp+14h]`, the real `float deltaSeconds`, is only ever loaded
   * for `RenderProjectileIcons` and `RenderCommandGraph`.
   *
   * The body then reads that argument back with `movss` at 0x0086044B and feeds
   * it to `UserEntity::GetInterpolatedTransform(float)`, so the shipped engine
   * interpolates arc samples at whatever a heap pointer's bit pattern denotes as
   * a float - around 1e-13 for any real allocation, i.e. zero. Recovered as an
   * explicit `0.0f`, which is bit-for-bit the same sample and does not pretend a
   * pointer is a fraction. `CWldSession::DrawEconomyOverlay` had the identical
   * defect and was corrected the same way in 0652678.
   */
  void RenderProjectileArcs(
    CWldSession* session, GeomCamera3* camera, CD3DPrimBatcher* primBatcher, CWldMap* map
  );
} // namespace moho
