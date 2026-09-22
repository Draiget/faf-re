#pragma once

#include <cstddef>

#include "gpg/core/containers/FastVector.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RRef;
  class RType;
} // namespace gpg

namespace moho
{
  class REmitterBlueprintCurve;

  /**
   * Runtime emitter curve sample set.
   *
   * Layout evidence:
   * - `FUN_00516D20` / `FUN_00516DD0` serialize two `Vector2f` lanes
   *   plus one `fastvector<Vector3f>` lane.
   * - `FUN_00515320` sets X-range as `[0, blueprint.XRange]` and inserts key triples.
   */
  struct SEfxCurve
  {
    static gpg::RType* sType;

    /**
     * Address: 0x0065DD90 (FUN_0065DD90)
     *
     * IDA signature:
     * Moho::SEfxCurve *__usercall SEfxCurve@<eax>(Moho::SEfxCurve *this@<eax>);
     *
     * What it does:
     * Arms `mKeys` on its own two-slot inline window and leaves the two bounds
     * lanes alone -- `lea ecx,[this+0x20]; lea edx,[ecx+0x18]` then
     * `start_ = end_ = originalVec_ = ecx`, `capacity_ = edx`, which is the
     * defaulted default constructor of a struct whose only non-trivial member
     * is the vector at `+0x10`. Nothing writes `+0x00..+0x0F`, so a
     * default-constructed curve's bounds are indeterminate until
     * `BuildEmitterCurveFromBlueprint` or `RecomputeEmitterCurveYBounds` sets
     * them; `CEfxEmitter`'s blueprint constructor copies exactly such a curve
     * into all 21 emitter lanes.
     *
     * Zero callers and no xrefs: every use site inlined it and the linker kept
     * the COMDAT. See the matching note on `gpg::core::FastVectorN<T, N>()`.
     */
    SEfxCurve() = default;
    SEfxCurve(const SEfxCurve& other);
    SEfxCurve& operator=(const SEfxCurve& other);

    [[nodiscard]]
    static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00514D40 (FUN_00514D40, Moho::SEfxCurveSerializer::Deserialize)
     *
     * What it does:
     * Archive callback adapter that deserializes one `SEfxCurve` object.
     */
    static void DeserializeFromArchive(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00514D50 (FUN_00514D50, Moho::SEfxCurveSerializer::Serialize)
     *
     * What it does:
     * Archive callback adapter that serializes one `SEfxCurve` object.
     */
    static void SerializeToArchive(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00516D20 (FUN_00516D20, Moho::SEfxCurve::MemberDeserialize)
     *
     * What it does:
     * Loads bounds and key-vector payload from a read archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00516DD0 (FUN_00516DD0, Moho::SEfxCurve::MemberSerialize)
     *
     * What it does:
     * Saves bounds and key-vector payload to a write archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00514E50 (FUN_00514E50, Moho::SEfxCurve::GetValue)
     *
     * What it does:
     * Evaluates one interpolated curve sample at `interp` and applies per-key
     * random spread (Z lane) through the process-global random helper.
     */
    [[nodiscard]] float GetValue(float interp) const;

    Wm3::Vector2f mBoundsMin;
    Wm3::Vector2f mBoundsMax;
    gpg::fastvector_n<Wm3::Vector3f, 2> mKeys;
  };

  /**
   * Address: 0x00514FF0 (FUN_00514FF0, SEfxCurve y-bounds recompute lane)
   *
   * What it does:
   * Recomputes the curve's Y min/max bounds by scanning every key lane.
   * Called across translation units by the curve editor after a key move.
   */
  void RecomputeEmitterCurveYBounds(SEfxCurve& curve);

  /**
   * Address: 0x00515270 (FUN_00515270)
   *
   * What it does:
   * Returns the key nearest `point` by Euclidean distance over
   * `(time, value)`, or `mKeys.end()` when the curve is empty.
   */
  [[nodiscard]] Wm3::Vector3f* FindNearestCurveKey(SEfxCurve& curve, const Wm3::Vector2f& point);

  /**
   * Address: 0x005158C0 (FUN_005158C0)
   *
   * What it does:
   * Erases `[first, last)` from the curve's key vector, shifting the trailing
   * keys down and pulling the end lane back.
   */
  Wm3::Vector3f* EraseEmitterCurveKeyRange(Wm3::Vector3f* first, Wm3::Vector3f* last, SEfxCurve& curve);

  /**
   * Address: 0x005151B0 (FUN_005151B0, insert_emitter_curve_key)
   *
   * What it does:
   * Inserts one `(x,y,z)` key into a curve in ascending-X order and
   * recomputes the Y bounds from all keys.
   */
  void InsertEmitterCurveKey(SEfxCurve& curve, const Wm3::Vector3f& key);

  /**
   * Address: 0x00515090 (FUN_00515090, rescale_emitter_curve_x_range)
   *
   * What it does:
   * Rescales all key X lanes to a new `[minX,maxX]` range using the
   * current range ratio, then recomputes Y bounds from retained keys.
   */
  SEfxCurve* RescaleEmitterCurveXRange(SEfxCurve* curve, float minX, float maxX);

  /**
   * Address: 0x00515320 (FUN_00515320, make_emitter_curve_from_blueprint)
   *
   * What it does:
   * Rebuilds runtime curve keys/bounds from one blueprint curve key list,
   * or emits one default key when the source list is empty.
   */
  void BuildEmitterCurveFromBlueprint(SEfxCurve& destination, const REmitterBlueprintCurve& source);

  static_assert(sizeof(SEfxCurve) == 0x38, "SEfxCurve size must be 0x38");
} // namespace moho
