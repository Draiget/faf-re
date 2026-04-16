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
