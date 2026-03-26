#pragma once

#include <cstddef>

#include "gpg/core/containers/FastVector.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RRef;
  class RType;
} // namespace gpg

namespace moho
{
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

    Wm3::Vector2f mBoundsMin;
    Wm3::Vector2f mBoundsMax;
    gpg::fastvector_n<Wm3::Vector3f, 2> mKeys;
  };

  static_assert(sizeof(SEfxCurve) == 0x38, "SEfxCurve size must be 0x38");
} // namespace moho
