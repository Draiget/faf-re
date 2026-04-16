#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/Rect2.h"
#include "moho/render/camera/GeomCamera3.h"
#include "Wm3Quaternion.h"

namespace moho
{
  class ID3DTextureSheet;
  class MeshInstance;

  class MeshThumbnail
  {
  public:
    /**
     * Address: 0x007EA700 (FUN_007EA700, ??0MeshThumbnail@Moho@@QAE@XZ)
     * Mangled: ??0MeshThumbnail@Moho@@QAE@XZ
     *
     * What it does:
     * Initializes one empty thumbnail request with default camera state,
     * identity-forward orientation lane, magenta tint sentinel, and normalized
     * output rectangle `[0,0,1,1]`.
     */
    MeshThumbnail();

    /**
     * Address: 0x007EAF90 (FUN_007EAF90, ??0MeshThumbnail@Moho@@QAE@@Z)
     * Mangled: ??0MeshThumbnail@Moho@@QAE@@Z
     *
     * What it does:
     * Deep-copies the embedded camera payload and value-copy lanes, then
     * bumps shared ownership on the output-sheet smart pointer lane.
     */
    MeshThumbnail(const MeshThumbnail& rhs);

    MeshThumbnail& operator=(const MeshThumbnail& rhs);

    /**
     * Address: 0x007EA7A0 (FUN_007EA7A0)
     *
     * What it does:
     * Initializes one thumbnail request payload with camera/mesh/output metadata.
     */
    MeshThumbnail(
      const GeomCamera3& camera,
      std::uint32_t requestId,
      MeshInstance* meshInstance,
      const Wm3::Quatf& orientation,
      std::uint32_t color,
      const gpg::Rect2f& outputRect,
      const boost::shared_ptr<ID3DTextureSheet>& outputSheet
    );

    /**
     * Address: 0x007EA8A0 (FUN_007EA8A0)
     * Deleting thunk: 0x007EA780 (FUN_007EA780)
     *
     * What it does:
     * Releases output-sheet ownership and destroys embedded camera payload.
     */
    virtual ~MeshThumbnail();

  public:
    std::uint8_t mReserved04_07[0x04];               // +0x04 (observed gap in ctor/copy helper)
    std::uint32_t requestId;                         // +0x08
    std::uint8_t mPad0C_0F[0x04];                    // +0x0C
    GeomCamera3 camera;                              // +0x10
    MeshInstance* meshInstance;                      // +0x2D8
    Wm3::Quatf orientation;                          // +0x2DC
    std::uint32_t color;                             // +0x2EC
    gpg::Rect2f outputRect;                          // +0x2F0
    boost::shared_ptr<ID3DTextureSheet> outputSheet; // +0x300
  };

  static_assert(offsetof(MeshThumbnail, mReserved04_07) == 0x04, "MeshThumbnail::mReserved04_07 offset must be 0x04");
  static_assert(offsetof(MeshThumbnail, requestId) == 0x08, "MeshThumbnail::requestId offset must be 0x08");
  static_assert(offsetof(MeshThumbnail, mPad0C_0F) == 0x0C, "MeshThumbnail::mPad0C_0F offset must be 0x0C");
  static_assert(offsetof(MeshThumbnail, camera) == 0x10, "MeshThumbnail::camera offset must be 0x10");
  static_assert(offsetof(MeshThumbnail, meshInstance) == 0x2D8, "MeshThumbnail::meshInstance offset must be 0x2D8");
  static_assert(offsetof(MeshThumbnail, orientation) == 0x2DC, "MeshThumbnail::orientation offset must be 0x2DC");
  static_assert(offsetof(MeshThumbnail, color) == 0x2EC, "MeshThumbnail::color offset must be 0x2EC");
  static_assert(offsetof(MeshThumbnail, outputRect) == 0x2F0, "MeshThumbnail::outputRect offset must be 0x2F0");
  static_assert(offsetof(MeshThumbnail, outputSheet) == 0x300, "MeshThumbnail::outputSheet offset must be 0x300");
  static_assert(sizeof(MeshThumbnail) == 0x308, "MeshThumbnail size must be 0x308");
} // namespace moho
