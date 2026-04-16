#include "MeshThumbnail.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x007EA700 (FUN_007EA700, ??0MeshThumbnail@Moho@@QAE@XZ)
   * Mangled: ??0MeshThumbnail@Moho@@QAE@XZ
   *
   * What it does:
   * Initializes one empty thumbnail request with default camera state,
   * identity-forward orientation lane, magenta tint sentinel, and normalized
   * output rectangle `[0,0,1,1]`.
   */
  MeshThumbnail::MeshThumbnail()
    : requestId(0)
    , mPad0C_0F{}
    , camera()
    , meshInstance(nullptr)
    , orientation()
    , color(0xFFFF00FFu)
    , outputRect{}
    , outputSheet()
  {
    orientation.x = 1.0f;
    orientation.y = 0.0f;
    orientation.z = 0.0f;
    orientation.w = 0.0f;
    outputRect.x0 = 0.0f;
    outputRect.z0 = 0.0f;
    outputRect.x1 = 1.0f;
    outputRect.z1 = 1.0f;
  }

  /**
   * Address: 0x007EAF90 (FUN_007EAF90, ??0MeshThumbnail@Moho@@QAE@@Z)
   * Mangled: ??0MeshThumbnail@Moho@@QAE@@Z
   *
   * What it does:
   * Deep-copies the embedded camera payload and value-copy lanes, then
   * bumps shared ownership on the output-sheet smart pointer lane.
   */
  MeshThumbnail::MeshThumbnail(const MeshThumbnail& rhs)
    : requestId(rhs.requestId)
    , camera(rhs.camera)
    , meshInstance(rhs.meshInstance)
    , orientation(rhs.orientation)
    , color(rhs.color)
    , outputRect(rhs.outputRect)
    , outputSheet(rhs.outputSheet)
  {}

  MeshThumbnail& MeshThumbnail::operator=(const MeshThumbnail& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    this->~MeshThumbnail();
    new (this) MeshThumbnail(rhs);
    return *this;
  }

  /**
   * Address: 0x007EA7A0 (FUN_007EA7A0)
   *
   * What it does:
   * Initializes one thumbnail request payload with camera/mesh/output metadata.
   */
  MeshThumbnail::MeshThumbnail(
    const GeomCamera3& cameraArg,
    const std::uint32_t requestIdArg,
    MeshInstance* const meshInstanceArg,
    const Wm3::Quatf& orientationArg,
    const std::uint32_t colorArg,
    const gpg::Rect2f& outputRectArg,
    const boost::shared_ptr<ID3DTextureSheet>& outputSheetArg
  )
    : requestId(requestIdArg)
    , camera(cameraArg)
    , meshInstance(meshInstanceArg)
    , orientation(orientationArg)
    , color(colorArg)
    , outputRect(outputRectArg)
    , outputSheet(outputSheetArg)
  {}

  /**
   * Address: 0x007EA8A0 (FUN_007EA8A0)
   * Deleting thunk: 0x007EA780 (FUN_007EA780)
   *
   * What it does:
   * Releases output-sheet ownership and destroys embedded camera payload.
   */
  MeshThumbnail::~MeshThumbnail()
  {
    outputSheet.reset();
  }
} // namespace moho
