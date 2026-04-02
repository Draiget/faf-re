#pragma once

#include <cstdint>

#include "legacy/containers/Vector.h"
#include "wm3/Box3.h"
#include "wm3/Quaternion.h"
#include "wm3/Vector2.h"
#include "moho/math/Vector3f.h"
#include "moho/ui/SDebugDecal.h"
#include "moho/ui/SDebugLine.h"
#include "moho/ui/SDebugScreenText.h"
#include "moho/ui/SDebugWorldText.h"

namespace moho
{
  class CHeightField;
  class CD3DPrimBatcher;
  struct GeomCamera3;
  class VTransform;

  class CDebugCanvas
  {
  public:
    /**
     * Address: 0x00450030 (FUN_00450030, ?AddWireCircle@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MII@Z)
     *
     * What it does:
     * Appends a polyline circle in world space to the debug line buffer.
     */
    void AddWireCircle(
      const Wm3::Vector3f& normal,
      const Wm3::Vector3f& center,
      float radius,
      std::uint32_t depth,
      std::uint32_t precision
    );

    /**
     * Address: 0x0044FA70 (FUN_0044FA70, ?AddLine@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0I@Z)
     *
     * What it does:
     * Emits one debug line segment from `p0` to `p1` with uniform endpoint depth/color.
     */
    void AddLine(const Wm3::Vector3f& p0, const Wm3::Vector3f& p1, std::uint32_t depth);

    /**
     * Address: 0x0044FD50 (FUN_0044FD50, ?AddContouredLine@CDebugCanvas@Moho@@QAEXABV?$Vector2@M@Wm3@@0IABVCHeightField@2@@Z)
     *
     * What it does:
     * Draws a 10-step terrain-conforming line by sampling `heightField` between two XZ points.
     */
    void AddContouredLine(
      const Wm3::Vector2f& p0,
      const Wm3::Vector2f& p1,
      std::uint32_t depth,
      const CHeightField& heightField
    );

    /**
     * Address: 0x0044FED0 (FUN_0044FED0, ?AddWireOval@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@00II@Z)
     *
     * What it does:
     * Emits a wire oval around `center` using axis basis vectors `axis1` and `axis2`.
     */
    void AddWireOval(
      const Wm3::Vector3f& center,
      const Wm3::Vector3f& axis1,
      const Wm3::Vector3f& axis2,
      std::uint32_t depth,
      std::uint32_t precision
    );

    /**
     * Address: 0x00450110 (FUN_00450110, ?AddWireSphere@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MIHHH@Z)
     *
     * What it does:
     * Emits ring-based wire sphere debug geometry around `center`.
     */
    void AddWireSphere(
      const Wm3::Vector3f& center,
      const Wm3::Vector3f& upAxis,
      float radius,
      std::uint32_t depth,
      int unused0 = 0,
      int unused1 = 0,
      int unused2 = 0
    );

    /**
     * Address: 0x00450330 (FUN_00450330, ?AddWireCoords@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@ABV?$Quaternion@M@4@M@Z)
     *
     * What it does:
     * Draws RGB orientation axes of length `axisLength` from `origin` rotated by `orientation`.
     */
    void AddWireCoords(const Wm3::Vector3f& origin, const Wm3::Quaternionf& orientation, float axisLength);

    /**
     * Address: 0x00450500 (FUN_00450500, ?AddWireCoords@CDebugCanvas@Moho@@QAEXABVVTransform@2@M@Z)
     *
     * What it does:
     * Wrapper that forwards transform orientation/position to the vector+quaternion axis draw lane.
     */
    void AddWireCoords(const VTransform& transform, float axisLength = 1.0f);

    /**
     * Address: 0x00450520 (FUN_00450520, ?AddWireBox@CDebugCanvas@Moho@@QAEXABV?$Box3@M@Wm3@@I@Z)
     *
     * What it does:
     * Emits 12 wireframe edges for an oriented box.
     */
    void AddWireBox(const Wm3::Box3f& box, std::uint32_t depth);

    /**
     * Address: 0x00451320 (FUN_00451320, ?AddParabolaClosedForm@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MMM@Z)
     *
     * What it does:
     * Draws a closed-form ballistic/parabolic arc in 0.1 time-step segments.
     */
    void AddParabolaClosedForm(
      const Wm3::Vector3f& endPoint,
      const Wm3::Vector3f& startPoint,
      float angle,
      float speed,
      float gravity
    );

    /**
     * Address: 0x004514E0 (FUN_004514E0, ?AddParabolaStepped@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@000@Z)
     *
     * What it does:
     * Integrates a stepped ballistic arc using per-step velocity + acceleration
     * vectors and emits cyan line segments.
     */
    void AddParabolaStepped(
      const Wm3::Vector3f& velocityStep,
      const Wm3::Vector3f& startPoint,
      const Wm3::Vector3f& endPoint,
      const Wm3::Vector3f& accelerationStep
    );

    /**
     * Address: 0x004516C0 (FUN_004516C0, ?Render@CDebugCanvas@Moho@@QBEXPAVCD3DPrimBatcher@2@ABVGeomCamera3@2@HH@Z)
     *
     * What it does:
     * Renders buffered debug lines/text/decals through the caller-provided
     * prim batcher and camera.
     */
    void Render(CD3DPrimBatcher* primBatcher, const GeomCamera3& camera, int viewportWidth, int viewportHeight) const;

    /**
     * Address: 0x00451FB0 (FUN_00451FB0, ?Clear@CDebugCanvas@Moho@@QAEXXZ)
     *
     * What it does:
     * Clears all debug draw/text/decal buffers while preserving vector capacity.
     */
    void Clear();

    /**
     * Address: 0x00452070 (FUN_00452070, Moho::CDebugCanvas::DebugDrawLine)
     *
     * What it does:
     * Appends one line segment to the debug line buffer.
     */
    void DebugDrawLine(const SDebugLine& line);

    /**
     * Address: 0x006531D0 (FUN_006531D0, helper used by Moho::RDebugWeapons::OnTick)
     *
     * What it does:
     * Appends one world-space text label to the debug text buffer.
     */
    void AddWorldText(const SDebugWorldText& text);

  public:
    msvc8::vector<SDebugLine> lines;
    msvc8::vector<SDebugWorldText> worldText;
    msvc8::vector<SDebugScreenText> screenText;
    msvc8::vector<SDebugDecal> decals;
  };

  static_assert(sizeof(CDebugCanvas) == 0x40, "CDebugCanvas size must be 0x40");
} // namespace moho
