#include "moho/sim/SimPrivate.h"


/**
 * Address: 0x00746790 (FUN_00746790, ??0CDebugCanvas@Moho@@QAE@XZ)
 *
 * What it does:
 * Initializes all debug-geometry/text/decal buffers to empty.
 */
CDebugCanvas::CDebugCanvas()
  : lines()
  , worldText()
  , screenText()
  , decals()
{}

/**
 * Address: 0x00452070 (FUN_00452070, Moho::CDebugCanvas::DebugDrawLine)
 */
void CDebugCanvas::DebugDrawLine(const SDebugLine& line)
{
  lines.push_back(line);
}

/**
 * Address: 0x00652C00 (FUN_00652C00, Moho::CDebugCanvas::AddText)
 *
 * What it does:
 * Builds one world-space text entry from position/text/style/depth lanes
 * and appends it to the debug world-text buffer.
 */
void CDebugCanvas::AddText(
  const Wm3::Vector3f& position,
  const char* const text,
  const std::int32_t style,
  const std::uint32_t depth
)
{
  SDebugWorldText entry{};
  entry.position = position;
  entry.text.assign_owned(text != nullptr ? text : "");
  entry.style = style;
  entry.depth = depth;
  AddWorldText(entry);
}

/**
 * Address: 0x006531D0 (FUN_006531D0, helper used by Moho::RDebugWeapons::OnTick)
 */
void CDebugCanvas::AddWorldText(const SDebugWorldText& text)
{
  worldText.push_back(text);
}

/**
 * Address: 0x00450030 (FUN_00450030, ?AddWireCircle@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MII@Z)
 */
void CDebugCanvas::AddWireCircle(
  const Wm3::Vector3f& normal,
  const Wm3::Vector3f& center,
  const float radius,
  const std::uint32_t depth,
  const std::uint32_t precision
)
{
  Wm3::Quaternionf orientation{};
  // 0x00450043..0x00450083: v1 = +Z (0,0,1), v2 = `normal`, fallback axis
  // `edi` = +X (1,0,0).
  QuatCrossAdd(&orientation, {0.0f, 0.0f, 1.0f}, normal, {1.0f, 0.0f, 0.0f});

  Wm3::Vector3f axis2Input{0.0f, radius, 0.0f};
  Wm3::Vector3f axis2{};
  MultQuadVec(&axis2, &axis2Input, &orientation);

  Wm3::Vector3f axis1Input{radius, 0.0f, 0.0f};
  Wm3::Vector3f axis1{};
  MultQuadVec(&axis1, &axis1Input, &orientation);

  AddWireOval(center, axis1, axis2, depth, precision);
}

/**
 * Address: 0x0044FA70 (FUN_0044FA70, ?AddLine@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0I@Z)
 */
void CDebugCanvas::AddLine(const Wm3::Vector3f& p0, const Wm3::Vector3f& p1, const std::uint32_t depth)
{
  SDebugLine line{};
  line.p0 = p0;
  line.p1 = p1;
  line.depth0 = static_cast<std::int32_t>(depth);
  line.depth1 = static_cast<std::int32_t>(depth);
  DebugDrawLine(line);
}

/**
 * Address: 0x0044FD50 (FUN_0044FD50, ?AddContouredLine@CDebugCanvas@Moho@@QAEXABV?$Vector2@M@Wm3@@0IABVCHeightField@2@@Z)
 */
void CDebugCanvas::AddContouredLine(
  const Wm3::Vector2f& p0,
  const Wm3::Vector2f& p1,
  const std::uint32_t depth,
  const CHeightField& heightField
)
{
  const float stepX = (p0.x - p1.x) * 0.1f;
  const float stepZ = (p0.y - p1.y) * 0.1f;

  float prevX = p1.x;
  float prevZ = p1.y;
  float prevY = heightField.GetElevation(p1.x, p1.y);

  for (int i = 0; i < 10; ++i) {
    const float nextX = prevX + stepX;
    const float nextZ = prevZ + stepZ;

    if (static_cast<int>(nextX) > (heightField.width - 1)) {
      break;
    }
    if (static_cast<int>(nextZ) > (heightField.height - 1)) {
      break;
    }

    const float nextY = heightField.GetElevation(nextX, nextZ);
    AddLine({prevX, prevY, prevZ}, {nextX, nextY, nextZ}, depth);

    prevX = nextX;
    prevY = nextY;
    prevZ = nextZ;
  }
}

/**
 * Address: 0x0044FED0 (FUN_0044FED0, ?AddWireOval@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@00II@Z)
 */
void CDebugCanvas::AddWireOval(
  const Wm3::Vector3f& center,
  const Wm3::Vector3f& axis1,
  const Wm3::Vector3f& axis2,
  const std::uint32_t depth,
  const std::uint32_t precision
)
{
  constexpr float kTwoPi = 6.2831855f;

  float prevX = center.x + axis1.x;
  float prevY = center.y + axis1.y;
  float prevZ = center.z + axis1.z;

  for (std::uint32_t i = 1; i <= precision; ++i) {
    const float angle = (static_cast<float>(i) * kTwoPi) / static_cast<float>(precision);
    const float sinAngle = static_cast<float>(fa::sin(angle));
    const float cosAngle = static_cast<float>(fa::cos(angle));

    const float nextX = center.x + (axis1.x * cosAngle) + (axis2.x * sinAngle);
    const float nextY = center.y + (axis1.y * cosAngle) + (axis2.y * sinAngle);
    const float nextZ = center.z + (axis1.z * cosAngle) + (axis2.z * sinAngle);

    AddLine({prevX, prevY, prevZ}, {nextX, nextY, nextZ}, depth);

    prevX = nextX;
    prevY = nextY;
    prevZ = nextZ;
  }
}

/**
 * Address: 0x00450110 (FUN_00450110, ?AddWireSphere@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MIHHH@Z)
 */
void CDebugCanvas::AddWireSphere(
  const Wm3::Vector3f& center,
  const Wm3::Vector3f& upAxis,
  const float radius,
  const std::uint32_t depth,
  const int unused0,
  const int unused1,
  const int unused2
)
{
  (void)unused0;
  (void)unused1;
  (void)unused2;

  Wm3::Quaternionf orientation{};
  // 0x0045012C..0x0045016C: v1 = +Z (0,0,1), v2 = `upAxis`, fallback axis
  // `edi` = +X (1,0,0).
  QuatCrossAdd(&orientation, {0.0f, 0.0f, 1.0f}, upAxis, {1.0f, 0.0f, 0.0f});

  Wm3::Vector3f basisX{};
  const Wm3::Vector3f unitX{1.0f, 0.0f, 0.0f};
  MultQuadVec(&basisX, &unitX, &orientation);

  Wm3::Vector3f basisY{};
  const Wm3::Vector3f unitY{0.0f, 1.0f, 0.0f};
  MultQuadVec(&basisY, &unitY, &orientation);

  constexpr float kPiOver4 = 0.78539819f;
  for (int i = 0; i < 4; ++i) {
    const float angle = static_cast<float>(i) * kPiOver4;
    const float sinAngle = static_cast<float>(fa::sin(angle));
    const float cosAngle = static_cast<float>(fa::cos(angle));

    const Wm3::Vector3f dir{
      (basisX.x * cosAngle) + (basisY.x * sinAngle),
      (basisX.y * cosAngle) + (basisY.y * sinAngle),
      (basisX.z * cosAngle) + (basisY.z * sinAngle),
    };

    AddWireCircle(dir, center, radius, depth, 0x18u);
  }

  for (int i = 1; i <= 3; ++i) {
    const float angle = static_cast<float>(i) * kPiOver4;
    const float centerScale = static_cast<float>(fa::cos(angle)) * radius;
    const Wm3::Vector3f ringCenter{
      center.x + (upAxis.x * centerScale),
      center.y + (upAxis.y * centerScale),
      center.z + (upAxis.z * centerScale),
    };
    const float ringRadius = radius * static_cast<float>(fa::sin(angle));

    AddWireCircle(upAxis, ringCenter, ringRadius, depth, 0x18u);
  }
}

/**
 * Address: 0x00450330 (FUN_00450330, ?AddWireCoords@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@ABV?$Quaternion@M@4@M@Z)
 */
void CDebugCanvas::AddWireCoords(
  const Wm3::Vector3f& origin,
  const Wm3::Quaternionf& orientation,
  const float axisLength
)
{
  Wm3::Vector3f rotatedAxis{};

  Wm3::Vector3f axisX{axisLength, 0.0f, 0.0f};
  MultQuadVec(&rotatedAxis, &axisX, &orientation);
  AddLine(
    origin,
    {origin.x + rotatedAxis.x, origin.y + rotatedAxis.y, origin.z + rotatedAxis.z},
    static_cast<std::uint32_t>(0xFFFF0000u)
  );

  Wm3::Vector3f axisY{0.0f, axisLength, 0.0f};
  MultQuadVec(&rotatedAxis, &axisY, &orientation);
  AddLine(
    origin,
    {origin.x + rotatedAxis.x, origin.y + rotatedAxis.y, origin.z + rotatedAxis.z},
    static_cast<std::uint32_t>(0xFF00FF00u)
  );

  Wm3::Vector3f axisZ{0.0f, 0.0f, axisLength};
  MultQuadVec(&rotatedAxis, &axisZ, &orientation);
  AddLine(
    origin,
    {origin.x + rotatedAxis.x, origin.y + rotatedAxis.y, origin.z + rotatedAxis.z},
    static_cast<std::uint32_t>(0xFF0000FFu)
  );
}

/**
 * Address: 0x00450500 (FUN_00450500, ?AddWireCoords@CDebugCanvas@Moho@@QAEXABVVTransform@2@M@Z)
 */
void CDebugCanvas::AddWireCoords(const VTransform& transform, const float axisLength)
{
  (void)axisLength;
  AddWireCoords(transform.pos_, transform.orient_, 1.0f);
}

/**
 * Address: 0x00450520 (FUN_00450520, ?AddWireBox@CDebugCanvas@Moho@@QAEXABV?$Box3@M@Wm3@@I@Z)
 */
void CDebugCanvas::AddWireBox(const Wm3::Box3f& box, const std::uint32_t depth)
{
  const Wm3::Vector3f center{box.Center[0], box.Center[1], box.Center[2]};
  const Wm3::Vector3f axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
  const Wm3::Vector3f axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
  const Wm3::Vector3f axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

  const Wm3::Vector3f e0 = axis0 * box.Extent[0];
  const Wm3::Vector3f e1 = axis1 * box.Extent[1];
  const Wm3::Vector3f e2 = axis2 * box.Extent[2];

  const Wm3::Vector3f c000 = center - e0 - e1 - e2;
  const Wm3::Vector3f c001 = center - e0 - e1 + e2;
  const Wm3::Vector3f c010 = center - e0 + e1 - e2;
  const Wm3::Vector3f c011 = center - e0 + e1 + e2;
  const Wm3::Vector3f c100 = center + e0 - e1 - e2;
  const Wm3::Vector3f c101 = center + e0 - e1 + e2;
  const Wm3::Vector3f c110 = center + e0 + e1 - e2;
  const Wm3::Vector3f c111 = center + e0 + e1 + e2;

  AddLine(c000, c001, depth);
  AddLine(c001, c011, depth);
  AddLine(c011, c010, depth);
  AddLine(c010, c000, depth);

  AddLine(c100, c101, depth);
  AddLine(c101, c111, depth);
  AddLine(c111, c110, depth);
  AddLine(c110, c100, depth);

  AddLine(c000, c100, depth);
  AddLine(c001, c101, depth);
  AddLine(c011, c111, depth);
  AddLine(c010, c110, depth);
}

/**
 * Address: 0x00451320 (FUN_00451320, ?AddParabolaClosedForm@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MMM@Z)
 */
void CDebugCanvas::AddParabolaClosedForm(
  const Wm3::Vector3f& endPoint,
  const Wm3::Vector3f& startPoint,
  const float angle,
  const float speed,
  const float gravity
)
{
  const float dx = endPoint.x - startPoint.x;
  const float dz = endPoint.z - startPoint.z;

  Wm3::Vector3f direction{dx, 0.0f, dz};
  const float horizontalSpeed = static_cast<float>(fa::cos(angle)) * speed;
  const float totalTime = std::sqrt((dx * dx) + (dz * dz)) / horizontalSpeed;
  Wm3::Vector3f::Normalize(&direction);

  const float launchVertical = static_cast<float>(fa::sin(angle)) * speed;
  const float halfGravity = gravity * 0.5f;

  float previousX = startPoint.x;
  float previousY = startPoint.y;
  float previousZ = startPoint.z;
  float t = 0.1f;

  if (totalTime >= 0.1f) {
    while (true) {
      const float yOffset = ((t * halfGravity) + launchVertical) * t;
      const float horizontalDistance = t * horizontalSpeed;

      const float nextX = startPoint.x + (horizontalDistance * direction.x);
      const float nextY = startPoint.y + (horizontalDistance * direction.y) + yOffset;
      const float nextZ = startPoint.z + (horizontalDistance * direction.z);

      AddLine(
        {previousX, previousY, previousZ},
        {nextX, nextY, nextZ},
        static_cast<std::uint32_t>(0xFFFFFFFFu)
      );

      const float nextT = t + 0.1f;
      previousX = nextX;
      previousY = nextY;
      previousZ = nextZ;
      t = nextT;

      if (totalTime < nextT) {
        break;
      }
    }
  }
}

/**
 * Address: 0x004514E0 (FUN_004514E0, ?AddParabolaStepped@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@000@Z)
 */
void CDebugCanvas::AddParabolaStepped(
  const Wm3::Vector3f& velocityStep,
  const Wm3::Vector3f& startPoint,
  const Wm3::Vector3f& endPoint,
  const Wm3::Vector3f& accelerationStep
)
{
  Wm3::Vector3f stepVelocity = velocityStep;

  const float horizontalDistance =
    std::sqrt(((endPoint.z - startPoint.z) * (endPoint.z - startPoint.z)) + ((endPoint.x - startPoint.x) * (endPoint.x - startPoint.x)));
  const float horizontalStepLength = std::sqrt((stepVelocity.z * stepVelocity.z) + (stepVelocity.x * stepVelocity.x));
  if (horizontalStepLength <= 0.0f) {
    return;
  }

  const float steps = horizontalDistance / horizontalStepLength;
  if (steps < 1.0f) {
    return;
  }

  float currentX = startPoint.x;
  float currentY = startPoint.y;
  float currentZ = startPoint.z;

  int stepIndex = 1;
  while (true) {
    const float previousVelocityX = stepVelocity.x;
    const float previousVelocityY = stepVelocity.y;
    const float previousVelocityZ = stepVelocity.z;

    stepVelocity.x += accelerationStep.x;
    stepVelocity.y += accelerationStep.y;
    stepVelocity.z += accelerationStep.z;

    const float nextX = currentX + ((previousVelocityX + stepVelocity.x) * 0.5f);
    const float nextY = currentY + ((previousVelocityY + stepVelocity.y) * 0.5f);
    const float nextZ = currentZ + ((previousVelocityZ + stepVelocity.z) * 0.5f);

    SDebugLine line{};
    line.p0 = {currentX, currentY, currentZ};
    line.p1 = {nextX, nextY, nextZ};
    line.depth0 = static_cast<std::int32_t>(0xFF00FFFFu);
    line.depth1 = static_cast<std::int32_t>(0xFF00FFFFu);
    DebugDrawLine(line);

    currentX = nextX;
    currentY = nextY;
    currentZ = nextZ;
    ++stepIndex;
    if (steps < static_cast<float>(stepIndex)) {
      break;
    }
  }
}


/**
 * Address: 0x00451FB0 (FUN_00451FB0, ?Clear@CDebugCanvas@Moho@@QAEXXZ)
 */
void CDebugCanvas::Clear()
{
  lines.clear();
  screenText.clear();
  worldText.clear();
  decals.clear();
}

/**
 * Address: 0x00756C30 (FUN_00756C30, ??1CDebugCanvas@Moho@@QAE@XZ)
 *
 * What it does:
 * Releases all debug line/text/decal vector storage lanes.
 */
CDebugCanvas::~CDebugCanvas() = default;
