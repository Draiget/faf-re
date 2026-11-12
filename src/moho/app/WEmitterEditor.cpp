#include "moho/app/WEmitterEditor.h"
#include "legacy/math/X87Math.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>

#include <SDL3/SDL.h>

#include "imgui.h"

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/UserEntity.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/render/EEmitterCurve.h"
#include "moho/render/EEmitterParam.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/REffectBlueprint.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

namespace
{
  /** Smallest visible value span the curve editor will zoom down to (0x00E4F714). */
  constexpr float kMinimumVisibleValueSpan = 0.1f;

  /** Side of the square grab handle drawn per key by FUN_00662180. */
  constexpr int kCurveKeyHandleSize = 5;

  /** Drag buttons stored in WCurveEditor::mActiveDragButton. */
  constexpr int kCurveDragNone = 0;
  constexpr int kCurveDragKey = 1;
  constexpr int kCurveDragTangent = 2;

  // The binary's pens and brush (0x00661B90, 0x00662180): red, cyan, and the default white brush.
  constexpr ImU32 kRedPen = IM_COL32(255, 0, 0, 255);
  constexpr ImU32 kCyanPen = IM_COL32(0, 255, 255, 255);
  constexpr ImU32 kWhiteBrush = IM_COL32(255, 255, 255, 255);
  constexpr ImU32 kEditorBackground = IM_COL32(64, 64, 64, 255);

  /**
   * One row of the curve tabs, read from .rdata at 0x00E24F00 by the WEmitterWx constructor's
   * loop (0x00666BF7-0x00666EE7, stride 0x1C): the key the curve is saved under, the title of
   * the tab it opens (empty for curves that join the previous tab), its caption, then the view
   * range and first key its WCurveEditorPanel is built with.
   */
  struct SEmitterCurveEditorDesc
  {
    const char* mScriptName;
    const char* mTabTitle;
    const char* mCaption;
    float mViewValueMin;
    float mViewValueMax;
    float mInitialKeyValue;
    float mInitialKeyTangent;
  };

  const SEmitterCurveEditorDesc kEmitterCurveEditors[moho::EMITTER_LAST_CURVE] = {
    {"XDirectionCurve", "Direction, Rate, Lifetime", "X Direction", -1.0f, 1.0f, 0.0f, 0.0f},
    {"YDirectionCurve", "", "Y Direction", -1.0f, 1.0f, 0.5f, 0.0f},
    {"ZDirectionCurve", "", "Z Direction", -1.0f, 1.0f, 0.0f, 0.0f},
    {"EmitRateCurve", "", "Emit Rate", -0.5f, 30.0f, 1.0f, 0.0f},
    {"LifetimeCurve", "", "Lifetime", 0.0f, 30.0f, 10.0f, 0.0f},
    {"VelocityCurve", "Forces", "Velocity", 0.0f, 5.0f, 1.0f, 0.0f},
    {"XAccelCurve", "", "X Acceleration", -0.5f, 0.5f, 0.0f, 0.0f},
    {"YAccelCurve", "", "Y Acceleration", -0.5f, 0.5f, 0.0f, 0.0f},
    {"ZAccelCurve", "", "Z Acceleration", -0.5f, 0.5f, 0.0f, 0.0f},
    {"ResistanceCurve", "", "Resistance", 0.0f, 1.0f, 0.0f, 0.0f},
    {"SizeCurve", "Spacial", "Emitter Size", 0.0f, 5.0f, 0.0f, 0.0f},
    {"XPosCurve", "", "X Position", -5.0f, 5.0f, 0.0f, 0.0f},
    {"YPosCurve", "", "Y Position", -5.0f, 5.0f, 0.0f, 0.0f},
    {"ZPosCurve", "", "Z Position", -5.0f, 5.0f, 0.0f, 0.0f},
    {"StartSizeCurve", "Size and Rotation", "Particle Start Size", 0.0f, 2.0f, 1.0f, 0.0f},
    {"EndSizeCurve", "", "Particle End Size", 0.0f, 2.0f, 1.0f, 0.1f},
    {"InitialRotationCurve", "", "Particle Rotation", 0.0f, 360.0f, 180.0f, 360.0f},
    {"RotationRateCurve", "", "Particle Rotation Rate", -90.0f, 90.0f, 0.0f, 10.0f},
    {"FrameRateCurve", "Animation and Selection", "Particle Frame Rate", 0.0f, 5.0f, 1.0f, 0.0f},
    {"TextureSelectionCurve", "", "Particle Texture Selection", 0.0f, 5.0f, 0.0f, 0.0f},
    {"RampSelectionCurve", "", "Color/Alpha Ramp Selection", 0.0f, 1.0f, 0.0f, 0.0f},
  };

  // The curves that open a tab; the others join the tab before them.
  [[nodiscard]] bool OpensCurveTab(
    const int curve
  )
  {
    return curve == moho::EMITTER_XDIR_CURVE || curve == moho::EMITTER_VELOCITY_CURVE ||
      curve == moho::EMITTER_SIZE_CURVE || curve == moho::EMITTER_BEGINSIZE_CURVE ||
      curve == moho::EMITTER_FRAMERATE_CURVE;
  }

  const char* const kBlendModes[] = {
    "Alpha Blend",
    "Modulate Inverse",
    "Modulate2X Inverse",
    "Add",
    "Premodulated Alpha",
    "Refract",
  };

  const char* const kFidelities[] = {
    "Low",
    "Medium",
    "Medium/Low",
    "High",
    "High/Low",
    "High/Medium",
    "High/Medium/Low",
  };

  const char* BoolString(
    const bool value
  )
  {
    return value ? "true" : "false";
  }

  // The number in a field as the binary read it (0x006671F0): wcstod's value, 0 when nothing parses.
  [[nodiscard]] double ParseNumber(
    const char* const text
  )
  {
    return std::strtod(text, nullptr);
  }

  template <std::size_t N>
  void FormatInto(
    std::array<char, N>& buffer,
    const char* const format,
    const double value
  )
  {
    std::snprintf(buffer.data(), buffer.size(), format, value);
  }

  // The *.bp test of 0x00668B00, case as written.
  [[nodiscard]] bool EndsWithBlueprintExtension(
    const fa::string& fileName
  )
  {
    const std::size_t length = fileName.size();
    return length >= 3u && std::string(fileName.c_str() + length - 3u) == ".bp";
  }

  // The directory and the file name of a full path, as 0x00668B00 took them from its file dialog.
  void SplitPath(
    const fa::string& path,
    fa::string& directory,
    fa::string& fileName
  )
  {
    const std::string text(path.c_str());
    const std::size_t slash = text.find_last_of("/\\");
    if (slash == std::string::npos) {
      directory = "";
      fileName = text.c_str();
      return;
    }
    directory = text.substr(0, slash).c_str();
    fileName = text.substr(slash + 1).c_str();
  }

  // The blueprint id 0x00668B00 writes: the text before the last underscore, empty without one.
  [[nodiscard]] fa::string BeforeLastUnderscore(
    const fa::string& text
  )
  {
    const std::string value(text.c_str());
    const std::size_t underscore = value.rfind('_');
    return underscore == std::string::npos ? fa::string("") : fa::string(value.substr(0, underscore).c_str());
  }

  // The editors still open, for WEmitterEditor::DestroyAll (WINX_Exit, as managedFrames).
  std::vector<moho::WEmitterEditor*> gOpenEditors;
} // namespace

// ---------------------------------------------------------------------------
// WCurveEditor

/**
 * Address: 0x00661100 (FUN_00661100)
 *
 * What it does:
 * The binary called wxControl::ProcessCommand (0x0098D5F0) with a button-clicked command whose
 * id routed it to WEmitterWx::OnSettingChanged; the owner is called directly.
 */
void moho::WCurveEditor::PostCurveChangedCommand()
{
  mCurveDirty = false;
  if (mOwnerPanel != nullptr && mOwnerPanel->mOwner != nullptr) {
    mOwnerPanel->mOwner->OnSettingChanged();
  }
}

/**
 * Address: 0x006612A0 (FUN_006612A0)
 *
 * What it does:
 * The horizontal axis maps time through mViewTimeScale relative to mViewTimeMin; the vertical
 * axis is inverted, measuring up from the bottom of the client area.
 */
moho::CurveScreenPoint moho::WCurveEditor::ProjectCurvePointToScreen(
  const std::int32_t edge,
  const CurveEnvelopeColumn& column
) const
{
  CurveScreenPoint projected;

  float value = column.mValue;
  if (edge == kCurveEnvelopeUpperEdge) {
    value = column.mTangent * 0.5f + column.mValue;
  } else if (edge == kCurveEnvelopeLowerEdge) {
    value = column.mValue - column.mTangent * 0.5f;
  }

  projected.x = static_cast<int>(mViewTimeScale * (column.mTime - mViewTimeMin));
  projected.y = static_cast<int>(static_cast<float>(mClientHeight) - mViewValueScale * (value - mViewValueMin));
  return projected;
}

/**
 * Address: 0x00661330 (FUN_00661330, Moho::WCurveEditor::WCurveEditor)
 */
moho::WCurveEditor::WCurveEditor(
  WCurveEditorPanel* const parent,
  const float viewTimeMax,
  const float viewValueMin,
  const float viewValueMax,
  const float initialKeyValue,
  const float initialKeyTangent
)
{
  mViewValueMin = viewValueMin;
  mOwnerPanel = parent;
  mMouseCaptured = false;
  mViewTimeMin = 0.0f;
  mViewTimeMax = viewTimeMax;
  mViewValueMax = viewValueMax;

  RescaleEmitterCurveXRange(&mCurve, 0.0f, mViewTimeMax);
  InsertEmitterCurveKey(mCurve, Wm3::Vector3f(mViewTimeMax * 0.5f, initialKeyValue, initialKeyTangent));
  mSelectedKey = mCurve.mKeys.begin();
  mCurveDirty = false;
}

/**
 * Address: 0x00661700 (FUN_00661700)
 */
void moho::WCurveEditor::SetName(
  const std::string& name
)
{
  mCaption = name;
}

/**
 * Address: 0x00661710 (FUN_00661710)
 */
void moho::WCurveEditor::SetScriptName(
  const std::string& scriptName
)
{
  mScriptName = scriptName;
}

/**
 * Address: 0x00661720 (FUN_00661720)
 */
void moho::WCurveEditor::ResetCurveXRange(
  const float rangeMax
)
{
  mViewTimeMin = 0.0f;
  mViewTimeMax = rangeMax;
  RescaleEmitterCurveXRange(&mCurve, 0.0f, rangeMax);
}

/**
 * Address: 0x006614B0 (FUN_006614B0)
 *
 * What it does:
 * The time is clamped into the visible range and then between the key's neighbours, so moving
 * a key never reorders the curve; the value is clamped into the visible range and the tangent
 * is stored as given. The curve's Y bounds are rederived afterwards.
 */
void moho::WCurveEditor::MoveSelectedKeyTo(
  const float time,
  const float value,
  const float tangent
)
{
  Wm3::Vector3f* const key = mSelectedKey;
  if (key == mCurve.mKeys.end()) {
    return;
  }

  float clampedTime = mViewTimeMax > time ? time : mViewTimeMax;
  clampedTime = mViewTimeMin > clampedTime ? mViewTimeMin : clampedTime;
  float clampedValue = mViewValueMax > value ? value : mViewValueMax;
  clampedValue = mViewValueMin > clampedValue ? mViewValueMin : clampedValue;

  if (key != mCurve.mKeys.begin() && key[-1].x > clampedTime) {
    clampedTime = key[-1].x;
  }
  if (key + 1 != mCurve.mKeys.end() && clampedTime > key[1].x) {
    clampedTime = key[1].x;
  }

  key->x = clampedTime;
  key->y = clampedValue;
  key->z = tangent;
  RecomputeEmitterCurveYBounds(mCurve);

  PostCurveChangedCommand();
}

/**
 * Address: 0x00661580 (FUN_00661580)
 *
 * What it does:
 * The XRange is the curve's upper time bound (`mBoundsMax.x`).
 */
void moho::WCurveEditor::WriteCurveScript(
  gpg::TextWriter& writer
) const
{
  writer.Printf("\t%s = {\n\t\tXRange = %.2f,\n\t\tKeys = {\n", mScriptName.c_str(), mCurve.mBoundsMax.x);
  for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
    writer.Printf("\t\t\t{ x=%.3f,y=%.3f,z=%.3f },\n", key->x, key->y, key->z);
  }
  writer.Printf("\t\t},\n\t},\n");
}

/**
 * Address: 0x006617A0 (FUN_006617A0)
 */
void moho::WCurveEditor::ZoomValueAxisByWheel(
  const int wheelRotation
)
{
  const float valueDelta = static_cast<float>(wheelRotation) / (mViewValueScale * 5.0f) * 0.5f;
  const float zoomedMin = mViewValueMin + valueDelta;
  const float zoomedMax = mViewValueMax - valueDelta;
  if (zoomedMax - zoomedMin < kMinimumVisibleValueSpan) {
    return;
  }

  mViewValueMin = zoomedMin;
  mViewValueMax = zoomedMax;
}

/**
 * Address: 0x00661820 (FUN_00661820)
 */
void moho::WCurveEditor::OnMouseDown(
  const int mouseX,
  const int mouseY,
  const bool middleButton
)
{
  mLastMouseX = mouseX;
  mLastMouseY = mouseY;

  const Wm3::Vector2f point(
    mViewTimeMin + static_cast<float>(mLastMouseX) / mViewTimeScale,
    mViewValueMin + static_cast<float>(mClientHeight - mouseY) / mViewValueScale
  );
  mSelectedKey = FindNearestCurveKey(mCurve, point);

  mActiveDragButton = middleButton ? kCurveDragTangent : kCurveDragKey;
  PostCurveChangedCommand();

  // The binary called CaptureMouse here; ImGui keeps the pressed editor active until the
  // button is let go.
  mMouseCaptured = true;
}

/**
 * Address: 0x00661900 (FUN_00661900)
 */
void moho::WCurveEditor::OnMouseMove(
  const int mouseX,
  const int mouseY
)
{
  // Motion converts pixels to units by multiplying with the reciprocal (0x00DFEC20 is 1.0f),
  // unlike the button handlers, which divide.
  const float valuePerPixel = 1.0f / mViewValueScale;
  const float time = mViewTimeMin + static_cast<float>(mouseX) / mViewTimeScale;
  const float value = mViewValueMin + static_cast<float>(mClientHeight - mouseY) * valuePerPixel;

  if (mActiveDragButton == kCurveDragKey && mSelectedKey != mCurve.mKeys.end()) {
    // The same clamping as MoveSelectedKeyTo. The binary has no no-selection test here; a key
    // is always selected by the press that starts the drag.
    Wm3::Vector3f* const key = mSelectedKey;
    const float tangent = key->z;

    float clampedTime = mViewTimeMax > time ? time : mViewTimeMax;
    clampedTime = mViewTimeMin > clampedTime ? mViewTimeMin : clampedTime;
    float clampedValue = mViewValueMax > value ? value : mViewValueMax;
    clampedValue = mViewValueMin > clampedValue ? mViewValueMin : clampedValue;

    if (key != mCurve.mKeys.begin() && key[-1].x > clampedTime) {
      clampedTime = key[-1].x;
    }
    if (key + 1 != mCurve.mKeys.end() && clampedTime > key[1].x) {
      clampedTime = key[1].x;
    }

    key->x = clampedTime;
    key->y = clampedValue;
    key->z = tangent;
    RecomputeEmitterCurveYBounds(mCurve);

    PostCurveChangedCommand();
  } else if (mActiveDragButton == kCurveDragTangent && mSelectedKey != mCurve.mKeys.end()) {
    mSelectedKey->z += static_cast<float>(mLastMouseY - mouseY) * valuePerPixel;
    if (0.0f > mSelectedKey->z) {
      mSelectedKey->z = 0.0f;
    }

    PostCurveChangedCommand();
  }

  mLastMouseY = mouseY;
  mLastMouseX = mouseX;
}

/**
 * Address: 0x00661A50 (FUN_00661A50)
 */
void moho::WCurveEditor::OnMouseUp()
{
  mActiveDragButton = kCurveDragNone;
  if (mMouseCaptured) {
    mMouseCaptured = false;
    PostCurveChangedCommand();
  }
}

/**
 * Address: 0x00661A90 (FUN_00661A90)
 */
void moho::WCurveEditor::OnCurveKeyEdit(
  const int mouseX,
  const int mouseY,
  const bool controlDown
)
{
  Wm3::Vector3f point;
  point.x = mViewTimeMin + static_cast<float>(mouseX) / mViewTimeScale;
  point.y = mViewValueMin + static_cast<float>(mClientHeight - mouseY) / mViewValueScale;

  if (controlDown) {
    if (mCurve.mKeys.size() > 1) {
      Wm3::Vector3f* const nearest = FindNearestCurveKey(mCurve, Wm3::Vector2f(point.x, point.y));
      (void)EraseEmitterCurveKeyRange(nearest, nearest + 1, mCurve);
      RecomputeEmitterCurveYBounds(mCurve);
      mSelectedKey = mCurve.mKeys.begin();
    }
  } else {
    point.z = 0.0f;
    InsertEmitterCurveKey(mCurve, point);
    mSelectedKey = FindNearestCurveKey(mCurve, Wm3::Vector2f(point.x, point.y));
  }

  PostCurveChangedCommand();
}

/**
 * Address: 0x00661B90 (FUN_00661B90)
 *
 * What it does:
 * The span runs between two columns: before the first key, from mViewTimeMin to that key; past
 * the last key (`key` is the end sentinel), from the last key to mViewTimeMax; otherwise from
 * the previous key to this one. Each column contributes its upper edge, curve value and lower
 * edge, and the six points are filled as one polygon with the red pen around it; then the red
 * curve line. The binary drew through a wxDC; ImGui's draw list takes the same points.
 */
void moho::WCurveEditor::DrawKeyEnvelopeSpan(
  ImDrawList& drawList,
  const float originX,
  const float originY,
  const Wm3::Vector3f* const key
) const
{
  const auto toScreen = [originX, originY](const CurveScreenPoint point) {
    return ImVec2(originX + static_cast<float>(point.x), originY + static_cast<float>(point.y));
  };

  const auto fillBand = [&](const CurveEnvelopeColumn& left, const CurveEnvelopeColumn& right) {
    const ImVec2 envelope[6] = {
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeUpperEdge, left)),
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeUpperEdge, right)),
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, right)),
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeLowerEdge, right)),
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeLowerEdge, left)),
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, left)),
    };
    drawList.AddConvexPolyFilled(envelope, 6, kWhiteBrush);
    drawList.AddPolyline(envelope, 6, kRedPen, ImDrawFlags_Closed, 1.0f);
  };

  const auto drawLine = [&](const CurveEnvelopeColumn& from, const CurveEnvelopeColumn& to) {
    drawList.AddLine(
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, from)),
      toScreen(ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, to)),
      kRedPen
    );
  };

  if (key == mCurve.mKeys.begin()) {
    const CurveEnvelopeColumn start{mViewTimeMin, key->y, key->z};
    const CurveEnvelopeColumn current{key->x, key->y, key->z};
    fillBand(start, current);
    drawLine(start, current);
  } else if (key == mCurve.mKeys.end()) {
    const Wm3::Vector3f* const last = key - 1;
    const CurveEnvelopeColumn previous{last->x, last->y, last->z};
    const CurveEnvelopeColumn finish{mViewTimeMax, last->y, last->z};
    fillBand(previous, finish);
    drawLine(finish, previous);
  } else {
    const Wm3::Vector3f* const before = key - 1;
    const CurveEnvelopeColumn previous{before->x, before->y, before->z};
    const CurveEnvelopeColumn current{key->x, key->y, key->z};
    fillBand(previous, current);
    drawLine(current, previous);
  }
}

/**
 * Address: 0x00662180 (FUN_00662180)
 */
void moho::WCurveEditor::DrawKeyHandle(
  ImDrawList& drawList,
  const float originX,
  const float originY,
  const Wm3::Vector3f* const key
) const
{
  const ImU32 pen = key == mSelectedKey ? kCyanPen : kRedPen;
  const CurveScreenPoint handle = ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, {key->x, key->y, key->z});
  const ImVec2 topLeft(originX + static_cast<float>(handle.x), originY + static_cast<float>(handle.y));
  const ImVec2 bottomRight(
    topLeft.x + static_cast<float>(kCurveKeyHandleSize), topLeft.y + static_cast<float>(kCurveKeyHandleSize)
  );
  drawList.AddRectFilled(topLeft, bottomRight, kWhiteBrush);
  drawList.AddRect(topLeft, bottomRight, pen);
}

/**
 * Address: 0x006621F0 (FUN_006621F0)
 *
 * What it does:
 * The scales are stored as the spans first and divided in place, in the binary's order. The
 * four axis labels: time bounds centred on the left and right edges, value bounds centred on the
 * bottom and top edges, and the caption top left. The binary's event table routed the mouse to
 * the handlers (left/middle down OnMouseDown, right down OnCurveKeyEdit, left/middle up
 * OnMouseUp, motion OnMouseMove, wheel ZoomValueAxisByWheel; entering, 0x00662570, did nothing);
 * here the editor reads ImGui's mouse while it draws.
 */
void moho::WCurveEditor::Draw(
  const int width,
  const int height
)
{
  const int clientWidth = std::max(width, 16);
  const int clientHeight = std::max(height, 16);
  mClientWidth = clientWidth;
  mClientHeight = clientHeight;

  mViewTimeScale = mViewTimeMax - mViewTimeMin;
  mViewValueScale = mViewValueMax - mViewValueMin;
  mViewTimeScale = static_cast<float>(clientWidth) / mViewTimeScale;
  mViewValueScale = static_cast<float>(clientHeight) / mViewValueScale;

  const ImVec2 origin = ImGui::GetCursorScreenPos();
  const ImVec2 size(static_cast<float>(clientWidth), static_cast<float>(clientHeight));
  (void)ImGui::InvisibleButton(
    "##curve",
    size,
    ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonMiddle | ImGuiButtonFlags_MouseButtonRight
  );
  const bool hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);

  // The mouse, in client pixels.
  const ImGuiIO& io = ImGui::GetIO();
  const int mouseX = static_cast<int>(io.MousePos.x - origin.x);
  const int mouseY = static_cast<int>(io.MousePos.y - origin.y);
  if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
    OnMouseDown(mouseX, mouseY, false);
  } else if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Middle)) {
    OnMouseDown(mouseX, mouseY, true);
  } else if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
    OnCurveKeyEdit(mouseX, mouseY, io.KeyCtrl);
  }
  if ((hovered || mMouseCaptured) && (mouseX != mLastMouseX || mouseY != mLastMouseY)) {
    OnMouseMove(mouseX, mouseY);
  }
  if (
    mMouseCaptured && (ImGui::IsMouseReleased(ImGuiMouseButton_Left) || ImGui::IsMouseReleased(ImGuiMouseButton_Middle))
  ) {
    OnMouseUp();
  }
  if (hovered && io.MouseWheel != 0.0f) {
    ZoomValueAxisByWheel(static_cast<int>(std::lround(io.MouseWheel * 120.0f)));
  }

  // A change above may have moved the view; the scales follow it before drawing.
  mViewTimeScale = static_cast<float>(clientWidth) / (mViewTimeMax - mViewTimeMin);
  mViewValueScale = static_cast<float>(clientHeight) / (mViewValueMax - mViewValueMin);

  ImDrawList& drawList = *ImGui::GetWindowDrawList();
  const ImVec2 corner(origin.x + size.x, origin.y + size.y);
  drawList.PushClipRect(origin, corner, true);
  drawList.AddRectFilled(origin, corner, kEditorBackground);

  for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
    DrawKeyEnvelopeSpan(drawList, origin.x, origin.y, key);
  }
  DrawKeyEnvelopeSpan(drawList, origin.x, origin.y, mCurve.mKeys.end());

  for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
    DrawKeyHandle(drawList, origin.x, origin.y, key);
  }

  const ImU32 textColour = ImGui::GetColorU32(ImGuiCol_Text);
  const auto drawLabel = [&](const float value, const int anchor) {
    char label[32];
    std::snprintf(label, sizeof(label), "%.1f", value);
    const ImVec2 extent = ImGui::CalcTextSize(label);
    const int textWidth = static_cast<int>(extent.x);
    const int textHeight = static_cast<int>(extent.y);
    int x = 0;
    int y = 0;
    switch (anchor) {
    case 0: // left edge
      y = clientHeight / 2 - textHeight / 2;
      break;
    case 1: // right edge
      x = clientWidth - textWidth;
      y = clientHeight / 2 - textHeight / 2;
      break;
    case 2: // bottom edge
      x = clientWidth / 2 - textWidth / 2;
      y = clientHeight - textHeight;
      break;
    default: // top edge
      x = clientWidth / 2 - textWidth / 2;
      break;
    }
    drawList.AddText(ImVec2(origin.x + static_cast<float>(x), origin.y + static_cast<float>(y)), textColour, label);
  };
  drawLabel(mViewTimeMin, 0);
  drawLabel(mViewTimeMax, 1);
  drawLabel(mViewValueMin, 2);
  drawLabel(mViewValueMax, 3);
  drawList.AddText(origin, textColour, mCaption.c_str());
  drawList.PopClipRect();
}

/**
 * Address: 0x00669E40 (FUN_00669E40)
 */
void moho::WCurveEditor::AssignCurve(
  const SEfxCurve& source
)
{
  mCurve = source;
  mSelectedKey = mCurve.mKeys.end();
  PostCurveChangedCommand();
  mOwnerPanel->RefreshFieldsFromCurve();
}

// ---------------------------------------------------------------------------
// WCurveEditorPanel

/**
 * Address: 0x00662680 (FUN_00662680, Moho::WCurveEditorPanel::WCurveEditorPanel)
 *
 * What it does:
 * Creates the editor; the five fields (Tick, Value, Range, Window Min:, Max:) start from the
 * selected key and the view range, `%f` each.
 */
moho::WCurveEditorPanel::WCurveEditorPanel(
  WEmitterEditor* const owner,
  const float viewTimeMax,
  const float viewValueMin,
  const float viewValueMax,
  const float initialKeyValue,
  const float initialKeyTangent
)
  : mOwner(owner)
{
  mCurveEditor =
    std::make_unique<WCurveEditor>(this, viewTimeMax, viewValueMin, viewValueMax, initialKeyValue, initialKeyTangent);
  RefreshFieldsFromCurve();
  mFieldsLive = true;
}

/**
 * Address: 0x00663400 (FUN_00663400)
 */
void moho::WCurveEditorPanel::RefreshFieldsFromCurve()
{
  const WCurveEditor& editor = *mCurveEditor;
  const Wm3::Vector3f* const keysEnd = editor.mCurve.mKeys.end();
  const bool selected = editor.mSelectedKey != keysEnd;

  FormatInto(mFields[0], "%f", selected ? editor.mSelectedKey->x : 0.0f);
  FormatInto(mFields[1], "%f", selected ? editor.mSelectedKey->y : 0.0f);
  FormatInto(mFields[2], "%f", selected ? editor.mSelectedKey->z : 0.0f);
  FormatInto(mFields[3], "%f", editor.mViewValueMin);
  FormatInto(mFields[4], "%f", editor.mViewValueMax);
}

/**
 * Address: 0x00663650 (FUN_00663650)
 *
 * What it does:
 * Every value seeds from the current one; the committed field's text replaces its own. The key
 * is always moved (MoveSelectedKeyTo), the value-range pair only applied when the span stays at
 * least 0.1. The binary read the text from the wx text-enter command (ids 622..626).
 */
void moho::WCurveEditorPanel::OnCurveFieldCommitted(
  const int field
)
{
  if (!mFieldsLive) {
    return;
  }

  WCurveEditor& editor = *mCurveEditor;
  const Wm3::Vector3f* const keysEnd = editor.mCurve.mKeys.end();
  double keyTime = editor.mSelectedKey != keysEnd ? editor.mSelectedKey->x : 0.0f;
  double keyValue = editor.mSelectedKey != keysEnd ? editor.mSelectedKey->y : 0.0f;
  double keyTangent = editor.mSelectedKey != keysEnd ? editor.mSelectedKey->z : 0.0f;

  if (field == 0) {
    keyTime = ParseNumber(mFields[0].data());
  }
  if (field == 1) {
    keyValue = ParseNumber(mFields[1].data());
  }
  if (field == 2) {
    keyTangent = ParseNumber(mFields[2].data());
  }
  editor.MoveSelectedKeyTo(static_cast<float>(keyTime), static_cast<float>(keyValue), static_cast<float>(keyTangent));

  double viewValueMin = editor.mViewValueMin;
  double viewValueMax = editor.mViewValueMax;
  if (field == 3) {
    viewValueMin = ParseNumber(mFields[3].data());
  }
  if (field == 4) {
    viewValueMax = ParseNumber(mFields[4].data());
  }

  const bool spanTooSmall = viewValueMax - viewValueMin < kMinimumVisibleValueSpan;
  if (!spanTooSmall) {
    editor.mViewValueMin = static_cast<float>(viewValueMin);
    editor.mViewValueMax = static_cast<float>(viewValueMax);
  }
}

void moho::WCurveEditorPanel::Draw(
  const int index,
  const float height
)
{
  static const char* const kFieldLabels[] = {"Tick", "Value", "Range", "Window Min:", "Max:"};
  ImGui::PushID(index);
  const float rowTop = ImGui::GetCursorPosY();
  for (int field = 0; field < 5; ++field) {
    if (field != 0) {
      ImGui::SameLine();
    }
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(kFieldLabels[field]);
    ImGui::SameLine();
    ImGui::PushID(field);
    ImGui::SetNextItemWidth(90.0f);
    if (
      ImGui::InputText(
        "##field",
        mFields[static_cast<std::size_t>(field)].data(),
        mFields[0].size(),
        ImGuiInputTextFlags_EnterReturnsTrue
      )
    ) {
      OnCurveFieldCommitted(field);
    }
    ImGui::PopID();
  }
  const float editorHeight = height - (ImGui::GetCursorPosY() - rowTop) - ImGui::GetStyle().ItemSpacing.y;
  mCurveEditor->Draw(static_cast<int>(ImGui::GetContentRegionAvail().x), static_cast<int>(editorHeight));
  ImGui::PopID();
}

// ---------------------------------------------------------------------------
// WEmitterEditor

struct moho::WEmitterEditor::PendingPick
{
  std::mutex lock;
  bool answered = false;
  fa::string path; // empty: cancelled
};

/**
 * Address: 0x00663900 (FUN_00663900, Moho::WEmitterWx::WEmitterWx)
 *
 * What it does:
 * The menus (File, Options, LOD with their check items' first states), the accelerators (Ctrl+N,
 * Ctrl+S, Alt+S, Ctrl+O, Ctrl+T, Ctrl+R), the two rows of controls with their first values, the
 * time slider and the curve tabs are what Draw shows; the binary built them as wx windows here.
 */
moho::WEmitterEditor::WEmitterEditor(
  UserEntity* const attachEntity,
  const Wm3::Vector3f& spawnPosition,
  const char* const boneName
)
  : platform::tools::ToolWindow("Emitter Editor", 800, 600)
  , mPendingPick(std::make_shared<PendingPick>())
{
  gOpenEditors.push_back(this);

  // Slot 36 hands back the sim with the driver's interlock held; the destructor's
  // ReleaseInterlockRef (slot 37) gives it back.
  mSim = WLD_GetDriver()->ProcessEvents();

  // Engine addition, server mode: a server session's client has no sim (`ProcessEvents` gives none).
  if (attachEntity != nullptr && mSim != nullptr) {
    Entity* const entity = mSim->mEntityDB->FindEntityById(attachEntity->mParams.mEntityId);
    mAttachedUnit.Set(entity != nullptr ? entity->IsUnit() : nullptr);
  } else {
    mAttachedUnit.Set(nullptr);
  }
  if (boneName != nullptr) {
    mBoneName = boneName;
  }

  mTexturePath = "/textures/particles/smoke.dds";
  mRampTexturePath = "/textures/particles/testramp.dds";

  // The Options and LOD menus' first states.
  MenuCheck(kMenuInterpolateEmission) = true;
  MenuCheck(kMenuEmitIfVisible) = true;
  MenuCheck(kMenuCatchupEmit) = true;

  // The first preview never has a blueprint: the constructor passes null where
  // RefreshPreviewEmitter passes BlueprintNameOrNull(). Engine change: no sim, no preview.
  mSpawnPosition = spawnPosition;
  if (mSim != nullptr) {
    IEffect* effect;
    if (mAttachedUnit.GetObjectPtr() != nullptr) {
      const int bone = mAttachedUnit.GetObjectPtr()->ResolveBoneIndex(mBoneName.c_str());
      effect = mSim->mEffectManager->CreateAttachedEmitter(mAttachedUnit.GetObjectPtr(), bone, nullptr, -1);
    } else {
      effect = mSim->mEffectManager->CreateEmitter(mSpawnPosition, nullptr, -1);
    }
    mPreviewEffect.Set(effect);
  }

  std::snprintf(mLifetimeText.data(), mLifetimeText.size(), "-1");
  mCachedRepeatTime = 1.0;
  std::snprintf(mRepeatTimeText.data(), mRepeatTimeText.size(), "50.0");
  mBlendModeSelection = 3;
  mFidelitySelection = 6;
  std::snprintf(mTextureFrameCountText.data(), mTextureFrameCountText.size(), "1");
  std::snprintf(mTextureStripCountText.data(), mTextureStripCountText.size(), "1");
  std::snprintf(mSortOrderText.data(), mSortOrderText.size(), "0");
  std::snprintf(mLodCutoffText.data(), mLodCutoffText.size(), "100");
  mPlaying = true;
  mTimeSliderValue = 0;
  mTimeSliderMax = 100;

  for (int curve = 0; curve < EMITTER_LAST_CURVE; ++curve) {
    const SEmitterCurveEditorDesc& desc = kEmitterCurveEditors[curve];
    auto panel = std::make_unique<WCurveEditorPanel>(
      this,
      static_cast<float>(mCachedRepeatTime),
      desc.mViewValueMin,
      desc.mViewValueMax,
      desc.mInitialKeyValue,
      desc.mInitialKeyTangent
    );
    panel->mCurveEditor->SetName(desc.mCaption);
    panel->mCurveEditor->SetScriptName(desc.mScriptName);
    mCurvePanels.push_back(std::move(panel));
  }

  mControlsBuilt = true;
  RefreshPreviewEmitter();
}

/**
 * Address: 0x00666F40 (FUN_00666F40, Moho::WEmitterWx::~WEmitterWx)
 * Address: 0x00669E10 (FUN_00669E10, scalar deleting destructor)
 */
moho::WEmitterEditor::~WEmitterEditor()
{
  gOpenEditors.erase(std::remove(gOpenEditors.begin(), gOpenEditors.end(), this), gOpenEditors.end());
  mCurvePanels.clear();

  if (mPreviewEffect.GetObjectPtr() != nullptr && mSim != nullptr) {
    mSim->mEffectManager->DestroyEffect(mPreviewEffect.GetObjectPtr());
  }
  // Engine change: retail calls the driver unconditionally (0x00666FD0 reads 0x010C4F50 and calls slot +0x94). A
  // window still open when the game ends outlives the sim driver, and that read of a null driver crashed at exit
  // (coverage campaign run 2026-11-12, EFX_CreateEmitterWindow then ExitApplication). With no driver there is no
  // interlock left to release.
  if (ISTIDriver* const driver = WLD_GetDriver()) {
    driver->ReleaseInterlockRef();
  }
}

void moho::WEmitterEditor::DestroyAll()
{
  while (!gOpenEditors.empty()) {
    delete gOpenEditors.back(); // the destructor takes it off the list
  }
}

/**
 * Address: 0x006671C0 (FUN_006671C0)
 */
const char* moho::WEmitterEditor::BlueprintNameOrNull() const
{
  return mBlueprintName.empty() ? nullptr : mBlueprintName.c_str();
}

bool& moho::WEmitterEditor::MenuCheck(
  const std::int32_t commandId
)
{
  return mMenuChecks[static_cast<std::size_t>(commandId - kMenuLocalVelocity)];
}

/**
 * Address: 0x006671F0 (FUN_006671F0)
 */
void moho::WEmitterEditor::ApplyTextFieldParam(
  const char* const field,
  const std::int32_t parameter
)
{
  mPreviewEffect.GetObjectPtr()->SetFloatParam(parameter, static_cast<float>(ParseNumber(field)));
}

/**
 * Address: 0x00667290 (FUN_00667290)
 */
void moho::WEmitterEditor::ApplyMenuFlagParam(
  const std::int32_t commandId,
  const std::int32_t parameter
)
{
  mPreviewEffect.GetObjectPtr()->SetFloatParam(parameter, MenuCheck(commandId) ? 1.0f : 0.0f);
}

/**
 * Address: 0x006672F0 (FUN_006672F0)
 *
 * What it does:
 * A dead effect is recreated from the loaded blueprint, attached to the unit when there is one,
 * and the cached repeat time is reset to -1 so the time axes are pushed again. The repeat time
 * only goes out when it changed and is above 0.001; the time slider's range follows it.
 */
void moho::WEmitterEditor::RefreshPreviewEmitter()
{
  if (!mControlsBuilt || mRefreshGuard || mSim == nullptr) {
    return;
  }

  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    IEffect* effect;
    if (mAttachedUnit.GetObjectPtr() != nullptr) {
      const int bone = mAttachedUnit.GetObjectPtr()->ResolveBoneIndex(mBoneName.c_str());
      effect =
        mSim->mEffectManager->CreateAttachedEmitter(mAttachedUnit.GetObjectPtr(), bone, BlueprintNameOrNull(), -1);
    } else {
      effect = mSim->mEffectManager->CreateEmitter(mSpawnPosition, BlueprintNameOrNull(), -1);
    }
    mPreviewEffect.Set(effect);
    mCachedRepeatTime = -1.0;
    if (mPreviewEffect.GetObjectPtr() == nullptr) {
      return;
    }
  }

  mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_BLENDMODE, static_cast<float>(mBlendModeSelection));

  ApplyMenuFlagParam(kMenuLocalVelocity, EFFECT_USE_LOCAL_VELOCITY);
  ApplyMenuFlagParam(kMenuLocalAcceleration, EFFECT_USE_LOCAL_ACCELERATION);
  ApplyMenuFlagParam(kMenuGravity, EFFECT_USE_GRAVITY);
  ApplyMenuFlagParam(kMenuAlignRotation, EFFECT_ALIGN_ROTATION);
  ApplyMenuFlagParam(kMenuInterpolateEmission, EFFECT_INTERPOLATE_EMISSION);
  ApplyMenuFlagParam(kMenuAlignToBone, EFFECT_ALIGN_TO_BONE);
  ApplyMenuFlagParam(kMenuFlat, EFFECT_FLAT);
  ApplyMenuFlagParam(kMenuSnapToWaterline, EFFECT_SNAPTOWATERLINE);
  ApplyMenuFlagParam(kMenuOnlyEmitOnWater, EFFECT_ONLYEMITONWATER);
  ApplyMenuFlagParam(kMenuParticleResistance, EFFECT_PARTICLERESISTANCE);
  ApplyMenuFlagParam(kMenuEmitIfVisible, EFFECT_EMITIFVISIBLE);
  ApplyMenuFlagParam(kMenuCatchupEmit, EFFECT_CATCHUPEMIT);
  ApplyMenuFlagParam(kMenuCreateIfVisible, EFFECT_CREATEIFVISIBLE);

  const double repeatTime = ParseNumber(mRepeatTimeText.data());
  if (repeatTime != mCachedRepeatTime && repeatTime > 0.001) {
    mCachedRepeatTime = repeatTime;
    for (const std::unique_ptr<WCurveEditorPanel>& panel : mCurvePanels) {
      panel->mCurveEditor->ResetCurveXRange(static_cast<float>(mCachedRepeatTime));
    }
    mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_REPEATTIME, static_cast<float>(mCachedRepeatTime));
    mTimeSliderMax = static_cast<int>(mCachedRepeatTime);
    mTimeSliderValue = static_cast<int>(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT));
  }

  ApplyTextFieldParam(mLifetimeText.data(), EFFECT_LIFETIME);
  ApplyTextFieldParam(mTextureFrameCountText.data(), EFFECT_FRAMECOUNT);
  ApplyTextFieldParam(mSortOrderText.data(), EFFECT_SORTORDER);
  ApplyTextFieldParam(mLodCutoffText.data(), EFFECT_LODCUTOFF);
  ApplyTextFieldParam(mTextureStripCountText.data(), EFFECT_TEXTURE_STRIPCOUNT);

  for (std::size_t i = 0; i < mCurvePanels.size(); ++i) {
    WCurveEditor& editor = *mCurvePanels[i]->mCurveEditor;
    editor.mCurveDirty = false;
    mPreviewEffect.GetObjectPtr()->SetCurveParam(static_cast<std::int32_t>(i), &editor.mCurve);
  }

  // Slot 4 takes the texture paths: 0 the particle texture, 1 the ramp.
  mPreviewEffect.GetObjectPtr()->OnInit(0, mTexturePath.c_str());
  mPreviewEffect.GetObjectPtr()->OnInit(1, mRampTexturePath.c_str());
}

/**
 * Address: 0x00667860 (FUN_00667860)
 *
 * What it does:
 * Reads back, in order: both texture paths (into the labels), every curve, the blend mode, the
 * fidelity from the loaded blueprint's High/Med/Low flags (selection = mask - 1, bit 2 High ..
 * bit 0 Low), the repeat time (field and slider range), the current tick, the four remaining
 * numeric fields, and the thirteen flags into their menu check items.
 */
void moho::WEmitterEditor::LoadFromEffect()
{
  IEffect* const effect = mPreviewEffect.GetObjectPtr();
  if (effect == nullptr) {
    return;
  }

  mRefreshGuard = true;

  mTexturePath = *effect->GetStringParam(0);
  mRampTexturePath = *effect->GetStringParam(1);

  for (std::size_t i = 0; i < mCurvePanels.size(); ++i) {
    mCurvePanels[i]->mCurveEditor->AssignCurve(*effect->GetCurveParam(static_cast<std::int32_t>(i)));
  }

  mBlendModeSelection = static_cast<int>(effect->GetFloatParam(EFFECT_BLENDMODE));

  {
    RResId blueprintId;
    gpg::STR_SetFilename(&blueprintId.name, BlueprintNameOrNull());
    if (const REffectBlueprint* const blueprint = mSim->mRules->GetEffectBlueprint(blueprintId)) {
      const int fidelity = ((blueprint->HighFidelity * 2 | blueprint->MedFidelity) * 2 | blueprint->LowFidelity);
      mFidelitySelection = fidelity - 1;
    }
  }

  FormatInto(mRepeatTimeText, "%.2f", effect->GetFloatParam(EFFECT_REPEATTIME));
  mTimeSliderMax = static_cast<int>(effect->GetFloatParam(EFFECT_REPEATTIME));
  mTimeSliderValue = static_cast<int>(effect->GetFloatParam(EFFECT_TICKCOUNT));
  FormatInto(mLifetimeText, "%.2f", effect->GetFloatParam(EFFECT_LIFETIME));
  FormatInto(mTextureFrameCountText, "%.2f", effect->GetFloatParam(EFFECT_FRAMECOUNT));
  FormatInto(mTextureStripCountText, "%.2f", effect->GetFloatParam(EFFECT_TEXTURE_STRIPCOUNT));
  FormatInto(mSortOrderText, "%.2f", effect->GetFloatParam(EFFECT_SORTORDER));
  FormatInto(mLodCutoffText, "%.2f", effect->GetFloatParam(EFFECT_LODCUTOFF));

  const auto flag = [effect](const EEmitterParam parameter) {
    return effect->GetFloatParam(parameter) > 0.0f;
  };
  MenuCheck(kMenuLocalVelocity) = flag(EFFECT_USE_LOCAL_VELOCITY);
  MenuCheck(kMenuLocalAcceleration) = flag(EFFECT_USE_LOCAL_ACCELERATION);
  MenuCheck(kMenuGravity) = flag(EFFECT_USE_GRAVITY);
  MenuCheck(kMenuAlignRotation) = flag(EFFECT_ALIGN_ROTATION);
  MenuCheck(kMenuInterpolateEmission) = flag(EFFECT_INTERPOLATE_EMISSION);
  MenuCheck(kMenuAlignToBone) = flag(EFFECT_ALIGN_TO_BONE);
  MenuCheck(kMenuFlat) = flag(EFFECT_FLAT);
  MenuCheck(kMenuSnapToWaterline) = flag(EFFECT_SNAPTOWATERLINE);
  MenuCheck(kMenuOnlyEmitOnWater) = flag(EFFECT_ONLYEMITONWATER);
  MenuCheck(kMenuParticleResistance) = flag(EFFECT_PARTICLERESISTANCE);
  MenuCheck(kMenuEmitIfVisible) = flag(EFFECT_EMITIFVISIBLE);
  MenuCheck(kMenuCatchupEmit) = flag(EFFECT_CATCHUPEMIT);
  MenuCheck(kMenuCreateIfVisible) = flag(EFFECT_CREATEIFVISIBLE);

  mRefreshGuard = false;
}

/**
 * Address: 0x00668180 (FUN_00668180)
 */
void moho::WEmitterEditor::OnSettingChanged()
{
  for (const std::unique_ptr<WCurveEditorPanel>& panel : mCurvePanels) {
    panel->RefreshFieldsFromCurve();
  }
  RefreshPreviewEmitter();
}

/**
 * Address: 0x006681D0 (FUN_006681D0)
 */
void moho::WEmitterEditor::OnPlayingToggled()
{
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    return;
  }
  mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_TICKINCREMENT, mPlaying ? 1.0f : 0.0f);
}

/**
 * Address: 0x00668240 (FUN_00668240)
 */
void moho::WEmitterEditor::OnTimeSliderTrack()
{
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    return;
  }
  mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_TICKCOUNT, static_cast<float>(mTimeSliderValue));
}

/**
 * Address: 0x00668290 (FUN_00668290)
 *
 * What it does:
 * wx asked for it whenever the window was idle (EVT_UPDATE_UI); Draw calls it every frame the
 * slider isn't held.
 */
void moho::WEmitterEditor::OnTimeSliderUpdateUI()
{
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    return;
  }

  int tick =
    static_cast<int>(fa::fmod(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT), mCachedRepeatTime));
  if (mCachedRepeatTime >= mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT)) {
    tick = static_cast<int>(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT));
  }
  mTimeSliderValue = tick;
}

/**
 * Address: 0x00668340 (FUN_00668340)
 *
 * What it does:
 * Refreshes the preview first, then writes through a gpg::TextWriter over DISK_OpenFileWrite.
 * The fidelity lines come from the combo box: selection + 1 is the Low|Med|High mask. A missing
 * effect only warns; a file that cannot be opened is skipped silently.
 */
void moho::WEmitterEditor::WriteBlueprintScript(
  const fa::string& path,
  const fa::string& blueprintId
)
{
  RefreshPreviewEmitter();
  IEffect* const effect = mPreviewEffect.GetObjectPtr();
  if (effect == nullptr) {
    gpg::Warnf("Invalid effect. Skip saving blueprint!");
    return;
  }

  fa::auto_ptr<gpg::Stream> file = DISK_OpenFileWrite(path.c_str());
  if (file.get() == nullptr) {
    return;
  }

  const auto flag = [effect](const EEmitterParam parameter) {
    return BoolString(effect->GetFloatParam(parameter) > 0.0f);
  };

  gpg::TextWriter writer(file.get(), 2);
  writer.Printf("EmitterBlueprint {\n");
  writer.Printf("\tBlueprintId = '%s',\n", blueprintId.c_str());
  writer.Printf("\tLifetime = %.2f,\n", effect->GetFloatParam(EFFECT_LIFETIME));
  writer.Printf("\tRepeattime = %.2f,\n", effect->GetFloatParam(EFFECT_REPEATTIME));
  writer.Printf("\tTextureFramecount = %.2f,\n", effect->GetFloatParam(EFFECT_FRAMECOUNT));
  writer.Printf("\tBlendmode = %.2f,\n", effect->GetFloatParam(EFFECT_BLENDMODE));
  writer.Printf("\tLocalVelocity = %s,\n", flag(EFFECT_USE_LOCAL_VELOCITY));
  writer.Printf("\tLocalAcceleration = %s,\n", flag(EFFECT_USE_LOCAL_ACCELERATION));
  writer.Printf("\tGravity = %s,\n", flag(EFFECT_USE_GRAVITY));
  writer.Printf("\tAlignRotation = %s,\n", flag(EFFECT_ALIGN_ROTATION));
  writer.Printf("\tAlignToBone = %s,\n", flag(EFFECT_ALIGN_TO_BONE));
  writer.Printf("\tFlat = %s,\n", flag(EFFECT_FLAT));
  writer.Printf("\tLODCutoff = %.2f,\n", effect->GetFloatParam(EFFECT_LODCUTOFF));
  writer.Printf("\tEmitIfVisible = %s,\n", flag(EFFECT_EMITIFVISIBLE));
  writer.Printf("\tCatchupEmit = %s,\n", flag(EFFECT_CATCHUPEMIT));
  writer.Printf("\tCreateIfVisible = %s,\n", flag(EFFECT_CREATEIFVISIBLE));
  writer.Printf("\tSnapToWaterline = %s,\n", flag(EFFECT_SNAPTOWATERLINE));
  writer.Printf("\tOnlyEmitOnWater = %s,\n", flag(EFFECT_ONLYEMITONWATER));
  writer.Printf("\tParticleResistance = %s,\n", flag(EFFECT_PARTICLERESISTANCE));
  writer.Printf("\tInterpolateEmission = %s,\n", flag(EFFECT_INTERPOLATE_EMISSION));
  writer.Printf("\tTextureStripcount = %.2f,\n", effect->GetFloatParam(EFFECT_TEXTURE_STRIPCOUNT));
  writer.Printf("\tSortOrder = %.2f,\n", effect->GetFloatParam(EFFECT_SORTORDER));

  const int fidelity = mFidelitySelection + 1;
  writer.Printf("\tLowFidelity = %s,\n", BoolString((fidelity & 1) != 0));
  writer.Printf("\tMedFidelity = %s,\n", BoolString((fidelity & 2) != 0));
  writer.Printf("\tHighFidelity = %s,\n", BoolString((fidelity & 4) != 0));

  writer.Printf("\tTexture = [[%s]],\n", mTexturePath.c_str());
  writer.Printf("\tRampTexture = [[%s]],\n", mRampTexturePath.c_str());

  for (const std::unique_ptr<WCurveEditorPanel>& panel : mCurvePanels) {
    panel->mCurveEditor->WriteCurveScript(writer);
  }

  writer.Printf("}\n\n");
  file->VirtClose(gpg::Stream::ModeBoth);
}

/**
 * The file dialogs of 0x00668B00 (wxFileDialog in the binary, modal) are SDL3's, which answer
 * through a callback, possibly on another thread; the answer waits in `mPendingPick` for Tick.
 * One dialog at a time, as a modal one was.
 */
void moho::WEmitterEditor::ShowFileDialog(
  const FilePick purpose,
  const char* const title,
  const char* const defaultDirectory,
  const bool save
)
{
  if (mPickInFlight != FilePick::None) {
    return;
  }

  static const SDL_DialogFileFilter kBlueprintFilter[] = {{"Emitter blueprint (*.bp)", "bp"}};
  static const SDL_DialogFileFilter kTextureFilter[] = {{"Texture (*.dds)", "dds"}};
  const bool blueprint = purpose == FilePick::OpenBlueprint || purpose == FilePick::SaveBlueprint;

  {
    std::lock_guard<std::mutex> guard(mPendingPick->lock);
    mPendingPick->answered = false;
    mPendingPick->path = "";
  }
  mPickInFlight = purpose;

  // The callback keeps the answer's slot alive even if the editor closes first.
  auto* const holder = new std::shared_ptr<PendingPick>(mPendingPick);
  const SDL_DialogFileCallback callback =
    [](void* const userdata, const char* const* const fileList, const int filter) {
    (void)filter;
    auto* const slot = static_cast<std::shared_ptr<PendingPick>*>(userdata);
    {
      std::lock_guard<std::mutex> guard((*slot)->lock);
      (*slot)->path = (fileList != nullptr && fileList[0] != nullptr) ? fileList[0] : "";
      (*slot)->answered = true;
    }
    delete slot;
  };

  const SDL_PropertiesID properties = SDL_CreateProperties();
  (void)SDL_SetPointerProperty(
    properties,
    SDL_PROP_FILE_DIALOG_FILTERS_POINTER,
    const_cast<SDL_DialogFileFilter*>(blueprint ? kBlueprintFilter : kTextureFilter)
  );
  (void)SDL_SetNumberProperty(properties, SDL_PROP_FILE_DIALOG_NFILTERS_NUMBER, 1);
  (void)SDL_SetStringProperty(properties, SDL_PROP_FILE_DIALOG_TITLE_STRING, title);
  if (defaultDirectory != nullptr && *defaultDirectory != '\0') {
    (void)SDL_SetStringProperty(properties, SDL_PROP_FILE_DIALOG_LOCATION_STRING, defaultDirectory);
  }
  (void)SDL_SetBooleanProperty(properties, SDL_PROP_FILE_DIALOG_MANY_BOOLEAN, false);
  SDL_ShowFileDialogWithProperties(
    save ? SDL_FILEDIALOG_SAVEFILE : SDL_FILEDIALOG_OPENFILE, callback, holder, properties
  );
  SDL_DestroyProperties(properties);
}

/**
 * Address: 0x00668B00 (FUN_00668B00)
 *
 * What it does:
 * Open Blueprint, Save (when no file is remembered) and the texture entries open a file
 * dialog; OnFileChosen carries each on with the answer. Save with a remembered file writes at
 * once; Save As forgets the file and falls into Save. The check items refresh the preview,
 * except Enable Particle Resistance (685), which the binary's menu range (666..684) left out.
 * New (667) does nothing, as in the binary.
 */
void moho::WEmitterEditor::OnMenuCommand(
  const std::int32_t command
)
{
  switch (command) {
  case kMenuOpen: {
    fa::string emittersRoot;
    (void)DISK_GetVFS()->FindFile(&emittersRoot, "/effects/Emitters", nullptr);
    mBlueprintDirectory = emittersRoot;
    ShowFileDialog(FilePick::OpenBlueprint, "Select Blueprint", mBlueprintDirectory.c_str(), false);
    return;
  }

  case kMenuSaveAs:
    mBlueprintPath = "";
    mBlueprintFileName = "";
    [[fallthrough]];

  case kMenuSave: {
    if (mBlueprintFileName.empty()) {
      fa::string emittersRoot;
      (void)DISK_GetVFS()->FindFile(&emittersRoot, "/effects/Emitters", nullptr);
      mBlueprintDirectory = emittersRoot;
      ShowFileDialog(FilePick::SaveBlueprint, "Choose a file to save as.", mBlueprintDirectory.c_str(), true);
      return;
    }
    WriteBlueprintScript(mBlueprintPath, BeforeLastUnderscore(mBlueprintFileName));
    SetTitle(mBlueprintPath.c_str());
    return;
  }

  case kMenuOpenTexture:
  case kMenuOpenRamp: {
    fa::string texturesRoot;
    (void)DISK_GetVFS()->FindFile(&texturesRoot, "/textures/particles", nullptr);
    mTextureDirectory = texturesRoot;
    const bool ramp = command == kMenuOpenRamp;
    ShowFileDialog(
      ramp ? FilePick::OpenRamp : FilePick::OpenTexture,
      ramp ? "Select Ramp Texture" : "Select Particle Texture",
      mTextureDirectory.c_str(),
      false
    );
    return;
  }

  case kMenuLocalVelocity:
  case kMenuLocalAcceleration:
  case kMenuGravity:
  case kMenuAlignRotation:
  case kMenuInterpolateEmission:
  case kMenuAlignToBone:
  case kMenuFlat:
  case kMenuEmitIfVisible:
  case kMenuCatchupEmit:
  case kMenuCreateIfVisible:
  case kMenuSnapToWaterline:
  case kMenuOnlyEmitOnWater:
    RefreshPreviewEmitter();
    return;

  default:
    return;
  }
}

/**
 * Address: 0x00668B00 (FUN_00668B00), each command's half after its file dialog
 *
 * What it does:
 * Open Blueprint remembers the directory, file name and path, rejects names that are not *.bp,
 * converts the path to a VFS name and asks the rules for that effect blueprint: an emitter
 * replaces the preview (the old effect is destroyed through its manager, the editor reloads from
 * the new one and the path becomes the title); beams and trails are refused with a warning, as
 * is a name the rules do not know. On any failure the previous effect is put back - and the
 * path, except that the copy it restores was taken after the new path was stored, so the new
 * path stays.
 *
 * Save remembers the chosen file; a name that is not *.bp is reported and cleared, and the
 * write still runs (DISK_OpenFileWrite then fails on the empty path). The texture and ramp
 * entries convert the chosen file to a VFS path, show it and refresh.
 *
 * A cancelled dialog does nothing, as `ShowModal() != wxID_OK` returned.
 */
void moho::WEmitterEditor::OnFileChosen(
  const FilePick purpose,
  const fa::string& path
)
{
  if (path.empty()) {
    return;
  }

  switch (purpose) {
  case FilePick::OpenBlueprint: {
    if (mSim == nullptr) {
      return;
    }
    SplitPath(path, mBlueprintDirectory, mBlueprintFileName);
    if (!EndsWithBlueprintExtension(mBlueprintFileName)) {
      (void)SDL_ShowSimpleMessageBox(
        SDL_MESSAGEBOX_INFORMATION, "Bad name!", "You didn't open a valid blueprint", nullptr
      );
      return;
    }

    mBlueprintPath = path;

    IEffect* const previousEffect = mPreviewEffect.GetObjectPtr();
    const fa::string previousPath = mBlueprintPath;
    mPreviewEffect.Set(nullptr);

    {
      fa::string mountedPath;
      (void)DISK_GetVFS()->ToMountedPath(&mountedPath, mBlueprintPath.c_str());
      mBlueprintName = mountedPath;
    }

    REffectBlueprint* blueprint;
    {
      RResId blueprintId;
      gpg::STR_InitFilename(&blueprintId.name, BlueprintNameOrNull());
      blueprint = mSim->mRules->GetEffectBlueprint(blueprintId);
    }
    if (mAttachedUnit.GetObjectPtr() != nullptr) {
      if (blueprint == nullptr) {
        gpg::Warnf(gpg::STR_Printf("%s: %s", DISK_GetLastError().c_str(), mBlueprintName.c_str()).c_str());
      } else if (blueprint->IsBeam() != nullptr) {
        gpg::Warnf("Sorry, beams are not supported at the moment");
      } else if (blueprint->IsTrail() != nullptr) {
        gpg::Warnf("Sorry, trails are not supported at the moment");
      } else if (blueprint->IsEmitter() != nullptr) {
        const int bone = mAttachedUnit.GetObjectPtr()->ResolveBoneIndex(mBoneName.c_str());
        mPreviewEffect.Set(
          mSim->mEffectManager->CreateAttachedEmitter(mAttachedUnit.GetObjectPtr(), bone, BlueprintNameOrNull(), -1)
        );
      }
    } else {
      if (blueprint == nullptr) {
        gpg::Warnf(gpg::STR_Printf("%s: %s", DISK_GetLastError().c_str(), mBlueprintName.c_str()).c_str());
      } else if (blueprint->IsEmitter() != nullptr) {
        mPreviewEffect.Set(mSim->mEffectManager->CreateEmitter(mSpawnPosition, BlueprintNameOrNull(), -1));
      } else if (blueprint->IsBeam() != nullptr) {
        gpg::Warnf("Sorry, beams are not supported at the moment");
      } else if (blueprint->IsTrail() != nullptr) {
        gpg::Warnf("Sorry, trails are not supported at the moment");
      }
    }

    if (mPreviewEffect.GetObjectPtr() == nullptr) {
      mPreviewEffect.Set(previousEffect);
      mBlueprintPath = previousPath;
      RefreshPreviewEmitter();
    } else {
      if (previousEffect != nullptr) {
        previousEffect->mManager->DestroyEffect(previousEffect);
      }
      LoadFromEffect();
      SetTitle(mBlueprintPath.c_str());
    }
    return;
  }

  case FilePick::SaveBlueprint: {
    SplitPath(path, mBlueprintDirectory, mBlueprintFileName);
    mBlueprintPath = path;
    if (!EndsWithBlueprintExtension(mBlueprintFileName)) {
      mBlueprintFileName = "";
      mBlueprintPath = "";
      (void)SDL_ShowSimpleMessageBox(
        SDL_MESSAGEBOX_INFORMATION, "Bad name!", "Since this is a blueprint you must save as *.bp", nullptr
      );
    }
    WriteBlueprintScript(mBlueprintPath, BeforeLastUnderscore(mBlueprintFileName));
    SetTitle(mBlueprintPath.c_str());
    return;
  }

  case FilePick::OpenTexture:
  case FilePick::OpenRamp: {
    fa::string fileName;
    SplitPath(path, mTextureDirectory, fileName);
    fa::string mountedPath;
    (void)DISK_GetVFS()->ToMountedPath(&mountedPath, path.c_str());
    (purpose == FilePick::OpenRamp ? mRampTexturePath : mTexturePath) = mountedPath;
    RefreshPreviewEmitter();
    return;
  }

  default:
    return;
  }
}

void moho::WEmitterEditor::Tick()
{
  if (mCloseRequested) {
    delete this; // RenderAll checks the window is still open before drawing it
    return;
  }

  if (mPickInFlight == FilePick::None) {
    return;
  }
  fa::string path;
  {
    std::lock_guard<std::mutex> guard(mPendingPick->lock);
    if (!mPendingPick->answered) {
      return;
    }
    mPendingPick->answered = false;
    path = mPendingPick->path;
  }
  const FilePick purpose = mPickInFlight;
  mPickInFlight = FilePick::None;
  OnFileChosen(purpose, path);
}

void moho::WEmitterEditor::OnCloseRequested()
{
  // The binary's frame was destroyed by its close button (0x00666F40 ran); the editor goes at the
  // next Tick, outside the event that asked.
  Show(false);
  mCloseRequested = true;
}

// The binary's accelerator table (0x00663900): Ctrl+N, Ctrl+S, Alt+S, Ctrl+O, Ctrl+T, Ctrl+R.
void moho::WEmitterEditor::HandleShortcuts()
{
  struct Accelerator
  {
    ImGuiKeyChord chord;
    std::int32_t command;
  };
  static const Accelerator kAccelerators[] = {
    {ImGuiMod_Ctrl | ImGuiKey_N, kMenuNew},
    {ImGuiMod_Ctrl | ImGuiKey_S, kMenuSave},
    {ImGuiMod_Alt | ImGuiKey_S, kMenuSaveAs},
    {ImGuiMod_Ctrl | ImGuiKey_O, kMenuOpen},
    {ImGuiMod_Ctrl | ImGuiKey_T, kMenuOpenTexture},
    {ImGuiMod_Ctrl | ImGuiKey_R, kMenuOpenRamp},
  };
  for (const Accelerator& accelerator : kAccelerators) {
    if (ImGui::Shortcut(accelerator.chord, ImGuiInputFlags_RouteGlobal)) {
      OnMenuCommand(accelerator.command);
    }
  }
}

// The File, Options and LOD menus (0x00663900 builds them; 0x00668B00 handles them).
void moho::WEmitterEditor::DrawMenuBar()
{
  if (!ImGui::BeginMenuBar()) {
    return;
  }
  if (ImGui::BeginMenu("File")) {
    if (ImGui::MenuItem("New", "Ctrl+N")) {
      OnMenuCommand(kMenuNew);
    }
    if (ImGui::MenuItem("Open Blueprint", "Ctrl+O")) {
      OnMenuCommand(kMenuOpen);
    }
    if (ImGui::MenuItem("Save Blueprint", "Ctrl+S")) {
      OnMenuCommand(kMenuSave);
    }
    if (ImGui::MenuItem("Save Blueprint As..", "Alt+S")) {
      OnMenuCommand(kMenuSaveAs);
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Open Texture", "Ctrl+T")) {
      OnMenuCommand(kMenuOpenTexture);
    }
    if (ImGui::MenuItem("Open Ramp", "Ctrl+R")) {
      OnMenuCommand(kMenuOpenRamp);
    }
    ImGui::EndMenu();
  }

  // A check item toggles itself, then the command runs (0x00668B00 found it toggled).
  const auto checkItem = [this](const char* const label, const std::int32_t command) {
    if (ImGui::MenuItem(label, nullptr, &MenuCheck(command))) {
      OnMenuCommand(command);
    }
  };
  if (ImGui::BeginMenu("Options")) {
    checkItem("Use Local Velocity", kMenuLocalVelocity);
    checkItem("Use Local Acceleration", kMenuLocalAcceleration);
    checkItem("Gravity", kMenuGravity);
    checkItem("Lock Particles to Velocity", kMenuAlignRotation);
    checkItem("Interpolate Emitter Position", kMenuInterpolateEmission);
    checkItem("Align Initial Rotation To Bone", kMenuAlignToBone);
    checkItem("Particles are flat in world space", kMenuFlat);
    checkItem("Snap To Waterline", kMenuSnapToWaterline);
    checkItem("Only Emit On Water", kMenuOnlyEmitOnWater);
    checkItem("Enable Particle Resistance", kMenuParticleResistance);
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("LOD")) {
    checkItem("Only Emit If Visible", kMenuEmitIfVisible);
    checkItem("Catch up when Visible", kMenuCatchupEmit);
    checkItem("Only Create if Visible", kMenuCreateIfVisible);
    ImGui::EndMenu();
  }
  ImGui::EndMenuBar();
}

/**
 * The controls of 0x00663900 and the frame's event table (rows 0x00F59DF8): the Life Time,
 * Repeat Time, Frame Count and LOD Cutoff fields and both combo boxes refresh on every change
 * (EVT_TEXT, EVT_COMBOBOX); Strip Count and Sort Order are read at the next refresh, as the
 * table has no row for them; Playing toggles the tick increment; dragging the slider scrubs.
 */
void moho::WEmitterEditor::Draw()
{
  if (!ImGui::BeginChild("##emitter", ImVec2(0.0f, 0.0f), 0, ImGuiWindowFlags_MenuBar)) {
    ImGui::EndChild();
    return;
  }
  DrawMenuBar();
  HandleShortcuts();

  const auto field = [](const char* const label, const char* const id, char* const buffer, const std::size_t size) {
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(label);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(70.0f);
    return ImGui::InputText(id, buffer, size);
  };

  // The top row.
  bool changed = field("Life Time", "##lifetime", mLifetimeText.data(), mLifetimeText.size());
  ImGui::SameLine();
  changed |= field("Repeat Time", "##repeattime", mRepeatTimeText.data(), mRepeatTimeText.size());
  ImGui::SameLine();
  ImGui::TextUnformatted("Blend Mode");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(150.0f);
  changed |= ImGui::Combo("##blendmode", &mBlendModeSelection, kBlendModes, IM_ARRAYSIZE(kBlendModes));
  ImGui::SameLine();
  ImGui::TextUnformatted("Fidelity");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(130.0f);
  changed |= ImGui::Combo("##fidelity", &mFidelitySelection, kFidelities, IM_ARRAYSIZE(kFidelities));
  ImGui::SameLine();
  ImGui::Text("Texture: %s", mTexturePath.c_str());

  // The bottom row.
  changed |= field("Frame Count", "##framecount", mTextureFrameCountText.data(), mTextureFrameCountText.size());
  ImGui::SameLine();
  (void)field("Strip Count", "##stripcount", mTextureStripCountText.data(), mTextureStripCountText.size());
  ImGui::SameLine();
  (void)field("Sort Order", "##sortorder", mSortOrderText.data(), mSortOrderText.size());
  ImGui::SameLine();
  changed |= field("LOD Cutoff Distance", "##lodcutoff", mLodCutoffText.data(), mLodCutoffText.size());
  ImGui::SameLine();
  if (ImGui::Checkbox("Playing", &mPlaying)) {
    OnPlayingToggled();
  }
  ImGui::SameLine();
  ImGui::Text("Ramp: %s", mRampTexturePath.c_str());

  if (changed) {
    OnSettingChanged();
  }

  // The time slider (0x00668240, 0x00668290): 0..repeat time, with its value shown.
  ImGui::SetNextItemWidth(-1.0f);
  if (ImGui::SliderInt("##time", &mTimeSliderValue, 0, std::max(mTimeSliderMax, 0))) {
    OnTimeSliderTrack();
  }
  if (!ImGui::IsItemActive()) {
    OnTimeSliderUpdateUI();
  }

  // The curve tabs: each group of curves shares a tab, the first curve of a group opens it.
  if (ImGui::BeginTabBar("##curves")) {
    int curve = 0;
    while (curve < static_cast<int>(mCurvePanels.size())) {
      int groupEnd = curve + 1;
      while (groupEnd < static_cast<int>(mCurvePanels.size()) && !OpensCurveTab(groupEnd)) {
        ++groupEnd;
      }
      if (ImGui::BeginTabItem(kEmitterCurveEditors[curve].mTabTitle)) {
        const float available = ImGui::GetContentRegionAvail().y;
        const int count = groupEnd - curve;
        const float panelHeight =
          std::max(120.0f, (available - ImGui::GetStyle().ItemSpacing.y * static_cast<float>(count - 1)) / count);
        if (ImGui::BeginChild("##tab", ImVec2(0.0f, 0.0f))) {
          for (int index = curve; index < groupEnd; ++index) {
            mCurvePanels[static_cast<std::size_t>(index)]->Draw(index, panelHeight);
          }
        }
        ImGui::EndChild();
        ImGui::EndTabItem();
      }
      curve = groupEnd;
    }
    ImGui::EndTabBar();
  }

  ImGui::EndChild();
}
