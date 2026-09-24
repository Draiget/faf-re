#include "moho/app/WEmitterWx.h"

#include <cmath>
#include <string>

#include "platform/WxWidgets.h"
#include <wx/accel.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/notebook.h>
#include <wx/sizer.h>
#include <wx/slider.h>

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
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

namespace
{
  // Window ids; the frame's event table (rows 0x00F59DF8) routes them.
  constexpr int kLifetimeFieldId = 556;
  constexpr int kRepeatTimeFieldId = 557;
  constexpr int kEffectChoiceId = 558; // both combo boxes
  constexpr int kFrameCountFieldId = 559;
  constexpr int kStripCountFieldId = 560;
  constexpr int kPlayingCheckBoxId = 561;
  constexpr int kTimeSliderId = 562;
  constexpr int kSortOrderFieldId = 563;
  constexpr int kLodCutoffFieldId = 565;
  constexpr int kFirstCurveEditorId = 605; // + EEmitterCurve, so 605..625

  // The curve panels' numeric fields; FUN_00663650 compares [event+0x14]
  // against 0x26E..0x272.
  constexpr int kKeyTimeFieldId = 622;
  constexpr int kKeyValueFieldId = 623;
  constexpr int kKeyTangentFieldId = 624;
  constexpr int kViewValueMinFieldId = 625;
  constexpr int kViewValueMaxFieldId = 626;

  enum EEmitterMenuId
  {
    ID_EMITTER_NEW = 667,
    ID_EMITTER_OPEN = 668,
    ID_EMITTER_SAVE = 669,
    ID_EMITTER_OPEN_TEXTURE = 670,
    ID_EMITTER_OPEN_RAMP = 671,
    ID_EMITTER_LOCAL_VELOCITY = 672,
    ID_EMITTER_LOCAL_ACCELERATION = 673,
    ID_EMITTER_GRAVITY = 674,
    ID_EMITTER_ALIGN_ROTATION = 675,
    ID_EMITTER_INTERPOLATE_EMISSION = 676,
    ID_EMITTER_ALIGN_TO_BONE = 677,
    ID_EMITTER_FLAT = 678,
    ID_EMITTER_SAVE_AS = 679,
    ID_EMITTER_EMIT_IF_VISIBLE = 680,
    ID_EMITTER_CATCHUP_EMIT = 681,
    ID_EMITTER_CREATE_IF_VISIBLE = 682,
    ID_EMITTER_SNAP_TO_WATERLINE = 683,
    ID_EMITTER_ONLY_EMIT_ON_WATER = 684,
    ID_EMITTER_PARTICLE_RESISTANCE = 685,
  };

  // wxALIGN_CENTRE_HORIZONTAL | wxLEFT (0x110), pushed for every field label.
  constexpr long kFieldLabelStyle = wxALIGN_CENTRE_HORIZONTAL | wxLEFT;

  /** Smallest visible value span the curve editor will zoom down to (0x00E4F714). */
  constexpr float kMinimumVisibleValueSpan = 0.1f;

  /** Side of the square grab handle drawn per key by FUN_00662180. */
  constexpr int kCurveKeyHandleSize = 5;

  /** Drag buttons stored in WCurveEditor::mActiveDragButton. */
  constexpr int kCurveDragNone = 0;
  constexpr int kCurveDragKey = 1;
  constexpr int kCurveDragTangent = 2;

  /**
   * One row of the curve notebook, read from .rdata at 0x00E24F00 by the
   * WEmitterWx constructor's loop (0x00666BF7-0x00666EE7, stride 0x1C): the
   * key the curve is saved under, the title of the notebook tab it opens
   * (empty for curves that join the previous tab), its caption, then the view
   * range and first key its WCurveEditorPanel is built with.
   */
  struct SEmitterCurveEditorDesc
  {
    const wxChar* mScriptName;
    const wxChar* mTabTitle;
    const wxChar* mCaption;
    float mViewValueMin;
    float mViewValueMax;
    float mInitialKeyValue;
    float mInitialKeyTangent;
  };
  static_assert(sizeof(SEmitterCurveEditorDesc) == 0x1C, "SEmitterCurveEditorDesc size must be 0x1C");

  const SEmitterCurveEditorDesc kEmitterCurveEditors[moho::EMITTER_LAST_CURVE] = {
    {wxT("XDirectionCurve"), wxT("Direction, Rate, Lifetime"), wxT("X Direction"), -1.0f, 1.0f, 0.0f, 0.0f},
    {wxT("YDirectionCurve"), wxT(""), wxT("Y Direction"), -1.0f, 1.0f, 0.5f, 0.0f},
    {wxT("ZDirectionCurve"), wxT(""), wxT("Z Direction"), -1.0f, 1.0f, 0.0f, 0.0f},
    {wxT("EmitRateCurve"), wxT(""), wxT("Emit Rate"), -0.5f, 30.0f, 1.0f, 0.0f},
    {wxT("LifetimeCurve"), wxT(""), wxT("Lifetime"), 0.0f, 30.0f, 10.0f, 0.0f},
    {wxT("VelocityCurve"), wxT("Forces"), wxT("Velocity"), 0.0f, 5.0f, 1.0f, 0.0f},
    {wxT("XAccelCurve"), wxT(""), wxT("X Acceleration"), -0.5f, 0.5f, 0.0f, 0.0f},
    {wxT("YAccelCurve"), wxT(""), wxT("Y Acceleration"), -0.5f, 0.5f, 0.0f, 0.0f},
    {wxT("ZAccelCurve"), wxT(""), wxT("Z Acceleration"), -0.5f, 0.5f, 0.0f, 0.0f},
    {wxT("ResistanceCurve"), wxT(""), wxT("Resistance"), 0.0f, 1.0f, 0.0f, 0.0f},
    {wxT("SizeCurve"), wxT("Spacial"), wxT("Emitter Size"), 0.0f, 5.0f, 0.0f, 0.0f},
    {wxT("XPosCurve"), wxT(""), wxT("X Position"), -5.0f, 5.0f, 0.0f, 0.0f},
    {wxT("YPosCurve"), wxT(""), wxT("Y Position"), -5.0f, 5.0f, 0.0f, 0.0f},
    {wxT("ZPosCurve"), wxT(""), wxT("Z Position"), -5.0f, 5.0f, 0.0f, 0.0f},
    {wxT("StartSizeCurve"), wxT("Size and Rotation"), wxT("Particle Start Size"), 0.0f, 2.0f, 1.0f, 0.0f},
    {wxT("EndSizeCurve"), wxT(""), wxT("Particle End Size"), 0.0f, 2.0f, 1.0f, 0.1f},
    {wxT("InitialRotationCurve"), wxT(""), wxT("Particle Rotation"), 0.0f, 360.0f, 180.0f, 360.0f},
    {wxT("RotationRateCurve"), wxT(""), wxT("Particle Rotation Rate"), -90.0f, 90.0f, 0.0f, 10.0f},
    {wxT("FrameRateCurve"), wxT("Animation and Selection"), wxT("Particle Frame Rate"), 0.0f, 5.0f, 1.0f, 0.0f},
    {wxT("TextureSelectionCurve"), wxT(""), wxT("Particle Texture Selection"), 0.0f, 5.0f, 0.0f, 0.0f},
    {wxT("RampSelectionCurve"), wxT(""), wxT("Color/Alpha Ramp Selection"), 0.0f, 1.0f, 0.0f, 0.0f},
  };

  /**
   * Address: 0x006638B0 (FUN_006638B0)
   *
   * What it does:
   * Shrinks a numeric field to a third of its default width. The constructor
   * calls it (window in esi) for each of the six fields before adding it.
   */
  void NarrowToThird(wxWindow* const window)
  {
    int width = 0;
    int height = 0;
    window->GetSize(&width, &height);
    window->SetSize(-1, -1, width / 3, height, wxSIZE_USE_EXISTING);
  }

  const char* BoolString(const bool value)
  {
    return value ? "true" : "false";
  }
} // namespace

// ---------------------------------------------------------------------------
// WCurveEditor

/**
 * Address: 0x00661100 (FUN_00661100)
 *
 * What it does:
 * The binary calls wxControl::ProcessCommand directly (0x0098D5F0), a plain
 * base-class member call.
 */
void moho::WCurveEditor::PostCurveChangedCommand()
{
  mCurveDirty = false;
  wxCommandEvent event(wxEVT_COMMAND_BUTTON_CLICKED, GetId());
  event.SetEventObject(this);
  ProcessCommand(event);
}

/**
 * Address: 0x006612A0 (FUN_006612A0)
 *
 * What it does:
 * The horizontal axis maps time through mViewTimeScale relative to
 * mViewTimeMin; the vertical axis is inverted, measuring up from the bottom
 * of the client area.
 */
wxPoint moho::WCurveEditor::ProjectCurvePointToScreen(
  const std::int32_t edge,
  const CurveEnvelopeColumn& column
) const
{
  wxPoint projected;

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
  const std::int32_t id,
  const float viewTimeMax,
  const float viewValueMin,
  const float viewValueMax,
  const float initialKeyValue,
  const float initialKeyTangent
)
  : wxControl(parent, id)
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

  Show(true);
}

/**
 * Address: 0x00661700 (FUN_00661700)
 */
void moho::WCurveEditor::SetName(const wxString& name)
{
  mCaption = name;
}

/**
 * Address: 0x00661710 (FUN_00661710)
 */
void moho::WCurveEditor::SetScriptName(const wxString& scriptName)
{
  mScriptName = scriptName;
}

/**
 * Address: 0x00661720 (FUN_00661720)
 */
void moho::WCurveEditor::ResetCurveXRange(const float rangeMax)
{
  mViewTimeMin = 0.0f;
  mViewTimeMax = rangeMax;
  RescaleEmitterCurveXRange(&mCurve, 0.0f, rangeMax);
  Refresh();
}

/**
 * Address: 0x006614B0 (FUN_006614B0)
 *
 * What it does:
 * The time is clamped into the visible range and then between the key's
 * neighbours, so moving a key never reorders the curve; the value is clamped
 * into the visible range and the tangent is stored as given. The curve's Y
 * bounds are rederived afterwards.
 */
void moho::WCurveEditor::MoveSelectedKeyTo(const float time, const float value, const float tangent)
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
  Refresh();
}

/**
 * Address: 0x00661580 (FUN_00661580)
 *
 * What it does:
 * The XRange is the curve's upper time bound (`mBoundsMax.x`). The binary
 * passes the writer in the stack slot and `this` in edi.
 */
void moho::WCurveEditor::WriteCurveScript(gpg::TextWriter& writer) const
{
  writer.Printf(
    "\t%s = {\n\t\tXRange = %.2f,\n\t\tKeys = {\n",
    gpg::STR_WideToUtf8(mScriptName.c_str()).c_str(),
    mCurve.mBoundsMax.x
  );
  for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
    writer.Printf("\t\t\t{ x=%.3f,y=%.3f,z=%.3f },\n", key->x, key->y, key->z);
  }
  writer.Printf("\t\t},\n\t},\n");
}

/**
 * Address: 0x006617A0 (FUN_006617A0)
 */
void moho::WCurveEditor::ZoomValueAxisByWheel(wxMouseEvent& event)
{
  const float valueDelta = static_cast<float>(event.m_wheelRotation) / (mViewValueScale * 5.0f) * 0.5f;
  const float zoomedMin = mViewValueMin + valueDelta;
  const float zoomedMax = mViewValueMax - valueDelta;
  if (zoomedMax - zoomedMin < kMinimumVisibleValueSpan) {
    return;
  }

  mViewValueMin = zoomedMin;
  mViewValueMax = zoomedMax;
  Refresh();
}

/**
 * Address: 0x00661820 (FUN_00661820)
 */
void moho::WCurveEditor::OnMouseDown(wxMouseEvent& event)
{
  mLastMouseX = event.m_x;
  mLastMouseY = event.m_y;

  const Wm3::Vector2f point(
    mViewTimeMin + static_cast<float>(mLastMouseX) / mViewTimeScale,
    mViewValueMin + static_cast<float>(mClientHeight - event.m_y) / mViewValueScale
  );
  mSelectedKey = FindNearestCurveKey(mCurve, point);

  if (event.GetEventType() == wxEVT_LEFT_DOWN) {
    mActiveDragButton = kCurveDragKey;
    PostCurveChangedCommand();
  }
  if (event.GetEventType() == wxEVT_MIDDLE_DOWN) {
    mActiveDragButton = kCurveDragTangent;
    PostCurveChangedCommand();
  }

  if (!mMouseCaptured) {
    CaptureMouse();
    mMouseCaptured = true;
  }
  Refresh();
}

/**
 * Address: 0x00661900 (FUN_00661900)
 */
void moho::WCurveEditor::OnMouseMove(wxMouseEvent& event)
{
  const int mouseX = event.m_x;
  const int mouseY = event.m_y;

  // Motion converts pixels to units by multiplying with the reciprocal
  // (0x00DFEC20 is 1.0f), unlike the button handlers, which divide.
  const float valuePerPixel = 1.0f / mViewValueScale;
  const float time = mViewTimeMin + static_cast<float>(mouseX) / mViewTimeScale;
  const float value = mViewValueMin + static_cast<float>(mClientHeight - mouseY) * valuePerPixel;

  if (mActiveDragButton == kCurveDragKey) {
    // The same clamping as MoveSelectedKeyTo, without its no-selection test.
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
    Refresh();
  } else if (mActiveDragButton == kCurveDragTangent) {
    mSelectedKey->z += static_cast<float>(mLastMouseY - mouseY) * valuePerPixel;
    if (0.0f > mSelectedKey->z) {
      mSelectedKey->z = 0.0f;
    }

    PostCurveChangedCommand();
    Refresh();
  }

  mLastMouseY = mouseY;
  mLastMouseX = mouseX;
}

/**
 * Address: 0x00661A50 (FUN_00661A50)
 */
void moho::WCurveEditor::OnMouseUp(wxMouseEvent&)
{
  mActiveDragButton = kCurveDragNone;
  if (mMouseCaptured) {
    ReleaseMouse();
    mMouseCaptured = false;
    PostCurveChangedCommand();
  }
  Refresh();
}

/**
 * Address: 0x00661A90 (FUN_00661A90)
 */
void moho::WCurveEditor::OnCurveKeyEdit(wxMouseEvent& event)
{
  Wm3::Vector3f point;
  point.x = mViewTimeMin + static_cast<float>(event.m_x) / mViewTimeScale;
  point.y = mViewValueMin + static_cast<float>(mClientHeight - event.m_y) / mViewValueScale;

  if (event.m_controlDown) {
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
  Refresh();
}

/**
 * Address: 0x00661B90 (FUN_00661B90)
 *
 * What it does:
 * The span runs between two columns: before the first key, from
 * mViewTimeMin to that key; past the last key (`key` is the end sentinel),
 * from the last key to mViewTimeMax; otherwise from the previous key to this
 * one. Each column contributes its upper edge, curve value and lower edge, and
 * the six points are filled as one polygon.
 *
 * The line over the curve does not always run left to right: the first span
 * draws it from the clamped column to the key, the other two from the later
 * column back to the earlier one. GDI leaves a line's last pixel out, so the
 * direction is kept.
 */
void moho::WCurveEditor::DrawKeyEnvelopeSpan(wxDC& dc, const Wm3::Vector3f* const key) const
{
  wxPoint envelope[6];
  dc.SetPen(*wxRED_PEN);

  const auto fillBand = [&](const CurveEnvelopeColumn& left, const CurveEnvelopeColumn& right) {
    envelope[0] = ProjectCurvePointToScreen(kCurveEnvelopeUpperEdge, left);
    envelope[1] = ProjectCurvePointToScreen(kCurveEnvelopeUpperEdge, right);
    envelope[2] = ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, right);
    envelope[3] = ProjectCurvePointToScreen(kCurveEnvelopeLowerEdge, right);
    envelope[4] = ProjectCurvePointToScreen(kCurveEnvelopeLowerEdge, left);
    envelope[5] = ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, left);
    dc.DrawPolygon(6, envelope, 0, 0, wxWINDING_RULE);
  };

  if (key == mCurve.mKeys.begin()) {
    const CurveEnvelopeColumn start{mViewTimeMin, key->y, key->z};
    const CurveEnvelopeColumn current{key->x, key->y, key->z};
    fillBand(start, current);
    dc.DrawLine(
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, start),
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, current)
    );
  } else if (key == mCurve.mKeys.end()) {
    const Wm3::Vector3f* const last = key - 1;
    const CurveEnvelopeColumn previous{last->x, last->y, last->z};
    const CurveEnvelopeColumn finish{mViewTimeMax, last->y, last->z};
    fillBand(previous, finish);
    dc.DrawLine(
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, finish),
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, previous)
    );
  } else {
    const Wm3::Vector3f* const before = key - 1;
    const CurveEnvelopeColumn previous{before->x, before->y, before->z};
    const CurveEnvelopeColumn current{key->x, key->y, key->z};
    fillBand(previous, current);
    dc.DrawLine(
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, current),
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, previous)
    );
  }
}

/**
 * Address: 0x00662180 (FUN_00662180)
 */
void moho::WCurveEditor::DrawKeyHandle(wxDC& dc, const Wm3::Vector3f* const key) const
{
  if (key == mSelectedKey) {
    dc.SetPen(*wxCYAN_PEN);
  } else {
    dc.SetPen(*wxRED_PEN);
  }

  const wxPoint handle = ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, {key->x, key->y, key->z});
  dc.DrawRectangle(handle.x, handle.y, kCurveKeyHandleSize, kCurveKeyHandleSize);
}

/**
 * Address: 0x006621F0 (FUN_006621F0)
 *
 * What it does:
 * The scales are stored as the spans first and divided in place, which is
 * the order the binary writes them. The four axis labels use the control's
 * own GetTextExtent: time bounds centred on the left and right edges, value
 * bounds centred on the bottom and top edges, and the caption top left.
 */
void moho::WCurveEditor::OnPaint(wxPaintEvent&)
{
  wxPaintDC dc(this);

  int width = 0;
  int height = 0;
  dc.GetSize(&width, &height);
  mClientWidth = width;
  mClientHeight = height;

  mViewTimeScale = mViewTimeMax - mViewTimeMin;
  mViewValueScale = mViewValueMax - mViewValueMin;
  mViewTimeScale = static_cast<float>(width) / mViewTimeScale;
  mViewValueScale = static_cast<float>(height) / mViewValueScale;

  for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
    DrawKeyEnvelopeSpan(dc, key);
  }
  DrawKeyEnvelopeSpan(dc, mCurve.mKeys.end());

  for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
    DrawKeyHandle(dc, key);
  }

  wxString label;
  int textWidth = 0;
  int textHeight = 0;

  label.Printf(wxT("%.1f"), mViewTimeMin);
  GetTextExtent(label, &textWidth, &textHeight);
  dc.DrawText(label, 0, height / 2 - textHeight / 2);

  label.Printf(wxT("%.1f"), mViewTimeMax);
  GetTextExtent(label, &textWidth, &textHeight);
  dc.DrawText(label, width - textWidth, height / 2 - textHeight / 2);

  label.Printf(wxT("%.1f"), mViewValueMin);
  GetTextExtent(label, &textWidth, &textHeight);
  dc.DrawText(label, width / 2 - textWidth / 2, height - textHeight);

  label.Printf(wxT("%.1f"), mViewValueMax);
  GetTextExtent(label, &textWidth, &textHeight);
  dc.DrawText(label, width / 2 - textWidth / 2, 0);

  dc.DrawText(mCaption, 0, 0);
}

/**
 * Address: 0x00662570 (FUN_00662570, nullsub_1719)
 */
void moho::WCurveEditor::IgnoreEvent(wxMouseEvent&)
{
}

/**
 * Address: 0x00669E40 (FUN_00669E40)
 */
void moho::WCurveEditor::AssignCurve(const SEfxCurve& source)
{
  mCurve = source;
  mSelectedKey = mCurve.mKeys.end();
  Refresh();
  PostCurveChangedCommand();
  mOwnerPanel->RefreshFieldsFromCurve();
}

// Table 0x00DFEF70 = {&wxControl::sm_eventTable (0x00D54D70), rows 0x00F59CB8};
// GetEventTable (0x00662660) comes with it.
BEGIN_EVENT_TABLE(moho::WCurveEditor, wxControl)
  EVT_PAINT(moho::WCurveEditor::OnPaint)
  EVT_LEFT_DOWN(moho::WCurveEditor::OnMouseDown)
  EVT_MIDDLE_DOWN(moho::WCurveEditor::OnMouseDown)
  EVT_RIGHT_DOWN(moho::WCurveEditor::OnCurveKeyEdit)
  EVT_LEFT_UP(moho::WCurveEditor::OnMouseUp)
  EVT_MIDDLE_UP(moho::WCurveEditor::OnMouseUp)
  EVT_MOTION(moho::WCurveEditor::OnMouseMove)
  EVT_MOUSEWHEEL(moho::WCurveEditor::ZoomValueAxisByWheel)
  EVT_ENTER_WINDOW(moho::WCurveEditor::IgnoreEvent)
END_EVENT_TABLE()

// ---------------------------------------------------------------------------
// WCurveEditorPanel

/**
 * Address: 0x00662680 (FUN_00662680, Moho::WCurveEditorPanel::WCurveEditorPanel)
 */
moho::WCurveEditorPanel::WCurveEditorPanel(
  wxWindow* const parent,
  const std::int32_t childId,
  const float viewTimeMax,
  const float viewValueMin,
  const float viewValueMax,
  const float initialKeyValue,
  const float initialKeyTangent
)
  : wxPanel(parent)
  , mCurveEditor(nullptr)
  , mKeyTimeText(nullptr)
  , mKeyValueText(nullptr)
  , mKeyTangentText(nullptr)
  , mViewValueMinText(nullptr)
  , mViewValueMaxText(nullptr)
  , mFieldsLive(false)
{
  mCurveEditor =
    new WCurveEditor(this, childId, viewTimeMax, viewValueMin, viewValueMax, initialKeyValue, initialKeyTangent);

  wxBoxSizer* const panelSizer = new wxBoxSizer(wxVERTICAL);
  wxBoxSizer* const fieldSizer = new wxBoxSizer(wxHORIZONTAL);
  panelSizer->Add(fieldSizer, 0, wxALL | wxEXPAND, 1);

  // Each field shows the selected key's value, or 0 when there is none (the
  // binary checks mSelectedKey against the key vector's end every time).
  const auto selectedKeyValue = [this](const int component) -> float {
    const Wm3::Vector3f* const key = mCurveEditor->mSelectedKey;
    if (key == mCurveEditor->mCurve.mKeys.end()) {
      return 0.0f;
    }
    return component == 0 ? key->x : (component == 1 ? key->y : key->z);
  };

  const auto addField = [this, fieldSizer](const int id, const wxChar* const label, const float value) {
    fieldSizer->Add(new wxStaticText(this, -1, label, wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
    wxTextCtrl* const text = new wxTextCtrl(
      this, id, wxString::Format(wxT("%f"), static_cast<double>(value)), wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER
    );
    fieldSizer->Add(text, 0, wxALL, 1);
    return text;
  };

  mKeyTimeText = addField(kKeyTimeFieldId, wxT("Tick"), selectedKeyValue(0));
  mKeyValueText = addField(kKeyValueFieldId, wxT("Value"), selectedKeyValue(1));
  mKeyTangentText = addField(kKeyTangentFieldId, wxT("Range"), selectedKeyValue(2));
  mViewValueMinText = addField(kViewValueMinFieldId, wxT("Window Min:"), mCurveEditor->mViewValueMin);
  mViewValueMaxText = addField(kViewValueMaxFieldId, wxT("Max:"), mCurveEditor->mViewValueMax);

  panelSizer->Add(mCurveEditor, 1, wxALL | wxEXPAND, 1);
  SetSizer(panelSizer);
  SetAutoLayout(true);
  mFieldsLive = true;
}

/**
 * Address: 0x00663400 (FUN_00663400)
 */
void moho::WCurveEditorPanel::RefreshFieldsFromCurve()
{
  const Wm3::Vector3f* const keysEnd = mCurveEditor->mCurve.mKeys.end();

  mKeyTimeText->SetValue(
    wxString::Format(wxT("%f"), mCurveEditor->mSelectedKey != keysEnd ? mCurveEditor->mSelectedKey->x : 0.0f)
  );
  mKeyValueText->SetValue(
    wxString::Format(wxT("%f"), mCurveEditor->mSelectedKey != keysEnd ? mCurveEditor->mSelectedKey->y : 0.0f)
  );
  mKeyTangentText->SetValue(
    wxString::Format(wxT("%f"), mCurveEditor->mSelectedKey != keysEnd ? mCurveEditor->mSelectedKey->z : 0.0f)
  );
  mViewValueMinText->SetValue(wxString::Format(wxT("%f"), mCurveEditor->mViewValueMin));
  mViewValueMaxText->SetValue(wxString::Format(wxT("%f"), mCurveEditor->mViewValueMax));
}

/**
 * Address: 0x00663650 (FUN_00663650)
 *
 * What it does:
 * Every field seeds from the current value, so text that does not parse
 * leaves it as it was (wxString::ToDouble still writes wcstod's 0 when the
 * whole string fails, as the binary's does). The value-range pair is only
 * applied when the span stays at least 0.1.
 */
void moho::WCurveEditorPanel::OnCurveFieldCommitted(wxCommandEvent& event)
{
  if (!mFieldsLive) {
    event.Skip();
    return;
  }

  const Wm3::Vector3f* const keysEnd = mCurveEditor->mCurve.mKeys.end();
  double keyTime = mCurveEditor->mSelectedKey != keysEnd ? mCurveEditor->mSelectedKey->x : 0.0f;
  double keyValue = mCurveEditor->mSelectedKey != keysEnd ? mCurveEditor->mSelectedKey->y : 0.0f;
  double keyTangent = mCurveEditor->mSelectedKey != keysEnd ? mCurveEditor->mSelectedKey->z : 0.0f;

  if (event.GetId() == kKeyTimeFieldId) {
    event.m_commandString.ToDouble(&keyTime);
    mKeyTimeText->SetValue(event.m_commandString);
  }
  if (event.GetId() == kKeyValueFieldId) {
    event.m_commandString.ToDouble(&keyValue);
    mKeyValueText->SetValue(event.m_commandString);
  }
  if (event.GetId() == kKeyTangentFieldId) {
    event.m_commandString.ToDouble(&keyTangent);
    mKeyTangentText->SetValue(event.m_commandString);
  }
  mCurveEditor->MoveSelectedKeyTo(
    static_cast<float>(keyTime), static_cast<float>(keyValue), static_cast<float>(keyTangent)
  );

  double viewValueMin = mCurveEditor->mViewValueMin;
  double viewValueMax = mCurveEditor->mViewValueMax;
  if (event.GetId() == kViewValueMinFieldId) {
    event.m_commandString.ToDouble(&viewValueMin);
    mViewValueMinText->SetValue(event.m_commandString);
  }
  if (event.GetId() == kViewValueMaxFieldId) {
    event.m_commandString.ToDouble(&viewValueMax);
    mViewValueMaxText->SetValue(event.m_commandString);
  }

  const bool spanTooSmall = viewValueMax - viewValueMin < kMinimumVisibleValueSpan;
  if (!spanTooSmall) {
    mCurveEditor->mViewValueMin = static_cast<float>(viewValueMin);
    mCurveEditor->mViewValueMax = static_cast<float>(viewValueMax);
    mCurveEditor->Refresh();
  }

  event.Skip();
}

// Table 0x00DFEF78 = {&wxPanel::sm_eventTable (0x00D5A910), rows 0x00F59D80};
// GetEventTable (0x006638A0) comes with it. The destructors are the compiler's
// (0x00663870 deleting).
BEGIN_EVENT_TABLE(moho::WCurveEditorPanel, wxPanel)
  EVT_TEXT_ENTER(kKeyTimeFieldId, moho::WCurveEditorPanel::OnCurveFieldCommitted)
  EVT_TEXT_ENTER(kKeyValueFieldId, moho::WCurveEditorPanel::OnCurveFieldCommitted)
  EVT_TEXT_ENTER(kKeyTangentFieldId, moho::WCurveEditorPanel::OnCurveFieldCommitted)
  EVT_TEXT_ENTER(kViewValueMinFieldId, moho::WCurveEditorPanel::OnCurveFieldCommitted)
  EVT_TEXT_ENTER(kViewValueMaxFieldId, moho::WCurveEditorPanel::OnCurveFieldCommitted)
END_EVENT_TABLE()

// ---------------------------------------------------------------------------
// WEmitterWx

/**
 * Address: 0x00663900 (FUN_00663900, Moho::WEmitterWx::WEmitterWx)
 */
moho::WEmitterWx::WEmitterWx(UserEntity* const attachEntity, const Wm3::Vector3f& spawnPosition, const char* const boneName)
  : WWinManagedFrame(
      nullptr, -1, wxT("Emitter Editor"), wxDefaultPosition, wxSize(800, 600), wxDEFAULT_FRAME_STYLE, wxT("MohoFrame")
    )
  , mRepeatTimeControl(nullptr)
  , mTimeSlider(nullptr)
  , mRefreshGuard(false)
{
  // Slot 36 hands back the sim with the driver's interlock held; the
  // destructor's ReleaseInterlockRef (slot 37) gives it back.
  mSim = SIM_GetActiveDriver()->ProcessEvents();

  if (attachEntity != nullptr) {
    Entity* const entity = mSim->mEntityDB->FindEntityById(attachEntity->mParams.mEntityId);
    mAttachedUnit.Set(entity != nullptr ? entity->IsUnit() : nullptr);
  } else {
    mAttachedUnit.Set(nullptr);
  }
  if (boneName != nullptr) {
    mBoneName = boneName;
  }

  mTexturePath = wxT("/textures/particles/smoke.dds");
  mRampTexturePath = wxT("/textures/particles/testramp.dds");

  mFileMenu = new wxMenu;
  mFileMenu->Append(ID_EMITTER_NEW, wxT("&New  ( Ctrl+N ) "));
  mFileMenu->Append(ID_EMITTER_OPEN, wxT("&Open Blueprint  ( Ctrl+O )"));
  mFileMenu->Append(ID_EMITTER_SAVE, wxT("&Save Blueprint  ( Ctrl+S )"));
  mFileMenu->Append(ID_EMITTER_SAVE_AS, wxT("&Save &Blueprint As..  ( Alt+S )"));
  mFileMenu->AppendSeparator();
  mFileMenu->Append(ID_EMITTER_OPEN_TEXTURE, wxT("Open &Texture  ( Ctrl+T )"));
  mFileMenu->Append(ID_EMITTER_OPEN_RAMP, wxT("Open &Ramp  ( Ctrl+R )"));

  mOptionsMenu = new wxMenu;
  mOptionsMenu->AppendCheckItem(ID_EMITTER_LOCAL_VELOCITY, wxT("Use Local &Velocity"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_LOCAL_ACCELERATION, wxT("Use Local &Acceleration"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_GRAVITY, wxT("&Gravity"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_ALIGN_ROTATION, wxT("Lock &Particles to Velocity"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_INTERPOLATE_EMISSION, wxT("Interpolate &Emitter Position"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_ALIGN_TO_BONE, wxT("Align Initial Rotation To &Bone"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_FLAT, wxT("Particles are &flat in world space"));
  mOptionsMenu->Check(ID_EMITTER_INTERPOLATE_EMISSION, true);
  mOptionsMenu->AppendCheckItem(ID_EMITTER_SNAP_TO_WATERLINE, wxT("&Snap To Waterline"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_ONLY_EMIT_ON_WATER, wxT("&Only Emit On Water"));
  mOptionsMenu->AppendCheckItem(ID_EMITTER_PARTICLE_RESISTANCE, wxT("&Enable Particle Resistance"));

  mLodMenu = new wxMenu;
  mLodMenu->AppendCheckItem(ID_EMITTER_EMIT_IF_VISIBLE, wxT("&Only Emit If Visible"));
  mLodMenu->Check(ID_EMITTER_EMIT_IF_VISIBLE, true);
  mLodMenu->AppendCheckItem(ID_EMITTER_CATCHUP_EMIT, wxT("&Catch up when Visible"));
  mLodMenu->Check(ID_EMITTER_CATCHUP_EMIT, true);
  mLodMenu->AppendCheckItem(ID_EMITTER_CREATE_IF_VISIBLE, wxT("&Only Create if Visible"));

  wxAcceleratorEntry accelerators[6];
  accelerators[0].Set(wxACCEL_CTRL, 'N', ID_EMITTER_NEW);
  accelerators[1].Set(wxACCEL_CTRL, 'S', ID_EMITTER_SAVE);
  accelerators[2].Set(wxACCEL_ALT, 'S', ID_EMITTER_SAVE_AS);
  accelerators[3].Set(wxACCEL_CTRL, 'O', ID_EMITTER_OPEN);
  accelerators[4].Set(wxACCEL_CTRL, 'T', ID_EMITTER_OPEN_TEXTURE);
  accelerators[5].Set(wxACCEL_CTRL, 'R', ID_EMITTER_OPEN_RAMP);
  const wxAcceleratorTable acceleratorTable(6, accelerators);
  SetAcceleratorTable(acceleratorTable);

  mMenuBar = new wxMenuBar;
  mMenuBar->Append(mFileMenu, wxT("&File"));
  mMenuBar->Append(mOptionsMenu, wxT("&Options"));
  mMenuBar->Append(mLodMenu, wxT("&LOD"));
  SetMenuBar(mMenuBar);

  // The first preview never has a blueprint: the constructor passes null
  // where RefreshPreviewEmitter passes BlueprintNameOrNull().
  mSpawnPosition = spawnPosition;
  IEffect* effect;
  if (mAttachedUnit.GetObjectPtr() != nullptr) {
    const int bone = mAttachedUnit.GetObjectPtr()->ResolveBoneIndex(mBoneName.c_str());
    effect = mSim->mEffectManager->CreateAttachedEmitter(mAttachedUnit.GetObjectPtr(), bone, nullptr, -1);
  } else {
    effect = mSim->mEffectManager->CreateEmitter(mSpawnPosition, nullptr, -1);
  }
  mPreviewEffect.Set(effect);

  wxBoxSizer* const mainSizer = new wxBoxSizer(wxVERTICAL);
  wxBoxSizer* const topRow = new wxBoxSizer(wxHORIZONTAL);
  mainSizer->Add(topRow, 0, wxEXPAND | wxALL, 2);
  wxBoxSizer* const bottomRow = new wxBoxSizer(wxHORIZONTAL);
  mainSizer->Add(bottomRow, 0, wxEXPAND | wxALL, 2);

  topRow->Add(new wxStaticText(this, -1, wxT("Life Time"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mLifetimeControl = new wxTextCtrl(this, kLifetimeFieldId, wxT("-1"));
  NarrowToThird(mLifetimeControl);
  topRow->Add(mLifetimeControl, 0, wxALL, 3);

  mCachedRepeatTime = 1.0;
  topRow->Add(new wxStaticText(this, -1, wxT("Repeat Time"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mRepeatTimeControl = new wxTextCtrl(this, kRepeatTimeFieldId, wxT("50.0"));
  NarrowToThird(mRepeatTimeControl);
  topRow->Add(mRepeatTimeControl, 0, wxALL, 3);

  topRow->Add(new wxStaticText(this, -1, wxT("Blend Mode"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mBlendModeChoice = new wxComboBox(this, kEffectChoiceId);
  mBlendModeChoice->Append(wxT("Alpha Blend"));
  mBlendModeChoice->Append(wxT("Modulate Inverse"));
  mBlendModeChoice->Append(wxT("Modulate2X Inverse"));
  mBlendModeChoice->Append(wxT("Add"));
  mBlendModeChoice->Append(wxT("Premodulated Alpha"));
  mBlendModeChoice->Append(wxT("Refract"));
  mBlendModeChoice->SetSelection(3);
  topRow->Add(mBlendModeChoice, 0, wxALL, 3);

  topRow->Add(new wxStaticText(this, -1, wxT("Fidelity"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mFidelityChoice = new wxComboBox(this, kEffectChoiceId);
  mFidelityChoice->Append(wxT("Low"));
  mFidelityChoice->Append(wxT("Medium"));
  mFidelityChoice->Append(wxT("Medium/Low"));
  mFidelityChoice->Append(wxT("High"));
  mFidelityChoice->Append(wxT("High/Low"));
  mFidelityChoice->Append(wxT("High/Medium"));
  mFidelityChoice->Append(wxT("High/Medium/Low"));
  mFidelityChoice->SetSelection(6);
  topRow->Add(mFidelityChoice, 0, wxALL, 3);

  bottomRow->Add(new wxStaticText(this, -1, wxT("Frame Count"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mTextureFrameCountControl = new wxTextCtrl(this, kFrameCountFieldId, wxT("1"));
  NarrowToThird(mTextureFrameCountControl);
  bottomRow->Add(mTextureFrameCountControl, 0, wxALL, 3);

  bottomRow->Add(new wxStaticText(this, -1, wxT("Strip Count"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mTextureStripCountControl = new wxTextCtrl(this, kStripCountFieldId, wxT("1"));
  NarrowToThird(mTextureStripCountControl);
  bottomRow->Add(mTextureStripCountControl, 0, wxALL, 3);

  bottomRow->Add(new wxStaticText(this, -1, wxT("Sort Order"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mSortOrderControl = new wxTextCtrl(this, kSortOrderFieldId, wxT("0"));
  NarrowToThird(mSortOrderControl);
  bottomRow->Add(mSortOrderControl, 0, wxALL, 3);

  bottomRow->Add(
    new wxStaticText(this, -1, wxT("LOD Cutoff Distance"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3
  );
  mLodCutoffControl = new wxTextCtrl(this, kLodCutoffFieldId, wxT("100"));
  NarrowToThird(mLodCutoffControl);
  bottomRow->Add(mLodCutoffControl, 0, wxALL, 3);

  mPlayingCheckBox = new wxCheckBox(this, kPlayingCheckBoxId, wxT("Playing"));
  mPlayingCheckBox->SetValue(true);
  bottomRow->Add(mPlayingCheckBox, 0, wxALL, 3);

  topRow->Add(new wxStaticText(this, -1, wxT("Texture:"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mTextureNameControl = new wxStaticText(this, -1, mTexturePath, wxDefaultPosition, wxDefaultSize, kFieldLabelStyle);
  topRow->Add(mTextureNameControl, 0, wxALL, 3);

  bottomRow->Add(new wxStaticText(this, -1, wxT("Ramp:"), wxDefaultPosition, wxDefaultSize, kFieldLabelStyle), 0, wxALL, 3);
  mRampNameControl = new wxStaticText(this, -1, mRampTexturePath, wxDefaultPosition, wxDefaultSize, kFieldLabelStyle);
  bottomRow->Add(mRampNameControl, 0, wxALL, 3);

  wxBoxSizer* const sliderRow = new wxBoxSizer(wxHORIZONTAL);
  mainSizer->Add(sliderRow, 0, wxEXPAND | wxALL, 5);
  mTimeSlider = new wxSlider(
    this, kTimeSliderId, 0, 0, 100, wxDefaultPosition, wxDefaultSize, wxSL_HORIZONTAL | wxSL_AUTOTICKS | wxSL_LABELS
  );
  sliderRow->Add(mTimeSlider, 1, wxALL, 0);

  wxNotebook* const notebook = new wxNotebook(this, -1);
  mainSizer->Add(new wxNotebookSizer(notebook), 1, wxEXPAND | wxALL, 5);

  // Each group of curves shares a tab; the first curve of a group opens it.
  wxPanel* page = nullptr;
  wxBoxSizer* pageSizer = nullptr;
  for (int curve = 0; curve < EMITTER_LAST_CURVE; ++curve) {
    const SEmitterCurveEditorDesc& desc = kEmitterCurveEditors[curve];
    if (curve == EMITTER_XDIR_CURVE || curve == EMITTER_VELOCITY_CURVE || curve == EMITTER_SIZE_CURVE
        || curve == EMITTER_BEGINSIZE_CURVE || curve == EMITTER_FRAMERATE_CURVE) {
      page = new wxPanel(notebook);
      pageSizer = new wxBoxSizer(wxVERTICAL);
      page->SetAutoLayout(true);
      page->SetSizer(pageSizer);
      notebook->AddPage(page, desc.mTabTitle);
    }

    WCurveEditorPanel* const panel = new WCurveEditorPanel(
      page,
      kFirstCurveEditorId + curve,
      static_cast<float>(mCachedRepeatTime),
      desc.mViewValueMin,
      desc.mViewValueMax,
      desc.mInitialKeyValue,
      desc.mInitialKeyTangent
    );
    panel->mCurveEditor->SetName(desc.mCaption);
    panel->mCurveEditor->SetScriptName(desc.mScriptName);
    mCurvePanels.push_back(panel);
    pageSizer->Add(panel, 1, wxEXPAND | wxALL, 5);
  }

  SetSizer(mainSizer);
  SetAutoLayout(true);
  RefreshPreviewEmitter();
}

/**
 * Address: 0x00666F40 (FUN_00666F40, Moho::WEmitterWx::~WEmitterWx)
 * Address: 0x00669E10 (FUN_00669E10, scalar deleting destructor)
 */
moho::WEmitterWx::~WEmitterWx()
{
  for (WCurveEditorPanel* const panel : mCurvePanels) {
    delete panel;
  }

  if (mPreviewEffect.GetObjectPtr() != nullptr) {
    mSim->mEffectManager->DestroyEffect(mPreviewEffect.GetObjectPtr());
  }
  SIM_GetActiveDriver()->ReleaseInterlockRef();
}

/**
 * Address: 0x006671C0 (FUN_006671C0)
 */
const char* moho::WEmitterWx::BlueprintNameOrNull() const
{
  return mBlueprintName.empty() ? nullptr : mBlueprintName.c_str();
}

/**
 * Address: 0x006671F0 (FUN_006671F0)
 */
void moho::WEmitterWx::ApplyTextFieldParam(wxTextCtrl* const field, const std::int32_t parameter)
{
  double value;
  field->GetValue().ToDouble(&value);
  mPreviewEffect.GetObjectPtr()->SetFloatParam(parameter, static_cast<float>(value));
}

/**
 * Address: 0x00667290 (FUN_00667290)
 */
void moho::WEmitterWx::ApplyMenuFlagParam(wxMenu* const menu, const std::int32_t commandId, const std::int32_t parameter)
{
  if (menu->IsChecked(commandId)) {
    mPreviewEffect.GetObjectPtr()->SetFloatParam(parameter, 1.0f);
  } else {
    mPreviewEffect.GetObjectPtr()->SetFloatParam(parameter, 0.0f);
  }
}

/**
 * Address: 0x006672F0 (FUN_006672F0)
 *
 * What it does:
 * A dead effect is recreated from the loaded blueprint, attached to the unit
 * when there is one, and the cached repeat time is reset to -1 so the time
 * axes are pushed again. The repeat time only goes out when it changed and is
 * above 0.001; the time slider's range follows it.
 */
void moho::WEmitterWx::RefreshPreviewEmitter()
{
  if (mRepeatTimeControl == nullptr || mTimeSlider == nullptr || mRefreshGuard) {
    return;
  }

  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    IEffect* effect;
    if (mAttachedUnit.GetObjectPtr() != nullptr) {
      const int bone = mAttachedUnit.GetObjectPtr()->ResolveBoneIndex(mBoneName.c_str());
      effect = mSim->mEffectManager->CreateAttachedEmitter(mAttachedUnit.GetObjectPtr(), bone, BlueprintNameOrNull(), -1);
    } else {
      effect = mSim->mEffectManager->CreateEmitter(mSpawnPosition, BlueprintNameOrNull(), -1);
    }
    mPreviewEffect.Set(effect);
    mCachedRepeatTime = -1.0;
    if (mPreviewEffect.GetObjectPtr() == nullptr) {
      return;
    }
  }

  mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_BLENDMODE, static_cast<float>(mBlendModeChoice->GetSelection()));

  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_LOCAL_VELOCITY, EFFECT_USE_LOCAL_VELOCITY);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_LOCAL_ACCELERATION, EFFECT_USE_LOCAL_ACCELERATION);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_GRAVITY, EFFECT_USE_GRAVITY);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_ALIGN_ROTATION, EFFECT_ALIGN_ROTATION);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_INTERPOLATE_EMISSION, EFFECT_INTERPOLATE_EMISSION);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_ALIGN_TO_BONE, EFFECT_ALIGN_TO_BONE);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_FLAT, EFFECT_FLAT);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_SNAP_TO_WATERLINE, EFFECT_SNAPTOWATERLINE);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_ONLY_EMIT_ON_WATER, EFFECT_ONLYEMITONWATER);
  ApplyMenuFlagParam(mOptionsMenu, ID_EMITTER_PARTICLE_RESISTANCE, EFFECT_PARTICLERESISTANCE);
  ApplyMenuFlagParam(mLodMenu, ID_EMITTER_EMIT_IF_VISIBLE, EFFECT_EMITIFVISIBLE);
  ApplyMenuFlagParam(mLodMenu, ID_EMITTER_CATCHUP_EMIT, EFFECT_CATCHUPEMIT);
  ApplyMenuFlagParam(mLodMenu, ID_EMITTER_CREATE_IF_VISIBLE, EFFECT_CREATEIFVISIBLE);

  double repeatTime;
  mRepeatTimeControl->GetValue().ToDouble(&repeatTime);
  if (repeatTime != mCachedRepeatTime && repeatTime > 0.001) {
    mCachedRepeatTime = repeatTime;
    for (unsigned int i = 0; i < mCurvePanels.size(); ++i) {
      mCurvePanels[i]->mCurveEditor->ResetCurveXRange(static_cast<float>(mCachedRepeatTime));
    }
    mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_REPEATTIME, static_cast<float>(mCachedRepeatTime));
    mTimeSlider->SetRange(0, static_cast<int>(mCachedRepeatTime));
    mTimeSlider->SetValue(static_cast<int>(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT)));
  }

  ApplyTextFieldParam(mLifetimeControl, EFFECT_LIFETIME);
  ApplyTextFieldParam(mTextureFrameCountControl, EFFECT_FRAMECOUNT);
  ApplyTextFieldParam(mSortOrderControl, EFFECT_SORTORDER);
  ApplyTextFieldParam(mLodCutoffControl, EFFECT_LODCUTOFF);
  ApplyTextFieldParam(mTextureStripCountControl, EFFECT_TEXTURE_STRIPCOUNT);

  for (unsigned int i = 0; i < mCurvePanels.size(); ++i) {
    WCurveEditor* const editor = mCurvePanels[i]->mCurveEditor;
    editor->mCurveDirty = false;
    mPreviewEffect.GetObjectPtr()->SetCurveParam(static_cast<std::int32_t>(i), &editor->mCurve);
  }

  // Slot 4 takes the texture paths: 0 the particle texture, 1 the ramp.
  msvc8::string path = gpg::STR_WideToUtf8(mTexturePath.c_str());
  mPreviewEffect.GetObjectPtr()->OnInit(0, path.c_str());
  path = gpg::STR_WideToUtf8(mRampTexturePath.c_str());
  mPreviewEffect.GetObjectPtr()->OnInit(1, path.c_str());
}

/**
 * Address: 0x00667860 (FUN_00667860)
 *
 * What it does:
 * Reads back, in order: both texture paths (into the labels), every curve,
 * the blend mode, the fidelity from the loaded blueprint's High/Med/Low flags
 * (selection = mask - 1, bit 2 High .. bit 0 Low), the repeat time (field and
 * slider range), the current tick, the four remaining numeric fields, and the
 * thirteen flags into their menu check items.
 */
void moho::WEmitterWx::LoadFromEffect()
{
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    return;
  }

  mRefreshGuard = true;

  mTexturePath = gpg::STR_Utf8ToWide(mPreviewEffect.GetObjectPtr()->GetStringParam(0)->c_str()).c_str();
  mTextureNameControl->SetLabel(mTexturePath);
  mRampTexturePath = gpg::STR_Utf8ToWide(mPreviewEffect.GetObjectPtr()->GetStringParam(1)->c_str()).c_str();
  mRampNameControl->SetLabel(mRampTexturePath);

  for (unsigned int i = 0; i < mCurvePanels.size(); ++i) {
    mCurvePanels[i]->mCurveEditor->AssignCurve(
      *mPreviewEffect.GetObjectPtr()->GetCurveParam(static_cast<std::int32_t>(i))
    );
  }

  mBlendModeChoice->SetSelection(static_cast<int>(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_BLENDMODE)));

  {
    RResId blueprintId;
    gpg::STR_SetFilename(&blueprintId.name, BlueprintNameOrNull());
    if (const REffectBlueprint* const blueprint = mSim->mRules->GetEffectBlueprint(blueprintId)) {
      const int fidelity =
        ((blueprint->HighFidelity * 2 | blueprint->MedFidelity) * 2 | blueprint->LowFidelity);
      mFidelityChoice->SetSelection(fidelity - 1);
    }
  }

  wxString text;
  text = wxString::Format(wxT("%.2f"), mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_REPEATTIME));
  mRepeatTimeControl->SetValue(text);
  mTimeSlider->SetRange(0, static_cast<int>(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_REPEATTIME)));
  mTimeSlider->SetValue(static_cast<int>(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT)));
  text = wxString::Format(wxT("%.2f"), mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_LIFETIME));
  mLifetimeControl->SetValue(text);
  text = wxString::Format(wxT("%.2f"), mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_FRAMECOUNT));
  mTextureFrameCountControl->SetValue(text);
  text = wxString::Format(wxT("%.2f"), mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TEXTURE_STRIPCOUNT));
  mTextureStripCountControl->SetValue(text);
  text = wxString::Format(wxT("%.2f"), mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_SORTORDER));
  mSortOrderControl->SetValue(text);
  text = wxString::Format(wxT("%.2f"), mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_LODCUTOFF));
  mLodCutoffControl->SetValue(text);

  const auto flag = [this](const EEmitterParam parameter) {
    return mPreviewEffect.GetObjectPtr()->GetFloatParam(parameter) > 0.0f;
  };
  mOptionsMenu->Check(ID_EMITTER_LOCAL_VELOCITY, flag(EFFECT_USE_LOCAL_VELOCITY));
  mOptionsMenu->Check(ID_EMITTER_LOCAL_ACCELERATION, flag(EFFECT_USE_LOCAL_ACCELERATION));
  mOptionsMenu->Check(ID_EMITTER_GRAVITY, flag(EFFECT_USE_GRAVITY));
  mOptionsMenu->Check(ID_EMITTER_ALIGN_ROTATION, flag(EFFECT_ALIGN_ROTATION));
  mOptionsMenu->Check(ID_EMITTER_INTERPOLATE_EMISSION, flag(EFFECT_INTERPOLATE_EMISSION));
  mOptionsMenu->Check(ID_EMITTER_ALIGN_TO_BONE, flag(EFFECT_ALIGN_TO_BONE));
  mOptionsMenu->Check(ID_EMITTER_FLAT, flag(EFFECT_FLAT));
  mOptionsMenu->Check(ID_EMITTER_SNAP_TO_WATERLINE, flag(EFFECT_SNAPTOWATERLINE));
  mOptionsMenu->Check(ID_EMITTER_ONLY_EMIT_ON_WATER, flag(EFFECT_ONLYEMITONWATER));
  mOptionsMenu->Check(ID_EMITTER_PARTICLE_RESISTANCE, flag(EFFECT_PARTICLERESISTANCE));
  mLodMenu->Check(ID_EMITTER_EMIT_IF_VISIBLE, flag(EFFECT_EMITIFVISIBLE));
  mLodMenu->Check(ID_EMITTER_CATCHUP_EMIT, flag(EFFECT_CATCHUPEMIT));
  mLodMenu->Check(ID_EMITTER_CREATE_IF_VISIBLE, flag(EFFECT_CREATEIFVISIBLE));

  mRefreshGuard = false;
}

/**
 * Address: 0x00668180 (FUN_00668180)
 */
void moho::WEmitterWx::OnSettingChanged(wxCommandEvent&)
{
  for (unsigned int i = 0; i < mCurvePanels.size(); ++i) {
    mCurvePanels[i]->RefreshFieldsFromCurve();
  }
  RefreshPreviewEmitter();
}

/**
 * Address: 0x006681D0 (FUN_006681D0)
 */
void moho::WEmitterWx::OnPlayingToggled(wxCommandEvent&)
{
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    return;
  }
  const float tickIncrement = mPlayingCheckBox->GetValue() ? 1.0f : 0.0f;
  mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_TICKINCREMENT, tickIncrement);
}

/**
 * Address: 0x00668240 (FUN_00668240)
 */
void moho::WEmitterWx::OnTimeSliderTrack(wxScrollEvent&)
{
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    return;
  }
  mPreviewEffect.GetObjectPtr()->SetFloatParam(EFFECT_TICKCOUNT, static_cast<float>(mTimeSlider->GetValue()));
}

/**
 * Address: 0x00668290 (FUN_00668290)
 */
void moho::WEmitterWx::OnTimeSliderUpdateUI(wxUpdateUIEvent&)
{
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    return;
  }

  int tick = static_cast<int>(std::fmod(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT), mCachedRepeatTime));
  if (mCachedRepeatTime >= mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT)) {
    tick = static_cast<int>(mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TICKCOUNT));
  }
  mTimeSlider->SetValue(tick);
}

/**
 * Address: 0x00668340 (FUN_00668340)
 *
 * What it does:
 * Refreshes the preview first, then writes through a gpg::TextWriter over
 * DISK_OpenFileWrite (0x00957250 is TextWriter::Printf, not STR_Printf). The
 * fidelity lines come from the combo box: selection + 1 is the Low|Med|High
 * mask. A missing effect only warns; a file that cannot be opened is skipped
 * silently.
 */
void moho::WEmitterWx::WriteBlueprintScript(const wxString& path, const wxString& blueprintId)
{
  RefreshPreviewEmitter();
  if (mPreviewEffect.GetObjectPtr() == nullptr) {
    gpg::Warnf("Invalid effect. Skip saving blueprint!");
    return;
  }

  msvc8::auto_ptr<gpg::Stream> file = DISK_OpenFileWrite(gpg::STR_WideToUtf8(path.c_str()).c_str());
  if (file.get() == nullptr) {
    return;
  }

  const auto flag = [this](const EEmitterParam parameter) {
    return BoolString(mPreviewEffect.GetObjectPtr()->GetFloatParam(parameter) > 0.0f);
  };

  gpg::TextWriter writer(file.get(), 2);
  writer.Printf("EmitterBlueprint {\n");
  writer.Printf("\tBlueprintId = '%s',\n", gpg::STR_WideToUtf8(blueprintId.c_str()).c_str());
  writer.Printf("\tLifetime = %.2f,\n", mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_LIFETIME));
  writer.Printf("\tRepeattime = %.2f,\n", mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_REPEATTIME));
  writer.Printf("\tTextureFramecount = %.2f,\n", mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_FRAMECOUNT));
  writer.Printf("\tBlendmode = %.2f,\n", mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_BLENDMODE));
  writer.Printf("\tLocalVelocity = %s,\n", flag(EFFECT_USE_LOCAL_VELOCITY));
  writer.Printf("\tLocalAcceleration = %s,\n", flag(EFFECT_USE_LOCAL_ACCELERATION));
  writer.Printf("\tGravity = %s,\n", flag(EFFECT_USE_GRAVITY));
  writer.Printf("\tAlignRotation = %s,\n", flag(EFFECT_ALIGN_ROTATION));
  writer.Printf("\tAlignToBone = %s,\n", flag(EFFECT_ALIGN_TO_BONE));
  writer.Printf("\tFlat = %s,\n", flag(EFFECT_FLAT));
  writer.Printf("\tLODCutoff = %.2f,\n", mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_LODCUTOFF));
  writer.Printf("\tEmitIfVisible = %s,\n", flag(EFFECT_EMITIFVISIBLE));
  writer.Printf("\tCatchupEmit = %s,\n", flag(EFFECT_CATCHUPEMIT));
  writer.Printf("\tCreateIfVisible = %s,\n", flag(EFFECT_CREATEIFVISIBLE));
  writer.Printf("\tSnapToWaterline = %s,\n", flag(EFFECT_SNAPTOWATERLINE));
  writer.Printf("\tOnlyEmitOnWater = %s,\n", flag(EFFECT_ONLYEMITONWATER));
  writer.Printf("\tParticleResistance = %s,\n", flag(EFFECT_PARTICLERESISTANCE));
  writer.Printf("\tInterpolateEmission = %s,\n", flag(EFFECT_INTERPOLATE_EMISSION));
  writer.Printf("\tTextureStripcount = %.2f,\n", mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_TEXTURE_STRIPCOUNT));
  writer.Printf("\tSortOrder = %.2f,\n", mPreviewEffect.GetObjectPtr()->GetFloatParam(EFFECT_SORTORDER));

  const int fidelity = mFidelityChoice->GetSelection() + 1;
  writer.Printf("\tLowFidelity = %s,\n", BoolString((fidelity & 1) != 0));
  writer.Printf("\tMedFidelity = %s,\n", BoolString((fidelity & 2) != 0));
  writer.Printf("\tHighFidelity = %s,\n", BoolString((fidelity & 4) != 0));

  writer.Printf("\tTexture = [[%s]],\n", gpg::STR_WideToUtf8(mTexturePath.c_str()).c_str());
  writer.Printf("\tRampTexture = [[%s]],\n", gpg::STR_WideToUtf8(mRampTexturePath.c_str()).c_str());

  for (unsigned int i = 0; i < mCurvePanels.size(); ++i) {
    mCurvePanels[i]->mCurveEditor->WriteCurveScript(writer);
  }

  writer.Printf("}\n\n");
  file->VirtClose(gpg::Stream::ModeBoth);
}

/**
 * Address: 0x00668B00 (FUN_00668B00)
 *
 * What it does:
 * The dialogs are created with new and never destroyed, and the "Bad name!"
 * boxes likewise; the binary leaks each one.
 *
 * Open Blueprint remembers the directory, file name and path, rejects names
 * that are not *.bp, converts the path to a VFS name and asks the rules for
 * that effect blueprint: an emitter replaces the preview (the old effect is
 * destroyed through its manager, the editor reloads from the new one and the
 * path becomes the title); beams and trails are refused with a warning, as is
 * a name the rules do not know. On any failure the previous effect is put
 * back - and the path, except that the copy it restores was taken after the
 * new path was stored, so the new path stays. It also computes the file name
 * up to its last '_' and never uses it.
 *
 * Save writes to the remembered path, prompting first when there is none;
 * a name that is not *.bp is reported and cleared, and the write still runs
 * (DISK_OpenFileWrite then fails on the empty path). Save As forgets the path
 * and falls into Save. The texture and ramp entries convert the chosen file
 * to a VFS path, show it and refresh; the check items refresh.
 */
void moho::WEmitterWx::OnMenuCommand(wxCommandEvent& event)
{
  switch (event.GetId()) {
    case ID_EMITTER_OPEN: {
      msvc8::string emittersRoot;
      (void)DISK_GetVFS()->FindFile(&emittersRoot, "/effects/Emitters", nullptr);
      mBlueprintDirectory = gpg::STR_Utf8ToWide(emittersRoot.c_str()).c_str();

      wxFileDialog* const dialog = new wxFileDialog(
        this, wxT("Select Blueprint"), mBlueprintDirectory, wxEmptyString, wxT("*.bp"), wxOPEN | wxCHANGE_DIR,
        wxDefaultPosition
      );
      if (dialog->ShowModal() != wxID_OK) {
        return;
      }

      mBlueprintDirectory = dialog->GetDirectory();
      mBlueprintFileName = dialog->GetFilename();
      if (!mBlueprintFileName.Matches(wxT("*.bp"))) {
        wxMessageDialog* const badName = new wxMessageDialog(
          this, wxT("You didn't open a valid blueprint"), wxT("Bad name!"), wxOK, wxDefaultPosition
        );
        badName->ShowModal();
        return;
      }

      mBlueprintPath = dialog->GetPath();
      const wxString unusedBaseName = mBlueprintFileName.BeforeLast(wxT('_'));

      IEffect* const previousEffect = mPreviewEffect.GetObjectPtr();
      const wxString previousPath = mBlueprintPath;
      mPreviewEffect.Set(nullptr);

      {
        msvc8::string mountedPath;
        (void)DISK_GetVFS()->ToMountedPath(&mountedPath, gpg::STR_WideToUtf8(mBlueprintPath.c_str()).c_str());
        mBlueprintName = mountedPath;
      }

      if (mAttachedUnit.GetObjectPtr() != nullptr) {
        REffectBlueprint* blueprint;
        {
          RResId blueprintId;
          gpg::STR_InitFilename(&blueprintId.name, BlueprintNameOrNull());
          blueprint = mSim->mRules->GetEffectBlueprint(blueprintId);
        }
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
        REffectBlueprint* blueprint;
        {
          RResId blueprintId;
          gpg::STR_InitFilename(&blueprintId.name, BlueprintNameOrNull());
          blueprint = mSim->mRules->GetEffectBlueprint(blueprintId);
        }
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
        SetTitle(mBlueprintPath);
      }
      return;
    }

    case ID_EMITTER_SAVE_AS:
      mBlueprintPath = wxT("");
      mBlueprintFileName = wxT("");
      [[fallthrough]];

    case ID_EMITTER_SAVE: {
      if (mBlueprintFileName.IsEmpty()) {
        msvc8::string emittersRoot;
        (void)DISK_GetVFS()->FindFile(&emittersRoot, "/effects/Emitters", nullptr);
        mBlueprintDirectory = gpg::STR_Utf8ToWide(emittersRoot.c_str()).c_str();

        wxFileDialog* const dialog = new wxFileDialog(
          this, wxT("Choose a file to save as."), mBlueprintDirectory, wxEmptyString, wxT("*.bp"), wxSAVE,
          wxDefaultPosition
        );
        if (dialog->ShowModal() != wxID_OK) {
          return;
        }

        mBlueprintDirectory = dialog->GetDirectory();
        mBlueprintFileName = dialog->GetFilename();
        mBlueprintPath = dialog->GetPath();
        if (!mBlueprintFileName.Matches(wxT("*.bp"))) {
          mBlueprintFileName = wxT("");
          mBlueprintPath = wxT("");
          wxMessageDialog* const badName = new wxMessageDialog(
            this, wxT("Since this is a blueprint you must save as *.bp"), wxT("Bad name!"), wxOK, wxDefaultPosition
          );
          badName->ShowModal();
        }
      }

      WriteBlueprintScript(mBlueprintPath, mBlueprintFileName.BeforeLast(wxT('_')));
      SetTitle(mBlueprintPath);
      return;
    }

    case ID_EMITTER_OPEN_TEXTURE: {
      msvc8::string texturesRoot;
      (void)DISK_GetVFS()->FindFile(&texturesRoot, "/textures/particles", nullptr);
      mTextureDirectory = gpg::STR_Utf8ToWide(texturesRoot.c_str()).c_str();

      wxFileDialog* const dialog = new wxFileDialog(
        this, wxT("Select Particle Texture"), mTextureDirectory, wxEmptyString, wxT("*.dds"), wxOPEN, wxDefaultPosition
      );
      if (dialog->ShowModal() != wxID_OK) {
        return;
      }

      mTextureDirectory = dialog->GetDirectory();
      mTexturePath = dialog->GetPath();

      msvc8::string mountedPath;
      (void)DISK_GetVFS()->ToMountedPath(&mountedPath, gpg::STR_WideToUtf8(mTexturePath.c_str()).c_str());
      mTexturePath = gpg::STR_Utf8ToWide(mountedPath.c_str()).c_str();
      mTextureNameControl->SetLabel(mTexturePath);
      RefreshPreviewEmitter();
      return;
    }

    case ID_EMITTER_OPEN_RAMP: {
      msvc8::string texturesRoot;
      (void)DISK_GetVFS()->FindFile(&texturesRoot, "/textures/particles", nullptr);
      mTextureDirectory = gpg::STR_Utf8ToWide(texturesRoot.c_str()).c_str();

      wxFileDialog* const dialog = new wxFileDialog(
        this, wxT("Select Ramp Texture"), mTextureDirectory, wxEmptyString, wxT("*.dds"), wxOPEN, wxDefaultPosition
      );
      if (dialog->ShowModal() != wxID_OK) {
        return;
      }

      mTextureDirectory = dialog->GetDirectory();
      mRampTexturePath = dialog->GetPath();

      msvc8::string mountedPath;
      (void)DISK_GetVFS()->ToMountedPath(&mountedPath, gpg::STR_WideToUtf8(mRampTexturePath.c_str()).c_str());
      mRampTexturePath = gpg::STR_Utf8ToWide(mountedPath.c_str()).c_str();
      mRampNameControl->SetLabel(mRampTexturePath);
      RefreshPreviewEmitter();
      return;
    }

    case ID_EMITTER_LOCAL_VELOCITY:
    case ID_EMITTER_LOCAL_ACCELERATION:
    case ID_EMITTER_GRAVITY:
    case ID_EMITTER_ALIGN_ROTATION:
    case ID_EMITTER_INTERPOLATE_EMISSION:
    case ID_EMITTER_ALIGN_TO_BONE:
    case ID_EMITTER_FLAT:
    case ID_EMITTER_EMIT_IF_VISIBLE:
    case ID_EMITTER_CATCHUP_EMIT:
    case ID_EMITTER_CREATE_IF_VISIBLE:
    case ID_EMITTER_SNAP_TO_WATERLINE:
    case ID_EMITTER_ONLY_EMIT_ON_WATER:
      RefreshPreviewEmitter();
      return;

    default:
      return;
  }
}

// Table 0x00DFEF80 = {&wxFrame::sm_eventTable (0x00D56F70), rows 0x00F59DF8};
// GetEventTable (0x00669E30) comes with it. 0x00F8F8A8 in the text rows is
// wxEVT_COMMAND_TEXT_UPDATED (wxListCtrl::MSWCommand raises it for EN_UPDATE).
// The menu range stops at 684, so Enable Particle Resistance (685) toggles
// without a refresh.
BEGIN_EVENT_TABLE(moho::WEmitterWx, moho::WWinManagedFrame)
  EVT_TEXT(kLifetimeFieldId, moho::WEmitterWx::OnSettingChanged)
  EVT_TEXT(kRepeatTimeFieldId, moho::WEmitterWx::OnSettingChanged)
  EVT_TEXT(kFrameCountFieldId, moho::WEmitterWx::OnSettingChanged)
  EVT_COMBOBOX(kEffectChoiceId, moho::WEmitterWx::OnSettingChanged)
  EVT_CHECKBOX(kPlayingCheckBoxId, moho::WEmitterWx::OnPlayingToggled)
  EVT_COMMAND_SCROLL_THUMBTRACK(kTimeSliderId, moho::WEmitterWx::OnTimeSliderTrack)
  EVT_UPDATE_UI(kTimeSliderId, moho::WEmitterWx::OnTimeSliderUpdateUI)
  EVT_TEXT(kLodCutoffFieldId, moho::WEmitterWx::OnSettingChanged)
  EVT_COMMAND_RANGE(kFirstCurveEditorId, kViewValueMaxFieldId, wxEVT_COMMAND_BUTTON_CLICKED, moho::WEmitterWx::OnSettingChanged)
  EVT_MENU_RANGE(666, ID_EMITTER_ONLY_EMIT_ON_WATER, moho::WEmitterWx::OnMenuCommand)
END_EVENT_TABLE()
