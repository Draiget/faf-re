#include "WxCoreGdiRuntime.h"

namespace
{
  void* gWxFontListClassInfoTable[1] = {nullptr};
  void* gWxResourceCacheClassInfoTable[1] = {nullptr};
  void* gWxColourDatabaseClassInfoTable[1] = {nullptr};
  void* gWxBitmapListClassInfoTable[1] = {nullptr};
  void* gWxLocaleModuleClassInfoTable[1] = {nullptr};
  void* gWxHelpProviderModuleClassInfoTable[1] = {nullptr};
  void* gWxContextHelpClassInfoTable[1] = {nullptr};
  void* gWxContextHelpButtonClassInfoTable[1] = {nullptr};
  void* gWxSystemSettingsModuleClassInfoTable[1] = {nullptr};
  void* gWxBrushClassInfoTable[1] = {nullptr};
  void* gWxDcBaseClassInfoTable[1] = {nullptr};
  void* gWxDcModuleClassInfoTable[1] = {nullptr};
  void* gWxToolTipClassInfoTable[1] = {nullptr};
  void* gWxIndividualLayoutConstraintClassInfoTable[1] = {nullptr};
  void* gWxLayoutConstraintsClassInfoTable[1] = {nullptr};
  void* gWxFontDialogClassInfoTable[1] = {nullptr};
  void* gWxHashTableClassInfoTable[1] = {nullptr};
  void* gWxPopupWindowClassInfoTable[1] = {nullptr};
  void* gWxSpinCtrlClassInfoTable[1] = {nullptr};
  void* gWxMemoryDcClassInfoTable[1] = {nullptr};
  void* gWxFontMapperModuleClassInfoTable[1] = {nullptr};
  void* gWxFontDataClassInfoTable[1] = {nullptr};
  void* gWxIcoHandlerClassInfoTable[1] = {nullptr};
  void* gWxCurHandlerClassInfoTable[1] = {nullptr};
  void* gWxAniHandlerClassInfoTable[1] = {nullptr};
  void* gWxPathListClassInfoTable[1] = {nullptr};
  void* gWxPenClassInfoTable[1] = {nullptr};
  void* gWxSpinEventClassInfoTable[1] = {nullptr};
  void* gWxListBoxClassInfoTable[1] = {nullptr};
  void* gWxTimerEventClassInfoTable[1] = {nullptr};
  void* gWxScreenDcClassInfoTable[1] = {nullptr};
  void* gWxMdiParentFrameClassInfoTable[1] = {nullptr};
  void* gWxDragImageClassInfoTable[1] = {nullptr};
  void* gWxMswSystemMenuFontModuleClassInfoTable[1] = {nullptr};
  void* gWxRadioBoxClassInfoTable[1] = {nullptr};
  void* gWxStaticLineClassInfoTable[1] = {nullptr};
  void* gWxToolBarBaseClassInfoTable[1] = {nullptr};
  void* gWxEnhMetaFileClassInfoTable[1] = {nullptr};
  void* gWxClipboardClassInfoTable[1] = {nullptr};
  void* gWxFileProtoClassInfoTable[1] = {nullptr};
  void* gWxServerBaseClassInfoTable[1] = {nullptr};
  void* gWxClientBaseClassInfoTable[1] = {nullptr};
  void* gWxDdeModuleClassInfoTable[1] = {nullptr};
  void* gWxDdeConnectionClassInfoTable[1] = {nullptr};
  void* gWxDdeClientClassInfoTable[1] = {nullptr};
  void* gWxDdeServerClassInfoTable[1] = {nullptr};
  void* gWxPrintPaperTypeClassInfoTable[1] = {nullptr};
  void* gWxPrintPaperDatabaseClassInfoTable[1] = {nullptr};
  void* gWxPrintPaperModuleClassInfoTable[1] = {nullptr};
  void* gWxClipboardModuleClassInfoTable[1] = {nullptr};
  void* gWxConnectionBaseClassInfoTable[1] = {nullptr};

  // Owner types for these three event-table storage anchors are still unresolved.
  void* gWxEventTableRuntimeBridgeA[1] = {nullptr};
  void* gWxEventTableRuntimeBridgeB[1] = {nullptr};
  void* gWxEventTableRuntimeBridgeC[1] = {nullptr};
  void* gWxEventTableRuntimeBridgeD = nullptr;
  void* gWxEventTableRuntimeBridgeE = nullptr;
  void* gWxEventTableRuntimeBridgeF = nullptr;
  void* gWxEventTableRuntimeBridgeG = nullptr;
  void* gWxEventTableRuntimeBridgeH = nullptr;
  void** gWxEventTableRuntimeBridgeI = nullptr;

  struct WxEventTableRuntimeAnchor
  {
    void* lane00 = nullptr;
  };

  WxEventTableRuntimeAnchor gWxEventTableRuntimeAnchorA{};
  WxEventTableRuntimeAnchor gWxEventTableRuntimeAnchorB{};


} // namespace

/**
 * Address: 0x009D2570 (FUN_009D2570)
 * Mangled: ??0wxBrushRefData@@QAE@ABVwxColour@@H@Z
 *
 * What it does:
 * Seeds a one-owner ref count, stores the requested style and colour, and
 * leaves the stipple bitmap ("null", default-constructed) and native handle
 * empty - matching the binary body field for field.
 */
wxBrushRefDataRuntimeObject::wxBrushRefDataRuntimeObject(
  const wxColourRuntimeObject& colour,
  const std::int32_t style
) noexcept
  : mStyle(style)
  , mColour(colour)
{}

/**
 * Address: 0x009C8760 (FUN_009C8760)
 * Mangled: ??0wxBrush@@QAE@@Z
 *
 * What it does:
 * Default-constructs an empty ("null") brush: no ref-data, not visible.
 */
wxBrushRuntimeObject::wxBrushRuntimeObject() noexcept = default;

/**
 * Address: 0x009D2860 (FUN_009D2860)
 * Mangled: ??0wxBrush@@QAE@ABV0@@Z
 *
 * What it does:
 * Shares the source brush's ref-data (`wxObject::Ref`): points at the same
 * payload and bumps its ref count, matching the binary's
 * `wxObject::Ref(this, a2)` tail call.
 */
wxBrushRuntimeObject::wxBrushRuntimeObject(const wxBrushRuntimeObject& other) noexcept
{
  mRefData = other.mRefData;
  if (auto* const refData = static_cast<wxBrushRefDataRuntimeObject*>(mRefData)) {
    refData->AddRef();
  }
}

/**
 * Address: 0x009D2880 (FUN_009D2880)
 * Mangled: ??0wxBrush@@QAE@ABVwxColour@@H@Z
 *
 * What it does:
 * Allocates a fresh, single-owner `wxBrushRefData` for the given
 * colour/style pair, matching `operator new(0x2Cu)` plus the ref-data
 * constructor in the binary.
 */
wxBrushRuntimeObject::wxBrushRuntimeObject(
  const wxColourRuntimeObject& colour,
  const std::int32_t style
)
{
  mRefData = new wxBrushRefDataRuntimeObject(colour, style);
}

/**
 * Address: 0x009D2910 (FUN_009D2910)
 * Mangled: ??1wxBrush@@QAE@XZ
 *
 * What it does:
 * Drops this instance's share of the ref-data (`wxEvent::UnRef`), freeing
 * the shared payload once nothing references it any more.
 */
wxBrushRuntimeObject::~wxBrushRuntimeObject()
{
  if (auto* const refData = static_cast<wxBrushRefDataRuntimeObject*>(mRefData)) {
    if (refData->ReleaseRef()) {
      delete refData;
    }
    mRefData = nullptr;
  }
}

/**
 * Address: 0x009EB0F0 (FUN_009EB0F0)
 * Mangled: ??0wxPenRefData@@QAE@XZ
 *
 * What it does:
 * Seeds a one-owner ref count and wx's default pen description, writing every
 * field the binary writes: width 1 (+0x08), `wxSOLID` (+0x0C), `wxJOIN_ROUND`
 * (+0x10), `wxCAP_ROUND` (+0x14), an empty dash array (+0x24/+0x28) and a null
 * native handle (+0x3C). The stipple bitmap (+0x18) and colour (+0x2C) are
 * default-constructed in place, matching the two embedded constructor calls.
 */
wxPenRefDataRuntimeObject::wxPenRefDataRuntimeObject() noexcept = default;

/**
 * Address: 0x009EB2A0 (FUN_009EB2A0)
 * Mangled: ??0wxPen@@QAE@@Z
 *
 * What it does:
 * Default-constructs an empty ("null") pen: no ref-data, not visible.
 */
wxPenRuntimeObject::wxPenRuntimeObject() noexcept = default;

/**
 * Address: 0x009EB8D0 (FUN_009EB8D0)
 * Mangled: ??0wxPen@@QAE@ABVwxColour@@HH@Z
 *
 * IDA signature:
 * wxPen *__thiscall wxPen::wxPen(wxPen *this, const wxColour *col, int Width, int Style);
 *
 * What it does:
 * Allocates a fresh, single-owner `wxPenRefData` (`operator new(0x40u)` then
 * the ref-data constructor), stores the requested colour, width and style over
 * its defaults, then applies wx's Win32S guard: that platform cannot draw a
 * dashed pen wider than one unit, so any of `wxDOT`/`wxLONG_DASH`/
 * `wxSHORT_DASH`/`wxDOT_DASH`/`wxUSER_DASH` is clamped back to width 1. The
 * binary compares `wxGetOsVersion()` against 0x13 for exactly this test and
 * matches dependencies/wxWindows-2.4.2/src/msw/pen.cpp:78-112.
 *
 * The trailing `RealizeResource()` is the binary's `call 0x009EB630`
 * (`wxPen::Create`, this class's slot-4 override). That override is not
 * recovered yet, so the call currently reaches `wxGDIObject`'s base answer of
 * "no realizable native resource" and no HPEN is produced; the pen's
 * description is still correct and shared. Its return value is discarded here
 * because the binary discards it too - it returns `this`, never the flag.
 */
wxPenRuntimeObject::wxPenRuntimeObject(
  const wxColourRuntimeObject& colour,
  const std::int32_t width,
  const std::int32_t style
)
{
  auto* const refData = new wxPenRefDataRuntimeObject();
  refData->SetColour(colour);
  refData->SetWidth(width);
  refData->SetStyle(style);
  mRefData = refData;

  const bool isDashedStyle = style == kWxStyleDot || style == kWxStyleLongDash
                          || style == kWxStyleShortDash || style == kWxStyleDotDash
                          || style == kWxStyleUserDash;
  if (wxGetOsVersion(nullptr, nullptr) == kWxPlatformWin32s && isDashedStyle) {
    refData->SetWidth(1);
  }

  (void)RealizeResource();
}

/**
 * Address: 0x009EB2E0 (FUN_009EB2E0)
 * Mangled: ??1wxPen@@QAE@XZ
 *
 * What it does:
 * Drops this instance's share of the ref-data, freeing the shared payload once
 * nothing references it any more. The binary stamps the `wxGDIObject` vtable
 * back down and tail-jumps to the shared unref lane; the base's
 * `ReleaseRefData` only clears the pointer, so - exactly as
 * `~wxBrushRuntimeObject` does - the typed release belongs here.
 */
wxPenRuntimeObject::~wxPenRuntimeObject()
{
  if (auto* const refData = static_cast<wxPenRefDataRuntimeObject*>(mRefData)) {
    if (refData->ReleaseRef()) {
      delete refData;
    }
    mRefData = nullptr;
  }
}
