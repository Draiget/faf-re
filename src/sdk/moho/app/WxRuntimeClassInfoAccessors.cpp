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

  /**
   * Address: 0x009BC560 (FUN_009BC560)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFontList::sm_classInfo`.
   */
  void* wxGetFontListClassInfoRuntime() noexcept
  {
    return gWxFontListClassInfoTable;
  }

  /**
   * Address: 0x009BC590 (FUN_009BC590)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxResourceCache::sm_classInfo`.
   */
  void* wxGetResourceCacheClassInfoRuntime() noexcept
  {
    return gWxResourceCacheClassInfoTable;
  }

  /**
   * Address: 0x009BC9C0 (FUN_009BC9C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxColourDatabase::sm_classInfo`.
   */
  void* wxGetColourDatabaseClassInfoRuntime() noexcept
  {
    return gWxColourDatabaseClassInfoTable;
  }

  /**
   * Address: 0x009BCE60 (FUN_009BCE60)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxBitmapList::sm_classInfo`.
   */
  void* wxGetBitmapListClassInfoRuntime() noexcept
  {
    return gWxBitmapListClassInfoTable;
  }

  /**
   * Address: 0x009BF1E0 (FUN_009BF1E0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxLocaleModule::sm_classInfo`.
   */
  void* wxGetLocaleModuleClassInfoRuntime() noexcept
  {
    return gWxLocaleModuleClassInfoTable;
  }

  /**
   * Address: 0x009C5ED0 (FUN_009C5ED0)
   *
   * What it does:
   * Returns one runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeA() noexcept
  {
    return gWxEventTableRuntimeBridgeA;
  }

  /**
   * Address: 0x009C62F0 (FUN_009C62F0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxHelpProviderModule::sm_classInfo`.
   */
  void* wxGetHelpProviderModuleClassInfoRuntime() noexcept
  {
    return gWxHelpProviderModuleClassInfoTable;
  }

  /**
   * Address: 0x009C6380 (FUN_009C6380)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxContextHelp::sm_classInfo`.
   */
  void* wxGetContextHelpClassInfoRuntime() noexcept
  {
    return gWxContextHelpClassInfoTable;
  }

  /**
   * Address: 0x009C65C0 (FUN_009C65C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxContextHelpButton::sm_classInfo`.
   */
  void* wxGetContextHelpButtonClassInfoRuntime() noexcept
  {
    return gWxContextHelpButtonClassInfoTable;
  }

  /**
   * Address: 0x009C6940 (FUN_009C6940)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxSystemSettingsModule::sm_classInfo`.
   */
  void* wxGetSystemSettingsModuleClassInfoRuntime() noexcept
  {
    return gWxSystemSettingsModuleClassInfoTable;
  }

  /**
   * Address: 0x009C87C0 (FUN_009C87C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxBrush::sm_classInfo`.
   */
  void* wxGetBrushClassInfoRuntime() noexcept
  {
    return gWxBrushClassInfoTable;
  }

  /**
   * Address: 0x009C89A0 (FUN_009C89A0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDCBase::sm_classInfo`.
   */
  void* wxGetDcBaseClassInfoRuntime() noexcept
  {
    return gWxDcBaseClassInfoTable;
  }

  /**
   * Address: 0x009CA320 (FUN_009CA320)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDCModule::sm_classInfo`.
   */
  void* wxGetDcModuleClassInfoRuntime() noexcept
  {
    return gWxDcModuleClassInfoTable;
  }

  /**
   * Address: 0x009CBB80 (FUN_009CBB80)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxToolTip::sm_classInfo`.
   */
  void* wxGetToolTipClassInfoRuntime() noexcept
  {
    return gWxToolTipClassInfoTable;
  }

  /**
   * Address: 0x009CBFD0 (FUN_009CBFD0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxIndividualLayoutConstraint::sm_classInfo`.
   */
  void* wxGetIndividualLayoutConstraintClassInfoRuntime() noexcept
  {
    return gWxIndividualLayoutConstraintClassInfoTable;
  }

  /**
   * Address: 0x009CC470 (FUN_009CC470)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxLayoutConstraints::sm_classInfo`.
   */
  void* wxGetLayoutConstraintsClassInfoRuntime() noexcept
  {
    return gWxLayoutConstraintsClassInfoTable;
  }

  /**
   * Address: 0x009CE990 (FUN_009CE990)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFontDialog::sm_classInfo`.
   */
  void* wxGetFontDialogClassInfoRuntime() noexcept
  {
    return gWxFontDialogClassInfoTable;
  }

  /**
   * Address: 0x009D1930 (FUN_009D1930)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxHashTable::sm_classInfo`.
   */
  void* wxGetHashTableClassInfoRuntime() noexcept
  {
    return gWxHashTableClassInfoTable;
  }

  /**
   * Address: 0x009D2460 (FUN_009D2460)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPopupWindow::sm_classInfo`.
   */
  void* wxGetPopupWindowClassInfoRuntime() noexcept
  {
    return gWxPopupWindowClassInfoTable;
  }

  /**
   * Address: 0x009D3700 (FUN_009D3700)
   *
   * What it does:
   * Returns one runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeB() noexcept
  {
    return gWxEventTableRuntimeBridgeB;
  }

  /**
   * Address: 0x009D3D40 (FUN_009D3D40)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxSpinCtrl::sm_classInfo`.
   */
  void* wxGetSpinCtrlClassInfoRuntime() noexcept
  {
    return gWxSpinCtrlClassInfoTable;
  }

  /**
   * Address: 0x009D4610 (FUN_009D4610)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxMemoryDC::sm_classInfo`.
   */
  void* wxGetMemoryDcClassInfoRuntime() noexcept
  {
    return gWxMemoryDcClassInfoTable;
  }

  /**
   * Address: 0x009D5910 (FUN_009D5910)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFontMapperModule::sm_classInfo`.
   */
  void* wxGetFontMapperModuleClassInfoRuntime() noexcept
  {
    return gWxFontMapperModuleClassInfoTable;
  }

  /**
   * Address: 0x009D6CA0 (FUN_009D6CA0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFontData::sm_classInfo`.
   */
  void* wxGetFontDataClassInfoRuntime() noexcept
  {
    return gWxFontDataClassInfoTable;
  }

  /**
   * Address: 0x009D7E90 (FUN_009D7E90)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxICOHandler::sm_classInfo`.
   */
  void* wxGetIcoHandlerClassInfoRuntime() noexcept
  {
    return gWxIcoHandlerClassInfoTable;
  }

  /**
   * Address: 0x009D7F30 (FUN_009D7F30)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxCURHandler::sm_classInfo`.
   */
  void* wxGetCurHandlerClassInfoRuntime() noexcept
  {
    return gWxCurHandlerClassInfoTable;
  }

  /**
   * Address: 0x009D7FE0 (FUN_009D7FE0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxANIHandler::sm_classInfo`.
   */
  void* wxGetAniHandlerClassInfoRuntime() noexcept
  {
    return gWxAniHandlerClassInfoTable;
  }

  /**
   * Address: 0x009DDD20 (FUN_009DDD20)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPathList::sm_classInfo`.
   */
  void* wxGetPathListClassInfoRuntime() noexcept
  {
    return gWxPathListClassInfoTable;
  }

  /**
   * Address: 0x009EB2C0 (FUN_009EB2C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPen::sm_classInfo`.
   */
  void* wxGetPenClassInfoRuntime() noexcept
  {
    return gWxPenClassInfoTable;
  }

  /**
   * Address: 0x009ED2D0 (FUN_009ED2D0)
   *
   * What it does:
   * Returns one runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeC() noexcept
  {
    return gWxEventTableRuntimeBridgeC;
  }

  /**
   * Address: 0x009EDF40 (FUN_009EDF40)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxSpinEvent::sm_classInfo`.
   */
  void* wxGetSpinEventClassInfoRuntime() noexcept
  {
    return gWxSpinEventClassInfoTable;
  }

  /**
   * Address: 0x009EE860 (FUN_009EE860)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxListBox::sm_classInfo`.
   */
  void* wxGetListBoxClassInfoRuntime() noexcept
  {
    return gWxListBoxClassInfoTable;
  }

  /**
   * Address: 0x009F2400 (FUN_009F2400)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxTimerEvent::sm_classInfo`.
   */
  void* wxGetTimerEventClassInfoRuntime() noexcept
  {
    return gWxTimerEventClassInfoTable;
  }

  /**
   * Address: 0x009F2C70 (FUN_009F2C70)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxScreenDC::sm_classInfo`.
   */
  void* wxGetScreenDcClassInfoRuntime() noexcept
  {
    return gWxScreenDcClassInfoTable;
  }

  /**
   * Address: 0x009FB6F0 (FUN_009FB6F0)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeD() noexcept
  {
    return &gWxEventTableRuntimeBridgeD;
  }

  /**
   * Address: 0x009FB700 (FUN_009FB700)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeE() noexcept
  {
    return &gWxEventTableRuntimeBridgeE;
  }

  /**
   * Address: 0x009FB710 (FUN_009FB710)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeF() noexcept
  {
    return &gWxEventTableRuntimeBridgeF;
  }

  /**
   * Address: 0x009FB750 (FUN_009FB750)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxMDIParentFrame::sm_classInfo`.
   */
  void* wxGetMdiParentFrameClassInfoRuntime() noexcept
  {
    return gWxMdiParentFrameClassInfoTable;
  }

  /**
   * Address: 0x009FD9A0 (FUN_009FD9A0)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeG() noexcept
  {
    return &gWxEventTableRuntimeBridgeG;
  }

  /**
   * Address: 0x009FE780 (FUN_009FE780)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDragImage::sm_classInfo`.
   */
  void* wxGetDragImageClassInfoRuntime() noexcept
  {
    return gWxDragImageClassInfoTable;
  }

  /**
   * Address: 0x00A02FA0 (FUN_00A02FA0)
   *
   * What it does:
   * Returns the runtime class-info storage for
   * `wxMSWSystemMenuFontModule::sm_classInfo`.
   */
  void* wxGetMswSystemMenuFontModuleClassInfoRuntime() noexcept
  {
    return gWxMswSystemMenuFontModuleClassInfoTable;
  }

  /**
   * Address: 0x00A045B0 (FUN_00A045B0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxRadioBox::sm_classInfo`.
   */
  void* wxGetRadioBoxClassInfoRuntime() noexcept
  {
    return gWxRadioBoxClassInfoTable;
  }

  /**
   * Address: 0x00A05D20 (FUN_00A05D20)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxStaticLine::sm_classInfo`.
   */
  void* wxGetStaticLineClassInfoRuntime() noexcept
  {
    return gWxStaticLineClassInfoTable;
  }

  /**
   * Address: 0x00A061D0 (FUN_00A061D0)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  void** wxGetEventTableRuntimeBridgeH() noexcept
  {
    return &gWxEventTableRuntimeBridgeH;
  }

  /**
   * Address: 0x00A064F0 (FUN_00A064F0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxToolBarBase::sm_classInfo`.
   */
  void* wxGetToolBarBaseClassInfoRuntime() noexcept
  {
    return gWxToolBarBaseClassInfoTable;
  }

  /**
   * Address: 0x00A07570 (FUN_00A07570)
   *
   * What it does:
   * Returns one third-level runtime event-table storage anchor.
   */
  void*** wxGetEventTableRuntimeBridgeI() noexcept
  {
    return &gWxEventTableRuntimeBridgeI;
  }

  /**
   * Address: 0x00A0A730 (FUN_00A0A730)
   *
   * What it does:
   * Returns one runtime event-table anchor object.
   */
  void* wxGetEventTableRuntimeAnchorA() noexcept
  {
    return &gWxEventTableRuntimeAnchorA;
  }

  /**
   * Address: 0x00A0AB40 (FUN_00A0AB40)
   *
   * What it does:
   * Returns one runtime event-table anchor object.
   */
  void* wxGetEventTableRuntimeAnchorB() noexcept
  {
    return &gWxEventTableRuntimeAnchorB;
  }

  /**
   * Address: 0x00A0D670 (FUN_00A0D670)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxEnhMetaFile::sm_classInfo`.
   */
  void* wxGetEnhMetaFileClassInfoRuntime() noexcept
  {
    return gWxEnhMetaFileClassInfoTable;
  }

  /**
   * Address: 0x00A0DB40 (FUN_00A0DB40)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxClipboard::sm_classInfo`.
   */
  void* wxGetClipboardClassInfoRuntime() noexcept
  {
    return gWxClipboardClassInfoTable;
  }

  /**
   * Address: 0x00A0E420 (FUN_00A0E420)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFileProto::sm_classInfo`.
   */
  void* wxGetFileProtoClassInfoRuntime() noexcept
  {
    return gWxFileProtoClassInfoTable;
  }

  /**
   * Address: 0x00A30C30 (FUN_00A30C30)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxServerBase::sm_classInfo`.
   */
  void* wxGetServerBaseClassInfoRuntime() noexcept
  {
    return gWxServerBaseClassInfoTable;
  }

  /**
   * Address: 0x00A30C90 (FUN_00A30C90)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxClientBase::sm_classInfo`.
   */
  void* wxGetClientBaseClassInfoRuntime() noexcept
  {
    return gWxClientBaseClassInfoTable;
  }

  /**
   * Address: 0x00A30D30 (FUN_00A30D30)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEModule::sm_classInfo`.
   */
  void* wxGetDdeModuleClassInfoRuntime() noexcept
  {
    return gWxDdeModuleClassInfoTable;
  }

  /**
   * Address: 0x00A30EA0 (FUN_00A30EA0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEConnection::sm_classInfo`.
   */
  void* wxGetDdeConnectionClassInfoRuntime() noexcept
  {
    return gWxDdeConnectionClassInfoTable;
  }

  /**
   * Address: 0x00A31120 (FUN_00A31120)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEClient::sm_classInfo`.
   */
  void* wxGetDdeClientClassInfoRuntime() noexcept
  {
    return gWxDdeClientClassInfoTable;
  }

  /**
   * Address: 0x00A31C70 (FUN_00A31C70)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEServer::sm_classInfo`.
   */
  void* wxGetDdeServerClassInfoRuntime() noexcept
  {
    return gWxDdeServerClassInfoTable;
  }

  /**
   * Address: 0x00A32BA0 (FUN_00A32BA0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPrintPaperType::sm_classInfo`.
   */
  void* wxGetPrintPaperTypeClassInfoRuntime() noexcept
  {
    return gWxPrintPaperTypeClassInfoTable;
  }

  /**
   * Address: 0x00A32D10 (FUN_00A32D10)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPrintPaperDatabase::sm_classInfo`.
   */
  void* wxGetPrintPaperDatabaseClassInfoRuntime() noexcept
  {
    return gWxPrintPaperDatabaseClassInfoTable;
  }

  /**
   * Address: 0x00A32E70 (FUN_00A32E70)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPrintPaperModule::sm_classInfo`.
   */
  void* wxGetPrintPaperModuleClassInfoRuntime() noexcept
  {
    return gWxPrintPaperModuleClassInfoTable;
  }

  /**
   * Address: 0x00A37EF0 (FUN_00A37EF0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxClipboardModule::sm_classInfo`.
   */
  void* wxGetClipboardModuleClassInfoRuntime() noexcept
  {
    return gWxClipboardModuleClassInfoTable;
  }

  /**
   * Address: 0x00A383E0 (FUN_00A383E0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxConnectionBase::sm_classInfo`.
   */
  void* wxGetConnectionBaseClassInfoRuntime() noexcept
  {
    return gWxConnectionBaseClassInfoTable;
  }
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
