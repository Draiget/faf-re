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
  [[maybe_unused]] void* wxGetFontListClassInfoRuntime() noexcept
  {
    return gWxFontListClassInfoTable;
  }

  /**
   * Address: 0x009BC590 (FUN_009BC590)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxResourceCache::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetResourceCacheClassInfoRuntime() noexcept
  {
    return gWxResourceCacheClassInfoTable;
  }

  /**
   * Address: 0x009BC9C0 (FUN_009BC9C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxColourDatabase::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetColourDatabaseClassInfoRuntime() noexcept
  {
    return gWxColourDatabaseClassInfoTable;
  }

  /**
   * Address: 0x009BCE60 (FUN_009BCE60)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxBitmapList::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetBitmapListClassInfoRuntime() noexcept
  {
    return gWxBitmapListClassInfoTable;
  }

  /**
   * Address: 0x009BF1E0 (FUN_009BF1E0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxLocaleModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetLocaleModuleClassInfoRuntime() noexcept
  {
    return gWxLocaleModuleClassInfoTable;
  }

  /**
   * Address: 0x009C5ED0 (FUN_009C5ED0)
   *
   * What it does:
   * Returns one runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeA() noexcept
  {
    return gWxEventTableRuntimeBridgeA;
  }

  /**
   * Address: 0x009C62F0 (FUN_009C62F0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxHelpProviderModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetHelpProviderModuleClassInfoRuntime() noexcept
  {
    return gWxHelpProviderModuleClassInfoTable;
  }

  /**
   * Address: 0x009C6380 (FUN_009C6380)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxContextHelp::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetContextHelpClassInfoRuntime() noexcept
  {
    return gWxContextHelpClassInfoTable;
  }

  /**
   * Address: 0x009C65C0 (FUN_009C65C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxContextHelpButton::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetContextHelpButtonClassInfoRuntime() noexcept
  {
    return gWxContextHelpButtonClassInfoTable;
  }

  /**
   * Address: 0x009C6940 (FUN_009C6940)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxSystemSettingsModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetSystemSettingsModuleClassInfoRuntime() noexcept
  {
    return gWxSystemSettingsModuleClassInfoTable;
  }

  /**
   * Address: 0x009C87C0 (FUN_009C87C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxBrush::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetBrushClassInfoRuntime() noexcept
  {
    return gWxBrushClassInfoTable;
  }

  /**
   * Address: 0x009C89A0 (FUN_009C89A0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDCBase::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetDcBaseClassInfoRuntime() noexcept
  {
    return gWxDcBaseClassInfoTable;
  }

  /**
   * Address: 0x009CA320 (FUN_009CA320)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDCModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetDcModuleClassInfoRuntime() noexcept
  {
    return gWxDcModuleClassInfoTable;
  }

  /**
   * Address: 0x009CBB80 (FUN_009CBB80)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxToolTip::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetToolTipClassInfoRuntime() noexcept
  {
    return gWxToolTipClassInfoTable;
  }

  /**
   * Address: 0x009CBFD0 (FUN_009CBFD0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxIndividualLayoutConstraint::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetIndividualLayoutConstraintClassInfoRuntime() noexcept
  {
    return gWxIndividualLayoutConstraintClassInfoTable;
  }

  /**
   * Address: 0x009CC470 (FUN_009CC470)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxLayoutConstraints::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetLayoutConstraintsClassInfoRuntime() noexcept
  {
    return gWxLayoutConstraintsClassInfoTable;
  }

  /**
   * Address: 0x009CE990 (FUN_009CE990)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFontDialog::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetFontDialogClassInfoRuntime() noexcept
  {
    return gWxFontDialogClassInfoTable;
  }

  /**
   * Address: 0x009D1930 (FUN_009D1930)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxHashTable::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetHashTableClassInfoRuntime() noexcept
  {
    return gWxHashTableClassInfoTable;
  }

  /**
   * Address: 0x009D2460 (FUN_009D2460)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPopupWindow::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetPopupWindowClassInfoRuntime() noexcept
  {
    return gWxPopupWindowClassInfoTable;
  }

  /**
   * Address: 0x009D3700 (FUN_009D3700)
   *
   * What it does:
   * Returns one runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeB() noexcept
  {
    return gWxEventTableRuntimeBridgeB;
  }

  /**
   * Address: 0x009D3D40 (FUN_009D3D40)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxSpinCtrl::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetSpinCtrlClassInfoRuntime() noexcept
  {
    return gWxSpinCtrlClassInfoTable;
  }

  /**
   * Address: 0x009D4610 (FUN_009D4610)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxMemoryDC::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetMemoryDcClassInfoRuntime() noexcept
  {
    return gWxMemoryDcClassInfoTable;
  }

  /**
   * Address: 0x009D5910 (FUN_009D5910)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFontMapperModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetFontMapperModuleClassInfoRuntime() noexcept
  {
    return gWxFontMapperModuleClassInfoTable;
  }

  /**
   * Address: 0x009D6CA0 (FUN_009D6CA0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFontData::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetFontDataClassInfoRuntime() noexcept
  {
    return gWxFontDataClassInfoTable;
  }

  /**
   * Address: 0x009D7E90 (FUN_009D7E90)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxICOHandler::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetIcoHandlerClassInfoRuntime() noexcept
  {
    return gWxIcoHandlerClassInfoTable;
  }

  /**
   * Address: 0x009D7F30 (FUN_009D7F30)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxCURHandler::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetCurHandlerClassInfoRuntime() noexcept
  {
    return gWxCurHandlerClassInfoTable;
  }

  /**
   * Address: 0x009D7FE0 (FUN_009D7FE0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxANIHandler::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetAniHandlerClassInfoRuntime() noexcept
  {
    return gWxAniHandlerClassInfoTable;
  }

  /**
   * Address: 0x009DDD20 (FUN_009DDD20)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPathList::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetPathListClassInfoRuntime() noexcept
  {
    return gWxPathListClassInfoTable;
  }

  /**
   * Address: 0x009EB2C0 (FUN_009EB2C0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPen::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetPenClassInfoRuntime() noexcept
  {
    return gWxPenClassInfoTable;
  }

  /**
   * Address: 0x009ED2D0 (FUN_009ED2D0)
   *
   * What it does:
   * Returns one runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeC() noexcept
  {
    return gWxEventTableRuntimeBridgeC;
  }

  /**
   * Address: 0x009EDF40 (FUN_009EDF40)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxSpinEvent::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetSpinEventClassInfoRuntime() noexcept
  {
    return gWxSpinEventClassInfoTable;
  }

  /**
   * Address: 0x009EE860 (FUN_009EE860)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxListBox::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetListBoxClassInfoRuntime() noexcept
  {
    return gWxListBoxClassInfoTable;
  }

  /**
   * Address: 0x009F2400 (FUN_009F2400)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxTimerEvent::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetTimerEventClassInfoRuntime() noexcept
  {
    return gWxTimerEventClassInfoTable;
  }

  /**
   * Address: 0x009F2C70 (FUN_009F2C70)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxScreenDC::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetScreenDcClassInfoRuntime() noexcept
  {
    return gWxScreenDcClassInfoTable;
  }

  /**
   * Address: 0x009FB6F0 (FUN_009FB6F0)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeD() noexcept
  {
    return &gWxEventTableRuntimeBridgeD;
  }

  /**
   * Address: 0x009FB700 (FUN_009FB700)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeE() noexcept
  {
    return &gWxEventTableRuntimeBridgeE;
  }

  /**
   * Address: 0x009FB710 (FUN_009FB710)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeF() noexcept
  {
    return &gWxEventTableRuntimeBridgeF;
  }

  /**
   * Address: 0x009FB750 (FUN_009FB750)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxMDIParentFrame::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetMdiParentFrameClassInfoRuntime() noexcept
  {
    return gWxMdiParentFrameClassInfoTable;
  }

  /**
   * Address: 0x009FD9A0 (FUN_009FD9A0)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeG() noexcept
  {
    return &gWxEventTableRuntimeBridgeG;
  }

  /**
   * Address: 0x009FE780 (FUN_009FE780)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDragImage::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetDragImageClassInfoRuntime() noexcept
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
  [[maybe_unused]] void* wxGetMswSystemMenuFontModuleClassInfoRuntime() noexcept
  {
    return gWxMswSystemMenuFontModuleClassInfoTable;
  }

  /**
   * Address: 0x00A045B0 (FUN_00A045B0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxRadioBox::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetRadioBoxClassInfoRuntime() noexcept
  {
    return gWxRadioBoxClassInfoTable;
  }

  /**
   * Address: 0x00A05D20 (FUN_00A05D20)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxStaticLine::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetStaticLineClassInfoRuntime() noexcept
  {
    return gWxStaticLineClassInfoTable;
  }

  /**
   * Address: 0x00A061D0 (FUN_00A061D0)
   *
   * What it does:
   * Returns one additional runtime event-table storage anchor.
   */
  [[maybe_unused]] void** wxGetEventTableRuntimeBridgeH() noexcept
  {
    return &gWxEventTableRuntimeBridgeH;
  }

  /**
   * Address: 0x00A064F0 (FUN_00A064F0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxToolBarBase::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetToolBarBaseClassInfoRuntime() noexcept
  {
    return gWxToolBarBaseClassInfoTable;
  }

  /**
   * Address: 0x00A07570 (FUN_00A07570)
   *
   * What it does:
   * Returns one third-level runtime event-table storage anchor.
   */
  [[maybe_unused]] void*** wxGetEventTableRuntimeBridgeI() noexcept
  {
    return &gWxEventTableRuntimeBridgeI;
  }

  /**
   * Address: 0x00A0A730 (FUN_00A0A730)
   *
   * What it does:
   * Returns one runtime event-table anchor object.
   */
  [[maybe_unused]] void* wxGetEventTableRuntimeAnchorA() noexcept
  {
    return &gWxEventTableRuntimeAnchorA;
  }

  /**
   * Address: 0x00A0AB40 (FUN_00A0AB40)
   *
   * What it does:
   * Returns one runtime event-table anchor object.
   */
  [[maybe_unused]] void* wxGetEventTableRuntimeAnchorB() noexcept
  {
    return &gWxEventTableRuntimeAnchorB;
  }

  /**
   * Address: 0x00A0D670 (FUN_00A0D670)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxEnhMetaFile::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetEnhMetaFileClassInfoRuntime() noexcept
  {
    return gWxEnhMetaFileClassInfoTable;
  }

  /**
   * Address: 0x00A0DB40 (FUN_00A0DB40)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxClipboard::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetClipboardClassInfoRuntime() noexcept
  {
    return gWxClipboardClassInfoTable;
  }

  /**
   * Address: 0x00A0E420 (FUN_00A0E420)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxFileProto::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetFileProtoClassInfoRuntime() noexcept
  {
    return gWxFileProtoClassInfoTable;
  }

  /**
   * Address: 0x00A30C30 (FUN_00A30C30)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxServerBase::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetServerBaseClassInfoRuntime() noexcept
  {
    return gWxServerBaseClassInfoTable;
  }

  /**
   * Address: 0x00A30C90 (FUN_00A30C90)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxClientBase::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetClientBaseClassInfoRuntime() noexcept
  {
    return gWxClientBaseClassInfoTable;
  }

  /**
   * Address: 0x00A30D30 (FUN_00A30D30)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetDdeModuleClassInfoRuntime() noexcept
  {
    return gWxDdeModuleClassInfoTable;
  }

  /**
   * Address: 0x00A30EA0 (FUN_00A30EA0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEConnection::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetDdeConnectionClassInfoRuntime() noexcept
  {
    return gWxDdeConnectionClassInfoTable;
  }

  /**
   * Address: 0x00A31120 (FUN_00A31120)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEClient::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetDdeClientClassInfoRuntime() noexcept
  {
    return gWxDdeClientClassInfoTable;
  }

  /**
   * Address: 0x00A31C70 (FUN_00A31C70)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxDDEServer::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetDdeServerClassInfoRuntime() noexcept
  {
    return gWxDdeServerClassInfoTable;
  }

  /**
   * Address: 0x00A32BA0 (FUN_00A32BA0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPrintPaperType::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetPrintPaperTypeClassInfoRuntime() noexcept
  {
    return gWxPrintPaperTypeClassInfoTable;
  }

  /**
   * Address: 0x00A32D10 (FUN_00A32D10)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPrintPaperDatabase::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetPrintPaperDatabaseClassInfoRuntime() noexcept
  {
    return gWxPrintPaperDatabaseClassInfoTable;
  }

  /**
   * Address: 0x00A32E70 (FUN_00A32E70)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxPrintPaperModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetPrintPaperModuleClassInfoRuntime() noexcept
  {
    return gWxPrintPaperModuleClassInfoTable;
  }

  /**
   * Address: 0x00A37EF0 (FUN_00A37EF0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxClipboardModule::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetClipboardModuleClassInfoRuntime() noexcept
  {
    return gWxClipboardModuleClassInfoTable;
  }

  /**
   * Address: 0x00A383E0 (FUN_00A383E0)
   *
   * What it does:
   * Returns the runtime class-info storage for `wxConnectionBase::sm_classInfo`.
   */
  [[maybe_unused]] void* wxGetConnectionBaseClassInfoRuntime() noexcept
  {
    return gWxConnectionBaseClassInfoTable;
  }
} // namespace
