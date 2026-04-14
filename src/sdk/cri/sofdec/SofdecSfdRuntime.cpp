  struct SofdecHeaderAnalyzerRuntimeView
  {
    std::int32_t state = 0;          // +0x00
    std::int32_t bufferAddress = 0;  // +0x04
    std::int32_t remainingBytes = 0; // +0x08
    std::int32_t version = 0;        // +0x0C
  };
  static_assert(offsetof(SofdecHeaderAnalyzerRuntimeView, state) == 0x00, "SofdecHeaderAnalyzerRuntimeView::state offset must be 0x00");
  static_assert(offsetof(SofdecHeaderAnalyzerRuntimeView, bufferAddress) == 0x04, "SofdecHeaderAnalyzerRuntimeView::bufferAddress offset must be 0x04");
  static_assert(
    offsetof(SofdecHeaderAnalyzerRuntimeView, remainingBytes) == 0x08,
    "SofdecHeaderAnalyzerRuntimeView::remainingBytes offset must be 0x08"
  );
  static_assert(offsetof(SofdecHeaderAnalyzerRuntimeView, version) == 0x0C, "SofdecHeaderAnalyzerRuntimeView::version offset must be 0x0C");
  static_assert(sizeof(SofdecHeaderAnalyzerRuntimeView) == 0x10, "SofdecHeaderAnalyzerRuntimeView size must be 0x10");

  struct SofdecHeaderAnalyzerPoolState
  {
    std::int32_t size = 0;                                  // +0x00
    std::int32_t cur = 0;                                   // +0x04
    SofdecHeaderAnalyzerRuntimeView* ptr = nullptr;         // +0x08
  };
  static_assert(offsetof(SofdecHeaderAnalyzerPoolState, size) == 0x00, "SofdecHeaderAnalyzerPoolState::size offset must be 0x00");
  static_assert(offsetof(SofdecHeaderAnalyzerPoolState, cur) == 0x04, "SofdecHeaderAnalyzerPoolState::cur offset must be 0x04");
  static_assert(offsetof(SofdecHeaderAnalyzerPoolState, ptr) == 0x08, "SofdecHeaderAnalyzerPoolState::ptr offset must be 0x08");
  static_assert(sizeof(SofdecHeaderAnalyzerPoolState) == 0x0C, "SofdecHeaderAnalyzerPoolState size must be 0x0C");

  extern "C" SofdecHeaderAnalyzerPoolState sfh_workinfo;
  /**
   * Address: 0x00ADC800 (FUN_00ADC800, func_SofDec_InitSfhWork)
   *
   * What it does:
   * Initializes one SFH pool-state descriptor with slot count, zero cursor,
   * and backing slot-array pointer.
   */
  extern "C" SofdecHeaderAnalyzerPoolState* func_SofDec_InitSfhWork(
    SofdecHeaderAnalyzerPoolState* const poolState,
    const std::int32_t slotCount,
    SofdecHeaderAnalyzerRuntimeView* const slotArray
  )
  {
    poolState->size = slotCount;
    poolState->cur = 0;
    poolState->ptr = slotArray;
    return poolState;
  }

  /**
   * Address: 0x00ADC840 (FUN_00ADC840, func_SofDec_InitSfhObj)
   *
   * What it does:
   * Marks one SFH analyzer slot as active and binds `(bufferAddress,
   * remainingBytes)` to that slot.
   */
  extern "C" SofdecHeaderAnalyzerRuntimeView* func_SofDec_InitSfhObj(
    SofdecHeaderAnalyzerRuntimeView* const handle,
    const std::int32_t bufferAddress,
    const std::int32_t remainingBytes
  )
  {
    handle->state = 1;
    handle->bufferAddress = bufferAddress;
    handle->remainingBytes = remainingBytes;
    return handle;
  }

  /**
   * Address: 0x00ADC880 (FUN_00ADC880, func_SofDec_Unk5Unused)
   *
   * What it does:
   * Reports whether one SFH analyzer slot is still idle.
   */
  extern "C" std::int32_t func_SofDec_Unk5Unused(SofdecHeaderAnalyzerRuntimeView* handle);

  /**
   * Address: 0x00ADC760 (FUN_00ADC760, _SFH_Create)
   *
   * What it does:
   * Returns one header-analyzer slot from the global SFH pool, initializes it
   * for `(bufferAddress, remainingBytes)`, and increments the active slot
   * counter.
   */
  extern "C" SofdecHeaderAnalyzerRuntimeView*
  SFH_Create(const std::int32_t bufferAddress, const std::int32_t remainingBytes)
  {
    SofdecHeaderAnalyzerRuntimeView* selectedSlot = nullptr;
    const std::int32_t poolSize = sfh_workinfo.size;
    if (sfh_workinfo.cur >= poolSize) {
      return nullptr;
    }

    if (poolSize > 0) {
      SofdecHeaderAnalyzerRuntimeView* slot = sfh_workinfo.ptr;
      std::int32_t index = 0;
      do {
        selectedSlot = slot;
        if (func_SofDec_Unk5Unused(slot) != 0) {
          break;
        }
        ++index;
        ++slot;
      } while (index < poolSize);
    }

    func_SofDec_InitSfhObj(selectedSlot, bufferAddress, remainingBytes);
    ++sfh_workinfo.cur;
    return selectedSlot;
  }

  /**
   * Address: 0x00ADC820 (FUN_00ADC820, _initSfhObj)
   *
   * What it does:
   * Resets one SFH analyzer slot to the idle zeroed state.
   */
  extern "C" void initSfhObj(SofdecHeaderAnalyzerRuntimeView* const handle)
  {
    handle->state = 0;
    handle->bufferAddress = 0;
    handle->remainingBytes = 0;
    handle->version = 0;
  }

  /**
   * Address: 0x00ADC880 (FUN_00ADC880, func_SofDec_Unk5Unused)
   *
   * What it does:
   * Reports whether one SFH analyzer slot is still idle.
   */
  extern "C" std::int32_t func_SofDec_Unk5Unused(SofdecHeaderAnalyzerRuntimeView* const handle)
  {
    return handle->state == 0 ? 1 : 0;
  }

  /**
   * Address: 0x00ADC860 (FUN_00ADC860, func_SofDef_InitAllUnk5)
   *
   * What it does:
   * Reinitializes each SFH analyzer slot in one contiguous slot array.
   */
  extern "C" void func_SofDef_InitAllUnk5(
    std::int32_t slotCount,
    SofdecHeaderAnalyzerRuntimeView* slotArray
  )
  {
    while (slotCount > 0) {
      initSfhObj(slotArray);
      ++slotArray;
      --slotCount;
    }
  }

  /**
   * Address: 0x00ADCDC0 (FUN_00ADCDC0, _convAsciiToDigit)
   *
   * What it does:
   * Parses one ASCII decimal lane from `text` until one non-digit delimiter and
   * writes the parsed value to `outValue`; returns first non-digit cursor.
   */
  extern "C" const char* convAsciiToDigit(const char* text, std::uint32_t* outValue)
  {
    std::uint32_t value = 0;
    const char* cursor = text;
    while (*cursor >= '0' && *cursor <= '9') {
      value = (value * 10u) + static_cast<std::uint32_t>(*cursor - '0');
      ++cursor;
    }

    *outValue = value;
    return cursor;
  }

  /**
   * Address: 0x00ADCD80 (FUN_00ADCD80, _getToolVer)
   *
   * What it does:
   * Finds `Ver.` in one Sofdec banner string, parses major/minor decimal lanes,
   * and returns `1` on success (`0` when tag is missing).
   */
  extern "C" std::int32_t getToolVer(char* text, std::uint32_t* major, std::uint32_t* minor)
  {
    if (text == nullptr || major == nullptr || minor == nullptr) {
      return 0;
    }

    char* versionTag = text;
    while (*versionTag != '\0') {
      if (versionTag[0] == 'V' && versionTag[1] == 'e' && versionTag[2] == 'r' && versionTag[3] == '.') {
        break;
      }
      ++versionTag;
    }

    if (*versionTag == '\0') {
      return 0;
    }

    const char* const afterMajor = convAsciiToDigit(versionTag + 4, major);
    (void)convAsciiToDigit((*afterMajor == '.') ? (afterMajor + 1) : afterMajor, minor);
    return 1;
  }

  /**
   * Address: 0x00ADD870 (FUN_00ADD870, _chkStmId)
   *
   * What it does:
   * Classifies one stream-id byte into known stream-class roots used by SFD
   * header-analysis dispatch.
   */
  extern "C" std::int32_t chkStmId(const std::uint32_t streamId)
  {
    if (streamId >= 0xC0u && streamId <= 0xDFu) {
      return 0xC0;
    }
    if (streamId >= 0xE0u && streamId <= 0xEFu) {
      return 0xE0;
    }
    if (streamId == 0xBDu || streamId == 0xBFu) {
      return 0xBD;
    }
    return 0;
  }

  struct SofdecFeatureFlagRuntimeView
  {
    std::uint8_t reserved00[0x20];
    std::uint8_t enabledFlag; // +0x20
  };
  static_assert(
    offsetof(SofdecFeatureFlagRuntimeView, enabledFlag) == 0x20,
    "SofdecFeatureFlagRuntimeView::enabledFlag offset must be 0x20"
  );

  /**
   * Address: 0x00ADD840 (FUN_00ADD840, _isEnableFtr)
   *
   * What it does:
   * Validates that one stream id belongs to the feature-stream class (`0xE0`)
   * and returns `1` only when the feature flag byte at `+0x20` is exactly `1`.
   */
  extern "C" std::int32_t isEnableFtr(
    const std::uint32_t streamId,
    const SofdecFeatureFlagRuntimeView* const featureInfo
  )
  {
    if (chkStmId(streamId) != 0xE0) {
      return 0;
    }

    if (featureInfo == nullptr) {
      return 0;
    }

    return featureInfo->enabledFlag == 1 ? 1 : 0;
  }

  /**
   * Address: 0x00ADD810 (FUN_00ADD810, _isEnableFtr_0)
   *
   * What it does:
   * Returns 1 when stream id resolves to audio class (`0xC0`) and the feature
   * enable byte is exactly `1`.
   */
  extern "C" std::int32_t isEnableFtr_0(
    const std::uint32_t streamId,
    const SofdecFeatureFlagRuntimeView* const featureInfo
  )
  {
    if (chkStmId(streamId) != 0xC0 || featureInfo == nullptr) {
      return 0;
    }
    return featureInfo->enabledFlag == 1 ? 1 : 0;
  }

  /**
   * Address: 0x00AE7050 (FUN_00AE7050, _MEM_Copy)
   *
   * What it does:
   * Copies `sizeBytes` from source to destination and returns destination.
   */
  extern "C" void* MEM_Copy(void* const destination, const void* const source, const std::uint32_t sizeBytes)
  {
    std::memcpy(destination, source, sizeBytes);
    return destination;
  }

  /**
   * Address: 0x00AE7080 (FUN_00AE7080, _MEM_Copy4)
   *
   * What it does:
   * Copies `sizeBytes` from source to destination and returns destination.
   */
  extern "C" void* MEM_Copy4(void* const destination, const void* const source, const std::uint32_t sizeBytes)
  {
    std::memcpy(destination, source, sizeBytes);
    return destination;
  }

  /**
   * Address: 0x00AE70B0 (FUN_00AE70B0, _MEM_Copy8)
   *
   * What it does:
   * Copies `sizeBytes` from source to destination and returns destination.
   */
  extern "C" void* MEM_Copy8(void* const destination, const void* const source, const std::uint32_t sizeBytes)
  {
    std::memcpy(destination, source, sizeBytes);
    return destination;
  }

  /**
   * Address: 0x00AE70E0 (FUN_00AE70E0, _MEM_Copy32)
   *
   * What it does:
   * Copies `sizeBytes` from source to destination and returns destination.
   */
  extern "C" void* MEM_Copy32(void* const destination, const void* const source, const std::uint32_t sizeBytes)
  {
    std::memcpy(destination, source, sizeBytes);
    return destination;
  }

  /**
   * Address: 0x00ADD7A0 (FUN_00ADD7A0, _getPicRate)
   *
   * What it does:
   * Converts one MPEG picture-rate code (`1..8`) into the corresponding scaled
   * rate value used by SFH analysis.
   */
  extern "C" std::int32_t getPicRate(const std::int32_t pictureRateCode)
  {
    switch (pictureRateCode) {
      case 1:
        return 23976;
      case 2:
        return 24000;
      case 3:
        return 25000;
      case 4:
        return 29970;
      case 5:
        return 30000;
      case 6:
        return 50000;
      case 7:
        return 59940;
      case 8:
        return 60000;
      default:
        return 0;
    }
  }

  struct M2TLibraryRuntimeView
  {
    std::uint32_t m2tInitRefCount = 0; // +0x00
    std::uint8_t m2tInitScratch[0x80]{}; // +0x04
    std::uint8_t reserved84[0x1C]{}; // +0x84
    std::uint32_t m2pesInitRefCount = 0; // +0xA0
    std::array<std::int32_t, 64> m2pesHandleSlots{}; // +0xA4
  };
  static_assert(
    offsetof(M2TLibraryRuntimeView, m2tInitRefCount) == 0x00,
    "M2TLibraryRuntimeView::m2tInitRefCount offset must be 0x00"
  );
  static_assert(
    offsetof(M2TLibraryRuntimeView, m2tInitScratch) == 0x04,
    "M2TLibraryRuntimeView::m2tInitScratch offset must be 0x04"
  );
  static_assert(
    offsetof(M2TLibraryRuntimeView, m2pesInitRefCount) == 0xA0,
    "M2TLibraryRuntimeView::m2pesInitRefCount offset must be 0xA0"
  );
  static_assert(
    offsetof(M2TLibraryRuntimeView, m2pesHandleSlots) == 0xA4,
    "M2TLibraryRuntimeView::m2pesHandleSlots offset must be 0xA4"
  );
  static_assert(sizeof(M2TLibraryRuntimeView) == 0x1A4, "M2TLibraryRuntimeView size must be 0x1A4");

  extern "C" M2TLibraryRuntimeView M2T_libobj;
  extern "C" const char* cri_verstr_ptr_m2t;
  extern "C" const char* cri_verstr_ptr_m2spes;
  extern "C" std::int32_t M2TSD_libobj = 0;
  extern "C" std::int32_t m2tsd_relaysj[3];
  extern "C" std::int32_t m2tsd_outsj[3];
  extern "C" std::int32_t m2tsd_insj = 0;

  /**
   * Address: 0x00ACF120 (FUN_00ACF120, _chkFatal)
   *
   * What it does:
   * Reports whether the Sofdec runtime is in a fatal startup state.
   */
  extern "C" std::int32_t chkFatal()
  {
    return 0;
  }

  [[nodiscard]] static std::int32_t Align32ByteAddress(const std::int32_t address) noexcept
  {
    const std::uint32_t rawAddress = static_cast<std::uint32_t>(address);
    return static_cast<std::int32_t>((rawAddress + 31u) & ~31u);
  }

  [[nodiscard]] static std::array<std::int32_t, 64>& M2PesHandleSlots() noexcept
  {
    return M2T_libobj.m2pesHandleSlots;
  }

  [[nodiscard]] static std::array<std::int32_t, 32>& M2THandleSlots() noexcept
  {
    auto* const slots = reinterpret_cast<std::array<std::int32_t, 32>*>(M2T_libobj.m2tInitScratch);
    return *slots;
  }

  static constexpr char kM2TVersionString[] = "\nCRI M2T/PC Ver.1.022 Build:Feb 28 2005 21:37:19\n";
  static constexpr char kM2PesVersionString[] = "\nCRI M2PES/PC Ver.1.022 Build:Feb 28 2005 21:37:17\n";
  static constexpr char kM2TsdVersionString[] = "\nCRI M2TSD/PC Ver.1.022 Build:Feb 28 2005 21:37:20\n";

  /**
   * Address: 0x00AE3240 (FUN_00AE3240, _M2T_Init)
   *
   * What it does:
   * Updates the M2T version-string pointer, bumps the shared M2T init
   * reference count, and clears M2T startup scratch lanes on first init.
   */
  extern "C" std::int32_t M2T_Init()
  {
    cri_verstr_ptr_m2t = kM2TVersionString;

    const std::uint32_t previousRefCount = M2T_libobj.m2tInitRefCount;
    M2T_libobj.m2tInitRefCount = previousRefCount + 1u;
    if (previousRefCount == 0u) {
      std::memset(M2T_libobj.m2tInitScratch, 0, sizeof(M2T_libobj.m2tInitScratch));
      return 0;
    }

    return static_cast<std::int32_t>(previousRefCount + 1u);
  }

  /**
   * Address: 0x00AE3230 (FUN_00AE3230, _M2T_GetVersionStr)
   *
   * What it does:
   * Returns the static CRI M2T runtime version banner string.
   */
  extern "C" const char* M2T_GetVersionStr()
  {
    return kM2TVersionString;
  }

  /**
   * Address: 0x00AE0C80 (FUN_00AE0C80, _M2PES_Init)
   *
   * What it does:
   * Updates CRI M2PES version-string pointer, bumps the shared M2T init
   * reference count, and clears the M2PES scratch lane on first init.
   */
  extern "C" std::int32_t M2PES_Init()
  {
    cri_verstr_ptr_m2spes = kM2PesVersionString;

    const std::uint32_t previousRefCount = M2T_libobj.m2pesInitRefCount;
    M2T_libobj.m2pesInitRefCount = previousRefCount + 1u;
    if (previousRefCount == 0u) {
      M2PesHandleSlots().fill(0);
      return 0;
    }

    return static_cast<std::int32_t>(previousRefCount + 1u);
  }

  /**
   * Address: 0x00AE0C70 (FUN_00AE0C70, _M2PES_GetVersionStr)
   *
   * What it does:
   * Returns the static CRI M2PES runtime version banner string.
   */
  extern "C" const char* M2PES_GetVersionStr()
  {
    return kM2PesVersionString;
  }

  extern "C" std::int32_t M2TSD_Init();
  extern "C" void M2TSD_Finish();
  extern "C" std::int32_t M2TSD_Destroy(std::int32_t runtimeAddress);
  extern "C" std::int32_t SFLIB_SetErr(std::int32_t errorObjectAddress, std::int32_t errorCode);

  /**
   * Address: 0x00ACF100 (FUN_00ACF100, _SFM2TS_Init)
   *
   * What it does:
   * Validates fatal startup state, then initializes M2T, M2PES, and M2TSD
   * runtime lanes in order.
   */
  extern "C" std::int32_t SFM2TS_Init()
  {
    if (chkFatal() != 0) {
      for (;;) {
      }
    }

    (void)M2T_Init();
    (void)M2PES_Init();
    (void)M2TSD_Init();
    return 0;
  }

  /**
   * Address: 0x00ACF130 (FUN_00ACF130, _SFM2TS_Finish)
   *
   * What it does:
   * Finalizes the M2TSD runtime lane and returns Sofdec success code `0`.
   */
  extern "C" std::int32_t SFM2TS_Finish()
  {
    M2TSD_Finish();
    return 0;
  }

  /**
   * Address: 0x00ADFDE0 (FUN_00ADFDE0, _M2TSD_Finish)
   *
   * What it does:
   * Decrements the process-global M2TSD library reference counter.
   */
  extern "C" void M2TSD_Finish()
  {
    --M2TSD_libobj;
  }

  /**
   * Address: 0x00ADFD80 (FUN_00ADFD80, _M2TSD_GetVersionStr)
   *
   * What it does:
   * Returns the static CRI M2TSD runtime version banner string.
   */
  extern "C" const char* M2TSD_GetVersionStr()
  {
    return kM2TsdVersionString;
  }

  struct M2TsdSupplyStatusView
  {
    std::int32_t status = 0; // +0x00
    std::int32_t terminateFlag = 0; // +0x04
  };
  static_assert(offsetof(M2TsdSupplyStatusView, status) == 0x00, "M2TsdSupplyStatusView::status offset must be 0x00");
  static_assert(
    offsetof(M2TsdSupplyStatusView, terminateFlag) == 0x04,
    "M2TsdSupplyStatusView::terminateFlag offset must be 0x04"
  );
  static_assert(sizeof(M2TsdSupplyStatusView) == 0x08, "M2TsdSupplyStatusView size must be 0x08");

  struct M2PesSupplyControlView
  {
    std::int32_t status = 0; // +0x00
    std::int32_t terminateEnableFlag = 0; // +0x04
    std::int32_t errorCallbackAddress = 0; // +0x08
    std::int32_t errorCallbackObject = 0; // +0x0C
  };
  static_assert(offsetof(M2PesSupplyControlView, status) == 0x00, "M2PesSupplyControlView::status offset must be 0x00");
  static_assert(
    offsetof(M2PesSupplyControlView, terminateEnableFlag) == 0x04,
    "M2PesSupplyControlView::terminateEnableFlag offset must be 0x04"
  );
  static_assert(
    offsetof(M2PesSupplyControlView, errorCallbackAddress) == 0x08,
    "M2PesSupplyControlView::errorCallbackAddress offset must be 0x08"
  );
  static_assert(
    offsetof(M2PesSupplyControlView, errorCallbackObject) == 0x0C,
    "M2PesSupplyControlView::errorCallbackObject offset must be 0x0C"
  );
  static_assert(sizeof(M2PesSupplyControlView) == 0x10, "M2PesSupplyControlView size must be 0x10");

  struct M2PesDecodeRuntimeView
  {
    std::int32_t status = 0; // +0x00
    std::int32_t terminateEnableFlag = 0; // +0x04
    std::int32_t errorCallbackAddress = 0; // +0x08
    std::int32_t errorCallbackObject = 0; // +0x0C
    std::uint8_t reserved10_3F[0x30]{}; // +0x10
    std::int32_t bitScratchWord = 0; // +0x40
    std::uint8_t reserved44_F7[0xB4]{}; // +0x44
    std::int32_t fallbackPacketPayloadBytes = 0; // +0xF8
    std::int32_t decodedPayloadAddress = 0; // +0xFC
    std::int32_t parsedPayloadAdvanceBytes = 0; // +0x100
    std::uint8_t reserved104_11F[0x1C]{}; // +0x104
    std::int32_t parsedHeaderAdvanceBytes = 0; // +0x120
  };
  static_assert(offsetof(M2PesDecodeRuntimeView, status) == 0x00, "M2PesDecodeRuntimeView::status offset must be 0x00");
  static_assert(
    offsetof(M2PesDecodeRuntimeView, terminateEnableFlag) == 0x04,
    "M2PesDecodeRuntimeView::terminateEnableFlag offset must be 0x04"
  );
  static_assert(
    offsetof(M2PesDecodeRuntimeView, errorCallbackAddress) == 0x08,
    "M2PesDecodeRuntimeView::errorCallbackAddress offset must be 0x08"
  );
  static_assert(
    offsetof(M2PesDecodeRuntimeView, errorCallbackObject) == 0x0C,
    "M2PesDecodeRuntimeView::errorCallbackObject offset must be 0x0C"
  );
  static_assert(offsetof(M2PesDecodeRuntimeView, bitScratchWord) == 0x40, "M2PesDecodeRuntimeView::bitScratchWord offset must be 0x40");
  static_assert(
    offsetof(M2PesDecodeRuntimeView, fallbackPacketPayloadBytes) == 0xF8,
    "M2PesDecodeRuntimeView::fallbackPacketPayloadBytes offset must be 0xF8"
  );
  static_assert(
    offsetof(M2PesDecodeRuntimeView, parsedPayloadAdvanceBytes) == 0x100,
    "M2PesDecodeRuntimeView::parsedPayloadAdvanceBytes offset must be 0x100"
  );
  static_assert(
    offsetof(M2PesDecodeRuntimeView, parsedHeaderAdvanceBytes) == 0x120,
    "M2PesDecodeRuntimeView::parsedHeaderAdvanceBytes offset must be 0x120"
  );
  static_assert(sizeof(M2PesDecodeRuntimeView) == 0x124, "M2PesDecodeRuntimeView size must be 0x124");

  /**
   * Address: 0x00AE0130 (FUN_00AE0130, _M2TSD_SetPesSw)
   *
   * What it does:
   * Stores one PES-switch mode value on the active M2TSD runtime block.
   */
  extern "C" std::int32_t M2TSD_SetPesSw(const std::int32_t runtimeAddress, const std::int32_t pesSwitchValue)
  {
    auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(SjAddressToPointer(runtimeAddress));
    *reinterpret_cast<std::int32_t*>(runtimeBytes + 0xBC) = pesSwitchValue;
    return pesSwitchValue;
  }

  /**
   * Address: 0x00AE01D0 (FUN_00AE01D0, _M2TSD_SetCbFn)
   *
   * What it does:
   * Stores one callback function/object pair in the selected M2TSD lane slot.
   */
  extern "C" std::int32_t M2TSD_SetCbFn(
    const std::int32_t runtimeAddress,
    const std::int32_t laneIndex,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(SjAddressToPointer(runtimeAddress));
    auto* const laneEntries = *reinterpret_cast<std::uint8_t**>(runtimeBytes + 0xB4);
    auto* const lane = laneEntries + (laneIndex * 0x28);
    *reinterpret_cast<std::int32_t*>(lane + 0x10) = callbackAddress;
    *reinterpret_cast<std::int32_t*>(lane + 0x14) = callbackObject;
    return laneIndex * 0x28;
  }

  /**
   * Address: 0x00AE0200 (FUN_00AE0200, _M2TSD_SetTsMapFn)
   *
   * What it does:
   * Stores the TS-map callback pair on one M2TSD runtime block and returns the
   * runtime address unchanged.
   */
  extern "C" std::int32_t M2TSD_SetTsMapFn(
    const std::int32_t runtimeAddress,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(SjAddressToPointer(runtimeAddress));
    *reinterpret_cast<std::int32_t*>(runtimeBytes + 0xC0) = callbackAddress;
    *reinterpret_cast<std::int32_t*>(runtimeBytes + 0xC4) = callbackObject;
    return runtimeAddress;
  }

  /**
   * Address: 0x00AE0220 (FUN_00AE0220, _M2TSD_SetPesFn)
   *
   * What it does:
   * Stores the PES callback pair on one M2TSD runtime block and returns the
   * runtime address unchanged.
   */
  extern "C" std::int32_t M2TSD_SetPesFn(
    const std::int32_t runtimeAddress,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(SjAddressToPointer(runtimeAddress));
    *reinterpret_cast<std::int32_t*>(runtimeBytes + 0xC8) = callbackAddress;
    *reinterpret_cast<std::int32_t*>(runtimeBytes + 0xCC) = callbackObject;
    return runtimeAddress;
  }

  /**
   * Address: 0x00AE0240 (FUN_00AE0240, _M2TSD_GetStat)
   *
   * What it does:
   * Returns the current status word from one M2TSD supply block.
   */
  extern "C" std::int32_t M2TSD_GetStat(const std::int32_t streamSupplyAddress)
  {
    const auto* const supplyView =
      reinterpret_cast<const M2TsdSupplyStatusView*>(SjAddressToPointer(streamSupplyAddress));
    return supplyView->status;
  }

  /**
   * Address: 0x00AE0250 (FUN_00AE0250, _M2TSD_TermSupply)
   *
   * What it does:
   * Marks one M2TSD supply block as terminated and returns the original
   * address.
   */
  extern "C" std::int32_t M2TSD_TermSupply(const std::int32_t streamSupplyAddress)
  {
    auto* const supplyView =
      reinterpret_cast<M2TsdSupplyStatusView*>(SjAddressToPointer(streamSupplyAddress));
    supplyView->terminateFlag = 1;
    return streamSupplyAddress;
  }

  struct Sfm2tsDestroyRuntimeNode
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Destroy() = 0; // +0x0C
  };

  struct Sfm2tsDestroyCallbackLane
  {
    Sfm2tsDestroyRuntimeNode* runtimeNode = nullptr; // +0x00
    std::int32_t reserved04 = 0; // +0x04
    std::int32_t reserved08 = 0; // +0x08
  };
  static_assert(
    offsetof(Sfm2tsDestroyCallbackLane, runtimeNode) == 0x00,
    "Sfm2tsDestroyCallbackLane::runtimeNode offset must be 0x00"
  );
  static_assert(sizeof(Sfm2tsDestroyCallbackLane) == 0x0C, "Sfm2tsDestroyCallbackLane size must be 0x0C");

  struct Sfm2tsParameterSnapshot
  {
    std::int32_t paramWord0 = 0; // +0x00
    std::int32_t paramWord1 = 0; // +0x04
    std::int32_t destroyLaneCount = 0; // +0x08
    std::array<std::int32_t, 16> tailWords{}; // +0x0C
  };
  static_assert(
    offsetof(Sfm2tsParameterSnapshot, destroyLaneCount) == 0x08,
    "Sfm2tsParameterSnapshot::destroyLaneCount offset must be 0x08"
  );
  static_assert(sizeof(Sfm2tsParameterSnapshot) == 0x4C, "Sfm2tsParameterSnapshot size must be 0x4C");

  struct Sfm2tsDestroyRuntimeView
  {
    std::int32_t m2tsdRuntimeAddress = 0; // +0x00
    Sfm2tsParameterSnapshot parameterSnapshot{}; // +0x04
    std::int32_t reserved50 = 0; // +0x50
    std::int32_t reserved54 = 0; // +0x54
    Sfm2tsDestroyCallbackLane destroyLanes[1]{}; // +0x58
  };
  static_assert(
    offsetof(Sfm2tsDestroyRuntimeView, m2tsdRuntimeAddress) == 0x00,
    "Sfm2tsDestroyRuntimeView::m2tsdRuntimeAddress offset must be 0x00"
  );
  static_assert(
    offsetof(Sfm2tsDestroyRuntimeView, parameterSnapshot) == 0x04,
    "Sfm2tsDestroyRuntimeView::parameterSnapshot offset must be 0x04"
  );
  static_assert(
    offsetof(Sfm2tsDestroyRuntimeView, destroyLanes) == 0x58,
    "Sfm2tsDestroyRuntimeView::destroyLanes offset must be 0x58"
  );

  Sfm2tsParameterSnapshot sfdm2ts_para{};

  struct Sfm2tsInitInfoRuntimeView
  {
    std::int32_t runtimeStatus = 0; // +0x00
    Sfm2tsParameterSnapshot parameterSnapshot{}; // +0x04
  };
  static_assert(offsetof(Sfm2tsInitInfoRuntimeView, runtimeStatus) == 0x00, "Sfm2tsInitInfoRuntimeView::runtimeStatus offset must be 0x00");
  static_assert(
    offsetof(Sfm2tsInitInfoRuntimeView, parameterSnapshot) == 0x04,
    "Sfm2tsInitInfoRuntimeView::parameterSnapshot offset must be 0x04"
  );
  static_assert(sizeof(Sfm2tsInitInfoRuntimeView) == 0x50, "Sfm2tsInitInfoRuntimeView size must be 0x50");

  /**
   * Address: 0x00ACF030 (FUN_00ACF030, _SFD_SetM2tsPara)
   *
   * What it does:
   * Copies one caller-supplied M2TS parameter snapshot into process-global
   * `sfdm2ts_para`.
   */
  extern "C" void SFD_SetM2tsPara(const Sfm2tsParameterSnapshot* const parameterSnapshot)
  {
    if (parameterSnapshot == nullptr) {
      return;
    }

    sfdm2ts_para = *parameterSnapshot;
  }

  /**
   * Address: 0x00ACF8F0 (FUN_00ACF8F0, _initInf)
   *
   * What it does:
   * Clears one init-info status lane and seeds its parameter snapshot from the
   * process-global `sfdm2ts_para` template.
   */
  extern "C" Sfm2tsInitInfoRuntimeView* initInf(Sfm2tsInitInfoRuntimeView* const initInfo)
  {
    if (initInfo == nullptr) {
      return nullptr;
    }

    initInfo->runtimeStatus = 0;
    initInfo->parameterSnapshot = sfdm2ts_para;
    return initInfo;
  }

  /**
   * Address: 0x00ACF920 (FUN_00ACF920, _SFM2TS_Destroy)
   *
   * What it does:
   * Copies the active SFM2TS parameter snapshot to process-global storage,
   * destroys the active M2TSD runtime lane, and releases each registered
   * callback-runtime lane.
   */
  extern "C" std::int32_t SFM2TS_Destroy(const std::int32_t runtimeAddress)
  {
    auto* const runtimeView = reinterpret_cast<Sfm2tsDestroyRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(runtimeAddress))
    );

    if (runtimeView->m2tsdRuntimeAddress != 0) {
      sfdm2ts_para = runtimeView->parameterSnapshot;
      (void)M2TSD_Destroy(runtimeView->m2tsdRuntimeAddress);

      const std::int32_t laneCount = runtimeView->parameterSnapshot.destroyLaneCount;
      Sfm2tsDestroyCallbackLane* lane = runtimeView->destroyLanes;
      for (std::int32_t laneIndex = 0; laneIndex < laneCount; ++laneIndex, ++lane) {
        if (lane->runtimeNode != nullptr) {
          lane->runtimeNode->Destroy();
          lane->runtimeNode = nullptr;
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x00ACF990 (FUN_00ACF990, _SFM2TS_RequestStop)
   *
   * What it does:
   * No-op request-stop lane for the M2TS stream-descriptor transport table.
   */
  extern "C" std::int32_t SFM2TS_RequestStop()
  {
    return 0;
  }

  /**
   * Address: 0x00ACF9A0 (FUN_00ACF9A0, _SFM2TS_Start)
   *
   * What it does:
   * No-op start lane for the M2TS stream-descriptor transport table.
   */
  extern "C" std::int32_t SFM2TS_Start()
  {
    return 0;
  }

  /**
   * Address: 0x00ACF9B0 (FUN_00ACF9B0, _SFM2TS_Stop)
   *
   * What it does:
   * No-op stop lane for the M2TS stream-descriptor transport table.
   */
  extern "C" std::int32_t SFM2TS_Stop()
  {
    return 0;
  }

  /**
   * Address: 0x00ACF9C0 (FUN_00ACF9C0, _SFM2TS_Pause)
   *
   * What it does:
   * No-op pause lane for the M2TS stream-descriptor transport table.
   */
  extern "C" std::int32_t SFM2TS_Pause()
  {
    return 0;
  }

  /**
   * Address: 0x00ACF9D0 (FUN_00ACF9D0, _SFM2TS_GetWrite)
   *
   * What it does:
   * Reports unsupported write-window API for SFM2TS by setting the canonical
   * SFLIB error lane.
   */
  extern "C" std::int32_t SFM2TS_GetWrite(const std::int32_t runtimeAddress)
  {
    return SFLIB_SetErr(runtimeAddress, static_cast<std::int32_t>(0xFF000D22u));
  }

  /**
   * Address: 0x00ACF9F0 (FUN_00ACF9F0, _SFM2TS_AddWrite)
   *
   * What it does:
   * Reports unsupported write-commit API for SFM2TS by setting the canonical
   * SFLIB error lane.
   */
  extern "C" std::int32_t SFM2TS_AddWrite(const std::int32_t runtimeAddress)
  {
    return SFLIB_SetErr(runtimeAddress, static_cast<std::int32_t>(0xFF000D22u));
  }

  /**
   * Address: 0x00ACFA10 (FUN_00ACFA10, _SFM2TS_GetRead)
   *
   * What it does:
   * Reports unsupported read-window API for SFM2TS by setting the canonical
   * SFLIB error lane.
   */
  extern "C" std::int32_t SFM2TS_GetRead(const std::int32_t runtimeAddress)
  {
    return SFLIB_SetErr(runtimeAddress, static_cast<std::int32_t>(0xFF000D22u));
  }

  /**
   * Address: 0x00ACFA30 (FUN_00ACFA30, _SFM2TS_AddRead)
   *
   * What it does:
   * Reports unsupported read-commit API for SFM2TS by setting the canonical
   * SFLIB error lane.
   */
  extern "C" std::int32_t SFM2TS_AddRead(const std::int32_t runtimeAddress)
  {
    return SFLIB_SetErr(runtimeAddress, static_cast<std::int32_t>(0xFF000D22u));
  }

  /**
   * Address: 0x00ACFA50 (FUN_00ACFA50, _SFM2TS_Seek)
   *
   * What it does:
   * No-op seek lane for the M2TS stream-descriptor transport table.
   */
  extern "C" std::int32_t SFM2TS_Seek()
  {
    return 0;
  }

  extern "C" std::int32_t M2T_GetStat(const std::int32_t streamSupplyAddress);
  extern "C" std::int32_t M2T_TermSupply(const std::int32_t streamSupplyAddress);
  /**
   * Address: 0x00AE0E20 (FUN_00AE0E20, _M2PES_GetStat)
   *
   * What it does:
   * Returns the active M2PES runtime status lane.
   */
  extern "C" std::int32_t M2PES_GetStat(const std::int32_t streamSupplyAddress);
  /**
   * Address: 0x00AE0E30 (FUN_00AE0E30, _M2PES_TermSupply)
   *
   * What it does:
   * Sets the M2PES terminate-request flag and returns the supply address.
   */
  extern "C" std::int32_t M2PES_TermSupply(const std::int32_t streamSupplyAddress);
  /**
   * Address: 0x00AE0F60 (FUN_00AE0F60, _shartSupply)
   *
   * What it does:
   * Promotes one M2PES runtime to finished state (`status = 4`) after the
   * terminate-request flag is armed.
   */
  extern "C" M2PesSupplyControlView* shartSupply(M2PesSupplyControlView* supplyView);

  struct M2TsdLaneRuntimeView
  {
    std::int32_t laneState = 0; // +0x00
    std::int32_t streamIdFilter = -1; // +0x04
    std::int32_t callbackSinkAddress = 0; // +0x08
    std::int32_t needsTerminationCheck = 0; // +0x0C
    std::int32_t callbackAddress = 0; // +0x10
    std::int32_t callbackObject = 0; // +0x14
    std::int32_t callbackReserved = 0; // +0x18
    std::int32_t m2pesSupplyAddress = 0; // +0x1C
    std::int32_t payloadDispatchPending = 0; // +0x20
    std::int32_t streamEndMarker = -1; // +0x24
  };
  static_assert(offsetof(M2TsdLaneRuntimeView, laneState) == 0x00, "M2TsdLaneRuntimeView::laneState offset must be 0x00");
  static_assert(
    offsetof(M2TsdLaneRuntimeView, streamIdFilter) == 0x04,
    "M2TsdLaneRuntimeView::streamIdFilter offset must be 0x04"
  );
  static_assert(
    offsetof(M2TsdLaneRuntimeView, callbackSinkAddress) == 0x08,
    "M2TsdLaneRuntimeView::callbackSinkAddress offset must be 0x08"
  );
  static_assert(
    offsetof(M2TsdLaneRuntimeView, needsTerminationCheck) == 0x0C,
    "M2TsdLaneRuntimeView::needsTerminationCheck offset must be 0x0C"
  );
  static_assert(offsetof(M2TsdLaneRuntimeView, callbackAddress) == 0x10, "M2TsdLaneRuntimeView::callbackAddress offset must be 0x10");
  static_assert(offsetof(M2TsdLaneRuntimeView, callbackObject) == 0x14, "M2TsdLaneRuntimeView::callbackObject offset must be 0x14");
  static_assert(
    offsetof(M2TsdLaneRuntimeView, callbackReserved) == 0x18,
    "M2TsdLaneRuntimeView::callbackReserved offset must be 0x18"
  );
  static_assert(
    offsetof(M2TsdLaneRuntimeView, m2pesSupplyAddress) == 0x1C,
    "M2TsdLaneRuntimeView::m2pesSupplyAddress offset must be 0x1C"
  );
  static_assert(
    offsetof(M2TsdLaneRuntimeView, payloadDispatchPending) == 0x20,
    "M2TsdLaneRuntimeView::payloadDispatchPending offset must be 0x20"
  );
  static_assert(
    offsetof(M2TsdLaneRuntimeView, streamEndMarker) == 0x24,
    "M2TsdLaneRuntimeView::streamEndMarker offset must be 0x24"
  );
  static_assert(sizeof(M2TsdLaneRuntimeView) == 0x28, "M2TsdLaneRuntimeView size must be 0x28");

  struct M2TsdStatusGate
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void Reserved14() = 0;
    virtual void AcquireReadWindow(std::int32_t mode, std::int32_t maxBytes, std::int32_t* outChunkWords) = 0; // +0x18
    virtual void SubmitSplitChunk(std::int32_t laneIndex, std::int32_t* splitChunkWords) = 0; // +0x1C
    virtual void CommitReadWindow(std::int32_t laneIndex, std::int32_t* chunkWords) = 0; // +0x20
    virtual std::int32_t QueryGate(std::int32_t queryMode) = 0; // +0x24
  };

  struct SjChunkRuntimeView
  {
    std::int32_t chunkAddress = 0; // +0x00
    std::int32_t chunkBytes = 0; // +0x04
  };
  static_assert(offsetof(SjChunkRuntimeView, chunkAddress) == 0x00, "SjChunkRuntimeView::chunkAddress offset must be 0x00");
  static_assert(offsetof(SjChunkRuntimeView, chunkBytes) == 0x04, "SjChunkRuntimeView::chunkBytes offset must be 0x04");
  static_assert(sizeof(SjChunkRuntimeView) == 0x08, "SjChunkRuntimeView size must be 0x08");

  struct M2TsdRuntimeView
  {
    std::int32_t status = 0; // +0x00
    std::int32_t streamActiveFlag = 0; // +0x04
    std::int32_t errorCallbackAddress = 0; // +0x08
    std::int32_t errorCallbackObject = 0; // +0x0C
    std::int32_t reserved10 = 0; // +0x10
    std::int32_t decodeCycleProgressFlag = 0; // +0x14
    std::int32_t decodeMode = 1; // +0x18
    std::int32_t streamEndCode = -1; // +0x1C
    std::uint8_t reserved20[0x88]{};
    std::int32_t m2tSupplyAddress = 0; // +0xA8
    M2TsdStatusGate* statusGate = nullptr; // +0xAC
    std::int32_t laneCount = 0; // +0xB0
    M2TsdLaneRuntimeView* laneEntries = nullptr; // +0xB4
    std::int32_t reservedB8 = 0; // +0xB8
    std::int32_t controllerGateEnabled = 0; // +0xBC
    std::int32_t tsMapCallbackAddress = 0; // +0xC0
    std::int32_t tsMapCallbackObject = 0; // +0xC4
    std::int32_t pesCallbackAddress = 0; // +0xC8
    std::int32_t pesCallbackObject = 0; // +0xCC
  };
  static_assert(offsetof(M2TsdRuntimeView, status) == 0x00, "M2TsdRuntimeView::status offset must be 0x00");
  static_assert(offsetof(M2TsdRuntimeView, streamActiveFlag) == 0x04, "M2TsdRuntimeView::streamActiveFlag offset must be 0x04");
  static_assert(offsetof(M2TsdRuntimeView, errorCallbackAddress) == 0x08, "M2TsdRuntimeView::errorCallbackAddress offset must be 0x08");
  static_assert(offsetof(M2TsdRuntimeView, errorCallbackObject) == 0x0C, "M2TsdRuntimeView::errorCallbackObject offset must be 0x0C");
  static_assert(offsetof(M2TsdRuntimeView, reserved10) == 0x10, "M2TsdRuntimeView::reserved10 offset must be 0x10");
  static_assert(
    offsetof(M2TsdRuntimeView, decodeCycleProgressFlag) == 0x14,
    "M2TsdRuntimeView::decodeCycleProgressFlag offset must be 0x14"
  );
  static_assert(offsetof(M2TsdRuntimeView, decodeMode) == 0x18, "M2TsdRuntimeView::decodeMode offset must be 0x18");
  static_assert(
    offsetof(M2TsdRuntimeView, streamEndCode) == 0x1C,
    "M2TsdRuntimeView::streamEndCode offset must be 0x1C"
  );
  static_assert(offsetof(M2TsdRuntimeView, m2tSupplyAddress) == 0xA8, "M2TsdRuntimeView::m2tSupplyAddress offset must be 0xA8");
  static_assert(offsetof(M2TsdRuntimeView, statusGate) == 0xAC, "M2TsdRuntimeView::statusGate offset must be 0xAC");
  static_assert(offsetof(M2TsdRuntimeView, laneCount) == 0xB0, "M2TsdRuntimeView::laneCount offset must be 0xB0");
  static_assert(offsetof(M2TsdRuntimeView, laneEntries) == 0xB4, "M2TsdRuntimeView::laneEntries offset must be 0xB4");
  static_assert(offsetof(M2TsdRuntimeView, reservedB8) == 0xB8, "M2TsdRuntimeView::reservedB8 offset must be 0xB8");
  static_assert(
    offsetof(M2TsdRuntimeView, controllerGateEnabled) == 0xBC,
    "M2TsdRuntimeView::controllerGateEnabled offset must be 0xBC"
  );
  static_assert(offsetof(M2TsdRuntimeView, tsMapCallbackAddress) == 0xC0, "M2TsdRuntimeView::tsMapCallbackAddress offset must be 0xC0");
  static_assert(offsetof(M2TsdRuntimeView, tsMapCallbackObject) == 0xC4, "M2TsdRuntimeView::tsMapCallbackObject offset must be 0xC4");
  static_assert(offsetof(M2TsdRuntimeView, pesCallbackAddress) == 0xC8, "M2TsdRuntimeView::pesCallbackAddress offset must be 0xC8");
  static_assert(offsetof(M2TsdRuntimeView, pesCallbackObject) == 0xCC, "M2TsdRuntimeView::pesCallbackObject offset must be 0xCC");
  static_assert(sizeof(M2TsdRuntimeView) == 0xD0, "M2TsdRuntimeView size must be 0xD0");

  struct M2TsdChunkIoGate
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void Reserved14() = 0;
    virtual void AcquireChunk(std::int32_t lane, std::int32_t requestedBytes, moho::SjChunkRange* outChunk) = 0; // +0x18
    virtual void ReturnChunk(std::int32_t lane, const moho::SjChunkRange* chunk) = 0; // +0x1C
    virtual void CommitChunk(std::int32_t lane, const moho::SjChunkRange* chunk) = 0; // +0x20
    virtual std::int32_t QueryCapacity(std::int32_t lane) = 0; // +0x24
  };

  struct M2PesPacketRuntimeView
  {
    std::uint8_t reserved00_1F[0x20]{};
    std::uint8_t streamIdByte = 0; // +0x20
    std::uint8_t reserved21_3F[0x1F]{};
    std::int32_t hasTimestampLane = 0; // +0x40
    std::uint8_t reserved44_67[0x24]{};
    std::int32_t timestampWord26 = 0; // +0x68
    std::int32_t timestampWord27 = 0; // +0x6C
    std::int32_t timestampWord28 = 0; // +0x70
    std::uint8_t reserved74_FB[0x88]{};
    const void* decodedPayload = nullptr; // +0xFC
    std::int32_t decodedPayloadBytes = 0; // +0x100
  };
  static_assert(offsetof(M2PesPacketRuntimeView, streamIdByte) == 0x20, "M2PesPacketRuntimeView::streamIdByte offset must be 0x20");
  static_assert(offsetof(M2PesPacketRuntimeView, hasTimestampLane) == 0x40, "M2PesPacketRuntimeView::hasTimestampLane offset must be 0x40");
  static_assert(offsetof(M2PesPacketRuntimeView, timestampWord26) == 0x68, "M2PesPacketRuntimeView::timestampWord26 offset must be 0x68");
  static_assert(offsetof(M2PesPacketRuntimeView, timestampWord27) == 0x6C, "M2PesPacketRuntimeView::timestampWord27 offset must be 0x6C");
  static_assert(offsetof(M2PesPacketRuntimeView, timestampWord28) == 0x70, "M2PesPacketRuntimeView::timestampWord28 offset must be 0x70");
  static_assert(
    offsetof(M2PesPacketRuntimeView, decodedPayload) == 0xFC,
    "M2PesPacketRuntimeView::decodedPayload offset must be 0xFC"
  );
  static_assert(
    offsetof(M2PesPacketRuntimeView, decodedPayloadBytes) == 0x100,
    "M2PesPacketRuntimeView::decodedPayloadBytes offset must be 0x100"
  );
  static_assert(sizeof(M2PesPacketRuntimeView) == 0x104, "M2PesPacketRuntimeView size must be 0x104");

  [[nodiscard]] M2TsdChunkIoGate* AsM2TsdChunkIoGate(const std::int32_t address) noexcept
  {
    return reinterpret_cast<M2TsdChunkIoGate*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
  }

  [[nodiscard]] M2PesPacketRuntimeView* AsM2PesPacketRuntimeView(const std::int32_t address) noexcept
  {
    return reinterpret_cast<M2PesPacketRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
  }

  [[nodiscard]] static std::array<std::int32_t, 32>& M2TsdHandleSlots() noexcept
  {
    static std::array<std::int32_t, 32> slots{};
    return slots;
  }

  extern "C" std::int32_t M2T_Create(std::int32_t workAddress, std::int32_t workSizeBytes);
  /**
   * Address: 0x00AE0CF0 (FUN_00AE0CF0, _M2PES_Create)
   *
   * What it does:
   * Claims one free M2PES handle slot, 32-byte-aligns caller work memory, and
   * initializes one PES runtime handle in place.
   */
  extern "C" std::int32_t M2PES_Create(std::int32_t workAddress, std::uint32_t workSizeBytes);
  /**
   * Address: 0x00ADFE40 (FUN_00ADFE40, _M2TSD_Create)
   *
   * What it does:
   * Claims one free M2TSD handle slot, partitions caller work memory into
   * runtime/lane/PES/M2T regions, and initializes one M2TSD runtime.
   */
  extern "C" std::int32_t M2TSD_Create(std::int32_t workAddress, std::uint32_t workSizeBytes, std::int32_t laneCount);
  /**
   * Address: 0x00AE0020 (FUN_00AE0020, _M2TSD_Destroy)
   *
   * What it does:
   * Releases one M2TSD handle slot and destroys the associated M2TSD runtime.
   */
  extern "C" std::int32_t M2TSD_Destroy(std::int32_t runtimeAddress);
  extern "C" std::int32_t M2T_Destroy(std::int32_t streamSupplyAddress);
  extern "C" std::int32_t M2PES_Destroy(std::int32_t streamSupplyAddress);
  extern "C" std::int32_t M2T_SetErrFn(std::int32_t streamSupplyAddress, std::int32_t callbackAddress, std::int32_t callbackObject);
  /**
   * Address: 0x00AE0E00 (FUN_00AE0E00, _M2PES_SetErrFn)
   *
   * What it does:
   * Stores one error callback function/object pair in the M2PES runtime
   * control lanes.
   */
  extern "C" std::int32_t M2PES_SetErrFn(
    std::int32_t streamSupplyAddress,
    std::int32_t callbackAddress,
    std::int32_t callbackObject
  );
  /**
   * Address: 0x00AE0E40 (FUN_00AE0E40, _M2PES_DecHd)
   *
   * What it does:
   * Decodes one PES packet header from stream bytes, updates parser lanes, and
   * reports the consumed byte count.
   */
  extern "C" std::int32_t M2PES_DecHd(
    std::int32_t streamSupplyAddress,
    std::int32_t chunkAddress,
    std::int32_t chunkBytes,
    std::int32_t* outReadEndAddress
  );
  /**
   * Address: 0x00AF5A70 (FUN_00AF5A70, _M2S_SearchDelim)
   *
   * What it does:
   * Routes delimiter scans through specialized M2S search helpers.
   */
  extern "C" std::uint8_t*
  M2S_SearchDelim(std::uint8_t* buffer, std::int32_t sizeBytes, std::int32_t delimiterMask);
  extern "C"
  std::int32_t parse_PES_packet_sub(M2PesDecodeRuntimeView* runtimeView, const std::uint8_t* chunkBytes, std::int32_t chunkSize);
  struct M2PesHandleInitRuntimeView
  {
    std::int32_t status = 0; // +0x00
    std::int32_t runtimeWord04 = 0; // +0x04
    std::int32_t runtimeWord08 = 0; // +0x08
    std::int32_t runtimeWord0C = 0; // +0x0C
    std::int32_t runtimeWord10 = 0; // +0x10
    std::uint8_t reserved14_F7[0xE4]{};
    std::int32_t reservedF8 = 0; // +0xF8
    std::int32_t chunkLaneWords[10]{}; // +0xFC
  };
  static_assert(offsetof(M2PesHandleInitRuntimeView, runtimeWord04) == 0x04, "M2PesHandleInitRuntimeView::runtimeWord04 offset must be 0x04");
  static_assert(
    offsetof(M2PesHandleInitRuntimeView, reservedF8) == 0xF8,
    "M2PesHandleInitRuntimeView::reservedF8 offset must be 0xF8"
  );
  static_assert(
    offsetof(M2PesHandleInitRuntimeView, chunkLaneWords) == 0xFC,
    "M2PesHandleInitRuntimeView::chunkLaneWords offset must be 0xFC"
  );
  static_assert(sizeof(M2PesHandleInitRuntimeView) == 0x124, "M2PesHandleInitRuntimeView size must be 0x124");

  struct M2THandleInitRuntimeView
  {
    std::int32_t status = 0; // +0x00
    std::int32_t runtimeWord04 = 0; // +0x04
    std::int32_t runtimeWord08 = 0; // +0x08
    std::int32_t runtimeWord0C = 0; // +0x0C
    std::int32_t runtimeWord10 = 0; // +0x10
    std::uint8_t reserved14_1B[0x08]{};
    std::int32_t runtimeWord1C = 0; // +0x1C
    std::int32_t runtimeWord20 = 0; // +0x20
    std::int32_t runtimeWord24 = 0; // +0x24
    std::int32_t runtimeWord28 = 0; // +0x28
    std::int32_t streamEndMarker = -1; // +0x2C
    std::uint8_t reserved30_13B[0x10C]{};
    std::int32_t chunkLaneWords[9]{}; // +0x13C
  };
  static_assert(offsetof(M2THandleInitRuntimeView, runtimeWord04) == 0x04, "M2THandleInitRuntimeView::runtimeWord04 offset must be 0x04");
  static_assert(
    offsetof(M2THandleInitRuntimeView, streamEndMarker) == 0x2C,
    "M2THandleInitRuntimeView::streamEndMarker offset must be 0x2C"
  );
  static_assert(
    offsetof(M2THandleInitRuntimeView, chunkLaneWords) == 0x13C,
    "M2THandleInitRuntimeView::chunkLaneWords offset must be 0x13C"
  );
  static_assert(sizeof(M2THandleInitRuntimeView) == 0x160, "M2THandleInitRuntimeView size must be 0x160");

  extern "C" M2PesHandleInitRuntimeView* initChunks_m2spes(M2PesHandleInitRuntimeView* runtimeView);
  extern "C" M2PesHandleInitRuntimeView* initHn_m2spes(M2PesHandleInitRuntimeView* runtimeView);
  extern "C" M2THandleInitRuntimeView* initChunks(M2THandleInitRuntimeView* runtimeView);
  extern "C" M2THandleInitRuntimeView* initHn_m2sts(M2THandleInitRuntimeView* runtimeView);
  /**
   * Address: 0x00AE0AD0 (FUN_00AE0AD0, _callCbFn)
   *
   * What it does:
   * Invokes one optional per-lane PES callback with sink chunks plus decoded
   * timestamp lanes reconstructed from the active M2PES packet runtime.
   */
  extern "C" std::int32_t callCbFn(
    M2TsdLaneRuntimeView* laneRuntime,
    std::int32_t streamSupplyAddress,
    std::int32_t callbackSinkAddress,
    const moho::SjChunkRange* firstChunk,
    const moho::SjChunkRange* secondChunk
  );
  extern "C" std::int32_t destroySub(M2TsdRuntimeView* runtimeView);
  extern "C" std::int32_t decodeTs(M2TsdRuntimeView* runtimeView);
  extern "C" std::int32_t decodePes(M2TsdRuntimeView* runtimeView, M2TsdRuntimeView** ioRuntimeCursor);
  extern "C" std::int32_t decodePesSub(
    M2TsdRuntimeView* runtimeView,
    M2TsdLaneRuntimeView* laneRuntime,
    std::int32_t chunkAddress,
    std::int32_t chunkBytes,
    std::int32_t* outReadEndAddress,
    M2TsdRuntimeView** ioRuntimeCursor
  );
  /**
   * Address: 0x00AE0390 (FUN_00AE0390, _movePes)
   *
   * What it does:
   * Moves one TS chunk into relay output lane and reports consumed bytes.
   */
  extern "C" std::int32_t movePes(
    M2TsdRuntimeView* runtimeView,
    std::int32_t chunkAddress,
    std::int32_t chunkBytes,
    std::int32_t* outReadEndAddress
  );
  extern "C" std::int32_t decodeTsSub(
    M2TsdRuntimeView* runtimeView,
    std::int32_t chunkAddress,
    std::int32_t chunkBytes,
    std::int32_t* outReadEndAddress
  );
  extern "C" std::int32_t MPS_CheckDelim(const void* packetPrefix);
  /**
   * Address: 0x00AE07D0 (FUN_00AE07D0, _searchIndex)
   *
   * What it does:
   * Finds lane index for one stream-id filter, or `-1` when absent.
   */
  extern "C" std::int32_t searchIndex(const M2TsdRuntimeView* runtimeView, std::int32_t streamIdFilter);

  /**
   * Address: 0x00AE0140 (FUN_00AE0140, _M2TSD_SetInSj)
   *
   * What it does:
   * Updates one M2TSD runtime status-gate input lane and mirrors non-zero
   * values into the process-global `m2tsd_insj` lane.
   */
  extern "C" std::int32_t M2TSD_SetInSj(M2TsdRuntimeView* const runtimeView, const std::int32_t inSjAddress)
  {
    if (runtimeView != nullptr) {
      runtimeView->statusGate =
        reinterpret_cast<M2TsdStatusGate*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(inSjAddress)));
    }

    if (inSjAddress != 0) {
      m2tsd_insj = inSjAddress;
    }

    return inSjAddress;
  }

  /**
   * Address: 0x00AE0160 (FUN_00AE0160, _M2TSD_SetOutSj)
   *
   * What it does:
   * Updates one lane's stream-id filter and chunk-join callback pair, and
   * mirrors callback addresses into process-global low-lane slots.
   */
  extern "C" std::int32_t M2TSD_SetOutSj(
    M2TsdRuntimeView* const runtimeView,
    const std::int32_t laneIndex,
    const std::int32_t streamIdFilter,
    const std::int32_t relayStreamJoinAddress,
    const std::int32_t outStreamJoinAddress
  )
  {
    if (streamIdFilter != -1) {
      runtimeView->laneEntries[laneIndex].streamIdFilter = streamIdFilter;
      runtimeView->decodeMode = 0;
    }

    M2TsdLaneRuntimeView& lane = runtimeView->laneEntries[laneIndex];
    lane.needsTerminationCheck = relayStreamJoinAddress;
    lane.callbackSinkAddress = outStreamJoinAddress;

    if (laneIndex < 3) {
      if (relayStreamJoinAddress != 0) {
        m2tsd_relaysj[laneIndex] = relayStreamJoinAddress;
      }
      if (outStreamJoinAddress != 0) {
        m2tsd_outsj[laneIndex] = outStreamJoinAddress;
      }
    }

    return laneIndex * static_cast<std::int32_t>(sizeof(M2TsdLaneRuntimeView));
  }

  /**
   * Address: 0x00AE0DD0 (FUN_00AE0DD0, _M2PES_Destroy)
   *
   * What it does:
   * Finds one matching active M2PES handle slot, clears that slot, and marks
   * the target runtime handle as destroyed.
   */
  extern "C" std::int32_t M2PES_Destroy(const std::int32_t streamSupplyAddress)
  {
    auto& slots = M2PesHandleSlots();
    for (std::size_t slotIndex = 0; slotIndex < slots.size(); ++slotIndex) {
      if (slots[slotIndex] != streamSupplyAddress) {
        continue;
      }

      slots[slotIndex] = 0;
      auto* const runtimeStatusWord = reinterpret_cast<std::int32_t*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(streamSupplyAddress))
      );
      *runtimeStatusWord = 1;
      return static_cast<std::int32_t>(slotIndex);
    }

    return static_cast<std::int32_t>(slots.size());
  }

  /**
   * Address: 0x00AE0E00 (FUN_00AE0E00, _M2PES_SetErrFn)
   *
   * What it does:
   * Stores one error callback function/object pair in the M2PES runtime
   * control lanes and returns the runtime address unchanged.
   */
  extern "C" std::int32_t
  M2PES_SetErrFn(const std::int32_t streamSupplyAddress, const std::int32_t callbackAddress, const std::int32_t callbackObject)
  {
    auto* const supplyView = reinterpret_cast<M2PesSupplyControlView*>(SjAddressToPointer(streamSupplyAddress));
    supplyView->errorCallbackAddress = callbackAddress;
    supplyView->errorCallbackObject = callbackObject;
    return streamSupplyAddress;
  }

  /**
   * Address: 0x00AE0E20 (FUN_00AE0E20, _M2PES_GetStat)
   *
   * What it does:
   * Returns the status lane from one M2PES runtime control block.
   */
  extern "C" std::int32_t M2PES_GetStat(const std::int32_t streamSupplyAddress)
  {
    const auto* const supplyView = reinterpret_cast<const M2PesSupplyControlView*>(SjAddressToPointer(streamSupplyAddress));
    return supplyView->status;
  }

  /**
   * Address: 0x00AE0E40 (FUN_00AE0E40, _M2PES_DecHd)
   *
   * What it does:
   * Initializes one M2PES decode pass, searches for PES delimiters, parses one
   * packet header lane, and reports how many input bytes should be committed.
   */
  extern "C" std::int32_t M2PES_DecHd(
    const std::int32_t streamSupplyAddress,
    const std::int32_t chunkAddress,
    const std::int32_t chunkBytes,
    std::int32_t* const outReadEndAddress
  )
  {
    constexpr std::int32_t kDelimiterProgramStreamMap = static_cast<std::int32_t>(0x00040000u);
    constexpr std::int32_t kDelimiterSystemEndOrPsm = static_cast<std::int32_t>(0xFFFF0000u);

    auto* const runtimeView = reinterpret_cast<M2PesDecodeRuntimeView*>(SjAddressToPointer(streamSupplyAddress));
    if (runtimeView == nullptr) {
      return 0;
    }

    *outReadEndAddress = 0;
    (void)initChunks_m2spes(reinterpret_cast<M2PesHandleInitRuntimeView*>(runtimeView));
    runtimeView->bitScratchWord = 0;

    const std::int32_t status = runtimeView->status;
    if (status == 1 || status == 4) {
      return 0;
    }

    auto* const chunkBuffer = reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(chunkAddress)));
    std::uint8_t* const delimiter = M2S_SearchDelim(chunkBuffer, chunkBytes, kDelimiterProgramStreamMap);

    if (delimiter != chunkBuffer) {
      if (delimiter == nullptr) {
        const std::int32_t fallbackAdvance = ((chunkBytes - 3) > 0) ? (chunkBytes - 3) : 0;
        *outReadEndAddress = fallbackAdvance;
        if (fallbackAdvance != 0) {
          return 0;
        }
        (void)shartSupply(reinterpret_cast<M2PesSupplyControlView*>(runtimeView));
        return 0;
      }

      *outReadEndAddress = static_cast<std::int32_t>(delimiter - chunkBuffer);
      return 0;
    }

    if (chunkBytes < 6 || (MPS_CheckDelim(chunkBuffer) & kDelimiterProgramStreamMap) == 0) {
      (void)shartSupply(reinterpret_cast<M2PesSupplyControlView*>(runtimeView));
      return 0;
    }

    std::int32_t packetPayloadBytes =
      (static_cast<std::int32_t>(chunkBuffer[4]) << 8) | static_cast<std::int32_t>(chunkBuffer[5]);

    if (packetPayloadBytes == 0) {
      std::uint8_t* const nextDelimiter =
        M2S_SearchDelim(chunkBuffer + 1, chunkBytes - 1, kDelimiterSystemEndOrPsm);
      if (nextDelimiter == nullptr) {
        (void)shartSupply(reinterpret_cast<M2PesSupplyControlView*>(runtimeView));
        return 0;
      }

      packetPayloadBytes = static_cast<std::int32_t>(nextDelimiter - chunkBuffer) - 6;
      runtimeView->fallbackPacketPayloadBytes = packetPayloadBytes;
    }

    const std::int32_t packetTotalBytes = packetPayloadBytes + 6;
    if (chunkBytes < packetTotalBytes) {
      (void)shartSupply(reinterpret_cast<M2PesSupplyControlView*>(runtimeView));
      return 0;
    }

    if (parse_PES_packet_sub(runtimeView, chunkBuffer, chunkBytes) == -1) {
      *outReadEndAddress = packetTotalBytes;
      return 0;
    }

    std::int32_t parserAdvanceBytes = runtimeView->parsedPayloadAdvanceBytes;
    if (parserAdvanceBytes <= runtimeView->parsedHeaderAdvanceBytes) {
      parserAdvanceBytes = runtimeView->parsedHeaderAdvanceBytes;
    }

    *outReadEndAddress = packetTotalBytes - parserAdvanceBytes;
    if (runtimeView->status == 2) {
      runtimeView->status = 3;
    }
    return 1;
  }

  /**
   * Address: 0x00AE0E30 (FUN_00AE0E30, _M2PES_TermSupply)
   *
   * What it does:
   * Sets the M2PES terminate-request flag and returns the runtime address.
   */
  extern "C" std::int32_t M2PES_TermSupply(const std::int32_t streamSupplyAddress)
  {
    auto* const supplyView = reinterpret_cast<M2PesSupplyControlView*>(SjAddressToPointer(streamSupplyAddress));
    supplyView->terminateEnableFlag = 1;
    return streamSupplyAddress;
  }

  /**
   * Address: 0x00AE0F60 (FUN_00AE0F60, _shartSupply)
   *
   * What it does:
   * Promotes one M2PES runtime to finished state (`status = 4`) once the
   * terminate-request flag is armed.
   */
  extern "C" M2PesSupplyControlView* shartSupply(M2PesSupplyControlView* const supplyView)
  {
    if (supplyView->terminateEnableFlag != 0) {
      supplyView->status = 4;
    }
    return supplyView;
  }

  /**
   * Address: 0x00AE33A0 (FUN_00AE33A0, _M2T_Destroy)
   *
   * What it does:
   * Finds one matching active M2T handle slot, clears that slot, and marks
   * the target runtime handle as destroyed.
   */
  extern "C" std::int32_t M2T_Destroy(const std::int32_t streamSupplyAddress)
  {
    auto& slots = M2THandleSlots();
    for (std::size_t slotIndex = 0; slotIndex < slots.size(); ++slotIndex) {
      if (slots[slotIndex] != streamSupplyAddress) {
        continue;
      }

      slots[slotIndex] = 0;
      auto* const runtimeStatusWord = reinterpret_cast<std::int32_t*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(streamSupplyAddress))
      );
      *runtimeStatusWord = 1;
      return static_cast<std::int32_t>(slotIndex);
    }

    return static_cast<std::int32_t>(slots.size());
  }

  /**
   * Address: 0x00AE33D0 (FUN_00AE33D0, _M2T_SetErrFn)
   *
   * What it does:
   * Stores one error callback function/object pair in the M2T runtime control lanes.
   */
  extern "C" std::int32_t
  M2T_SetErrFn(const std::int32_t streamSupplyAddress, const std::int32_t callbackAddress, const std::int32_t callbackObject)
  {
    auto* const supplyView = reinterpret_cast<M2PesSupplyControlView*>(SjAddressToPointer(streamSupplyAddress));
    supplyView->errorCallbackAddress = callbackAddress;
    supplyView->errorCallbackObject = callbackObject;
    return streamSupplyAddress;
  }

  /**
   * Address: 0x00AE33F0 (FUN_00AE33F0, _M2T_GetStat)
   *
   * What it does:
   * Returns the status lane from one M2T runtime control block.
   */
  extern "C" std::int32_t M2T_GetStat(const std::int32_t streamSupplyAddress)
  {
    const auto* const supplyView = reinterpret_cast<const M2TsdSupplyStatusView*>(SjAddressToPointer(streamSupplyAddress));
    return supplyView->status;
  }

  /**
   * Address: 0x00AE3400 (FUN_00AE3400, _M2T_TermSupply)
   *
   * What it does:
   * Sets the M2T runtime terminate-request flag and returns the runtime address.
   */
  extern "C" std::int32_t M2T_TermSupply(const std::int32_t streamSupplyAddress)
  {
    auto* const supplyView = reinterpret_cast<M2TsdSupplyStatusView*>(SjAddressToPointer(streamSupplyAddress));
    supplyView->terminateFlag = 1;
    return streamSupplyAddress;
  }

  /**
   * Address: 0x00AE3500 (FUN_00AE3500, _shortSupply)
   *
   * What it does:
   * Marks one supply runtime as finished (`status = 4`) when termination has
   * been requested.
   */
  extern "C" M2TsdSupplyStatusView* shortSupply(M2TsdSupplyStatusView* const supplyView)
  {
    if (supplyView->terminateFlag != 0) {
      supplyView->status = 4;
    }
    return supplyView;
  }

  moho::SjChunkRange* SJ_SplitChunk(
    const moho::SjChunkRange* sourceChunk,
    std::int32_t splitAddress,
    moho::SjChunkRange* outSourceChunk,
    moho::SjChunkRange* outSplitChunk
  );
  char* MPV_SearchDelim(const char* chunkAddress, std::int32_t chunkBytes, std::int32_t delimiterMask);

  /**
   * Address: 0x00AE0050 (FUN_00AE0050, _destroySub)
   *
   * What it does:
   * Destroys every active M2PES lane for one M2TSD runtime handle, tears down
   * the M2T supply lane, and resets handle state to idle.
   */
  extern "C" std::int32_t destroySub(M2TsdRuntimeView* const runtimeView)
  {
    if (runtimeView == nullptr) {
      return 0;
    }

    for (std::int32_t laneIndex = 0; laneIndex < runtimeView->laneCount; ++laneIndex) {
      std::int32_t& m2pesSupplyAddress = runtimeView->laneEntries[laneIndex].m2pesSupplyAddress;
      if (m2pesSupplyAddress != 0) {
        (void)M2PES_Destroy(m2pesSupplyAddress);
        m2pesSupplyAddress = 0;
      }
    }

    std::int32_t destroyResult = runtimeView->m2tSupplyAddress;
    if (destroyResult != 0) {
      destroyResult = M2T_Destroy(runtimeView->m2tSupplyAddress);
      runtimeView->m2tSupplyAddress = 0;
    }

    runtimeView->status = 1;
    return destroyResult;
  }

  /**
   * Address: 0x00AE00C0 (FUN_00AE00C0, _M2TSD_SetErrFn)
   *
   * What it does:
   * Sets one M2TSD error callback pair on the owner runtime and propagates it
   * to the active M2T lane plus each active M2PES lane.
   */
  extern "C" std::int32_t M2TSD_SetErrFn(
    M2TsdRuntimeView* const runtimeView,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    runtimeView->errorCallbackAddress = callbackAddress;
    runtimeView->errorCallbackObject = callbackObject;

    if (runtimeView->m2tSupplyAddress != 0) {
      (void)M2T_SetErrFn(runtimeView->m2tSupplyAddress, callbackAddress, callbackObject);
    }

    const std::int32_t laneCount = runtimeView->laneCount;
    for (std::int32_t laneIndex = 0; laneIndex < laneCount; ++laneIndex) {
      const std::int32_t laneSupplyAddress = runtimeView->laneEntries[laneIndex].m2pesSupplyAddress;
      if (laneSupplyAddress != 0) {
        (void)M2PES_SetErrFn(laneSupplyAddress, callbackAddress, callbackObject);
      }
    }

    return laneCount;
  }

  /**
   * Address: 0x00AE0B40 (FUN_00AE0B40, _updateStat_m2tsd)
   *
   * What it does:
   * Advances the M2TSD state machine after decode progress, terminates the
   * active M2T or M2PES supply chain when the controller reports closure, and
   * marks the runtime finished once every lane has drained.
   */
  std::int32_t updateStat_m2tsd(M2TsdRuntimeView* const runtimeView, const std::int32_t didDecodeSomething)
  {
    constexpr std::int32_t kStateReady = 2;
    constexpr std::int32_t kStateClosing = 3;
    constexpr std::int32_t kStateFinished = 4;

    if (runtimeView->status == kStateReady && didDecodeSomething != 0) {
      runtimeView->status = kStateClosing;
    }

    if (runtimeView->controllerGateEnabled != 0) {
      if (runtimeView->streamActiveFlag != 0 && runtimeView->statusGate->QueryGate(1) == 0) {
        for (std::int32_t laneIndex = 0; laneIndex < runtimeView->laneCount; ++laneIndex) {
          M2PES_TermSupply(runtimeView->laneEntries[laneIndex].m2pesSupplyAddress);
        }
      }
    } else {
      if (runtimeView->streamActiveFlag != 0) {
        M2T_TermSupply(runtimeView->m2tSupplyAddress);
      }

      if (M2T_GetStat(runtimeView->m2tSupplyAddress) == kStateFinished) {
        for (std::int32_t laneIndex = 0; laneIndex < runtimeView->laneCount; ++laneIndex) {
          M2PES_TermSupply(runtimeView->laneEntries[laneIndex].m2pesSupplyAddress);
        }
      }
    }

    std::int32_t drainedLaneCount = 0;
    for (std::int32_t laneIndex = 0; laneIndex < runtimeView->laneCount; ++laneIndex) {
      const auto& lane = runtimeView->laneEntries[laneIndex];
      if (lane.needsTerminationCheck != 0 && M2PES_GetStat(lane.m2pesSupplyAddress) != kStateFinished) {
        break;
      }

      ++drainedLaneCount;
    }

    const std::int32_t laneCount = runtimeView->laneCount;
    if (drainedLaneCount == laneCount) {
      runtimeView->status = kStateFinished;
    }

    return laneCount;
  }

  /**
   * Address: 0x00ADFEC0 (FUN_00ADFEC0, _initHn_m2tsd)
   *
   * What it does:
   * Clears one M2TSD runtime handle, creates M2T/M2PES supply lanes, and
   * marks the handle ready once all per-lane decoders are initialized.
   */
  extern "C" M2TsdRuntimeView*
  initHn_m2tsd(
    M2TsdRuntimeView* const runtimeView,
    const std::int32_t laneCount,
    const std::int32_t laneEntriesAddress,
    const std::int32_t m2tWorkAddress,
    std::int32_t m2pesWorkAddress
  )
  {
    std::memset(runtimeView, 0, sizeof(M2TsdRuntimeView));
    runtimeView->decodeMode = 1;
    runtimeView->streamEndCode = -1;

    runtimeView->m2tSupplyAddress = M2T_Create(m2tWorkAddress, 384);
    if (runtimeView->m2tSupplyAddress == 0) {
      return nullptr;
    }

    runtimeView->statusGate = nullptr;
    runtimeView->laneCount = laneCount;
    runtimeView->laneEntries = reinterpret_cast<M2TsdLaneRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(laneEntriesAddress))
    );
    runtimeView->reservedB8 = 0;
    runtimeView->controllerGateEnabled = 0;
    runtimeView->tsMapCallbackAddress = 0;
    runtimeView->tsMapCallbackObject = 0;
    runtimeView->pesCallbackAddress = 0;
    runtimeView->pesCallbackObject = 0;

    if (laneCount <= 0) {
      runtimeView->status = 2;
      return runtimeView;
    }

    for (std::int32_t laneIndex = 0; laneIndex < laneCount; ++laneIndex) {
      M2TsdLaneRuntimeView& lane = runtimeView->laneEntries[laneIndex];
      lane.laneState = 0;
      lane.streamIdFilter = -1;
      lane.callbackSinkAddress = 0;
      lane.needsTerminationCheck = 0;
      lane.callbackAddress = 0;
      lane.callbackObject = 0;
      lane.callbackReserved = 0;
      lane.payloadDispatchPending = 0;
      lane.streamEndMarker = -1;

      lane.m2pesSupplyAddress = M2PES_Create(m2pesWorkAddress, 324);
      if (lane.m2pesSupplyAddress == 0) {
        destroySub(runtimeView);
        return nullptr;
      }

      m2pesWorkAddress += 324;
    }

    runtimeView->status = 2;
    return runtimeView;
  }

  /**
   * Address: 0x00ADFE40 (FUN_00ADFE40, _M2TSD_Create)
   *
   * What it does:
   * Claims one free M2TSD handle slot, 32-byte-aligns caller work memory, and
   * initializes one M2TSD runtime plus lane-owned M2PES handles in that work
   * block.
   */
  extern "C" std::int32_t
  M2TSD_Create(const std::int32_t workAddress, const std::uint32_t workSizeBytes, const std::int32_t laneCount)
  {
    constexpr std::uint32_t kRuntimeBytes = static_cast<std::uint32_t>(sizeof(M2TsdRuntimeView)); // 0xD0
    constexpr std::uint32_t kLaneEntryBytes = static_cast<std::uint32_t>(sizeof(M2TsdLaneRuntimeView)); // 0x28
    constexpr std::uint32_t kM2PesWorkBytesPerLane = 0x144u;
    constexpr std::uint32_t kPerLaneBytes = 0x16Cu;
    constexpr std::uint32_t kCreateBaseBytes = 0x270u;

    if (workAddress == 0) {
      return 0;
    }

    const std::uint32_t laneCountWord = static_cast<std::uint32_t>(laneCount);
    const std::uint32_t requiredBytes = kPerLaneBytes * laneCountWord + kCreateBaseBytes;
    if (workSizeBytes < requiredBytes) {
      return 0;
    }

    auto& runtimeSlots = M2TsdHandleSlots();
    std::size_t freeSlotIndex = runtimeSlots.size();
    for (std::size_t slotIndex = 0; slotIndex < runtimeSlots.size(); ++slotIndex) {
      if (runtimeSlots[slotIndex] == 0) {
        freeSlotIndex = slotIndex;
        break;
      }
    }
    if (freeSlotIndex == runtimeSlots.size()) {
      return 0;
    }

    const std::int32_t alignedWorkAddress = Align32ByteAddress(workAddress);
    const std::int32_t laneEntriesAddress = alignedWorkAddress + static_cast<std::int32_t>(kRuntimeBytes);
    const std::int32_t m2pesWorkAddress =
      laneEntriesAddress + laneCount * static_cast<std::int32_t>(kLaneEntryBytes);
    const std::int32_t m2tWorkAddress =
      m2pesWorkAddress + laneCount * static_cast<std::int32_t>(kM2PesWorkBytesPerLane);

    M2TsdRuntimeView* const runtimeView = initHn_m2tsd(
      reinterpret_cast<M2TsdRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(alignedWorkAddress))),
      laneCount,
      laneEntriesAddress,
      m2tWorkAddress,
      m2pesWorkAddress
    );

    const std::int32_t runtimeAddress = SjPointerToAddress(runtimeView);
    runtimeSlots[freeSlotIndex] = runtimeAddress;
    return runtimeAddress;
  }

  /**
   * Address: 0x00AE0020 (FUN_00AE0020, _M2TSD_Destroy)
   *
   * What it does:
   * Finds one M2TSD runtime in the global slot table, clears its slot, and
   * tears down owned M2T/M2PES lanes through `destroySub`.
   */
  extern "C" std::int32_t M2TSD_Destroy(const std::int32_t runtimeAddress)
  {
    auto& runtimeSlots = M2TsdHandleSlots();
    std::int32_t slotIndex = 0;
    for (; slotIndex < static_cast<std::int32_t>(runtimeSlots.size()); ++slotIndex) {
      if (runtimeSlots[static_cast<std::size_t>(slotIndex)] == runtimeAddress) {
        runtimeSlots[static_cast<std::size_t>(slotIndex)] = 0;
        return destroySub(
          reinterpret_cast<M2TsdRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(runtimeAddress)))
        );
      }
    }

    return slotIndex;
  }

  /**
   * Address: 0x00AE0D80 (FUN_00AE0D80, _initChunks_m2spes)
   *
   * What it does:
   * Clears the 10-dword decoded-chunk lane used by one M2PES runtime handle.
   */
  extern "C" M2PesHandleInitRuntimeView* initChunks_m2spes(M2PesHandleInitRuntimeView* const runtimeView)
  {
    runtimeView->chunkLaneWords[0] = 0;
    runtimeView->chunkLaneWords[1] = 0;
    runtimeView->chunkLaneWords[2] = 0;
    runtimeView->chunkLaneWords[3] = 0;
    runtimeView->chunkLaneWords[4] = 0;
    runtimeView->chunkLaneWords[5] = 0;
    runtimeView->chunkLaneWords[6] = 0;
    runtimeView->chunkLaneWords[7] = 0;
    runtimeView->chunkLaneWords[8] = 0;
    runtimeView->chunkLaneWords[9] = 0;
    return runtimeView;
  }

  /**
   * Address: 0x00AE0D40 (FUN_00AE0D40, _initHn_m2spes)
   *
   * What it does:
   * Resets one M2PES runtime handle storage block and marks it ready.
   */
  extern "C" M2PesHandleInitRuntimeView* initHn_m2spes(M2PesHandleInitRuntimeView* const runtimeView)
  {
    std::memset(runtimeView, 0, sizeof(M2PesHandleInitRuntimeView));
    runtimeView->runtimeWord04 = 0;
    runtimeView->runtimeWord08 = 0;
    runtimeView->runtimeWord0C = 0;
    runtimeView->runtimeWord10 = 0;
    runtimeView->reservedF8 = 0;
    M2PesHandleInitRuntimeView* const result = initChunks_m2spes(runtimeView);
    runtimeView->status = 2;
    return result;
  }

  /**
   * Address: 0x00AE3360 (FUN_00AE3360, _initChunks)
   *
   * What it does:
   * Clears the 9-dword decoded-chunk lane used by one M2T runtime handle.
   */
  extern "C" M2THandleInitRuntimeView* initChunks(M2THandleInitRuntimeView* const runtimeView)
  {
    runtimeView->chunkLaneWords[0] = 0;
    runtimeView->chunkLaneWords[1] = 0;
    runtimeView->chunkLaneWords[2] = 0;
    runtimeView->chunkLaneWords[3] = 0;
    runtimeView->chunkLaneWords[4] = 0;
    runtimeView->chunkLaneWords[5] = 0;
    runtimeView->chunkLaneWords[6] = 0;
    runtimeView->chunkLaneWords[7] = 0;
    runtimeView->chunkLaneWords[8] = 0;
    return runtimeView;
  }

  /**
   * Address: 0x00AE3310 (FUN_00AE3310, _initHn_m2sts)
   *
   * What it does:
   * Resets one M2T runtime handle storage block and marks it ready.
   */
  extern "C" M2THandleInitRuntimeView* initHn_m2sts(M2THandleInitRuntimeView* const runtimeView)
  {
    std::memset(runtimeView, 0, sizeof(M2THandleInitRuntimeView));
    runtimeView->runtimeWord04 = 0;
    runtimeView->runtimeWord08 = 0;
    runtimeView->runtimeWord0C = 0;
    runtimeView->runtimeWord10 = 0;
    runtimeView->runtimeWord1C = 0;
    runtimeView->runtimeWord20 = 0;
    runtimeView->runtimeWord24 = 0;
    runtimeView->runtimeWord28 = 0;
    runtimeView->streamEndMarker = -1;
    M2THandleInitRuntimeView* const result = initChunks(runtimeView);
    runtimeView->status = 2;
    return result;
  }

  /**
   * Address: 0x00AE0CF0 (FUN_00AE0CF0, _M2PES_Create)
   *
   * What it does:
   * Claims one free M2PES handle slot from `M2T_libobj`, initializes one
   * aligned M2PES runtime handle, and returns that runtime address.
   */
  extern "C" std::int32_t M2PES_Create(const std::int32_t workAddress, const std::uint32_t workSizeBytes)
  {
    constexpr std::uint32_t kM2PesWorkBytes = 0x144u;
    if (workAddress == 0 || workSizeBytes < kM2PesWorkBytes) {
      return 0;
    }

    auto& pesSlots = M2PesHandleSlots();
    std::size_t freeSlotIndex = pesSlots.size();
    for (std::size_t slotIndex = 0; slotIndex < pesSlots.size(); ++slotIndex) {
      if (pesSlots[slotIndex] == 0) {
        freeSlotIndex = slotIndex;
        break;
      }
    }
    if (freeSlotIndex == pesSlots.size()) {
      return 0;
    }

    const std::int32_t alignedWorkAddress = Align32ByteAddress(workAddress);
    (void)initHn_m2spes(
      reinterpret_cast<M2PesHandleInitRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(alignedWorkAddress)))
    );
    pesSlots[freeSlotIndex] = alignedWorkAddress;
    return alignedWorkAddress;
  }

  /**
   * Address: 0x00AE0260 (FUN_00AE0260, _M2TSD_Decode)
   *
   * What it does:
   * Runs TS and PES decode loops until both make no progress (or decode cursor
   * closure is signaled), then updates M2TSD runtime status.
   */
  extern "C" void M2TSD_Decode(M2TsdRuntimeView* const runtimeView)
  {
    std::int32_t didDecodeSomething = 0;
    if (runtimeView == nullptr) {
      return;
    }

    runtimeView->decodeCycleProgressFlag = 0;
    if (runtimeView->status == 1 || runtimeView->status == 4) {
      return;
    }

    M2TsdRuntimeView* decodeCursor = runtimeView;
    do {
      std::int32_t tsDecodeCount = 0;
      while (decodeTs(runtimeView) == 1) {
        ++tsDecodeCount;
      }

      std::int32_t pesDecodeCount = 0;
      while (decodePes(runtimeView, &decodeCursor) == 1) {
        ++pesDecodeCount;
        if (decodeCursor != nullptr) {
          break;
        }
      }

      if (tsDecodeCount == 0 && pesDecodeCount == 0) {
        break;
      }

      didDecodeSomething = 1;
    } while (decodeCursor == nullptr);

    (void)updateStat_m2tsd(runtimeView, didDecodeSomething);
  }

  /**
   * Address: 0x00AE0300 (FUN_00AE0300, _decodeTs)
   *
   * What it does:
   * Pulls one readable TS chunk from the stream-join gate, dispatches either
   * PES move or TS decode sub-lane, then commits split chunks back to the
   * stream-join interface.
   */
  extern "C" std::int32_t decodeTs(M2TsdRuntimeView* const runtimeView)
  {
    SjChunkRuntimeView streamChunk{};
    std::int32_t splitChunkWords[2]{};
    moho::SjChunkRange committedChunk{};
    moho::SjChunkRange splitChunk{};

    auto* const streamJoin = runtimeView->statusGate;
    streamJoin->AcquireReadWindow(1, static_cast<std::int32_t>(0x7FFFFFFFu), &streamChunk.chunkAddress);

    std::int32_t readEndAddress = 0;
    const std::int32_t decodeResult = (runtimeView->controllerGateEnabled != 0)
      ? movePes(runtimeView, streamChunk.chunkAddress, streamChunk.chunkBytes, &readEndAddress)
      : decodeTsSub(runtimeView, streamChunk.chunkAddress, streamChunk.chunkBytes, &readEndAddress);

    const moho::SjChunkRange streamChunkRange{
      streamChunk.chunkAddress,
      streamChunk.chunkBytes,
    };
    (void)SJ_SplitChunk(&streamChunkRange, readEndAddress, &committedChunk, &splitChunk);
    streamChunk.chunkAddress = committedChunk.bufferAddress;
    streamChunk.chunkBytes = committedChunk.byteCount;
    splitChunkWords[0] = splitChunk.bufferAddress;
    splitChunkWords[1] = splitChunk.byteCount;
    streamJoin->CommitReadWindow(0, &streamChunk.chunkAddress);
    streamJoin->SubmitSplitChunk(1, splitChunkWords);
    return decodeResult;
  }

  /**
   * Address: 0x00AE0390 (FUN_00AE0390, _movePes)
   *
   * What it does:
   * Copies one TS chunk into lane-0 relay output when relay join is present,
   * otherwise reports direct pass-through byte count.
   */
  extern "C" std::int32_t movePes(
    M2TsdRuntimeView* const runtimeView,
    const std::int32_t chunkAddress,
    const std::int32_t chunkBytes,
    std::int32_t* const outReadEndAddress
  )
  {
    std::int32_t copiedBytes = chunkBytes;
    *outReadEndAddress = 0;
    if (chunkBytes <= 0) {
      return 0;
    }

    const std::int32_t relayStreamJoinAddress = runtimeView->laneEntries[0].needsTerminationCheck;
    if (relayStreamJoinAddress != 0) {
      auto* const relayJoin = AsM2TsdChunkIoGate(relayStreamJoinAddress);
      moho::SjChunkRange relayChunk{};
      relayJoin->AcquireChunk(0, chunkBytes, &relayChunk);
      if (relayChunk.byteCount == 0) {
        return 0;
      }

      (void)MEM_Copy(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(relayChunk.bufferAddress))),
        reinterpret_cast<const void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(chunkAddress))),
        static_cast<std::uint32_t>(relayChunk.byteCount)
      );
      relayJoin->CommitChunk(1, &relayChunk);
      copiedBytes = relayChunk.byteCount;
    }

    *outReadEndAddress = copiedBytes;
    return 1;
  }

  /**
   * Address: 0x00AE07D0 (FUN_00AE07D0, _searchIndex)
   *
   * What it does:
   * Scans M2TSD lane entries for one matching stream-id filter and returns the
   * lane index, or `-1` when no match exists.
   */
  extern "C" std::int32_t searchIndex(
    const M2TsdRuntimeView* const runtimeView,
    const std::int32_t streamIdFilter
  )
  {
    const std::int32_t laneCount = runtimeView->laneCount;
    if (laneCount <= 0) {
      return -1;
    }

    for (std::int32_t laneIndex = 0; laneIndex < laneCount; ++laneIndex) {
      if (runtimeView->laneEntries[laneIndex].streamIdFilter == streamIdFilter) {
        return laneIndex;
      }
    }

    return -1;
  }

  /**
   * Address: 0x00AE0800 (FUN_00AE0800, _decodePes)
   *
   * What it does:
   * Pulls PES chunks from every active lane supply, decodes one PES unit per
   * lane via `_decodePesSub`, then commits/splits chunk windows back to each
   * lane supply.
   */
  extern "C" std::int32_t decodePes(M2TsdRuntimeView* const runtimeView, M2TsdRuntimeView** const ioRuntimeCursor)
  {
    auto* const outCallbackResult = reinterpret_cast<std::int32_t*>(ioRuntimeCursor);
    *outCallbackResult = 0;

    std::int32_t didDecodeLane = 0;
    const std::int32_t laneCount = runtimeView->laneCount;
    if (laneCount <= 0) {
      return 0;
    }

    for (std::int32_t laneIndex = 0; laneIndex < laneCount; ++laneIndex) {
      M2TsdLaneRuntimeView& laneRuntime = runtimeView->laneEntries[laneIndex];
      if (laneRuntime.m2pesSupplyAddress == 0) {
        continue;
      }

      auto* const laneSupply = AsM2TsdChunkIoGate(laneRuntime.m2pesSupplyAddress);
      moho::SjChunkRange sourceChunk{};
      moho::SjChunkRange splitChunk{};

      laneSupply->AcquireChunk(1, static_cast<std::int32_t>(0x7FFFFFFFu), &sourceChunk);

      std::int32_t splitAddress = 0;
      if (
        decodePesSub(
          runtimeView,
          &laneRuntime,
          sourceChunk.bufferAddress,
          sourceChunk.byteCount,
          &splitAddress,
          ioRuntimeCursor
        ) == 1
      ) {
        didDecodeLane = 1;
      }

      (void)SJ_SplitChunk(&sourceChunk, splitAddress, &sourceChunk, &splitChunk);
      laneSupply->CommitChunk(0, &sourceChunk);
      laneSupply->ReturnChunk(1, &splitChunk);

      if (*outCallbackResult != 0) {
        break;
      }
    }

    return didDecodeLane;
  }

  /**
   * Address: 0x00AE0AD0 (FUN_00AE0AD0, _callCbFn)
   *
   * What it does:
   * Dispatches one optional lane callback and forwards reconstructed timestamp
   * lanes derived from the active M2PES packet runtime.
   */
  extern "C" std::int32_t callCbFn(
    M2TsdLaneRuntimeView* const laneRuntime,
    const std::int32_t streamSupplyAddress,
    const std::int32_t callbackSinkAddress,
    const moho::SjChunkRange* const firstChunk,
    const moho::SjChunkRange* const secondChunk
  )
  {
    using M2PesLaneCallback = std::int32_t(__cdecl*)(
      std::int32_t callbackObject,
      std::int32_t callbackSinkAddress,
      const moho::SjChunkRange* firstChunk,
      const moho::SjChunkRange* secondChunk,
      std::int32_t ptsWordLow,
      std::int32_t ptsWordHigh
    );

    auto* const callback = reinterpret_cast<M2PesLaneCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(laneRuntime->callbackAddress))
    );
    if (callback == nullptr) {
      return 0;
    }

    const auto* const packetRuntime = AsM2PesPacketRuntimeView(streamSupplyAddress);
    std::int32_t ptsWordLow = -1;
    std::int32_t ptsWordHigh = -1;
    if (packetRuntime->hasTimestampLane != 0) {
      const std::uint64_t packedHigh =
        (static_cast<std::uint64_t>(static_cast<std::uint32_t>(packetRuntime->timestampWord26)) << 15u)
        | static_cast<std::uint32_t>(packetRuntime->timestampWord27);
      const std::uint32_t packedLow =
        (static_cast<std::uint32_t>(packetRuntime->timestampWord26) << 15u)
        | static_cast<std::uint32_t>(packetRuntime->timestampWord27);
      ptsWordHigh = static_cast<std::int32_t>(packedHigh >> 17u);
      ptsWordLow = packetRuntime->timestampWord28 | static_cast<std::int32_t>(packedLow << 15u);
    }

    return callback(
      laneRuntime->callbackObject,
      callbackSinkAddress,
      firstChunk,
      secondChunk,
      ptsWordLow,
      ptsWordHigh
    );
  }

  /**
   * Address: 0x00AE08F0 (FUN_00AE08F0, _decodePesSub)
   *
   * What it does:
   * Decodes one PES header/payload lane, forwards payload bytes into callback
   * sink chunks, and emits optional stream-id callback notification.
   */
  extern "C" std::int32_t decodePesSub(
    M2TsdRuntimeView* const runtimeView,
    M2TsdLaneRuntimeView* const laneRuntime,
    const std::int32_t chunkAddress,
    const std::int32_t chunkBytes,
    std::int32_t* const outReadEndAddress,
    M2TsdRuntimeView** const ioRuntimeCursor
  )
  {
    auto* const outCallbackResult = reinterpret_cast<std::int32_t*>(ioRuntimeCursor);
    *outReadEndAddress = 0;
    *outCallbackResult = 0;

    const std::int32_t m2pesSupplyAddress = laneRuntime->m2pesSupplyAddress;
    auto* const pesPacketView = AsM2PesPacketRuntimeView(m2pesSupplyAddress);

    if (laneRuntime->payloadDispatchPending == 0) {
      const std::int32_t decodeHeaderResult = M2PES_DecHd(m2pesSupplyAddress, chunkAddress, chunkBytes, outReadEndAddress);
      if (*outReadEndAddress == 0) {
        return 0;
      }
      if (decodeHeaderResult == 0) {
        return 1;
      }
    }

    const std::int32_t callbackSinkAddress = laneRuntime->callbackSinkAddress;
    if (callbackSinkAddress == 0) {
      *outReadEndAddress += pesPacketView->decodedPayloadBytes;
      return 1;
    }

    auto* const callbackSink = AsM2TsdChunkIoGate(callbackSinkAddress);
    const std::int32_t decodedPayloadBytes = pesPacketView->decodedPayloadBytes;
    if (callbackSink->QueryCapacity(0) < decodedPayloadBytes) {
      laneRuntime->payloadDispatchPending = 1;
      return 0;
    }

    *outCallbackResult = callCbFn(laneRuntime, m2pesSupplyAddress, callbackSinkAddress, nullptr, nullptr);
    if (*outCallbackResult != 0) {
      laneRuntime->payloadDispatchPending = 1;
      return 0;
    }

    laneRuntime->payloadDispatchPending = 0;

    moho::SjChunkRange firstChunk{};
    callbackSink->AcquireChunk(0, decodedPayloadBytes, &firstChunk);

    std::int32_t firstCopyBytes = firstChunk.byteCount;
    if (firstCopyBytes > decodedPayloadBytes) {
      firstCopyBytes = decodedPayloadBytes;
    }

    std::memcpy(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(firstChunk.bufferAddress))),
      pesPacketView->decodedPayload,
      static_cast<std::size_t>(static_cast<std::uint32_t>(firstCopyBytes))
    );
    callbackSink->CommitChunk(1, &firstChunk);

    moho::SjChunkRange secondChunk{};
    if (firstCopyBytes < decodedPayloadBytes) {
      callbackSink->AcquireChunk(0, decodedPayloadBytes - firstCopyBytes, &secondChunk);
      std::memcpy(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(secondChunk.bufferAddress))),
        static_cast<const std::uint8_t*>(pesPacketView->decodedPayload) + firstCopyBytes,
        static_cast<std::size_t>(static_cast<std::uint32_t>(secondChunk.byteCount))
      );
      callbackSink->CommitChunk(1, &secondChunk);
    }

    *outCallbackResult = callCbFn(laneRuntime, m2pesSupplyAddress, callbackSinkAddress, &firstChunk, &secondChunk);
    *outReadEndAddress += decodedPayloadBytes;

    if (runtimeView->pesCallbackAddress != 0) {
      using DecodePesNotifyCallback = void(__cdecl*)(std::int32_t callbackObject, std::int32_t streamIdByte);
      auto* const callback = reinterpret_cast<DecodePesNotifyCallback>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(runtimeView->pesCallbackAddress))
      );
      callback(runtimeView->pesCallbackObject, pesPacketView->streamIdByte);
    }

    return 1;
  }

  struct SofdecCreateStreamDescriptor;

  struct SofdecCreateInfoRuntimeView
  {
    std::uint8_t headerWord0 = 0; // +0x00
    std::uint8_t headerWord1 = 0; // +0x01
    std::uint8_t reserved02_03[0x02]{}; // +0x02
    const SofdecCreateStreamDescriptor* streamDescriptor = nullptr; // +0x04
    const SofdecCreateStreamDescriptor* videoDescriptor = nullptr; // +0x08
    const void* audioDescriptor = nullptr; // +0x0C
    std::int32_t packetSizeBytes = 0; // +0x10
    std::int32_t videoWidthPixels = 0; // +0x14
    std::int32_t videoHeightPixels = 0; // +0x18
    std::int32_t streamTimingMetric = 0; // +0x1C
    std::int32_t videoFrameMetric = 0; // +0x20
    std::int32_t videoBitRate = 0; // +0x24
    std::int32_t frameCountMetric = 0; // +0x28
    std::int32_t extraMetric = 0; // +0x2C
    std::uint8_t reserved30_3F[0x10]{}; // +0x30
  };
  static_assert(offsetof(SofdecCreateInfoRuntimeView, headerWord0) == 0x00, "SofdecCreateInfoRuntimeView::headerWord0 offset must be 0x00");
  static_assert(offsetof(SofdecCreateInfoRuntimeView, headerWord1) == 0x01, "SofdecCreateInfoRuntimeView::headerWord1 offset must be 0x01");
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, streamDescriptor) == 0x04,
    "SofdecCreateInfoRuntimeView::streamDescriptor offset must be 0x04"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, videoDescriptor) == 0x08,
    "SofdecCreateInfoRuntimeView::videoDescriptor offset must be 0x08"
  );
  static_assert(offsetof(SofdecCreateInfoRuntimeView, audioDescriptor) == 0x0C, "SofdecCreateInfoRuntimeView::audioDescriptor offset must be 0x0C");
  static_assert(offsetof(SofdecCreateInfoRuntimeView, packetSizeBytes) == 0x10, "SofdecCreateInfoRuntimeView::packetSizeBytes offset must be 0x10");
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, videoWidthPixels) == 0x14,
    "SofdecCreateInfoRuntimeView::videoWidthPixels offset must be 0x14"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, videoHeightPixels) == 0x18,
    "SofdecCreateInfoRuntimeView::videoHeightPixels offset must be 0x18"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, streamTimingMetric) == 0x1C,
    "SofdecCreateInfoRuntimeView::streamTimingMetric offset must be 0x1C"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, videoFrameMetric) == 0x20,
    "SofdecCreateInfoRuntimeView::videoFrameMetric offset must be 0x20"
  );
  static_assert(offsetof(SofdecCreateInfoRuntimeView, videoBitRate) == 0x24, "SofdecCreateInfoRuntimeView::videoBitRate offset must be 0x24");
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, frameCountMetric) == 0x28,
    "SofdecCreateInfoRuntimeView::frameCountMetric offset must be 0x28"
  );
  static_assert(offsetof(SofdecCreateInfoRuntimeView, extraMetric) == 0x2C, "SofdecCreateInfoRuntimeView::extraMetric offset must be 0x2C");
  static_assert(sizeof(SofdecCreateInfoRuntimeView) == 0x40, "SofdecCreateInfoRuntimeView size must be 0x40");

  struct SfcreHeaderRuntimeView
  {
    std::int32_t headerValid = 0; // +0x00
    std::uint8_t reserved04[0x08]{}; // +0x04
    std::int32_t streamTimingMetric = 0; // +0x0C
    std::uint8_t reserved10[0x54]{}; // +0x10
    std::int32_t widthPixels = 0; // +0x64
    std::int32_t heightPixels = 0; // +0x68
    std::int32_t videoFrameMetric = 0; // +0x6C
  };
  static_assert(
    offsetof(SfcreHeaderRuntimeView, streamTimingMetric) == 0x0C,
    "SfcreHeaderRuntimeView::streamTimingMetric offset must be 0x0C"
  );
  static_assert(offsetof(SfcreHeaderRuntimeView, widthPixels) == 0x64, "SfcreHeaderRuntimeView::widthPixels offset must be 0x64");
  static_assert(
    offsetof(SfcreHeaderRuntimeView, heightPixels) == 0x68,
    "SfcreHeaderRuntimeView::heightPixels offset must be 0x68"
  );
  static_assert(
    offsetof(SfcreHeaderRuntimeView, videoFrameMetric) == 0x6C,
    "SfcreHeaderRuntimeView::videoFrameMetric offset must be 0x6C"
  );
  static_assert(sizeof(SfcreHeaderRuntimeView) == 0x70, "SfcreHeaderRuntimeView size must be 0x70");

  extern "C" SofdecCreateStreamDescriptor SFD_tr_sd_m2ts;
  extern "C" SofdecCreateStreamDescriptor SFD_tr_sd_mps;
  extern "C" SofdecCreateStreamDescriptor SFD_tr_vd_mpv;
  extern "C" void SFD_tr_ad_adxt();
  extern "C" std::int32_t ADXT_DetachMpa();
  extern "C" std::int32_t ADXT_DetachMPEG2AAC(void* adxtRuntime);
  extern "C" std::int32_t sfcre_mpv_picrate[];
  extern "C" void SFLIB_LockCs();
  extern "C" void SFLIB_UnlockCs();
  extern "C" SfcreHeaderRuntimeView sfcre_fhd;
  alignas(4) std::uint8_t sfcre_tmpbuf[2048]{};
  extern "C" std::int32_t M2T_IsConformable(char* buffer, std::int32_t sizeBytes);
  /**
   * Address: 0x00AF5860 (FUN_00AF5860, _M2S_SearchSyncByteGap)
   *
   * What it does:
   * Searches one MPEG-TS/M2S buffer for a sync-byte gap lane and returns the
   * first cursor that matches the recovered probe pattern.
   */
  extern "C" char*
    M2S_SearchSyncByteGap(char* buffer, std::int32_t sizeBytes, std::int32_t* outSyncGapValue);
  struct M2TStreamSupplyRuntimeView
  {
    std::uint8_t reserved00_37[0x38]{};
    std::int32_t parserStateWord = 0; // +0x38
  };
  static_assert(
    offsetof(M2TStreamSupplyRuntimeView, parserStateWord) == 0x38,
    "M2TStreamSupplyRuntimeView::parserStateWord offset must be 0x38"
  );

  struct M2TParserWindowRuntimeView
  {
    std::int32_t bufferAddress = 0; // +0x00
    std::int32_t bufferOffset = 0; // +0x04
  };
  static_assert(
    offsetof(M2TParserWindowRuntimeView, bufferAddress) == 0x00,
    "M2TParserWindowRuntimeView::bufferAddress offset must be 0x00"
  );
  static_assert(
    offsetof(M2TParserWindowRuntimeView, bufferOffset) == 0x04,
    "M2TParserWindowRuntimeView::bufferOffset offset must be 0x04"
  );
  static_assert(sizeof(M2TParserWindowRuntimeView) == 0x08, "M2TParserWindowRuntimeView size must be 0x08");

  struct M2TParserGapRuntimeView
  {
    std::uint8_t reserved00_23[0x24]{};
    std::int32_t packetStrideBytes = 0; // +0x24
    std::int32_t nextPacketStrideBytes = 0; // +0x28
    std::int32_t continuitySeed = 0; // +0x2C
    std::uint8_t reserved30_15B[0x12C]{};
    M2TParserWindowRuntimeView* parserWindow = nullptr; // +0x15C
  };
  static_assert(
    offsetof(M2TParserGapRuntimeView, packetStrideBytes) == 0x24,
    "M2TParserGapRuntimeView::packetStrideBytes offset must be 0x24"
  );
  static_assert(
    offsetof(M2TParserGapRuntimeView, nextPacketStrideBytes) == 0x28,
    "M2TParserGapRuntimeView::nextPacketStrideBytes offset must be 0x28"
  );
  static_assert(
    offsetof(M2TParserGapRuntimeView, continuitySeed) == 0x2C,
    "M2TParserGapRuntimeView::continuitySeed offset must be 0x2C"
  );
  static_assert(
    offsetof(M2TParserGapRuntimeView, parserWindow) == 0x15C,
    "M2TParserGapRuntimeView::parserWindow offset must be 0x15C"
  );
  static_assert(sizeof(M2TParserGapRuntimeView) == 0x160, "M2TParserGapRuntimeView size must be 0x160");

  struct M2TSectionRuntimeView
  {
    std::uint8_t reserved00_13[0x14]{};
    std::int32_t parserControlBits = 0; // +0x14
    std::uint8_t reserved18_CB[0xB4]{};
    std::int32_t patTableId = 0; // +0xCC
    std::int32_t patSectionSyntaxIndicator = 0; // +0xD0
    std::int32_t patSectionZeroBit = 0; // +0xD4
    std::int32_t patSectionLength = 0; // +0xD8
    std::int32_t patTransportStreamId = 0; // +0xDC
    std::int32_t patVersionNumber = 0; // +0xE0
    std::int32_t patCurrentNextIndicator = 0; // +0xE4
    std::int32_t patSectionNumber = 0; // +0xE8
    std::int32_t patLastSectionNumber = 0; // +0xEC
    std::int32_t patProgramNumberScratch = 0; // +0xF0
    std::int32_t patNetworkPid = 0; // +0xF4
    std::int32_t patProgramMapPid = 0; // +0xF8
    std::int32_t patTailBits = 0; // +0xFC
    std::int32_t pmapTableId = 0; // +0x100
    std::int32_t pmapSectionSyntaxIndicator = 0; // +0x104
    std::int32_t pmapSectionZeroBit = 0; // +0x108
    std::int32_t pmapSectionLength = 0; // +0x10C
    std::int32_t pmapProgramNumber = 0; // +0x110
    std::int32_t pmapVersionNumber = 0; // +0x114
    std::int32_t pmapCurrentNextIndicator = 0; // +0x118
    std::int32_t pmapSectionNumber = 0; // +0x11C
    std::int32_t pmapLastSectionNumber = 0; // +0x120
    std::int32_t pmapPcrPid = 0; // +0x124
    std::int32_t pmapProgramInfoLength = 0; // +0x128
    std::int32_t pmapStreamType = 0; // +0x12C
    std::int32_t pmapElementaryPid = 0; // +0x130
    std::int32_t pmapElementaryInfoLength = 0; // +0x134
    std::int32_t pmapTailBits = 0; // +0x138
  };
  static_assert(offsetof(M2TSectionRuntimeView, parserControlBits) == 0x14, "M2TSectionRuntimeView::parserControlBits offset must be 0x14");
  static_assert(offsetof(M2TSectionRuntimeView, patTableId) == 0xCC, "M2TSectionRuntimeView::patTableId offset must be 0xCC");
  static_assert(
    offsetof(M2TSectionRuntimeView, patSectionLength) == 0xD8,
    "M2TSectionRuntimeView::patSectionLength offset must be 0xD8"
  );
  static_assert(
    offsetof(M2TSectionRuntimeView, patTransportStreamId) == 0xDC,
    "M2TSectionRuntimeView::patTransportStreamId offset must be 0xDC"
  );
  static_assert(
    offsetof(M2TSectionRuntimeView, patProgramMapPid) == 0xF8,
    "M2TSectionRuntimeView::patProgramMapPid offset must be 0xF8"
  );
  static_assert(offsetof(M2TSectionRuntimeView, pmapTableId) == 0x100, "M2TSectionRuntimeView::pmapTableId offset must be 0x100");
  static_assert(
    offsetof(M2TSectionRuntimeView, pmapSectionLength) == 0x10C,
    "M2TSectionRuntimeView::pmapSectionLength offset must be 0x10C"
  );
  static_assert(
    offsetof(M2TSectionRuntimeView, pmapProgramInfoLength) == 0x128,
    "M2TSectionRuntimeView::pmapProgramInfoLength offset must be 0x128"
  );
  static_assert(
    offsetof(M2TSectionRuntimeView, pmapElementaryPid) == 0x130,
    "M2TSectionRuntimeView::pmapElementaryPid offset must be 0x130"
  );
  static_assert(offsetof(M2TSectionRuntimeView, pmapTailBits) == 0x138, "M2TSectionRuntimeView::pmapTailBits offset must be 0x138");
  static_assert(sizeof(M2TSectionRuntimeView) >= 0x13C, "M2TSectionRuntimeView size must cover PMAP lanes");

  struct M2TPatProgramEntryRuntimeView
  {
    std::uint16_t programNumber = 0; // +0x00
    std::uint16_t programPid = 0; // +0x02
  };
  static_assert(sizeof(M2TPatProgramEntryRuntimeView) == 0x04, "M2TPatProgramEntryRuntimeView size must be 0x04");

  struct M2TPatTableRuntimeView
  {
    std::int32_t entryCount = 0; // +0x00
    M2TPatProgramEntryRuntimeView entries[16]{};
  };
  static_assert(offsetof(M2TPatTableRuntimeView, entryCount) == 0x00, "M2TPatTableRuntimeView::entryCount offset must be 0x00");
  static_assert(offsetof(M2TPatTableRuntimeView, entries) == 0x04, "M2TPatTableRuntimeView::entries offset must be 0x04");
  static_assert(sizeof(M2TPatTableRuntimeView) == 0x44, "M2TPatTableRuntimeView size must be 0x44");

  struct M2TPmapStreamEntryRuntimeView
  {
    std::uint8_t streamType = 0; // +0x00
    std::uint8_t reserved01 = 0; // +0x01
    std::uint16_t elementaryPid = 0; // +0x02
  };
  static_assert(sizeof(M2TPmapStreamEntryRuntimeView) == 0x04, "M2TPmapStreamEntryRuntimeView size must be 0x04");

  struct M2TPmapTableRuntimeView
  {
    std::int32_t entryCount = 0; // +0x00
    M2TPmapStreamEntryRuntimeView entries[16]{};
  };
  static_assert(offsetof(M2TPmapTableRuntimeView, entryCount) == 0x00, "M2TPmapTableRuntimeView::entryCount offset must be 0x00");
  static_assert(offsetof(M2TPmapTableRuntimeView, entries) == 0x04, "M2TPmapTableRuntimeView::entries offset must be 0x04");
  static_assert(sizeof(M2TPmapTableRuntimeView) == 0x44, "M2TPmapTableRuntimeView size must be 0x44");

  class M2TSectionBitReader
  {
   public:
    M2TSectionBitReader(const std::uint8_t* const bytes, const std::int32_t sizeBytes) noexcept
      : mBytes(bytes), mSizeBits((sizeBytes > 0) ? (sizeBytes * 8) : 0)
    {
    }

    [[nodiscard]] std::uint32_t ReadBits(const std::int32_t bitCount) noexcept
    {
      if (bitCount <= 0) {
        return 0;
      }

      std::uint32_t value = 0;
      for (std::int32_t bitIndex = 0; bitIndex < bitCount; ++bitIndex) {
        value <<= 1;
        if (mBitOffset < mSizeBits && mBytes != nullptr) {
          const std::int32_t byteOffset = mBitOffset >> 3;
          const std::int32_t bitInByte = 7 - (mBitOffset & 7);
          value |= (static_cast<std::uint32_t>(mBytes[byteOffset]) >> bitInByte) & 1u;
        }
        ++mBitOffset;
      }
      return value;
    }

    void SkipBits(const std::int32_t bitCount) noexcept
    {
      if (bitCount <= 0) {
        return;
      }

      mBitOffset += bitCount;
      if (mBitOffset > mSizeBits) {
        mBitOffset = mSizeBits;
      }
    }

    [[nodiscard]] const std::uint8_t* CurrentByteCursor() const noexcept
    {
      if (mBytes == nullptr) {
        return nullptr;
      }

      const std::int32_t byteOffset = mBitOffset >> 3;
      return mBytes + byteOffset;
    }

    [[nodiscard]] std::uint32_t PeekBits32() const noexcept
    {
      M2TSectionBitReader probe = *this;
      const std::int32_t remainingBits = mSizeBits - mBitOffset;
      const std::int32_t readBits = (remainingBits >= 32) ? 32 : ((remainingBits > 0) ? remainingBits : 0);
      const std::uint32_t value = probe.ReadBits(readBits);
      return (readBits == 32) ? value : (value << (32 - readBits));
    }

   private:
    const std::uint8_t* mBytes = nullptr;
    std::int32_t mSizeBits = 0;
    std::int32_t mBitOffset = 0;
  };

  /**
   * Address: 0x00AE4930 (FUN_00AE4930, _initPat)
   *
   * What it does:
   * Initializes one PAT parser table lane with cleared header state and
   * sixteen `0xFFFF` PID/tag pairs.
   */
  extern "C" std::uint16_t* initPat(std::int32_t* parserWorkWords);
  /**
   * Address: 0x00AE47B0 (FUN_00AE47B0, _analyzeGap)
   *
   * What it does:
   * Updates TS packet stride/continuity lanes by comparing adjacent packet-id
   * triplets in parser window data.
   */
  extern "C" std::int32_t analyzeGap(std::int32_t* parserWorkWords, std::int32_t availableBytes);
  /**
   * Address: 0x00AE50E0 (FUN_00AE50E0, _initPmap)
   *
   * What it does:
   * Initializes one PMAP parser table lane with cleared count and sixteen
   * entries seeded to `(stream_type=0, pid=0xFFFF)`.
   */
  extern "C" std::uint16_t* initPmap(std::int32_t* parserWorkWords);
  /**
   * Address: 0x00AE4960 (FUN_00AE4960, _parse_program_association_section)
   *
   * What it does:
   * Decodes one MPEG-TS PAT section and writes parsed table/header lanes into
   * stream-supply and PAT work buffers.
   */
  extern "C" char* parse_program_association_section(
    M2TStreamSupplyRuntimeView* streamSupply,
    char* payload,
    std::int32_t payloadBytes,
    std::int32_t* parserWorkWords
  );
  /**
   * Address: 0x00AE5100 (FUN_00AE5100, _parse_ts_program_map_section)
   *
   * What it does:
   * Decodes one MPEG-TS PMAP section and writes parsed elementary-stream lanes
   * into stream-supply and PMAP work buffers.
   */
  extern "C" char* parse_ts_program_map_section(
    M2TStreamSupplyRuntimeView* streamSupply,
    char* payload,
    std::int32_t payloadBytes,
    std::int32_t* parserWorkWords
  );
  extern "C" std::int32_t
    sfcre_AnalyPackSiz(std::int32_t bufferAddress, std::int32_t sizeBytes, std::int32_t* outPacketSizeBytes);
  extern "C" std::int32_t sfcre_AnalyMuxRate(
    std::int32_t decodeBufferAddress,
    std::int32_t decodeSizeBytes,
    std::int32_t* outMuxRateUnits50BytesPerSecond
  );
  extern "C" std::int32_t sfcre_SetDflCreInf(SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t sfcre_AnalyM2ts(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t sfcre_AnalyMps(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" void sfcre_AnalyCreInf(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" void sfcre_AnalySfh(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t sfcre_AnalyAudio(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t sfcre_AnalyMpv(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t SFADXT_IsHeader(char* buffer, std::int32_t sizeBytes, std::int32_t* outHeaderSizeBytes);
  extern "C" std::int32_t SFHDS_IsSfdHeader(std::int32_t bufferAddress, std::int32_t sizeBytes);
  extern "C" std::int32_t SFHDS_ProcessHdr(std::int32_t headerAddress);
  extern "C" void sfcre_ProcessHdr(std::int32_t bufferAddress, std::int32_t sizeBytes, std::int32_t headerAddress);
  extern "C" char* MPS_SearchDelim(char* buffer, std::int32_t sizeBytes, std::int32_t delimiterMask);
  extern "C" char* sfcre_GetPketData(std::int32_t packetAddress, std::int32_t packetWindowBytes);
  extern "C" std::int32_t sfcre_AnalyAdx(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t sfcre_AnalyAdxAlign4(
    char* buffer,
    std::int32_t sizeBytes,
    SofdecCreateInfoRuntimeView* createInfo
  );
  extern "C" std::int32_t sfcre_AnalyMpa(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  std::int32_t MPS_Create();
  std::int32_t MPS_DecHd(
    std::int32_t mpsHandleAddress,
    void* decodeRuntimeAddress,
    std::int32_t expectedLength,
    std::int32_t* ioParserRuntimeAddress,
    std::int32_t* ioHeaderRuntimeAddress
  );
  std::int32_t MPS_CheckDelim(const void* packetPrefix);
  std::int32_t MPS_Destroy(std::int32_t mpsHandleAddress);

  /**
   * Address: 0x00AE4930 (FUN_00AE4930, _initPat)
   *
   * What it does:
   * Clears PAT parser header lane and fills sixteen PAT entry pairs with
   * sentinel value `0xFFFF`.
   */
  extern "C" std::uint16_t* initPat(std::int32_t* const parserWorkWords)
  {
    parserWorkWords[0] = 0;
    std::uint16_t* entryWords = reinterpret_cast<std::uint16_t*>(parserWorkWords) + 3;
    for (std::int32_t index = 0; index < 16; ++index) {
      entryWords[-1] = 0xFFFFu;
      entryWords[0] = 0xFFFFu;
      entryWords += 2;
    }
    return entryWords;
  }

  /**
   * Address: 0x00AE50E0 (FUN_00AE50E0, _initPmap)
   *
   * What it does:
   * Clears PMAP parser entry count, then seeds sixteen PMAP entry lanes with
   * stream-type `0` and elementary-PID sentinel `0xFFFF`.
   */
  extern "C" std::uint16_t* initPmap(std::int32_t* const parserWorkWords)
  {
    auto* const parserTable = reinterpret_cast<M2TPmapTableRuntimeView*>(parserWorkWords);
    parserTable->entryCount = 0;

    auto* entryCursor = reinterpret_cast<std::uint8_t*>(parserWorkWords) + 6;
    for (std::int32_t index = 0; index < 16; ++index) {
      entryCursor[-2] = 0;
      *reinterpret_cast<std::uint16_t*>(entryCursor) = 0xFFFFu;
      entryCursor += 4;
    }

    return reinterpret_cast<std::uint16_t*>(entryCursor);
  }

  /**
   * Address: 0x00AE4960 (FUN_00AE4960, _parse_program_association_section)
   *
   * What it does:
   * Parses one PAT section from section payload bits and stores header fields
   * plus up to sixteen `(program_number, pid)` entries into PAT work lanes.
   */
  extern "C" char* parse_program_association_section(
    M2TStreamSupplyRuntimeView* const streamSupply,
    char* const payload,
    const std::int32_t payloadBytes,
    std::int32_t* const parserWorkWords
  )
  {
    if (streamSupply == nullptr || payload == nullptr || parserWorkWords == nullptr || payloadBytes <= 0) {
      return payload;
    }

    auto* const sectionState = reinterpret_cast<M2TSectionRuntimeView*>(streamSupply);
    auto* const parserTable = reinterpret_cast<M2TPatTableRuntimeView*>(parserWorkWords);

    M2TSectionBitReader bitReader(reinterpret_cast<const std::uint8_t*>(payload), payloadBytes);
    sectionState->patTableId = static_cast<std::int32_t>(bitReader.ReadBits(8));

    if (sectionState->patTableId == 0) {
      sectionState->patSectionSyntaxIndicator = static_cast<std::int32_t>(bitReader.ReadBits(1));
      sectionState->patSectionZeroBit = static_cast<std::int32_t>(bitReader.ReadBits(1));
      sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(2));
      sectionState->patSectionLength = static_cast<std::int32_t>(bitReader.ReadBits(12));
      sectionState->patTransportStreamId = static_cast<std::int32_t>(bitReader.ReadBits(16));
      sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(2));
      sectionState->patVersionNumber = static_cast<std::int32_t>(bitReader.ReadBits(5));
      sectionState->patCurrentNextIndicator = static_cast<std::int32_t>(bitReader.ReadBits(1));
      sectionState->patSectionNumber = static_cast<std::int32_t>(bitReader.ReadBits(8));
      sectionState->patLastSectionNumber = static_cast<std::int32_t>(bitReader.ReadBits(8));

      const std::int32_t sectionPayloadBytesNoCrc = sectionState->patSectionLength - 9;
      const std::int32_t entryCountInSection = (sectionPayloadBytesNoCrc > 0) ? (sectionPayloadBytesNoCrc >> 2) : 0;
      for (std::int32_t entryIndex = 0; entryIndex < entryCountInSection; ++entryIndex) {
        sectionState->patProgramNumberScratch = static_cast<std::int32_t>(bitReader.ReadBits(16));
        sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(3));
        const std::int32_t programPid = static_cast<std::int32_t>(bitReader.ReadBits(13));
        if (sectionState->patProgramNumberScratch != 0) {
          sectionState->patProgramMapPid = programPid;
        } else {
          sectionState->patNetworkPid = programPid;
        }

        const std::int32_t tableIndex = parserTable->entryCount;
        if (tableIndex < 16) {
          auto& entry = parserTable->entries[static_cast<std::size_t>(tableIndex)];
          entry.programNumber = static_cast<std::uint16_t>(sectionState->patProgramNumberScratch);
          entry.programPid = static_cast<std::uint16_t>((sectionState->patProgramNumberScratch != 0)
                                                          ? sectionState->patProgramMapPid
                                                          : sectionState->patNetworkPid);
        }
        ++parserTable->entryCount;
      }

      sectionState->patTailBits = static_cast<std::int32_t>(bitReader.PeekBits32());
    }

    return reinterpret_cast<char*>(const_cast<std::uint8_t*>(bitReader.CurrentByteCursor()));
  }

  /**
   * Address: 0x00AE5100 (FUN_00AE5100, _parse_ts_program_map_section)
   *
   * What it does:
   * Parses one PMAP section from section payload bits, updates PMAP header
   * lanes, and stores up to sixteen `(stream_type, elementary_pid)` entries.
   */
  extern "C" char* parse_ts_program_map_section(
    M2TStreamSupplyRuntimeView* const streamSupply,
    char* const payload,
    const std::int32_t payloadBytes,
    std::int32_t* const parserWorkWords
  )
  {
    if (streamSupply == nullptr || payload == nullptr || parserWorkWords == nullptr || payloadBytes <= 0) {
      return payload;
    }

    auto* const sectionState = reinterpret_cast<M2TSectionRuntimeView*>(streamSupply);
    auto* const parserTable = reinterpret_cast<M2TPmapTableRuntimeView*>(parserWorkWords);

    M2TSectionBitReader bitReader(reinterpret_cast<const std::uint8_t*>(payload), payloadBytes);
    sectionState->pmapTableId = static_cast<std::int32_t>(bitReader.ReadBits(8));

    if (sectionState->pmapTableId == 2) {
      sectionState->pmapSectionSyntaxIndicator = static_cast<std::int32_t>(bitReader.ReadBits(1));
      sectionState->pmapSectionZeroBit = static_cast<std::int32_t>(bitReader.ReadBits(1));
      sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(2));
      sectionState->pmapSectionLength = static_cast<std::int32_t>(bitReader.ReadBits(12));
      sectionState->pmapProgramNumber = static_cast<std::int32_t>(bitReader.ReadBits(16));
      sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(2));
      sectionState->pmapVersionNumber = static_cast<std::int32_t>(bitReader.ReadBits(5));
      sectionState->pmapCurrentNextIndicator = static_cast<std::int32_t>(bitReader.ReadBits(1));
      sectionState->pmapSectionNumber = static_cast<std::int32_t>(bitReader.ReadBits(8));
      sectionState->pmapLastSectionNumber = static_cast<std::int32_t>(bitReader.ReadBits(8));
      sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(3));
      sectionState->pmapPcrPid = static_cast<std::int32_t>(bitReader.ReadBits(13));
      sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(4));
      sectionState->pmapProgramInfoLength = static_cast<std::int32_t>(bitReader.ReadBits(12));

      bitReader.SkipBits(sectionState->pmapProgramInfoLength * 8);

      std::int32_t sectionBytesRemaining = sectionState->pmapSectionLength - sectionState->pmapProgramInfoLength - 13;
      while (sectionBytesRemaining >= 5) {
        sectionState->pmapStreamType = static_cast<std::int32_t>(bitReader.ReadBits(8));
        sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(3));
        sectionState->pmapElementaryPid = static_cast<std::int32_t>(bitReader.ReadBits(13));
        sectionState->parserControlBits = static_cast<std::int32_t>(bitReader.ReadBits(4));
        sectionState->pmapElementaryInfoLength = static_cast<std::int32_t>(bitReader.ReadBits(12));

        bitReader.SkipBits(sectionState->pmapElementaryInfoLength * 8);
        sectionBytesRemaining -= (5 + sectionState->pmapElementaryInfoLength);

        const std::int32_t tableIndex = parserTable->entryCount;
        if (tableIndex < 16) {
          auto& entry = parserTable->entries[static_cast<std::size_t>(tableIndex)];
          entry.streamType = static_cast<std::uint8_t>(sectionState->pmapStreamType);
          entry.elementaryPid = static_cast<std::uint16_t>(sectionState->pmapElementaryPid);
        }
        ++parserTable->entryCount;
      }

      sectionState->pmapTailBits = static_cast<std::int32_t>(bitReader.PeekBits32());
    }

    return reinterpret_cast<char*>(const_cast<std::uint8_t*>(bitReader.CurrentByteCursor()));
  }

  /**
   * Address: 0x00AE47B0 (FUN_00AE47B0, _analyzeGap)
   *
   * What it does:
   * Computes the next TS packet gap/continuity decision from parser window
   * bytes and updates packet-stride lanes used by M2T header decode.
   */
  extern "C" std::int32_t analyzeGap(std::int32_t* const parserWorkWords, const std::int32_t availableBytes)
  {
    auto* const parserView = reinterpret_cast<M2TParserGapRuntimeView*>(parserWorkWords);
    M2TParserWindowRuntimeView* const parserWindow = parserView->parserWindow;

    if (parserWindow == nullptr) {
      parserView->nextPacketStrideBytes = 0;
      parserView->continuitySeed = -1;
      return 0;
    }

    const std::int32_t continuitySeed = parserView->continuitySeed;
    if (continuitySeed == -2) {
      parserView->nextPacketStrideBytes = parserView->packetStrideBytes;
      return parserView->packetStrideBytes;
    }

    const std::int32_t packetStrideBytes = parserView->packetStrideBytes;
    if (packetStrideBytes <= 0 || availableBytes < (packetStrideBytes + 2)) {
      parserView->nextPacketStrideBytes = 0;
      parserView->continuitySeed = -1;
      return 0;
    }

    const auto* const packetBase = reinterpret_cast<const std::uint8_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(parserWindow->bufferAddress + parserWindow->bufferOffset))
    );
    const auto* const probe = packetBase + packetStrideBytes - 4;

    auto read24 = [](const std::uint8_t* const bytes) -> std::int32_t {
      return (static_cast<std::int32_t>(bytes[0]) << 16)
        | (static_cast<std::int32_t>(bytes[1]) << 8)
        | static_cast<std::int32_t>(bytes[2]);
    };

    const std::int32_t prevTriplet = read24(probe - 2);
    const std::int32_t currentTriplet = read24(probe);
    const std::int32_t nextTriplet = read24(probe + 2);

    if (continuitySeed == -1) {
      parserView->nextPacketStrideBytes = packetStrideBytes;

      const std::int32_t expectedTriplet = read24(probe + packetStrideBytes + 188);
      const std::int32_t continuityNext = currentTriplet + 1;
      if (continuityNext == expectedTriplet) {
        parserView->continuitySeed = currentTriplet;
      } else {
        parserView->continuitySeed = -2;
      }
      return continuityNext;
    }

    const std::int32_t continuityNext = continuitySeed + 1;
    parserView->continuitySeed = continuityNext;

    if (continuityNext == currentTriplet) {
      parserView->nextPacketStrideBytes = packetStrideBytes;
      return continuityNext;
    }
    if (continuityNext == prevTriplet) {
      parserView->nextPacketStrideBytes = packetStrideBytes - 2;
      return continuityNext;
    }
    if (continuityNext == nextTriplet) {
      parserView->nextPacketStrideBytes = packetStrideBytes + 2;
      return parserView->nextPacketStrideBytes;
    }

    parserView->nextPacketStrideBytes = 0;
    parserView->continuitySeed = -1;
    return continuityNext;
  }

  /**
   * Address: 0x00AE48E0 (FUN_00AE48E0, _M2T_DecPat)
   *
   * What it does:
   * Initializes the PAT parser lane, then forwards the section payload to the
   * program-association parser when the stream-supply parser state is active.
   */
  extern "C" std::int32_t M2T_DecPat(
    M2TStreamSupplyRuntimeView* const streamSupply,
    const std::uint8_t* const payload,
    const std::int32_t payloadBytes,
    std::int32_t* const parserWorkWords
  )
  {
    if (streamSupply == nullptr || parserWorkWords == nullptr) {
      return 0;
    }

    initPat(parserWorkWords);
    const std::int32_t parserStateWord = streamSupply->parserStateWord;
    if (parserStateWord != 0) {
      const std::uint8_t sectionSkipBytes = payload[0];
      char* const sectionPayload = const_cast<char*>(
        reinterpret_cast<const char*>(payload + static_cast<std::size_t>(sectionSkipBytes) + 1u)
      );
      const std::int32_t sectionPayloadBytes = payloadBytes - static_cast<std::int32_t>(sectionSkipBytes) - 1;
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(
        parse_program_association_section(streamSupply, sectionPayload, sectionPayloadBytes, parserWorkWords)
      ));
    }

    return parserStateWord;
  }

  /**
   * Address: 0x00AE5090 (FUN_00AE5090, _M2T_DecPmap)
   *
   * What it does:
   * Initializes the PMAP parser lane, then forwards the section payload to the
   * TS program-map parser when the stream-supply parser state is active.
   */
  extern "C" char* M2T_DecPmap(
    M2TStreamSupplyRuntimeView* const streamSupply,
    const std::uint8_t* const payload,
    const std::int32_t payloadBytes,
    std::int32_t* const parserWorkWords
  )
  {
    if (streamSupply == nullptr || parserWorkWords == nullptr) {
      return nullptr;
    }

    initPmap(parserWorkWords);
    char* const parserStateWord = reinterpret_cast<char*>(static_cast<std::uintptr_t>(
      static_cast<std::uint32_t>(streamSupply->parserStateWord)
    ));
    if (parserStateWord != nullptr) {
      const std::uint8_t sectionSkipBytes = payload[0];
      char* const sectionPayload = const_cast<char*>(
        reinterpret_cast<const char*>(payload + static_cast<std::size_t>(sectionSkipBytes) + 1u)
      );
      const std::int32_t sectionPayloadBytes = payloadBytes - static_cast<std::int32_t>(sectionSkipBytes) - 1;
      return parse_ts_program_map_section(streamSupply, sectionPayload, sectionPayloadBytes, parserWorkWords);
    }

    return parserStateWord;
  }

  /**
   * Address: 0x00ADA080 (FUN_00ADA080, _sfcre_SetDflCreInf)
   *
   * What it does:
   * Clears one create-info lane to defaults before stream probing.
   */
  extern "C" std::int32_t sfcre_SetDflCreInf(SofdecCreateInfoRuntimeView* const createInfo)
  {
    std::memset(createInfo, 0, sizeof(SofdecCreateInfoRuntimeView));
    createInfo->headerWord0 = 0;
    createInfo->headerWord1 = 0;
    createInfo->streamDescriptor = nullptr;
    createInfo->videoDescriptor = nullptr;
    createInfo->audioDescriptor = nullptr;
    createInfo->packetSizeBytes = 0;
    createInfo->videoWidthPixels = 0;
    createInfo->videoHeightPixels = 0;
    createInfo->streamTimingMetric = 0;
    createInfo->videoFrameMetric = 0;
    createInfo->videoBitRate = 0;
    createInfo->frameCountMetric = 0;
    createInfo->extraMetric = 0;
    return 0;
  }

  /**
   * Address: 0x00AE3280 (FUN_00AE3280, _M2T_IsConformable)
   *
   * What it does:
   * Checks whether the input buffer is M2T-conformable by probing sync-byte
   * spacing, clamping the probe window to at most 1880 bytes.
   */
  extern "C" std::int32_t M2T_IsConformable(char* const buffer, std::int32_t sizeBytes)
  {
    constexpr std::int32_t kMaxProbeBytes = 1880;
    std::int32_t syncGapProbeValue = 0;

    if (sizeBytes > kMaxProbeBytes) {
      sizeBytes = kMaxProbeBytes;
    }

    return (M2S_SearchSyncByteGap(buffer, sizeBytes, &syncGapProbeValue) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AF5860 (FUN_00AF5860, _M2S_SearchSyncByteGap)
   *
   * What it does:
   * Searches one MPEG-TS/M2S buffer for a sync-byte gap lane and returns the
   * first cursor that matches the recovered probe pattern.
   */
  extern "C" char* M2S_SearchSyncByteGap(char* const buffer, std::int32_t sizeBytes, std::int32_t* const outSyncGapValue)
  {
    constexpr std::int32_t kSyncByteValue = 0x47;
    constexpr std::int32_t kPacketStrideBytes = 188;
    constexpr std::int32_t kThreePacketStrideBytes = 564;
    constexpr std::int32_t kProbeLaneCount = 24;

    const std::int32_t initialSyncGap = *outSyncGapValue;
    if (initialSyncGap == 0) {
      if (sizeBytes > kThreePacketStrideBytes) {
        std::int32_t scanOffset = 0;
        while (true) {
          std::int32_t probeLane = 0;
          std::int32_t forwardProbeAddress = kThreePacketStrideBytes + scanOffset;
          do {
            if (forwardProbeAddress >= sizeBytes) {
              break;
            }

            if (
              buffer[scanOffset] == kSyncByteValue
              && buffer[scanOffset + kPacketStrideBytes + probeLane] == kSyncByteValue
              && buffer[scanOffset + (2 * kPacketStrideBytes) + (2 * probeLane)] == kSyncByteValue
              && (
                (static_cast<std::uint8_t>(buffer[scanOffset + 1])
                 + 1 != static_cast<std::uint8_t>(buffer[scanOffset + kPacketStrideBytes + probeLane + 1]))
                || buffer[scanOffset + 2] != 1
                || buffer[scanOffset + kPacketStrideBytes + probeLane + 2] != 1
              )
            ) {
              *outSyncGapValue = probeLane;
              return &buffer[scanOffset];
            }

            ++probeLane;
            forwardProbeAddress += 3;
          } while (probeLane < kProbeLaneCount);

          ++scanOffset;
          if ((kThreePacketStrideBytes + scanOffset) < sizeBytes) {
            continue;
          }
          break;
        }
      }

      return nullptr;
    }

    std::int32_t scanLimitBytes = sizeBytes;
    std::int32_t scanAddress = (3 * initialSyncGap) + kThreePacketStrideBytes;
    if (scanAddress < sizeBytes) {
      std::int32_t scanOffset = 0;
      while (scanOffset < kPacketStrideBytes) {
        if (buffer[scanOffset] == kSyncByteValue) {
          if (
            buffer[initialSyncGap + kPacketStrideBytes + scanOffset] == kSyncByteValue
            && buffer[(2 * initialSyncGap) + (2 * kPacketStrideBytes) + scanOffset] == kSyncByteValue
          ) {
            return &buffer[scanOffset];
          }
          scanLimitBytes = sizeBytes;
        }

        ++scanOffset;
        if (++scanAddress >= scanLimitBytes) {
          break;
        }
      }
    }

    scanAddress = (3 * initialSyncGap) + kThreePacketStrideBytes;
    if (scanAddress >= scanLimitBytes) {
      return nullptr;
    }

    std::int32_t scanOffset = 0;
    do {
      if (buffer[scanOffset] == kSyncByteValue) {
        const char* const middlePacket = &buffer[initialSyncGap];
        if (
          (
            buffer[initialSyncGap + kPacketStrideBytes + scanOffset] == kSyncByteValue
            || middlePacket[scanOffset + 186] == kSyncByteValue
            || middlePacket[scanOffset + 190] == kSyncByteValue
          )
          && (
            buffer[(2 * initialSyncGap) + (2 * kPacketStrideBytes) + scanOffset] == kSyncByteValue
            || buffer[(2 * initialSyncGap) + 374 + scanOffset] == kSyncByteValue
            || buffer[(2 * initialSyncGap) + 378 + scanOffset] == kSyncByteValue
          )
        ) {
          if (
            static_cast<std::uint8_t>(buffer[scanOffset + 1]) + 1 != static_cast<std::uint8_t>(middlePacket[scanOffset + 189])
            || buffer[scanOffset + 2] != 1
            || middlePacket[scanOffset + 190] != 1
          ) {
            return &buffer[scanOffset];
          }

          scanLimitBytes = sizeBytes;
        }
      }

      ++scanOffset;
      ++scanAddress;
    } while (scanAddress < scanLimitBytes);

    return nullptr;
  }

  /**
   * Address: 0x00ADA0C0 (FUN_00ADA0C0, _sfcre_AnalyM2ts)
   *
   * What it does:
   * Detects M2TS-compatible input, binds M2TS stream descriptor, and delegates
   * MPV lane probing for video/audio descriptor lanes.
   */
  extern "C" std::int32_t
  sfcre_AnalyM2ts(char* const buffer, const std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* const createInfo)
  {
    const std::int32_t isConformable = M2T_IsConformable(buffer, sizeBytes);
    if (isConformable == 0) {
      return 0;
    }

    createInfo->streamDescriptor = &SFD_tr_sd_m2ts;
    (void)sfcre_AnalyMpv(buffer, sizeBytes, createInfo);
    if (createInfo->videoDescriptor != nullptr) {
      createInfo->audioDescriptor = reinterpret_cast<const void*>(&SFD_tr_ad_adxt);
    }
    return 1;
  }

  /**
   * Address: 0x00ADA880 (FUN_00ADA880, _sfcre_AnalyMpv)
   *
   * What it does:
   * Scans MPEG picture-start delimiters, extracts video dimensions and timing
   * metadata, and binds MPV video descriptor lanes when a valid sequence header
   * payload is found.
   */
  extern "C" std::int32_t
  sfcre_AnalyMpv(char* buffer, const std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* const createInfo)
  {
    std::int32_t remainingBytes = sizeBytes;
    if (remainingBytes > 0) {
      while (true) {
        char* const delimiter = MPV_SearchDelim(buffer, remainingBytes, 0x40);
        if (delimiter == nullptr) {
          return 0;
        }

        const std::uint8_t byte04 = static_cast<std::uint8_t>(delimiter[4]);
        const std::uint8_t byte05 = static_cast<std::uint8_t>(delimiter[5]);
        const std::uint8_t byte06 = static_cast<std::uint8_t>(delimiter[6]);
        const std::uint8_t byte07 = static_cast<std::uint8_t>(delimiter[7]);
        const std::uint8_t byte08 = static_cast<std::uint8_t>(delimiter[8]);
        const std::uint8_t byte09 = static_cast<std::uint8_t>(delimiter[9]);
        const std::uint8_t byte0A = static_cast<std::uint8_t>(delimiter[10]);
        const std::uint8_t byte0B = static_cast<std::uint8_t>(delimiter[11]);

        const std::int32_t consumedBytes = static_cast<std::int32_t>(delimiter - buffer) + 1;
        buffer = delimiter + 1;
        remainingBytes -= consumedBytes;

        const std::uint8_t pictureRateIndex = static_cast<std::uint8_t>(byte07 & 0x0Fu);
        const bool hasNonZeroSequenceHeader = (byte07 & 0xF0u) != 0;
        const bool hasSupportedRateIndex = (pictureRateIndex >= 1u) && (pictureRateIndex <= 8u);
        const bool hasSequenceExtension = (byte0A & 0x20u) != 0;
        if (hasNonZeroSequenceHeader && hasSupportedRateIndex && hasSequenceExtension) {
          createInfo->videoWidthPixels = (static_cast<std::int32_t>(byte04) << 4) | static_cast<std::int32_t>(byte05 >> 4);
          createInfo->videoHeightPixels =
            static_cast<std::int32_t>(byte06) | (static_cast<std::int32_t>(byte05 & 0x0Fu) << 8);

          if (createInfo->streamTimingMetric == 0) {
            const std::uint16_t sequenceWord = static_cast<std::uint16_t>((static_cast<std::uint16_t>(byte08) << 8) | byte09);
            const std::int32_t timingMetric =
              static_cast<std::int32_t>(byte0A >> 6) | (4 * static_cast<std::int32_t>(sequenceWord));
            createInfo->streamTimingMetric = timingMetric * 50;
          }

          createInfo->videoDescriptor = &SFD_tr_vd_mpv;
          createInfo->videoFrameMetric = sfcre_mpv_picrate[static_cast<std::size_t>(pictureRateIndex)];
          createInfo->videoBitRate =
            static_cast<std::int32_t>((static_cast<std::int32_t>(byte0B >> 3) | (32 * static_cast<std::int32_t>(byte0A & 0x1Fu)))
                                      << 11);
          return 1;
        }

        if (remainingBytes <= 0) {
          return 1;
        }
      }
    }

    return 1;
  }

  /**
   * Address: 0x00ADA020 (FUN_00ADA020, _sfcre_AnalyCreInf)
   *
   * What it does:
   * Resets one create-info lane and probes stream format in priority order:
   * M2TS -> MPS -> MPV -> ADX -> MPA.
   */
  extern "C" void
  sfcre_AnalyCreInf(char* const buffer, const std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* const createInfo)
  {
    sfcre_SetDflCreInf(createInfo);
    if (sfcre_AnalyM2ts(buffer, sizeBytes, createInfo) == 0 && sfcre_AnalyMps(buffer, sizeBytes, createInfo) == 0 &&
        sfcre_AnalyMpv(buffer, sizeBytes, createInfo) == 0 && sfcre_AnalyAdx(buffer, sizeBytes, createInfo) == 0) {
      (void)sfcre_AnalyMpa(buffer, sizeBytes, createInfo);
    }
  }

  /**
   * Address: 0x00AD9FC0 (FUN_00AD9FC0, _SFD_AnalyCreInf)
   *
   * What it does:
   * Runs create-info probing under SFLIB lock and raises header/stream-valid
   * flags when descriptor and packet-size lanes indicate playable content.
   */
  extern "C" void
  SFD_AnalyCreInf(const char* const buffer, const std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* const createInfo)
  {
    SFLIB_LockCs();
    sfcre_AnalyCreInf(const_cast<char*>(buffer), sizeBytes, createInfo);

    const bool hasVideoDescriptor = createInfo->videoDescriptor != nullptr;
    const bool hasAudioDescriptor = createInfo->audioDescriptor != nullptr;
    if (hasVideoDescriptor || hasAudioDescriptor || createInfo->packetSizeBytes == -1) {
      createInfo->headerWord0 = 1;
    }
    if (hasVideoDescriptor || hasAudioDescriptor) {
      createInfo->headerWord1 = 1;
    }

    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADA110 (FUN_00ADA110, _sfcre_AnalyMps)
   *
   * What it does:
   * Detects MPS packet sizing from one Sofdec create-info probe and fills MPS
   * descriptor lanes before delegating to stream/header/audio analyzers.
   */
  extern "C"
  std::int32_t sfcre_AnalyMps(char* const buffer, const std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* const createInfo)
  {
    std::int32_t packetSizeCandidate = sizeBytes;
    const std::int32_t packetSize = sfcre_AnalyPackSiz(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(buffer)),
      sizeBytes,
      &packetSizeCandidate
    );
    if (packetSize == 0) {
      return 0;
    }

    createInfo->packetSizeBytes = packetSize;
    if (packetSize != -1) {
      if (packetSizeCandidate > 0) {
        createInfo->streamTimingMetric = packetSizeCandidate * 50;
      }

      createInfo->streamDescriptor = &SFD_tr_sd_mps;
      sfcre_AnalySfh(buffer, sizeBytes, createInfo);
      sfcre_AnalyAudio(buffer, sizeBytes, createInfo);
      sfcre_AnalyMpv(buffer, sizeBytes, createInfo);
    }

    return 1;
  }

  /**
   * Address: 0x00ADA190 (FUN_00ADA190, _sfcre_AnalyPackSiz)
   *
   * What it does:
   * Searches three MPS delimiters to validate constant packet spacing, derives
   * packet size when spacing/alignment are valid, and updates mux-rate side
   * channel through `_sfcre_AnalyMuxRate`.
   */
  extern "C" std::int32_t sfcre_AnalyPackSiz(
    std::int32_t bufferAddress,
    const std::int32_t sizeBytes,
    std::int32_t* const outPacketSizeBytes
  )
  {
    auto* const buffer = reinterpret_cast<char*>(static_cast<std::uintptr_t>(bufferAddress));
    *outPacketSizeBytes = 0;

    char* const firstDelimiter = MPS_SearchDelim(buffer, sizeBytes, 0x10000);
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(firstDelimiter));
    if (firstDelimiter == nullptr) {
      return result;
    }

    const std::int32_t firstWindowBytes = sizeBytes - static_cast<std::int32_t>(firstDelimiter - buffer);
    char* const secondDelimiter = MPS_SearchDelim(firstDelimiter + 1, firstWindowBytes - 1, 0x10000);
    result = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(secondDelimiter));
    if (secondDelimiter == nullptr) {
      return result;
    }

    const std::int32_t secondWindowBytes = sizeBytes - static_cast<std::int32_t>(secondDelimiter - buffer) - 1;
    char* const thirdDelimiter = MPS_SearchDelim(secondDelimiter + 1, secondWindowBytes, 0x10000);
    result = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(thirdDelimiter));
    if (thirdDelimiter == nullptr) {
      return result;
    }

    const std::int32_t packetStrideBytes = static_cast<std::int32_t>(secondDelimiter - firstDelimiter);
    if (packetStrideBytes != static_cast<std::int32_t>(thirdDelimiter - secondDelimiter)) {
      return -1;
    }

    const std::int32_t firstDelimiterOffset = static_cast<std::int32_t>(firstDelimiter - buffer);
    if ((firstDelimiterOffset % packetStrideBytes) != 0) {
      return -1;
    }

    (void)sfcre_AnalyMuxRate(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(firstDelimiter)),
      firstWindowBytes,
      outPacketSizeBytes
    );
    return packetStrideBytes;
  }

  /**
   * Address: 0x00AF5A10 (FUN_00AF5A10, _M2S_CheckDelim)
   *
   * What it does:
   * Classifies one MPEG start-code prefix (`00 00 01 xx`) into CRI delimiter
   * masks used by M2S/MPS parser lanes.
   */
  extern "C" std::int32_t MPS_CheckDelim(const void* const packetPrefix)
  {
    constexpr std::int32_t kDelimiterSystemEndCode = static_cast<std::int32_t>(0x00080000u); // 0xB9
    constexpr std::int32_t kDelimiterPackHeader = static_cast<std::int32_t>(0x00010000u); // 0xBA
    constexpr std::int32_t kDelimiterSystemHeader = static_cast<std::int32_t>(0x00020000u); // 0xBB
    constexpr std::int32_t kDelimiterProgramStreamMap = static_cast<std::int32_t>(0x00040000u); // >= 0xBC

    if (packetPrefix == nullptr) {
      return 0;
    }

    const auto* const bytes = static_cast<const std::uint8_t*>(packetPrefix);
    if (bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 1) {
      return 0;
    }

    switch (bytes[3]) {
      case 0xB9:
        return kDelimiterSystemEndCode;
      case 0xBA:
        return kDelimiterPackHeader;
      case 0xBB:
        return kDelimiterSystemHeader;
      default:
        break;
    }

    if (bytes[3] >= 0xBC) {
      return kDelimiterProgramStreamMap;
    }

    return 0;
  }

  /**
   * Address: 0x00ADA450 (FUN_00ADA450, _MPS_SearchDelim)
   *
   * What it does:
   * Performs a bytewise scan for one MPEG packet delimiter code and returns the
   * first matching cursor; returns null when fewer than four bytes remain.
   */
  extern "C" char* MPS_SearchDelim(char* buffer, std::int32_t sizeBytes, const std::int32_t delimiterMask)
  {
    std::int32_t remainingBytes = sizeBytes;
    if (remainingBytes < 4) {
      return nullptr;
    }

    while (MPS_CheckDelim(buffer) != delimiterMask) {
      ++buffer;
      if (--remainingBytes < 4) {
        return nullptr;
      }
    }
    return buffer;
  }

  /**
   * Address: 0x00AECCE0 (FUN_00AECCE0, _search1_mps)
   *
   * What it does:
   * Scans for one MPEG start-code prefix whose trailing delimiter byte matches
   * `startCodeByte` exactly.
   */
  extern "C" std::uint8_t* search1_mps(
    std::uint8_t* const buffer,
    const std::int32_t sizeBytes,
    const std::uint8_t startCodeByte
  )
  {
    std::int32_t index = 0;
    if (sizeBytes <= 3) {
      return nullptr;
    }

    while (
      buffer[index] != 0
      || buffer[index + 1] != 0
      || buffer[index + 2] != 1
      || buffer[index + 3] != startCodeByte
    ) {
      ++index;
      if (index + 3 >= sizeBytes) {
        return nullptr;
      }
    }

    return buffer + index;
  }

  /**
   * Address: 0x00AF5B00 (FUN_00AF5B00, _searchU_m2s)
   *
   * What it does:
   * Scans for one raw MPEG start-code prefix (`00 00 01`) without checking the
   * trailing start-code byte.
   */
  extern "C" std::uint8_t* searchU_m2s(std::uint8_t* const buffer, const std::int32_t sizeBytes)
  {
    std::int32_t index = 0;
    if (sizeBytes <= 3) {
      return nullptr;
    }

    while (buffer[index] != 0 || buffer[index + 1] != 0 || buffer[index + 2] != 1) {
      ++index;
      if (index + 3 >= sizeBytes) {
        return nullptr;
      }
    }

    return buffer + index;
  }

  /**
   * Address: 0x00AF5B40 (FUN_00AF5B40, _search1_m2s)
   *
   * What it does:
   * Scans for one MPEG start-code prefix whose trailing delimiter byte matches
   * `startCodeByte` exactly.
   */
  extern "C"
  std::uint8_t* search1_m2s(std::uint8_t* const buffer, const std::int32_t sizeBytes, const std::uint8_t startCodeByte)
  {
    std::int32_t index = 0;
    if (sizeBytes <= 3) {
      return nullptr;
    }

    while (
      buffer[index] != 0
      || buffer[index + 1] != 0
      || buffer[index + 2] != 1
      || buffer[index + 3] != startCodeByte
    ) {
      ++index;
      if (index + 3 >= sizeBytes) {
        return nullptr;
      }
    }

    return buffer + index;
  }

  /**
   * Address: 0x00AF5B90 (FUN_00AF5B90, _searchR_m2s)
   *
   * What it does:
   * Scans for one MPEG start-code prefix whose trailing delimiter byte is at
   * least `minimumStartCodeByte`.
   */
  extern "C"
  std::uint8_t* searchR_m2s(
    std::uint8_t* const buffer,
    const std::int32_t sizeBytes,
    const std::uint8_t minimumStartCodeByte
  )
  {
    std::int32_t index = 0;
    if (sizeBytes <= 3) {
      return nullptr;
    }

    while (
      buffer[index] != 0
      || buffer[index + 1] != 0
      || buffer[index + 2] != 1
      || buffer[index + 3] < minimumStartCodeByte
    ) {
      ++index;
      if (index + 3 >= sizeBytes) {
        return nullptr;
      }
    }

    return buffer + index;
  }

  /**
   * Address: 0x00AF5BE0 (FUN_00AF5BE0, _searchM_m2s)
   *
   * What it does:
   * Scans for one `00 00 01` start-code prefix and returns the first matching
   * cursor when the delimiter mask check succeeds.
   */
  extern "C" std::uint8_t* searchM_m2s(
    std::uint8_t* const buffer,
    const std::int32_t sizeBytes,
    const std::int32_t delimiterMask
  )
  {
    if (sizeBytes <= 3) {
      return nullptr;
    }

    std::int32_t index = 0;
    while (
      buffer[index] != 0
      || buffer[index + 1] != 0
      || buffer[index + 2] != 1
      || (MPS_CheckDelim(buffer) & delimiterMask) == 0
    ) {
      ++index;
      if (index + 3 >= sizeBytes) {
        return nullptr;
      }
    }

    return buffer + index;
  }

  /**
   * Address: 0x00AF5A70 (FUN_00AF5A70, _M2S_SearchDelim)
   *
   * What it does:
   * Dispatches delimiter scanning to one specialized M2S search helper based on
   * the delimiter-mask selector used by CRI M2PES parser lanes.
   */
  extern "C"
  std::uint8_t* M2S_SearchDelim(std::uint8_t* const buffer, const std::int32_t sizeBytes, const std::int32_t delimiterMask)
  {
    constexpr std::int32_t kDelimiterPackHeader = static_cast<std::int32_t>(0x00010000u);
    constexpr std::int32_t kDelimiterSystemHeader = static_cast<std::int32_t>(0x00020000u);
    constexpr std::int32_t kDelimiterProgramStreamMap = static_cast<std::int32_t>(0x00040000u);
    constexpr std::int32_t kDelimiterSystemEndCode = static_cast<std::int32_t>(0x00080000u);
    constexpr std::int32_t kDelimiterSearchUpper = static_cast<std::int32_t>(0xFFFFFFFFu);
    constexpr std::int32_t kDelimiterSearchRange = static_cast<std::int32_t>(0xFFFF0000u);

    if (delimiterMask <= kDelimiterSystemHeader) {
      switch (delimiterMask) {
        case kDelimiterSystemHeader:
          return search1_m2s(buffer, sizeBytes, 0xBB);
        case kDelimiterSearchRange:
          return searchR_m2s(buffer, sizeBytes, 0xB9);
        case kDelimiterSearchUpper:
          return searchU_m2s(buffer, sizeBytes);
        case kDelimiterPackHeader:
          return search1_m2s(buffer, sizeBytes, 0xBA);
        default:
          return searchM_m2s(buffer, sizeBytes, delimiterMask);
      }
    }

    if (delimiterMask == kDelimiterProgramStreamMap) {
      return searchR_m2s(buffer, sizeBytes, 0xBC);
    }
    if (delimiterMask == kDelimiterSystemEndCode) {
      return search1_m2s(buffer, sizeBytes, 0xB9);
    }
    return searchM_m2s(buffer, sizeBytes, delimiterMask);
  }

  struct SfcreAauHeaderRuntimeView
  {
    std::uint8_t word0[4]{}; // +0x00
    std::uint8_t word1[4]{}; // +0x04
    std::uint8_t word2[4]{}; // +0x08
  };
  static_assert(offsetof(SfcreAauHeaderRuntimeView, word0) == 0x00, "SfcreAauHeaderRuntimeView::word0 offset must be 0x00");
  static_assert(offsetof(SfcreAauHeaderRuntimeView, word1) == 0x04, "SfcreAauHeaderRuntimeView::word1 offset must be 0x04");
  static_assert(offsetof(SfcreAauHeaderRuntimeView, word2) == 0x08, "SfcreAauHeaderRuntimeView::word2 offset must be 0x08");
  static_assert(sizeof(SfcreAauHeaderRuntimeView) == 0x0C, "SfcreAauHeaderRuntimeView size must be 0x0C");

  /**
   * Address: 0x00ADA800 (FUN_00ADA800, _sfcre_ReadAauHdr)
   *
   * What it does:
   * Decodes one 4-byte MPA AAU packed header into the expanded 12-byte
   * `SfcreAauHeaderRuntimeView` lane layout.
   */
  extern "C" SfcreAauHeaderRuntimeView* sfcre_ReadAauHdr(
    SfcreAauHeaderRuntimeView* const header,
    const std::uint8_t* const headerBytes
  )
  {
    const std::uint8_t byte1 = headerBytes[1];
    const std::uint8_t byte2 = headerBytes[2];
    const std::uint8_t byte3 = headerBytes[3];

    header->word0[0] = static_cast<std::uint8_t>((byte1 >> 1) & 3u);
    header->word0[1] = static_cast<std::uint8_t>(byte1 & 1u);
    header->word0[2] = static_cast<std::uint8_t>(byte2 >> 4);
    header->word0[3] = static_cast<std::uint8_t>((byte2 >> 2) & 3u);

    header->word1[1] = static_cast<std::uint8_t>(byte2 & 1u);
    header->word1[2] = static_cast<std::uint8_t>(byte3 >> 6);
    header->word1[3] = static_cast<std::uint8_t>((byte3 >> 4) & 3u);

    header->word2[0] = static_cast<std::uint8_t>((byte3 & 8u) != 0u);
    header->word1[0] = static_cast<std::uint8_t>((byte2 & 2u) != 0u);
    header->word2[1] = static_cast<std::uint8_t>((byte3 & 4u) != 0u);
    header->word2[2] = static_cast<std::uint8_t>(byte3 & 3u);
    return header;
  }

  /**
   * Address: 0x00ADA7A0 (FUN_00ADA7A0, _sfcre_SerachMpaAau)
   *
   * What it does:
   * Scans forward for one MPA AAU sync header, decodes the packed AAU header
   * bytes, and returns the matching cursor when the binary lane accepts it.
   */
  extern "C" std::uint8_t* sfcre_SerachMpaAau(
    SfcreAauHeaderRuntimeView* const header,
    std::uint8_t* buffer,
    const std::int32_t sizeBytes
  )
  {
    std::int32_t remainingBytes = sizeBytes;
    if (remainingBytes < 4) {
      return nullptr;
    }

    while (true) {
      if (buffer[0] == 0xFFu && (buffer[1] & 0xF8u) == 0xF8u) {
        sfcre_ReadAauHdr(header, buffer);

        if (header->word0[0] != 0u && header->word0[2] != 15u && header->word0[3] != 3u) {
          break;
        }
      }

      ++buffer;
      if (--remainingBytes < 4) {
        return nullptr;
      }
    }

    return buffer;
  }

  /**
   * Address: 0x00ADA360 (FUN_00ADA360, _sfcre_ProcessHdr)
   *
   * What it does:
   * Copies at most `0x800` bytes of header input into the SFHDS work lane,
   * stores copied length, then runs Sofdec header processing.
   */
  extern "C" void sfcre_ProcessHdr(
    const std::int32_t bufferAddress,
    const std::int32_t sizeBytes,
    const std::int32_t headerAddress
  )
  {
    std::int32_t copyBytes = sizeBytes;
    if (copyBytes > 0x800) {
      copyBytes = 0x800;
    }

    auto* const headerBytes = reinterpret_cast<std::uint8_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(headerAddress))
    );
    (void)MEM_Copy(headerBytes + 0x94, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(bufferAddress)), copyBytes);
    *reinterpret_cast<std::int32_t*>(headerBytes + 0x90) = copyBytes;
    (void)SFHDS_ProcessHdr(headerAddress);
  }

  /**
   * Address: 0x00ADA2B0 (FUN_00ADA2B0, _sfcre_AnalySfh)
   *
   * What it does:
   * Locates one valid SFD header lane inside packet-aligned windows, runs header
   * processing into `sfcre_fhd`, and propagates validated width/height/timing
   * fields into create-info lanes.
   */
  extern "C" void sfcre_AnalySfh(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* const createInfo)
  {
    std::int32_t remainingBytes = sizeBytes;
    const std::int32_t packetStrideBytes = createInfo->packetSizeBytes;
    char* cursor = buffer;
    std::int32_t probeCount = 0;

    if (SFHDS_IsSfdHeader(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(cursor)), remainingBytes) == 0) {
      while (true) {
        cursor += packetStrideBytes;
        remainingBytes -= packetStrideBytes;
        if (probeCount >= 3 || remainingBytes <= 0) {
          return;
        }

        ++probeCount;
        if (SFHDS_IsSfdHeader(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(cursor)), remainingBytes) != 0) {
          break;
        }
      }
    }

    sfcre_fhd.headerValid = 0;
    sfcre_ProcessHdr(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(cursor)),
      remainingBytes,
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&sfcre_fhd))
    );
    if (sfcre_fhd.headerValid == 0) {
      return;
    }

    if (sfcre_fhd.streamTimingMetric > 0) {
      createInfo->streamTimingMetric = sfcre_fhd.streamTimingMetric;
    }
    if (sfcre_fhd.widthPixels > 0) {
      createInfo->videoWidthPixels = sfcre_fhd.widthPixels;
    }
    if (sfcre_fhd.heightPixels > 0) {
      createInfo->videoHeightPixels = sfcre_fhd.heightPixels;
    }
    if (sfcre_fhd.videoFrameMetric > 0) {
      createInfo->videoFrameMetric = sfcre_fhd.videoFrameMetric;
      createInfo->videoDescriptor = &SFD_tr_vd_mpv;
    }
  }

  /**
   * Address: 0x00ADA490 (FUN_00ADA490, _sfcre_GetPketData)
   *
   * What it does:
   * Decodes one MPS header to resolve packet payload start offset and returns
   * payload pointer; falls back to `min(size, 6)` byte skip when parser create
   * fails.
   */
  extern "C" char* sfcre_GetPketData(const std::int32_t packetAddress, const std::int32_t packetWindowBytes)
  {
    const std::int32_t mpsHandleAddress = MPS_Create();
    if (mpsHandleAddress != 0) {
      std::int32_t packetDataOffset = 0;
      std::int32_t headerRuntimeAddress = 0;
      (void)MPS_DecHd(
        mpsHandleAddress,
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(packetAddress)),
        packetWindowBytes,
        &packetDataOffset,
        &headerRuntimeAddress
      );
      (void)MPS_Destroy(mpsHandleAddress);
      return reinterpret_cast<char*>(static_cast<std::uintptr_t>(packetAddress + packetDataOffset));
    }

    std::int32_t fallbackOffset = packetWindowBytes;
    if (fallbackOffset > 6) {
      fallbackOffset = 6;
    }
    return reinterpret_cast<char*>(static_cast<std::uintptr_t>(packetAddress + fallbackOffset));
  }

  /**
   * Address: 0x00ADA3A0 (FUN_00ADA3A0, _sfcre_AnalyAudio)
   *
   * What it does:
   * Scans MPS packet delimiters for audio stream ids (`0xC0..0xDF`) and
   * delegates packet payload analysis to ADX/MPA analyzers using the create-info
   * packet-size cap lane.
   */
  extern "C"
  std::int32_t sfcre_AnalyAudio(char* buffer, const std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* const createInfo)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(createInfo));
    std::int32_t remainingBytes = sizeBytes;
    char* cursor = buffer;
    char* const bufferEnd = buffer + sizeBytes;
    const std::int32_t packetSizeCap = createInfo->packetSizeBytes;

    while (remainingBytes > 0) {
      char* const delimiter = MPS_SearchDelim(cursor, remainingBytes, 0x40000);
      result = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(delimiter));
      if (delimiter == nullptr) {
        break;
      }

      const std::uint8_t streamId = static_cast<std::uint8_t>(delimiter[3]);
      if (streamId >= 0xC0u && streamId <= 0xDFu) {
        char* const packetData = sfcre_GetPketData(
          static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(delimiter)),
          static_cast<std::int32_t>(bufferEnd - delimiter)
        );
        std::int32_t analyzeBytes = packetSizeCap;
        const std::int32_t availableBytes = static_cast<std::int32_t>(bufferEnd - packetData);
        if (availableBytes < analyzeBytes) {
          analyzeBytes = availableBytes;
        }

        result = sfcre_AnalyAdx(packetData, analyzeBytes, createInfo);
        if (result != 0) {
          return result;
        }

        result = sfcre_AnalyMpa(packetData, analyzeBytes, createInfo);
        if (result != 0) {
          return result;
        }
      }

      const std::int32_t advanceBytes = static_cast<std::int32_t>((delimiter - cursor) + 1);
      remainingBytes -= advanceBytes;
      cursor += advanceBytes;
      buffer = cursor;
    }

    return result;
  }

  /**
   * Address: 0x00AD00A0 (FUN_00AD00A0, _SFADXT_IsHeader)
   *
   * What it does:
   * Writes the fixed ADX header length into the caller lane, then checks the
   * magic prefix and trailing CRI marker that identify a valid ADXT header.
   */
  extern "C" std::int32_t SFADXT_IsHeader(char* const buffer, const std::int32_t sizeBytes, std::int32_t* const outHeaderSizeBytes)
  {
    *outHeaderSizeBytes = 0x120;
    if (sizeBytes < 0x120) {
      return 0;
    }

    if (buffer[0] != static_cast<char>(0x80)) {
      return 0;
    }

    if (buffer[1] != '\0') {
      return 0;
    }

    return (std::strncmp(buffer + 0x11A, "(c)CRI", 6u) == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00ADA570 (FUN_00ADA570, _sfcre_AnalyAdxAlign4)
   *
   * What it does:
   * Copies up to 0x800 bytes into the shared ADX scratch buffer, then scans
   * for a valid ADX header on 4-byte boundaries and, when found, binds the
   * ADXT audio descriptor plus the captured header lanes.
   */
  extern "C" std::int32_t sfcre_AnalyAdxAlign4(
    char* const buffer,
    std::int32_t sizeBytes,
    SofdecCreateInfoRuntimeView* const createInfo
  )
  {
    std::int32_t copyBytes = sizeBytes;
    if (copyBytes >= 2048) {
      copyBytes = 2048;
    }

    std::memcpy(sfcre_tmpbuf, buffer, static_cast<std::size_t>(copyBytes));
    char* const scanCursor = reinterpret_cast<char*>(sfcre_tmpbuf);
    if (copyBytes <= 0) {
      return 0;
    }

    std::int32_t headerSizeBytes = sizeBytes;
    char* headerScanCursor = scanCursor;
    while (!SFADXT_IsHeader(headerScanCursor, copyBytes, &headerSizeBytes)) {
      copyBytes -= 4;
      headerScanCursor += 4;
      if (copyBytes <= 0) {
        return 0;
      }
    }

    createInfo->audioDescriptor = reinterpret_cast<const void*>(&SFD_tr_ad_adxt);
    createInfo->frameCountMetric = static_cast<std::int32_t>(static_cast<std::uint8_t>(headerScanCursor[7]));
    createInfo->extraMetric =
      static_cast<std::int32_t>(static_cast<std::uint8_t>(headerScanCursor[11]))
      | (static_cast<std::int32_t>(static_cast<std::uint8_t>(headerScanCursor[10])) << 8)
      | (static_cast<std::int32_t>(static_cast<std::uint8_t>(headerScanCursor[9])) << 16)
      | (static_cast<std::int32_t>(static_cast<std::uint8_t>(headerScanCursor[8])) << 24);
    return 1;
  }

  /**
   * Address: 0x00ADA4F0 (FUN_00ADA4F0, _sfcre_AnalyAdx)
   *
   * What it does:
   * Tries the ADX header scanner on four byte alignments and returns success
   * as soon as one aligned probe accepts the stream.
   */
  extern "C" std::int32_t sfcre_AnalyAdx(
    char* const buffer,
    const std::int32_t sizeBytes,
    SofdecCreateInfoRuntimeView* const createInfo
  )
  {
    if (sfcre_AnalyAdxAlign4(buffer, sizeBytes, createInfo) != 0) {
      return 1;
    }
    if (sfcre_AnalyAdxAlign4(buffer + 2, sizeBytes - 2, createInfo) != 0) {
      return 1;
    }
    if (sfcre_AnalyAdxAlign4(buffer + 1, sizeBytes - 1, createInfo) != 0) {
      return 1;
    }
    return (sfcre_AnalyAdxAlign4(buffer + 3, sizeBytes - 3, createInfo) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD8840 (FUN_00AD8840, _SFSET_SetCond)
   *
   * What it does:
   * Validates one condition write and stores it in the work-control condition
   * array when allowed.
   */
  std::int32_t SFSET_SetCond(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    const std::int32_t value
  )
  {
    const std::int32_t valid = sfset_IsCondValid(workctrlSubobj, conditionId, value);
    if (valid != 0) {
      auto* const conditionState = reinterpret_cast<SfsetConditionStateView*>(workctrlSubobj);
      conditionState->setConditions[conditionId] = value;
    }
    return valid;
  }

  /**
   * Address: 0x00AD8800 (FUN_00AD8800, _sfset_SetCondAll)
   *
   * What it does:
   * Applies one condition value to every valid SFD handle currently tracked in
   * global SFLIB work state.
   */
  std::int32_t sfset_SetCondAll(const std::int32_t conditionId, const std::int32_t value)
  {
    std::int32_t result = 0;
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(objectHandle);
      result = SFLIB_CheckHn(workctrlSubobj);
      if (result == 0) {
        result = SFSET_SetCond(workctrlSubobj, conditionId, value);
      }
    }
    return result;
  }

  struct SfsetUserConditionStateView
  {
    std::uint8_t reserved00_B9B[0xB9C]{}; // +0x00
    std::int32_t userConditions[1]{}; // +0xB9C (indexed by condition id)
  };
  static_assert(
    offsetof(SfsetUserConditionStateView, userConditions) == 0xB9C,
    "SfsetUserConditionStateView::userConditions offset must be 0xB9C"
  );

  /**
   * Address: 0x00AD8870 (FUN_00AD8870, _sfset_SetUsrCond)
   *
   * What it does:
   * Validates one condition write and mirrors it into the user-condition lane.
   */
  std::int32_t sfset_SetUsrCond(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    const std::int32_t value
  )
  {
    const std::int32_t valid = sfset_IsCondValid(workctrlSubobj, conditionId, value);
    if (valid != 0) {
      auto* const conditionState = reinterpret_cast<SfsetUserConditionStateView*>(workctrlSubobj);
      conditionState->userConditions[conditionId] = value;
    }
    return valid;
  }

  /**
   * Address: 0x00AD8790 (FUN_00AD8790, _SFD_SetCond)
   *
   * What it does:
   * Applies one condition either globally (null handle) or to one validated
   * handle, mirroring writes into both public and user-condition lanes.
   */
  std::int32_t SFD_SetCond(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    const std::int32_t value
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetCond = static_cast<std::int32_t>(0xFF000112u);
    if (workctrlSubobj == nullptr) {
      (void)sfset_SetCondAll(conditionId, value);
      gSflibLibWork.defaultConditions[conditionId] = value;
      return 0;
    }

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetCond);
    }

    (void)SFSET_SetCond(workctrlSubobj, conditionId, value);
    (void)sfset_SetUsrCond(workctrlSubobj, conditionId, value);
    return 0;
  }

  /**
   * Address: 0x00AD0220 (FUN_00AD0220, _SFD_SetAudioStreamType)
   *
   * What it does:
   * Writes one audio-stream-type selector into SFD condition lane `84` for a
   * non-null work-control handle.
   */
  std::int32_t SFD_SetAudioStreamType(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t audioStreamType
  )
  {
    if (workctrlSubobj == nullptr) {
      return 0;
    }
    return SFD_SetCond(workctrlSubobj, 84, audioStreamType);
  }

  /**
   * Address: 0x00ADDAA0 (FUN_00ADDAA0, _SFD_SetAudioCh)
   *
   * What it does:
   * Validates one handle and stores forced audio-channel condition `30`.
   */
  std::int32_t SFD_SetAudioCh(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t audioChannelIndex
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetAudioChannel = static_cast<std::int32_t>(0xFF000145u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetAudioChannel);
    }

    (void)SFD_SetCond(workctrlSubobj, 30, audioChannelIndex);
    return 0;
  }

  /**
   * Address: 0x00ADDAE0 (FUN_00ADDAE0, _SFD_SetVideoCh)
   *
   * What it does:
   * Validates one handle and stores forced video-channel condition `29`.
   */
  std::int32_t SFD_SetVideoCh(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t videoChannelIndex
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetVideoChannel = static_cast<std::int32_t>(0xFF000146u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetVideoChannel);
    }

    (void)SFD_SetCond(workctrlSubobj, 29, videoChannelIndex);
    return 0;
  }

  /**
   * Address: 0x00AD8940 (FUN_00AD8940, _SFSET_GetCond)
   *
   * What it does:
   * Returns one stored condition value from the work-control condition array.
   */
  std::int32_t SFSET_GetCond(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t conditionId)
  {
    const auto* const conditionState = reinterpret_cast<const SfsetConditionStateView*>(workctrlSubobj);
    return conditionState->setConditions[conditionId];
  }

  /**
   * Address: 0x00AD88E0 (FUN_00AD88E0, _SFD_GetCond)
   *
   * What it does:
   * Reads one condition lane from a valid SFD work-control handle, or from
   * process-global default conditions when handle is null.
   */
  std::int32_t SFD_GetCond(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    std::int32_t* const outConditionValue
  )
  {
    if (workctrlSubobj != nullptr) {
      if (SFLIB_CheckHn(workctrlSubobj) != 0) {
        return SFLIB_SetErr(0, kSflibErrInvalidHandleGetCond);
      }

      *outConditionValue = SFSET_GetCond(workctrlSubobj, conditionId);
      return 0;
    }

    *outConditionValue = static_cast<std::int32_t>(gSflibLibWork.defaultConditions[conditionId]);
    return 0;
  }

  struct SfdGetMvInfRuntimeView
  {
    std::uint8_t mUnknown00[0x90C]{};
    std::uint8_t mvInfoLane[0x40]{};
  };
  static_assert(offsetof(SfdGetMvInfRuntimeView, mvInfoLane) == 0x90C, "SfdGetMvInfRuntimeView::mvInfoLane offset must be 0x90C");
  static_assert(sizeof(SfdGetMvInfRuntimeView) >= 0x94C, "SfdGetMvInfRuntimeView size must cover mvInfo lane");

  /**
   * Address: 0x00AD8950 (FUN_00AD8950, _SFD_GetMvInf)
   *
   * What it does:
   * Validates one SFD handle, then copies the 0x40-byte movie-info lane at
   * `+0x90C` into caller output storage.
   */
  std::int32_t SFD_GetMvInf(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, void* const outMvInfo)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetMvInfo = static_cast<std::int32_t>(0xFF000114u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetMvInfo);
    }

    const auto* const runtimeView = reinterpret_cast<const SfdGetMvInfRuntimeView*>(workctrlSubobj);
    std::memcpy(outMvInfo, runtimeView->mvInfoLane, sizeof(runtimeView->mvInfoLane));
    return 0;
  }

  namespace
  {
    constexpr std::int32_t kSfsetCondConcatPlay = 49;
    constexpr std::int32_t kSfsetCondSystemEndcodeSkip = 56;
    constexpr std::int32_t kSfsetCondAudioOutput = 6;
    constexpr std::int32_t kSfsetCondVideoEnable = 5;
    constexpr std::int32_t kSfsetCondAudioEnable = 6;
    constexpr std::int32_t kSfsetCondSeekRequest = 47;
    constexpr std::int32_t kSflibErrInvalidHandleIsSeekAble = static_cast<std::int32_t>(0xFF000155u);
    constexpr std::int32_t kSflibErrInvalidHandleCnvTimeToPos = static_cast<std::int32_t>(0xFF000156u);
    constexpr std::int32_t kSflibErrInvalidHandleCnvPosToTime = static_cast<std::int32_t>(0xFF000157u);
    constexpr std::int32_t kSflibErrInvalidHandleSeek = static_cast<std::int32_t>(0xFF000158u);
    constexpr std::int32_t kSflibErrInvalidHandleSetSeekPos = static_cast<std::int32_t>(0xFF00015Cu);
    constexpr std::int32_t kSflibErrInvalidHandleSetConcatPlay = static_cast<std::int32_t>(0xFF000161u);
    constexpr std::int32_t kSflibErrInvalidHandleSetOutPan = static_cast<std::int32_t>(0xFF0001A1u);
    constexpr std::int32_t kSflibErrInvalidHandleGetOutPan = static_cast<std::int32_t>(0xFF0001A2u);
    constexpr std::int32_t kSflibErrInvalidHandleSetOutVol = static_cast<std::int32_t>(0xFF0001A3u);
    constexpr std::int32_t kSflibErrInvalidHandleGetOutVol = static_cast<std::int32_t>(0xFF0001A4u);

    using SfdSetOutPanFn = std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t laneIndex, std::int32_t panLevel);
    using SfdGetOutPanFn = std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t laneIndex);
    using SfdSetOutVolFn = std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t volumeLevel);
    using SfdGetOutVolFn = std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

    struct SfdAudioOutputOps
    {
      void* reserved00 = nullptr; // +0x00
      SfdSetOutPanFn setOutPan = nullptr; // +0x04
      SfdGetOutPanFn getOutPan = nullptr; // +0x08
      SfdSetOutVolFn setOutVol = nullptr; // +0x0C
      SfdGetOutVolFn getOutVol = nullptr; // +0x10
    };
    static_assert(offsetof(SfdAudioOutputOps, setOutPan) == 0x04, "SfdAudioOutputOps::setOutPan offset must be 0x04");
    static_assert(offsetof(SfdAudioOutputOps, getOutPan) == 0x08, "SfdAudioOutputOps::getOutPan offset must be 0x08");
    static_assert(offsetof(SfdAudioOutputOps, setOutVol) == 0x0C, "SfdAudioOutputOps::setOutVol offset must be 0x0C");
    static_assert(offsetof(SfdAudioOutputOps, getOutVol) == 0x10, "SfdAudioOutputOps::getOutVol offset must be 0x10");
    static_assert(sizeof(SfdAudioOutputOps) == 0x14, "SfdAudioOutputOps size must be 0x14");

    struct SfdAudioOutputRuntimeView
    {
      std::uint8_t reserved00_2113[0x2114]{};
      SfdAudioOutputOps* audioOutputOps = nullptr; // +0x2114
    };
    static_assert(
      offsetof(SfdAudioOutputRuntimeView, audioOutputOps) == 0x2114,
      "SfdAudioOutputRuntimeView::audioOutputOps offset must be 0x2114"
    );

    [[nodiscard]] SfdAudioOutputOps* GetSfdAudioOutputOps(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj) noexcept
    {
      return reinterpret_cast<SfdAudioOutputRuntimeView*>(workctrlSubobj)->audioOutputOps;
    }

    struct SfptsQueueRuntimeView
    {
      std::int32_t entriesAddress = 0; // +0x00
      std::int32_t capacity = 0; // +0x04
      std::int32_t queuedCount = 0; // +0x08
      std::int32_t writeIndex = 0; // +0x0C
      std::int32_t readIndex = 0; // +0x10
      std::uint8_t reserved14_73[0x60]{};
    };
    static_assert(offsetof(SfptsQueueRuntimeView, entriesAddress) == 0x00, "SfptsQueueRuntimeView::entriesAddress offset must be 0x00");
    static_assert(offsetof(SfptsQueueRuntimeView, capacity) == 0x04, "SfptsQueueRuntimeView::capacity offset must be 0x04");
    static_assert(offsetof(SfptsQueueRuntimeView, queuedCount) == 0x08, "SfptsQueueRuntimeView::queuedCount offset must be 0x08");
    static_assert(offsetof(SfptsQueueRuntimeView, writeIndex) == 0x0C, "SfptsQueueRuntimeView::writeIndex offset must be 0x0C");
    static_assert(offsetof(SfptsQueueRuntimeView, readIndex) == 0x10, "SfptsQueueRuntimeView::readIndex offset must be 0x10");
    static_assert(sizeof(SfptsQueueRuntimeView) == 0x74, "SfptsQueueRuntimeView size must be 0x74");

    struct SfdPtsQueueOwnerRuntimeView
    {
      std::uint8_t reserved0000[0x13BC]{};
      SfptsQueueRuntimeView videoPtsQueue; // +0x13BC
    };
    static_assert(
      offsetof(SfdPtsQueueOwnerRuntimeView, videoPtsQueue) == 0x13BC,
      "SfdPtsQueueOwnerRuntimeView::videoPtsQueue offset must be 0x13BC"
    );

    constexpr std::int32_t kSfdPtsQueueBaseOffset = 0x1348;
    constexpr std::int32_t kSfdPtsQueueStride = 0x74;
    static_assert(
      kSfdPtsQueueBaseOffset + kSfdPtsQueueStride == static_cast<std::int32_t>(offsetof(SfdPtsQueueOwnerRuntimeView, videoPtsQueue)),
      "SFD queue stride/offset mapping must match video queue lane"
    );

    [[nodiscard]] SfptsQueueRuntimeView*
    GetSfptsQueueLane(const std::int32_t workctrlAddress, const std::int32_t queueIndex) noexcept
    {
      const auto baseAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(workctrlAddress));
      const auto queueAddress = baseAddress + static_cast<std::uintptr_t>(kSfdPtsQueueBaseOffset + queueIndex * kSfdPtsQueueStride);
      return reinterpret_cast<SfptsQueueRuntimeView*>(queueAddress);
    }

    struct SfptsQueueEntryWords
    {
      std::int32_t word0 = 0;
      std::int32_t word1 = 0;
      std::int32_t word2 = 0;
      std::int32_t word3 = 0;
    };
    static_assert(sizeof(SfptsQueueEntryWords) == 0x10, "SfptsQueueEntryWords size must be 0x10");

    struct SfseeHeadAnalyLaneRuntimeView
    {
      std::int32_t analyzingComplete = 0; // +0x00
      std::int32_t analyzedTimeMajor = 0; // +0x04
      std::int32_t analyzedTimeMinor = 0; // +0x08
    };
    static_assert(
      offsetof(SfseeHeadAnalyLaneRuntimeView, analyzingComplete) == 0x00,
      "SfseeHeadAnalyLaneRuntimeView::analyzingComplete offset must be 0x00"
    );
    static_assert(
      offsetof(SfseeHeadAnalyLaneRuntimeView, analyzedTimeMajor) == 0x04,
      "SfseeHeadAnalyLaneRuntimeView::analyzedTimeMajor offset must be 0x04"
    );
    static_assert(
      offsetof(SfseeHeadAnalyLaneRuntimeView, analyzedTimeMinor) == 0x08,
      "SfseeHeadAnalyLaneRuntimeView::analyzedTimeMinor offset must be 0x08"
    );
    static_assert(sizeof(SfseeHeadAnalyLaneRuntimeView) == 0x0C, "SfseeHeadAnalyLaneRuntimeView size must be 0x0C");

    struct SfseeRuntimeView
    {
      std::int32_t headAnalyzedFlag = 0; // +0x0000
      std::int32_t streamByteRateHint = 0; // +0x0004
      std::int32_t streamTimeMinorHint = 0; // +0x0008
      std::int32_t hasMuxHeaderTiming = 0; // +0x000C
      std::uint8_t reserved0010[0x08]{};
      std::int32_t muxHeaderTimeMajor = 0; // +0x0018
      std::uint8_t reserved001C[0x24]{};
      std::int32_t muxHeaderTimeMinor = 0; // +0x0040
      std::uint8_t reserved0044[0x85C]{};
      std::int32_t mpsStreamDetected = 0; // +0x08A0
      std::int32_t mpsFallbackTimeMajor = 0; // +0x08A4
      std::int32_t mpsFallbackTimeMinor = 0; // +0x08A8
      std::int32_t mpsHeaderWord08AC = 0; // +0x08AC
      std::int32_t mpsHeaderWord08B0 = 0; // +0x08B0
      std::uint8_t reserved08B4[0x04]{};
      std::int32_t mpsHeaderWord08B8 = 0; // +0x08B8
      std::int32_t mpsHeaderWord08BC = 0; // +0x08BC
      std::int32_t mpsHeaderWord08C0 = 0; // +0x08C0
      std::int32_t mpsHeaderWord08C4 = 0; // +0x08C4
      std::int32_t mpsHeaderWord08C8 = 0; // +0x08C8
      std::int32_t mpsHeaderWord08CC = 0; // +0x08CC
      std::uint8_t reserved08D0[0x200]{};
      SfseeHeadAnalyLaneRuntimeView videoAnalyzingLane; // +0x0AD0
      std::uint8_t headAnalyzeTimerState[0x30]{}; // +0x0ADC
      std::uint8_t reserved0B0C[0x200]{};
      SfseeHeadAnalyLaneRuntimeView audioAnalyzingLane; // +0x0D0C
      std::int32_t audioAnalyzeWord0 = 0; // +0x0D18
      std::int32_t audioAnalyzeWord1 = 0; // +0x0D1C
      std::int32_t audioAnalyzeWord2 = 0; // +0x0D20
      std::uint8_t reserved0D24[0x84]{};
      std::int32_t effectiveByteRate = 0; // +0x0DA8
      std::int32_t inputReadTotalBytes = 0; // +0x0DAC
      std::int32_t effectiveTotalTimeMajor = 0; // +0x0DB0
      std::int32_t effectiveTotalTimeMinor = 0; // +0x0DB4
      std::int32_t keepVideoEnabledOnSeek = 0; // +0x0DB8
      std::int32_t keepAudioEnabledOnSeek = 0; // +0x0DBC
      std::int32_t seekReadyFlag = 0; // +0x0DC0
      std::int32_t fileSizeBytes = 0; // +0x0DC4
      std::int32_t configuredTotalTimeMajor = 0; // +0x0DC8
      std::int32_t configuredTotalTimeMinor = 0; // +0x0DCC
      std::int32_t configuredByteRate = 0; // +0x0DD0
      std::int32_t seekBaseReadTotalBytes = 0; // +0x0DD4
    };
    static_assert(offsetof(SfseeRuntimeView, headAnalyzedFlag) == 0x0000, "SfseeRuntimeView::headAnalyzedFlag offset must be 0x0000");
    static_assert(
      offsetof(SfseeRuntimeView, streamByteRateHint) == 0x0004,
      "SfseeRuntimeView::streamByteRateHint offset must be 0x0004"
    );
    static_assert(
      offsetof(SfseeRuntimeView, streamTimeMinorHint) == 0x0008,
      "SfseeRuntimeView::streamTimeMinorHint offset must be 0x0008"
    );
    static_assert(
      offsetof(SfseeRuntimeView, hasMuxHeaderTiming) == 0x000C,
      "SfseeRuntimeView::hasMuxHeaderTiming offset must be 0x000C"
    );
    static_assert(
      offsetof(SfseeRuntimeView, muxHeaderTimeMajor) == 0x0018,
      "SfseeRuntimeView::muxHeaderTimeMajor offset must be 0x0018"
    );
    static_assert(
      offsetof(SfseeRuntimeView, muxHeaderTimeMinor) == 0x0040,
      "SfseeRuntimeView::muxHeaderTimeMinor offset must be 0x0040"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsStreamDetected) == 0x08A0,
      "SfseeRuntimeView::mpsStreamDetected offset must be 0x08A0"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsFallbackTimeMajor) == 0x08A4,
      "SfseeRuntimeView::mpsFallbackTimeMajor offset must be 0x08A4"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsFallbackTimeMinor) == 0x08A8,
      "SfseeRuntimeView::mpsFallbackTimeMinor offset must be 0x08A8"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08AC) == 0x08AC,
      "SfseeRuntimeView::mpsHeaderWord08AC offset must be 0x08AC"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08B0) == 0x08B0,
      "SfseeRuntimeView::mpsHeaderWord08B0 offset must be 0x08B0"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08B8) == 0x08B8,
      "SfseeRuntimeView::mpsHeaderWord08B8 offset must be 0x08B8"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08BC) == 0x08BC,
      "SfseeRuntimeView::mpsHeaderWord08BC offset must be 0x08BC"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08C0) == 0x08C0,
      "SfseeRuntimeView::mpsHeaderWord08C0 offset must be 0x08C0"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08C4) == 0x08C4,
      "SfseeRuntimeView::mpsHeaderWord08C4 offset must be 0x08C4"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08C8) == 0x08C8,
      "SfseeRuntimeView::mpsHeaderWord08C8 offset must be 0x08C8"
    );
    static_assert(
      offsetof(SfseeRuntimeView, mpsHeaderWord08CC) == 0x08CC,
      "SfseeRuntimeView::mpsHeaderWord08CC offset must be 0x08CC"
    );
    static_assert(
      offsetof(SfseeRuntimeView, videoAnalyzingLane) == 0x0AD0,
      "SfseeRuntimeView::videoAnalyzingLane offset must be 0x0AD0"
    );
    static_assert(
      offsetof(SfseeRuntimeView, headAnalyzeTimerState) == 0x0ADC,
      "SfseeRuntimeView::headAnalyzeTimerState offset must be 0x0ADC"
    );
    static_assert(
      offsetof(SfseeRuntimeView, audioAnalyzingLane) == 0x0D0C,
      "SfseeRuntimeView::audioAnalyzingLane offset must be 0x0D0C"
    );
    static_assert(
      offsetof(SfseeRuntimeView, audioAnalyzeWord0) == 0x0D18,
      "SfseeRuntimeView::audioAnalyzeWord0 offset must be 0x0D18"
    );
    static_assert(
      offsetof(SfseeRuntimeView, audioAnalyzeWord1) == 0x0D1C,
      "SfseeRuntimeView::audioAnalyzeWord1 offset must be 0x0D1C"
    );
    static_assert(
      offsetof(SfseeRuntimeView, audioAnalyzeWord2) == 0x0D20,
      "SfseeRuntimeView::audioAnalyzeWord2 offset must be 0x0D20"
    );
    static_assert(
      offsetof(SfseeRuntimeView, keepVideoEnabledOnSeek) == 0x0DB8,
      "SfseeRuntimeView::keepVideoEnabledOnSeek offset must be 0x0DB8"
    );
    static_assert(
      offsetof(SfseeRuntimeView, keepAudioEnabledOnSeek) == 0x0DBC,
      "SfseeRuntimeView::keepAudioEnabledOnSeek offset must be 0x0DBC"
    );
    static_assert(
      offsetof(SfseeRuntimeView, seekReadyFlag) == 0x0DC0,
      "SfseeRuntimeView::seekReadyFlag offset must be 0x0DC0"
    );
    static_assert(
      offsetof(SfseeRuntimeView, effectiveByteRate) == 0x0DA8,
      "SfseeRuntimeView::effectiveByteRate offset must be 0x0DA8"
    );
    static_assert(
      offsetof(SfseeRuntimeView, inputReadTotalBytes) == 0x0DAC,
      "SfseeRuntimeView::inputReadTotalBytes offset must be 0x0DAC"
    );
    static_assert(
      offsetof(SfseeRuntimeView, effectiveTotalTimeMajor) == 0x0DB0,
      "SfseeRuntimeView::effectiveTotalTimeMajor offset must be 0x0DB0"
    );
    static_assert(
      offsetof(SfseeRuntimeView, effectiveTotalTimeMinor) == 0x0DB4,
      "SfseeRuntimeView::effectiveTotalTimeMinor offset must be 0x0DB4"
    );
    static_assert(offsetof(SfseeRuntimeView, fileSizeBytes) == 0x0DC4, "SfseeRuntimeView::fileSizeBytes offset must be 0x0DC4");
    static_assert(
      offsetof(SfseeRuntimeView, configuredTotalTimeMajor) == 0x0DC8,
      "SfseeRuntimeView::configuredTotalTimeMajor offset must be 0x0DC8"
    );
    static_assert(
      offsetof(SfseeRuntimeView, configuredTotalTimeMinor) == 0x0DCC,
      "SfseeRuntimeView::configuredTotalTimeMinor offset must be 0x0DCC"
    );
    static_assert(
      offsetof(SfseeRuntimeView, configuredByteRate) == 0x0DD0,
      "SfseeRuntimeView::configuredByteRate offset must be 0x0DD0"
    );
    static_assert(
      offsetof(SfseeRuntimeView, seekBaseReadTotalBytes) == 0x0DD4,
      "SfseeRuntimeView::seekBaseReadTotalBytes offset must be 0x0DD4"
    );

    struct SfdSfseeOwnerRuntimeView
    {
      std::uint8_t reserved0000[0x3550]{};
      SfseeRuntimeView* sfseeHandle = nullptr; // +0x3550
    };
    static_assert(
      offsetof(SfdSfseeOwnerRuntimeView, sfseeHandle) == 0x3550,
      "SfdSfseeOwnerRuntimeView::sfseeHandle offset must be 0x3550"
    );

    struct SfdSeekRequestRuntimeView
    {
      std::uint8_t reserved0000[0x3550]{};
      SfseeRuntimeView* sfseeHandle = nullptr; // +0x3550
      std::int32_t seekRequestWord0 = 0; // +0x3554
      std::int32_t seekRequestWord1 = 0; // +0x3558
      std::int32_t seekRequestWord2 = 0; // +0x355C
    };
    static_assert(
      offsetof(SfdSeekRequestRuntimeView, sfseeHandle) == 0x3550,
      "SfdSeekRequestRuntimeView::sfseeHandle offset must be 0x3550"
    );
    static_assert(
      offsetof(SfdSeekRequestRuntimeView, seekRequestWord0) == 0x3554,
      "SfdSeekRequestRuntimeView::seekRequestWord0 offset must be 0x3554"
    );
    static_assert(
      offsetof(SfdSeekRequestRuntimeView, seekRequestWord1) == 0x3558,
      "SfdSeekRequestRuntimeView::seekRequestWord1 offset must be 0x3558"
    );
    static_assert(
      offsetof(SfdSeekRequestRuntimeView, seekRequestWord2) == 0x355C,
      "SfdSeekRequestRuntimeView::seekRequestWord2 offset must be 0x355C"
    );

    struct SfseeFinAnalyControlRuntimeView
    {
      std::uint8_t reserved0000[0x0DE8]{};
      std::int32_t stagedTotalTimeMajor = 0; // +0x0DE8
      std::int32_t stagedTotalTimeMinor = 0; // +0x0DEC
      std::uint8_t reserved0DF0[0x2760]{};
      SfseeRuntimeView* sfseeHandle = nullptr; // +0x3550
      std::int32_t sfseeReserved3554 = 0; // +0x3554
      std::int32_t finAnalyMode = 0; // +0x3558
    };
    static_assert(
      offsetof(SfseeFinAnalyControlRuntimeView, stagedTotalTimeMajor) == 0x0DE8,
      "SfseeFinAnalyControlRuntimeView::stagedTotalTimeMajor offset must be 0x0DE8"
    );
    static_assert(
      offsetof(SfseeFinAnalyControlRuntimeView, stagedTotalTimeMinor) == 0x0DEC,
      "SfseeFinAnalyControlRuntimeView::stagedTotalTimeMinor offset must be 0x0DEC"
    );
    static_assert(
      offsetof(SfseeFinAnalyControlRuntimeView, sfseeHandle) == 0x3550,
      "SfseeFinAnalyControlRuntimeView::sfseeHandle offset must be 0x3550"
    );
    static_assert(
      offsetof(SfseeFinAnalyControlRuntimeView, finAnalyMode) == 0x3558,
      "SfseeFinAnalyControlRuntimeView::finAnalyMode offset must be 0x3558"
    );
  }

  extern "C" std::int32_t sfpts_SetupPtsQue(
    SfptsQueueRuntimeView* ptsQueue,
    std::int32_t ptsQueueSourceAddress,
    std::int32_t ptsEntryCount
  );
  extern "C" std::int32_t UTY_MemsetDword(void* destination, std::uint32_t value, unsigned int dwordCount);
  extern "C" std::int32_t SFHDS_InitFhd(void* headerAddress);
  extern "C" std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue);
  extern "C" std::int32_t sfsee_UpdateEByteRate(std::int32_t workctrlAddress);
  std::int32_t sfsee_GetInSjReadTot(std::int32_t workctrlAddress);
  std::int32_t SFCON_IsEndcodeSkip(std::int32_t workctrlAddress);
  std::int32_t sfsee_ExecHeadAnaly(std::int32_t workctrlAddress);
  std::int32_t sfsee_ExecFinAnaly(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  /**
   * Address: 0x00AECFC0 (FUN_00AECFC0, _sfsee_IsHeadAnalyEnd)
   *
   * What it does:
   * Mirrors the header-analysis completion flag into the output lane and
   * returns the same boolean result.
   */
  std::int32_t sfsee_IsHeadAnalyEnd(SfseeRuntimeView* sfseeHandle, std::int32_t* outHeadAnalyEnd);
  std::int32_t SFHDS_GetMuxVerNum(std::int32_t workctrlAddress);
  std::int32_t sfsee_CnvTimeToPos(
    SfseeRuntimeView* sfseeHandle,
    std::int32_t timeMajor,
    std::int32_t timeMinor,
    std::int32_t* outSeekPosition
  );
  std::int32_t* sfsee_SearchPosToTime(
    std::int32_t workctrlAddress,
    std::int32_t seekPosition,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t sfsee_CnvPosToTime(
    SfseeRuntimeView* sfseeHandle,
    std::int32_t seekPosition,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t SFPL2_Standby(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

  /**
   * Address: 0x00AE5B00 (FUN_00AE5B00, _sfpts_SetupPtsQue)
   *
   * What it does:
   * 8-byte aligns one caller-provided queue buffer, clears the queue storage,
   * computes entry capacity in 16-byte units, and resets queue cursors.
   */
  extern "C" std::int32_t sfpts_SetupPtsQue(
    SfptsQueueRuntimeView* const ptsQueue,
    const std::int32_t ptsQueueSourceAddress,
    const std::int32_t ptsEntryCount
  )
  {
    const std::int32_t alignedEntriesAddress = (ptsQueueSourceAddress + 7) & ~7;
    const std::int32_t queueBytes = ptsQueueSourceAddress - alignedEntriesAddress + ptsEntryCount;

    std::memset(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(alignedEntriesAddress))),
      0,
      static_cast<std::size_t>(queueBytes)
    );

    ptsQueue->entriesAddress = alignedEntriesAddress;
    ptsQueue->capacity = queueBytes / static_cast<std::int32_t>(sizeof(SfptsQueueEntryWords));
    ptsQueue->queuedCount = 0;
    ptsQueue->writeIndex = 0;
    ptsQueue->readIndex = 0;
    return 0;
  }

  struct SftstFrameStepRuntimeView
  {
    std::int32_t testFlag = 0; // +0x00
    std::int32_t pauseFlag = 0; // +0x04
    std::uint8_t reserved0008[0x04]{};
    std::int32_t statusCode = 0; // +0x0C
    std::uint8_t reserved0010[0x118]{};
    std::int64_t accumulatedFrameUnits = 0; // +0x128
    std::int64_t stepUnitsPerFrame = 0; // +0x130
    struct SftstConfigLane
    {
      std::int32_t word0 = 0; // +0x00
      std::int32_t word1 = 0; // +0x04
      std::int32_t word2 = 0; // +0x08
      std::int32_t word3 = 0; // +0x0C
    };
    SftstConfigLane toleranceConfig{}; // +0x138
    SftstConfigLane excessErrorConfig{}; // +0x148
    SftstConfigLane adjustStartConfig{}; // +0x158
    SftstConfigLane adjustPositionOffsetConfig{}; // +0x168
  };
  static_assert(offsetof(SftstFrameStepRuntimeView, testFlag) == 0x00, "SftstFrameStepRuntimeView::testFlag offset must be 0x00");
  static_assert(offsetof(SftstFrameStepRuntimeView, pauseFlag) == 0x04, "SftstFrameStepRuntimeView::pauseFlag offset must be 0x04");
  static_assert(
    offsetof(SftstFrameStepRuntimeView, statusCode) == 0x0C,
    "SftstFrameStepRuntimeView::statusCode offset must be 0x0C"
  );
  static_assert(
    offsetof(SftstFrameStepRuntimeView, accumulatedFrameUnits) == 0x128,
    "SftstFrameStepRuntimeView::accumulatedFrameUnits offset must be 0x128"
  );
  static_assert(
    offsetof(SftstFrameStepRuntimeView, stepUnitsPerFrame) == 0x130,
    "SftstFrameStepRuntimeView::stepUnitsPerFrame offset must be 0x130"
  );
  static_assert(
    offsetof(SftstFrameStepRuntimeView, toleranceConfig) == 0x138,
    "SftstFrameStepRuntimeView::toleranceConfig offset must be 0x138"
  );
  static_assert(
    offsetof(SftstFrameStepRuntimeView, excessErrorConfig) == 0x148,
    "SftstFrameStepRuntimeView::excessErrorConfig offset must be 0x148"
  );
  static_assert(
    offsetof(SftstFrameStepRuntimeView, adjustStartConfig) == 0x158,
    "SftstFrameStepRuntimeView::adjustStartConfig offset must be 0x158"
  );
  static_assert(
    offsetof(SftstFrameStepRuntimeView, adjustPositionOffsetConfig) == 0x168,
    "SftstFrameStepRuntimeView::adjustPositionOffsetConfig offset must be 0x168"
  );

  struct SftstFrameStepRateRuntimeView
  {
    std::int64_t numerator = 0;
    std::int64_t denominator = 0;
  };
  static_assert(sizeof(SftstFrameStepRateRuntimeView) == 0x10, "SftstFrameStepRateRuntimeView size must be 0x10");

  struct SftstMovingAverageRuntimeView
  {
    std::uint8_t reserved0000[0x10]{};
    std::int32_t historyValueCount = 0; // +0x10
    std::int32_t historyWriteOrdinal = 0; // +0x14
    std::int32_t historyValues[99]{}; // +0x18
    std::int32_t movingAveragePrimary = 0; // +0x1A4
    std::int32_t movingAverageAdjusted = 0; // +0x1A8
  };
  static_assert(
    offsetof(SftstMovingAverageRuntimeView, historyValueCount) == 0x10,
    "SftstMovingAverageRuntimeView::historyValueCount offset must be 0x10"
  );
  static_assert(
    offsetof(SftstMovingAverageRuntimeView, historyWriteOrdinal) == 0x14,
    "SftstMovingAverageRuntimeView::historyWriteOrdinal offset must be 0x14"
  );
  static_assert(
    offsetof(SftstMovingAverageRuntimeView, historyValues) == 0x18,
    "SftstMovingAverageRuntimeView::historyValues offset must be 0x18"
  );
  static_assert(
    offsetof(SftstMovingAverageRuntimeView, movingAveragePrimary) == 0x1A4,
    "SftstMovingAverageRuntimeView::movingAveragePrimary offset must be 0x1A4"
  );
  static_assert(
    offsetof(SftstMovingAverageRuntimeView, movingAverageAdjusted) == 0x1A8,
    "SftstMovingAverageRuntimeView::movingAverageAdjusted offset must be 0x1A8"
  );
  static_assert(sizeof(SftstMovingAverageRuntimeView) == 0x1AC, "SftstMovingAverageRuntimeView size must be 0x1AC");

  constexpr std::size_t kSftstResetHistoryBytes = 0xF0;
  constexpr std::size_t kSftstHistoryResetGenerationIndex = 97;
  static_assert(
    offsetof(SftstMovingAverageRuntimeView, historyValues) + (kSftstHistoryResetGenerationIndex * sizeof(std::int32_t)) == 0x19C,
    "SftstMovingAverageRuntimeView::historyValues[97] offset must be 0x19C"
  );

  /**
   * Address: 0x00AE6340 (FUN_00AE6340, _sftst_ResetHist)
   *
   * What it does:
   * Clears the 0xF0-byte history reset lane, resets the write ordinal, and
   * returns the incremented reset-generation counter.
   */
  std::int32_t sftst_ResetHist(SftstMovingAverageRuntimeView* const runtimeView)
  {
    std::memset(runtimeView->historyValues, 0, kSftstResetHistoryBytes);
    runtimeView->historyWriteOrdinal = 0;
    const std::uint32_t nextGeneration = static_cast<std::uint32_t>(runtimeView->historyValues[kSftstHistoryResetGenerationIndex]) + 1u;
    runtimeView->historyValues[kSftstHistoryResetGenerationIndex] = static_cast<std::int32_t>(nextGeneration);
    return static_cast<std::int32_t>(nextGeneration);
  }

  /**
   * Address: 0x00AE6370 (FUN_00AE6370, _SFTST_SetTstFlg)
   *
   * What it does:
   * Stores one SFTST test-flag lane and returns the stored value.
   */
  std::int32_t SFTST_SetTstFlg(SftstFrameStepRuntimeView* const runtimeView, const std::int32_t testFlag)
  {
    runtimeView->testFlag = testFlag;
    return testFlag;
  }

  /**
   * Address: 0x00AE6380 (FUN_00AE6380, _SFTST_SetTolerance)
   *
   * What it does:
   * Copies one 4-word tolerance configuration lane to the frame-step runtime.
   */
  SftstFrameStepRuntimeView::SftstConfigLane* SFTST_SetTolerance(
    SftstFrameStepRuntimeView* const runtimeView,
    const SftstFrameStepRuntimeView::SftstConfigLane* const toleranceConfig
  )
  {
    runtimeView->toleranceConfig = *toleranceConfig;
    return &runtimeView->toleranceConfig;
  }

  /**
   * Address: 0x00AE63B0 (FUN_00AE63B0, _SFTST_SetExcessErr)
   *
   * What it does:
   * Copies one 4-word excess-error configuration lane to the frame-step runtime.
   */
  SftstFrameStepRuntimeView::SftstConfigLane* SFTST_SetExcessErr(
    SftstFrameStepRuntimeView* const runtimeView,
    const SftstFrameStepRuntimeView::SftstConfigLane* const excessErrorConfig
  )
  {
    runtimeView->excessErrorConfig = *excessErrorConfig;
    return &runtimeView->excessErrorConfig;
  }

  /**
   * Address: 0x00AE63E0 (FUN_00AE63E0, _SFTST_SetAdjStart)
   *
   * What it does:
   * Copies one 4-word adjustment-start configuration lane to the frame-step runtime.
   */
  SftstFrameStepRuntimeView::SftstConfigLane* SFTST_SetAdjStart(
    SftstFrameStepRuntimeView* const runtimeView,
    const SftstFrameStepRuntimeView::SftstConfigLane* const adjustStartConfig
  )
  {
    runtimeView->adjustStartConfig = *adjustStartConfig;
    return &runtimeView->adjustStartConfig;
  }

  /**
   * Address: 0x00AE6410 (FUN_00AE6410, _SFTST_SetAdjPoff)
   *
   * What it does:
   * Copies one 4-word adjustment-position-offset lane to the frame-step runtime.
   */
  SftstFrameStepRuntimeView::SftstConfigLane* SFTST_SetAdjPoff(
    SftstFrameStepRuntimeView* const runtimeView,
    const SftstFrameStepRuntimeView::SftstConfigLane* const adjustPositionOffsetConfig
  )
  {
    runtimeView->adjustPositionOffsetConfig = *adjustPositionOffsetConfig;
    return &runtimeView->adjustPositionOffsetConfig;
  }

  /**
   * Address: 0x00AE6440 (FUN_00AE6440, _SFTST_SetMovaveRange)
   *
   * What it does:
   * Updates the moving-average history-window size when the requested range is
   * positive and returns the requested range value.
   */
  std::int32_t SFTST_SetMovaveRange(SftstMovingAverageRuntimeView* const runtimeView, const std::int32_t historyRange)
  {
    if (historyRange > 0) {
      runtimeView->historyValueCount = historyRange;
    }
    return historyRange;
  }

  /**
   * Address: 0x00AE6450 (FUN_00AE6450, _SFTST_Pause)
   *
   * What it does:
   * Stores one pause flag lane on the frame-step runtime and returns it.
   */
  std::int32_t SFTST_Pause(SftstFrameStepRuntimeView* const runtimeView, const std::int32_t pauseFlag)
  {
    runtimeView->pauseFlag = pauseFlag;
    return pauseFlag;
  }

  /**
   * Address: 0x00AE6460 (FUN_00AE6460, _SFTST_SetAdjFlg)
   *
   * What it does:
   * Stores one adjustment/status flag lane on the frame-step runtime and
   * returns the stored value.
   */
  std::int32_t SFTST_SetAdjFlg(SftstFrameStepRuntimeView* const runtimeView, const std::int32_t adjustFlag)
  {
    runtimeView->statusCode = adjustFlag;
    return adjustFlag;
  }

  /**
   * Address: 0x00AE6B40 (FUN_00AE6B40, _sftst_CalcMovAve)
   *
   * What it does:
   * Computes the integer moving average over the active history lane.
   */
  std::int32_t sftst_CalcMovAve(SftstMovingAverageRuntimeView* const runtimeView)
  {
    std::int32_t historySum = 0;
    const std::int32_t historyValueCount = runtimeView->historyValueCount;
    if (historyValueCount > 0) {
      for (std::int32_t index = 0; index < historyValueCount; ++index) {
        historySum += runtimeView->historyValues[index];
      }
    }

    return historySum / historyValueCount;
  }

  /**
   * Address: 0x00AE6AC0 (FUN_00AE6AC0, _sftst_UpdateMovAve)
   *
   * What it does:
   * Writes one new history sample into the moving-average ring and refreshes
   * both output average lanes.
   */
  std::int32_t sftst_UpdateMovAve(SftstMovingAverageRuntimeView* const runtimeView, const std::int32_t sampleValue)
  {
    runtimeView->historyValues[runtimeView->historyWriteOrdinal++ % runtimeView->historyValueCount] = sampleValue;
    const std::int32_t movingAverage = sftst_CalcMovAve(runtimeView);
    runtimeView->movingAveragePrimary = movingAverage;
    runtimeView->movingAverageAdjusted = movingAverage;
    return movingAverage;
  }

  /**
   * Address: 0x00AE6B00 (FUN_00AE6B00, _sftst_ModifyHist)
   *
   * What it does:
   * Subtracts one delta value from every history sample and refreshes the
   * adjusted moving-average lane.
   */
  std::int32_t sftst_ModifyHist(SftstMovingAverageRuntimeView* const runtimeView, const std::int32_t deltaValue)
  {
    for (std::int32_t index = 0; index < runtimeView->historyValueCount; ++index) {
      runtimeView->historyValues[index] -= deltaValue;
    }

    const std::int32_t movingAverage = sftst_CalcMovAve(runtimeView);
    runtimeView->movingAverageAdjusted = movingAverage;
    return movingAverage;
  }

  /**
   * Address: 0x00AE6470 (FUN_00AE6470, _SFTST_GoNextFrame)
   *
   * What it does:
   * Advances one SFTST fractional frame accumulator by one step fraction and
   * returns the high 32-bit frame lane unless the stepper is paused.
   */
  std::int32_t SFTST_GoNextFrame(
    SftstFrameStepRuntimeView* const frameStepper,
    const SftstFrameStepRateRuntimeView* const stepRate
  )
  {
    const std::int32_t statusCode = frameStepper->statusCode;
    if (statusCode != 0) {
      return statusCode;
    }

    const std::int64_t stepDelta = (frameStepper->stepUnitsPerFrame * stepRate->numerator) / stepRate->denominator;
    frameStepper->accumulatedFrameUnits += stepDelta;
    return static_cast<std::int32_t>(static_cast<std::uint64_t>(frameStepper->accumulatedFrameUnits) >> 32);
  }

  /**
   * Address: 0x00AECE00 (FUN_00AECE00, _sfsee_InitHeadInf)
   *
   * What it does:
   * Clears SFSEE head-analysis lanes, initializes SFHDS header state, and
   * seeds head-analysis timer lanes.
   */
  std::int32_t sfsee_InitHeadInf(SfseeRuntimeView* const sfseeHandle)
  {
    sfseeHandle->headAnalyzedFlag = 0;
    sfseeHandle->streamByteRateHint = 0;
    sfseeHandle->streamTimeMinorHint = 0;
    (void)SFHDS_InitFhd(&sfseeHandle->hasMuxHeaderTiming);

    sfseeHandle->mpsStreamDetected = 0;
    sfseeHandle->mpsFallbackTimeMajor = 0;
    sfseeHandle->mpsFallbackTimeMinor = 0;
    sfseeHandle->mpsHeaderWord08AC = 0;
    sfseeHandle->mpsHeaderWord08B0 = 0;
    sfseeHandle->mpsHeaderWord08B8 = 0;
    sfseeHandle->mpsHeaderWord08BC = 0;
    sfseeHandle->mpsHeaderWord08C0 = 0;
    sfseeHandle->mpsHeaderWord08C4 = 0;
    sfseeHandle->mpsHeaderWord08C8 = 0;
    sfseeHandle->mpsHeaderWord08CC = 0;

    sfseeHandle->videoAnalyzingLane.analyzingComplete = 0;
    sfseeHandle->videoAnalyzingLane.analyzedTimeMajor = 0;
    sfseeHandle->videoAnalyzingLane.analyzedTimeMinor = 0;
    const std::int32_t initResult =
      SFTIM_InitTtu(reinterpret_cast<std::uint32_t*>(sfseeHandle->headAnalyzeTimerState), 0x7FFFFFFF);

    sfseeHandle->audioAnalyzingLane.analyzingComplete = 0;
    sfseeHandle->audioAnalyzingLane.analyzedTimeMajor = 0;
    sfseeHandle->audioAnalyzingLane.analyzedTimeMinor = 1;
    sfseeHandle->audioAnalyzeWord0 = 0;
    sfseeHandle->audioAnalyzeWord1 = 0;
    sfseeHandle->audioAnalyzeWord2 = 0;
    return initResult;
  }

  struct SfseeInitHandleRuntimeView
  {
    std::int32_t word0 = 0; // +0x00
    std::int32_t word1 = 0; // +0x04
    std::int32_t word2 = 0; // +0x08
    std::int32_t word3 = 0; // +0x0C
  };
  static_assert(offsetof(SfseeInitHandleRuntimeView, word0) == 0x00, "SfseeInitHandleRuntimeView::word0 offset must be 0x00");
  static_assert(offsetof(SfseeInitHandleRuntimeView, word1) == 0x04, "SfseeInitHandleRuntimeView::word1 offset must be 0x04");
  static_assert(offsetof(SfseeInitHandleRuntimeView, word2) == 0x08, "SfseeInitHandleRuntimeView::word2 offset must be 0x08");
  static_assert(offsetof(SfseeInitHandleRuntimeView, word3) == 0x0C, "SfseeInitHandleRuntimeView::word3 offset must be 0x0C");
  static_assert(sizeof(SfseeInitHandleRuntimeView) == 0x10, "SfseeInitHandleRuntimeView size must be 0x10");

  /**
   * Address: 0x00AECD30 (FUN_00AECD30, _SFSEE_InitHn)
   *
   * What it does:
   * Initializes one SFSEE handle lane to the binary's four-word default state.
   */
  extern "C" SfseeInitHandleRuntimeView* SFSEE_InitHn(SfseeInitHandleRuntimeView* const handle)
  {
    handle->word0 = 0;
    handle->word1 = 0;
    handle->word2 = -3;
    handle->word3 = 1;
    return handle;
  }

  /**
   * Address: 0x00AECD80 (FUN_00AECD80, _sfsee_InitSeekInf)
   *
   * What it does:
   * Clears one SFSEE seek/runtime lane, reinitializes head-analysis state, and
   * seeds default seek-time and byte-rate conversion lanes.
   */
  std::int32_t sfsee_InitSeekInf(SfseeRuntimeView* const sfseeHandle)
  {
    constexpr std::int32_t kSfseeDwordCount = 0x376;
    (void)UTY_MemsetDword(sfseeHandle, 0, kSfseeDwordCount);
    (void)sfsee_InitHeadInf(sfseeHandle);

    sfseeHandle->effectiveByteRate = 0;
    sfseeHandle->inputReadTotalBytes = 0;
    sfseeHandle->seekReadyFlag = 0;
    sfseeHandle->fileSizeBytes = 0;
    sfseeHandle->configuredByteRate = 0;

    sfseeHandle->effectiveTotalTimeMajor = -8;
    sfseeHandle->effectiveTotalTimeMinor = 1;
    sfseeHandle->keepVideoEnabledOnSeek = -1;
    sfseeHandle->keepAudioEnabledOnSeek = -1;
    sfseeHandle->configuredTotalTimeMajor = -8;
    sfseeHandle->configuredTotalTimeMinor = 1;
    sfseeHandle->seekBaseReadTotalBytes = -1;
    return -1;
  }

  /**
   * Address: 0x00AECEB0 (FUN_00AECEB0, _SFD_EntrySeek)
   *
   * What it does:
   * Validates one SFD work-control handle and binds one SFSEE seek-handle
   * pointer lane used by seek services.
   */
  std::int32_t SFD_EntrySeek(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sfseeHandleAddress
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleEntrySeek = static_cast<std::int32_t>(0xFF000151u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleEntrySeek);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    runtimeView->sfseeHandle = reinterpret_cast<SfseeRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfseeHandleAddress))
    );
    return 0;
  }

  /**
   * Address: 0x00AED160 (FUN_00AED160, _sfsee_IsAudioAnalyzing)
   *
   * What it does:
   * Returns whether audio head-analysis is still pending when audio transfer
   * lane `3` is set up and condition lane `6` is enabled.
   */
  std::int32_t sfsee_IsAudioAnalyzing(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const ioAudioAnalyzeState,
    std::int32_t* const outAudioLaneEnabled
  )
  {
    if (SFTRN_IsSetup(workctrlSubobj, 3) != 0 && SFSET_GetCond(workctrlSubobj, kSfsetCondAudioEnable) == 1) {
      *outAudioLaneEnabled = 1;
      return (*ioAudioAnalyzeState == 0) ? 1 : 0;
    }

    *outAudioLaneEnabled = 0;
    return 0;
  }

  /**
   * Address: 0x00AED1B0 (FUN_00AED1B0, _sfsee_IsVideoAnalyzing)
   *
   * What it does:
   * Returns whether video head-analysis is still pending when video transfer
   * lane `2` is set up and condition lane `5` is enabled.
   */
  std::int32_t sfsee_IsVideoAnalyzing(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const ioVideoAnalyzeState,
    std::int32_t* const outVideoLaneEnabled
  )
  {
    if (SFTRN_IsSetup(workctrlSubobj, 2) != 0 && SFSET_GetCond(workctrlSubobj, kSfsetCondVideoEnable) == 1) {
      *outVideoLaneEnabled = 1;
      return (*ioVideoAnalyzeState == 0) ? 1 : 0;
    }

    *outVideoLaneEnabled = 0;
    return 0;
  }

  /**
   * Address: 0x00AED200 (FUN_00AED200, _sfsee_IsMpsStream)
   *
   * What it does:
   * Returns whether MPS transfer lane `1` is set up for this work-control
   * handle.
   */
  std::int32_t sfsee_IsMpsStream(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return (SFTRN_IsSetup(workctrlSubobj, 1) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AED040 (FUN_00AED040, _sfsee_ExecHeadAnaly)
   *
   * What it does:
   * Finalizes SFSEE header-analysis timing lanes from audio/video or MPS
   * metadata and commits one global stream timing pair.
   */
  std::int32_t sfsee_ExecHeadAnaly(const std::int32_t workctrlAddress)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj)->sfseeHandle;

    std::int32_t result = runtimeView->headAnalyzedFlag;
    if (result != 0) {
      return result;
    }

    std::int32_t audioLaneEnabled = 0;
    result = sfsee_IsAudioAnalyzing(
      workctrlSubobj,
      &runtimeView->audioAnalyzingLane.analyzingComplete,
      &audioLaneEnabled
    );
    if (result != 0) {
      return result;
    }

    std::int32_t videoLaneEnabled = 0;
    result = sfsee_IsVideoAnalyzing(
      workctrlSubobj,
      &runtimeView->videoAnalyzingLane.analyzingComplete,
      &videoLaneEnabled
    );
    if (result != 0) {
      return result;
    }

    std::int32_t streamTimeMajor = runtimeView->mpsFallbackTimeMajor;
    std::int32_t streamTimeMinor = runtimeView->mpsFallbackTimeMinor;

    if (sfsee_IsMpsStream(workctrlSubobj) == 0) {
      if (videoLaneEnabled != 0) {
        streamTimeMajor = runtimeView->videoAnalyzingLane.analyzedTimeMajor;
        streamTimeMinor = runtimeView->videoAnalyzingLane.analyzedTimeMinor;
      } else {
        result = audioLaneEnabled;
        if (result == 0) {
          return result;
        }

        streamTimeMajor = runtimeView->audioAnalyzingLane.analyzedTimeMajor;
        streamTimeMinor = runtimeView->audioAnalyzingLane.analyzedTimeMinor;
      }
    } else {
      runtimeView->mpsStreamDetected = 1;
      if (runtimeView->hasMuxHeaderTiming != 0) {
        streamTimeMajor = runtimeView->muxHeaderTimeMajor;
        if (streamTimeMajor > 0) {
          const std::int32_t fileSizeBytes = runtimeView->fileSizeBytes;
          const std::int32_t muxHeaderTimeMinor = runtimeView->muxHeaderTimeMinor;
          if (fileSizeBytes > 0 && muxHeaderTimeMinor > 0) {
            streamTimeMajor = UTY_MulDiv(fileSizeBytes, 1000, muxHeaderTimeMinor);
          }
          streamTimeMinor = runtimeView->mpsFallbackTimeMinor;
        } else {
          if (SFHDS_GetMuxVerNum(workctrlAddress) < 108) {
            streamTimeMajor = (runtimeView->mpsFallbackTimeMajor << 11) / 2018;
          } else {
            streamTimeMajor = runtimeView->mpsFallbackTimeMajor;
          }
          streamTimeMinor = runtimeView->mpsFallbackTimeMinor;
        }
      }
    }

    runtimeView->streamByteRateHint = streamTimeMajor;
    runtimeView->streamTimeMinorHint = streamTimeMinor;
    runtimeView->headAnalyzedFlag = 1;
    return sfsee_UpdateEByteRate(workctrlAddress);
  }

  /**
   * Address: 0x00AED020 (FUN_00AED020, _SFSEE_ExecServer)
   *
   * What it does:
   * Executes SFSEE header-analysis and final-analysis passes while an SFSEE
   * runtime handle is attached.
   */
  std::int32_t SFSEE_ExecServer(const std::int32_t workctrlAddress)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    if (runtimeView->sfseeHandle == nullptr) {
      return 0;
    }

    (void)sfsee_ExecHeadAnaly(workctrlAddress);
    return sfsee_ExecFinAnaly(workctrlSubobj);
  }

  /**
   * Address: 0x00AECFE0 (FUN_00AECFE0, _SFSEE_FixAvPlay)
   *
   * What it does:
   * Repairs negative keep-video/keep-audio seek lanes on the attached SFSEE
   * runtime when those lanes are still unset.
   */
  extern "C" std::int32_t SFSEE_FixAvPlay(
    const std::int32_t workctrlAddress,
    const std::int32_t condition5State,
    const std::int32_t condition6State
  )
  {
    auto* const ownerView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(SjAddressToPointer(workctrlAddress));
    SfseeRuntimeView* const sfseeHandle = ownerView->sfseeHandle;
    if (sfseeHandle != nullptr) {
      if (sfseeHandle->keepVideoEnabledOnSeek < 0) {
        sfseeHandle->keepVideoEnabledOnSeek = condition5State;
      }
      if (sfseeHandle->keepAudioEnabledOnSeek < 0) {
        sfseeHandle->keepAudioEnabledOnSeek = condition6State;
      }
    }

    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sfseeHandle));
  }

  /**
   * Address: 0x00AECFC0 (FUN_00AECFC0, _sfsee_IsHeadAnalyEnd)
   *
   * What it does:
   * Mirrors the header-analysis completion flag into the output lane and
   * returns the same boolean result.
   */
  std::int32_t sfsee_IsHeadAnalyEnd(SfseeRuntimeView* const sfseeHandle, std::int32_t* const outHeadAnalyEnd)
  {
    const std::int32_t result = (sfseeHandle->headAnalyzedFlag == 1) ? 1 : 0;
    *outHeadAnalyEnd = result;
    return result;
  }

  /**
   * Address: 0x00AECEF0 (FUN_00AECEF0, _SFD_SetSeekPosTbl)
   *
   * What it does:
   * Validates one SFD handle and writes one seek-position table lane value
   * into the attached SFSEE runtime state.
   */
  std::int32_t SFD_SetSeekPosTbl(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t seekTableAddress
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetSeekPosTable = static_cast<std::int32_t>(0xFF000152u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetSeekPosTable);
    }

    auto* const ownerView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    ownerView->sfseeHandle->seekReadyFlag = seekTableAddress;
    return 0;
  }

  /**
   * Address: 0x00AECF30 (FUN_00AECF30, _SFD_StartHeadAnaly)
   *
   * What it does:
   * Validates one SFD handle, forces condition lane `47` to enabled, and
   * transitions playback control into standby for head analysis.
   */
  std::int32_t SFD_StartHeadAnaly(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrInvalidHandleStartHeadAnaly = static_cast<std::int32_t>(0xFF000153u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleStartHeadAnaly);
    }

    (void)SFSET_SetCond(workctrlSubobj, 47, 1);
    return SFPL2_Standby(workctrlSubobj);
  }

  /**
   * Address: 0x00AECF70 (FUN_00AECF70, _SFD_IsHeadAnalyEnd)
   *
   * What it does:
   * Validates one SFD handle and mirrors SFSEE head-analysis completion flag
   * into caller output storage.
   */
  std::int32_t SFD_IsHeadAnalyEnd(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outHeadAnalyzed
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleIsHeadAnalyEnd = static_cast<std::int32_t>(0xFF000154u);
    *outHeadAnalyzed = 0;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleIsHeadAnalyEnd);
    }

    auto* const ownerView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    (void)sfsee_IsHeadAnalyEnd(ownerView->sfseeHandle, outHeadAnalyzed);
    return 0;
  }

  /**
   * Address: 0x00AED270 (FUN_00AED270, _sfsee_IsSeekAble)
   *
   * What it does:
   * Reports seek availability after header-analysis completion and seek-rate
   * readiness checks.
   */
  std::int32_t sfsee_IsSeekAble(SfseeRuntimeView* const sfseeHandle, std::int32_t* const outSeekable)
  {
    *outSeekable = 0;
    if (sfseeHandle == nullptr) {
      return 0;
    }

    std::int32_t headAnalyzed = 0;
    (void)sfsee_IsHeadAnalyEnd(sfseeHandle, &headAnalyzed);
    if (headAnalyzed != 0) {
      if (sfseeHandle->seekReadyFlag != 0 || sfseeHandle->effectiveByteRate > 0) {
        *outSeekable = 1;
      }
    }
    return headAnalyzed;
  }

  /**
   * Address: 0x00AED330 (FUN_00AED330, _sfsee_CnvTimeToPos)
   *
   * What it does:
   * Converts one time pair to seek position using effective byte-rate, or
   * resets output to zero when seek-table lane is active.
   */
  std::int32_t sfsee_CnvTimeToPos(
    SfseeRuntimeView* const sfseeHandle,
    const std::int32_t timeMajor,
    const std::int32_t timeMinor,
    std::int32_t* const outSeekPosition
  )
  {
    if (sfseeHandle->seekReadyFlag != 0) {
      *outSeekPosition = 0;
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outSeekPosition));
    }

    const std::int32_t seekPosition = UTY_MulDiv(sfseeHandle->effectiveByteRate, timeMajor, timeMinor);
    *outSeekPosition = seekPosition;
    return seekPosition;
  }

  /**
   * Address: 0x00AED400 (FUN_00AED400, _sfsee_CnvPosToTime)
   *
   * What it does:
   * Converts one seek position to time pair through seek-table lane (when
   * configured) or effective byte-rate fallback.
   */
  std::int32_t sfsee_CnvPosToTime(
    SfseeRuntimeView* const sfseeHandle,
    const std::int32_t seekPosition,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    if (sfseeHandle->seekReadyFlag != 0) {
      const std::uintptr_t searchResult = reinterpret_cast<std::uintptr_t>(
        sfsee_SearchPosToTime(sfseeHandle->seekReadyFlag, seekPosition, outTimeMajor, outTimeMinor)
      );
      return static_cast<std::int32_t>(static_cast<std::uint32_t>(searchResult));
    }

    const std::int32_t effectiveByteRate = sfseeHandle->effectiveByteRate;
    if (effectiveByteRate <= 0) {
      *outTimeMajor = 0;
      *outTimeMinor = 1000;
      return effectiveByteRate;
    }

    const std::int32_t convertedTimeMajor = UTY_MulDiv(seekPosition, 1000, effectiveByteRate);
    *outTimeMajor = convertedTimeMajor;
    *outTimeMinor = 1000;
    return convertedTimeMajor;
  }

  /**
   * Address: 0x00AED220 (FUN_00AED220, _SFD_IsSeekAble)
   *
   * What it does:
   * Validates one SFD handle and reports whether seek conversion lanes are
   * currently available.
   */
  std::int32_t SFD_IsSeekAble(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, std::int32_t* const outSeekable)
  {
    *outSeekable = 0;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleIsSeekAble);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    (void)sfsee_IsSeekAble(runtimeView->sfseeHandle, outSeekable);
    return 0;
  }

  /**
   * Address: 0x00AED2C0 (FUN_00AED2C0, _SFD_CnvTimeToPos)
   *
   * What it does:
   * Validates one SFD handle and converts one playback time pair into seek
   * position when SFSEE seek conversion is available.
   */
  std::int32_t SFD_CnvTimeToPos(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t timeMajor,
    const std::int32_t timeMinor,
    std::int32_t* const outSeekPosition
  )
  {
    *outSeekPosition = 0;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleCnvTimeToPos);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    std::int32_t isSeekable = 0;
    (void)sfsee_IsSeekAble(runtimeView->sfseeHandle, &isSeekable);
    if (isSeekable != 0) {
      (void)sfsee_CnvTimeToPos(runtimeView->sfseeHandle, timeMajor, timeMinor, outSeekPosition);
    }
    return 0;
  }

  /**
   * Address: 0x00AED380 (FUN_00AED380, _SFD_CnvPosToTime)
   *
   * What it does:
   * Validates one SFD handle and converts one seek position into playback time
   * when SFSEE seek conversion is available.
   */
  std::int32_t SFD_CnvPosToTime(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t seekPosition,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    *outTimeMajor = 0;
    *outTimeMinor = 1;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleCnvPosToTime);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    std::int32_t isSeekable = 0;
    (void)sfsee_IsSeekAble(runtimeView->sfseeHandle, &isSeekable);
    if (isSeekable != 0) {
      (void)sfsee_CnvPosToTime(runtimeView->sfseeHandle, seekPosition, outTimeMajor, outTimeMinor);
    }
    return 0;
  }

  /**
   * Address: 0x00AED460 (FUN_00AED460, _sfsee_SearchPosToTime)
   *
   * What it does:
   * Returns default seek-position to time mapping lane (`0/1000`) for this
   * build.
   */
  std::int32_t* sfsee_SearchPosToTime(
    const std::int32_t workctrlAddress,
    const std::int32_t seekPosition,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    (void)workctrlAddress;
    (void)seekPosition;
    *outTimeMajor = 0;
    *outTimeMinor = 1000;
    return outTimeMajor;
  }

  /**
   * Address: 0x00AED480 (FUN_00AED480, _SFD_Seek)
   *
   * What it does:
   * Stops active playback, clears seek-related condition lanes, stores seek
   * request words, and dispatches transfer setup callback lane `13`.
   */
  std::int32_t SFD_Seek(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const seekRequestWords
  )
  {
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSeek);
    }

    auto* const runtimeView = reinterpret_cast<SfdSeekRequestRuntimeView*>(workctrlSubobj);
    SfseeRuntimeView* const sfseeHandle = runtimeView->sfseeHandle;
    if (sfseeHandle == nullptr) {
      return 0;
    }

    const std::int32_t stopResult = SFPLY_Stop(workctrlSubobj);
    if (stopResult != 0) {
      return stopResult;
    }

    (void)SFSET_SetCond(workctrlSubobj, kSfsetCondSeekRequest, 0);
    if (sfseeHandle->keepVideoEnabledOnSeek == 0) {
      (void)SFSET_SetCond(workctrlSubobj, kSfsetCondVideoEnable, 0);
    }
    if (sfseeHandle->keepAudioEnabledOnSeek == 0) {
      (void)SFSET_SetCond(workctrlSubobj, kSfsetCondAudioEnable, 0);
    }

    runtimeView->seekRequestWord0 = seekRequestWords[0];
    runtimeView->seekRequestWord1 = seekRequestWords[1];
    runtimeView->seekRequestWord2 = seekRequestWords[2];
    return SFTRN_CallTrSetup(SjPointerToAddress(workctrlSubobj), 13);
  }

  /**
   * Address: 0x00AED620 (FUN_00AED620, _SFD_SetSeekPos)
   *
   * What it does:
   * Validates one SFD handle and updates SFSEE seek base position lane.
   */
  std::int32_t
  SFD_SetSeekPos(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t seekPositionBytes)
  {
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetSeekPos);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    if (runtimeView->sfseeHandle != nullptr) {
      runtimeView->sfseeHandle->seekBaseReadTotalBytes = seekPositionBytes;
    }
    return 0;
  }

  /**
   * Address: 0x00AE5E90 (FUN_00AE5E90, _SFD_SetConcatPlay)
   *
   * What it does:
   * Validates one SFD handle and enables concat-play condition lane `49`.
   */
  std::int32_t SFD_SetConcatPlay(void* const sfdHandle)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetConcatPlay);
    }

    (void)SFSET_SetCond(workctrlSubobj, kSfsetCondConcatPlay, 1);
    return 0;
  }

  /**
   * Address: 0x00ACFA60 (FUN_00ACFA60, _SFD_SetOutPan)
   *
   * What it does:
   * Validates one SFD handle, checks output condition lane `6`, and forwards
   * pan update to the audio-output ops lane.
   */
  std::int32_t
  SFD_SetOutPan(void* const sfdHandle, const std::int32_t laneIndex, const std::int32_t panLevel)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetOutPan);
    }

    const std::int32_t result = SFSET_GetCond(workctrlSubobj, kSfsetCondAudioOutput);
    if (result != 0) {
      return GetSfdAudioOutputOps(workctrlSubobj)->setOutPan(workctrlSubobj, laneIndex, panLevel);
    }
    return result;
  }

  /**
   * Address: 0x00ACFAB0 (FUN_00ACFAB0, _SFD_GetOutPan)
   *
   * What it does:
   * Validates one SFD handle, checks output condition lane `6`, and forwards
   * pan read to the audio-output ops lane.
   */
  std::int32_t SFD_GetOutPan(void* const sfdHandle, const std::int32_t laneIndex)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      (void)SFLIB_SetErr(0, kSflibErrInvalidHandleGetOutPan);
      return 0;
    }

    const std::int32_t result = SFSET_GetCond(workctrlSubobj, kSfsetCondAudioOutput);
    if (result != 0) {
      return GetSfdAudioOutputOps(workctrlSubobj)->getOutPan(workctrlSubobj, laneIndex);
    }
    return result;
  }

  /**
   * Address: 0x00ACFB00 (FUN_00ACFB00, _SFD_SetOutVol)
   *
   * What it does:
   * Validates one SFD handle, checks output condition lane `6`, and forwards
   * volume update to the audio-output ops lane.
   */
  std::int32_t SFD_SetOutVol(void* const sfdHandle, const std::int32_t volumeLevel)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetOutVol);
    }

    const std::int32_t result = SFSET_GetCond(workctrlSubobj, kSfsetCondAudioOutput);
    if (result != 0) {
      return GetSfdAudioOutputOps(workctrlSubobj)->setOutVol(workctrlSubobj, volumeLevel);
    }
    return result;
  }

  /**
   * Address: 0x00ACFB50 (FUN_00ACFB50, _SFD_GetOutVol)
   *
   * What it does:
   * Validates one SFD handle, checks output condition lane `6`, and forwards
   * volume read to the audio-output ops lane.
   */
  std::int32_t SFD_GetOutVol(void* const sfdHandle)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      (void)SFLIB_SetErr(0, kSflibErrInvalidHandleGetOutVol);
      return 0;
    }

    const std::int32_t result = SFSET_GetCond(workctrlSubobj, kSfsetCondAudioOutput);
    if (result != 0) {
      return GetSfdAudioOutputOps(workctrlSubobj)->getOutVol(workctrlSubobj);
    }
    return result;
  }

  /**
   * Address: 0x00AE5AB0 (FUN_00AE5AB0, _SFD_SetVideoPts)
   *
   * What it does:
   * Validates one SFD handle and seeds the video PTS queue lane at `+0x13BC`
   * when source queue address/count inputs are valid.
   */
  std::int32_t SFD_SetVideoPts(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t ptsQueueSourceAddress,
    const std::int32_t ptsEntryCount
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetVideoPts = static_cast<std::int32_t>(0xFF000165u);

    if (ptsQueueSourceAddress != 0 && ptsEntryCount > 0) {
      if (SFLIB_CheckHn(workctrlSubobj) != 0) {
        return SFLIB_SetErr(0, kSflibErrInvalidHandleSetVideoPts);
      }

      auto* const runtimeView = reinterpret_cast<SfdPtsQueueOwnerRuntimeView*>(workctrlSubobj);
      sfpts_SetupPtsQue(&runtimeView->videoPtsQueue, ptsQueueSourceAddress, ptsEntryCount);
    }

    return 0;
  }

  /**
   * Address: 0x00AED530 (FUN_00AED530, _SFD_SetFileSize)
   *
   * What it does:
   * Validates one SFD handle, updates sfsee file-size lane, then refreshes
   * effective byte-rate tracking for the active stream.
   */
  std::int32_t
  SFD_SetFileSize(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t fileSizeBytes)
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetFileSize = static_cast<std::int32_t>(0xFF000159u);

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetFileSize);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    if (runtimeView->sfseeHandle != nullptr) {
      runtimeView->sfseeHandle->fileSizeBytes = fileSizeBytes;

      const auto workctrlAddress =
        static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
      sfsee_UpdateEByteRate(workctrlAddress);
    }

    return 0;
  }

  /**
   * Address: 0x00AED580 (FUN_00AED580, _SFD_SetTotTime)
   *
   * What it does:
   * Validates one SFD handle, updates configured sfsee total-time lanes, then
   * refreshes effective byte-rate tracking.
   */
  std::int32_t SFD_SetTotTime(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t totalTimeMajor,
    const std::int32_t totalTimeMinor
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetTotTime = static_cast<std::int32_t>(0xFF00015Au);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetTotTime);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    if (runtimeView->sfseeHandle != nullptr) {
      runtimeView->sfseeHandle->configuredTotalTimeMajor = totalTimeMajor;
      runtimeView->sfseeHandle->configuredTotalTimeMinor = totalTimeMinor;

      const auto workctrlAddress =
        static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
      (void)sfsee_UpdateEByteRate(workctrlAddress);
    }

    return 0;
  }

  /**
   * Address: 0x00AED5D0 (FUN_00AED5D0, _SFD_SetByteRate)
   *
   * What it does:
   * Validates one SFD handle, updates configured sfsee byte-rate lane, then
   * refreshes effective byte-rate tracking.
   */
  std::int32_t
  SFD_SetByteRate(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t byteRate)
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetByteRate = static_cast<std::int32_t>(0xFF00015Bu);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetByteRate);
    }

    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(workctrlSubobj);
    if (runtimeView->sfseeHandle != nullptr) {
      runtimeView->sfseeHandle->configuredByteRate = byteRate;

      const auto workctrlAddress =
        static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
      (void)sfsee_UpdateEByteRate(workctrlAddress);
    }

    return 0;
  }

  /**
   * Address: 0x00AED660 (FUN_00AED660, _sfsee_ExecFinAnaly)
   *
   * What it does:
   * Finalizes SFSEE total-time lanes from staged or measured stream input
   * totals and refreshes byte-rate tracking when a committed value changes.
   */
  std::int32_t sfsee_ExecFinAnaly(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const runtimeView = reinterpret_cast<SfseeFinAnalyControlRuntimeView*>(workctrlSubobj);
    SfseeRuntimeView* const sfseeHandle = runtimeView->sfseeHandle;

    const std::int32_t endcodeSkipResult =
      SFCON_IsEndcodeSkip(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
    if (endcodeSkipResult != 0) {
      return endcodeSkipResult;
    }

    std::int32_t didUpdateInputTotal = 0;
    if (sfseeHandle->inputReadTotalBytes <= 0) {
      std::int32_t baseReadTotalBytes = 0;
      if (runtimeView->finAnalyMode != -3) {
        baseReadTotalBytes = sfseeHandle->seekBaseReadTotalBytes;
        if (baseReadTotalBytes < 0) {
          baseReadTotalBytes = -1;
        }
      }

      if (baseReadTotalBytes >= 0) {
        const std::int32_t inSjReadTotal =
          sfsee_GetInSjReadTot(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
        if (inSjReadTotal != -1) {
          didUpdateInputTotal = 1;
          sfseeHandle->inputReadTotalBytes = baseReadTotalBytes + inSjReadTotal;
        }
      }
    }

    std::int32_t effectiveTotalMajor = sfseeHandle->effectiveTotalTimeMajor;
    if (effectiveTotalMajor <= 0) {
      effectiveTotalMajor = runtimeView->stagedTotalTimeMajor;
      if (effectiveTotalMajor > 0) {
        sfseeHandle->effectiveTotalTimeMajor = effectiveTotalMajor;
        sfseeHandle->effectiveTotalTimeMinor = runtimeView->stagedTotalTimeMinor;
        return sfsee_UpdateEByteRate(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
      }
    }

    if (didUpdateInputTotal != 0) {
      return sfsee_UpdateEByteRate(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
    }

    return effectiveTotalMajor;
  }

  struct SfseeInputSelectorEntryRuntimeView
  {
    std::int32_t inputTotalLaneIndex = 0; // +0x00
    std::uint8_t reserved04[0x70]{};
  };
  static_assert(
    offsetof(SfseeInputSelectorEntryRuntimeView, inputTotalLaneIndex) == 0x00,
    "SfseeInputSelectorEntryRuntimeView::inputTotalLaneIndex offset must be 0x00"
  );
  static_assert(
    sizeof(SfseeInputSelectorEntryRuntimeView) == 0x74,
    "SfseeInputSelectorEntryRuntimeView size must be 0x74"
  );

  struct SfseeInputTotalLaneRuntimeView
  {
    std::int32_t inputReadTotalBytes = 0; // +0x00
    std::uint8_t reserved04[0x40]{};
  };
  static_assert(
    offsetof(SfseeInputTotalLaneRuntimeView, inputReadTotalBytes) == 0x00,
    "SfseeInputTotalLaneRuntimeView::inputReadTotalBytes offset must be 0x00"
  );
  static_assert(sizeof(SfseeInputTotalLaneRuntimeView) == 0x44, "SfseeInputTotalLaneRuntimeView size must be 0x44");

  struct SfseeInputRouterRuntimeView
  {
    std::uint8_t reserved0000[0x1F44]{};
    std::int32_t activeSelectorIndex = 0; // +0x1F44
  };
  static_assert(
    offsetof(SfseeInputRouterRuntimeView, activeSelectorIndex) == 0x1F44,
    "SfseeInputRouterRuntimeView::activeSelectorIndex offset must be 0x1F44"
  );

  /**
   * Address: 0x00AE5ED0 (FUN_00AE5ED0, _SFCON_IsEndcodeSkip)
   *
   * What it does:
   * Returns whether endcode-skip condition lane `49` is enabled for one SFD
   * work-control handle.
   */
  std::int32_t SFCON_IsEndcodeSkip(const std::int32_t workctrlAddress)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(workctrlAddress))
    );
    return (SFSET_GetCond(workctrlSubobj, kSfsetCondConcatPlay) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AED710 (FUN_00AED710, _sfsee_GetInSjReadTot)
   *
   * What it does:
   * Resolves currently-selected input-SJ lane and returns its accumulated
   * read-total byte counter (`-1` when lane reports a negative sentinel).
   */
  std::int32_t sfsee_GetInSjReadTot(const std::int32_t workctrlAddress)
  {
    constexpr std::int32_t kSelectorTableOffset = 0x1360;
    constexpr std::int32_t kInputTotalTableOffset = 0x1F50;

    const auto* const runtimeView = reinterpret_cast<const SfseeInputRouterRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(workctrlAddress))
    );
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(runtimeView);
    const auto* const selectorEntries = reinterpret_cast<const SfseeInputSelectorEntryRuntimeView*>(bytes + kSelectorTableOffset);
    const auto* const inputTotalLanes = reinterpret_cast<const SfseeInputTotalLaneRuntimeView*>(bytes + kInputTotalTableOffset);
    const std::int32_t selectorIndex = runtimeView->activeSelectorIndex;
    const std::int32_t inputTotalLaneIndex = selectorEntries[selectorIndex].inputTotalLaneIndex;
    const std::int32_t readTotalBytes = inputTotalLanes[inputTotalLaneIndex].inputReadTotalBytes;
    return (readTotalBytes < 0) ? -1 : readTotalBytes;
  }

  /**
   * Address: 0x00AED750 (FUN_00AED750, _sfsee_UpdateEByteRate)
   *
   * What it does:
   * Recomputes one sfsee effective byte-rate lane from configured byte-rate,
   * explicit file-size/total-time lanes, or measured stream input totals.
   */
  extern "C" std::int32_t sfsee_UpdateEByteRate(const std::int32_t workctrlAddress)
  {
    auto* const runtimeView = reinterpret_cast<SfdSfseeOwnerRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(workctrlAddress))
    );
    SfseeRuntimeView* const sfseeHandle = runtimeView->sfseeHandle;

    std::int32_t computedByteRate = sfseeHandle->configuredByteRate;
    if (computedByteRate > 0) {
      sfseeHandle->effectiveByteRate = computedByteRate;
      return computedByteRate;
    }

    computedByteRate = sfseeHandle->fileSizeBytes;
    std::int32_t totalTimeMajor = sfseeHandle->configuredTotalTimeMajor;
    std::int32_t totalTimeMinor = sfseeHandle->configuredTotalTimeMinor;
    if (computedByteRate > 0 && totalTimeMajor > 0) {
      computedByteRate = UTY_MulDiv(computedByteRate, totalTimeMinor, totalTimeMajor);
      sfseeHandle->effectiveByteRate = computedByteRate;
      return computedByteRate;
    }

    const std::int32_t streamByteRateHint = sfseeHandle->streamByteRateHint;
    if (streamByteRateHint <= 0) {
      if (computedByteRate <= 0) {
        computedByteRate = sfseeHandle->inputReadTotalBytes;
      }

      if (totalTimeMajor <= 0) {
        totalTimeMajor = sfseeHandle->effectiveTotalTimeMajor;
        totalTimeMinor = sfseeHandle->effectiveTotalTimeMinor;
      }

      if (computedByteRate > 0 && totalTimeMajor > 0) {
        computedByteRate = UTY_MulDiv(computedByteRate, totalTimeMinor, totalTimeMajor);
        sfseeHandle->effectiveByteRate = computedByteRate;
        return computedByteRate;
      }
    }

    sfseeHandle->effectiveByteRate = streamByteRateHint;
    return computedByteRate;
  }

  struct SfmpvInfoRuntimeView
  {
    std::int32_t decoderHandle; // +0x00
  };

  struct SfdMpvHandleRuntimeView
  {
    std::uint8_t reserved00[0x1FC0]; // +0x00
    SfmpvInfoRuntimeView* mpvInfo; // +0x1FC0
  };
  static_assert(offsetof(SfdMpvHandleRuntimeView, mpvInfo) == 0x1FC0, "SfdMpvHandleRuntimeView::mpvInfo offset must be 0x1FC0");

  extern "C" std::int32_t MPV_SetCond(
    std::int32_t handleAddress,
    std::int32_t conditionId,
    std::int32_t (*conditionCallback)()
  );
  extern "C" std::int32_t MPV_GetCond(
    std::int32_t handleAddress,
    std::int32_t conditionId,
    std::int32_t* outConditionCallbackAddress
  );
  extern "C" std::int32_t* MPV_SetUsrSj(
    std::int32_t handleAddress,
    std::int32_t streamIndex,
    std::int32_t streamObjectAddress,
    std::int32_t streamCallbackAddress,
    std::int32_t streamContextAddress
  );
  extern "C" std::int32_t SFMPVF_GetNumFrm(std::int32_t workctrlAddress);
  extern "C" std::int32_t sfmpvf_SetPicUsrBuf(
    std::int32_t workctrlAddress,
    std::int32_t userBufferAddress,
    std::int32_t frameSlotCount,
    std::int32_t bytesPerFrame
  );

  struct SfdMpvParameterSnapshot
  {
    std::int32_t field_0x00 = 0; // +0x00
    std::int32_t field_0x04 = 0; // +0x04
    std::int32_t field_0x08 = 0; // +0x08
    std::int32_t field_0x0C = 0; // +0x0C
    std::int32_t val4 = 0; // +0x10
    std::int32_t field_0x14 = 0; // +0x14
    std::int32_t field_0x18 = 0; // +0x18
    std::int32_t framePoolCount = 0; // +0x1C
    std::int32_t val8 = 0; // +0x20
  };
  static_assert(offsetof(SfdMpvParameterSnapshot, val4) == 0x10, "SfdMpvParameterSnapshot::val4 offset must be 0x10");
  static_assert(
    offsetof(SfdMpvParameterSnapshot, framePoolCount) == 0x1C,
    "SfdMpvParameterSnapshot::framePoolCount offset must be 0x1C"
  );
  static_assert(offsetof(SfdMpvParameterSnapshot, val8) == 0x20, "SfdMpvParameterSnapshot::val8 offset must be 0x20");
  static_assert(sizeof(SfdMpvParameterSnapshot) == 0x24, "SfdMpvParameterSnapshot size must be 0x24");

  extern "C" SfdMpvParameterSnapshot sfmpv_para;
  extern "C" std::int32_t sfmpv_rfb_adr_tbl[2];
  extern "C" std::int32_t sSofDec_tabs[16];

  /**
   * Address: 0x00AD1970 (FUN_00AD1970, _SFMPV_SaveCond)
   *
   * What it does:
   * Reads MPV condition callback lanes from one work-control MPV handle into
   * caller storage and returns the number of lanes copied.
   */
  std::int32_t SFMPV_SaveCond(
    const std::int32_t workctrlAddress,
    std::int32_t* const outConditionCallbackAddresses,
    const std::uint32_t outConditionCallbackBytes
  )
  {
    const auto* const runtimeView = reinterpret_cast<const SfdMpvHandleRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(workctrlAddress))
    );
    const std::int32_t decoderHandle = runtimeView->mpvInfo->decoderHandle;
    if (decoderHandle == 0) {
      return 0;
    }

    std::int32_t conditionCount = static_cast<std::int32_t>(outConditionCallbackBytes >> 2u);
    if (conditionCount > 16) {
      conditionCount = 16;
    }

    for (std::int32_t conditionIndex = 0; conditionIndex < conditionCount; ++conditionIndex) {
      (void)MPV_GetCond(decoderHandle, conditionIndex, outConditionCallbackAddresses + conditionIndex);
    }

    return conditionCount;
  }

  /**
   * Address: 0x00AD19C0 (FUN_00AD19C0, _SFMPV_RestoreCond)
   *
   * What it does:
   * Restores MPV condition callback lanes for one work-control MPV handle from
   * caller-provided callback-address storage.
   */
  std::int32_t SFMPV_RestoreCond(
    const std::int32_t workctrlAddress,
    const std::int32_t* const conditionCallbackAddresses,
    const std::int32_t conditionCount
  )
  {
    std::int32_t result = workctrlAddress;
    const auto* const runtimeView = reinterpret_cast<const SfdMpvHandleRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(workctrlAddress))
    );
    const std::int32_t decoderHandle = runtimeView->mpvInfo->decoderHandle;
    if (decoderHandle == 0) {
      return result;
    }

    for (std::int32_t conditionIndex = 0; conditionIndex < conditionCount; ++conditionIndex) {
      const auto callback = reinterpret_cast<std::int32_t(*)()>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(conditionCallbackAddresses[conditionIndex]))
      );
      result = MPV_SetCond(decoderHandle, conditionIndex, callback);
    }

    return result;
  }

  /**
   * Address: 0x00AD16A0 (FUN_00AD16A0, _SFD_SetMpvPara)
   *
   * What it does:
   * Copies one MPV parameter snapshot into global runtime state, aligns two
   * address lanes to 0x800, and clears ring-buffer/SofDec tab slots.
   */
  std::int32_t SFD_SetMpvPara(const void* const parameterSnapshot)
  {
    const auto* const typedSnapshot = static_cast<const SfdMpvParameterSnapshot*>(parameterSnapshot);
    sfmpv_para = *typedSnapshot;
    sfmpv_para.val4 = static_cast<std::int32_t>((static_cast<std::uint32_t>(sfmpv_para.val4) + 0x7FFu) & 0xFFFFF800u);
    sfmpv_para.val8 = static_cast<std::int32_t>((static_cast<std::uint32_t>(sfmpv_para.val8) + 0x7FFu) & 0xFFFFF800u);
    sfmpv_rfb_adr_tbl[0] = 0;
    std::memset(sSofDec_tabs, 0, sizeof(sSofDec_tabs));
    sfmpv_rfb_adr_tbl[1] = 0;
    return 0;
  }

  /**
   * Address: 0x00AD1900 (FUN_00AD1900, _SFD_SetMpvCond)
   *
   * What it does:
   * Resolves one MPV handle from an optional SFD work-control handle, applies
   * one MPV condition callback, and reports SFLIB error codes on failure.
   */
  std::int32_t SFD_SetMpvCond(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    std::int32_t (*conditionCallback)()
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetMpvCond = static_cast<std::int32_t>(0xFF000181u);
    constexpr std::int32_t kSfmpvErrSetCondFailed = static_cast<std::int32_t>(0xFF000F12u);

    std::int32_t decoderHandle = 0;
    if (workctrlSubobj != nullptr) {
      if (SFLIB_CheckHn(workctrlSubobj) != 0) {
        return SFLIB_SetErr(0, kSflibErrInvalidHandleSetMpvCond);
      }

      const auto* const runtimeView = reinterpret_cast<const SfdMpvHandleRuntimeView*>(workctrlSubobj);
      if (runtimeView->mpvInfo != nullptr) {
        decoderHandle = runtimeView->mpvInfo->decoderHandle;
      }
    }

    std::int32_t (*const callback)() = (conditionId == 5) ? nullptr : conditionCallback;
    if (MPV_SetCond(decoderHandle, conditionId, callback) != 0) {
      const auto workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrSetCondFailed);
    }

    return 0;
  }

  /**
   * Address: 0x00AD1A50 (FUN_00AD1A50, _SFD_SetVideoUsrSj)
   *
   * What it does:
   * Validates one SFD handle and forwards one user stream/callback lane to
   * the bound MPV decoder handle.
   */
  std::int32_t SFD_SetVideoUsrSj(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t streamIndex,
    const std::int32_t streamObjectAddress,
    const std::int32_t streamCallbackAddress,
    const std::int32_t streamContextAddress
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetVideoUserStream = static_cast<std::int32_t>(0xFF000184u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetVideoUserStream);
    }

    const auto* const runtimeView = reinterpret_cast<const SfdMpvHandleRuntimeView*>(workctrlSubobj);
    (void)MPV_SetUsrSj(
      runtimeView->mpvInfo->decoderHandle,
      streamIndex,
      streamObjectAddress,
      streamCallbackAddress,
      streamContextAddress
    );
    return 0;
  }

  struct SfhdsColorTypeRuntimeView
  {
    std::uint8_t reserved00_77[0x78]{}; // +0x00
    std::int32_t hasHeaderState = 0; // +0x78
    std::uint8_t reserved7C_E7[0x6C]{}; // +0x7C
    std::int32_t hasColorType = 0; // +0xE8
    std::int32_t colorType = 0; // +0xEC
  };
  static_assert(
    offsetof(SfhdsColorTypeRuntimeView, hasHeaderState) == 0x78,
    "SfhdsColorTypeRuntimeView::hasHeaderState offset must be 0x78"
  );
  static_assert(
    offsetof(SfhdsColorTypeRuntimeView, hasColorType) == 0xE8,
    "SfhdsColorTypeRuntimeView::hasColorType offset must be 0xE8"
  );
  static_assert(offsetof(SfhdsColorTypeRuntimeView, colorType) == 0xEC, "SfhdsColorTypeRuntimeView::colorType offset must be 0xEC");

  /**
   * Address: 0x00AE78A0 (FUN_00AE78A0, _SFHDS_GetColType)
   *
   * What it does:
   * Returns decoded color-type lane from SFHDS runtime state; returns `-1`
   * when header state is missing or color-type lane is not valid.
   */
  std::int32_t SFHDS_GetColType(const std::int32_t workctrlAddress)
  {
    const auto* const colorTypeView =
      reinterpret_cast<const SfhdsColorTypeRuntimeView*>(SjAddressToPointer(workctrlAddress));
    if (colorTypeView->hasHeaderState == 0) {
      return -1;
    }
    if (colorTypeView->hasColorType == 0) {
      return -1;
    }
    return colorTypeView->colorType;
  }

  /**
   * Address: 0x00AD1A00 (FUN_00AD1A00, _SFD_GetNumFrm)
   *
   * What it does:
   * Validates one SFD handle, then returns current decodable-frame count from
   * the bound MPV handle through output pointer.
   */
  std::int32_t SFD_GetNumFrm(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outFrameCount
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetNumFrames = static_cast<std::int32_t>(0xFF000182u);

    *outFrameCount = 0;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetNumFrames);
    }

    const auto workctrlAddress =
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
    *outFrameCount = SFMPVF_GetNumFrm(workctrlAddress);
    return 0;
  }

  /**
   * Address: 0x00AD1AA0 (FUN_00AD1AA0, _SFD_SetPicUsrBuf)
   *
   * What it does:
   * Validates one SFD handle and forwards picture-user buffer registration to
   * the MPV frame-pool lane.
   */
  std::int32_t SFD_SetPicUsrBuf(
    void* const sfdHandle,
    const std::int32_t userBufferAddress,
    const std::int32_t frameSlotCount,
    const std::int32_t bytesPerFrame
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetPicUserBuffer = static_cast<std::int32_t>(0xFF000185u);
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetPicUserBuffer);
    }

    const auto sfdHandleAddress =
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
    return sfmpvf_SetPicUsrBuf(sfdHandleAddress, userBufferAddress, frameSlotCount, bytesPerFrame);
  }

  struct SfdAudioTransportVtableRuntimeView
  {
    void(__cdecl* reserved00)() = nullptr; // +0x00
    void(__cdecl* reserved04)() = nullptr; // +0x04
    void(__cdecl* reserved08)() = nullptr; // +0x08
    void(__cdecl* readTotalSamplesProc)() = nullptr; // +0x0C
  };
  static_assert(
    offsetof(SfdAudioTransportVtableRuntimeView, readTotalSamplesProc) == 0x0C,
    "SfdAudioTransportVtableRuntimeView::readTotalSamplesProc offset must be 0x0C"
  );

  struct SfdAudioTransportGateRuntimeView
  {
    SfdAudioTransportVtableRuntimeView* vtable = nullptr; // +0x00
    std::uint8_t reserved04_2003[0x2000]{}; // +0x04
    void** adxtRuntimeSlot = nullptr; // +0x2004
  };
  static_assert(
    offsetof(SfdAudioTransportGateRuntimeView, adxtRuntimeSlot) == 0x2004,
    "SfdAudioTransportGateRuntimeView::adxtRuntimeSlot offset must be 0x2004"
  );

  [[nodiscard]] static bool IsAdxtAudioTransportLane(
    const moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj
  ) noexcept
  {
    const auto* const transportView = reinterpret_cast<const SfdAudioTransportGateRuntimeView*>(workctrlSubobj);
    return transportView->vtable != nullptr && transportView->vtable->readTotalSamplesProc == &SFD_tr_ad_adxt;
  }

  [[nodiscard]] static void* ReadAttachedAdxtRuntime(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj
  ) noexcept
  {
    auto* const transportView = reinterpret_cast<SfdAudioTransportGateRuntimeView*>(workctrlSubobj);
    return *transportView->adxtRuntimeSlot;
  }

  /**
   * Address: 0x00AD0170 (FUN_00AD0170, _SFD_DetachMpa)
   *
   * What it does:
   * Detaches the ADXT MPEG-audio lane for one SFD handle when the active
   * audio transport is ADXT and an ADXT runtime is currently attached.
   */
  std::int32_t SFD_DetachMpa(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    std::int32_t result =
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
    if (workctrlSubobj != nullptr && IsAdxtAudioTransportLane(workctrlSubobj)) {
      void* const adxtRuntime = ReadAttachedAdxtRuntime(workctrlSubobj);
      result = static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(adxtRuntime)));
      if (adxtRuntime != nullptr) {
        return ADXT_DetachMpa();
      }
    }
    return result;
  }

  /**
   * Address: 0x00AD01F0 (FUN_00AD01F0, _SFD_DetachMPEG2AAC)
   *
   * What it does:
   * Detaches the ADXT MPEG-2 AAC lane for one SFD handle when the active
   * audio transport is ADXT and an ADXT runtime is currently attached.
   */
  std::int32_t SFD_DetachMPEG2AAC(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    std::int32_t result =
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
    if (workctrlSubobj != nullptr && IsAdxtAudioTransportLane(workctrlSubobj)) {
      void* const adxtRuntime = ReadAttachedAdxtRuntime(workctrlSubobj);
      result = static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(adxtRuntime)));
      if (adxtRuntime != nullptr) {
        return ADXT_DetachMPEG2AAC(adxtRuntime);
      }
    }
    return result;
  }

  extern "C" moho::SofdecAdxtParams sfadxt_para{};

  /**
   * Address: 0x00AD0270 (FUN_00AD0270, _SFD_SetAdxtPara)
   *
   * What it does:
   * Copies one ADXT parameter block into global `sfadxt_para`, aligning
   * work-buffer bytes to 0x20 and preserving low-byte-only alignment behavior
   * for the input-buffer lane.
   */
  std::int32_t SFD_SetAdxtPara(const moho::SofdecAdxtParams* const params)
  {
    sfadxt_para.value0 = params->value0;
    sfadxt_para.value1 = params->value1;

    const std::uint32_t alignedWorkBytes = static_cast<std::uint32_t>(params->adxWorkBytes) + 0x1Fu;
    sfadxt_para.adxWorkBytes = static_cast<std::int32_t>(alignedWorkBytes & 0xFFFFFFE0u);

    sfadxt_para.value3 = params->value3;
    sfadxt_para.value4 = params->value4;
    sfadxt_para.value5 = params->value5;

    const std::uint32_t inputWithBias = static_cast<std::uint32_t>(params->adxInputBufferBytes) + 0x1Fu;
    const std::uint32_t lowByteAlignedInput = (inputWithBias & 0xFFFFFF00u) | (inputWithBias & 0xE0u);
    sfadxt_para.adxInputBufferBytes = static_cast<std::int32_t>(lowByteAlignedInput);
    return static_cast<std::int32_t>(lowByteAlignedInput);
  }

  /**
   * Address: 0x00ADFB70 (FUN_00ADFB70, _sftrn_ConnTrnBuf0)
   */
  std::int32_t sftrn_ConnTrnBuf0(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 0, targetLane);
  }

  /**
   * Address: 0x00ADFB90 (FUN_00ADFB90, _sftrn_ConnTrnBufV)
   */
  std::int32_t sftrn_ConnTrnBufV(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 0, targetLane);
  }

  /**
   * Address: 0x00ADFBB0 (FUN_00ADFBB0, _sftrn_ConnTrnBufA)
   */
  std::int32_t sftrn_ConnTrnBufA(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 1, targetLane);
  }

  /**
   * Address: 0x00ADFBD0 (FUN_00ADFBD0, _sftrn_ConnTrnBufU)
   */
  std::int32_t sftrn_ConnTrnBufU(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 2, targetLane);
  }

  /**
   * Address: 0x00ADFBF0 (FUN_00ADFBF0, _sftrn_ConnTrnBuf)
   */
  std::int32_t sftrn_ConnTrnBuf(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t transferSlot,
    const std::int32_t targetLane
  )
  {
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(workctrlSubobj);
    auto* const sfbufRuntime = reinterpret_cast<SfbufRuntimeHandleView*>(workctrlSubobj);

    SftrnTransferDataLaneView* const sourceTransferLane = &transferRuntime->transferLanes[sourceLane];
    (&sourceTransferLane->targetLaneIndex0)[transferSlot] = targetLane;
    sfbufRuntime->lanes[targetLane].runtimeState0 = sourceLane;
    return 29 * targetLane;
  }

  /**
   * Address: 0x00ADFC30 (FUN_00ADFC30, _sftrn_ConnBufTrn)
   */
  std::int32_t sftrn_ConnBufTrn(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    auto* const sfbufRuntime = reinterpret_cast<SfbufRuntimeHandleView*>(workctrlSubobj);
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(workctrlSubobj);

    sfbufRuntime->lanes[sourceLane].runtimeState1 = targetLane;
    transferRuntime->transferLanes[targetLane].sourceLaneIndex = sourceLane;
    return sourceLane;
  }

  /**
   * Address: 0x00ADFC60 (FUN_00ADFC60, _SFTRN_CallTrSetup)
   */
  std::int32_t SFTRN_CallTrSetup(const std::int32_t workctrlAddress, const std::int32_t callbackIndex)
  {
    using SftrnTransferCallback =
      std::int32_t(__cdecl*)(std::int32_t workctrlArg, std::int32_t arg0, std::int32_t arg1, std::int32_t arg2);

    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    std::int32_t result = 0;
    for (std::int32_t laneIndex = 0; laneIndex < static_cast<std::int32_t>(transferRuntime->transferLanes.size()); ++laneIndex) {
      const std::int32_t descriptorAddress = transferRuntime->transferLanes[laneIndex].transferDescriptorAddress;
      if (descriptorAddress != 0) {
        auto* const callbacks = reinterpret_cast<SftrnTransferCallback*>(SjAddressToPointer(descriptorAddress));
        result = callbacks[callbackIndex](workctrlAddress, 0, 0, 0);
        if (result != 0) {
          break;
        }
      }
    }
    return result;
  }

  /**
   * Address: 0x00ADFCA0 (FUN_00ADFCA0, _SFTRN_CallTrtTrif)
   */
  std::int32_t SFTRN_CallTrtTrif(
    const std::int32_t workctrlAddress,
    const std::int32_t transferLaneIndex,
    const std::int32_t callbackIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  )
  {
    using SftrnTransferCallback =
      std::int32_t(__cdecl*)(std::int32_t workctrlArg, std::int32_t arg0, std::int32_t arg1, std::int32_t arg2);

    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    const std::int32_t descriptorAddress = transferRuntime->transferLanes[transferLaneIndex].transferDescriptorAddress;
    if (descriptorAddress == 0) {
      return 0;
    }

    auto* const callbacks = reinterpret_cast<SftrnTransferCallback*>(SjAddressToPointer(descriptorAddress));
    return callbacks[callbackIndex](workctrlAddress, arg0, arg1, 0);
  }

  /**
   * Address: 0x00ADFCE0 (FUN_00ADFCE0, _SFTRN_SetPrepFlg)
   */
  std::int32_t SFTRN_SetPrepFlg(
    const std::int32_t workctrlAddress,
    const std::int32_t transferLaneIndex,
    const std::int32_t prepFlag
  )
  {
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    transferRuntime->transferLanes[transferLaneIndex].prepFlag = prepFlag;
    return workctrlAddress;
  }

  /**
   * Address: 0x00ADFD00 (FUN_00ADFD00, _SFTRN_GetPrepFlg)
   */
  std::int32_t SFTRN_GetPrepFlg(const std::int32_t workctrlAddress, const std::int32_t transferLaneIndex)
  {
    const auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    return transferRuntime->transferLanes[transferLaneIndex].prepFlag;
  }

  /**
   * Address: 0x00ADFD20 (FUN_00ADFD20, _SFTRN_SetTermFlg)
   */
  std::int32_t SFTRN_SetTermFlg(
    const std::int32_t workctrlAddress,
    const std::int32_t transferLaneIndex,
    const std::int32_t termFlag
  )
  {
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    transferRuntime->transferLanes[transferLaneIndex].termFlag = termFlag;
    return workctrlAddress;
  }

  /**
   * Address: 0x00ADFD40 (FUN_00ADFD40, _SFTRN_GetTermFlg)
   */
  std::int32_t SFTRN_GetTermFlg(const std::int32_t workctrlAddress, const std::int32_t transferLaneIndex)
  {
    const auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    return transferRuntime->transferLanes[transferLaneIndex].termFlag;
  }

  /**
   * Address: 0x00ADFD60 (FUN_00ADFD60, _SFTRN_IsSetup)
   */
  std::int32_t SFTRN_IsSetup(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t transferLaneType)
  {
    const auto* const transferRuntime = reinterpret_cast<const SftrnTransferRuntimeView*>(workctrlSubobj);
    return (transferRuntime->transferLanes[transferLaneType].prepFlag != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00ADEF70 (FUN_00ADEF70, _SFBUF_RingGetDataSiz)
   */
  std::int32_t SFBUF_RingGetDataSiz(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[ringIndex].queuedDataBytes;
  }

  /**
   * Address: 0x00ADEF90 (FUN_00ADEF90, _SFBUF_GetRTot)
   */
  std::int32_t SFBUF_GetRTot(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[ringIndex].readTotalBytes;
  }

  struct SfbufDestroyLaneRuntimeView
  {
    std::int32_t laneType = 0; // +0x00
    std::uint8_t reserved04[0x10]{}; // +0x04
    moho::SofdecSjSupplyHandle* supplyHandle = nullptr; // +0x14
    std::uint8_t reserved18[0x5C]{}; // +0x18
  };
  static_assert(
    offsetof(SfbufDestroyLaneRuntimeView, laneType) == 0x00,
    "SfbufDestroyLaneRuntimeView::laneType offset must be 0x00"
  );
  static_assert(
    offsetof(SfbufDestroyLaneRuntimeView, supplyHandle) == 0x14,
    "SfbufDestroyLaneRuntimeView::supplyHandle offset must be 0x14"
  );
  static_assert(sizeof(SfbufDestroyLaneRuntimeView) == 0x74, "SfbufDestroyLaneRuntimeView size must be 0x74");

  struct SfbufDestroyRuntimeView
  {
    std::uint8_t reserved00[0x1310]{}; // +0x00
    std::array<SfbufDestroyLaneRuntimeView, 8> lanes{}; // +0x1310
  };
  static_assert(
    offsetof(SfbufDestroyRuntimeView, lanes) == 0x1310,
    "SfbufDestroyRuntimeView::lanes offset must be 0x1310"
  );

  /**
   * Address: 0x00ADE6F0 (FUN_00ADE6F0, _sfbuf_DestroySjSub)
   *
   * What it does:
   * For one SFBUF lane, destroys the bound SJ supply object when the lane is a
   * user-supply lane (`type 5`) and clears the supply-handle slot.
   */
  std::int32_t sfbuf_DestroySjSub(const std::int32_t sfbufHandleAddress, const std::int32_t laneIndex)
  {
    auto* const runtimeView = reinterpret_cast<SfbufDestroyRuntimeView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufDestroyLaneRuntimeView* const laneView = &runtimeView->lanes[laneIndex];

    std::int32_t result = laneView->laneType;
    if (result == 5) {
      auto* const supplyHandle = laneView->supplyHandle;
      result = SjPointerToAddress(supplyHandle);
      if (supplyHandle != nullptr) {
        supplyHandle->dispatchTable->destroy(supplyHandle);
        laneView->supplyHandle = nullptr;
      }
    }

    return result;
  }

  /**
   * Address: 0x00ADE6C0 (FUN_00ADE6C0, _SFBUF_DestroySj)
   *
   * What it does:
   * Calls SFBUF supply-destroy teardown for the three playback lanes in fixed
   * order (`0`, `1`, `2`) and returns the last lane result.
   */
  void SFBUF_DestroySj(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t sfbufHandleAddress = SjPointerToAddress(workctrlSubobj);
    (void)sfbuf_DestroySjSub(sfbufHandleAddress, 0);
    (void)sfbuf_DestroySjSub(sfbufHandleAddress, 1);
    (void)sfbuf_DestroySjSub(sfbufHandleAddress, 2);
  }

  /**
   * Address: 0x00ADDC70 (FUN_00ADDC70, _mwPlyStartFnameLp)
   */
  void mwPlyStartFnameLp(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrInvalidHandle);
      return;
    }

    if (fname == nullptr) {
      (void)MWSFSVM_Error(kMwsfdErrNullFileName);
      return;
    }

    MWSFPLY_RecordFname(ply, fname);
    lsc_Stop(ply->lscHandle);
    mwPlyEntryFname(ply, ply->fname);
    mwPlySetSeamlessLp(ply, 1);
    mwPlyStartSeamless(ply);
  }

  /**
   * Address: 0x00AC9290 (FUN_00AC9290, _mwsflib_SetSvrFunc)
   */
  void mwsflib_SetSvrFunc()
  {
    (void)MWSFSVM_EntryIdVfunc(
      2,
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFSVR_VsyncThrdProc)),
      0,
      "MWSFSVR_VsyncThrdProc"
    );
    (void)MWSFSVM_EntryMainFunc(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFSVR_MainThrdProc)),
      0,
      "MWSFSVR_MainThrdProc"
    );
    (void)MWSFSVM_EntryIdleFunc(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFSVR_IdleThrdProc)),
      0,
      "MWSFSVR_IdleThrdProc"
    );
  }

  extern "C" std::int32_t MWSFD_SetReqSvrBdrHn(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t requestEnabled);
  extern "C" void MWSFSVM_GotoIdleBorder();
  extern "C" std::int32_t MWSFSVR_CheckForceSvrBdr(std::int32_t plyAddress);

  /**
   * Address: 0x00AD9960 (FUN_00AD9960, _mwlSfdSleepDecSvr)
   *
   * What it does:
   * Saves playback resources, toggles decode-server border-request state
   * through the idle-border lane, restores resources, and returns force-border
   * status.
   */
  std::int32_t mwlSfdSleepDecSvr(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    mwPlySaveRsc();
    (void)MWSFD_SetReqSvrBdrHn(ply, 1);
    MWSFSVM_GotoIdleBorder();
    (void)MWSFD_SetReqSvrBdrHn(ply, 0);
    mwPlyRestoreRsc();
    return MWSFSVR_CheckForceSvrBdr(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply)));
  }

  struct SfmpvfFrameReadyWindowView
  {
    std::uint8_t reserved00[0x38]{}; // +0x00
    float frameStartTime = 0.0f;     // +0x38
    float frameEndTime = 0.0f;       // +0x3C
  };
  static_assert(
    offsetof(SfmpvfFrameReadyWindowView, frameStartTime) == 0x38,
    "SfmpvfFrameReadyWindowView::frameStartTime offset must be 0x38"
  );
  static_assert(
    offsetof(SfmpvfFrameReadyWindowView, frameEndTime) == 0x3C,
    "SfmpvfFrameReadyWindowView::frameEndTime offset must be 0x3C"
  );

  struct SfmpvfDecodeStateView
  {
    std::uint8_t reserved00[0x48]{}; // +0x00
    std::int32_t decodeState = 0; // +0x48
  };
  static_assert(
    offsetof(SfmpvfDecodeStateView, decodeState) == 0x48,
    "SfmpvfDecodeStateView::decodeState offset must be 0x48"
  );

  struct SfmpvfFrameObjectRuntimeView
  {
    std::int32_t decodeState = 0; // +0x00
    std::int32_t lockReferenceCount = 0; // +0x04
    std::uint8_t reserved08[0x50]{}; // +0x08
    std::int32_t frameId = 0; // +0x58
    std::uint8_t reserved5C[0x8C]{}; // +0x5C
  };
  static_assert(
    offsetof(SfmpvfFrameObjectRuntimeView, decodeState) == 0x00,
    "SfmpvfFrameObjectRuntimeView::decodeState offset must be 0x00"
  );
  static_assert(
    offsetof(SfmpvfFrameObjectRuntimeView, lockReferenceCount) == 0x04,
    "SfmpvfFrameObjectRuntimeView::lockReferenceCount offset must be 0x04"
  );
  static_assert(
    offsetof(SfmpvfFrameObjectRuntimeView, frameId) == 0x58,
    "SfmpvfFrameObjectRuntimeView::frameId offset must be 0x58"
  );
  static_assert(sizeof(SfmpvfFrameObjectRuntimeView) == 0xE8, "SfmpvfFrameObjectRuntimeView size must be 0xE8");

  struct SfmpvfInfoRuntimeView
  {
    std::uint8_t reserved00[0x7C]{}; // +0x00
    std::int32_t termDecodeState = 0; // +0x7C
    std::int32_t allowSingleFrameOutput = 0; // +0x80
    std::uint8_t reserved84[0xF4]{}; // +0x84
    std::int32_t frameObjectCount = 0; // +0x178
    std::array<SfmpvfFrameObjectRuntimeView, 16> frameObjects{}; // +0x180
  };
  static_assert(
    offsetof(SfmpvfInfoRuntimeView, termDecodeState) == 0x7C,
    "SfmpvfInfoRuntimeView::termDecodeState offset must be 0x7C"
  );
  static_assert(
    offsetof(SfmpvfInfoRuntimeView, allowSingleFrameOutput) == 0x80,
    "SfmpvfInfoRuntimeView::allowSingleFrameOutput offset must be 0x80"
  );
  static_assert(
    offsetof(SfmpvfInfoRuntimeView, frameObjectCount) == 0x178,
    "SfmpvfInfoRuntimeView::frameObjectCount offset must be 0x178"
  );

  struct SfmpvfSearchWorkctrlRuntimeView
  {
    std::uint8_t reserved00_16B7[0x16B8]{}; // +0x00
    std::array<std::uint8_t, 0x88> frameSearchLanes[16]{}; // +0x16B8
    std::uint8_t reserved1F38_1FBF[0x88]{}; // +0x1F38
    SfmpvfInfoRuntimeView* mpvInfo = nullptr; // +0x1FC0
  };
  static_assert(
    offsetof(SfmpvfSearchWorkctrlRuntimeView, frameSearchLanes) == 0x16B8,
    "SfmpvfSearchWorkctrlRuntimeView::frameSearchLanes offset must be 0x16B8"
  );
  static_assert(
    offsetof(SfmpvfSearchWorkctrlRuntimeView, mpvInfo) == 0x1FC0,
    "SfmpvfSearchWorkctrlRuntimeView::mpvInfo offset must be 0x1FC0"
  );

  struct SfdFrameLockRuntimeView
  {
    std::uint8_t reserved00_97F[0x980]{}; // +0x000
    std::int32_t activeLockedFrameCount = 0; // +0x980
  };
  static_assert(
    offsetof(SfdFrameLockRuntimeView, activeLockedFrameCount) == 0x980,
    "SfdFrameLockRuntimeView::activeLockedFrameCount offset must be 0x980"
  );

  /**
   * Address: 0x00ADC050 (FUN_00ADC050, _SFMPVF_SearchFrmObj)
   *
   * What it does:
   * Resolves one frame-search lane pointer to the corresponding MPV frame
   * object lane and returns its SJ address, or `0` when the lane is outside
   * the 16-slot frame-search window.
   */
  extern "C" std::int32_t SFMPVF_SearchFrmObj(const std::int32_t workctrlAddress, const std::int32_t frameSearchLaneAddress)
  {
    auto* const workctrlView = reinterpret_cast<SfmpvfSearchWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    std::uintptr_t laneCursor = reinterpret_cast<std::uintptr_t>(&workctrlView->frameSearchLanes[0]);
    const std::uintptr_t targetLane = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(frameSearchLaneAddress));

    std::int32_t frameIndex = 0;
    while (laneCursor != targetLane) {
      ++frameIndex;
      if (frameIndex >= 16) {
        return 0;
      }
      laneCursor += 0x88;
    }

    return SjPointerToAddress(&workctrlView->mpvInfo->frameObjects[frameIndex]);
  }

  /**
   * Address: 0x00ADBF60 (FUN_00ADBF60, _SFD_LockFrm)
   *
   * What it does:
   * Resolves one frame-search lane to one MPV frame object, increments that
   * frame object's lock counter, and increments per-handle lock depth.
   */
  std::int32_t SFD_LockFrm(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t frameSearchLaneAddress
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleLockFrame = static_cast<std::int32_t>(0xFF000188u);
    constexpr std::int32_t kSfmpvErrFrameSearchNotFoundForLock = static_cast<std::int32_t>(0xFF000F30u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleLockFrame);
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t frameObjectAddress = SFMPVF_SearchFrmObj(workctrlAddress, frameSearchLaneAddress);
    if (frameObjectAddress != 0) {
      auto* const frameObject = reinterpret_cast<SfmpvfFrameObjectRuntimeView*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(frameObjectAddress))
      );
      ++frameObject->lockReferenceCount;
    } else {
      (void)SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameSearchNotFoundForLock);
    }

    auto* const lockRuntimeView = reinterpret_cast<SfdFrameLockRuntimeView*>(workctrlSubobj);
    ++lockRuntimeView->activeLockedFrameCount;
    return lockRuntimeView->activeLockedFrameCount;
  }

  /**
   * Address: 0x00ADBFD0 (FUN_00ADBFD0, _SFD_UnlockFrm)
   *
   * What it does:
   * Resolves one frame-search lane to one MPV frame object, decrements that
   * frame object's lock counter with floor-at-zero semantics, and decrements
   * per-handle lock depth.
   */
  std::int32_t SFD_UnlockFrm(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t frameSearchLaneAddress
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleUnlockFrame = static_cast<std::int32_t>(0xFF000189u);
    constexpr std::int32_t kSfmpvErrFrameSearchNotFoundForUnlock = static_cast<std::int32_t>(0xFF000F31u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleUnlockFrame);
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t frameObjectAddress = SFMPVF_SearchFrmObj(workctrlAddress, frameSearchLaneAddress);
    if (frameObjectAddress != 0) {
      auto* const frameObject = reinterpret_cast<SfmpvfFrameObjectRuntimeView*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(frameObjectAddress))
      );
      --frameObject->lockReferenceCount;
      if (frameObject->lockReferenceCount < 0) {
        frameObject->lockReferenceCount = 0;
      }
    } else {
      (void)SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameSearchNotFoundForUnlock);
    }

    auto* const lockRuntimeView = reinterpret_cast<SfdFrameLockRuntimeView*>(workctrlSubobj);
    --lockRuntimeView->activeLockedFrameCount;
    return lockRuntimeView->activeLockedFrameCount;
  }

  extern "C" std::int32_t
    sfmpvf_IsChkFirst(const SfmpvfFrameObjectRuntimeView* selectedFrameObject, const SfmpvfFrameObjectRuntimeView* candidateFrameObject);

  /**
   * Address: 0x00ADC570 (FUN_00ADC570, _sfmpvf_SearchStbyFrm)
   *
   * What it does:
   * Scans decoded standby frame objects and outputs the two earliest
   * candidates based on `_sfmpvf_IsChkFirst` ordering semantics.
   */
  extern "C" std::int32_t sfmpvf_SearchStbyFrm(
    std::int32_t workctrlAddress,
    std::int32_t* outFirstStandbyFrameAddress,
    std::int32_t* outSecondStandbyFrameAddress
  )
  {
    auto* const workctrlView = reinterpret_cast<SfmpvfSearchWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    auto* const mpvInfo = workctrlView->mpvInfo;

    *outFirstStandbyFrameAddress = 0;
    *outSecondStandbyFrameAddress = 0;

    std::int32_t selectableFrameCount = 0;
    if (mpvInfo->frameObjectCount > 0) {
      auto asFrameObject = [](const std::int32_t frameObjectAddress) -> const SfmpvfFrameObjectRuntimeView* {
        return reinterpret_cast<const SfmpvfFrameObjectRuntimeView*>(
          static_cast<std::uintptr_t>(static_cast<std::uint32_t>(frameObjectAddress))
        );
      };

      for (std::int32_t frameIndex = 0; frameIndex < mpvInfo->frameObjectCount; ++frameIndex) {
        auto* const candidateFrameObject = &mpvInfo->frameObjects[frameIndex];
        if ((candidateFrameObject->decodeState == 2 || candidateFrameObject->decodeState == 4) &&
            candidateFrameObject->frameId == -1) {
          ++selectableFrameCount;
          if (sfmpvf_IsChkFirst(asFrameObject(*outFirstStandbyFrameAddress), candidateFrameObject) != 0) {
            *outSecondStandbyFrameAddress = *outFirstStandbyFrameAddress;
            *outFirstStandbyFrameAddress = SjPointerToAddress(candidateFrameObject);
          } else if (sfmpvf_IsChkFirst(asFrameObject(*outSecondStandbyFrameAddress), candidateFrameObject) != 0) {
            *outSecondStandbyFrameAddress = SjPointerToAddress(candidateFrameObject);
          }
        }
      }
    }

    std::int32_t result = selectableFrameCount;
    if (mpvInfo->termDecodeState == 0) {
      --result;
    }

    if (result > 0) {
      if (result == 1) {
        *outSecondStandbyFrameAddress = 0;
      }
    } else {
      *outFirstStandbyFrameAddress = 0;
      *outSecondStandbyFrameAddress = 0;
    }

    return result;
  }

  std::int32_t SFTIM_IsGetFrmTimeTunit(std::int32_t workctrlAddress, float frameStartTime, float frameEndTime);

  /**
   * Address: 0x00ADC400 (FUN_00ADC400, _sfmpvf_GetNumFrmOverTime)
   *
   * What it does:
   * Counts standby frames currently over the time gate (0, 1, or 2), honoring
   * condition 15 timing checks and decode-state restrictions.
   */
  std::int32_t sfmpvf_GetNumFrmOverTime(const std::int32_t workctrlAddress)
  {
    std::int32_t firstStandbyFrameAddress = 0;
    std::int32_t secondStandbyFrameAddress = 0;

    SFLIB_LockCs();
    sfmpvf_SearchStbyFrm(workctrlAddress, &firstStandbyFrameAddress, &secondStandbyFrameAddress);

    const auto* const workctrlView = reinterpret_cast<const SfmpvfDecodeStateView*>(SjAddressToPointer(workctrlAddress));
    if (workctrlView->decodeState != 4) {
      secondStandbyFrameAddress = 0;
    }

    const std::int32_t requiresTimeGate = SFSET_GetCond(
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(const_cast<SfmpvfDecodeStateView*>(workctrlView)),
      15
    );

    auto isFrameOverTimeGate = [&](const std::int32_t frameAddress) -> bool {
      if (frameAddress == 0) {
        return false;
      }
      if (requiresTimeGate == 0) {
        return true;
      }
      const auto* const frameWindow = reinterpret_cast<const SfmpvfFrameReadyWindowView*>(static_cast<std::uintptr_t>(frameAddress));
      return SFTIM_IsGetFrmTimeTunit(workctrlAddress, frameWindow->frameStartTime, frameWindow->frameEndTime) != 0;
    };

    std::int32_t overTimeFrameCount = 0;
    if (isFrameOverTimeGate(firstStandbyFrameAddress)) {
      overTimeFrameCount = isFrameOverTimeGate(secondStandbyFrameAddress) ? 2 : 1;
    }

    SFLIB_UnlockCs();
    return overTimeFrameCount;
  }

  /**
   * Address: 0x00ADC4F0 (FUN_00ADC4F0, _sfmpvf_ReferNextFrmReady)
   *
   * What it does:
   * Returns the next standby-picture frame pointer when decode state is ready,
   * optionally filtering by timer-unit gate when condition 15 is enabled.
   */
  std::int32_t sfmpvf_ReferNextFrmReady(const std::int32_t workctrlAddress)
  {
    std::int32_t readyFrameAddress = 0;
    std::int32_t searchState = 0;

    SFLIB_LockCs();

    const auto* const workctrlStorage =
      reinterpret_cast<const std::uint8_t*>(SjAddressToPointer(workctrlAddress));
    const std::int32_t decodeState = *reinterpret_cast<const std::int32_t*>(workctrlStorage + 0x48);
    if (decodeState == 4) {
      sfmpvf_SearchStbyFrm(workctrlAddress, &searchState, &readyFrameAddress);
      if (readyFrameAddress != 0 &&
          SFSET_GetCond(reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(const_cast<std::uint8_t*>(workctrlStorage)), 15)
              != 0) {
        const auto* const frameWindow =
          reinterpret_cast<const SfmpvfFrameReadyWindowView*>(static_cast<std::uintptr_t>(readyFrameAddress));
        if (SFTIM_IsGetFrmTimeTunit(workctrlAddress, frameWindow->frameStartTime, frameWindow->frameEndTime) == 0) {
          readyFrameAddress = 0;
        }
      }
    }

    SFLIB_UnlockCs();
    return readyFrameAddress;
  }

  struct SfmpvfReadyFramePictureUserView
  {
    std::uint8_t reserved00_53[0x54]{};
    const std::int32_t* pictureUserWords = nullptr; // +0x54
  };
  static_assert(
    offsetof(SfmpvfReadyFramePictureUserView, pictureUserWords) == 0x54,
    "SfmpvfReadyFramePictureUserView::pictureUserWords offset must be 0x54"
  );

  /**
   * Address: 0x00ADC360 (FUN_00ADC360, _SFD_GetNextPicUsr)
   *
   * What it does:
   * Fetches the next ready frame and copies its 2-word picture-user lane into
   * caller output storage; preserves the original null-user return quirk by
   * returning `outPictureUserWord0` when the frame has no picture-user lane.
   */
  std::int32_t SFD_GetNextPicUsr(
    const std::int32_t workctrlAddress,
    std::int32_t* const outPictureUserWord0,
    std::int32_t* const outPictureUserWord1
  )
  {
    std::int32_t result = sfmpvf_ReferNextFrmReady(workctrlAddress);
    if (result == 0) {
      *outPictureUserWord0 = 0;
      *outPictureUserWord1 = 0;
      return result;
    }

    const auto* const readyFrameView = reinterpret_cast<const SfmpvfReadyFramePictureUserView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(result))
    );
    const std::int32_t* const pictureUserWords = readyFrameView->pictureUserWords;
    if (pictureUserWords == nullptr) {
      result = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(outPictureUserWord0))
      );
      *outPictureUserWord0 = 0;
      *outPictureUserWord1 = 0;
      return result;
    }

    *outPictureUserWord0 = pictureUserWords[0];
    result = pictureUserWords[1];
    *outPictureUserWord1 = result;
    return result;
  }

  /**
   * Address: 0x00ACB130 (FUN_00ACB130, _mwSfdStopDec)
   */
  void mwSfdStopDec(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    void* const handle = ply->handle;
    if (handle == nullptr) {
      return;
    }

    mwlSfdSleepDecSvr(ply);
    ply->compoMode = 0;
    ply->handle = nullptr;

    if (SFD_Stop(handle) != 0) {
      (void)MWSFLIB_SetErrCode(-308);
      (void)MWSFSVM_Error(kMwsfdErrStopFailed);
    }

    ply->handle = handle;
    MWSST_Stop(&ply->streamState);
    ply->streamState.decodeServerSleepState = 0;

    if (ply->adxStreamHandle != nullptr) {
      MWSTM_ReqStop(ply->adxStreamHandle);
    }
    if (ply->lscHandle != nullptr) {
      lsc_Stop(ply->lscHandle);
    }
  }

  /**
   * Address: 0x00AD8B90 (FUN_00AD8B90, _SFD_Init)
   *
   * What it does:
   * Initializes SFLIB base state and starts all subordinate init lanes.
   */
  std::int32_t SFD_Init(moho::MwsfdInitSfdParams* const initParams)
  {
    gSflibLibWork.versionTag = kMwsfdRequiredVersionTag;
    gCriVerstrPtrSfd = kCriSfdVersionString;

    sflib_InitBaseLib();
    const std::int32_t initResult = sflib_InitLibWork(initParams);
    if (initResult != 0) {
      return initResult;
    }

    sflib_InitSub();
    sflib_InitCs();
    return 0;
  }

  /**
   * Address: 0x00AD8BD0 (FUN_00AD8BD0, _sflib_InitLibWork)
   *
   * What it does:
   * Resets global SFLIB work state, installs default condition lanes, and
   * initializes timer/buffer/transfer subordinate lanes.
   */
  std::int32_t sflib_InitLibWork(const moho::MwsfdInitSfdParams* const initParams)
  {
    std::memset(&gSflibLibWork, 0, offsetof(SflibLibWorkRuntime, versionTag));
    gSflibLibWork.defaultConditions = kSfplyDefaultConditions;
    gSflibLibWork.initParams = *initParams;
    gSflibLibWork.initState = 0;

    (void)sflib_InitErr(&gSflibLibWork.errInfo);
    SFTIM_Init(gSflibLibWork.timeState, initParams->version);
    (void)SFBUF_Init();
    (void)sflib_InitResetPara(&gSflibLibWork);
    std::memset(gSflibLibWork.objectHandles.data(), 0, sizeof(gSflibLibWork.objectHandles));

    return SFTRN_Init(
      &gSflibLibWork.transferInitState,
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(initParams->callbacks))
    );
  }

  /**
   * Address: 0x00AD8C70 (FUN_00AD8C70, _sflib_InitResetPara)
   *
   * What it does:
   * Clears two reset/runtime lanes in one SFLIB work object.
   */
  SflibLibWorkRuntime* sflib_InitResetPara(SflibLibWorkRuntime* const libWork)
  {
    libWork->transferInitState.resetParameter = 0;
    libWork->transferInitState.adxtHandle = 0;
    return libWork;
  }

  /**
   * Address: 0x00AD8D10 (FUN_00AD8D10, _SFLIB_InitErrInf)
   *
   * What it does:
   * Clears one SFLIB error-info lane.
   */
  SflibErrorInfo* SFLIB_InitErrInf(SflibErrorInfo* const errInfo)
  {
    errInfo->callback = nullptr;
    errInfo->callbackObject = 0;
    errInfo->firstErrorCode = 0;
    errInfo->reserved0 = 0;
    errInfo->reserved1 = 0;
    return errInfo;
  }

  /**
   * Address: 0x00AD8D00 (FUN_00AD8D00, _sflib_InitErr)
   *
   * What it does:
   * Thunk to `SFLIB_InitErrInf`.
   */
  SflibErrorInfo* sflib_InitErr(SflibErrorInfo* const errInfo)
  {
    return SFLIB_InitErrInf(errInfo);
  }

  /**
   * Address: 0x00AD8D80 (FUN_00AD8D80, _sflib_SetErrSub)
   *
   * What it does:
   * Latches first error code and dispatches callback when configured.
   */
  std::int32_t sflib_SetErrSub(SflibErrorInfo* const errInfo, const std::int32_t errorCode)
  {
    if (errInfo->firstErrorCode == 0) {
      errInfo->firstErrorCode = errorCode;
    }

    if (errorCode != 0 && errInfo->callback != nullptr) {
      return errInfo->callback(errInfo->callbackObject, errorCode);
    }

    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(errInfo));
  }

  /**
   * Address: 0x00AD8D30 (FUN_00AD8D30, _SFLIB_SetErr)
   *
   * What it does:
   * Routes one non-zero error code into object-local or global SFLIB error
   * lanes and flips positive owner state into negative faulted state.
   */
  std::int32_t SFLIB_SetErr(const std::int32_t errorObjectAddress, const std::int32_t errorCode)
  {
    if (errorCode == 0) {
      return 0;
    }

    if (errorObjectAddress == 0) {
      (void)sflib_SetErrSub(&gSflibLibWork.errInfo, errorCode);
      return errorCode;
    }

    auto* const errorOwner =
      reinterpret_cast<SflibErrorOwnerRuntimeView*>(SjAddressToPointer(errorObjectAddress));
    (void)sflib_SetErrSub(&errorOwner->errInfo, errorCode);

    if (errorOwner->handleState > 0) {
      errorOwner->handleState = -errorOwner->handleState;
    }

    return errorCode;
  }

  /**
   * Address: 0x00ACF910 (FUN_00ACF910, errFn)
   *
   * What it does:
   * Internal error thunk that forwards `(object, code)` to `SFLIB_SetErr`.
   */
  std::int32_t sfbuf_ErrFn(const std::int32_t errorObjectAddress, const std::int32_t errorCode)
  {
    return SFLIB_SetErr(errorObjectAddress, errorCode);
  }

  /**
   * Address: 0x00AD6A60 (FUN_00AD6A60, _sfmps_ErrFn)
   *
   * What it does:
   * Stream parser error thunk that forwards `(object, code)` to `SFLIB_SetErr`.
   */
  std::int32_t sfmps_ErrFn(const std::int32_t errorObjectAddress, const std::int32_t errorCode)
  {
    return SFLIB_SetErr(errorObjectAddress, errorCode);
  }

  /**
   * Address: 0x00AD55A0 (FUN_00AD55A0, _sfmps_ChkFatal)
   *
   * What it does:
   * Returns parser fatal-state lane for SFMPS startup checks. This build keeps
   * the lane disabled and always returns `0`.
   */
  std::int32_t sfmps_ChkFatal()
  {
    return 0;
  }

  struct MpslibErrorInfoRuntimeView
  {
    std::int32_t callbackAddress = 0; // +0x00
    std::int32_t callbackObject = 0; // +0x04
    std::int32_t lastErrorCode = 0; // +0x08
  };
  static_assert(sizeof(MpslibErrorInfoRuntimeView) == 0x0C, "MpslibErrorInfoRuntimeView size must be 0x0C");

  struct MpslibHandleRuntimeView
  {
    std::int32_t handleState = 1; // +0x00
    std::uint8_t reserved04_FF[0xFC]{}; // +0x04
  };
  static_assert(offsetof(MpslibHandleRuntimeView, handleState) == 0x00, "MpslibHandleRuntimeView::handleState offset must be 0x00");
  static_assert(sizeof(MpslibHandleRuntimeView) == 0x100, "MpslibHandleRuntimeView size must be 0x100");

  struct MpslibRuntimeView
  {
    MpslibErrorInfoRuntimeView errInfo{}; // +0x00
    std::int32_t handleCount = 0; // +0x0C
    std::array<MpslibHandleRuntimeView, 32> handles{}; // +0x10
  };
  static_assert(offsetof(MpslibRuntimeView, errInfo) == 0x00, "MpslibRuntimeView::errInfo offset must be 0x00");
  static_assert(offsetof(MpslibRuntimeView, handleCount) == 0x0C, "MpslibRuntimeView::handleCount offset must be 0x0C");
  static_assert(offsetof(MpslibRuntimeView, handles) == 0x10, "MpslibRuntimeView::handles offset must be 0x10");
  static_assert(sizeof(MpslibRuntimeView) == 0x2010, "MpslibRuntimeView size must be 0x2010");

  MpslibRuntimeView sfmps_libwork{};
  MpslibRuntimeView* MPSLIB_libwork = nullptr;
  const char* cri_verstr_ptr_mps = nullptr;
  std::int32_t copy_sj_error = 0;
  std::int32_t mpslib_deb_hn_last = 0;

  /**
   * Address: 0x00AEB080 (FUN_00AEB080, _MPSLIB_InitErrInf)
   *
   * What it does:
   * Clears one MPSLIB error-info lane.
   */
  MpslibErrorInfoRuntimeView* MPSLIB_InitErrInf(MpslibErrorInfoRuntimeView* const errInfo)
  {
    errInfo->callbackAddress = 0;
    errInfo->callbackObject = 0;
    errInfo->lastErrorCode = 0;
    return errInfo;
  }

  /**
   * Address: 0x00AEB070 (FUN_00AEB070, _mpslib_InitErr)
   *
   * What it does:
   * Thunk to `MPSLIB_InitErrInf`.
   */
  MpslibErrorInfoRuntimeView* mpslib_InitErr(MpslibErrorInfoRuntimeView* const errInfo)
  {
    return MPSLIB_InitErrInf(errInfo);
  }

  /**
   * Address: 0x00AEAFD0 (FUN_00AEAFD0, _mpslib_InitLibWork)
   *
   * What it does:
   * Installs one MPSLIB work area, clears it, initializes error-info lanes,
   * sets handle count, and marks each handle slot as free (`state = 1`).
   */
  std::int32_t mpslib_InitLibWork(const std::int32_t handleCount, const std::int32_t workAddress)
  {
    auto* const workBase = reinterpret_cast<std::uint8_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(workAddress))
    );
    MPSLIB_libwork = reinterpret_cast<MpslibRuntimeView*>(workBase);

    const std::size_t workBytes = (static_cast<std::size_t>(handleCount) << 8u) + 0x10u;
    std::memset(workBase, 0, workBytes);
    (void)mpslib_InitErr(&MPSLIB_libwork->errInfo);
    MPSLIB_libwork->handleCount = handleCount;

    auto* handleSlot = reinterpret_cast<MpslibHandleRuntimeView*>(workBase + 0x10);
    for (std::int32_t slotIndex = 0; slotIndex < handleCount; ++slotIndex) {
      handleSlot->handleState = 1;
      handleSlot = reinterpret_cast<MpslibHandleRuntimeView*>(
        reinterpret_cast<std::uint8_t*>(handleSlot) + sizeof(MpslibHandleRuntimeView)
      );
    }

    return 0;
  }

  /**
   * Address: 0x00AEB0C0 (FUN_00AEB0C0, _mpslib_SetErrSub)
   *
   * What it does:
   * Stores last MPSLIB error code and dispatches optional callback.
   */
  void mpslib_SetErrSub(MpslibErrorInfoRuntimeView* const errInfo, const std::int32_t errorCode)
  {
    errInfo->lastErrorCode = errorCode;
    if (errorCode == 0 || errInfo->callbackAddress == 0) {
      return;
    }

    const auto callback = reinterpret_cast<void(__cdecl*)(std::int32_t callbackObject, std::int32_t errorCode)>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(errInfo->callbackAddress))
    );
    callback(errInfo->callbackObject, errorCode);
  }

  /**
   * Address: 0x00AEB150 (FUN_00AEB150, _mpslib_SetErrFnSub)
   *
   * What it does:
   * Stores MPSLIB error callback address/object pair and returns updated lane.
   */
  MpslibErrorInfoRuntimeView* mpslib_SetErrFnSub(
    MpslibErrorInfoRuntimeView* const errInfo,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    errInfo->callbackAddress = callbackAddress;
    errInfo->callbackObject = callbackObject;
    return errInfo;
  }

  /**
   * Address: 0x00AEB1E0 (FUN_00AEB1E0, _MPSLIB_CheckHn)
   *
   * What it does:
   * Saves last debug handle lane and returns `0` for active handles
   * (`handleState != 1`), `-1` otherwise.
   */
  std::int32_t MPSLIB_CheckHn(MpslibHandleRuntimeView* const handle)
  {
    mpslib_deb_hn_last = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(handle));
    if (handle == nullptr) {
      return -1;
    }
    return (handle->handleState != 1) ? 0 : -1;
  }

  /**
   * Address: 0x00AEB090 (FUN_00AEB090, _MPSLIB_SetErr)
   *
   * What it does:
   * Routes MPSLIB error codes into either per-handle or global error lanes.
   */
  std::int32_t MPSLIB_SetErr(const std::int32_t mpsHandleAddress, const std::int32_t errorCode)
  {
    if (mpsHandleAddress != 0) {
      auto* const handle = reinterpret_cast<std::uint8_t*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(mpsHandleAddress))
      );
      auto* const handleErrInfo = reinterpret_cast<MpslibErrorInfoRuntimeView*>(handle + 4);
      mpslib_SetErrSub(handleErrInfo, errorCode);
    } else {
      mpslib_SetErrSub(&MPSLIB_libwork->errInfo, errorCode);
    }
    return errorCode;
  }

  /**
   * Address: 0x00AEB0F0 (FUN_00AEB0F0, _MPS_SetErrFn)
   *
   * What it does:
   * Installs MPS error callback pair on one handle (or globally when handle is
   * null), validating handle state first.
   */
  std::int32_t MPS_SetErrFn(
    const std::int32_t mpsHandleAddress,
    std::int32_t(__cdecl* const errorCallback)(std::int32_t errorObjectAddress, std::int32_t errorCode),
    const std::int32_t errorObjectAddress
  )
  {
    if (mpsHandleAddress != 0) {
      auto* const handle = reinterpret_cast<MpslibHandleRuntimeView*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(mpsHandleAddress))
      );
      if (MPSLIB_CheckHn(handle) != 0) {
        return MPSLIB_SetErr(0, -16645887);
      }

      auto* const handleErrInfo = reinterpret_cast<MpslibErrorInfoRuntimeView*>(
        reinterpret_cast<std::uint8_t*>(handle) + 4
      );
      const auto callbackAddress =
        static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(errorCallback)));
      (void)mpslib_SetErrFnSub(handleErrInfo, callbackAddress, errorObjectAddress);
      return 0;
    }

    const auto callbackAddress =
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(errorCallback)));
    (void)mpslib_SetErrFnSub(&MPSLIB_libwork->errInfo, callbackAddress, errorObjectAddress);
    return 0;
  }

  /**
   * Address: 0x00AEB170 (FUN_00AEB170, _MPS_GetErrInf)
   *
   * What it does:
   * Returns three-lane error-info snapshot from one handle or global lane.
   */
  std::int32_t MPS_GetErrInf(const std::int32_t mpsHandleAddress, std::int32_t* const outErrInfo)
  {
    if (mpsHandleAddress != 0) {
      auto* const handle = reinterpret_cast<MpslibHandleRuntimeView*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(mpsHandleAddress))
      );
      if (MPSLIB_CheckHn(handle) != 0) {
        return MPSLIB_SetErr(0, -16645886);
      }

      auto* const handleWords = reinterpret_cast<const std::int32_t*>(handle);
      outErrInfo[0] = handleWords[1];
      outErrInfo[1] = handleWords[2];
      outErrInfo[2] = handleWords[3];
      return 0;
    }

    outErrInfo[0] = MPSLIB_libwork->errInfo.callbackAddress;
    outErrInfo[1] = MPSLIB_libwork->errInfo.callbackObject;
    outErrInfo[2] = MPSLIB_libwork->errInfo.lastErrorCode;
    return 0;
  }

  /**
   * Address: 0x00AEB280 (FUN_00AEB280, _mpslib_SearchFreeHn)
   *
   * What it does:
   * Scans MPS handle table and returns first free handle (`state == 1`).
   */
  MpslibHandleRuntimeView* mpslib_SearchFreeHn()
  {
    auto* handle = &MPSLIB_libwork->handles[0];
    if (MPSLIB_libwork->handleCount <= 0) {
      return nullptr;
    }

    for (std::int32_t handleIndex = 0; handleIndex < MPSLIB_libwork->handleCount; ++handleIndex) {
      if (handle->handleState == 1) {
        return handle;
      }
      ++handle;
    }

    return nullptr;
  }

  /**
   * Address: 0x00AEB470 (FUN_00AEB470, _MPSDEC_Init)
   *
   * What it does:
   * No-op init lane for this build's MPS decoder helper.
   */
  void MPSDEC_Init()
  {
  }

  /**
   * Address: 0x00AEB480 (FUN_00AEB480, _MPSDEC_Finish)
   *
   * What it does:
   * No-op finalize lane for this build's MPS decoder helper.
   */
  void MPSDEC_Finish()
  {
  }

  /**
   * Address: 0x00AECA90 (FUN_00AECA90, _MPSGET_Init)
   *
   * What it does:
   * No-op init lane for this build's MPS getter helper.
   */
  void MPSGET_Init()
  {
  }

  /**
   * Address: 0x00AECAA0 (FUN_00AECAA0, _MPSGET_Finish)
   *
   * What it does:
   * No-op finalize lane for this build's MPS getter helper.
   */
  void MPSGET_Finish()
  {
  }

  std::int32_t M2P_Init();

  /**
   * Address: 0x00AEAF90 (FUN_00AEAF90, _MPS_Init)
   *
   * What it does:
   * Installs CRI MPS version string, initializes MPS library work, then
   * initializes MPS decoder/getter helpers and M2P runtime lane.
   */
  std::int32_t MPS_Init(const std::int32_t handleCount, const std::int32_t workAddress)
  {
    static constexpr char kCriMpsVersionString[] = "\nCRI MPS/PC Ver.1.924 Build:Feb 28 2005 21:33:31\n";
    cri_verstr_ptr_mps = kCriMpsVersionString;

    const std::int32_t initResult = mpslib_InitLibWork(handleCount, workAddress);
    if (initResult != 0) {
      return initResult;
    }

    MPSDEC_Init();
    MPSGET_Init();
    (void)M2P_Init();
    return 0;
  }

  /**
   * Address: 0x00AD5560 (FUN_00AD5560, _SFMPS_Init)
   *
   * What it does:
   * Runs SFMPS fatal gate, initializes MPS runtime work area (`32` handles),
   * reports one SFLIB error on init failure, and resets copy-sj error counter.
   */
  std::int32_t SFMPS_Init()
  {
    constexpr std::int32_t kSflibErrSfmpsInitFailed = static_cast<std::int32_t>(0xFF000D01u);

    if (sfmps_ChkFatal() != 0) {
      while (true) {
      }
    }

    if (MPS_Init(32, SjPointerToAddress(&sfmps_libwork)) != 0) {
      return SFLIB_SetErr(0, kSflibErrSfmpsInitFailed);
    }

    copy_sj_error = 0;
    return 0;
  }

  struct SfmpsSupplyLaneRuntimeView;
  struct MpsElementaryInfoEntryView;

  SfmpsSupplyLaneRuntimeView* getSupSj(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t setTermDst(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t termFlag);
  std::int32_t getTermDst(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

  std::int32_t sfmps_Concat(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_ChkSupply(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    const char* supplyBuffer,
    std::int32_t supplyBytes,
    std::int32_t shortSupplyBytes
  );
  std::int32_t sfmps_ShortSupply(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t* outShortSupplyLatched);
  std::int32_t sfmps_InitInf(void* parserRuntimeAddress);
  std::int32_t SFMPS_Create(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_SetElementOutSj(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t elementType,
    std::int32_t elementOutputJoinAddress,
    std::int32_t copyCompleteCallbackAddress,
    std::int32_t copyCompleteCallbackContext
  );
  std::int32_t SFD_GetVideoCh(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_GetAudioCh(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFMPS_ExecServer(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_ExecServerSub(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_DecodeSomeUnit(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_DecodeOneUnit(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t readAddress,
    std::int32_t readBytes,
    std::int32_t* outConsumedBytes,
    std::int32_t* outDecodedUnits,
    std::int32_t readEndAddress
  );
  std::int32_t sfmps_ProcPrep(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_CopyPketData(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    char* packetPayloadAddress,
    std::int32_t packetPayloadBytes,
    std::int32_t* outCopiedBytes,
    std::int32_t* outCopyStatus
  );
  std::int32_t sfmps_SkipNext(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    char* packetCursor,
    std::int32_t packetBytes,
    std::int32_t* outSkipBytes
  );
  std::int32_t sfmps_IsZero(const std::uint8_t* buffer, std::int32_t byteCount);
  std::int32_t sfmps_IsEndOfRingBuf(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t cursorAddress);
  std::uint32_t sfmps_CopyElemOutSj(
    std::int32_t sourceJoinAddress,
    void(__cdecl* onCopyComplete)(std::int32_t callbackContext, std::int32_t streamType),
    std::int32_t callbackContext,
    std::int32_t streamType,
    char* destination,
    std::int32_t byteCount
  );
  std::int32_t sfmps_CopyAudio(
    std::int32_t workctrlAddress,
    std::int32_t streamType,
    char* destination,
    std::int32_t byteCount,
    std::int32_t packetTimestampLow,
    std::int32_t packetTimestampHigh
  );
  std::int32_t sfmps_CopyVideo(
    std::int32_t workctrlAddress,
    std::int32_t streamType,
    char* destination,
    std::int32_t byteCount,
    std::int32_t packetTimestampLow,
    std::int32_t packetTimestampHigh
  );
  std::int32_t sfmps_CopyPadding(
    std::int32_t workctrlAddress,
    std::int32_t streamType,
    char* destination,
    std::int32_t byteCount,
    std::int32_t packetTimestampLow,
    std::int32_t packetTimestampHigh
  );
  std::int32_t sfmps_CopyDstBuft(
    std::int32_t workctrlAddress,
    std::int32_t destinationLaneIndex,
    char* sourceBytes,
    std::int32_t sourceByteCount,
    std::int32_t packetTimestampLow,
    std::int32_t packetTimestampHigh
  );
  std::int32_t sfmps_AutoVchPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t currentVideoChannel);
  std::int32_t sfmps_CopyPrvate(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t streamType,
    std::int32_t packetAddress,
    std::int32_t packetBytes
  );
  std::int32_t sfmps_CopyUsrSj(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t uochSlotIndex,
    char* destination,
    std::int32_t byteCount
  );
  std::uint32_t sfmps_CopySj(std::int32_t sourceJoinAddress, char* destination, std::int32_t byteCount);
  std::uint32_t sfmps_ExecCopySj(std::int32_t sourceJoinAddress, const void* source, std::int32_t byteCount);
  std::int32_t sfmps_UpdateFlowCnt(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t consumedBytesDelta,
    std::int32_t decodedUnitsDelta
  );
  std::int32_t sfmps_SetOption(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_RingGetRead(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outReadAddress,
    std::int32_t* outReadBytes,
    std::int32_t unusedArg,
    std::int32_t* outReadEndAddress
  );
  std::int32_t sfmps_RingAddRead(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t addBytes);

  std::int32_t* sfmps_GetStmNum(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outVideoStreamIndex,
    std::int32_t* outAudioStreamIndex
  );
  SfmpsSupplyLaneRuntimeView* sfmps_GetSupSj(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_GetTermDst(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_SetTermDst(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t ignoredTermFlag);
  std::int32_t sfmps_ChkPrepFlg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_GetPrepDst(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_SetPrepDst(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t prepFlag);
  std::int32_t sfmps_IsPrepEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t ignoredLaneIndex);
  std::int32_t sfmps_SetMvInf(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_AdjustAvPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_SetMpsHd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_SetAudioStreamType(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::uint32_t sfmps_SetMpsRaw(
    std::int32_t workctrlAddress,
    std::int32_t parserHandleAddress,
    const void* packetAddress,
    std::int32_t packetBytes
  );
  std::int32_t SFMPS_Destroy(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFMPS_Seek(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFMPS_GetConcatCnt(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

  std::int32_t SFBUF_GetWTot(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex);
  std::int32_t SFBUF_SetPrepFlg(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t prepFlag
  );
  std::int32_t SFBUF_GetPrepFlg(const std::int32_t sfbufHandleAddress, const std::int32_t laneIndex);
  std::int32_t SFBUF_SetTermFlg(const std::int32_t sfbufHandleAddress, const std::int32_t laneIndex, const std::int32_t termFlag);
  std::int32_t MPS_Create();
  void MPS_Finish();
  std::int32_t MPS_SetErrFn(
    std::int32_t mpsHandleAddress,
    std::int32_t(__cdecl* errorCallback)(std::int32_t errorObjectAddress, std::int32_t errorCode),
    std::int32_t errorObjectAddress
  );
  std::int32_t MPS_Destroy(std::int32_t mpsHandleAddress);
  std::int32_t MPS_DecHd(
    std::int32_t mpsHandleAddress,
    void* decodeRuntimeAddress,
    std::int32_t expectedLength,
    std::int32_t* ioParserRuntimeAddress,
    std::int32_t* ioHeaderRuntimeAddress
  );
  std::int32_t MPS_CheckDelim(const void* packetPrefix);
  std::int32_t MPS_GetPackHd(const void* mpsHandle, void* outPackHeader);
  std::int32_t MPS_GetSysHd(const void* mpsHandle, void* outSystemHeader, const std::int32_t headerSlot);
  std::int32_t MPS_SetPsMapFn(
    const std::int32_t mpsHandleAddress,
    const std::int32_t psMapCondition,
    const std::int32_t psMapAuxCondition
  );
  std::int32_t MPS_SetPesFn(
    const std::int32_t mpsHandleAddress,
    const std::int32_t pesCondition,
    const std::int32_t pesAuxCondition
  );
  std::int32_t MPS_GetPketHd(std::int32_t mpsHandleAddress, void* outPacketHeader);
  std::int32_t MPS_GetLastSysHd(const std::int32_t mpsHandleAddress, void* outLastSystemHeaderProbe);
  std::int32_t MPS_GetElementaryInfo(
    const void* mpsHandle,
    std::int32_t* outElementaryCount,
    const MpsElementaryInfoEntryView** outElementaryEntries
  );
  std::int32_t SFADXT_SetAudioStreamType(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t elementaryStreamType);
  std::int32_t SFCON_IsEndcodeSkip(std::int32_t workctrlAddress);
  std::int32_t SFCON_IsSystemEndcodeSkip(std::int32_t workctrlAddress);
  std::int32_t sfmps_IsEffectiveEndcode(const std::int32_t workctrlAddress, const std::int32_t delimiterCode);
  std::int32_t sfmps_DestroySub(const std::int32_t parserHandleAddress);
  std::int32_t sfmps_GetHd(const std::int32_t workctrlAddress);
  void sfmps_SetCustomPketLen(const std::int32_t workctrlAddress);
  std::int32_t sfmps_ReprocessHdr(
    const std::int32_t workctrlAddress,
    const std::int32_t parserRuntimeAddress,
    const std::int32_t headerRuntimeAddress
  );
  std::int32_t SFHDS_ReprocessHdr(const std::int32_t workctrlAddress);
  std::int32_t SFHDS_SetHdr(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t streamType,
    std::int32_t packetAddress,
    std::int32_t packetBytes,
    std::int32_t* ioPacketBytes
  );
  std::int32_t MPS_SetPesSw(const std::int32_t mpsHandleAddress, const std::int32_t pesSwitchCondition);
  std::int32_t MPS_SetSystemFn(
    const std::int32_t mpsHandleAddress,
    const std::int32_t systemFnCondition,
    const std::int32_t systemFnAuxCondition
  );
  std::int32_t SFBUF_GetUoch(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t uochSlotIndex,
    std::int32_t* outChunkDescriptorWords
  );
  std::int32_t SFBUF_RingGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* outCursor
  );
  std::int32_t SFBUF_RingAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addBytes
  );
  std::int32_t SFBUF_RingGetWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* outCursor
  );
  std::int32_t SFBUF_RingAddWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t advanceCount
  );
  std::int32_t SFBUF_VfrmGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  );
  std::int32_t SFBUF_VfrmAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  );
  std::int32_t SFPTS_IsPtsQueFull(const std::int32_t workctrlAddress, const std::int32_t queueIndex);
  std::int32_t SFPTS_WritePtsQue(
    const std::int32_t workctrlAddress,
    const std::int32_t queueIndex,
    std::int32_t* ptsInfoWords,
    std::int32_t* outQueueTag
  );
  extern "C" std::int32_t(__cdecl * SFPLY_SetPtsInfo)(std::int32_t playbackLaneAddress, std::int32_t* ptsInfoWords);
  /**
   * Address: 0x00ACF3C0 (FUN_00ACF3C0, _sfm2ts_cbfn)
   *
   * What it does:
   * Routes SFM2TS lane updates into either the video PTS queue lane or the
   * SFPLY PTS-info callback lane, preserving the original full/empty checks
   * and copy behavior.
   */
  extern "C" BOOL sfm2ts_cbfn(
    const std::int32_t workctrlAddress,
    const std::int32_t destinationLaneIndex,
    std::int32_t* const ptsInfoWords,
    const std::int32_t packetHeaderAddress,
    const std::int32_t packetTimestampLow,
    const std::int32_t packetTimestampHigh
  );
  std::int32_t
  SFBUF_GetFlowCnt(const std::int32_t sjHandleAddress, std::int32_t* outLane1FlowCount, std::int32_t* outLane0FlowCount);
  std::int64_t SFBUF_UpdateFlowCnt(
    std::int32_t previousFlowLow,
    std::int32_t previousFlowHigh,
    std::int32_t nextFlowLow
  );

  /**
   * Address: 0x00AE5BC0 (FUN_00AE5BC0, _sfpts_WritePtsQueSub)
   *
   * What it does:
   * Appends one 4-word PTS entry into the circular queue, updates write/count
   * lanes, and reports whether the queue became full.
   */
  std::int32_t sfpts_WritePtsQueSub(
    SfptsQueueRuntimeView* const queue,
    const std::int32_t* const ptsInfoWords,
    std::int32_t* const outQueueTag
  )
  {
    if (queue->queuedCount == queue->capacity) {
      *outQueueTag = 1;
      return -1;
    }

    auto* const entries = reinterpret_cast<SfptsQueueEntryWords*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(queue->entriesAddress))
    );

    SfptsQueueEntryWords& destination = entries[queue->writeIndex];
    destination.word0 = ptsInfoWords[0];
    destination.word1 = ptsInfoWords[1];
    destination.word2 = ptsInfoWords[2];
    destination.word3 = ptsInfoWords[3];

    const std::int32_t nextIndex = queue->writeIndex + 1;
    queue->writeIndex = (nextIndex >= queue->capacity) ? (nextIndex - queue->capacity) : nextIndex;

    ++queue->queuedCount;
    *outQueueTag = queue->queuedCount >= queue->capacity ? 1 : 0;
    return 0;
  }

  /**
   * Address: 0x00AE5DD0 (FUN_00AE5DD0, _SFPTS_IsPtsQueFull)
   *
   * What it does:
   * Returns whether one indexed PTS queue lane is configured and currently full.
   */
  std::int32_t SFPTS_IsPtsQueFull(const std::int32_t workctrlAddress, const std::int32_t queueIndex)
  {
    const SfptsQueueRuntimeView* const queue = GetSfptsQueueLane(workctrlAddress, queueIndex);
    return (queue->entriesAddress != 0 && queue->queuedCount >= queue->capacity) ? 1 : 0;
  }

  /**
   * Address: 0x00AE5B50 (FUN_00AE5B50, _SFPTS_WritePtsQue)
   *
   * What it does:
   * Queues one PTS descriptor when queue/lane inputs are valid and reports
   * overflow through SFLIB error code `0xFF000421`.
   */
  std::int32_t SFPTS_WritePtsQue(
    const std::int32_t workctrlAddress,
    const std::int32_t queueIndex,
    std::int32_t* const ptsInfoWords,
    std::int32_t* const outQueueTag
  )
  {
    constexpr std::int32_t kSflibErrSfptsWritePtsQueFailed = static_cast<std::int32_t>(0xFF000421u);

    *outQueueTag = 0;

    SfptsQueueRuntimeView* const queue = GetSfptsQueueLane(workctrlAddress, queueIndex);
    if (ptsInfoWords[1] >= 0 && queue->entriesAddress != 0
        && sfpts_WritePtsQueSub(queue, ptsInfoWords, outQueueTag) == -1) {
      return SFLIB_SetErr(workctrlAddress, kSflibErrSfptsWritePtsQueFailed);
    }

    return 0;
  }

  /**
   * Address: 0x00ACF3C0 (FUN_00ACF3C0, _sfm2ts_cbfn)
   *
   * What it does:
   * Routes SFM2TS lane updates into either the video PTS queue lane or the
   * SFPLY PTS-info callback lane, preserving the original full/empty checks
   * and copy behavior.
   */
  extern "C" BOOL sfm2ts_cbfn(
    const std::int32_t workctrlAddress,
    const std::int32_t destinationLaneIndex,
    std::int32_t* const ptsInfoWords,
    const std::int32_t packetHeaderAddress,
    const std::int32_t packetTimestampLow,
    const std::int32_t packetTimestampHigh
  )
  {
    struct Sfm2tsCallbackRuntimeView
    {
      std::uint8_t reserved00[0x1398]{};
      std::int32_t videoPtsQueueLaneIndex = 0; // +0x1398
      std::uint8_t reserved139C[0x70]{};
      std::int32_t audioPtsInfoLaneIndex = 0; // +0x140C
    };
    static_assert(offsetof(Sfm2tsCallbackRuntimeView, videoPtsQueueLaneIndex) == 0x1398);
    static_assert(offsetof(Sfm2tsCallbackRuntimeView, audioPtsInfoLaneIndex) == 0x140C);

    struct Sfm2tsPacketHeaderRuntimeView
    {
      std::int32_t word0 = 0;
      std::int32_t word1 = 0;
    };

    const auto* const runtimeView =
      reinterpret_cast<const Sfm2tsCallbackRuntimeView*>(SjAddressToPointer(workctrlAddress));
    BOOL result = FALSE;
    constexpr std::int32_t kSfplyPtsInfoLaneOffset = 0x12E0;

    if (destinationLaneIndex == runtimeView->videoPtsQueueLaneIndex) {
      if ((packetTimestampHigh & packetTimestampLow) != -1) {
        if (ptsInfoWords != nullptr) {
          std::int32_t ptsQueueWords[4];
          ptsQueueWords[0] = packetTimestampLow;
          ptsQueueWords[1] = packetTimestampHigh;
          ptsQueueWords[2] = ptsInfoWords[0];
          ptsQueueWords[3] = ptsInfoWords[1];

          std::int32_t queueTag = 0;
          SFPTS_WritePtsQue(workctrlAddress, 1, ptsQueueWords, &queueTag);
          return queueTag;
        }

        return SFPTS_IsPtsQueFull(workctrlAddress, 1);
      }
    } else if (destinationLaneIndex == runtimeView->audioPtsInfoLaneIndex && SFPLY_SetPtsInfo != nullptr) {
      const auto* const packetHeader =
        reinterpret_cast<const Sfm2tsPacketHeaderRuntimeView*>(SjAddressToPointer(packetHeaderAddress));
      const std::int32_t sfplyPtsInfoAddress = static_cast<std::int32_t>(
        reinterpret_cast<std::uintptr_t>(runtimeView) + static_cast<std::uintptr_t>(kSfplyPtsInfoLaneOffset)
      );

      if (ptsInfoWords != nullptr) {
        std::int32_t ptsInfoLaneWords[3];
        ptsInfoLaneWords[0] = packetTimestampLow;
        ptsInfoLaneWords[1] = packetTimestampHigh;
        ptsInfoLaneWords[2] = packetHeader->word1 + ptsInfoWords[1];

        result = TRUE;
        if (SFPLY_SetPtsInfo(sfplyPtsInfoAddress, ptsInfoLaneWords) == -1) {
          return result;
        }
      } else if (SFPLY_SetPtsInfo(sfplyPtsInfoAddress, nullptr) == -1) {
        return TRUE;
      }

      return 0;
    }

    return result;
  }

  /**
   * Address: 0x00ADBEC0 (FUN_00ADBEC0, _SFTIM_SetSpeed)
   *
   * What it does:
   * Stores one per-handle timer speed rational lane.
   */
  std::int32_t SFTIM_SetSpeed(const std::int32_t workctrlAddress, const std::int32_t speedRational);
  std::int32_t SFAOAP_SetSpeed(const std::int32_t workctrlAddress, const std::int32_t speedRational);

  struct SfmpsSupplyLaneRuntimeView
  {
    std::int32_t reserved00 = 0; // +0x00
    std::int32_t supplyJoinAddress = 0; // +0x04
    std::int32_t reserved08 = 0; // +0x08
    std::int32_t supplyWindowBytes = 0; // +0x0C
    std::int32_t reserved10Word0 = 0; // +0x10
    std::int32_t reserved14Word1 = 0; // +0x14
    std::uint8_t reserved18[0x5C]{}; // +0x18
  };
  static_assert(
    offsetof(SfmpsSupplyLaneRuntimeView, supplyJoinAddress) == 0x04,
    "SfmpsSupplyLaneRuntimeView::supplyJoinAddress offset must be 0x04"
  );
  static_assert(
    offsetof(SfmpsSupplyLaneRuntimeView, supplyWindowBytes) == 0x0C,
    "SfmpsSupplyLaneRuntimeView::supplyWindowBytes offset must be 0x0C"
  );
  static_assert(
    offsetof(SfmpsSupplyLaneRuntimeView, reserved10Word0) == 0x10,
    "SfmpsSupplyLaneRuntimeView::reserved10Word0 offset must be 0x10"
  );
  static_assert(
    offsetof(SfmpsSupplyLaneRuntimeView, reserved14Word1) == 0x14,
    "SfmpsSupplyLaneRuntimeView::reserved14Word1 offset must be 0x14"
  );
  static_assert(sizeof(SfmpsSupplyLaneRuntimeView) == 0x74, "SfmpsSupplyLaneRuntimeView size must be 0x74");

  struct SfmpsStreamPrepRuntimeView
  {
    std::int32_t m2tsdRuntimeAddress = 0; // +0x00
    std::int32_t pendingCondition5Bytes = 0; // +0x04
    std::int32_t pendingCondition6Bytes = 0; // +0x08
  };
  static_assert(
    offsetof(SfmpsStreamPrepRuntimeView, m2tsdRuntimeAddress) == 0x00,
    "SfmpsStreamPrepRuntimeView::m2tsdRuntimeAddress offset must be 0x00"
  );
  static_assert(
    offsetof(SfmpsStreamPrepRuntimeView, pendingCondition5Bytes) == 0x04,
    "SfmpsStreamPrepRuntimeView::pendingCondition5Bytes offset must be 0x04"
  );
  static_assert(
    offsetof(SfmpsStreamPrepRuntimeView, pendingCondition6Bytes) == 0x08,
    "SfmpsStreamPrepRuntimeView::pendingCondition6Bytes offset must be 0x08"
  );
  static_assert(sizeof(SfmpsStreamPrepRuntimeView) == 0x0C, "SfmpsStreamPrepRuntimeView size must be 0x0C");

  struct SfmpsParserRuntimeView
  {
    std::int32_t parserHandleAddress = 0; // +0x00
    std::int32_t cachedSystemField3Max = 0; // +0x04
    std::int32_t cachedSystemField2Max = 0; // +0x08
    std::int32_t reserved0C = 0; // +0x0C
    std::int32_t parserField4Default = -1; // +0x10
    std::int32_t parserField5Ceiling = static_cast<std::int32_t>(0x7FFFFFFFu); // +0x14
    std::int32_t parserField6Low = -1; // +0x18
    std::int32_t parserField7High = static_cast<std::int32_t>(0x7FFFFFFFu); // +0x1C
    std::int32_t concatCount = 0; // +0x20
    std::int32_t parserField9Ceiling = static_cast<std::int32_t>(0x7FFFFFFFu); // +0x24
    std::int32_t parserField10Ceiling = static_cast<std::int32_t>(0x7FFFFFFFu); // +0x28
    std::int32_t reprocessField11 = -1; // +0x2C
    std::int32_t reprocessField12 = -1; // +0x30
    std::int32_t videoChannel = -1; // +0x34
    std::int32_t audioChannel = -1; // +0x38
    std::int32_t effectiveEndcodeMode = 0; // +0x3C
    std::array<std::int32_t, 68> elementOutSjByElementType{}; // +0x40 (element types 188..255)
    std::int32_t copyElemOutCallbackAddress = 0; // +0x150
    std::int32_t copyElemOutCallbackContext = 0; // +0x154
    std::int32_t selectedElementaryLane = -1; // +0x158
  };
  static_assert(
    offsetof(SfmpsParserRuntimeView, parserHandleAddress) == 0x00,
    "SfmpsParserRuntimeView::parserHandleAddress offset must be 0x00"
  );
  static_assert(
    offsetof(SfmpsParserRuntimeView, cachedSystemField3Max) == 0x04,
    "SfmpsParserRuntimeView::cachedSystemField3Max offset must be 0x04"
  );
  static_assert(
    offsetof(SfmpsParserRuntimeView, cachedSystemField2Max) == 0x08,
    "SfmpsParserRuntimeView::cachedSystemField2Max offset must be 0x08"
  );
  static_assert(offsetof(SfmpsParserRuntimeView, concatCount) == 0x20, "SfmpsParserRuntimeView::concatCount offset must be 0x20");
  static_assert(
    offsetof(SfmpsParserRuntimeView, effectiveEndcodeMode) == 0x3C,
    "SfmpsParserRuntimeView::effectiveEndcodeMode offset must be 0x3C"
  );
  static_assert(
    offsetof(SfmpsParserRuntimeView, elementOutSjByElementType) == 0x40,
    "SfmpsParserRuntimeView::elementOutSjByElementType offset must be 0x40"
  );
  static_assert(
    offsetof(SfmpsParserRuntimeView, copyElemOutCallbackAddress) == 0x150,
    "SfmpsParserRuntimeView::copyElemOutCallbackAddress offset must be 0x150"
  );
  static_assert(
    offsetof(SfmpsParserRuntimeView, copyElemOutCallbackContext) == 0x154,
    "SfmpsParserRuntimeView::copyElemOutCallbackContext offset must be 0x154"
  );
  static_assert(
    offsetof(SfmpsParserRuntimeView, selectedElementaryLane) == 0x158,
    "SfmpsParserRuntimeView::selectedElementaryLane offset must be 0x158"
  );
  static_assert(sizeof(SfmpsParserRuntimeView) == 0x15C, "SfmpsParserRuntimeView size must be 0x15C");

  struct SfmpsM2tsdRuntimeView
  {
    std::uint8_t reserved00[0xB4]{};
    std::int32_t playbackStateAddress = 0; // +0xB4
  };
  static_assert(
    offsetof(SfmpsM2tsdRuntimeView, playbackStateAddress) == 0xB4,
    "SfmpsM2tsdRuntimeView::playbackStateAddress offset must be 0xB4"
  );

  struct SfmpsM2tsdPlaybackStateView
  {
    std::uint8_t reserved00[0x18]{};
    std::int32_t condition5BlockFlag = 0; // +0x18
    std::uint8_t reserved1C[0x24]{};
    std::int32_t condition6BlockFlag = 0; // +0x40
  };
  static_assert(
    offsetof(SfmpsM2tsdPlaybackStateView, condition5BlockFlag) == 0x18,
    "SfmpsM2tsdPlaybackStateView::condition5BlockFlag offset must be 0x18"
  );
  static_assert(
    offsetof(SfmpsM2tsdPlaybackStateView, condition6BlockFlag) == 0x40,
    "SfmpsM2tsdPlaybackStateView::condition6BlockFlag offset must be 0x40"
  );

  struct MpsPackHeaderRuntimeView
  {
    std::int32_t reserved00 = 0; // +0x00
    std::int32_t reserved04 = 0; // +0x04
    std::int32_t reserved08 = 0; // +0x08
    std::int32_t muxRateUnits50BytesPerSecond = -1; // +0x0C
  };
  static_assert(
    offsetof(MpsPackHeaderRuntimeView, muxRateUnits50BytesPerSecond) == 0x0C,
    "MpsPackHeaderRuntimeView::muxRateUnits50BytesPerSecond offset must be 0x0C"
  );
  static_assert(sizeof(MpsPackHeaderRuntimeView) == 0x10, "MpsPackHeaderRuntimeView size must be 0x10");

  /**
   * Address: 0x00ADA250 (FUN_00ADA250, _sfcre_AnalyMuxRate)
   *
   * What it does:
   * Runs one temporary MPS header decode and extracts mux-rate units from the
   * pack header when the decoded flag lane reports a valid pack-header marker.
   */
  extern "C" std::int32_t sfcre_AnalyMuxRate(
    const std::int32_t decodeBufferAddress,
    const std::int32_t decodeSizeBytes,
    std::int32_t* const outMuxRateUnits50BytesPerSecond
  )
  {
    const std::int32_t mpsHandleAddress = MPS_Create();
    if (mpsHandleAddress == 0) {
      return 0;
    }

    std::int32_t parserRuntimeAddress = 0;
    std::int32_t decodeFlags = 0;
    (void)MPS_DecHd(
      mpsHandleAddress,
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(decodeBufferAddress)),
      decodeSizeBytes,
      &parserRuntimeAddress,
      &decodeFlags
    );

    std::int32_t result = decodeFlags;
    if ((decodeFlags & 0x10000) != 0) {
      MpsPackHeaderRuntimeView packHeader{};
      (void)MPS_GetPackHd(reinterpret_cast<void*>(static_cast<std::uintptr_t>(mpsHandleAddress)), &packHeader);
      (void)MPS_Destroy(mpsHandleAddress);
      result = packHeader.muxRateUnits50BytesPerSecond;
      *outMuxRateUnits50BytesPerSecond = packHeader.muxRateUnits50BytesPerSecond;
    }

    return result;
  }

  struct MpsSystemHeaderRuntimeView
  {
    std::int32_t reserved00 = 0; // +0x00
    std::int32_t reserved04 = 0; // +0x04
    std::int32_t maxSystemField2 = 0; // +0x08
    std::int32_t maxSystemField3 = 0; // +0x0C
    std::int32_t rateBound = -1; // +0x10
    std::int32_t reserved14 = 0; // +0x14
    std::int32_t reserved18 = 0; // +0x18
    std::int32_t reserved1C = 0; // +0x1C
  };
  static_assert(
    offsetof(MpsSystemHeaderRuntimeView, maxSystemField2) == 0x08,
    "MpsSystemHeaderRuntimeView::maxSystemField2 offset must be 0x08"
  );
  static_assert(
    offsetof(MpsSystemHeaderRuntimeView, maxSystemField3) == 0x0C,
    "MpsSystemHeaderRuntimeView::maxSystemField3 offset must be 0x0C"
  );
  static_assert(offsetof(MpsSystemHeaderRuntimeView, rateBound) == 0x10, "MpsSystemHeaderRuntimeView::rateBound offset must be 0x10");
  static_assert(sizeof(MpsSystemHeaderRuntimeView) == 0x20, "MpsSystemHeaderRuntimeView size must be 0x20");

  struct MpsElementaryInfoEntryView
  {
    std::uint8_t streamType = 0; // +0x00
    std::uint8_t streamId = 0; // +0x01
  };
  static_assert(sizeof(MpsElementaryInfoEntryView) == 0x2, "MpsElementaryInfoEntryView size must be 0x2");

  struct SfmpsHeaderRuntimeView
  {
    std::int32_t activeFlag = 0; // +0x00
    std::int32_t muxRateBytesPerSecond = 0; // +0x04
    std::int32_t systemHeaderMetric = 0; // +0x08
    std::int32_t parserCachedField3Max = 0; // +0x0C
    std::int32_t parserCachedField2Max = 0; // +0x10
    std::int32_t reserved14 = 0; // +0x14
    std::int32_t seekField0 = 0; // +0x18
    std::int32_t seekField1 = 0; // +0x1C
    std::int32_t parserField6Low = 0; // +0x20
    std::int32_t parserField7High = 0; // +0x24
    std::int32_t parserField11 = 0; // +0x28
    std::int32_t parserField12 = 0; // +0x2C
  };
  static_assert(sizeof(SfmpsHeaderRuntimeView) == 0x30, "SfmpsHeaderRuntimeView size must be 0x30");

  struct SfmpsWorkctrlRuntimeView
  {
    std::int32_t reserved0000 = 0; // +0x00
    std::int32_t reserved0004 = 0; // +0x04
    std::int32_t prepEndOverrideBytes = 0; // +0x08
    std::uint8_t reserved000C[0x918]{};
    std::int32_t detectedMuxRateUnits50BytesPerSecond = -1; // +0x0924
    std::int32_t detectedSystemHeaderMetric = -1; // +0x0928
    std::int32_t reserved092C = 0; // +0x092C
    std::int32_t defaultSystemField2Max = -1; // +0x0930
    std::int32_t defaultSystemField3Max = -1; // +0x0934
    std::uint8_t reserved0938[0x12C]{};
    std::int32_t prepEndDefaultBytes = 0; // +0x0A64
    std::uint8_t reserved0A68[0x418]{};
    std::int32_t seekField0 = 0; // +0x0E80
    std::int32_t seekField1 = 0; // +0x0E84
    std::int32_t headerDeltaField0 = 0; // +0x0E88
    std::int32_t headerDeltaField1 = 0; // +0x0E8C
    std::uint8_t reserved0E90[0x490]{};
    std::array<SfmpsSupplyLaneRuntimeView, 8> supplyLanes; // +0x1320
    std::uint8_t reserved16C0_1F43[0x884]{};
    std::int32_t memoryPrepLaneIndex = 0; // +0x1F44
    std::uint8_t reserved1F48_1F7B[0x34]{};
    SfmpsStreamPrepRuntimeView* streamPrepRuntime = nullptr; // +0x1F7C
    std::int32_t reserved1F80 = 0; // +0x1F80
    std::int32_t activeSupplyLaneIndex = 0; // +0x1F84
    std::int32_t termDestinationLaneA = 0; // +0x1F88
    std::int32_t termDestinationLaneB = 0; // +0x1F8C
    std::int32_t termDestinationLaneC = 0; // +0x1F90
    std::int32_t effectiveEndcodeBoundaryBytes = -1; // +0x1F94
  };
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, prepEndOverrideBytes) == 0x08,
    "SfmpsWorkctrlRuntimeView::prepEndOverrideBytes offset must be 0x08"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, detectedMuxRateUnits50BytesPerSecond) == 0x0924,
    "SfmpsWorkctrlRuntimeView::detectedMuxRateUnits50BytesPerSecond offset must be 0x0924"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, detectedSystemHeaderMetric) == 0x0928,
    "SfmpsWorkctrlRuntimeView::detectedSystemHeaderMetric offset must be 0x0928"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, defaultSystemField2Max) == 0x0930,
    "SfmpsWorkctrlRuntimeView::defaultSystemField2Max offset must be 0x0930"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, defaultSystemField3Max) == 0x0934,
    "SfmpsWorkctrlRuntimeView::defaultSystemField3Max offset must be 0x0934"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, prepEndDefaultBytes) == 0x0A64,
    "SfmpsWorkctrlRuntimeView::prepEndDefaultBytes offset must be 0x0A64"
  );
  static_assert(offsetof(SfmpsWorkctrlRuntimeView, seekField0) == 0x0E80, "SfmpsWorkctrlRuntimeView::seekField0 offset must be 0x0E80");
  static_assert(offsetof(SfmpsWorkctrlRuntimeView, seekField1) == 0x0E84, "SfmpsWorkctrlRuntimeView::seekField1 offset must be 0x0E84");
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, headerDeltaField0) == 0x0E88,
    "SfmpsWorkctrlRuntimeView::headerDeltaField0 offset must be 0x0E88"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, headerDeltaField1) == 0x0E8C,
    "SfmpsWorkctrlRuntimeView::headerDeltaField1 offset must be 0x0E8C"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, supplyLanes) == 0x1320,
    "SfmpsWorkctrlRuntimeView::supplyLanes offset must be 0x1320"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, memoryPrepLaneIndex) == 0x1F44,
    "SfmpsWorkctrlRuntimeView::memoryPrepLaneIndex offset must be 0x1F44"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, streamPrepRuntime) == 0x1F7C,
    "SfmpsWorkctrlRuntimeView::streamPrepRuntime offset must be 0x1F7C"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, activeSupplyLaneIndex) == 0x1F84,
    "SfmpsWorkctrlRuntimeView::activeSupplyLaneIndex offset must be 0x1F84"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, termDestinationLaneA) == 0x1F88,
    "SfmpsWorkctrlRuntimeView::termDestinationLaneA offset must be 0x1F88"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, termDestinationLaneB) == 0x1F8C,
    "SfmpsWorkctrlRuntimeView::termDestinationLaneB offset must be 0x1F8C"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, termDestinationLaneC) == 0x1F90,
    "SfmpsWorkctrlRuntimeView::termDestinationLaneC offset must be 0x1F90"
  );
  static_assert(
    offsetof(SfmpsWorkctrlRuntimeView, effectiveEndcodeBoundaryBytes) == 0x1F94,
    "SfmpsWorkctrlRuntimeView::effectiveEndcodeBoundaryBytes offset must be 0x1F94"
  );

  struct SfmpsExecRuntimeView
  {
    std::uint8_t reserved00[0x48]{};
    std::int32_t executionStage = 0; // +0x48
  };
  static_assert(
    offsetof(SfmpsExecRuntimeView, executionStage) == 0x48,
    "SfmpsExecRuntimeView::executionStage offset must be 0x48"
  );

  struct SfmpsDecodeWindowRuntimeView
  {
    std::uint8_t reserved00[0x28]{};
    std::int32_t decodeWindowBytes = 0; // +0x28
  };
  static_assert(
    offsetof(SfmpsDecodeWindowRuntimeView, decodeWindowBytes) == 0x28,
    "SfmpsDecodeWindowRuntimeView::decodeWindowBytes offset must be 0x28"
  );

  struct SfmpsFlowCountRuntimeView
  {
    std::uint8_t reserved00[0x988]{};
    std::int32_t sourceFlowLow = 0; // +0x988
    std::int32_t sourceFlowHigh = 0; // +0x98C
    std::int32_t consumedBytesLow = 0; // +0x990
    std::int32_t consumedBytesHigh = 0; // +0x994
    std::int32_t decodedUnitsLow = 0; // +0x998
    std::int32_t decodedUnitsHigh = 0; // +0x99C
  };
  static_assert(
    offsetof(SfmpsFlowCountRuntimeView, sourceFlowLow) == 0x988,
    "SfmpsFlowCountRuntimeView::sourceFlowLow offset must be 0x988"
  );
  static_assert(
    offsetof(SfmpsFlowCountRuntimeView, decodedUnitsHigh) == 0x99C,
    "SfmpsFlowCountRuntimeView::decodedUnitsHigh offset must be 0x99C"
  );

  struct MpsPacketHeaderRuntimeView
  {
    std::int32_t packetTimestampLow = 0; // +0x00
    std::int32_t packetTimestampHigh = 0; // +0x04
    std::int32_t reserved08 = 0; // +0x08
    std::int32_t reserved0C = 0; // +0x0C
    std::int32_t streamType = 0; // +0x10
    std::int32_t copyDispatchIndex = 0; // +0x14
    std::int32_t packetStreamType = 0; // +0x18
    std::int32_t reserved1C = 0; // +0x1C
    std::int32_t reserved20 = 0; // +0x20
    std::int32_t payloadBytes = 0; // +0x24
  };
  static_assert(
    offsetof(MpsPacketHeaderRuntimeView, streamType) == 0x10,
    "MpsPacketHeaderRuntimeView::streamType offset must be 0x10"
  );
  static_assert(
    offsetof(MpsPacketHeaderRuntimeView, copyDispatchIndex) == 0x14,
    "MpsPacketHeaderRuntimeView::copyDispatchIndex offset must be 0x14"
  );
  static_assert(
    offsetof(MpsPacketHeaderRuntimeView, packetStreamType) == 0x18,
    "MpsPacketHeaderRuntimeView::packetStreamType offset must be 0x18"
  );
  static_assert(
    offsetof(MpsPacketHeaderRuntimeView, payloadBytes) == 0x24,
    "MpsPacketHeaderRuntimeView::payloadBytes offset must be 0x24"
  );
  static_assert(sizeof(MpsPacketHeaderRuntimeView) == 0x28, "MpsPacketHeaderRuntimeView size must be 0x28");

  struct SfbufRingWriteDescriptorView
  {
    void* firstWriteAddress = nullptr; // +0x00
    std::int32_t firstWriteBytes = 0; // +0x04
    void* secondWriteAddress = nullptr; // +0x08
    std::int32_t secondWriteBytes = 0; // +0x0C
    std::int32_t writeCursor = 0; // +0x10
  };
  static_assert(
    offsetof(SfbufRingWriteDescriptorView, firstWriteAddress) == 0x00,
    "SfbufRingWriteDescriptorView::firstWriteAddress offset must be 0x00"
  );
  static_assert(
    offsetof(SfbufRingWriteDescriptorView, secondWriteAddress) == 0x08,
    "SfbufRingWriteDescriptorView::secondWriteAddress offset must be 0x08"
  );
  static_assert(
    offsetof(SfbufRingWriteDescriptorView, writeCursor) == 0x10,
    "SfbufRingWriteDescriptorView::writeCursor offset must be 0x10"
  );
  static_assert(sizeof(SfbufRingWriteDescriptorView) == 0x14, "SfbufRingWriteDescriptorView size must be 0x14");

  struct MpsLastSystemHeaderProbeRuntimeView
  {
    std::uint8_t reserved00[0x08]{};
    std::int32_t hasSecondarySystemHeader = 0; // +0x08
    std::int32_t hasPrimarySystemHeader = 0; // +0x0C
  };
  static_assert(
    offsetof(MpsLastSystemHeaderProbeRuntimeView, hasSecondarySystemHeader) == 0x08,
    "MpsLastSystemHeaderProbeRuntimeView::hasSecondarySystemHeader offset must be 0x08"
  );
  static_assert(
    offsetof(MpsLastSystemHeaderProbeRuntimeView, hasPrimarySystemHeader) == 0x0C,
    "MpsLastSystemHeaderProbeRuntimeView::hasPrimarySystemHeader offset must be 0x0C"
  );
  static_assert(
    sizeof(MpsLastSystemHeaderProbeRuntimeView) == 0x10,
    "MpsLastSystemHeaderProbeRuntimeView size must be 0x10"
  );

  struct SfmpsHeaderRawCaptureRuntimeView
  {
    std::int32_t activeFlag = 0; // +0x00
    std::uint8_t reserved04[0x2C]{}; // +0x04
    std::array<std::uint8_t, 0xB0> primaryMpsRaw{}; // +0x30
    std::array<std::uint8_t, 0xB0> secondaryMpsRaw{}; // +0xE0
    std::int32_t primaryMpsRawBytes = 0; // +0x190
    std::int32_t secondaryMpsRawBytes = 0; // +0x194
  };
  static_assert(
    offsetof(SfmpsHeaderRawCaptureRuntimeView, primaryMpsRaw) == 0x30,
    "SfmpsHeaderRawCaptureRuntimeView::primaryMpsRaw offset must be 0x30"
  );
  static_assert(
    offsetof(SfmpsHeaderRawCaptureRuntimeView, secondaryMpsRaw) == 0xE0,
    "SfmpsHeaderRawCaptureRuntimeView::secondaryMpsRaw offset must be 0xE0"
  );
  static_assert(
    offsetof(SfmpsHeaderRawCaptureRuntimeView, primaryMpsRawBytes) == 0x190,
    "SfmpsHeaderRawCaptureRuntimeView::primaryMpsRawBytes offset must be 0x190"
  );
  static_assert(
    offsetof(SfmpsHeaderRawCaptureRuntimeView, secondaryMpsRawBytes) == 0x194,
    "SfmpsHeaderRawCaptureRuntimeView::secondaryMpsRawBytes offset must be 0x194"
  );
  static_assert(
    sizeof(SfmpsHeaderRawCaptureRuntimeView) == 0x198,
    "SfmpsHeaderRawCaptureRuntimeView size must be 0x198"
  );

  using SfmpsUserOutputCallback = void(__cdecl*)(std::int32_t callbackContext, std::int32_t streamType);

  struct SfbufUserOutputChannelRuntimeView
  {
    std::int32_t sourceJoinAddress = 0; // +0x00
    SfmpsUserOutputCallback onPrimaryCopy = nullptr; // +0x04
    SfmpsUserOutputCallback onSecondaryCopy = nullptr; // +0x08
    std::int32_t secondaryCallbackContext = 0; // +0x0C
  };
  static_assert(
    offsetof(SfbufUserOutputChannelRuntimeView, sourceJoinAddress) == 0x00,
    "SfbufUserOutputChannelRuntimeView::sourceJoinAddress offset must be 0x00"
  );
  static_assert(
    offsetof(SfbufUserOutputChannelRuntimeView, onPrimaryCopy) == 0x04,
    "SfbufUserOutputChannelRuntimeView::onPrimaryCopy offset must be 0x04"
  );
  static_assert(
    offsetof(SfbufUserOutputChannelRuntimeView, secondaryCallbackContext) == 0x0C,
    "SfbufUserOutputChannelRuntimeView::secondaryCallbackContext offset must be 0x0C"
  );
  static_assert(
    sizeof(SfbufUserOutputChannelRuntimeView) == 0x10,
    "SfbufUserOutputChannelRuntimeView size must be 0x10"
  );

  struct SfmpsCopySourceWindowRuntimeView
  {
    void* destination = nullptr; // +0x00
    std::uint32_t copiedBytes = 0; // +0x04
  };
  static_assert(
    offsetof(SfmpsCopySourceWindowRuntimeView, destination) == 0x00,
    "SfmpsCopySourceWindowRuntimeView::destination offset must be 0x00"
  );
  static_assert(
    offsetof(SfmpsCopySourceWindowRuntimeView, copiedBytes) == 0x04,
    "SfmpsCopySourceWindowRuntimeView::copiedBytes offset must be 0x04"
  );
  static_assert(
    sizeof(SfmpsCopySourceWindowRuntimeView) == 0x08,
    "SfmpsCopySourceWindowRuntimeView size must be 0x08"
  );

  using SfmpsCopySourceGetWritableBytesProc = std::int32_t(__cdecl*)(std::int32_t sourceJoinAddress, std::int32_t mode);
  using SfmpsCopySourceAcquireWriteProc = void(__cdecl*)(
    std::int32_t sourceJoinAddress,
    std::int32_t mode,
    std::int32_t requestedBytes,
    SfmpsCopySourceWindowRuntimeView* outWindow
  );
  using SfmpsCopySourceCommitWriteProc = void(__cdecl*)(
    std::int32_t sourceJoinAddress,
    std::int32_t mode,
    SfmpsCopySourceWindowRuntimeView* ioWindow
  );

  struct SfmpsCopySourceVtableRuntimeView
  {
    void(__cdecl* reserved00)() = nullptr; // +0x00
    void(__cdecl* reserved04)() = nullptr; // +0x04
    void(__cdecl* reserved08)() = nullptr; // +0x08
    void(__cdecl* reserved0C)() = nullptr; // +0x0C
    void(__cdecl* reserved10)() = nullptr; // +0x10
    void(__cdecl* reserved14)() = nullptr; // +0x14
    SfmpsCopySourceAcquireWriteProc acquireWriteWindow = nullptr; // +0x18
    void(__cdecl* reserved1C)() = nullptr; // +0x1C
    SfmpsCopySourceCommitWriteProc commitWriteWindow = nullptr; // +0x20
    SfmpsCopySourceGetWritableBytesProc queryWritableBytes = nullptr; // +0x24
  };
  static_assert(
    offsetof(SfmpsCopySourceVtableRuntimeView, acquireWriteWindow) == 0x18,
    "SfmpsCopySourceVtableRuntimeView::acquireWriteWindow offset must be 0x18"
  );
  static_assert(
    offsetof(SfmpsCopySourceVtableRuntimeView, commitWriteWindow) == 0x20,
    "SfmpsCopySourceVtableRuntimeView::commitWriteWindow offset must be 0x20"
  );
  static_assert(
    offsetof(SfmpsCopySourceVtableRuntimeView, queryWritableBytes) == 0x24,
    "SfmpsCopySourceVtableRuntimeView::queryWritableBytes offset must be 0x24"
  );

  struct SfmpsCopySourceRuntimeView
  {
    SfmpsCopySourceVtableRuntimeView* vtable = nullptr; // +0x00
  };
  static_assert(
    offsetof(SfmpsCopySourceRuntimeView, vtable) == 0x00,
    "SfmpsCopySourceRuntimeView::vtable offset must be 0x00"
  );

  struct SfmpsWorkctrlCreateRuntimeView
  {
    std::uint8_t reserved0000[0x1F7C]{};
    SfmpsStreamPrepRuntimeView* streamPrepRuntime = nullptr; // +0x1F7C
    std::uint8_t reserved1F80[0x218]{};
    SfmpsParserRuntimeView parserRuntime{}; // +0x2198
  };
  static_assert(
    offsetof(SfmpsWorkctrlCreateRuntimeView, streamPrepRuntime) == 0x1F7C,
    "SfmpsWorkctrlCreateRuntimeView::streamPrepRuntime offset must be 0x1F7C"
  );
  static_assert(
    offsetof(SfmpsWorkctrlCreateRuntimeView, parserRuntime) == 0x2198,
    "SfmpsWorkctrlCreateRuntimeView::parserRuntime offset must be 0x2198"
  );

  struct SfmpsWorkctrlHeaderBankView
  {
    std::uint8_t reserved0000[0x3550]{};
    std::int32_t headerBankAddress = 0; // +0x3550
  };
  static_assert(
    offsetof(SfmpsWorkctrlHeaderBankView, headerBankAddress) == 0x3550,
    "SfmpsWorkctrlHeaderBankView::headerBankAddress offset must be 0x3550"
  );

  struct SfmpsHeaderDecodeControlView
  {
    std::uint8_t reserved00[0x160]{};
    std::int32_t firstExpectedLength = 0; // +0x160
    std::int32_t secondExpectedLength = 0; // +0x164
  };
  static_assert(
    offsetof(SfmpsHeaderDecodeControlView, firstExpectedLength) == 0x160,
    "SfmpsHeaderDecodeControlView::firstExpectedLength offset must be 0x160"
  );
  static_assert(
    offsetof(SfmpsHeaderDecodeControlView, secondExpectedLength) == 0x164,
    "SfmpsHeaderDecodeControlView::secondExpectedLength offset must be 0x164"
  );

  struct SfbufRingReadDescriptorView
  {
    std::int32_t readAddress = 0; // +0x00
    std::int32_t readBytes = 0; // +0x04
    std::int32_t reserved08 = 0; // +0x08
    std::int32_t trailingBytes = 0; // +0x0C
  };
  static_assert(sizeof(SfbufRingReadDescriptorView) == 0x10, "SfbufRingReadDescriptorView size must be 0x10");

  struct SjBufferedSourceDispatch
  {
    std::uint8_t reserved00[0x24]{};
    std::int32_t (__cdecl* QueryBufferedBytes)(std::int32_t sourceAddress, std::int32_t mode) = nullptr; // +0x24
  };
  static_assert(
    offsetof(SjBufferedSourceDispatch, QueryBufferedBytes) == 0x24,
    "SjBufferedSourceDispatch::QueryBufferedBytes offset must be 0x24"
  );

  struct SjBufferedSourceView
  {
    SjBufferedSourceDispatch* dispatch = nullptr; // +0x00
  };
  static_assert(sizeof(SjBufferedSourceView) == 0x4, "SjBufferedSourceView size must be 0x4");

  /**
   * Address: 0x00ACF630 (FUN_00ACF630, _getSupSj)
   *
   * What it does:
   * Returns the active SFMPS supply-lane descriptor selected by work-control
   * lane index `+0x1F84`.
   */
  SfmpsSupplyLaneRuntimeView* getSupSj(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    return &runtimeView->supplyLanes[runtimeView->activeSupplyLaneIndex];
  }

  /**
   * Address: 0x00ACF560 (FUN_00ACF560, _getPrepDst)
   *
   * What it does:
   * Reads and OR-combines preparation flags from the three destination ring
   * lanes tracked by the SFMPS work-control runtime view. This is the SJ-layer
   * primary copy; `sfmps_GetPrepDst` below is an independent binary duplicate
   * emitted from the sibling translation unit.
   */
  std::int32_t sj_GetPrepDst(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t laneBPrep = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneB);
    const std::int32_t laneAPrep = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneA);
    const std::int32_t laneCPrep = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneC);
    return laneBPrep | laneAPrep | laneCPrep;
  }

  /**
   * Address: 0x00ACF5A0 (FUN_00ACF5A0, _setPrepDst)
   *
   * What it does:
   * Writes one preparation flag value to the three SFMPS destination ring
   * lanes (B, A, then C). SJ-layer primary copy mirrored by `sfmps_SetPrepDst`.
   */
  std::int32_t sj_SetPrepDst(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t prepFlag
  )
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    (void)SFBUF_SetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneB, prepFlag);
    (void)SFBUF_SetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneA, prepFlag);
    return SFBUF_SetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneC, prepFlag);
  }

  /**
   * Address: 0x00ACF5E0 (FUN_00ACF5E0, _isPrepEnd)
   *
   * What it does:
   * Computes one prep-end threshold from work-control defaults and the active
   * supply-lane window bytes, then reports whether ring 0 write-total has
   * reached that threshold. SJ-layer primary copy of `sfmps_IsPrepEnd`.
   */
  std::int32_t sj_IsPrepEnd(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    std::int32_t candidateThreshold = runtimeView->prepEndOverrideBytes;
    std::int32_t thresholdBytes = runtimeView->prepEndDefaultBytes;
    if (candidateThreshold <= 0) {
      candidateThreshold = getSupSj(workctrlSubobj)->supplyWindowBytes;
    }

    if (candidateThreshold > 0 && candidateThreshold < thresholdBytes) {
      thresholdBytes = candidateThreshold;
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    return (SFBUF_GetWTot(workctrlAddress, 0) >= thresholdBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00ACF510 (FUN_00ACF510, _chkPrepFlg)
   *
   * What it does:
   * Checks destination prep state, then latches destination prep flags when
   * the active supply lane has reached its prep-end threshold. SJ-layer
   * primary copy of `sfmps_ChkPrepFlg`.
   */
  std::int32_t sj_ChkPrepFlg(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    std::int32_t result = sj_GetPrepDst(workctrlSubobj);
    if (result != 1) {
      const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
      const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
      result = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->activeSupplyLaneIndex);
      if (result == 1) {
        result = sj_IsPrepEnd(workctrlSubobj);
        if (result != 0) {
          return sj_SetPrepDst(workctrlSubobj, 1);
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00AD5B50 (FUN_00AD5B50, _sfmps_GetSupSj)
   *
   * What it does:
   * Returns one active SFMPS supply lane selected by work-control lane index.
   */
  SfmpsSupplyLaneRuntimeView* sfmps_GetSupSj(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return getSupSj(workctrlSubobj);
  }

  /**
   * Address: 0x00AD6260 (FUN_00AD6260, _sfmps_GetTermDst)
   *
   * What it does:
   * Reads and AND-combines termination flags from the three SFMPS destination
   * lanes.
   */
  std::int32_t sfmps_GetTermDst(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return getTermDst(workctrlSubobj);
  }

  /**
   * Address: 0x00AD6390 (FUN_00AD6390, _sfmps_SetTermDst)
   *
   * What it does:
   * Forces termination on all three SFMPS destination lanes.
   */
  std::int32_t sfmps_SetTermDst(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t ignoredTermFlag
  )
  {
    (void)ignoredTermFlag;
    return setTermDst(workctrlSubobj, 1);
  }

  SfmpsParserRuntimeView* getSfmpsParserRuntime(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    return reinterpret_cast<SfmpsParserRuntimeView*>(runtimeView->streamPrepRuntime);
  }

  /**
   * Address: 0x00AD6AA0 (FUN_00AD6AA0, _sfmps_DestroySub)
   *
   * What it does:
   * Destroys one SFMPS parser handle.
   */
  std::int32_t sfmps_DestroySub(const std::int32_t parserHandleAddress)
  {
    return MPS_Destroy(parserHandleAddress);
  }

  /**
   * Address: 0x00AD6BE0 (FUN_00AD6BE0, _sfmps_SetCustomPketLen)
   *
   * What it does:
   * Placeholder hook for custom packet-length setup; current binary keeps it as
   * a no-op.
   */
  void sfmps_SetCustomPketLen(const std::int32_t workctrlAddress)
  {
    (void)workctrlAddress;
  }

  /**
   * Address: 0x00AD6C60 (FUN_00AD6C60, _sfmps_GetHd)
   *
   * What it does:
   * Resolves active SFMPS header runtime lane when header-bank storage exists
   * and concat mode is not active.
   */
  std::int32_t sfmps_GetHd(const std::int32_t workctrlAddress)
  {
    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    const auto* const headerBankView = reinterpret_cast<const SfmpsWorkctrlHeaderBankView*>(workctrlSubobj);
    if (headerBankView->headerBankAddress == 0) {
      return 0;
    }
    if (SFMPS_GetConcatCnt(workctrlSubobj) > 0) {
      return 0;
    }
    return headerBankView->headerBankAddress + 0x8A0;
  }

  /**
   * Address: 0x00AD6BF0 (FUN_00AD6BF0, _sfmps_ReprocessHdr)
   *
   * What it does:
   * Re-decodes two SFMPS header segments and reports SFLIB error on decode
   * failure.
   */
  std::int32_t sfmps_ReprocessHdr(
    const std::int32_t workctrlAddress,
    const std::int32_t parserRuntimeAddress,
    const std::int32_t headerRuntimeAddress
  )
  {
    constexpr std::int32_t kSflibErrSfmpsReprocessFailed = static_cast<std::int32_t>(0xFF000D0Du);

    auto* const parserRuntime =
      reinterpret_cast<SfmpsParserRuntimeView*>(SjAddressToPointer(parserRuntimeAddress));
    auto* const decodeRuntimeBase =
      reinterpret_cast<std::uint8_t*>(SjAddressToPointer(headerRuntimeAddress)) + 0x30;
    const auto* const decodeControl = reinterpret_cast<const SfmpsHeaderDecodeControlView*>(decodeRuntimeBase);

    const std::int32_t mpsHandleAddress = parserRuntime->parserHandleAddress;
    std::int32_t ioParserRuntimeAddress = parserRuntimeAddress;
    std::int32_t ioHeaderRuntimeAddress = headerRuntimeAddress;
    const std::int32_t firstDecodeResult = MPS_DecHd(
      mpsHandleAddress,
      decodeRuntimeBase,
      decodeControl->firstExpectedLength,
      &ioParserRuntimeAddress,
      &ioHeaderRuntimeAddress
    );
    const std::int32_t secondDecodeResult = MPS_DecHd(
      mpsHandleAddress,
      decodeRuntimeBase + 0xB0,
      decodeControl->secondExpectedLength,
      &ioParserRuntimeAddress,
      &ioHeaderRuntimeAddress
    );

    if (firstDecodeResult != 0 || secondDecodeResult != 0) {
      return SFLIB_SetErr(workctrlAddress, kSflibErrSfmpsReprocessFailed);
    }
    return secondDecodeResult;
  }

  /**
   * Address: 0x00AD6990 (FUN_00AD6990, _SFMPS_Create)
   *
   * What it does:
   * Creates and initializes SFMPS parser runtime, then binds parser error
   * callback to current work-control object.
   */
  std::int32_t SFMPS_Create(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrSfmpsCreateFailed = static_cast<std::int32_t>(0xFF000D08u);
    constexpr std::int32_t kSflibErrSfmpsSetErrFnFailed = static_cast<std::int32_t>(0xFF000D09u);

    auto* const createView = reinterpret_cast<SfmpsWorkctrlCreateRuntimeView*>(workctrlSubobj);
    createView->streamPrepRuntime = reinterpret_cast<SfmpsStreamPrepRuntimeView*>(&createView->parserRuntime);
    (void)sfmps_InitInf(&createView->parserRuntime);

    const std::int32_t parserHandleAddress = MPS_Create();
    if (parserHandleAddress == 0) {
      return SFLIB_SetErr(0, kSflibErrSfmpsCreateFailed);
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    if (MPS_SetErrFn(parserHandleAddress, sfmps_ErrFn, workctrlAddress) != 0) {
      (void)sfmps_DestroySub(parserHandleAddress);
      return SFLIB_SetErr(0, kSflibErrSfmpsSetErrFnFailed);
    }

    createView->parserRuntime.parserHandleAddress = parserHandleAddress;
    return 0;
  }

  /**
   * Address: 0x00AD54C0 (FUN_00AD54C0, _SFD_SetElementOutSj)
   *
   * What it does:
   * Validates one SFD handle and registers one element-output SJ lane mapping
   * for element types in range `[188, 255]`.
   */
  std::int32_t SFD_SetElementOutSj(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t elementType,
    const std::int32_t elementOutputJoinAddress,
    const std::int32_t copyCompleteCallbackAddress,
    const std::int32_t copyCompleteCallbackContext
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetElementOutSj = static_cast<std::int32_t>(0xFF000171u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetElementOutSj);
    }

    if (elementType >= 188 && elementType <= 255) {
      auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
      parserRuntime->copyElemOutCallbackAddress = copyCompleteCallbackAddress;
      parserRuntime->copyElemOutCallbackContext = copyCompleteCallbackContext;
      parserRuntime->elementOutSjByElementType[elementType - 188] = elementOutputJoinAddress;
    }
    return 0;
  }

  /**
   * Address: 0x00AD5520 (FUN_00AD5520, _SFD_GetVideoCh)
   *
   * What it does:
   * Returns SFMPS video-channel lane for one handle; returns `-1` when handle is
   * null.
   */
  std::int32_t SFD_GetVideoCh(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (workctrlSubobj == nullptr) {
      return -1;
    }
    return getSfmpsParserRuntime(workctrlSubobj)->videoChannel;
  }

  /**
   * Address: 0x00AD5540 (FUN_00AD5540, _SFD_GetAudioCh)
   *
   * What it does:
   * Returns SFMPS audio-channel lane for one handle; returns `-1` when handle
   * is null.
   */
  std::int32_t SFD_GetAudioCh(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (workctrlSubobj == nullptr) {
      return -1;
    }
    return getSfmpsParserRuntime(workctrlSubobj)->audioChannel;
  }

  /**
   * Address: 0x00AD55B0 (FUN_00AD55B0, _SFMPS_Finish)
   *
   * What it does:
   * Finalizes global MPS runtime state and returns success.
   */
  std::int32_t SFMPS_Finish()
  {
    MPS_Finish();
    return 0;
  }

  /**
   * Address: 0x00AD55C0 (FUN_00AD55C0, _SFMPS_ExecServer)
   *
   * What it does:
   * Thin thunk wrapper that dispatches to `sfmps_ExecServerSub`.
   */
  std::int32_t SFMPS_ExecServer(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return sfmps_ExecServerSub(workctrlSubobj);
  }

  /**
   * Address: 0x00AD55D0 (FUN_00AD55D0, _sfmps_ExecServerSub)
   *
   * What it does:
   * Runs one parser server step unless termination is latched, then executes
   * prep-path processing when execution stage 2 is active.
   */
  std::int32_t sfmps_ExecServerSub(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (sfmps_GetTermDst(workctrlSubobj) == 1) {
      return 0;
    }

    (void)sfmps_SetOption(workctrlSubobj);
    const std::int32_t decodeResult = sfmps_DecodeSomeUnit(workctrlSubobj);

    const auto* const execView = reinterpret_cast<const SfmpsExecRuntimeView*>(workctrlSubobj);
    if (execView->executionStage == 2) {
      (void)sfmps_ProcPrep(workctrlSubobj);
    }

    return decodeResult;
  }

  /**
   * Address: 0x00AD5660 (FUN_00AD5660, _sfmps_DecodeSomeUnit)
   *
   * What it does:
   * Repeatedly fetches ring read windows, decodes packet units, advances read
   * cursor by consumed bytes, and updates flow counters.
   */
  std::int32_t sfmps_DecodeSomeUnit(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const decodeWindowView = reinterpret_cast<const SfmpsDecodeWindowRuntimeView*>(workctrlSubobj);
    const std::int32_t decodeWindowBytes = decodeWindowView->decodeWindowBytes;

    std::int32_t totalConsumedBytes = 0;
    std::int32_t totalDecodedUnits = 0;
    std::int32_t result = 0;

    do {
      std::int32_t readAddress = 0;
      std::int32_t readBytes = 0;
      std::int32_t readEndAddress = 0;
      result = sfmps_RingGetRead(workctrlSubobj, &readAddress, &readBytes, decodeWindowBytes, &readEndAddress);
      if (result != 0) {
        break;
      }

      std::int32_t consumedBytes = 0;
      std::int32_t decodedUnits = 0;
      result = sfmps_DecodeOneUnit(
        workctrlSubobj,
        readAddress,
        readBytes,
        &consumedBytes,
        &decodedUnits,
        readEndAddress
      );
      if (result != 0) {
        break;
      }

      if (consumedBytes == 0) {
        break;
      }

      result = sfmps_RingAddRead(workctrlSubobj, consumedBytes);
      if (result != 0) {
        break;
      }

      totalConsumedBytes += consumedBytes;
      totalDecodedUnits += decodedUnits;
    } while (totalConsumedBytes != static_cast<std::int32_t>(0x7FFFFFFFu));

    (void)sfmps_UpdateFlowCnt(workctrlSubobj, totalConsumedBytes, totalDecodedUnits);
    return result;
  }

  /**
   * Address: 0x00AD5780 (FUN_00AD5780, _sfmps_DecodeOneUnit)
   *
   * What it does:
   * Validates one supply chunk, applies parser map/PES option lanes, decodes
   * one packet header, and routes either skip/concat or packet-copy handling.
   */
  std::int32_t sfmps_DecodeOneUnit(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t readAddress,
    const std::int32_t readBytes,
    std::int32_t* const outConsumedBytes,
    std::int32_t* const outDecodedUnits,
    const std::int32_t readEndAddress
  )
  {
    constexpr std::int32_t kSflibErrSfmpsDecodeHeaderFailed = static_cast<std::int32_t>(0xFF000D03u);
    constexpr std::int32_t kPacketFlagsHasRawMps = static_cast<std::int32_t>(0x00020000u);
    constexpr std::int32_t kPacketFlagsHasPayload = static_cast<std::int32_t>(0x00040000u);
    constexpr std::int32_t kPacketFlagsSystemEndcode = static_cast<std::int32_t>(0x00080000u);

    *outConsumedBytes = 0;
    *outDecodedUnits = 0;

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    const std::int32_t parserHandleAddress = parserRuntime->parserHandleAddress;
    const auto* const decodeWindowView = reinterpret_cast<const SfmpsDecodeWindowRuntimeView*>(workctrlSubobj);

    if (
      sfmps_ChkSupply(
        workctrlSubobj,
        reinterpret_cast<const char*>(static_cast<std::uintptr_t>(readAddress)),
        readBytes,
        readEndAddress
      ) == 0
    ) {
      return 0;
    }

    const std::int32_t delimiterCode =
      (readBytes < 4)
        ? 0
        : MPS_CheckDelim(reinterpret_cast<const void*>(static_cast<std::uintptr_t>(readAddress)));
    (void)MPS_SetPsMapFn(parserHandleAddress, SFSET_GetCond(workctrlSubobj, 87), SFSET_GetCond(workctrlSubobj, 88));
    (void)MPS_SetPesFn(parserHandleAddress, SFSET_GetCond(workctrlSubobj, 91), SFSET_GetCond(workctrlSubobj, 92));

    std::int32_t decodeResult = 0;
    std::int32_t consumedByHeaderDecode = readEndAddress;
    std::int32_t packetHeaderFlags = 0;
    if (
      MPS_DecHd(
        parserHandleAddress,
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(readAddress)),
        readBytes,
        &consumedByHeaderDecode,
        &packetHeaderFlags
      ) != 0
    ) {
      decodeResult = SFLIB_SetErr(workctrlAddress, kSflibErrSfmpsDecodeHeaderFailed);
    }

    if ((packetHeaderFlags & kPacketFlagsHasRawMps) != 0) {
      (void)sfmps_SetMpsRaw(
        workctrlAddress,
        parserHandleAddress,
        reinterpret_cast<const void*>(static_cast<std::uintptr_t>(readAddress)),
        readBytes
      );
    }

    if (packetHeaderFlags == kPacketFlagsSystemEndcode) {
      if (SFCON_IsEndcodeSkip(workctrlAddress) != 0) {
        (void)sfmps_Concat(workctrlSubobj);
        *outConsumedBytes = 4;
        parserRuntime->selectedElementaryLane = 4;
        return decodeResult;
      }

      if (SFCON_IsSystemEndcodeSkip(workctrlAddress) != 0) {
        *outConsumedBytes = 4;
        parserRuntime->selectedElementaryLane = 4;
        return decodeResult;
      }
    }

    if (delimiterCode == 0) {
      (void)sfmps_SkipNext(
        workctrlSubobj,
        reinterpret_cast<char*>(static_cast<std::uintptr_t>(readAddress)),
        readBytes,
        outDecodedUnits
      );

      const std::int32_t skippedBytes = *outDecodedUnits;
      *outConsumedBytes = skippedBytes;
      if (skippedBytes > 0) {
        const std::int32_t selectedLane = parserRuntime->selectedElementaryLane;
        if (selectedLane >= 0) {
          const std::int32_t decodeWindowBytes = decodeWindowView->decodeWindowBytes;
          if (selectedLane < decodeWindowBytes) {
            const std::int32_t nextLane = selectedLane + skippedBytes;
            if (nextLane <= decodeWindowBytes) {
              parserRuntime->selectedElementaryLane = nextLane;
              *outDecodedUnits = 0;
            } else {
              const std::int32_t wrappedBytes = nextLane - decodeWindowBytes;
              *outDecodedUnits = wrappedBytes;
              parserRuntime->selectedElementaryLane = wrappedBytes + decodeWindowBytes;
            }
          } else {
            parserRuntime->selectedElementaryLane = selectedLane + skippedBytes;
          }
        }
      }

      return decodeResult;
    }

    if ((packetHeaderFlags & kPacketFlagsHasPayload) != 0) {
      std::int32_t copiedPayloadBytes = 0;
      std::int32_t copyStatus = 0;
      decodeResult = sfmps_CopyPketData(
        workctrlSubobj,
        reinterpret_cast<char*>(static_cast<std::uintptr_t>(readAddress + consumedByHeaderDecode)),
        readBytes - consumedByHeaderDecode,
        &copiedPayloadBytes,
        &copyStatus
      );
      if (copyStatus == 1) {
        *outConsumedBytes = consumedByHeaderDecode + copiedPayloadBytes;
      }
      parserRuntime->selectedElementaryLane = -1;
      return decodeResult;
    }

    std::int32_t shortSupplyLatched = 0;
    (void)sfmps_ShortSupply(workctrlSubobj, &shortSupplyLatched);
    if (shortSupplyLatched != 0 || readBytes <= decodeWindowView->decodeWindowBytes) {
      return decodeResult;
    }

    if (consumedByHeaderDecode > 0) {
      *outConsumedBytes = consumedByHeaderDecode;
      *outDecodedUnits = consumedByHeaderDecode;
    } else {
      *outConsumedBytes = 1;
      *outDecodedUnits = 1;
    }

    return decodeResult;
  }

  /**
   * Address: 0x00AD5AE0 (FUN_00AD5AE0, _sfmps_IsZero)
   *
   * What it does:
   * Returns `1` when all bytes in the provided range are zero (`0` otherwise).
   */
  std::int32_t sfmps_IsZero(const std::uint8_t* const buffer, const std::int32_t byteCount)
  {
    if (byteCount <= 0) {
      return 1;
    }

    for (std::int32_t index = 0; index < byteCount; ++index) {
      if (buffer[index] != 0) {
        return 0;
      }
    }
    return 1;
  }

  /**
   * Address: 0x00AD5B10 (FUN_00AD5B10, _sfmps_IsEndOfRingBuf)
   *
   * What it does:
   * Checks whether a cursor points to the supply-lane end address under the
   * lane-end validity conditions used by parser skip logic.
   */
  std::int32_t sfmps_IsEndOfRingBuf(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t cursorAddress
  )
  {
    const SfmpsSupplyLaneRuntimeView* const supplyLane = sfmps_GetSupSj(workctrlSubobj);
    const bool hasEndReference =
      (supplyLane->reserved00 != 0) || (supplyLane->reserved10Word0 == 0 && supplyLane->reserved14Word1 == 0);
    if (!hasEndReference) {
      return 0;
    }

    const std::int32_t ringEndAddress = supplyLane->reserved08 + supplyLane->supplyWindowBytes;
    return (cursorAddress == ringEndAddress) ? 1 : 0;
  }

  /**
   * Address: 0x00AD5A60 (FUN_00AD5A60, _sfmps_SkipNext)
   *
   * What it does:
   * Computes skip distance to next packet delimiter using zero-range fast path,
   * delimiter scan, and ring-end fallback for short tails.
   */
  std::int32_t sfmps_SkipNext(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    char* packetCursor,
    const std::int32_t packetBytes,
    std::int32_t* const outSkipBytes
  )
  {
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const auto* const decodeWindowView = reinterpret_cast<const SfmpsDecodeWindowRuntimeView*>(workctrlSubobj);

    std::int32_t result = workctrlAddress;
    std::int32_t remainingBytes = packetBytes;
    char* scanCursor = packetCursor;
    *outSkipBytes = 0;

    std::int32_t skipBytes = decodeWindowView->decodeWindowBytes;
    if (
      packetBytes < (skipBytes + 3)
      || (result = sfmps_IsZero(reinterpret_cast<const std::uint8_t*>(packetCursor), decodeWindowView->decodeWindowBytes)) == 0
    ) {
      skipBytes = 0;
      if (remainingBytes >= 4) {
        while (true) {
          result = MPS_CheckDelim(scanCursor);
          if ((result & 0xD0000) != 0) {
            break;
          }

          ++skipBytes;
          ++scanCursor;
          --remainingBytes;
          if (remainingBytes < 4) {
            break;
          }
        }
      }

      if (remainingBytes > 0 && remainingBytes < 4) {
        const std::int32_t tailCursorAddress = static_cast<std::int32_t>(
          reinterpret_cast<std::uintptr_t>(scanCursor + remainingBytes)
        );
        result = sfmps_IsEndOfRingBuf(workctrlSubobj, tailCursorAddress);
        if (result != 0) {
          skipBytes += remainingBytes;
        }
      }
    }

    *outSkipBytes = skipBytes;
    return result;
  }

  using SfmpsCopyPketDispatchProc = std::int32_t(__cdecl*)(
    std::int32_t workctrlAddress,
    std::int32_t streamType,
    char* destination,
    std::int32_t byteCount,
    std::int32_t packetTimestampLow,
    std::int32_t packetTimestampHigh
  );

  std::int32_t sfmps_CopyPrvatePketDispatch(
    const std::int32_t workctrlAddress,
    const std::int32_t streamType,
    char* const destination,
    const std::int32_t byteCount,
    const std::int32_t packetTimestampLow,
    const std::int32_t packetTimestampHigh
  )
  {
    (void)packetTimestampLow;
    (void)packetTimestampHigh;
    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    return sfmps_CopyPrvate(
      workctrlSubobj,
      streamType,
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(destination)),
      byteCount
    );
  }

  /**
   * Address: 0x00AD5B70 (FUN_00AD5B70, _sfmps_CopyPketData)
   *
   * What it does:
   * Decodes one packet header, validates payload byte count, then dispatches
   * payload copy through element-output or packet-type copy handlers.
   */
  std::int32_t sfmps_CopyPketData(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    char* const packetPayloadAddress,
    const std::int32_t packetPayloadBytes,
    std::int32_t* const outCopiedBytes,
    std::int32_t* const outCopyStatus
  )
  {
    constexpr std::int32_t kSflibErrSfmpsGetPacketHeaderFailed = static_cast<std::int32_t>(0xFF000D06u);
    constexpr std::int32_t kSflibErrSfmpsInvalidPayloadSize = static_cast<std::int32_t>(0xFF000D0Eu);

    *outCopiedBytes = 0;
    *outCopyStatus = 0;

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);

    MpsPacketHeaderRuntimeView packetHeader{};
    std::int32_t result = 0;
    if (MPS_GetPketHd(parserRuntime->parserHandleAddress, &packetHeader) != 0) {
      result = SFLIB_SetErr(workctrlAddress, kSflibErrSfmpsGetPacketHeaderFailed);
    }

    if (packetHeader.payloadBytes < 0) {
      return SFLIB_SetErr(workctrlAddress, kSflibErrSfmpsInvalidPayloadSize);
    }

    if (packetHeader.payloadBytes == 0) {
      *outCopiedBytes = 0;
      *outCopyStatus = 1;
      return 0;
    }

    if (packetPayloadBytes < packetHeader.payloadBytes) {
      (void)sfmps_ShortSupply(workctrlSubobj, nullptr);
      return 0;
    }

    std::int32_t copyResult = 0;
    const std::int32_t elementOutJoinAddress = parserRuntime->elementOutSjByElementType[packetHeader.streamType - 188];
    if (elementOutJoinAddress != 0) {
      const auto onElementCopyComplete = reinterpret_cast<void(__cdecl*)(std::int32_t, std::int32_t)>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(parserRuntime->copyElemOutCallbackAddress))
      );
      copyResult = static_cast<std::int32_t>(sfmps_CopyElemOutSj(
        elementOutJoinAddress,
        onElementCopyComplete,
        parserRuntime->copyElemOutCallbackContext,
        packetHeader.streamType,
        packetPayloadAddress,
        packetHeader.payloadBytes
      ));
    } else {
      static constexpr std::array<SfmpsCopyPketDispatchProc, 4> kCopyPketFn = {
        sfmps_CopyAudio,
        sfmps_CopyVideo,
        sfmps_CopyPrvatePketDispatch,
        sfmps_CopyPadding,
      };
      copyResult = kCopyPketFn[packetHeader.copyDispatchIndex](
        workctrlAddress,
        packetHeader.packetStreamType,
        packetPayloadAddress,
        packetHeader.payloadBytes,
        packetHeader.packetTimestampLow,
        packetHeader.packetTimestampHigh
      );
    }

    *outCopyStatus = copyResult;
    if (copyResult != 0) {
      if (copyResult != 1) {
        return copyResult;
      }
      *outCopiedBytes = packetHeader.payloadBytes;
    }

    return result;
  }

  /**
   * Address: 0x00AD5C90 (FUN_00AD5C90, _sfmps_CopyElemOutSj)
   *
   * What it does:
   * Copies one element payload to the destination SJ and triggers an optional
   * completion callback on successful copy.
   */
  std::uint32_t sfmps_CopyElemOutSj(
    const std::int32_t sourceJoinAddress,
    void(__cdecl* const onCopyComplete)(std::int32_t callbackContext, std::int32_t streamType),
    const std::int32_t callbackContext,
    const std::int32_t streamType,
    char* const destination,
    const std::int32_t byteCount
  )
  {
    const std::uint32_t copyResult = sfmps_CopySj(sourceJoinAddress, destination, byteCount);
    if (copyResult == 1 && onCopyComplete != nullptr) {
      onCopyComplete(callbackContext, streamType);
    }
    return copyResult;
  }

  /**
   * Address: 0x00AD5CD0 (FUN_00AD5CD0, _sfmps_CopyAudio)
   *
   * What it does:
   * Applies audio-lane channel gating and PTS-min tracking, then copies the
   * packet payload into the audio destination lane.
   */
  std::int32_t sfmps_CopyAudio(
    const std::int32_t workctrlAddress,
    const std::int32_t streamType,
    char* const destination,
    const std::int32_t byteCount,
    const std::int32_t packetTimestampLow,
    const std::int32_t packetTimestampHigh
  )
  {
    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    if (SFSET_GetCond(workctrlSubobj, 6) == 0) {
      return 1;
    }

    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    if (parserRuntime->audioChannel == -1) {
      parserRuntime->audioChannel = streamType;
    }
    if (parserRuntime->reprocessField12 == -1) {
      parserRuntime->reprocessField12 = streamType;
    }

    const std::int32_t forcedAudioChannel = SFSET_GetCond(workctrlSubobj, 30);
    if (forcedAudioChannel != -1) {
      const bool canSwitchChannel =
        (SFSET_GetCond(workctrlSubobj, 55) != 0) ? (streamType < parserRuntime->parserField10Ceiling)
                                                 : (streamType == parserRuntime->reprocessField12);
      if (canSwitchChannel) {
        parserRuntime->audioChannel = forcedAudioChannel;
      }
    }

    const std::int32_t selectedAudioChannel = parserRuntime->audioChannel;
    parserRuntime->parserField10Ceiling = streamType;
    if (selectedAudioChannel != streamType) {
      return 1;
    }

    const std::int64_t packetTimestamp =
      (static_cast<std::int64_t>(packetTimestampHigh) << 32)
      | static_cast<std::uint32_t>(packetTimestampLow);
    if (packetTimestamp >= 0) {
      std::int64_t currentTimestampMin0 =
        (static_cast<std::int64_t>(parserRuntime->parserField5Ceiling) << 32)
        | static_cast<std::uint32_t>(parserRuntime->parserField4Default);
      if (packetTimestamp < currentTimestampMin0) {
        currentTimestampMin0 = packetTimestamp;
      }
      parserRuntime->parserField4Default = static_cast<std::int32_t>(currentTimestampMin0);
      parserRuntime->parserField5Ceiling = static_cast<std::int32_t>(currentTimestampMin0 >> 32);

      std::int64_t currentTimestampMin1 =
        (static_cast<std::int64_t>(parserRuntime->parserField7High) << 32)
        | static_cast<std::uint32_t>(parserRuntime->parserField6Low);
      if (packetTimestamp < currentTimestampMin1) {
        currentTimestampMin1 = packetTimestamp;
      }
      parserRuntime->parserField6Low = static_cast<std::int32_t>(currentTimestampMin1);
      parserRuntime->parserField7High = static_cast<std::int32_t>(currentTimestampMin1 >> 32);
    }

    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    return sfmps_CopyDstBuft(
      workctrlAddress,
      runtimeView->termDestinationLaneB,
      destination,
      byteCount,
      packetTimestampLow,
      packetTimestampHigh
    );
  }

  /**
   * Address: 0x00AD5DD0 (FUN_00AD5DD0, _sfmps_CopyVideo)
   *
   * What it does:
   * Applies video-lane channel gating (including sequence-header promoted
   * channel switch) and copies payload into the video destination lane.
   */
  std::int32_t sfmps_CopyVideo(
    const std::int32_t workctrlAddress,
    const std::int32_t streamType,
    char* const destination,
    const std::int32_t byteCount,
    const std::int32_t packetTimestampLow,
    const std::int32_t packetTimestampHigh
  )
  {
    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    if (SFSET_GetCond(workctrlSubobj, 5) == 0) {
      return 1;
    }

    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    if (parserRuntime->videoChannel == -1) {
      parserRuntime->videoChannel = sfmps_AutoVchPlay(workctrlSubobj, streamType);
    }
    if (parserRuntime->reprocessField11 == -1) {
      parserRuntime->reprocessField11 = streamType;
    }

    const std::int32_t forcedVideoChannel = SFSET_GetCond(workctrlSubobj, 29);
    if (forcedVideoChannel != -1) {
      const bool canSwitchChannel =
        (SFSET_GetCond(workctrlSubobj, 55) != 0) ? (streamType < parserRuntime->parserField9Ceiling)
                                                 : (streamType == parserRuntime->reprocessField11);
      if (
        canSwitchChannel
        && parserRuntime->videoChannel != forcedVideoChannel
        && byteCount >= 4
        && destination[0] == '\0'
        && destination[1] == '\0'
        && static_cast<std::uint8_t>(destination[2]) == 1u
      ) {
        const std::uint8_t startCode = static_cast<std::uint8_t>(destination[3]);
        if (startCode == 0xB3u || startCode == 0xB8u) {
          parserRuntime->videoChannel = forcedVideoChannel;
        }
      }
    }

    const std::int32_t selectedVideoChannel = parserRuntime->videoChannel;
    parserRuntime->parserField9Ceiling = streamType;
    if (selectedVideoChannel != streamType) {
      return 1;
    }

    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    return sfmps_CopyDstBuft(
      workctrlAddress,
      runtimeView->termDestinationLaneA,
      destination,
      byteCount,
      packetTimestampLow,
      packetTimestampHigh
    );
  }

  /**
   * Address: 0x00AD5EE0 (FUN_00AD5EE0, _sfmps_AutoVchPlay)
   *
   * What it does:
   * Applies automatic video-channel selection when condition 59 requests
   * auto-mode and two or more audio streams are present.
   */
  std::int32_t sfmps_AutoVchPlay(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t currentVideoChannel
  )
  {
    if (SFSET_GetCond(workctrlSubobj, 59) != 2) {
      return currentVideoChannel;
    }

    std::int32_t videoStreamIndex = 0;
    std::int32_t audioStreamIndex = 0;
    (void)sfmps_GetStmNum(workctrlSubobj, &videoStreamIndex, &audioStreamIndex);
    return (audioStreamIndex >= 2) ? 2 : currentVideoChannel;
  }

  /**
   * Address: 0x00AD5F20 (FUN_00AD5F20, _sfmps_CopyPrvate)
   *
   * What it does:
   * Handles private-packet header stripping; copies payload through user-SJ
   * path and replays with adjusted packet window when header extraction occurs.
   */
  std::int32_t sfmps_CopyPrvate(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t streamType,
    const std::int32_t packetAddress,
    const std::int32_t packetBytes
  )
  {
    std::int32_t remainingPacketBytes = packetBytes;
    if (SFHDS_SetHdr(workctrlSubobj, streamType, packetAddress, packetBytes, &remainingPacketBytes) == 0) {
      return sfmps_CopyUsrSj(
        workctrlSubobj,
        streamType,
        reinterpret_cast<char*>(static_cast<std::uintptr_t>(packetAddress)),
        packetBytes
      );
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    sfmps_SetCustomPketLen(workctrlAddress);
    if (remainingPacketBytes != 0) {
      (void)sfmps_CopyUsrSj(
        workctrlSubobj,
        0,
        reinterpret_cast<char*>(static_cast<std::uintptr_t>(packetAddress - 18)),
        packetBytes + 18
      );
    }

    return 1;
  }

  /**
   * Address: 0x00AD5F90 (FUN_00AD5F90, _sfmps_CopyUsrSj)
   *
   * What it does:
   * Fetches user-output channel wiring for one slot, copies payload into the
   * bound SJ source, and executes optional post-copy callbacks.
   */
  std::int32_t sfmps_CopyUsrSj(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t uochSlotIndex,
    char* const destination,
    const std::int32_t byteCount
  )
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t laneIndex = runtimeView->termDestinationLaneC;
    if (laneIndex == 8) {
      return 1;
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    SfbufUserOutputChannelRuntimeView outputChannel{};
    (void)SFBUF_GetUoch(workctrlAddress, laneIndex, uochSlotIndex, reinterpret_cast<std::int32_t*>(&outputChannel));
    if (outputChannel.sourceJoinAddress == 0) {
      return 1;
    }

    const std::uint32_t copyResult = sfmps_CopySj(outputChannel.sourceJoinAddress, destination, byteCount);
    if (copyResult == 1) {
      if (outputChannel.onPrimaryCopy != nullptr) {
        outputChannel.onPrimaryCopy(workctrlAddress, uochSlotIndex);
      }
      if (outputChannel.onSecondaryCopy != nullptr) {
        outputChannel.onSecondaryCopy(outputChannel.secondaryCallbackContext, uochSlotIndex);
      }
    }

    return static_cast<std::int32_t>(copyResult);
  }

  /**
   * Address: 0x00AD6030 (FUN_00AD6030, _sfmps_CopySj)
   *
   * What it does:
   * Copies bytes from one SJ source into caller buffer using up to two copy
   * windows and tracks partial-copy mismatches in `copy_sj_error`.
   */
  std::uint32_t sfmps_CopySj(
    const std::int32_t sourceJoinAddress,
    char* const destination,
    const std::int32_t byteCount
  )
  {
    const auto* const source = reinterpret_cast<const SfmpsCopySourceRuntimeView*>(SjAddressToPointer(sourceJoinAddress));
    if (source->vtable->queryWritableBytes(sourceJoinAddress, 0) < byteCount) {
      return 0;
    }

    const std::uint32_t firstCopiedBytes = sfmps_ExecCopySj(sourceJoinAddress, destination, byteCount);
    if (firstCopiedBytes == 0) {
      return 0;
    }

    const std::int32_t remainingBytes = byteCount - static_cast<std::int32_t>(firstCopiedBytes);
    if (remainingBytes > 0) {
      const std::uint32_t secondCopiedBytes = sfmps_ExecCopySj(
        sourceJoinAddress,
        destination + firstCopiedBytes,
        remainingBytes
      );
      if (secondCopiedBytes != static_cast<std::uint32_t>(remainingBytes)) {
        ++copy_sj_error;
      }
    }

    return 1;
  }

  /**
   * Address: 0x00AD6090 (FUN_00AD6090, _sfmps_ExecCopySj)
   *
   * What it does:
   * Requests one writable SJ copy window, copies bytes with `MEM_Copy`, then
   * commits the written window back to the source object.
   */
  std::uint32_t sfmps_ExecCopySj(
    const std::int32_t sourceJoinAddress,
    const void* const source,
    const std::int32_t byteCount
  )
  {
    auto* const sourceView = reinterpret_cast<SfmpsCopySourceRuntimeView*>(SjAddressToPointer(sourceJoinAddress));
    SfmpsCopySourceWindowRuntimeView writeWindow{};
    sourceView->vtable->acquireWriteWindow(sourceJoinAddress, 0, byteCount, &writeWindow);
    (void)MEM_Copy(writeWindow.destination, source, writeWindow.copiedBytes);
    sourceView->vtable->commitWriteWindow(sourceJoinAddress, 1, &writeWindow);
    return writeWindow.copiedBytes;
  }

  /**
   * Address: 0x00AD60E0 (FUN_00AD60E0, _sfmps_CopyPadding)
   *
   * What it does:
   * Padding-packet copy handler that accepts and ignores packet payload.
   */
  std::int32_t sfmps_CopyPadding(
    const std::int32_t workctrlAddress,
    const std::int32_t streamType,
    char* const destination,
    const std::int32_t byteCount,
    const std::int32_t packetTimestampLow,
    const std::int32_t packetTimestampHigh
  )
  {
    (void)workctrlAddress;
    (void)streamType;
    (void)destination;
    (void)byteCount;
    (void)packetTimestampLow;
    (void)packetTimestampHigh;
    return 1;
  }

  /**
   * Address: 0x00AD60F0 (FUN_00AD60F0, _sfmps_CopyDstBuft)
   *
   * What it does:
   * Acquires one destination-ring write window, performs optional PTS queue
   * side-effects, copies payload bytes, and commits the write cursor advance.
   */
  std::int32_t sfmps_CopyDstBuft(
    const std::int32_t workctrlAddress,
    const std::int32_t destinationLaneIndex,
    char* const sourceBytes,
    const std::int32_t sourceByteCount,
    const std::int32_t packetTimestampLow,
    const std::int32_t packetTimestampHigh
  )
  {
    SfbufRingWriteDescriptorView writeDescriptor{};
    std::int32_t result = SFBUF_RingGetWrite(
      workctrlAddress,
      destinationLaneIndex,
      reinterpret_cast<std::int32_t*>(&writeDescriptor)
    );
    if (result != 0) {
      return result;
    }

    if (sourceByteCount > (writeDescriptor.firstWriteBytes + writeDescriptor.secondWriteBytes)) {
      return 0;
    }

    if (destinationLaneIndex == 1) {
      const std::int64_t packetTimestamp =
        (static_cast<std::int64_t>(packetTimestampHigh) << 32)
        | static_cast<std::uint32_t>(packetTimestampLow);
      if (packetTimestamp >= 0) {
        if (SFPTS_IsPtsQueFull(workctrlAddress, 1) != 0) {
          return 0;
        }

        std::int32_t ptsQueueWords[4] = {
          packetTimestampLow,
          packetTimestampHigh,
          static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(writeDescriptor.firstWriteAddress)),
          sourceByteCount,
        };
        std::int32_t ptsQueueTag = 0;
        result = SFPTS_WritePtsQue(workctrlAddress, 1, ptsQueueWords, &ptsQueueTag);
        if (result != 0) {
          return result;
        }
      }
    } else if (destinationLaneIndex == 2 && SFPLY_SetPtsInfo != nullptr) {
      std::int32_t ptsInfoWords[3] = { packetTimestampLow, packetTimestampHigh, sourceByteCount };
      if (SFPLY_SetPtsInfo(workctrlAddress + 0x12E0, ptsInfoWords) == -1) {
        return 0;
      }
    }

    if (sourceByteCount > writeDescriptor.firstWriteBytes) {
      (void)MEM_Copy(writeDescriptor.firstWriteAddress, sourceBytes, static_cast<std::uint32_t>(writeDescriptor.firstWriteBytes));
      (void)MEM_Copy(
        writeDescriptor.secondWriteAddress,
        sourceBytes + writeDescriptor.firstWriteBytes,
        static_cast<std::uint32_t>(sourceByteCount - writeDescriptor.firstWriteBytes)
      );
    } else {
      (void)MEM_Copy(writeDescriptor.firstWriteAddress, sourceBytes, static_cast<std::uint32_t>(sourceByteCount));
    }

    (void)writeDescriptor.writeCursor;
    result = SFBUF_RingAddWrite(workctrlAddress, destinationLaneIndex, sourceByteCount);
    if (result == 0) {
      return 1;
    }
    return result;
  }

  /**
   * Address: 0x00AD6900 (FUN_00AD6900, _sfmps_UpdateFlowCnt)
   *
   * What it does:
   * Updates parser flow counters from SFBUF flow snapshots and accumulates
   * consumed-byte / decoded-unit signed 64-bit totals.
   */
  std::int32_t sfmps_UpdateFlowCnt(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t consumedBytesDelta,
    const std::int32_t decodedUnitsDelta
  )
  {
    auto* const flowView = reinterpret_cast<SfmpsFlowCountRuntimeView*>(workctrlSubobj);
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);

    std::int32_t result = runtimeView->supplyLanes[0].supplyJoinAddress;
    if (result != 0) {
      std::int32_t flowCountLow = 0;
      std::int32_t flowCountHigh = 0;
      (void)SFBUF_GetFlowCnt(result, &flowCountLow, &flowCountHigh);

      const std::int64_t updatedFlow = SFBUF_UpdateFlowCnt(flowView->sourceFlowLow, flowView->sourceFlowHigh, flowCountLow);
      flowView->sourceFlowLow = static_cast<std::int32_t>(updatedFlow);
      flowView->sourceFlowHigh = static_cast<std::int32_t>(updatedFlow >> 32);

      const std::int64_t consumedAccumulated =
        (static_cast<std::int64_t>(flowView->consumedBytesHigh) << 32)
        | static_cast<std::uint32_t>(flowView->consumedBytesLow);
      const std::int64_t nextConsumed = consumedAccumulated + static_cast<std::int64_t>(consumedBytesDelta);
      flowView->consumedBytesLow = static_cast<std::int32_t>(nextConsumed);
      flowView->consumedBytesHigh = static_cast<std::int32_t>(nextConsumed >> 32);

      const std::int64_t decodedAccumulated =
        (static_cast<std::int64_t>(flowView->decodedUnitsHigh) << 32)
        | static_cast<std::uint32_t>(flowView->decodedUnitsLow);
      const std::int64_t nextDecoded = decodedAccumulated + static_cast<std::int64_t>(decodedUnitsDelta);
      flowView->decodedUnitsLow = static_cast<std::int32_t>(nextDecoded);
      flowView->decodedUnitsHigh = static_cast<std::int32_t>(nextDecoded >> 32);
      result = flowView->decodedUnitsHigh;
    }

    return result;
  }

  /**
   * Address: 0x00ACF330 (FUN_00ACF330, _sfm2ts_UpdateFlowCnt)
   *
   * What it does:
   * SJ-layer flow-counter update wrapper: refreshes source flow counters and
   * accumulates consumed/decoded 64-bit totals through the common SFMPS lane.
   */
  std::int32_t sj_UpdateFlowCnt(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t consumedBytesDelta,
    const std::int32_t decodedUnitsDelta
  )
  {
    return sfmps_UpdateFlowCnt(workctrlSubobj, consumedBytesDelta, decodedUnitsDelta);
  }

  /**
   * Address: 0x00AD5610 (FUN_00AD5610, _sfmps_SetOption)
   *
   * What it does:
   * Pushes PES/system parsing options from SFSET condition lanes into current
   * MPS parser handle.
   */
  std::int32_t sfmps_SetOption(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t parserHandleAddress = getSfmpsParserRuntime(workctrlSubobj)->parserHandleAddress;
    const std::int32_t pesSwitchCondition = SFSET_GetCond(workctrlSubobj, 74);
    (void)MPS_SetPesSw(parserHandleAddress, pesSwitchCondition);
    const std::int32_t systemFnAuxCondition = SFSET_GetCond(workctrlSubobj, 86);
    const std::int32_t systemFnCondition = SFSET_GetCond(workctrlSubobj, 85);
    return MPS_SetSystemFn(parserHandleAddress, systemFnCondition, systemFnAuxCondition);
  }

  /**
   * Address: 0x00AD5710 (FUN_00AD5710, _sfmps_RingGetRead)
   *
   * What it does:
   * Reads one active supply-lane ring descriptor and exports read-window start,
   * size, and end addresses.
   */
  std::int32_t sfmps_RingGetRead(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outReadAddress,
    std::int32_t* const outReadBytes,
    const std::int32_t unusedArg,
    std::int32_t* const outReadEndAddress
  )
  {
    (void)unusedArg;

    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    SfbufRingReadDescriptorView readDescriptor{};
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t result = SFBUF_RingGetRead(
      workctrlAddress,
      runtimeView->activeSupplyLaneIndex,
      reinterpret_cast<std::int32_t*>(&readDescriptor)
    );
    if (result != 0) {
      return result;
    }

    *outReadAddress = readDescriptor.readAddress;
    *outReadBytes = readDescriptor.readBytes;
    *outReadEndAddress = readDescriptor.readBytes + readDescriptor.trailingBytes;
    return 0;
  }

  /**
   * Address: 0x00AD5760 (FUN_00AD5760, _sfmps_RingAddRead)
   *
   * What it does:
   * Advances active supply-lane ring read cursor by one caller-provided byte
   * count.
   */
  std::int32_t sfmps_RingAddRead(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t addBytes)
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    return SFBUF_RingAddRead(workctrlAddress, runtimeView->activeSupplyLaneIndex, addBytes);
  }

  /**
   * Address: 0x00AD62A0 (FUN_00AD62A0, _sfmps_Concat)
   *
   * What it does:
   * Increments parser-runtime concat counter and returns parser-runtime address.
   */
  std::int32_t sfmps_Concat(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    ++parserRuntime->concatCount;
    return SjPointerToAddress(parserRuntime);
  }

  /**
   * Address: 0x00AD6410 (FUN_00AD6410, _sfmps_ShortSupply)
   *
   * What it does:
   * Detects short-supply termination on active lane and propagates destination
   * termination flags when active source lane has already terminated.
   */
  std::int32_t sfmps_ShortSupply(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outShortSupplyLatched
  )
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);

    std::int32_t result = 0;
    if (SFBUF_GetTermFlg(workctrlAddress, runtimeView->activeSupplyLaneIndex) == 1) {
      (void)sfmps_SetTermDst(workctrlSubobj, parserRuntime->effectiveEndcodeMode);
      result = 1;
    }

    if (outShortSupplyLatched != nullptr) {
      *outShortSupplyLatched = result;
    }
    return result;
  }

  /**
   * Address: 0x00AE5EF0 (FUN_00AE5EF0, _SFCON_IsSystemEndcodeSkip)
   *
   * What it does:
   * Returns whether either system-endcode skip condition lane (`49` or `56`)
   * is enabled for one SFD work-control handle.
   */
  std::int32_t SFCON_IsSystemEndcodeSkip(const std::int32_t workctrlAddress)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    if (SFSET_GetCond(workctrlSubobj, kSfsetCondConcatPlay) != 0) {
      return 1;
    }
    return (SFSET_GetCond(workctrlSubobj, kSfsetCondSystemEndcodeSkip) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD63D0 (FUN_00AD63D0, _sfmps_IsEffectiveEndcode)
   *
   * What it does:
   * Reports one effective endcode only for pack delimiters (`0x80000`) when
   * neither endcode-skip gate is active.
   */
  std::int32_t sfmps_IsEffectiveEndcode(const std::int32_t workctrlAddress, const std::int32_t delimiterCode)
  {
    return (delimiterCode == static_cast<std::int32_t>(0x00080000u)
            && SFCON_IsEndcodeSkip(workctrlAddress) == 0
            && SFCON_IsSystemEndcodeSkip(workctrlAddress) == 0)
      ? 1
      : 0;
  }

  /**
   * Address: 0x00AD62B0 (FUN_00AD62B0, _sfmps_ChkSupply)
   *
   * What it does:
   * Evaluates packet delimiter and short-supply thresholds, latches endcode
   * readiness in parser runtime, and decides whether supply processing may
   * continue.
   */
  std::int32_t sfmps_ChkSupply(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const char* const supplyBuffer,
    const std::int32_t supplyBytes,
    const std::int32_t shortSupplyBytes
  )
  {
    constexpr std::int32_t kDelimiterPack = static_cast<std::int32_t>(0x00080000u);
    constexpr std::int32_t kDelimiterSystem = static_cast<std::int32_t>(0x00010000u);
    constexpr std::int32_t kDelimiterPsm = static_cast<std::int32_t>(0x00040000u);

    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);

    std::int32_t delimiterCode = 0;
    if (supplyBytes >= 4) {
      delimiterCode = MPS_CheckDelim(supplyBuffer);
      if (delimiterCode == kDelimiterPack) {
        if (runtimeView->effectiveEndcodeBoundaryBytes < 0) {
          runtimeView->effectiveEndcodeBoundaryBytes =
            SFBUF_GetRTot(workctrlAddress, runtimeView->activeSupplyLaneIndex) + 4;
        }
        parserRuntime->effectiveEndcodeMode = 1;
      } else if (delimiterCode != 0) {
        parserRuntime->effectiveEndcodeMode = 0;
      }
    }

    if (sfmps_IsEffectiveEndcode(workctrlAddress, delimiterCode) != 0) {
      (void)sfmps_SetTermDst(workctrlSubobj, 1);
      return 0;
    }

    if (shortSupplyBytes < 4) {
      std::int32_t shortSupplyLatched = 0;
      (void)sfmps_ShortSupply(workctrlSubobj, &shortSupplyLatched);
      if (shortSupplyLatched != 0) {
        return 0;
      }
    }

    if (supplyBytes < 64 && (delimiterCode == kDelimiterSystem || delimiterCode == kDelimiterPsm)) {
      (void)sfmps_ShortSupply(workctrlSubobj, nullptr);
      return 0;
    }

    return 1;
  }

  /**
   * Address: 0x00ACF780 (FUN_00ACF780, _setTermDst)
   *
   * What it does:
   * Writes one termination flag to the three destination ring lanes tracked by
   * the SFMPS work-control runtime view.
   */
  std::int32_t setTermDst(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t termFlag)
  {
    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    (void)SFBUF_SetTermFlg(workctrlAddress, runtimeView->termDestinationLaneB, termFlag);
    (void)SFBUF_SetTermFlg(workctrlAddress, runtimeView->termDestinationLaneA, termFlag);
    return SFBUF_SetTermFlg(workctrlAddress, runtimeView->termDestinationLaneC, termFlag);
  }

  /**
   * Address: 0x00ACF7C0 (FUN_00ACF7C0, _getTermDst)
   *
   * What it does:
   * Reads and AND-combines termination flags from the three SFMPS destination
   * ring lanes.
   */
  std::int32_t getTermDst(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t laneBTerm = SFBUF_GetTermFlg(workctrlAddress, runtimeView->termDestinationLaneB);
    const std::int32_t laneATerm = SFBUF_GetTermFlg(workctrlAddress, runtimeView->termDestinationLaneA);
    const std::int32_t laneCTerm = SFBUF_GetTermFlg(workctrlAddress, runtimeView->termDestinationLaneC);
    return laneBTerm & laneATerm & laneCTerm;
  }

  /**
   * Address: 0x00ACF720 (FUN_00ACF720, _chkTermFlg)
   *
   * What it does:
   * Checks SFMPS destination termination state, forwards termination to M2TSD
   * supply lane when source lane ended, and seals destination lanes on M2TSD
   * terminal state.
   */
  std::int32_t chkTermFlg(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    std::int32_t result = getTermDst(workctrlSubobj);
    if (result != 1) {
      const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
      const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
      const std::int32_t m2tsdRuntimeAddress = runtimeView->streamPrepRuntime->m2tsdRuntimeAddress;
      if (SFBUF_GetTermFlg(workctrlAddress, runtimeView->activeSupplyLaneIndex) == 1) {
        (void)M2TSD_TermSupply(m2tsdRuntimeAddress);
      }

      result = M2TSD_GetStat(m2tsdRuntimeAddress);
      if (result == 4) {
        return setTermDst(workctrlSubobj, 1);
      }
    }

    return result;
  }

  /**
   * Address: 0x00AD64F0 (FUN_00AD64F0, _sfmps_GetPrepDst)
   *
   * What it does:
   * Reads and OR-combines preparation flags from the three SFMPS destination
   * lanes.
   */
  std::int32_t sfmps_GetPrepDst(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t laneBPrep = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneB);
    const std::int32_t laneAPrep = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneA);
    const std::int32_t laneCPrep = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneC);
    return laneBPrep | laneAPrep | laneCPrep;
  }

  /**
   * Address: 0x00AD6530 (FUN_00AD6530, _sfmps_SetPrepDst)
   *
   * What it does:
   * Writes one preparation flag value to all three SFMPS destination lanes.
   */
  std::int32_t sfmps_SetPrepDst(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t prepFlag
  )
  {
    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    (void)SFBUF_SetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneB, prepFlag);
    (void)SFBUF_SetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneA, prepFlag);
    return SFBUF_SetPrepFlg(workctrlAddress, runtimeView->termDestinationLaneC, prepFlag);
  }

  /**
   * Address: 0x00AD6570 (FUN_00AD6570, _sfmps_IsPrepEnd)
   *
   * What it does:
   * Computes one prep-end threshold from work-control defaults and active
   * supply-lane window limits, then checks whether ring 0 write-total reached it.
   */
  std::int32_t sfmps_IsPrepEnd(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t ignoredLaneIndex
  )
  {
    (void)ignoredLaneIndex;

    const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    std::int32_t candidateThreshold = runtimeView->prepEndOverrideBytes;
    std::int32_t thresholdBytes = runtimeView->prepEndDefaultBytes;
    if (candidateThreshold <= 0) {
      candidateThreshold = sfmps_GetSupSj(workctrlSubobj)->supplyWindowBytes;
    }

    if (candidateThreshold > 0 && candidateThreshold < thresholdBytes) {
      thresholdBytes = candidateThreshold;
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    return (SFBUF_GetWTot(workctrlAddress, 0) >= thresholdBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00AD64A0 (FUN_00AD64A0, _sfmps_ChkPrepFlg)
   *
   * What it does:
   * Checks destination prep state, then latches destination prep flags when the
   * active source lane is prepared and ring-0 prep threshold is reached.
   */
  std::int32_t sfmps_ChkPrepFlg(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    std::int32_t result = sfmps_GetPrepDst(workctrlSubobj);
    if (result != 1) {
      const auto* const runtimeView = reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
      const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
      result = SFBUF_GetPrepFlg(workctrlAddress, runtimeView->activeSupplyLaneIndex);
      if (result == 1) {
        result = sfmps_IsPrepEnd(workctrlSubobj, runtimeView->activeSupplyLaneIndex);
        if (result != 0) {
          return sfmps_SetPrepDst(workctrlSubobj, 1);
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00ACF650 (FUN_00ACF650, _adjustAvPlay)
   *
   * What it does:
   * Adjusts AV enable conditions from active SJ buffered-bytes threshold,
   * destination termination state, transfer prep flags, and M2TSD playback
   * block flags.
   */
  std::int32_t adjustAvPlay(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kCondVideoEnable = 5;
    constexpr std::int32_t kCondAudioEnable = 6;
    constexpr std::int32_t kTransferLaneVideo = 7;
    constexpr std::int32_t kTransferLaneAudio = 6;

    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    SfmpsSupplyLaneRuntimeView* const supplyLane = getSupSj(workctrlSubobj);
    const auto* const sourceView =
      reinterpret_cast<const SjBufferedSourceView*>(SjAddressToPointer(supplyLane->supplyJoinAddress));
    const std::int32_t sourceBufferedBytes = sourceView->dispatch->QueryBufferedBytes(supplyLane->supplyJoinAddress, 1);

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    std::int32_t result = 0;
    if (
      sourceBufferedBytes >= (supplyLane->supplyWindowBytes / 2) ||
      (result = SFBUF_GetTermFlg(workctrlAddress, runtimeView->activeSupplyLaneIndex)) != 0
    ) {
      const auto* const m2tsdRuntime =
        reinterpret_cast<const SfmpsM2tsdRuntimeView*>(SjAddressToPointer(runtimeView->streamPrepRuntime->m2tsdRuntimeAddress));
      const auto* const m2tsdPlaybackState =
        reinterpret_cast<const SfmpsM2tsdPlaybackStateView*>(SjAddressToPointer(m2tsdRuntime->playbackStateAddress));

      if (
        SFSET_GetCond(workctrlSubobj, kCondAudioEnable) == 1 &&
        SFTRN_GetPrepFlg(workctrlAddress, kTransferLaneAudio) != 0 &&
        m2tsdPlaybackState->condition6BlockFlag == 0
      ) {
        (void)SFSET_SetCond(workctrlSubobj, kCondAudioEnable, 0);
      }

      result = SFSET_GetCond(workctrlSubobj, kCondVideoEnable);
      if (result == 1) {
        result = SFTRN_GetPrepFlg(workctrlAddress, kTransferLaneVideo);
        if (result != 0 && m2tsdPlaybackState->condition5BlockFlag == 0) {
          return SFSET_SetCond(workctrlSubobj, kCondVideoEnable, 0);
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00ACF4F0 (FUN_00ACF4F0, _procPrep)
   *
   * What it does:
   * Runs SJ prep-flag update and then executes AV-play condition adjustment.
   */
  std::int32_t sj_ProcPrep(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    (void)sj_ChkPrepFlg(workctrlSubobj);
    return adjustAvPlay(workctrlSubobj);
  }

  /**
   * Address: 0x00ACF4C0 (FUN_00ACF4C0, _updateState)
   *
   * What it does:
   * Dispatches SJ state updates by execution stage: stage 2 runs prep
   * processing, stage 4 checks termination, all other stages return unchanged.
   */
  std::int32_t sj_UpdateState(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const execView = reinterpret_cast<const SfmpsExecRuntimeView*>(workctrlSubobj);
    const std::int32_t executionStage = execView->executionStage;
    if (executionStage == 2) {
      return sj_ProcPrep(workctrlSubobj);
    }
    if (executionStage == 4) {
      return chkTermFlg(workctrlSubobj);
    }
    return executionStage;
  }

  /**
   * Address: 0x00AD65B0 (FUN_00AD65B0, _sfmps_AdjustAvPlay)
   *
   * What it does:
   * Adjusts SFMPS AV condition lanes from parser pending-byte lanes, transfer
   * prep flags, and ring write totals.
   */
  std::int32_t sfmps_AdjustAvPlay(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kCondVideoEnable = 5;
    constexpr std::int32_t kCondAudioEnable = 6;
    constexpr std::int32_t kCondAutoAudio = 80;
    constexpr std::int32_t kCondAutoVideo = 79;
    constexpr std::int32_t kRingAudio = 2;
    constexpr std::int32_t kRingVideo = 1;
    constexpr std::int32_t kTransferLaneAudio = 6;
    constexpr std::int32_t kTransferLaneVideo = 7;

    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);

    if (
      SFSET_GetCond(workctrlSubobj, kCondAudioEnable) != 0 &&
      SFSET_GetCond(workctrlSubobj, kCondAutoAudio) != 0 &&
      SFBUF_GetWTot(workctrlAddress, kRingAudio) == 0 &&
      runtimeView->streamPrepRuntime->pendingCondition6Bytes == 0 &&
      SFTRN_GetPrepFlg(workctrlAddress, kTransferLaneAudio) != 0
    ) {
      (void)SFSET_SetCond(workctrlSubobj, kCondAudioEnable, 0);
    }

    std::int32_t result = SFSET_GetCond(workctrlSubobj, kCondVideoEnable);
    if (result != 0) {
      result = SFSET_GetCond(workctrlSubobj, kCondAutoVideo);
      if (result != 0) {
        result = SFBUF_GetWTot(workctrlAddress, kRingVideo);
        if (result == 0) {
          result = runtimeView->streamPrepRuntime->pendingCondition5Bytes;
          if (result == 0) {
            result = SFTRN_GetPrepFlg(workctrlAddress, kTransferLaneVideo);
            if (result != 0) {
              return SFSET_SetCond(workctrlSubobj, kCondVideoEnable, 0);
            }
          }
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00AD6660 (FUN_00AD6660, _sfmps_GetStmNum)
   *
   * What it does:
   * Scans three MPS system headers, stores maxima for two system-element lanes
   * into parser runtime cache, and mirrors them to output pointers.
   */
  std::int32_t* sfmps_GetStmNum(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outVideoStreamIndex,
    std::int32_t* const outAudioStreamIndex
  )
  {
    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    auto* const parserRuntime = reinterpret_cast<SfmpsParserRuntimeView*>(runtimeView->streamPrepRuntime);
    void* const parserHandle = reinterpret_cast<void*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(parserRuntime->parserHandleAddress))
    );

    std::int32_t maxSystemField2 = 0;
    std::int32_t maxSystemField3 = 0;
    for (std::int32_t headerIndex = 0; headerIndex < 3; ++headerIndex) {
      MpsSystemHeaderRuntimeView systemHeader{};
      (void)MPS_GetSysHd(parserHandle, &systemHeader, headerIndex);
      if (maxSystemField2 <= systemHeader.maxSystemField2) {
        maxSystemField2 = systemHeader.maxSystemField2;
      }
      if (maxSystemField3 <= systemHeader.maxSystemField3) {
        maxSystemField3 = systemHeader.maxSystemField3;
      }
    }

    parserRuntime->cachedSystemField2Max = maxSystemField2;
    parserRuntime->cachedSystemField3Max = maxSystemField3;
    *outVideoStreamIndex = maxSystemField2;
    *outAudioStreamIndex = parserRuntime->cachedSystemField3Max;
    return outAudioStreamIndex;
  }

  /**
   * Address: 0x00AD66D0 (FUN_00AD66D0, _sfmps_SetMvInf)
   *
   * What it does:
   * Refreshes movie-info lanes from current MPS pack/system headers and backfills
   * default system-element lanes when sentinel values are still active.
   */
  std::int32_t sfmps_SetMvInf(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    auto* const parserRuntime = reinterpret_cast<SfmpsParserRuntimeView*>(runtimeView->streamPrepRuntime);
    void* const parserHandle = reinterpret_cast<void*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(parserRuntime->parserHandleAddress))
    );

    MpsPackHeaderRuntimeView packHeader{};
    (void)MPS_GetPackHd(parserHandle, &packHeader);
    if (packHeader.muxRateUnits50BytesPerSecond > 0) {
      runtimeView->detectedMuxRateUnits50BytesPerSecond = packHeader.muxRateUnits50BytesPerSecond;
    }

    MpsSystemHeaderRuntimeView systemHeader{};
    (void)MPS_GetSysHd(parserHandle, &systemHeader, 1);
    std::int32_t result = systemHeader.rateBound;
    if (result != -1) {
      runtimeView->detectedSystemHeaderMetric = result;
    }

    if (runtimeView->defaultSystemField2Max == -1) {
      runtimeView->defaultSystemField2Max = parserRuntime->cachedSystemField2Max;
    }

    if (runtimeView->defaultSystemField3Max == -1) {
      result = parserRuntime->cachedSystemField3Max;
      runtimeView->defaultSystemField3Max = result;
    }

    return result;
  }

  /**
   * Address: 0x00AD6750 (FUN_00AD6750, _sfmps_SetMpsHd)
   *
   * What it does:
   * Updates one active SFMPS header lane from parser/runtime fields and stores
   * computed header timestamp delta in work-control runtime.
   */
  std::int32_t sfmps_SetMpsHd(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t headerAddress = sfmps_GetHd(workctrlAddress);
    if (headerAddress != 0) {
      auto* const headerRuntime = reinterpret_cast<SfmpsHeaderRuntimeView*>(SjAddressToPointer(headerAddress));
      const std::uint32_t parserField6 = static_cast<std::uint32_t>(parserRuntime->parserField6Low);
      const std::uint32_t parserField7 = static_cast<std::uint32_t>(parserRuntime->parserField7High);
      if (parserField6 != 0xFFFFFFFFu || parserField7 != 0x7FFFFFFFu) {
        const std::uint64_t parserStamp = (static_cast<std::uint64_t>(parserField7) << 32u) | parserField6;
        const std::uint64_t headerStamp =
          (static_cast<std::uint64_t>(static_cast<std::uint32_t>(headerRuntime->parserField7High)) << 32u) |
          static_cast<std::uint32_t>(headerRuntime->parserField6Low);
        const std::uint64_t stampDelta = parserStamp - headerStamp;
        runtimeView->headerDeltaField0 = static_cast<std::int32_t>(stampDelta & 0xFFFFFFFFu);
        runtimeView->headerDeltaField1 = static_cast<std::int32_t>((stampDelta >> 32u) & 0xFFFFFFFFu);

        if (headerRuntime->activeFlag == 0) {
          headerRuntime->muxRateBytesPerSecond = 50 * runtimeView->detectedMuxRateUnits50BytesPerSecond;
          headerRuntime->systemHeaderMetric = runtimeView->detectedSystemHeaderMetric;
          headerRuntime->parserCachedField3Max = parserRuntime->cachedSystemField3Max;
          headerRuntime->parserCachedField2Max = parserRuntime->cachedSystemField2Max;
          headerRuntime->seekField0 = runtimeView->seekField0;
          headerRuntime->seekField1 = runtimeView->seekField1;
          headerRuntime->parserField6Low = parserRuntime->parserField6Low;
          headerRuntime->parserField7High = parserRuntime->parserField7High;
          headerRuntime->parserField11 = parserRuntime->reprocessField11;
          headerRuntime->parserField12 = parserRuntime->reprocessField12;
        }
      }
    }
    return headerAddress;
  }

  /**
   * Address: 0x00AD6800 (FUN_00AD6800, _sfmps_SetAudioStreamType)
   *
   * What it does:
   * Reads MPS elementary-stream list and forwards supported audio stream types
   * to SFADXT runtime.
   */
  std::int32_t sfmps_SetAudioStreamType(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    void* const parserHandle = reinterpret_cast<void*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(parserRuntime->parserHandleAddress))
    );

    std::int32_t elementaryCount = 0;
    const MpsElementaryInfoEntryView* elementaryEntries = nullptr;
    (void)MPS_GetElementaryInfo(parserHandle, &elementaryCount, &elementaryEntries);

    for (std::int32_t index = 0; index < elementaryCount; ++index) {
      const std::uint8_t streamType = elementaryEntries[index].streamType;
      if (streamType >= 3u && (streamType <= 4u || streamType == 15u)) {
        (void)SFADXT_SetAudioStreamType(workctrlSubobj, static_cast<std::int32_t>(streamType));
      }
    }

    return elementaryCount;
  }

  /**
   * Address: 0x00AD6870 (FUN_00AD6870, _sfmps_SetMpsRaw)
   *
   * What it does:
   * Caches up to 0xB0 bytes of the current MPS raw chunk into header-side
   * primary/secondary raw lanes according to last-system-header probe flags.
   */
  std::uint32_t sfmps_SetMpsRaw(
    const std::int32_t workctrlAddress,
    const std::int32_t parserHandleAddress,
    const void* const packetAddress,
    const std::int32_t packetBytes
  )
  {
    std::uint32_t result = static_cast<std::uint32_t>(sfmps_GetHd(workctrlAddress));
    if (result != 0) {
      auto* const headerCaptureView =
        reinterpret_cast<SfmpsHeaderRawCaptureRuntimeView*>(SjAddressToPointer(static_cast<std::int32_t>(result)));
      if (headerCaptureView->activeFlag == 0) {
        MpsLastSystemHeaderProbeRuntimeView lastSystemHeaderProbe{};
        (void)MPS_GetLastSysHd(parserHandleAddress, &lastSystemHeaderProbe);

        std::int32_t copyBytes = packetBytes;
        if (copyBytes >= 0xB0) {
          copyBytes = 0xB0;
        }

        result = static_cast<std::uint32_t>(copyBytes);
        if (lastSystemHeaderProbe.hasPrimarySystemHeader > 0) {
          headerCaptureView->primaryMpsRawBytes = copyBytes;
          return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(MEM_Copy(
            headerCaptureView->primaryMpsRaw.data(),
            packetAddress,
            static_cast<std::uint32_t>(copyBytes)
          )));
        }

        if (lastSystemHeaderProbe.hasSecondarySystemHeader > 0) {
          headerCaptureView->secondaryMpsRawBytes = copyBytes;
          return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(MEM_Copy(
            headerCaptureView->secondaryMpsRaw.data(),
            packetAddress,
            static_cast<std::uint32_t>(copyBytes)
          )));
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00AD6A00 (FUN_00AD6A00, _sfmps_InitInf)
   *
   * What it does:
   * Initializes one SFMPS parser-runtime block with default sentinel lanes.
   */
  std::int32_t sfmps_InitInf(void* const parserRuntimeAddress)
  {
    auto* const parserRuntime = static_cast<SfmpsParserRuntimeView*>(parserRuntimeAddress);
    *parserRuntime = {};
    parserRuntime->parserField4Default = -1;
    parserRuntime->parserField5Ceiling = static_cast<std::int32_t>(0x7FFFFFFFu);
    parserRuntime->parserField6Low = -1;
    parserRuntime->parserField7High = static_cast<std::int32_t>(0x7FFFFFFFu);
    parserRuntime->parserField9Ceiling = static_cast<std::int32_t>(0x7FFFFFFFu);
    parserRuntime->parserField10Ceiling = static_cast<std::int32_t>(0x7FFFFFFFu);
    parserRuntime->reprocessField11 = -1;
    parserRuntime->reprocessField12 = -1;
    parserRuntime->videoChannel = -1;
    parserRuntime->audioChannel = -1;
    parserRuntime->selectedElementaryLane = -1;
    return 0;
  }

  /**
   * Address: 0x00AD6A70 (FUN_00AD6A70, _SFMPS_Destroy)
   *
   * What it does:
   * Destroys one SFMPS parser handle and reports SFLIB error on destroy failure.
   */
  std::int32_t SFMPS_Destroy(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrSfmpsDestroyFailed = static_cast<std::int32_t>(0xFF000D0Au);
    const auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
    if (sfmps_DestroySub(parserRuntime->parserHandleAddress) != 0) {
      return SFLIB_SetErr(SjPointerToAddress(workctrlSubobj), kSflibErrSfmpsDestroyFailed);
    }
    return 0;
  }

  /**
   * Address: 0x00AD6AB0 (FUN_00AD6AB0, _SFMPS_RequestStop)
   *
   * What it does:
   * No-op request-stop lane for MPEG program-stream transport runtime.
   */
  std::int32_t SFMPS_RequestStop()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6AC0 (FUN_00AD6AC0, _SFMPS_Start)
   *
   * What it does:
   * No-op start lane for MPEG program-stream transport runtime.
   */
  std::int32_t SFMPS_Start()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6AD0 (FUN_00AD6AD0, _SFMPS_Stop)
   *
   * What it does:
   * No-op stop lane for MPEG program-stream transport runtime.
   */
  std::int32_t SFMPS_Stop()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6AE0 (FUN_00AD6AE0, _SFMPS_Pause)
   *
   * What it does:
   * No-op pause lane for MPEG program-stream transport runtime.
   */
  std::int32_t SFMPS_Pause()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6AF0 (FUN_00AD6AF0, _SFMPS_GetWrite)
   *
   * What it does:
   * Reports unsupported parser write-window API for SFMPS.
   */
  std::int32_t SFMPS_GetWrite(const std::int32_t workctrlAddress)
  {
    return SFLIB_SetErr(workctrlAddress, static_cast<std::int32_t>(0xFF000D0Bu));
  }

  /**
   * Address: 0x00AD6B10 (FUN_00AD6B10, _SFMPS_AddWrite)
   *
   * What it does:
   * Reports unsupported parser write-commit API for SFMPS.
   */
  std::int32_t SFMPS_AddWrite(const std::int32_t workctrlAddress)
  {
    return SFLIB_SetErr(workctrlAddress, static_cast<std::int32_t>(0xFF000D0Bu));
  }

  /**
   * Address: 0x00AD6B30 (FUN_00AD6B30, _SFMPS_GetRead)
   *
   * What it does:
   * Reports unsupported parser read-window API for SFMPS.
   */
  std::int32_t SFMPS_GetRead(const std::int32_t workctrlAddress)
  {
    return SFLIB_SetErr(workctrlAddress, static_cast<std::int32_t>(0xFF000D0Bu));
  }

  /**
   * Address: 0x00AD6B50 (FUN_00AD6B50, _SFMPS_AddRead)
   *
   * What it does:
   * Reports unsupported parser read-commit API for SFMPS.
   */
  std::int32_t SFMPS_AddRead(const std::int32_t workctrlAddress)
  {
    return SFLIB_SetErr(workctrlAddress, static_cast<std::int32_t>(0xFF000D0Bu));
  }

  /**
   * Address: 0x00AD6B70 (FUN_00AD6B70, _SFMPS_Seek)
   *
   * What it does:
   * Reprocesses SFMPS headers for seek, then syncs parser/runtime header fields
   * from refreshed SFMPS header state.
   */
  std::int32_t SFMPS_Seek(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    const std::int32_t headerAddress = sfmps_GetHd(workctrlAddress);
    if (headerAddress != 0) {
      auto* const headerRuntime = reinterpret_cast<SfmpsHeaderRuntimeView*>(SjAddressToPointer(headerAddress));
      if (headerRuntime->activeFlag != 0) {
        auto* const runtimeView = reinterpret_cast<SfmpsWorkctrlRuntimeView*>(workctrlSubobj);
        auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
        (void)SFHDS_ReprocessHdr(workctrlAddress);
        (void)sfmps_SetCustomPketLen(workctrlAddress);
        const std::int32_t result =
          sfmps_ReprocessHdr(workctrlAddress, SjPointerToAddress(parserRuntime), headerAddress);
        if (result != 0) {
          return result;
        }

        parserRuntime->reprocessField11 = headerRuntime->parserField11;
        parserRuntime->reprocessField12 = headerRuntime->parserField12;
        runtimeView->seekField0 = headerRuntime->seekField0;
        runtimeView->seekField1 = headerRuntime->seekField1;
        parserRuntime->parserField6Low = headerRuntime->parserField6Low;
        parserRuntime->parserField7High = headerRuntime->parserField7High;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00AD6CA0 (FUN_00AD6CA0, _SFMPS_GetConcatCnt)
   *
   * What it does:
   * Returns current parser-runtime concat counter.
   */
  std::int32_t SFMPS_GetConcatCnt(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return getSfmpsParserRuntime(workctrlSubobj)->concatCount;
  }

  /**
   * Address: 0x00AD6CB0 (FUN_00AD6CB0, _SFMEM_Init)
   *
   * What it does:
   * No-op init lane for memory-supply transport strategy.
   */
  std::int32_t SFMEM_Init()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6CC0 (FUN_00AD6CC0, _SFMEM_Finish)
   *
   * What it does:
   * No-op finalize lane for memory-supply transport strategy.
   */
  std::int32_t SFMEM_Finish()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6CD0 (FUN_00AD6CD0, _SFMEM_ExecServer)
   *
   * What it does:
   * Raises prep flag on the active memory-prep lane selected by workctrl
   * runtime field `+0x1F44`.
   */
  std::int32_t SFMEM_ExecServer(const std::int32_t workctrlAddress)
  {
    const auto* const runtimeView =
      reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    (void)SFBUF_SetPrepFlg(workctrlAddress, runtimeView->memoryPrepLaneIndex, 1);
    return 0;
  }

  /**
   * Address: 0x00AD6CF0 (FUN_00AD6CF0, _SFMEM_Create)
   *
   * What it does:
   * No-op create lane for memory-supply transport strategy.
   */
  std::int32_t SFMEM_Create()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6D00 (FUN_00AD6D00, _SFMEM_Destroy)
   *
   * What it does:
   * No-op destroy lane for memory-supply transport strategy.
   */
  std::int32_t SFMEM_Destroy()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6D10 (FUN_00AD6D10, _SFMEM_RequestStop)
   *
   * What it does:
   * No-op stop-request lane for memory-supply transport strategy.
   */
  std::int32_t SFMEM_RequestStop()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6D20 (FUN_00AD6D20, _SFMEM_Start)
   *
   * What it does:
   * No-op start lane for memory-input transport runtime.
   */
  std::int32_t SFMEM_Start()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6D30 (FUN_00AD6D30, _SFMEM_Stop)
   *
   * What it does:
   * No-op stop lane for memory-input transport runtime.
   */
  std::int32_t SFMEM_Stop()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6D40 (FUN_00AD6D40, _SFMEM_Pause)
   *
   * What it does:
   * No-op pause lane for memory-input transport runtime.
   */
  std::int32_t SFMEM_Pause()
  {
    return 0;
  }

  /**
   * Address: 0x00AD6D50 (FUN_00AD6D50, _SFMEM_GetWrite)
   *
   * What it does:
   * Returns one ring write window for the active memory-prep SFBUF lane.
   */
  std::int32_t SFMEM_GetWrite(const std::int32_t workctrlAddress, std::int32_t* const outCursor)
  {
    const auto* const runtimeView =
      reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    return SFBUF_RingGetWrite(workctrlAddress, runtimeView->memoryPrepLaneIndex, outCursor);
  }

  /**
   * Address: 0x00AD6D70 (FUN_00AD6D70, _SFMEM_AddWrite)
   *
   * What it does:
   * Commits one write advance for the active memory-prep SFBUF lane.
   */
  std::int32_t SFMEM_AddWrite(
    const std::int32_t workctrlAddress,
    const std::int32_t advanceCount,
    const std::int32_t advanceMode
  )
  {
    const auto* const runtimeView =
      reinterpret_cast<const SfmpsWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    (void)advanceMode;
    return SFBUF_RingAddWrite(workctrlAddress, runtimeView->memoryPrepLaneIndex, advanceCount);
  }

  /**
   * Address: 0x00AD6D90 (FUN_00AD6D90, _SFMEM_GetRead)
   *
   * What it does:
   * Reports unsupported memory-supply read-window API.
   */
  std::int32_t SFMEM_GetRead(const std::int32_t workctrlAddress)
  {
    return SFLIB_SetErr(workctrlAddress, static_cast<std::int32_t>(0xFF000501u));
  }

  /**
   * Address: 0x00AD6DB0 (FUN_00AD6DB0, _SFMEM_AddRead)
   *
   * What it does:
   * Reports unsupported memory-supply read-commit API.
   */
  std::int32_t SFMEM_AddRead(const std::int32_t workctrlAddress)
  {
    return SFLIB_SetErr(workctrlAddress, static_cast<std::int32_t>(0xFF000501u));
  }

  /**
   * Address: 0x00AD6DD0 (FUN_00AD6DD0, _SFMEM_Seek)
   *
   * What it does:
   * No-op seek lane for memory-input transport runtime.
   */
  std::int32_t SFMEM_Seek()
  {
    return 0;
  }

  /**
   * Address: 0x00ADDA50 (FUN_00ADDA50, _SFD_SetSpeedRational)
   *
   * What it does:
   * Validates one SFD handle and updates both timer and AOAP speed-rational
   * lanes.
   */
  std::int32_t SFD_SetSpeedRational(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t speedRational
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetSpeedRational = static_cast<std::int32_t>(0xFF000144u);

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetSpeedRational);
    }

    const std::int32_t workctrlAddress = SjPointerToAddress(workctrlSubobj);
    (void)SFTIM_SetSpeed(workctrlAddress, speedRational);
    (void)SFAOAP_SetSpeed(workctrlAddress, speedRational);
    return 0;
  }

  /**
   * Address: 0x00AD6460 (FUN_00AD6460, _sfmps_ProcPrep)
   *
   * What it does:
   * Runs stream-parser preparation flow in fixed order: stream-number resolve,
   * prep-flag validation, movie-info setup, AV-play adjustment, MPS header
   * setup, then audio-stream type selection.
   */
  std::int32_t sfmps_ProcPrep(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    std::int32_t videoStreamIndex = 0;
    std::int32_t audioStreamIndex = 0;
    (void)sfmps_GetStmNum(workctrlSubobj, &videoStreamIndex, &audioStreamIndex);
    (void)sfmps_ChkPrepFlg(workctrlSubobj);
    (void)sfmps_SetMvInf(workctrlSubobj);
    (void)sfmps_AdjustAvPlay(workctrlSubobj);
    (void)sfmps_SetMpsHd(workctrlSubobj);
    return sfmps_SetAudioStreamType(workctrlSubobj);
  }

  /**
   * Address: 0x00AD8DB0 (FUN_00AD8DB0, _SFD_SetErrFn)
   *
   * What it does:
   * Binds one SFLIB error callback to either one specific SFD handle or the
   * global SFLIB error lane.
   */
  std::int32_t SFD_SetErrFn(
    const std::int32_t errorObjectAddress,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    const auto callback = reinterpret_cast<SflibErrorCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackAddress))
    );

    if (errorObjectAddress == 0) {
      (void)sflib_SetErrFnSub(&gSflibLibWork.errInfo, callback, callbackObject);
      return 0;
    }

    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(errorObjectAddress));
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetErrFn);
    }

    auto* const errorOwner =
      reinterpret_cast<SflibErrorOwnerRuntimeView*>(SjAddressToPointer(errorObjectAddress));
    (void)sflib_SetErrFnSub(&errorOwner->errInfo, callback, callbackObject);
    return 0;
  }

  /**
   * Address: 0x00AD8E30 (FUN_00AD8E30, _SFD_GetErrInf)
   *
   * What it does:
   * Copies one SFLIB error-info lane from one specific SFD handle or the global
   * SFLIB lane into caller output storage.
   */
  std::int32_t SFD_GetErrInf(const std::int32_t errorObjectAddress, void* const outErrInfo)
  {
    auto* const outErrorInfo = static_cast<SflibErrorInfo*>(outErrInfo);

    if (errorObjectAddress == 0) {
      std::memcpy(outErrorInfo, &gSflibLibWork.errInfo, sizeof(SflibErrorInfo));
      return 0;
    }

    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(errorObjectAddress));
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetErrInf);
    }

    auto* const errorOwner =
      reinterpret_cast<SflibErrorOwnerRuntimeView*>(SjAddressToPointer(errorObjectAddress));
    std::memcpy(outErrorInfo, &errorOwner->errInfo, sizeof(SflibErrorInfo));
    return 0;
  }

  /**
   * Address: 0x00AD8E10 (FUN_00AD8E10, _sflib_SetErrFnSub)
   *
   * What it does:
   * Stores one SFLIB error callback and callback-object lanes.
   */
  SflibErrorInfo*
  sflib_SetErrFnSub(SflibErrorInfo* const errInfo, SflibErrorCallback const callback, const std::int32_t callbackObject)
  {
    errInfo->callback = callback;
    errInfo->callbackObject = callbackObject;
    return errInfo;
  }

  /**
   * Address: 0x00AD8E90 (FUN_00AD8E90, _SFLIB_CheckHn)
   *
   * What it does:
   * Validates one SFD work-control handle and records last validated handle.
   */
  std::int32_t SFLIB_CheckHn(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (workctrlSubobj == nullptr || workctrlSubobj->handleState == 0) {
      return -1;
    }

    gSfdDebugLastHandle = workctrlSubobj;
    return 0;
  }

  /**
   * Address: 0x00AD6DE0 (FUN_00AD6DE0, _SFPLY_Init)
   *
   * What it does:
   * Initializes SFPLY runtime defaults and clears record-get-frame counter.
   */
  std::int32_t SFPLY_Init()
  {
    const std::int32_t result = sfply_ChkCondDfl();
    SFPLY_recordgetfrm = 0;
    return result;
  }

  /**
   * Address: 0x00AD6DF0 (FUN_00AD6DF0, _sfply_ChkCondDfl)
   *
   * What it does:
   * Latches default-condition validation error code in global SFLIB error lane.
   */
  std::int32_t sfply_ChkCondDfl()
  {
    return SFLIB_SetErr(0, kSflibErrDefaultConditionMissing);
  }

  /**
   * Address: 0x00AD9290 (FUN_00AD9290, _mwSfdVsync)
   *
   * What it does:
   * Advances MWSFD vsync counters, enters one SFD vertical-blank lane while
   * holding `MwsfdLibWork::initLatch`, then releases the latch.
   */
  std::int32_t mwSfdVsync()
  {
    ++mwg_vcnt;
    ++mwsfd_vsync_dispatch_count;

    std::int32_t result = mwsfd_init_flag;
    if (mwsfd_init_flag == 1) {
      auto* const libWork = MWSFLIB_GetLibWorkPtr();
      std::int32_t* const initLatch = &libWork->initLatch;
      result = MWSFSVM_TestAndSet(initLatch);
      if (result == 1) {
        if (mwsfd_init_flag == 1) {
          result = SFD_VbIn();
        }
        *initLatch = 0;
      }
    }

    return result;
  }

  /**
   * Address: 0x00AD6E00 (FUN_00AD6E00, _SFD_VbIn)
   *
   * What it does:
   * Forwards one SFD vertical-blank enter lane to timer runtime.
   */
  std::int32_t SFD_VbIn()
  {
    return SFTIM_VbIn();
  }

  struct SflibTimerStateRuntimeView
  {
    std::int32_t verticalBlankCount = 0; // +0x00
    std::int32_t timerVersion = 0; // +0x04
    std::int32_t ticksPerSecond = 0; // +0x08
  };
  static_assert(sizeof(SflibTimerStateRuntimeView) == 0x0C, "SflibTimerStateRuntimeView size must be 0x0C");

  struct SftimWorkctrlRuntimeView
  {
    std::uint8_t mUnknown00_91F[0x920]{}; // +0x000
    std::int32_t decodeChannelMode = 0; // +0x920
    std::uint8_t mUnknown924_94F[0x2C]{}; // +0x924
    std::int32_t videoLaneEnabled = 0; // +0x950
    std::uint8_t mUnknown954_A47[0xF4]{}; // +0x954
    std::int32_t execComparisonMode = 0; // +0xA48
    std::uint8_t mUnknownA4C_AC3[0x78]{}; // +0xA4C
    std::int32_t executionWindowTicks = 0; // +0xAC4
    std::uint8_t mUnknownAC8_E47[0x380]{}; // +0xAC8
    std::int32_t timeSubScaleEnabled = 0; // +0xE48
    std::uint8_t mUnknownE4C_E6B[0x20]{}; // +0xE4C
    std::int32_t timeSubScaleNumerator = 0; // +0xE6C
    std::int32_t timeSubScaleDenominator = 0; // +0xE70
    std::int32_t timeSubWrapCarryMajor = 0; // +0xE74
    std::int32_t timeSubWrapMinorValue = 0; // +0xE78
    std::uint8_t mUnknownE7C_E93[0x18]{}; // +0xE7C
    std::int32_t perFileTimeQueueEnabled = 0; // +0xE94
    std::int32_t perFileTimeQueueOrdinal = 0; // +0xE98
    std::array<std::int32_t, 32> perFileQueuedTimeMajor{}; // +0xE9C
    std::uint8_t mUnknownF1C_FAB[0x90]{}; // +0xF1C
    std::int32_t videoTermMajor = 0; // +0xFAC
    std::int32_t videoTermMinor = 0; // +0xFB0
    std::uint8_t mUnknownFB4_FBB[0x08]{}; // +0xFB4
    std::int32_t currentTimeMajor = 0; // +0xFBC
    std::int32_t currentTimeMinor = 0; // +0xFC0
    std::uint8_t mUnknownFC4_FD7[0x14]{}; // +0xFC4
    std::int32_t vsyncTimeMajor = 0; // +0xFD8
    std::int32_t timeBaseScale = 0; // +0xFDC
    std::uint8_t mUnknownFE0_FEB[0x0C]{}; // +0xFE0
    std::int32_t graceWindowCounter = 0; // +0xFEC
    float lastLowerSample = 0.0f; // +0xFF0
    std::int32_t lastGraceResult = 0; // +0xFF4
    float lastUpperSample = 0.0f; // +0xFF8
    std::int32_t takeOffExecTimeMajor = 0; // +0xFFC
    std::uint8_t mUnknown1000_1003[0x04]{}; // +0x1000
    std::int32_t externalTimeCallbackAddress = 0; // +0x1004
    std::int32_t previousExternalMajor = 0; // +0x1008
    std::int32_t externalPauseAccumulatedMajor = 0; // +0x100C
    std::int32_t externalReportedMinor = 0; // +0x1010
    std::int32_t externalWrapMinorLimit = 0; // +0x1014
    std::int32_t externalCallbackContext = 0; // +0x1018
  };
  static_assert(offsetof(SftimWorkctrlRuntimeView, decodeChannelMode) == 0x920, "SftimWorkctrlRuntimeView::decodeChannelMode offset must be 0x920");
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, execComparisonMode) == 0xA48,
    "SftimWorkctrlRuntimeView::execComparisonMode offset must be 0xA48"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, executionWindowTicks) == 0xAC4,
    "SftimWorkctrlRuntimeView::executionWindowTicks offset must be 0xAC4"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, timeSubScaleEnabled) == 0xE48,
    "SftimWorkctrlRuntimeView::timeSubScaleEnabled offset must be 0xE48"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, timeSubScaleNumerator) == 0xE6C,
    "SftimWorkctrlRuntimeView::timeSubScaleNumerator offset must be 0xE6C"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, timeSubScaleDenominator) == 0xE70,
    "SftimWorkctrlRuntimeView::timeSubScaleDenominator offset must be 0xE70"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, timeSubWrapCarryMajor) == 0xE74,
    "SftimWorkctrlRuntimeView::timeSubWrapCarryMajor offset must be 0xE74"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, timeSubWrapMinorValue) == 0xE78,
    "SftimWorkctrlRuntimeView::timeSubWrapMinorValue offset must be 0xE78"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, perFileTimeQueueEnabled) == 0xE94,
    "SftimWorkctrlRuntimeView::perFileTimeQueueEnabled offset must be 0xE94"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, perFileTimeQueueOrdinal) == 0xE98,
    "SftimWorkctrlRuntimeView::perFileTimeQueueOrdinal offset must be 0xE98"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, perFileQueuedTimeMajor) == 0xE9C,
    "SftimWorkctrlRuntimeView::perFileQueuedTimeMajor offset must be 0xE9C"
  );
  static_assert(offsetof(SftimWorkctrlRuntimeView, videoLaneEnabled) == 0x950, "SftimWorkctrlRuntimeView::videoLaneEnabled offset must be 0x950");
  static_assert(offsetof(SftimWorkctrlRuntimeView, videoTermMajor) == 0xFAC, "SftimWorkctrlRuntimeView::videoTermMajor offset must be 0xFAC");
  static_assert(offsetof(SftimWorkctrlRuntimeView, videoTermMinor) == 0xFB0, "SftimWorkctrlRuntimeView::videoTermMinor offset must be 0xFB0");
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, currentTimeMajor) == 0xFBC,
    "SftimWorkctrlRuntimeView::currentTimeMajor offset must be 0xFBC"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, currentTimeMinor) == 0xFC0,
    "SftimWorkctrlRuntimeView::currentTimeMinor offset must be 0xFC0"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, vsyncTimeMajor) == 0xFD8,
    "SftimWorkctrlRuntimeView::vsyncTimeMajor offset must be 0xFD8"
  );
  static_assert(offsetof(SftimWorkctrlRuntimeView, timeBaseScale) == 0xFDC, "SftimWorkctrlRuntimeView::timeBaseScale offset must be 0xFDC");
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, graceWindowCounter) == 0xFEC,
    "SftimWorkctrlRuntimeView::graceWindowCounter offset must be 0xFEC"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, lastLowerSample) == 0xFF0,
    "SftimWorkctrlRuntimeView::lastLowerSample offset must be 0xFF0"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, lastGraceResult) == 0xFF4,
    "SftimWorkctrlRuntimeView::lastGraceResult offset must be 0xFF4"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, lastUpperSample) == 0xFF8,
    "SftimWorkctrlRuntimeView::lastUpperSample offset must be 0xFF8"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, takeOffExecTimeMajor) == 0xFFC,
    "SftimWorkctrlRuntimeView::takeOffExecTimeMajor offset must be 0xFFC"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, externalTimeCallbackAddress) == 0x1004,
    "SftimWorkctrlRuntimeView::externalTimeCallbackAddress offset must be 0x1004"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, previousExternalMajor) == 0x1008,
    "SftimWorkctrlRuntimeView::previousExternalMajor offset must be 0x1008"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, externalPauseAccumulatedMajor) == 0x100C,
    "SftimWorkctrlRuntimeView::externalPauseAccumulatedMajor offset must be 0x100C"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, externalReportedMinor) == 0x1010,
    "SftimWorkctrlRuntimeView::externalReportedMinor offset must be 0x1010"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, externalWrapMinorLimit) == 0x1014,
    "SftimWorkctrlRuntimeView::externalWrapMinorLimit offset must be 0x1014"
  );
  static_assert(
    offsetof(SftimWorkctrlRuntimeView, externalCallbackContext) == 0x1018,
    "SftimWorkctrlRuntimeView::externalCallbackContext offset must be 0x1018"
  );

  using SftimGetNowTimeFunction =
    std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t* outTimeMajor, std::int32_t* outTimeMinor);
  using SftimExternalTimeCallback =
    std::int32_t(__cdecl*)(std::int32_t callbackContext, std::int32_t* outExternalMajor, std::int32_t* outExternalMinor);
  struct SftimTimecodeRuntimeView
  {
    std::uint8_t words[0x20]{}; // +0x00
  };
  static_assert(sizeof(SftimTimecodeRuntimeView) == 0x20, "SftimTimecodeRuntimeView size must be 0x20");

  struct SftimTtuRuntimeView
  {
    std::uint32_t state = 0; // +0x00
    SftimTimecodeRuntimeView timecode{}; // +0x04
    std::int32_t timeMajor = 0; // +0x24
    std::int32_t timeMinor = 0; // +0x28
  };
  static_assert(offsetof(SftimTtuRuntimeView, state) == 0x00, "SftimTtuRuntimeView::state offset must be 0x00");
  static_assert(offsetof(SftimTtuRuntimeView, timecode) == 0x04, "SftimTtuRuntimeView::timecode offset must be 0x04");
  static_assert(offsetof(SftimTtuRuntimeView, timeMajor) == 0x24, "SftimTtuRuntimeView::timeMajor offset must be 0x24");
  static_assert(offsetof(SftimTtuRuntimeView, timeMinor) == 0x28, "SftimTtuRuntimeView::timeMinor offset must be 0x28");
  static_assert(sizeof(SftimTtuRuntimeView) == 0x2C, "SftimTtuRuntimeView size must be 0x2C");

  struct SftimTimecodeLaneView
  {
    std::int32_t frameRateIndex = 0; // +0x00
    std::int32_t modeIndex = 0; // +0x04
    std::int32_t hours = 0; // +0x08
    std::int32_t minutes = 0; // +0x0C
    std::int32_t seconds = 0; // +0x10
    std::int32_t frameNumber = 0; // +0x14
    std::int32_t halfFrameCarry = 0; // +0x18
    std::int16_t repeatFieldCount = 0; // +0x1C
    std::int16_t repeatFieldAccumulated = 0; // +0x1E
  };
  static_assert(
    offsetof(SftimTimecodeLaneView, frameRateIndex) == 0x00,
    "SftimTimecodeLaneView::frameRateIndex offset must be 0x00"
  );
  static_assert(offsetof(SftimTimecodeLaneView, modeIndex) == 0x04, "SftimTimecodeLaneView::modeIndex offset must be 0x04");
  static_assert(offsetof(SftimTimecodeLaneView, hours) == 0x08, "SftimTimecodeLaneView::hours offset must be 0x08");
  static_assert(offsetof(SftimTimecodeLaneView, minutes) == 0x0C, "SftimTimecodeLaneView::minutes offset must be 0x0C");
  static_assert(offsetof(SftimTimecodeLaneView, seconds) == 0x10, "SftimTimecodeLaneView::seconds offset must be 0x10");
  static_assert(offsetof(SftimTimecodeLaneView, frameNumber) == 0x14, "SftimTimecodeLaneView::frameNumber offset must be 0x14");
  static_assert(
    offsetof(SftimTimecodeLaneView, halfFrameCarry) == 0x18,
    "SftimTimecodeLaneView::halfFrameCarry offset must be 0x18"
  );
  static_assert(
    offsetof(SftimTimecodeLaneView, repeatFieldCount) == 0x1C,
    "SftimTimecodeLaneView::repeatFieldCount offset must be 0x1C"
  );
  static_assert(
    offsetof(SftimTimecodeLaneView, repeatFieldAccumulated) == 0x1E,
    "SftimTimecodeLaneView::repeatFieldAccumulated offset must be 0x1E"
  );
  static_assert(sizeof(SftimTimecodeLaneView) == 0x20, "SftimTimecodeLaneView size must be 0x20");

  using SftimTc2TimeFunction = std::int32_t(__cdecl*)(
    std::int32_t frameRateUnits,
    SftimTimecodeLaneView* timecodeLane,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );

  extern "C" std::int32_t SFTIM_prate[];
  extern "C" SftimTc2TimeFunction sftim_tc2time[];
  extern "C" std::int32_t SFTIM_InitTcode(void* timecodeState);
  extern "C" std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue);
  extern std::int64_t sftim_as_pts;
  extern std::int32_t sftim_a_sample;
  extern std::int32_t sftim_v_time;
  extern std::int32_t sftim_v_sample;

  /**
   * Address: 0x00ADBA10 (FUN_00ADBA10, _SFD_GetFps)
   *
   * What it does:
   * Validates one SFD handle, then resolves the timer frame-rate lane through
   * `SFTIM_prate`; writes `-1` when the lane is not available.
   */
  std::int32_t
  SFD_GetFps(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, std::int32_t* const outFramesPerSecond)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetFps = static_cast<std::int32_t>(0xFF00011Bu);

    *outFramesPerSecond = -1;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetFps);
    }

    const auto* const timerView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t frameRateIndex = timerView->decodeChannelMode;
    if (frameRateIndex != 0) {
      *outFramesPerSecond = SFTIM_prate[frameRateIndex];
    }

    return 0;
  }

  /**
   * Address: 0x00ADBA60 (FUN_00ADBA60, _SFD_GetPlayFps)
   *
   * What it does:
   * Validates one SFD handle and reports effective playback FPS derived from
   * timer frame-rate and time-base scale lanes.
   */
  std::int32_t SFD_GetPlayFps(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outPlayFramesPerSecond
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetPlayFps = static_cast<std::int32_t>(0xFF000118u);

    *outPlayFramesPerSecond = -1;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetPlayFps);
    }

    const auto* const timerView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t frameRateIndex = timerView->decodeChannelMode;
    if (frameRateIndex != 0) {
      *outPlayFramesPerSecond = UTY_MulDiv(SFTIM_prate[frameRateIndex], timerView->timeBaseScale, 1000);
    }

    return 0;
  }

  struct SfdOutputSyncRuntimeView
  {
    std::uint8_t reserved0000_0043[0x44]{}; // +0x0000
    std::int32_t outputSyncDirtyFlag = 0; // +0x0044
    std::uint8_t reserved0048_0FD3[0xF8C]{}; // +0x0048
    std::int32_t userFrameSyncSequence = 0; // +0x0FD4
    std::uint8_t reserved0FD8_0FDF[0x08]{}; // +0x0FD8
    std::int32_t displaySyncSequence = 0; // +0x0FE0
    std::int32_t displaySyncTimeMajor = 0; // +0x0FE4
    std::int32_t displaySyncTimeMinor = 0; // +0x0FE8
  };
  static_assert(
    offsetof(SfdOutputSyncRuntimeView, outputSyncDirtyFlag) == 0x44,
    "SfdOutputSyncRuntimeView::outputSyncDirtyFlag offset must be 0x44"
  );
  static_assert(
    offsetof(SfdOutputSyncRuntimeView, userFrameSyncSequence) == 0xFD4,
    "SfdOutputSyncRuntimeView::userFrameSyncSequence offset must be 0xFD4"
  );
  static_assert(
    offsetof(SfdOutputSyncRuntimeView, displaySyncSequence) == 0xFE0,
    "SfdOutputSyncRuntimeView::displaySyncSequence offset must be 0xFE0"
  );
  static_assert(
    offsetof(SfdOutputSyncRuntimeView, displaySyncTimeMajor) == 0xFE4,
    "SfdOutputSyncRuntimeView::displaySyncTimeMajor offset must be 0xFE4"
  );
  static_assert(
    offsetof(SfdOutputSyncRuntimeView, displaySyncTimeMinor) == 0xFE8,
    "SfdOutputSyncRuntimeView::displaySyncTimeMinor offset must be 0xFE8"
  );

  /**
   * Address: 0x00ADB350 (FUN_00ADB350, _SFD_OutUsrFrmSync)
   *
   * What it does:
   * Validates one SFD handle, increments user-frame sync sequence lane, and
   * marks output-sync state as dirty.
   */
  std::int32_t SFD_OutUsrFrmSync(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrInvalidHandleOutUserFrameSync = static_cast<std::int32_t>(0xFF000122u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleOutUserFrameSync);
    }

    auto* const syncView = reinterpret_cast<SfdOutputSyncRuntimeView*>(workctrlSubobj);
    ++syncView->userFrameSyncSequence;
    syncView->outputSyncDirtyFlag = 1;
    return 0;
  }

  /**
   * Address: 0x00ADBB30 (FUN_00ADBB30, _SFD_OutDispSync)
   *
   * What it does:
   * Validates one SFD handle, stores display-sync time lanes, increments the
   * display-sync sequence lane, and marks output-sync state as dirty.
   */
  std::int32_t SFD_OutDispSync(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t displayTimeMajor,
    const std::int32_t displayTimeMinor
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleOutDisplaySync = static_cast<std::int32_t>(0xFF000125u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleOutDisplaySync);
    }

    auto* const syncView = reinterpret_cast<SfdOutputSyncRuntimeView*>(workctrlSubobj);
    ++syncView->displaySyncSequence;
    syncView->displaySyncTimeMajor = displayTimeMajor;
    syncView->displaySyncTimeMinor = displayTimeMinor;
    syncView->outputSyncDirtyFlag = 1;
    return 0;
  }

  struct SftimVblankCounterLaneView
  {
    std::array<SftimGetNowTimeFunction, 6> nowTimeFunctions{}; // +0x000
    std::uint8_t mUnknown018_28B[0x274]{}; // +0x018
    std::int32_t lastTimerMajor = 0; // +0x28C
    std::int32_t lastTimerMinor = 0; // +0x290
    std::uint8_t mUnknown294_2A7[0x14]{}; // +0x294
    std::int32_t accumulatedTicks = 0; // +0x2A8
    std::int32_t tickStep = 0; // +0x2AC
    std::uint8_t mUnknown2B0_2CB[0x1C]{}; // +0x2B0
    std::int32_t vblankStateTicks = 0; // +0x2CC
    std::int32_t currentVtimeMajor = 0; // +0x2D0
    SftimExternalTimeCallback externalTimeCallback = nullptr; // +0x2D4
    std::int32_t previousExternalMinor = 0; // +0x2D8
    std::int32_t externalAccumulatedMajor = 0; // +0x2DC
    std::int32_t externalReportedMinor = 0; // +0x2E0
    std::int32_t externalWrapMinorLimit = 0; // +0x2E4
    std::int32_t externalCallbackContext = 0; // +0x2E8
    std::uint8_t mUnknown2EC_5AF[0x2C4]{}; // +0x2EC
    std::int32_t initScratchWord0 = 0; // +0x5B0
    std::int32_t initScratchWord1 = 0; // +0x5B4
    std::int32_t initScratchWord2 = 0; // +0x5B8
  };
  static_assert(
    offsetof(SftimVblankCounterLaneView, nowTimeFunctions) == 0x00,
    "SftimVblankCounterLaneView::nowTimeFunctions offset must be 0x00"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, lastTimerMajor) == 0x28C,
    "SftimVblankCounterLaneView::lastTimerMajor offset must be 0x28C"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, lastTimerMinor) == 0x290,
    "SftimVblankCounterLaneView::lastTimerMinor offset must be 0x290"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, accumulatedTicks) == 0x2A8,
    "SftimVblankCounterLaneView::accumulatedTicks offset must be 0x2A8"
  );
  static_assert(offsetof(SftimVblankCounterLaneView, tickStep) == 0x2AC, "SftimVblankCounterLaneView::tickStep offset must be 0x2AC");
  static_assert(
    offsetof(SftimVblankCounterLaneView, vblankStateTicks) == 0x2CC,
    "SftimVblankCounterLaneView::vblankStateTicks offset must be 0x2CC"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, currentVtimeMajor) == 0x2D0,
    "SftimVblankCounterLaneView::currentVtimeMajor offset must be 0x2D0"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, externalTimeCallback) == 0x2D4,
    "SftimVblankCounterLaneView::externalTimeCallback offset must be 0x2D4"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, previousExternalMinor) == 0x2D8,
    "SftimVblankCounterLaneView::previousExternalMinor offset must be 0x2D8"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, externalAccumulatedMajor) == 0x2DC,
    "SftimVblankCounterLaneView::externalAccumulatedMajor offset must be 0x2DC"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, externalReportedMinor) == 0x2E0,
    "SftimVblankCounterLaneView::externalReportedMinor offset must be 0x2E0"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, externalWrapMinorLimit) == 0x2E4,
    "SftimVblankCounterLaneView::externalWrapMinorLimit offset must be 0x2E4"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, externalCallbackContext) == 0x2E8,
    "SftimVblankCounterLaneView::externalCallbackContext offset must be 0x2E8"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, initScratchWord0) == 0x5B0,
    "SftimVblankCounterLaneView::initScratchWord0 offset must be 0x5B0"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, initScratchWord1) == 0x5B4,
    "SftimVblankCounterLaneView::initScratchWord1 offset must be 0x5B4"
  );
  static_assert(
    offsetof(SftimVblankCounterLaneView, initScratchWord2) == 0x5B8,
    "SftimVblankCounterLaneView::initScratchWord2 offset must be 0x5B8"
  );
  static_assert(sizeof(SftimVblankCounterLaneView) == 0x5BC, "SftimVblankCounterLaneView size must be 0x5BC");

  struct SftimInitHandleRuntimeView
  {
    std::array<SftimGetNowTimeFunction, 6> nowTimeFunctions{}; // +0x000
    std::int32_t activeTimeMode = 0; // +0x018
    SftimTimecodeRuntimeView activeTimecode{}; // +0x01C
    SftimTtuRuntimeView ttuLaneA{}; // +0x03C
    SftimTtuRuntimeView ttuLaneB{}; // +0x068
    SftimTtuRuntimeView ttuLaneC{}; // +0x094
    SftimTtuRuntimeView ttuLaneD{}; // +0x0C0
    SftimTtuRuntimeView ttuLaneE{}; // +0x0EC
    SftimTtuRuntimeView ttuLaneF{}; // +0x118
    std::int32_t startTimeMajor = 0; // +0x144
    std::int32_t startTimeMinor = 0; // +0x148
    std::uint8_t reserved14C_14F[0x04]{}; // +0x14C
    std::int32_t resetMajorA = 0; // +0x150
    std::int32_t resetMinorA = 0; // +0x154
    std::int32_t resetMajorB = 0; // +0x158
    std::int32_t resetMinorB = 0; // +0x15C
    std::int32_t resetMajorC = 0; // +0x160
    std::int32_t resetMinorC = 0; // +0x164
    std::int32_t resetWord168 = 0; // +0x168
    std::array<std::uint8_t, 0x80> resetBufferA{}; // +0x16C
    std::int32_t resetWord1EC = 0; // +0x1EC
    std::int32_t resetWord1F0 = 0; // +0x1F0
    std::int32_t resetWord1F4 = 0; // +0x1F4
    std::int32_t resetWord1F8 = 0; // +0x1F8
    std::array<std::uint8_t, 0x80> resetBufferB{}; // +0x1FC
    std::int32_t defaultMajorA = 0; // +0x27C
    std::int32_t defaultMinorA = 0; // +0x280
    std::int32_t defaultMajorB = 0; // +0x284
    std::int32_t defaultMinorB = 0; // +0x288
    std::int32_t lastTimerMajor = 0; // +0x28C
    std::int32_t lastTimerMinor = 0; // +0x290
    std::int32_t defaultMajorC = 0; // +0x294
    std::int32_t wrapMajorA = 0; // +0x298
    std::int32_t wrapMinorA = 0; // +0x29C
    std::int32_t wrapMajorB = 0; // +0x2A0
    std::int32_t wrapMinorB = 0; // +0x2A4
    std::int32_t accumulatedTicks = 0; // +0x2A8
    std::int32_t tickStep = 0; // +0x2AC
    std::int32_t playbackWord2B0 = 0; // +0x2B0
    std::int32_t playbackWord2B4 = 0; // +0x2B4
    std::int32_t playbackWord2B8 = 0; // +0x2B8
    std::int32_t playbackWord2BC = 0; // +0x2BC
    float lowerSample = 0.0f; // +0x2C0
    std::int32_t playbackWord2C4 = 0; // +0x2C4
    float upperSample = 0.0f; // +0x2C8
    std::int32_t vblankStateTicks = 0; // +0x2CC
    std::int32_t currentVtimeMajor = 0; // +0x2D0
    SftimExternalTimeCallback externalTimeCallback = nullptr; // +0x2D4
    std::int32_t previousExternalMinor = 0; // +0x2D8
    std::int32_t externalAccumulatedMajor = 0; // +0x2DC
    std::int32_t externalReportedMinor = 0; // +0x2E0
    std::int32_t externalWrapMinorLimit = 0; // +0x2E4
    std::int32_t externalCallbackContext = 0; // +0x2E8
    std::array<std::uint8_t, 0x2C4> reserved2EC_5AF{}; // +0x2EC
    std::int32_t initScratchWord0 = 0; // +0x5B0
    std::int32_t initScratchWord1 = 0; // +0x5B4
    std::int32_t initScratchWord2 = 0; // +0x5B8
  };
  static_assert(offsetof(SftimInitHandleRuntimeView, activeTimeMode) == 0x18, "SftimInitHandleRuntimeView::activeTimeMode offset must be 0x18");
  static_assert(
    offsetof(SftimInitHandleRuntimeView, activeTimecode) == 0x1C,
    "SftimInitHandleRuntimeView::activeTimecode offset must be 0x1C"
  );
  static_assert(offsetof(SftimInitHandleRuntimeView, ttuLaneA) == 0x3C, "SftimInitHandleRuntimeView::ttuLaneA offset must be 0x3C");
  static_assert(offsetof(SftimInitHandleRuntimeView, ttuLaneD) == 0xC0, "SftimInitHandleRuntimeView::ttuLaneD offset must be 0xC0");
  static_assert(offsetof(SftimInitHandleRuntimeView, ttuLaneF) == 0x118, "SftimInitHandleRuntimeView::ttuLaneF offset must be 0x118");
  static_assert(
    offsetof(SftimInitHandleRuntimeView, accumulatedTicks) == 0x2A8,
    "SftimInitHandleRuntimeView::accumulatedTicks offset must be 0x2A8"
  );
  static_assert(offsetof(SftimInitHandleRuntimeView, tickStep) == 0x2AC, "SftimInitHandleRuntimeView::tickStep offset must be 0x2AC");
  static_assert(
    offsetof(SftimInitHandleRuntimeView, externalTimeCallback) == 0x2D4,
    "SftimInitHandleRuntimeView::externalTimeCallback offset must be 0x2D4"
  );
  static_assert(
    offsetof(SftimInitHandleRuntimeView, externalWrapMinorLimit) == 0x2E4,
    "SftimInitHandleRuntimeView::externalWrapMinorLimit offset must be 0x2E4"
  );
  static_assert(
    offsetof(SftimInitHandleRuntimeView, externalCallbackContext) == 0x2E8,
    "SftimInitHandleRuntimeView::externalCallbackContext offset must be 0x2E8"
  );
  static_assert(
    offsetof(SftimInitHandleRuntimeView, initScratchWord0) == 0x5B0,
    "SftimInitHandleRuntimeView::initScratchWord0 offset must be 0x5B0"
  );
  static_assert(sizeof(SftimInitHandleRuntimeView) == 0x5BC, "SftimInitHandleRuntimeView size must be 0x5BC");

  struct SftimWorkctrlTickFlagsView
  {
    std::uint8_t mUnknown00_43[0x44]{}; // +0x00
    std::int32_t tickUpdatedFlag = 0;   // +0x44
  };
  static_assert(
    offsetof(SftimWorkctrlTickFlagsView, tickUpdatedFlag) == 0x44,
    "SftimWorkctrlTickFlagsView::tickUpdatedFlag offset must be 0x44"
  );

  struct SfdDrawTimeRuntimeView
  {
    std::uint8_t mUnknown00_4B[0x4C]{}; // +0x00
    std::int32_t playbackStatusLane = 0; // +0x4C
  };
  static_assert(
    offsetof(SfdDrawTimeRuntimeView, playbackStatusLane) == 0x4C,
    "SfdDrawTimeRuntimeView::playbackStatusLane offset must be 0x4C"
  );

  struct SftimStatusGateRuntimeView
  {
    std::uint8_t mUnknown00_47[0x48]{}; // +0x00
    std::int32_t statusLane = 0; // +0x48
    std::int32_t phaseLane = 0; // +0x4C
    std::int32_t startupGateFlag = 0; // +0x50
    std::uint8_t mUnknown54_96F[0x91C]{}; // +0x54
    std::int32_t timerFreezeFlag = 0; // +0x970
  };
  static_assert(
    offsetof(SftimStatusGateRuntimeView, statusLane) == 0x48,
    "SftimStatusGateRuntimeView::statusLane offset must be 0x48"
  );
  static_assert(
    offsetof(SftimStatusGateRuntimeView, phaseLane) == 0x4C,
    "SftimStatusGateRuntimeView::phaseLane offset must be 0x4C"
  );
  static_assert(
    offsetof(SftimStatusGateRuntimeView, startupGateFlag) == 0x50,
    "SftimStatusGateRuntimeView::startupGateFlag offset must be 0x50"
  );
  static_assert(
    offsetof(SftimStatusGateRuntimeView, timerFreezeFlag) == 0x970,
    "SftimStatusGateRuntimeView::timerFreezeFlag offset must be 0x970"
  );

  struct SftimFrameReadyWindowView
  {
    std::uint8_t mUnknown00_13[0x14]{}; // +0x00
    float frameStartTime = 0.0f; // +0x14
    float frameEndTime = 0.0f; // +0x18
  };
  static_assert(
    offsetof(SftimFrameReadyWindowView, frameStartTime) == 0x14,
    "SftimFrameReadyWindowView::frameStartTime offset must be 0x14"
  );
  static_assert(
    offsetof(SftimFrameReadyWindowView, frameEndTime) == 0x18,
    "SftimFrameReadyWindowView::frameEndTime offset must be 0x18"
  );

  struct SftimAudioStartSampleRuntimeView
  {
    std::uint8_t mUnknown00_157[0x158]{};
    std::int64_t audioStartPts90k = -1; // +0x158
  };
  static_assert(
    offsetof(SftimAudioStartSampleRuntimeView, audioStartPts90k) == 0x158,
    "SftimAudioStartSampleRuntimeView::audioStartPts90k offset must be 0x158"
  );

  struct SftimVideoStartSampleRuntimeView
  {
    std::array<std::uint8_t, 0x110> reserved00_10F{};
    std::int32_t fallbackTimeMajor = -1; // +0x110
    std::int32_t fallbackTimeMinor = 0; // +0x114
    std::int32_t hasExplicitStartTime = 0; // +0x118
    std::array<std::uint8_t, 0x20> reserved11C_13B{};
    std::int32_t explicitTimeMajor = 0; // +0x13C
    std::int32_t explicitTimeMinor = 1; // +0x140
  };
  static_assert(
    offsetof(SftimVideoStartSampleRuntimeView, fallbackTimeMajor) == 0x110,
    "SftimVideoStartSampleRuntimeView::fallbackTimeMajor offset must be 0x110"
  );
  static_assert(
    offsetof(SftimVideoStartSampleRuntimeView, fallbackTimeMinor) == 0x114,
    "SftimVideoStartSampleRuntimeView::fallbackTimeMinor offset must be 0x114"
  );
  static_assert(
    offsetof(SftimVideoStartSampleRuntimeView, hasExplicitStartTime) == 0x118,
    "SftimVideoStartSampleRuntimeView::hasExplicitStartTime offset must be 0x118"
  );
  static_assert(
    offsetof(SftimVideoStartSampleRuntimeView, explicitTimeMajor) == 0x13C,
    "SftimVideoStartSampleRuntimeView::explicitTimeMajor offset must be 0x13C"
  );
  static_assert(
    offsetof(SftimVideoStartSampleRuntimeView, explicitTimeMinor) == 0x140,
    "SftimVideoStartSampleRuntimeView::explicitTimeMinor offset must be 0x140"
  );
  static_assert(sizeof(SftimVideoStartSampleRuntimeView) == 0x144, "SftimVideoStartSampleRuntimeView size must be 0x144");

  std::int32_t sftim_CntupHnVbIn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sftim_UpdateTime(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sftim_HnVbIn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFTIM_InitHn(std::int32_t workctrlAddress, void* timerHandleAddress);
  std::int32_t SFTIM_ChkRegularTime(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t SFTIM_GetTimeSub(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t SFD_GetTimeAfterSeek(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t SFD_GetNowTime(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t SFTIM_GetNowTime(
    std::int32_t workctrlAddress,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t sftim_GetTimeNone(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t sftim_GetTimeVsync(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t sftim_GetTimeUfrm(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t sftim_GetTimeExtClock(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t sftim_IsTimeIncre(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t
  sftim_IsVbinStIncre(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, SftimVblankCounterLaneView* counterLane);
  std::int32_t
  sftim_ResetVtimeTmr(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, SftimVblankCounterLaneView* counterLane);
  void sftim_GetVtimeTmr(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    SftimVblankCounterLaneView* counterLane,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  /**
   * Address: 0x00ADAF30 (FUN_00ADAF30, _SFTIM_GetAudioStartSample)
   *
   * What it does:
   * Converts one ADXT audio-start PTS lane (90 kHz clock) to start sample at
   * requested sample rate and caches both PTS and sample in global lanes.
   */
  std::int32_t SFTIM_GetAudioStartSample(void* adxtRuntime, std::int32_t audioSampleRate);
  /**
   * Address: 0x00ADAF90 (FUN_00ADAF90, _SFTIM_GetVideoStartSample)
   *
   * What it does:
   * Converts one ADXT video-start time lane to sample index, reports whether
   * explicit start-time lanes were used, and updates global video timing
   * caches.
   */
  std::int32_t SFTIM_GetVideoStartSample(void* adxtRuntime, std::int32_t audioSampleRate, std::int32_t* outHasExplicitStartTime);
  /**
   * Address: 0x00ADAFF0 (FUN_00ADAFF0, _SFTIM_SetStartTime)
   *
   * What it does:
   * Stores one per-handle playback start-time pair.
   */
  std::int32_t
  SFTIM_SetStartTime(const std::int32_t workctrlAddress, const std::int32_t startTimeMajor, const std::int32_t startTimeMinor);
  std::int32_t SFTIM_IsGetFrmTime(const std::int32_t workctrlAddress, const std::int32_t frameReadyWindowAddress);

  /**
   * Address: 0x00ADA9C0 (FUN_00ADA9C0, _SFTIM_Init)
   *
   * What it does:
   * Initializes global SFLIB timer lanes and stores caller timer-version tag.
   */
  void SFTIM_Init(void* const timerState, const std::int32_t versionTag)
  {
    auto* const timerView = static_cast<SflibTimerStateRuntimeView*>(timerState);
    timerView->verticalBlankCount = 0;
    timerView->timerVersion = 0;
    timerView->ticksPerSecond = versionTag;
  }

  /**
   * Address: 0x00ADA9E0 (FUN_00ADA9E0, _SFTIM_Finish)
   *
   * What it does:
   * Finalizes global timer runtime (no-op in this build).
   */
  void SFTIM_Finish(void* const timerState)
  {
    (void)timerState;
  }

  /**
   * Address: 0x00ADAED0 (FUN_00ADAED0, _sftim_GetVtimeTmr)
   *
   * What it does:
   * Returns the active VTime major/minor pair from either the VBlank
   * accumulation lane or the external-clock lane, depending on condition `71`.
   */
  void sftim_GetVtimeTmr(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    SftimVblankCounterLaneView* const counterLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    if (SFSET_GetCond(workctrlSubobj, 71) == 1) {
      *outTimeMajor = counterLane->accumulatedTicks - counterLane->currentVtimeMajor;
      const auto* const timerState = reinterpret_cast<const SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
      *outTimeMinor = (timerState != nullptr) ? timerState->timerVersion : 0;
      return;
    }

    *outTimeMajor = counterLane->externalAccumulatedMajor - counterLane->currentVtimeMajor;
    *outTimeMinor = counterLane->externalReportedMinor;
  }

  /**
   * Address: 0x00ADB600 (FUN_00ADB600, _SFTIM_SetTimeFn)
   *
   * What it does:
   * Stores one time-source callback in the per-handle timer callback table slot
   * selected by `timeModeIndex`.
   */
  std::int32_t
  SFTIM_SetTimeFn(const std::int32_t workctrlAddress, const std::int32_t callbackAddress, const std::int32_t timeModeIndex)
  {
    auto* const counterLane = reinterpret_cast<SftimVblankCounterLaneView*>(SjAddressToPointer(workctrlAddress));
    counterLane->nowTimeFunctions[static_cast<std::size_t>(timeModeIndex)] = reinterpret_cast<SftimGetNowTimeFunction>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackAddress))
    );
    return timeModeIndex;
  }

  [[nodiscard]] static std::int32_t SftimFunctionAddress(const SftimGetNowTimeFunction callback) noexcept
  {
    return static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(callback)));
  }

  /**
   * Address: 0x00ADA9F0 (FUN_00ADA9F0, _SFTIM_InitHn)
   *
   * What it does:
   * Initializes one per-handle timer runtime lane, binds default time-source
   * callbacks, clears playback-time history buffers, and restores sentinel
   * timing lanes used by external clock and VBlank timing paths.
   */
  std::int32_t SFTIM_InitHn(const std::int32_t workctrlAddress, void* const timerHandleAddress)
  {
    auto* const timerHandle = static_cast<SftimInitHandleRuntimeView*>(timerHandleAddress);

    (void)SFTIM_SetTimeFn(workctrlAddress, SftimFunctionAddress(sftim_GetTimeNone), 0);
    (void)SFTIM_SetTimeFn(workctrlAddress, SftimFunctionAddress(sftim_GetTimeVsync), 1);
    (void)SFTIM_SetTimeFn(workctrlAddress, 0, 2);
    (void)SFTIM_SetTimeFn(workctrlAddress, SftimFunctionAddress(sftim_GetTimeUfrm), 3);
    (void)SFTIM_SetTimeFn(workctrlAddress, 0, 4);
    (void)SFTIM_SetTimeFn(workctrlAddress, SftimFunctionAddress(sftim_GetTimeExtClock), 5);

    timerHandle->activeTimeMode = 0;
    (void)SFTIM_InitTcode(&timerHandle->activeTimecode);
    (void)SFTIM_InitTtu(reinterpret_cast<std::uint32_t*>(&timerHandle->ttuLaneD), 0);
    (void)SFTIM_InitTtu(reinterpret_cast<std::uint32_t*>(&timerHandle->ttuLaneA), 0x7FFFFFFF);
    (void)SFTIM_InitTtu(reinterpret_cast<std::uint32_t*>(&timerHandle->ttuLaneB), -1);
    (void)SFTIM_InitTtu(reinterpret_cast<std::uint32_t*>(&timerHandle->ttuLaneC), -1);
    (void)SFTIM_InitTtu(reinterpret_cast<std::uint32_t*>(&timerHandle->ttuLaneE), -1);
    (void)SFTIM_InitTtu(reinterpret_cast<std::uint32_t*>(&timerHandle->ttuLaneF), 0x7FFFFFFF);

    timerHandle->startTimeMajor = 0;
    timerHandle->startTimeMinor = 0;
    timerHandle->resetMajorA = -1;
    timerHandle->resetMinorA = -1;
    timerHandle->resetMajorB = -1;
    timerHandle->resetMinorB = -1;
    timerHandle->resetMajorC = 0;
    timerHandle->resetMinorC = 0;
    timerHandle->resetWord168 = 0;
    std::memset(timerHandle->resetBufferA.data(), 0, timerHandle->resetBufferA.size());

    timerHandle->resetWord1EC = 1;
    timerHandle->resetWord1F0 = 0;
    timerHandle->resetWord1F4 = 0;
    timerHandle->resetWord1F8 = 0;
    std::memset(timerHandle->resetBufferB.data(), 0, timerHandle->resetBufferB.size());

    timerHandle->accumulatedTicks = 0;
    timerHandle->lowerSample = -1.0f;
    timerHandle->upperSample = -1.0f;
    timerHandle->vblankStateTicks = -1;
    timerHandle->externalWrapMinorLimit = -1;
    timerHandle->defaultMajorA = -5;
    timerHandle->defaultMinorA = 1;
    timerHandle->defaultMajorB = -5;
    timerHandle->defaultMinorB = 1;
    timerHandle->lastTimerMajor = -1;
    timerHandle->lastTimerMinor = 1;
    timerHandle->defaultMajorC = -5;
    timerHandle->wrapMajorA = 0x7FFFFFFF;
    timerHandle->wrapMinorA = 0;
    timerHandle->wrapMajorB = 0x7FFFFFFF;
    timerHandle->wrapMinorB = 0;
    timerHandle->tickStep = 1000;
    timerHandle->playbackWord2B0 = 0;
    timerHandle->playbackWord2B4 = 0;
    timerHandle->playbackWord2B8 = 1;
    timerHandle->playbackWord2BC = 100;
    timerHandle->playbackWord2C4 = 0;
    timerHandle->currentVtimeMajor = timerHandle->accumulatedTicks;
    timerHandle->externalTimeCallback = nullptr;
    timerHandle->previousExternalMinor = -5;
    timerHandle->externalAccumulatedMajor = 0;
    timerHandle->externalReportedMinor = 1;
    timerHandle->externalCallbackContext = 0;
    timerHandle->initScratchWord0 = 0;
    timerHandle->initScratchWord1 = 0;
    timerHandle->initScratchWord2 = 0;
    return -5;
  }

  /**
   * Address: 0x00ADB3E0 (FUN_00ADB3E0, _SFD_SetUsrTimeFn)
   *
   * What it does:
   * Validates one handle, writes user timer callback slot `4`, and marks
   * condition `15` when callback binding is non-null.
   */
  std::int32_t
  SFD_SetUsrTimeFn(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t callbackAddress)
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetUserTimeCallback = static_cast<std::int32_t>(0xFF000123u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetUserTimeCallback);
    }

    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    (void)SFTIM_SetTimeFn(workctrlAddress, callbackAddress, 4);
    if (callbackAddress != 0) {
      (void)SFSET_SetCond(workctrlSubobj, 15, 4);
    }
    return 0;
  }

  /**
   * Address: 0x00ADB510 (FUN_00ADB510, _sftim_UpdateTimeOne)
   *
   * What it does:
   * Validates one SFD handle and updates timer lanes when condition `71` does
   * not lock timer updates.
   */
  std::int32_t sftim_UpdateTimeOne(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrInvalidHandleUpdateTime = static_cast<std::int32_t>(0xFF00012Au);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleUpdateTime);
    }

    if (SFSET_GetCond(workctrlSubobj, 71) != 1) {
      (void)sftim_UpdateTime(workctrlSubobj);
    }
    return 0;
  }

  /**
   * Address: 0x00ADB4D0 (FUN_00ADB4D0, _SFD_UpdateTime)
   *
   * What it does:
   * Updates one handle's timer lanes, or all active handles when `workctrlSubobj`
   * is null.
   */
  std::int32_t SFD_UpdateTime(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (workctrlSubobj != nullptr) {
      return sftim_UpdateTimeOne(workctrlSubobj);
    }

    std::int32_t updateResult = 0;
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      auto* const activeWorkctrl = static_cast<moho::SofdecSfdWorkctrlSubobj*>(objectHandle);
      if (activeWorkctrl != nullptr) {
        const std::int32_t handleUpdateResult = sftim_UpdateTimeOne(activeWorkctrl);
        if (handleUpdateResult != 0) {
          updateResult = handleUpdateResult;
        }
      }
    }
    return updateResult;
  }

  /**
   * Address: 0x00ADB920 (FUN_00ADB920, _sftim_AddHnVbIn)
   *
   * What it does:
   * Converts one paused frame-time lane to VBlank ticks and accumulates it into
   * per-handle VSync and takeoff-exec timer lanes under the SFLIB lock.
   */
  void sftim_AddHnVbIn(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t frameTimeMajor,
    const std::int32_t frameTimeMinor
  )
  {
    const auto* const timerState = reinterpret_cast<const SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
    const std::int32_t additionalTicks = UTY_MulDiv(timerState->timerVersion, frameTimeMajor, frameTimeMinor);

    SFLIB_LockCs();
    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(workctrlSubobj);
    runtimeView->vsyncTimeMajor += additionalTicks;
    runtimeView->takeOffExecTimeMajor += additionalTicks;
    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADB980 (FUN_00ADB980, _sftim_AddExtClock)
   *
   * What it does:
   * Converts one paused-frame interval into external-clock ticks and
   * accumulates it into the per-handle external pause lane under SFLIB lock.
   */
  void sftim_AddExtClock(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t frameTimeMajor,
    const std::int32_t frameTimeMinor
  )
  {
    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t additionalTicks =
      UTY_MulDiv(runtimeView->externalReportedMinor, frameTimeMajor, frameTimeMinor);
    SFLIB_LockCs();
    runtimeView->externalPauseAccumulatedMajor += additionalTicks;
    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADB9D0 (FUN_00ADB9D0, _SFTIM_GetTimeOneFrmVideo)
   *
   * What it does:
   * Returns one-frame video time as `(1000, rate)` when decode-channel mode is
   * set, otherwise `(0, 29970)`.
   */
  std::int32_t* SFTIM_GetTimeOneFrmVideo(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outFrameTimeMajor,
    std::int32_t* const outFrameTimeMinor
  )
  {
    const auto* const runtimeView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t decodeChannelMode = runtimeView->decodeChannelMode;
    if (decodeChannelMode != 0) {
      *outFrameTimeMajor = 1000;
      *outFrameTimeMinor = SFTIM_prate[decodeChannelMode];
      return outFrameTimeMinor;
    }

    *outFrameTimeMajor = 0;
    *outFrameTimeMinor = 29970;
    return nullptr;
  }

  /**
   * Address: 0x00ADB8D0 (FUN_00ADB8D0, _SFTIM_Pause)
   *
   * What it does:
   * For pause mode `2`, snapshots one-frame video time and accumulates it into
   * both vblank and external-clock pause lanes; otherwise returns `pauseMode-2`.
   */
  std::int32_t SFTIM_Pause(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t pauseMode)
  {
    const std::int32_t result = pauseMode - 2;
    if (pauseMode == 2) {
      std::int32_t frameTimeMajor = 0;
      std::int32_t frameTimeMinor = 0;
      (void)SFTIM_GetTimeOneFrmVideo(workctrlSubobj, &frameTimeMajor, &frameTimeMinor);
      sftim_AddHnVbIn(workctrlSubobj, frameTimeMajor, frameTimeMinor);
      sftim_AddExtClock(workctrlSubobj, frameTimeMajor, frameTimeMinor);
    }
    return result;
  }

  /**
   * Address: 0x00ADB680 (FUN_00ADB680, _sftim_Tc2TimeN)
   *
   * What it does:
   * Converts packed timecode fields into `(major, minor)` timeline lanes for a
   * caller-supplied frame-rate scale.
   */
  std::int32_t sftim_Tc2TimeN(
    const std::int32_t frameRateUnits,
    SftimTimecodeLaneView* const timecodeLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t secondUnits =
      timecodeLane->seconds + 60 * (timecodeLane->minutes + 60 * timecodeLane->hours);
    const std::int32_t halfFrameUnits =
      static_cast<std::int32_t>(timecodeLane->repeatFieldAccumulated)
      + 2 * (timecodeLane->halfFrameCarry + timecodeLane->frameNumber);

    *outTimeMajor = frameRateUnits * secondUnits + 500 * halfFrameUnits;
    *outTimeMinor = frameRateUnits;
    return SjPointerToAddress(outTimeMajor);
  }

  /**
   * Address: 0x00ADB6E0 (FUN_00ADB6E0, _sftim_Tc2Time23N)
   *
   * What it does:
   * Converts one timecode lane through the shared converter with a fixed
   * 24k frame-rate scale and then restores caller-selected minor-rate output.
   */
  std::int32_t sftim_Tc2Time23N(
    const std::int32_t requestedMinorRate,
    SftimTimecodeLaneView* const timecodeLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t result = sftim_Tc2TimeN(24000, timecodeLane, outTimeMajor, outTimeMinor);
    *outTimeMinor = requestedMinorRate;
    return result;
  }

  /**
   * Address: 0x00ADB710 (FUN_00ADB710, _sftim_Tc2Time29N)
   *
   * What it does:
   * Converts one timecode lane through the shared converter with a fixed
   * 30k frame-rate scale and then restores caller-selected minor-rate output.
   */
  std::int32_t sftim_Tc2Time29N(
    const std::int32_t requestedMinorRate,
    SftimTimecodeLaneView* const timecodeLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t result = sftim_Tc2TimeN(30000, timecodeLane, outTimeMajor, outTimeMinor);
    *outTimeMinor = requestedMinorRate;
    return result;
  }

  /**
   * Address: 0x00ADB740 (FUN_00ADB740, _sftim_Tc2Time59N)
   *
   * What it does:
   * Converts one timecode lane through the shared converter with a fixed
   * 60k frame-rate scale and then restores caller-selected minor-rate output.
   */
  std::int32_t sftim_Tc2Time59N(
    const std::int32_t requestedMinorRate,
    SftimTimecodeLaneView* const timecodeLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t result = sftim_Tc2TimeN(60000, timecodeLane, outTimeMajor, outTimeMinor);
    *outTimeMinor = requestedMinorRate;
    return result;
  }

  /**
   * Address: 0x00ADB770 (FUN_00ADB770, _sftim_Tc2Time23D)
   *
   * What it does:
   * Converts drop-frame 23.976-style timecode fields into `(major, minor)` time
   * lanes using the fixed drop-frame coefficient set.
   */
  std::int32_t sftim_Tc2Time23D(
    const std::int32_t requestedMinorRate,
    SftimTimecodeLaneView* const timecodeLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t scaledSecondUnits =
      (timecodeLane->minutes / 2) + (719 * timecodeLane->minutes) + (12 * timecodeLane->seconds)
      + (43146 * timecodeLane->hours);
    const std::int32_t halfFrameUnits =
      static_cast<std::int32_t>(timecodeLane->repeatFieldAccumulated)
      + 2 * (timecodeLane->frameNumber + timecodeLane->halfFrameCarry + 2 * scaledSecondUnits);
    *outTimeMajor = 500 * halfFrameUnits;
    *outTimeMinor = requestedMinorRate;
    return requestedMinorRate;
  }

  /**
   * Address: 0x00ADB7F0 (FUN_00ADB7F0, _sftim_Tc2Time29D)
   *
   * What it does:
   * Converts drop-frame 29.97-style timecode fields into `(major, minor)` time
   * lanes using the fixed drop-frame coefficient set.
   */
  std::int32_t sftim_Tc2Time29D(
    const std::int32_t requestedMinorRate,
    SftimTimecodeLaneView* const timecodeLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t scaledSecondUnits =
      (timecodeLane->minutes / 2) + (899 * timecodeLane->minutes) + (15 * timecodeLane->seconds)
      + (53946 * timecodeLane->hours);
    const std::int32_t halfFrameUnits =
      static_cast<std::int32_t>(timecodeLane->repeatFieldAccumulated)
      + 2 * (timecodeLane->frameNumber + timecodeLane->halfFrameCarry + 2 * scaledSecondUnits);
    *outTimeMajor = 500 * halfFrameUnits;
    *outTimeMinor = requestedMinorRate;
    return SjPointerToAddress(outTimeMajor);
  }

  /**
   * Address: 0x00ADB860 (FUN_00ADB860, _sftim_Tc2Time59D)
   *
   * What it does:
   * Converts drop-frame 59.94-style timecode fields into `(major, minor)` time
   * lanes using the fixed drop-frame coefficient set.
   */
  std::int32_t sftim_Tc2Time59D(
    const std::int32_t requestedMinorRate,
    SftimTimecodeLaneView* const timecodeLane,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t scaledSecondUnits =
      (timecodeLane->minutes / 2) + (1799 * timecodeLane->minutes) + (30 * timecodeLane->seconds)
      + (107946 * timecodeLane->hours);
    const std::int32_t halfFrameUnits =
      static_cast<std::int32_t>(timecodeLane->repeatFieldAccumulated)
      + 2 * (timecodeLane->frameNumber + timecodeLane->halfFrameCarry + 2 * scaledSecondUnits);
    *outTimeMajor = 500 * halfFrameUnits;
    *outTimeMinor = requestedMinorRate;
    return SjPointerToAddress(outTimeMajor);
  }

  /**
   * Address: 0x00ADB620 (FUN_00ADB620, _SFTIM_Tc2Time)
   *
   * What it does:
   * Dispatches one timecode-to-time converter selected by frame-rate and mode
   * lanes, or emits `FF000221` with `(0, 1)` sentinel output when no converter
   * exists for the selected pair.
   */
  extern "C" std::int32_t
  SFTIM_Tc2Time(SftimTimecodeLaneView* const timecodeLane, std::int32_t* const outTimeMajor, std::int32_t* const outTimeMinor)
  {
    const std::int32_t tableIndex = (2 * timecodeLane->frameRateIndex) + timecodeLane->modeIndex;
    SftimTc2TimeFunction converter = sftim_tc2time[tableIndex];
    if (converter != nullptr) {
      return converter(SFTIM_prate[timecodeLane->frameRateIndex], timecodeLane, outTimeMajor, outTimeMinor);
    }

    const std::int32_t result = SFLIB_SetErr(0, static_cast<std::int32_t>(0xFF000221u));
    *outTimeMajor = 0;
    *outTimeMinor = 1;
    return result;
  }

  /**
   * Address: 0x00ADAD20 (FUN_00ADAD20, _SFTIM_VbIn)
   *
   * What it does:
   * Increments the global timer VBlank counter and dispatches per-handle timer
   * VBlank entry for every active SFLIB object slot.
   */
  std::int32_t SFTIM_VbIn()
  {
    auto* const timerState = reinterpret_cast<SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
    ++timerState->verticalBlankCount;

    std::int32_t result = -1;
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(objectHandle);
      result = SFLIB_CheckHn(workctrlSubobj);
      if (result != -1) {
        result = sftim_HnVbIn(workctrlSubobj);
      }
    }

    return result;
  }

  /**
   * Address: 0x00ADAD60 (FUN_00ADAD60, _sftim_HnVbIn)
   *
   * What it does:
   * Increments one handle's VBlank lane and updates timer progress when
   * condition `71` enables timer ticking.
   */
  std::int32_t sftim_HnVbIn(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCondEnableTimerTick = 71;
    sftim_CntupHnVbIn(workctrlSubobj);

    const std::int32_t timerTickEnabled = SFSET_GetCond(workctrlSubobj, kSfsetCondEnableTimerTick);
    if (timerTickEnabled == 1) {
      return sftim_UpdateTime(workctrlSubobj);
    }
    return timerTickEnabled;
  }

  /**
   * Address: 0x00ADB310 (FUN_00ADB310, _SFTIM_ChkRegularTime)
   *
   * What it does:
   * Validates one work-control status lane for regular timer reads and writes
   * sentinel time values when current status is non-regular.
   */
  std::int32_t SFTIM_ChkRegularTime(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const auto* const gateView = reinterpret_cast<const SftimStatusGateRuntimeView*>(workctrlSubobj);
    const std::int32_t statusLane = gateView->statusLane;
    if (statusLane == 4 || statusLane == -4 || statusLane == 6 || statusLane == -6) {
      return 1;
    }

    *outTimeMajor = -1;
    *outTimeMinor = 1;
    return 0;
  }

  /**
   * Address: 0x00ADB1C0 (FUN_00ADB1C0, _sftim_GetTimeNone)
   *
   * What it does:
   * Resolves "none" timer mode: emits `(-2, 1)` on regular status, otherwise
   * returns the regular-time sentinel lane from `SFTIM_ChkRegularTime`.
   */
  std::int32_t sftim_GetTimeNone(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    if (SFTIM_ChkRegularTime(workctrlSubobj, outTimeMajor, outTimeMinor) != 0) {
      *outTimeMajor = -2;
      *outTimeMinor = 1;
    }
    return 0;
  }

  /**
   * Address: 0x00ADB1F0 (FUN_00ADB1F0, _sftim_GetTimeVsync)
   *
   * What it does:
   * Resolves VSync timer mode by returning per-handle VSync major lane and the
   * global timer version lane when status is regular.
   */
  std::int32_t sftim_GetTimeVsync(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    if (SFTIM_ChkRegularTime(workctrlSubobj, outTimeMajor, outTimeMinor) != 0) {
      const auto* const runtimeView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(workctrlSubobj);
      const auto* const timerState = reinterpret_cast<const SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
      *outTimeMajor = runtimeView->vsyncTimeMajor;
      *outTimeMinor = timerState->timerVersion;
    }
    return 0;
  }

  /**
   * Address: 0x00ADB230 (FUN_00ADB230, _sftim_GetTimeUfrm)
   *
   * What it does:
   * User-frame timer mode: performs regular-time validation and keeps output
   * lanes as-is (sentinel lanes are set by `SFTIM_ChkRegularTime` when needed).
   */
  std::int32_t sftim_GetTimeUfrm(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    (void)SFTIM_ChkRegularTime(workctrlSubobj, outTimeMajor, outTimeMinor);
    return 0;
  }

  /**
   * Address: 0x00ADB250 (FUN_00ADB250, _sftim_GetTimeExtClock)
   *
   * What it does:
   * Reads one external clock callback lane, accumulates wrapped major deltas
   * into external pause time when timer increment is enabled, and emits the
   * accumulated external-clock time pair.
   */
  std::int32_t sftim_GetTimeExtClock(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    const std::int32_t regularResult = SFTIM_ChkRegularTime(workctrlSubobj, outTimeMajor, outTimeMinor);
    if (regularResult == 0) {
      return regularResult;
    }

    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(workctrlSubobj);
    if (runtimeView->externalTimeCallbackAddress == 0) {
      *outTimeMajor = -2;
      *outTimeMinor = 1;
      return regularResult;
    }

    std::int32_t externalMajor = 0;
    std::int32_t externalMinor = 0;
    const auto externalTimeCallback = reinterpret_cast<SftimExternalTimeCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(runtimeView->externalTimeCallbackAddress))
    );
    const std::int32_t callbackResult = externalTimeCallback(runtimeView->externalCallbackContext, &externalMajor, &externalMinor);

    if (sftim_IsTimeIncre(workctrlSubobj) != 0 && runtimeView->previousExternalMajor != -5) {
      std::int32_t externalDelta = externalMajor - runtimeView->previousExternalMajor;
      if (externalDelta < 0) {
        externalDelta += runtimeView->externalWrapMinorLimit + 1;
      }
      runtimeView->externalPauseAccumulatedMajor += externalDelta;
    }

    runtimeView->previousExternalMajor = externalMajor;
    runtimeView->externalReportedMinor = externalMinor;
    *outTimeMajor = runtimeView->externalPauseAccumulatedMajor;
    *outTimeMinor = runtimeView->externalReportedMinor;
    return callbackResult;
  }

  /**
   * Address: 0x00ADB170 (FUN_00ADB170, _SFTIM_GetNowTime)
   *
   * What it does:
   * Locks SFLIB timer state, dispatches one current-time provider selected by
   * condition `15`, and unlocks before returning provider status.
   */
  std::int32_t SFTIM_GetNowTime(
    const std::int32_t workctrlAddress,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    SFLIB_LockCs();

    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    auto* const counterLane = reinterpret_cast<SftimVblankCounterLaneView*>(reinterpret_cast<std::uint8_t*>(workctrlSubobj) + 0xD30);
    const std::int32_t timerMode = SFSET_GetCond(workctrlSubobj, 15);

    SftimGetNowTimeFunction nowTimeFunction = *(counterLane->nowTimeFunctions.data() + timerMode);
    if (nowTimeFunction == nullptr) {
      nowTimeFunction = sftim_GetTimeNone;
    }

    const std::int32_t result = nowTimeFunction(workctrlSubobj, outTimeMajor, outTimeMinor);
    SFLIB_UnlockCs();
    return result;
  }

  /**
   * Address: 0x00ADB130 (FUN_00ADB130, _SFD_GetNowTime)
   *
   * What it does:
   * Validates one SFD handle and forwards to `SFTIM_GetNowTime`.
   */
  std::int32_t SFD_GetNowTime(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetNowTime = static_cast<std::int32_t>(0xFF000128u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetNowTime);
    }
    return SFTIM_GetNowTime(SjPointerToAddress(workctrlSubobj), outTimeMajor, outTimeMinor);
  }

  /**
   * Address: 0x00ADADF0 (FUN_00ADADF0, _sftim_IsTimeIncre)
   *
   * What it does:
   * Returns whether timer increment is enabled for the current handle state.
   */
  std::int32_t sftim_IsTimeIncre(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const gateView = reinterpret_cast<const SftimStatusGateRuntimeView*>(workctrlSubobj);
    if (gateView->statusLane != 4) {
      return 0;
    }
    if (gateView->startupGateFlag != 0) {
      return 0;
    }
    return (gateView->timerFreezeFlag == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00ADAE20 (FUN_00ADAE20, _sftim_IsVbinStIncre)
   *
   * What it does:
   * Returns whether VBlank-state accumulator should increment for current
   * handle phase and VBlank gate lane.
   */
  std::int32_t
  sftim_IsVbinStIncre(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, SftimVblankCounterLaneView* const counterLane)
  {
    if (counterLane->vblankStateTicks == -1) {
      return 0;
    }
    const auto* const gateView = reinterpret_cast<const SftimStatusGateRuntimeView*>(workctrlSubobj);
    return (gateView->phaseLane == 4) ? 1 : 0;
  }

  /**
   * Address: 0x00ADAF30 (FUN_00ADAF30, _SFTIM_GetAudioStartSample)
   *
   * What it does:
   * Converts one ADXT runtime audio-start PTS lane from 90 kHz ticks to sample
   * index for the requested sample rate and updates global cache lanes.
   */
  std::int32_t SFTIM_GetAudioStartSample(void* const adxtRuntime, const std::int32_t audioSampleRate)
  {
    const auto* const runtimeView = static_cast<const SftimAudioStartSampleRuntimeView*>(adxtRuntime);
    const std::int64_t audioStartPts = runtimeView->audioStartPts90k;
    if (audioStartPts < 0) {
      return -1;
    }

    const std::int64_t startSample =
      (static_cast<std::int64_t>(audioSampleRate) * audioStartPts) / static_cast<std::int64_t>(90000);
    sftim_as_pts = audioStartPts;
    sftim_a_sample = static_cast<std::int32_t>(startSample);
    return static_cast<std::int32_t>(startSample);
  }

  /**
   * Address: 0x00ADAF90 (FUN_00ADAF90, _SFTIM_GetVideoStartSample)
   *
   * What it does:
   * Converts one ADXT runtime video-start time lane to sample index at the
   * requested sample rate, with explicit-time preference and fallback-time
   * handling.
   */
  std::int32_t
  SFTIM_GetVideoStartSample(void* const adxtRuntime, const std::int32_t audioSampleRate, std::int32_t* const outHasExplicitStartTime)
  {
    const auto* const runtimeView = static_cast<const SftimVideoStartSampleRuntimeView*>(adxtRuntime);
    const std::int32_t hasExplicitStartTime = runtimeView->hasExplicitStartTime;
    *outHasExplicitStartTime = hasExplicitStartTime;

    std::int32_t timeMajor = runtimeView->explicitTimeMajor;
    std::int32_t timeMinor = runtimeView->explicitTimeMinor;
    if (hasExplicitStartTime == 0) {
      timeMajor = runtimeView->fallbackTimeMajor;
      if (timeMajor < 0) {
        return -1;
      }
      timeMinor = runtimeView->fallbackTimeMinor;
    }

    const std::int32_t startSample = UTY_MulDiv(timeMajor, audioSampleRate, timeMinor);
    sftim_v_time = timeMajor;
    sftim_v_sample = startSample;
    return startSample;
  }

  /**
   * Address: 0x00ADB5C0 (FUN_00ADB5C0, _sftim_ResetVtimeTmr)
   *
   * What it does:
   * Resets per-handle VTime major lane from either accumulated VSync ticks or
   * external-clock accumulated lane based on condition `71`.
   */
  std::int32_t
  sftim_ResetVtimeTmr(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, SftimVblankCounterLaneView* const counterLane)
  {
    if (SFSET_GetCond(workctrlSubobj, 71) == 1) {
      counterLane->currentVtimeMajor = counterLane->accumulatedTicks;
    } else {
      counterLane->currentVtimeMajor = counterLane->externalAccumulatedMajor;
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(counterLane));
  }

  /**
   * Address: 0x00ADB110 (FUN_00ADB110, _SFTIM_GetTime)
   *
   * What it does:
   * Returns current integer/fractional playback timer lanes from one SFD
   * work-control object.
   */
  void SFTIM_GetTime(const std::int32_t workctrlAddress, std::int32_t* const outTimeMajor, std::int32_t* const outTimeMinor)
  {
    const auto* const runtimeView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    *outTimeMajor = runtimeView->currentTimeMajor;
    *outTimeMinor = runtimeView->currentTimeMinor;
  }

  /**
   * Address: 0x00ADBEC0 (FUN_00ADBEC0, _SFTIM_SetSpeed)
   *
   * What it does:
   * Stores one per-handle timer speed rational lane and returns the written
   * value.
   */
  std::int32_t SFTIM_SetSpeed(const std::int32_t workctrlAddress, const std::int32_t speedRational)
  {
    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    runtimeView->timeBaseScale = speedRational;
    return speedRational;
  }

  /**
   * Address: 0x00ADBED0 (FUN_00ADBED0, _SFTIM_GetSpeed)
   *
   * What it does:
   * Returns one per-handle timer speed rational lane.
   */
  std::int32_t SFTIM_GetSpeed(const std::int32_t workctrlAddress)
  {
    const auto* const runtimeView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    return runtimeView->timeBaseScale;
  }

  /**
   * Address: 0x00ADBEE0 (FUN_00ADBEE0, _UTY_CmpTime)
   *
   * What it does:
   * Cross-multiplies two time/unit pairs and returns whether left lane is less
   * than or equal to right lane.
   */
  std::int32_t UTY_CmpTime(
    const std::int32_t leftTime,
    const std::int32_t leftUnit,
    const std::int32_t rightTime,
    const std::int32_t rightUnit
  )
  {
    const std::int64_t leftScaled = static_cast<std::int64_t>(rightUnit) * static_cast<std::int64_t>(leftTime);
    const std::int64_t rightScaled = static_cast<std::int64_t>(rightTime) * static_cast<std::int64_t>(leftUnit);
    return (leftScaled <= rightScaled) ? 1 : 0;
  }

  /**
   * Address: 0x00ADB3D0 (FUN_00ADB3D0, _SFD_CmpTime)
   *
   * What it does:
   * Forwards one time-pair compare request to `UTY_CmpTime`.
   */
  std::int32_t SFD_CmpTime(
    const std::int32_t lhsIntegerPart,
    const std::int32_t lhsFractionalPart,
    const std::int32_t rhsIntegerPart,
    const std::int32_t rhsFractionalPart
  )
  {
    return UTY_CmpTime(lhsIntegerPart, lhsFractionalPart, rhsIntegerPart, rhsFractionalPart);
  }

  /**
   * Address: 0x00ADAD90 (FUN_00ADAD90, _sftim_CntupHnVbIn)
   *
   * What it does:
   * Updates per-handle timer accumulators on VBlank entry according to timer
   * increment and VBlank-state increment gates.
   */
  std::int32_t sftim_CntupHnVbIn(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const counterLane = reinterpret_cast<SftimVblankCounterLaneView*>(reinterpret_cast<std::uint8_t*>(workctrlSubobj) + 0xD30);
    if (sftim_IsTimeIncre(workctrlSubobj) != 0) {
      counterLane->accumulatedTicks += counterLane->tickStep;
    }

    std::int32_t result = sftim_IsVbinStIncre(workctrlSubobj, counterLane);
    if (result != 0) {
      result = counterLane->tickStep;
      counterLane->vblankStateTicks += result;
    }
    return result;
  }

  /**
   * Address: 0x00ADB550 (FUN_00ADB550, _sftim_UpdateTime)
   *
   * What it does:
   * Refreshes one handle's current-time lanes from system timer and resets
   * VTime timers when wall-clock lanes changed.
   */
  std::int32_t sftim_UpdateTime(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const counterLane = reinterpret_cast<SftimVblankCounterLaneView*>(reinterpret_cast<std::uint8_t*>(workctrlSubobj) + 0xD30);

    std::int32_t nowMajor = 0;
    std::int32_t nowMinor = 0;
    SFTIM_GetNowTime(SjPointerToAddress(workctrlSubobj), &nowMajor, &nowMinor);

    std::int32_t result = 0;
    if (counterLane->lastTimerMajor != nowMajor || counterLane->lastTimerMinor != nowMinor) {
      result = sftim_ResetVtimeTmr(workctrlSubobj, counterLane);
      counterLane->lastTimerMajor = nowMajor;
      counterLane->lastTimerMinor = nowMinor;
    }

    auto* const tickFlags = reinterpret_cast<SftimWorkctrlTickFlagsView*>(workctrlSubobj);
    tickFlags->tickUpdatedFlag = 1;
    return result;
  }

  /**
   * Address: 0x00ADAFF0 (FUN_00ADAFF0, _SFTIM_SetStartTime)
   *
   * What it does:
   * Stores one per-handle playback start-time pair.
   */
  std::int32_t
  SFTIM_SetStartTime(const std::int32_t workctrlAddress, const std::int32_t startTimeMajor, const std::int32_t startTimeMinor)
  {
    auto* const timerHandle = reinterpret_cast<SftimInitHandleRuntimeView*>(SjAddressToPointer(workctrlAddress));
    timerHandle->startTimeMajor = startTimeMajor;
    timerHandle->startTimeMinor = startTimeMinor;
    return workctrlAddress;
  }

  /**
   * Address: 0x00ADB100 (FUN_00ADB100, _sfdtim_GetTimeAfterSeek)
   *
   * What it does:
   * Thunk wrapper that forwards to `SFTIM_GetTime`.
   */
  std::int32_t sfdtim_GetTimeAfterSeek(
    const std::int32_t workctrlAddress,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    SFTIM_GetTime(workctrlAddress, outTimeMajor, outTimeMinor);
    return 0;
  }

  /**
   * Address: 0x00ADB010 (FUN_00ADB010, _SFD_GetTime)
   *
   * What it does:
   * Validates one handle and returns current timer lanes from `SFTIM_GetTimeSub`.
   */
  std::int32_t SFD_GetTime(
    void* const sfdHandle,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetTime = static_cast<std::int32_t>(0xFF000121u);
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetTime);
    }
    return SFTIM_GetTimeSub(workctrlSubobj, outTimeMajor, outTimeMinor);
  }

  /**
   * Address: 0x00ADB0C0 (FUN_00ADB0C0, _SFD_GetTimeAfterSeek)
   *
   * What it does:
   * Validates one SFD handle and forwards seek-adjusted timer lanes from
   * `sfdtim_GetTimeAfterSeek`.
   */
  std::int32_t SFD_GetTimeAfterSeek(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetTimeAfterSeek = static_cast<std::int32_t>(0xFF000127u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetTimeAfterSeek);
    }
    return sfdtim_GetTimeAfterSeek(SjPointerToAddress(workctrlSubobj), outTimeMajor, outTimeMinor);
  }

  /**
   * Address: 0x00AE60E0 (FUN_00AE60E0, _SFD_GetTimePerFile)
   *
   * What it does:
   * Validates one SFD handle, reads current timer lanes, and when per-file
   * queue mode is enabled adjusts major time/output file ordinal from queued
   * sample-total history lanes.
   */
  std::int32_t SFD_GetTimePerFile(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor,
    std::int32_t* const outFileHistoryOrdinal
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetTimePerFile = static_cast<std::int32_t>(0xFF000162u);
    constexpr std::int32_t kPerFileHistoryLaneCount = 32;

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetTimePerFile);
    }

    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t timeMinorDenominator = runtimeView->timeSubScaleDenominator;
    *outFileHistoryOrdinal = 0;

    const std::int32_t timeResult = SFTIM_GetTimeSub(workctrlSubobj, outTimeMajor, outTimeMinor);
    if (runtimeView->perFileTimeQueueEnabled != 0 && *outTimeMinor != 1) {
      SFLIB_LockCs();
      std::int32_t historyOrdinal = runtimeView->perFileTimeQueueOrdinal;
      std::int32_t historyTimeMajor = 0;
      for (std::int32_t iteration = 0; iteration < kPerFileHistoryLaneCount; ++iteration) {
        const std::int32_t ringSlot = historyOrdinal % kPerFileHistoryLaneCount;
        const std::size_t queueIndex = static_cast<std::size_t>(ringSlot < 0 ? (ringSlot + kPerFileHistoryLaneCount) : ringSlot);
        historyTimeMajor = UTY_MulDiv(runtimeView->perFileQueuedTimeMajor[queueIndex], *outTimeMinor, timeMinorDenominator);
        if (historyTimeMajor <= *outTimeMajor) {
          break;
        }
        --historyOrdinal;
      }

      *outFileHistoryOrdinal = historyOrdinal;
      *outTimeMajor -= historyTimeMajor;
      if (*outTimeMajor < 0) {
        *outTimeMajor = 0;
      }

      SFLIB_UnlockCs();
    }

    return timeResult;
  }

  /**
   * Address: 0x00ADB050 (FUN_00ADB050, _SFTIM_GetTimeSub)
   *
   * What it does:
   * Returns seek-adjusted timer lanes and applies wrap/scale correction lanes
   * for timer-sub mode.
   */
  std::int32_t SFTIM_GetTimeSub(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outTimeMajor,
    std::int32_t* const outTimeMinor
  )
  {
    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(workctrlSubobj);
    const std::int32_t result = sfdtim_GetTimeAfterSeek(SjPointerToAddress(workctrlSubobj), outTimeMajor, outTimeMinor);
    const std::int32_t timeMinor = *outTimeMinor;
    if (timeMinor != 1) {
      if (timeMinor == runtimeView->timeSubWrapMinorValue) {
        *outTimeMajor += runtimeView->timeSubWrapCarryMajor;
        return result;
      }
      if (runtimeView->timeSubScaleEnabled != 0) {
        *outTimeMajor +=
          UTY_MulDiv(runtimeView->timeSubScaleNumerator, timeMinor, runtimeView->timeSubScaleDenominator);
      }
    }
    return result;
  }

  /**
   * Address: 0x00ADBAD0 (FUN_00ADBAD0, _SFTIM_IsGetFrmTime)
   *
   * What it does:
   * Checks whether one frame-ready window is in executable timer range.
   */
  std::int32_t SFTIM_IsGetFrmTime(const std::int32_t workctrlAddress, const std::int32_t frameReadyWindowAddress)
  {
    if (frameReadyWindowAddress != 0) {
      const auto* const frameWindow =
        reinterpret_cast<const SftimFrameReadyWindowView*>(static_cast<std::uintptr_t>(frameReadyWindowAddress));
      return SFTIM_IsGetFrmTimeTunit(workctrlAddress, frameWindow->frameStartTime, frameWindow->frameEndTime);
    }
    return frameReadyWindowAddress;
  }

  [[nodiscard]] static std::int32_t SftimFloatBitsAsInt(const float value)
  {
    std::int32_t bitPattern = 0;
    std::memcpy(&bitPattern, &value, sizeof(bitPattern));
    return bitPattern;
  }

  /**
   * Address: 0x00ADBCE0 (FUN_00ADBCE0, _sftim_IsTakeOffExecTime)
   *
   * What it does:
   * Resolves take-off execution timing against one per-handle threshold lane
   * and writes the resulting execute gate to `outShouldExecute`.
   */
  std::int32_t sftim_IsTakeOffExecTime(
    const std::int32_t workctrlAddress,
    const std::int32_t currentTimeMajor,
    const std::int32_t currentTimeMinor,
    std::int32_t* const outShouldExecute
  )
  {
    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    if (runtimeView->takeOffExecTimeMajor >= 0) {
      const auto* const timerState = reinterpret_cast<const SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
      const std::int32_t compareResult =
        UTY_CmpTime(currentTimeMajor, currentTimeMinor, runtimeView->takeOffExecTimeMajor, timerState->ticksPerSecond);
      *outShouldExecute = (compareResult != 0) ? 1 : 0;
      return *outShouldExecute;
    }

    runtimeView->takeOffExecTimeMajor = 0;
    *outShouldExecute = 1;
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outShouldExecute));
  }

  /**
   * Address: 0x00ADBD30 (FUN_00ADBD30, _sftim_IsGrExecTime)
   *
   * What it does:
   * Evaluates execution timing window with grace-band hysteresis and writes one
   * execute gate to `outShouldExecute`.
   */
  void sftim_IsGrExecTime(
    const std::int32_t workctrlAddress,
    const float currentScaledTime,
    const float executionScaledTime,
    std::int32_t* const outShouldExecute
  )
  {
    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    const double executionWindow = static_cast<double>(runtimeView->executionWindowTicks);

    if (static_cast<double>(executionScaledTime) + executionWindow < static_cast<double>(currentScaledTime)) {
      *outShouldExecute = 0;
      return;
    }

    if (static_cast<double>(executionScaledTime) - executionWindow < static_cast<double>(currentScaledTime)) {
      const auto* const timerState = reinterpret_cast<const SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
      const std::int32_t guardThreshold =
        (timerState->ticksPerSecond == 59940 && runtimeView->decodeChannelMode <= 2 && runtimeView->timeBaseScale == 1000)
        ? 1
        : 0;

      if (runtimeView->graceWindowCounter > guardThreshold) {
        *outShouldExecute = (static_cast<double>(executionScaledTime) >= static_cast<double>(currentScaledTime)) ? 1 : 0;
      } else {
        *outShouldExecute = runtimeView->lastGraceResult;
      }

      runtimeView->graceWindowCounter = 0;
      runtimeView->lastUpperSample = currentScaledTime;
      runtimeView->lastGraceResult = *outShouldExecute;
      return;
    }

    *outShouldExecute = 1;
    if (runtimeView->lastUpperSample != currentScaledTime && runtimeView->lastLowerSample != currentScaledTime) {
      runtimeView->lastLowerSample = currentScaledTime;
      ++runtimeView->graceWindowCounter;
    }
  }

  /**
   * Address: 0x00ADBC00 (FUN_00ADBC00, _SFTIM_IsExecTime)
   *
   * What it does:
   * Compares playback timer progress to one target timing lane and determines
   * whether execution for the target step should run this frame.
   */
  void SFTIM_IsExecTime(
    const std::int32_t workctrlAddress,
    const std::int32_t targetTimeMajor,
    const std::int32_t targetTimeMinor,
    std::int32_t* const outShouldExecute,
    const std::int32_t frameStepTicks
  )
  {
    std::int32_t currentTimeMajor = 0;
    std::int32_t currentTimeMinor = 0;
    SFTIM_GetTime(workctrlAddress, &currentTimeMajor, &currentTimeMinor);

    if (currentTimeMinor == 1) {
      if (currentTimeMajor == -2) {
        *outShouldExecute = 1;
      } else {
        (void)sftim_IsTakeOffExecTime(workctrlAddress, targetTimeMajor, targetTimeMinor, outShouldExecute);
      }
      return;
    }

    const float scaledTargetTime = static_cast<float>(
      static_cast<double>(targetTimeMajor) * 10000.0 / static_cast<double>(targetTimeMinor)
    );
    const auto* const timerState = reinterpret_cast<const SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
    auto* const runtimeView = reinterpret_cast<SftimWorkctrlRuntimeView*>(SjAddressToPointer(workctrlAddress));
    currentTimeMajor += (frameStepTicks * currentTimeMinor) / timerState->ticksPerSecond;

    const float scaledCurrentTime = static_cast<float>(
      static_cast<double>(currentTimeMajor) * 10000.0 / static_cast<double>(currentTimeMinor)
    );

    if (runtimeView->execComparisonMode == 1) {
      *outShouldExecute = (scaledTargetTime <= scaledCurrentTime) ? 1 : 0;
      return;
    }

    sftim_IsGrExecTime(workctrlAddress, scaledTargetTime, scaledCurrentTime, outShouldExecute);
  }

  /**
   * Address: 0x00ADBAF0 (FUN_00ADBAF0, _SFTIM_IsGetFrmTimeTunit)
   *
   * What it does:
   * Resolves whether one frame-time window is executable against current SFTIM
   * state, honoring condition lane `14` short-circuit behavior.
   */
  std::int32_t
  SFTIM_IsGetFrmTimeTunit(const std::int32_t workctrlAddress, const float frameStartTime, const float frameEndTime)
  {
    constexpr std::int32_t kSfsetCondStartModeGate = 14;
    constexpr std::int32_t kSfsetCondFrameStep = 45;
    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    if (SFSET_GetCond(workctrlSubobj, kSfsetCondStartModeGate) != 0) {
      return 1;
    }

    std::int32_t shouldExecute = 0;
    SFTIM_IsExecTime(
      workctrlAddress,
      SftimFloatBitsAsInt(frameStartTime),
      SftimFloatBitsAsInt(frameEndTime),
      &shouldExecute,
      SFSET_GetCond(workctrlSubobj, kSfsetCondFrameStep)
    );
    return shouldExecute;
  }

  /**
   * Address: 0x00ADBB80 (FUN_00ADBB80, _SFD_IsDrawTime)
   *
   * What it does:
   * Validates handle/timer draw gates and computes whether one frame should be
   * drawn on this tick.
   */
  std::int32_t SFD_IsDrawTime(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const float frameStartTime,
    const float frameEndTime,
    std::int32_t* const outShouldDraw
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleDrawTime = static_cast<std::int32_t>(0xFF000126u);
    constexpr std::int32_t kSfsetCondStartModeGate = 14;
    constexpr std::int32_t kSfsetCondFrameStep = 45;

    *outShouldDraw = 0;
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleDrawTime);
    }

    if (SFSET_GetCond(workctrlSubobj, kSfsetCondStartModeGate) == 0) {
      *outShouldDraw = 1;
      return 0;
    }

    const auto* const drawState = reinterpret_cast<const SfdDrawTimeRuntimeView*>(workctrlSubobj);
    if (drawState->playbackStatusLane == 4) {
      SFTIM_IsExecTime(
        SjPointerToAddress(workctrlSubobj),
        SftimFloatBitsAsInt(frameStartTime),
        SftimFloatBitsAsInt(frameEndTime),
        outShouldDraw,
        SFSET_GetCond(workctrlSubobj, kSfsetCondFrameStep)
      );
    } else {
      *outShouldDraw = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00ADBE40 (FUN_00ADBE40, _SFTIM_IsVideoTerm)
   *
   * What it does:
   * Returns whether configured video termination time has been reached for one
   * handle.
   */
  std::int32_t SFTIM_IsVideoTerm(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kVideoTermDisabled = -5;
    constexpr std::int32_t kTimeScaleBase = 2000;
    constexpr std::int32_t kTimeScaleDenominator = 59940;
    const auto* const runtimeView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(workctrlSubobj);

    if (runtimeView->videoLaneEnabled == 0) {
      return 1;
    }
    if (runtimeView->videoTermMajor == kVideoTermDisabled) {
      return 0;
    }

    std::int32_t currentTimeMajor = 0;
    std::int32_t currentTimeMinor = 0;
    SFTIM_GetTime(SjPointerToAddress(workctrlSubobj), &currentTimeMajor, &currentTimeMinor);

    const std::int32_t scaledVideoMajor =
      runtimeView->videoTermMajor + ((kTimeScaleBase * runtimeView->videoTermMinor) / kTimeScaleDenominator);
    return UTY_CmpTime(scaledVideoMajor, runtimeView->videoTermMinor, currentTimeMajor, currentTimeMinor);
  }

  /**
   * Address: 0x00AD6E10 (FUN_00AD6E10, _SFD_VbOut)
   *
   * What it does:
   * Reserved vertical-blank leave lane (no-op in this build).
   */
  void SFD_VbOut()
  {
  }

  /**
   * Address: 0x00AD6E20 (FUN_00AD6E20, _SFD_IsHnSvrWait)
   *
   * What it does:
   * Returns whether one SFD handle can proceed outside server-wait states.
   */
  std::int32_t SFD_IsHnSvrWait(const std::int32_t sfdHandleAddress)
  {
    struct SfdServerWaitView
    {
      std::uint8_t mUnknown00[0x44]{};
      std::int32_t serverWaitFlag = 0; // +0x44
      std::int32_t serverState = 0; // +0x48
    };
    static_assert(
      offsetof(SfdServerWaitView, serverWaitFlag) == 0x44,
      "SfdServerWaitView::serverWaitFlag offset must be 0x44"
    );
    static_assert(offsetof(SfdServerWaitView, serverState) == 0x48, "SfdServerWaitView::serverState offset must be 0x48");

    auto* const view = reinterpret_cast<SfdServerWaitView*>(SjAddressToPointer(sfdHandleAddress));
    const std::int32_t state = view->serverState;
    const bool isServerWaitState = (state == 1 || state == 2 || state == 3 || state == 4);
    if (!isServerWaitState) {
      return 1;
    }
    return (view->serverWaitFlag == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD6E50 (FUN_00AD6E50, _SFD_IsSvrWait)
   *
   * What it does:
   * Returns `1` when every tracked SFD handle is either invalid or currently in
   * one server-wait state; returns `0` once one valid non-wait handle exists.
   */
  std::int32_t SFD_IsSvrWait()
  {
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(objectHandle);
      if (SFLIB_CheckHn(workctrlSubobj) == 0) {
        const auto workctrlAddress =
          static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
        if (SFD_IsHnSvrWait(workctrlAddress) == 0) {
          return 0;
        }
      }
    }
    return 1;
  }

  std::int32_t SFPLY_DecideSvrStat();

  /**
   * Address: 0x00AD6EC0 (FUN_00AD6EC0, _SFD_ExecServer)
   *
   * What it does:
   * Executes one server tick for every valid SFD handle tracked by SFLIB and
   * returns the global playback server status lane.
   */
  std::int32_t SFD_ExecServer()
  {
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(objectHandle);
      if (SFLIB_CheckHn(workctrlSubobj) == 0) {
        (void)sfply_ExecOne(workctrlSubobj);
      }
    }
    return SFPLY_DecideSvrStat();
  }

  /**
   * Address: 0x00AD6E90 (FUN_00AD6E90, _SFD_ExecOne)
   *
   * What it does:
   * Executes one SFD per-handle server step after handle validation.
   */
  std::int32_t SFD_ExecOne(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleExecOne);
    }
    (void)sfply_ExecOne(workctrlSubobj);
    return 0;
  }

  /**
   * Address: 0x00AD6FD0 (FUN_00AD6FD0, _sfply_ExecOneSub)
   *
   * What it does:
   * Executes transfer-server lane and SFSEE server lane for one SFD handle.
   */
  std::int32_t sfply_ExecOneSub(const std::int32_t workctrlAddress)
  {
    (void)sfply_TrExecServer(workctrlAddress);
    return SFSEE_ExecServer(workctrlAddress);
  }

  /**
   * Address: 0x00AD6FF0 (FUN_00AD6FF0, _sfply_TrExecServer)
   *
   * What it does:
   * Dispatches transfer setup callback lane `2` for one SFD handle.
   */
  std::int32_t sfply_TrExecServer(const std::int32_t workctrlAddress)
  {
    return SFTRN_CallTrSetup(workctrlAddress, 2);
  }

  /**
   * Address: 0x00AD7000 (FUN_00AD7000, _sfply_StatStop)
   *
   * What it does:
   * Resolves STOP state lane for one playback handle from current phase flags.
   */
  std::int32_t sfply_StatStop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    const std::int32_t phaseLane = stateView->phaseLane;
    if (phaseLane >= 2 && (phaseLane <= 4 || phaseLane == 6)) {
      return 2;
    }
    return stateView->statusLane;
  }

  /**
   * Address: 0x00AD7020 (FUN_00AD7020, _sfply_StatPrep)
   *
   * What it does:
   * Resolves PREP state lane and dispatches transfer start when sync gate opens.
   */
  std::int32_t sfply_StatPrep(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    std::int32_t nextState = stateView->statusLane;
    const std::int32_t phaseLane = stateView->phaseLane;

    if (sfply_IsPrepEnd(workctrlSubobj) != 0) {
      (void)sfply_AdjustPrepEnd(workctrlSubobj);
      switch (phaseLane) {
      case 2:
        return 2;
      case 3:
        nextState = 3;
        break;
      case 4:
      case 6:
        if (sfply_IsStartSync(workctrlSubobj) != 0) {
          sfply_TrStart(workctrlSubobj);
          return 4;
        }
        nextState = 3;
        break;
      default:
        return nextState;
      }
    }

    return nextState;
  }

  /**
   * Address: 0x00AD70A0 (FUN_00AD70A0, _sfply_IsPrepEnd)
   *
   * What it does:
   * Checks whether audio/video transfer preparation lanes are completed.
   */
  std::int32_t sfply_IsPrepEnd(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kTransferLane6 = 6;
    constexpr std::int32_t kTransferLane7 = 7;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));

    std::int32_t cond5Ready = 1;
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond5) != 0) {
      const std::int32_t prepFlag = SFTRN_GetPrepFlg(workctrlAddress, kTransferLane6);
      cond5Ready = SFTRN_GetTermFlg(workctrlAddress, kTransferLane6) | prepFlag;
    }

    std::int32_t cond6Ready = 1;
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond6) != 0) {
      const std::int32_t prepFlag = SFTRN_GetPrepFlg(workctrlAddress, kTransferLane7);
      cond6Ready = SFTRN_GetTermFlg(workctrlAddress, kTransferLane7) | prepFlag;
    }

    return (cond5Ready != 0 && cond6Ready != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7120 (FUN_00AD7120, _sfply_AdjustPrepEnd)
   *
   * What it does:
   * Finalizes PREP completion by fixing AV flags, sync mode, and ETRG lane.
   */
  std::int32_t sfply_AdjustPrepEnd(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    (void)sfply_FixAvPlay(workctrlSubobj);
    (void)sfply_AdjustSyncMode(workctrlSubobj);
    return sfply_AdjustEtrg(workctrlSubobj);
  }

  /**
   * Address: 0x00AD7140 (FUN_00AD7140, _sfply_FixAvPlay)
   *
   * What it does:
   * Clears stale AV condition lanes when ring-buffer totals are empty.
   */
  std::int32_t sfply_FixAvPlay(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    if (
      stateView->setConditions[kSfsetCond5] == 1 && SFBUF_GetWTot(workctrlAddress, 1) == 0 &&
      SFBUF_GetRTot(workctrlAddress, 1) == 0
    ) {
      stateView->setConditions[kSfsetCond5] = 0;
    }

    if (
      stateView->setConditions[kSfsetCond6] == 1 && SFBUF_GetWTot(workctrlAddress, 2) == 0 &&
      SFBUF_GetRTot(workctrlAddress, 2) == 0
    ) {
      stateView->setConditions[kSfsetCond6] = 0;
    }

    return SFSEE_FixAvPlay(workctrlAddress, stateView->setConditions[kSfsetCond5], stateView->setConditions[kSfsetCond6]);
  }

  /**
   * Address: 0x00AD71C0 (FUN_00AD71C0, _sfply_AdjustSyncMode)
   *
   * What it does:
   * Normalizes sync-mode condition lane against current AV-enable conditions.
   */
  std::int32_t sfply_AdjustSyncMode(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCondSyncMode = 15;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    if (stateView->setConditions[kSfsetCond6] == 0 && stateView->setConditions[kSfsetCondSyncMode] == 2) {
      SFSET_SetCond(workctrlSubobj, kSfsetCondSyncMode, 1);
    }

    const std::int32_t cond5Value = stateView->setConditions[kSfsetCond5];
    if (cond5Value == 0 && stateView->setConditions[kSfsetCondSyncMode] == 1) {
      return SFSET_SetCond(workctrlSubobj, kSfsetCondSyncMode, 2);
    }
    return cond5Value;
  }

  /**
   * Address: 0x00AD7210 (FUN_00AD7210, _sfply_AdjustEtrg)
   *
   * What it does:
   * Reconciles ETRG condition lane (`25`) from AV-enable lanes and timer policy.
   */
  std::int32_t sfply_AdjustEtrg(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCondEtrg = 25;
    constexpr std::int32_t kSfsetCondTimerPolicy = 72;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    std::int32_t etrgConditionValue = 1;
    std::int32_t avMask = (stateView->setConditions[kSfsetCond6] == 1) ? 1 : 0;
    if (stateView->setConditions[kSfsetCond5] == 1) {
      avMask |= 2;
    }

    std::int32_t adjustedMask = avMask - 1;
    if (adjustedMask != 0) {
      adjustedMask -= 1;
      if (adjustedMask != 0) {
        if (adjustedMask != 1) {
          return SFSET_SetCond(workctrlSubobj, kSfsetCondEtrg, 3);
        }

        etrgConditionValue = SFSET_GetCond(workctrlSubobj, kSfsetCondEtrg);
        if (
          etrgConditionValue == 0 &&
          (UTY_IsTmrVoid() != 0 || SFSET_GetCond(workctrlSubobj, kSfsetCondTimerPolicy) == 0)
        ) {
          return SFSET_SetCond(workctrlSubobj, kSfsetCondEtrg, 3);
        }
      } else {
        etrgConditionValue = 2;
      }
    }

    return SFSET_SetCond(workctrlSubobj, kSfsetCondEtrg, etrgConditionValue);
  }

  /**
   * Address: 0x00AD72A0 (FUN_00AD72A0, _sfply_StatStby)
   *
   * What it does:
   * Resolves STANDBY state lane and starts transfers once sync preconditions hold.
   */
  std::int32_t sfply_StatStby(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    std::int32_t nextState = stateView->statusLane;

    switch (stateView->phaseLane) {
    case 2:
      return 2;
    case 3:
      return 3;
    case 4:
    case 6:
      if (sfply_IsStartSync(workctrlSubobj) != 0) {
        sfply_TrStart(workctrlSubobj);
        nextState = 4;
      }
      break;
    default:
      break;
    }

    return nextState;
  }

  /**
   * Address: 0x00AD7310 (FUN_00AD7310, _sfply_StatPlay)
   *
   * What it does:
   * Resolves PLAY state lane with finish and BPA transition checks.
   */
  std::int32_t sfply_StatPlay(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (sfply_ChkFin(workctrlSubobj) != 0) {
      return stateView->statusLane;
    }

    if (sfply_ChkBpa(workctrlSubobj) == 0 && stateView->phaseLane == 6) {
      return 6;
    }
    return stateView->statusLane;
  }

  /**
   * Address: 0x00AD7350 (FUN_00AD7350, _sfply_StatFin)
   *
   * What it does:
   * Returns current FIN state lane from one playback work-control object.
   */
  std::int32_t sfply_StatFin(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj)->statusLane;
  }

  /**
   * Address: 0x00AD7360 (FUN_00AD7360, _sfply_IsStartSync)
   *
   * What it does:
   * Evaluates whether transfer start is sync-safe for one playback handle.
   */
  std::int32_t sfply_IsStartSync(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond14 = 14;
    constexpr std::int32_t kSfsetCond45 = 45;
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);

    if (stateView->setConditions[kSfsetCond14] == 0) {
      return 1;
    }
    if (stateView->setConditions[kSfsetCond5] == 0) {
      return 1;
    }
    if (stateView->startSyncBypassFlag != 0) {
      return 1;
    }
    if (stateView->startSyncCurrentTicks < stateView->setConditions[kSfsetCond45]) {
      return (sfply_IsEtrg(workctrlSubobj) != 0) ? 1 : 0;
    }
    return 1;
  }

  /**
   * Address: 0x00AD73C0 (FUN_00AD73C0, _sfply_ChkBpa)
   *
   * What it does:
   * Toggles BPA pause state under SFLIB critical section and dispatches pause op.
   */
  std::int32_t sfply_ChkBpa(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    SFLIB_LockCs();
    std::int32_t result = 0;
    if (stateView->bpaActiveFlag != 0) {
      if (sfply_IsBpaOff(workctrlSubobj) != 0) {
        stateView->bpaActiveFlag = 0;
        result = SFPL2_Pause(workctrlSubobj, 0);
      }
    } else if (sfply_IsBpaOn(workctrlSubobj) != 0) {
      stateView->bpaActiveFlag = 1;
      stateView->bpaToggleCount += 1;
      result = SFPL2_Pause(workctrlSubobj, 1);
    }
    SFLIB_UnlockCs();

    return result;
  }

  /**
   * Address: 0x00AD7440 (FUN_00AD7440, _sfply_IsBpaOn)
   *
   * What it does:
   * Decides whether BPA pause should be enabled from playback/data/timer lanes.
   */
  std::int32_t sfply_IsBpaOn(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCond15 = 15;
    constexpr std::int32_t kSfsetCond67 = 67;
    constexpr std::int32_t kSfsetCond68 = 68;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);

    if (
      SFSET_GetCond(workctrlSubobj, kSfsetCond67) == 0 || SFSET_GetCond(workctrlSubobj, kSfsetCond15) == 0 ||
      stateView->startupGateFlag != 0 || stateView->statusLane != 4 || sfply_IsAnyoneTerm(workctrlSubobj) != 0 ||
      (SFSET_GetCond(workctrlSubobj, kSfsetCond5) == 1 && stateView->videoLaneReadyFlag == 0)
    ) {
      return 0;
    }

    if (SFSET_GetCond(workctrlSubobj, kSfsetCond6) == 1 && SFBUF_GetRingBufSiz(workctrlAddress, 2) > 0) {
      return 0;
    }
    if (SFTRN_IsSetup(workctrlSubobj, 1) != 0 && SFBUF_GetRingBufSiz(workctrlAddress, 0) > 0) {
      return 0;
    }
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond5) == 1 && sfply_EnoughViData(workctrlSubobj) != 0) {
      return 0;
    }

    std::int32_t currentTimeInteger = 0;
    std::int32_t currentTimeFractional = 0;
    SFTIM_GetTime(workctrlAddress, &currentTimeInteger, &currentTimeFractional);

    const std::int32_t scaledWindow =
      stateView->bpaWindowTicks - UTY_MulDiv(SFSET_GetCond(workctrlSubobj, kSfsetCond68), stateView->bpaTickRate, 1000000);
    if (currentTimeInteger <= 0 || scaledWindow <= 0) {
      return 0;
    }
    return (SFD_CmpTime(currentTimeInteger, currentTimeFractional, scaledWindow, stateView->bpaTickRate) == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7580 (FUN_00AD7580, _sfply_IsBpaOff)
   *
   * What it does:
   * Decides whether BPA pause should be released from playback/data/timer lanes.
   */
  std::int32_t sfply_IsBpaOff(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCond69 = 69;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);

    if (sfply_IsAnyoneTerm(workctrlSubobj) != 0) {
      return 1;
    }
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond5) == 1 && sfply_EnoughViData(workctrlSubobj) != 0) {
      return 1;
    }
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond6) == 1 && sfply_EnoughAiData(workctrlSubobj) != 0) {
      return 1;
    }

    std::int32_t currentTimeInteger = 0;
    std::int32_t currentTimeFractional = 0;
    SFTIM_GetTime(workctrlAddress, &currentTimeFractional, &currentTimeInteger);

    const std::int32_t scaledWindow =
      stateView->bpaWindowTicks - UTY_MulDiv(SFSET_GetCond(workctrlSubobj, kSfsetCond69), stateView->bpaTickRate, 1000000);
    return (SFD_CmpTime(currentTimeFractional, currentTimeInteger, scaledWindow, stateView->bpaTickRate) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7640 (FUN_00AD7640, _sfply_IsAnyoneTerm)
   *
   * What it does:
   * Checks transfer and buffer termination flags across active playback lanes.
   */
  std::int32_t sfply_IsAnyoneTerm(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    if (SFSET_GetCond(workctrlSubobj, 5) != 0 && SFTRN_GetTermFlg(workctrlAddress, 6) != 0) {
      return 1;
    }
    if (SFSET_GetCond(workctrlSubobj, 6) != 0 && SFTRN_GetTermFlg(workctrlAddress, 7) != 0) {
      return 1;
    }

    for (std::int32_t laneIndex = 0; laneIndex < 8; ++laneIndex) {
      if (SFBUF_GetTermFlg(workctrlAddress, laneIndex) != 0) {
        return 1;
      }
    }
    return 0;
  }

  /**
   * Address: 0x00AD76B0 (FUN_00AD76B0, _sfply_EnoughViData)
   *
   * What it does:
   * Checks whether the active video lane has enough buffered data for playback.
   */
  std::int32_t sfply_EnoughViData(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetVideoReadyThreshold = 70;
    const auto* const readinessView = reinterpret_cast<const SfplyDataReadinessIndexView*>(workctrlSubobj);
    const auto* const videoLane = SfplyGetDataLaneDescriptor(workctrlSubobj, readinessView->activeVideoLaneIndex);
    const std::int32_t availableBytes = SfplyQueryLaneReadyBytes(videoLane);
    const std::int32_t laneThreshold = (videoLane->readyThresholdBytes * 80) / 100;
    if (availableBytes >= laneThreshold) {
      return 1;
    }
    return (availableBytes >= SFSET_GetCond(workctrlSubobj, kSfsetVideoReadyThreshold)) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7720 (FUN_00AD7720, _sfply_EnoughAiData)
   *
   * What it does:
   * Checks whether the active audio lane has enough buffered data for playback.
   */
  std::int32_t sfply_EnoughAiData(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const readinessView = reinterpret_cast<const SfplyDataReadinessIndexView*>(workctrlSubobj);
    const auto* const audioLane = SfplyGetDataLaneDescriptor(workctrlSubobj, readinessView->activeAudioLaneIndex);
    const std::int32_t availableBytes = SfplyQueryLaneReadyBytes(audioLane);
    const std::int32_t laneThreshold = (audioLane->readyThresholdBytes * 80) / 100;
    return (availableBytes >= laneThreshold) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7780 (FUN_00AD7780, _sfply_ChkFin)
   *
   * What it does:
   * Evaluates all playback finish triggers and transitions to FIN when hit.
   */
  std::int32_t sfply_ChkFin(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (sfply_IsEtime(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    if (sfply_IsEtrg(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    if (sfply_IsStagnant(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    if (sfply_IsPlayTimeAutoStop(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    return 0;
  }

  /**
   * Address: 0x00AD77D0 (FUN_00AD77D0, _sfply_IsEtime)
   *
   * What it does:
   * Checks whether current playback time reached configured end time.
   */
  std::int32_t sfply_IsEtime(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kNoEndTimeSentinel = -4;
    const auto* const endTimeView = reinterpret_cast<const SfplyEndTimeView*>(workctrlSubobj);
    if (endTimeView->endTimeMajor == kNoEndTimeSentinel) {
      return 0;
    }

    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    std::int32_t currentTimeMajor = 0;
    std::int32_t currentTimeMinor = 0;
    SFTIM_GetTime(workctrlAddress, &currentTimeMajor, &currentTimeMinor);
    if (currentTimeMajor < 0) {
      return 0;
    }

    return (UTY_CmpTime(currentTimeMajor, currentTimeMinor, endTimeView->endTimeMajor, endTimeView->endTimeMinor) == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7830 (FUN_00AD7830, _sfply_IsEtrg)
   *
   * What it does:
   * Evaluates end-trigger condition policy from transfer termination flags.
   */
  std::int32_t sfply_IsEtrg(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCondEtrg = 25;
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->setConditions[kSfsetCond6] == 0 && stateView->setConditions[kSfsetCond5] == 0) {
      return 1;
    }

    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    const std::int32_t termFlag6 = SFTRN_GetTermFlg(workctrlAddress, 6);
    const std::int32_t termFlag7 = SFTRN_GetTermFlg(workctrlAddress, 7);

    switch (SFSET_GetCond(workctrlSubobj, kSfsetCondEtrg)) {
    case 0:
      return termFlag7 & termFlag6;
    case 1:
      return termFlag7;
    case 2:
      return termFlag6;
    case 3:
      return termFlag6 | termFlag7;
    default:
      return 0;
    }
  }

  /**
   * Address: 0x00ADAE70 (FUN_00ADAE70, _sftim_IsAudioStagnant)
   *
   * What it does:
   * Evaluates audio stagnation when audio output is enabled and condition `51`
   * provides a positive stagnation threshold; compares `vtimeMajor/vtimeMinor`
   * ratio against that threshold.
   */
  std::int32_t sftim_IsAudioStagnant(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCondAudioEnable = 6;
    constexpr std::int32_t kSfsetCondStagnationThreshold = 51;

    std::int32_t result = SFSET_GetCond(workctrlSubobj, kSfsetCondAudioEnable);
    if (result == 0) {
      return 0;
    }

    const std::int32_t stagnationThreshold = SFSET_GetCond(workctrlSubobj, kSfsetCondStagnationThreshold);
    result = stagnationThreshold;
    if (stagnationThreshold == 0) {
      return result;
    }

    std::int32_t vtimeMajor = 0;
    std::int32_t vtimeMinor = 0;
    auto* const counterLane = reinterpret_cast<SftimVblankCounterLaneView*>(
      static_cast<std::uint8_t*>(static_cast<void*>(workctrlSubobj)) + 0xD30
    );
    sftim_GetVtimeTmr(workctrlSubobj, counterLane, &vtimeMajor, &vtimeMinor);
    if (vtimeMinor == 0) {
      return 0;
    }

    return (vtimeMajor / vtimeMinor > stagnationThreshold) ? 1 : 0;
  }

  /**
   * Address: 0x00ADAE40 (FUN_00ADAE40, _SFTIM_IsStagnant)
   *
   * What it does:
   * Checks audio stagnation and emits SFLIB error `0xFF000222` when stagnant.
   */
  std::int32_t SFTIM_IsStagnant(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrTimerStagnant = static_cast<std::int32_t>(0xFF000222u);
    if (sftim_IsAudioStagnant(workctrlSubobj) == 0) {
      return 0;
    }

    (void)SFLIB_SetErr(SjPointerToAddress(workctrlSubobj), kSflibErrTimerStagnant);
    return 1;
  }

  /**
   * Address: 0x00AD78B0 (FUN_00AD78B0, _sfply_IsStagnant)
   *
   * What it does:
   * Checks playback stagnation under active-playing and non-paused conditions.
   */
  std::int32_t sfply_IsStagnant(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->statusLane != 4) {
      return 0;
    }
    if (stateView->startupGateFlag == 1) {
      return 0;
    }
    if (stateView->bpaActiveFlag == 1) {
      return 0;
    }
    return (SFTIM_IsStagnant(workctrlSubobj) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD78F0 (FUN_00AD78F0, _sfply_IsPlayTimeAutoStop)
   *
   * What it does:
   * Checks whether configured play-time auto-stop condition has been reached.
   */
  std::int32_t sfply_IsPlayTimeAutoStop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCondAutoStopTime = 54;
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->statusLane != 4) {
      return 0;
    }
    if (stateView->startupGateFlag == 1) {
      return 0;
    }
    if (stateView->bpaActiveFlag == 1) {
      return 0;
    }

    std::int32_t currentTimeMajor = 0;
    std::int32_t currentTimeMinor = 0;
    if (SFTIM_GetTimeSub(workctrlSubobj, &currentTimeMajor, &currentTimeMinor) != 0 || currentTimeMajor < 0) {
      return 0;
    }

    const std::int32_t autoStopTime = SFSET_GetCond(workctrlSubobj, kSfsetCondAutoStopTime);
    return (SFD_CmpTime(autoStopTime, 1000, currentTimeMajor, currentTimeMinor) != 0) ? 1 : 0;
  }

  extern "C" std::int64_t UTY_GetTmr();
  extern "C" std::int64_t UTY_GetTmrUnit();
  extern "C" std::int64_t SFTMR_GetTmr();
  extern "C" std::int64_t SFTMR_GetTmrUnit();
  extern "C" moho::SfplyTimerSummary* SFTMR_InitTsum(moho::SfplyTimerSummary* timerSummary);

  /**
   * Address: 0x00AD8420 (FUN_00AD8420, _SFPLY_MeasureFps)
   *
   * What it does:
   * Captures current timer ticks, computes elapsed ticks from the previous
   * sample pair, and updates per-handle FPS measurement lanes.
   */
  void SFPLY_MeasureFps(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    struct SfplyFpsMeasurementRuntimeView
    {
      std::uint8_t mUnknown00_967[0x968]; // +0x00
      std::int32_t measuredFrameCount; // +0x968
      std::uint8_t mUnknown96C_361F[0x2CB4]; // +0x96C
      std::uint32_t previousMeasureTicksLow; // +0x3620
      std::uint32_t previousMeasureTicksHigh; // +0x3624
      std::uint32_t currentMeasureTicksLow; // +0x3628
      std::uint32_t currentMeasureTicksHigh; // +0x362C
      std::uint32_t timerUnitLow; // +0x3630
      std::uint32_t timerUnitHigh; // +0x3634
      std::int32_t sampledFrameCount; // +0x3638
      float measuredFramesPerSecond; // +0x363C
    };
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, measuredFrameCount) == 0x968,
      "SfplyFpsMeasurementRuntimeView::measuredFrameCount offset must be 0x968"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, previousMeasureTicksLow) == 0x3620,
      "SfplyFpsMeasurementRuntimeView::previousMeasureTicksLow offset must be 0x3620"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, previousMeasureTicksHigh) == 0x3624,
      "SfplyFpsMeasurementRuntimeView::previousMeasureTicksHigh offset must be 0x3624"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, currentMeasureTicksLow) == 0x3628,
      "SfplyFpsMeasurementRuntimeView::currentMeasureTicksLow offset must be 0x3628"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, currentMeasureTicksHigh) == 0x362C,
      "SfplyFpsMeasurementRuntimeView::currentMeasureTicksHigh offset must be 0x362C"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, timerUnitLow) == 0x3630,
      "SfplyFpsMeasurementRuntimeView::timerUnitLow offset must be 0x3630"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, timerUnitHigh) == 0x3634,
      "SfplyFpsMeasurementRuntimeView::timerUnitHigh offset must be 0x3634"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, sampledFrameCount) == 0x3638,
      "SfplyFpsMeasurementRuntimeView::sampledFrameCount offset must be 0x3638"
    );
    static_assert(
      offsetof(SfplyFpsMeasurementRuntimeView, measuredFramesPerSecond) == 0x363C,
      "SfplyFpsMeasurementRuntimeView::measuredFramesPerSecond offset must be 0x363C"
    );

    auto* const runtimeView = reinterpret_cast<SfplyFpsMeasurementRuntimeView*>(workctrlSubobj);
    const std::int64_t currentTicks = SFTMR_GetTmr();
    runtimeView->currentMeasureTicksLow = static_cast<std::uint32_t>(currentTicks & 0xFFFFFFFFull);
    runtimeView->currentMeasureTicksHigh = static_cast<std::uint32_t>(static_cast<std::uint64_t>(currentTicks) >> 32u);

    const std::int64_t timerUnit = SFTMR_GetTmrUnit();
    runtimeView->timerUnitLow = static_cast<std::uint32_t>(timerUnit & 0xFFFFFFFFull);
    runtimeView->timerUnitHigh = static_cast<std::uint32_t>(static_cast<std::uint64_t>(timerUnit) >> 32u);

    const std::uint64_t previousTicksU64 =
      (static_cast<std::uint64_t>(runtimeView->previousMeasureTicksHigh) << 32u) | runtimeView->previousMeasureTicksLow;
    const std::uint64_t currentTicksU64 =
      (static_cast<std::uint64_t>(runtimeView->currentMeasureTicksHigh) << 32u) | runtimeView->currentMeasureTicksLow;
    const std::int64_t elapsedTicks = static_cast<std::int64_t>(currentTicksU64 - previousTicksU64);

    runtimeView->sampledFrameCount = runtimeView->measuredFrameCount;
    if (elapsedTicks != 0) {
      const std::int64_t scaledFrameTicks =
        static_cast<std::int64_t>(runtimeView->sampledFrameCount) * timerUnit;
      runtimeView->measuredFramesPerSecond =
        static_cast<float>(static_cast<double>(scaledFrameTicks) / static_cast<double>(elapsedTicks));
    }
  }

  /**
   * Address: 0x00AD7960 (FUN_00AD7960, _sfply_Fin)
   *
   * What it does:
   * Stops transfer lanes and transitions one playback handle to FIN phase.
   */
  std::int32_t sfply_Fin(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t stopResult = sfply_TrStop(workctrlSubobj);
    if (stopResult != 0) {
      return stopResult;
    }

    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->phaseLane = 6;
    SFPLY_MeasureFps(workctrlSubobj);
    return 0;
  }

  /**
   * Address: 0x00AD7990 (FUN_00AD7990, _SFPLY_DecideSvrStat)
   *
   * What it does:
   * Reduces all SFLIB handle states into one decode-server status lane:
   * `0` (idle), `1` (active work), or `2` (terminal/error-wait present).
   */
  std::int32_t sfply_DecideSvrStat()
  {
    std::int32_t idleHandleCount = 0;
    std::int32_t activeHandleCount = 0;
    std::int32_t terminalOrErrorHandleCount = 0;

    SFLIB_LockCs();
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(objectHandle);
      if (workctrlSubobj == nullptr) {
        continue;
      }

      const std::int32_t handleState = workctrlSubobj->handleState;
      if (handleState == 0) {
        ++idleHandleCount;
      } else if (handleState == 6 || handleState < 0) {
        ++terminalOrErrorHandleCount;
      } else {
        ++activeHandleCount;
      }
    }

    const std::int32_t serverStatus =
      (activeHandleCount != 0) ? 1 : ((terminalOrErrorHandleCount != 0) ? 2 : 0);
    gSflibLibWork.initState = serverStatus;
    SFLIB_UnlockCs();
    return serverStatus;
  }

  /**
   * Address: 0x00AD7A30 (FUN_00AD7A30, _sfply_Create)
   *
   * What it does:
   * Validates create parameters, allocates one free SFLIB slot, and initializes one SFPLY handle.
   */
  moho::SofdecSfdWorkctrlSubobj*
  sfply_Create(const moho::SfplyCreateParams* const createParams, const std::int32_t createContext)
  {
    if (sfply_ChkCrePara(createParams) != 0) {
      return nullptr;
    }

    const std::int32_t freeHandleIndex = sfply_SearchFreeHn();
    if (freeHandleIndex == -1) {
      (void)SFLIB_SetErr(0, kSflibErrCreateNoFreeHandle);
      return nullptr;
    }

    moho::SofdecSfdWorkctrlSubobj* const handle = sfply_InitHn(createParams, createContext);
    gSflibLibWork.objectHandles[static_cast<std::size_t>(freeHandleIndex)] = handle;
    return handle;
  }

  /**
   * Address: 0x00AD7A80 (FUN_00AD7A80, _sfply_ChkCrePara)
   *
   * What it does:
   * Validates SFPLY create parameters and reports SFLIB error lanes on invalid input.
   */
  std::int32_t sfply_ChkCrePara(const moho::SfplyCreateParams* const createParams)
  {
    if (createParams->workControlBuffer == nullptr) {
      return SFLIB_SetErr(0, kSflibErrCreateMissingWorkArea);
    }
    if (createParams->workControlSizeBytes >= 0x3660u) {
      return 0;
    }
    return SFLIB_SetErr(0, kSflibErrCreateWorkSizeTooSmall);
  }

  /**
   * Address: 0x00AD7AC0 (FUN_00AD7AC0, _sfply_SearchFreeHn)
   *
   * What it does:
   * Scans SFLIB object slots and returns first free handle index, or `-1`.
   */
  std::int32_t sfply_SearchFreeHn()
  {
    for (std::int32_t handleIndex = 0; handleIndex < static_cast<std::int32_t>(gSflibLibWork.objectHandles.size()); ++handleIndex) {
      if (gSflibLibWork.objectHandles[static_cast<std::size_t>(handleIndex)] == nullptr) {
        return handleIndex;
      }
    }
    return -1;
  }

  /**
   * Address: 0x00AD7C30 (FUN_00AD7C30, _sfply_InitMvInf)
   *
   * What it does:
   * Resets one SFPLY movie-info lane and restores default sentinel indices.
   */
  std::int32_t sfply_InitMvInf(moho::SfplyMovieInfo* const movieInfo)
  {
    *movieInfo = {};
    movieInfo->decodeDirection = 1;
    movieInfo->firstFrameIndex = -1;
    movieInfo->lastFrameIndex = -1;
    movieInfo->activeFrameIndex = -1;
    return -1;
  }

  /**
   * Address: 0x00AD7C80 (FUN_00AD7C80, _sfply_InitPlyInf)
   *
   * What it does:
   * Clears one playback-info lane and initializes all four embedded flow counters.
   */
  std::int32_t sfply_InitPlyInf(moho::SfplyPlaybackInfo* const playbackInfo)
  {
    *playbackInfo = {};
    (void)sfply_InitFlowCnt(&playbackInfo->flowCounter0);
    (void)sfply_InitFlowCnt(&playbackInfo->flowCounter1);
    (void)sfply_InitFlowCnt(&playbackInfo->flowCounter2);
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sfply_InitFlowCnt(&playbackInfo->flowCounter3)));
  }

  /**
   * Address: 0x00AD7CF0 (FUN_00AD7CF0, _sfply_InitFlowCnt)
   *
   * What it does:
   * Clears one SFPLY flow-counter lane.
   */
  moho::SfplyFlowCount* sfply_InitFlowCnt(moho::SfplyFlowCount* const flowCount)
  {
    flowCount->producedBytes = 0;
    flowCount->consumedBytes = 0;
    flowCount->producedPackets = 0;
    flowCount->consumedPackets = 0;
    flowCount->producedFrames = 0;
    flowCount->consumedFrames = 0;
    return flowCount;
  }

  /**
   * Address: 0x00AD7D10 (FUN_00AD7D10, _sfply_InitTmrInf)
   *
   * What it does:
   * Clears one timer-info lane and initializes all timer-summary sub-lanes.
   */
  std::int32_t sfply_InitTmrInf(moho::SfplyTimerInfo* const timerInfo)
  {
    *timerInfo = {};

    for (std::size_t summaryIndex = 0; summaryIndex < 5; ++summaryIndex) {
      (void)SFTMR_InitTsum(&timerInfo->summaries[summaryIndex]);
    }

    const std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(SFTMR_InitTsum(&timerInfo->summaries[5])));
    timerInfo->mUnknownC0.fill(0);
    return result;
  }

  std::int64_t sftmr_tmrunit = 0;

  /**
   * Address: 0x00AEADC0 (FUN_00AEADC0, _SFTMR_InitTsum)
   *
   * What it does:
   * Initializes one timer-summary lane to neutral sum/min/max/count defaults.
   */
  extern "C" moho::SfplyTimerSummary* SFTMR_InitTsum(moho::SfplyTimerSummary* const timerSummary)
  {
    timerSummary->accumulatedTicksLow = 0;
    timerSummary->accumulatedTicksHigh = 0;
    timerSummary->minTicksLow = -1;
    timerSummary->minTicksHigh = 0x7FFFFFFF;
    timerSummary->maxTicksLow = 0;
    timerSummary->maxTicksHigh = 0;
    timerSummary->sampleCount = 0;
    return timerSummary;
  }

  /**
   * Address: 0x00AEADF0 (FUN_00AEADF0, _SFTMR_AddTsum)
   *
   * What it does:
   * Adds one signed 64-bit sample into sum/min/max/count lanes for one timer
   * summary.
   */
  extern "C" void*
  SFTMR_AddTsum(void* const timerSummaryLane, const std::int32_t deltaLowWord, const std::int32_t deltaHighWord)
  {
    auto* const timerSummary = static_cast<moho::SfplyTimerSummary*>(timerSummaryLane);

    const std::uint64_t accumulatedTicks = (static_cast<std::uint64_t>(static_cast<std::uint32_t>(timerSummary->accumulatedTicksHigh)) << 32u)
      | static_cast<std::uint32_t>(timerSummary->accumulatedTicksLow);
    const std::uint64_t sampleTicks = (static_cast<std::uint64_t>(static_cast<std::uint32_t>(deltaHighWord)) << 32u)
      | static_cast<std::uint32_t>(deltaLowWord);
    const std::uint64_t mergedTicks = accumulatedTicks + sampleTicks;
    timerSummary->accumulatedTicksLow = static_cast<std::int32_t>(mergedTicks & 0xFFFFFFFFull);
    timerSummary->accumulatedTicksHigh = static_cast<std::int32_t>(mergedTicks >> 32u);

    const std::int64_t sampleTicksSigned = static_cast<std::int64_t>(sampleTicks);
    const std::int64_t minTicks = static_cast<std::int64_t>(
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(timerSummary->minTicksHigh)) << 32u)
      | static_cast<std::uint32_t>(timerSummary->minTicksLow)
    );
    if (sampleTicksSigned < minTicks) {
      timerSummary->minTicksLow = deltaLowWord;
      timerSummary->minTicksHigh = deltaHighWord;
    }

    const std::int64_t maxTicks = static_cast<std::int64_t>(
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(timerSummary->maxTicksHigh)) << 32u)
      | static_cast<std::uint32_t>(timerSummary->maxTicksLow)
    );
    if (sampleTicksSigned > maxTicks) {
      timerSummary->maxTicksLow = deltaLowWord;
      timerSummary->maxTicksHigh = deltaHighWord;
    }

    ++timerSummary->sampleCount;
    return timerSummary;
  }

  /**
   * Address: 0x00AEACF0 (FUN_00AEACF0, _SFTMR_GetTmr)
   *
   * What it does:
   * Resolves current timer ticks from UTY timer lanes when available, otherwise
   * falls back to external callback/global vblank timer lanes and updates the
   * global timer-unit cache.
   */
  extern "C" std::int64_t SFTMR_GetTmr()
  {
    if (UTY_IsTmrVoid() == 0) {
      sftmr_tmrunit = UTY_GetTmrUnit();
      return UTY_GetTmr();
    }

    auto* const lastHandle = gSfdDebugLastHandle;
    if (lastHandle != nullptr && lastHandle->handleState != 0) {
      const auto* const runtimeView = reinterpret_cast<const SftimWorkctrlRuntimeView*>(lastHandle);
      if (runtimeView->externalTimeCallbackAddress != 0) {
        std::int32_t callbackTimeMajor = 0;
        std::int32_t callbackTimerUnit = 0;
        const auto externalTimeCallback = reinterpret_cast<SftimExternalTimeCallback>(
          static_cast<std::uintptr_t>(static_cast<std::uint32_t>(runtimeView->externalTimeCallbackAddress))
        );
        (void)externalTimeCallback(runtimeView->externalCallbackContext, &callbackTimeMajor, &callbackTimerUnit);

        sftmr_tmrunit = static_cast<std::int64_t>(callbackTimerUnit);
        return static_cast<std::int64_t>(callbackTimeMajor);
      }
    }

    const auto* const timerState = reinterpret_cast<const SflibTimerStateRuntimeView*>(gSflibLibWork.timeState);
    sftmr_tmrunit = static_cast<std::int64_t>(timerState->timerVersion);
    return static_cast<std::int64_t>(timerState->verticalBlankCount) * 1000ll;
  }

  /**
   * Address: 0x00AEAD90 (FUN_00AEAD90, _SFTMR_GetTmrUnit)
   *
   * What it does:
   * Returns cached timer-unit ticks and lazily refreshes the cache through
   * `_SFTMR_GetTmr` when the cache is empty.
   */
  extern "C" std::int64_t SFTMR_GetTmrUnit()
  {
    if (sftmr_tmrunit == 0) {
      (void)SFTMR_GetTmr();
    }
    return sftmr_tmrunit;
  }

  /**
   * Address: 0x00AD7D80 (FUN_00AD7D80, _SFPLY_AddDecPic)
   *
   * What it does:
   * Adds decoded-picture count and calls optional condition callback `36`.
   */
  std::int32_t SFPLY_AddDecPic(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t decodedPictureDelta,
    const std::int32_t callbackContext
  )
  {
    constexpr std::int32_t kSfsetCondDecodedPicture = 36;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->pictureCounts.decodedPictureCount += decodedPictureDelta;

    const std::int32_t callbackAddress = SFSET_GetCond(workctrlSubobj, kSfsetCondDecodedPicture);
    if (callbackAddress == 0) {
      return 0;
    }

    const auto callback = reinterpret_cast<SfplyPictureCountCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackAddress))
    );
    return callback(workctrlSubobj, callbackContext, &stateView->pictureCounts);
  }

  /**
   * Address: 0x00AD7DC0 (FUN_00AD7DC0, _SFPLY_AddSkipPic)
   *
   * What it does:
   * Adds skipped-picture count and calls optional condition callback `37`.
   */
  std::int32_t SFPLY_AddSkipPic(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t skippedPictureDelta,
    const std::int32_t callbackContext
  )
  {
    constexpr std::int32_t kSfsetCondSkippedPicture = 37;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->pictureCounts.skippedPictureCount += skippedPictureDelta;

    const std::int32_t callbackAddress = SFSET_GetCond(workctrlSubobj, kSfsetCondSkippedPicture);
    if (callbackAddress == 0) {
      return 0;
    }

    const auto callback = reinterpret_cast<SfplyPictureCountCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackAddress))
    );
    return callback(workctrlSubobj, callbackContext, &stateView->pictureCounts);
  }

  /**
   * Address: 0x00AD7E00 (FUN_00AD7E00, _sfply_TrCreate)
   *
   * What it does:
   * Runs transfer setup callback lane `3` for one SFPLY handle.
   */
  std::int32_t sfply_TrCreate(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    return SFTRN_CallTrSetup(workctrlAddress, 3);
  }

  /**
   * Address: 0x00AD7E10 (FUN_00AD7E10, _SFD_Destroy)
   *
   * What it does:
   * Stops and destroys one SFD handle, then clears every matching global slot.
   */
  std::int32_t SFD_Destroy(void* const sfdHandle)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleDestroy);
    }

    (void)SFPLY_Stop(workctrlSubobj);

    auto* const fileHeaderView = reinterpret_cast<SfplyFileHeaderLaneView*>(workctrlSubobj);
    (void)SFHDS_FinishFhd(fileHeaderView->fileHeaderState);
    SFBUF_DestroySj(workctrlSubobj);

    const std::int32_t destroyResult = sfply_TrDestroy(workctrlSubobj);
    for (void*& objectHandle : gSflibLibWork.objectHandles) {
      if (objectHandle == workctrlSubobj) {
        objectHandle = nullptr;
      }
    }

    return destroyResult;
  }

  /**
   * Address: 0x00AD7E70 (FUN_00AD7E70, _sfply_TrDestroy)
   *
   * What it does:
   * Clears transfer status lanes and runs transfer teardown callback lane `4`.
   */
  std::int32_t sfply_TrDestroy(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->statusLane = 0;
    stateView->phaseLane = 0;

    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    return SFTRN_CallTrSetup(workctrlAddress, 4);
  }

  /**
   * Address: 0x00ADD950 (FUN_00ADD950, _SFPL2_Pause)
   *
   * What it does:
   * Applies pause transition mode against per-handle pause-depth/state lanes.
   */
  std::int32_t SFPL2_Pause(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t pauseMode);
  /**
   * Address: 0x00ADD9C0 (FUN_00ADD9C0, _sfpl2_PauseExec)
   *
   * What it does:
   * Executes pause transition side-effects when handle phase allows it.
   */
  std::int32_t sfpl2_PauseExec(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t pauseMode);
  /**
   * Address: 0x00ADD9F0 (FUN_00ADD9F0, _sfpl2_TrPause)
   *
   * What it does:
   * Dispatches transfer-layer pause transition (`7 -> 8`) for one handle.
   */
  std::int32_t sfpl2_TrPause(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t pauseMode);
  /**
   * Address: 0x00ADDA40 (FUN_00ADDA40, _SFPL2_Standby)
   *
   * What it does:
   * Switches one handle to standby phase lane.
   */
  std::int32_t SFPL2_Standby(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

  /**
   * Address: 0x00AD7E90 (FUN_00AD7E90, _SFD_Start)
   *
   * What it does:
   * Starts one SFD handle either in standby mode or immediate-play mode.
   */
  std::int32_t SFD_Start(void* const sfdHandle)
  {
    constexpr std::int32_t kSfsetCondStartMode = 47;
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleStart);
    }

    std::int32_t result = 0;
    if (SFSET_GetCond(workctrlSubobj, kSfsetCondStartMode) == 1) {
      result = SFPL2_Standby(workctrlSubobj);
    } else {
      result = sfply_Start(workctrlSubobj);
    }

    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->serverWaitFlag = 1;
    return result;
  }

  /**
   * Address: 0x00AD7EF0 (FUN_00AD7EF0, _sfply_Start)
   *
   * What it does:
   * Transitions one SFPLY handle into PLAY phase.
   */
  std::int32_t sfply_Start(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->phaseLane = 4;
    return 0;
  }

  /**
   * Address: 0x00AD7F00 (FUN_00AD7F00, _sfply_TrStart)
   *
   * What it does:
   * Dispatches transfer start transition (`7 -> 6`) for one SFPLY handle.
   */
  std::int32_t sfply_TrStart(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    return SFTRN_CallTrtTrif(workctrlAddress, 7, 6, 0, 0);
  }

  /**
   * Address: 0x00AD7F20 (FUN_00AD7F20, _SFD_Stop)
   *
   * What it does:
   * Stops one SFD handle and sets server-wait/start gate lane.
   */
  std::int32_t SFD_Stop(void* const sfdHandle)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleStop);
    }

    const std::int32_t result = SFPLY_Stop(workctrlSubobj);
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->serverWaitFlag = 1;
    return result;
  }

  struct SfdPauseRuntimeView
  {
    std::uint8_t reserved00_43[0x44]{}; // +0x00
    std::int32_t pauseStateDirtyFlag = 0; // +0x44
    std::uint8_t reserved48_4F[0x08]{}; // +0x48
    std::int32_t pauseRequestedFlag = 0; // +0x50
  };
  static_assert(
    offsetof(SfdPauseRuntimeView, pauseStateDirtyFlag) == 0x44,
    "SfdPauseRuntimeView::pauseStateDirtyFlag offset must be 0x44"
  );
  static_assert(
    offsetof(SfdPauseRuntimeView, pauseRequestedFlag) == 0x50,
    "SfdPauseRuntimeView::pauseRequestedFlag offset must be 0x50"
  );

  struct Sfpl2PauseRuntimeView
  {
    std::uint8_t reserved00_47[0x48]{}; // +0x00
    std::int32_t statusLane = 0; // +0x48
    std::int32_t phaseLane = 0; // +0x4C
    std::int32_t pauseRequestedFlag = 0; // +0x50
    std::int32_t pauseDepth = 0; // +0x54
  };
  static_assert(offsetof(Sfpl2PauseRuntimeView, statusLane) == 0x48, "Sfpl2PauseRuntimeView::statusLane offset must be 0x48");
  static_assert(offsetof(Sfpl2PauseRuntimeView, phaseLane) == 0x4C, "Sfpl2PauseRuntimeView::phaseLane offset must be 0x4C");
  static_assert(
    offsetof(Sfpl2PauseRuntimeView, pauseRequestedFlag) == 0x50,
    "Sfpl2PauseRuntimeView::pauseRequestedFlag offset must be 0x50"
  );
  static_assert(offsetof(Sfpl2PauseRuntimeView, pauseDepth) == 0x54, "Sfpl2PauseRuntimeView::pauseDepth offset must be 0x54");

  /**
   * Address: 0x00ADD9F0 (FUN_00ADD9F0, _sfpl2_TrPause)
   *
   * What it does:
   * Dispatches transfer-layer pause transition (`7 -> 8`) for one handle.
   */
  std::int32_t sfpl2_TrPause(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t pauseMode)
  {
    return SFTRN_CallTrtTrif(SjPointerToAddress(workctrlSubobj), 7, 8, pauseMode, 0);
  }

  /**
   * Address: 0x00ADD9C0 (FUN_00ADD9C0, _sfpl2_PauseExec)
   *
   * What it does:
   * Executes pause transition side-effects when current handle phase is standby
   * or play.
   */
  std::int32_t sfpl2_PauseExec(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t pauseMode)
  {
    const auto* const pauseView = reinterpret_cast<const Sfpl2PauseRuntimeView*>(workctrlSubobj);
    if (pauseView->phaseLane != 3 && pauseView->phaseLane != 4) {
      return 0;
    }

    (void)SFTIM_Pause(workctrlSubobj, pauseMode);
    return sfpl2_TrPause(workctrlSubobj, pauseMode);
  }

  /**
   * Address: 0x00ADD950 (FUN_00ADD950, _SFPL2_Pause)
   *
   * What it does:
   * Applies pause/unpause transition mode against per-handle pause depth, with
   * mode `2` forcing re-dispatch only in active status lane.
   */
  std::int32_t SFPL2_Pause(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t pauseMode)
  {
    auto* const pauseView = reinterpret_cast<Sfpl2PauseRuntimeView*>(workctrlSubobj);
    if (pauseMode == 0) {
      --pauseView->pauseDepth;
      if (pauseView->pauseDepth == 0) {
        return sfpl2_PauseExec(workctrlSubobj, 0);
      }
      return 0;
    }

    if (pauseMode == 1) {
      const std::int32_t previousDepth = pauseView->pauseDepth;
      pauseView->pauseDepth = previousDepth + 1;
      if (previousDepth == 0) {
        return sfpl2_PauseExec(workctrlSubobj, 1);
      }
      return 0;
    }

    if (pauseMode == 2 && pauseView->statusLane == 4) {
      return sfpl2_PauseExec(workctrlSubobj, 2);
    }
    return 0;
  }

  /**
   * Address: 0x00ADDA40 (FUN_00ADDA40, _SFPL2_Standby)
   *
   * What it does:
   * Switches one handle to standby phase lane and returns zero.
   */
  std::int32_t SFPL2_Standby(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const pauseView = reinterpret_cast<Sfpl2PauseRuntimeView*>(workctrlSubobj);
    pauseView->phaseLane = 3;
    return 0;
  }

  /**
   * Address: 0x00ADD8F0 (FUN_00ADD8F0, _SFD_Pause)
   *
   * What it does:
   * Validates one handle, updates pause-request state, dispatches SFPL2 pause
   * transition mode, and marks pause-state dirty lane.
   */
  std::int32_t SFD_Pause(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t pauseRequested
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandlePause = static_cast<std::int32_t>(0xFF000142u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandlePause);
    }

    auto* const pauseView = reinterpret_cast<SfdPauseRuntimeView*>(workctrlSubobj);
    std::int32_t pauseMode = 0;
    if (pauseRequested != 0) {
      pauseMode = (pauseView->pauseRequestedFlag != 0) ? 2 : 1;
    } else if (pauseView->pauseRequestedFlag == 0) {
      return 0;
    }

    pauseView->pauseRequestedFlag = pauseRequested;
    const std::int32_t result = SFPL2_Pause(workctrlSubobj, pauseMode);
    pauseView->pauseStateDirtyFlag = 1;
    return result;
  }

  /**
   * Address: 0x00ADDA10 (FUN_00ADDA10, _SFD_Standby)
   *
   * What it does:
   * Validates one handle and enters standby through SFPL2 standby lane.
   */
  std::int32_t SFD_Standby(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrInvalidHandleStandby = static_cast<std::int32_t>(0xFF000143u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleStandby);
    }
    return SFPL2_Standby(workctrlSubobj);
  }

  [[nodiscard]] static std::int32_t& SFPLY_ResetFlagLane()
  {
    return *reinterpret_cast<std::int32_t*>(&gSflibLibWork.objectHandles[0]);
  }

  /**
   * Address: 0x00AD7FA0 (FUN_00AD7FA0, _SFPLY_SetResetFlg)
   *
   * What it does:
   * Writes SFPLY global reset-guard flag and returns written value.
   */
  std::int32_t SFPLY_SetResetFlg(const std::int32_t enabled)
  {
    SFPLY_ResetFlagLane() = enabled;
    return enabled;
  }

  /**
   * Address: 0x00AD7FB0 (FUN_00AD7FB0, _SFPLY_GetResetFlg)
   *
   * What it does:
   * Reads SFPLY global reset-guard flag.
   */
  std::int32_t SFPLY_GetResetFlg()
  {
    return SFPLY_ResetFlagLane();
  }

  /**
   * Address: 0x00AD7F60 (FUN_00AD7F60, _SFPLY_Stop)
   *
   * What it does:
   * Stops transfer lanes and rebuilds/reset one SFPLY handle when needed.
   */
  std::int32_t SFPLY_Stop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->statusLane == 1) {
      return 0;
    }

    const std::int32_t stopResult = sfply_TrStop(workctrlSubobj);
    if (stopResult != 0) {
      return stopResult;
    }

    stateView->phaseLane = 0;
    stateView->statusLane = 0;
    (void)SFPLY_SetResetFlg(1);
    const std::int32_t resetResult = sfply_ResetHn(workctrlSubobj);
    (void)SFPLY_SetResetFlg(0);
    return resetResult;
  }

  /**
   * Address: 0x00AD7FC0 (FUN_00AD7FC0, _sfply_TrStop)
   *
   * What it does:
   * Dispatches transfer stop transition and updates local stop-state lanes.
   */
  std::int32_t sfply_TrStop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    std::int32_t result = 0;
    if (stateView->statusLane == 4) {
      const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
      result = SFTRN_CallTrtTrif(workctrlAddress, 7, 7, 0, 0);
      if (result != 0) {
        return result;
      }
    }

    stateView->statusLane = 1;
    stateView->phaseLane = 1;
    return 0;
  }

  struct SfplyGetFrameRuntimeView
  {
    std::uint8_t mUnknown00[0x58]{}; // +0x00
    std::int32_t frameApiType = 0; // +0x58
    std::uint8_t mUnknown5C[0x90C]{}; // +0x5C
    std::int32_t retainedFrameCount = 0; // +0x968
    std::int32_t releasedFrameCount = 0; // +0x96C
    std::uint8_t mUnknown970[0x2CB0]{}; // +0x970
    std::int32_t firstRetainedFrameTimeLow = 0; // +0x3620
    std::int32_t firstRetainedFrameTimeHigh = 0; // +0x3624
  };
  static_assert(offsetof(SfplyGetFrameRuntimeView, frameApiType) == 0x58, "SfplyGetFrameRuntimeView::frameApiType offset must be 0x58");
  static_assert(
    offsetof(SfplyGetFrameRuntimeView, retainedFrameCount) == 0x968,
    "SfplyGetFrameRuntimeView::retainedFrameCount offset must be 0x968"
  );
  static_assert(
    offsetof(SfplyGetFrameRuntimeView, releasedFrameCount) == 0x96C,
    "SfplyGetFrameRuntimeView::releasedFrameCount offset must be 0x96C"
  );
  static_assert(
    offsetof(SfplyGetFrameRuntimeView, firstRetainedFrameTimeLow) == 0x3620,
    "SfplyGetFrameRuntimeView::firstRetainedFrameTimeLow offset must be 0x3620"
  );
  static_assert(
    offsetof(SfplyGetFrameRuntimeView, firstRetainedFrameTimeHigh) == 0x3624,
    "SfplyGetFrameRuntimeView::firstRetainedFrameTimeHigh offset must be 0x3624"
  );

  using SfplyRecordGetFrameCallback = void(__cdecl*)(moho::SofdecSfdWorkctrlSubobj*, void*);

  extern "C" std::int64_t SFTMR_GetTmr();

  [[nodiscard]] SfplyGetFrameRuntimeView* AsSfplyGetFrameRuntimeView(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj) noexcept
  {
    return reinterpret_cast<SfplyGetFrameRuntimeView*>(workctrlSubobj);
  }

  [[nodiscard]] std::int32_t SfdWorkctrlToAddress(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj) noexcept
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
  }

  [[nodiscard]] moho::SofdecSfdWorkctrlSubobj* SfdAddressToWorkctrl(const std::int32_t sfdHandleAddress) noexcept
  {
    return reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfdHandleAddress))
    );
  }

  struct SfuoDescriptorView
  {
    std::int32_t word0 = 0; // +0x00
    std::int32_t word1 = 0; // +0x04
    std::int32_t word2 = 0; // +0x08
    std::int32_t word3 = 0; // +0x0C
  };
  static_assert(sizeof(SfuoDescriptorView) == 0x10, "SfuoDescriptorView size must be 0x10");

  struct SfdUserOutputRuntimeView
  {
    std::uint8_t mUnknown00[0x2158]{}; // +0x00
    std::int32_t* uochDescriptorWords = nullptr; // +0x2158
    std::uint8_t mPad215C[0x04]{}; // +0x215C — implicit 4-byte gap before sfbufLaneIndex
    std::int32_t sfbufLaneIndex = 0; // +0x2160
    std::uint8_t mUnknown2164[0x13B4]{}; // +0x2164
    std::int32_t uochInlineHeader = 0; // +0x3518
    SfuoDescriptorView uochInlineDescriptors[3]{}; // +0x351C
  };
  static_assert(
    offsetof(SfdUserOutputRuntimeView, uochDescriptorWords) == 0x2158,
    "SfdUserOutputRuntimeView::uochDescriptorWords offset must be 0x2158"
  );
  static_assert(
    offsetof(SfdUserOutputRuntimeView, sfbufLaneIndex) == 0x2160,
    "SfdUserOutputRuntimeView::sfbufLaneIndex offset must be 0x2160"
  );
  static_assert(
    offsetof(SfdUserOutputRuntimeView, uochInlineHeader) == 0x3518,
    "SfdUserOutputRuntimeView::uochInlineHeader offset must be 0x3518"
  );
  static_assert(
    offsetof(SfdUserOutputRuntimeView, uochInlineDescriptors) == 0x351C,
    "SfdUserOutputRuntimeView::uochInlineDescriptors offset must be 0x351C"
  );

  [[nodiscard]] SfuoDescriptorView*
  ResolveSfuoDescriptor(SfdUserOutputRuntimeView* const runtimeView, const std::int32_t descriptorIndex) noexcept
  {
    auto* const descriptors = reinterpret_cast<SfuoDescriptorView*>(runtimeView->uochDescriptorWords + 1);
    return &descriptors[descriptorIndex];
  }

  /**
   * Address: 0x00ACE2C0 (FUN_00ACE2C0, _sfuo_SetUoch)
   *
   * What it does:
   * Stores four user-output-channel descriptor words and returns descriptor
   * base.
   */
  SfuoDescriptorView* sfuo_SetUoch(
    SfuoDescriptorView* const descriptor,
    const std::int32_t word0,
    const std::int32_t word1,
    const std::int32_t word2,
    const std::int32_t word3
  )
  {
    descriptor->word0 = word0;
    descriptor->word1 = word1;
    descriptor->word2 = word2;
    descriptor->word3 = word3;
    return descriptor;
  }

  /**
   * Address: 0x00ACE2A0 (FUN_00ACE2A0, _sfuo_InitUoch)
   *
   * What it does:
   * Clears one user-output-channel descriptor to all-zero words.
   */
  SfuoDescriptorView* sfuo_InitUoch(SfuoDescriptorView* const descriptor)
  {
    return sfuo_SetUoch(descriptor, 0, 0, 0, 0);
  }

  /**
   * Address: 0x00ACE260 (FUN_00ACE260, _sfuo_InitInf)
   *
   * What it does:
   * Initializes one user-output descriptor table with three zeroed UOCH slots
   * and mirrors each slot into the selected SFBUF lane.
   */
  std::int32_t* sfuo_InitInf(
    const std::int32_t sfdHandleAddress,
    std::int32_t* const descriptorWords,
    const std::int32_t sfbufLaneIndex
  )
  {
    descriptorWords[0] = 0;
    auto* descriptor = reinterpret_cast<SfuoDescriptorView*>(descriptorWords + 1);

    std::int32_t* result = nullptr;
    for (std::int32_t slotIndex = 0; slotIndex < 3; ++slotIndex, ++descriptor) {
      (void)sfuo_InitUoch(descriptor);
      result = SFBUF_SetUoch(sfdHandleAddress, sfbufLaneIndex, slotIndex, &descriptor->word0);
    }
    return result;
  }

  struct SfdVideoOutputManualRuntimeView
  {
    std::uint8_t mUnknown00[0x20D8]{}; // +0x00
    std::int32_t sfbufLaneIndex = 0; // +0x20D8
  };
  static_assert(
    offsetof(SfdVideoOutputManualRuntimeView, sfbufLaneIndex) == 0x20D8,
    "SfdVideoOutputManualRuntimeView::sfbufLaneIndex offset must be 0x20D8"
  );

  /**
   * Address: 0x00ACFF10 (FUN_00ACFF10, _sfvom_IsTerm)
   *
   * What it does:
   * Returns `1` when video-output manual lane is configured to terminate
   * immediately or timer-side video termination is reached.
   */
  std::int32_t sfvom_IsTerm(const std::int32_t sfdHandleAddress)
  {
    auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);
    if (SFSET_GetCond(workctrlSubobj, 15) == 0) {
      return 1;
    }
    return (SFTIM_IsVideoTerm(workctrlSubobj) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00ACFF90 (FUN_00ACFF90, _sfvom_IsPrepEnd)
   *
   * What it does:
   * Reports immediate readiness for the manual video-output prep gate.
   */
  std::int32_t sfvom_IsPrepEnd(const std::int32_t /*sfdHandleAddress*/)
  {
    return 1;
  }

  /**
   * Address: 0x00ACFFA0 (FUN_00ACFFA0, _sfvom_OutputServer)
   *
   * What it does:
   * Manual video-output server lane currently has no body work.
   */
  std::int32_t sfvom_OutputServer(const std::int32_t /*sfdHandleAddress*/)
  {
    return 0;
  }

  /**
   * Address: 0x00ACFEC0 (FUN_00ACFEC0, _sfvom_ChkTermFlg)
   *
   * What it does:
   * Latches transfer-lane `6` termination once SFBUF lane term is raised and
   * manual-video termination predicate becomes true.
   */
  std::int32_t sfvom_ChkTermFlg(const std::int32_t sfdHandleAddress)
  {
    constexpr std::int32_t kVideoManualTransferLane = 6;
    std::int32_t result = SFTRN_GetTermFlg(sfdHandleAddress, kVideoManualTransferLane);
    if (result == 1) {
      return result;
    }

    auto* const runtimeView = reinterpret_cast<SfdVideoOutputManualRuntimeView*>(SfdAddressToWorkctrl(sfdHandleAddress));
    result = SFBUF_GetTermFlg(sfdHandleAddress, runtimeView->sfbufLaneIndex);
    if (result != 1) {
      return result;
    }

    result = sfvom_IsTerm(sfdHandleAddress);
    if (result != 0) {
      return SFTRN_SetTermFlg(sfdHandleAddress, kVideoManualTransferLane, 1);
    }
    return result;
  }

  /**
   * Address: 0x00ACFF40 (FUN_00ACFF40, _sfvom_ChkPrepFlg)
   *
   * What it does:
   * Latches transfer-lane `6` prep once SFBUF lane prep is raised and manual
   * video-output prep predicate becomes true.
   */
  std::int32_t sfvom_ChkPrepFlg(const std::int32_t sfdHandleAddress)
  {
    constexpr std::int32_t kVideoManualTransferLane = 6;
    std::int32_t result = SFTRN_GetPrepFlg(sfdHandleAddress, kVideoManualTransferLane);
    if (result == 1) {
      return result;
    }

    auto* const runtimeView = reinterpret_cast<SfdVideoOutputManualRuntimeView*>(SfdAddressToWorkctrl(sfdHandleAddress));
    result = SFBUF_GetPrepFlg(sfdHandleAddress, runtimeView->sfbufLaneIndex);
    if (result != 1) {
      return result;
    }

    result = sfvom_IsPrepEnd(sfdHandleAddress);
    if (result != 0) {
      return SFTRN_SetPrepFlg(sfdHandleAddress, kVideoManualTransferLane, 1);
    }
    return result;
  }

  /**
   * Address: 0x00AD0010 (FUN_00AD0010, _SFVOM_GetWrite)
   *
   * What it does:
   * Reports unsupported write-window API for manual video-output strategy.
   */
  std::int32_t SFVOM_GetWrite(const std::int32_t sfdHandleAddress)
  {
    return SFLIB_SetErr(sfdHandleAddress, static_cast<std::int32_t>(0xFF000701u));
  }

  /**
   * Address: 0x00ACFE60 (FUN_00ACFE60, _SFVOM_Init)
   *
   * What it does:
   * No-op init lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Init()
  {
    return 0;
  }

  /**
   * Address: 0x00ACFE70 (FUN_00ACFE70, _SFVOM_Finish)
   *
   * What it does:
   * No-op finish lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Finish()
  {
    return 0;
  }

  /**
   * Address: 0x00ACFFB0 (FUN_00ACFFB0, _SFVOM_Create)
   *
   * What it does:
   * No-op create lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Create()
  {
    return 0;
  }

  /**
   * Address: 0x00ACFFC0 (FUN_00ACFFC0, _SFVOM_Destroy)
   *
   * What it does:
   * No-op destroy lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Destroy()
  {
    return 0;
  }

  /**
   * Address: 0x00ACFFD0 (FUN_00ACFFD0, _SFVOM_RequestStop)
   *
   * What it does:
   * No-op request-stop lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_RequestStop()
  {
    return 0;
  }

  /**
   * Address: 0x00ACFFE0 (FUN_00ACFFE0, _SFVOM_Start)
   *
   * What it does:
   * No-op start lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Start()
  {
    return 0;
  }

  /**
   * Address: 0x00ACFFF0 (FUN_00ACFFF0, _SFVOM_Stop)
   *
   * What it does:
   * No-op stop lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Stop()
  {
    return 0;
  }

  /**
   * Address: 0x00AD0000 (FUN_00AD0000, _SFVOM_Pause)
   *
   * What it does:
   * No-op pause lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Pause()
  {
    return 0;
  }

  /**
   * Address: 0x00AD0020 (FUN_00AD0020, _SFVOM_AddWrite)
   *
   * What it does:
   * Reports unsupported write-commit API for manual video-output strategy.
   */
  std::int32_t SFVOM_AddWrite(const std::int32_t sfdHandleAddress)
  {
    return SFLIB_SetErr(sfdHandleAddress, static_cast<std::int32_t>(0xFF000701u));
  }

  /**
   * Address: 0x00AD0030 (FUN_00AD0030, _SFVOM_GetRead)
   *
   * What it does:
   * Returns one manual video-output read window while execution stage is `3`
   * or `4`; otherwise clears output lane and reports success.
   */
  std::int32_t SFVOM_GetRead(
    const std::int32_t sfdHandleAddress,
    std::int32_t* const outChunkWords,
    const std::int32_t maxBytes
  )
  {
    const auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);
    const auto* const execView = reinterpret_cast<const SfmpsExecRuntimeView*>(workctrlSubobj);
    if (execView->executionStage == 3 || execView->executionStage == 4) {
      const auto* const runtimeView = reinterpret_cast<const SfdVideoOutputManualRuntimeView*>(workctrlSubobj);
      return SFBUF_VfrmGetRead(
        sfdHandleAddress,
        runtimeView->sfbufLaneIndex,
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outChunkWords)),
        maxBytes
      );
    }

    *outChunkWords = 0;
    return 0;
  }

  /**
   * Address: 0x00AD0070 (FUN_00AD0070, _SFVOM_AddRead)
   *
   * What it does:
   * Commits one manual video-output read advance on the active SFBUF lane.
   */
  std::int32_t SFVOM_AddRead(
    const std::int32_t sfdHandleAddress,
    const std::int32_t arg0,
    const std::int32_t arg1
  )
  {
    const auto* const runtimeView =
      reinterpret_cast<const SfdVideoOutputManualRuntimeView*>(SfdAddressToWorkctrl(sfdHandleAddress));
    return SFBUF_VfrmAddRead(sfdHandleAddress, runtimeView->sfbufLaneIndex, arg0, arg1);
  }

  /**
   * Address: 0x00AD0090 (FUN_00AD0090, _SFVOM_Seek)
   *
   * What it does:
   * No-op seek lane for manual video-output transport runtime.
   */
  std::int32_t SFVOM_Seek()
  {
    return 0;
  }

  /**
   * Address: 0x00ACFE80 (FUN_00ACFE80, _SFVOM_ExecServer)
   *
   * What it does:
   * Runs manual video-output server tick when video condition (`5`) is enabled:
   * updates term/prep latches around the output lane body.
   */
  std::int32_t SFVOM_ExecServer(const std::int32_t sfdHandleAddress)
  {
    constexpr std::int32_t kSfsetCondVideoEnable = 5;
    auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);
    if (SFSET_GetCond(workctrlSubobj, kSfsetCondVideoEnable) == 0) {
      return 0;
    }

    (void)sfvom_ChkTermFlg(sfdHandleAddress);
    const std::int32_t outputResult = sfvom_OutputServer(sfdHandleAddress);
    (void)sfvom_ChkPrepFlg(sfdHandleAddress);
    return outputResult;
  }

  /**
   * Address: 0x00ACE1B0 (FUN_00ACE1B0, _sfuo_IsTerm)
   *
   * What it does:
   * Reports immediate termination readiness for user-output lane.
   */
  std::int32_t sfuo_IsTerm(const std::int32_t /*sfdHandleAddress*/)
  {
    return 1;
  }

  /**
   * Address: 0x00ACE210 (FUN_00ACE210, _sfuo_IsPrepEnd)
   *
   * What it does:
   * Reports immediate prep readiness for user-output lane.
   */
  std::int32_t sfuo_IsPrepEnd(const std::int32_t /*sfdHandleAddress*/)
  {
    return 1;
  }

  /**
   * Address: 0x00ACE220 (FUN_00ACE220, _sfuo_OutputServer)
   *
   * What it does:
   * User-output server lane currently has no body work.
   */
  std::int32_t sfuo_OutputServer(const std::int32_t /*sfdHandleAddress*/)
  {
    return 0;
  }

  /**
   * Address: 0x00ACE160 (FUN_00ACE160, _sfuo_ChkTermFlg)
   *
   * What it does:
   * Latches transfer-lane `8` termination once active SFBUF lane term is raised
   * and user-output termination predicate becomes true.
   */
  std::int32_t sfuo_ChkTermFlg(const std::int32_t sfdHandleAddress)
  {
    constexpr std::int32_t kUserOutputTransferLane = 8;
    std::int32_t result = SFTRN_GetTermFlg(sfdHandleAddress, kUserOutputTransferLane);
    if (result == 1) {
      return result;
    }

    auto* const runtimeView = reinterpret_cast<SfdUserOutputRuntimeView*>(SfdAddressToWorkctrl(sfdHandleAddress));
    result = SFBUF_GetTermFlg(sfdHandleAddress, runtimeView->sfbufLaneIndex);
    if (result != 1) {
      return result;
    }

    result = sfuo_IsTerm(sfdHandleAddress);
    if (result != 0) {
      return SFTRN_SetTermFlg(sfdHandleAddress, kUserOutputTransferLane, 1);
    }
    return result;
  }

  /**
   * Address: 0x00ACE1C0 (FUN_00ACE1C0, _sfuo_ChkPrepFlg)
   *
   * What it does:
   * Latches transfer-lane `8` prep once active SFBUF lane prep is raised and
   * user-output prep predicate becomes true.
   */
  std::int32_t sfuo_ChkPrepFlg(const std::int32_t sfdHandleAddress)
  {
    constexpr std::int32_t kUserOutputTransferLane = 8;
    std::int32_t result = SFTRN_GetPrepFlg(sfdHandleAddress, kUserOutputTransferLane);
    if (result == 1) {
      return result;
    }

    auto* const runtimeView = reinterpret_cast<SfdUserOutputRuntimeView*>(SfdAddressToWorkctrl(sfdHandleAddress));
    result = SFBUF_GetPrepFlg(sfdHandleAddress, runtimeView->sfbufLaneIndex);
    if (result != 1) {
      return result;
    }

    result = sfuo_IsPrepEnd(sfdHandleAddress);
    if (result != 0) {
      return SFTRN_SetPrepFlg(sfdHandleAddress, kUserOutputTransferLane, 1);
    }
    return result;
  }

  /**
   * Address: 0x00ACE130 (FUN_00ACE130, _SFUO_ExecServer)
   *
   * What it does:
   * Runs user-output server tick: updates term/prep latches around the output
   * lane body and returns lane output status.
   */
  std::int32_t SFUO_ExecServer(const std::int32_t sfdHandleAddress)
  {
    (void)sfuo_ChkTermFlg(sfdHandleAddress);
    const std::int32_t outputResult = sfuo_OutputServer(sfdHandleAddress);
    (void)sfuo_ChkPrepFlg(sfdHandleAddress);
    return outputResult;
  }

  /**
   * Address: 0x00ACE110 (FUN_00ACE110, _SFUO_Init)
   *
   * What it does:
   * No-op init lane for user-output transport runtime.
   */
  std::int32_t SFUO_Init()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE120 (FUN_00ACE120, _SFUO_Finish)
   *
   * What it does:
   * No-op finish lane for user-output transport runtime.
   */
  std::int32_t SFUO_Finish()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE230 (FUN_00ACE230, _SFUO_Create)
   *
   * What it does:
   * Binds the in-object user-output descriptor table and initializes its three
   * descriptor slots for the current SFBUF lane selection.
   */
  std::int32_t SFUO_Create(const std::int32_t sfdHandleAddress)
  {
    auto* const runtimeView = reinterpret_cast<SfdUserOutputRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfdHandleAddress))
    );
    runtimeView->uochDescriptorWords = &runtimeView->uochInlineHeader;
    (void)sfuo_InitInf(sfdHandleAddress, runtimeView->uochDescriptorWords, runtimeView->sfbufLaneIndex);
    return 0;
  }

  /**
   * Address: 0x00ACE2E0 (FUN_00ACE2E0, _SFUO_Destroy)
   *
   * What it does:
   * No-op destroy lane for user-output transport runtime.
   */
  std::int32_t SFUO_Destroy()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE2F0 (FUN_00ACE2F0, _SFUO_RequestStop)
   *
   * What it does:
   * No-op request-stop lane for user-output transport runtime.
   */
  std::int32_t SFUO_RequestStop()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE300 (FUN_00ACE300, _SFUO_Start)
   *
   * What it does:
   * No-op start lane for user-output transport runtime.
   */
  std::int32_t SFUO_Start()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE310 (FUN_00ACE310, _SFUO_Stop)
   *
   * What it does:
   * No-op stop lane for user-output transport runtime.
   */
  std::int32_t SFUO_Stop()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE320 (FUN_00ACE320, _SFUO_Pause)
   *
   * What it does:
   * No-op pause lane for user-output transport runtime.
   */
  std::int32_t SFUO_Pause()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE330 (FUN_00ACE330, _SFUO_GetWrite)
   *
   * What it does:
   * Reports unsupported user-output write-window API.
   */
  std::int32_t SFUO_GetWrite(const std::int32_t sfdHandleAddress)
  {
    return SFLIB_SetErr(sfdHandleAddress, static_cast<std::int32_t>(0xFF000601u));
  }

  /**
   * Address: 0x00ACE350 (FUN_00ACE350, _SFUO_AddWrite)
   *
   * What it does:
   * Reports unsupported user-output write-commit API.
   */
  std::int32_t SFUO_AddWrite(const std::int32_t sfdHandleAddress)
  {
    return SFLIB_SetErr(sfdHandleAddress, static_cast<std::int32_t>(0xFF000601u));
  }

  /**
   * Address: 0x00ACE370 (FUN_00ACE370, _SFUO_GetRead)
   *
   * What it does:
   * Reports unsupported user-output read-window API.
   */
  std::int32_t SFUO_GetRead(const std::int32_t sfdHandleAddress)
  {
    return SFLIB_SetErr(sfdHandleAddress, static_cast<std::int32_t>(0xFF000601u));
  }

  /**
   * Address: 0x00ACE390 (FUN_00ACE390, _SFUO_AddRead)
   *
   * What it does:
   * Reports unsupported user-output read-commit API.
   */
  std::int32_t SFUO_AddRead(const std::int32_t sfdHandleAddress)
  {
    return SFLIB_SetErr(sfdHandleAddress, static_cast<std::int32_t>(0xFF000601u));
  }

  /**
   * Address: 0x00ACE3B0 (FUN_00ACE3B0, _SFUO_Seek)
   *
   * What it does:
   * No-op seek lane for user-output transport runtime.
   */
  std::int32_t SFUO_Seek()
  {
    return 0;
  }

  /**
   * Address: 0x00ACE010 (FUN_00ACE010, _SFD_SetSystemUsrSj)
   *
   * What it does:
   * Writes one system user-SJ descriptor slot, then mirrors that descriptor
   * into the active SFBUF lane user-output slot table.
   */
  std::int32_t SFD_SetSystemUsrSj(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t uochSlotIndex,
    const std::int32_t word0,
    const std::int32_t word2,
    const std::int32_t word3
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetSystemUsrSj = static_cast<std::int32_t>(0xFF000192u);
    constexpr std::int32_t kSflibErrInvalidSfbufLaneForUserOutput = static_cast<std::int32_t>(0xFF000602u);
    constexpr std::int32_t kSfbufLaneSentinel = 8;

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetSystemUsrSj);
    }

    auto* const runtimeView = reinterpret_cast<SfdUserOutputRuntimeView*>(workctrlSubobj);
    if (runtimeView->sfbufLaneIndex == kSfbufLaneSentinel) {
      return SFLIB_SetErr(SfdWorkctrlToAddress(workctrlSubobj), kSflibErrInvalidSfbufLaneForUserOutput);
    }

    SfuoDescriptorView* const descriptor = ResolveSfuoDescriptor(runtimeView, uochSlotIndex);
    (void)sfuo_SetUoch(descriptor, word0, 0, word2, word3);
    (void)SFBUF_SetUoch(
      SfdWorkctrlToAddress(workctrlSubobj),
      runtimeView->sfbufLaneIndex,
      uochSlotIndex,
      &descriptor->word0
    );
    return 0;
  }

  /**
   * Address: 0x00ACE090 (FUN_00ACE090, _SFD_SetUsrSj)
   *
   * What it does:
   * Writes one user-SJ descriptor slot, then mirrors that descriptor into the
   * active SFBUF lane user-output slot table.
   */
  std::int32_t SFD_SetUsrSj(
    const std::int32_t sfdHandleAddress,
    const std::int32_t uochSlotIndex,
    const std::int32_t word0,
    const std::int32_t word1
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetUsrSj = static_cast<std::int32_t>(0xFF000191u);
    constexpr std::int32_t kSflibErrInvalidSfbufLaneForUserOutput = static_cast<std::int32_t>(0xFF000602u);
    constexpr std::int32_t kSfbufLaneSentinel = 8;

    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfdHandleAddress))
    );
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetUsrSj);
    }

    auto* const runtimeView = reinterpret_cast<SfdUserOutputRuntimeView*>(workctrlSubobj);
    if (runtimeView->sfbufLaneIndex == kSfbufLaneSentinel) {
      return SFLIB_SetErr(sfdHandleAddress, kSflibErrInvalidSfbufLaneForUserOutput);
    }

    SfuoDescriptorView* const descriptor = ResolveSfuoDescriptor(runtimeView, uochSlotIndex);
    (void)sfuo_SetUoch(descriptor, word0, word1, 0, 0);
    (void)SFBUF_SetUoch(sfdHandleAddress, runtimeView->sfbufLaneIndex, uochSlotIndex, &descriptor->word0);
    return 0;
  }

  void sfply_RecordGetFrmEvent(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, void* const frameAddress)
  {
    if (SFPLY_recordgetfrm == 0) {
      return;
    }

    const auto callback = reinterpret_cast<SfplyRecordGetFrameCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(SFPLY_recordgetfrm))
    );
    callback(workctrlSubobj, frameAddress);
  }

  /**
   * Address: 0x00AD86E0 (FUN_00AD86E0, _sfply_CheckGetFrmApi)
   *
   * What it does:
   * Latches the active frame-fetch API lane (`1` direct-frame, `2` id+frame)
   * and reports one SFLIB error when callers mix both APIs on one handle.
   */
  std::int32_t sfply_CheckGetFrmApi(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t frameApiType)
  {
    constexpr std::int32_t kSflibErrFrameApiMismatch = static_cast<std::int32_t>(0xFF000207u);
    auto* const frameView = AsSfplyGetFrameRuntimeView(workctrlSubobj);

    if (frameView->frameApiType == 0) {
      frameView->frameApiType = frameApiType;
      return 0;
    }

    if (frameView->frameApiType == frameApiType) {
      return 0;
    }

    return SFLIB_SetErr(SfdWorkctrlToAddress(workctrlSubobj), kSflibErrFrameApiMismatch);
  }

  /**
   * Address: 0x00AD84C0 (FUN_00AD84C0, _SFD_GetIdFrm)
   *
   * What it does:
   * Fetches one frame plus frame-id lane (`API type 2`), records optional
   * get-frame callback telemetry, and updates first-retain timestamp lanes.
   */
  std::int32_t
  SFD_GetIdFrm(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, std::int32_t* const outFrameId, void** const outFrame)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetIdFrm = static_cast<std::int32_t>(0xFF00013Au);
    if (outFrameId != nullptr) {
      *outFrameId = -1;
    }
    if (outFrame != nullptr) {
      *outFrame = nullptr;
    }

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      (void)SFLIB_SetErr(0, kSflibErrInvalidHandleGetIdFrm);
      return 0;
    }

    if (sfply_CheckGetFrmApi(workctrlSubobj, 2) != 0) {
      return 0;
    }

    (void)SFTRN_CallTrtTrif(
      SfdWorkctrlToAddress(workctrlSubobj),
      6,
      11,
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outFrame)),
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outFrameId))
    );
    sfply_RecordGetFrmEvent(workctrlSubobj, (outFrame != nullptr) ? *outFrame : nullptr);

    if (outFrame == nullptr || *outFrame == nullptr) {
      return 0;
    }

    auto* const frameView = AsSfplyGetFrameRuntimeView(workctrlSubobj);
    if (frameView->retainedFrameCount == 0) {
      const std::int64_t currentTime = SFTMR_GetTmr();
      const auto currentTimeU64 = static_cast<std::uint64_t>(currentTime);
      frameView->firstRetainedFrameTimeLow = static_cast<std::int32_t>(currentTimeU64 & 0xFFFFFFFFu);
      frameView->firstRetainedFrameTimeHigh = static_cast<std::int32_t>(currentTimeU64 >> 32u);
    }

    ++frameView->retainedFrameCount;
    return 1;
  }

  /**
   * Address: 0x00AD8570 (FUN_00AD8570, _SFD_RelIdFrm)
   *
   * What it does:
   * Releases one frame-id lane fetched through API mode `2`, increments the
   * release counter, and forwards release to transfer callback `6:12`.
   */
  std::int32_t SFD_RelIdFrm(const std::int32_t sfdHandleAddress, const std::int32_t frameId)
  {
    constexpr std::int32_t kSflibErrInvalidHandleRelIdFrm = static_cast<std::int32_t>(0xFF00013Bu);
    auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleRelIdFrm);
    }

    const std::int32_t apiCheckResult = sfply_CheckGetFrmApi(workctrlSubobj, 2);
    if (apiCheckResult != 0) {
      return apiCheckResult;
    }

    ++AsSfplyGetFrameRuntimeView(workctrlSubobj)->releasedFrameCount;
    return SFTRN_CallTrtTrif(sfdHandleAddress, 6, 12, 0, frameId);
  }

  /**
   * Address: 0x00AD85D0 (FUN_00AD85D0, _SFD_GetFrm)
   *
   * What it does:
   * Fetches one frame pointer lane (`API type 1`), keeps retain/release counters
   * in sync, and records optional get-frame callback telemetry.
   */
  std::int32_t SFD_GetFrm(const std::int32_t sfdHandleAddress, void** const outFrame)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetFrm = static_cast<std::int32_t>(0xFF000136u);
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfdHandleAddress))
    );

    if (outFrame != nullptr) {
      *outFrame = nullptr;
    }

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetFrm);
    }

    const std::int32_t apiCheckResult = sfply_CheckGetFrmApi(workctrlSubobj, 1);
    if (apiCheckResult != 0) {
      return apiCheckResult;
    }

    const std::int32_t transferResult = SFTRN_CallTrtTrif(
      sfdHandleAddress,
      6,
      11,
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outFrame)),
      0
    );

    if (outFrame != nullptr && *outFrame != nullptr) {
      auto* const frameView = AsSfplyGetFrameRuntimeView(workctrlSubobj);
      if (frameView->retainedFrameCount == frameView->releasedFrameCount) {
        if (frameView->retainedFrameCount == 0) {
          const std::int64_t currentTime = SFTMR_GetTmr();
          const auto currentTimeU64 = static_cast<std::uint64_t>(currentTime);
          frameView->firstRetainedFrameTimeLow = static_cast<std::int32_t>(currentTimeU64 & 0xFFFFFFFFu);
          frameView->firstRetainedFrameTimeHigh = static_cast<std::int32_t>(currentTimeU64 >> 32u);
        }
        ++frameView->retainedFrameCount;
      }
    }

    sfply_RecordGetFrmEvent(workctrlSubobj, (outFrame != nullptr) ? *outFrame : nullptr);
    return transferResult;
  }

  /**
   * Address: 0x00AD8670 (FUN_00AD8670, _SFD_RelFrm)
   *
   * What it does:
   * Releases one previously retained frame lane for direct-frame API usage and
   * forwards release into transfer callback lane `6:12`.
   */
  void SFD_RelFrm(const std::int32_t sfdHandleAddress, void* const frameAddress)
  {
    constexpr std::int32_t kSflibErrInvalidHandleRelFrm = static_cast<std::int32_t>(0xFF000137u);
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfdHandleAddress))
    );

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      (void)SFLIB_SetErr(0, kSflibErrInvalidHandleRelFrm);
      return;
    }

    if (sfply_CheckGetFrmApi(workctrlSubobj, 1) != 0) {
      return;
    }

    auto* const frameView = AsSfplyGetFrameRuntimeView(workctrlSubobj);
    if (frameView->releasedFrameCount < frameView->retainedFrameCount) {
      ++frameView->releasedFrameCount;
    }

    (void)SFTRN_CallTrtTrif(
      sfdHandleAddress,
      6,
      12,
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(frameAddress))),
      0
    );
  }

  /**
   * Address: 0x00ADC3B0 (FUN_00ADC3B0, _SFD_GetNumRemainFrm)
   *
   * What it does:
   * Returns over-time standby-frame count and applies frame-API retain/release
   * correction for direct-frame mode.
   */
  std::int32_t SFD_GetNumRemainFrm(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetNumRemainFrm = static_cast<std::int32_t>(0xFF000187u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      (void)SFLIB_SetErr(0, kSflibErrInvalidHandleGetNumRemainFrm);
      return 0;
    }

    std::int32_t result = sfmpvf_GetNumFrmOverTime(SfdWorkctrlToAddress(workctrlSubobj));
    const auto* const frameView = AsSfplyGetFrameRuntimeView(workctrlSubobj);
    if (
      frameView->frameApiType == 1 &&
      frameView->retainedFrameCount > frameView->releasedFrameCount &&
      result > 0
    ) {
      --result;
    }
    return result;
  }

  /**
   * Address: 0x00ADC4B0 (FUN_00ADC4B0, _SFD_IsNextFrmReady)
   *
   * What it does:
   * Returns `1` when the next standby frame is ready for retrieval on a valid
   * handle; reports SFLIB error and returns `0` for invalid handles.
   */
  std::int32_t SFD_IsNextFrmReady(const std::int32_t sfdHandleAddress)
  {
    constexpr std::int32_t kSflibErrInvalidHandleIsNextFrmReady = static_cast<std::int32_t>(0xFF000183u);
    auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      (void)SFLIB_SetErr(0, kSflibErrInvalidHandleIsNextFrmReady);
      return 0;
    }
    return (sfmpvf_ReferNextFrmReady(sfdHandleAddress) != 0) ? 1 : 0;
  }

  struct SfdTransferWriteCursor
  {
    std::int32_t writePtrAddress = 0; // +0x00
    std::int32_t availableBytes = 0; // +0x04
    std::int32_t availablePackets = 0; // +0x08
  };
  static_assert(sizeof(SfdTransferWriteCursor) == 0x0C, "SfdTransferWriteCursor size must be 0x0C");

  /**
   * Address: 0x00AD8320 (FUN_00AD8320, _SFD_GetWritePtr)
   *
   * What it does:
   * Validates one handle, then queries transfer lane `0:9` to fetch current
   * write cursor information.
   */
  std::int32_t SFD_GetWritePtr(const std::int32_t sfdHandleAddress, SfdTransferWriteCursor* const outWriteCursor)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetWritePtr = static_cast<std::int32_t>(0xFF000134u);
    auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetWritePtr);
    }

    return SFTRN_CallTrtTrif(
      sfdHandleAddress,
      0,
      9,
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(outWriteCursor))),
      0
    );
  }

  /**
   * Address: 0x00AD8360 (FUN_00AD8360, _SFD_AddWritePtr)
   *
   * What it does:
   * Validates one handle, then advances transfer lane `0:10` by the supplied
   * byte/packet deltas.
   */
  std::int32_t SFD_AddWritePtr(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t addBytes,
    const std::int32_t addPackets
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleAddWritePtr = static_cast<std::int32_t>(0xFF000135u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleAddWritePtr);
    }
    return SFTRN_CallTrtTrif(SfdWorkctrlToAddress(workctrlSubobj), 0, 10, addBytes, addPackets);
  }

  std::int32_t
  SFBUF_SetSupplySj(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, const std::int32_t* supplyDescriptorWords);
  std::int32_t SFPLY_DecideSvrStat();

  /**
   * Address: 0x00AD8710 (FUN_00AD8710, _SFD_SetSupplySj)
   *
   * What it does:
   * Validates one SFD handle, then binds one supply descriptor into SFBUF
   * transfer routing.
   */
  std::int32_t SFD_SetSupplySj(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const supplyDescriptorWords
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetSupplySj = static_cast<std::int32_t>(0xFF000139u);

    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetSupplySj);
    }

    return SFBUF_SetSupplySj(workctrlSubobj, supplyDescriptorWords);
  }

  /**
   * Address: 0x00AD8750 (FUN_00AD8750, _SFD_GetSvrStat)
   *
   * What it does:
   * Thin thunk that returns current SFPLY decode-server status.
   */
  std::int32_t SFD_GetSvrStat()
  {
    return SFPLY_DecideSvrStat();
  }

  /**
   * Address: 0x00AD8760 (FUN_00AD8760, _SFD_GetHnStat)
   *
   * What it does:
   * Returns current handle state lane (`+0x48`) and reports SFLIB error on
   * invalid handle checks.
   */
  std::int32_t SFD_GetHnStat(void* const sfdHandle)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetHandleState = static_cast<std::int32_t>(0xFF000111u);
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      (void)SFLIB_SetErr(0, kSflibErrInvalidHandleGetHandleState);
    }
    return workctrlSubobj->handleState;
  }

  struct SfdPlaybackInfoRuntimeView
  {
    std::uint8_t mUnknown00_94F[0x950]{}; // +0x00
    moho::SfplyPlaybackInfo playbackInfo{}; // +0x950
  };
  static_assert(
    offsetof(SfdPlaybackInfoRuntimeView, playbackInfo) == 0x950,
    "SfdPlaybackInfoRuntimeView::playbackInfo offset must be 0x950"
  );

  /**
   * Address: 0x00AD8990 (FUN_00AD8990, _SFD_GetPlyInf)
   *
   * What it does:
   * Copies one handle playback-info snapshot (`0xA8` bytes) to caller output.
   */
  std::int32_t SFD_GetPlyInf(const std::int32_t sfdHandleAddress, void* const outPlaybackInfo)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetPlaybackInfo = static_cast<std::int32_t>(0xFF000119u);
    auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetPlaybackInfo);
    }

    const auto* const runtimeView = reinterpret_cast<const SfdPlaybackInfoRuntimeView*>(workctrlSubobj);
    std::memcpy(outPlaybackInfo, &runtimeView->playbackInfo, sizeof(runtimeView->playbackInfo));
    return 0;
  }

  struct SfdTimerInfoRuntimeView
  {
    std::uint8_t mUnknown00_355F[0x3560]{}; // +0x00
    moho::SfplyTimerInfo timerInfo{}; // +0x3560
  };
  static_assert(offsetof(SfdTimerInfoRuntimeView, timerInfo) == 0x3560, "SfdTimerInfoRuntimeView::timerInfo offset must be 0x3560");

  [[nodiscard]] std::uint64_t PackUnsignedPair64(const std::int32_t lowWord, const std::int32_t highWord) noexcept
  {
    return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(highWord)) << 32u)
      | static_cast<std::uint32_t>(lowWord);
  }

  [[nodiscard]] std::int64_t PackSignedPair64(const std::int32_t lowWord, const std::int32_t highWord) noexcept
  {
    return (static_cast<std::int64_t>(highWord) << 32u) | static_cast<std::uint32_t>(lowWord);
  }

  void UnpackSignedPair64(
    const std::int64_t value,
    std::int32_t* const outLowWord,
    std::int32_t* const outHighWord
  ) noexcept
  {
    *outLowWord = static_cast<std::int32_t>(value & 0xFFFFFFFFll);
    *outHighWord = static_cast<std::int32_t>(value >> 32u);
  }

  /**
   * Address: 0x00AD89D0 (FUN_00AD89D0, _SFD_GetTmrInf)
   *
   * What it does:
   * Copies one handle timer-info snapshot and folds summaries `1..3` into
   * summary `0` using sum/min/max merge semantics for aggregate lanes.
   */
  std::int32_t SFD_GetTmrInf(const std::int32_t sfdHandleAddress, void* const outTimerInfo)
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetTimerInfo = static_cast<std::int32_t>(0xFF00011Au);
    auto* const workctrlSubobj = SfdAddressToWorkctrl(sfdHandleAddress);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetTimerInfo);
    }

    auto* const mergedTimerInfo = static_cast<moho::SfplyTimerInfo*>(outTimerInfo);
    const auto* const runtimeView = reinterpret_cast<const SfdTimerInfoRuntimeView*>(workctrlSubobj);
    std::memcpy(mergedTimerInfo, &runtimeView->timerInfo, sizeof(runtimeView->timerInfo));

    auto& aggregateSummary = mergedTimerInfo->summaries[0];
    for (std::size_t summaryIndex = 1; summaryIndex < 4; ++summaryIndex) {
      const auto& sourceSummary = mergedTimerInfo->summaries[summaryIndex];

      const std::uint64_t mergedSum =
        PackUnsignedPair64(aggregateSummary.accumulatedTicksLow, aggregateSummary.accumulatedTicksHigh)
        + PackUnsignedPair64(sourceSummary.accumulatedTicksLow, sourceSummary.accumulatedTicksHigh);
      aggregateSummary.accumulatedTicksLow = static_cast<std::int32_t>(mergedSum & 0xFFFFFFFFull);
      aggregateSummary.accumulatedTicksHigh = static_cast<std::int32_t>(mergedSum >> 32u);

      std::int64_t mergedMinPair = PackSignedPair64(aggregateSummary.minTicksLow, aggregateSummary.minTicksHigh);
      const std::int64_t sourceMinPair = PackSignedPair64(sourceSummary.minTicksLow, sourceSummary.minTicksHigh);
      if (sourceMinPair < mergedMinPair) {
        mergedMinPair = sourceMinPair;
      }
      UnpackSignedPair64(mergedMinPair, &aggregateSummary.minTicksLow, &aggregateSummary.minTicksHigh);

      std::int64_t mergedMaxPair = PackSignedPair64(aggregateSummary.maxTicksLow, aggregateSummary.maxTicksHigh);
      const std::int64_t sourceMaxPair = PackSignedPair64(sourceSummary.maxTicksLow, sourceSummary.maxTicksHigh);
      if (sourceMaxPair > mergedMaxPair) {
        mergedMaxPair = sourceMaxPair;
      }
      UnpackSignedPair64(mergedMaxPair, &aggregateSummary.maxTicksLow, &aggregateSummary.maxTicksHigh);

      aggregateSummary.sampleCount += sourceSummary.sampleCount;
    }

    if (reinterpret_cast<const SftimStatusGateRuntimeView*>(workctrlSubobj)->phaseLane == 4) {
      SFPLY_MeasureFps(workctrlSubobj);
    }
    return 0;
  }

  struct SfsetTransferHandleLaneView
  {
    std::int32_t transferHandleAddress = 0; // +0x00
    std::uint8_t reserved04_43[0x40]{}; // +0x04
  };
  static_assert(sizeof(SfsetTransferHandleLaneView) == 0x44, "SfsetTransferHandleLaneView size must be 0x44");

  struct SfsetTransferHandleTableRuntimeView
  {
    std::uint8_t reserved00_1F37[0x1F38]{}; // +0x00
    SfsetTransferHandleLaneView transferHandleLanes[9]{}; // +0x1F38
  };
  static_assert(
    offsetof(SfsetTransferHandleTableRuntimeView, transferHandleLanes) == 0x1F38,
    "SfsetTransferHandleTableRuntimeView::transferHandleLanes offset must be 0x1F38"
  );

  /**
   * Address: 0x00AD8AE0 (FUN_00AD8AE0, _SFSET_GetTrHn)
   *
   * What it does:
   * Resolves one transfer lane handle pointer and writes its handle value to
   * caller output (or zero when lane handle is missing).
   */
  std::int32_t* SFSET_GetTrHn(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t transferLaneIndex,
    std::int32_t* const outTransferHandle
  )
  {
    auto* const runtimeView = reinterpret_cast<SfsetTransferHandleTableRuntimeView*>(workctrlSubobj);
    SfsetTransferHandleLaneView* const laneView = &runtimeView->transferHandleLanes[transferLaneIndex];
    if (laneView->transferHandleAddress == 0) {
      *outTransferHandle = 0;
      return outTransferHandle;
    }

    auto* const transferHandleWords = reinterpret_cast<std::int32_t*>(SjAddressToPointer(laneView->transferHandleAddress));
    *outTransferHandle = transferHandleWords[0];
    return transferHandleWords;
  }

  /**
   * Address: 0x00AD8AA0 (FUN_00AD8AA0, _SFD_GetTrHn)
   *
   * What it does:
   * Validates one SFD handle and reads one transfer-handle lane from SFSET.
   */
  std::int32_t SFD_GetTrHn(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t transferLaneIndex,
    std::int32_t* const outTransferHandle
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetTransferHandle = static_cast<std::int32_t>(0xFF000117u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetTransferHandle);
    }

    (void)SFSET_GetTrHn(workctrlSubobj, transferLaneIndex, outTransferHandle);
    return 0;
  }

  struct SfdSofdecHeaderRuntimeView
  {
    std::uint8_t reserved00_77[0x78]{}; // +0x00
    std::int32_t fileHeaderState = 0; // +0x78
    std::uint8_t reserved7C_107[0x8C]{}; // +0x7C
    std::int32_t sofdecHeaderWordCount = 0; // +0x108
    std::int32_t sofdecHeaderWord0 = 0; // +0x10C
  };
  static_assert(
    offsetof(SfdSofdecHeaderRuntimeView, fileHeaderState) == 0x78,
    "SfdSofdecHeaderRuntimeView::fileHeaderState offset must be 0x78"
  );
  static_assert(
    offsetof(SfdSofdecHeaderRuntimeView, sofdecHeaderWordCount) == 0x108,
    "SfdSofdecHeaderRuntimeView::sofdecHeaderWordCount offset must be 0x108"
  );
  static_assert(
    offsetof(SfdSofdecHeaderRuntimeView, sofdecHeaderWord0) == 0x10C,
    "SfdSofdecHeaderRuntimeView::sofdecHeaderWord0 offset must be 0x10C"
  );

  /**
   * Address: 0x00AD8B10 (FUN_00AD8B10, _SFD_GetSofdecHeader)
   *
   * What it does:
   * Validates one handle and returns SOFDEC header lane pointer/count outputs
   * when file-header state is present.
   */
  std::int32_t SFD_GetSofdecHeader(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    std::int32_t* const outHeaderWordsAddress,
    std::int32_t* const outHeaderWordCount
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleGetSofdecHeader = static_cast<std::int32_t>(0xFF00011Cu);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetSofdecHeader);
    }

    auto* const runtimeView = reinterpret_cast<SfdSofdecHeaderRuntimeView*>(workctrlSubobj);
    if (runtimeView->fileHeaderState != 0) {
      *outHeaderWordsAddress = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&runtimeView->sofdecHeaderWord0))
      );
      *outHeaderWordCount = runtimeView->sofdecHeaderWordCount;
    } else {
      *outHeaderWordsAddress = 0;
      *outHeaderWordCount = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00AD8B70 (FUN_00AD8B70, _SFD_GetVersionStr)
   *
   * What it does:
   * Returns static CRI SFD runtime version banner string.
   */
  const char* SFD_GetVersionStr()
  {
    static constexpr char kSfdVersionString[] = "\nCRI SFD/PC Ver.1.958 Build:Feb 28 2005 21:33:54\n";
    return kSfdVersionString;
  }

  /**
   * Address: 0x00AD8B80 (FUN_00AD8B80, _SFD_IsVersionCompatible)
   *
   * What it does:
   * Returns `1` only when supplied SFD version tag equals `0x3640`.
   */
  std::int32_t SFD_IsVersionCompatible(const char* const /*versionText*/, const std::int32_t versionTag)
  {
    constexpr std::int32_t kSfdVersionTagCompat = 0x3640;
    return (versionTag == kSfdVersionTagCompat) ? 1 : 0;
  }

  struct SfdUserSkipCallbackRuntimeView
  {
    std::uint8_t reserved00_D47[0xD48]{};
    std::int32_t userSkipCallbackAddress = 0; // +0xD48
  };
  static_assert(
    offsetof(SfdUserSkipCallbackRuntimeView, userSkipCallbackAddress) == 0xD48,
    "SfdUserSkipCallbackRuntimeView::userSkipCallbackAddress offset must be 0xD48"
  );

  /**
   * Address: 0x00ADB390 (FUN_00ADB390, _SFD_SetUsrIsSkipFn)
   *
   * What it does:
   * Binds one user skip callback lane on a validated SFD handle.
   */
  std::int32_t SFD_SetUsrIsSkipFn(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t callbackAddress
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetUsrIsSkipFn = static_cast<std::int32_t>(0xFF000124u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetUsrIsSkipFn);
    }

    auto* const runtimeView = reinterpret_cast<SfdUserSkipCallbackRuntimeView*>(workctrlSubobj);
    runtimeView->userSkipCallbackAddress = callbackAddress;
    return 0;
  }

  struct SfdExternalClockRuntimeView
  {
    std::uint8_t mUnknown00_1003[0x1004]{}; // +0x00
    std::int32_t externalClockCallbackAddress = 0; // +0x1004
    std::uint8_t mUnknown1008_1013[0x0C]{}; // +0x1008
    std::int32_t externalClockParam0 = 0; // +0x1014
    std::int32_t externalClockParam1 = 0; // +0x1018
  };
  static_assert(
    offsetof(SfdExternalClockRuntimeView, externalClockCallbackAddress) == 0x1004,
    "SfdExternalClockRuntimeView::externalClockCallbackAddress offset must be 0x1004"
  );
  static_assert(
    offsetof(SfdExternalClockRuntimeView, externalClockParam0) == 0x1014,
    "SfdExternalClockRuntimeView::externalClockParam0 offset must be 0x1014"
  );
  static_assert(
    offsetof(SfdExternalClockRuntimeView, externalClockParam1) == 0x1018,
    "SfdExternalClockRuntimeView::externalClockParam1 offset must be 0x1018"
  );

  /**
   * Address: 0x00ADB430 (FUN_00ADB430, _SFD_SetExtClockFn)
   *
   * What it does:
   * Binds/unbinds one external clock callback lane and updates sync/timer
   * conditions (`15` and `71`) accordingly.
   */
  std::int32_t SFD_SetExtClockFn(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t callbackAddress,
    const std::int32_t callbackParam0,
    const std::int32_t callbackParam1
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetExternalClockCallback = static_cast<std::int32_t>(0xFF000129u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetExternalClockCallback);
    }

    auto* const runtimeView = reinterpret_cast<SfdExternalClockRuntimeView*>(workctrlSubobj);
    if (callbackAddress != 0) {
      runtimeView->externalClockCallbackAddress = callbackAddress;
      runtimeView->externalClockParam0 = callbackParam0;
      runtimeView->externalClockParam1 = callbackParam1;
      (void)SFSET_SetCond(workctrlSubobj, 15, 5);
      (void)SFSET_SetCond(workctrlSubobj, 71, 0);
    } else {
      (void)SFSET_SetCond(workctrlSubobj, 71, 1);
      (void)SFSET_SetCond(workctrlSubobj, 15, 1);
      runtimeView->externalClockParam1 = callbackParam1;
      runtimeView->externalClockParam0 = callbackParam0;
      runtimeView->externalClockCallbackAddress = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00AD8EB0 (FUN_00AD8EB0, _sflib_InitBaseLib)
   *
   * What it does:
   * Initializes SFLIB base runtime lane.
   */
  void sflib_InitBaseLib()
  {
    SJRBF_Init();
  }

  /**
   * Address: 0x00AD8EC0 (FUN_00AD8EC0, _sflib_FinishBaseLib)
   *
   * What it does:
   * Finalizes SFLIB base runtime lane.
   */
  std::int32_t sflib_FinishBaseLib()
  {
    return SJRBF_Finish();
  }

  /**
   * Address: 0x00AD8ED0 (FUN_00AD8ED0, _sflib_InitSub)
   *
   * What it does:
   * Initializes SFLIB subordinate runtime lanes.
   */
  void sflib_InitSub()
  {
    SFPLY_Init();
    (void)SFHDS_Init();
  }

  /**
   * Address: 0x00AD8EE0 (FUN_00AD8EE0, _sflib_FinishSub)
   *
   * What it does:
   * Finalizes SFLIB subordinate runtime lanes.
   */
  std::int32_t sflib_FinishSub()
  {
    return SFHDS_Finish();
  }

  /**
   * Address: 0x00AD8EF0 (FUN_00AD8EF0, _sflib_InitCs)
   *
   * What it does:
   * No-op critical-section init lane for this binary build.
   */
  void sflib_InitCs()
  {
  }

  /**
   * Address: 0x00AD8F00 (FUN_00AD8F00, _sflib_FinishCs)
   *
   * What it does:
   * No-op critical-section finalize lane for this binary build.
   */
  void sflib_FinishCs()
  {
  }

  /**
   * Address: 0x00AD8C90 (FUN_00AD8C90, _SFD_Finish)
   *
   * What it does:
   * Destroys all active SFD object lanes, finalizes timer/buffer/transfer
   * subsystems, and returns transfer-finalize result when non-zero.
   */
  std::int32_t SFD_Finish()
  {
    std::int32_t destroyResult = 0;
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      if (objectHandle != nullptr) {
        destroyResult = SFD_Destroy(objectHandle);
      }
    }

    SFTIM_Finish(gSflibLibWork.timeState);
    SFBUF_Finish();
    const std::int32_t transferResult = SFTRN_Finish(&gSflibLibWork.transferInitState);

    sflib_FinishCs();
    sflib_FinishSub();
    sflib_FinishBaseLib();

    if (transferResult != 0) {
      return transferResult;
    }

    return destroyResult;
  }
