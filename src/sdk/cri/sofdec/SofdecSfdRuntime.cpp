  struct SofdecHeaderAnalyzerRuntimeView
  {
    std::uint8_t bytes[0x10];
  };
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
  extern "C" std::int32_t func_SofDec_Unk5Unused(SofdecHeaderAnalyzerRuntimeView* handle);
  extern "C" void
    func_SofDec_InitSfhObj(SofdecHeaderAnalyzerRuntimeView* handle, std::int32_t bufferAddress, std::int32_t remainingBytes);

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

  struct M2TLibraryRuntimeView
  {
    std::uint32_t m2tInitRefCount = 0; // +0x00
    std::uint8_t m2tInitScratch[0x80]{}; // +0x04
    std::uint8_t reserved84[0x1C]{}; // +0x84
    std::uint32_t m2pesInitRefCount = 0; // +0xA0
    std::uint8_t m2pesInitScratch[0x100]{}; // +0xA4
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
    offsetof(M2TLibraryRuntimeView, m2pesInitScratch) == 0xA4,
    "M2TLibraryRuntimeView::m2pesInitScratch offset must be 0xA4"
  );
  static_assert(sizeof(M2TLibraryRuntimeView) == 0x1A4, "M2TLibraryRuntimeView size must be 0x1A4");

  extern "C" M2TLibraryRuntimeView M2T_libobj;
  extern "C" const char* cri_verstr_ptr_m2t;
  extern "C" const char* cri_verstr_ptr_m2spes;

  /**
   * Address: 0x00AE3240 (FUN_00AE3240, _M2T_Init)
   *
   * What it does:
   * Updates the M2T version-string pointer, bumps the shared M2T init
   * reference count, and clears M2T startup scratch lanes on first init.
   */
  extern "C" std::int32_t M2T_Init()
  {
    static constexpr char kM2TVersionString[] = "\nCRI M2T/PC Ver.1.022 Build:Feb 28 2005 21:37:19\n";
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
   * Address: 0x00AE0C80 (FUN_00AE0C80, _M2PES_Init)
   *
   * What it does:
   * Updates CRI M2PES version-string pointer, bumps the shared M2T init
   * reference count, and clears the M2PES scratch lane on first init.
   */
  extern "C" std::int32_t M2PES_Init()
  {
    static constexpr char kM2PesVersionString[] = "\nCRI M2PES/PC Ver.1.022 Build:Feb 28 2005 21:37:17\n";
    cri_verstr_ptr_m2spes = kM2PesVersionString;

    const std::uint32_t previousRefCount = M2T_libobj.m2pesInitRefCount;
    M2T_libobj.m2pesInitRefCount = previousRefCount + 1u;
    if (previousRefCount == 0u) {
      std::memset(M2T_libobj.m2pesInitScratch, 0, sizeof(M2T_libobj.m2pesInitScratch));
      return 0;
    }

    return static_cast<std::int32_t>(previousRefCount + 1u);
  }

  struct SofdecCreateStreamDescriptor;

  struct SofdecCreateInfoRuntimeView
  {
    std::int32_t headerWord0 = 0; // +0x00
    const SofdecCreateStreamDescriptor* streamDescriptor = nullptr; // +0x04
    const SofdecCreateStreamDescriptor* videoDescriptor = nullptr; // +0x08
    std::int32_t reserved0C = 0; // +0x0C
    std::int32_t packetSizeBytes = 0; // +0x10
    std::int32_t videoWidthPixels = 0; // +0x14
    std::int32_t videoHeightPixels = 0; // +0x18
    std::int32_t streamTimingMetric = 0; // +0x1C
    std::int32_t videoFrameMetric = 0; // +0x20
  };
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, streamDescriptor) == 0x04,
    "SofdecCreateInfoRuntimeView::streamDescriptor offset must be 0x04"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, videoDescriptor) == 0x08,
    "SofdecCreateInfoRuntimeView::videoDescriptor offset must be 0x08"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, packetSizeBytes) == 0x10,
    "SofdecCreateInfoRuntimeView::packetSizeBytes offset must be 0x10"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, streamTimingMetric) == 0x1C,
    "SofdecCreateInfoRuntimeView::streamTimingMetric offset must be 0x1C"
  );
  static_assert(
    offsetof(SofdecCreateInfoRuntimeView, videoFrameMetric) == 0x20,
    "SofdecCreateInfoRuntimeView::videoFrameMetric offset must be 0x20"
  );
  static_assert(sizeof(SofdecCreateInfoRuntimeView) == 0x24, "SofdecCreateInfoRuntimeView size must be 0x24");

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

  extern "C" SofdecCreateStreamDescriptor SFD_tr_sd_mps;
  extern "C" SofdecCreateStreamDescriptor SFD_tr_vd_mpv;
  extern "C" SfcreHeaderRuntimeView sfcre_fhd;
  extern "C" std::int32_t
    sfcre_AnalyPackSiz(std::int32_t bufferAddress, std::int32_t sizeBytes, std::int32_t* outPacketSizeBytes);
  extern "C" std::int32_t sfcre_AnalyMuxRate(
    std::int32_t decodeBufferAddress,
    std::int32_t decodeSizeBytes,
    std::int32_t* outMuxRateUnits50BytesPerSecond
  );
  extern "C" void sfcre_AnalySfh(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t sfcre_AnalyAudio(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" void sfcre_AnalyMpv(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
  extern "C" std::int32_t SFHDS_IsSfdHeader(std::int32_t bufferAddress, std::int32_t sizeBytes);
  extern "C" void sfcre_ProcessHdr(std::int32_t bufferAddress, std::int32_t sizeBytes, std::int32_t headerAddress);
  extern "C" char* MPS_SearchDelim(char* buffer, std::int32_t sizeBytes, std::int32_t delimiterMask);
  extern "C" char* sfcre_GetPketData(std::int32_t packetAddress, std::int32_t packetWindowBytes);
  extern "C" std::int32_t sfcre_AnalyAdx(char* buffer, std::int32_t sizeBytes, SofdecCreateInfoRuntimeView* createInfo);
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

  extern "C" void mwPlySaveRsc();
  extern "C" void mwPlyRestoreRsc();
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

  extern "C" void sfmpvf_SearchStbyFrm(
    std::int32_t workctrlAddress,
    void* searchState,
    std::int32_t* outFrameAddress
  );
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
    std::uint32_t searchState = 0;

    SFLIB_LockCs();

    const auto* const workctrlStorage =
      static_cast<const std::uint8_t*>(SjAddressToPointer(workctrlAddress));
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
    std::int32_t destinationAddress,
    std::int32_t sourceAddress,
    std::int32_t windowBytes
  );
  std::int32_t SFD_GetVideoCh(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
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
  std::int32_t M2TSD_TermSupply(const std::int32_t streamSupplyAddress);
  std::int32_t M2TSD_GetStat(const std::int32_t streamSupplyAddress);
  std::int32_t MPS_Create();
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
  std::int32_t MPS_GetElementaryInfo(
    const void* mpsHandle,
    std::int32_t* outElementaryCount,
    const MpsElementaryInfoEntryView** outElementaryEntries
  );
  std::int32_t SFADXT_SetAudioStreamType(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t elementaryStreamType);
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
  std::int32_t MPS_SetPesSw(const std::int32_t mpsHandleAddress, const std::int32_t pesSwitchCondition);
  std::int32_t MPS_SetSystemFn(
    const std::int32_t mpsHandleAddress,
    const std::int32_t systemFnCondition,
    const std::int32_t systemFnAuxCondition
  );
  std::int32_t SFBUF_RingGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    void* outReadDescriptor
  );
  std::int32_t SFBUF_RingAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addBytes
  );
  std::int32_t SFTIM_SetSpeed(const std::int32_t workctrlAddress, const std::int32_t speedRational);
  std::int32_t SFAOAP_SetSpeed(const std::int32_t workctrlAddress, const std::int32_t speedRational);

  struct SfmpsSupplyLaneRuntimeView
  {
    std::int32_t reserved00 = 0; // +0x00
    std::int32_t supplyJoinAddress = 0; // +0x04
    std::int32_t reserved08 = 0; // +0x08
    std::int32_t supplyWindowBytes = 0; // +0x0C
    std::uint8_t reserved10[0x64]{}; // +0x10
  };
  static_assert(
    offsetof(SfmpsSupplyLaneRuntimeView, supplyJoinAddress) == 0x04,
    "SfmpsSupplyLaneRuntimeView::supplyJoinAddress offset must be 0x04"
  );
  static_assert(
    offsetof(SfmpsSupplyLaneRuntimeView, supplyWindowBytes) == 0x0C,
    "SfmpsSupplyLaneRuntimeView::supplyWindowBytes offset must be 0x0C"
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
    std::int32_t copyElemOutSourceAddress = 0; // +0x150
    std::int32_t copyElemOutWindowBytes = 0; // +0x154
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
    offsetof(SfmpsParserRuntimeView, copyElemOutSourceAddress) == 0x150,
    "SfmpsParserRuntimeView::copyElemOutSourceAddress offset must be 0x150"
  );
  static_assert(
    offsetof(SfmpsParserRuntimeView, copyElemOutWindowBytes) == 0x154,
    "SfmpsParserRuntimeView::copyElemOutWindowBytes offset must be 0x154"
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
    std::uint8_t reserved16C0[0x8BC]{};
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
    const std::int32_t destinationAddress,
    const std::int32_t sourceAddress,
    const std::int32_t windowBytes
  )
  {
    constexpr std::int32_t kSflibErrInvalidHandleSetElementOutSj = static_cast<std::int32_t>(0xFF000171u);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetElementOutSj);
    }

    if (elementType >= 188 && elementType <= 255) {
      auto* const parserRuntime = getSfmpsParserRuntime(workctrlSubobj);
      parserRuntime->copyElemOutSourceAddress = sourceAddress;
      parserRuntime->copyElemOutWindowBytes = windowBytes;
      parserRuntime->elementOutSjByElementType[elementType - 188] = destinationAddress;
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
      &readDescriptor
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
    std::uint8_t mUnknownE7C_FAB[0x130]{}; // +0xE7C
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

  using SftimGetNowTimeFunction =
    std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t* outTimeMajor, std::int32_t* outTimeMinor);
  using SftimExternalTimeCallback =
    std::int32_t(__cdecl*)(std::int32_t callbackContext, std::int32_t** outExternalMinor, std::int32_t** outExternalMajor);
  struct SftimTimecodeLaneView
  {
    std::int32_t frameRateIndex = 0; // +0x00
    std::int32_t modeIndex = 0; // +0x04
  };
  static_assert(
    offsetof(SftimTimecodeLaneView, frameRateIndex) == 0x00,
    "SftimTimecodeLaneView::frameRateIndex offset must be 0x00"
  );
  static_assert(offsetof(SftimTimecodeLaneView, modeIndex) == 0x04, "SftimTimecodeLaneView::modeIndex offset must be 0x04");
  static_assert(sizeof(SftimTimecodeLaneView) == 0x08, "SftimTimecodeLaneView size must be 0x08");

  using SftimTc2TimeFunction = std::int32_t(__cdecl*)(
    std::int32_t frameRateUnits,
    SftimTimecodeLaneView* timecodeLane,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );

  extern "C" std::int32_t SFTIM_prate[];
  extern "C" SftimTc2TimeFunction sftim_tc2time[];

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

  std::int32_t sftim_CntupHnVbIn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sftim_UpdateTime(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sftim_HnVbIn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
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
  std::int32_t sftim_IsTimeIncre(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t
  sftim_IsVbinStIncre(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, SftimVblankCounterLaneView* counterLane);
  std::int32_t
  sftim_ResetVtimeTmr(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, SftimVblankCounterLaneView* counterLane);
  std::int32_t SFTIM_IsGetFrmTime(const std::int32_t workctrlAddress, const std::int32_t frameReadyWindowAddress);

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

    const std::int32_t result = SFTMR_InitTsum(&timerInfo->summaries[5]);
    timerInfo->mUnknownC0.fill(0);
    return result;
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

