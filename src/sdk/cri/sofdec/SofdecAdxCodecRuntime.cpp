  /**
   * Address: 0x00B19610 (FUN_00B19610, _ADXAMP_Init)
   *
   * What it does:
   * Increments ADXAMP init-refcount and clears ADXAMP object pool on first init.
   */
  [[maybe_unused]] std::int32_t ADXAMP_Init()
  {
    const std::int32_t previousCount = adxsmp_init_cnt;
    if (previousCount == 0) {
      std::memset(adxamp_obj, 0, sizeof(adxamp_obj));
    }
    ++adxsmp_init_cnt;
    return previousCount;
  }

  /**
   * Address: 0x00B19630 (FUN_00B19630, _ADXAMP_Finish)
   *
   * What it does:
   * Decrements ADXAMP init-refcount and clears ADXAMP object pool on last finish.
   */
  [[maybe_unused]] std::int32_t ADXAMP_Finish()
  {
    const std::int32_t nextCount = --adxsmp_init_cnt;
    if (nextCount == 0) {
      std::memset(adxamp_obj, 0, sizeof(adxamp_obj));
    }
    return nextCount;
  }

  /**
   * Address: 0x00B19650 (FUN_00B19650, _ADXAMP_Create)
   *
   * What it does:
   * Allocates one ADXAMP runtime slot, wires lane streams, initializes runtime
   * defaults, and marks slot used.
   */
  [[maybe_unused]] void* ADXAMP_Create(
    const std::int32_t outputChannelCount,
    M2asjdIoStream* const* const inputStreams,
    M2asjdIoStream* const* const outputStreams
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < static_cast<std::int32_t>(std::size(adxamp_obj))) {
      if (adxamp_obj[slotIndex].used == 0) {
        break;
      }
      ++slotIndex;
    }

    if (slotIndex == static_cast<std::int32_t>(std::size(adxamp_obj))) {
      return nullptr;
    }

    ADXCRS_Lock();

    auto* const runtime = &adxamp_obj[slotIndex];
    runtime->outputChannelCount = static_cast<std::int8_t>(outputChannelCount);
    if (outputChannelCount > 0) {
      for (std::int32_t lane = 0; lane < outputChannelCount; ++lane) {
        runtime->inputStreams[lane] = inputStreams[lane];
        runtime->outputStreams[lane] = outputStreams[lane];
        runtime->extractedSamplesByLane[lane] = 0;
      }
    }

    runtime->executionState = 0;
    runtime->extractIterationCount = 0;
    runtime->activeLaneCount = outputChannelCount;
    runtime->sampleRate = 44100;
    runtime->frameLength = 0.1f;
    runtime->framePeriod = 0.1f;
    runtime->used = 1;

    ADXCRS_Unlock();
    return runtime;
  }

  /**
   * Address: 0x00B196F0 (FUN_00B196F0, _ADXAMP_Destroy)
   *
   * What it does:
   * Clears one ADXAMP runtime slot under ADX lock when handle is non-null.
   */
  [[maybe_unused]] void ADXAMP_Destroy(void* const channelExpandHandle)
  {
    if (channelExpandHandle == nullptr) {
      return;
    }

    ADXCRS_Lock();
    std::memset(channelExpandHandle, 0, sizeof(AdxampRuntimeState));
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B19710 (FUN_00B19710, _ADXAMP_GetStat)
   *
   * What it does:
   * Returns current ADXAMP execution-state byte as signed 32-bit value.
   */
  [[maybe_unused]] std::int32_t ADXAMP_GetStat(const void* const channelExpandHandle)
  {
    return static_cast<std::int32_t>(static_cast<std::int8_t>(AsAdxampRuntimeStateConst(channelExpandHandle)->executionState));
  }

  /**
   * Address: 0x00B19720 (FUN_00B19720, _ADXAMP_Start)
   *
   * What it does:
   * Resets channel-expand extraction cursors, clears source/output stream
   * lanes, and switches ADXAMP runtime state to active (`2`).
   */
  std::int32_t ADXAMP_Start(void* const channelExpandHandle)
  {
    auto* const runtime = AsAdxampRuntimeState(channelExpandHandle);
    const std::int32_t outputChannelCount = static_cast<std::int32_t>(runtime->outputChannelCount);

    for (std::int32_t lane = 0; lane < outputChannelCount; ++lane) {
      runtime->extractedSamplesByLane[lane] = 0;
    }

    runtime->extractIterationCount = 0;

    for (std::int32_t lane = 0; lane < outputChannelCount; ++lane) {
      AdxampClearLaneStream(runtime->inputStreams[lane]);
    }

    for (std::int32_t lane = 0; lane < outputChannelCount; ++lane) {
      AdxampClearLaneStream(runtime->outputStreams[lane]);
    }

    runtime->executionState = 2;
    return outputChannelCount;
  }

  /**
   * Address: 0x00B19840 (FUN_00B19840, _ADXAMP_Stop)
   *
   * What it does:
   * Stops one ADXAMP channel-expand runtime lane.
   */
  void ADXAMP_Stop(void* const channelExpandHandle)
  {
    AsAdxampRuntimeState(channelExpandHandle)->executionState = 0;
  }

  /**
   * Address: 0x00B19850 (FUN_00B19850, _adxamp_extract)
   *
   * What it does:
   * Builds per-frame peak envelopes from source lanes and commits metadata
   * blocks to output lanes.
   */
  std::int32_t __cdecl adxamp_extract(AdxampRuntimeState* const runtime)
  {
    const auto frameSampleCount =
      static_cast<std::int32_t>(static_cast<double>(runtime->sampleRate) * static_cast<double>(runtime->framePeriod));
    std::int32_t processedLaneCount = 0;

    if (runtime->activeLaneCount <= 0) {
      return processedLaneCount;
    }

    for (std::int32_t lane = 0; lane < runtime->activeLaneCount; ++lane) {
      M2asjdIoStream* const inputStream = runtime->inputStreams[lane];
      M2asjdIoStream* const outputStream = runtime->outputStreams[lane];

      std::int32_t extractFrameCount = inputStream->QueryAvailableBytes(1) / 2 / frameSampleCount;
      const std::int32_t outputFrameBudget = outputStream->QueryAvailableBytes(0) / 16;
      if (extractFrameCount > outputFrameBudget) {
        extractFrameCount = outputFrameBudget;
      }

      for (std::int32_t frameIndex = 0; frameIndex < extractFrameCount; ++frameIndex) {
        std::int32_t consumedSamples = 0;
        std::int32_t peakSampleAbs = 0;

        if (frameSampleCount > 0) {
          do {
            SjChunkRange inputChunk{};
            inputStream->AcquireChunk(1, 2 * (frameSampleCount - consumedSamples), &inputChunk);

            const auto* const sampleWords = reinterpret_cast<const std::int16_t*>(SjAddressToPointer(inputChunk.bufferAddress));
            const std::int32_t sampleWordCount = inputChunk.byteCount / 2;
            for (std::int32_t sampleIndex = 0; sampleIndex < sampleWordCount; ++sampleIndex) {
              std::int32_t sampleValue = static_cast<std::int32_t>(sampleWords[sampleIndex]);
              if (sampleValue < 0) {
                sampleValue = -sampleValue;
              }
              if (sampleValue > peakSampleAbs) {
                peakSampleAbs = sampleValue;
              }
            }

            inputStream->CommitChunk(0, &inputChunk);
            consumedSamples += sampleWordCount;
          } while (consumedSamples < frameSampleCount);
        }

        SjChunkRange outputChunk{};
        outputStream->AcquireChunk(0, 16, &outputChunk);
        if (outputChunk.byteCount == 0) {
          for (;;) {
          }
        }

        auto* const envelopeWords = reinterpret_cast<std::int32_t*>(SjAddressToPointer(outputChunk.bufferAddress));
        envelopeWords[0] = peakSampleAbs;
        envelopeWords[1] = runtime->extractedSamplesByLane[lane];
        envelopeWords[2] = runtime->sampleRate;
        envelopeWords[3] = frameSampleCount;

        outputStream->CommitChunk(1, &outputChunk);
        runtime->extractedSamplesByLane[lane] += frameSampleCount;
        ++runtime->extractIterationCount;
      }

      ++processedLaneCount;
    }

    return processedLaneCount;
  }

  /**
   * Address: 0x00B199D0 (FUN_00B199D0, _ADXAMP_ExecHndl)
   *
   * What it does:
   * Executes one ADXAMP lane when active.
   */
  std::int32_t ADXAMP_ExecHndl(void* const channelExpandHandle)
  {
    auto* const runtime = AsAdxampRuntimeState(channelExpandHandle);
    if (runtime->executionState == 2) {
      return adxamp_extract(runtime);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(channelExpandHandle));
  }

  /**
   * Address: 0x00B199F0 (FUN_00B199F0, _ADXAMP_ExecServer)
   *
   * What it does:
   * Iterates ADXAMP runtime pool and executes each active lane.
   */
  std::int32_t ADXAMP_ExecServer()
  {
    std::int32_t result = 0;
    for (auto& runtime : adxamp_obj) {
      if (runtime.used == 1u) {
        result = ADXAMP_ExecHndl(&runtime);
      }
    }
    return result;
  }

  /**
   * Address: 0x00B19A20 (FUN_00B19A20, _ADXAMP_GetExtractNumSmpl)
   *
   * What it does:
   * Returns lane-0 extracted sample cursor.
   */
  std::int32_t ADXAMP_GetExtractNumSmpl(const void* const channelExpandHandle)
  {
    return AsAdxampRuntimeStateConst(channelExpandHandle)->extractedSamplesByLane[0];
  }

  /**
   * Address: 0x00B19A30 (FUN_00B19A30, _ADXAMP_SetSfreq)
   *
   * What it does:
   * Stores ADXAMP sample-rate lane.
   */
  std::int32_t ADXAMP_SetSfreq(void* const channelExpandHandle, const std::int32_t sampleRate)
  {
    AsAdxampRuntimeState(channelExpandHandle)->sampleRate = sampleRate;
    return sampleRate;
  }

  /**
   * Address: 0x00B19A40 (FUN_00B19A40, _ADXAMP_GetSfreq)
   *
   * What it does:
   * Returns ADXAMP sample-rate lane.
   */
  std::int32_t ADXAMP_GetSfreq(const void* const channelExpandHandle)
  {
    return AsAdxampRuntimeStateConst(channelExpandHandle)->sampleRate;
  }

  /**
   * Address: 0x00B19A50 (FUN_00B19A50, _ADXAMP_SetFrmLen)
   *
   * What it does:
   * Sets one ADXAMP frame-length lane.
   */
  void* ADXAMP_SetFrmLen(void* const channelExpandHandle, const float frameLength)
  {
    AsAdxampRuntimeState(channelExpandHandle)->frameLength = frameLength;
    return channelExpandHandle;
  }

  /**
   * Address: 0x00B19A60 (FUN_00B19A60, _ADXAMP_GetFrmLen)
   *
   * What it does:
   * Returns one ADXAMP frame-length lane.
   */
  double ADXAMP_GetFrmLen(const void* const channelExpandHandle)
  {
    return static_cast<double>(AsAdxampRuntimeStateConst(channelExpandHandle)->frameLength);
  }

  /**
   * Address: 0x00B19A70 (FUN_00B19A70, _ADXAMP_SetFrmPrd)
   *
   * What it does:
   * Sets one ADXAMP frame-period lane.
   */
  void* ADXAMP_SetFrmPrd(void* const channelExpandHandle, const float framePeriod)
  {
    AsAdxampRuntimeState(channelExpandHandle)->framePeriod = framePeriod;
    return channelExpandHandle;
  }

  /**
   * Address: 0x00B19A80 (FUN_00B19A80, _ADXAMP_GetFrmPrd)
   *
   * What it does:
   * Returns one ADXAMP frame-period lane.
   */
  double ADXAMP_GetFrmPrd(const void* const channelExpandHandle)
  {
    return static_cast<double>(AsAdxampRuntimeStateConst(channelExpandHandle)->framePeriod);
  }

  /**
   * Address: 0x00B19A90 (FUN_00B19A90, _ADX_GetCoefficient)
   *
   * What it does:
   * Computes ADX predictor coefficients for one coefficient/sample-rate pair.
   */
  std::int32_t ADX_GetCoefficient(
    const std::int32_t coefficientIndex,
    const std::int32_t sampleRate,
    std::int16_t* const outCoefficient0,
    std::int16_t* const outCoefficient1
  )
  {
    const double sqrt2 = std::sqrt(2.0);
    const double phase = (static_cast<double>(coefficientIndex) * 6.2831855) / static_cast<double>(sampleRate);
    const double lane0 = sqrt2 - std::cos(phase);
    const double lane1 = sqrt2 - 1.0;
    const double lane2 = (lane0 - std::sqrt((lane0 - lane1) * (lane1 + lane0))) / lane1;

    *outCoefficient0 = static_cast<std::int16_t>(static_cast<std::int32_t>(8192.0 * lane2));
    const std::int32_t result = static_cast<std::int32_t>(lane2 * lane2 * -4096.0);
    *outCoefficient1 = static_cast<std::int16_t>(result);
    return result;
  }

  /**
   * Address: 0x00B19B00 (FUN_00B19B00, _ADX_ScanInfoCode)
   *
   * What it does:
   * Scans one byte lane for ADX info-code marker word `0x0080`.
   */
  int ADX_ScanInfoCode(const std::uint8_t* const sourceBytes, const std::int32_t sourceLength, std::int16_t* const outOffset)
  {
    std::int32_t scanOffset = 0;
    if (sourceLength - 1 <= 0) {
      *outOffset = 0;
      return -1;
    }

    while (sourceBytes[scanOffset] != 0x80u || sourceBytes[scanOffset + 1] != 0x00u) {
      scanOffset += 2;
      if (scanOffset >= sourceLength - 1) {
        *outOffset = 0;
        return -1;
      }
    }

    if (scanOffset == 0x7FFFFFFF) {
      *outOffset = 0;
      return -1;
    }

    *outOffset = static_cast<std::int16_t>(scanOffset);
    return 0;
  }

  /**
   * Address: 0x00B19B40 (FUN_00B19B40, _ADX_IsAdxFmt)
   *
   * What it does:
   * Validates ADX header/footer signature and optional `(c)CRI` trailer lane.
   */
  int ADX_IsAdxFmt(const std::uint8_t* const sourceBytes, const std::int32_t sourceLength, std::int16_t* const outHeaderBytes)
  {
    if (sourceLength < 16) {
      return 0;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8000u) {
      return 0;
    }

    const std::int32_t headerBytes = static_cast<std::int32_t>(ReadAdxBigEndianU16(sourceBytes + 2) + 4u);
    if (sourceLength < 0x8000) {
      return 0;
    }

    const bool hasCopyrightMarker =
      std::memcmp(sourceBytes + headerBytes - 6, kAdxCopyrightSignature, std::strlen(kAdxCopyrightSignature)) == 0;
    if (!hasCopyrightMarker) {
      return 0;
    }

    if (outHeaderBytes != nullptr) {
      *outHeaderBytes = static_cast<std::int16_t>(headerBytes);
    }
    return 1;
  }

  /**
   * Address: 0x00B19BB0 (FUN_00B19BB0, _ADX_DecodeInfo)
   *
   * What it does:
   * Decodes core ADX header lanes (format, channel/sample layout, timing info).
   */
  int ADX_DecodeInfo(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int32_t* const outHeaderIdentity,
    std::int8_t* const outHeaderType,
    std::int8_t* const outSampleBits,
    std::int8_t* const outChannels,
    std::int8_t* const outBlockBytes,
    std::int32_t* const outBlockSamples,
    std::int32_t* const outSampleRate,
    std::int32_t* const outTotalSamples
  )
  {
    if (sourceLength < 16) {
      return -1;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8000u) {
      return -2;
    }

    *outHeaderIdentity = static_cast<std::int32_t>(ReadAdxBigEndianU16(sourceBytes + 2) + 4u);
    *outHeaderType = static_cast<std::int8_t>(sourceBytes[4]);
    *outChannels = static_cast<std::int8_t>(sourceBytes[5]);
    *outSampleBits = static_cast<std::int8_t>(sourceBytes[6]);
    *outBlockBytes = static_cast<std::int8_t>(sourceBytes[7]);
    *outBlockSamples = static_cast<std::int32_t>(ReadAdxBigEndianU32(sourceBytes + 8));
    *outSampleRate = static_cast<std::int32_t>(ReadAdxBigEndianU32(sourceBytes + 12));

    if (*outSampleBits != 0) {
      *outTotalSamples = ((8 * static_cast<std::int32_t>(*outChannels)) - 16) / static_cast<std::int32_t>(*outSampleBits);
      return 0;
    }

    *outTotalSamples = 0;
    return 0;
  }

  /**
   * Address: 0x00B19CD0 (FUN_00B19CD0, _ADX_DecodeInfoExVer)
   *
   * What it does:
   * Decodes ADX extension version lanes (encryption mode + version).
   */
  int ADX_DecodeInfoExVer(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int32_t* const outEncryptionMode,
    std::int32_t* const outVersion
  )
  {
    if (sourceLength < 20) {
      return -1;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8000u) {
      return -2;
    }

    if (ReadAdxBigEndianU16(sourceBytes + 2) < 16u) {
      return -1;
    }

    *outEncryptionMode = static_cast<std::int32_t>(sourceBytes[18]);
    *outVersion = static_cast<std::int32_t>(sourceBytes[19]);
    return 0;
  }

  /**
   * Address: 0x00B19C80 (FUN_00B19C80, _ADX_DecodeInfoExADPCM2)
   *
   * What it does:
   * Decodes ADPCM2 coefficient index lane from ADX extension header.
   */
  int ADX_DecodeInfoExADPCM2(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int16_t* const outCoefficientIndex
  )
  {
    if (sourceLength < 18) {
      return -1;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8000u) {
      return -2;
    }

    if (ReadAdxBigEndianU16(sourceBytes + 2) < 14u) {
      return -1;
    }

    *outCoefficientIndex = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + 16));
    return 0;
  }

  /**
   * Address: 0x00B19D20 (FUN_00B19D20, _ADX_DecodeInfoExIdly)
   *
   * What it does:
   * Decodes ADX initial delay lanes and clears them for non-extended mode.
   */
  int ADX_DecodeInfoExIdly(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int16_t* const outDelay0,
    std::int16_t* const outDelay1
  )
  {
    std::int32_t encryptionMode = 0;
    std::int32_t version = 0;
    if (ADX_DecodeInfoExVer(sourceBytes, sourceLength, &encryptionMode, &version) != 0) {
      return -1;
    }

    if (static_cast<std::uint8_t>(encryptionMode) < 4u) {
      outDelay0[0] = 0;
      outDelay1[0] = 0;
      outDelay0[1] = 0;
      outDelay1[1] = 0;
      return 0;
    }

    if (sourceLength < 32) {
      return -1;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8000u) {
      return -2;
    }

    if (ReadAdxBigEndianU16(sourceBytes + 2) < 28u) {
      return -1;
    }

    outDelay0[0] = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + 24));
    outDelay1[0] = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + 26));
    outDelay0[1] = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + 28));
    outDelay1[1] = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + 30));
    return 0;
  }

  /**
   * Address: 0x00B19E90 (FUN_00B19E90, _ADX_DecodeInfoExLoop)
   *
   * What it does:
   * Decodes ADX loop metadata lanes from extension header.
   */
  int ADX_DecodeInfoExLoop(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int32_t* const outInsertedSamples,
    std::int16_t* const outLoopCount,
    std::uint16_t* const outLoopType,
    std::int32_t* const outLoopStartSample,
    std::int32_t* const outLoopStartOffset,
    std::int32_t* const outLoopEndSample,
    std::int32_t* const outLoopEndOffset
  )
  {
    std::int32_t encryptionMode = 0;
    std::int32_t version = 0;
    *outLoopCount = 0;

    const int decodeResult = ADX_DecodeInfoExVer(sourceBytes, sourceLength, &encryptionMode, &version);
    if (decodeResult != 0) {
      return decodeResult;
    }

    const auto encryptionModeByte = static_cast<std::uint8_t>(encryptionMode);
    const std::int32_t requiredBytes = (encryptionModeByte == 4u) ? 60 : 48;
    if (sourceLength < requiredBytes) {
      return -1;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8000u) {
      return -2;
    }

    if (ReadAdxBigEndianU16(sourceBytes + 2) < static_cast<std::uint16_t>(requiredBytes - 4)) {
      return -1;
    }

    std::int32_t offset = (encryptionModeByte == 4u) ? 32 : 20;
    *outInsertedSamples = static_cast<std::int32_t>(ReadAdxBigEndianU16(sourceBytes + offset));
    offset += 2;

    const auto loopCount = static_cast<std::uint16_t>(ReadAdxBigEndianU16(sourceBytes + offset));
    *outLoopCount = static_cast<std::int16_t>(loopCount);
    if (loopCount != 1u) {
      return -2;
    }

    offset += 4;
    *outLoopType = ReadAdxBigEndianU16(sourceBytes + offset);
    offset += 2;
    *outLoopStartSample = static_cast<std::int32_t>(ReadAdxBigEndianU32(sourceBytes + offset));
    offset += 4;
    *outLoopStartOffset = static_cast<std::int32_t>(ReadAdxBigEndianU32(sourceBytes + offset));
    offset += 4;
    *outLoopEndSample = static_cast<std::int32_t>(ReadAdxBigEndianU32(sourceBytes + offset));
    offset += 4;
    *outLoopEndOffset = static_cast<std::int32_t>(ReadAdxBigEndianU32(sourceBytes + offset));
    return 0;
  }

  /**
   * Address: 0x00B1A040 (FUN_00B1A040, _ADX_DecodeInfoAinf)
   *
   * What it does:
   * Decodes ADX AINF extension block (data-id, default volume, default pan).
   */
  int ADX_DecodeInfoAinf(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int32_t* const outAinfLength,
    std::uint8_t* const outDataIdBytes,
    std::int16_t* const outDefaultVolume,
    std::int16_t* const outDefaultPanByChannel
  )
  {
    constexpr std::uint32_t kAinfTag = 0x41494E46u;

    std::int32_t encryptionMode = 0;
    std::int32_t version = 0;
    *outAinfLength = 0;

    const int decodeResult = ADX_DecodeInfoExVer(sourceBytes, sourceLength, &encryptionMode, &version);
    if (decodeResult != 0) {
      return decodeResult;
    }

    const auto encryptionModeByte = static_cast<std::uint8_t>(encryptionMode);
    const std::int32_t requiredBytes = (encryptionModeByte == 4u) ? 72 : 60;
    if (sourceLength < requiredBytes) {
      return -1;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8000u) {
      return -2;
    }

    if (ReadAdxBigEndianU16(sourceBytes + 2) < static_cast<std::uint16_t>(requiredBytes - 4)) {
      return -1;
    }

    std::int32_t offset = (encryptionModeByte == 4u) ? 32 : 20;
    offset += 2;
    if (ReadAdxBigEndianU16(sourceBytes + offset) != 0u) {
      offset += 20;
    }
    offset += 2;

    if (ReadAdxBigEndianU32(sourceBytes + offset) != kAinfTag) {
      return -2;
    }
    offset += 4;

    *outAinfLength = static_cast<std::int32_t>(ReadAdxBigEndianU32(sourceBytes + offset));
    offset += 4;

    std::memcpy(outDataIdBytes, sourceBytes + offset, 16);
    offset += 16;

    *outDefaultVolume = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + offset));
    offset += 2;
    outDefaultPanByChannel[0] = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + offset));
    offset += 2;
    outDefaultPanByChannel[1] = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + offset));
    return 0;
  }

  /**
   * Address: 0x00B19DF0 (FUN_00B19DF0, _ADX_DecodeInfoExLoopEncTime)
   *
   * What it does:
   * Converts loop sample lanes to encoded-time lanes with ADX 2048-sample wrap.
   */
  int ADX_DecodeInfoExLoopEncTime(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int16_t* const outLoopEnabled,
    std::int32_t* const outLoopStartEncodedSamples,
    std::int32_t* const outLoopEndEncodedSamples
  )
  {
    std::int32_t insertedSamples = 0;
    std::int16_t loopCount = 0;
    std::uint16_t loopType = 0;
    std::int32_t loopStartSample = 0;
    std::int32_t loopStartOffset = 0;
    std::int32_t loopEndSample = 0;
    std::int32_t loopEndOffset = 0;
    ADX_DecodeInfoExLoop(
      sourceBytes,
      sourceLength,
      &insertedSamples,
      &loopCount,
      &loopType,
      &loopStartSample,
      &loopStartOffset,
      &loopEndSample,
      &loopEndOffset
    );

    *outLoopEnabled = (loopCount == 1) ? 1 : 0;
    if (*outLoopEnabled != 0) {
      const std::int32_t moduloSamples = insertedSamples % 2048;
      *outLoopStartEncodedSamples = loopStartSample - moduloSamples;
      *outLoopEndEncodedSamples = loopEndSample - moduloSamples;
    } else {
      *outLoopStartEncodedSamples = 0;
      *outLoopEndEncodedSamples = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00B1A1B0 (FUN_00B1A1B0, _ADX_DecodeFooter)
   *
   * What it does:
   * Decodes ADX footer marker and reports footer-byte span.
   */
  int ADX_DecodeFooter(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int16_t* const outFooterBytes
  )
  {
    if (sourceLength < 16) {
      return -1;
    }

    if (ReadAdxBigEndianU16(sourceBytes) != 0x8001u) {
      return -2;
    }

    *outFooterBytes = static_cast<std::int16_t>(ReadAdxBigEndianU16(sourceBytes + 2) + 4u);
    return 0;
  }

  /**
   * Address: 0x00B1A1F0 (FUN_00B1A1F0, _ADX_CalcHdrInfoLen)
   *
   * What it does:
   * Computes ADX header-info byte span aligned to the caller-provided lane size.
   */
  std::int32_t __cdecl ADX_CalcHdrInfoLen(
    const std::int32_t hasLoopBlock,
    const std::int32_t lane0,
    const std::int32_t lane1,
    const std::int32_t alignmentBytes
  )
  {
    std::int32_t alignedBytes = 0;
    if (hasLoopBlock != 0) {
      alignedBytes = alignmentBytes * ((lane0 + lane1 + alignmentBytes + 57) / alignmentBytes);
    } else {
      alignedBytes = alignmentBytes * ((lane1 + lane0 + alignmentBytes + 33) / alignmentBytes);
    }
    return alignedBytes - lane1;
  }

  /**
   * Address: 0x00B20D40 (ADXB_DecodeHeaderAdx)
   *
   * What it does:
   * Decodes one ADX/AHX header and seeds ADXB decoder state lanes.
   */
  std::int32_t ADXB_DecodeHeaderAdx(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    const std::int32_t headerSize
  )
  {
    constexpr const char* kDecodeHeaderAdxPrefix = "E1060101 ADXB_DecodeHeaderAdx: ";
    constexpr const char* kCantPlayAhxByHandle = "can't play AHX data by this handle";

    std::int32_t headerIdentity = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder));
    decoder->initState = 1;

    if (ADX_DecodeInfo(
          headerBytes,
          headerSize,
          &headerIdentity,
          &decoder->headerType,
          &decoder->sourceSampleBits,
          &decoder->sourceChannels,
          &decoder->sourceBlockBytes,
          &decoder->sourceBlockSamples,
          &decoder->sampleRate,
          &decoder->totalSampleCount
        ) < 0)
    {
      return 0;
    }

    if (decoder->headerType <= 4) {
      std::int32_t encryptionMode = 0;
      std::int32_t headerVersion = 0;
      if (ADX_DecodeInfoExVer(headerBytes, headerSize, &encryptionMode, &headerVersion) < 0) {
        return 0;
      }

      std::int16_t extKey0 = 0;
      std::int16_t extKeyMultiplier = 0;
      std::int16_t extKeyAdder = 0;
      if (adxb_get_key(
            decoder,
            static_cast<std::uint8_t>(encryptionMode),
            static_cast<std::uint8_t>(headerVersion),
            decoder->totalSampleCount,
            &extKey0,
            &extKeyMultiplier,
            &extKeyAdder
          ) < 0)
      {
        return -1;
      }

      ADXPD_SetExtPrm(decoder->adxPacketDecoder, extKey0, extKeyMultiplier, extKeyAdder);

      if (ADX_DecodeInfoExADPCM2(headerBytes, headerSize, &decoder->adpcmCoefficientIndex) < 0) {
        return 0;
      }

      std::int16_t decodeDelay0[2]{};
      std::int16_t decodeDelay1[2]{};
      if (ADX_DecodeInfoExIdly(headerBytes, headerSize, decodeDelay0, decodeDelay1) < 0) {
        return 0;
      }

      ADXPD_SetCoef(decoder->adxPacketDecoder, decoder->sampleRate, decoder->adpcmCoefficientIndex);
      ADXPD_SetDly(decoder->adxPacketDecoder, &decodeDelay0[0], &decodeDelay1[0]);

      ADX_DecodeInfoExLoop(
        headerBytes,
        headerSize,
        &decoder->loopInsertedSamples,
        &decoder->loopCount,
        &decoder->loopType,
        &decoder->loopStartSample,
        &decoder->loopStartOffset,
        &decoder->loopEndSample,
        &decoder->loopEndOffset
      );

      ADX_DecodeInfoAinf(
        headerBytes,
        headerSize,
        &decoder->ainfLength,
        decoder->dataIdBytes,
        &decoder->defaultOutputVolume,
        decoder->defaultPanByChannel
      );

      decoder->format = 0;
    } else {
      if (decoder->ahxDecoderHandle == nullptr) {
        ADXERR_CallErrFunc2_(kDecodeHeaderAdxPrefix, kCantPlayAhxByHandle);
        return -1;
      }

      const auto signedChannels = static_cast<std::int16_t>(static_cast<std::int8_t>(decoder->sourceChannels));
      decoder->sourceBlockBytes = static_cast<std::int8_t>(signedChannels * static_cast<std::int16_t>(-64));
      decoder->sourceSampleBits = 8;
      decoder->sourceBlockSamples = 96;
      decoder->format = 10;
      decoder->adpcmCoefficientIndex = 0;
      decoder->loopCount = 0;
      decoder->loopType = 0;
      decoder->loopInsertedSamples = 0;
      decoder->loopStartSample = 0;
      decoder->loopStartOffset = 0;
      decoder->loopEndSample = 0;
      decoder->loopEndOffset = 0;
      decoder->entrySubmittedBytes = 0;

      std::int32_t encryptionMode = 0;
      std::int32_t headerVersion = 0;
      if (ADX_DecodeInfoExVer(headerBytes, headerSize, &encryptionMode, &headerVersion) < 0) {
        return 0;
      }

      std::int16_t ahxExtParams[4]{};
      if (adxb_get_key(
            decoder,
            static_cast<std::uint8_t>(encryptionMode),
            static_cast<std::uint8_t>(headerVersion),
            decoder->totalSampleCount,
            &ahxExtParams[1],
            &ahxExtParams[2],
            &ahxExtParams[3]
          ) < 0)
      {
        return -1;
      }

      if (ahxsetextfunc != nullptr) {
        ahxsetextfunc(decoder->ahxDecoderHandle, ahxExtParams);
      }
    }

    decoder->outputChannels = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceChannels));
    decoder->outputBlockBytes = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceBlockBytes));
    decoder->outputBlockSamples = decoder->sourceBlockSamples;
    decoder->entryCommittedBytes = 0;
    decoder->outputPcmBuffer0 = decoder->pcmBuffer0;
    decoder->outputPcmBuffer1 = decoder->pcmBuffer1;
    decoder->outputPcmBuffer2 = decoder->pcmBuffer2;

    return static_cast<std::int16_t>(headerIdentity);
  }

  /**
   * Address: 0x00B1B130 (_ADXB_CheckMpa)
   *
   * What it does:
   * Recognizes MPEG audio headers by sync byte and layer/profile marker.
   */
  int ADXB_CheckMpa(const std::uint8_t* headerBytes)
  {
    if (headerBytes[0] != 0xFF) {
      return 0;
    }

    const auto headerMarker = static_cast<std::uint8_t>(headerBytes[1]);
    return (headerMarker == 0xFC || headerMarker == 0xFD) ? 1 : 0;
  }

  /**
   * Address: 0x00B1B070 (_ADXB_DecodeHeaderMpa)
   *
   * What it does:
   * Seeds ADXB runtime lanes for MPEG audio decode using frame-header
   * sample-rate/channel metadata.
   */
  int ADXB_DecodeHeaderMpa(
    moho::AdxBitstreamDecoderState* const decoder,
    const std::uint8_t* const headerBytes,
    const std::int32_t headerSize
  )
  {
    if (decoder->mpegAudioDecoder == nullptr) {
      return -1;
    }
    if (headerSize < 4) {
      return 0;
    }

    const auto sampleRateIndex = static_cast<std::uint8_t>(headerBytes[2] >> 2) & 0x03u;
    const auto channelCount = static_cast<std::int8_t>(((headerBytes[3] & 0xC0u) != 0xC0u) ? 2 : 1);

    decoder->sourceBlockSamples = 1152;
    decoder->sourceChannels = channelCount;
    decoder->outputBlockSamples = 1152;
    decoder->sampleRate = kMpegAudioSampleRateByHeaderIndex[sampleRateIndex];
    decoder->outputChannels = static_cast<std::int32_t>(channelCount);
    decoder->outputPcmBuffer0 = decoder->pcmBuffer0;
    decoder->outputPcmBuffer1 = decoder->pcmBuffer1;
    decoder->outputPcmBuffer2 = decoder->pcmBuffer2;

    decoder->initState = 1;
    decoder->sourceSampleBits = 16;
    decoder->totalSampleCount = 0x7FFFFFFF;
    decoder->sourceBlockBytes = 127;
    decoder->format = 11;
    decoder->outputBlockBytes = 127;
    decoder->entryCommittedBytes = 0;
    decoder->adpcmCoefficientIndex = 0;
    decoder->loopCount = 0;
    decoder->loopType = 0;
    decoder->loopInsertedSamples = 0;
    decoder->loopStartSample = 0;
    decoder->loopStartOffset = 0;
    decoder->loopEndSample = 0;
    decoder->loopEndOffset = 0;
    decoder->entrySubmittedBytes = 0;
    return 1;
  }

  /**
   * Address: 0x00B1BE40 (_ADXB_SetM2aInSj)
   *
   * What it does:
   * Applies input-SJ binding to the embedded M2A decoder lane when present.
   */
  std::int32_t ADXB_SetM2aInSj(moho::AdxBitstreamDecoderState* const decoder)
  {
    void* const m2aDecoderHandle = decoder->mpeg2AacDecoder;
    if (m2aDecoderHandle != nullptr) {
      return m2asetsjifunc(m2aDecoderHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B1BF90 (_ADXB_CheckM2a)
   *
   * What it does:
   * Recognizes MPEG-2 AAC headers by ADTS sync bytes or ADIF marker.
   */
  int ADXB_CheckM2a(const std::uint8_t* headerBytes)
  {
    if (headerBytes[0] == 0xFF) {
      const auto syncByte = static_cast<std::uint8_t>(headerBytes[1]);
      if (syncByte == 0xF8 || syncByte == 0xF9) {
        return 1;
      }
    } else if (headerBytes[0] == 'A' && headerBytes[1] == 'D' && headerBytes[2] == 'I' && headerBytes[3] == 'F') {
      return 1;
    }

    return 0;
  }

  /**
   * Address: 0x00B1BED0 (_ADXB_DecodeHeaderM2a)
   *
   * What it does:
   * Seeds ADXB runtime lanes for MPEG-2 AAC decode using ADTS/ADIF frequency
   * index mapping.
   */
  int ADXB_DecodeHeaderM2a(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    const std::int32_t headerSize
  )
  {
    if (decoder->mpeg2AacDecoder == nullptr) {
      return -1;
    }
    if (headerSize < 4) {
      return 0;
    }

    std::uint32_t sampleRateIndex = 0;
    if (headerBytes[0] == 0xFF) {
      sampleRateIndex = static_cast<std::uint32_t>(headerBytes[2]) >> 2;
    } else {
      sampleRateIndex = static_cast<std::uint32_t>(headerBytes[11]) >> 3;
    }
    sampleRateIndex &= 0x0F;

    decoder->initState = 1;
    decoder->sampleRate = m2adec_frequency_table[sampleRateIndex];
    decoder->sourceBlockSamples = 1024;
    decoder->outputBlockSamples = 1024;
    decoder->sourceChannels = 2;
    decoder->outputPcmBuffer0 = decoder->pcmBuffer0;
    decoder->outputPcmBuffer1 = decoder->pcmBuffer1;
    decoder->sourceSampleBits = 16;
    decoder->totalSampleCount = 0x7FFFFFFF;
    decoder->sourceBlockBytes = 127;
    decoder->format = 12;
    decoder->outputChannels = 2;
    decoder->outputBlockBytes = 127;
    decoder->outputPcmBuffer2 = decoder->pcmBuffer2;
    decoder->entryCommittedBytes = 0;
    decoder->adpcmCoefficientIndex = 0;
    decoder->loopCount = 0;
    decoder->loopType = 0;
    decoder->loopInsertedSamples = 0;
    decoder->loopStartSample = 0;
    decoder->loopStartOffset = 0;
    decoder->loopEndSample = 0;
    decoder->loopEndOffset = 0;
    decoder->entrySubmittedBytes = 0;
    return 1;
  }

  /**
   * Address: 0x00B20FE0 (ADXB_SetDefFmt)
   *
   * What it does:
   * Selects default ADXB output format from requested codec family.
   */
  void ADXB_SetDefFmt(moho::AdxBitstreamDecoderState* decoder, const std::int32_t requestedFormat)
  {
    constexpr const char* kMpegAudioNotInitialized = "E20040217 : MPEG Audio decoding function is not initialized!";
    constexpr const char* kMpeg2AacNotInitialized = "E20040217 : MPEG2 AAC decoding function is not initialized!";

    if (requestedFormat < 3 || requestedFormat > 4) {
      if (requestedFormat == 15) {
        if (decoder->mpeg2AacDecoder != nullptr) {
          decoder->preferredFormat = 12;
        } else {
          ADXERR_CallErrFunc1_(kMpeg2AacNotInitialized);
        }
        return;
      }

      decoder->preferredFormat = 0;
      return;
    }

    if (decoder->mpegAudioDecoder != nullptr) {
      decoder->preferredFormat = 11;
    } else {
      ADXERR_CallErrFunc1_(kMpegAudioNotInitialized);
    }
  }

  /**
   * Address: 0x00B21050 (ADXB_SetDefPrm)
   *
   * What it does:
   * Resets ADXB runtime parameters to default decode lanes.
   */
  moho::AdxBitstreamDecoderState* ADXB_SetDefPrm(moho::AdxBitstreamDecoderState* decoder)
  {
    decoder->sourceBlockSamples = 1024;
    decoder->outputBlockSamples = 1024;
    decoder->outputPcmBuffer0 = decoder->pcmBuffer0;
    decoder->sourceBlockBytes = 127;
    decoder->outputBlockBytes = 127;
    decoder->outputPcmBuffer2 = decoder->pcmBuffer2;
    decoder->format = decoder->preferredFormat;
    decoder->initState = 1;
    decoder->sampleRate = 48000;
    decoder->sourceChannels = 2;
    decoder->sourceSampleBits = 16;
    decoder->totalSampleCount = 0x7FFFFFFF;
    decoder->outputChannels = 2;
    decoder->outputPcmBuffer1 = decoder->pcmBuffer1;
    decoder->entryCommittedBytes = 0;
    decoder->adpcmCoefficientIndex = 0;
    decoder->loopCount = 0;
    decoder->loopType = 0;
    decoder->loopInsertedSamples = 0;
    decoder->loopStartSample = 0;
    decoder->loopStartOffset = 0;
    decoder->loopEndSample = 0;
    decoder->loopEndOffset = 0;
    decoder->entrySubmittedBytes = 0;
    return decoder;
  }

  /**
   * Address: 0x00B210E0 (ADXB_DecodeHeader)
   *
   * What it does:
   * Dispatches one input header to the matching ADXB decode path.
   */
  std::int32_t ADXB_DecodeHeader(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    const std::int32_t headerSize
  )
  {
    adxb_ResetAinf(decoder);

    const auto marker = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(headerBytes[0]) << 8 | static_cast<std::uint16_t>(headerBytes[1])
    );

    if (marker == 0x8000) {
      return ADXB_DecodeHeaderAdx(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckSpsd(headerBytes)) {
      return ADXB_DecodeHeaderSpsd(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckWav(headerBytes)) {
      return ADXB_DecodeHeaderWav(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckAiff(headerBytes)) {
      return ADXB_DecodeHeaderAiff(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckAu(headerBytes)) {
      return ADXB_DecodeHeaderAu(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckMpa(headerBytes)) {
      return ADXB_DecodeHeaderMpa(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckM2a(headerBytes)) {
      return ADXB_DecodeHeaderM2a(decoder, headerBytes, headerSize);
    }

    return -1;
  }

  /**
   * Address: 0x00B211E0 (ADXB_EntryGetWrFunc)
   *
   * What it does:
   * Registers entry-get write callback lane and context.
   */
  moho::AdxBitstreamDecoderState* ADXB_EntryGetWrFunc(
    moho::AdxBitstreamDecoderState* decoder,
    void* entryGetWriteFunc,
    const std::int32_t entryGetWriteContext
  )
  {
    decoder->entryGetWriteFunc = entryGetWriteFunc;
    decoder->entryGetWriteContext = entryGetWriteContext;
    return decoder;
  }

  /**
   * Address: 0x00B21200 (ADXB_EntryAddWrFunc)
   *
   * What it does:
   * Registers entry-add write callback lane and context.
   */
  moho::AdxBitstreamDecoderState* ADXB_EntryAddWrFunc(
    moho::AdxBitstreamDecoderState* decoder,
    void* entryAddWriteFunc,
    const std::int32_t entryAddWriteContext
  )
  {
    decoder->entryAddWriteFunc = entryAddWriteFunc;
    decoder->entryAddWriteContext = entryAddWriteContext;
    return decoder;
  }

  /**
   * Address: 0x00B21220 (ADXB_GetPcmBuf)
   *
   * What it does:
   * Returns primary PCM buffer lane.
   */
  void* ADXB_GetPcmBuf(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->pcmBuffer0;
  }

  /**
   * Address: 0x00B21230 (ADXB_GetFormat)
   *
   * What it does:
   * Returns active ADXB decode format lane.
   */
  std::int32_t ADXB_GetFormat(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int16_t>(decoder->format);
  }

  /**
   * Address: 0x00B21240 (ADXB_GetSfreq)
   *
   * What it does:
   * Returns stream sample-rate lane.
   */
  std::int32_t ADXB_GetSfreq(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->sampleRate;
  }

  /**
   * Address: 0x00B21250 (ADXB_GetNumChan)
   *
   * What it does:
   * Returns effective output channel count with expand-handle override.
   */
  std::int32_t ADXB_GetNumChan(const moho::AdxBitstreamDecoderState* decoder)
  {
    const auto sourceChannels = static_cast<std::int8_t>(decoder->sourceChannels);
    if (sourceChannels == 1 && decoder->channelExpandHandle != 0) {
      return 2;
    }
    return sourceChannels;
  }

  /**
   * Address: 0x00B21270 (ADXB_GetFmtBps)
   *
   * What it does:
   * Returns source bit-depth lane.
   */
  std::int32_t ADXB_GetFmtBps(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int8_t>(decoder->sourceSampleBits);
  }

  /**
   * Address: 0x00B21280 (ADXB_GetOutBps)
   *
   * What it does:
   * Returns output sample packing bit-depth from format and packing lanes.
   */
  std::int32_t ADXB_GetOutBps(const moho::AdxBitstreamDecoderState* decoder)
  {
    const auto format = static_cast<std::int16_t>(decoder->format);
    if (format == 0) {
      return 16;
    }

    const auto outputPacking = static_cast<std::int16_t>(decoder->outputSamplePacking);

    if (format == 2) {
      if (outputPacking == 2) {
        return 4;
      }
      return (outputPacking == 1) ? 8 : 16;
    }

    if (format == 1) {
      return (outputPacking == 2) ? 4 : 16;
    }

    return 16;
  }

  /**
   * Address: 0x00B212E0 (ADXB_GetBlkSmpl)
   *
   * What it does:
   * Returns source block sample-count lane.
   */
  std::int32_t ADXB_GetBlkSmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->sourceBlockSamples;
  }

  /**
   * Address: 0x00B212F0 (ADXB_GetBlkLen)
   *
   * What it does:
   * Returns source block byte-length lane.
   */
  std::int32_t ADXB_GetBlkLen(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int8_t>(decoder->sourceBlockBytes);
  }

  /**
   * Address: 0x00B21300 (ADXB_GetTotalNumSmpl)
   *
   * What it does:
   * Returns total decoded sample count.
   */
  std::int32_t ADXB_GetTotalNumSmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->totalSampleCount;
  }

  /**
   * Address: 0x00B21310 (ADXB_GetCof)
   *
   * What it does:
   * Returns ADPCM coefficient index lane.
   */
  std::int32_t ADXB_GetCof(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int16_t>(decoder->adpcmCoefficientIndex);
  }

  /**
   * Address: 0x00B21320 (ADXB_GetLpInsNsmpl)
   *
   * What it does:
   * Returns inserted sample count for active loop lane.
   */
  std::int32_t ADXB_GetLpInsNsmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopInsertedSamples;
  }

  /**
   * Address: 0x00B21330 (ADXB_GetNumLoop)
   *
   * What it does:
   * Returns loop count lane.
   */
  std::int32_t ADXB_GetNumLoop(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int16_t>(decoder->loopCount);
  }

  /**
   * Address: 0x00B21340 (ADXB_GetLpStartPos)
   *
   * What it does:
   * Returns loop-start sample index from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpStartPos(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopStartSample;
  }

  /**
   * Address: 0x00B21350 (ADXB_GetLpStartOfst)
   *
   * What it does:
   * Returns loop-start byte offset from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpStartOfst(const moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder == nullptr) {
      return 0;
    }
    return decoder->loopStartOffset;
  }

  /**
   * Address: 0x00B21360 (ADXB_GetLpEndPos)
   *
   * What it does:
   * Returns loop-end sample index from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpEndPos(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopEndSample;
  }

  /**
   * Address: 0x00B21370 (ADXB_GetLpEndOfst)
   *
   * What it does:
   * Returns loop-end byte offset from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpEndOfst(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopEndOffset;
  }

  /**
   * Address: 0x00B21380 (ADXB_GetAinfLen)
   *
   * What it does:
   * Returns AINF extension payload length cached in the decoder state.
   */
  std::int32_t ADXB_GetAinfLen(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->ainfLength;
  }

  /**
   * Address: 0x00B21390 (ADXB_GetDefOutVol)
   *
   * What it does:
   * Returns default output volume from AINF metadata.
   */
  std::int16_t ADXB_GetDefOutVol(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->defaultOutputVolume;
  }

  /**
   * Address: 0x00B213A0 (ADXB_GetDefPan)
   *
   * What it does:
   * Returns one default pan lane from AINF metadata.
   */
  std::int16_t ADXB_GetDefPan(const moho::AdxBitstreamDecoderState* decoder, const std::int32_t channelIndex)
  {
    return decoder->defaultPanByChannel[channelIndex];
  }

  /**
   * Address: 0x00B213C0 (ADXB_GetDataId)
   *
   * What it does:
   * Returns pointer to cached AINF data-id bytes.
   */
  std::uint8_t* ADXB_GetDataId(moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->dataIdBytes;
  }

  /**
   * Address: 0x00B213D0 (ADXB_TakeSnapshot)
   *
   * What it does:
   * Captures ADX packet-decoder delay/ext-key lanes into ADXB snapshot fields.
   */
  std::int32_t ADXB_TakeSnapshot(moho::AdxBitstreamDecoderState* decoder)
  {
    ADXPD_GetDly(decoder->adxPacketDecoder, &decoder->snapshotDelay0, &decoder->snapshotDelay1);
    return ADXPD_GetExtPrm(
      decoder->adxPacketDecoder,
      &decoder->snapshotExtKey0,
      &decoder->snapshotExtKeyMultiplier,
      &decoder->snapshotExtKeyAdder
    );
  }

  /**
   * Address: 0x00B21410 (ADXB_RestoreSnapshot)
   *
   * What it does:
   * Restores ADX packet-decoder delay/ext-key lanes from ADXB snapshot fields.
   */
  std::int32_t ADXB_RestoreSnapshot(moho::AdxBitstreamDecoderState* decoder)
  {
    ADXPD_SetDly(decoder->adxPacketDecoder, &decoder->snapshotDelay0, &decoder->snapshotDelay1);
    const void* const result = ADXPD_SetExtPrm(
      decoder->adxPacketDecoder,
      decoder->snapshotExtKey0,
      decoder->snapshotExtKeyMultiplier,
      decoder->snapshotExtKeyAdder
    );
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B1E170 (FUN_00B1E170, _adxsje_encode_data)
   *
   * What it does:
   * Encodes and emits ADXSJE blocks while output-lane capacity can fit at least
   * one encoded frame slice.
   */
  std::int32_t __cdecl adxsje_encode_data(AdxStreamJoinEncoderState* const encoder)
  {
    constexpr std::int32_t kBlockLengthDivisionMagic = 954437177;

    std::int32_t emittedBytes = 0;
    moho::SofdecSjSupplyHandle* const outputSjHandle = encoder->outputSjHandle;

    const auto queryOutputBlockCapacity = [&]() -> std::int32_t {
      const std::int32_t availableBytes = outputSjHandle->dispatchTable->queryAvailableBytes(outputSjHandle, 0);
      const std::int64_t scaledBytes = static_cast<std::int64_t>(availableBytes) * kBlockLengthDivisionMagic;
      std::int32_t framesByBlockLength = static_cast<std::int32_t>(scaledBytes >> 32);
      framesByBlockLength >>= 2;
      framesByBlockLength += static_cast<std::int32_t>(static_cast<std::uint32_t>(framesByBlockLength) >> 31);
      return framesByBlockLength / encoder->channelCount;
    };

    if (queryOutputBlockCapacity() > 0) {
      do {
        if (adxsje_encode_blk(encoder) == 0) {
          break;
        }

        emittedBytes += adxsje_output_sdata(encoder);
        if (encoder->encodedSamplePosition >= encoder->totalSampleCount) {
          break;
        }
      } while (queryOutputBlockCapacity() > 0);
    }

    return emittedBytes;
  }

  /**
   * Address: 0x00B1E200 (FUN_00B1E200, _adxsje_write_end_code)
   *
   * What it does:
   * Emits ADX end-code marker/padding block once the output SJ lane has
   * sufficient writable space.
   */
  std::int32_t __cdecl adxsje_write_end_code(AdxStreamJoinEncoderState* const encoder)
  {
    moho::SofdecSjSupplyHandle* const outputSjHandle = encoder->outputSjHandle;

    std::int32_t endCodeBlockBytes = 0;
    if (encoder->loopCount > 0) {
      std::int32_t alignedBlockEnd = encoder->blockLengthBytes + encoder->encodedDataBytes + 0x7FF;
      alignedBlockEnd += (alignedBlockEnd >> 31) & 0x7FF;
      alignedBlockEnd = (alignedBlockEnd >> 11) << 11;
      endCodeBlockBytes = alignedBlockEnd - encoder->encodedDataBytes;
    } else {
      endCodeBlockBytes = encoder->blockLengthBytes;
    }

    std::int32_t zeroPaddingBytes = endCodeBlockBytes - 4;
    if (outputSjHandle->dispatchTable->queryAvailableBytes(outputSjHandle, 0) < endCodeBlockBytes) {
      return 0;
    }

    std::int32_t endCodeMarker = 0x8001;
    adxsje_write68(&endCodeMarker, 2, 1, outputSjHandle);

    std::int32_t blockPayloadBytes = endCodeBlockBytes - 4;
    adxsje_write68(&blockPayloadBytes, 2, 1, outputSjHandle);

    std::uint8_t zeroByte = 0;
    while (zeroPaddingBytes > 0) {
      adxsje_write68(&zeroByte, 1, 1, outputSjHandle);
      --zeroPaddingBytes;
    }

    return endCodeBlockBytes;
  }

  /**
   * Address: 0x00B1E2A0 (FUN_00B1E2A0, _adxsje_output_header)
   *
   * What it does:
   * Serializes one ADX stream header (base/loop/AINF/CINF lanes plus copyright
   * footer) into the ADXSJE output SJ lane.
   */
  std::int32_t __cdecl
  adxsje_output_header(AdxStreamJoinEncoderState* const encoder, moho::SofdecSjSupplyHandle* const outputSjHandle)
  {
    constexpr std::uint16_t kAdxHeaderSignature = 0x8000;
    constexpr std::int32_t kAinfFourCc = 0x41494E46;
    constexpr std::int32_t kCinfFourCc = 0x43494E46;
    constexpr std::int32_t kAinfPayloadBytes = 24;
    constexpr char kAdxCopyrightSignature[] = "(c)CRI";

    const std::int32_t copyrightBytes = static_cast<std::int32_t>(std::strlen(kAdxCopyrightSignature));

    SjChunkRange writableChunk{};
    outputSjHandle->dispatchTable->getChunk(outputSjHandle, 0, 0x7FFFFFFF, &writableChunk);
    const std::int32_t writableBytes = writableChunk.byteCount;
    outputSjHandle->dispatchTable->putChunk(outputSjHandle, 0, &writableChunk);
    if (writableBytes < encoder->headerInfoSizeBytes + 4) {
      return 0;
    }

    const auto writeU8 = [&](const std::uint8_t value) -> bool {
      return adxsje_write68(&value, 1, 1, outputSjHandle) == 1;
    };
    const auto writeU16 = [&](const std::uint16_t value) -> bool {
      return adxsje_write68(&value, 2, 1, outputSjHandle) == 1;
    };
    const auto writeS32 = [&](const std::int32_t value) -> bool {
      return adxsje_write68(&value, 4, 1, outputSjHandle) == 1;
    };

    if (!writeU16(kAdxHeaderSignature)) {
      return 0;
    }
    if (!writeU16(static_cast<std::uint16_t>(encoder->headerInfoSizeBytes))) {
      return 0;
    }
    if (!writeU8(static_cast<std::uint8_t>(encoder->headerCodecType))) {
      return 0;
    }
    if (!writeU8(static_cast<std::uint8_t>(encoder->blockLengthBytes))) {
      return 0;
    }
    if (!writeU8(static_cast<std::uint8_t>(encoder->outputBitsPerSample))) {
      return 0;
    }
    if (!writeU8(static_cast<std::uint8_t>(encoder->channelCount))) {
      return 0;
    }
    if (!writeS32(encoder->predictorSampleRate)) {
      return 0;
    }
    if (!writeS32(encoder->totalSampleCountMirror)) {
      return 0;
    }
    if (!writeU16(static_cast<std::uint16_t>(encoder->predictorPreset))) {
      return 0;
    }
    if (!writeU8(4)) {
      return 0;
    }

    const std::uint8_t encryptionFlag = (encoder->extKey0 != 0) ? 8 : 0;
    if (!writeU8(encryptionFlag)) {
      return 0;
    }
    if (!writeS32(0)) {
      return 0;
    }

    const auto* const stagedPredictorWords = reinterpret_cast<const std::int16_t*>(encoder->stagedPredictorWindow);
    if (!writeU16(static_cast<std::uint16_t>(stagedPredictorWords[0]))) {
      return 0;
    }
    if (!writeU16(static_cast<std::uint16_t>(stagedPredictorWords[2]))) {
      return 0;
    }
    if (!writeU16(static_cast<std::uint16_t>(stagedPredictorWords[1]))) {
      return 0;
    }
    if (!writeU16(static_cast<std::uint16_t>(stagedPredictorWords[3]))) {
      return 0;
    }

    std::int32_t headerBytesWritten = 0x1C;
    const std::int32_t loopCount = encoder->loopCount;
    if (loopCount > 0) {
      if (!writeU16(static_cast<std::uint16_t>(encoder->loopInsertedSampleCount))) {
        return 0;
      }
      if (!writeU16(static_cast<std::uint16_t>(loopCount))) {
        return 0;
      }
      headerBytesWritten = 0x20;

      for (std::int32_t loopIndex = 0; loopIndex < loopCount; ++loopIndex) {
        if (!writeU16(static_cast<std::uint16_t>(loopIndex))) {
          return 0;
        }
        if (!writeU16(1)) {
          return 0;
        }
        if (!writeS32(encoder->loopStartSamplePosition)) {
          return 0;
        }
        if (!writeS32(encoder->loopStartByteOffset)) {
          return 0;
        }
        if (!writeS32(encoder->loopEndSamplePosition)) {
          return 0;
        }
        if (!writeS32(encoder->loopEndByteOffset)) {
          return 0;
        }
        headerBytesWritten += 20;
      }
    }

    if (encoder->hasAinfInfo == 1) {
      if (loopCount == 0) {
        if (!writeS32(0)) {
          return 0;
        }
        headerBytesWritten += 4;
      }

      if (!writeS32(kAinfFourCc)) {
        return 0;
      }
      if (!writeS32(kAinfPayloadBytes)) {
        return 0;
      }
      const std::int32_t dataIdBytes = static_cast<std::int32_t>(sizeof(encoder->ainfDataIdBytes));
      if (adxsje_write68(encoder->ainfDataIdBytes, 1, dataIdBytes, outputSjHandle) != dataIdBytes) {
        return 0;
      }
      if (!writeU16(static_cast<std::uint16_t>(encoder->ainfOutputVolume))) {
        return 0;
      }
      if (!writeU16(0)) {
        return 0;
      }
      if (!writeU16(static_cast<std::uint16_t>(encoder->ainfOutputPanByChannel[0]))) {
        return 0;
      }
      if (!writeU16(static_cast<std::uint16_t>(encoder->ainfOutputPanByChannel[1]))) {
        return 0;
      }
      headerBytesWritten += 0x20;
    }

    if (encoder->commonInfoEnabled == 1) {
      if (loopCount == 0) {
        if (!writeS32(0)) {
          return 0;
        }
        headerBytesWritten += 4;
      }

      if (!writeS32(kCinfFourCc)) {
        return 0;
      }
      if (!writeS32(encoder->commonInfoDataBytes)) {
        return 0;
      }
      headerBytesWritten += 8;

      if (encoder->commonInfoDataBytes != 0 && encoder->commonInfoDataOffset != 0) {
        const void* const commonInfoData = reinterpret_cast<const void*>(
          static_cast<std::uintptr_t>(static_cast<std::uint32_t>(encoder->commonInfoDataOffset))
        );
        if (adxsje_write68(commonInfoData, 1, encoder->commonInfoDataBytes, outputSjHandle) != encoder->commonInfoDataBytes) {
          return 0;
        }
        headerBytesWritten += encoder->commonInfoDataBytes;
      }
    }

    const std::int32_t headerContentTarget = encoder->headerInfoSizeBytes - copyrightBytes;
    std::uint8_t zeroByte = 0;
    while (headerBytesWritten < headerContentTarget) {
      if (adxsje_write68(&zeroByte, 1, 1, outputSjHandle) != 1) {
        return 0;
      }
      ++headerBytesWritten;
    }

    if (adxsje_write68(kAdxCopyrightSignature, 1, copyrightBytes, outputSjHandle) != copyrightBytes) {
      return 0;
    }

    return headerBytesWritten + copyrightBytes + 4;
  }

  /**
   * Address: 0x00B1D6F0 (FUN_00B1D6F0, _iirflt_create)
   *
   * What it does:
   * Returns one free ADXSJE IIR filter lane from the fixed 16-slot pool.
   */
  char* __cdecl iirflt_create()
  {
    std::int32_t slotIndex = 0;
    AdxsjeIirFilterState* filterState = adxsje_prdflt_obj;
    while (filterState->used != 0) {
      ++filterState;
      ++slotIndex;
      if (filterState >= adxsje_prdflt_obj + kAdxsjePredictorFilterSlotCount) {
        return nullptr;
      }
    }

    if (slotIndex >= kAdxsjePredictorFilterSlotCount) {
      return nullptr;
    }
    return reinterpret_cast<char*>(filterState);
  }

  /**
   * Address: 0x00B1D720 (FUN_00B1D720, _iirflt_destroy)
   *
   * What it does:
   * Clears one ADXSJE IIR filter lane and returns the original handle.
   */
  std::int32_t __cdecl iirflt_destroy(const std::int32_t iirFilterHandle)
  {
    auto* const filterState = reinterpret_cast<AdxsjeIirFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iirFilterHandle))
    );
    if (filterState != nullptr) {
      std::memset(filterState, 0, sizeof(AdxsjeIirFilterState));
    }
    return iirFilterHandle;
  }

  /**
   * Address: 0x00B1D740 (FUN_00B1D740, _iirflt_set_coef)
   *
   * What it does:
   * Updates one ADXSJE IIR predictor coefficient pair.
   */
  std::int32_t __cdecl
  iirflt_set_coef(const std::int32_t iirFilterHandle, const std::int16_t coefficient0, const std::int16_t coefficient1)
  {
    auto* const filterState = reinterpret_cast<AdxsjeIirFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iirFilterHandle))
    );
    filterState->coefficient0 = coefficient0;
    filterState->coefficient1 = coefficient1;
    return iirFilterHandle;
  }

  /**
   * Address: 0x00B1D760 (FUN_00B1D760, _iirflt_set_delay)
   *
   * What it does:
   * Stores one ADXSJE IIR delay pair.
   */
  std::int32_t __cdecl
  iirflt_set_delay(const std::int32_t iirFilterHandle, const std::int16_t delay0, const std::int16_t delay1)
  {
    auto* const filterState = reinterpret_cast<AdxsjeIirFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iirFilterHandle))
    );
    filterState->delay0 = delay0;
    filterState->delay1 = delay1;
    return iirFilterHandle;
  }

  /**
   * Address: 0x00B1D780 (FUN_00B1D780, _iirflt_get_delay)
   *
   * What it does:
   * Reads one ADXSJE IIR delay pair.
   */
  std::int16_t __cdecl
  iirflt_get_delay(const std::int32_t iirFilterHandle, std::int16_t* const outDelay0, std::int16_t* const outDelay1)
  {
    const auto* const filterState = reinterpret_cast<AdxsjeIirFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iirFilterHandle))
    );
    *outDelay0 = filterState->delay0;
    *outDelay1 = filterState->delay1;
    return filterState->delay1;
  }

  /**
   * Address: 0x00B1D7A0 (FUN_00B1D7A0, _iirflt_put_sig)
   *
   * What it does:
   * Applies one biquad-like ADXSJE predictor step and updates delay history.
   */
  std::int16_t __cdecl iirflt_put_sig(const std::int32_t iirFilterHandle, const std::int16_t sample)
  {
    if (iirFilterHandle == 0) {
      return sample;
    }

    auto* const filterState = reinterpret_cast<AdxsjeIirFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iirFilterHandle))
    );

    const std::int16_t previousDelay0 = filterState->delay0;
    std::int32_t predictedSample = sample;
    predictedSample += ((static_cast<std::int32_t>(filterState->coefficient1) * static_cast<std::int32_t>(filterState->delay1)) +
                        (static_cast<std::int32_t>(filterState->coefficient0) * static_cast<std::int32_t>(previousDelay0))) >>
                       12;

    if (predictedSample <= -32768) {
      predictedSample = -32768;
    } else if (predictedSample >= 0x7FFF) {
      predictedSample = 0x7FFF;
    }

    filterState->delay1 = previousDelay0;
    filterState->delay0 = static_cast<std::int16_t>(predictedSample);
    return static_cast<std::int16_t>(predictedSample);
  }

  /**
   * Address: 0x00B1D810 (FUN_00B1D810, _pflt_create)
   *
   * What it does:
   * Allocates one predictor-filter lane and binds it to one IIR state lane.
   */
  std::int32_t __cdecl pflt_create(const std::int32_t blockSampleCount)
  {
    const char* const iirFilterState = iirflt_create();
    if (iirFilterState == nullptr) {
      return 0;
    }

    std::int32_t slotIndex = 0;
    AdxsjePredictorFilterState* filterState = adxsje_predictor_filter_pool;
    AdxsjePredictorFilterState* selectedState = filterState;
    do {
      selectedState = filterState;
      if (filterState->used == 0) {
        break;
      }
      ++filterState;
      ++slotIndex;
    } while (slotIndex < kAdxsjePredictorFilterSlotCount);

    selectedState->blockSampleCount = blockSampleCount;
    selectedState->iirFilterHandle =
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(iirFilterState));

    if (slotIndex >= kAdxsjePredictorFilterSlotCount) {
      return 0;
    }

    selectedState->used = 1;
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(selectedState));
  }

  /**
   * Address: 0x00B1D860 (FUN_00B1D860, _pflt_destroy)
   *
   * What it does:
   * Clears one predictor-filter lane.
   */
  void __cdecl pflt_destroy(const std::int32_t filterHandle)
  {
    auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );
    if (filterState != nullptr) {
      std::memset(filterState, 0, sizeof(AdxsjePredictorFilterState));
    }
  }

  /**
   * Address: 0x00B1D880 (FUN_00B1D880, _pflt_set_coef)
   *
   * What it does:
   * Stores one predictor coefficient pair for one ADXSJE predictor-filter lane.
   */
  std::int32_t __cdecl
  pflt_set_coef(const std::int32_t filterHandle, const std::int16_t coefficient0, const std::int16_t coefficient1)
  {
    auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );
    filterState->coefficient0 = coefficient0;
    filterState->coefficient1 = coefficient1;
    return filterHandle;
  }

  /**
   * Address: 0x00B1D8A0 (FUN_00B1D8A0, _pflt_calc_coef)
   *
   * What it does:
   * Resolves ADX coefficient pair from preset/sample-rate and applies it to both
   * predictor and IIR lanes.
   */
  std::int32_t __cdecl
  pflt_calc_coef(const std::int32_t filterHandle, const std::int32_t preset, const std::int32_t sampleRate)
  {
    std::int16_t coefficient0 = static_cast<std::int16_t>(preset);
    std::int16_t coefficient1 = static_cast<std::int16_t>(sampleRate);
    ADX_GetCoefficient(static_cast<std::int32_t>(coefficient0), sampleRate, &coefficient0, &coefficient1);

    pflt_set_coef(filterHandle, coefficient0, coefficient1);
    const auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );
    return iirflt_set_coef(filterState->iirFilterHandle, coefficient0, coefficient1);
  }

  /**
   * Address: 0x00B1D8F0 (FUN_00B1D8F0, _pflt_set_delay)
   *
   * What it does:
   * Stores one predictor delay pair for one ADXSJE predictor-filter lane.
   */
  std::int32_t __cdecl pflt_set_delay(const std::int32_t filterHandle, const std::int16_t delay0, const std::int16_t delay1)
  {
    auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );
    filterState->delay0 = delay0;
    filterState->delay1 = delay1;
    return filterHandle;
  }

  /**
   * Address: 0x00B1D910 (FUN_00B1D910, _pflt_put_sig)
   *
   * What it does:
   * Updates one predictor residual lane and tracks absolute-peak residual.
   */
  std::int32_t __cdecl pflt_put_sig(const std::int32_t filterHandle, const std::int32_t sampleIndex, const std::int16_t sample)
  {
    const auto clampPcm16 = [](const std::int32_t value) -> std::int16_t {
      if (value < -32768) {
        return static_cast<std::int16_t>(-32768);
      }
      if (value > 0x7FFF) {
        return static_cast<std::int16_t>(0x7FFF);
      }
      return static_cast<std::int16_t>(value);
    };

    auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );

    if (sampleIndex == 0) {
      for (std::int32_t index = 0; index < filterState->blockSampleCount; ++index) {
        filterState->residualSignals[index] = 0;
      }
      filterState->peakAbsResidual = 0;
    }

    if (filterHandle != 0) {
      std::int32_t residual = sample;
      residual -= (static_cast<std::int32_t>(filterState->delay1) * static_cast<std::int32_t>(filterState->coefficient1)) >> 12;
      residual -= (static_cast<std::int32_t>(filterState->delay0) * static_cast<std::int32_t>(filterState->coefficient0)) >> 12;
      const std::int16_t clampedResidual = clampPcm16(residual);

      filterState->residualSignals[sampleIndex] = clampedResidual;
      const std::int32_t absResidual = (clampedResidual < 0) ? -static_cast<std::int32_t>(clampedResidual)
                                                             : static_cast<std::int32_t>(clampedResidual);
      if (absResidual > filterState->peakAbsResidual) {
        filterState->peakAbsResidual = absResidual;
      }

      const std::int16_t previousDelay0 = filterState->delay0;
      filterState->delay0 = sample;
      filterState->delay1 = previousDelay0;
    }

    return filterHandle;
  }

  /**
   * Address: 0x00B1D9C0 (FUN_00B1D9C0, _pflt_calc_gain)
   *
   * What it does:
   * Derives ADX gain-step and reciprocal residual scale for one predictor lane.
   */
  std::int32_t __cdecl pflt_calc_gain(const std::int32_t filterHandle)
  {
    constexpr double kAdxPcm16MaxMagnitude = 32767.0;

    auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );

    const std::int32_t peakAbsResidual = filterState->peakAbsResidual;
    std::int32_t gainStep = ((peakAbsResidual - 1) / 7) + 1;

    std::int32_t clampedGainStep = gainStep;
    if (clampedGainStep >= AdxGainDataMax) {
      clampedGainStep = AdxGainDataMax;
    }

    if (clampedGainStep <= 1) {
      gainStep = 1;
    } else if (gainStep >= AdxGainDataMax) {
      gainStep = AdxGainDataMax;
    }

    filterState->gainStep = static_cast<std::int16_t>(gainStep);
    if (peakAbsResidual == 0) {
      filterState->residualScale = kAdxPcm16MaxMagnitude;
    } else {
      filterState->residualScale = kAdxPcm16MaxMagnitude / static_cast<double>(peakAbsResidual);
    }

    return gainStep;
  }

  /**
   * Address: 0x00B1DA40 (FUN_00B1DA40, _pflt_get_rsig)
   *
   * What it does:
   * Reads one residual sample from one predictor-filter lane.
   */
  std::int16_t __cdecl pflt_get_rsig(const std::int32_t filterHandle, const std::int32_t sampleIndex)
  {
    if (filterHandle == 0) {
      return 0;
    }

    const auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );
    return filterState->residualSignals[sampleIndex];
  }

  /**
   * Address: 0x00B1DA60 (FUN_00B1DA60, _pflt_get_rsig_q)
   *
   * What it does:
   * Reads one quantized residual nibble lane.
   */
  std::int8_t __cdecl pflt_get_rsig_q(const std::int32_t filterHandle, const std::int32_t sampleIndex)
  {
    if (filterHandle == 0) {
      return 0;
    }

    const auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );
    return filterState->quantizedResidualSignals[sampleIndex];
  }

  /**
   * Address: 0x00B1DA80 (FUN_00B1DA80, _pflt_set_rsig_q)
   *
   * What it does:
   * Stores one quantized residual nibble lane.
   */
  std::int8_t __cdecl pflt_set_rsig_q(const std::int32_t filterHandle, const std::int32_t sampleIndex, const std::int8_t value)
  {
    auto* const filterState = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(filterHandle))
    );
    filterState->quantizedResidualSignals[sampleIndex] = value;
    return value;
  }

  /**
   * Address: 0x00B1DAA0 (FUN_00B1DAA0, _adxsje_get_pcm_data)
   *
   * What it does:
   * Pulls one block of PCM16 samples from each ADXSJE input lane into channel
   * staging planes.
   */
  std::int32_t __cdecl adxsje_get_pcm_data(
    AdxStreamJoinEncoderState* const encoder,
    const std::int32_t encodedSamplePosition,
    const std::int32_t requestedSampleCount,
    std::int16_t** const channelSamplePlanes
  )
  {
    (void)encodedSamplePosition;

    std::int32_t samplesRead = 0;
    for (std::int32_t channelIndex = 0; channelIndex < encoder->channelCount; ++channelIndex) {
      moho::SofdecSjSupplyHandle* const inputHandle = encoder->inputSjHandles[channelIndex];
      samplesRead = inputHandle->dispatchTable->queryAvailableBytes(inputHandle, 1) >> 1;
      if (samplesRead < requestedSampleCount) {
        return 0;
      }
    }

    for (std::int32_t channelIndex = 0; channelIndex < encoder->channelCount; ++channelIndex) {
      samplesRead = 0;
      if (requestedSampleCount > 0) {
        while (samplesRead < requestedSampleCount) {
          moho::SofdecSjSupplyHandle* const inputHandle = encoder->inputSjHandles[channelIndex];
          SjChunkRange sourceChunk{};
          inputHandle->dispatchTable->getChunk(inputHandle, 1, requestedSampleCount * 2, &sourceChunk);

          const void* const sourceBytes = reinterpret_cast<const void*>(
            static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceChunk.bufferAddress))
          );
          std::memcpy(channelSamplePlanes[channelIndex] + samplesRead, sourceBytes, sourceChunk.byteCount);

          samplesRead += static_cast<std::int16_t>(sourceChunk.byteCount >> 1);
          inputHandle->dispatchTable->putChunk(inputHandle, 0, &sourceChunk);
        }
      }
    }

    return samplesRead;
  }

  /**
   * Address: 0x00B1DB90 (FUN_00B1DB90, _adxsje_calc_rsig)
   *
   * What it does:
   * Computes predictor residual and quantized residual lanes for one ADXSJE
   * channel block.
   */
  std::int32_t __cdecl adxsje_calc_rsig(AdxStreamJoinEncoderState* const encoder, const std::int32_t channelIndex)
  {
    const auto clampPcm16 = [](const std::int32_t value) -> std::int16_t {
      if (value < -32768) {
        return static_cast<std::int16_t>(-32768);
      }
      if (value > 0x7FFF) {
        return static_cast<std::int16_t>(0x7FFF);
      }
      return static_cast<std::int16_t>(value);
    };
    const auto quantizeBy4681 = [](const std::int32_t value) -> std::int32_t {
      if (value >= 0) {
        return (value + 2340) / 4681;
      }
      return (value - 2340) / 4681;
    };

    const std::int32_t predictorFilterHandle = encoder->predictorFilterHandles[channelIndex];
    auto* const predictorFilter = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(predictorFilterHandle))
    );

    auto* const predictorDelay0ByChannel = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x88
    );
    auto* const predictorDelay1ByChannel = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x8C
    );
    const std::int16_t delay0 = predictorDelay0ByChannel[channelIndex];
    const std::int16_t delay1 = predictorDelay1ByChannel[channelIndex];
    const std::int32_t iirFilterHandle = predictorFilter->iirFilterHandle;

    pflt_set_delay(predictorFilterHandle, delay0, delay1);

    const auto* const channelSourceSamples = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x90 + (channelIndex << 6)
    );
    for (std::int32_t sampleIndex = 0; sampleIndex < encoder->blockSampleCount; ++sampleIndex) {
      pflt_put_sig(predictorFilterHandle, sampleIndex, channelSourceSamples[sampleIndex]);
    }

    pflt_calc_gain(predictorFilterHandle);
    iirflt_set_delay(iirFilterHandle, delay0, delay1);

    for (std::int32_t sampleIndex = 0; sampleIndex < encoder->blockSampleCount; ++sampleIndex) {
      std::int16_t iirDelay0 = 0;
      std::int16_t iirDelay1 = 0;
      iirflt_get_delay(iirFilterHandle, &iirDelay0, &iirDelay1);
      pflt_set_delay(predictorFilterHandle, iirDelay0, iirDelay1);
      pflt_put_sig(predictorFilterHandle, sampleIndex, channelSourceSamples[sampleIndex]);

      const std::int16_t residualSignal = pflt_get_rsig(predictorFilterHandle, sampleIndex);
      const std::int16_t scaledResidual = clampPcm16(
        static_cast<std::int32_t>(static_cast<double>(residualSignal) * predictorFilter->residualScale)
      );

      std::int32_t quantizedResidual = quantizeBy4681(static_cast<std::int32_t>(scaledResidual));
      if (quantizedResidual < -8) {
        quantizedResidual = -8;
      } else if (quantizedResidual >= 7) {
        quantizedResidual = 7;
      }
      pflt_set_rsig_q(predictorFilterHandle, sampleIndex, static_cast<std::int8_t>(quantizedResidual));

      const std::int16_t predictorInput = clampPcm16(quantizedResidual * static_cast<std::int32_t>(predictorFilter->gainStep));
      iirflt_put_sig(iirFilterHandle, predictorInput);
    }

    return 0;
  }

  /**
   * Address: 0x00B1DD60 (FUN_00B1DD60, _adxsje_set_rsig)
   *
   * What it does:
   * Builds residual staging lanes and bit-packed residual nibble stream for one
   * ADXSJE channel block.
   */
  std::int32_t __cdecl adxsje_set_rsig(AdxStreamJoinEncoderState* const encoder, const std::int32_t channelIndex)
  {
    const auto clampPcm16 = [](const std::int32_t value) -> std::int16_t {
      if (value < -32768) {
        return static_cast<std::int16_t>(-32768);
      }
      if (value > 0x7FFF) {
        return static_cast<std::int16_t>(0x7FFF);
      }
      return static_cast<std::int16_t>(value);
    };
    const auto quantizeBy4681 = [](const std::int32_t value) -> std::int32_t {
      if (value >= 0) {
        return (value + 2340) / 4681;
      }
      return (value - 2340) / 4681;
    };

    const std::int32_t predictorFilterHandle = encoder->predictorFilterHandles[channelIndex];
    const auto* const predictorFilter = reinterpret_cast<AdxsjePredictorFilterState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(predictorFilterHandle))
    );

    auto* const rawResidualSignals = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x110 + (channelIndex << 6)
    );
    auto* const scaledResidualSignals = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x190 + (channelIndex << 6)
    );
    auto* const reconstructedSignals = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x210 + (channelIndex << 6)
    );
    auto* const packedResidualBytes = reinterpret_cast<std::uint8_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x2A8 + (channelIndex << 4)
    );

    const std::int32_t samplesPerByte = 8 / encoder->outputBitsPerSample;
    std::int32_t packedSampleIndex = 0;
    std::uint8_t* packedWriteCursor = packedResidualBytes - 1;

    for (std::int32_t sampleIndex = 0; sampleIndex < encoder->blockSampleCount; ++sampleIndex) {
      const std::int16_t residualSignal = pflt_get_rsig(predictorFilterHandle, sampleIndex);
      rawResidualSignals[sampleIndex] = residualSignal;

      const std::int16_t scaledResidual = clampPcm16(
        static_cast<std::int32_t>(static_cast<double>(residualSignal) * predictorFilter->residualScale)
      );
      scaledResidualSignals[sampleIndex] = scaledResidual;

      std::int32_t quantizedSignal = quantizeBy4681(static_cast<std::int32_t>(scaledResidual));
      if (quantizedSignal < -8) {
        quantizedSignal = -8;
      } else if (quantizedSignal >= 7) {
        quantizedSignal = 7;
      }

      const std::int16_t reconstructedSignal = clampPcm16(static_cast<std::int32_t>(
        static_cast<double>(quantizedSignal * static_cast<std::int32_t>(predictorFilter->gainStep)) *
        predictorFilter->residualScale
      ));
      reconstructedSignals[sampleIndex] = reconstructedSignal;

      if ((sampleIndex % samplesPerByte) == 0) {
        ++packedWriteCursor;
        packedSampleIndex = 1;
        *packedWriteCursor = 0;
      }

      const std::uint8_t quantizedNibble =
        static_cast<std::uint8_t>(quantizedSignal) & static_cast<std::uint8_t>((1 << encoder->outputBitsPerSample) - 1);
      const std::int32_t bitShift = encoder->outputBitsPerSample * (samplesPerByte - packedSampleIndex);
      *packedWriteCursor |= static_cast<std::uint8_t>(quantizedNibble << bitShift);

      ++packedSampleIndex;
    }

    return encoder->blockSampleCount;
  }

  /**
   * Address: 0x00B1DF30 (FUN_00B1DF30, _adxsje_encode_blk)
   *
   * What it does:
   * Encodes one ADXSJE block from staged PCM lanes into per-channel residual and
   * packed nibble lanes.
   */
  std::int32_t __cdecl adxsje_encode_blk(AdxStreamJoinEncoderState* const encoder)
  {
    std::int16_t* channelSamplePlanes[2] = {
      reinterpret_cast<std::int16_t*>(reinterpret_cast<std::uint8_t*>(encoder) + 0x90),
      reinterpret_cast<std::int16_t*>(reinterpret_cast<std::uint8_t*>(encoder) + 0xD0),
    };

    std::int32_t blockSamplesToRead = encoder->blockSampleCount;
    const std::int32_t remainingSamples = encoder->totalSampleCount - encoder->encodedSamplePosition;
    if (blockSamplesToRead >= remainingSamples) {
      blockSamplesToRead = remainingSamples;
    }

    const std::int32_t samplesRead = adxsje_get_pcm_data(
      encoder,
      encoder->encodedSamplePosition,
      blockSamplesToRead,
      channelSamplePlanes
    );
    if (samplesRead == 0) {
      return 0;
    }

    if (blockSamplesToRead < encoder->blockSampleCount) {
      for (std::int32_t channelIndex = 0; channelIndex < encoder->channelCount; ++channelIndex) {
        std::memset(
          channelSamplePlanes[channelIndex] + blockSamplesToRead,
          0,
          static_cast<std::size_t>(2 * (encoder->blockSampleCount - blockSamplesToRead))
        );
      }
    }

    encoder->encodedSamplePosition += encoder->blockSampleCount;

    auto* const predictorDelay0ByChannel = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x88
    );
    auto* const predictorDelay1ByChannel = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x8C
    );
    auto* const gainByChannel = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x290
    );
    auto* const scaleByChannel = reinterpret_cast<double*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x298
    );

    for (std::int32_t channelIndex = 0; channelIndex < encoder->channelCount; ++channelIndex) {
      adxsje_calc_rsig(encoder, channelIndex);

      const std::int32_t predictorFilterHandle = encoder->predictorFilterHandles[channelIndex];
      const auto* const predictorFilter = reinterpret_cast<AdxsjePredictorFilterState*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(predictorFilterHandle))
      );

      gainByChannel[channelIndex] = predictorFilter->gainStep;
      scaleByChannel[channelIndex] = predictorFilter->residualScale;
      iirflt_get_delay(
        predictorFilter->iirFilterHandle,
        &predictorDelay0ByChannel[channelIndex],
        &predictorDelay1ByChannel[channelIndex]
      );

      adxsje_set_rsig(encoder, channelIndex);
    }

    return encoder->blockSampleCount;
  }

  /**
   * Address: 0x00B1E070 (FUN_00B1E070, _adxsje_output_sdata)
   *
   * What it does:
   * Emits one encoded ADX data slice per active channel (seed word + 16-byte
   * residual payload).
   */
  std::int32_t __cdecl adxsje_output_sdata(AdxStreamJoinEncoderState* const encoder)
  {
    moho::SofdecSjSupplyHandle* const outputSjHandle = encoder->outputSjHandle;
    if (encoder->channelCount <= 0) {
      return 0;
    }

    auto* const gainByChannel = reinterpret_cast<std::int16_t*>(
      reinterpret_cast<std::uint8_t*>(encoder) + 0x290
    );

    std::int32_t emittedBytes = 0;
    for (std::int32_t channelIndex = 0; channelIndex < encoder->channelCount; ++channelIndex) {
      const std::int16_t previousKey = encoder->extKey0;
      const std::int16_t gainWordMinusOne = static_cast<std::int16_t>(gainByChannel[channelIndex] - 1);
      const std::int16_t keyProduct = static_cast<std::int16_t>(encoder->extKeyMultiplier * previousKey);
      const std::int16_t nextKey = static_cast<std::int16_t>(keyProduct + encoder->extKeyAdder);
      encoder->extKey0 = static_cast<std::int16_t>(nextKey & 0x7FFF);

      std::int16_t seedWord = static_cast<std::int16_t>(previousKey ^ gainWordMinusOne);
      const auto* const packedBlockWords = reinterpret_cast<const std::int32_t*>(
        reinterpret_cast<const std::uint8_t*>(encoder) + 0x2A8 + (channelIndex * 0x10)
      );
      if (packedBlockWords[0] == 0 && packedBlockWords[1] == 0 && packedBlockWords[2] == 0 && packedBlockWords[3] == 0) {
        seedWord = 0;
      }

      std::uint8_t outputByte = static_cast<std::uint8_t>((seedWord >> 8) & 0xFF);
      adxsje_write68(&outputByte, 1, 1, outputSjHandle);

      outputByte = static_cast<std::uint8_t>(seedWord & 0xFF);
      adxsje_write68(&outputByte, 1, 1, outputSjHandle);

      adxsje_write68(packedBlockWords, 1, 0x10, outputSjHandle);
      emittedBytes += 0x12;
    }

    return emittedBytes;
  }

  /**
   * Address: 0x00B1E890 (FUN_00B1E890, _ADXSJE_Init)
   *
   * What it does:
   * Initializes ADXSJE global state and clears encoder slots on first init.
   */
  std::int32_t __cdecl ADXSJE_Init()
  {
    if (adxsje_init_cnt == 0) {
      SKG_Init_also();
      std::memset(adxsje_obj, 0, sizeof(adxsje_obj));
    }

    ++adxsje_init_cnt;
    return adxsje_init_cnt;
  }

  /**
   * Address: 0x00B1E8C0 (FUN_00B1E8C0, _SKG_Init_also)
   *
   * What it does:
   * Increments ADXSJE-local SKG init reference count.
   */
  std::int32_t __cdecl SKG_Init_also()
  {
    ++skg_init_count_also;
    return 0;
  }

  /**
   * Address: 0x00B1E8D0 (FUN_00B1E8D0, _ADXSJE_Finish)
   *
   * What it does:
   * Decrements ADXSJE init refcount and clears slot pool on final release.
   */
  std::int32_t __cdecl ADXSJE_Finish()
  {
    const std::int32_t remainingInitCount = --adxsje_init_cnt;
    if (adxsje_init_cnt == 0) {
      SKG_Finish_also();
      std::memset(adxsje_obj, 0, sizeof(adxsje_obj));
      return 0;
    }

    return remainingInitCount;
  }

  /**
   * Address: 0x00B1E900 (FUN_00B1E900, _SKG_Finish_also)
   *
   * What it does:
   * Decrements ADXSJE-local SKG init reference count.
   */
  std::int32_t __cdecl SKG_Finish_also()
  {
    --skg_init_count_also;
    return 0;
  }

  /**
   * Address: 0x00B1E910 (FUN_00B1E910, _ADXSJE_Create)
   *
   * What it does:
   * Allocates one ADXSJE encoder slot from the fixed pool and seeds default
   * ADX encode parameters/predictor filters.
   */
  AdxStreamJoinEncoderState* __cdecl ADXSJE_Create(
    const std::int32_t channelCount,
    moho::SofdecSjSupplyHandle* const* const inputSjHandles,
    moho::SofdecSjSupplyHandle* const outputSjHandle
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < static_cast<std::int32_t>(kAdxsjeObjectCount) && adxsje_obj[slotIndex].used != 0) {
      ++slotIndex;
    }

    if (slotIndex == static_cast<std::int32_t>(kAdxsjeObjectCount)) {
      return nullptr;
    }

    AdxStreamJoinEncoderState* const encoder = &adxsje_obj[slotIndex];
    encoder->inputChannelCountCompact = static_cast<std::uint8_t>(channelCount);

    if (channelCount > 0) {
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        encoder->inputSjHandles[channelIndex] = inputSjHandles[channelIndex];
      }
    }

    encoder->outputSjHandle = outputSjHandle;
    encoder->executionStage = 0;
    encoder->streamDataOffset = 0;
    encoder->encodedDataBytes = 0;
    encoder->encodedSamplePosition = 0;
    encoder->totalSampleCountLimit = 0x7FFF0000;
    encoder->mUnknown38 = 0;
    encoder->totalSampleCount = 0;
    encoder->totalSampleCountLimitMirror = 0x7FFF0000;
    encoder->headerInfoSizeBytes = ADX_CalcHdrInfoLen(0, 0, 4, 4);
    encoder->headerCodecType = 3;
    encoder->channelCount = channelCount;
    encoder->predictorSampleRate = 44100;
    encoder->outputBitsPerSample = 4;
    encoder->blockLengthBytes = 0x12;
    encoder->blockSampleCount = 0x20;
    encoder->totalSampleCountMirror = 0x7FFF0000;
    encoder->predictorPreset = 500;
    encoder->loopInsertedSampleCount = 0;
    encoder->loopCount = 0;
    encoder->loopStartSamplePosition = 0;
    encoder->loopStartByteOffset = 0;
    encoder->loopEndSamplePosition = 0;
    encoder->loopEndByteOffset = 0;
    encoder->predictorFilterHandles[0] = pflt_create(0x20);
    encoder->predictorFilterHandles[1] = pflt_create(encoder->blockSampleCount);
    encoder->ainfOutputPanByChannel[0] = -128;
    encoder->ainfOutputPanByChannel[1] = -128;

    auto* const stagedPredictorWords = reinterpret_cast<std::int16_t*>(encoder->stagedPredictorWindow);
    stagedPredictorWords[2] = 0;
    stagedPredictorWords[0] = 0;
    stagedPredictorWords[3] = 0;
    stagedPredictorWords[1] = 0;

    encoder->hasAinfInfo = 0;
    encoder->ainfOutputVolume = 0;
    std::memset(encoder->ainfDataIdBytes, 0, sizeof(encoder->ainfDataIdBytes));
    encoder->used = 1;
    return encoder;
  }

  /**
   * Address: 0x00B1EA60 (FUN_00B1EA60, _ADXSJE_Destroy)
   *
   * What it does:
   * Destroys predictor-filter lanes for one ADXSJE slot and marks the slot as
   * unused under ADXCRS lock.
   */
  void __cdecl ADXSJE_Destroy(AdxStreamJoinEncoderState* const encoder)
  {
    if (encoder == nullptr) {
      return;
    }

    ADXCRS_Lock();
    if (encoder->predictorFilterHandles[0] != 0) {
      pflt_destroy(encoder->predictorFilterHandles[0]);
    }
    if (encoder->predictorFilterHandles[1] != 0) {
      pflt_destroy(encoder->predictorFilterHandles[1]);
    }
    encoder->used = 0;
    encoder->executionStage = 0;
    encoder->inputChannelCountCompact = 0;
    encoder->endCodePending = 0;
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B1EAC0 (FUN_00B1EAC0, _ADXSJE_Start)
   *
   * What it does:
   * Clears loop-insert priming region on each input lane and arms the encoder
   * state for prep-stage execution.
   */
  std::int32_t __cdecl ADXSJE_Start(AdxStreamJoinEncoderState* const encoder)
  {
    std::int32_t laneIndex = 0;
    if (encoder->channelCount > 0) {
      while (laneIndex < encoder->channelCount) {
        const std::int32_t primingBytes = encoder->loopInsertedSampleCount * 2;
        if (primingBytes > 0) {
          moho::SofdecSjSupplyHandle* const inputSjHandle = encoder->inputSjHandles[laneIndex];
          SjChunkRange chunkRange{};
          inputSjHandle->dispatchTable->getChunk(inputSjHandle, 0, primingBytes, &chunkRange);
          if (chunkRange.byteCount != primingBytes) {
            inputSjHandle->dispatchTable->putChunk(inputSjHandle, 0, &chunkRange);
            while (true) {
              Sleep(0);
            }
          }

          std::memset(
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(chunkRange.bufferAddress))),
            0,
            static_cast<std::size_t>(chunkRange.byteCount)
          );
          inputSjHandle->dispatchTable->submitChunk(inputSjHandle, 1, &chunkRange);
        }

        ++laneIndex;
      }
    }

    encoder->streamDataOffset = 0;
    encoder->encodedDataBytes = 0;
    encoder->encodedSamplePosition = 0;
    encoder->endCodePending = 0;
    encoder->executionStage = 1;
    return 0;
  }

  /**
   * Address: 0x00B1EB70 (FUN_00B1EB70, _ADXSJE_Stop)
   *
   * What it does:
   * Flags ADXSJE encoder state to emit end-code and stop after current payload.
   */
  AdxStreamJoinEncoderState* __cdecl ADXSJE_Stop(AdxStreamJoinEncoderState* const encoder)
  {
    encoder->endCodePending = 1;
    return encoder;
  }

  /**
   * Address: 0x00B1EB80 (FUN_00B1EB80, _ADXSJE_SetSfreq)
   *
   * What it does:
   * Stores ADXSJE sample-rate lane.
   */
  std::int32_t __cdecl ADXSJE_SetSfreq(AdxStreamJoinEncoderState* const encoder, const std::int32_t sampleRate)
  {
    encoder->predictorSampleRate = sampleRate;
    return sampleRate;
  }

  /**
   * Address: 0x00B1EB90 (FUN_00B1EB90, _ADXSJE_SetHdInfoSize)
   *
   * What it does:
   * Stores ADXSJE header-info byte-size lane.
   */
  std::int32_t __cdecl
  ADXSJE_SetHdInfoSize(AdxStreamJoinEncoderState* const encoder, const std::int32_t headerInfoSizeBytes)
  {
    encoder->headerInfoSizeBytes = headerInfoSizeBytes;
    return headerInfoSizeBytes;
  }

  /**
   * Address: 0x00B1EBA0 (FUN_00B1EBA0, _ADXSJE_SetNumChan)
   *
   * What it does:
   * Stores ADXSJE input channel-count lane.
   */
  std::int32_t __cdecl ADXSJE_SetNumChan(AdxStreamJoinEncoderState* const encoder, const std::int32_t channelCount)
  {
    encoder->channelCount = channelCount;
    return channelCount;
  }

  /**
   * Address: 0x00B1EBB0 (FUN_00B1EBB0, _ADXSJE_SetOutBps)
   *
   * What it does:
   * Stores ADXSJE output bit-depth lane.
   */
  std::int32_t __cdecl ADXSJE_SetOutBps(
    AdxStreamJoinEncoderState* const encoder,
    const std::int32_t outputBitsPerSample
  )
  {
    encoder->outputBitsPerSample = outputBitsPerSample;
    return outputBitsPerSample;
  }

  /**
   * Address: 0x00B1EBC0 (FUN_00B1EBC0, _ADXSJE_SetBlkSmpl)
   *
   * What it does:
   * Updates ADXSJE block sample-count lane and recreates predictor filters for
   * both channel lanes.
   */
  std::int32_t __cdecl ADXSJE_SetBlkSmpl(
    AdxStreamJoinEncoderState* const encoder,
    const std::int32_t blockSampleCount
  )
  {
    encoder->blockSampleCount = blockSampleCount;

    if (encoder->predictorFilterHandles[0] != 0) {
      pflt_destroy(encoder->predictorFilterHandles[0]);
    }
    encoder->predictorFilterHandles[0] = pflt_create(encoder->blockSampleCount);

    if (encoder->predictorFilterHandles[1] != 0) {
      pflt_destroy(encoder->predictorFilterHandles[1]);
    }
    const std::int32_t secondFilterHandle = pflt_create(encoder->blockSampleCount);
    encoder->predictorFilterHandles[1] = secondFilterHandle;
    return secondFilterHandle;
  }

  /**
   * Address: 0x00B1EC20 (FUN_00B1EC20, _ADXSJE_SetBlkLen)
   *
   * What it does:
   * Stores ADXSJE encoded-block byte-length lane.
   */
  std::int32_t __cdecl ADXSJE_SetBlkLen(
    AdxStreamJoinEncoderState* const encoder,
    const std::int32_t blockLengthBytes
  )
  {
    encoder->blockLengthBytes = blockLengthBytes;
    return blockLengthBytes;
  }

  /**
   * Address: 0x00B1EC30 (FUN_00B1EC30, _ADXSJE_SetTotalNumSmpl)
   *
   * What it does:
   * Stores ADXSJE total-sample-count lanes.
   */
  std::int32_t __cdecl
  ADXSJE_SetTotalNumSmpl(AdxStreamJoinEncoderState* const encoder, const std::int32_t totalSampleCount)
  {
    encoder->totalSampleCount = totalSampleCount;
    encoder->totalSampleCountMirror = totalSampleCount;
    return totalSampleCount;
  }

  /**
   * Address: 0x00B1EC40 (FUN_00B1EC40, _ADXSJE_SetCof)
   *
   * What it does:
   * Stores ADXSJE predictor preset/coefficient lane.
   */
  std::int32_t __cdecl ADXSJE_SetCof(AdxStreamJoinEncoderState* const encoder, const std::int32_t predictorPreset)
  {
    encoder->predictorPreset = predictorPreset;
    return predictorPreset;
  }

  /**
   * Address: 0x00B1EC50 (FUN_00B1EC50, _ADXSJE_SetNumLoop)
   *
   * What it does:
   * Stores ADXSJE loop-count lane.
   */
  std::int32_t __cdecl ADXSJE_SetNumLoop(AdxStreamJoinEncoderState* const encoder, const std::int32_t loopCount)
  {
    encoder->loopCount = loopCount;
    return loopCount;
  }

  /**
   * Address: 0x00B1EC60 (FUN_00B1EC60, _ADXSJE_SetLpInsNsmpl)
   *
   * What it does:
   * Stores ADXSJE loop-inserted-sample lane.
   */
  std::int32_t __cdecl
  ADXSJE_SetLpInsNsmpl(AdxStreamJoinEncoderState* const encoder, const std::int32_t loopInsertedSamples)
  {
    encoder->loopInsertedSampleCount = loopInsertedSamples;
    return loopInsertedSamples;
  }

  /**
   * Address: 0x00B1EC70 (FUN_00B1EC70, _ADXSJE_SetLpStartPos)
   *
   * What it does:
   * Stores ADXSJE loop-start sample-position lane.
   */
  std::int32_t __cdecl
  ADXSJE_SetLpStartPos(AdxStreamJoinEncoderState* const encoder, const std::int32_t loopStartSamplePosition)
  {
    encoder->loopStartSamplePosition = loopStartSamplePosition;
    return loopStartSamplePosition;
  }

  /**
   * Address: 0x00B1EC80 (FUN_00B1EC80, _ADXSJE_SetLpStartOfst)
   *
   * What it does:
   * Stores ADXSJE loop-start byte-offset lane.
   */
  std::int32_t __cdecl
  ADXSJE_SetLpStartOfst(AdxStreamJoinEncoderState* const encoder, const std::int32_t loopStartByteOffset)
  {
    encoder->loopStartByteOffset = loopStartByteOffset;
    return loopStartByteOffset;
  }

  /**
   * Address: 0x00B1EC90 (FUN_00B1EC90, _ADXSJE_SetLpEndPos)
   *
   * What it does:
   * Stores ADXSJE loop-end sample-position lane.
   */
  std::int32_t __cdecl
  ADXSJE_SetLpEndPos(AdxStreamJoinEncoderState* const encoder, const std::int32_t loopEndSamplePosition)
  {
    encoder->loopEndSamplePosition = loopEndSamplePosition;
    return loopEndSamplePosition;
  }

  /**
   * Address: 0x00B1ECA0 (FUN_00B1ECA0, _ADXSJE_SetLpEndOfst)
   *
   * What it does:
   * Stores ADXSJE loop-end byte-offset lane.
   */
  std::int32_t __cdecl
  ADXSJE_SetLpEndOfst(AdxStreamJoinEncoderState* const encoder, const std::int32_t loopEndByteOffset)
  {
    encoder->loopEndByteOffset = loopEndByteOffset;
    return loopEndByteOffset;
  }

  /**
   * Address: 0x00B1ECB0 (FUN_00B1ECB0, _ADXSJE_SetAinfOutputVol)
   *
   * What it does:
   * Enables AINF extension block (if needed) and stores default output volume.
   */
  AdxStreamJoinEncoderState* __cdecl
  ADXSJE_SetAinfOutputVol(AdxStreamJoinEncoderState* const encoder, const std::int16_t outputVolume)
  {
    if (encoder->hasAinfInfo != 1) {
      encoder->hasAinfInfo = 1;
      encoder->headerInfoSizeBytes += 36;
    }

    encoder->ainfOutputVolume = outputVolume;
    return encoder;
  }

  /**
   * Address: 0x00B1ECF0 (FUN_00B1ECF0, _ADXSJE_SetAinfOutputPan)
   *
   * What it does:
   * Enables AINF extension block (if needed) and stores one output pan lane.
   */
  AdxStreamJoinEncoderState* __cdecl ADXSJE_SetAinfOutputPan(
    AdxStreamJoinEncoderState* const encoder,
    const std::int32_t channelIndex,
    const std::int16_t outputPan
  )
  {
    if (encoder->hasAinfInfo != 1) {
      encoder->hasAinfInfo = 1;
      encoder->headerInfoSizeBytes += 36;
    }

    auto* const panLanes = encoder->ainfOutputPanByChannel;
    panLanes[channelIndex] = outputPan;
    return encoder;
  }

  /**
   * Address: 0x00B1ED30 (FUN_00B1ED30, _ADXSJE_SetAinfDataId)
   *
   * What it does:
   * Enables AINF extension block (if needed), clears data-id bytes, and copies
   * up to 16 bytes from a C-string source.
   */
  std::uint8_t* __cdecl
  ADXSJE_SetAinfDataId(AdxStreamJoinEncoderState* const encoder, const char* const sourceDataIdBytes)
  {
    if (encoder->hasAinfInfo != 1) {
      encoder->hasAinfInfo = 1;
      encoder->headerInfoSizeBytes += 36;
    }

    std::memset(encoder->ainfDataIdBytes, 0, sizeof(encoder->ainfDataIdBytes));
    std::strncpy(reinterpret_cast<char*>(encoder->ainfDataIdBytes), sourceDataIdBytes, sizeof(encoder->ainfDataIdBytes));
    return encoder->ainfDataIdBytes;
  }

  /**
   * Address: 0x00B1ED80 (FUN_00B1ED80, _ADXSJE_SetAinfDataIdMem)
   *
   * What it does:
   * Enables AINF extension block (if needed), clears data-id bytes, then
   * copies 16-byte data-id payload from memory.
   */
  std::uint8_t* __cdecl ADXSJE_SetAinfDataIdMem(
    AdxStreamJoinEncoderState* const encoder,
    const std::uint8_t (*const sourceDataIdBytes)[0x10]
  )
  {
    if (encoder->hasAinfInfo != 1) {
      encoder->hasAinfInfo = 1;
      encoder->headerInfoSizeBytes += 36;
    }

    std::memset(encoder->ainfDataIdBytes, 0, sizeof(encoder->ainfDataIdBytes));
    std::memcpy(encoder->ainfDataIdBytes, *sourceDataIdBytes, sizeof(encoder->ainfDataIdBytes));
    return encoder->ainfDataIdBytes;
  }

  /**
   * Address: 0x00B1EDD0 (FUN_00B1EDD0, _ADXSJE_ClearAinf)
   *
   * What it does:
   * Clears AINF extension lanes and restores default output volume/pan values.
   */
  std::uint8_t* __cdecl ADXSJE_ClearAinf(AdxStreamJoinEncoderState* const encoder)
  {
    if (encoder->hasAinfInfo == 1) {
      encoder->hasAinfInfo = 0;
      encoder->headerInfoSizeBytes += 36;
    }

    encoder->ainfOutputVolume = 0;
    encoder->ainfOutputPanByChannel[0] = -128;
    encoder->ainfOutputPanByChannel[1] = -128;
    std::memset(encoder->ainfDataIdBytes, 0, sizeof(encoder->ainfDataIdBytes));
    return encoder->ainfDataIdBytes;
  }

  /**
   * Address: 0x00B1EE20 (FUN_00B1EE20, _ADXSJE_SetCommonInf)
   *
   * What it does:
   * Enables one ADXSJE common-info lane and reserves aligned header bytes for
   * common-info payload.
   */
  std::int8_t __cdecl ADXSJE_SetCommonInf(
    AdxStreamJoinEncoderState* const encoder,
    const std::int32_t commonInfoDataOffset,
    const std::int32_t commonInfoDataBytes
  )
  {
    if (encoder->commonInfoEnabled != 1) {
      encoder->commonInfoEnabled = 1;
      encoder->commonInfoDataOffset = commonInfoDataOffset;
      encoder->commonInfoDataBytes = commonInfoDataBytes;

      const std::uint32_t roundedInput = static_cast<std::uint32_t>(commonInfoDataBytes) + 0x7FFu;
      const std::uint32_t signBias = (roundedInput & 0x80000000u) == 0 ? 0u : 0x7FFu;
      const std::int32_t alignedCommonInfoBytes = (static_cast<std::int32_t>(roundedInput + signBias) >> 11) << 11;
      encoder->headerInfoSizeBytes += alignedCommonInfoBytes + 4;
    }

    return 1;
  }

  /**
   * Address: 0x00B1EE70 (FUN_00B1EE70, _ADXSJE_SetConfigSfa)
   *
   * What it does:
   * Applies SFA encoder config lanes (channels/sample-rate/total-samples) and
   * resets header-info size to default SFA header bytes (`0x11C`).
   */
  std::int32_t __cdecl ADXSJE_SetConfigSfa(
    AdxStreamJoinEncoderState* const encoder,
    const std::int32_t channelCount,
    const std::int32_t sampleRate,
    const std::int32_t totalSampleCount
  )
  {
    ADXSJE_SetNumChan(encoder, channelCount);
    ADXSJE_SetSfreq(encoder, sampleRate);
    ADXSJE_SetTotalNumSmpl(encoder, totalSampleCount);
    return ADXSJE_SetHdInfoSize(encoder, 0x11C);
  }

  /**
   * Address: 0x00B1EEB0 (FUN_00B1EEB0, _ADXSJE_SetExtString_also)
   *
   * What it does:
   * Generates and stores ADXSJE encoder key triple from one extension string.
   */
  AdxStreamJoinEncoderState* __cdecl
  ADXSJE_SetExtStringForEncoder(AdxStreamJoinEncoderState* const encoder, const char* const extString)
  {
    std::int16_t key0 = 0;
    std::int16_t keyMultiplier = 0;
    std::int16_t keyAdder = 0;
    SKG_GenerateKeyForEncoder(
      extString,
      static_cast<std::int32_t>(std::strlen(extString)),
      &key0,
      &keyMultiplier,
      &keyAdder
    );
    encoder->extKey0 = key0;
    encoder->extKeyMultiplier = keyMultiplier;
    encoder->extKeyAdder = keyAdder;
    return encoder;
  }

  /**
   * Address: 0x00B1EF10 (FUN_00B1EF10, _SKG_GenerateKey_also)
   *
   * What it does:
   * Generates ADXSJE key triple (`k0, km, ka`) using the legacy SKG seed lane.
   */
  std::int32_t __cdecl SKG_GenerateKeyForEncoder(
    const char* const sourceBytes,
    const std::int32_t sourceLength,
    std::int16_t* const outKey0,
    std::int16_t* const outKeyMultiplier,
    std::int16_t* const outKeyAdder
  )
  {
    if (skg_init_count_also == 0) {
      ++skg_init_count_also;
    }

    *outKey0 = 0;
    *outKeyMultiplier = 0;
    *outKeyAdder = 0;

    if (sourceBytes != nullptr || sourceLength > 0) {
      *outKey0 = GenerateKeyLane(sourceBytes, sourceLength, skg_prim_tbl[0x100]);
      *outKeyMultiplier = GenerateKeyLane(sourceBytes, sourceLength, skg_prim_tbl[0x200]);
      *outKeyAdder = GenerateKeyLane(sourceBytes, sourceLength, skg_prim_tbl[0x300]);
    }

    return 0;
  }

  /**
   * Address: 0x00B1F020 (FUN_00B1F020, _ADXSJE_GetEncDtLen)
   *
   * What it does:
   * Returns encoded ADXSJE output byte count.
   */
  std::int32_t __cdecl ADXSJE_GetEncDtLen(const AdxStreamJoinEncoderState* const encoder)
  {
    return encoder->encodedDataBytes;
  }

  /**
   * Address: 0x00B1F030 (FUN_00B1F030, _ADXSJE_GetEncNumSmpl)
   *
   * What it does:
   * Returns encoded ADXSJE sample position.
   */
  std::int32_t __cdecl ADXSJE_GetEncNumSmpl(const AdxStreamJoinEncoderState* const encoder)
  {
    return encoder->encodedSamplePosition;
  }

  /**
   * Address: 0x00B1F040 (FUN_00B1F040, _ADXSJE_SetEncPos)
   *
   * What it does:
   * Updates encoded sample position lane.
   */
  std::int32_t __cdecl
  ADXSJE_SetEncPos(AdxStreamJoinEncoderState* const encoder, const std::int32_t encodedSamplePosition)
  {
    encoder->encodedSamplePosition = encodedSamplePosition;
    return encodedSamplePosition;
  }

  /**
   * Address: 0x00B1F050 (FUN_00B1F050, _ADXSJE_GetEncPos)
   *
   * What it does:
   * Returns current encoded sample position lane.
   */
  std::int32_t __cdecl ADXSJE_GetEncPos(const AdxStreamJoinEncoderState* const encoder)
  {
    return encoder->encodedSamplePosition;
  }

  /**
   * Address: 0x00B1F060 (FUN_00B1F060, _ADXSJE_SetInSj)
   *
   * What it does:
   * Sets one ADXSJE input SJ lane handle when index is in range `[0, 2)`.
   */
  std::uint32_t __cdecl ADXSJE_SetInSj(
    AdxStreamJoinEncoderState* const encoder,
    const std::uint32_t inputLaneIndex,
    moho::SofdecSjSupplyHandle* const inputSjHandle
  )
  {
    if (inputLaneIndex < 2u) {
      encoder->inputSjHandles[inputLaneIndex] = inputSjHandle;
    }

    return inputLaneIndex;
  }

  /**
   * Address: 0x00B1F080 (FUN_00B1F080, _ADXSJE_SetOutSj)
   *
   * What it does:
   * Sets ADXSJE output SJ handle lane.
   */
  moho::SofdecSjSupplyHandle* __cdecl
  ADXSJE_SetOutSj(AdxStreamJoinEncoderState* const encoder, moho::SofdecSjSupplyHandle* const outputSjHandle)
  {
    encoder->outputSjHandle = outputSjHandle;
    return outputSjHandle;
  }

  /**
   * Address: 0x00B1F090 (FUN_00B1F090, _adxsje_encode_prep)
   *
   * What it does:
   * Pulls one priming sample from each input lane, writes ADX header, and
   * initializes predictor coefficients for active channels.
   */
  std::int32_t __cdecl adxsje_encode_prep(AdxStreamJoinEncoderState* const encoder)
  {
    std::int32_t preparedLaneCount = 0;
    moho::SofdecSjSupplyHandle* const outputSjHandle = encoder->outputSjHandle;

    if (encoder->channelCount > 0) {
      auto* const stagedPredictorStates = reinterpret_cast<std::int16_t*>(encoder->stagedPredictorWindow);
      for (; preparedLaneCount < encoder->channelCount; ++preparedLaneCount) {
        moho::SofdecSjSupplyHandle* const inputSjHandle = encoder->inputSjHandles[preparedLaneCount];
        SjChunkRange sourceChunk{};
        inputSjHandle->dispatchTable->getChunk(inputSjHandle, 1, 2, &sourceChunk);
        if (sourceChunk.byteCount == 0) {
          break;
        }

        const auto* const sourceSample = reinterpret_cast<const std::int16_t*>(
          static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceChunk.bufferAddress))
        );
        stagedPredictorStates[preparedLaneCount] = *sourceSample;
        stagedPredictorStates[preparedLaneCount + 2] = *sourceSample;
        inputSjHandle->dispatchTable->putChunk(inputSjHandle, 1, &sourceChunk);
      }
    }

    std::int32_t result = encoder->channelCount;
    if (preparedLaneCount >= result) {
      if (result > 0) {
        auto* const predictorHistory = reinterpret_cast<std::int16_t*>(encoder->predictorHistoryWindow);
        auto* const stagedPredictorStates = reinterpret_cast<std::int16_t*>(encoder->stagedPredictorWindow);
        for (std::int32_t channelIndex = 0; channelIndex < encoder->channelCount; ++channelIndex) {
          predictorHistory[channelIndex] = stagedPredictorStates[channelIndex];
          predictorHistory[channelIndex + 2] = stagedPredictorStates[channelIndex + 2];
        }
      }

      result = adxsje_output_header(encoder, outputSjHandle);
      if (result != 0) {
        encoder->encodedDataBytes += result;
        if (encoder->channelCount > 0) {
          for (std::int32_t channelIndex = 0; channelIndex < encoder->channelCount; ++channelIndex) {
            pflt_calc_coef(
              encoder->predictorFilterHandles[channelIndex],
              encoder->predictorPreset,
              encoder->predictorSampleRate
            );
          }
        }
        encoder->executionStage = 2;
        result = encoder->channelCount;
      }
    }

    return result;
  }

  /**
   * Address: 0x00B1F190 (FUN_00B1F190, _adxsje_encode_exec)
   *
   * What it does:
   * Encodes ADXSJE payload blocks until stream-end, then emits ADX end code.
   */
  std::int32_t __cdecl adxsje_encode_exec(AdxStreamJoinEncoderState* const encoder)
  {
    std::int32_t result = 0;
    if (encoder->endCodePending == 0) {
      while (true) {
        result = adxsje_encode_data(encoder);
        if (result == 0) {
          return result;
        }

        encoder->encodedDataBytes += result;
        if (encoder->encodedSamplePosition >= encoder->totalSampleCount) {
          encoder->endCodePending = 1;
          break;
        }
      }
    }

    result = adxsje_write_end_code(encoder);
    if (result > 0) {
      encoder->executionStage = 3;
    }
    return result;
  }

  /**
   * Address: 0x00B1F1E0 (FUN_00B1F1E0, _ADXSJE_ExecHndl)
   *
   * What it does:
   * Dispatches one ADXSJE handle execution state to prep or encode stage.
   */
  std::int32_t __cdecl ADXSJE_ExecHndl(AdxStreamJoinEncoderState* const encoder)
  {
    if (encoder->executionStage == 1) {
      return adxsje_encode_prep(encoder);
    }

    if (encoder->executionStage == 2) {
      return adxsje_encode_exec(encoder);
    }

    return encoder->executionStage;
  }

  /**
   * Address: 0x00B1F210 (FUN_00B1F210, _ADXSJE_ExecServer)
   *
   * What it does:
   * Runs ADXSJE handle execution over all active encoder slots.
   */
  std::int32_t ADXSJE_ExecServer()
  {
    std::int32_t lastResult = 0;
    for (auto* encoder = adxsje_obj; encoder < adxsje_obj + kAdxsjeObjectCount; ++encoder) {
      if (encoder->used == 1) {
        lastResult = ADXSJE_ExecHndl(encoder);
      }
    }
    return lastResult;
  }

  /**
   * Address: 0x00B1F240 (FUN_00B1F240, nullsub_3629)
   *
   * What it does:
   * No-op ADXSJE callback slot.
   */
  void ADXSJE_NoOpStateCallback()
  {
  }

  /**
   * Address: 0x00B1F280 (FUN_00B1F280, nullsub_3630)
   *
   * What it does:
   * No-op ADXSJE callback slot.
   */
  void ADXSJE_NoOpSupplyCallback()
  {
  }

  /**
   * Address: 0x00B21460 (ADXSJE_SetExtString)
   *
   * What it does:
   * Generates and stores per-stream ADX key triple from one extension string.
   */
  moho::AdxBitstreamDecoderState* ADXSJE_SetExtString(moho::AdxBitstreamDecoderState* decoder, const char* extString)
  {
    std::int16_t key0 = 0;
    std::int16_t keyMultiplier = 0;
    std::int16_t keyAdder = 0;
    SKG_GenerateKey(extString, static_cast<std::int32_t>(std::strlen(extString)), &key0, &keyMultiplier, &keyAdder);
    decoder->extKey0 = key0;
    decoder->extKeyMultiplier = keyMultiplier;
    decoder->extKeyAdder = keyAdder;
    return decoder;
  }

  /**
   * Address: 0x00B214C0 (SKG_GenerateKey)
   *
   * What it does:
   * Generates one ADX key triple (`k0, km, ka`) from input bytes.
   */
  std::int32_t SKG_GenerateKey(
    const char* sourceBytes,
    const std::int32_t sourceLength,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    if (skg_init_count == 0) {
      ++skg_init_count;
    }

    *outKey0 = 0;
    *outKeyMultiplier = 0;
    *outKeyAdder = 0;

    if (sourceBytes != nullptr || sourceLength > 0) {
      *outKey0 = GenerateKeyLane(sourceBytes, sourceLength, 18973);
      *outKeyMultiplier = GenerateKeyLane(sourceBytes, sourceLength, 21503);
      *outKeyAdder = GenerateKeyLane(sourceBytes, sourceLength, 24001);
    }

    return 0;
  }

  /**
   * Address: 0x00B215D0 (ADXB_SetDefExtString)
   *
   * What it does:
   * Updates process-global default ADX extension key triple from one string.
   */
  std::int32_t ADXB_SetDefExtString(const char* extString)
  {
    return SKG_GenerateKey(
      extString,
      static_cast<std::int32_t>(std::strlen(extString)),
      &adxb_def_k0,
      &adxb_def_km,
      &adxb_def_ka
    );
  }

  /**
   * Address: 0x00B21600 (ADXB_GetExtParams)
   *
   * What it does:
   * Returns decoder-local ADX extension key triple.
   */
  std::int16_t ADXB_GetExtParams(
    const moho::AdxBitstreamDecoderState* decoder,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    *outKey0 = decoder->extKey0;
    *outKeyMultiplier = decoder->extKeyMultiplier;
    *outKeyAdder = decoder->extKeyAdder;
    return decoder->extKeyAdder;
  }

  /**
   * Address: 0x00B21630 (ADXB_SetExtParams)
   *
   * What it does:
   * Stores decoder-local ADX extension key triple.
   */
  moho::AdxBitstreamDecoderState* ADXB_SetExtParams(
    moho::AdxBitstreamDecoderState* decoder,
    const std::int16_t key0,
    const std::int16_t keyMultiplier,
    const std::int16_t keyAdder
  )
  {
    decoder->extKey0 = key0;
    decoder->extKeyMultiplier = keyMultiplier;
    decoder->extKeyAdder = keyAdder;
    return decoder;
  }

  /**
   * Address: 0x00B21660 (adxb_get_key)
   *
   * What it does:
   * Resolves runtime key triple based on ADX encryption mode/version lanes.
   */
  std::int32_t adxb_get_key(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t encryptionMode,
    const std::uint8_t headerVersion,
    const std::int32_t streamId,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    if (encryptionMode < 4) {
      *outKey0 = 0;
      *outKeyMultiplier = 0;
      *outKeyAdder = 0;
      return 0;
    }

    if (headerVersion >= 0x10) {
      char streamIdHex[16]{};
      std::snprintf(streamIdHex, sizeof(streamIdHex), "%08X", static_cast<unsigned int>(streamId));
      SKG_GenerateKey(streamIdHex, 8, outKey0, outKeyMultiplier, outKeyAdder);
      return 0;
    }

    if (headerVersion < 8) {
      *outKey0 = 0;
      *outKeyMultiplier = 0;
      *outKeyAdder = 0;
      return 0;
    }

    if (decoder->extKey0 == 0 && decoder->extKeyMultiplier == 0 && decoder->extKeyAdder == 0) {
      decoder->extKey0 = adxb_def_k0;
      decoder->extKeyMultiplier = adxb_def_km;
      decoder->extKeyAdder = adxb_def_ka;
    }

    *outKey0 = decoder->extKey0;
    *outKeyMultiplier = decoder->extKeyMultiplier;
    *outKeyAdder = decoder->extKeyAdder;
    return 0;
  }

  /**
   * Address: 0x00B21770 (ADXB_GetStat)
   *
   * What it does:
   * Returns decoder status lane.
   */
  std::int32_t ADXB_GetStat(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->status;
  }

  /**
   * Address: 0x00B21780 (ADXB_EntryData)
   *
   * What it does:
   * Seeds one decode-entry run and returns number of decode blocks.
   */
  std::int32_t ADXB_EntryData(
    moho::AdxBitstreamDecoderState* decoder,
    const std::int32_t streamDataOffset,
    const std::int32_t inputBytes
  )
  {
    decoder->decodeCursor = 0;

    std::int32_t unitBytes = 0;
    decoder->streamDataOffset = streamDataOffset;

    if (decoder->format == 0) {
      unitBytes = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceBlockBytes));
    } else {
      const auto sampleBits = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceSampleBits));
      const auto roundedBytes = (sampleBits + ((sampleBits >> 31) & 7)) >> 3;
      unitBytes = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceChannels)) * roundedBytes;
    }

    decoder->decodeProgress0 = 0;
    decoder->decodeProgress1 = 0;
    decoder->pendingConsumeBytes = 0;
    decoder->pendingSubmitBytes = 0;
    decoder->streamBlockCount = inputBytes / unitBytes;
    return decoder->streamBlockCount;
  }

  /**
   * Address: 0x00B217F0 (ADXB_Start)
   *
   * What it does:
   * Transitions one ADXB decoder to running state.
   */
  moho::AdxBitstreamDecoderState* ADXB_Start(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder->status == 0) {
      decoder->status = 1;
    }
    return decoder;
  }

  /**
   * Address: 0x00B21810 (ADXB_Stop)
   *
   * What it does:
   * Runs optional post-process detach and stops one ADX packet decoder.
   */
  std::int32_t ADXB_Stop(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder->channelExpandHandle != 0) {
      ADXB_OnStopPostProcess(decoder);
    }

    const void* const result = ADXPD_Stop(decoder->adxPacketDecoder);
    decoder->status = 0;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B21840 (ADXB_Reset)
   *
   * What it does:
   * Resets ADX packet-decode state when one decode pass reached done state.
   */
  std::int32_t ADXB_Reset(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->runState == 3) {
      ADXPD_Reset(runtime->adxPacketDecoder);
      runtime->entryCommittedBytes = 0;
      runtime->runState = 0;
    }

    return 0;
  }

  /**
   * Address: 0x00B21870 (ADXB_GetDecDtLen)
   *
   * What it does:
   * Returns decoded output-byte count from one ADXB runtime object.
   */
  std::int32_t ADXB_GetDecDtLen(const moho::AdxBitstreamDecoderState* decoder)
  {
    return AsAdxbRuntimeView(decoder)->producedByteCount;
  }

  /**
   * Address: 0x00B21880 (ADXB_GetDecNumSmpl)
   *
   * What it does:
   * Returns decoded output-sample count from one ADXB runtime object.
   */
  std::int32_t ADXB_GetDecNumSmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return AsAdxbRuntimeView(decoder)->producedSampleCount;
  }

  /**
   * Address: 0x00B21890 (ADXB_SetCbDec)
   *
   * What it does:
   * Registers one decode-progress callback and callback context.
   */
  moho::AdxBitstreamDecoderState* ADXB_SetCbDec(
    moho::AdxBitstreamDecoderState* decoder,
    std::int32_t(__cdecl* callback)(std::int32_t, std::int32_t, std::int32_t),
    const std::int32_t callbackContext
  )
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    runtime->decodeCallback = callback;
    runtime->decodeCallbackContext = callbackContext;
    return decoder;
  }

  /**
   * Address: 0x00B218B0 (ADXB_GetAdxpd)
   *
   * What it does:
   * Returns attached ADX packet-decoder handle from one ADXB runtime object.
   */
  void* ADXB_GetAdxpd(const moho::AdxBitstreamDecoderState* decoder)
  {
    return AsAdxbRuntimeView(decoder)->adxPacketDecoder;
  }

  /**
   * Address: 0x00B218C0 (ADXB_EvokeExpandMono)
   *
   * What it does:
   * Queues one mono expansion decode job into ADXPD and starts execution.
   */
  std::int32_t ADXB_EvokeExpandMono(moho::AdxBitstreamDecoderState* decoder, const std::int32_t blockCount)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputLeft = runtime->outputWordStream0 + runtime->entryWriteStartWordIndex;

    ADXPD_EntryMono(
      runtime->adxPacketDecoder,
      runtime->sourceWordStream,
      blockCount,
      reinterpret_cast<std::uint16_t*>(outputLeft),
      nullptr
    );

    const auto result = ADXPD_Start(runtime->adxPacketDecoder);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B218F0 (ADXB_EvokeExpandPl2)
   *
   * What it does:
   * Queues one PL2 expansion decode job into ADXPD and starts execution.
   */
  std::int32_t ADXB_EvokeExpandPl2(moho::AdxBitstreamDecoderState* decoder, const std::int32_t blockCount)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputLeft = runtime->outputWordStream0 + runtime->entryWriteStartWordIndex;
    auto* const outputRight = outputLeft + runtime->outputSecondChannelOffset;

    ADXPD_EntryPl2(
      runtime->adxPacketDecoder,
      runtime->sourceWordStream,
      blockCount * 2,
      reinterpret_cast<std::uint16_t*>(outputLeft),
      reinterpret_cast<std::uint16_t*>(outputRight)
    );

    const auto result = ADXPD_Start(runtime->adxPacketDecoder);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B21930 (ADXB_EvokeExpandSte)
   *
   * What it does:
   * Queues one stereo expansion decode job into ADXPD and starts execution.
   */
  std::int32_t ADXB_EvokeExpandSte(moho::AdxBitstreamDecoderState* decoder, const std::int32_t blockCount)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputLeft = runtime->outputWordStream0 + runtime->entryWriteStartWordIndex;
    auto* const outputRight = outputLeft + runtime->outputSecondChannelOffset;

    ADXPD_EntrySte(
      runtime->adxPacketDecoder,
      runtime->sourceWordStream,
      blockCount,
      reinterpret_cast<std::uint16_t*>(outputLeft),
      reinterpret_cast<std::uint16_t*>(outputRight)
    );

    const auto result = ADXPD_Start(runtime->adxPacketDecoder);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B21970 (ADXB_EvokeDecode)
   *
   * What it does:
   * Computes bounded decode-block count for current write window and dispatches
   * mono/stereo/PL2 expansion lane.
   */
  std::int32_t ADXB_EvokeDecode(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    const auto decodeUnitWords = runtime->entrySubmittedBytes;
    const auto outputChannelCount = runtime->outputChannels;

    const auto blockLimitByInput = runtime->sourceWordLimit / outputChannelCount;
    auto blockLimitByWindowCapacity = (runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords;

    const auto tailRemainder = (runtime->entryWriteCapacityWords + decodeUnitWords - 1) % decodeUnitWords;
    const auto tailSlackWords = decodeUnitWords - tailRemainder - 1;

    auto blockLimitByOutputWindow =
      (runtime->outputWordLimit - runtime->entryWriteStartWordIndex + decodeUnitWords - 1) / decodeUnitWords;

    if (
      ((runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords) < blockLimitByOutputWindow
      && runtime->entryWriteStartWordIndex + decodeUnitWords * blockLimitByOutputWindow - tailSlackWords < runtime->outputWordLimit
    ) {
      ++blockLimitByOutputWindow;
    }

    auto pendingWriteWords = runtime->entryWriteUsedWordCount;
    if (runtime->entryWriteCapacityWords < pendingWriteWords) {
      pendingWriteWords += tailSlackWords;
    }

    auto decodeBlockCount = pendingWriteWords / decodeUnitWords;
    if (decodeBlockCount > blockLimitByInput) {
      decodeBlockCount = blockLimitByInput;
    }
    if (decodeBlockCount > ((runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords)) {
      decodeBlockCount = (runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords;
    }
    if (decodeBlockCount > blockLimitByWindowCapacity) {
      decodeBlockCount = blockLimitByWindowCapacity;
    }
    if (decodeBlockCount > blockLimitByOutputWindow) {
      decodeBlockCount = blockLimitByOutputWindow;
    }

    if (outputChannelCount == 2) {
      return ADXB_EvokeExpandPl2(decoder, decodeBlockCount);
    }
    if (runtime->channelExpandHandle != 0) {
      return ADXB_EvokeExpandSte(decoder, decodeBlockCount);
    }
    return ADXB_EvokeExpandMono(decoder, decodeBlockCount);
  }

  /**
   * Address: 0x00B21A50 (memcpy2)
   *
   * What it does:
   * Copies one signed-16 sample lane in word units.
   */
  std::int16_t* memcpy2(std::int16_t* destinationWords, const std::int16_t* sourceWords, std::int32_t wordCount)
  {
    if (wordCount <= 0) {
      return destinationWords;
    }

    while (wordCount > 0) {
      *destinationWords++ = *sourceWords++;
      --wordCount;
    }
    return destinationWords;
  }

  /**
   * Address: 0x00B21A80 (ADXB_CopyExtraBufSte)
   *
   * What it does:
   * Rolls and copies stereo tail words into wrap region and secondary lane.
   */
  std::int16_t* ADXB_CopyExtraBufSte(
    std::int16_t* sampleWords,
    const std::int32_t wrapBaseWord,
    const std::int32_t secondaryStartWord,
    const std::int32_t tailWordCount
  )
  {
    memcpy2(sampleWords + wrapBaseWord, sampleWords, tailWordCount);
    return memcpy2(
      sampleWords + secondaryStartWord,
      sampleWords + wrapBaseWord + secondaryStartWord,
      tailWordCount
    );
  }

  /**
   * Address: 0x00B21AC0 (ADXB_CopyExtraBufMono)
   *
   * What it does:
   * Rolls and copies mono tail words into wrap region.
   */
  std::int16_t* ADXB_CopyExtraBufMono(
    std::int16_t* sampleWords,
    const std::int32_t wrapBaseWord,
    const std::int32_t /*unusedSecondaryWord*/,
    const std::int32_t tailWordCount
  )
  {
    return memcpy2(sampleWords, sampleWords + wrapBaseWord, tailWordCount);
  }

  /**
   * Address: 0x00B21AE0 (ADXB_EndDecode)
   *
   * What it does:
   * Finalizes one ADXPD decode step, computes produced counts, and applies
   * wrap-buffer copy lanes when window overflows.
   */
  std::int16_t* ADXB_EndDecode(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputWords = runtime->outputWordStream0;
    const auto decodedBlockCount = ADXPD_GetNumBlk(runtime->adxPacketDecoder);

    std::int32_t producedSamples = runtime->outputBlockSamples * decodedBlockCount / runtime->outputChannels;
    if (
      ((runtime->entryWriteCapacityWords + runtime->outputBlockSamples - 1) / runtime->outputBlockSamples) * runtime->outputChannels
      <= decodedBlockCount
    ) {
      producedSamples +=
        ((runtime->entryWriteCapacityWords + runtime->outputBlockSamples - 1) % runtime->outputBlockSamples)
        - runtime->outputBlockSamples + 1;
    }

    runtime->producedSampleCount = producedSamples;
    runtime->producedByteCount = runtime->outputBlockBytes * decodedBlockCount;

    const auto windowTailWord = runtime->entryWriteStartWordIndex + producedSamples;
    if (windowTailWord >= runtime->pcmBufferSampleLimit) {
      const auto tailWordCount = windowTailWord - runtime->pcmBufferSampleLimit;
      if (runtime->outputChannels == 2 || runtime->channelExpandHandle != 0) {
        ADXB_CopyExtraBufSte(
          outputWords,
          runtime->pcmBufferSampleLimit,
          runtime->outputSecondChannelOffset,
          tailWordCount
        );
      } else {
        ADXB_CopyExtraBufMono(
          outputWords,
          runtime->pcmBufferSampleLimit,
          runtime->outputSecondChannelOffset,
          tailWordCount
        );
      }
    }

    return outputWords;
  }

  /**
   * Address: 0x00B21BC0 (ADXB_ExecOneAdx)
   *
   * What it does:
   * Executes one ADX decode step: acquires write window, runs ADXPD, handles
   * optional channel-expand callbacks, and commits produced output.
   */
  void ADXB_ExecOneAdx(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);

    if (runtime->runState == 1 && ADXPD_GetStat(runtime->adxPacketDecoder) == 0) {
      runtime->entryGetWriteFunc(
        runtime->entryGetWriteContext,
        &runtime->entryWriteStartWordIndex,
        &runtime->entryWriteUsedWordCount,
        &runtime->entryWriteCapacityWords
      );

      ADXB_EvokeDecode(decoder);
      runtime->runState = 2;
    }

    if (runtime->runState != 2) {
      return;
    }

    ADXPD_ExecHndl(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(runtime->adxPacketDecoder)));
    if (ADXPD_GetStat(runtime->adxPacketDecoder) != 3) {
      return;
    }

    if (runtime->channelExpandHandle != 0) {
      auto* const packetState = reinterpret_cast<AdxPacketDecodeSampleView*>(runtime->adxPacketDecoder);
      ADXCRS_Lock();
      for (std::int32_t sampleIndex = 0; sampleIndex < 32 * packetState->sourceChannels; ++sampleIndex) {
        const auto sampleOffsetBytes = static_cast<std::size_t>(2 * sampleIndex);
        const auto* const leftSample =
          reinterpret_cast<const std::int16_t*>(packetState->primaryOutputBytes + sampleOffsetBytes);
        const auto* const rightSample =
          reinterpret_cast<const std::int16_t*>(packetState->secondaryOutputBytes + sampleOffsetBytes);
        const auto sampleValue = static_cast<std::int32_t>(*leftSample);
        ADXB_OnExpandSamplePair(decoder, sampleValue, leftSample, rightSample);
      }
      ADXCRS_Unlock();
    }

    ADXB_EndDecode(decoder);
    ADXPD_Reset(runtime->adxPacketDecoder);

    runtime->entryAddWriteFunc(
      runtime->entryAddWriteContext,
      runtime->producedByteCount,
      runtime->producedSampleCount
    );

    runtime->runState = 3;
  }

  std::int32_t adxb_dec_cb_proc(moho::AdxBitstreamDecoderState* decoder);

  /**
   * Address: 0x00B21CB0 (ADXB_ExecHndl)
   *
   * What it does:
   * Dispatches one ADXB execution lane by decoded format and runs optional
   * decode-progress callback hook.
   */
  std::int32_t ADXB_ExecHndl(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);

    switch (runtime->format) {
      case 0:
        ADXB_ExecOneAdx(decoder);
        break;
      case 10:
        ADXB_ExecOneAhx(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 2:
        ADXB_ExecOneSpsd(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 3:
        ADXB_ExecOneAiff(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 4:
        ADXB_ExecOneAu(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 1:
        ADXB_ExecOneWav(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 11:
        ADXB_ExecOneMpa(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 12:
        ADXB_ExecOneM2a(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      default:
        break;
    }

    if (runtime->decodeCallback != nullptr) {
      return adxb_dec_cb_proc(decoder);
    }
    return 0;
  }

  /**
   * Address: 0x00B21D50 (adxb_dec_cb_proc)
   *
   * What it does:
   * Computes decode delta accounting and invokes ADXB decode callback.
   */
  std::int32_t adxb_dec_cb_proc(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);

    auto producedDelta = runtime->producedByteCount - runtime->decodeCallbackConsumedBytes;
    if (producedDelta < 0) {
      producedDelta += 0x7FFFFFFF;
    }

    const auto producedBytes =
      2 * runtime->producedSampleCount * static_cast<std::int32_t>(runtime->sourceChannels);

    const auto result = runtime->decodeCallback(runtime->decodeCallbackContext, producedDelta, producedBytes);
    runtime->decodeCallbackConsumedBytes = runtime->producedByteCount;
    return result;
  }

  /**
   * Address: 0x00B21DA0 (ADXB_ExecServer)
   *
   * What it does:
   * Iterates ADXB slot pool and executes active decoder lanes.
   */
  std::int32_t ADXB_ExecServer()
  {
    std::int32_t lastResult = 0;
    for (auto& decoder : adxb_obj) {
      if (decoder.slotState == 1) {
        lastResult = ADXB_ExecHndl(&decoder);
      }
    }
    return lastResult;
  }

  /**
   * Address: 0x00B21DD0 (ADXB_SetAhxInSj)
   *
   * What it does:
   * Forwards stream-join input setup into AHX runtime handle when attached.
   */
  std::int32_t ADXB_SetAhxInSj(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->ahxDecoderHandle != nullptr && ahxsetsjifunc != nullptr) {
      return ahxsetsjifunc(runtime->ahxDecoderHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B21DF0 (ADXB_SetAhxDecSmpl)
   *
   * What it does:
   * Stores AHX max decode samples and derived 96-sample block count lane.
   */
  std::uint32_t ADXB_SetAhxDecSmpl(moho::AdxBitstreamDecoderState* decoder, const std::int32_t maxDecodeSamples)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->ahxDecoderHandle != nullptr && ahxsetdecsmplfunc != nullptr) {
      ahxsetdecsmplfunc(runtime->ahxDecoderHandle, maxDecodeSamples);
    }

    runtime->ahxMaxDecodeSamples = maxDecodeSamples;

    const auto highProductWord = static_cast<std::int32_t>(
      (0x2AAAAAABLL * static_cast<long long>(maxDecodeSamples)) >> 32
    );
    auto divideBy96 = highProductWord >> 4;
    const auto signAdjust = static_cast<std::uint32_t>(divideBy96) >> 31;
    divideBy96 += static_cast<std::int32_t>(signAdjust);
    runtime->ahxMaxDecodeBlocks = divideBy96;
    return signAdjust;
  }

  /**
   * Address: 0x00B1AFE0 (FUN_00B1AFE0, _ADXB_SetMpaInSj)
   *
   * What it does:
   * Forwards stream-join input setup into MPEG audio runtime handle when
   * decoder lane is attached.
   */
  std::int32_t ADXB_SetMpaInSj(moho::AdxBitstreamDecoderState* const decoder)
  {
    void* const mpegAudioDecoder = decoder->mpegAudioDecoder;
    if (mpegAudioDecoder != nullptr) {
      return mpasetsjifunc(mpegAudioDecoder);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(mpegAudioDecoder));
  }

  /**
   * Address: 0x00B1B000 (FUN_00B1B000, _ADXB_SetMpaDecSmpl)
   *
   * What it does:
   * Stores MPEG audio decode sample limit and derived 1152-sample block count.
   */
  std::uint32_t ADXB_SetMpaDecSmpl(moho::AdxBitstreamDecoderState* const decoder, const std::int32_t maxDecodeSamples)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    const auto highProductWord = static_cast<std::int32_t>(
      (0x38E38E39LL * static_cast<long long>(maxDecodeSamples)) >> 32
    );
    auto divideBy1152 = highProductWord >> 8;
    const auto signAdjust = static_cast<std::uint32_t>(divideBy1152) >> 31;
    divideBy1152 += static_cast<std::int32_t>(signAdjust);

    runtime->mpaDecodeSampleLimit = maxDecodeSamples;
    runtime->mpaDecodeBlockLimit = divideBy1152;
    return signAdjust;
  }

  /**
   * Address: 0x00B1BE60 (_ADXB_SetM2aDecSmpl)
   *
   * What it does:
   * Stores MPEG-2 AAC decode sample limit and derived 1024-sample block count.
   */
  std::int32_t ADXB_SetM2aDecSmpl(moho::AdxBitstreamDecoderState* decoder, const std::int32_t maxDecodeSamples)
  {
    decoder->m2aDecodeSampleLimit = maxDecodeSamples;
    decoder->m2aDecodeBlockLimit = maxDecodeSamples / 1024;
    return decoder->m2aDecodeBlockLimit;
  }

  /**
   * Address: 0x00B1B030 (_ADXB_MpaTermSupply)
   *
   * What it does:
   * Forwards terminate-supply to MPEG audio runtime when decoder handle exists.
   */
  std::int32_t ADXB_MpaTermSupply(moho::AdxBitstreamDecoderState* decoder)
  {
    void* const mpegAudioDecoder = decoder->mpegAudioDecoder;
    if (mpegAudioDecoder != nullptr) {
      return mpatermsupplyfunc(mpegAudioDecoder);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(mpegAudioDecoder));
  }

  /**
   * Address: 0x00B1B050 (_ADXB_ExecOneMpa)
   *
   * What it does:
   * Executes one MPEG audio decode step through registered runtime callback.
   */
  std::int32_t __cdecl ADXB_ExecOneMpa(const std::int32_t decoderAddress)
  {
    auto* const decoder = reinterpret_cast<moho::AdxBitstreamDecoderState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(decoderAddress))
    );
    if (decoder->mpegAudioDecoder != nullptr) {
      return mpaexecfunc();
    }
    return decoderAddress;
  }

  /**
   * Address: 0x00B1BE90 (_ADXB_M2aTermSupply)
   *
   * What it does:
   * Forwards terminate-supply to MPEG-2 AAC runtime when decoder handle exists.
   */
  std::int32_t ADXB_M2aTermSupply(moho::AdxBitstreamDecoderState* decoder)
  {
    void* const m2aDecoderHandle = decoder->mpeg2AacDecoder;
    if (m2aDecoderHandle != nullptr) {
      return m2atermsupplyfunc(m2aDecoderHandle);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(m2aDecoderHandle));
  }

  /**
   * Address: 0x00B1BEB0 (_ADXB_ExecOneM2a)
   *
   * What it does:
   * Executes one MPEG-2 AAC decode step through registered runtime callback.
   */
  std::int32_t __cdecl ADXB_ExecOneM2a(const std::int32_t decoderAddress)
  {
    auto* const decoder = reinterpret_cast<moho::AdxBitstreamDecoderState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(decoderAddress))
    );
    if (decoder->mpeg2AacDecoder != nullptr) {
      return m2aexecfunc();
    }
    return decoderAddress;
  }

  /**
   * Address: 0x00B21E30 (ADXB_ExecOneAhx)
   *
   * What it does:
   * Executes AHX decode lane through registered runtime callback.
   */
  std::int32_t __cdecl ADXB_ExecOneAhx(const std::int32_t /*decoderAddress*/)
  {
    if (ahxexecfunc != nullptr) {
      return ahxexecfunc();
    }
    return 0;
  }

  /**
   * Address: 0x00B21E40 (ADXB_AhxTermSupply)
   *
   * What it does:
   * Forwards AHX terminate-supply request when AHX handle is attached.
   */
  std::int32_t ADXB_AhxTermSupply(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->ahxDecoderHandle != nullptr && ahxtermsupplyfunc != nullptr) {
      return ahxtermsupplyfunc(runtime->ahxDecoderHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B21E60 (j_func_sofdec_EnterLock_7)
   *
   * What it does:
   * Enters Sofdec global lock lane.
   */
  void sofdec_EnterLock_7()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B21E70 (j_func_sofdec_LeaveLock_7)
   *
   * What it does:
   * Leaves Sofdec global lock lane.
   */
  void sofdec_LeaveLock_7()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B21EA0 (sub_B21EA0)
   *
   * What it does:
   * Stores global report callback and callback context lanes.
   */
  SofdecReportCallback ADXT_SetReportCallback(
    const SofdecReportCallback callback,
    const std::int32_t callbackContext
  )
  {
    gSofdecReportCallback = callback;
    gSofdecReportCallbackContext = callbackContext;
    return callback;
  }

  /**
   * Address: 0x00B21E80 (sub_B21E80)
   *
   * What it does:
   * Lock-guarded wrapper for report callback registration.
   */
  void ADXT_SetReportCallbackLocked(const SofdecReportCallback callback, const std::int32_t callbackContext)
  {
    sofdec_EnterLock_7();
    ADXT_SetReportCallback(callback, callbackContext);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B21EE0 (sub_B21EE0)
   *
   * What it does:
   * Increments global Dolby-attach reference counter lane.
   */
  void ADXT_IncrementAttachRef()
  {
    ++gSofdecDolbyAttachRefCount;
  }

  /**
   * Address: 0x00B21EC0 (sub_B21EC0)
   *
   * What it does:
   * Lock-guarded wrapper for incrementing attach-reference counter.
   */
  void ADXT_IncrementAttachRefLocked(const std::int32_t /*unused*/)
  {
    sofdec_EnterLock_7();
    ADXT_IncrementAttachRef();
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B21F10 (sub_B21F10)
   *
   * What it does:
   * Decrements global Dolby-attach reference counter lane.
   */
  void ADXT_DecrementAttachRef()
  {
    --gSofdecDolbyAttachRefCount;
  }

  /**
   * Address: 0x00B21EF0 (sub_B21EF0)
   *
   * What it does:
   * Lock-guarded wrapper for decrementing attach-reference counter.
   */
  void ADXT_DecrementAttachRefLocked(const std::int32_t /*unused*/)
  {
    sofdec_EnterLock_7();
    ADXT_DecrementAttachRef();
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B0CE90 (FUN_00B0CE90, _adxt_detach_ahx)
   *
   * What it does:
   * Dispatches ADXT AHX detach through installed AHX detach callback lane.
   */
  void adxt_detach_ahx()
  {
    if (ahxdetachfunc != nullptr) {
      (void)ahxdetachfunc();
    }
  }

  /**
   * Address: 0x00B0CEA0 (FUN_00B0CEA0, _adxt_detach_mpa)
   * Also emitted at: 0x00B0F010 (FUN_00B0F010, _ADXT_DetachMpa)
   *
   * What it does:
   * Dispatches ADXT MPEG-audio detach through installed detach callback lane.
   */
  std::int32_t ADXT_DetachMpa()
  {
    const auto detachThunk = reinterpret_cast<AdxtCodecDetachThunkCallback>(mpadetachfunc);
    if (detachThunk != nullptr) {
      return detachThunk();
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(detachThunk));
  }

  /**
   * Address: 0x00B0CB60 (FUN_00B0CB60, _ADXT_Create)
   *
   * What it does:
   * Creates one ADXT runtime under ADXCRS enter/leave guards.
   */
  void* ADXT_Create(const std::int32_t maxChannelCount, void* const workBuffer, const std::int32_t workBytes)
  {
    ADXCRS_Enter();
    void* const runtime = adxt_Create(maxChannelCount, workBuffer, workBytes);
    ADXCRS_Leave();
    return runtime;
  }

  /**
   * Address: 0x00B0CE20 (FUN_00B0CE20)
   *
   * What it does:
   * Creates one ADXT runtime with Dolby Pro Logic II setup under ADXCRS
   * enter/leave guards.
   */
  void* ADXT_CreateDolbyProLogicII(void* const workBuffer, const std::int32_t workBytes)
  {
    ADXCRS_Enter();
    void* const runtime = adxt_CreateDolbyProLogicII(workBuffer, workBytes);
    ADXCRS_Leave();
    return runtime;
  }

  /**
   * Address: 0x00B0CE50 (FUN_00B0CE50)
   *
   * What it does:
   * Creates one 2-channel ADXT runtime using remaining work area and attaches
   * Dolby Pro Logic II state from the reserved lead block.
   */
  void* adxt_CreateDolbyProLogicII(void* const workBuffer, const std::int32_t workBytes)
  {
    auto* const runtime = adxt_Create(
      2,
      static_cast<void*>(static_cast<std::uint8_t*>(workBuffer) + 0x400),
      workBytes - 0x400
    );
    if (runtime != nullptr) {
      (void)ADXT_AttachDolbyProLogicII(runtime, workBuffer, 0x400);
    }
    return runtime;
  }

  /**
   * Address: 0x00B0D9C0 (FUN_00B0D9C0, _ADXT_SetOutPan)
   *
   * What it does:
   * Runs one ADXT output-pan update inside legacy ADX enter/leave wrappers.
   */
  void ADXT_SetOutPan(void* const adxtRuntime, const std::int32_t laneIndex, const std::int32_t panLevel)
  {
    ADXCRS_Enter();
    (void)adxt_SetOutPan(adxtRuntime, laneIndex, panLevel);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D9F0 (FUN_00B0D9F0, _adxt_SetOutPan)
   *
   * What it does:
   * Resolves one effective channel pan (default/override/mono rules), stores
   * the caller pan lane, and applies output pan to ADX RNA.
   */
  std::int32_t adxt_SetOutPan(void* const adxtRuntime, const std::int32_t laneIndex, const std::int32_t panLevel)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtSetOutPanNullRuntimeMessage);
    }

    std::int32_t defaultPan = 0;
    if (runtime->DefaultPanSeedEnabled() == 1u) {
      defaultPan = static_cast<std::int32_t>(ADXSJD_GetDefPan(runtime->sjdHandle, laneIndex));
      if (defaultPan == -128) {
        defaultPan = 0;
      }
    }

    std::int32_t effectivePan = 0;
    if (adxt_output_mono_flag != 0) {
      effectivePan = 0;
    } else if (panLevel == -128) {
      if (ResolveAdxsjdChannelCount(runtime->sjdHandle) == 2) {
        effectivePan = defaultPan + (laneIndex != 0 ? 15 : -15);
      } else {
        effectivePan = defaultPan;
      }
    } else {
      effectivePan = defaultPan + panLevel;
    }

    runtime->RequestedPanLane(laneIndex) = static_cast<std::int16_t>(panLevel);

    if (laneIndex >= static_cast<std::int32_t>(runtime->maxChannelCount)) {
      return ADXERR_CallErrFunc1_(kAdxtSetOutPanLaneRangeMessage);
    }

    return SetAdxrnaOutputPan(runtime->rnaHandle, laneIndex, effectivePan);
  }

  /**
   * Address: 0x00B0DAE0 (FUN_00B0DAE0, _adxt_GetOutPan)
   *
   * What it does:
   * Returns ADXT requested output-pan lane (`+0x42 + lane*2`) or reports null
   * runtime parameter usage.
   */
  std::int32_t adxt_GetOutPan(void* const adxtRuntime, const std::int32_t laneIndex)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetOutPanParameterErrorMessage);
      return 0;
    }

    return static_cast<std::int32_t>(runtime->RequestedPanLane(laneIndex));
  }

  /**
   * Address: 0x00B0DAB0 (FUN_00B0DAB0, _ADXT_GetOutPan)
   *
   * What it does:
   * Returns ADXT output-pan lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetOutPan(void* const adxtRuntime, const std::int32_t laneIndex)
  {
    ADXCRS_Enter();
    const std::int32_t outputPan = adxt_GetOutPan(adxtRuntime, laneIndex);
    ADXCRS_Leave();
    return outputPan;
  }

  /**
   * Address: 0x00B0DB30 (FUN_00B0DB30, _adxt_SetOutBalance)
   *
   * What it does:
   * Clamps/stores ADXT output-balance lane (`+0x46`) and applies effective RNA
   * output-balance (mono override uses `-128`).
   */
  void adxt_SetOutBalance(void* const adxtRuntime, const std::int32_t balanceLevel)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetOutBalanceParameterErrorMessage);
      return;
    }

    std::int32_t clampedBalance = balanceLevel;
    if (clampedBalance < -15) {
      clampedBalance = -15;
    } else if (clampedBalance > 15) {
      clampedBalance = 15;
    }

    runtime->OutputBalanceLevel() = static_cast<std::int16_t>(clampedBalance);

    if (adxt_output_mono_flag != 0) {
      (void)ADXRNA_SetOutBalance(runtime->rnaHandle, -128);
      return;
    }

    (void)ADXRNA_SetOutBalance(runtime->rnaHandle, static_cast<std::int32_t>(runtime->OutputBalanceLevel()));
  }

  /**
   * Address: 0x00B0DB10 (FUN_00B0DB10, _ADXT_SetOutBalance)
   *
   * What it does:
   * Stores ADXT output-balance lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetOutBalance(void* const adxtRuntime, const std::int32_t balanceLevel)
  {
    ADXCRS_Enter();
    adxt_SetOutBalance(adxtRuntime, balanceLevel);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0CEB0 (FUN_00B0CEB0, _adxt_detach_m2a)
   *
   * What it does:
   * Dispatches optional ADXT MPEG-2 AAC detach callback lane with one runtime handle.
   */
  [[nodiscard]] std::int32_t ADXT_InvokeM2aDetachCallbackIfPresent(void* const adxtRuntime)
  {
    if (m2adetachfunc != nullptr) {
      return m2adetachfunc(adxtRuntime);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(m2adetachfunc));
  }

  /**
   * Address: 0x00B194B0 (FUN_00B194B0, sub_B194B0)
   * Also emitted at: 0x00B0CEC0 (FUN_00B0CEC0, sub_B0CEC0)
   *
   * What it does:
   * Dispatches optional ADXT destroy callback lane with one runtime handle.
   */
  [[nodiscard]] std::int32_t ADXT_InvokeDestroyCallbackIfPresent(void* const adxtRuntime)
  {
    if (gAdxtDestroyCallback != nullptr) {
      gAdxtDestroyCallback(adxtRuntime);
      return 0;
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(gAdxtDestroyCallback));
  }

  void ADXT_ReleaseLaneHandle(AdxtDestroyableHandle*& laneHandle)
  {
    if (laneHandle == nullptr) {
      return;
    }

    auto* const handle = laneHandle;
    laneHandle = nullptr;
    handle->Destroy();
  }

  /**
   * Address: 0x00B0CEF0 (_adxt_Destroy)
   *
   * What it does:
   * Tears down one ADXT runtime object by detaching optional middleware
   * sub-lanes, destroying owned handles, clearing the runtime block, and
   * reporting null-parameter usage through ADXERR callback lane.
   */
  void adxt_Destroy(AdxtRuntimeState* const runtime)
  {
    if (runtime == nullptr) {
      ADXERR_CallErrFunc1_(kAdxtDestroyParameterErrorMessage);
      return;
    }

    adxt_detach_ahx();
    adxt_detach_mpa(runtime);
    (void)ADXT_InvokeM2aDetachCallbackIfPresent(runtime);
    (void)ADXT_InvokeDestroyCallbackIfPresent(runtime);

    if (runtime->used == 1u) {
      adxt_Stop(runtime);
    }

    if (runtime->rnaHandle != 0) {
      const auto rnaHandle = runtime->rnaHandle;
      runtime->rnaHandle = 0;
      ADXRNA_Destroy(rnaHandle);
    }

    if (runtime->sjdHandle != 0) {
      const auto sjdHandle = runtime->sjdHandle;
      runtime->sjdHandle = 0;
      ADXSJD_Destroy(sjdHandle);
    }

    if (runtime->streamHandle != nullptr) {
      auto* const streamHandle = runtime->streamHandle;
      runtime->streamHandle = nullptr;
      ADXSTM_EntryEosFunc(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(streamHandle)),
        0,
        0
      );
      ADXSTM_Destroy(streamHandle);
    }

    if (runtime->linkControlHandle != nullptr) {
      auto* const linkControlHandle = runtime->linkControlHandle;
      runtime->linkControlHandle = nullptr;
      LSC_Destroy(linkControlHandle);
    }

    ADXCRS_Lock();

    ADXT_ReleaseLaneHandle(runtime->sourceRingHandle);

    const auto channelCount = static_cast<std::int32_t>(runtime->maxChannelCount);
    for (std::int32_t lane = 0; lane < channelCount; ++lane) {
      ADXT_ReleaseLaneHandle(runtime->SourceChannelRingLane(lane));
      ADXT_ReleaseLaneHandle(runtime->AuxReleaseLaneA(lane));
      ADXT_ReleaseLaneHandle(runtime->AuxReleaseLaneB(lane));
    }

    if (runtime->channelExpandHandle != nullptr) {
      auto* const channelExpandHandle = runtime->channelExpandHandle;
      runtime->channelExpandHandle = nullptr;
      ADXAMP_Destroy(channelExpandHandle);
    }

    std::memset(runtime, 0, sizeof(AdxtRuntimeState));
    runtime->used = 0;

    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0CED0 (FUN_00B0CED0, _ADXT_Destroy)
   *
   * What it does:
   * Runs one ADXT runtime teardown lane under ADXCRS enter/leave guards.
   */
  void ADXT_Destroy(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_Destroy(static_cast<AdxtRuntimeState*>(adxtRuntime));
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D040 (FUN_00B0D040, _adxt_DestroyAll)
   *
   * What it does:
   * Tears down every active ADXT runtime slot in the global runtime pool.
   */
  void adxt_DestroyAll()
  {
    for (auto& runtimeSlot : gAdxtRuntimePool) {
      if (runtimeSlot.used != 0u) {
        adxt_Destroy(&runtimeSlot);
      }
    }
  }

  /**
   * Address: 0x00B0D030 (FUN_00B0D030, _ADXT_DestroyAll)
   *
   * What it does:
   * Runs full ADXT runtime-pool teardown under ADXCRS enter/leave guards.
   */
  void ADXT_DestroyAll()
  {
    ADXCRS_Enter();
    adxt_DestroyAll();
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D080 (FUN_00B0D080, _adxt_CloseAllHandles)
   *
   * What it does:
   * Closes all ADXT runtime handles by forwarding to full runtime-pool teardown.
   */
  void adxt_CloseAllHandles()
  {
    adxt_DestroyAll();
  }

  /**
   * Address: 0x00B0D070 (FUN_00B0D070, _ADXT_CloseAllHandles)
   *
   * What it does:
   * Closes all ADXT runtime handles under ADXCRS enter/leave guards.
   */
  void ADXT_CloseAllHandles()
  {
    ADXCRS_Enter();
    adxt_CloseAllHandles();
    ADXCRS_Leave();
  }

  std::int32_t ADXT_ReportMessage(const char* message);
  std::int32_t ADXT_ResetHistoryState(AdxtDolbyRuntimeState* state);

  /**
   * Address: 0x00B21F50 (sub_B21F50)
   *
   * What it does:
   * Initializes one Dolby runtime work-state object inside caller-provided work
   * memory with alignment and bounds checks.
   */
  AdxtDolbyRuntimeState* ADXT_AttachDolbyState(AdxtDolbyRuntimeState* workMemory, const std::int32_t workBytes)
  {
    if (workMemory == nullptr) {
      ADXT_ReportMessage(kAdxtNullWorkPointerMessage);
      return nullptr;
    }

    if (workBytes < 0x400) {
      ADXT_ReportMessage(kAdxtShortWorkBufferMessage);
      return nullptr;
    }

    auto* const alignedState =
      reinterpret_cast<AdxtDolbyRuntimeState*>(AlignPointerTo4Bytes(reinterpret_cast<std::uint8_t*>(workMemory)));
    std::memset(alignedState, 0, sizeof(AdxtDolbyRuntimeState));

    alignedState->workBufferBase = workMemory;
    alignedState->workBufferBytes = workBytes;

    auto* historyBase = AlignPointerTo4Bytes(reinterpret_cast<std::uint8_t*>(alignedState) + sizeof(AdxtDolbyRuntimeState));
    alignedState->historyLaneA = reinterpret_cast<std::int32_t*>(historyBase);
    alignedState->historyLaneB = alignedState->historyLaneA + 96;

    ADXT_ResetHistoryState(alignedState);

    auto* const workEnd = reinterpret_cast<std::uint8_t*>(workMemory) + workBytes;
    if (reinterpret_cast<std::uint8_t*>(alignedState->historyLaneA + 192) > workEnd) {
      ADXT_ReportMessage(kAdxtShortAlignedWorkBufferMessage);
      return nullptr;
    }

    return alignedState;
  }

  /**
   * Address: 0x00B21F20 (sub_B21F20)
   *
   * What it does:
   * Lock-guarded wrapper for Dolby work-state attachment/initialization.
   */
  AdxtDolbyRuntimeState* ADXT_AttachDolbyStateLocked(AdxtDolbyRuntimeState* workMemory, const std::int32_t workBytes)
  {
    sofdec_EnterLock_7();
    auto* const result = ADXT_AttachDolbyState(workMemory, workBytes);
    sofdec_LeaveLock_7();
    return result;
  }

  /**
   * Address: 0x00B22000 (sub_B22000)
   *
   * What it does:
   * Dispatches one report message through registered callback lanes.
   */
  std::int32_t ADXT_ReportMessage(const char* message)
  {
    if (gSofdecReportCallback != nullptr) {
      return gSofdecReportCallback(gSofdecReportCallbackContext, message);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(gSofdecReportCallback));
  }

  /**
   * Address: 0x00B22040 (sub_B22040)
   *
   * What it does:
   * Clears one Dolby work-state control block.
   */
  std::int32_t ADXT_ClearControlState(AdxtDolbyRuntimeState* state)
  {
    std::memset(state, 0, sizeof(AdxtDolbyRuntimeState));
    return 0;
  }

  /**
   * Address: 0x00B22020 (sub_B22020)
   *
   * What it does:
   * Lock-guarded wrapper for clearing one Dolby control state block.
   */
  void ADXT_ClearControlStateLocked(AdxtDolbyRuntimeState* state)
  {
    sofdec_EnterLock_7();
    ADXT_ClearControlState(state);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B22070 (sub_B22070)
   *
   * What it does:
   * Resets fixed history lanes and ring-buffer cursor for Dolby runtime state.
   */
  std::int32_t ADXT_ResetHistoryState(AdxtDolbyRuntimeState* state)
  {
    for (std::int32_t lane = 0; lane < 96; ++lane) {
      state->historyLaneA[lane] = 0;
      state->historyLaneB[lane] = 0;
    }
    state->historyWriteIndex = 0;
    state->historyWindowLength = 64;
    return 0x180;
  }

  /**
   * Address: 0x00B22050 (sub_B22050)
   *
   * What it does:
   * Lock-guarded wrapper for history-lane reset.
   */
  void ADXT_ResetHistoryStateLocked(AdxtDolbyRuntimeState* state)
  {
    sofdec_EnterLock_7();
    ADXT_ResetHistoryState(state);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B220E0 (sub_B220E0)
   *
   * What it does:
   * Processes one Dolby matrix sample through Q12 coefficient lanes and updates
   * circular history buffers.
   */
  AdxtDolbyRuntimeState* ADXT_ProcessSample(
    AdxtDolbyRuntimeState* state,
    const std::int16_t inputSample,
    std::int16_t* const outSampleA,
    std::int16_t* const outSampleB
  )
  {
    const auto sample = static_cast<std::int32_t>(inputSample);
    const auto coeffA = adxt_q12_mix_table[state->mixTableIndexA];
    const auto coeffB = adxt_q12_mix_table[state->mixTableIndexB];
    const auto coeffC = adxt_q12_mix_table[state->mixTableIndexC];
    const auto coeffD = adxt_q12_mix_table[state->mixTableIndexD];

    const auto laneA = (sample * coeffA) >> 12;
    const auto laneB = (sample * coeffB) >> 12;

    const auto feedbackCD = (laneB * coeffD) >> 12;
    const auto feedbackAC = (laneA * coeffD) >> 12;

    const auto feedbackLeft = state->historyLaneA[state->historyWriteIndex] + ((laneA * coeffC) >> 12);
    const auto feedbackRight = state->historyLaneB[state->historyWriteIndex] + ((laneB * coeffC) >> 12);

    auto clampA = feedbackLeft;
    if (clampA > 0x7FFF) {
      clampA = 0x7FFF;
    } else if (clampA < -32768) {
      clampA = -32768;
    }

    auto clampB = feedbackRight;
    if (clampB > 0x7FFF) {
      clampB = 0x7FFF;
    } else if (clampB < -32768) {
      clampB = -32768;
    }

    *outSampleA = static_cast<std::int16_t>(clampA);
    *outSampleB = static_cast<std::int16_t>(clampB);

    state->historyLaneA[state->historyWriteIndex] = (-2006 * feedbackCD - 3567 * feedbackAC) >> 12;
    state->historyLaneB[state->historyWriteIndex] = (3567 * feedbackCD + 2006 * feedbackAC) >> 12;

    ++state->historyWriteIndex;
    if (state->historyWriteIndex >= state->historyWindowLength) {
      state->historyWriteIndex = 0;
    }

    return state;
  }

  /**
   * Address: 0x00B220B0 (sub_B220B0)
   *
   * What it does:
   * Lock-guarded wrapper for single-sample Dolby matrix processing.
   */
  void ADXT_ProcessSampleLocked(
    AdxtDolbyRuntimeState* state,
    const std::int16_t inputSample,
    std::int16_t* outSampleA,
    std::int16_t* outSampleB
  )
  {
    sofdec_EnterLock_7();
    ADXT_ProcessSample(state, inputSample, outSampleA, outSampleB);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B22250 (sub_B22250)
   *
   * What it does:
   * Processes one 32-sample block through Dolby matrix lanes and updates the
   * first history window segment.
   */
  std::int32_t ADXT_ProcessSampleBlock(
    AdxtDolbyRuntimeState* state,
    const std::int16_t* inputSamples,
    std::int16_t* outputSamplesA,
    std::int16_t* outputSamplesB
  )
  {
    std::int32_t lastResult = 0;
    for (std::int32_t lane = 0; lane < 32; ++lane) {
      const auto sample = static_cast<std::int32_t>(inputSamples[lane]);
      const auto coeffA = adxt_q12_mix_table[state->mixTableIndexA];
      const auto coeffB = adxt_q12_mix_table[state->mixTableIndexB];
      const auto coeffC = adxt_q12_mix_table[state->mixTableIndexC];
      const auto coeffD = adxt_q12_mix_table[state->mixTableIndexD];

      auto laneA = (sample * coeffA) >> 12;
      auto laneB = (sample * coeffB) >> 12;

      const auto feedbackCD = (laneB * coeffD) >> 12;
      const auto feedbackAC = (laneA * coeffD) >> 12;

      const auto mixA = state->historyLaneA[lane] + ((laneA * coeffC) >> 12);
      const auto mixB = state->historyLaneB[lane] + ((laneB * coeffC) >> 12);

      auto clampA = mixA;
      if (clampA > 0x7FFF) {
        clampA = 0x7FFF;
      } else if (clampA < -32768) {
        clampA = -32768;
      }

      auto clampB = mixB;
      if (clampB > 0x7FFF) {
        clampB = 0x7FFF;
      } else if (clampB < -32768) {
        clampB = -32768;
      }

      outputSamplesA[lane] = static_cast<std::int16_t>(clampA);
      outputSamplesB[lane] = static_cast<std::int16_t>(clampB);

      state->historyLaneA[lane] = (-2006 * feedbackCD - 3567 * feedbackAC) >> 12;
      lastResult = 1003 * feedbackAC;
      state->historyLaneB[lane] = (3567 * feedbackCD + (2 * lastResult)) >> 12;
    }

    return lastResult;
  }

  /**
   * Address: 0x00B22220 (sub_B22220)
   *
   * What it does:
   * Lock-guarded wrapper for 32-sample Dolby block processing.
   */
  void ADXT_ProcessSampleBlockLocked(
    AdxtDolbyRuntimeState* state,
    const std::int16_t* inputSamples,
    std::int16_t* outputSamplesA,
    std::int16_t* outputSamplesB
  )
  {
    sofdec_EnterLock_7();
    ADXT_ProcessSampleBlock(state, inputSamples, outputSamplesA, outputSamplesB);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B223D0 (sub_B223D0)
   *
   * What it does:
   * Updates Dolby matrix lookup-table index lanes from signed user parameters.
   */
  std::int32_t ADXT_SetMixTableIndices(
    AdxtDolbyRuntimeState* state,
    const std::int32_t matrixParamA,
    const std::int32_t matrixParamB
  )
  {
    if (state == nullptr) {
      return ADXT_ReportMessage(kAdxtNullMatrixStateMessage);
    }

    if (
      matrixParamA < -127
      || matrixParamA > 127
      || matrixParamB < -127
      || matrixParamB > 127
    ) {
      return ADXT_ReportMessage(kAdxtIllegalMatrixParameterMessage);
    }

    const auto indexA = matrixParamA + 127;
    state->mixTableIndexA = indexA >= 0 ? indexA : (-127 - matrixParamA);

    const auto indexB = matrixParamA - 127;
    state->mixTableIndexB = indexB >= 0 ? indexB : (127 - matrixParamA);

    const auto indexC = matrixParamB + 127;
    state->mixTableIndexC = indexC >= 0 ? indexC : (-127 - matrixParamB);

    const auto indexD = matrixParamB - 127;
    state->mixTableIndexD = indexD >= 0 ? indexD : (127 - matrixParamB);
    return state->mixTableIndexD;
  }

  /**
   * Address: 0x00B223A0 (sub_B223A0)
   *
   * What it does:
   * Lock-guarded wrapper for Dolby mix-table index updates.
   */
  void ADXT_SetMixTableIndicesLocked(
    AdxtDolbyRuntimeState* state,
    const std::int32_t matrixParamA,
    const std::int32_t matrixParamB
  )
  {
    sofdec_EnterLock_7();
    ADXT_SetMixTableIndices(state, matrixParamA, matrixParamB);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B22480 (sub_B22480)
   *
   * What it does:
   * Sets Dolby sample-rate lane and derives clamped history window length.
   */
  std::uint32_t ADXT_SetSampleRate(AdxtDolbyRuntimeState* state, const std::int32_t sampleRate)
  {
    if (state == nullptr) {
      return static_cast<std::uint32_t>(ADXT_ReportMessage(kAdxtNullRateStateMessage));
    }

    if (sampleRate <= 0) {
      return static_cast<std::uint32_t>(ADXT_ReportMessage(kAdxtIllegalRateParameterMessage));
    }

    const auto scaledRate = static_cast<std::int32_t>(sampleRate << 6);
    const auto highProductWord = static_cast<std::int32_t>(
      (0x57619F1LL * static_cast<long long>(scaledRate)) >> 32
    );
    auto normalizedWindow = highProductWord >> 10;
    const auto signAdjust = static_cast<std::uint32_t>(normalizedWindow) >> 31;
    normalizedWindow += static_cast<std::int32_t>(signAdjust);

    if (normalizedWindow > 96) {
      normalizedWindow = 96;
    } else if (normalizedWindow < 1) {
      normalizedWindow = 1;
    }

    state->sampleRate = sampleRate;
    state->historyWindowLength = normalizedWindow;
    return signAdjust;
  }

  /**
   * Address: 0x00B22460 (sub_B22460)
   *
   * What it does:
   * Lock-guarded wrapper for Dolby sample-rate configuration.
   */
  void ADXT_SetSampleRateLocked(AdxtDolbyRuntimeState* state, const std::int32_t sampleRate)
  {
    sofdec_EnterLock_7();
    ADXT_SetSampleRate(state, sampleRate);
    sofdec_LeaveLock_7();
  }

  [[nodiscard]] static AdxtDolbyRuntimeState* ADXB_GetDolbyState(moho::AdxBitstreamDecoderState* const decoder)
  {
    const auto* const decoderView = AsAdxbRuntimeView(decoder);
    return reinterpret_cast<AdxtDolbyRuntimeState*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(decoderView->channelExpandHandle))
    );
  }

  /**
   * Address: 0x00B194C0 (FUN_00B194C0, sub_B194C0)
   *
   * What it does:
   * Applies Dolby matrix parameters to one ADXT-owned ADXB decode lane and
   * latches the caller-provided matrix parameters in decoder runtime state.
   */
  [[maybe_unused]] void ADXT_UpdateDolbyMatrixFromRuntime(
    void* const adxtRuntime,
    const std::int32_t matrixParamA,
    const std::int32_t matrixParamB
  )
  {
    if (adxtRuntime == nullptr) {
      ADXERR_CallErrFunc1_(kAdxtDolbySetParamsNullRuntimeMessage);
      return;
    }

    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    auto* const decoder = AsAdxsjdRuntimeView(runtime->sjdHandle)->Decoder();
    auto* const decoderView = AsAdxbRuntimeView(decoder);
    auto* const dolbyState = ADXB_GetDolbyState(decoder);
    if (runtime->maxChannelCount >= 2 && dolbyState != nullptr) {
      ADXT_SetMixTableIndicesLocked(dolbyState, matrixParamA, matrixParamB);
      decoderView->expandMatrixParamA = matrixParamA;
      decoderView->expandMatrixParamB = matrixParamB;
      return;
    }

    ADXERR_CallErrFunc1_(kAdxtDolbySetParamsInvalidRuntimeMessage);
  }

  /**
   * Address: 0x00B19530 (FUN_00B19530, sub_B19530)
   *
   * What it does:
   * Detaches one ADXT Dolby runtime state from decoder post-process lane,
   * clears control state, and decrements global Dolby attach refcount.
   */
  [[maybe_unused]] void ADXT_DetachDolbyState(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    auto* const decoder = AsAdxsjdRuntimeView(runtime->sjdHandle)->Decoder();
    auto* const decoderView = AsAdxbRuntimeView(decoder);
    auto* const dolbyState = ADXB_GetDolbyState(decoder);
    if (dolbyState == nullptr) {
      return;
    }

    ADXT_Stop(adxtRuntime);
    sofdec_EnterLock_7();
    ADXT_ClearControlStateLocked(dolbyState);
    decoderView->channelExpandHandle = 0;
    ADXT_DecrementAttachRefLocked(0);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B19580 (FUN_00B19580, sub_B19580)
   *
   * What it does:
   * Resets Dolby matrix-history lanes for one ADXB post-process runtime.
   */
  [[maybe_unused]] void ADXB_ResetDolbyHistoryOnStop(moho::AdxBitstreamDecoderState* const decoder)
  {
    ADXT_ResetHistoryStateLocked(ADXB_GetDolbyState(decoder));
  }

  /**
   * Address: 0x00B195A0 (FUN_00B195A0, sub_B195A0)
   *
   * What it does:
   * Runs one ADXB Dolby matrix sample callback step using current decoder
   * post-process runtime state.
   */
  [[maybe_unused]] void ADXB_ProcessDolbySamplePair(
    moho::AdxBitstreamDecoderState* const decoder,
    const std::int32_t sampleValue,
    const std::int16_t* const sampleOutA,
    const std::int16_t* const sampleOutB
  )
  {
    ADXT_ProcessSampleLocked(
      ADXB_GetDolbyState(decoder),
      static_cast<std::int16_t>(sampleValue),
      const_cast<std::int16_t*>(sampleOutA),
      const_cast<std::int16_t*>(sampleOutB)
    );
  }

  /**
   * Address: 0x00B195C0 (FUN_00B195C0, sub_B195C0)
   *
   * What it does:
   * Updates Dolby matrix coefficient-table indices for one ADXB decoder lane.
   */
  [[maybe_unused]] void ADXB_SetDolbyMatrixParams(
    moho::AdxBitstreamDecoderState* const decoder,
    const std::int32_t matrixParamA,
    const std::int32_t matrixParamB
  )
  {
    ADXT_SetMixTableIndicesLocked(ADXB_GetDolbyState(decoder), matrixParamA, matrixParamB);
  }

  /**
   * Address: 0x00B195E0 (FUN_00B195E0, sub_B195E0)
   *
   * What it does:
   * Updates Dolby sample-rate derived history-window state for one ADXB
   * decoder post-process runtime lane.
   */
  [[maybe_unused]] void ADXB_UpdateDolbySampleRate(
    moho::AdxBitstreamDecoderState* const decoder,
    const std::int32_t sampleRate
  )
  {
    ADXT_SetSampleRateLocked(ADXB_GetDolbyState(decoder), sampleRate);
  }

  /**
   * Address: 0x00B19600 (FUN_00B19600, sub_B19600)
   *
   * What it does:
   * Bridges ADXT report callback messages into shared ADXERR sink.
   */
  [[maybe_unused]] std::int32_t ADXT_ReportMessageToAdxerr(
    [[maybe_unused]] const std::int32_t callbackContext,
    const char* const message
  )
  {
    return ADXERR_CallErrFunc1_(message);
  }

