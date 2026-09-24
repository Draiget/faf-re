
  /**
   * Address: 0x00B20AF0 (func_SofDecGetTime)
   *
   * What it does:
   * Returns monotonic performance-counter time in microseconds.
   */
  std::int32_t SofDecGetTimeMicroseconds()
  {
    LARGE_INTEGER frequency{};
    if (QueryPerformanceFrequency(&frequency) == 0) {
      return 0;
    }

    LARGE_INTEGER performanceCount{};
    QueryPerformanceCounter(&performanceCount);

    const double micros = static_cast<double>(performanceCount.QuadPart) / (static_cast<double>(frequency.QuadPart) * 0.000001);
    return static_cast<std::int32_t>(micros);
  }

  /**
   * Address: 0x00B20B30 (ADXB_SetDecErrMode)
   *
   * What it does:
   * Sets process-global ADXB decode-error mode lane.
   */
  std::int32_t ADXB_SetDecErrMode(const std::int32_t decodeErrorMode)
  {
    adxb_dec_err_mode = decodeErrorMode;
    return decodeErrorMode;
  }

  /**
   * Address: 0x00B20B40 (ADXB_GetDecErrMode)
   *
   * What it does:
   * Returns process-global ADXB decode-error mode lane.
   */
  std::int32_t ADXB_GetDecErrMode()
  {
    return adxb_dec_err_mode;
  }

  /**
   * Address: 0x00B20B50 (ADXB_Init)
   *
   * What it does:
   * Initializes ADXB runtime globals and clears decoder object pool.
   */
  std::int32_t ADXB_Init()
  {
    ADXPD_Init();
    SKG_Init();
    std::memset(adxb_obj, 0, sizeof(adxb_obj));
    return ADXB_SetDecErrMode(0);
  }

  /**
   * Address: 0x00B20B80 (ADXB_Finish)
   *
   * What it does:
   * Shuts down ADXB runtime globals and clears decoder object pool.
   */
  std::int32_t ADXB_Finish()
  {
    ADXPD_Finish();
    SKG_Finish();
    std::memset(adxb_obj, 0, sizeof(adxb_obj));
    return 0;
  }

  /**
   * Address: 0x00B20BA0 (adxb_DefGetWr)
   *
   * What it does:
   * Default get-write callback: decoding appends to the decoder's own PCM
   * ring, so the window starts at the buffered sample count, is bounded by the
   * room left in the ring, and the trap is the end of the stream.
   */
  std::int16_t* adxb_DefGetWr(
    void* const context,
    std::int32_t* const outWriteSampleIndex,
    std::int32_t* const outWritableSamples,
    std::int32_t* const outSamplesUntilTrap
  )
  {
    const auto* const decoder = static_cast<const moho::AdxBitstreamDecoderState*>(context);
    *outWriteSampleIndex = decoder->bufferedSampleCount;
    *outWritableSamples = decoder->pcmBufferSamples - decoder->bufferedSampleCount;
    *outSamplesUntilTrap = decoder->totalSampleCount - decoder->decodedSampleTotal;
    return decoder->pcmBuffer;
  }

  /**
   * Address: 0x00B20BE0 (adxb_DefAddWr)
   *
   * What it does:
   * Default add-write callback: advances the buffered and decoded sample
   * counts by the samples of the committed span.
   */
  std::int32_t adxb_DefAddWr(void* const context, std::int32_t /*decodedBytes*/, const std::int32_t decodedSamples)
  {
    auto* const decoder = static_cast<moho::AdxBitstreamDecoderState*>(context);
    decoder->bufferedSampleCount += decodedSamples;
    decoder->decodedSampleTotal += decodedSamples;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(decoder));
  }

  /**
   * Address: 0x00B20C10 (adxb_ResetAinf)
   *
   * What it does:
   * Clears AINF metadata lanes and restores default pan values.
   */
  std::uint8_t* adxb_ResetAinf(moho::AdxBitstreamDecoderState* decoder)
  {
    decoder->ainfLength = 0;
    decoder->defaultOutputVolume = 0;
    decoder->defaultPanByChannel[0] = -128;
    decoder->defaultPanByChannel[1] = -128;
    std::memset(decoder->dataIdBytes, 0, sizeof(decoder->dataIdBytes));
    return decoder->dataIdBytes;
  }

  /**
   * Address: 0x00B20C50 (ADXB_Create)
   *
   * What it does:
   * Allocates one ADXB decoder object from fixed runtime pool and initializes core lanes.
   */
  moho::AdxBitstreamDecoderState* ADXB_Create(
    const std::int32_t maxChannels,
    std::int16_t* const pcmBuffer,
    const std::int32_t pcmBufferSamples,
    const std::int32_t pcmChannelStride
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < 32 && adxb_obj[slotIndex].slotState != 0) {
      ++slotIndex;
    }

    if (slotIndex == 32) {
      return nullptr;
    }

    auto* const decoder = &adxb_obj[slotIndex];
    std::memset(decoder, 0, sizeof(*decoder));
    decoder->slotState = 1;

    decoder->adxPacketDecoder = ADXPD_Create();
    if (decoder->adxPacketDecoder == nullptr) {
      ADXB_Destroy(decoder);
      return nullptr;
    }

    decoder->maxChannels = maxChannels;
    decoder->pcmBuffer = pcmBuffer;
    decoder->pcmBufferSamples = pcmBufferSamples;
    decoder->pcmChannelStride = pcmChannelStride;
    decoder->getWriteFunc = adxb_DefGetWr;
    decoder->getWriteContext = decoder;
    decoder->addWriteFunc = adxb_DefAddWr;
    decoder->addWriteContext = decoder;
    adxb_ResetAinf(decoder);
    return decoder;
  }

  /**
   * Address: 0x00B20CF0 (ADXB_Destroy)
   *
   * What it does:
   * Destroys ADXB decoder backend and clears one runtime slot.
   */
  std::int32_t ADXB_Destroy(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder == nullptr) {
      return 0;
    }

    moho::AdxPacketDecoder* const adxPacketDecoder = decoder->adxPacketDecoder;
    decoder->adxPacketDecoder = nullptr;
    ADXPD_Destroy(adxPacketDecoder);
    std::memset(decoder, 0, sizeof(*decoder));
    decoder->slotState = 0;
    return 0;
  }

  /**
   * Address: 0x00B20D20 (SKG_Init)
   *
   * What it does:
   * Increments global SKG init reference count.
   */
  std::int32_t SKG_Init()
  {
    ++skg_init_count;
    return 0;
  }

  /**
   * Address: 0x00B20D30 (SKG_Finish)
   *
   * What it does:
   * Decrements global SKG init reference count.
   */
  std::int32_t SKG_Finish()
  {
    --skg_init_count;
    return 0;
  }

  [[nodiscard]] static std::uint16_t ReadAdxBigEndianU16(const std::uint8_t* const sourceBytes) noexcept
  {
    return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(sourceBytes[0]) << 8) | static_cast<std::uint16_t>(sourceBytes[1])
    );
  }

  [[nodiscard]] static std::uint32_t ReadAdxBigEndianU32(const std::uint8_t* const sourceBytes) noexcept
  {
    return (static_cast<std::uint32_t>(sourceBytes[0]) << 24) | (static_cast<std::uint32_t>(sourceBytes[1]) << 16)
      | (static_cast<std::uint32_t>(sourceBytes[2]) << 8) | static_cast<std::uint32_t>(sourceBytes[3]);
  }

  [[nodiscard]] static AdxampRuntimeState* AsAdxampRuntimeState(void* const channelExpandHandle)
  {
    return reinterpret_cast<AdxampRuntimeState*>(channelExpandHandle);
  }

  [[nodiscard]] static const AdxampRuntimeState* AsAdxampRuntimeStateConst(const void* const channelExpandHandle)
  {
    return reinterpret_cast<const AdxampRuntimeState*>(channelExpandHandle);
  }

  static void AdxampClearLaneStream(M2asjdIoStream* const stream)
  {
    if (stream == nullptr) {
      return;
    }

    stream->Reset();
    SjChunkRange chunk{};
    stream->AcquireChunk(0, stream->QueryAvailableBytes(0), &chunk);
    if (chunk.byteCount > 0) {
      std::memset(SjAddressToPointer(chunk.bufferAddress), 0, static_cast<std::size_t>(chunk.byteCount));
    }
    stream->ReturnChunk(0, &chunk);
  }

