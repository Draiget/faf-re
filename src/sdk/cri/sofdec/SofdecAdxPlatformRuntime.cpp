
  /**
   * Address: 0x00B15FB0 (FUN_00B15FB0, func_SofDec_DefaultWaveFormat)
   *
   * What it does:
   * Writes one default 44.1kHz/16-bit PCM wave-format block.
   */
  moho::SofdecPcmWaveFormat* SofdecBuildDefaultPcmWaveFormat(
    const std::uint16_t channels,
    moho::SofdecPcmWaveFormat* const outWaveFormat
  )
  {
    std::memset(outWaveFormat, 0, sizeof(*outWaveFormat));
    outWaveFormat->channelCount = channels;
    outWaveFormat->blockAlignBytes = static_cast<std::uint16_t>(2u * channels);
    outWaveFormat->formatTag = 1;
    outWaveFormat->samplesPerSecond = 44100;
    outWaveFormat->bitsPerSample = 16;
    outWaveFormat->extraBytes = 0;
    outWaveFormat->averageBytesPerSecond =
      outWaveFormat->samplesPerSecond * static_cast<std::uint32_t>(outWaveFormat->blockAlignBytes);
    return outWaveFormat;
  }

  /**
   * Address: 0x00B164E0 (FUN_00B164E0, func_DirectSoundBuffer_Restore)
   *
   * What it does:
   * Returns success for no-error or `DSERR_BUFFERLOST` after calling `Restore`.
   */
  std::int32_t SofdecRestoreBufferIfLost(IDirectSoundBuffer* const soundBuffer, const std::int32_t operationResult)
  {
    if (operationResult == 0) {
      return 1;
    }
    if (operationResult != static_cast<std::int32_t>(DSERR_BUFFERLOST)) {
      return 0;
    }
    soundBuffer->lpVtbl->Restore(soundBuffer);
    return 1;
  }

  /**
   * Address: 0x00B16010 (FUN_00B16010, sub_B16010)
   *
   * What it does:
   * Starts one DirectSound buffer and polls status until playback bit sets
   * or timeout/error path triggers.
   */
  std::int32_t SofdecStartBufferAndWaitForPlaying(IDirectSoundBuffer* const soundBuffer)
  {
    const std::int32_t playResult = soundBuffer->lpVtbl->Play(soundBuffer, 0, 0, DSBPLAY_LOOPING);
    if (playResult != 0 && SofdecRestoreBufferIfLost(soundBuffer, playResult) == 0) {
      return ADXERR_CallErrFunc1_(kSofdecErrPlayFailed);
    }

    SofdecPollBufferPlaybackState(soundBuffer, true);

    DWORD status = 0;
    return static_cast<std::int32_t>(soundBuffer->lpVtbl->GetStatus(soundBuffer, &status));
  }

  /**
   * Address: 0x00B160F0 (FUN_00B160F0, _mwSndStop)
   *
   * What it does:
   * Stops one DirectSound buffer and polls until playback bit clears.
   */
  void SofdecStopBufferAndWaitForIdle(IDirectSoundBuffer* const soundBuffer)
  {
    if (soundBuffer->lpVtbl->Stop(soundBuffer) != DS_OK) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrStopFailed);
      return;
    }

    SofdecPollBufferPlaybackState(soundBuffer, false);
  }

  /**
   * Address: 0x00B161C0 (FUN_00B161C0, func_SofDec_RestoreSoundBuffer)
   *
   * What it does:
   * Creates and zero-fills the global restore-probe DirectSound buffer.
   */
  std::int32_t SofdecCreateRestoreProbeBuffer()
  {
    moho::SofdecPcmWaveFormat waveFormat{};
    SofdecBuildDefaultPcmWaveFormat(1u, &waveFormat);

    DSBUFFERDESC bufferDesc{};
    bufferDesc.dwSize = sizeof(bufferDesc);
    bufferDesc.dwFlags = 0x8u;
    bufferDesc.dwBufferBytes = waveFormat.averageBytesPerSecond / 10u;
    bufferDesc.lpwfxFormat = reinterpret_cast<WAVEFORMATEX*>(&waveFormat);

    if (gSofdecDirectSound->lpVtbl->CreateSoundBuffer(gSofdecDirectSound, &bufferDesc, &gSofdecRestoreProbeBuffer, nullptr)
        < 0) {
      return 0;
    }

    void* lockBase = nullptr;
    DWORD lockBytes = 0;
    const std::int32_t lockResult = gSofdecRestoreProbeBuffer->lpVtbl->Lock(
      gSofdecRestoreProbeBuffer, 0, 0, &lockBase, &lockBytes, nullptr, nullptr, DSBLOCK_ENTIREBUFFER
    );

    if (lockResult < 0 && SofdecRestoreBufferIfLost(gSofdecRestoreProbeBuffer, lockResult) == 0) {
      return 0;
    }

    if (lockBase != nullptr && lockBytes != 0) {
      std::memset(lockBase, 0, lockBytes);
    }

    gSofdecRestoreProbeBuffer->lpVtbl->Unlock(gSofdecRestoreProbeBuffer, lockBase, lockBytes, nullptr, 0);
    return 1;
  }

  /**
   * Address: 0x00B162B0 (FUN_00B162B0, func_SofDec_Stop)
   *
   * What it does:
   * Stops/releases the global restore-probe DirectSound buffer.
   */
  void SofdecShutdownRestoreProbeBuffer()
  {
    if (gSofdecRestoreProbeBuffer == nullptr) {
      return;
    }

    SofdecStopBufferAndWaitForIdle(gSofdecRestoreProbeBuffer);
    gSofdecRestoreProbeBuffer->lpVtbl->Release(gSofdecRestoreProbeBuffer);
    gSofdecRestoreProbeBuffer = nullptr;
  }

  /**
   * Address: 0x00B164A0 (FUN_00B164A0, sub_B164A0)
   *
   * What it does:
   * Mirrors current play cursor from primary to secondary port buffer.
   */
  std::int32_t SofdecMirrorPrimaryCursorToSecondaryBuffer(moho::SofdecSoundPort* const soundPort)
  {
    const std::int32_t defaultResult = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort->primaryBuffer));
    if (soundPort->primaryBuffer == nullptr || soundPort->secondaryBuffer == nullptr) {
      return defaultResult;
    }

    DWORD playCursor = 0;
    DWORD writeCursor = 0;
    soundPort->primaryBuffer->lpVtbl->GetCurrentPosition(soundPort->primaryBuffer, &playCursor, &writeCursor);
    return static_cast<std::int32_t>(soundPort->secondaryBuffer->lpVtbl->SetCurrentPosition(soundPort->secondaryBuffer, playCursor));
  }

  /**
   * Address: 0x00B16510 (FUN_00B16510, SofDecVirt::Init)
   *
   * What it does:
   * Captures DirectSound runtime lane and clears sound-port slot activity.
   */
  IDirectSoundBuffer** SofdecInitSoundPortRuntime(IDirectSound* const directSound)
  {
    IDirectSound8* directSound8 = nullptr;
    if (directSound->lpVtbl->QueryInterface(directSound, IID_IDirectSound8, reinterpret_cast<void**>(&directSound8)) >= 0
        && directSound8 != nullptr) {
      gSofdecDirectSoundVersionTag = kSofdecLegacyDx8CapabilityTag;
      directSound8->lpVtbl->Release(directSound8);
    } else {
      gSofdecDirectSoundVersionTag = kSofdecLegacyDx7CapabilityTag;
    }

    gSofdecDirectSound = directSound;
    for (auto& soundPort : gSofdecSoundPortPool) {
      soundPort.used = 0;
      soundPort.primaryBuffer = nullptr;
    }
    gSofdecOpenPortCount = 0;

    return reinterpret_cast<IDirectSoundBuffer**>(
      reinterpret_cast<std::uint8_t*>(gSofdecSoundPortPool) + sizeof(gSofdecSoundPortPool) + offsetof(moho::SofdecSoundPort, primaryBuffer)
    );
  }

  /**
   * Address: 0x00B16580 (FUN_00B16580, SofDecVirt::Func2)
   *
   * What it does:
   * Stops sound-port runtime and clears global mode/slot lanes.
   */
  std::uint32_t* SofdecShutdownSoundPortRuntime()
  {
    SofdecShutdownRestoreProbeBuffer();
    gSofdecOpenPortCount = 0;
    gSofdecFrequencyMode = 0;
    gSofdecGlobalFocusMode = 0;
    gSofdecBufferPlacementMode = 0;
    gSofdecDirectSound = nullptr;

    for (auto& soundPort : gSofdecSoundPortPool) {
      soundPort.used = 0;
      soundPort.primaryBuffer = nullptr;
    }

    gSofdecMonoRoutingMode = 0;
    gSofdecPortBufferBytesPerChannel = 0x10000u;

    return reinterpret_cast<std::uint32_t*>(
      reinterpret_cast<std::uint8_t*>(gSofdecSoundPortPool) + sizeof(gSofdecSoundPortPool) + offsetof(moho::SofdecSoundPort, primaryBuffer)
    );
  }

  /**
   * Address: 0x00B165E0 (FUN_00B165E0, func_SofDec_NextUnk3)
   *
   * What it does:
   * Finds first free sound-port slot in the fixed 32-entry pool.
   */
  moho::SofdecSoundPort* SofdecAcquireFreeSoundPort()
  {
    for (auto& soundPort : gSofdecSoundPortPool) {
      if (soundPort.used == 0) {
        return &soundPort;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B16610 (FUN_00B16610, sub_B16610)
   *
   * What it does:
   * Resets one sound-port slot to zeroed state.
   */
  std::int32_t SofdecResetSoundPort(moho::SofdecSoundPort* const soundPort)
  {
    std::memset(soundPort, 0, sizeof(*soundPort));
    soundPort->used = 0;
    return 0;
  }

  /**
   * Address: 0x00B16630 (FUN_00B16630, func_SofDec_CreateSoundBuffer)
   *
   * What it does:
   * Creates one DirectSound playback buffer using current Sofdec mode flags.
   */
  IDirectSoundBuffer* SofdecCreatePlaybackBuffer(const std::int32_t channels, const std::uint32_t bufferBytes)
  {
    if (gSofdecDirectSound == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrDirectSoundMissing);
      return nullptr;
    }

    DSBUFFERDESC bufferDesc{};
    moho::SofdecPcmWaveFormat waveFormat{};
    SofdecBuildDefaultPcmWaveFormat(static_cast<std::uint16_t>(channels), &waveFormat);
    bufferDesc.lpwfxFormat = reinterpret_cast<WAVEFORMATEX*>(&waveFormat);
    bufferDesc.dwBufferBytes = bufferBytes;
    bufferDesc.dwSize = sizeof(bufferDesc);

    DWORD flags = kSofdecPrimaryBufferFlagsLegacy;
    if (gSofdecBufferPlacementMode == 1) {
      if (gSofdecDirectSoundVersionTag >= kSofdecLegacyDx8CapabilityTag) {
        flags = kSofdecPrimaryBufferFlagsDx8;
      }
    } else {
      flags = kSofdecPrimaryBufferFlagsAlt;
    }

    if (gSofdecGlobalFocusMode == 1) {
      flags |= 0x8000u;
    }

    if (gSofdecMonoRoutingMode == 1 && channels == 1) {
      flags |= 0x10u;
    } else {
      flags |= 0x40u;
    }

    switch (gSofdecFrequencyMode) {
    case 1:
      flags |= 0x4u;
      break;
    case 2:
      break;
    case 3:
      flags |= 0x40000u;
      break;
    default:
      flags |= 0x8u;
      break;
    }

    bufferDesc.dwFlags = flags;

    IDirectSoundBuffer* soundBuffer = nullptr;
    const std::int32_t createResult =
      gSofdecDirectSound->lpVtbl->CreateSoundBuffer(gSofdecDirectSound, &bufferDesc, &soundBuffer, nullptr);
    if (createResult < 0 || soundBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrCreateBuffer);
      return nullptr;
    }

    return soundBuffer;
  }

  /**
   * Address: 0x00B16750 (FUN_00B16750, mwSndOpenPort)
   *
   * What it does:
   * Opens/configures one Sofdec sound-port handle from the slot pool.
   */
  moho::SofdecSoundPort* SofdecOpenSoundPort(const std::int32_t channels)
  {
    if (channels < 1 || channels > 2) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrChannelCountRange);
      return nullptr;
    }

    moho::SofdecSoundPort* const soundPort = SofdecAcquireFreeSoundPort();
    if (soundPort == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNoFreeSoundPort);
      return nullptr;
    }

    std::memset(soundPort, 0, sizeof(*soundPort));
    soundPort->dispatchTable = &gSofdecSoundPortVtable2Tag;
    soundPort->primaryBuffer = SofdecCreatePlaybackBuffer(
      channels, static_cast<std::uint32_t>(channels) * gSofdecPortBufferBytesPerChannel
    );

    if (soundPort->primaryBuffer == nullptr) {
      (void)SofdecResetSoundPort(soundPort);
      return nullptr;
    }

    soundPort->monoRoutingMode = gSofdecMonoRoutingMode;
    soundPort->bufferPlacementMode = gSofdecBufferPlacementMode;

    if (gSofdecOpenPortCount == 0 && SofdecCreateRestoreProbeBuffer() != 1) {
      SofdecShutdownRestoreProbeBuffer();
      (void)ADXERR_CallErrFunc1_(kSofdecErrCreatePlaybackFailed);
    }

    ++gSofdecOpenPortCount;

    moho::SofdecPcmWaveFormat defaultWaveFormat{};
    SofdecBuildDefaultPcmWaveFormat(static_cast<std::uint16_t>(channels), &defaultWaveFormat);
    soundPort->channelCountPrimary = channels;
    soundPort->channelModeFlag = channels;
    soundPort->format = defaultWaveFormat;
    soundPort->used = 1;
    return soundPort;
  }

  /**
   * Address: 0x00B16870 (FUN_00B16870, SofDecVirt2_Func1)
   *
   * What it does:
   * Closes one sound-port handle, releasing buffers and pool slot state.
   */
  std::int32_t SofdecCloseSoundPort(moho::SofdecSoundPort* const soundPort)
  {
    const std::int32_t inUseState = soundPort->used;
    if (inUseState == 0) {
      return inUseState;
    }

    SofdecStopSoundPortBuffers(soundPort);

    if (soundPort->primaryBuffer != nullptr) {
      soundPort->primaryBuffer->lpVtbl->Release(soundPort->primaryBuffer);
      soundPort->primaryBuffer = nullptr;
    }

    if (soundPort->secondaryBuffer != nullptr) {
      soundPort->secondaryBuffer->lpVtbl->Release(soundPort->secondaryBuffer);
      soundPort->secondaryBuffer = nullptr;
    }

    if (--gSofdecOpenPortCount == 0) {
      SofdecShutdownRestoreProbeBuffer();
    }

    return SofdecResetSoundPort(soundPort);
  }

  /**
   * Address: 0x00B168D0 (FUN_00B168D0, SofDecVirt2_Func2)
   *
   * What it does:
   * Stops/drains active sound-port buffers and re-synchronizes dual-buffer
   * cursor state when secondary buffer exists.
   */
  std::int32_t SofdecDrainAndSyncSoundPort(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return soundPort->used;
    }

    IDirectSoundBuffer* const primaryBuffer = soundPort->primaryBuffer;
    if (primaryBuffer == nullptr) {
      return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }

    if (soundPort->bufferPlacementMode == 0
        && primaryBuffer->lpVtbl->SetFrequency(primaryBuffer, soundPort->format.samplesPerSecond) != DS_OK) {
      return ADXERR_CallErrFunc1_(kSofdecErrSetFrequencyFailed);
    }

    if (soundPort->playbackCursorResetPending == 1) {
      if (primaryBuffer->lpVtbl->SetCurrentPosition(primaryBuffer, 0) != DS_OK) {
        (void)ADXERR_CallErrFunc1_(kSofdecErrSetCurrentPositionFailed);
      }
      soundPort->playbackCursorResetPending = 0;
    }

    (void)SofdecStartBufferAndWaitForPlaying(primaryBuffer);
    if (soundPort->secondaryBuffer == nullptr) {
      return soundPort->used;
    }

    SofdecStopBufferAndWaitForIdle(primaryBuffer);
    SofdecStopBufferAndWaitForIdle(soundPort->secondaryBuffer);
    (void)SofdecStartBufferAndWaitForPlaying(primaryBuffer);
    (void)SofdecStartBufferAndWaitForPlaying(soundPort->secondaryBuffer);
    return SofdecMirrorPrimaryCursorToSecondaryBuffer(soundPort);
  }

  /**
   * Address: 0x00B16990 (FUN_00B16990, SofDecVirt2_Func3)
   *
   * What it does:
   * Stops one sound-port's primary/secondary buffers and validates the global
   * restore-probe lane when present.
   */
  void SofdecStopSoundPortBuffers(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return;
    }

    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return;
    }

    if (gSofdecRestoreProbeBuffer != nullptr) {
      gSofdecRestoreProbeBuffer->lpVtbl->SetCurrentPosition(gSofdecRestoreProbeBuffer, 0);
      const std::int32_t playResult = gSofdecRestoreProbeBuffer->lpVtbl->Play(gSofdecRestoreProbeBuffer, 0, 0, 0);
      if (playResult != 0 && SofdecRestoreBufferIfLost(gSofdecRestoreProbeBuffer, playResult) == 0) {
        (void)ADXERR_CallErrFunc1_(kSofdecErrPlayFailed);
        return;
      }
    }

    SofdecStopBufferAndWaitForIdle(soundPort->primaryBuffer);
    if (soundPort->secondaryBuffer != nullptr) {
      SofdecStopBufferAndWaitForIdle(soundPort->secondaryBuffer);
    }
  }

  namespace
  {
    constexpr std::int32_t kSofdecTagNameBytes = 7;
    constexpr std::int32_t kSofdecTagHeaderBytes = 16;
    constexpr std::int32_t kSofdecFileTypeVideoElementary = 2;
    constexpr char kSofdecTagCritags[] = "CRITAGS";
    constexpr char kSofdecTagCritage[] = "CRITAGE";
    constexpr char kSofdecTagSfxz[] = "SFXZ";
    constexpr char kSofdecTagSfxinfs[] = "SFXINFS";
    constexpr char kSofdecTagSfxinfe[] = "SFXINFE";
    constexpr char kSofdecTagZmhdr[] = "ZMHDR";
    constexpr char kSofdecTagZmvfrm[] = "ZMVFRM";
    constexpr char kSofdecTagUsrinfe[] = "USRINFE";
    constexpr char kSofdecTagTunit[] = "TUNIT";
    constexpr char kSofdecTagTimedat[] = "TIMEDAT";
    constexpr char kSofdecTagIntime[] = "INTIME";
    constexpr char kSofdecTagDurtime[] = "DURTIME";

    struct MwsfdTagInfoRuntimeView
    {
      std::uint8_t mUnknown00_A7[0xA8]{};
      void* sfxHandle = nullptr; // +0xA8
      std::uint8_t mUnknownAC_17B[0xD0]{};
      moho::SofdecSjRingBufferHandle* sjTagRingHandle = nullptr; // +0x17C
      std::int8_t* ainfSearchBuffer = nullptr; // +0x180
      std::uint8_t mUnknown184_187[0x04]{};
      std::int8_t* ainfUserBuffer = nullptr; // +0x188
      std::uint8_t mUnknown18C_18F[0x04]{};
      std::int32_t ainfTagInfoSlot0 = 0; // +0x190
      std::int32_t ainfTagInfoReady = 0; // +0x194
      std::int32_t ainfTagInfoDataAddress = 0; // +0x198
      std::int32_t ainfTagInfoLength = 0; // +0x19C
    };

    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, sfxHandle) == 0xA8, "MwsfdTagInfoRuntimeView::sfxHandle offset must be 0xA8"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, sjTagRingHandle) == 0x17C,
      "MwsfdTagInfoRuntimeView::sjTagRingHandle offset must be 0x17C"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfSearchBuffer) == 0x180,
      "MwsfdTagInfoRuntimeView::ainfSearchBuffer offset must be 0x180"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfUserBuffer) == 0x188,
      "MwsfdTagInfoRuntimeView::ainfUserBuffer offset must be 0x188"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfTagInfoReady) == 0x194,
      "MwsfdTagInfoRuntimeView::ainfTagInfoReady offset must be 0x194"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfTagInfoDataAddress) == 0x198,
      "MwsfdTagInfoRuntimeView::ainfTagInfoDataAddress offset must be 0x198"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfTagInfoLength) == 0x19C,
      "MwsfdTagInfoRuntimeView::ainfTagInfoLength offset must be 0x19C"
    );

    struct SfxzTagGroupRuntimeView
    {
      std::uint8_t mUnknown00_07[0x8]{};
      std::int32_t hasTagPayload = 0; // +0x08
      std::int32_t tagPayloadAddress = 0; // +0x0C
      std::int32_t tagPayloadLength = 0; // +0x10
      std::uint8_t mUnknown14_17[0x4]{};
      std::int32_t zmhdrReady = 0; // +0x18
      std::int32_t zmhdrPayloadAddress = 0; // +0x1C
      std::int32_t zmhdrPayloadLength = 0; // +0x20
      std::uint8_t mUnknown24_27[0x4]{};
      std::int32_t zmvfrmReady = 0; // +0x28
      std::int32_t zmvfrmPayloadAddress = 0; // +0x2C
      std::int32_t zmvfrmPayloadLength = 0; // +0x30
    };

    static_assert(
      offsetof(SfxzTagGroupRuntimeView, hasTagPayload) == 0x08,
      "SfxzTagGroupRuntimeView::hasTagPayload offset must be 0x08"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, tagPayloadAddress) == 0x0C,
      "SfxzTagGroupRuntimeView::tagPayloadAddress offset must be 0x0C"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, tagPayloadLength) == 0x10,
      "SfxzTagGroupRuntimeView::tagPayloadLength offset must be 0x10"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmhdrReady) == 0x18,
      "SfxzTagGroupRuntimeView::zmhdrReady offset must be 0x18"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmhdrPayloadAddress) == 0x1C,
      "SfxzTagGroupRuntimeView::zmhdrPayloadAddress offset must be 0x1C"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmhdrPayloadLength) == 0x20,
      "SfxzTagGroupRuntimeView::zmhdrPayloadLength offset must be 0x20"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmvfrmReady) == 0x28,
      "SfxzTagGroupRuntimeView::zmvfrmReady offset must be 0x28"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmvfrmPayloadAddress) == 0x2C,
      "SfxzTagGroupRuntimeView::zmvfrmPayloadAddress offset must be 0x2C"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmvfrmPayloadLength) == 0x30,
      "SfxzTagGroupRuntimeView::zmvfrmPayloadLength offset must be 0x30"
    );

    struct SfxTagInfoRuntimeView
    {
      std::uint8_t mUnknown00_13[0x14]{};
      std::int32_t tagInfoReady = 0; // +0x14
      std::int32_t tagDataAddress = 0; // +0x18
      std::int32_t tagDataLength = 0; // +0x1C
      std::uint8_t mUnknown20_23[0x4]{};
      SfxzTagGroupRuntimeView* sfxzTagGroup = nullptr; // +0x24
    };

    static_assert(
      offsetof(SfxTagInfoRuntimeView, tagInfoReady) == 0x14,
      "SfxTagInfoRuntimeView::tagInfoReady offset must be 0x14"
    );
    static_assert(
      offsetof(SfxTagInfoRuntimeView, tagDataAddress) == 0x18,
      "SfxTagInfoRuntimeView::tagDataAddress offset must be 0x18"
    );
    static_assert(
      offsetof(SfxTagInfoRuntimeView, tagDataLength) == 0x1C,
      "SfxTagInfoRuntimeView::tagDataLength offset must be 0x1C"
    );
    static_assert(
      offsetof(SfxTagInfoRuntimeView, sfxzTagGroup) == 0x24,
      "SfxTagInfoRuntimeView::sfxzTagGroup offset must be 0x24"
    );

    [[nodiscard]] constexpr std::int32_t SofdecDecodeHexNibble(const char digit) noexcept
    {
      if (digit >= '0' && digit <= '9') {
        return digit - '0';
      }
      if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
      }
      if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
      }
      return 0;
    }

    [[nodiscard]] char SofdecEncodeHex7Digits(std::int32_t value, char* const outHexString)
    {
      constexpr char kHexDigits[] = "0123456789abcdef";

      outHexString[6] = kHexDigits[value & 0xF];
      value >>= 4;
      outHexString[5] = kHexDigits[value & 0xF];
      value >>= 4;
      outHexString[4] = kHexDigits[value & 0xF];
      value >>= 4;
      outHexString[3] = kHexDigits[value & 0xF];
      value >>= 4;
      outHexString[2] = kHexDigits[value & 0xF];
      value >>= 4;
      outHexString[1] = kHexDigits[value & 0xF];
      value >>= 4;
      outHexString[0] = kHexDigits[value & 0xF];
      return outHexString[0];
    }
  } // namespace

  /**
   * Address: 0x00B08810 (FUN_00B08810, _SJ_SplitChunk)
   *
   * What it does:
   * Splits one `(address,size)` chunk into head/tail lanes at `splitBytes`.
   */
  SjChunkRange* SJ_SplitChunk(
    const SjChunkRange* const sourceChunk,
    const std::int32_t splitBytes,
    SjChunkRange* const outHeadChunk,
    SjChunkRange* const outTailChunk
  )
  {
    outHeadChunk->bufferAddress = sourceChunk->bufferAddress;
    outHeadChunk->byteCount = sourceChunk->byteCount;
    outTailChunk->byteCount = outHeadChunk->byteCount;
    if (outHeadChunk->byteCount > splitBytes) {
      outHeadChunk->byteCount = splitBytes;
    }

    outTailChunk->byteCount -= outHeadChunk->byteCount;
    if (outTailChunk->byteCount != 0) {
      outTailChunk->bufferAddress = outHeadChunk->bufferAddress + outHeadChunk->byteCount;
    } else {
      outTailChunk->bufferAddress = 0;
    }

    return outHeadChunk;
  }

  /**
   * Address: 0x00B08960 (FUN_00B08960, _SJ_MakeTag)
   *
   * What it does:
   * Writes one tag header (`name + 7-hex-length`) into output tag window.
   */
  std::int32_t SJ_MakeTag(moho::MwsfTagWindow* const tagWindow, const char* const sourceTagName)
  {
    std::memset(tagWindow->data, 0, static_cast<std::size_t>(tagWindow->size));
    std::strncpy(reinterpret_cast<char*>(tagWindow->data), sourceTagName, static_cast<std::size_t>(kSofdecTagNameBytes));
    return static_cast<std::int32_t>(SofdecEncodeHex7Digits(
      tagWindow->size - kSofdecTagHeaderBytes,
      reinterpret_cast<char*>(tagWindow->data) + 8
    ));
  }

  /**
   * Address: 0x00B088E0 (FUN_00B088E0, _sj_hexstr_to_val)
   *
   * What it does:
   * Decodes one 7-digit hex-length lane used by Sofdec tag headers.
   */
  std::int32_t sj_hexstr_to_val(const char* const hexString)
  {
    if (hexString == nullptr) {
      return 0;
    }

    std::int32_t value = 0;
    for (std::int32_t i = 0; i < kSofdecTagNameBytes; ++i) {
      value = (value << 4) + SofdecDecodeHexNibble(hexString[i]);
    }
    return value;
  }

  /**
   * Address: 0x00B089B0 (FUN_00B089B0, _SJ_GetTagContent)
   *
   * What it does:
   * Expands one tag-header pointer into payload `(data,size)` window lanes.
   */
  std::int32_t SJ_GetTagContent(std::int8_t* const tagHeader, moho::MwsfTagWindow* const outWindow)
  {
    if (tagHeader == nullptr || outWindow == nullptr) {
      return 0;
    }

    outWindow->data = tagHeader + kSofdecTagHeaderBytes;
    outWindow->size = sj_hexstr_to_val(reinterpret_cast<const char*>(tagHeader + 8));
    return outWindow->size;
  }

  /**
   * Address: 0x00B089D0 (FUN_00B089D0, _SJ_SearchTag)
   *
   * What it does:
   * Scans one tag stream for `beginTagName` and optionally early-outs on
   * `endTagName`, returning the matched tag header address when found.
   */
  const char* SJ_SearchTag(
    const moho::MwsfTagWindow* const inputWindow,
    const char* const beginTagName,
    const char* const endTagName,
    moho::MwsfTagWindow* const outWindow
  )
  {
    if (inputWindow == nullptr || outWindow == nullptr || beginTagName == nullptr) {
      return nullptr;
    }

    outWindow->data = nullptr;
    outWindow->size = 0;
    if (inputWindow->data == nullptr || inputWindow->size <= 0) {
      return nullptr;
    }

    std::int8_t* cursor = inputWindow->data;
    const std::int8_t* const end = inputWindow->data + inputWindow->size;
    if (cursor >= end) {
      return nullptr;
    }

    while (std::strncmp(reinterpret_cast<const char*>(cursor), beginTagName, kSofdecTagNameBytes) != 0) {
      if (endTagName == nullptr
          || std::strncmp(reinterpret_cast<const char*>(cursor), endTagName, kSofdecTagNameBytes) != 0) {
        cursor += sj_hexstr_to_val(reinterpret_cast<const char*>(cursor + 8)) + kSofdecTagHeaderBytes;
        if (cursor < end) {
          continue;
        }
      }
      return nullptr;
    }

    (void)SJ_GetTagContent(cursor, outWindow);
    if (cursor >= end) {
      return nullptr;
    }
    return reinterpret_cast<const char*>(cursor);
  }

  /**
   * Address: 0x00AC66E0 (FUN_00AC66E0, _MWSFSFX_GetSfxHn)
   *
   * What it does:
   * Returns one playback object's bound SFX handle lane.
   */
  void* MWSFSFX_GetSfxHn(const moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return ply->sfxHandle;
  }

  /**
   * Address: 0x00AC6CF0 (FUN_00AC6CF0, _mwPlyFxGetCompoMode)
   *
   * What it does:
   * Reads the active SFX composition mode for one playback handle and
   * normalizes dynamic-B/C modes to dynamic-A.
   */
  std::int32_t mwPlyFxGetCompoMode(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetCompoModeInvalidHandle);
      return 0;
    }

    std::int32_t compositionMode = SFX_GetCompoMode(MWSFSFX_GetSfxHn(ply));
    if (compositionMode == kSfxCompoModeDynamicB || compositionMode == kSfxCompoModeDynamicC) {
      compositionMode = kSfxCompoModeDynamicA;
    }
    return compositionMode;
  }

  /**
   * Address: 0x00AC6D40 (FUN_00AC6D40, _mwPlyFxSetOutBufSize)
   *
   * What it does:
   * Sets SFX output pitch/height with default unit-width lane.
   */
  void mwPlyFxSetOutBufSize(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t outputPitch,
    const std::int32_t outputHeight
  )
  {
    MWSFSFX_SetOutBufSize(ply, outputPitch, outputHeight, 0);
  }

  /**
   * Address: 0x00AC6DA0 (FUN_00AC6DA0, _mwPlyFxSetOutBufPitchHeight)
   *
   * What it does:
   * Alias wrapper for `mwPlyFxSetOutBufSize`.
   */
  void mwPlyFxSetOutBufPitchHeight(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t outputPitch,
    const std::int32_t outputHeight
  )
  {
    MWSFSFX_SetOutBufSize(ply, outputPitch, outputHeight, 0);
  }

  /**
   * Address: 0x00AC6DD0 (FUN_00AC6DD0, _MWSFSFX_SetOutBufSize)
   *
   * What it does:
   * For valid playback handles, applies output dimensions and unit-width lanes
   * on the bound SFX runtime handle.
   */
  void MWSFSFX_SetOutBufSize(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t outputPitch,
    const std::int32_t outputHeight,
    const std::int32_t unitWidth
  )
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      void* const sfxHandle = MWSFSFX_GetSfxHn(ply);
      SFX_SetOutBufSize(sfxHandle, outputPitch, outputHeight);
      SFX_SetUnitWidth(sfxHandle, unitWidth);
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrSetOutBufSizeInvalidHandle);
  }

  /**
   * Address: 0x00AC6FF0 (FUN_00AC6FF0, _mwsftag_IsPlayVideoElementary)
   *
   * What it does:
   * Returns `1` when playback is configured for elementary-video mode.
   */
  std::int32_t mwsftag_IsPlayVideoElementary(const moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return 0;
    }
    return (ply->fileType == kSofdecFileTypeVideoElementary) ? 1 : 0;
  }

  /**
   * Address: 0x00AC70A0 (FUN_00AC70A0, _mwsftag_GetAinfFromSj)
   *
   * What it does:
   * Reads `CRITAGS` AINF payload from SJ lane-1 data and updates cached tag
   * info lanes for the playback object.
   */
  const char* mwsftag_GetAinfFromSj(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return nullptr;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    moho::SofdecSjRingBufferHandle* const sjRingHandle = runtimeView->sjTagRingHandle;
    const std::int32_t availableAinfBytes = (sjRingHandle != nullptr) ? SJRBF_GetNumData(sjRingHandle, 1) : 0;
    const char* result = reinterpret_cast<const char*>(static_cast<std::intptr_t>(availableAinfBytes));

    moho::MwsfTagWindow inputWindow{};
    moho::MwsfTagWindow outputWindow{};
    if (availableAinfBytes != 0) {
      inputWindow.data = runtimeView->ainfSearchBuffer;
      inputWindow.size = availableAinfBytes;
      result = SJ_SearchTag(&inputWindow, kSofdecTagCritags, kSofdecTagCritage, &outputWindow);
    }

    if (result != nullptr) {
      if (runtimeView->ainfUserBuffer != nullptr) {
        std::memcpy(runtimeView->ainfUserBuffer, outputWindow.data, static_cast<std::size_t>(outputWindow.size));
        runtimeView->ainfTagInfoDataAddress = static_cast<std::int32_t>(
          reinterpret_cast<std::intptr_t>(runtimeView->ainfUserBuffer)
        );
        runtimeView->ainfTagInfoLength = outputWindow.size;
        runtimeView->ainfTagInfoReady = 1;

        moho::SjChunkRange lane1Chunk{};
        SJRBF_GetChunk(sjRingHandle, 1, 0x7FFFFFFF, &lane1Chunk);
        SJRBF_PutChunk(sjRingHandle, 0, &lane1Chunk);
        return reinterpret_cast<const char*>(sjrbf_Reset(sjRingHandle));
      }

      runtimeView->ainfTagInfoDataAddress = static_cast<std::int32_t>(
        reinterpret_cast<std::intptr_t>(outputWindow.data)
      );
      runtimeView->ainfTagInfoLength = outputWindow.size;
      runtimeView->ainfTagInfoReady = 1;
      return reinterpret_cast<const char*>(
        static_cast<std::intptr_t>(MWSFTAG_ClearUsrSj(ply))
      );
    }

    runtimeView->ainfTagInfoReady = 1;
    runtimeView->ainfTagInfoDataAddress = 0;
    runtimeView->ainfTagInfoLength = 0;
    return result;
  }

  /**
   * Address: 0x00ACD6C0 (FUN_00ACD6C0, _sfxzmv_SetTagGrp)
   *
   * What it does:
   * Parses one SFXZ payload block and caches ZMHDR/ZMVFRM child-tag windows in
   * the SFXZ tag-group runtime lane.
   */
  const char* sfxzmv_SetTagGrp(SfxzTagGroupRuntimeView* const tagGroup)
  {
    if (tagGroup == nullptr) {
      return nullptr;
    }

    const char* result = reinterpret_cast<const char*>(static_cast<std::intptr_t>(tagGroup->tagPayloadAddress));
    if (tagGroup->tagPayloadAddress != 0) {
      moho::MwsfTagWindow sourceWindow{};
      sourceWindow.data = reinterpret_cast<std::int8_t*>(static_cast<std::intptr_t>(tagGroup->tagPayloadAddress));
      sourceWindow.size = tagGroup->tagPayloadLength;

      moho::MwsfTagWindow tagWindow{};
      (void)SJ_SearchTag(&sourceWindow, kSofdecTagZmhdr, kSofdecTagSfxinfe, &tagWindow);
      tagGroup->zmhdrReady = 1;
      tagGroup->zmhdrPayloadAddress = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(tagWindow.data));
      tagGroup->zmhdrPayloadLength = tagWindow.size;

      result = SJ_SearchTag(&sourceWindow, kSofdecTagZmvfrm, kSofdecTagSfxinfe, &tagWindow);
      tagGroup->zmvfrmReady = 1;
      tagGroup->zmvfrmPayloadAddress = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(tagWindow.data));
      tagGroup->zmvfrmPayloadLength = tagWindow.size;
      return result;
    }

    tagGroup->zmhdrReady = 1;
    tagGroup->zmhdrPayloadAddress = 0;
    tagGroup->zmhdrPayloadLength = 0;
    tagGroup->zmvfrmReady = 1;
    tagGroup->zmvfrmPayloadAddress = 0;
    tagGroup->zmvfrmPayloadLength = 0;
    return result;
  }

  /**
   * Address: 0x00ACD690 (FUN_00ACD690, _SFXZ_SetTagInf)
   *
   * What it does:
   * Records one raw SFXZ payload window in the target SFXZ tag-group lane and
   * refreshes derived ZMHDR/ZMVFRM child-tag windows.
   */
  const char* SFXZ_SetTagInf(
    SfxzTagGroupRuntimeView* const tagGroup,
    const std::int32_t tagPayloadAddress,
    const std::int32_t tagPayloadLength
  )
  {
    if (tagGroup == nullptr) {
      return nullptr;
    }

    tagGroup->hasTagPayload = 1;
    tagGroup->tagPayloadAddress = tagPayloadAddress;
    tagGroup->tagPayloadLength = tagPayloadLength;
    return sfxzmv_SetTagGrp(tagGroup);
  }

  /**
   * Address: 0x00ACCDF0 (FUN_00ACCDF0, _SFX_SetTagInf)
   *
   * What it does:
   * Stores the latest SFXINFS payload lane on one SFX runtime object, extracts
   * nested SFXZ content when present, and marks tag-info readiness.
   */
  std::int32_t SFX_SetTagInf(void* const sfxHandle, const std::int32_t tagDataAddress, const std::int32_t tagDataLength)
  {
    auto* const runtimeView = reinterpret_cast<SfxTagInfoRuntimeView*>(sfxHandle);
    runtimeView->tagDataAddress = tagDataAddress;
    runtimeView->tagDataLength = tagDataLength;

    moho::MwsfTagWindow sourceWindow{};
    sourceWindow.data = reinterpret_cast<std::int8_t*>(static_cast<std::intptr_t>(tagDataAddress));
    sourceWindow.size = tagDataLength;

    moho::MwsfTagWindow sfxzWindow{};
    const char* const searchResult = SJ_SearchTag(&sourceWindow, kSofdecTagSfxz, kSofdecTagSfxinfe, &sfxzWindow);

    const char* result = nullptr;
    if (searchResult != nullptr) {
      result = SFXZ_SetTagInf(
        runtimeView->sfxzTagGroup,
        static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(sfxzWindow.data)),
        sfxzWindow.size
      );
    } else {
      result = SFXZ_SetTagInf(runtimeView->sfxzTagGroup, 0, 0);
    }

    runtimeView->tagInfoReady = 1;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00AC7210 (FUN_00AC7210, _mwsftag_GetSFXinfFromAinf)
   *
   * What it does:
   * Extracts `SFXINFS` tag payload from cached AINF lanes and applies it to
   * the current SFX handle.
   */
  std::int32_t mwsftag_GetSFXinfFromAinf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    if (runtimeView->ainfTagInfoDataAddress == 0) {
      return SFX_SetTagInf(runtimeView->sfxHandle, 0, 0);
    }

    moho::MwsfTagWindow inputWindow{};
    inputWindow.data = reinterpret_cast<std::int8_t*>(static_cast<std::intptr_t>(runtimeView->ainfTagInfoDataAddress));
    inputWindow.size = runtimeView->ainfTagInfoLength;

    moho::MwsfTagWindow outputWindow{};
    if (SJ_SearchTag(&inputWindow, kSofdecTagSfxinfs, kSofdecTagSfxinfe, &outputWindow) != nullptr) {
      return SFX_SetTagInf(
        runtimeView->sfxHandle,
        static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(outputWindow.data)),
        outputWindow.size
      );
    }
    return SFX_SetTagInf(runtimeView->sfxHandle, 0, 0);
  }

  /**
   * Address: 0x00AC7050 (FUN_00AC7050, _MWSFTAG_SetTagInf)
   *
   * What it does:
   * Populates playback AINF/SFX tag lanes once when SJ ring input exists and
   * cached tag state is not yet marked ready.
   */
  std::int32_t MWSFTAG_SetTagInf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    const std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtimeView->sjTagRingHandle));
    if (result != 0 && runtimeView->ainfTagInfoReady != 1) {
      (void)mwsftag_GetAinfFromSj(ply);
      return mwsftag_GetSFXinfFromAinf(ply);
    }
    return result;
  }

  /**
   * Address: 0x00AC7080 (FUN_00AC7080, _MWSFTAG_UpdateTagInf)
   *
   * What it does:
   * Refreshes playback AINF/SFX tag lanes from the current SJ ring input.
   */
  std::int32_t MWSFTAG_UpdateTagInf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    const std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtimeView->sjTagRingHandle));
    if (result != 0) {
      (void)mwsftag_GetAinfFromSj(ply);
      return mwsftag_GetSFXinfFromAinf(ply);
    }
    return result;
  }

  /**
   * Address: 0x00AC7290 (FUN_00AC7290, _MWSFTAG_ClearUsrSj)
   *
   * What it does:
   * Clears SFD user-SJ lane for non-elementary playback objects with active
   * SJ ring ownership.
   */
  std::int32_t MWSFTAG_ClearUsrSj(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr || mwsftag_IsPlayVideoElementary(ply) == 1) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    if (runtimeView->sjTagRingHandle != nullptr) {
      return -(SFD_SetUsrSj(static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(ply->handle)), 2, 0, 0) != 0);
    }
    return 0;
  }

  /**
   * Address: 0x00AC9A70 (FUN_00AC9A70, _mwsftag_GetTag)
   *
   * What it does:
   * Searches one source tag window for a named tag span and writes the
   * matching child window (`data,size`) to `outWindow`.
   */
  moho::MwsfTagWindow* mwsftag_GetTag(
    moho::MwsfTagWindow* const sourceWindow,
    const char* const tagName,
    const char* const userInfoTag,
    moho::MwsfTagWindow* const outWindow
  )
  {
    if (outWindow == nullptr) {
      return nullptr;
    }

    if (sourceWindow != nullptr && sourceWindow->data != nullptr) {
      moho::MwsfTagWindow inputWindow{};
      inputWindow.data = sourceWindow->data;
      inputWindow.size = sourceWindow->size;
      (void)SJ_SearchTag(&inputWindow, tagName, userInfoTag, outWindow);
      return outWindow;
    }

    outWindow->data = nullptr;
    outWindow->size = 0;
    return outWindow;
  }

  /**
   * Address: 0x00AC9AD0 (FUN_00AC9AD0, _mwsftag_GetIntVal)
   *
   * What it does:
   * Reads one decimal integer payload from a named child tag and writes it to
   * `outValue`; returns `-1` when the target tag is missing.
   */
  std::int32_t mwsftag_GetIntVal(
    moho::MwsfTagWindow* const sourceWindow,
    const char* const tagName,
    const char* const userInfoTag,
    std::int32_t* const outValue
  )
  {
    moho::MwsfTagWindow valueWindow{};
    (void)mwsftag_GetTag(sourceWindow, tagName, userInfoTag, &valueWindow);
    if (valueWindow.data == nullptr) {
      if (outValue != nullptr) {
        *outValue = -1;
      }
      return -1;
    }

    long parsedValue = 0;
    (void)std::sscanf(reinterpret_cast<const char*>(valueWindow.data), "%ld", &parsedValue);
    if (outValue != nullptr) {
      *outValue = static_cast<std::int32_t>(parsedValue);
    }
    return static_cast<std::int32_t>(parsedValue);
  }

  /**
   * Address: 0x00AC9C20 (FUN_00AC9C20, _mwsftag_MoveNextTag)
   *
   * What it does:
   * Advances from one current child tag to the remaining source window span.
   */
  std::int32_t mwsftag_MoveNextTag(
    const moho::MwsfTagWindow* const sourceWindow,
    const moho::MwsfTagWindow* const currentTagWindow,
    moho::MwsfTagWindow* const outRemainingWindow
  )
  {
    if (sourceWindow == nullptr || currentTagWindow == nullptr || outRemainingWindow == nullptr) {
      return 0;
    }

    outRemainingWindow->data = currentTagWindow->data + currentTagWindow->size;
    outRemainingWindow->size =
      static_cast<std::int32_t>((sourceWindow->data + sourceWindow->size) - currentTagWindow->data - currentTagWindow->size);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(sourceWindow->data));
  }

  /**
   * Address: 0x00AC9ED0 (FUN_00AC9ED0, _MWSFD_CmpTime)
   *
   * What it does:
   * Clamps negative left/right time lanes to zero and forwards to
   * `UTY_CmpTime`.
   */
  std::int32_t MWSFD_CmpTime(
    std::int32_t leftTime,
    const std::int32_t timeUnit,
    std::int32_t rightTime,
    const std::int32_t currentTime
  )
  {
    if (leftTime < 0) {
      leftTime = 0;
    }
    if (rightTime < 0) {
      rightTime = 0;
    }
    return UTY_CmpTime(leftTime, timeUnit, rightTime, currentTime);
  }

  /**
   * Address: 0x00AC9D00 (FUN_00AC9D00, _MWSFTAG_SearchTimedatFromChdat)
   *
   * What it does:
   * Selects the active `TIMEDAT` child span from one chapter-data window based
   * on current playback time and writes that window into `outTimedatWindow`.
   */
  std::int8_t* MWSFTAG_SearchTimedatFromChdat(
    moho::MwsfTagWindow* const chapterDataWindow,
    const std::int32_t compareArg0,
    const std::int32_t compareArg1,
    const std::int32_t baseTime,
    moho::MwsfTagWindow* const outTimedatWindow
  )
  {
    if (chapterDataWindow == nullptr || outTimedatWindow == nullptr) {
      return nullptr;
    }

    moho::MwsfTagWindow remainingWindow{};
    remainingWindow.data = chapterDataWindow->data;
    remainingWindow.size = chapterDataWindow->size;
    outTimedatWindow->data = nullptr;
    outTimedatWindow->size = 0;

    std::int32_t timeUnit = -1;
    (void)mwsftag_GetIntVal(chapterDataWindow, kSofdecTagTunit, kSofdecTagUsrinfe, &timeUnit);

    moho::MwsfTagWindow selectedTimedatWindow{};
    std::int8_t* result = reinterpret_cast<std::int8_t*>(mwsftag_GetTag(
      &remainingWindow, kSofdecTagTimedat, kSofdecTagUsrinfe, &selectedTimedatWindow
    ));
    if (selectedTimedatWindow.data == nullptr) {
      return result;
    }

    std::int32_t currentInTime = -1;
    moho::MwsfTagWindow workingTimedatWindow = selectedTimedatWindow;
    (void)mwsftag_GetIntVal(&workingTimedatWindow, kSofdecTagIntime, kSofdecTagUsrinfe, &currentInTime);
    (void)mwsftag_MoveNextTag(chapterDataWindow, &workingTimedatWindow, &remainingWindow);

    result = reinterpret_cast<std::int8_t*>(
      static_cast<std::intptr_t>(MWSFD_CmpTime(baseTime + currentInTime, timeUnit, compareArg0, compareArg1))
    );
    if (result == reinterpret_cast<std::int8_t*>(1)) {
      while (remainingWindow.size >= kSofdecTagHeaderBytes) {
        moho::MwsfTagWindow nextTimedatWindow{};
        (void)mwsftag_GetTag(&remainingWindow, kSofdecTagTimedat, kSofdecTagUsrinfe, &nextTimedatWindow);
        if (nextTimedatWindow.data == nullptr) {
          break;
        }

        std::int32_t nextInTime = -1;
        moho::MwsfTagWindow nextTimedatCopy = nextTimedatWindow;
        (void)mwsftag_GetIntVal(&nextTimedatCopy, kSofdecTagIntime, kSofdecTagUsrinfe, &nextInTime);
        (void)mwsftag_MoveNextTag(chapterDataWindow, &nextTimedatCopy, &remainingWindow);

        if (MWSFD_CmpTime(baseTime + nextInTime, timeUnit, compareArg0, compareArg1) != 1) {
          break;
        }

        selectedTimedatWindow = nextTimedatWindow;
        currentInTime = nextInTime;
      }

      std::int32_t duration = -1;
      moho::MwsfTagWindow selectedTimedatCopy = selectedTimedatWindow;
      (void)mwsftag_GetIntVal(&selectedTimedatCopy, kSofdecTagDurtime, kSofdecTagUsrinfe, &duration);

      result = reinterpret_cast<std::int8_t*>(
        static_cast<std::intptr_t>(MWSFD_CmpTime(baseTime + currentInTime + duration, timeUnit, compareArg0, compareArg1))
      );
      if (result != reinterpret_cast<std::int8_t*>(1)) {
        *outTimedatWindow = selectedTimedatWindow;
        result = reinterpret_cast<std::int8_t*>(outTimedatWindow);
      }
    }

    return result;
  }

  /**
   * Address: 0x00AC8D10 (FUN_00AC8D10, _mwply_Destroy)
   *
   * What it does:
   * Stops active decode lanes, tears down all linked playback resources,
   * checks allocation leak counters, and clears the playback object.
   */
  void mwply_Destroy(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return;
    }

    mwSfdStopDec(ply);
    ply->compoMode = 0;
    MWSFTAG_DestroyAinfSj(ply);

    if (ply->sfxHandle != nullptr) {
      MWSFSFX_Destroy(ply->sfxHandle);
    }
    if (ply->lscHandle != nullptr) {
      LSC_Destroy(ply->lscHandle);
    }
    if (ply->adxStreamHandle != nullptr) {
      MWSTM_Destroy(ply->adxStreamHandle);
    }
    if (ply->sjRingBufferHandle != nullptr) {
      sjrbf_Destroy(ply->sjRingBufferHandle);
    }
    if (ply->sjMemoryHandle != nullptr) {
      sjmem_Destroy(ply->sjMemoryHandle);
    }
    if (ply->handle != nullptr) {
      MWSFCRE_DestroySfd(static_cast<char*>(ply->handle));
    }

    MWSST_Destroy(&ply->streamState);
    mwsfcre_AllFree(ply);
    if (mwsfcre_GetMallocCnt(ply) != 0) {
      (void)MWSFSVM_Error(kMwsfdErrForgotFree);
    }

    std::memset(ply, 0, sizeof(*ply));
    ply->compoMode = 0;
  }

  /**
   * Address: 0x00AC8D00 (FUN_00AC8D00, _mwPlyDestroy)
   *
   * What it does:
   * Public thunk that forwards playback-handle teardown to `mwply_Destroy`.
   */
  void mwPlyDestroy(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    mwply_Destroy(ply);
  }

  /**
   * Address: 0x00AC8F60 (FUN_00AC8F60, _MWSFD_Malloc)
   *
   * What it does:
   * Allocates one playback-owned work block through arena/user alloc path and
   * records the allocation pointer in the playback allocation table.
   */
  void* MWSFD_Malloc(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t size)
  {
    if (ply->mwsfcreAllocationCount >= static_cast<std::int32_t>(ply->mwsfcreAllocations.size())) {
      (void)MWSFSVM_Error(kMwsfdErrMallocCountOver);
      return nullptr;
    }

    if (size < 0) {
      return nullptr;
    }

    void* allocation = nullptr;
    if (ply->mwsfcreWorkSizeBytes != 0) {
      allocation = mwsfcre_OrgMalloc(ply, size);
    } else {
      allocation = mwsfcre_UsrMalloc(size);
    }

    if (allocation != nullptr) {
      ply->mwsfcreAllocations[static_cast<std::size_t>(ply->mwsfcreAllocationCount)] = allocation;
      mwsfcre_IncMallocCnt(ply);
    }
    return allocation;
  }

  /**
   * Address: 0x00AC9120 (FUN_00AC9120, _MWSFLIB_GetLibWorkPtr)
   */
  moho::MwsfdLibWork* MWSFLIB_GetLibWorkPtr()
  {
    return &gMwsfdLibWork;
  }

  /**
   * Address: 0x00AC9280 (FUN_00AC9280, _mwsflib_LscErrFunc)
   *
   * What it does:
   * Forwards one LSC runtime error message into the shared MWSFSVM error lane.
   */
  void mwsflib_LscErrFunc(const std::int32_t callbackObject, const char* const message)
  {
    (void)callbackObject;
    (void)MWSFSVM_Error(message);
  }

  /**
   * Address: 0x00AC92D0 (FUN_00AC92D0, _mwsflib_InitLibWork)
   *
   * What it does:
   * Clears global MWSFD library work state and applies startup/default display
   * condition lanes.
   */
  void mwsflib_InitLibWork(moho::MwsfdInitPrm* const initParams)
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    std::memset(libWork, 0, sizeof(*libWork));

    MWSFSVR_SetMwsfdSvrFlg(0);
    libWork->initLatch = 0;

    if (initParams != nullptr) {
      libWork->displayRefreshHz = initParams->vhz;
      libWork->displayCycle = initParams->disp_cycle;
      libWork->displayLatency = initParams->disp_latency;
      libWork->decodeServerSelection = static_cast<std::int32_t>(initParams->dec_svr);
    } else {
      libWork->displayRefreshHz = std::bit_cast<float>(0x426FC28Fu);
      libWork->displayCycle = 1;
      libWork->displayLatency = 1;
      libWork->decodeServerSelection = 0;
    }

    libWork->defaultConditionReserved = 0;
    libWork->defaultConditionInitialized = 1;
  }

  /**
   * Address: 0x00AC9380 (FUN_00AC9380, _mwsflib_SetDefCond)
   *
   * What it does:
   * Applies default playback condition lanes (`27`, `7`) in MWSFD runtime.
   */
  std::int32_t mwsflib_SetDefCond(const float* const startupConditionValue)
  {
    (void)MWSFD_SetCond(0, 27, static_cast<std::int32_t>(*startupConditionValue));
    return MWSFD_SetCond(0, 7, 1);
  }

  /**
   * Address: 0x00AC9470 (FUN_00AC9470, _MWSFLIB_SetErrCode)
   *
   * What it does:
   * Stores the current MWSFD library error-code lane and returns written value.
   */
  std::int32_t MWSFLIB_SetErrCode(const std::int32_t errorCode)
  {
    MWSFLIB_GetLibWorkPtr()->lastErrorCode = errorCode;
    return errorCode;
  }

  /**
   * Address: 0x00AC9490 (FUN_00AC9490, _mwPlySfdInit)
   */
  std::int32_t mwPlySfdInit(const std::int32_t requestedVersion)
  {
    moho::MwsfdInitSfdParams initParams{};
    initParams.callbacks = gMwsfdInitSfdParams.callbacks;
    initParams.version = requestedVersion;

    if (SFD_IsVersionCompatible(kMwsfdRequiredVersion, kMwsfdRequiredVersionTag) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrIncompatibleVersion);
      return -1;
    }

    if (SFD_Init(&initParams) != 0) {
      return MWSFLIB_SetErrCode(kMwsfdErrInitFailed);
    }

    const auto callbackAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFLIB_SfdErrFunc));
    if (SFD_SetErrFn(0, callbackAddress, 0) != 0) {
      return MWSFLIB_SetErrCode(kMwsfdErrSetErrFnFailed);
    }

    return 0;
  }

  /**
   * Address: 0x00AC9530 (FUN_00AC9530, _mwPlySfdFinish)
   *
   * What it does:
   * Runs one SFD global shutdown pass and returns success.
   */
  std::int32_t mwPlySfdFinish()
  {
    (void)SFD_Finish();
    return 0;
  }

  /**
   * Address: 0x00AC9540 (FUN_00AC9540, _MWSFLIB_SfdErrFunc)
   */
  std::int32_t MWSFLIB_SfdErrFunc(const std::int32_t mwsfdHandle, const std::int32_t errorCode)
  {
    if (mwsfdHandle != 0) {
      auto* const playbackHandle = reinterpret_cast<moho::MwsfdPlaybackStateSubobj*>(
        static_cast<std::uintptr_t>(mwsfdHandle)
      );
      gMwsfdLastSfdHandle = mwPlyGetSfdHn(playbackHandle);
      gMwsfdLastMwsfdHandle = mwsfdHandle;
    } else {
      gMwsfdLastMwsfdHandle = 0;
      gMwsfdLastSfdHandle = 0;
    }

    if (errorCode != 0) {
      const std::int32_t historyIndex = gMwsfdErrorCount;
      gMwsfdErrorCodeHistory[historyIndex] = errorCode;
      if (historyIndex < kMwsfdErrorHistoryMaxIndex) {
        gMwsfdErrorCount = historyIndex + 1;
      }
    }

    if (errorCode > kMwsfdErrFramePoolSize) {
      if (errorCode > kMwsfdErrRelFrameDoubleRelease) {
        if (errorCode >= kMwsfdErrDataLowerBound && errorCode <= kMwsfdErrDataUpperBound) {
          std::snprintf(
            gMwsfdErrorString,
            sizeof(gMwsfdErrorString),
            kMwsfdFmtDataError,
            static_cast<unsigned int>(errorCode)
          );
          return MWSFSVM_Error(gMwsfdErrorString);
        }
      } else if (errorCode == kMwsfdErrRelFrameDoubleRelease) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgRelFrameDoubleRelease,
          static_cast<unsigned int>(kMwsfdErrRelFrameDoubleRelease)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      } else if (errorCode >= kMwsfdErrMaxWidthHeightSmallMin && errorCode <= kMwsfdErrMaxWidthHeightSmallMax) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgMaxWidthHeightSmall,
          static_cast<unsigned int>(errorCode)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      } else if (errorCode == kMwsfdErrReadBufferSmallA) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgReadBufferSmall,
          static_cast<unsigned int>(errorCode)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      }
    } else if (errorCode == kMwsfdErrFramePoolSize) {
      std::snprintf(
        gMwsfdErrorString,
        sizeof(gMwsfdErrorString),
        kMwsfdMsgFramePoolSize,
        static_cast<unsigned int>(kMwsfdErrFramePoolSize)
      );
      return MWSFSVM_Error(gMwsfdErrorString);
    } else if (errorCode > kMwsfdErrLibraryMessage) {
      if (errorCode == kMwsfdErrAdxtHandleLimit) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgAdxtHandleLimit,
          static_cast<unsigned int>(errorCode)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      }
    } else if (errorCode == kMwsfdErrLibraryMessage) {
      std::snprintf(
        gMwsfdErrorString,
        sizeof(gMwsfdErrorString),
        kMwsfdFmtSfdErrorWithText,
        static_cast<unsigned int>(kMwsfdErrLibraryMessage),
        gMwsfdBackendErrorText
      );
      return MWSFSVM_Error(gMwsfdErrorString);
    } else if (errorCode == kMwsfdErrReadBufferSmallB || errorCode == kMwsfdErrReadBufferSmallC) {
      std::snprintf(
        gMwsfdErrorString,
        sizeof(gMwsfdErrorString),
        kMwsfdMsgReadBufferSmall,
        static_cast<unsigned int>(errorCode)
      );
      return MWSFSVM_Error(gMwsfdErrorString);
    }

    std::snprintf(gMwsfdErrorString, sizeof(gMwsfdErrorString), kMwsfdFmtSfdError, static_cast<unsigned int>(errorCode));
    return MWSFSVM_Error(gMwsfdErrorString);
  }

  /**
   * Address: 0x00AC96A0 (FUN_00AC96A0, _MWSFLIB_SetSeekFlg)
   *
   * What it does:
   * Stores global MWSFD seek-flag lane.
   */
  void MWSFLIB_SetSeekFlg(const std::int32_t enabled)
  {
    MWSFLIB_GetLibWorkPtr()->seekFlag = enabled;
  }

  /**
   * Address: 0x00AC96B0 (FUN_00AC96B0, _MWSFLIB_GetSeekFlg)
   *
   * What it does:
   * Returns global MWSFD seek-flag lane.
   */
  std::int32_t MWSFLIB_GetSeekFlg()
  {
    return MWSFLIB_GetLibWorkPtr()->seekFlag;
  }

  /**
   * Address: 0x00ACA090 (FUN_00ACA090, _mwPlyGetCurFrm)
   *
   * What it does:
   * Fetches the current SFD frame into one runtime frame-info object and
   * updates playback frame counters/concat tracking lanes.
   */
  moho::MwsfdFrameInfo*
  mwPlyGetCurFrm(moho::MwsfdPlaybackStateSubobj* const ply, moho::MwsfdFrameInfo* const outFrameInfo)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetCurFrmInvalidHandle);
      std::memset(outFrameInfo, 0, sizeof(*outFrameInfo));
      outFrameInfo->bufferAddress = 0;
      return nullptr;
    }

    mwsffrm_SetFrmApi(ply, 1);
    const std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
    if (sfdHandleAddress == 0) {
      std::memset(outFrameInfo, 0, sizeof(*outFrameInfo));
      outFrameInfo->bufferAddress = 0;
      return nullptr;
    }

    void* sfdFrame = nullptr;
    SFD_GetFrm(sfdHandleAddress, &sfdFrame);

    if (sfdFrame == nullptr) {
      outFrameInfo->bufferAddress = 0;
      return outFrameInfo;
    }

    if (ply->disableIntermediateFrameDrop == 0) {
      const std::int32_t framePoolSize = ply->framePoolSize;
      for (std::int32_t droppedFrames = 0; droppedFrames < framePoolSize; ++droppedFrames) {
        if (mwPlyIsNextFrmReady(ply) != 1) {
          break;
        }

        SFD_RelFrm(sfdHandleAddress, sfdFrame);
        ++ply->releasedFrameCount;
        SFD_GetFrm(sfdHandleAddress, &sfdFrame);
      }
    }

    if (sfdFrame != nullptr) {
      ++ply->retrievedFrameCount;
      ply->lastSfdFrame = sfdFrame;

      mwsffrm_SaveFrmDetail(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sfdFrame))
      );
      mwl_convFrmInfFromSFD(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sfdFrame)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outFrameInfo))
      );

      outFrameInfo->frameId = outFrameInfo->frameNumber;
      ply->lastFrameConcatCount = outFrameInfo->concatCount;
      return reinterpret_cast<moho::MwsfdFrameInfo*>(mwsffrm_CheckAinf(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outFrameInfo))
      ));
    }

    outFrameInfo->bufferAddress = 0;
    return outFrameInfo;
  }

  /**
   * Address: 0x00ACA760 (FUN_00ACA760, _mwPlyRelCurFrm)
   *
   * What it does:
   * Releases one current SFD frame lane and advances playback frame cursors
   * when one unreleased frame is still pending.
   */
  void mwPlyRelCurFrm(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      void* const currentFrame = ply->lastSfdFrame;
      const std::int32_t releasedFrameCursor = ply->mUnknown80;
      const std::int32_t retrievedFrameCursor = ply->retrievedFrameCount;

      mwsffrm_SetFrmApi(ply, 1);
      const std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
      if (retrievedFrameCursor > releasedFrameCursor) {
        SFD_RelFrm(sfdHandleAddress, currentFrame);
        const std::int32_t nextFrameCursor = ply->mUnknown80 + 1;
        ply->mUnknown80 = nextFrameCursor;
        ply->retrievedFrameCount = nextFrameCursor;
      }
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrRelCurFrmInvalidHandle);
  }

  /**
   * Address: 0x00ACA8A0 (FUN_00ACA8A0, _mwPlyGetNumSkipDisp)
   *
   * What it does:
   * Returns display-skip frame counter lane from playback state.
   */
  std::int32_t mwPlyGetNumSkipDisp(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetNumSkipDispInvalidHandle);
      return 0;
    }
    return ply->releasedFrameCount;
  }

  /**
   * Address: 0x00ACB5C0 (FUN_00ACB5C0, _mwPlyGetSfdHn)
   *
   * What it does:
   * Returns active SFD handle-address lane when playback handle is valid.
   */
  std::int32_t mwPlyGetSfdHn(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply->handle));
    }

    (void)MWSFSVM_Error(kMwsfdErrGetSfdHandleInvalidHandle);
    return 0;
  }

  /**
   * Address: 0x00ACB620 (FUN_00ACB620, _mwPlyGetNumDropFrm)
   *
   * What it does:
   * Returns aggregate dropped-frame count (decode-skip + display-skip).
   */
  std::int32_t mwPlyGetNumDropFrm(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      return mwPlyGetNumSkipDec(ply) + mwPlyGetNumSkipDisp(ply);
    }

    (void)MWSFSVM_Error(kMwsfdErrGetNumDropFrmInvalidHandle);
    return 0;
  }

  /**
   * Address: 0x00ACB660 (FUN_00ACB660, _mwPlyGetNumSkipDec)
   *
   * What it does:
   * Returns decode-skip count as the delta of two SFD playback-info lanes.
   */
  std::int32_t mwPlyGetNumSkipDec(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetNumSkipDecInvalidHandle);
      return 0;
    }

    const std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
    if (sfdHandleAddress == 0) {
      return sfdHandleAddress;
    }

    MwsfdRawPlaybackInfo playbackInfo{};
    (void)SFD_GetPlyInf(sfdHandleAddress, &playbackInfo);
    return playbackInfo.dropFrameAccumulator - playbackInfo.skipEmptyBFrameCount;
  }

  /**
   * Address: 0x00ACB8E0 (FUN_00ACB8E0, _MWSFD_GetPlyInf)
   *
   * What it does:
   * Copies one SFD playback-info snapshot into caller output memory.
   */
  std::int32_t MWSFD_GetPlyInf(moho::MwsfdPlaybackStateSubobj* const ply, void* const outPlyInfo)
  {
    const std::int32_t sfdHandleAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply->handle));
    if (sfdHandleAddress != 0) {
      return SFD_GetPlyInf(sfdHandleAddress, outPlyInfo);
    }

    std::memset(outPlyInfo, 0, sizeof(MwsfdRawPlaybackInfo));
    return sfdHandleAddress;
  }

  /**
   * Address: 0x00ACB950 (FUN_00ACB950, _MWSFD_GetCond)
   *
   * What it does:
   * Reads one condition lane from playback SFD handle when present, otherwise
   * from process-global default condition storage.
   */
  std::int32_t MWSFD_GetCond(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t conditionId,
    std::int32_t* const outConditionValue
  )
  {
    if (ply != nullptr) {
      return SFD_GetCond(
        reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle),
        conditionId,
        outConditionValue
      );
    }

    return SFD_GetCond(nullptr, conditionId, outConditionValue);
  }

  /**
   * Address: 0x00ACBA90 (FUN_00ACBA90, _mwPlyGetStat)
   *
   * What it does:
   * Returns playback status lane directly from composition mode, with special
   * streaming-mode mapping based on current SFD handle status.
   */
  std::int32_t mwPlyGetStat(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    constexpr std::int32_t kMwsfdCompoModeStreaming = 2;
    constexpr std::int32_t kSfdHandleStatusEos = 4;
    constexpr std::int32_t kSfdHandleStatusEnded = 6;
    constexpr std::int32_t kMwsfdPlaybackStatusRunning = 1;
    constexpr std::int32_t kMwsfdPlaybackStatusHold = 2;
    constexpr std::int32_t kMwsfdPlaybackStatusError = 4;

    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFLIB_SetErrCode(kMwsfdErrCodeInvalidHandle);
      (void)MWSFSVM_Error(kMwsfdErrGetStatInvalidHandle);
      return 0;
    }

    std::int32_t status = ply->compoMode;
    if (status == kMwsfdCompoModeStreaming) {
      status = SFD_GetHnStat(ply->handle);
      if (status == kSfdHandleStatusEos || status == kSfdHandleStatusEnded) {
        return kMwsfdPlaybackStatusHold;
      }
      return (status >= 0) ? kMwsfdPlaybackStatusRunning : kMwsfdPlaybackStatusError;
    }
    return status;
  }

  /**
   * Address: 0x00ACBBC0 (FUN_00ACBBC0, _mwPlyGetSyncMode)
   *
   * What it does:
   * Reads sync-mode condition lane (`15`) and returns normalized sync mode
   * (`0`, `1`, `2`) or `-1` on invalid handle/mode.
   */
  std::int32_t mwPlyGetSyncMode(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    constexpr std::int32_t kMwsfdConditionSyncMode = 15;
    constexpr std::int32_t kMwsfdSyncModeExternal = 1;
    constexpr std::int32_t kMwsfdSyncModeInternal = 2;

    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetSyncModeInvalidHandle);
      return -1;
    }

    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);
    if (workctrlSubobj == nullptr) {
      return 0;
    }

    // Binary writes condition output into stack slot that originally held `ply`.
    std::int32_t syncMode = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply));
    (void)SFD_GetCond(workctrlSubobj, kMwsfdConditionSyncMode, &syncMode);

    if (syncMode == 0) {
      return 0;
    }
    if (syncMode == kMwsfdSyncModeExternal) {
      return kMwsfdSyncModeExternal;
    }
    if (syncMode == kMwsfdSyncModeInternal) {
      return kMwsfdSyncModeInternal;
    }

    (void)MWSFSVM_Error(kMwsfdErrGetSyncModeInvalidMode);
    return -1;
  }

  /**
   * Address: 0x00ACBFC0 (FUN_00ACBFC0, _mwPlyGetNumSkipEmptyB)
   *
   * What it does:
   * Returns empty-B skip counter lane from playback-info snapshot.
   */
  std::int32_t mwPlyGetNumSkipEmptyB(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      MwsfdRawPlaybackInfo playbackInfo{};
      (void)MWSFD_GetPlyInf(ply, &playbackInfo);
      return playbackInfo.skipEmptyBFrameCount;
    }

    (void)MWSFSVM_Error(kMwsfdErrGetNumSkipEmptyBInvalidHandle);
    return 0;
  }

  /**
   * Address: 0x00ACC080 (FUN_00ACC080, _mwPlyGetPlyInf)
   *
   * What it does:
   * Builds six playback-debug counters for movie debug output.
   */
  std::int32_t mwPlyGetPlyInf(moho::MwsfdPlaybackStateSubobj* const ply, std::int32_t* const outInfoWords)
  {
    auto* const playbackSummary = reinterpret_cast<MwsfdPlaybackInfoSummary*>(outInfoWords);
    if (MWSFD_IsEnableHndl(ply) == 1) {
      std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
      if (sfdHandleAddress != 0) {
        MwsfdRawPlaybackInfo playbackInfo{};
        MwsfdRawTimerInfo timerInfo{};
        (void)SFD_GetPlyInf(sfdHandleAddress, &playbackInfo);

        playbackSummary->dropFrameCount = mwPlyGetNumDropFrm(ply);
        playbackSummary->skipDecodeCount = mwPlyGetNumSkipDec(ply);
        playbackSummary->skipDisplayCount = mwPlyGetNumSkipDisp(ply);
        playbackSummary->skipEmptyBCount = mwPlyGetNumSkipEmptyB(ply);
        playbackSummary->noSupplyCount = playbackInfo.noSupplyFrameCount;

        (void)SFD_GetTmrInf(sfdHandleAddress, &timerInfo);
        sfdHandleAddress = timerInfo.timerEndSample;
        playbackSummary->timerSample = timerInfo.timerEndSample;
      } else {
        std::memset(playbackSummary, 0, sizeof(*playbackSummary));
      }
      return sfdHandleAddress;
    }

    (void)MWSFSVM_Error(kMwsfdErrGetPlyInfInvalidHandle);
    std::memset(playbackSummary, 0, sizeof(*playbackSummary));
    return 0;
  }

  /**
   * Address: 0x00ACC6C0 (FUN_00ACC6C0, _mwPlyGetTimerCh)
   *
   * What it does:
   * Returns default timer-channel lane from global condition slot `61`.
   */
  void* mwPlyGetTimerCh(void* const timerChannelFallback)
  {
    constexpr std::int32_t kMwsfdConditionTimerChannel = 61;
    std::int32_t timerChannel = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(timerChannelFallback));
    (void)SFD_GetCond(nullptr, kMwsfdConditionTimerChannel, &timerChannel);
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(timerChannel)));
  }

  /**
   * Address: 0x00ACE9A0 (FUN_00ACE9A0, _SFX_CnvFrmByCbFunc)
   */
  void SFX_CnvFrmByCbFunc(
    moho::SfxCallbackFrameContext* const conversionState,
    moho::SfxStreamState* const streamState,
    const std::int32_t callbackArg
  )
  {
    const std::int32_t compositionCode = conversionState->compositionCode;
    if (compositionCode == 0) {
      conversionState->compositionCode = SFXINF_GetStmInf(streamState, kSfxTagCompo);
    }

    if (compositionCode > kSfxCompoModeDynamicB) {
      if (compositionCode == kSfxCompoModeDynamicC) {
        const std::int32_t tableMode = SFX_DecideTableAlph3(conversionState, streamState);
        SFX_MakeTable(conversionState, streamState, tableMode);
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        return;
      }

      if (compositionCode == kSfxCompoModeDirect) {
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 0);
        return;
      }

      if (compositionCode == kSfxCompoModeForcedLookup) {
        SFX_MakeTable(conversionState, streamState, kSfxCompoTableForced);
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        return;
      }

      SFXLIB_Error(conversionState, streamState, kSfxErrUnsupportedCompo);
      return;
    }

    if (compositionCode == kSfxCompoModeDynamicB || compositionCode == kSfxCompoModeDynamicA) {
      const std::int32_t tableMode = SFX_DecideTableAlph3(conversionState, streamState);
      SFX_MakeTable(conversionState, streamState, tableMode);
      sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
      return;
    }

    switch (compositionCode) {
      case kSfxCompoModeHalfAlpha:
        if (streamState->fieldTransformMode == 1) {
          SFX_MakeTable(conversionState, streamState, kSfxCompoTableForced);
          sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        } else {
          sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 0);
        }
        return;
      case kSfxCompoModeFullAlpha:
        SFX_MakeTable(conversionState, streamState, kSfxCompoTableFullAlpha);
        sfxcnv_ExecFullAlphaByCbFunc(conversionState, streamState, callbackArg);
        return;
      case kSfxCompoModeLookup:
        SFX_MakeTable(conversionState, streamState, kSfxCompoTableLookup);
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        return;
      default:
        SFXLIB_Error(conversionState, streamState, kSfxErrUnsupportedCompo);
        return;
    }
  }

  [[nodiscard]] moho::MwsfdPlaybackStateSubobj*
  GetMwsfdDecodeServerPlaybackSlot(moho::MwsfdLibWork* const libWork, const std::int32_t slotIndex)
  {
    auto* const slotBase = reinterpret_cast<std::uint8_t*>(libWork->playbackSlotsRaw);
    return reinterpret_cast<moho::MwsfdPlaybackStateSubobj*>(
      slotBase + (static_cast<std::size_t>(slotIndex) * sizeof(moho::MwsfdPlaybackStateSubobj))
    );
  }

  /**
   * Address: 0x00ACCCB0 (FUN_00ACCCB0, _MWSFSVM_TestAndSet)
   *
   * What it does:
   * Forwards one signal lane to `_SVM_TestAndSet`.
   */
  BOOL MWSFSVM_TestAndSet(std::int32_t* const signalLane)
  {
    return SVM_TestAndSet(signalLane);
  }

  /**
   * Address: 0x00AD93D0 (FUN_00AD93D0, _mwsfsvr_ExecCbFnDecSvrTop)
   *
   * What it does:
   * Invokes optional decode-server "top" callback lane from global MWSFD
   * library work.
   */
  void mwsfsvr_ExecCbFnDecSvrTop()
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (libWork->decodeServerTopCallback != nullptr) {
      (void)libWork->decodeServerTopCallback(libWork->decodeServerTopContext);
    }
  }

  /**
   * Address: 0x00AD93F0 (FUN_00AD93F0, _mwsfsvr_ExecCbFnDecSvrEnd)
   *
   * What it does:
   * Invokes optional decode-server "end" callback lane from global MWSFD
   * library work.
   */
  void mwsfsvr_ExecCbFnDecSvrEnd()
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (libWork->decodeServerEndCallback != nullptr) {
      (void)libWork->decodeServerEndCallback(libWork->decodeServerEndContext);
    }
  }

  /**
   * Address: 0x00AD9410 (FUN_00AD9410, _mwsfsvr_ExecCbFnRestDecSvr)
   *
   * What it does:
   * Invokes optional decode-server "rest" callback lane from global MWSFD
   * library work.
   */
  void mwsfsvr_ExecCbFnRestDecSvr()
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (libWork->decodeServerRestCallback != nullptr) {
      (void)libWork->decodeServerRestCallback(libWork->decodeServerRestContext);
    }
  }

  /**
   * Address: 0x00AD9430 (FUN_00AD9430, _mwPlyExecSvrHndl)
   *
   * What it does:
   * Thin thunk to `mwply_ExecSvrHndl`.
   */
  std::int32_t mwPlyExecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return mwply_ExecSvrHndl(ply);
  }

  /**
   * Address: 0x00AD9440 (FUN_00AD9440, _mwply_ExecSvrHndl)
   *
   * What it does:
   * Validates one playback object for decode-server execution and dispatches
   * into per-handle server execution when server gates are clear.
   */
  std::int32_t mwply_ExecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (mwsfd_init_flag != 1) {
      return 0;
    }

    if (ply == nullptr) {
      (void)MWSFSVM_Error(kMwsfdErrExecSvrNullHandle);
      return 0;
    }

    if (ply->used != 1) {
      return 0;
    }
    if (MWSFSVR_GetHnMwplySvrFlg(ply) == 1) {
      return 0;
    }
    if (MWSFD_GetReqSvrBdrLib() == 1) {
      return 0;
    }

    return mwsfd_ExecSvrHndl(ply);
  }

  /**
   * Address: 0x00AD94A0 (FUN_00AD94A0, _mwsfd_ExecSvrHndl)
   *
   * What it does:
   * Executes one SFD server tick for a playback handle and runs decode-server
   * side lanes when composition mode is active.
   */
  std::int32_t mwsfd_ExecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);
    (void)MWSFSVR_SetHnMwplySvrFlg(ply, 1);

    if (ply->used != 1) {
      (void)MWSFSVR_SetHnMwplySvrFlg(ply, 0);
      return FALSE;
    }

    mwsfd_hn_last = ply;
    (void)MWSFSVR_SetHnSfdSvrFlg(ply, 1);
    SFD_ExecOne(workctrlSubobj);
    (void)MWSFSVR_SetHnSfdSvrFlg(ply, 0);

    if (ply->compoMode != 0) {
      ply->decodeServerDispatchFlag = 1;
      (void)mwSfdExecDecSvrHndl(ply);
    } else {
      ply->decodeServerDispatchFlag = 0;
    }

    (void)MWSFSVR_SetHnMwplySvrFlg(ply, 0);
    return (SFD_IsHnSvrWait(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj))) == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD9530 (FUN_00AD9530, _mwSfdExecDecSvrHndl)
   *
   * What it does:
   * Dispatches one decode-server tick for prep/playing composition lanes, then
   * runs file-system and supply checks.
   */
  std::int32_t mwSfdExecDecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply->compoMode == 1) {
      (void)mwlSfdExecDecSvrPrep(ply);
    } else if (ply->compoMode == 2) {
      (void)mwlSfdExecDecSvrPlaying(ply);
    }

    (void)mwsfd_CheckFsErr(ply);
    mwsfsvr_CheckSupply();
    return 0;
  }

  /**
   * Address: 0x00AD9570 (FUN_00AD9570, _mwlSfdExecDecSvrPrep)
   *
   * What it does:
   * Runs prep-state decode-server step: executes pending stream start request,
   * starts playback lanes, and transitions into playing composition mode when
   * handle status reaches active/ready states.
   */
  std::int32_t mwlSfdExecDecSvrPrep(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);

    if (ply->pendingStartRequestType == 1 && mwsfsvr_StartStream(ply) == 1) {
      ply->pendingStartRequestType = 0;
    }

    mwsfsvr_StartPlayback(ply);
    const std::int32_t status = SFD_GetHnStat(workctrlSubobj);
    if (status == 4 || status == 6) {
      ply->compoMode = 2;
    }
    return status;
  }

  /**
   * Address: 0x00AD9790 (FUN_00AD9790, _mwlSfdExecDecSvrPlaying)
   *
   * What it does:
   * Runs one playing-state decode-server step: terminates prepared supply lane
   * when seamless list is empty, checks supply starvation, and transitions to
   * hold state on SFD status `6`.
   */
  std::int32_t mwlSfdExecDecSvrPlaying(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);

    if (ply->isPrepared == 1 && LSC_GetNumStm(ply->lscHandle) == 0) {
      if (sfply_TermSupply(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj))) != 0) {
        (void)MWSFSVM_Error(kMwsfdErrExecSvrPlayingTermFailed);
      }
      ply->isPrepared = 0;
    }

    if (ply->concatPlayArmed == 0 && ply->isPrepared == 0 && LSC_GetNumStm(ply->lscHandle) == 0) {
      (void)mwPlyChkSupply(ply);
    }

    const std::int32_t status = SFD_GetHnStat(workctrlSubobj);
    if (status == 6) {
      ply->compoMode = 3;
    }
    return status;
  }

  /**
   * Address: 0x00AD9810 (FUN_00AD9810, _mwsfd_CheckFsErr)
   *
   * What it does:
   * Maps stream and seamless-link filesystem error states to composition-mode
   * error state (`4`).
   */
  std::int32_t mwsfd_CheckFsErr(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply->adxStreamHandle != nullptr && MWSTM_IsFsStatErr(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply->adxStreamHandle)))) {
      ply->compoMode = 4;
    }

    if (ply->lscHandle != nullptr) {
      const bool hasFsError = MWSFLSC_IsFsStatErr(ply->lscHandle);
      if (hasFsError) {
        ply->compoMode = 4;
      }
      return hasFsError ? 1 : 0;
    }
    return 0;
  }

  /**
   * Address: 0x00ADDB40 (FUN_00ADDB40, _mwsfsvr_CheckSupply)
   *
   * What it does:
   * Reserved supply-check lane (no-op in this build).
   */
  void mwsfsvr_CheckSupply()
  {
  }

  /**
   * Address: 0x00AD9890 (FUN_00AD9890, _MWSFSVR_SetHnMwplySvrFlg)
   *
   * What it does:
   * Sets one playback "mwply server active" flag lane.
   */
  std::int32_t MWSFSVR_SetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t enabled)
  {
    ply->mwplyServerFlag = enabled;
    return enabled;
  }

  /**
   * Address: 0x00AD98A0 (FUN_00AD98A0, _MWSFSVR_GetHnMwplySvrFlg)
   *
   * What it does:
   * Returns one playback "mwply server active" flag lane.
   */
  std::int32_t MWSFSVR_GetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return ply->mwplyServerFlag;
  }

  /**
   * Address: 0x00AD98B0 (FUN_00AD98B0, _MWSFSVR_SetHnSfdSvrFlg)
   *
   * What it does:
   * Sets one playback "sfd server active" flag lane.
   */
  std::int32_t MWSFSVR_SetHnSfdSvrFlg(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t enabled)
  {
    ply->sfdServerFlag = enabled;
    return enabled;
  }

  /**
   * Address: 0x00AD9940 (FUN_00AD9940, _MWSFD_GetReqSvrBdrLib)
   *
   * What it does:
   * Returns global "request server bridge" control flag from MWSFD library
   * work lane.
   */
  std::int32_t MWSFD_GetReqSvrBdrLib()
  {
    return MWSFLIB_GetLibWorkPtr()->requestServerBridgeFlag;
  }

  /**
   * Address: 0x00ACB360 (FUN_00ACB360, _mwPlyChkSupply)
   *
   * What it does:
   * Terminates SFD supply when bound stream lane reaches status `3`.
   */
  std::int32_t mwPlyChkSupply(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);
    if (ply->adxStreamHandle != nullptr) {
      const std::int32_t status = MWSTM_GetStat(ply->adxStreamHandle);
      if (status == 3) {
        return sfply_TermSupply(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
      }
      return status;
    }
    return 0;
  }

  /**
   * Address: 0x00AD83A0 (FUN_00AD83A0, _sfply_TermSupply)
   *
   * What it does:
   * Marks one SFD SFBUF transfer lane as terminated and latches term-request
   * flag in work-control runtime state.
   */
  std::int32_t sfply_TermSupply(const std::int32_t sfdHandleAddress)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfdHandleAddress))
    );
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleTermSupply);
    }

    struct SfplyTermSupplyRuntimeView
    {
      std::uint8_t mUnknown00[0x44]{};
      std::int32_t termRequestedFlag = 0; // +0x44
      std::uint8_t mUnknown48[0x1EFC]{};
      std::int32_t sfbufLaneIndex = 0; // +0x1F44
    };
    static_assert(
      offsetof(SfplyTermSupplyRuntimeView, termRequestedFlag) == 0x44,
      "SfplyTermSupplyRuntimeView::termRequestedFlag offset must be 0x44"
    );
    static_assert(
      offsetof(SfplyTermSupplyRuntimeView, sfbufLaneIndex) == 0x1F44,
      "SfplyTermSupplyRuntimeView::sfbufLaneIndex offset must be 0x1F44"
    );

    auto* const runtime = reinterpret_cast<SfplyTermSupplyRuntimeView*>(workctrlSubobj);
    const std::int32_t laneIndex = runtime->sfbufLaneIndex;
    if (SFBUF_GetTermFlg(sfdHandleAddress, laneIndex) != 1) {
      (void)SFBUF_SetTermFlg(sfdHandleAddress, laneIndex, 1);
      runtime->termRequestedFlag = 1;
    }
    return 0;
  }

  /**
   * Address: 0x00AD9340 (FUN_00AD9340, _mwsfsvr_DecodeServer)
   *
   * What it does:
   * Runs one global decode-server tick: acquires server gate, executes
   * per-playback server handles, clears server flag, and dispatches server
   * lifecycle callbacks.
   */
  std::int32_t mwsfsvr_DecodeServer()
  {
    if (mwsfd_init_flag != 1) {
      return 0;
    }

    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (MWSFSVM_TestAndSet(&libWork->decodeServerSignal) != TRUE) {
      return 0;
    }

    mwsfsvr_ExecCbFnDecSvrTop();
    for (std::int32_t slotIndex = 0; slotIndex < moho::kMwsfdDecodeServerSlotCount; ++slotIndex) {
      auto* const playbackSlot = GetMwsfdDecodeServerPlaybackSlot(libWork, slotIndex);
      if (playbackSlot != nullptr) {
        (void)mwPlyExecSvrHndl(playbackSlot);
      }
    }

    MWSFSVR_SetMwsfdSvrFlg(0);

    const BOOL hasPendingSvrWait = (SFD_IsSvrWait() == 1) ? TRUE : FALSE;
    const BOOL decodePassFinished = (hasPendingSvrWait == FALSE) ? TRUE : FALSE;

    mwsfsvr_ExecCbFnDecSvrEnd();
    if (decodePassFinished == FALSE && MWSFD_GetReqSvrBdrLib() != 1) {
      mwsfsvr_ExecCbFnRestDecSvr();
    }

    return decodePassFinished;
  }

  /**
   * Address: 0x00AD95C0 (FUN_00AD95C0, _mwsfsvr_StartPlayback)
   */
  void mwsfsvr_StartPlayback(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply->streamState.state == 1) {
      const std::int32_t handleStatus = SFD_GetHnStat(ply->handle);
      const std::int32_t streamStatus = MWSST_GetStat(&ply->streamState);
      const std::int32_t pauseGateResult = ply->streamState.pauseGate->dispatchTable->queryStart(ply->streamState.pauseGate, 1);
      if (handleStatus == 3 && (streamStatus == 2 || pauseGateResult == 0)) {
        mwPlySfdStart(ply);
        if (ply->paused == 0) {
          mwPlyPause(ply, 0);
        }
        if (ply->concatPlayArmed == 1 && SFD_SetConcatPlay(ply->handle) != 0) {
          (void)MWSFSVM_Error(kMwsfdErrConcatPlayFailed);
        }
        if (ply->paused == 0) {
          (void)MWSST_Pause(&ply->streamState, 0);
        }
      }
      return;
    }

    if (SFD_GetHnStat(ply->handle) == 3) {
      mwPlySfdStart(ply);
      if (ply->paused == 0) {
        mwPlyPause(ply, 0);
      }
      if (ply->concatPlayArmed == 1 && SFD_SetConcatPlay(ply->handle) != 0) {
        (void)MWSFSVM_Error(kMwsfdErrConcatPlayFailed);
      }
    }
  }

  /**
   * Address: 0x00AD96E0 (FUN_00AD96E0, _mwsfsvr_StartStream)
   *
   * What it does:
   * Starts one pending MWSTM lane for playback object after applying stored
   * filename/range request and arming SJ supply state.
   */
  [[maybe_unused]] std::int32_t mwsfsvr_StartStream(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSTM_GetStat(ply->adxStreamHandle) == 2) {
      return -1;
    }

    if (ply->sjSupplyHandle != nullptr) {
      ply->sjSupplyHandle->dispatchTable->onStart(ply->sjSupplyHandle);
    }

    MWSTM_SetFileRange(
      ply->adxStreamHandle,
      ply->fname,
      ply->pendingStartRequestReserved,
      ply->pendingStartRangeStart,
      ply->pendingStartRangeEnd
    );

    if (MWSTM_ReqStart(ply->adxStreamHandle) == -1) {
      ply->compoMode = 4;
      (void)MWSFLIB_SetErrCode(-102);
      (void)MWSFSVM_Error(kMwsfdErrStartStreamReqStartFailedFmt, ply->fname);
      ply->pendingStartRequestType = 0;
      return -1;
    }

    (void)MWSFCRE_SetSupplySj(ply);
    return 1;
  }

  /**
   * Address: 0x00ACB020 (FUN_00ACB020, _mwPlyStartMem)
   */
  std::int32_t mwPlyStartMem(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t bufferAddress,
    const std::int32_t bufferSize
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      return MWSFSVM_Error(kMwsfdErrStartMemInvalidHandle);
    }
    if (ply->fileType == kMwsfdFileTypeMpv) {
      return MWSFSVM_Error(kMwsfdErrStartMemUnsupportedMpv);
    }

    mwSfdStopDec(ply);
    sjmem_Destroy(ply->sjMemoryHandle);

    auto* const memoryHandle = SJMEM_Create(bufferAddress, bufferSize);
    ply->sjMemoryHandle = memoryHandle;
    ply->sjSupplyHandle = reinterpret_cast<moho::SofdecSjSupplyHandle*>(memoryHandle);
    ply->sjMemoryBufferAddress = bufferAddress;
    ply->sjMemoryBufferSize = bufferSize;

    mw_sfd_start_ex(ply);
    return MWSFCRE_SetSupplySj(ply);
  }

  /**
   * Address: 0x00ACB010 (FUN_00ACB010, j__mwPlyStartMem)
   *
   * What it does:
   * Thunk wrapper around `mwPlyStartMem`.
   */
  std::int32_t mwPlyStartMemThunk(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t bufferAddress,
    const std::int32_t bufferSize
  )
  {
    return mwPlyStartMem(ply, bufferAddress, bufferSize);
  }

  /**
   * Address: 0x00ACB0C0 (FUN_00ACB0C0, _mwPlyStartSj)
   */
  std::int32_t mwPlyStartSj(moho::MwsfdPlaybackStateSubobj* const ply, moho::SofdecSjSupplyHandle* const supplyHandle)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      return MWSFSVM_Error(kMwsfdErrStartSjInvalidHandle);
    }

    mwSfdStopDec(ply);
    ply->sjSupplyHandle = supplyHandle;
    ply->sjSupplyMode = 2;
    ply->sjSupplyArg0 = 0;
    ply->sjSupplyArg1 = 0;
    ply->sjSupplyArg2 = 0;
    mw_sfd_start_ex(ply);
    return MWSFCRE_SetSupplySj(ply);
  }

  /**
   * Address: 0x00ACB0B0 (FUN_00ACB0B0, _MWSFD_StartInternalSj)
   *
   * What it does:
   * Playback shim that forwards ring-buffer start requests to SJ-supply start.
   */
  std::int32_t MWSFD_StartInternalSj(
    moho::MwsfdPlaybackStateSubobj* const ply,
    moho::SofdecSjRingBufferHandle* const ringBufferHandle
  )
  {
    return mwPlyStartSj(ply, reinterpret_cast<moho::SofdecSjSupplyHandle*>(ringBufferHandle));
  }

  /**
   * Address: 0x00ACB1D0 (FUN_00ACB1D0, _mwply_Stop)
   *
   * What it does:
   * Stops SFD decode, unlinks seamless-stream lane, resets seamless-entry
   * counter lane, and stops the linked LSC handle.
   */
  void mwply_Stop(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      mwSfdStopDec(ply);
      mwPlyLinkStm(ply, 0);
      void* const lscHandle = ply->lscHandle;
      ply->seamlessEntryCount = 0;
      lsc_Stop(lscHandle);
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrStopInvalidHandle);
  }

  /**
   * Address: 0x00ACB1C0 (FUN_00ACB1C0, _mwPlyStop)
   *
   * What it does:
   * Thunk wrapper to `mwply_Stop`.
   */
  void mwPlyStop(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    mwply_Stop(ply);
  }

  /**
   * Address: 0x00ADDB20 (FUN_00ADDB20, _MWSFSEE_StartFnameSub1)
   *
   * What it does:
   * Reserved filename-start hook lane (no-op in this build).
   */
  void MWSFSEE_StartFnameSub1()
  {
  }

  /**
   * Address: 0x00ADDB30 (FUN_00ADDB30, _MWSFSEE_StartFnameSub2)
   *
   * What it does:
   * Reserved filename-start hook lane (no-op in this build).
   */
  void MWSFSEE_StartFnameSub2()
  {
  }

  /**
   * Address: 0x00ACB3F0 (FUN_00ACB3F0, _MWSFPLY_ReqStartFname)
   *
   * What it does:
   * Requests one filename start with default full-range bounds.
   */
  std::int32_t MWSFPLY_ReqStartFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    MWSFPLY_ReqStartFnameRange(ply, fname, 0, 0xFFFFF);
    return 0;
  }

  /**
   * Address: 0x00ACAEF0 (FUN_00ACAEF0, _mwSfdStartFnameSub)
   *
   * What it does:
   * Switches playback to ring-buffer supply lane, resets decode/start state,
   * then queues one filename start request.
   */
  void mwSfdStartFnameSub(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t /*rangeStart*/,
    const std::int32_t /*rangeEnd*/
  )
  {
    ply->sjSupplyHandle = reinterpret_cast<moho::SofdecSjSupplyHandle*>(ply->sjRingBufferHandle);
    mwSfdStopDec(ply);
    mw_sfd_start_ex(ply);
    (void)MWSFPLY_ReqStartFname(ply, fname);
    MWSFSEE_StartFnameSub1();
    MWSFSEE_StartFnameSub2();
  }

  /**
   * Address: 0x00ACAEA0 (FUN_00ACAEA0, _mwply_StartFname)
   *
   * What it does:
   * Validates one playback handle + filename, then forwards into internal
   * filename-start setup path.
   */
  void mwply_StartFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      if (fname != nullptr) {
        mwSfdStartFnameSub(ply, fname, 0, -1);
      } else {
        (void)MWSFSVM_Error(kMwsfdErrStartFnameNullFileName);
      }
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrStartFnameInvalidHandle);
  }

  /**
   * Address: 0x00ACAE90 (FUN_00ACAE90, _mwPlyStartFname)
   *
   * What it does:
   * Public filename-start entry that forwards to `mwply_StartFname`.
   */
  void mwPlyStartFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    mwply_StartFname(ply, fname);
  }

  /**
   * Address: 0x00ACB390 (FUN_00ACB390, _MWSFPLY_RecordFname)
   */
  void MWSFPLY_RecordFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (static_cast<std::int32_t>(std::strlen(fname)) <= ply->fnameCapacity) {
      std::strcpy(ply->fname, fname);
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrFileNameTooLong);
    std::strncpy(ply->fname, fname, static_cast<std::size_t>(ply->fnameCapacity));
  }

  /**
   * Address: 0x00ACB410 (FUN_00ACB410, _MWSFPLY_ReqStartFnameRange)
   */
  void MWSFPLY_ReqStartFnameRange(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    MWSFPLY_RecordFname(ply, fname);
    ply->pendingStartRequestReserved = 0;
    ply->pendingStartRangeStart = rangeStart;
    ply->pendingStartRangeEnd = rangeEnd;
    ply->pendingStartRequestType = 1;
  }

  struct SofdecFeatureHeaderRuntimeView
  {
    std::int32_t state = 0; // +0x00
    std::uint8_t* elementInfoBuffer = nullptr; // +0x04
    std::int32_t version = 0; // +0x08
  };

  static_assert(
    offsetof(SofdecFeatureHeaderRuntimeView, state) == 0x00,
    "SofdecFeatureHeaderRuntimeView::state offset must be 0x00"
  );
  static_assert(
    offsetof(SofdecFeatureHeaderRuntimeView, elementInfoBuffer) == 0x04,
    "SofdecFeatureHeaderRuntimeView::elementInfoBuffer offset must be 0x04"
  );
  static_assert(
    offsetof(SofdecFeatureHeaderRuntimeView, version) == 0x08,
    "SofdecFeatureHeaderRuntimeView::version offset must be 0x08"
  );

  constexpr std::int32_t kSfhElementTableOffset = 0x180;
  constexpr std::int32_t kSfhElementStrideBytes = 0x40;
  constexpr std::int32_t kSfhElementTableEntryCount = 26;
  constexpr std::int32_t kSfhElementStreamIdOffset = 0x18;

  /**
   * Address: 0x00ADC9B0 (FUN_00ADC9B0, _isEffectiveObj)
   *
   * What it does:
   * Validates the feature-header state lane against the accepted range.
   */
  [[nodiscard]] bool SfhIsObjectStateEffective(const SofdecFeatureHeaderRuntimeView* const featureHeader) noexcept
  {
    return featureHeader->state < -1 || featureHeader->state > 1;
  }

  /**
   * Address: 0x00ADC980 (FUN_00ADC980, _isEffectiveVer)
   *
   * What it does:
   * Applies object-state validation and accepts parser versions `107` and
   * `>=110`.
   */
  [[nodiscard]] bool SfhIsVersionEffective(const SofdecFeatureHeaderRuntimeView* const featureHeader) noexcept
  {
    if (!SfhIsObjectStateEffective(featureHeader)) {
      return false;
    }

    const std::int32_t version = featureHeader->version;
    return version == 107 || version >= 110;
  }

  /**
   * Address: 0x00ADCA60 (FUN_00ADCA60, _searchStmId)
   *
   * What it does:
   * Scans the fixed feature-element table for one stream-id lane match.
   */
  [[nodiscard]] std::uint8_t* SfhSearchStreamId(std::uint8_t* const elementInfoBuffer, const std::int32_t streamId)
  {
    std::uint8_t* elementInfo = elementInfoBuffer + kSfhElementTableOffset;
    for (std::int32_t index = 0; index < kSfhElementTableEntryCount; ++index) {
      if (elementInfo[kSfhElementStreamIdOffset] == static_cast<std::uint8_t>(streamId)) {
        return elementInfo;
      }
      elementInfo += kSfhElementStrideBytes;
    }

    return nullptr;
  }

  /**
   * Address: 0x00ADD110 (FUN_00ADD110, _getElemInfPtr)
   *
   * What it does:
   * Returns matching feature-element info pointer when state/version lanes are
   * accepted; otherwise returns null.
   */
  [[nodiscard]]
  std::uint8_t* SfhGetElementInfoPtr(SofdecFeatureHeaderRuntimeView* const featureHeader, const std::int32_t streamId)
  {
    if (!SfhIsVersionEffective(featureHeader)) {
      return nullptr;
    }

    return SfhSearchStreamId(featureHeader->elementInfoBuffer, streamId);
  }

  struct LscStreamEntryRuntimeView
  {
    std::int32_t streamId = 0; // +0x00
    const char* fileName = nullptr; // +0x04
    std::int32_t fileNameChecksum = 0; // +0x08
    std::int32_t startOffset = 0; // +0x0C
    std::int32_t rangeStart = 0; // +0x10
    std::int32_t rangeEnd = 0; // +0x14
    std::int32_t streamStatus = 0; // +0x18
    std::int32_t readSector = 0; // +0x1C
  };

  static_assert(
    offsetof(LscStreamEntryRuntimeView, streamId) == 0x00, "LscStreamEntryRuntimeView::streamId offset must be 0x00"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, fileName) == 0x04, "LscStreamEntryRuntimeView::fileName offset must be 0x04"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, fileNameChecksum) == 0x08,
    "LscStreamEntryRuntimeView::fileNameChecksum offset must be 0x08"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, startOffset) == 0x0C, "LscStreamEntryRuntimeView::startOffset offset must be 0x0C"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, rangeStart) == 0x10, "LscStreamEntryRuntimeView::rangeStart offset must be 0x10"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, rangeEnd) == 0x14, "LscStreamEntryRuntimeView::rangeEnd offset must be 0x14"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, streamStatus) == 0x18,
    "LscStreamEntryRuntimeView::streamStatus offset must be 0x18"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, readSector) == 0x1C, "LscStreamEntryRuntimeView::readSector offset must be 0x1C"
  );
  static_assert(sizeof(LscStreamEntryRuntimeView) == 0x20, "LscStreamEntryRuntimeView size must be 0x20");

  struct LscRuntimeView
  {
    std::uint8_t used = 0; // +0x00
    std::int8_t status = 0; // +0x01
    std::uint8_t streamHandleActive = 0; // +0x02
    std::uint8_t loopEnabled = 0; // +0x03
    std::uint8_t paused = 0; // +0x04
    std::uint8_t mUnknown05_07[0x03]{}; // +0x05
    void* sjHandle = nullptr; // +0x08
    std::uint8_t mUnknown0C_13[0x08]{}; // +0x0C
    std::int32_t flowLimit = 0; // +0x14
    std::int32_t flowLimitMax = 0; // +0x18
    std::int32_t streamWriteCursor = 0; // +0x1C
    std::int32_t streamReadCursor = 0; // +0x20
    std::int32_t streamCount = 0; // +0x24
    void* streamHandle = nullptr; // +0x28
    std::int32_t activeStreamId = 0; // +0x2C
    std::int32_t mUnknown30 = 0; // +0x30
    std::int32_t activeReadSector = 0; // +0x34
    LscStreamEntryRuntimeView streamEntries[16]{}; // +0x38
  };

  static_assert(offsetof(LscRuntimeView, used) == 0x00, "LscRuntimeView::used offset must be 0x00");
  static_assert(offsetof(LscRuntimeView, status) == 0x01, "LscRuntimeView::status offset must be 0x01");
  static_assert(
    offsetof(LscRuntimeView, streamHandleActive) == 0x02, "LscRuntimeView::streamHandleActive offset must be 0x02"
  );
  static_assert(offsetof(LscRuntimeView, loopEnabled) == 0x03, "LscRuntimeView::loopEnabled offset must be 0x03");
  static_assert(offsetof(LscRuntimeView, paused) == 0x04, "LscRuntimeView::paused offset must be 0x04");
  static_assert(offsetof(LscRuntimeView, sjHandle) == 0x08, "LscRuntimeView::sjHandle offset must be 0x08");
  static_assert(offsetof(LscRuntimeView, flowLimit) == 0x14, "LscRuntimeView::flowLimit offset must be 0x14");
  static_assert(offsetof(LscRuntimeView, flowLimitMax) == 0x18, "LscRuntimeView::flowLimitMax offset must be 0x18");
  static_assert(
    offsetof(LscRuntimeView, streamWriteCursor) == 0x1C, "LscRuntimeView::streamWriteCursor offset must be 0x1C"
  );
  static_assert(
    offsetof(LscRuntimeView, streamReadCursor) == 0x20, "LscRuntimeView::streamReadCursor offset must be 0x20"
  );
  static_assert(offsetof(LscRuntimeView, streamCount) == 0x24, "LscRuntimeView::streamCount offset must be 0x24");
  static_assert(
    offsetof(LscRuntimeView, streamHandle) == 0x28, "LscRuntimeView::streamHandle offset must be 0x28"
  );
  static_assert(
    offsetof(LscRuntimeView, activeStreamId) == 0x2C, "LscRuntimeView::activeStreamId offset must be 0x2C"
  );
  static_assert(
    offsetof(LscRuntimeView, activeReadSector) == 0x34, "LscRuntimeView::activeReadSector offset must be 0x34"
  );
  static_assert(
    offsetof(LscRuntimeView, streamEntries) == 0x38, "LscRuntimeView::streamEntries offset must be 0x38"
  );
  static_assert(sizeof(LscRuntimeView) == 0x238, "LscRuntimeView size must be 0x238");

  constexpr std::int32_t kLscRingCapacity = 16;
  constexpr std::int32_t kLscObjectPoolCapacity = 64;
  constexpr std::int32_t kLscRangeEndAll = 0xFFFFF;
  constexpr std::int32_t kLscStatusStarted = 1;
  constexpr std::int32_t kLscStatusQueued = 2;
  constexpr std::int32_t kLscMaxStreamId = 0x7FFFFFFF;
  constexpr std::size_t kLscErrorMessageCapacity = 0x400;
  constexpr char kLscErrInvalidSjHandle[] = "E2005012801: Illigal parameter=sj (LSC_Create)\n";
  constexpr char kLscErrNoFreeLscInstance[] = "E2005012802: Not enough instance (LSC_Create)\n";
  constexpr char kLscErrLscNull[] = "E2005012803: Illigal parameter lsc=NULL";
  constexpr char kLscErrFileNameNullFmt[] = "E2005012804: Illigal parameter fname=%s\n";
  constexpr char kLscErrLscNullReset[] = "E2005012805: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullStart[] = "E2005012806: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullStop[] = "E2005012807: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullPause[] = "E2005012808: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullGetStat[] = "E2005012809: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullGetNumStm[] = "E2005012810: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullGetStmId[] = "E2005012811: Illigal parameter lsc=NULL";
  constexpr char kLscErrInvalidStmIndexFmt[] = "E2005012812: Illigal parameter no=%d\n";
  constexpr char kLscErrLscNullGetStmFname[] = "E2005012813: Illigal parameter lsc=NULL";
  constexpr char kLscErrStreamNotFoundFnameFmt[] = "E2005012814: Can not find stream ID =%d\n";
  constexpr char kLscErrLscNullGetStmStat[] = "E2005012815: Illigal parameter lsc=NULL";
  constexpr char kLscErrStreamNotFoundStatFmt[] = "E2005012816: Can not find stream ID =%d\n";
  constexpr char kLscErrLscNullGetStmRdSct[] = "E2005012817: Illigal parameter lsc=NULL";
  constexpr char kLscErrStreamNotFoundRdSctFmt[] = "E2005012818: Can not find stream ID =%d\n";
  constexpr char kLscErrLscNullSetFlowLimit[] = "E2005012819: Illigal parameter lsc=NULL";
  constexpr char kLscErrInvalidFlowLimitFmt[] = "E2005012820: Illigal parameter min_val=%d\n";
  constexpr char kLscErrLscNullGetFlowLimit[] = "E2005012821: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullSetLoopFlag[] = "E2005012822: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscFilePointerNull[] = "E0007: lsc->fp=NULL\n";
  constexpr char kLscErrEntryFileMismatchFmt[] = "E0013: '%s' is different from entry file name.(LSC_ExecServer)\n";
  constexpr char kAdxtErrCannotEntryFilePrefix[] = "E4063001:Can't entry file ";
  constexpr char kAdxtErrEntryAfsCannotEntryPrefix[] = "E0071301 adxt_EntryAfs: can't entry ";
  constexpr char kAdxtErrSetSeamlessLpParameter[] = "E02080851 adxt_SetSeamlessLp: parameter error";
  constexpr char kAdxtErrStartSjParameter[] = "E02080812 adxt_StartSj: parameter error";
  constexpr char kAdxtErrStartFnameRangeLpParameter[] = "E02080852 adxt_StartFnameRangeLp: parameter error";
  constexpr char kAdxtErrStartAfsLpParameter[] = "E0405100 adxt_StartAfsLp: parameter error";
  constexpr char kAdxtErrGetNumFilesParameter[] = "E02080854 adxt_GetNumFiles: parameter error";
  constexpr char kAdxtErrResetEntryParameter[] = "E02080849 adxt_ResetEntry: parameter error";

  using LscErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, const char* message);
  std::array<LscRuntimeView, kLscObjectPoolCapacity> gLscObjectPool{};
  std::array<char, kLscErrorMessageCapacity> gLscErrorMessage{};
  LscErrorCallback gLscErrorCallback = nullptr;
  std::int32_t gLscErrorObject = 0;
  std::int32_t gLscInitCount = 0;

  struct LscSjRuntimeInterfaceVtable
  {
    std::uint8_t mUnknown00_23[0x24]{};
    std::int32_t(__cdecl* getNumData)(void* sjHandle, std::int32_t lane) = nullptr; // +0x24
  };

  struct LscSjRuntimeHandleView
  {
    std::int32_t runtimeSlot = 0; // +0x00
  };

  static_assert(sizeof(gLscObjectPool) == 0x8E00, "LSC object pool size must be 0x8E00");
  static_assert(
    offsetof(LscSjRuntimeInterfaceVtable, getNumData) == 0x24,
    "LscSjRuntimeInterfaceVtable::getNumData offset must be 0x24"
  );
  static_assert(sizeof(LscSjRuntimeHandleView) == 0x04, "LscSjRuntimeHandleView size must be 0x04");

  using LscStatusChangeCallback = std::int32_t(__cdecl*)(std::int32_t callbackObjectPrimary, std::int32_t callbackObjectSecondary);
  LscStatusChangeCallback gLscStatusChangeCallback = nullptr;
  std::int32_t gLscStatusChangeObjectPrimary = 0;
  std::int32_t gLscStatusChangeObjectSecondary = 0;

  [[nodiscard]] LscRuntimeView* AsLscRuntimeView(void* const lscHandle) noexcept
  {
    return reinterpret_cast<LscRuntimeView*>(lscHandle);
  }

  [[nodiscard]] constexpr std::int32_t LscWrapRingIndex(std::int32_t value) noexcept
  {
    value %= kLscRingCapacity;
    if (value < 0) {
      value += kLscRingCapacity;
    }
    return value;
  }

  [[nodiscard]] std::int32_t LscFindStreamEntryIndex(const LscRuntimeView* const lsc, const std::int32_t streamId) noexcept
  {
    for (std::int32_t i = 0; i < kLscRingCapacity; ++i) {
      if (lsc->streamEntries[i].streamId == streamId) {
        return i;
      }
    }
    return -1;
  }

  [[nodiscard]] std::int32_t LscComputeFileNameChecksum(const char* const fileName) noexcept
  {
    std::int32_t checksum = 0;
    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(fileName); *cursor != 0; ++cursor) {
      checksum += static_cast<std::int32_t>(*cursor);
    }
    return checksum;
  }

  [[nodiscard]] std::int32_t LscGetSjNumData(void* const sjHandle, const std::int32_t lane)
  {
    const auto* const sjRuntime = reinterpret_cast<const LscSjRuntimeHandleView*>(sjHandle);
    const auto* const runtimeInterface =
      reinterpret_cast<const LscSjRuntimeInterfaceVtable*>(SjAddressToPointer(sjRuntime->runtimeSlot));
    return runtimeInterface->getNumData(sjHandle, lane);
  }

  [[nodiscard]] LscStreamEntryRuntimeView& LscCurrentStreamEntry(LscRuntimeView* const lsc) noexcept
  {
    return lsc->streamEntries[LscWrapRingIndex(lsc->streamReadCursor)];
  }

  /**
   * Address: 0x00B08A60 (FUN_00B08A60, _lsc_Alloc)
   *
   * What it does:
   * Returns first free LSC object lane from the global fixed pool.
   */
  [[maybe_unused]] [[nodiscard]] LscRuntimeView* lsc_Alloc() noexcept
  {
    for (LscRuntimeView& lscObject : gLscObjectPool) {
      if (lscObject.used == 0) {
        return &lscObject;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B08A90 (FUN_00B08A90, _LSC_Create)
   *
   * What it does:
   * Allocates one LSC object from the global pool and binds it to an SJ
   * provider handle for seamless stream scheduling.
   */
  [[maybe_unused]] void* LSC_Create(void* const sjHandle)
  {
    if (sjHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrInvalidSjHandle);
      return nullptr;
    }

    SJCRS_Lock();
    LscRuntimeView* const lsc = lsc_Alloc();
    if (lsc == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrNoFreeLscInstance);
      SJCRS_Unlock();
      return nullptr;
    }

    lsc->sjHandle = sjHandle;
    lsc->status = 0;
    lsc->flowLimitMax = LscGetSjNumData(sjHandle, 1) + LscGetSjNumData(sjHandle, 0);
    lsc->flowLimit = (lsc->flowLimitMax * 8) / 10;

    for (LscStreamEntryRuntimeView& entry : lsc->streamEntries) {
      entry.streamStatus = 0;
    }

    lsc->used = 1;
    SJCRS_Unlock();
    return lsc;
  }

  /**
   * Address: 0x00B09820 (FUN_00B09820, _LSC_EntryErrFunc)
   *
   * What it does:
   * Registers or clears the LSC error callback lane and callback object.
   */
  [[maybe_unused]] std::int32_t LSC_EntryErrFunc(const LscErrorCallback callback, const std::int32_t callbackObject)
  {
    if (callback != nullptr) {
      gLscErrorCallback = callback;
      gLscErrorObject = callbackObject;
      return callbackObject;
    }

    gLscErrorCallback = nullptr;
    gLscErrorObject = 0;
    return 0;
  }

  /**
   * Address: 0x00B09850 (FUN_00B09850, _LSC_CallErrFunc_)
   *
   * What it does:
   * Formats one LSC error message into the global message buffer and calls the
   * registered error callback when present.
   */
  [[maybe_unused]] std::int32_t LSC_CallErrFunc_(const char* const format, ...)
  {
    va_list argumentList{};
    va_start(argumentList, format);
    std::vsprintf(gLscErrorMessage.data(), format, argumentList);
    va_end(argumentList);

    if (gLscErrorCallback == nullptr) {
      return 0;
    }
    return gLscErrorCallback(gLscErrorObject, gLscErrorMessage.data());
  }

  /**
   * Address: 0x00B09890 (FUN_00B09890, _lsc_EntrySvrInt)
   *
   * What it does:
   * Legacy server-interface entry hook for this build; no runtime behavior.
   */
  [[maybe_unused]] void lsc_EntrySvrInt()
  {
  }

  /**
   * Address: 0x00B098A0 (FUN_00B098A0, _lsc_DeleteSvrInt)
   *
   * What it does:
   * Legacy server-interface delete hook for this build; no runtime behavior.
   */
  [[maybe_unused]] void lsc_DeleteSvrInt()
  {
  }

  /**
   * Address: 0x00B098B0 (FUN_00B098B0, _LSC_Init)
   *
   * What it does:
   * Initializes shared LSC runtime state on first entry and increments init
   * reference count under SJ critical-section lock.
   */
  [[maybe_unused]] void LSC_Init()
  {
    SJCRS_Lock();
    if (gLscInitCount == 0) {
      std::memset(gLscObjectPool.data(), 0, sizeof(gLscObjectPool));
      (void)LSC_EntryErrFunc(nullptr, 0);
    }

    ++gLscInitCount;
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09910 (FUN_00B09910, _LSC_Finish)
   *
   * What it does:
   * Decrements LSC init reference count; on final release destroys active pool
   * objects, clears pool memory, and clears error callback state.
   */
  [[maybe_unused]] std::int32_t LSC_Finish()
  {
    const std::int32_t result = --gLscInitCount;
    if (gLscInitCount != 0) {
      return result;
    }

    for (LscRuntimeView& lscObject : gLscObjectPool) {
      if (lscObject.used == 1) {
        LSC_Destroy(&lscObject);
      }
    }

    std::memset(gLscObjectPool.data(), 0, sizeof(gLscObjectPool));
    return LSC_EntryErrFunc(nullptr, 0);
  }

  /**
   * Address: 0x00B08B70 (FUN_00B08B70, _LSC_SetStmHndl)
   *
   * What it does:
   * Stores one ADX stream-handle lane in the LSC runtime object.
   */
  void* LSC_SetStmHndl(void* const lscHandle, void* const streamHandle)
  {
    AsLscRuntimeView(lscHandle)->streamHandle = streamHandle;
    return streamHandle;
  }

  /**
   * Address: 0x00B08B80 (FUN_00B08B80, _LSC_EntryFname)
   *
   * What it does:
   * Queues one filename with full-range playback bounds.
   */
  std::int32_t LSC_EntryFname(void* const lscHandle, const char* const fileName)
  {
    return lsc_EntryFileRange(lscHandle, fileName, 0, 0, kLscRangeEndAll);
  }

  /**
   * Address: 0x00B08BA0 (FUN_00B08BA0, _lsc_EntryFileRange)
   *
   * What it does:
   * Enqueues one seamless-stream entry lane and returns its generated stream ID.
   */
  std::int32_t lsc_EntryFileRange(
    void* const lscHandle,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNull);
      return -1;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->streamCount >= kLscRingCapacity) {
      return -1;
    }

    if (fileName == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrFileNameNullFmt, fileName);
      return -1;
    }

    const std::int32_t previousSlot = LscWrapRingIndex(lsc->streamWriteCursor + (kLscRingCapacity - 1));
    const std::int32_t previousStreamId = lsc->streamEntries[previousSlot].streamId;
    const std::int32_t streamId = (previousStreamId == kLscMaxStreamId) ? 0 : previousStreamId + 1;

    LscStreamEntryRuntimeView& entry = lsc->streamEntries[LscWrapRingIndex(lsc->streamWriteCursor)];
    entry.streamId = streamId;
    entry.fileName = fileName;
    entry.fileNameChecksum = LscComputeFileNameChecksum(fileName);
    entry.startOffset = startOffset;
    entry.rangeStart = rangeStart;
    entry.rangeEnd = rangeEnd;
    entry.streamStatus = 0;
    entry.readSector = 0;

    ++lsc->streamCount;
    lsc->streamWriteCursor = LscWrapRingIndex(lsc->streamWriteCursor + 1);
    if (lsc->status == kLscStatusStarted) {
      lsc->status = kLscStatusQueued;
    }
    return streamId;
  }

  /**
   * Address: 0x00B08C90 (FUN_00B08C90, _LSC_ResetEntry)
   *
   * What it does:
   * Clears stream queue cursors/count when LSC is not in started state.
   */
  void LSC_ResetEntry(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullReset);
      return;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->status == 0) {
      lsc->streamWriteCursor = 0;
      lsc->streamReadCursor = 0;
      lsc->streamCount = 0;
    }
  }

  /**
   * Address: 0x00B08CC0 (FUN_00B08CC0, _lsc_Start)
   *
   * What it does:
   * Starts LSC playback state and upgrades status when queued streams exist.
   */
  void lsc_Start(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullStart);
      return;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->status != 0) {
      lsc_Stop(lscHandle);
    }

    lsc->status = static_cast<std::int8_t>((lsc->streamCount > 0) ? kLscStatusQueued : kLscStatusStarted);
  }

  /**
   * Address: 0x00B08D00 (FUN_00B08D00, _lsc_Stop)
   *
   * What it does:
   * Stops active LSC stream state, resets queue cursors, and clears active
   * stream-tracking lanes.
   */
  void lsc_Stop(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullStop);
      return;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->status == 0) {
      return;
    }

    void* const streamHandle = lsc->streamHandle;
    lsc->status = 0;
    if (streamHandle != nullptr && lsc->streamHandleActive == 1) {
      ADXSTM_Stop(streamHandle);
      lsc->streamHandleActive = 0;
    }

    lsc->activeStreamId = 0;
    LSC_ResetEntry(lscHandle);
    lsc->activeReadSector = 0;
  }

  /**
   * Address: 0x00B08D50 (FUN_00B08D50, _lsc_Pause)
   *
   * What it does:
   * Updates one pause-byte lane in the LSC runtime.
   */
  std::int32_t lsc_Pause(void* const lscHandle, const std::int32_t paused)
  {
    if (lscHandle == nullptr) {
      return LSC_CallErrFunc_(kLscErrLscNullPause);
    }

    AsLscRuntimeView(lscHandle)->paused = static_cast<std::uint8_t>(paused == 1);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(lscHandle));
  }

  /**
   * Address: 0x00B08B50 (FUN_00B08B50, _LSC_Destroy)
   *
   * What it does:
   * Stops one LSC handle and clears its full runtime lane.
   */
  void LSC_Destroy(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      return;
    }

    lsc_Stop(lscHandle);
    std::memset(lscHandle, 0, sizeof(LscRuntimeView));
  }

  /**
   * Address: 0x00B08DB0 (FUN_00B08DB0, _LSC_GetStat)
   *
   * What it does:
   * Returns current LSC status lane.
   */
  std::int32_t LSC_GetStat(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStat);
      return -1;
    }

    return static_cast<std::int32_t>(AsLscRuntimeView(lscHandle)->status);
  }

  /**
   * Address: 0x00B08DD0 (FUN_00B08DD0, _LSC_GetNumStm)
   *
   * What it does:
   * Returns queued seamless-stream count.
   */
  std::int32_t LSC_GetNumStm(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetNumStm);
      return -1;
    }

    return AsLscRuntimeView(lscHandle)->streamCount;
  }

  /**
   * Address: 0x00B08DF0 (FUN_00B08DF0, _lsc_GetStmId)
   *
   * What it does:
   * Returns stream ID by queue index relative to the current read cursor.
   */
  std::int32_t lsc_GetStmId(void* const lscHandle, const std::int32_t streamIndex)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmId);
      return -1;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (streamIndex < 0 || streamIndex >= lsc->streamCount) {
      (void)LSC_CallErrFunc_(kLscErrInvalidStmIndexFmt, streamIndex);
      return -1;
    }

    const std::int32_t slot = LscWrapRingIndex(lsc->streamReadCursor + streamIndex);
    return lsc->streamEntries[slot].streamId;
  }

  /**
   * Address: 0x00B08E50 (FUN_00B08E50, _lsc_GetStmFname)
   *
   * What it does:
   * Resolves file name lane by stream ID.
   */
  const char* lsc_GetStmFname(void* const lscHandle, const std::int32_t streamId)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmFname);
      return nullptr;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    const std::int32_t index = LscFindStreamEntryIndex(lsc, streamId);
    if (index < 0) {
      (void)LSC_CallErrFunc_(kLscErrStreamNotFoundFnameFmt, streamId);
      return nullptr;
    }

    return lsc->streamEntries[index].fileName;
  }

  /**
   * Address: 0x00B08EA0 (FUN_00B08EA0, _lsc_GetStmStat)
   *
   * What it does:
   * Resolves stream-status lane by stream ID.
   */
  std::int32_t lsc_GetStmStat(void* const lscHandle, const std::int32_t streamId)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmStat);
      return -1;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    const std::int32_t index = LscFindStreamEntryIndex(lsc, streamId);
    if (index < 0) {
      (void)LSC_CallErrFunc_(kLscErrStreamNotFoundStatFmt, streamId);
      return -1;
    }

    return lsc->streamEntries[index].streamStatus;
  }

  /**
   * Address: 0x00B08F00 (FUN_00B08F00, _lsc_GetStmRdSct)
   *
   * What it does:
   * Resolves current read-sector lane by stream ID.
   */
  std::int32_t lsc_GetStmRdSct(void* const lscHandle, const std::int32_t streamId)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmRdSct);
      return 0;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    const std::int32_t index = LscFindStreamEntryIndex(lsc, streamId);
    if (index < 0) {
      (void)LSC_CallErrFunc_(kLscErrStreamNotFoundRdSctFmt, streamId);
      return 0;
    }

    return lsc->streamEntries[index].readSector;
  }

  /**
   * Address: 0x00B08F50 (FUN_00B08F50, _lsc_SetFlowLimit)
   *
   * What it does:
   * Updates per-LSC minimum flow limit when inside valid range.
   */
  std::int32_t lsc_SetFlowLimit(void* const lscHandle, const std::int32_t flowLimit)
  {
    if (lscHandle == nullptr) {
      return LSC_CallErrFunc_(kLscErrLscNullSetFlowLimit);
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (flowLimit < 0 || flowLimit > lsc->flowLimitMax) {
      return LSC_CallErrFunc_(kLscErrInvalidFlowLimitFmt, flowLimit);
    }

    lsc->flowLimit = flowLimit;
    return flowLimit;
  }

  /**
   * Address: 0x00B08F90 (FUN_00B08F90, _lsc_GetFlowLimit)
   *
   * What it does:
   * Returns current LSC flow-limit lane.
   */
  std::int32_t lsc_GetFlowLimit(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetFlowLimit);
      return -1;
    }

    return AsLscRuntimeView(lscHandle)->flowLimit;
  }

  /**
   * Address: 0x00B09010 (FUN_00B09010, _LSC_SetLpFlg)
   *
   * What it does:
   * Stores one seamless-loop enabled flag byte in the LSC runtime.
   */
  void LSC_SetLpFlg(void* const lscHandle, const std::int32_t enabled)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullSetLoopFlag);
      return;
    }

    AsLscRuntimeView(lscHandle)->loopEnabled = static_cast<std::uint8_t>(enabled);
  }

  /**
   * Address: 0x00B08FB0 (FUN_00B08FB0, _LSC_EntryChgStatFunc)
   *
   * What it does:
   * Registers or clears one LSC status-change callback lane.
   */
  std::int32_t LSC_EntryChgStatFunc(
    LscStatusChangeCallback callback,
    const std::int32_t callbackObjectPrimary,
    const std::int32_t callbackObjectSecondary
  )
  {
    if (callback == nullptr) {
      gLscStatusChangeCallback = nullptr;
      gLscStatusChangeObjectPrimary = 0;
      gLscStatusChangeObjectSecondary = 0;
      return 0;
    }

    gLscStatusChangeCallback = callback;
    gLscStatusChangeObjectSecondary = callbackObjectSecondary;
    gLscStatusChangeObjectPrimary = callbackObjectPrimary;
    return callbackObjectPrimary;
  }

  /**
   * Address: 0x00B08FF0 (FUN_00B08FF0, _LSC_CallStatFunc)
   *
   * What it does:
   * Calls registered LSC status callback with stored callback objects.
   */
  std::int32_t LSC_CallStatFunc()
  {
    if (gLscStatusChangeCallback == nullptr) {
      return 0;
    }

    return gLscStatusChangeCallback(gLscStatusChangeObjectPrimary, gLscStatusChangeObjectSecondary);
  }

  /**
   * Address: 0x00B17810 (FUN_00B17810, _LSC_LockCrs)
   *
   * What it does:
   * LSC lock wrapper over the shared Sofdec critical section.
   */
  [[maybe_unused]] void LSC_LockCrs()
  {
    SJCRS_Lock();
  }

  /**
   * Address: 0x00B17820 (FUN_00B17820, _LSC_UnlockCrs)
   *
   * What it does:
   * LSC unlock wrapper over the shared Sofdec critical section.
   */
  [[maybe_unused]] void LSC_UnlockCrs()
  {
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B17830 (FUN_00B17830, _lsc_StatWait)
   *
   * What it does:
   * Binds the current queued entry to the ADX stream and starts non-blocking
   * playback when queue data is available.
   */
  [[maybe_unused]] std::int32_t lsc_StatWait(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    LscStreamEntryRuntimeView& entry = LscCurrentStreamEntry(lsc);

    if (lsc->streamCount <= 0) {
      return lsc->streamCount;
    }

    ADXSTM_StopNw(lsc->streamHandle);
    ADXSTM_ReleaseFileNw(lsc->streamHandle);

    const std::int32_t checksum = LscComputeFileNameChecksum(entry.fileName);
    if (checksum != entry.fileNameChecksum) {
      return LSC_CallErrFunc_(kLscErrEntryFileMismatchFmt, entry.fileName);
    }

    ADXSTM_BindFileNw(lsc->streamHandle, entry.fileName, entry.startOffset, entry.rangeStart, entry.rangeEnd);
    ADXSTM_SetEos(lsc->streamHandle, entry.rangeEnd);
    lsc->activeStreamId = entry.rangeEnd;
    entry.readSector = 0;

    lsc->streamHandleActive = 0;
    ADXSTM_SetBufSize(lsc->streamHandle, lsc->flowLimit, lsc->flowLimitMax);
    ADXSTM_Seek(lsc->streamHandle, 0);
    ADXSTM_Start(lsc->streamHandle);
    lsc->streamHandleActive = 1;

    entry.streamStatus = 1;
    return 1;
  }

  /**
   * Address: 0x00B17910 (FUN_00B17910, _lsc_StatRead)
   *
   * What it does:
   * Polls ADX stream state for the current entry and updates queued stream
   * status/read-sector lanes.
   */
  [[maybe_unused]] std::int32_t lsc_StatRead(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->streamHandle == nullptr) {
      return LSC_CallErrFunc_(kLscErrLscFilePointerNull);
    }

    LscStreamEntryRuntimeView& entry = LscCurrentStreamEntry(lsc);
    const std::int32_t statClass = ADXSTM_GetStat(lsc->streamHandle) - 2;
    if (statClass == 0) {
      entry.readSector = ADXSTM_Tell(lsc->streamHandle);
      return entry.readSector;
    }

    if (statClass == 1) {
      entry.streamStatus = 2;
      entry.readSector = lsc->activeStreamId;
      return 0;
    }

    if (statClass == 2) {
      lsc->status = 3;
      return 0;
    }

    return statClass - 2;
  }

  /**
   * Address: 0x00B17980 (FUN_00B17980, _lsc_StatEnd)
   *
   * What it does:
   * Finalizes current stream entry, advances the read cursor, triggers status
   * callback on queue depletion, and re-enqueues looped entries.
   */
  [[maybe_unused]] std::int32_t lsc_StatEnd(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->streamHandle == nullptr) {
      return 0;
    }

    const bool loopEnabled = (lsc->loopEnabled == 1);
    const LscStreamEntryRuntimeView entrySnapshot = loopEnabled ? LscCurrentStreamEntry(lsc) : LscStreamEntryRuntimeView{};

    --lsc->streamCount;
    std::int32_t result = lsc->streamCount;
    lsc->streamReadCursor = LscWrapRingIndex(lsc->streamReadCursor + 1);

    if (result <= 0) {
      result = LSC_CallStatFunc();
      lsc->status = 1;
    }

    if (loopEnabled) {
      return lsc_EntryFileRange(
        lscHandle,
        entrySnapshot.fileName,
        entrySnapshot.startOffset,
        entrySnapshot.rangeStart,
        entrySnapshot.rangeEnd
      );
    }

    return result;
  }

  /**
   * Address: 0x00B17A10 (FUN_00B17A10, _lsc_ExecHndl)
   *
   * What it does:
   * Runs one LSC handle tick lane: read poll, end handling, then wait/start.
   */
  [[maybe_unused]] std::int32_t lsc_ExecHndl(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    std::int32_t result = 1;

    if (lsc->paused == 1 || lsc->status != 2 || lsc->streamCount <= 0) {
      return result;
    }

    LscStreamEntryRuntimeView& entry = LscCurrentStreamEntry(lsc);
    if (entry.streamStatus == 1) {
      (void)lsc_StatRead(lscHandle);
    }

    if (entry.streamStatus == 2) {
      (void)lsc_StatEnd(lscHandle);
    }

    result = entry.streamStatus;
    if (result == 0) {
      return lsc_StatWait(lscHandle);
    }

    return result;
  }

  /**
   * Address: 0x00B08D80 (FUN_00B08D80, _lsc_ExecServer)
   *
   * What it does:
   * Ticks all active LSC object lanes in the fixed object pool.
   */
  [[maybe_unused]] std::int32_t lsc_ExecServer()
  {
    std::int32_t result = 0;
    for (LscRuntimeView& lsc : gLscObjectPool) {
      if (lsc.used == 1) {
        result = lsc_ExecHndl(&lsc);
      }
    }
    return result;
  }

  /**
   * Address: 0x00B193D0 (FUN_00B193D0, _LSC_ExecServer)
   *
   * What it does:
   * Public wrapper for the LSC server execution tick.
   */
  [[maybe_unused]] std::int32_t LSC_ExecServer()
  {
    return lsc_ExecServer();
  }

  /**
   * Address: 0x00B011E0 (FUN_00B011E0, _M2P_IsSetup)
   *
   * What it does:
   * Returns M2P setup-state lane for MPEG2 parser runtime.
   */
  std::int32_t M2P_IsSetup()
  {
    return m2sapi_m2p_issetup;
  }

  /**
   * Address: 0x00B011F0 (FUN_00B011F0, _M2P_GetVersionStr)
   *
   * What it does:
   * Returns M2P backend version string when callback lane is linked.
   */
  const char* M2P_GetVersionStr()
  {
    if (m2sapi_m2p_GetVersionStr != nullptr) {
      return m2sapi_m2p_GetVersionStr();
    }
    return nullptr;
  }

  /**
   * Address: 0x00B01200 (FUN_00B01200, _M2P_Init)
   *
   * What it does:
   * Calls M2P backend initialization callback lane.
   */
  std::int32_t M2P_Init()
  {
    if (m2sapi_m2p_Init != nullptr) {
      return m2sapi_m2p_Init();
    }
    return 0;
  }

  /**
   * Address: 0x00B01210 (FUN_00B01210, _M2P_Finish)
   *
   * What it does:
   * Calls M2P backend shutdown callback lane.
   */
  std::int32_t M2P_Finish()
  {
    if (m2sapi_m2p_Finish != nullptr) {
      return m2sapi_m2p_Finish();
    }
    return 0;
  }

  /**
   * Address: 0x00B01220 (FUN_00B01220, _M2P_IsConformable)
   *
   * What it does:
   * Queries stream conformance support from linked M2P backend.
   */
  std::int32_t M2P_IsConformable()
  {
    if (m2sapi_m2p_IsConformable != nullptr) {
      return m2sapi_m2p_IsConformable();
    }
    return 0;
  }

  /**
   * Address: 0x00B01230 (FUN_00B01230, _M2P_Create)
   *
   * What it does:
   * Creates one M2P parser runtime through linked backend callback lane.
   */
  std::int32_t M2P_Create()
  {
    if (m2sapi_m2p_Create != nullptr) {
      return m2sapi_m2p_Create();
    }
    return 0;
  }

  /**
   * Address: 0x00B01240 (FUN_00B01240, _M2P_Destroy)
   *
   * What it does:
   * Destroys one M2P parser runtime through linked backend callback lane.
   */
  std::int32_t M2P_Destroy()
  {
    if (m2sapi_m2p_Destroy != nullptr) {
      return m2sapi_m2p_Destroy();
    }
    return 0;
  }

  /**
   * Address: 0x00B01250 (FUN_00B01250, _M2P_SetErrFn)
   *
   * What it does:
   * Applies error-callback lane configuration on linked M2P backend.
   */
  std::int32_t M2P_SetErrFn()
  {
    if (m2sapi_m2p_SetErrFn != nullptr) {
      return m2sapi_m2p_SetErrFn();
    }
    return 0;
  }

  /**
   * Address: 0x00B01260 (FUN_00B01260, _M2P_GetStat)
   *
   * What it does:
   * Reads M2P backend status lane; returns default `1` when callback is absent.
   */
  std::int32_t M2P_GetStat()
  {
    if (m2sapi_m2p_GetStat != nullptr) {
      return m2sapi_m2p_GetStat();
    }
    return 1;
  }

  /**
   * Address: 0x00B01280 (FUN_00B01280, _M2P_TermSupply)
   *
   * What it does:
   * Calls M2P backend supply-termination callback lane.
   */
  std::int32_t M2P_TermSupply()
  {
    if (m2sapi_m2p_TermSupply != nullptr) {
      return m2sapi_m2p_TermSupply();
    }
    return 0;
  }

  /**
   * Address: 0x00B01290 (FUN_00B01290, _M2P_DecHd)
   *
   * What it does:
   * Calls M2P backend header-decode callback lane.
   */
  std::int32_t M2P_DecHd()
  {
    if (m2sapi_m2p_DecHd != nullptr) {
      return m2sapi_m2p_DecHd();
    }
    return 0;
  }

  /**
   * Address: 0x00B012A0 (FUN_00B012A0, _M2P_SetAccessUnitTable)
   *
   * What it does:
   * Forwards access-unit table configuration lane to linked M2P backend.
   */
  std::int32_t M2P_SetAccessUnitTable()
  {
    if (m2sapi_m2p_SetAccessUnitTable != nullptr) {
      return m2sapi_m2p_SetAccessUnitTable();
    }
    return 0;
  }

  /**
   * Address: 0x00B012B0 (FUN_00B012B0, _M2P_SetPsMapFn)
   *
   * What it does:
   * Forwards PS-map callback lane configuration to linked M2P backend.
   */
  std::int32_t M2P_SetPsMapFn()
  {
    if (m2sapi_m2p_SetPsMapFn != nullptr) {
      return m2sapi_m2p_SetPsMapFn();
    }
    return 0;
  }

  /**
   * Address: 0x00B012C0 (FUN_00B012C0, _M2P_SetPesFn)
   *
   * What it does:
   * Forwards PES callback lane configuration to linked M2P backend.
   */
  std::int32_t M2P_SetPesFn()
  {
    if (m2sapi_m2p_SetPesFn != nullptr) {
      return m2sapi_m2p_SetPesFn();
    }
    return 0;
  }

  /**
   * Address: 0x00B05520 (FUN_00B05520, _M2V_IsSetup)
   *
   * What it does:
   * Returns global M2V setup-state lane.
   */
  std::int32_t M2V_IsSetup()
  {
    return m2vapi_issetup;
  }

  /**
   * Address: 0x00B05530 (FUN_00B05530, _M2V_GetVersionStr)
   *
   * What it does:
   * Returns backend-reported M2V version string when callback is linked.
   */
  const char* M2V_GetVersionStr()
  {
    if (m2vapi_GetVersionStr != nullptr) {
      return m2vapi_GetVersionStr();
    }
    return nullptr;
  }

  /**
   * Address: 0x00B05540 (FUN_00B05540, _M2V_IsConformable)
   *
   * What it does:
   * Queries whether linked M2V backend supports current stream conformance.
   */
  std::int32_t M2V_IsConformable()
  {
    if (m2vapi_IsConformable != nullptr) {
      return m2vapi_IsConformable();
    }
    return 0;
  }

  /**
   * Address: 0x00B05550 (FUN_00B05550, _M2V_Init)
   *
   * What it does:
   * Calls linked M2V backend initialization lane.
   */
  std::int32_t M2V_Init()
  {
    if (m2vapi_Init != nullptr) {
      return m2vapi_Init();
    }
    return 0;
  }

  /**
   * Address: 0x00B05560 (FUN_00B05560, _M2V_Finish)
   *
   * What it does:
   * Calls linked M2V backend shutdown lane.
   */
  std::int32_t M2V_Finish()
  {
    if (m2vapi_Finish != nullptr) {
      return m2vapi_Finish();
    }
    return 0;
  }

  /**
   * Address: 0x00B05570 (FUN_00B05570, _M2V_Create)
   *
   * What it does:
   * Creates one M2V backend decoder handle when create callback is linked.
   */
  std::int32_t M2V_Create()
  {
    if (m2vapi_Create != nullptr) {
      return m2vapi_Create();
    }
    return 0;
  }

  /**
   * Address: 0x00B05580 (FUN_00B05580, _M2V_Destroy)
   *
   * What it does:
   * Destroys one M2V backend decoder handle when destroy callback is linked.
   */
  std::int32_t M2V_Destroy(const std::int32_t decoderHandle)
  {
    if (m2vapi_Destroy != nullptr) {
      return m2vapi_Destroy(decoderHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B05590 (FUN_00B05590, _M2V_SetCond)
   *
   * What it does:
   * Applies currently staged condition lanes to linked M2V backend.
   */
  std::int32_t M2V_SetCond()
  {
    if (m2vapi_SetCond != nullptr) {
      return m2vapi_SetCond();
    }
    return 0;
  }

  /**
   * Address: 0x00B055A0 (FUN_00B055A0, _M2V_SetMbCb)
   *
   * What it does:
   * Dispatches macroblock-callback installation to the linked M2V backend when
   * available.
   */
  std::int32_t M2V_SetMbCb(const std::uintptr_t macroblockCallback)
  {
    if (m2vapi_SetMbCb != nullptr) {
      return m2vapi_SetMbCb(macroblockCallback);
    }
    return 0;
  }

  /**
   * Address: 0x00B055B0 (FUN_00B055B0, _M2V_SetErrFunc)
   *
   * What it does:
   * Dispatches M2V error-callback installation to the backend when linked.
   */
  std::int32_t M2V_SetErrFunc(const std::uintptr_t errorCallback)
  {
    if (m2vapi_SetErrFunc != nullptr) {
      return m2vapi_SetErrFunc(errorCallback);
    }
    return 0;
  }

  /**
   * Address: 0x00B055C0 (FUN_00B055C0, _M2V_GetErrInf)
   *
   * What it does:
   * Requests decoder error information from the linked M2V backend.
   */
  std::int32_t M2V_GetErrInf()
  {
    if (m2vapi_GetErrInf != nullptr) {
      return m2vapi_GetErrInf();
    }
    return 0;
  }

  /**
   * Address: 0x00B055D0 (FUN_00B055D0, _M2V_DecodeFrm)
   *
   * What it does:
   * Dispatches one frame decode request to the linked M2V backend.
   */
  std::int32_t M2V_DecodeFrm(
    const std::int32_t decoderHandle,
    const std::int32_t decodeMode,
    const std::int32_t decodeFlags
  )
  {
    if (m2vapi_DecodeFrm != nullptr) {
      return m2vapi_DecodeFrm(decoderHandle, decodeMode, decodeFlags);
    }
    return 0;
  }

  /**
   * Address: 0x00B055E0 (FUN_00B055E0, _M2V_SkipFrm)
   *
   * What it does:
   * Forwards frame-skip requests to the linked M2V backend.
   */
  std::int32_t M2V_SkipFrm(const std::int32_t decoderHandle)
  {
    if (m2vapi_SkipFrm != nullptr) {
      return m2vapi_SkipFrm(decoderHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B055F0 (FUN_00B055F0, _M2V_SetUsrSj)
   *
   * What it does:
   * Configures one user side-data slot lane on the linked M2V backend.
   */
  std::int32_t M2V_SetUsrSj(
    const std::int32_t decoderHandle,
    const std::int32_t userSlotIndex,
    const std::int32_t lane0,
    const std::int32_t lane1,
    const std::int32_t lane2
  )
  {
    if (m2vapi_SetUsrSj != nullptr) {
      return m2vapi_SetUsrSj(decoderHandle, userSlotIndex, lane0, lane1, lane2);
    }
    return 0;
  }

  /**
   * Address: 0x00B05600 (FUN_00B05600, _M2V_SetPicUsrBuf)
   *
   * What it does:
   * Publishes caller-owned picture-user buffer lanes to the M2V backend.
   */
  std::int32_t M2V_SetPicUsrBuf(
    const std::int32_t decoderHandle,
    const std::uintptr_t userBufferAddress,
    const std::int32_t userBufferSizeBytes
  )
  {
    if (m2vapi_SetPicUsrBuf != nullptr) {
      return m2vapi_SetPicUsrBuf(decoderHandle, userBufferAddress, userBufferSizeBytes);
    }
    return 0;
  }

  /**
   * Address: 0x00B05610 (FUN_00B05610, _M2V_GetPicUsr)
   *
   * What it does:
   * Reads decoded picture-user metadata into caller-provided output storage.
   */
  std::int32_t M2V_GetPicUsr(
    const std::int32_t decoderHandle,
    const std::int32_t userSlotIndex,
    void* const outUserBuffer
  )
  {
    if (m2vapi_GetPicUsr != nullptr) {
      return m2vapi_GetPicUsr(decoderHandle, userSlotIndex, outUserBuffer);
    }
    return 0;
  }

  /**
   * Address: 0x00B05620 (FUN_00B05620, _M2V_DecodePicAtr)
   *
   * What it does:
   * Decodes picture-attribute payload lanes through the linked M2V backend.
   */
  std::int32_t M2V_DecodePicAtr(const std::int32_t decoderHandle, const std::int32_t decodeMode)
  {
    if (m2vapi_DecodePicAtr != nullptr) {
      return m2vapi_DecodePicAtr(decoderHandle, decodeMode);
    }
    return 0;
  }

  /**
   * Address: 0x00B05630 (FUN_00B05630, _M2V_GetPicAtr)
   *
   * What it does:
   * Copies current picture-attribute lanes from the M2V backend.
   */
  std::int32_t M2V_GetPicAtr(const std::int32_t decoderHandle, void* const outPictureAttributes)
  {
    if (m2vapi_GetPicAtr != nullptr) {
      return m2vapi_GetPicAtr(decoderHandle, outPictureAttributes);
    }
    return 0;
  }

  /**
   * Address: 0x00B05640 (FUN_00B05640, _M2V_GetBitRate)
   *
   * What it does:
   * Reads the current stream bitrate lane from the linked M2V backend.
   */
  std::int32_t M2V_GetBitRate(const std::int32_t decoderHandle, std::int32_t* const outBitRate)
  {
    if (m2vapi_GetBitRate != nullptr) {
      return m2vapi_GetBitRate(decoderHandle, outBitRate);
    }
    return 0;
  }

  /**
   * Address: 0x00B05650 (FUN_00B05650, _M2V_GetVbvBufSiz)
   *
   * What it does:
   * Reads VBV buffer-size and related picture-buffer lanes from the M2V backend.
   */
  std::int32_t M2V_GetVbvBufSiz(
    const std::int32_t decoderHandle,
    std::int32_t* const outVbvBufferSize,
    std::int32_t* const outVbvPayloadSize,
    void* const outVbvFlags
  )
  {
    if (m2vapi_GetVbvBufSiz != nullptr) {
      return m2vapi_GetVbvBufSiz(decoderHandle, outVbvBufferSize, outVbvPayloadSize, outVbvFlags);
    }
    return 0;
  }

  /**
   * Address: 0x00B05660 (FUN_00B05660, _M2V_GetLinkFlg)
   *
   * What it does:
   * Reads decoder link-flag lanes from the linked M2V backend.
   */
  std::int32_t M2V_GetLinkFlg(
    const std::int32_t decoderHandle,
    std::int32_t* const outLinkFlag,
    std::int32_t* const outLinkState
  )
  {
    if (m2vapi_GetLinkFlg != nullptr) {
      return m2vapi_GetLinkFlg(decoderHandle, outLinkFlag, outLinkState);
    }
    return 0;
  }

  /**
   * Address: 0x00B05670 (FUN_00B05670)
   *
   * What it does:
   * Clears four 32-bit state lanes and returns input pointer.
   */
  std::uint32_t* MPVCMC_ResetStateWords(std::uint32_t* const stateWords)
  {
    stateWords[0] = 0;
    stateWords[1] = 0;
    stateWords[2] = 0;
    stateWords[3] = 0;
    return stateWords;
  }

  /**
   * Address: 0x00B05690 (FUN_00B05690, _DCT_GetVerStr)
   *
   * What it does:
   * Publishes and returns static CRI DCT build/version banner.
   */
  const char* DCT_GetVerStr()
  {
    gCriVersionStringDct = kDctBuildVersion;
    return kDctBuildVersion;
  }

  /**
   * Address: 0x00B056A0 (FUN_00B056A0, _DCT_AcInit)
   *
   * What it does:
   * Initializes forward/inverse 8x8 DCT coefficient tables.
   */
  char* DCT_AcInit()
  {
    gDctAcVersionStringCache = DCT_GetVerStr();

    constexpr double kFirstRowScale = 0.3535533905932738;
    constexpr double kOtherRowsScale = 0.5;
    constexpr double kAngleScale = 0.3926990816987241;

    for (std::int32_t row = 0; row < 8; ++row) {
      const double rowScale = (row == 0) ? kFirstRowScale : kOtherRowsScale;
      for (std::int32_t col = 0; col < 8; ++col) {
        const double value = std::cos((static_cast<double>(col) + 0.5) * static_cast<double>(row) * kAngleScale) * rowScale;
        gDctAcInverseTransformMatrix[static_cast<std::size_t>((row * 8) + col)] = value;
        gDctAcForwardTransformMatrix[static_cast<std::size_t>((col * 8) + row)] = value;
      }
    }

    return reinterpret_cast<char*>(gDctAcInverseTransformMatrix.data()) + sizeof(gDctAcInverseTransformMatrix);
  }

  /**
   * Address: 0x00B058E0 (FUN_00B058E0, _dctac_TransDouble)
   *
   * What it does:
   * Applies two-pass 8x8 DCT matrix transform using caller-provided coefficient
   * matrix.
   */
  std::int32_t dctac_TransDouble(
    const double* const inputCoefficients,
    double* const outputCoefficients,
    const double* const transformMatrix
  )
  {
    std::array<double, 64> scratch{};

    for (std::int32_t row = 0; row < 8; ++row) {
      for (std::int32_t col = 0; col < 8; ++col) {
        double sum = 0.0;
        for (std::int32_t k = 0; k < 8; ++k) {
          sum += inputCoefficients[(row * 8) + k] * transformMatrix[(k * 8) + col];
        }
        scratch[static_cast<std::size_t>((row * 8) + col)] = sum;
      }
    }

    for (std::int32_t row = 0; row < 8; ++row) {
      for (std::int32_t col = 0; col < 8; ++col) {
        double sum = 0.0;
        for (std::int32_t k = 0; k < 8; ++k) {
          sum += scratch[static_cast<std::size_t>(row + (k * 8))] * transformMatrix[(k * 8) + col];
        }
        outputCoefficients[row + (col * 8)] = sum;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B058A0 (FUN_00B058A0, _DCT_AcFdctDouble)
   *
   * What it does:
   * Runs forward DCT transform over one 8x8 double matrix.
   */
  std::int32_t DCT_AcFdctDouble(const double* const inputCoefficients, double* const outputCoefficients)
  {
    return dctac_TransDouble(inputCoefficients, outputCoefficients, gDctAcForwardTransformMatrix.data());
  }

  /**
   * Address: 0x00B058C0 (FUN_00B058C0, _DCT_AcIdctDouble)
   *
   * What it does:
   * Runs inverse DCT transform over one 8x8 double matrix.
   */
  std::int32_t DCT_AcIdctDouble(const double* const inputCoefficients, double* const outputCoefficients)
  {
    return dctac_TransDouble(inputCoefficients, outputCoefficients, gDctAcInverseTransformMatrix.data());
  }

  /**
   * Address: 0x00B05720 (FUN_00B05720, _DCT_AcFdctShort)
   *
   * What it does:
   * Converts 8x8 signed-16 input to double domain, applies FDCT, rounds with
   * `floor(x+0.5)`, and clamps to [-2048, 2047].
   */
  std::int32_t DCT_AcFdctShort(const std::int16_t* const inputCoefficients, std::int16_t* const outputCoefficients)
  {
    std::array<double, 64> coefficients{};
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
      coefficients[i] = static_cast<double>(inputCoefficients[i]);
    }

    (void)DCT_AcFdctDouble(coefficients.data(), coefficients.data());

    for (std::size_t i = 0; i < coefficients.size(); ++i) {
      std::int32_t value = static_cast<std::int32_t>(std::floor(coefficients[i] + 0.5));
      if (value > 2047) {
        value = 2047;
      } else if (value < -2048) {
        value = -2048;
      }
      outputCoefficients[i] = static_cast<std::int16_t>(value);
    }
    return 0;
  }

  /**
   * Address: 0x00B057E0 (FUN_00B057E0, _DCT_AcIdctShort)
   *
   * What it does:
   * Converts 8x8 signed-16 input to double domain, applies IDCT, rounds with
   * `floor(x+0.5)`, and clamps to [-256, 255].
   */
  std::int32_t DCT_AcIdctShort(const std::int16_t* const inputCoefficients, std::int16_t* const outputCoefficients)
  {
    std::array<double, 64> coefficients{};
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
      coefficients[i] = static_cast<double>(inputCoefficients[i]);
    }

    (void)DCT_AcIdctDouble(coefficients.data(), coefficients.data());

    for (std::size_t i = 0; i < coefficients.size(); ++i) {
      std::int32_t value = static_cast<std::int32_t>(std::floor(coefficients[i] + 0.5));
      if (value > 255) {
        value = 255;
      } else if (value < -256) {
        value = -256;
      }
      outputCoefficients[i] = static_cast<std::int16_t>(value);
    }
    return 0;
  }

  /**
   * Address: 0x00B0A320 (FUN_00B0A320, _ADXT_GetVersion)
   *
   * What it does:
   * Returns static ADXT build/version banner text.
   */
  const char* ADXT_GetVersion()
  {
    return kAdxtBuildVersion;
  }

  /**
   * Address: 0x00B0A330 (FUN_00B0A330, _ADXT_ConfigVsyncSvr)
   *
   * What it does:
   * Stores ADXT vsync-server enable lane and returns stored value.
   */
  std::int32_t ADXT_ConfigVsyncSvr(const std::int32_t enableVsyncServer)
  {
    gAdxtVsyncServerEnabled = enableVsyncServer;
    return enableVsyncServer;
  }

  /**
   * Address: 0x00B0A340 (FUN_00B0A340, _adxini_rnaerr_cbfn)
   *
   * What it does:
   * Bridges ADXRNA error callback text into ADXERR reporter lane.
   */
  void adxini_rnaerr_cbfn(const std::int32_t /*errorObject*/, const char* const message)
  {
    (void)ADXERR_CallErrFunc1_(message);
  }

  /**
   * Address: 0x00B0A350 (FUN_00B0A350, _adxini_lscerr_cbfn)
   *
   * What it does:
   * Bridges LSC error callback messages into the shared ADX error reporter.
   */
  [[maybe_unused]] void adxini_lscerr_cbfn(const std::int32_t /*errorObject*/, const char* const message)
  {
    (void)ADXERR_CallErrFunc1_(message);
  }

  /**
   * Address: 0x00B0A360 (FUN_00B0A360, _ADXT_VsyncProc)
   *
   * What it does:
   * Increments global ADXT vsync counter and runs one ADXT server tick.
   */
  void ADXT_VsyncProc()
  {
    ++gAdxtVsyncCount;
    ADXT_ExecServer();
  }

  /**
   * Address: 0x00B0A370 (FUN_00B0A370, _adxt_exec_tsvr)
   *
   * What it does:
   * SVM callback thunk that runs one ADXT decode-server tick.
   */
  std::int32_t adxt_exec_tsvr()
  {
    ADXT_ExecServer();
    return 0;
  }

  /**
   * Address: 0x00B0A380 (FUN_00B0A380, _adxt_exec_fssvr)
   *
   * What it does:
   * SVM callback thunk that runs one ADXT filesystem-server tick.
   */
  std::int32_t adxt_exec_fssvr()
  {
    ADXT_ExecFsSvr();
    return 0;
  }

  /**
   * Address: 0x00B0A480 (FUN_00B0A480, _adxt_exec_main_thrd)
   *
   * What it does:
   * SVM callback thunk that runs one ADXT seamless-LSC server tick.
   */
  std::int32_t adxt_exec_main_thrd()
  {
    adxt_ExecLscSvr();
    return 0;
  }

  /**
   * Address: 0x00B0A490 (FUN_00B0A490, _ADXT_ResetLibrary)
   *
   * What it does:
   * Resets ADXT init-reference lane and reruns ADXT global initialization.
   */
  void ADXT_ResetLibrary()
  {
    gAdxtInitCount = 0;
    ADXT_Init();
  }

  /**
   * Address: 0x00B18FD0 (FUN_00B18FD0, _adxt_EntryFnameRange)
   *
   * What it does:
   * Enqueues one filename range into ADXT seamless LSC queue.
   */
  [[maybe_unused]] std::int32_t adxt_EntryFnameRange(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const std::int32_t result = lsc_EntryFileRange(runtime->SeamlessLscHandle(), fileName, 0, rangeStart, rangeEnd);
    if (result < 0) {
      return ADXERR_CallErrFunc2_(kAdxtErrCannotEntryFilePrefix, fileName);
    }
    return result;
  }

  /**
   * Address: 0x00B18F80 (FUN_00B18F80, _adxt_EntryFname)
   *
   * What it does:
   * Enqueues one filename with full-range seamless playback bounds.
   */
  [[maybe_unused]] std::int32_t adxt_EntryFname(void* const adxtRuntime, const char* const fileName)
  {
    return adxt_EntryFnameRange(adxtRuntime, fileName, 0, kLscRangeEndAll);
  }

  /**
   * Address: 0x00B19040 (FUN_00B19040, _adxt_EntryAfs)
   *
   * What it does:
   * Resolves one AFS entry into filename/range and enqueues it into seamless
   * LSC queue.
   */
  [[maybe_unused]] std::int32_t adxt_EntryAfs(
    void* const adxtRuntime,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    std::int32_t startOffset = 0;
    std::int32_t rangeStart = 0;
    std::int32_t rangeEnd = 0;
    if (ADXF_GetFnameRangeEx(
          afsHandle,
          fileIndex,
          runtime->SeamlessAfsNameBuffer(),
          &startOffset,
          &rangeStart,
          &rangeEnd
        ) == 0) {
      const char* const fileName = ADXF_GetFnameFromPt(afsHandle);
      return lsc_EntryFileRange(runtime->SeamlessLscHandle(), fileName, startOffset, rangeStart, rangeEnd);
    }

    char entryIdText[16]{};
    ADXERR_ItoA2(afsHandle, fileIndex, entryIdText, static_cast<std::int32_t>(sizeof(entryIdText)));
    return ADXERR_CallErrFunc2_(kAdxtErrEntryAfsCannotEntryPrefix, entryIdText);
  }

  /**
   * Address: 0x00B190F0 (FUN_00B190F0, _adxt_StartSeamless)
   *
   * What it does:
   * Starts ADXT seamless path by resetting non-LSC playback, preparing SJ input
   * path, and starting LSC queue playback.
   */
  [[maybe_unused]] std::int32_t adxt_StartSeamless(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    void* const lscHandle = runtime->SeamlessLscHandle();

    ADXT_StopWithoutLsc(runtime);
    ADXCRS_Lock();
    adxt_start_sj(runtime, runtime->sourceRingHandle);
    if (runtime->streamJoinInputHandle != nullptr) {
      runtime->streamJoinInputHandle->OnSeamlessStart();
    }

    const std::int32_t flowLimit = static_cast<std::int32_t>(runtime->SeamlessFlowSectorHint()) << 11;
    runtime->mUnknown02 = 4;
    (void)lsc_SetFlowLimit(lscHandle, flowLimit);
    ADXCRS_Unlock();

    lsc_Start(lscHandle);
    return ADXT_SetLnkSw(runtime, 1);
  }

  /**
   * Address: 0x00B0E830 (FUN_00B0E830, _ADXT_GetStm)
   *
   * What it does:
   * Returns ADXT stream handle lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetStm(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t streamHandle = adxt_GetStm(adxtRuntime);
    ADXCRS_Leave();
    return streamHandle;
  }

  /**
   * Address: 0x00B0E850 (FUN_00B0E850, _adxt_GetStm)
   *
   * What it does:
   * Returns ADXT runtime stream handle lane.
   */
  std::int32_t adxt_GetStm(void* const adxtRuntime)
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(static_cast<AdxtRuntimeState*>(adxtRuntime)->streamHandle));
  }

  /**
   * Address: 0x00B0E860 (FUN_00B0E860, _ADXT_TermSupply)
   *
   * What it does:
   * Runs ADXT terminate-supply request under ADXCRS enter/leave guards.
   */
  void ADXT_TermSupply(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    (void)adxt_TermSupply(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E880 (FUN_00B0E880, _adxt_TermSupply)
   *
   * What it does:
   * Forwards ADXT terminate-supply request to ADXSJD runtime.
   */
  std::int32_t adxt_TermSupply(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return ADXSJD_TermSupply(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0E890 (FUN_00B0E890, _ADXT_SetDrctLvl)
   *
   * What it does:
   * Legacy direct-level setter stub lane.
   */
  void ADXT_SetDrctLvl()
  {
  }

  /**
   * Address: 0x00B0E8A0 (FUN_00B0E8A0, _ADXT_GetDrctLvl)
   *
   * What it does:
   * Legacy direct-level getter stub lane; always returns zero.
   */
  std::int32_t ADXT_GetDrctLvl()
  {
    return 0;
  }

  /**
   * Address: 0x00B0E8B0 (FUN_00B0E8B0, _ADXT_SetFx)
   *
   * What it does:
   * Legacy effect setter stub lane.
   */
  void ADXT_SetFx()
  {
  }

  /**
   * Address: 0x00B0E8C0 (FUN_00B0E8C0, _ADXT_GetFx)
   *
   * What it does:
   * Legacy effect getter stub lane.
   */
  void ADXT_GetFx()
  {
  }

  /**
   * Address: 0x00B0E8D0 (FUN_00B0E8D0, _ADXT_SetFilter)
   *
   * What it does:
   * Legacy filter setter stub lane.
   */
  void ADXT_SetFilter()
  {
  }

  /**
   * Address: 0x00B0E8E0 (FUN_00B0E8E0, _ADXT_GetFilter)
   *
   * What it does:
   * Legacy filter getter stub lane.
   */
  void ADXT_GetFilter()
  {
  }

  /**
   * Address: 0x00B0EA70 (FUN_00B0EA70, _ADXT_GetLnkSw)
   *
   * What it does:
   * Internal ADXT link-switch lane: stores requested switch byte in runtime
   * state and forwards it to SJD lane when available.
   */
  std::int32_t adxt_SetLnkSwInternal(void* const adxtRuntime, const std::int32_t enabled)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    runtime->linkSwitchRequested = static_cast<std::uint8_t>(enabled);
    if (runtime->sjdHandle != 0) {
      return ADXSJD_SetLnkSw(runtime->sjdHandle, enabled);
    }
    return runtime->sjdHandle;
  }

  /**
   * Address: 0x00B0EA50 (FUN_00B0EA50, _ADXT_SetLnkSw)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT link-switch update lane.
   */
  std::int32_t ADXT_SetLnkSw(void* const adxtRuntime, const std::int32_t enabled)
  {
    ADXCRS_Enter();
    const std::int32_t result = adxt_SetLnkSwInternal(adxtRuntime, enabled);
    ADXCRS_Leave();
    return result;
  }

  /**
   * Address: 0x00B0CAE0 (FUN_00B0CAE0, _ADXT_GetEosSct)
   *
   * What it does:
   * Returns current ADXT stream end-sector override used by `_adxt_start_stm`.
   */
  [[maybe_unused]] std::int32_t ADXT_GetEosSct()
  {
    return gAdxtStreamEosSector;
  }

  /**
   * Address: 0x00B0CAF0 (FUN_00B0CAF0, _ADXT_SetEosSct)
   *
   * What it does:
   * Updates ADXT stream end-sector override used by `_adxt_start_stm`.
   */
  [[maybe_unused]] std::int32_t ADXT_SetEosSct(const std::int32_t eosSector)
  {
    gAdxtStreamEosSector = eosSector;
    return eosSector;
  }

  /**
   * Address: 0x00B0D090 (FUN_00B0D090, _adxt_start_sj)
   *
   * What it does:
   * Starts ADXT decode from one SJ input object, resets playback timing lanes,
   * and starts optional channel-expansion lane when present.
   */
  std::int32_t adxt_start_sj(void* const adxtRuntime, void* const sourceJoinHandle)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const std::int32_t maxChannels = static_cast<std::int32_t>(runtime->maxChannelCount);
    for (std::int32_t lane = 0; lane < maxChannels; ++lane) {
      runtime->SourceChannelRingLane(lane)->Destroy();
    }

    ADXSJD_SetInSj(runtime->sjdHandle, sourceJoinHandle);
    runtime->streamJoinInputHandle = static_cast<AdxtStreamJoinHandle*>(sourceJoinHandle);

    const std::int32_t startResult = ADXSJD_Start(runtime->sjdHandle);
    runtime->mUnknown01 = 1;
    runtime->StreamStartScratchWord() = 0;
    runtime->StreamStartLatchByte() = 0;
    runtime->StreamEndSector() = 0x7FFFFFFF;
    runtime->StreamLoopStartSample() = -1;
    runtime->PlaybackTimeBaseFrames() = 0;
    runtime->PlaybackTimeDeltaFrames() = 0;
    runtime->PlaybackTimeVsyncAnchor() = gAdxtVsyncCount;
    runtime->StreamDecodeWindowState() = 0;

    if (runtime->channelExpandHandle != nullptr) {
      return ADXAMP_Start(runtime->channelExpandHandle);
    }

    return startResult;
  }

  /**
   * Address: 0x00B0D130 (FUN_00B0D130, _adxt_start_stm)
   *
   * What it does:
   * Rebinds ADXT stream file range and starts stream + SJ decode chain for one
   * runtime object.
   */
  [[maybe_unused]] std::int32_t adxt_start_stm(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    ADXSTM_SetBufSize(
      runtime->streamHandle,
      static_cast<std::int32_t>(runtime->SeamlessFlowSectorHint()) << 11,
      static_cast<std::int32_t>(runtime->StreamBufferSectorLimitHint()) << 11
    );
    ADXSTM_SetEos(runtime->streamHandle, gAdxtStreamEosSector);
    ADXSTM_EntryEosFunc(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(runtime->streamHandle)),
      0,
      0
    );
    ADXSTM_Seek(runtime->streamHandle, 0);
    ADXSTM_StopNw(runtime->streamHandle);
    ADXSTM_ReleaseFileNw(runtime->streamHandle);
    ADXSTM_BindFileNw(runtime->streamHandle, fileName, startOffset, rangeStart, rangeEnd);
    ADXSTM_Start(runtime->streamHandle);
    return adxt_start_sj(runtime, runtime->sourceRingHandle);
  }

  /**
   * Address: 0x00B0D1C0 (FUN_00B0D1C0, _ADXT_StartSj)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT SJ-start lane.
   */
  [[maybe_unused]] void ADXT_StartSj(void* const adxtRuntime, void* const sourceJoinHandle)
  {
    ADXCRS_Enter();
    adxt_StartSj(adxtRuntime, sourceJoinHandle);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D1E0 (FUN_00B0D1E0, _adxt_StartSj)
   *
   * What it does:
   * Validates runtime + SJ handle, stops current ADXT lane, starts SJ input
   * path, sets ADXT mode byte to SJ mode (`3`), and enables link-switch lane.
   */
  [[maybe_unused]] void adxt_StartSj(void* const adxtRuntime, void* const sourceJoinHandle)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr || sourceJoinHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtErrStartSjParameter);
      return;
    }

    adxt_Stop(runtime);
    ADXCRS_Lock();
    adxt_start_sj(runtime, sourceJoinHandle);
    runtime->mUnknown02 = 3;
    (void)adxt_SetLnkSwInternal(runtime, 1);
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0D230 (FUN_00B0D230, _ADXT_StopWithoutLsc)
   *
   * What it does:
   * Guard wrapper for the internal non-LSC ADXT stop lane.
   */
  void ADXT_StopWithoutLsc(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_StopWithoutLsc(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D250 (FUN_00B0D250, _adxt_StopWithoutLsc)
   *
   * What it does:
   * Stops ADXT decode/transfer lanes while keeping seamless LSC queue owner
   * alive.
   */
  void adxt_StopWithoutLsc(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    ADXCRS_Lock();
    j__ADXRNA_Stop(runtime->rnaHandle);
    j__ADXRNA_SetTransSw(runtime->rnaHandle, 0);
    j__ADXRNA_SetPlaySw(runtime->rnaHandle, 0);
    ADXSJD_Stop(runtime->sjdHandle);

    if (runtime->mUnknown02 == 2 && runtime->streamJoinInputHandle != nullptr) {
      AdxtStreamJoinHandle* const streamJoinHandle = runtime->streamJoinInputHandle;
      runtime->streamJoinInputHandle = nullptr;
      streamJoinHandle->Reserved0C();
    }

    if (runtime->channelExpandHandle != nullptr) {
      ADXAMP_Stop(runtime->channelExpandHandle);
    }

    runtime->streamJoinInputHandle = nullptr;
    runtime->mUnknown01 = 0;
    runtime->linkSwitchActive = 0;
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0D2D0 (FUN_00B0D2D0, _ADXT_Stop)
   *
   * What it does:
   * Guard wrapper for the ADXT stop lane.
   */
  void ADXT_Stop(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_Stop(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D2F0 (FUN_00B0D2F0, _adxt_Stop)
   *
   * What it does:
   * Stops one ADXT runtime lane, including optional codec-side stop callbacks,
   * seamless LSC lane stop, and shared non-LSC stop cleanup.
   */
  void adxt_Stop(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtStopParameterErrorMessage);
      return;
    }

    if (mpastopfunc != nullptr) {
      ADXSJD_Stop(runtime->sjdHandle);
      mpastopfunc(runtime);
    }
    if (m2astopfunc != nullptr) {
      ADXSJD_Stop(runtime->sjdHandle);
      m2astopfunc(runtime);
    }

    if (runtime->streamHandle != nullptr) {
      ADXSTM_ReleaseFileNw(runtime->streamHandle);
    }

    if (runtime->mUnknown02 == 4) {
      lsc_Stop(runtime->SeamlessLscHandle());
      if (runtime->streamJoinInputHandle != nullptr) {
        runtime->streamJoinInputHandle->OnSeamlessStart();
      }
    }

    adxt_StopWithoutLsc(runtime);
  }

  void ADXF_CloseAll();

  /**
   * Address: 0x00B15810 (FUN_00B15810, sub_B15810)
   * Also emitted at: 0x00B17CA0 (FUN_00B17CA0)
   *
   * What it does:
   * Returns ADXRNA state byte.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStateByte(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return static_cast<std::int32_t>(AsAdxrnaStateControlRuntimeView(rnaHandle)->stateByte);
  }

  /**
   * Address: 0x00B15960 (FUN_00B15960, sub_B15960)
   * Also emitted at: 0x00B17CC0 (FUN_00B17CC0)
   *
   * What it does:
   * Stores one ADXRNA control word at lane `0x44`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetControlWord44(const std::int32_t rnaHandle, const std::int32_t controlWord)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    AsAdxrnaStateControlRuntimeView(rnaHandle)->flowLimitWord = controlWord;
    return rnaHandle;
  }

  /**
   * Address: 0x00B15F40 (FUN_00B15F40, _mwRnaCalcSfreq)
   *
   * What it does:
   * Computes effective ADXRNA sample frequency from transpose lanes and base
   * sample-rate lane.
   */
  [[maybe_unused]] std::int32_t mwRnaCalcSfreq(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    const auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    const double semitoneCents = static_cast<double>(runtime->transposeCents + (100 * runtime->transposeOctaves));
    const double ratio = std::pow(2.0, semitoneCents / 1200.0);
    const double scaledSfreq = ratio * static_cast<double>(runtime->timeScaleBase);
    if (scaledSfreq <= static_cast<double>(0x7FFFFFFF)) {
      return static_cast<std::int32_t>(scaledSfreq);
    }

    CRIERR_CallErr(kMwRnaCalcSfreqIllegalParameterMessage);
    return 0x7FFFFFFF;
  }

  /**
   * Address: 0x00B15980 (FUN_00B15980, sub_B15980)
   * Also emitted at: 0x00B17D20 (FUN_00B17D20, _ADXRNA_SetBitPerSmpl)
   *
   * What it does:
   * Updates ADXRNA bits-per-sample lane and rescales transfer-capacity lane.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetBitPerSmpl(const std::int32_t rnaHandle, const std::int32_t bitsPerSample)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const runtime = reinterpret_cast<MwlRnaRuntimeView*>(AsAdxrnaRuntimeView(rnaHandle));
    const std::int32_t scaledBits = runtime->transferCapacityBytes * runtime->bitsPerSample;
    const std::int32_t alignedBits = ((scaledBits >> 31) & 7) + scaledBits;
    runtime->transferCapacityBytes = ((alignedBits >> 3) / bitsPerSample) << 3;

    auto* const outputRuntime = AsAdxrnaRuntimeView(rnaHandle)->outputRuntime;
    const std::int32_t dispatchResult = outputRuntime->dispatchTable->setBitsPerSample(outputRuntime, bitsPerSample);
    runtime->bitsPerSample = bitsPerSample;
    return dispatchResult;
  }

  /**
   * Address: 0x00B159D0 (FUN_00B159D0, sub_B159D0)
   * Also emitted at: 0x00B17CE0 (FUN_00B17CE0, _ADXRNA_SetSfreq)
   *
   * What it does:
   * Stores ADXRNA base sample-rate lane and recomputes effective sample
   * frequency lane.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetSfreq(const std::int32_t rnaHandle, const std::int32_t sampleRate)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    runtime->timeScaleBase = sampleRate;
    runtime->calculatedSampleRate = mwRnaCalcSfreq(rnaHandle);
    return runtime->calculatedSampleRate;
  }

  /**
   * Address: 0x00B15A10 (FUN_00B15A10, sub_B15A10)
   *
   * What it does:
   * Forwards one generic lane-`6` control word pair into ADXRNA output
   * dispatch slot `0x4C`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetLane6WordPair(
    const std::int32_t rnaHandle,
    const std::int32_t word0,
    const std::int32_t word1
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const outputRuntime = AsAdxrnaTransportRuntimeView(rnaHandle)->outputRuntime;
    return outputRuntime->dispatchTable->setLaneWordPair(outputRuntime, 6, word0, word1);
  }

  /**
   * Address: 0x00B15A40 (FUN_00B15A40, sub_B15A40)
   * Also emitted at: 0x00B17CF0 (FUN_00B17CF0, _ADXRNA_SetOutVol)
   *
   * What it does:
   * Applies ADXRNA output-volume lane and mirrors clamped value to stream-info
   * lane at `0x60`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetOutVol(const std::int32_t rnaHandle, const std::int32_t volumeLevel)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    if (volumeLevel < 0) {
      const std::int32_t clampedVolume = (volumeLevel <= -999) ? -999 : volumeLevel;
      runtime->streamInfoWordA0 = clampedVolume;
      runtime->streamInfoWord60 = clampedVolume;
      return clampedVolume;
    }

    runtime->streamInfoWordA0 = 0;
    runtime->streamInfoWord60 = 0;
    return 0;
  }

  /**
   * Address: 0x00B15A80 (FUN_00B15A80, sub_B15A80)
   * Also emitted at: 0x00B17D00 (FUN_00B17D00, _ADXRNA_SetOutPan)
   *
   * What it does:
   * Applies one channel output-pan lane with ADXRNA bounds/clamp semantics.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetOutPan(
    const std::int32_t rnaHandle,
    const std::int32_t channelIndex,
    const std::int32_t panLevel
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const runtime = AsAdxrnaRuntimeView(rnaHandle);
    if (channelIndex < 0) {
      return 0;
    }

    const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
    if (channelIndex >= channelCount) {
      return channelCount;
    }

    const std::int32_t clampedPan = ClampAdxrnaPanLevel(panLevel);
    const std::int32_t dispatchResult = runtime->outputRuntime->dispatchTable->setOutputPan(
      runtime->outputRuntime,
      channelIndex,
      clampedPan
    );
    runtime->outputPanByChannel[channelIndex] = clampedPan;
    return dispatchResult;
  }

  /**
   * Address: 0x00B15AE0 (FUN_00B15AE0, sub_B15AE0)
   * Also emitted at: 0x00B17D10 (FUN_00B17D10, _ADXRNA_SetOutBalance)
   *
   * What it does:
   * Applies output-balance lane with ADXRNA clamp semantics and stores
   * clamped balance in stream-info lane `0x6C`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetOutBalance(const std::int32_t rnaHandle, const std::int32_t balanceLevel)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const runtime = AsAdxrnaRuntimeView(rnaHandle);
    auto* const metrics = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    const std::int32_t clampedBalance = ClampAdxrnaPanLevel(balanceLevel);
    const std::int32_t dispatchResult = runtime->outputRuntime->dispatchTable->setOutputBalance(runtime->outputRuntime, clampedBalance);
    metrics->streamInfoWord6C = clampedBalance;
    return dispatchResult;
  }

  /**
   * Address: 0x00B15B40 (FUN_00B15B40, mwRnaSetFx)
   *
   * What it does:
   * Applies ADXRNA FX lane selector/value pair, clamps effect level to
   * `[-45, 0]`, and mirrors both words into stream-info lanes `0x70/0x74`.
   */
  [[maybe_unused]] std::int32_t mwRnaSetFx(
    const std::int32_t rnaHandle,
    const std::int32_t fxLane,
    const std::int32_t fxLevel
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }
    if (fxLane < 0 || fxLane > 16) {
      CRIERR_CallErr(kMwRnaSetFxIllegalChannelMessage);
      return 0;
    }

    const std::int32_t clampedFxLevel = ClampAdxrnaFxLevel(fxLevel);
    auto* const outputRuntime = AsAdxrnaTransportRuntimeView(rnaHandle)->outputRuntime;
    const std::int32_t dispatchResult = outputRuntime->dispatchTable->setLaneWordPair(
      outputRuntime,
      0,
      fxLane,
      clampedFxLevel
    );

    auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    runtime->streamInfoWord70 = fxLane;
    runtime->streamInfoWord74 = clampedFxLevel;
    return dispatchResult;
  }

  /**
   * Address: 0x00B15BB0 (FUN_00B15BB0, sub_B15BB0)
   *
   * What it does:
   * Stores ADXRNA transpose octave/cent lanes and recomputes effective sample
   * frequency.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetTransposeWords(
    const std::int32_t rnaHandle,
    const std::int32_t transposeOctaves,
    const std::int32_t transposeCents
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    runtime->transposeOctaves = transposeOctaves;
    runtime->transposeCents = transposeCents;
    const std::int32_t calculatedSampleRate = mwRnaCalcSfreq(rnaHandle);
    runtime->calculatedSampleRate = calculatedSampleRate;
    return calculatedSampleRate;
  }

  /**
   * Address: 0x00B15BF0 (FUN_00B15BF0, sub_B15BF0)
   *
   * What it does:
   * Writes lane-`2` output word with `[-45, 0]` clamp and mirrors it to
   * stream-info lane `0x88`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetStreamInfoWord88(
    const std::int32_t rnaHandle,
    const std::int32_t streamInfoWord88
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    const std::int32_t clampedWord = ClampAdxrnaFxLevel(streamInfoWord88);
    auto* const outputRuntime = AsAdxrnaTransportRuntimeView(rnaHandle)->outputRuntime;
    const std::int32_t dispatchResult = outputRuntime->dispatchTable->setLaneWordPair(outputRuntime, 2, clampedWord, 0);
    AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->streamInfoWord88 = clampedWord;
    return dispatchResult;
  }

  /**
   * Address: 0x00B15CF0 (FUN_00B15CF0, sub_B15CF0)
   *
   * What it does:
   * Returns ADXRNA FX lane selector/value pair from stream-info lanes
   * `0x70/0x74`.
   */
  [[maybe_unused]] std::int32_t* mwRnaGetFx(
    const std::int32_t rnaHandle,
    std::int32_t* const outFxLane,
    std::int32_t* const outFxLevel
  )
  {
    if (rnaHandle != 0) {
      const auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
      *outFxLane = runtime->streamInfoWord70;
      *outFxLevel = runtime->streamInfoWord74;
      return outFxLevel;
    }

    CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
    *outFxLane = -1;
    *outFxLevel = -1;
    return outFxLane;
  }

  /**
   * Address: 0x00B15D30 (FUN_00B15D30, sub_B15D30)
   *
   * What it does:
   * Returns ADXRNA transpose lanes (`octave`, `cent`) into two output words.
   */
  [[maybe_unused]] std::int32_t* ADXRNA_GetTransposeWords(
    const std::int32_t rnaHandle,
    std::int32_t* const outOctaveWord,
    std::int32_t* const outCentWord
  )
  {
    if (rnaHandle != 0) {
      const auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
      *outOctaveWord = runtime->transposeOctaves;
      *outCentWord = runtime->transposeCents;
      return outCentWord;
    }

    CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
    *outOctaveWord = -1;
    *outCentWord = -1;
    return outOctaveWord;
  }

  /**
   * Address: 0x00B15D70 (FUN_00B15D70, sub_B15D70)
   *
   * What it does:
   * Returns ADXRNA stream-info word at lane `0x88`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamInfoWord88(const std::int32_t rnaHandle)
  {
    if (rnaHandle != 0) {
      return AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->streamInfoWord88;
    }

    CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
    return -1;
  }

  /**
   * Address: 0x00B15DA0 (FUN_00B15DA0, sub_B15DA0)
   *
   * What it does:
   * Returns ADXRNA transport reset-state byte at lane `+0x04`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetTransportResetState(const std::int32_t rnaHandle)
  {
    return static_cast<std::int32_t>(AsAdxrnaTransportRuntimeView(rnaHandle)->transportResetState);
  }

  /**
   * Address: 0x00B15DB0 (FUN_00B15DB0, sub_B15DB0)
   *
   * What it does:
   * Clears ADXRNA transport reset-state byte and returns handle.
   */
  [[maybe_unused]] std::int32_t ADXRNA_ClearTransportResetState(const std::int32_t rnaHandle)
  {
    AsAdxrnaTransportRuntimeView(rnaHandle)->transportResetState = 0;
    return rnaHandle;
  }

  /**
   * Address: 0x00B15DC0 (FUN_00B15DC0, sub_B15DC0)
   *
   * What it does:
   * Stores lane-`3` stream-header word pair and forwards it to output dispatch.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetStreamHeaderLane3(
    const std::int32_t rnaHandle,
    const std::int32_t word0,
    const std::int32_t word1
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    runtime->streamHeaderLane3Word0 = word0;
    runtime->streamHeaderLane3Word1 = word1;

    auto* const outputRuntime = AsAdxrnaTransportRuntimeView(rnaHandle)->outputRuntime;
    return outputRuntime->dispatchTable->setLaneWordPair(outputRuntime, 3, word0, word1);
  }

  /**
   * Address: 0x00B15E00 (FUN_00B15E00, sub_B15E00)
   *
   * What it does:
   * Returns stored lane-`3` stream-header word pair.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamHeaderLane3(
    const std::int32_t rnaHandle,
    std::int32_t* const outWord0,
    std::int32_t* const outWord1
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    const auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
    *outWord0 = runtime->streamHeaderLane3Word0;
    *outWord1 = runtime->streamHeaderLane3Word1;
    return runtime->streamHeaderLane3Word1;
  }

  /**
   * Address: 0x00B15E30 (FUN_00B15E30, sub_B15E30)
   *
   * What it does:
   * Applies lane-`4` stream-header word, snapshots dispatch-derived header
   * lanes, and refreshes ADXRNA bit-depth/sample-rate mirrors.
   */
  [[maybe_unused]] std::int32_t ADXRNA_SetStreamHeaderLane4(
    const std::int32_t rnaHandle,
    const std::int32_t lane4Word,
    std::int32_t* const inOutLane4Word
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    auto* const outputRuntime = AsAdxrnaTransportRuntimeView(rnaHandle)->outputRuntime;
    auto* const dispatch = outputRuntime->dispatchTable;
    dispatch->setLaneWordPair(outputRuntime, 4, lane4Word, 0);
    std::int32_t lane4AuxWord = 0;
    dispatch->queryLaneWordPair(outputRuntime, 4, inOutLane4Word, &lane4AuxWord);

    const std::int32_t lane4StatusWord = *inOutLane4Word;
    if (lane4StatusWord > 0) {
      const std::int32_t bitsPerSample = dispatch->getBitsPerSample(outputRuntime);
      const std::int32_t sampleRate = dispatch->getSampleRateBase(outputRuntime);
      const std::int32_t streamInfoWord60 = dispatch->getOutputVolume(outputRuntime);
      const std::int32_t streamInfoWord64 = dispatch->getIndexedWord(outputRuntime, 0);
      const std::int32_t streamInfoWord68 = dispatch->getIndexedWord(outputRuntime, 1);

      std::int32_t streamInfoWord70 = 0;
      std::int32_t streamInfoWord74 = 0;
      dispatch->queryLaneWordPair(outputRuntime, 0, &streamInfoWord70, &streamInfoWord74);

      std::int32_t lane3Word0 = 0;
      std::int32_t lane3Word1 = 0;
      dispatch->queryLaneWordPair(outputRuntime, 3, &lane3Word0, &lane3Word1);

      (void)ADXRNA_SetBitPerSmpl(rnaHandle, bitsPerSample);
      (void)ADXRNA_SetSfreq(rnaHandle, sampleRate);

      auto* const runtime = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle);
      runtime->streamInfoWords64[0] = streamInfoWord64;
      runtime->streamInfoWords64[1] = streamInfoWord68;
      runtime->streamInfoWord60 = streamInfoWord60;
      runtime->streamInfoWord70 = streamInfoWord70;
      runtime->streamInfoWord74 = streamInfoWord74;
      runtime->streamHeaderLane3Word0 = lane3Word0;
      runtime->streamHeaderLane3Word1 = lane3Word1;
    }

    return lane4StatusWord;
  }

  /**
   * Address: 0x00B17C90 (FUN_00B17C90, _ADXRNA_GetNumRoom)
   *
   * What it does:
   * Returns unconstrained room sentinel used by ADXRNA prep lanes.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetNumRoom()
  {
    return 0x7FFFFFFF;
  }

  /**
   * Address: 0x00B17CD0 (FUN_00B17CD0, _ADXRNA_SetNumChan)
   *
   * What it does:
   * Legacy thunk to ADXRNA channel-count setter.
   */
  [[maybe_unused]] void ADXRNA_SetNumChan(const std::int32_t rnaHandle, const std::int32_t channelCount)
  {
    mwRnaSetNumChan(AsAdxrnaRuntimeView(rnaHandle), channelCount);
  }

  /**
   * Address: 0x00B15C40 (FUN_00B15C40)
   *
   * What it does:
   * Returns legacy ADXRNA queue metric lane at offset `0x08`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetLegacyQueueMetricWord08(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->queuedDataCount;
  }

  /**
   * Address: 0x00B15C60 (FUN_00B15C60)
   *
   * What it does:
   * Returns ADXRNA time-scale base word for one RNA handle.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetTimeScaleBase(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->timeScaleBase;
  }

  /**
   * Address: 0x00B15C80 (FUN_00B15C80)
   *
   * What it does:
   * Returns ADXRNA stream-info word at lane `0x60`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamInfoWord60(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->streamInfoWord60;
  }

  /**
   * Address: 0x00B15CA0 (FUN_00B15CA0)
   *
   * What it does:
   * Returns ADXRNA stream-info word from lane array at `0x64 + 4*index`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamInfoWord64(const std::int32_t rnaHandle, const std::int32_t wordIndex)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->streamInfoWords64[wordIndex];
  }

  /**
   * Address: 0x00B15CD0 (FUN_00B15CD0)
   *
   * What it does:
   * Returns ADXRNA stream-info word at lane `0x6C`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamInfoWord6C(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->streamInfoWord6C;
  }

  /**
   * Address: 0x00B17D30 (FUN_00B17D30)
   *
   * What it does:
   * Legacy thunk that returns ADXRNA time-scale base word.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetTimeScaleBaseThunk(const std::int32_t rnaHandle)
  {
    return ADXRNA_GetTimeScaleBase(rnaHandle);
  }

  /**
   * Address: 0x00B17D40 (FUN_00B17D40)
   *
   * What it does:
   * Legacy thunk that returns ADXRNA stream-info word `0x60`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamInfoWord60Thunk(const std::int32_t rnaHandle)
  {
    return ADXRNA_GetStreamInfoWord60(rnaHandle);
  }

  /**
   * Address: 0x00B17D50 (FUN_00B17D50)
   *
   * What it does:
   * Legacy thunk that returns ADXRNA stream-info word `0x64 + 4*index`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamInfoWord64Thunk(const std::int32_t rnaHandle, const std::int32_t wordIndex)
  {
    return ADXRNA_GetStreamInfoWord64(rnaHandle, wordIndex);
  }

  /**
   * Address: 0x00B17D60 (FUN_00B17D60)
   *
   * What it does:
   * Legacy thunk that returns ADXRNA stream-info word `0x6C`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetStreamInfoWord6CThunk(const std::int32_t rnaHandle)
  {
    return ADXRNA_GetStreamInfoWord6C(rnaHandle);
  }

  /**
   * Address: 0x00B17D70 (FUN_00B17D70)
   *
   * What it does:
   * Legacy thunk that returns ADXRNA queue metric lane `0x08`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetLegacyQueueMetricWord08Thunk(const std::int32_t rnaHandle)
  {
    return ADXRNA_GetLegacyQueueMetricWord08(rnaHandle);
  }

  /**
   * Address: 0x00B17D80 (FUN_00B17D80)
   *
   * What it does:
   * Returns ADXRNA discard-sample result code for this build.
   */
  [[maybe_unused]] std::int32_t ADXRNA_DiscardSamples(const std::int32_t rnaHandle, const std::int32_t sampleCount)
  {
    (void)rnaHandle;
    (void)sampleCount;
    return adxrna_DiscardSamplesCoreNoOp();
  }

  /**
   * Address: 0x00B17D90 (FUN_00B17D90)
   *
   * What it does:
   * Legacy no-op hook.
   */
  [[maybe_unused]] void ADXRNA_NoopHook0()
  {
  }

  /**
   * Address: 0x00B17DA0 (FUN_00B17DA0)
   *
   * What it does:
   * Legacy no-op hook.
   */
  [[maybe_unused]] void ADXRNA_NoopHook1()
  {
  }

  /**
   * Address: 0x00B17DC0 (FUN_00B17DC0)
   *
   * What it does:
   * Returns global ADXRNA pause-all state.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetPauseAllState()
  {
    return gAdxrnaPauseAllState;
  }

  std::array<std::uint8_t, 16> gAdxtDataIdScratch{};

  constexpr char kAdxtGetNumSctIbufParameterErrorMessage[] = "E02080834 adxt_GetNumSctIbuf: parameter error";
  constexpr char kAdxtSetOutVolParameterErrorMessage[] = "E02080823 adxt_SetOutVol: parameter error";
  constexpr char kAdxtGetOutVolParameterErrorMessage[] = "E02080824 adxt_GetOutVol: parameter error";
  constexpr char kAdxtGetOutPanParameterErrorMessage[] = "E02080826 adxt_GetOutPan: parameter error";
  constexpr char kAdxtSetOutBalanceParameterErrorMessage[] = "E02080870 adxt_SetOutBalance: parameter error";
  constexpr char kAdxtGetOutBalanceParameterErrorMessage[] = "E02080871 adxt_GetOutBalance: parameter error";
  constexpr char kAdxtSetReloadTimeParameterErrorMessage[] = "E02080838 adxt_SetReloadTime: parameter error";
  constexpr char kAdxtSetReloadSctParameterErrorMessage[] = "E02080839 adxt_SetReloadSct: parameter error";
  constexpr char kAdxtResetReloadTimeParameterErrorMessage[] = "E03111501 adxt_ResetReloadTime: parameter error";
  constexpr char kAdxtSetSvrFreqParameterErrorMessage[] = "E02080840 adxt_SetSvrFreq: parameter error";
  constexpr char kAdxtGetNumSmplObufParameterErrorMessage[] = "E02080837 adxt_GetNumSmplObuf: parameter error";
  constexpr char kAdxtGetIbufRemainTimeParameterErrorMessage[] = "E02080835 adxt_GetIbufRemainTime: parameter error";
  constexpr char kAdxtIsIbufSafetyParameterErrorMessage[] = "E02080836 ADXT_IsIbufSafety: parameter error";
  constexpr double kAdxtResetReloadSctScale = 0.85000002;

  /**
   * Address: 0x00B0E320 (FUN_00B0E320, _ADXT_ExecDecServer)
   *
   * What it does:
   * Runs ADXT decode-server execution lane under ADXCRS enter/leave guards.
   */
  void ADXT_ExecDecServer()
  {
    ADXCRS_Enter();
    adxt_ExecDecServer();
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E330 (FUN_00B0E330, _adxt_ExecDecServer)
   *
   * What it does:
   * Legacy decode-server thunk that forwards to `adxt_ExecServer`.
   */
  void adxt_ExecDecServer()
  {
    adxt_ExecServer();
  }

  /**
   * Address: 0x00B0E340 (FUN_00B0E340, _ADXT_GetErrCode)
   *
   * What it does:
   * Returns ADXT error code lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetErrCode(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t errorCode = adxt_GetErrCode(adxtRuntime);
    ADXCRS_Leave();
    return errorCode;
  }

  /**
   * Address: 0x00B0DBA0 (FUN_00B0DBA0, _ADXT_GetOutBalance)
   *
   * What it does:
   * Returns ADXT output-balance lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetOutBalance(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t balanceLevel = adxt_GetOutBalance(adxtRuntime);
    ADXCRS_Leave();
    return balanceLevel;
  }

  /**
   * Address: 0x00B0DBC0 (FUN_00B0DBC0, _adxt_GetOutBalance)
   *
   * What it does:
   * Returns ADXT output-balance lane (`+0x46`) or reports parameter error.
   */
  std::int32_t adxt_GetOutBalance(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    if (runtime != nullptr) {
      return static_cast<std::int32_t>(runtime->OutputBalanceLevel());
    }
    (void)ADXERR_CallErrFunc1_(kAdxtGetOutBalanceParameterErrorMessage);
    return 0;
  }

  /**
   * Address: 0x00B0DBE0 (FUN_00B0DBE0, _ADXT_SetOutVol)
   *
   * What it does:
   * Stores ADXT output-volume lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetOutVol(void* const adxtRuntime, const std::int16_t volumeLevel)
  {
    ADXCRS_Enter();
    adxt_SetOutVol(adxtRuntime, volumeLevel);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0DC00 (FUN_00B0DC00, _adxt_SetOutVol)
   *
   * What it does:
   * Stores ADXT output-volume lane (`+0x40`) and applies effective RNA output
   * volume.
   */
  void adxt_SetOutVol(void* const adxtRuntime, const std::int16_t volumeLevel)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetOutVolParameterErrorMessage);
      return;
    }

    runtime->OutputVolumeLevel() = volumeLevel;
    std::int32_t effectiveVolume = 0;
    if (runtime->AinfSwitchFlag() == 1u) {
      effectiveVolume = static_cast<std::int32_t>(ADXSJD_GetDefOutVol(runtime->sjdHandle));
    }
    effectiveVolume += static_cast<std::int32_t>(runtime->OutputVolumeLevel());
    (void)ADXRNA_SetOutVol(runtime->rnaHandle, effectiveVolume);
  }

  /**
   * Address: 0x00B0DC60 (FUN_00B0DC60, _ADXT_GetOutVol)
   *
   * What it does:
   * Returns ADXT output-volume lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetOutVol(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t outputVolume = adxt_GetOutVol(adxtRuntime);
    ADXCRS_Leave();
    return outputVolume;
  }

  /**
   * Address: 0x00B0DC80 (FUN_00B0DC80, _adxt_GetOutVol)
   *
   * What it does:
   * Returns ADXT output-volume lane (`+0x40`) or reports parameter error.
   */
  std::int32_t adxt_GetOutVol(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    if (runtime != nullptr) {
      return static_cast<std::int32_t>(runtime->OutputVolumeLevel());
    }
    (void)ADXERR_CallErrFunc1_(kAdxtGetOutVolParameterErrorMessage);
    return 0;
  }

  /**
   * Address: 0x00B0DCA0 (FUN_00B0DCA0, _ADXT_GetDefOutVol)
   *
   * What it does:
   * Returns ADXT default output-volume lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDefOutVol(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t defaultOutVolume = adxt_GetDefOutVol(adxtRuntime);
    ADXCRS_Leave();
    return defaultOutVolume;
  }

  /**
   * Address: 0x00B0DCC0 (FUN_00B0DCC0, _adxt_GetDefOutVol)
   *
   * What it does:
   * Returns ADXSJD default output-volume lane for one ADXT runtime.
   */
  std::int32_t adxt_GetDefOutVol(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return static_cast<std::int32_t>(ADXSJD_GetDefOutVol(runtime->sjdHandle));
  }

  /**
   * Address: 0x00B0DCE0 (FUN_00B0DCE0, _ADXT_GetDefOutPan)
   *
   * What it does:
   * Returns ADXT default per-lane pan under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDefOutPan(void* const adxtRuntime, const std::int32_t laneIndex)
  {
    ADXCRS_Enter();
    const std::int32_t defaultPan = adxt_GetDefOutPan(adxtRuntime, laneIndex);
    ADXCRS_Leave();
    return defaultPan;
  }

  /**
   * Address: 0x00B0DD10 (FUN_00B0DD10, _adxt_GetDefOutPan)
   *
   * What it does:
   * Returns ADXSJD default per-lane pan for one ADXT runtime.
   */
  std::int32_t adxt_GetDefOutPan(void* const adxtRuntime, const std::int32_t laneIndex)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return static_cast<std::int32_t>(ADXSJD_GetDefPan(runtime->sjdHandle, laneIndex));
  }

  /**
   * Address: 0x00B0DD30 (FUN_00B0DD30, _ADXT_GetDataId)
   *
   * What it does:
   * Returns ADXT data-id pointer lane under ADXCRS enter/leave guards.
   */
  std::uint8_t* ADXT_GetDataId(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    std::uint8_t* const dataId = adxt_GetDataId(adxtRuntime);
    ADXCRS_Leave();
    return dataId;
  }

  /**
   * Address: 0x00B0DD50 (FUN_00B0DD50, _adxt_GetDataId)
   *
   * What it does:
   * Returns ADXT SJD data-id pointer lane.
   */
  std::uint8_t* adxt_GetDataId(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    return ADXSJD_GetDataId(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0DD60 (FUN_00B0DD60, _ADXT_GetDataIdFromMem)
   *
   * What it does:
   * Decodes AINF data-id from ADX header bytes under ADXCRS guards.
   */
  std::uint8_t* ADXT_GetDataIdFromMem(const std::uint8_t* const sourceBytes)
  {
    ADXCRS_Enter();
    std::uint8_t* const dataId = adxt_GetDataIdFromMem(sourceBytes);
    ADXCRS_Leave();
    return dataId;
  }

  /**
   * Address: 0x00B0DD80 (FUN_00B0DD80, _adxt_GetDataIdFromMem)
   *
   * What it does:
   * Decodes AINF data-id from ADX header bytes into shared ADXT scratch buffer
   * and returns that buffer only when AINF info is present.
   */
  std::uint8_t* adxt_GetDataIdFromMem(const std::uint8_t* const sourceBytes)
  {
    std::int32_t ainfLength = 0;
    std::int16_t defaultVolume = 0;
    std::int16_t defaultPanByChannel[2] = {0, 0};

    (void)ADX_DecodeInfoAinf(
      sourceBytes,
      2048,
      &ainfLength,
      gAdxtDataIdScratch.data(),
      &defaultVolume,
      defaultPanByChannel
    );
    return (ainfLength != 0) ? gAdxtDataIdScratch.data() : nullptr;
  }

  /**
   * Address: 0x00B0DDC0 (FUN_00B0DDC0, _ADXT_SetAinfSw)
   *
   * What it does:
   * Stores ADXT AINF-switch state under ADXCRS enter/leave guards.
   */
  void ADXT_SetAinfSw(void* const adxtRuntime, const std::int32_t enabled)
  {
    ADXCRS_Enter();
    (void)adxt_SetAinfSw(adxtRuntime, static_cast<std::int8_t>(enabled));
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0DDE0 (FUN_00B0DDE0, _ADXT_GetAinfSw)
   *
   * What it does:
   * Returns ADXT AINF-switch lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetAinfSw(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t ainfSwitch = adxt_GetAinfSw(adxtRuntime);
    ADXCRS_Leave();
    return ainfSwitch;
  }

  /**
   * Address: 0x00B0DE00 (FUN_00B0DE00, _adxt_SetAinfSw)
   *
   * What it does:
   * Stores ADXT AINF-switch byte lane (`+0xA9`).
   */
  std::int8_t adxt_SetAinfSw(void* const adxtRuntime, const std::int8_t enabled)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    runtime->AinfSwitchFlag() = static_cast<std::uint8_t>(enabled);
    return enabled;
  }

  /**
   * Address: 0x00B0DE10 (FUN_00B0DE10, _adxt_GetAinfSw)
   *
   * What it does:
   * Returns ADXT AINF-switch byte lane (`+0xA9`).
   */
  std::int32_t adxt_GetAinfSw(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return static_cast<std::int32_t>(static_cast<std::int8_t>(runtime->AinfSwitchFlag()));
  }

  /**
   * Address: 0x00B0DE20 (FUN_00B0DE20, _ADXT_SetDefSvrFreq)
   *
   * What it does:
   * Stores global ADXT default server-frequency lane under ADXCRS guards.
   */
  void ADXT_SetDefSvrFreq(const std::int32_t serverFrequency)
  {
    ADXCRS_Enter();
    (void)adxt_SetDefSvrFreq(serverFrequency);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0DE40 (FUN_00B0DE40, _adxt_SetDefSvrFreq)
   *
   * What it does:
   * Stores global ADXT default/last server-frequency lanes and returns value.
   */
  std::int32_t adxt_SetDefSvrFreq(const std::int32_t serverFrequency)
  {
    gAdxtDefaultServerFrequency = serverFrequency;
    gAdxtLastServerFrequency = serverFrequency;
    return serverFrequency;
  }

  /**
   * Address: 0x00B0DE50 (FUN_00B0DE50, _ADXT_SetSvrFreq)
   *
   * What it does:
   * Stores ADXT runtime server-frequency lane under ADXCRS guards.
   */
  void ADXT_SetSvrFreq(void* const adxtRuntime, const std::int32_t serverFrequency)
  {
    ADXCRS_Enter();
    adxt_SetSvrFreq(adxtRuntime, serverFrequency);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0DE70 (FUN_00B0DE70, _adxt_SetSvrFreq)
   *
   * What it does:
   * Stores ADXT runtime server-frequency lane (`+0x38`) and global last value.
   */
  void adxt_SetSvrFreq(void* const adxtRuntime, const std::int32_t serverFrequency)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetSvrFreqParameterErrorMessage);
      return;
    }

    runtime->ErrorCheckFrameWindow() = serverFrequency;
    gAdxtLastServerFrequency = serverFrequency;
  }

  /**
   * Address: 0x00B0DEA0 (FUN_00B0DEA0, _ADXT_SetReloadTime)
   *
   * What it does:
   * Stores ADXT reload-time-derived sector lane under ADXCRS guards.
   */
  void ADXT_SetReloadTime(
    void* const adxtRuntime,
    const float reloadSeconds,
    const std::int32_t channelCount,
    const std::int32_t sampleRate
  )
  {
    ADXCRS_Enter();
    adxt_SetReloadTime(adxtRuntime, reloadSeconds, channelCount, sampleRate);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0DED0 (FUN_00B0DED0, _adxt_SetReloadTime)
   *
   * What it does:
   * Converts reload time to sector budget and updates ADXSTM buffer sizing.
   */
  void adxt_SetReloadTime(
    void* const adxtRuntime,
    const float reloadSeconds,
    const std::int32_t channelCount,
    const std::int32_t sampleRate
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetReloadTimeParameterErrorMessage);
      return;
    }

    const std::int32_t streamBufferSectorLimit = static_cast<std::int32_t>(runtime->StreamBufferSectorLimitHint());
    const std::int32_t sampleFrames = static_cast<std::int32_t>(static_cast<double>(sampleRate) * reloadSeconds) / 32;
    std::int32_t reloadSectorCount = (18 * channelCount * sampleFrames) / 2048;
    if (reloadSectorCount >= streamBufferSectorLimit) {
      reloadSectorCount = streamBufferSectorLimit;
    }

    const std::int16_t storedReloadSectors = static_cast<std::int16_t>(reloadSectorCount);
    runtime->SeamlessFlowSectorHint() = storedReloadSectors;
    if (runtime->streamHandle != nullptr) {
      (void)ADXSTM_SetBufSize(
        runtime->streamHandle,
        static_cast<std::int32_t>(storedReloadSectors) << 11,
        streamBufferSectorLimit << 11
      );
    }
  }

  /**
   * Address: 0x00B0DF40 (FUN_00B0DF40, _ADXT_ResetReloadTime)
   *
   * What it does:
   * Runs ADXT reload-time reset lane under ADXCRS enter/leave guards.
   */
  void ADXT_ResetReloadTime(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_ResetReloadTime(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0DF60 (FUN_00B0DF60, _adxt_ResetReloadTime)
   *
   * What it does:
   * Recomputes ADXT seamless reload sector hint from stream-buffer sector limit
   * and reapplies stream buffer sizing when a stream handle is active.
   */
  void adxt_ResetReloadTime(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtResetReloadTimeParameterErrorMessage);
      return;
    }

    const std::int32_t streamBufferSectors = static_cast<std::int32_t>(runtime->StreamBufferSectorLimitHint());
    const std::int32_t computedReloadSectors =
      static_cast<std::int32_t>(static_cast<double>(streamBufferSectors) * kAdxtResetReloadSctScale);
    const std::int16_t storedReloadSectors = static_cast<std::int16_t>(computedReloadSectors);
    runtime->SeamlessFlowSectorHint() = storedReloadSectors;

    void* const streamHandle = runtime->streamHandle;
    if (streamHandle != nullptr) {
      (void)ADXSTM_SetBufSize(
        streamHandle,
        static_cast<std::int32_t>(storedReloadSectors) << 11,
        streamBufferSectors << 11
      );
    }
  }

  /**
   * Address: 0x00B0DFC0 (FUN_00B0DFC0, _ADXT_SetReloadSct)
   *
   * What it does:
   * Stores ADXT reload-sector hint under ADXCRS enter/leave guards.
   */
  void ADXT_SetReloadSct(void* const adxtRuntime, const std::int32_t reloadSectorCount)
  {
    ADXCRS_Enter();
    adxt_SetReloadSct(adxtRuntime, static_cast<std::int16_t>(reloadSectorCount));
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0DFE0 (FUN_00B0DFE0, _adxt_SetReloadSct)
   *
   * What it does:
   * Stores ADXT reload-sector hint lane (`+0x3E`) and refreshes stream buffer
   * size limits when a stream handle is active.
   */
  void adxt_SetReloadSct(void* const adxtRuntime, const std::int16_t reloadSectorCount)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetReloadSctParameterErrorMessage);
      return;
    }

    void* const streamHandle = runtime->streamHandle;
    runtime->SeamlessFlowSectorHint() = reloadSectorCount;
    if (streamHandle != nullptr) {
      const std::int32_t minBufferSectors = static_cast<std::int32_t>(reloadSectorCount);
      const std::int32_t maxBufferSectors = static_cast<std::int32_t>(runtime->StreamBufferSectorLimitHint());
      (void)ADXSTM_SetBufSize(streamHandle, minBufferSectors << 11, maxBufferSectors << 11);
    }
  }

  /**
   * Address: 0x00B0E020 (FUN_00B0E020, _ADXT_GetReloadSct)
   *
   * What it does:
   * Returns ADXT reload-sector hint lane (`+0x3E`).
   */
  std::int32_t ADXT_GetReloadSct(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    return static_cast<std::int32_t>(runtime->SeamlessFlowSectorHint());
  }

  /**
   * Address: 0x00B0E030 (FUN_00B0E030, _ADXT_GetNumSctIbuf)
   *
   * What it does:
   * Returns ADXT input-buffer queued sector count under ADXCRS enter/leave
   * guards.
   */
  std::int32_t ADXT_GetNumSctIbuf(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t queuedSectors = adxt_GetNumSctIbuf(adxtRuntime);
    ADXCRS_Leave();
    return queuedSectors;
  }

  /**
   * Address: 0x00B0E050 (FUN_00B0E050, _adxt_GetNumSctIbuf)
   *
   * What it does:
   * Returns ADXT input-buffer queued sector count or reports parameter error.
   */
  std::int32_t adxt_GetNumSctIbuf(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetNumSctIbufParameterErrorMessage);
      return -1;
    }

    if (runtime->streamJoinInputHandle == nullptr) {
      return 0;
    }

    return runtime->streamJoinInputHandle->QueryDecodeBacklog(1) / 2048;
  }

  /**
   * Address: 0x00B0E090 (FUN_00B0E090, _ADXT_GetNumSmplObuf)
   *
   * What it does:
   * Returns ADXT output-buffer sample count for one lane under ADXCRS guards.
   */
  std::int32_t ADXT_GetNumSmplObuf(void* const adxtRuntime, const std::int32_t lane)
  {
    ADXCRS_Enter();
    const std::int32_t sampleCount = adxt_GetNumSmplObuf(adxtRuntime, lane);
    ADXCRS_Leave();
    return sampleCount;
  }

  /**
   * Address: 0x00B0E0C0 (FUN_00B0E0C0, _adxt_GetNumSmplObuf)
   *
   * What it does:
   * Returns ADXT output-buffer sample count for one lane or reports parameter
   * error.
   */
  std::int32_t adxt_GetNumSmplObuf(void* const adxtRuntime, const std::int32_t lane)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr || lane < 0) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetNumSmplObufParameterErrorMessage);
      return -1;
    }

    auto* const sourceLane = reinterpret_cast<AdxtDecodeSourceHandle*>(runtime->SourceChannelRingLane(lane));
    if (sourceLane == nullptr) {
      return 0;
    }

    return sourceLane->QueryDecodeBacklog(1) / 2;
  }

  /**
   * Address: 0x00B0E100 (FUN_00B0E100, _ADXT_GetIbufRemainTime)
   *
   * What it does:
   * Returns ADXT input-buffer remaining playback time under ADXCRS guards.
   */
  double ADXT_GetIbufRemainTime(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const double remainingSeconds = adxt_GetIbufRemainTime(adxtRuntime);
    ADXCRS_Leave();
    return remainingSeconds;
  }

  /**
   * Address: 0x00B0E120 (FUN_00B0E120, _adxt_GetIbufRemainTime)
   *
   * What it does:
   * Returns ADXT input-buffer remaining playback time in seconds.
   */
  double adxt_GetIbufRemainTime(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetIbufRemainTimeParameterErrorMessage);
      return -1.0;
    }

    if (adxt_GetStat(runtime) >= 2 && runtime->streamJoinInputHandle != nullptr) {
      const std::int32_t inputQueuedBytes = runtime->streamJoinInputHandle->QueryDecodeBacklog(1);
      const std::int32_t bufferedSampleCount = 32 * (inputQueuedBytes / (18 * adxt_GetNumChan(runtime)));
      const float bufferedSamplesFloat = static_cast<float>(bufferedSampleCount);
      return bufferedSamplesFloat / static_cast<double>(ADXSJD_GetSfreq(runtime->sjdHandle));
    }

    return 0.0;
  }

  /**
   * Address: 0x00B0E1B0 (FUN_00B0E1B0, _ADXT_IsIbufSafety)
   *
   * What it does:
   * Returns whether ADXT input buffer is above safety threshold under ADXCRS
   * guards.
   */
  std::int32_t ADXT_IsIbufSafety(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t safetyState = adxt_IsIbufSafety(adxtRuntime);
    ADXCRS_Leave();
    return safetyState;
  }

  /**
   * Address: 0x00B0E1D0 (FUN_00B0E1D0, _adxt_IsIbufSafety)
   *
   * What it does:
   * Returns whether ADXT input buffer is above safety threshold.
   */
  std::int32_t adxt_IsIbufSafety(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtIsIbufSafetyParameterErrorMessage);
      return -1;
    }

    if (runtime->streamJoinInputHandle == nullptr) {
      return 0;
    }

    return runtime->streamJoinInputHandle->QueryDecodeBacklog(1)
      >= (static_cast<std::int32_t>(runtime->SeamlessFlowSectorHint()) << 11);
  }

  constexpr char kAdxtGetErrCodeParameterErrorMessage[] = "E02080843 adxt_GetErrCode: parameter error";
  constexpr char kAdxtClearErrCodeParameterErrorMessage[] = "E02080844 adxt_ClearErrCode: parameter error";
  constexpr char kAdxtGetLpCntParameterErrorMessage[] = "E02080829 adxt_GetLpCnt: parameter error";
  constexpr char kAdxtSetLpFlgParameterErrorMessage[] = "E02080828 adxt_SetLpFlg: parameter error";

  /**
   * Address: 0x00B0E360 (FUN_00B0E360, _adxt_GetErrCode)
   *
   * What it does:
   * Returns ADXT runtime error code lane or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetErrCode(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetErrCodeParameterErrorMessage);
    }
    return static_cast<std::int32_t>(runtime->ErrorStateCode());
  }

  /**
   * Address: 0x00B0E3A0 (FUN_00B0E3A0, _adxt_ClearErrCode)
   *
   * What it does:
   * Clears ADXT runtime decode/error tracking lanes or reports null-runtime
   * parameter error.
   */
  void adxt_ClearErrCode(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtClearErrCodeParameterErrorMessage);
      return;
    }

    runtime->ErrorStateCode() = 0;
    runtime->LastDecodedSampleCount() = 0;
    runtime->DecodeStallCounter() = 0;
    runtime->RecoveryWatchdogCounter() = 0;
  }

  /**
   * Address: 0x00B0E380 (FUN_00B0E380, _ADXT_ClearErrCode)
   *
   * What it does:
   * Clears ADXT error state lanes under ADXCRS enter/leave guards.
   */
  void ADXT_ClearErrCode(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_ClearErrCode(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E3F0 (FUN_00B0E3F0, _adxt_GetLpCnt)
   *
   * What it does:
   * Returns ADXT runtime loop-count lane or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetLpCnt(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetLpCntParameterErrorMessage);
      return -1;
    }
    return runtime->LoopCount();
  }

  /**
   * Address: 0x00B0E3D0 (FUN_00B0E3D0, _ADXT_GetLpCnt)
   *
   * What it does:
   * Returns ADXT loop-count lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetLpCnt(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t loopCount = adxt_GetLpCnt(adxtRuntime);
    ADXCRS_Leave();
    return loopCount;
  }

  /**
   * Address: 0x00B0E430 (FUN_00B0E430, _adxt_SetLpFlg)
   *
   * What it does:
   * Updates ADXT seamless-loop flag and aligned loop decode-window lane.
   */
  void adxt_SetLpFlg(void* const adxtRuntime, const std::int32_t enabled)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetLpFlgParameterErrorMessage);
      return;
    }

    const auto alignToSignedSectorBoundary = [](const std::int32_t byteOffset) -> std::int32_t {
      std::int32_t roundedOffset = byteOffset + 0x7FF;
      roundedOffset += (roundedOffset >> 31) & 0x7FF;
      return (roundedOffset >> 11) << 11;
    };

    runtime->StreamLoopSeekOnEosFlag() = static_cast<std::uint8_t>(enabled);

    std::int32_t streamBacklogBytes = 0;
    if (runtime->streamJoinInputHandle != nullptr) {
      streamBacklogBytes = runtime->streamJoinInputHandle->QueryDecodeBacklog(1);
    }

    const std::int32_t decodedBytes = streamBacklogBytes + ADXSJD_GetDecDtLen(runtime->sjdHandle);
    const std::int32_t loopStartBytes = alignToSignedSectorBoundary(ADXSJD_GetLpStartOfst(runtime->sjdHandle));
    const std::int32_t loopSpanBytes = alignToSignedSectorBoundary(ADXSJD_GetLpEndOfst(runtime->sjdHandle)) - loopStartBytes;
    if (loopSpanBytes > 0) {
      runtime->StreamDecodeWindowState() =
        loopStartBytes + loopSpanBytes * ((decodedBytes - loopStartBytes) / loopSpanBytes);
      return;
    }

    runtime->StreamDecodeWindowState() = 0;
  }

  /**
   * Address: 0x00B0E410 (FUN_00B0E410, _ADXT_SetLpFlg)
   *
   * What it does:
   * Updates ADXT seamless-loop flag under ADXCRS enter/leave guards.
   */
  void ADXT_SetLpFlg(void* const adxtRuntime, const std::int32_t enabled)
  {
    ADXCRS_Enter();
    adxt_SetLpFlg(adxtRuntime, enabled);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E6D0 (FUN_00B0E6D0, _ADXT_PauseAll)
   *
   * What it does:
   * Applies global ADXT pause-all state under ADXCRS enter/leave guards.
   */
  void ADXT_PauseAll(const std::int32_t pauseAllEnabled)
  {
    ADXCRS_Enter();
    (void)adxt_PauseAll(pauseAllEnabled);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E6F0 (FUN_00B0E6F0, _adxt_PauseAll)
   *
   * What it does:
   * Forwards global ADXT pause-all state to ADXRNA pause-all runtime lanes.
   */
  std::int32_t adxt_PauseAll(const std::int32_t pauseAllEnabled)
  {
    return adxrna_SetPauseAllState(pauseAllEnabled);
  }

  /**
   * Address: 0x00B0E700 (FUN_00B0E700, _ADXT_GetStatPauseAll)
   *
   * What it does:
   * Returns global ADXT pause-all state under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetStatPauseAll()
  {
    ADXCRS_Enter();
    const std::int32_t pauseAllState = adxt_GetStatPauseAll();
    ADXCRS_Leave();
    return pauseAllState;
  }

  /**
   * Address: 0x00B0E720 (FUN_00B0E720, _adxt_GetStatPauseAll)
   *
   * What it does:
   * ADXT-facing thunk that returns current ADXRNA pause-all status.
   */
  std::int32_t adxt_GetStatPauseAll()
  {
    return ADXRNA_GetPauseAllState();
  }

  constexpr char kAdxtIsCompletedParameterErrorMessage[] = "E02080802 adxt_IsCompleted: parameter error";
  constexpr char kAdxtGetInputSjParameterErrorMessage[] = "E02080833 adxt_GetInputSj: parameter error";
  constexpr char kAdxtSetWaitPlayStartParameterErrorMessage[] = "E02080830 adxt_SetWaitPlayStart: parameter error";
  constexpr char kAdxtIsReadyPlayStartParameterErrorMessage[] = "E02080831 adxt_IsReadyPlayStart: parameter error";
  constexpr char kAdxtGetStatPauseParameterErrorMessage[] = "E02080847 adxt_GetStatPause: parameter error";

  /**
   * Address: 0x00B0E220 (FUN_00B0E220, _ADXT_SetAutoRcvr)
   *
   * What it does:
   * Stores ADXT auto-recover mode lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetAutoRcvr(void* const adxtRuntime, const std::int32_t autoRecoverEnabled)
  {
    ADXCRS_Enter();
    (void)adxt_SetAutoRcvr(adxtRuntime, autoRecoverEnabled);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E240 (FUN_00B0E240, _adxt_SetAutoRcvr)
   *
   * What it does:
   * Stores ADXT auto-recover mode byte (`+0x6D`).
   */
  std::int32_t adxt_SetAutoRcvr(void* const adxtRuntime, const std::int32_t autoRecoverEnabled)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    runtime->ErrorRecoveryMode() = static_cast<std::uint8_t>(autoRecoverEnabled);
    return static_cast<std::int32_t>(runtime->ErrorRecoveryMode());
  }

  /**
   * Address: 0x00B0E250 (FUN_00B0E250, _ADXT_IsCompleted)
   *
   * What it does:
   * Returns ADXT completed-state lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_IsCompleted(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t completed = adxt_IsCompleted(adxtRuntime);
    ADXCRS_Leave();
    return completed;
  }

  /**
   * Address: 0x00B0E270 (FUN_00B0E270, _adxt_IsCompleted)
   *
   * What it does:
   * Returns whether ADXT runtime state byte (`+0x01`) equals terminal state `5`;
   * reports null-runtime parameter error and returns `-1` otherwise.
   */
  std::int32_t adxt_IsCompleted(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtIsCompletedParameterErrorMessage);
      return -1;
    }

    return (runtime->mUnknown01 == 5u) ? 1 : 0;
  }

  /**
   * Address: 0x00B0E4F0 (FUN_00B0E4F0, _ADXT_GetInputSj)
   *
   * What it does:
   * Returns ADXT input-SJ handle lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetInputSj(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t inputHandle = adxt_GetInputSj(adxtRuntime);
    ADXCRS_Leave();
    return inputHandle;
  }

  /**
   * Address: 0x00B0E510 (FUN_00B0E510, _adxt_GetInputSj)
   *
   * What it does:
   * Returns ADXT runtime input-SJ handle lane or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetInputSj(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetInputSjParameterErrorMessage);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtime->streamJoinInputHandle));
  }

  /**
   * Address: 0x00B0E530 (FUN_00B0E530, _ADXT_SetWaitPlayStart)
   *
   * What it does:
   * Stores ADXT wait-play-start lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetWaitPlayStart(void* const adxtRuntime, const std::int32_t waitEnabled)
  {
    ADXCRS_Enter();
    adxt_SetWaitPlayStart(adxtRuntime, waitEnabled);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E550 (FUN_00B0E550, _adxt_SetWaitPlayStart)
   *
   * What it does:
   * Stores ADXT wait-play-start flag byte (`+0x70`) or reports null-runtime
   * parameter error.
   */
  void adxt_SetWaitPlayStart(void* const adxtRuntime, const std::int32_t waitEnabled)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetWaitPlayStartParameterErrorMessage);
      return;
    }
    runtime->WaitPlayStartFlag() = static_cast<std::uint8_t>(waitEnabled);
  }

  /**
   * Address: 0x00B0E570 (FUN_00B0E570, _ADXT_IsReadyPlayStart)
   *
   * What it does:
   * Returns ADXT ready-play-start lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_IsReadyPlayStart(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t readyState = adxt_IsReadyPlayStart(adxtRuntime);
    ADXCRS_Leave();
    return readyState;
  }

  /**
   * Address: 0x00B0E590 (FUN_00B0E590, _adxt_IsReadyPlayStart)
   *
   * What it does:
   * Returns ADXT ready-play-start flag byte (`+0x71`) or `-1` on null runtime.
   */
  std::int32_t adxt_IsReadyPlayStart(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtIsReadyPlayStartParameterErrorMessage);
      return -1;
    }
    return static_cast<std::int32_t>(static_cast<std::int8_t>(runtime->ReadyPlayStartFlag()));
  }

  /**
   * Address: 0x00B0E5B0 (FUN_00B0E5B0, _ADXT_Pause)
   *
   * What it does:
   * Runs ADXT pause lane under ADXCRS enter/leave guards.
   */
  void ADXT_Pause(void* const adxtRuntime, const std::int32_t pauseEnabled)
  {
    ADXCRS_Enter();
    adxt_Pause(adxtRuntime, pauseEnabled);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E690 (FUN_00B0E690, _ADXT_GetStatPause)
   *
   * What it does:
   * Returns ADXT pause-state lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetStatPause(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t pauseState = adxt_GetStatPause(adxtRuntime);
    ADXCRS_Leave();
    return pauseState;
  }

  /**
   * Address: 0x00B0E6B0 (FUN_00B0E6B0, _adxt_GetStatPause)
   *
   * What it does:
   * Returns ADXT pause-state byte (`+0x72`) or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetStatPause(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetStatPauseParameterErrorMessage);
      return 0;
    }
    return static_cast<std::int32_t>(static_cast<std::int8_t>(runtime->PauseStateFlag()));
  }

  /**
   * Address: 0x00B0E730 (FUN_00B0E730, _ADXT_SetTranspose)
   *
   * What it does:
   * Runs ADXT transpose update lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetTranspose(void* const adxtRuntime, const std::int32_t transposeOctaves, const std::int32_t transposeCents)
  {
    ADXCRS_Enter();
    (void)adxt_SetTranspose(adxtRuntime, transposeOctaves, transposeCents);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E760 (FUN_00B0E760, _adxt_SetTranspose)
   *
   * What it does:
   * Updates ADXT transpose lanes and recomputes decode window/sample budget for
   * active decode state.
   */
  std::int32_t adxt_SetTranspose(void* const adxtRuntime, const std::int32_t transposeOctaves, const std::int32_t transposeCents)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const std::int32_t sjdHandle = runtime->sjdHandle;
    (void)ADXRNA_SetTransposeWords(runtime->rnaHandle, transposeOctaves, transposeCents);
    const std::int32_t calculatedSampleRate = mwRnaCalcSfreq(runtime->rnaHandle);

    std::int32_t result = ADXSJD_GetStat(sjdHandle);
    if (result == 2) {
      const std::int32_t dividedRate = calculatedSampleRate / runtime->TransposeScaleDivisor();
      if (ADXSJD_GetNumLoop(sjdHandle) <= 0) {
        runtime->TransposeDecodeWindowSamples() = (3 * dividedRate) / 2;
      } else {
        runtime->TransposeDecodeWindowSamples() = 3 * dividedRate;
      }

      const std::int32_t blockSamples = ADXSJD_GetBlkSmpl(sjdHandle);
      const std::int32_t frameSamples = 2 * blockSamples;
      const std::int32_t alignedMaxDecodeSamples =
        frameSamples * ((frameSamples + runtime->TransposeDecodeWindowSamples()) / frameSamples);
      runtime->TransposeDecodeWindowSamples() = alignedMaxDecodeSamples;
      return static_cast<std::int32_t>(ADXSJD_SetMaxDecSmpl(sjdHandle, alignedMaxDecodeSamples));
    }

    return result;
  }

  /**
   * Address: 0x00B0E7F0 (FUN_00B0E7F0, _ADXT_GetTranspose)
   *
   * What it does:
   * Returns ADXT transpose lanes under ADXCRS enter/leave guards.
   */
  void ADXT_GetTranspose(
    void* const adxtRuntime,
    std::int32_t* const outTransposeOctaves,
    std::int32_t* const outTransposeCents
  )
  {
    ADXCRS_Enter();
    (void)adxt_GetTranspose(adxtRuntime, outTransposeOctaves, outTransposeCents);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E820 (FUN_00B0E820, _adxt_GetTranspose)
   *
   * What it does:
   * Returns ADXT transpose lanes from RNA transpose words.
   */
  std::int32_t adxt_GetTranspose(
    void* const adxtRuntime,
    std::int32_t* const outTransposeOctaves,
    std::int32_t* const outTransposeCents
  )
  {
    const auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(
      ADXRNA_GetTransposeWords(runtime->rnaHandle, outTransposeOctaves, outTransposeCents)
    ));
  }

  /**
   * Address: 0x00B17DD0 (FUN_00B17DD0, _ADXRNA_SetTotalNumSmpl)
   *
   * What it does:
   * Legacy ADXRNA total-sample hook for this build; no runtime behavior.
   */
  [[maybe_unused]] void ADXRNA_SetTotalNumSmpl()
  {
  }

  /**
   * Address: 0x00B17DE0 (FUN_00B17DE0, _ADXRNA_SetWavFname)
   *
   * What it does:
   * Legacy ADXRNA wave-name hook for this build; no runtime behavior.
   */
  [[maybe_unused]] void ADXRNA_SetWavFname()
  {
  }

  /**
   * Address: 0x00B17E10 (FUN_00B17E10, _ADXF_Init)
   *
   * What it does:
   * Initializes ADXF global pools on first init and increments init reference count.
   */
  std::int32_t ADXF_Init()
  {
    const std::int32_t previousInitCount = gAdxfInitCount;
    gCriVersionStringAdxf = kAdxfBuildVersion;

    if (gAdxfInitCount == 0) {
      std::memset(gAdxfHandlePool.data(), 0, sizeof(gAdxfHandlePool));
      std::memset(gAdxfPointInfoById.data(), 0, sizeof(gAdxfPointInfoById));
      gAdxfHistoryWriteIndex = 0;
      std::memset(gAdxfCommandHistory.data(), 0xFF, sizeof(gAdxfCommandHistory));
      gAdxfOcbiEnabled = 0;
      std::memset(gAdxfCommandCallCountById.data(), 0, sizeof(gAdxfCommandCallCountById));
      gAdxfCurrentFileIndex = 0;
      gAdxfLoadedPointNetworkHandle = 0;
      gAdxfLoadedPointId = -1;
      gAdxfLoadedPointReadSectors = 0;
      gAdxfLoadedPointLastStatus = 1;
    }

    ++gAdxfInitCount;
    return previousInitCount;
  }

  /**
   * Address: 0x00B17EA0 (FUN_00B17EA0, _ADXF_Finish)
   *
   * What it does:
   * Decrements ADXF init reference count and resets ADXF global pools when the
   * final owner releases the subsystem.
   */
  std::int32_t ADXF_Finish()
  {
    const std::int32_t result = --gAdxfInitCount;
    if (gAdxfInitCount == 0) {
      ADXF_CloseAll();
      gAdxfLoadedPointNetworkHandle = 0;
      std::memset(gAdxfCommandCallCountById.data(), 0, sizeof(gAdxfCommandCallCountById));
      gAdxfCurrentFileIndex = 0;
      gAdxfOcbiEnabled = 0;
      gAdxfHistoryWriteIndex = 0;
      std::memset(gAdxfCommandHistory.data(), 0xFF, sizeof(gAdxfCommandHistory));
      gAdxfLoadedPointReadSectors = 0;
      gAdxfLoadedPointLastStatus = 1;
      std::memset(gAdxfPointInfoById.data(), 0, sizeof(gAdxfPointInfoById));
      std::memset(gAdxfHandlePool.data(), 0, sizeof(gAdxfHandlePool));
      gAdxfLoadedPointId = -1;
      return 0;
    }

    return result;
  }

  /**
   * Address: 0x00B17F20 (FUN_00B17F20, _ADXSJD_SetDecErrMode)
   *
   * What it does:
   * Forwards ADXSJD decode-error mode selection into ADXB.
   */
  std::int32_t ADXSJD_SetDecErrMode(const std::int32_t decodeErrorMode)
  {
    return ADXB_SetDecErrMode(decodeErrorMode);
  }

  /**
   * Address: 0x00B17F30 (FUN_00B17F30, _ADXSJD_GetDecErrMode)
   *
   * What it does:
   * Returns the current ADXSJD decode-error mode from ADXB.
   */
  std::int32_t ADXSJD_GetDecErrMode()
  {
    return ADXB_GetDecErrMode();
  }

  /**
   * Address: 0x00B0CB20 (FUN_00B0CB20, _adxt_SetDecErrMode)
   *
   * What it does:
   * ADXT-facing thunk that sets ADXSJD decode-error mode.
   */
  std::int32_t adxt_SetDecErrMode(const std::int32_t decodeErrorMode)
  {
    return ADXSJD_SetDecErrMode(decodeErrorMode);
  }

  /**
   * Address: 0x00B0CB50 (FUN_00B0CB50, _adxt_GetDecErrMode)
   *
   * What it does:
   * ADXT-facing thunk that returns ADXSJD decode-error mode.
   */
  std::int32_t adxt_GetDecErrMode()
  {
    return ADXSJD_GetDecErrMode();
  }

  /**
   * Address: 0x00B0CB00 (FUN_00B0CB00, _ADXT_SetDecErrMode)
   *
   * What it does:
   * Runs ADXT decode-error mode update under ADXCRS enter/leave guards.
   */
  void ADXT_SetDecErrMode(const std::int32_t decodeErrorMode)
  {
    ADXCRS_Enter();
    (void)adxt_SetDecErrMode(decodeErrorMode);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0CB30 (FUN_00B0CB30, _ADXT_GetDecErrMode)
   *
   * What it does:
   * Returns ADXT decode-error mode under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDecErrMode()
  {
    ADXCRS_Enter();
    const std::int32_t decodeErrorMode = adxt_GetDecErrMode();
    ADXCRS_Leave();
    return decodeErrorMode;
  }

  /**
   * Address: 0x00B17F40 (FUN_00B17F40, _ADXSJD_Init)
   *
   * What it does:
   * Initializes ADXSJD state on first entry and increments init reference count.
   */
  std::int32_t ADXSJD_Init()
  {
    if (gAdxsjdInitCount == 0) {
      ADXB_Init();
      std::memset(gAdxsjdObjectPool, 0, sizeof(gAdxsjdObjectPool));
    }

    return ++gAdxsjdInitCount;
  }

  /**
   * Address: 0x00B17F70 (FUN_00B17F70, _ADXSJD_Finish)
   *
   * What it does:
   * Decrements ADXSJD init reference count and clears runtime pool on final release.
   */
  std::int32_t ADXSJD_Finish()
  {
    const std::int32_t result = --gAdxsjdInitCount;
    if (gAdxsjdInitCount == 0) {
      std::memset(gAdxsjdObjectPool, 0, sizeof(gAdxsjdObjectPool));
      return 0;
    }
    return result;
  }

  /**
   * Address: 0x00B17F90 (FUN_00B17F90, _adxsjd_clear)
   *
   * What it does:
   * Clears one ADXSJD decode-lane runtime state back to default trap/decode values.
   */
  AdxsjdRuntimeView* adxsjd_clear(AdxsjdRuntimeView* const sjdRuntime)
  {
    sjdRuntime->linkSwitchEnabled = 0;
    sjdRuntime->decodedSampleCount = 0;
    sjdRuntime->decodedDataLengthBytes = 0;
    sjdRuntime->decodePositionSamples = 0;
    sjdRuntime->maxDecodeSamples = 0x7FFFFFFF;
    sjdRuntime->trapSampleCount = -1;
    sjdRuntime->trapCount = 0;
    sjdRuntime->trapDataLengthBytes = 0;
    sjdRuntime->decodeExecState = 0;
    sjdRuntime->positiveSampleAdjust = 0;
    sjdRuntime->negativeSampleAdjust = 0;
    return sjdRuntime;
  }

  /**
   * Address: 0x00B17FD0 (FUN_00B17FD0, _ADXSJD_Create)
   *
   * What it does:
   * Allocates one ADXSJD runtime slot, binds ADXB decode backend and write callback,
   * then stores source/output SJ handles for the new decode lane.
   */
  std::int32_t ADXSJD_Create(
    const std::int32_t inputSourceHandleAddress,
    const std::int32_t outputHandleCount,
    std::int32_t* const outputHandleAddresses
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < static_cast<std::int32_t>(kAdxsjdObjectCount) && gAdxsjdObjectPool[slotIndex].used != 0) {
      ++slotIndex;
    }

    if (slotIndex == static_cast<std::int32_t>(kAdxsjdObjectCount)) {
      return 0;
    }

    auto* const runtime = &gAdxsjdObjectPool[slotIndex];
    const std::int32_t sourceHandleAddress = outputHandleAddresses[0];
    auto* const sourceHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceHandleAddress))
    );

    const std::int32_t sourceBufferAddress = SJRBF_GetBufPtr(sourceHandle);
    const std::int32_t sourceHalfBufferBytes = SJRBF_GetBufSize(sourceHandle) / 2;
    const std::int32_t sourceHalfExtraBytes = SJRBF_GetXtrSize(sourceHandle) / 2;

    runtime->adxbHandle = ADXB_Create(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(outputHandleCount))),
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceBufferAddress))),
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceHalfBufferBytes))),
      reinterpret_cast<void*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceHalfBufferBytes + sourceHalfExtraBytes))
      )
    );

    if (runtime->adxbHandle == nullptr) {
      return 0;
    }

    ADXB_EntryGetWrFunc(
      runtime->adxbHandle,
      reinterpret_cast<void*>(adxsjd_get_wr),
      static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtime))
    );

    runtime->inputSourceHandle = reinterpret_cast<void*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(inputSourceHandleAddress))
    );
    runtime->outputHandleCount = static_cast<std::uint8_t>(outputHandleCount);

    if (outputHandleCount > 0) {
      for (std::int32_t lane = 0; lane < outputHandleCount; ++lane) {
        runtime->OutputHandle(lane) = reinterpret_cast<AdxsjdOutputHandle*>(
          static_cast<std::uintptr_t>(static_cast<std::uint32_t>(outputHandleAddresses[lane]))
        );
      }
    }

    runtime->streamFormatClass = 0;
    (void)adxsjd_clear(runtime);
    runtime->trapCallback = nullptr;
    runtime->trapCallbackContext = 0;
    runtime->filterCallback = nullptr;
    runtime->filterCallbackContext = 0;
    runtime->used = 1;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtime));
  }

  /**
   * Address: 0x00B180B0 (FUN_00B180B0, _ADXSJD_Destroy)
   *
   * What it does:
   * Releases one ADXSJD decoder backend and zeroes the runtime slot under lock.
   */
  void ADXSJD_Destroy(const std::int32_t sjdHandle)
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    if (sjdRuntime == nullptr) {
      return;
    }

    auto* const decoder = sjdRuntime->Decoder();
    if (decoder != nullptr) {
      sjdRuntime->adxbHandle = nullptr;
      ADXB_Destroy(decoder);
    }

    ADXCRS_Lock();
    std::memset(sjdRuntime, 0, sizeof(AdxsjdRuntimeView));
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B180F0 (FUN_00B180F0, _ADXSJD_GetStat)
   *
   * What it does:
   * Returns ADXSJD state byte.
   */
  std::int32_t ADXSJD_GetStat(const std::int32_t sjdHandle)
  {
    return static_cast<std::int32_t>(AsAdxsjdRuntimeView(sjdHandle)->streamFormatClass);
  }

  /**
   * Address: 0x00B18100 (FUN_00B18100, _ADXSJD_SetInSj)
   *
   * What it does:
   * Stores ADXSJD input source handle and forwards setup into attached codec lanes.
   */
  std::int32_t ADXSJD_SetInSj(const std::int32_t sjdHandle, void* const sourceJoinHandle)
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    sjdRuntime->inputSourceHandle = sourceJoinHandle;

    ADXB_SetAhxInSj(sjdRuntime->Decoder());
    ADXB_SetMpaInSj(sjdRuntime->Decoder());
    return ADXB_SetM2aInSj(sjdRuntime->Decoder());
  }

  /**
   * Address: 0x00B18140 (FUN_00B18140, _ADXSJD_SetOutSj)
   *
   * What it does:
   * Stores one ADXSJD output handle lane.
   */
  std::int32_t ADXSJD_SetOutSj(const std::int32_t sjdHandle, const std::int32_t outputLane, void* const outputHandle)
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    sjdRuntime->OutputHandle(outputLane) = reinterpret_cast<AdxsjdOutputHandle*>(outputHandle);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(outputHandle));
  }

  /**
   * Address: 0x00B18160 (FUN_00B18160, _ADXSJD_SetMaxDecSmpl)
   *
   * What it does:
   * Updates ADXSJD max decode-sample limit and forwards limit setup to attached codecs.
   */
  std::uint32_t ADXSJD_SetMaxDecSmpl(const std::int32_t sjdHandle, const std::int32_t maxDecodeSamples)
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    sjdRuntime->maxDecodeSamples = maxDecodeSamples;
    ADXB_SetAhxDecSmpl(sjdRuntime->Decoder(), maxDecodeSamples);
    return ADXB_SetMpaDecSmpl(sjdRuntime->Decoder(), maxDecodeSamples);
  }

  /**
   * Address: 0x00B18190 (FUN_00B18190, _ADXSJD_TermSupply)
   *
   * What it does:
   * Runs one terminate-supply tick across AHX/MPA/M2A codec lanes.
   */
  std::int32_t ADXSJD_TermSupply(const std::int32_t sjdHandle)
  {
    auto* const decoder = AsAdxsjdRuntimeView(sjdHandle)->Decoder();
    ADXB_AhxTermSupply(decoder);
    ADXB_MpaTermSupply(decoder);
    return ADXB_M2aTermSupply(decoder);
  }

  /**
   * Address: 0x00B181C0 (FUN_00B181C0, _ADXSJD_Start)
   *
   * What it does:
   * Clears one ADXSJD runtime state and switches it into active state `1`.
   */
  std::int32_t ADXSJD_Start(const std::int32_t sjdHandle)
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    auto* const result = adxsjd_clear(sjdRuntime);
    sjdRuntime->streamFormatClass = 1;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B181E0 (FUN_00B181E0, _ADXSJD_Stop)
   *
   * What it does:
   * Stops ADXSJD codec execution and switches runtime state to idle `0`.
   */
  std::int32_t ADXSJD_Stop(const std::int32_t sjdHandle)
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    const std::int32_t stopResult = ADXB_Stop(sjdRuntime->Decoder());
    sjdRuntime->streamFormatClass = 0;
    return stopResult;
  }

  /**
   * Address: 0x00B18440 (FUN_00B18440, _adxsjd_get_wr)
   *
   * What it does:
   * Fetches writable output chunks from ADXSJD output lanes and reports decode
   * write window/capacity/trap-distance lanes to ADXB.
   */
  std::int32_t adxsjd_get_wr(
    const std::int32_t callbackContext,
    std::int32_t* const outWriteOffsetSamples,
    std::int32_t* const outWritableSamples,
    std::int32_t* const outUntilTrapSamples
  )
  {
    auto* const runtime = reinterpret_cast<AdxsjdRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackContext))
    );

    const std::int32_t channelCount = ADXB_GetNumChan(runtime->Decoder());
    for (std::int32_t lane = 0; lane < channelCount; ++lane) {
      runtime->OutputHandle(lane)->GetChunk(0, 0x4000, &runtime->outputWriteChunks[lane]);
    }

    auto* const outputHandle0 = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(runtime->OutputHandle(0));
    *outWriteOffsetSamples = (runtime->outputWriteChunks[0].bufferAddress - SJRBF_GetBufPtr(outputHandle0)) / 2;

    std::int32_t writableSamples = runtime->outputWriteChunks[0].byteCount / 2;
    if (writableSamples >= runtime->maxDecodeSamples) {
      writableSamples = runtime->maxDecodeSamples;
    }
    *outWritableSamples = writableSamples;

    if (runtime->trapSampleCount < 0) {
      *outUntilTrapSamples = 0x1FFFFFFF;
    } else {
      *outUntilTrapSamples = runtime->trapSampleCount - runtime->trapCount;
    }

    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(ADXB_GetPcmBuf(runtime->Decoder())));
  }

  [[nodiscard]] static moho::SofdecSjSupplyHandle* AsSofdecSjSupplyHandle(void* const handle)
  {
    return reinterpret_cast<moho::SofdecSjSupplyHandle*>(handle);
  }

  [[nodiscard]] static moho::SofdecSjSupplyHandle* AsSofdecOutputSupplyHandle(AdxsjdOutputHandle* const handle)
  {
    return reinterpret_cast<moho::SofdecSjSupplyHandle*>(handle);
  }

  static void ADXSJD_GetSupplyChunk(
    moho::SofdecSjSupplyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    SjChunkRange* const outChunk
  )
  {
    handle->dispatchTable->getChunk(handle, lane, requestedBytes, outChunk);
  }

  static void ADXSJD_PutSupplyChunk(
    moho::SofdecSjSupplyHandle* const handle,
    const std::int32_t lane,
    SjChunkRange* const chunk
  )
  {
    handle->dispatchTable->putChunk(handle, lane, chunk);
  }

  static void ADXSJD_SubmitSupplyChunk(
    moho::SofdecSjSupplyHandle* const handle,
    const std::int32_t lane,
    SjChunkRange* const chunk
  )
  {
    handle->dispatchTable->submitChunk(handle, lane, chunk);
  }

  [[nodiscard]] static std::int32_t ADXSJD_QuerySupplyAvailableBytes(
    moho::SofdecSjSupplyHandle* const handle,
    const std::int32_t lane
  )
  {
    return handle->dispatchTable->queryAvailableBytes(handle, lane);
  }

  using AdxsjdTrapCallback = void(__cdecl*)(std::int32_t callbackContext);
  using AdxsjdFilterCallback =
    void(__cdecl*)(std::int32_t callbackContext, std::int32_t channelIndex, std::int32_t chunkAddress, std::int32_t chunkBytes);

  /**
   * Address: 0x00B18200 (FUN_00B18200, _adxsjd_decode_prep)
   *
   * What it does:
   * Prepares one ADXSJD decode step by aligning source stream data, decoding
   * codec headers, and transitioning runtime state into decode phase.
   */
  [[maybe_unused]] void adxsjd_decode_prep(AdxsjdRuntimeView* const runtime)
  {
    auto* const decoder = runtime->Decoder();
    auto* const sourceHandle = AsSofdecSjSupplyHandle(runtime->inputSourceHandle);

    ADXSJD_GetSupplyChunk(sourceHandle, 1, 0xC800, &runtime->outputWriteChunks[0]);

    std::int32_t firstNonZeroOffset = 0;
    while (firstNonZeroOffset < runtime->outputWriteChunks[0].byteCount) {
      const auto* const sourceBytes =
        reinterpret_cast<const std::uint8_t*>(SjAddressToPointer(runtime->outputWriteChunks[0].bufferAddress));
      if (sourceBytes[firstNonZeroOffset] != 0u) {
        break;
      }
      ++firstNonZeroOffset;
    }

    if ((firstNonZeroOffset & 1) != 0) {
      ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
      if (ADXB_GetDecErrMode() == 0) {
        ADXERR_CallErrFunc2_(kAdxsjdDecodePrepAlignmentErrorPrefix, kAdxsjdDecodePrepAlignmentErrorMessage);
      }
      runtime->streamFormatClass = 4;
      return;
    }

    SjChunkRange skippedPrefix{};
    SJ_SplitChunk(&runtime->outputWriteChunks[0], firstNonZeroOffset, &skippedPrefix, &runtime->outputWriteChunks[0]);
    ADXSJD_SubmitSupplyChunk(sourceHandle, 0, &skippedPrefix);

    const std::int32_t sourceBytesAvailable = runtime->outputWriteChunks[0].byteCount;
    std::int32_t headerConsumedBytes = 0;
    if (sourceBytesAvailable >= 16) {
      headerConsumedBytes = ADXB_DecodeHeader(
        decoder,
        reinterpret_cast<const std::uint8_t*>(SjAddressToPointer(runtime->outputWriteChunks[0].bufferAddress)),
        sourceBytesAvailable
      );
    }

    if (sourceBytesAvailable >= 16 && headerConsumedBytes != 0 && headerConsumedBytes <= sourceBytesAvailable) {
      if (headerConsumedBytes < 0) {
        const auto* const decoderView = AsAdxbRuntimeView(decoder);
        if (decoderView->preferredFormat == 0) {
          ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
          if (ADXB_GetDecErrMode() == 0) {
            ADXERR_CallErrFunc2_(kAdxsjdDecodePrepHeaderErrorPrefix, kAdxsjdDecodePrepHeaderErrorMessage);
          }
          runtime->streamFormatClass = 4;
          return;
        }

        (void)ADXB_SetDefPrm(decoder);
        headerConsumedBytes = 0;
      }

      runtime->headerLengthBytes = headerConsumedBytes;
      const std::int32_t format = ADXB_GetFormat(decoder);
      if (format == 4) {
        runtime->decodeExecState = 1;
      }

      if (format == 2) {
        std::int32_t copyBytes = sourceBytesAvailable;
        if (copyBytes > 64) {
          copyBytes = 64;
        }
        std::memcpy(
          runtime->spsdInfoState,
          SjAddressToPointer(runtime->outputWriteChunks[0].bufferAddress),
          static_cast<std::size_t>(copyBytes)
        );
      }

      if (format == 10 || format == 11 || format == 12 || format == 20 || format == 15) {
        ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
      } else {
        SjChunkRange payloadChunk{};
        SjChunkRange trailingChunk{};
        SJ_SplitChunk(&runtime->outputWriteChunks[0], headerConsumedBytes, &payloadChunk, &trailingChunk);
        ADXSJD_SubmitSupplyChunk(sourceHandle, 0, &payloadChunk);
        ADXSJD_PutSupplyChunk(sourceHandle, 1, &trailingChunk);
      }

      if (AsAdxbRuntimeView(decoder)->channelExpandHandle != 0 && ADXB_OnUpdateSampleRate != nullptr) {
        ADXB_OnUpdateSampleRate(decoder, AsAdxbRuntimeView(decoder)->sampleRate);
      }

      runtime->streamFormatClass = 2;
      return;
    }

    ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
  }

  /**
   * Address: 0x00B18510 (FUN_00B18510, _adxsjd_decexec_start)
   *
   * What it does:
   * Starts one ADXSJD decode cycle by preparing source chunk windows, handling
   * ADX footer/endcode paths, and dispatching ADXB input entry for active
   * decode formats.
   */
  [[maybe_unused]] std::int32_t adxsjd_decexec_start(AdxsjdRuntimeView* const runtime)
  {
    auto* const decoder = runtime->Decoder();
    auto* const sourceHandle = AsSofdecSjSupplyHandle(runtime->inputSourceHandle);

    if (runtime->trapSampleCount >= 0 && runtime->trapCount >= runtime->trapSampleCount) {
      if (runtime->trapCallback != nullptr) {
        const auto callback = reinterpret_cast<AdxsjdTrapCallback>(runtime->trapCallback);
        callback(runtime->trapCallbackContext);
      }
    }

    if (runtime->decodeExecState == 1u) {
      if (ADXSJD_QuerySupplyAvailableBytes(sourceHandle, 1) == 0) {
        runtime->streamFormatClass = 3;
        return 0;
      }
    }

    ADXSJD_GetSupplyChunk(sourceHandle, 1, 0x7FFFFFFF, &runtime->outputWriteChunks[0]);

    const std::int32_t sourceFormat = ADXB_GetFormat(decoder);
    if (
      sourceFormat == 0 && runtime->outputWriteChunks[0].byteCount >= 4
      && ((static_cast<std::uint16_t>(static_cast<std::uint8_t>(*reinterpret_cast<const std::uint8_t*>(
             SjAddressToPointer(runtime->outputWriteChunks[0].bufferAddress)
           )))
           << 8u)
          ^ static_cast<std::uint16_t>(static_cast<std::uint8_t>(
            *(reinterpret_cast<const std::uint8_t*>(SjAddressToPointer(runtime->outputWriteChunks[0].bufferAddress)) + 1)
          )))
          == 0x8001u
    ) {
      runtime->streamFormatClass = 3;

      std::int16_t footerBytes = 0;
      if (ADX_DecodeFooter(
            reinterpret_cast<const std::uint8_t*>(SjAddressToPointer(runtime->outputWriteChunks[0].bufferAddress)),
            runtime->outputWriteChunks[0].byteCount,
            &footerBytes
          )
          == 0) {
        const std::int32_t footerLengthBytes = static_cast<std::int32_t>(footerBytes);
        if (footerLengthBytes > runtime->outputWriteChunks[0].byteCount) {
          ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
          return 0;
        }

        SjChunkRange headerChunk{};
        SjChunkRange trailingChunk{};
        SJ_SplitChunk(&runtime->outputWriteChunks[0], footerLengthBytes, &headerChunk, &trailingChunk);
        ADXSJD_SubmitSupplyChunk(sourceHandle, 0, &headerChunk);
        ADXSJD_PutSupplyChunk(sourceHandle, 1, &trailingChunk);
      }

      if (runtime->linkSwitchEnabled != 0) {
        ADXSJD_GetSupplyChunk(sourceHandle, 1, 0x7FFFFFFF, &runtime->outputWriteChunks[0]);
        while (runtime->outputWriteChunks[0].byteCount > 0) {
          std::int32_t firstNonZeroOffset = 0;
          while (
            firstNonZeroOffset < runtime->outputWriteChunks[0].byteCount
            && *(reinterpret_cast<const std::uint8_t*>(SjAddressToPointer(runtime->outputWriteChunks[0].bufferAddress))
                 + firstNonZeroOffset)
                 == 0u
          ) {
            ++firstNonZeroOffset;
          }

          SjChunkRange zeroPrefix{};
          SjChunkRange remainder{};
          SJ_SplitChunk(&runtime->outputWriteChunks[0], firstNonZeroOffset, &zeroPrefix, &remainder);
          ADXSJD_SubmitSupplyChunk(sourceHandle, 0, &zeroPrefix);
          ADXSJD_PutSupplyChunk(sourceHandle, 1, &remainder);

          if (firstNonZeroOffset < runtime->outputWriteChunks[0].byteCount) {
            break;
          }
          ADXSJD_GetSupplyChunk(sourceHandle, 1, 0x7FFFFFFF, &runtime->outputWriteChunks[0]);
        }
      }

      return 0;
    }

    if (runtime->decodePositionSamples >= ADXSJD_GetTotalNumSmpl(static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtime)))) {
      runtime->streamFormatClass = 3;
      ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
      return 0;
    }

    const std::int32_t blockSamples = ADXSJD_GetBlkSmpl(static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtime)));
    auto* const outputHandle0 = AsSofdecOutputSupplyHandle(runtime->OutputHandle(0));
    if (ADXSJD_QuerySupplyAvailableBytes(outputHandle0, 0) / 2 < blockSamples) {
      ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
      return 0;
    }

    if (sourceFormat == 10 || sourceFormat == 11 || sourceFormat == 12) {
      ADXSJD_PutSupplyChunk(sourceHandle, 1, &runtime->outputWriteChunks[0]);
    }

    ADXB_EntryData(decoder, runtime->outputWriteChunks[0].bufferAddress, runtime->outputWriteChunks[0].byteCount);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(ADXB_Start(decoder)));
  }

  /**
   * Address: 0x00B18770 (FUN_00B18770, _adxsjd_decexec_end)
   *
   * What it does:
   * Finalizes one ADXSJD decode cycle by committing source/output chunks,
   * running optional per-channel filter callback lanes, updating counters, and
   * resetting ADXB state.
   */
  [[maybe_unused]] std::int32_t adxsjd_decexec_end(AdxsjdRuntimeView* const runtime)
  {
    auto* const decoder = runtime->Decoder();
    auto* const sourceHandle = AsSofdecSjSupplyHandle(runtime->inputSourceHandle);

    const std::int32_t totalSamples = ADXB_GetTotalNumSmpl(decoder);
    const std::int32_t decodedDataBytes = ADXB_GetDecDtLen(decoder);
    std::int32_t decodedSamples = ADXB_GetDecNumSmpl(decoder);

    const std::int32_t remainingSamples = totalSamples - runtime->decodePositionSamples;
    if (decodedSamples > remainingSamples) {
      decodedSamples = remainingSamples;
    }

    SjChunkRange committedSourceChunk{};
    SjChunkRange trailingSourceChunk{};
    SJ_SplitChunk(&runtime->outputWriteChunks[0], decodedDataBytes, &committedSourceChunk, &trailingSourceChunk);
    ADXSJD_SubmitSupplyChunk(sourceHandle, 0, &committedSourceChunk);
    ADXSJD_PutSupplyChunk(sourceHandle, 1, &trailingSourceChunk);

    const std::int32_t channelCount = ADXB_GetNumChan(decoder);
    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      SjChunkRange committedOutputChunk{};
      SjChunkRange trailingOutputChunk{};
      SJ_SplitChunk(
        &runtime->outputWriteChunks[channelIndex],
        2 * decodedSamples,
        &committedOutputChunk,
        &trailingOutputChunk
      );

      if (runtime->filterCallback != nullptr) {
        const auto filterCallback = reinterpret_cast<AdxsjdFilterCallback>(runtime->filterCallback);
        filterCallback(
          runtime->filterCallbackContext,
          channelIndex,
          committedOutputChunk.bufferAddress,
          committedOutputChunk.byteCount
        );
      }

      auto* const outputHandle = AsSofdecOutputSupplyHandle(runtime->OutputHandle(channelIndex));
      ADXSJD_SubmitSupplyChunk(outputHandle, 1, &committedOutputChunk);
      ADXSJD_PutSupplyChunk(outputHandle, 0, &trailingOutputChunk);
    }

    runtime->decodedSampleCount += decodedSamples;
    runtime->decodedDataLengthBytes += decodedDataBytes;
    runtime->decodePositionSamples += decodedSamples;
    runtime->trapCount += decodedSamples;
    runtime->trapDataLengthBytes += decodedDataBytes;

    return ADXB_Reset(decoder);
  }

  /**
   * Address: 0x00B18980 (FUN_00B18980, _adxsjd_decexec_extra)
   *
   * What it does:
   * Updates ADXSJD decode counters for codec lanes that bypass regular output
   * chunk split/submit completion handling.
   */
  [[maybe_unused]] std::int32_t adxsjd_decexec_extra(AdxsjdRuntimeView* const runtime)
  {
    auto* const decoder = runtime->Decoder();
    const std::int32_t totalSamples = ADXB_GetTotalNumSmpl(decoder);
    const std::int32_t decodedDataBytes = ADXB_GetDecDtLen(decoder);
    std::int32_t decodedSamples = ADXB_GetDecNumSmpl(decoder);

    const std::int32_t remainingSamples = totalSamples - runtime->decodePositionSamples;
    if (decodedSamples > remainingSamples) {
      decodedSamples = remainingSamples;
    }

    runtime->decodedSampleCount += decodedSamples;
    runtime->decodedDataLengthBytes += decodedDataBytes;
    runtime->decodePositionSamples += decodedSamples;
    return decodedSamples;
  }

  /**
   * Address: 0x00B18910 (FUN_00B18910, _adxsjd_decode_exec)
   *
   * What it does:
   * Runs one ADXSJD decode step (`start/exec/end`) and dispatches codec-specific
   * extra accounting for streamed compressed formats.
   */
  [[maybe_unused]] std::int32_t adxsjd_decode_exec(AdxsjdRuntimeView* const runtime)
  {
    auto* const decoder = runtime->Decoder();
    if (ADXB_GetStat(decoder) == 0) {
      (void)adxsjd_decexec_start(runtime);
    }

    ADXB_ExecHndl(decoder);
    if (ADXB_GetStat(decoder) == 3) {
      (void)adxsjd_decexec_end(runtime);
    }

    const std::int32_t format = ADXB_GetFormat(decoder);
    if (format == 10 || format == 20 || format == 11 || format == 12 || format == 15) {
      return adxsjd_decexec_extra(runtime);
    }
    return format;
  }

  /**
   * Address: 0x00B189D0 (FUN_00B189D0, _adxsjd_insert_proc)
   *
   * What it does:
   * Inserts silence samples into every ADXSJD output lane by zero-filling
   * writable lane-0 chunks and submitting them to lane 1.
   */
  [[maybe_unused]] std::int32_t adxsjd_insert_proc(AdxsjdRuntimeView* const runtime)
  {
    std::int32_t insertBytes = 2 * runtime->positiveSampleAdjust;
    const std::int32_t outputHandleCount = runtime->OutputChannelCount();

    for (std::int32_t lane = 0; lane < outputHandleCount; ++lane) {
      auto* const outputHandle = AsSofdecOutputSupplyHandle(runtime->OutputHandle(lane));
      SjChunkRange chunk{};
      ADXSJD_GetSupplyChunk(outputHandle, 0, 0x7FFFFFFF, &chunk);
      if (insertBytes > chunk.byteCount) {
        insertBytes = chunk.byteCount;
      }
      ADXSJD_PutSupplyChunk(outputHandle, 0, &chunk);
    }

    const std::int32_t insertedSamples = insertBytes / 2;
    const std::int32_t fillBytes = 2 * insertedSamples;
    if (fillBytes > 0) {
      for (std::int32_t lane = 0; lane < outputHandleCount; ++lane) {
        auto* const outputHandle = AsSofdecOutputSupplyHandle(runtime->OutputHandle(lane));
        SjChunkRange chunk{};
        ADXSJD_GetSupplyChunk(outputHandle, 0, fillBytes, &chunk);
        std::memset(SjAddressToPointer(chunk.bufferAddress), 0, static_cast<std::size_t>(fillBytes));
        ADXSJD_SubmitSupplyChunk(outputHandle, 1, &chunk);
      }
      runtime->positiveSampleAdjust -= insertedSamples;
    }

    return insertedSamples;
  }

  /**
   * Address: 0x00B18AB0 (FUN_00B18AB0, _adxsjd_discard_proc)
   *
   * What it does:
   * Discards queued ADXSJD lane-1 samples across all output lanes by consuming
   * chunks and returning them into lane 0.
   */
  [[maybe_unused]] std::int32_t adxsjd_discard_proc(AdxsjdRuntimeView* const runtime)
  {
    std::int32_t discardBytes = 2 * runtime->negativeSampleAdjust;
    const std::int32_t outputHandleCount = runtime->OutputChannelCount();

    for (std::int32_t lane = 0; lane < outputHandleCount; ++lane) {
      auto* const outputHandle = AsSofdecOutputSupplyHandle(runtime->OutputHandle(lane));
      SjChunkRange chunk{};
      ADXSJD_GetSupplyChunk(outputHandle, 1, 0x7FFFFFFF, &chunk);
      if (discardBytes > chunk.byteCount) {
        discardBytes = chunk.byteCount;
      }
      ADXSJD_PutSupplyChunk(outputHandle, 1, &chunk);
    }

    const std::int32_t discardedSamples = discardBytes / 2;
    const std::int32_t consumeBytes = 2 * discardedSamples;
    if (consumeBytes > 0) {
      for (std::int32_t lane = 0; lane < outputHandleCount; ++lane) {
        auto* const outputHandle = AsSofdecOutputSupplyHandle(runtime->OutputHandle(lane));
        SjChunkRange chunk{};
        ADXSJD_GetSupplyChunk(outputHandle, 1, consumeBytes, &chunk);
        ADXSJD_SubmitSupplyChunk(outputHandle, 0, &chunk);
      }
      runtime->negativeSampleAdjust -= discardedSamples;
    }

    return discardedSamples;
  }

  /**
   * Address: 0x00B188B0 (FUN_00B188B0, _ADXSJD_ExecHndl)
   *
   * What it does:
   * Runs one ADXSJD runtime tick: applies pending sample insert/discard lanes
   * under lock, then executes decode-prep/decode phases by state byte.
   */
  [[maybe_unused]] void ADXSJD_ExecHndl(AdxsjdRuntimeView* const runtime)
  {
    if (runtime->positiveSampleAdjust > 0) {
      ADXCRS_Lock();
      (void)adxsjd_insert_proc(runtime);
      ADXCRS_Unlock();
    }

    if (runtime->streamFormatClass == 2) {
      (void)adxsjd_decode_exec(runtime);
    } else if (runtime->streamFormatClass == 1) {
      adxsjd_decode_prep(runtime);
    }

    if (runtime->negativeSampleAdjust > 0) {
      ADXCRS_Lock();
      (void)adxsjd_discard_proc(runtime);
      ADXCRS_Unlock();
    }
  }

  /**
   * Address: 0x00B18B70 (FUN_00B18B70, _ADXSJD_ExecServer)
   *
   * What it does:
   * Iterates ADXSJD runtime pool and executes active runtime lanes.
   */
  [[maybe_unused]] void ADXSJD_ExecServer()
  {
    for (auto& runtime : gAdxsjdObjectPool) {
      if (runtime.used == 1u) {
        ADXSJD_ExecHndl(&runtime);
      }
    }
  }

  /**
   * Address: 0x00B18BA0 (FUN_00B18BA0, _ADXSJD_GetDecDtLen)
   *
   * What it does:
   * Returns decoded output-data length lane.
   */
  std::int32_t ADXSJD_GetDecDtLen(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->decodedDataLengthBytes;
  }

  /**
   * Address: 0x00B18BB0 (FUN_00B18BB0, _ADXSJD_GetDecNumSmpl)
   *
   * What it does:
   * Returns decoded output-sample count lane.
   */
  std::int32_t ADXSJD_GetDecNumSmpl(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->decodedSampleCount;
  }

  /**
   * Address: 0x00B18BC0 (FUN_00B18BC0, _ADXSJD_SetCbDec)
   *
   * What it does:
   * Forwards decode callback registration into underlying ADXB decoder.
   */
  std::int32_t ADXSJD_SetCbDec(
    const std::int32_t sjdHandle,
    void* const callbackAddress,
    const std::int32_t callbackContext
  )
  {
    auto* const decoder = AsAdxsjdRuntimeView(sjdHandle)->Decoder();
    return static_cast<std::int32_t>(
      reinterpret_cast<std::intptr_t>(
        ADXB_SetCbDec(
          decoder,
          reinterpret_cast<std::int32_t(__cdecl*)(std::int32_t, std::int32_t, std::int32_t)>(callbackAddress),
          callbackContext
        )
      )
    );
  }

  /**
   * Address: 0x00B18BD0 (FUN_00B18BD0, _ADXSJD_SetDecPos)
   *
   * What it does:
   * Stores decode-position lane.
   */
  std::int32_t ADXSJD_SetDecPos(const std::int32_t sjdHandle, const std::int32_t decodePosition)
  {
    AsAdxsjdRuntimeView(sjdHandle)->decodePositionSamples = decodePosition;
    return decodePosition;
  }

  /**
   * Address: 0x00B18BE0 (FUN_00B18BE0, _ADXSJD_GetDecPos)
   *
   * What it does:
   * Returns decode-position lane.
   */
  std::int32_t ADXSJD_GetDecPos(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->decodePositionSamples;
  }

  /**
   * Address: 0x00B18BF0 (FUN_00B18BF0, _ADXSJD_SetLnkSw)
   *
   * What it does:
   * Stores ADXSJD link-switch enable lane.
   */
  std::int32_t ADXSJD_SetLnkSw(const std::int32_t sjdHandle, const std::int32_t enabled)
  {
    AsAdxsjdRuntimeView(sjdHandle)->linkSwitchEnabled = enabled;
    return enabled;
  }

  /**
   * Address: 0x00B18C00 (FUN_00B18C00, _ADXSJD_GetLnkSw)
   *
   * What it does:
   * Returns ADXSJD link-switch enable lane.
   */
  std::int32_t ADXSJD_GetLnkSw(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->linkSwitchEnabled;
  }

  /**
   * Address: 0x00B18C10 (FUN_00B18C10, _ADXSJD_SetExtString)
   *
   * What it does:
   * Forwards ADXSJD ext-string setup into ADXB/ADXSJE lane.
   */
  moho::AdxBitstreamDecoderState* ADXSJD_SetExtString(const std::int32_t sjdHandle, const char* const extString)
  {
    return ADXSJE_SetExtString(AsAdxsjdRuntimeView(sjdHandle)->Decoder(), extString);
  }

  /**
   * Address: 0x00B18C20 (FUN_00B18C20, _ADXSJD_SetDefExtString)
   *
   * What it does:
   * Forwards default ext-string setup into ADXB lane.
   */
  std::int32_t ADXSJD_SetDefExtString(const char* const extString)
  {
    return ADXB_SetDefExtString(extString);
  }

  /**
   * Address: 0x00B18C30 (FUN_00B18C30, _ADXSJD_GetExtParams)
   *
   * What it does:
   * Returns ADXSJD ext parameter triplet from underlying ADXB decoder.
   */
  std::int16_t ADXSJD_GetExtParams(
    const std::int32_t sjdHandle,
    std::int16_t* const outK0,
    std::int16_t* const outKMultiplier,
    std::int16_t* const outKAdder
  )
  {
    return ADXB_GetExtParams(AsAdxsjdRuntimeView(sjdHandle)->Decoder(), outK0, outKMultiplier, outKAdder);
  }

  /**
   * Address: 0x00B18C40 (FUN_00B18C40, _ADXSJD_SetExtParams)
   *
   * What it does:
   * Stores ADXSJD ext parameter triplet into underlying ADXB decoder.
   */
  moho::AdxBitstreamDecoderState* ADXSJD_SetExtParams(
    const std::int32_t sjdHandle,
    const std::int16_t k0,
    const std::int16_t kMultiplier,
    const std::int16_t kAdder
  )
  {
    return ADXB_SetExtParams(AsAdxsjdRuntimeView(sjdHandle)->Decoder(), k0, kMultiplier, kAdder);
  }

  /**
   * Address: 0x00B18C70 (FUN_00B18C70, _ADXSJD_SetDefFmt)
   *
   * What it does:
   * Forwards ADXSJD default-format selection into ADXB decoder lane.
   */
  std::int32_t ADXSJD_SetDefFmt(const std::int32_t sjdHandle, const std::int32_t requestedFormat)
  {
    auto* const decoder = AsAdxsjdRuntimeView(sjdHandle)->Decoder();
    ADXB_SetDefFmt(decoder, requestedFormat);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(decoder));
  }

  /**
   * Address: 0x00B18C80 (FUN_00B18C80, _ADXSJD_AdjustSmpl)
   *
   * What it does:
   * Adjusts ADXSJD positive/negative sample correction counters under lock.
   */
  std::int32_t ADXSJD_AdjustSmpl(const std::int32_t sjdHandle, const std::int32_t sampleDelta)
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    ADXCRS_Lock();
    if (sampleDelta <= 0) {
      sjdRuntime->negativeSampleAdjust -= sampleDelta;
    } else {
      sjdRuntime->positiveSampleAdjust += sampleDelta;
    }
    ADXCRS_Unlock();
    return sampleDelta;
  }

  /**
   * Address: 0x00B18CB0 (FUN_00B18CB0, _ADXSJD_EntryFltFunc)
   *
   * What it does:
   * Registers ADXSJD filter callback and callback context.
   */
  std::int32_t ADXSJD_EntryFltFunc(
    const std::int32_t sjdHandle,
    void* const callbackAddress,
    const std::int32_t callbackContext
  )
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    sjdRuntime->filterCallback = callbackAddress;
    sjdRuntime->filterCallbackContext = callbackContext;
    return sjdHandle;
  }

  /**
   * Address: 0x00B18CD0 (FUN_00B18CD0, _ADXSJD_EntryTrapFunc)
   *
   * What it does:
   * Registers ADXSJD trap callback and callback context.
   */
  std::int32_t ADXSJD_EntryTrapFunc(
    const std::int32_t sjdHandle,
    void* const callbackAddress,
    const std::int32_t callbackContext
  )
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    sjdRuntime->trapCallback = callbackAddress;
    sjdRuntime->trapCallbackContext = callbackContext;
    return sjdHandle;
  }

  /**
   * Address: 0x00B18CF0 (FUN_00B18CF0, _ADXSJD_SetTrapNumSmpl)
   *
   * What it does:
   * Stores ADXSJD trap target sample-count lane.
   */
  std::int32_t ADXSJD_SetTrapNumSmpl(const std::int32_t sjdHandle, const std::int32_t trapSampleCount)
  {
    AsAdxsjdRuntimeView(sjdHandle)->trapSampleCount = trapSampleCount;
    return trapSampleCount;
  }

  /**
   * Address: 0x00B18D00 (FUN_00B18D00, _ADXSJD_GetTrapNumSmpl)
   *
   * What it does:
   * Returns ADXSJD trap target sample-count lane.
   */
  std::int32_t ADXSJD_GetTrapNumSmpl(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->trapSampleCount;
  }

  /**
   * Address: 0x00B18D10 (FUN_00B18D10, _ADXSJD_SetTrapCnt)
   *
   * What it does:
   * Stores ADXSJD trap-hit counter lane.
   */
  std::int32_t ADXSJD_SetTrapCnt(const std::int32_t sjdHandle, const std::int32_t trapCount)
  {
    AsAdxsjdRuntimeView(sjdHandle)->trapCount = trapCount;
    return trapCount;
  }

  /**
   * Address: 0x00B18D20 (FUN_00B18D20, _ADXSJD_GetTrapCnt)
   *
   * What it does:
   * Returns ADXSJD trap-hit counter lane.
   */
  std::int32_t ADXSJD_GetTrapCnt(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->trapCount;
  }

  /**
   * Address: 0x00B18D30 (FUN_00B18D30, _ADXSJD_SetTrapDtLen)
   *
   * What it does:
   * Stores ADXSJD trap target decoded-data length lane.
   */
  std::int32_t ADXSJD_SetTrapDtLen(const std::int32_t sjdHandle, const std::int32_t trapDataLengthBytes)
  {
    AsAdxsjdRuntimeView(sjdHandle)->trapDataLengthBytes = trapDataLengthBytes;
    return trapDataLengthBytes;
  }

  /**
   * Address: 0x00B18D40 (FUN_00B18D40, _ADXSJD_GetTrapDtLen)
   *
   * What it does:
   * Returns ADXSJD trap target decoded-data length lane.
   */
  std::int32_t ADXSJD_GetTrapDtLen(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->trapDataLengthBytes;
  }

  /**
   * Address: 0x00B18D50 (FUN_00B18D50, _ADXSJD_GetFormat)
   *
   * What it does:
   * Returns active ADXSJD decode format class from ADXB decoder lane.
   */
  std::int32_t ADXSJD_GetFormat(const std::int32_t sjdHandle)
  {
    return ADXB_GetFormat(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18D60 (FUN_00B18D60, _ADXSJD_GetSfreq)
   *
   * What it does:
   * Returns active ADXSJD sample-rate lane from ADXB decoder.
   */
  std::int32_t ADXSJD_GetSfreq(const std::int32_t sjdHandle)
  {
    return ADXB_GetSfreq(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18D70 (FUN_00B18D70, _ADXSJD_GetNumChan)
   */
  std::int32_t ADXSJD_GetNumChan(const std::int32_t sjdHandle)
  {
    return ResolveAdxsjdChannelCount(sjdHandle);
  }

  /**
   * Address: 0x00B18D80 (FUN_00B18D80, _ADXSJD_GetOutBps)
   */
  std::int32_t ADXSJD_GetOutBps(const std::int32_t sjdHandle)
  {
    return ADXB_GetOutBps(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18D90 (FUN_00B18D90, _ADXSJD_GetBlkSmpl)
   */
  std::int32_t ADXSJD_GetBlkSmpl(const std::int32_t sjdHandle)
  {
    return ADXB_GetBlkSmpl(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18DA0 (FUN_00B18DA0, _ADXSJD_GetBlkLen)
   */
  std::int32_t ADXSJD_GetBlkLen(const std::int32_t sjdHandle)
  {
    return ADXB_GetBlkLen(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18DB0 (FUN_00B18DB0, _ADXSJD_GetTotalNumSmpl)
   */
  std::int32_t ADXSJD_GetTotalNumSmpl(const std::int32_t sjdHandle)
  {
    return ADXB_GetTotalNumSmpl(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18DC0 (FUN_00B18DC0, _ADXSJD_GetCof)
   */
  std::int32_t ADXSJD_GetCof(const std::int32_t sjdHandle)
  {
    return ADXB_GetCof(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18DD0 (FUN_00B18DD0, _ADXSJD_GetNumLoop)
   */
  std::int32_t ADXSJD_GetNumLoop(const std::int32_t sjdHandle)
  {
    return ADXB_GetNumLoop(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18DE0 (FUN_00B18DE0, _ADXSJD_GetLpInsNsmpl)
   */
  std::int32_t ADXSJD_GetLpInsNsmpl(const std::int32_t sjdHandle)
  {
    return ADXB_GetLpInsNsmpl(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18DF0 (FUN_00B18DF0, _ADXSJD_GetLpStartPos)
   */
  std::int32_t ADXSJD_GetLpStartPos(const std::int32_t sjdHandle)
  {
    return ADXB_GetLpStartPos(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18E00 (FUN_00B18E00, _ADXSJD_GetLpStartOfst)
   */
  std::int32_t ADXSJD_GetLpStartOfst(const std::int32_t sjdHandle)
  {
    if (sjdHandle != 0) {
      return ADXB_GetLpStartOfst(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
    }
    return sjdHandle;
  }

  /**
   * Address: 0x00B18E20 (FUN_00B18E20, _ADXSJD_GetLpEndPos)
   */
  std::int32_t ADXSJD_GetLpEndPos(const std::int32_t sjdHandle)
  {
    return ADXB_GetLpEndPos(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18E30 (FUN_00B18E30, _ADXSJD_GetLpEndOfst)
   */
  std::int32_t ADXSJD_GetLpEndOfst(const std::int32_t sjdHandle)
  {
    return ADXB_GetLpEndOfst(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18E40 (FUN_00B18E40, _ADXSJD_GetAinfLen)
   */
  std::int32_t ADXSJD_GetAinfLen(const std::int32_t sjdHandle)
  {
    return ADXB_GetAinfLen(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18E50 (FUN_00B18E50, _ADXSJD_GetDefOutVol)
   */
  std::int16_t ADXSJD_GetDefOutVol(const std::int32_t sjdHandle)
  {
    auto* const runtime = AsAdxsjdRuntimeView(sjdHandle);
    if (
      ADXB_GetAinfLen(runtime->Decoder()) > 0
      && (runtime->streamFormatClass == 2 || runtime->streamFormatClass == 3)
    ) {
      return ADXB_GetDefOutVol(runtime->Decoder());
    }
    return 0;
  }

  /**
   * Address: 0x00B18E90 (FUN_00B18E90, _ADXSJD_GetDefPan)
   */
  std::int16_t ADXSJD_GetDefPan(const std::int32_t sjdHandle, const std::int32_t laneIndex)
  {
    return ResolveAdxsjdDefaultPanLane(sjdHandle, laneIndex);
  }

  /**
   * Address: 0x00B18ED0 (FUN_00B18ED0, _ADXSJD_GetDataId)
   */
  std::uint8_t* ADXSJD_GetDataId(const std::int32_t sjdHandle)
  {
    auto* const runtime = AsAdxsjdRuntimeView(sjdHandle);
    if (
      ADXB_GetAinfLen(runtime->Decoder()) > 0
      && (runtime->streamFormatClass == 2 || runtime->streamFormatClass == 3)
    ) {
      return ADXB_GetDataId(runtime->Decoder());
    }
    return nullptr;
  }

  /**
   * Address: 0x00B18F10 (FUN_00B18F10, _ADXSJD_GetHdrLen)
   */
  std::int32_t ADXSJD_GetHdrLen(const std::int32_t sjdHandle)
  {
    return AsAdxsjdRuntimeView(sjdHandle)->headerLengthBytes;
  }

  /**
   * Address: 0x00B18F20 (FUN_00B18F20, _ADXSJD_GetFmtBps)
   */
  std::int32_t ADXSJD_GetFmtBps(const std::int32_t sjdHandle)
  {
    return ADXB_GetFmtBps(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18F30 (FUN_00B18F30, _ADXSJD_GetSpsdInfo)
   */
  std::int32_t ADXSJD_GetSpsdInfo(const std::int32_t sjdHandle)
  {
    auto* const runtime = AsAdxsjdRuntimeView(sjdHandle);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(&runtime->spsdInfoState[0]));
  }

  /**
   * Address: 0x00B18F40 (FUN_00B18F40, _ADXSJD_TakeSnapshot)
   */
  std::int32_t ADXSJD_TakeSnapshot(const std::int32_t sjdHandle)
  {
    return ADXB_TakeSnapshot(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B18F50 (FUN_00B18F50, _ADXSJD_RestoreSnapshot)
   */
  std::int32_t ADXSJD_RestoreSnapshot(const std::int32_t sjdHandle)
  {
    return ADXB_RestoreSnapshot(AsAdxsjdRuntimeView(sjdHandle)->Decoder());
  }

  /**
   * Address: 0x00B0D380 (FUN_00B0D380, _ADXT_GetStat)
   *
   * What it does:
   * Returns one ADXT runtime status byte under legacy enter/leave guard wrappers.
   */
  std::int32_t ADXT_GetStat(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t status = adxt_GetStat(adxtRuntime);
    ADXCRS_Leave();
    return status;
  }

  /**
   * Address: 0x00B0D3A0 (FUN_00B0D3A0, _adxt_GetStat)
   *
   * What it does:
   * Returns one ADXT runtime status byte or reports parameter error for null runtime.
   */
  std::int32_t adxt_GetStat(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetStatParameterErrorMessage);
    }
    return static_cast<std::int32_t>(static_cast<std::int8_t>(runtime->mUnknown01));
  }

  /**
   * Address: 0x00B0D3C0 (FUN_00B0D3C0, _ADXT_SetTimeMode)
   *
   * What it does:
   * Updates ADXT global time-mode lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetTimeMode(const std::int32_t timeMode)
  {
    ADXCRS_Enter();
    (void)adxt_SetTimeMode(timeMode);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D3E0 (FUN_00B0D3E0, _adxt_SetTimeMode)
   *
   * What it does:
   * Stores ADXT global time-mode lane and updates time-to-vsync scale presets
   * for mode `1` and mode `2`.
   */
  std::int32_t adxt_SetTimeMode(const std::int32_t timeMode)
  {
    if (timeMode == 1) {
      gAdxtTimeToVsyncScale = 5994;
      gAdxtTimeMode = 1;
    } else {
      if (timeMode == 2) {
        gAdxtTimeToVsyncScale = 5000;
      }
      gAdxtTimeMode = timeMode;
    }
    return timeMode;
  }

  /**
   * Address: 0x00B0D410 (FUN_00B0D410, _ADXT_GetTimeSfreq)
   *
   * What it does:
   * Runs ADXT playback time units/frequency query under ADXCRS enter/leave
   * guards.
   */
  void ADXT_GetTimeSfreq(
    void* const adxtRuntime,
    std::int32_t* const outTimeUnits,
    std::int32_t* const outTimeScale
  )
  {
    ADXCRS_Enter();
    (void)adxt_GetTimeSfreq(adxtRuntime, outTimeUnits, outTimeScale);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D440 (FUN_00B0D440, _adxt_GetTimeSfreq)
   *
   * What it does:
   * Returns ADXT playback time units/frequency pair from RNA/SJD lanes and
   * applies runtime time offset lane.
   */
  std::int32_t adxt_GetTimeSfreq(
    void* const adxtRuntime,
    std::int32_t* const outTimeUnits,
    std::int32_t* const outTimeScale
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const auto status = static_cast<std::uint8_t>(runtime->mUnknown01);
    if (status == 3u || status == 4u) {
      ADXRNA_GetTime(runtime->rnaHandle, outTimeUnits, outTimeScale);
      *outTimeUnits += runtime->linkReadCursor;
      return *outTimeUnits;
    }

    if (status == 5u) {
      *outTimeUnits = ADXSJD_GetTotalNumSmpl(runtime->sjdHandle);
      *outTimeScale = ADXSJD_GetSfreq(runtime->sjdHandle);
      *outTimeUnits *= 16 / ADXSJD_GetOutBps(runtime->sjdHandle);
      *outTimeUnits += runtime->linkReadCursor;
      return *outTimeUnits;
    }

    *outTimeUnits = 0;
    *outTimeScale = 1;
    *outTimeUnits += runtime->linkReadCursor;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(outTimeUnits));
  }

  /**
   * Address: 0x00B0D4F0 (FUN_00B0D4F0, _ADXT_GetTimeSfreq2)
   *
   * What it does:
   * Runs secondary ADXT playback time units/frequency query under ADXCRS
   * enter/leave guards.
   */
  void ADXT_GetTimeSfreq2(
    void* const adxtRuntime,
    std::int32_t* const outTimeUnits,
    std::int32_t* const outTimeScale
  )
  {
    ADXCRS_Enter();
    (void)adxt_GetTimeSfreq2(adxtRuntime, outTimeUnits, outTimeScale);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D520 (FUN_00B0D520, _adxt_GetTimeSfreq2)
   *
   * What it does:
   * Returns ADXT decode-progress-based playback time units/frequency pair and
   * applies runtime time offset with floor-to-zero clamp.
   */
  std::int32_t adxt_GetTimeSfreq2(
    void* const adxtRuntime,
    std::int32_t* const outTimeUnits,
    std::int32_t* const outTimeScale
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const auto status = static_cast<std::uint8_t>(runtime->mUnknown01);
    if (status == 3u || status == 4u) {
      *outTimeScale = ADXSJD_GetSfreq(runtime->sjdHandle);
      const std::int32_t decodedSamples = ADXSJD_GetDecNumSmpl(runtime->sjdHandle);
      const std::int32_t queuedRnaSamples = ADXRNA_GetNumData(runtime->rnaHandle);
      *outTimeUnits =
        decodedSamples + runtime->PlaybackTimeDeltaFrames() - queuedRnaSamples - adxt_GetNumSmplObuf(runtime, 0);
    } else if (status == 5u) {
      *outTimeUnits = ADXSJD_GetTotalNumSmpl(runtime->sjdHandle);
      *outTimeScale = ADXSJD_GetSfreq(runtime->sjdHandle);
      *outTimeUnits *= 16 / ADXSJD_GetOutBps(runtime->sjdHandle);
      *outTimeUnits += runtime->PlaybackTimeDeltaFrames();
    } else {
      *outTimeUnits = 0;
      *outTimeScale = 1;
    }

    const std::int32_t offsetAppliedUnits = runtime->linkReadCursor + *outTimeUnits;
    *outTimeUnits = (offsetAppliedUnits < 0) ? 0 : offsetAppliedUnits;
    return offsetAppliedUnits;
  }

  /**
   * Address: 0x00B0D5F0 (FUN_00B0D5F0)
   *
   * What it does:
   * Increments ADXT auxiliary timing counter lane.
   */
  void ADXT_IncrementAuxTimeCounter()
  {
    ++gAdxtTimeAuxCounter;
  }

  /**
   * Address: 0x00B0D600 (FUN_00B0D600, _ADXT_GetTime)
   *
   * What it does:
   * Runs ADXT playback time query under ADXCRS enter/leave guards.
   */
  void ADXT_GetTime(void* const adxtRuntime, std::int32_t* const outTimeUnits, std::int32_t* const outTimeScale)
  {
    ADXCRS_Enter();
    adxt_GetTime(adxtRuntime, outTimeUnits, outTimeScale);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D8D0 (FUN_00B0D8D0, _ADXT_GetNumChan)
   *
   * What it does:
   * Returns active ADXT decode channel count under legacy enter/leave wrappers.
   */
  std::int32_t ADXT_GetNumChan(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t channelCount = adxt_GetNumChan(adxtRuntime);
    ADXCRS_Leave();
    return channelCount;
  }

  /**
   * Address: 0x00B0D8F0 (FUN_00B0D8F0, _adxt_GetNumChan)
   *
   * What it does:
   * Returns decoder channel count once ADXT runtime has entered decode-active states.
   */
  std::int32_t adxt_GetNumChan(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetNumChanParameterErrorMessage);
    }
    if (static_cast<std::int8_t>(runtime->mUnknown01) < 2) {
      return 0;
    }
    return ADXSJD_GetNumChan(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0D7E0 (FUN_00B0D7E0, _ADXT_GetTimeReal)
   *
   * What it does:
   * Returns ADXT playback time percentage under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetTimeReal(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t timePercent = adxt_GetTimeReal(adxtRuntime);
    ADXCRS_Leave();
    return timePercent;
  }

  /**
   * Address: 0x00B0D800 (FUN_00B0D800, _adxt_GetTimeReal)
   *
   * What it does:
   * Returns ADXT playback time percentage from current time units/scale.
   */
  std::int32_t adxt_GetTimeReal(void* const adxtRuntime)
  {
    std::int32_t timeUnits = 0;
    std::int32_t timeScale = 0;
    adxt_GetTime(adxtRuntime, &timeUnits, &timeScale);
    return static_cast<std::int32_t>((static_cast<double>(timeUnits) / static_cast<double>(timeScale)) * 100.0);
  }

  /**
   * Address: 0x00B0D830 (FUN_00B0D830, _ADXT_GetNumSmpl)
   *
   * What it does:
   * Returns ADXT total sample count under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetNumSmpl(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t totalSamples = adxt_GetNumSmpl(adxtRuntime);
    ADXCRS_Leave();
    return totalSamples;
  }

  /**
   * Address: 0x00B0D850 (FUN_00B0D850, _adxt_GetNumSmpl)
   *
   * What it does:
   * Returns ADXT total sample count when decode state is active.
   */
  std::int32_t adxt_GetNumSmpl(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetNumSmplParameterErrorMessage);
    }
    if (static_cast<std::int8_t>(runtime->mUnknown01) < 2) {
      return 0;
    }
    return ADXSJD_GetTotalNumSmpl(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0D880 (FUN_00B0D880, _ADXT_GetSfreq)
   *
   * What it does:
   * Returns ADXT sample-rate lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetSfreq(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t sampleRate = adxt_GetSfreq(adxtRuntime);
    ADXCRS_Leave();
    return sampleRate;
  }

  /**
   * Address: 0x00B0D8A0 (FUN_00B0D8A0, _adxt_GetSfreq)
   *
   * What it does:
   * Returns ADXT sample-rate lane when decode state is active.
   */
  std::int32_t adxt_GetSfreq(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetSfreqParameterErrorMessage);
    }
    if (static_cast<std::int8_t>(runtime->mUnknown01) < 2) {
      return 0;
    }
    return ADXSJD_GetSfreq(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0D920 (FUN_00B0D920, _ADXT_GetHdrLen)
   *
   * What it does:
   * Returns ADXT header-length lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetHdrLen(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t headerLength = adxt_GetHdrLen(adxtRuntime);
    ADXCRS_Leave();
    return headerLength;
  }

  /**
   * Address: 0x00B0D940 (FUN_00B0D940, _adxt_GetHdrLen)
   *
   * What it does:
   * Returns ADXT stream-header length when decode state is active.
   */
  std::int32_t adxt_GetHdrLen(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetHdrLenParameterErrorMessage);
    }
    if (static_cast<std::int8_t>(runtime->mUnknown01) < 2) {
      return 0;
    }
    return ADXSJD_GetHdrLen(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0D970 (FUN_00B0D970, _ADXT_GetFmtBps)
   *
   * What it does:
   * Returns ADXT format bit-depth under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetFmtBps(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t formatBitDepth = adxt_GetFmtBps(adxtRuntime);
    ADXCRS_Leave();
    return formatBitDepth;
  }

  /**
   * Address: 0x00B0D990 (FUN_00B0D990, _adxt_GetFmtBps)
   *
   * What it does:
   * Returns ADXT format bit-depth when decode state is active.
   */
  std::int32_t adxt_GetFmtBps(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtGetFmtBpsParameterErrorMessage);
    }
    if (static_cast<std::int8_t>(runtime->mUnknown01) < 2) {
      return 0;
    }
    return ADXSJD_GetFmtBps(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0E8F0 (FUN_00B0E8F0, _ADXT_EntryErrFunc)
   *
   * What it does:
   * Registers ADXT error callback lane through ADXERR callback owner.
   */
  void ADXT_EntryErrFunc(const moho::AdxmErrorCallback callbackFunction, const std::int32_t callbackObject)
  {
    ADXERR_EntryErrFunc(callbackFunction, callbackObject);
  }

  /**
   * Address: 0x00B0E900 (FUN_00B0E900, _ADXT_DiscardSmpl)
   *
   * What it does:
   * Runs ADXT discard-sample lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_DiscardSmpl(void* const adxtRuntime, const std::int32_t sampleCount)
  {
    ADXCRS_Enter();
    const std::int32_t discardResult = adxt_DiscardSmpl(adxtRuntime, sampleCount);
    ADXCRS_Leave();
    return discardResult;
  }

  /**
   * Address: 0x00B0E930 (FUN_00B0E930, _adxt_DiscardSmpl)
   *
   * What it does:
   * Discards ADXT samples, executes server tick, and refreshes playback time anchor lanes.
   */
  std::int32_t adxt_DiscardSmpl(void* const adxtRuntime, const std::int32_t sampleCount)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime->ErrorCheckSuppressedFlag() == 0u) {
      return 0;
    }

    const std::int32_t discardResult = ADXRNA_DiscardSamples(runtime->rnaHandle, sampleCount);
    ADXT_ExecServer();

    const std::int32_t previousTimeMode = gAdxtTimeMode;
    gAdxtTimeMode = 0;

    std::int32_t currentTimeUnits = 0;
    std::int32_t currentTimeScale = 0;
    adxt_GetTime(runtime, &currentTimeUnits, &currentTimeScale);
    gAdxtTimeMode = previousTimeMode;

    runtime->PlaybackTimeBaseFrames() = static_cast<std::int32_t>(
      (static_cast<double>(currentTimeUnits) / static_cast<double>(currentTimeScale))
      * static_cast<double>(gAdxtTimeToVsyncScale)
    );
    runtime->PlaybackTimeVsyncAnchor() = gAdxtVsyncCount;
    return discardResult;
  }

  /**
   * Address: 0x00B0E9B0 (FUN_00B0E9B0, _ADXT_GetTimeOfst)
   *
   * What it does:
   * Returns ADXT time-offset lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetTimeOfst(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t timeOffset = adxt_GetTimeOfst(adxtRuntime);
    ADXCRS_Leave();
    return timeOffset;
  }

  /**
   * Address: 0x00B0E9D0 (FUN_00B0E9D0, _adxt_GetTimeOfst)
   *
   * What it does:
   * Returns ADXT runtime time-offset lane.
   */
  std::int32_t adxt_GetTimeOfst(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return runtime->linkReadCursor;
  }

  /**
   * Address: 0x00B0E9E0 (FUN_00B0E9E0, _ADXT_SetTimeOfst)
   *
   * What it does:
   * Stores ADXT time-offset lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetTimeOfst(void* const adxtRuntime, const std::int32_t timeOffset)
  {
    ADXCRS_Enter();
    (void)adxt_SetTimeOfst(adxtRuntime, timeOffset);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0EA00 (FUN_00B0EA00, _adxt_SetTimeOfst)
   *
   * What it does:
   * Stores ADXT runtime time-offset lane and returns the stored value.
   */
  std::int32_t adxt_SetTimeOfst(void* const adxtRuntime, const std::int32_t timeOffset)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    runtime->linkReadCursor = timeOffset;
    return timeOffset;
  }

  /**
   * Address: 0x00B0EA10 (FUN_00B0EA10, _ADXT_AdjustSmpl)
   *
   * What it does:
   * Runs ADXT sample-adjust lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_AdjustSmpl(void* const adxtRuntime, const std::int32_t sampleDelta)
  {
    ADXCRS_Enter();
    const std::int32_t adjustResult = adxt_AdjustSmpl(adxtRuntime, sampleDelta);
    ADXCRS_Leave();
    return adjustResult;
  }

  /**
   * Address: 0x00B0EA40 (FUN_00B0EA40, _adxt_AdjustSmpl)
   *
   * What it does:
   * Forwards one ADXT sample-adjust request into ADXSJD adjust lane.
   */
  std::int32_t adxt_AdjustSmpl(void* const adxtRuntime, const std::int32_t sampleDelta)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return ADXSJD_AdjustSmpl(runtime->sjdHandle, sampleDelta);
  }

  /**
   * Address: 0x00B0EAA0 (FUN_00B0EAA0, _ADXT_EntryFltFunc)
   *
   * What it does:
   * Runs ADXT filter-entry query lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_EntryFltFunc(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t filterEntryResult = adxt_EntryFltFunc(adxtRuntime);
    ADXCRS_Leave();
    return filterEntryResult;
  }

  constexpr char kAdxtSetCbDecParameterErrorMessage[] = "E04041902 ADXT_SetCbDec: parameter error";
  constexpr char kAdxtGetDecDtLenParameterErrorMessage[] = "E04041901 adxt_GetDecDtLen: parameter error";
  constexpr char kAdxtGetDecNumSmplParameterErrorMessage[] = "E02080818 adxt_GetDecNumSmpl: parameter error";

  /**
   * Address: 0x00B0EAC0 (FUN_00B0EAC0, _adxt_EntryFltFunc)
   *
   * What it does:
   * Returns ADXT link-switch request byte as signed lane value.
   */
  std::int32_t adxt_EntryFltFunc(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return static_cast<std::int32_t>(static_cast<std::int8_t>(runtime->linkSwitchRequested));
  }

  /**
   * Address: 0x00B0EAD0 (FUN_00B0EAD0, _ADXT_SetCbHdrDec)
   *
   * What it does:
   * Runs ADXT header-filter callback registration under ADXCRS enter/leave guards.
   */
  void ADXT_SetCbHdrDec(
    void* const adxtRuntime,
    void* const filterCallbackAddress,
    const std::int32_t filterCallbackContext
  )
  {
    ADXCRS_Enter();
    (void)adxt_SetCbHdrDec(adxtRuntime, filterCallbackAddress, filterCallbackContext);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0EB00 (FUN_00B0EB00, _adxt_SetCbHdrDec)
   *
   * What it does:
   * Forwards one ADXT header-filter callback lane into ADXSJD filter registration.
   */
  std::int32_t adxt_SetCbHdrDec(
    void* const adxtRuntime,
    void* const filterCallbackAddress,
    const std::int32_t filterCallbackContext
  )
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    return ADXSJD_EntryFltFunc(runtime->sjdHandle, filterCallbackAddress, filterCallbackContext);
  }

  /**
   * Address: 0x00B0EB10 (FUN_00B0EB10, _ADXT_GetDecNumSmpl)
   *
   * What it does:
   * Returns ADXT decoded-sample count under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDecNumSmpl(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t decodedSamples = adxt_GetDecNumSmpl(adxtRuntime);
    ADXCRS_Leave();
    return decodedSamples;
  }

  /**
   * Address: 0x00B0EB30 (FUN_00B0EB30, _adxt_GetDecNumSmpl)
   *
   * What it does:
   * Returns decoded-sample count from ADXSJD or reports null-runtime parameter error.
   */
  std::int32_t adxt_GetDecNumSmpl(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetDecNumSmplParameterErrorMessage);
      return -1;
    }
    return ADXSJD_GetDecNumSmpl(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0EB60 (FUN_00B0EB60, _ADXT_GetDecDtLen)
   *
   * What it does:
   * Returns ADXT decoded-byte count under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDecDtLen(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t decodedBytes = adxt_GetDecDtLen(adxtRuntime);
    ADXCRS_Leave();
    return decodedBytes;
  }

  /**
   * Address: 0x00B0EB80 (FUN_00B0EB80, _adxt_GetDecDtLen)
   *
   * What it does:
   * Returns decoded-byte count from ADXSJD or reports null-runtime parameter error.
   */
  std::int32_t adxt_GetDecDtLen(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtGetDecDtLenParameterErrorMessage);
      return -1;
    }
    return ADXSJD_GetDecDtLen(runtime->sjdHandle);
  }

  /**
   * Address: 0x00B0EBB0 (FUN_00B0EBB0, _ADXT_SetCbDec)
   *
   * What it does:
   * Runs ADXT decode callback registration under ADXCRS enter/leave guards.
   */
  void ADXT_SetCbDec(
    void* const adxtRuntime,
    void* const decodeCallbackAddress,
    const std::int32_t decodeCallbackContext
  )
  {
    ADXCRS_Enter();
    (void)adxt_SetCbDec(adxtRuntime, decodeCallbackAddress, decodeCallbackContext);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0EBE0 (FUN_00B0EBE0, _adxt_SetCbDec)
   *
   * What it does:
   * Forwards one ADXT decode callback lane into ADXSJD decode callback registration.
   */
  std::int32_t adxt_SetCbDec(
    void* const adxtRuntime,
    void* const decodeCallbackAddress,
    const std::int32_t decodeCallbackContext
  )
  {
    const auto* const runtime = static_cast<const AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxtSetCbDecParameterErrorMessage);
    }
    return ADXSJD_SetCbDec(runtime->sjdHandle, decodeCallbackAddress, decodeCallbackContext);
  }

  /**
   * Address: 0x00B0EC10 (FUN_00B0EC10, _ADXT_IsHeader)
   *
   * What it does:
   * Validates ADX header marker and exports decoded header-identity lane.
   */
  std::int32_t ADXT_IsHeader(
    const std::uint8_t* const sourceBytes,
    const std::int32_t byteCount,
    std::int32_t* const outHeaderIdentity
  )
  {
    if (byteCount < 2) {
      return 0;
    }

    const std::uint16_t marker = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(sourceBytes[0]) << 8u) | static_cast<std::uint16_t>(sourceBytes[1])
    );
    if (marker != 0x8000u) {
      return 0;
    }

    std::int32_t headerIdentity = 0;
    std::int8_t headerType = 0;
    std::int8_t sampleBits = 0;
    std::int8_t channelCount = 0;
    std::int8_t blockBytes = 0;
    std::int32_t blockSamples = 0;
    std::int32_t sampleRate = 0;
    std::int32_t totalSamples = 0;
    if (
      ADX_DecodeInfo(
        sourceBytes,
        byteCount,
        &headerIdentity,
        &headerType,
        &sampleBits,
        &channelCount,
        &blockBytes,
        &blockSamples,
        &sampleRate,
        &totalSamples
      )
      < 0
    ) {
      return 0;
    }

    *outHeaderIdentity = static_cast<std::int32_t>(static_cast<std::int16_t>(headerIdentity));
    return 1;
  }

  constexpr char kAdxtSetKeyStringParameterErrorMessage[] = "E02080860 adxt_SetKeyString: parameter error";

  /**
   * Address: 0x00B0EE70 (FUN_00B0EE70, _ADXT_SetKeyString)
   *
   * What it does:
   * Runs one ADXT key-string update under ADXCRS enter/leave guards.
   */
  void ADXT_SetKeyString(void* const adxtRuntime, const char* const extString)
  {
    ADXCRS_Enter();
    adxt_SetKeyString(adxtRuntime, extString);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0EE90 (FUN_00B0EE90, _adxt_SetKeyString)
   *
   * What it does:
   * Updates ADXSJD key-string lane for one ADXT runtime or reports null-runtime
   * parameter error.
   */
  void adxt_SetKeyString(void* const adxtRuntime, const char* const extString)
  {
    const auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetKeyStringParameterErrorMessage);
      return;
    }

    (void)ADXSJD_SetExtString(runtime->sjdHandle, extString);
  }

  /**
   * Address: 0x00B0EEC0 (FUN_00B0EEC0, _ADXT_SetDefKeyString)
   *
   * What it does:
   * Runs one ADXT default key-string update under ADXCRS enter/leave guards.
   */
  void ADXT_SetDefKeyString(const char* const extString)
  {
    ADXCRS_Enter();
    (void)adxt_SetDefKeyString(extString);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0EEE0 (FUN_00B0EEE0, _adxt_SetDefKeyString)
   *
   * What it does:
   * Forwards default key-string lane to ADXSJD global default-key slot.
   */
  std::int32_t adxt_SetDefKeyString(const char* const extString)
  {
    return ADXSJD_SetDefExtString(extString);
  }

  /**
   * Address: 0x00B0EEF0 (FUN_00B0EEF0, _ADXT_GetRna)
   *
   * What it does:
   * Returns ADXT RNA handle lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetRna(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t rnaHandle = adxt_GetRna(adxtRuntime);
    ADXCRS_Leave();
    return rnaHandle;
  }

  /**
   * Address: 0x00B0EF10 (FUN_00B0EF10, _adxt_GetRna)
   *
   * What it does:
   * Returns ADXT RNA handle lane.
   */
  std::int32_t adxt_GetRna(void* const adxtRuntime)
  {
    return static_cast<AdxtRuntimeState*>(adxtRuntime)->rnaHandle;
  }

  /**
   * Address: 0x00B0EF20 (FUN_00B0EF20, _ADXT_SetDefFmt)
   *
   * What it does:
   * Runs one ADXT default-format update under ADXCRS enter/leave guards.
   */
  void ADXT_SetDefFmt(void* const adxtRuntime, const std::int32_t requestedFormat)
  {
    ADXCRS_Enter();
    (void)adxt_SetDefFmt(adxtRuntime, requestedFormat);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0EF40 (FUN_00B0EF40, _adxt_SetDefFmt)
   *
   * What it does:
   * Forwards one ADXT default-format update to ADXSJD using runtime SJD lane.
   */
  std::int32_t adxt_SetDefFmt(void* const adxtRuntime, const std::int32_t requestedFormat)
  {
    const auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    return ADXSJD_SetDefFmt(runtime->sjdHandle, requestedFormat);
  }

  /**
   * Address: 0x00B0EC90 (FUN_00B0EC90, _ADXT_IsEndcode)
   *
   * What it does:
   * Detects ADX stream end-code marker (`0x8001`) at the front of one byte
   * window and reports the consumed byte count.
   */
  std::int32_t ADXT_IsEndcode(const std::uint8_t* const sourceBytes, const std::int32_t byteCount, std::int32_t* const outConsumedBytes)
  {
    if (byteCount < 2) {
      return 0;
    }

    const std::uint16_t marker = static_cast<std::uint16_t>((static_cast<std::uint16_t>(sourceBytes[0]) << 8)
      | static_cast<std::uint16_t>(sourceBytes[1]));
    if (marker != 0x8001u) {
      return 0;
    }

    *outConsumedBytes = byteCount;
    return 1;
  }

  /**
   * Address: 0x00B0ECC0 (FUN_00B0ECC0, _ADXT_InsertSilence)
   *
   * What it does:
   * Inserts silent ADX frames into one ADXT runtime via stream-join lane
   * acquire/split/commit flow under ADXCRS guard wrappers.
   */
  std::int32_t ADXT_InsertSilence(void* const adxtRuntime, const std::int32_t channelCount, const std::int32_t sampleCount)
  {
    ADXCRS_Enter();
    const std::int32_t insertedSamples = adxt_InsertSilence(adxtRuntime, channelCount, sampleCount);
    ADXCRS_Leave();
    return insertedSamples;
  }

  /**
   * Address: 0x00B0ECF0 (FUN_00B0ECF0, _adxt_InsertSilence)
   *
   * What it does:
   * Zero-fills up to two aligned source chunks (lane 0), commits them to output
   * lane 1, and returns inserted sample count rounded to ADX frame units.
   */
  std::int32_t adxt_InsertSilence(void* const adxtRuntime, const std::int32_t channelCount, const std::int32_t sampleCount)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    auto* const streamJoinHandle = runtime->streamJoinInputHandle;
    if (streamJoinHandle == nullptr) {
      return 0;
    }

    const std::int32_t frameBytes = 18 * channelCount;
    const std::int32_t requestedBytes = frameBytes * (sampleCount / 32);

    SjChunkRange writableChunk{};
    streamJoinHandle->AcquireChunk(0, requestedBytes, &writableChunk);

    const std::int32_t firstFillBytes = frameBytes * (writableChunk.byteCount / frameBytes);
    std::memset(SjAddressToPointer(writableChunk.bufferAddress), 0, static_cast<std::size_t>(firstFillBytes));

    SjChunkRange firstTailChunk{};
    SJ_SplitChunk(&writableChunk, firstFillBytes, &writableChunk, &firstTailChunk);
    streamJoinHandle->CommitChunk(1, &writableChunk);
    streamJoinHandle->ReturnChunk(0, &firstTailChunk);

    streamJoinHandle->AcquireChunk(0, requestedBytes - firstFillBytes, &writableChunk);
    const std::int32_t secondFillBytes = frameBytes * (writableChunk.byteCount / frameBytes);
    std::memset(SjAddressToPointer(writableChunk.bufferAddress), 0, static_cast<std::size_t>(secondFillBytes));

    SjChunkRange secondTailChunk{};
    SJ_SplitChunk(&writableChunk, secondFillBytes, &writableChunk, &secondTailChunk);
    streamJoinHandle->CommitChunk(1, &writableChunk);
    streamJoinHandle->ReturnChunk(0, &secondTailChunk);

    return 32 * ((firstFillBytes + secondFillBytes) / frameBytes);
  }

  /**
   * Address: 0x00B0EE10 (FUN_00B0EE10, sub_B0EE10)
   *
   * What it does:
   * Toggles global ADXT mono-output lane and reapplies cached per-runtime
   * output pan/balance state across all ADXT runtime slots.
   */
  std::int32_t ADXT_SetOutputMonoMode(const std::int32_t enabled)
  {
    adxt_output_mono_flag = enabled;

    std::int32_t result = enabled;
    for (auto& runtimeSlot : gAdxtRuntimePool) {
      if (runtimeSlot.used != 1u) {
        continue;
      }

      const std::int32_t channelCount = static_cast<std::int32_t>(runtimeSlot.maxChannelCount);
      for (std::int32_t lane = 0; lane < channelCount; ++lane) {
        const std::int32_t outputPan = static_cast<std::int32_t>(runtimeSlot.RequestedPanLane(lane));
        (void)adxt_SetOutPan(&runtimeSlot, lane, outputPan);
      }

      std::int32_t balanceLevel = static_cast<std::int32_t>(runtimeSlot.OutputBalanceLevel());
      if (balanceLevel < -15) {
        balanceLevel = -15;
      } else if (balanceLevel > 15) {
        balanceLevel = 15;
      }
      runtimeSlot.OutputBalanceLevel() = static_cast<std::int16_t>(balanceLevel);

      if (adxt_output_mono_flag != 0) {
        result = ADXRNA_SetOutBalance(runtimeSlot.rnaHandle, -128);
      } else {
        result = ADXRNA_SetOutBalance(runtimeSlot.rnaHandle, balanceLevel);
      }
    }

    return result;
  }

  /**
   * Address: 0x00B1A3B0 (FUN_00B1A3B0, _adxt_eos_entry)
   *
   * What it does:
   * Handles ADXT stream EOS by either seeking to loop-start sector or arming
   * terminal trap/sample-window state before forcing open-ended EOS.
   */
  std::int32_t adxt_eos_entry(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const std::int32_t sjdHandle = runtime->sjdHandle;

    if (runtime->streamHandle != nullptr && sjdHandle != 0) {
      const std::int32_t loopStartOffsetBytes = ADXSJD_GetLpStartOfst(sjdHandle);
      if (runtime->StreamLoopSeekOnEosFlag() != 0u) {
        return ADXSTM_Seek(runtime->streamHandle, loopStartOffsetBytes / 2048);
      }

      if (ADXSJD_GetDecDtLen(sjdHandle) >= runtime->StreamDecodeWindowState()) {
        ADXSJD_SetTrapNumSmpl(sjdHandle, -1);
      }
      return ADXSTM_SetEos(runtime->streamHandle, 0x7FFFFFFF);
    }

    return sjdHandle;
  }

  /**
   * Address: 0x00B1A430 (FUN_00B1A430, _adxt_set_outpan)
   *
   * What it does:
   * Reapplies cached ADXT output-pan lanes to RNA based on decoded channel count.
   */
  std::int32_t adxt_set_outpan(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const std::int32_t lane0Pan = static_cast<std::int32_t>(runtime->RequestedPanLane(0));
    if (ADXSJD_GetNumChan(runtime->sjdHandle) == 1) {
      ADXT_SetOutPan(runtime, 0, lane0Pan);
      return 0;
    }

    ADXT_SetOutPan(runtime, 0, lane0Pan);
    const std::int32_t lane1Pan = static_cast<std::int32_t>(runtime->RequestedPanLane(1));
    ADXT_SetOutPan(runtime, 1, lane1Pan);
    return 0;
  }

  /**
   * Address: 0x00B1A9C0 (FUN_00B1A9C0, _ADXT_SetCbEndDecinfo)
   *
   * What it does:
   * Swaps ADXT decode-info completion callback and returns previous callback slot.
   */
  AdxtEndDecodeInfoCallback ADXT_SetCbEndDecinfo(const AdxtEndDecodeInfoCallback callback)
  {
    const auto previousCallback = adxt_enddecinfo_cbfn;
    adxt_enddecinfo_cbfn = callback;
    return previousCallback;
  }

  /**
   * Address: 0x00B1AB00 (FUN_00B1AB00, _adxt_stat_playing)
   *
   * What it does:
   * Executes ADXT playing-state transition checks and promotes runtime to
   * decode-end state when all source lanes drain below backlog threshold.
   */
  std::int32_t adxt_stat_playing(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime->StreamLoopSeekOnEosFlag() == 0u && ADXSJD_GetDecDtLen(runtime->sjdHandle) >= runtime->StreamDecodeWindowState()) {
      ADXSJD_SetTrapNumSmpl(runtime->sjdHandle, -1);
    }

    std::int32_t result = ADXSJD_GetStat(runtime->sjdHandle);
    if (result == 3) {
      const std::int32_t channelCount = ADXSJD_GetNumChan(runtime->sjdHandle);
      adxt_dbg_sj_channels = channelCount;

      std::int32_t lane = 0;
      while (lane < channelCount) {
        auto* const decodeSource = reinterpret_cast<AdxtDecodeSourceHandle*>(runtime->SourceChannelRingLane(lane));
        result = decodeSource->QueryDecodeBacklog(1);
        adxt_dbg_sj_backlog = result;
        if (result >= 64) {
          break;
        }
        ++lane;
      }

      if (lane == channelCount) {
        j__ADXRNA_SetTransSw(runtime->rnaHandle, 0);
        runtime->mUnknown01 = 4;
      }
    }

    return result;
  }

  /**
   * Address: 0x00B1ABA0 (FUN_00B1ABA0, _adxt_stat_decend)
   *
   * What it does:
   * Tracks ADXT RNA queued data and transitions to play-end once queue drains.
   */
  std::int32_t adxt_stat_decend(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    adxt_dbg_rna_ndata = ADXRNA_GetNumData(runtime->rnaHandle);

    const std::int32_t remainingData = ADXRNA_GetNumData(runtime->rnaHandle);
    if (remainingData <= 0) {
      j__ADXRNA_SetPlaySw(runtime->rnaHandle, 0);
      runtime->mUnknown01 = 5;
    }
    return remainingData;
  }

  /**
   * Address: 0x00B1ABE0 (FUN_00B1ABE0, _adxt_stat_playend)
   *
   * What it does:
   * Keeps the ADXT play-end status handler as an explicit no-op lane.
   */
  void adxt_stat_playend()
  {
  }

  /**
   * Address: 0x00B1ABF0 (FUN_00B1ABF0, _adxt_RcvrReplay)
   *
   * What it does:
   * Performs ADXT replay recovery by quiescing RNA/SJD lanes, resetting channel
   * source handles, restarting stream playback from sector 0 when present, and
   * restarting SJ decode on the retained stream-input handle.
   */
  void adxt_RcvrReplay(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);

    ADXCRS_Lock();
    j__ADXRNA_SetTransSw(runtime->rnaHandle, 0);
    j__ADXRNA_SetPlaySw(runtime->rnaHandle, 0);
    ADXSJD_Stop(runtime->sjdHandle);
    ADXCRS_Unlock();

    if (runtime->streamHandle != nullptr) {
      ADXSTM_Stop(runtime->streamHandle);
      runtime->streamJoinInputHandle->OnSeamlessStart();
    }

    ADXCRS_Lock();

    const auto channelCount = static_cast<std::int32_t>(runtime->maxChannelCount);
    for (std::int32_t lane = 0; lane < channelCount; ++lane) {
      runtime->SourceChannelRingLane(lane)->Destroy();
    }

    if (runtime->streamHandle != nullptr) {
      ADXSTM_Seek(runtime->streamHandle, 0);
      ADXSTM_Start(runtime->streamHandle);
    }

    (void)adxt_start_sj(runtime, runtime->streamJoinInputHandle);
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B1ACA0 (FUN_00B1ACA0, _ADXT_ExecErrChk)
   *
   * What it does:
   * Executes one ADXT error-monitor tick and applies configured stop/recover
   * behavior when decode progression, SJ backlog, or stream status indicates a
   * fault condition.
   */
  void ADXT_ExecErrChk(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const auto playbackState = static_cast<std::int32_t>(runtime->mUnknown01);

    const auto dispatchRecoveryAction = [&]() {
      const auto action = runtime->ErrorRecoveryMode();
      if (action == 1u) {
        ADXT_Stop(runtime);
      } else if (action == 2u) {
        adxt_RcvrReplay(runtime);
      }
    };

    if (
      playbackState != 3
      || runtime->ErrorCheckSuppressedFlag() != 0u
      || ADXSJD_GetStat(runtime->sjdHandle) == 3
    ) {
      runtime->DecodeStallCounter() = 0;
      if (playbackState < 1 || playbackState > 3) {
        runtime->RecoveryWatchdogCounter() = 0;
      }
    } else {
      const auto decodedSamples = ADXSJD_GetDecNumSmpl(runtime->sjdHandle);
      if (runtime->LastDecodedSampleCount() == decodedSamples) {
        const auto stallCounter = static_cast<std::int32_t>(++runtime->DecodeStallCounter());
        if (stallCounter > (5 * runtime->ErrorCheckFrameWindow())) {
          runtime->ErrorStateCode() = -2;
        }
      } else {
        runtime->DecodeStallCounter() = 0;
      }

      runtime->LastDecodedSampleCount() = decodedSamples;
      if (runtime->ErrorStateCode() != 0) {
        const auto action = runtime->ErrorRecoveryMode();
        if (action == 1u || action == 2u) {
          ADXT_Stop(runtime);
        }
        if (runtime->ErrorRecoveryMode() != 0u) {
          runtime->ErrorStateCode() = 0;
          runtime->DecodeStallCounter() = 0;
        }
      }
    }

    const bool hasBacklogFault =
      runtime->streamJoinInputHandle != nullptr
      && runtime->streamJoinInputHandle->QueryDecodeBacklog(1) >= 64;
    if (
      runtime->ErrorCheckSuppressedFlag() != 0u
      || ADXSJD_GetStat(runtime->sjdHandle) == 3
      || hasBacklogFault
    ) {
      runtime->RecoveryWatchdogCounter() = 0;
    } else {
      const auto watchdog = static_cast<std::int32_t>(++runtime->RecoveryWatchdogCounter());
      const auto watchdogLimit =
        (playbackState == 3) ? (5 * runtime->ErrorCheckFrameWindow()) : (20 * runtime->ErrorCheckFrameWindow());
      if (watchdog > watchdogLimit) {
        runtime->ErrorStateCode() = -1;
      }

      if (runtime->ErrorStateCode() != 0) {
        dispatchRecoveryAction();
        if (runtime->ErrorRecoveryMode() != 0u) {
          runtime->ErrorStateCode() = 0;
          runtime->RecoveryWatchdogCounter() = 0;
        }
      }
    }

    if (runtime->streamHandle != nullptr && ADXSTM_GetStat(runtime->streamHandle) == 4) {
      dispatchRecoveryAction();
      if (runtime->ErrorRecoveryMode() != 0u) {
        runtime->ErrorStateCode() = 0;
        runtime->RecoveryWatchdogCounter() = 0;
      }
    }
  }

  /**
   * Address: 0x00B1AE10 (FUN_00B1AE10, _ADXT_ExecRdErrChk)
   *
   * What it does:
   * Marks ADXT runtime as read-error state when stream or seamless-LSC lanes
   * report terminal read failures.
   */
  void ADXT_ExecRdErrChk(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime->streamHandle != nullptr && ADXSTM_GetStat(runtime->streamHandle) == kAdxstmStatusFilesystemError) {
      runtime->ErrorStateCode() = -1;
      runtime->mUnknown01 = 6;
    }

    void* const lscHandle = runtime->SeamlessLscHandle();
    if (lscHandle != nullptr && LSC_GetStat(lscHandle) == 3) {
      runtime->ErrorStateCode() = -1;
      runtime->mUnknown01 = 6;
    }
  }

  /**
   * Address: 0x00B1AE60 (FUN_00B1AE60, _ADXT_ExecRdCompChk)
   *
   * What it does:
   * Monitors ADXT read completion and requests SJD terminate-supply once the
   * transport lane reaches completion under eligible playback modes.
   */
  std::int32_t ADXT_ExecRdCompChk(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    std::int32_t status = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtime->streamHandle));
    if (status == 0) {
      return status;
    }

    status = ADXT_GetStat(runtime);
    if (status == 0) {
      return status;
    }

    const auto playbackModeByte = runtime->mUnknown02;
    status = (status & ~0xFF) | static_cast<std::int32_t>(playbackModeByte);

    if ((playbackModeByte & 0x80u) != 0u) {
      return status;
    }

    if (static_cast<std::int8_t>(playbackModeByte) <= 1) {
      status = ADXSTM_GetStat(runtime->streamHandle);
      if (status == 3) {
        return ADXSJD_TermSupply(runtime->sjdHandle);
      }
      return status;
    }

    if (playbackModeByte == 2u) {
      return ADXSJD_TermSupply(runtime->sjdHandle);
    }

    return status;
  }

  /**
   * Address: 0x00B1AEC0 (FUN_00B1AEC0, _ADXT_ExecHndl)
   *
   * What it does:
   * Runs one ADXT handle tick under ADX critical-section guards.
   */
  void ADXT_ExecHndl(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_ExecHndl(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B1AF80 (FUN_00B1AF80, _ADXT_GetStatRead)
   *
   * What it does:
   * Returns ADXT read-flag lane under ADX critical-section guards.
   */
  std::int32_t ADXT_GetStatRead(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t readFlag = adxt_GetStatRead(adxtRuntime);
    ADXCRS_Leave();
    return readFlag;
  }

  /**
   * Address: 0x00B1AFA0 (FUN_00B1AFA0, _adxt_GetStatRead)
   *
   * What it does:
   * Returns stream read-flag from primary ADXT stream lane, or from attached
   * seamless LSC stream lane when direct stream handle is absent.
   */
  std::int32_t adxt_GetStatRead(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      return 0;
    }

    if (runtime->streamHandle != nullptr) {
      return ADXSTM_GetReadFlg(runtime->streamHandle);
    }

    void* const lscHandle = runtime->SeamlessLscHandle();
    if (lscHandle == nullptr) {
      return 0;
    }

    void* const seamlessStreamHandle = AsLscRuntimeView(lscHandle)->streamHandle;
    if (seamlessStreamHandle == nullptr) {
      return 0;
    }

    return ADXSTM_GetReadFlg(seamlessStreamHandle);
  }

  /**
   * Address: 0x00B19170 (FUN_00B19170, _adxt_SetSeamlessLp)
   *
   * What it does:
   * Sets seamless-loop flag for ADXT-owned LSC queue.
   */
  [[maybe_unused]] void adxt_SetSeamlessLp(void* const adxtRuntime, const std::int32_t enabled)
  {
    if (adxtRuntime != nullptr) {
      auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
      LSC_SetLpFlg(runtime->SeamlessLscHandle(), enabled);
      return;
    }

    (void)ADXERR_CallErrFunc1_(kAdxtErrSetSeamlessLpParameter);
  }

  [[maybe_unused]] std::int32_t adxt_StartFnameRangeLp(
    void* adxtRuntime,
    const char* fileName,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );

  /**
   * Address: 0x00B191C0 (FUN_00B191C0, _adxt_StartFnameLp)
   *
   * What it does:
   * Starts seamless loop playback for full filename range.
   */
  [[maybe_unused]] std::int32_t adxt_StartFnameLp(void* const adxtRuntime, const char* const fileName)
  {
    return adxt_StartFnameRangeLp(adxtRuntime, fileName, 0, kLscRangeEndAll);
  }

  /**
   * Address: 0x00B19210 (FUN_00B19210, _adxt_StartFnameRangeLp)
   *
   * What it does:
   * Rebuilds seamless queue with one filename range, enables loop, and starts
   * seamless playback.
   */
  [[maybe_unused]] std::int32_t adxt_StartFnameRangeLp(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (adxtRuntime != nullptr && fileName != nullptr) {
      auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
      void* const lscHandle = runtime->SeamlessLscHandle();
      lsc_Stop(lscHandle);
      (void)adxt_EntryFnameRange(runtime, fileName, rangeStart, rangeEnd);
      LSC_SetLpFlg(lscHandle, 1);
      return adxt_StartSeamless(runtime);
    }

    return ADXERR_CallErrFunc1_(kAdxtErrStartFnameRangeLpParameter);
  }

  /**
   * Address: 0x00B192A0 (FUN_00B192A0, _adxt_StartAfsLp)
   *
   * What it does:
   * Rebuilds seamless queue from one AFS entry, enables loop, and starts
   * seamless playback.
   */
  [[maybe_unused]] std::int32_t adxt_StartAfsLp(
    void* const adxtRuntime,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    if (adxtRuntime != nullptr && afsHandle <= 0 && afsHandle < 0x100 && fileIndex >= 0 && fileIndex <= 0x10000) {
      auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
      void* const lscHandle = runtime->SeamlessLscHandle();
      lsc_Stop(lscHandle);
      (void)adxt_EntryAfs(runtime, afsHandle, fileIndex);
      LSC_SetLpFlg(lscHandle, 1);
      return adxt_StartSeamless(runtime);
    }

    return ADXERR_CallErrFunc1_(kAdxtErrStartAfsLpParameter);
  }

  /**
   * Address: 0x00B19340 (FUN_00B19340, _adxt_GetNumFiles)
   *
   * What it does:
   * Returns number of queued seamless files for ADXT runtime.
   */
  [[maybe_unused]] std::int32_t adxt_GetNumFiles(void* const adxtRuntime)
  {
    if (adxtRuntime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtErrGetNumFilesParameter);
      return -1;
    }

    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    return LSC_GetNumStm(runtime->SeamlessLscHandle());
  }

  /**
   * Address: 0x00B18F60 (FUN_00B18F60, _ADXT_EntryFname)
   *
   * What it does:
   * Lock-guarded wrapper for one ADXT seamless filename enqueue.
   */
  void ADXT_EntryFname(void* const adxtRuntime, const char* const fileName)
  {
    ADXCRS_Enter();
    (void)adxt_EntryFname(adxtRuntime, fileName);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B18FA0 (FUN_00B18FA0, _ADXT_EntryFnameRange)
   *
   * What it does:
   * Lock-guarded wrapper for one ADXT seamless filename-range enqueue.
   */
  void ADXT_EntryFnameRange(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    ADXCRS_Enter();
    (void)adxt_EntryFnameRange(adxtRuntime, fileName, rangeStart, rangeEnd);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B19010 (FUN_00B19010, _ADXT_EntryAfs)
   *
   * What it does:
   * Lock-guarded wrapper for one ADXT seamless AFS enqueue.
   */
  void ADXT_EntryAfs(void* const adxtRuntime, const std::int32_t afsHandle, const std::int32_t fileIndex)
  {
    ADXCRS_Enter();
    (void)adxt_EntryAfs(adxtRuntime, afsHandle, fileIndex);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B190D0 (FUN_00B190D0, _ADXT_StartSeamless)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT seamless-start lane.
   */
  void ADXT_StartSeamless(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    (void)adxt_StartSeamless(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B19150 (FUN_00B19150, _ADXT_SetSeamlessLp)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT seamless-loop flag lane.
   */
  void ADXT_SetSeamlessLp(void* const adxtRuntime, const std::int32_t enabled)
  {
    ADXCRS_Enter();
    adxt_SetSeamlessLp(adxtRuntime, enabled);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B191A0 (FUN_00B191A0, _ADXT_StartFnameLp)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT seamless loop start using one filename.
   */
  void ADXT_StartFnameLp(void* const adxtRuntime, const char* const fileName)
  {
    ADXCRS_Enter();
    (void)adxt_StartFnameLp(adxtRuntime, fileName);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B191E0 (FUN_00B191E0, _ADXT_StartFnameRangeLp)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT seamless loop start using one filename range.
   */
  void ADXT_StartFnameRangeLp(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    ADXCRS_Enter();
    (void)adxt_StartFnameRangeLp(adxtRuntime, fileName, rangeStart, rangeEnd);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B19270 (FUN_00B19270, _ADXT_StartAfsLp)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT seamless loop start using one AFS entry.
   */
  void ADXT_StartAfsLp(void* const adxtRuntime, const std::int32_t afsHandle, const std::int32_t fileIndex)
  {
    ADXCRS_Enter();
    (void)adxt_StartAfsLp(adxtRuntime, afsHandle, fileIndex);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B19310 (FUN_00B19310, _ADXT_ReleaseSeamless)
   *
   * What it does:
   * Legacy no-op release lane for ADXT seamless playback.
   */
  void ADXT_ReleaseSeamless()
  {}

  /**
   * Address: 0x00B19320 (FUN_00B19320, _ADXT_GetNumFiles)
   *
   * What it does:
   * Lock-guarded wrapper that returns ADXT seamless queued-file count.
   */
  std::int32_t ADXT_GetNumFiles(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t numFiles = adxt_GetNumFiles(adxtRuntime);
    ADXCRS_Leave();
    return numFiles;
  }

  /**
   * Address: 0x00B19370 (FUN_00B19370, _ADXT_ResetEntry)
   *
   * What it does:
   * Runs one ADXT seamless-entry reset under ADX global enter/leave guards.
   */
  [[maybe_unused]] void ADXT_ResetEntry(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_ResetEntry(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B19390 (FUN_00B19390, _adxt_ResetEntry)
   *
   * What it does:
   * Clears ADXT seamless queue when runtime is idle.
   */
  [[maybe_unused]] void adxt_ResetEntry(void* const adxtRuntime)
  {
    if (adxtRuntime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtErrResetEntryParameter);
      return;
    }

    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime->mUnknown01 == 0) {
      LSC_ResetEntry(runtime->SeamlessLscHandle());
    }
  }

  /**
   * Address: 0x00B193C0 (FUN_00B193C0, _adxt_ExecLscSvr)
   *
   * What it does:
   * Runs one ADXT seamless LSC server tick under ADX server enter/leave guards.
   */
  [[maybe_unused]] void adxt_ExecLscSvr()
  {
    ADXCRS_Enter();
    (void)LSC_ExecServer();
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B193E0 (FUN_00B193E0, _ADXF_Ocbi)
   *
   * What it does:
   * Legacy no-op ADXF callback lane.
   */
  [[maybe_unused]] void ADXF_Ocbi([[maybe_unused]] const std::int32_t callbackArg0, [[maybe_unused]] const std::int32_t callbackArg1)
  {}

  /**
   * Address: 0x00ACBD00 (FUN_00ACBD00, _mwPlyGetTime)
   *
   * What it does:
   * Returns current playback time from SFD handle, clamping negative values
   * to `(0,1)` fallback.
   */
  void mwPlyGetTime(
    moho::MwsfdPlaybackStateSubobj* const ply,
    std::int32_t* const outTime,
    std::int32_t* const outTimeScale
  )
  {
    *outTime = 0;
    *outTimeScale = 1;

    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetTimeInvalidHandle);
      return;
    }

    if (ply->handle == nullptr) {
      return;
    }

    if (SFD_GetTime(ply->handle, outTime, outTimeScale) != 0) {
      (void)MWSFLIB_SetErrCode(-309);
      (void)MWSFSVM_Error(kMwsfdErrGetTimeFailed);
    }

    if (*outTime < 0) {
      *outTime = 0;
      *outTimeScale = 1;
    }
  }

  /**
   * Address: 0x00ADE020 (FUN_00ADE020, _mwPlyLinkStm)
   *
   * What it does:
   * Toggles seamless-concat stream linkage and arms restart-on-next-start when
   * dropping from linked to unlinked playback.
   */
  void mwPlyLinkStm(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t linkMode)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrLinkStmInvalidHandle);
      return;
    }

    const std::uint8_t wasLinked = ply->concatPlayArmed;
    if (wasLinked == 1 && linkMode == 0) {
      ply->isPrepared = 1;
    }

    if (wasLinked == 0 && linkMode == 1) {
      if (SFD_SetConcatPlay(ply->handle) != 0) {
        (void)MWSFSVM_Error(kMwsfdErrLinkStmConcatPlayFailed);
      }
    }

    ply->concatPlayArmed = static_cast<std::uint8_t>(linkMode);
  }

  /**
   * Address: 0x00AC7ED0 (FUN_00AC7ED0, _mwsfcre_AttachPicUsrBuf)
   *
   * What it does:
   * Validates optional external picture-user buffer lane and binds it to the
   * current SFD handle when global user-buffer mode is enabled.
   */
  [[maybe_unused]] void mwsfcre_AttachPicUsrBuf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    const auto* const playbackView = reinterpret_cast<const MwsfdPlaybackPicUserView*>(ply);
    const MwsfdPicUserBufferDescriptor* const userBuffer = playbackView->picUserBuffer;
    if (userBuffer == nullptr) {
      (void)MWSFSVM_Error(kMwsfcreErrAttachPicUsrBufInternal);
      return;
    }

    const std::int32_t frameSlotCount = ply->framePoolSize + 3;
    if (userBuffer->bufferBytes < (userBuffer->bytesPerFrame * frameSlotCount)) {
      (void)MWSFSVM_Error(kMwsfcreErrAttachPicUsrBufShort);
      return;
    }

    if (MWSFD_GetUsePicUsr() == 1) {
      (void)SFD_SetPicUsrBuf(ply->handle, userBuffer->bufferAddress, frameSlotCount, userBuffer->bytesPerFrame);
    }
  }

  /**
   * Address: 0x00B0C1B0 (FUN_00B0C1B0, _adxf_enter)
   *
   * What it does:
   * Enters the ADX critical-section shim lane for ADXF API wrappers.
   */
  [[maybe_unused]] void adxf_enter()
  {
    ADXCRS_Enter();
  }

  /**
   * Address: 0x00B0C1C0 (FUN_00B0C1C0, _adxf_leave)
   *
   * What it does:
   * Leaves the ADX critical-section shim lane for ADXF API wrappers.
   */
  [[maybe_unused]] void adxf_leave()
  {
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0C1A0 (FUN_00B0C1A0, _adxf_GetFileSize)
   *
   * What it does:
   * Thin ADXF thunk that forwards file-size query to ADXSTM lane.
   */
  std::int32_t adxf_GetFileSize(char* const fileName)
  {
    return ADXSTM_GetFileSize(fileName);
  }

  /**
   * Address: 0x00B0C180 (FUN_00B0C180, _ADXF_GetFileSize)
   *
   * What it does:
   * Returns file size through ADXF lock/unlock wrappers.
   */
  std::int32_t ADXF_GetFileSize(char* const fileName)
  {
    adxf_enter();
    const std::int32_t fileSize = adxf_GetFileSize(fileName);
    adxf_leave();
    return fileSize;
  }

  /**
   * Address: 0x00B0AAE0 (FUN_00B0AAE0, _adxf_LoadPtFromAfsFmgLongNwEx)
   *
   * What it does:
   * Loads one point/file entry through the shared non-blocking load lane with
   * fixed long-range defaults.
   */
  std::int32_t adxf_LoadPtFromAfsFmgLongNwEx(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    return adxf_LoadPtBothNw(arg0, arg1, arg2, 0, 0, 0, 0x000FFFFF, arg3, arg4, arg5, 1);
  }

  /**
   * Address: 0x00B0AAA0 (FUN_00B0AAA0, _ADXF_LoadPtFromAfsFmgLongNwEx)
   *
   * What it does:
   * Runs long-range AFS point-load lane under ADXF enter/leave guards.
   */
  std::int32_t ADXF_LoadPtFromAfsFmgLongNwEx(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPtFromAfsFmgLongNwEx(arg0, arg1, arg2, arg3, arg4, arg5);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0AA60 (FUN_00B0AA60, _adxf_LoadPtFmgLongNwEx)
   *
   * What it does:
   * Runs long-range filename-based point-load lane through shared ADXF load
   * path with fixed upper range limit.
   */
  std::int32_t adxf_LoadPtFmgLongNwEx(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    return adxf_LoadPtBothNw(arg0, 0, 0, arg1, arg2, 0, 0x000FFFFF, arg3, arg4, arg5, 1);
  }

  /**
   * Address: 0x00B0AA20 (FUN_00B0AA20, _ADXF_LoadPtFmgLongNwEx)
   *
   * What it does:
   * Runs long-range filename-based point-load lane under ADXF enter/leave
   * guards.
   */
  std::int32_t ADXF_LoadPtFmgLongNwEx(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPtFmgLongNwEx(arg0, arg1, arg2, arg3, arg4, arg5);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A9E0 (FUN_00B0A9E0, _adxf_LoadPtFromAfsNwEx)
   *
   * What it does:
   * Runs AFS point-id based non-blocking point-load through shared ADXF load
   * path with fixed upper range limit.
   */
  std::int32_t adxf_LoadPtFromAfsNwEx(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    return adxf_LoadPtBothNw(arg0, arg1, arg2, 0, 0, 0, 0x000FFFFF, arg3, arg4, arg5, 0);
  }

  /**
   * Address: 0x00B0A9A0 (FUN_00B0A9A0, _ADXF_LoadPtFromAfsNwEx)
   *
   * What it does:
   * Runs AFS point-id based non-blocking point-load lane under ADXF
   * enter/leave guards.
   */
  std::int32_t ADXF_LoadPtFromAfsNwEx(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPtFromAfsNwEx(arg0, arg1, arg2, arg3, arg4, arg5);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A960 (FUN_00B0A960, _adxf_LoadPtNwEx)
   *
   * What it does:
   * Runs filename-based non-blocking point-load through shared ADXF load path
   * with fixed upper range limit.
   */
  std::int32_t adxf_LoadPtNwEx(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    return adxf_LoadPtBothNw(arg0, 0, 0, arg1, arg2, 0, 0x000FFFFF, arg3, arg4, arg5, 0);
  }

  /**
   * Address: 0x00B0A920 (FUN_00B0A920, _ADXF_LoadPtNwEx)
   *
   * What it does:
   * Runs filename-based non-blocking point-load lane under ADXF enter/leave
   * guards.
   */
  std::int32_t ADXF_LoadPtNwEx(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3,
    char* const arg4,
    const std::int32_t arg5
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPtNwEx(arg0, arg1, arg2, arg3, arg4, arg5);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A8F0 (FUN_00B0A8F0, _adxf_LoadPartitionFromAfsFmgLongNw)
   *
   * What it does:
   * Runs long-range partition load from AFS metadata using the default ADXF
   * partition staging buffer.
   */
  std::int32_t adxf_LoadPartitionFromAfsFmgLongNw(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    return adxf_LoadPtFromAfsFmgLongNwEx(
      arg0,
      arg1,
      arg2,
      arg3,
      reinterpret_cast<char*>(gAdxfPartitionLoadBuffer.data()),
      0x800
    );
  }

  /**
   * Address: 0x00B0A8C0 (FUN_00B0A8C0, _ADXF_LoadPartitionFromAfsFmgLongNw)
   *
   * What it does:
   * Runs long-range partition load-from-AFS lane under ADXF enter/leave
   * guards.
   */
  std::int32_t ADXF_LoadPartitionFromAfsFmgLongNw(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPartitionFromAfsFmgLongNw(arg0, arg1, arg2, arg3);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A890 (FUN_00B0A890, _adxf_LoadPartitionFmgLongNw)
   *
   * What it does:
   * Runs long-range partition load from filename path using the default ADXF
   * partition staging buffer.
   */
  std::int32_t adxf_LoadPartitionFmgLongNw(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    return adxf_LoadPtFmgLongNwEx(
      arg0,
      arg1,
      arg2,
      arg3,
      reinterpret_cast<char*>(gAdxfPartitionLoadBuffer.data()),
      0x800
    );
  }

  /**
   * Address: 0x00B0A860 (FUN_00B0A860, _ADXF_LoadPartitionFmgLongNw)
   *
   * What it does:
   * Runs long-range partition load-from-filename lane under ADXF enter/leave
   * guards.
   */
  std::int32_t ADXF_LoadPartitionFmgLongNw(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPartitionFmgLongNw(arg0, arg1, arg2, arg3);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A830 (FUN_00B0A830, _adxf_LoadPartitionFromAfsNw)
   *
   * What it does:
   * Runs partition load from AFS point/file metadata using the default ADXF
   * partition staging buffer.
   */
  std::int32_t adxf_LoadPartitionFromAfsNw(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    return adxf_LoadPtFromAfsNwEx(
      arg0,
      arg1,
      arg2,
      arg3,
      reinterpret_cast<char*>(gAdxfPartitionLoadBuffer.data()),
      0x800
    );
  }

  /**
   * Address: 0x00B0A800 (FUN_00B0A800, _ADXF_LoadPartitionFromAfsNw)
   *
   * What it does:
   * Runs partition load-from-AFS lane under ADXF enter/leave guards.
   */
  std::int32_t ADXF_LoadPartitionFromAfsNw(
    const std::int32_t arg0,
    const std::int32_t arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPartitionFromAfsNw(arg0, arg1, arg2, arg3);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A7C0 (FUN_00B0A7C0, _adxf_LoadPtRangeNwEx)
   *
   * What it does:
   * Runs non-blocking point-load with explicit filename/range window and
   * caller-provided scratch buffer.
   */
  std::int32_t adxf_LoadPtRangeNwEx(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    const std::int32_t arg3,
    const std::int32_t arg4,
    char* const arg5,
    char* const arg6,
    const std::int32_t arg7
  )
  {
    return adxf_LoadPtBothNw(arg0, 0, 0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, 0);
  }

  /**
   * Address: 0x00B0A780 (FUN_00B0A780, _adxf_LoadPartitionRangeNw)
   *
   * What it does:
   * Runs partition load with explicit range window using default ADXF partition
   * staging buffer.
   */
  std::int32_t adxf_LoadPartitionRangeNw(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    const std::int32_t arg3,
    const std::int32_t arg4,
    char* const arg5
  )
  {
    return adxf_LoadPtRangeNwEx(
      arg0,
      arg1,
      arg2,
      arg3,
      arg4,
      arg5,
      reinterpret_cast<char*>(gAdxfPartitionLoadBuffer.data()),
      0x800
    );
  }

  /**
   * Address: 0x00B0A740 (FUN_00B0A740, _ADXF_LoadPartitionRangeNw)
   *
   * What it does:
   * Runs partition range-load lane under ADXF enter/leave guards.
   */
  std::int32_t ADXF_LoadPartitionRangeNw(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    const std::int32_t arg3,
    const std::int32_t arg4,
    char* const arg5
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPartitionRangeNw(arg0, arg1, arg2, arg3, arg4, arg5);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A710 (FUN_00B0A710, _adxf_LoadPartitionNw)
   *
   * What it does:
   * Runs partition load from filename path with default ADXF partition staging
   * buffer.
   */
  std::int32_t adxf_LoadPartitionNw(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    return adxf_LoadPtNwEx(
      arg0,
      arg1,
      arg2,
      arg3,
      reinterpret_cast<char*>(gAdxfPartitionLoadBuffer.data()),
      0x800
    );
  }

  /**
   * Address: 0x00B0A6E0 (FUN_00B0A6E0, _ADXF_LoadPartitionNw)
   *
   * What it does:
   * Runs non-blocking partition load lane under ADXF enter/leave guards.
   */
  std::int32_t ADXF_LoadPartitionNw(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPartitionNw(arg0, arg1, arg2, arg3);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A690 (FUN_00B0A690, _adxf_LoadPartitionEx)
   *
   * What it does:
   * Runs partition load and polls ADXF point status until completion or failure
   * while pumping ADXM main callbacks.
   */
  std::int32_t adxf_LoadPartitionEx(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    const std::int32_t loadResult = adxf_LoadPartitionNw(arg0, arg1, arg2, arg3);
    if (loadResult < 0) {
      return loadResult;
    }

    std::int32_t pointStatus = adxf_GetPtStatJumpThunk(arg0);
    if (pointStatus == 3) {
      return 0;
    }

    while (pointStatus != 4) {
      (void)ADXM_ExecMain();
      pointStatus = adxf_GetPtStatJumpThunk(arg0);
      if (pointStatus == 3) {
        return 0;
      }
    }

    return -1;
  }

  /**
   * Address: 0x00B0A660 (FUN_00B0A660, _ADXF_LoadPartitionEx)
   *
   * What it does:
   * Runs blocking partition-load polling lane under ADXF enter/leave guards.
   */
  std::int32_t ADXF_LoadPartitionEx(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPartitionEx(arg0, arg1, arg2, arg3);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A640 (FUN_00B0A640, _adxf_LoadPartition)
   *
   * What it does:
   * Legacy partition-load compatibility lane that forces the range-start lane
   * to zero before forwarding to extended partition load.
   */
  std::int32_t adxf_LoadPartition(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    [[maybe_unused]] char* const arg3
  )
  {
    return adxf_LoadPartitionEx(arg0, arg1, 0, reinterpret_cast<char*>(static_cast<std::uintptr_t>(arg2)));
  }

  /**
   * Address: 0x00B0A610 (FUN_00B0A610, _ADXF_LoadPartition)
   *
   * What it does:
   * Runs legacy partition-load compatibility lane under ADXF enter/leave
   * guards.
   */
  std::int32_t ADXF_LoadPartition(
    const std::int32_t arg0,
    char* const arg1,
    const std::int32_t arg2,
    char* const arg3
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_LoadPartition(arg0, arg1, arg2, arg3);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0A520 (FUN_00B0A520, _ADXF_CALC_BYTE2SCT)
   *
   * What it does:
   * Converts byte-count lane to 2048-byte sector count with ceil division.
   */
  std::int32_t ADXF_CALC_BYTE2SCT(const std::int32_t byteCount)
  {
    std::int32_t sectorCount = byteCount / 2048;
    if ((byteCount % 2048) > 0) {
      ++sectorCount;
    }
    return sectorCount;
  }

  /**
   * Address: 0x00B0A550 (FUN_00B0A550, _adxf_SetCmdHstry)
   *
   * What it does:
   * Appends one ADXF command history entry and updates per-command call count.
   */
  std::int32_t adxf_SetCmdHstry(
    const std::int32_t commandId,
    const std::int32_t commandStage,
    void* const handleArg0,
    const std::int32_t arg1,
    const std::int32_t arg2
  )
  {
    const std::int32_t slot = gAdxfHistoryWriteIndex % static_cast<std::int32_t>(kAdxfCommandHistoryCount);
    auto& entry = gAdxfCommandHistory[static_cast<std::size_t>(slot)];
    const std::size_t commandIndex = static_cast<std::size_t>(commandId);

    if (commandStage == 0) {
      ++gAdxfCommandCallCountById[commandIndex];
    }

    entry.commandId = static_cast<std::uint8_t>(commandId);
    entry.commandStage = static_cast<std::uint8_t>(commandStage);
    entry.callCount = gAdxfCommandCallCountById[commandIndex];
    entry.argument0 = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(handleArg0));
    entry.argument1 = arg1;
    entry.argument2 = arg2;

    gAdxfHistoryWriteIndex = slot + 1;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(&entry));
  }

  /**
   * Address: 0x00B0A5D0 (FUN_00B0A5D0, _adxf_ChkPrmPt)
   *
   * What it does:
   * Validates ADXF partition id and point-info pointer for point-load lanes.
   */
  std::int32_t adxf_ChkPrmPt(const std::int32_t pointId, const void* const pointInfo)
  {
    if (pointId < 0 || pointId >= static_cast<std::int32_t>(kAdxfPointInfoCount)) {
      (void)ADXERR_CallErrFunc1_(kAdxfChkPrmPtPartitionOutOfRangeMessage);
      return -3;
    }
    if (pointInfo == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfChkPrmPtPointInfoNullMessage);
      return -3;
    }
    return 0;
  }

  /**
   * Address: 0x00B0A5C0 (FUN_00B0A5C0, _adxf_wait_1ms)
   *
   * What it does:
   * Legacy 1ms wait hook kept as a no-op in this build.
   */
  void adxf_wait_1ms()
  {}

  /**
   * Address: 0x00B0AD50 (FUN_00B0AD50, _adxf_CloseLdptnwHn)
   *
   * What it does:
   * Closes and clears the process-global loaded-point network handle lane.
   */
  std::int32_t adxf_CloseLdptnwHn()
  {
    adxf_Close(SjAddressToPointer(gAdxfLoadedPointNetworkHandle));
    gAdxfLoadedPointNetworkHandle = 0;
    gAdxfCurrentFileIndex = 0;
    gAdxfLoadedPointReadSectors = 0;
    return 0;
  }

  /**
   * Address: 0x00B0AD80 (FUN_00B0AD80, _adxf_StopPtLd)
   *
   * What it does:
   * Stops and closes the process-global loaded-point network stream when one
   * is active.
   */
  std::int32_t adxf_StopPtLd()
  {
    const std::int32_t loadedHandleAddress = gAdxfLoadedPointNetworkHandle;
    if (loadedHandleAddress != 0 && gAdxfLoadedPointId >= 0) {
      void* const loadedHandle = SjAddressToPointer(loadedHandleAddress);
      if (adxf_GetStat(loadedHandle) != 1) {
        (void)adxf_Stop(loadedHandle);
      }
      return adxf_CloseLdptnwHn();
    }
    return loadedHandleAddress;
  }

  /**
   * Address: 0x00B0AD70 (FUN_00B0AD70, _ADXF_StopPtLd)
   *
   * What it does:
   * Runs loaded-point stop/close lane under ADXF enter/leave guards.
   */
  void ADXF_StopPtLd()
  {
    adxf_enter();
    (void)adxf_StopPtLd();
    adxf_leave();
  }

  /**
   * Address: 0x00B0ADE0 (FUN_00B0ADE0, j__adxf_GetPtStat)
   *
   * What it does:
   * Jump thunk that forwards point-status queries to the core ADXF lane.
   */
  std::int32_t adxf_GetPtStatJumpThunk(const std::int32_t pointId)
  {
    return adxf_GetPtStat(pointId);
  }

  /**
   * Address: 0x00B0ADC0 (FUN_00B0ADC0)
   *
   * What it does:
   * Legacy lock-guarded compatibility wrapper around point-status query.
   */
  std::int32_t adxf_GetPtStatLockedCompatibility(const std::int32_t pointId)
  {
    adxf_enter();
    const std::int32_t pointStatus = adxf_GetPtStatJumpThunk(pointId);
    adxf_leave();
    return pointStatus;
  }

  /**
   * Address: 0x00B0ADF0 (FUN_00B0ADF0, _ADXF_GetPtStat)
   *
   * What it does:
   * Runs point-status query under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetPtStat(const std::int32_t pointId)
  {
    adxf_enter();
    const std::int32_t pointStatus = adxf_GetPtStat(pointId);
    adxf_leave();
    return pointStatus;
  }

  /**
   * Address: 0x00B0B130 (FUN_00B0B130, _adxf_GetPtinfoSize)
   *
   * What it does:
   * Returns metadata-size lane from one ADXF point-info table entry.
   */
  std::int32_t adxf_GetPtinfoSize(const std::int32_t pointId)
  {
    return gAdxfPointInfoById[static_cast<std::size_t>(pointId)]->pointInfoSizeBytes;
  }

  /**
   * Address: 0x00B0B110 (FUN_00B0B110, _ADXF_GetPtinfoSize)
   *
   * What it does:
   * Runs point-info-size query under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetPtinfoSize(const std::int32_t pointId)
  {
    adxf_enter();
    const std::int32_t pointInfoSize = adxf_GetPtinfoSize(pointId);
    adxf_leave();
    return pointInfoSize;
  }

  /**
   * Address: 0x00B0B140 (FUN_00B0B140, _adxf_AllocAdxFs)
   *
   * What it does:
   * Returns the first free ADXF runtime handle slot, or null when exhausted.
   */
  void* adxf_AllocAdxFs()
  {
    for (auto& adxfHandle : gAdxfHandlePool) {
      if (adxfHandle.used == 0u) {
        return &adxfHandle;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B0B2A0 (FUN_00B0B2A0, _adxf_OpenRange)
   *
   * What it does:
   * Allocates one ADXF handle and binds point/file range metadata for blocking
   * range-open lanes.
   */
  void* adxf_OpenRange(void* const afsPointHandle, const std::int32_t fileIndex)
  {
    (void)adxf_SetCmdHstry(1, 0, afsPointHandle, fileIndex, -1);

    void* openedHandle = adxf_CreateAdxFs();
    if (openedHandle != nullptr && adxf_SetFileInfoEx(openedHandle, afsPointHandle, fileIndex) < 0) {
      adxf_Close(openedHandle);
      openedHandle = nullptr;
    }

    (void)adxf_SetCmdHstry(1, 1, afsPointHandle, fileIndex, -1);
    return openedHandle;
  }

  /**
   * Address: 0x00B0B270 (FUN_00B0B270, _ADXF_OpenRange)
   *
   * What it does:
   * Runs point/file range-open lane under ADXF enter/leave guards.
   */
  void* ADXF_OpenRange(void* const afsPointHandle, const std::int32_t fileIndex)
  {
    adxf_enter();
    void* const openedHandle = adxf_OpenRange(afsPointHandle, fileIndex);
    adxf_leave();
    return openedHandle;
  }

  /**
   * Address: 0x00B0B400 (FUN_00B0B400, _adxf_SetAfsFileInfo)
   *
   * What it does:
   * Resolves one AFS point/file entry and binds the resolved file-range lanes
   * to one ADXF runtime handle.
   */
  std::int32_t adxf_SetAfsFileInfo(
    void* const adxfHandleAddress,
    void* const afsPointHandle,
    const std::int32_t fileIndex
  )
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    const std::int32_t afsHandle = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(afsPointHandle));

    std::int32_t rangeSectorCount = 0;
    std::int32_t rangeStartSector = 0;
    std::int32_t fileStartOffset = 0;
    std::array<char, 0x100> fileNameScratch{};
    if (adxf_GetFnameRangeEx(
          afsHandle,
          fileIndex,
          fileNameScratch.data(),
          &fileStartOffset,
          &rangeStartSector,
          &rangeSectorCount
        )
        < 0)
    {
      return -3;
    }

    adxfHandle->fileStartSector = rangeStartSector;
    adxfHandle->fileStartOffset = fileStartOffset;
    const char* const boundFileName = adxf_GetFnameFromPt(afsHandle);
    adxfHandle->boundRangeSectorCount = rangeSectorCount;
    adxfHandle->boundRangeStartSector = rangeStartSector;
    adxfHandle->boundFileName = boundFileName;
    adxfHandle->readStartSector = 0;
    (void)ADXSTM_BindFile(
      adxfHandle->streamHandle,
      boundFileName,
      adxfHandle->fileStartOffset,
      adxfHandle->boundRangeStartSector,
      adxfHandle->boundRangeSectorCount
    );
    if (ADXSTM_GetStat(adxfHandle->streamHandle) == 4) {
      ADXSTM_ReleaseFile(adxfHandle->streamHandle);
      return -1;
    }

    adxfHandle->fileSizeSectors = rangeSectorCount;
    adxfHandle->fileSizeBytes = rangeSectorCount << 11;
    return 0;
  }

  /**
   * Address: 0x00B0B390 (FUN_00B0B390, _adxf_SetFileInfoRangeNw)
   *
   * What it does:
   * Binds explicit filename/range lanes to one ADXF runtime handle for
   * non-blocking open paths.
   */
  std::int32_t adxf_SetFileInfoRangeNw(
    void* const adxfHandleAddress,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    adxfHandle->fileStartSector = rangeStart;
    adxfHandle->boundRangeStartSector = rangeStart;
    adxfHandle->fileStartOffset = startOffset;
    adxfHandle->boundFileName = fileName;
    adxfHandle->boundRangeSectorCount = rangeEnd;
    adxfHandle->readStartSector = 0;
    (void)ADXSTM_BindFile(
      adxfHandle->streamHandle,
      fileName,
      startOffset,
      rangeStart,
      rangeEnd
    );
    if (ADXSTM_GetStat(adxfHandle->streamHandle) == 4) {
      ADXSTM_ReleaseFile(adxfHandle->streamHandle);
      return -1;
    }

    adxfHandle->fileSizeSectors = rangeEnd;
    adxfHandle->fileSizeBytes = rangeEnd << 11;
    return 0;
  }

  /**
   * Address: 0x00B0B330 (FUN_00B0B330, _adxf_OpenRangeNw)
   *
   * What it does:
   * Allocates one ADXF handle and binds explicit filename/range metadata for
   * non-blocking open.
   */
  void* adxf_OpenRangeNw(
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    (void)adxf_SetCmdHstry(1, 0, const_cast<char*>(fileName), startOffset, -1);
    void* openedHandle = adxf_CreateAdxFs();
    if (openedHandle != nullptr && adxf_SetFileInfoRangeNw(openedHandle, fileName, startOffset, rangeStart, rangeEnd) < 0) {
      (void)adxf_Close(openedHandle);
      openedHandle = nullptr;
    }
    (void)adxf_SetCmdHstry(1, 1, const_cast<char*>(fileName), startOffset, -1);
    return openedHandle;
  }

  /**
   * Address: 0x00B0B300 (FUN_00B0B300, _ADXF_OpenRangeNw)
   *
   * What it does:
   * Runs one ADXF non-blocking range-open request under ADXF enter/leave
   * guards.
   */
  void* ADXF_OpenRangeNw(
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    adxf_enter();
    void* const openedHandle = adxf_OpenRangeNw(fileName, startOffset, rangeStart, rangeEnd);
    adxf_leave();
    return openedHandle;
  }

  /**
   * Address: 0x00B0B4D0 (FUN_00B0B4D0, _ADXF_OpenAfsNw)
   *
   * What it does:
   * Runs one ADXF non-blocking point/file open request under ADXF enter/leave
   * guards.
   */
  void* ADXF_OpenAfsNw(void* const afsPointHandle, const std::int32_t fileIndex)
  {
    adxf_enter();
    void* const openedHandle = adxf_OpenAfsNw(afsPointHandle, fileIndex);
    adxf_leave();
    return openedHandle;
  }

  /**
   * Address: 0x00B0B500 (FUN_00B0B500, _adxf_OpenAfsNw)
   *
   * What it does:
   * Allocates one ADXF runtime handle and binds point/file metadata for a
   * non-blocking AFS open request.
   */
  void* adxf_OpenAfsNw(void* const afsPointHandle, const std::int32_t fileIndex)
  {
    (void)adxf_SetCmdHstry(2, 0, afsPointHandle, fileIndex, -1);

    void* openedHandle = adxf_CreateAdxFs();
    if (openedHandle != nullptr && adxf_SetAfsFileInfo(openedHandle, afsPointHandle, fileIndex) < 0) {
      (void)adxf_Close(openedHandle);
      openedHandle = nullptr;
    }

    (void)adxf_SetCmdHstry(2, 1, afsPointHandle, fileIndex, -1);
    return openedHandle;
  }

  /**
   * Address: 0x00B0B560 (FUN_00B0B560, _adxf_CloseSjStm)
   *
   * What it does:
   * Releases and destroys the bound SJ source object when ADXF is responsible
   * for its lifetime.
   */
  void adxf_CloseSjStm(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    if (adxfHandle->sourceJoinObject != nullptr && adxfHandle->sjFlag == 0u) {
      if (gAdxfOcbiEnabled == 1) {
        ADXF_Ocbi(adxfHandle->ocbiCallbackArg0, adxfHandle->ocbiCallbackArg1);
      }

      moho::SofdecSjSupplyHandle* const sourceJoinObject = adxfHandle->sourceJoinObject;
      adxfHandle->sourceJoinObject = nullptr;
      sourceJoinObject->dispatchTable->destroy(sourceJoinObject);
    }
  }

  /**
   * Address: 0x00B0B5B0 (FUN_00B0B5B0, _ADXF_Close)
   *
   * What it does:
   * Runs one ADXF handle close request under ADXF enter/leave guards.
   */
  void ADXF_Close(void* const adxfHandle)
  {
    adxf_enter();
    (void)adxf_Close(adxfHandle);
    adxf_leave();
  }

  /**
   * Address: 0x00B0B5D0 (FUN_00B0B5D0, _adxf_Close)
   *
   * What it does:
   * Stops active transfer state, tears down stream resources, clears handle
   * memory, and records ADXF close command-history lanes.
   */
  void adxf_Close(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    (void)adxf_SetCmdHstry(3, 0, adxfHandleAddress, -1, -1);
    if (adxfHandle == nullptr) {
      return;
    }

    if (adxfHandle->status == 2u) {
      (void)adxf_Stop(adxfHandleAddress);
    }

    void* const streamHandle = adxfHandle->streamHandle;
    if (streamHandle != nullptr) {
      adxfHandle->used = 0;
      adxfHandle->streamHandle = nullptr;
      ADXSTM_ReleaseFile(streamHandle);
      (void)ADXSTM_Destroy(streamHandle);
    }

    std::memset(adxfHandle, 0, sizeof(*adxfHandle));
    (void)adxf_SetCmdHstry(3, 1, adxfHandleAddress, -1, -1);
  }

  /**
   * Address: 0x00B0B640 (FUN_00B0B640, _ADXF_CloseAll)
   *
   * What it does:
   * Closes all ADXF runtime handles under ADXF enter/leave guards.
   */
  void ADXF_CloseAll()
  {
    adxf_enter();
    adxf_CloseAll();
    adxf_leave();
  }

  /**
   * Address: 0x00B0B650 (FUN_00B0B650, _adxf_CloseAll)
   *
   * What it does:
   * Iterates ADXF runtime handle slots and closes each active entry.
   */
  void adxf_CloseAll()
  {
    for (auto& adxfHandle : gAdxfHandlePool) {
      if (adxfHandle.used == 1u) {
        adxf_Close(&adxfHandle);
      }
    }
  }

  /**
   * Address: 0x00B0B810 (FUN_00B0B810, _adxf_ReadSj)
   *
   * What it does:
   * Thin thunk that forwards ADXF SJ reads into the 32-bit implementation.
   */
  std::int32_t adxf_ReadSj(void* const adxfHandle, const std::int32_t requestedSectors, void* const sourceJoinObject)
  {
    return adxf_ReadSj32(adxfHandle, requestedSectors, sourceJoinObject);
  }

  /**
   * Address: 0x00B0B7E0 (FUN_00B0B7E0, _ADXF_ReadSj)
   *
   * What it does:
   * Runs one SJ-backed ADXF read request under ADXF enter/leave guards.
   */
  std::int32_t ADXF_ReadSj(void* const adxfHandle, const std::int32_t requestedSectors, void* const sourceJoinObject)
  {
    adxf_enter();
    const std::int32_t result = adxf_ReadSj(adxfHandle, requestedSectors, sourceJoinObject);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0B740 (FUN_00B0B740, _ADXF_ReadSj32)
   *
   * What it does:
   * Runs one 32-bit SJ-backed ADXF read request under ADXF enter/leave guards.
   */
  std::int32_t ADXF_ReadSj32(void* const adxfHandle, const std::int32_t requestedSectors, void* const sourceJoinObject)
  {
    adxf_enter();
    const std::int32_t result = adxf_ReadSj32(adxfHandle, requestedSectors, sourceJoinObject);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0B9C0 (FUN_00B0B9C0, _adxf_ReadNw)
   *
   * What it does:
   * Thin thunk that forwards ADXF network reads into the 32-bit implementation.
   */
  std::int32_t adxf_ReadNw(void* const adxfHandle, const std::int32_t requestedSectors, const std::int32_t readMode)
  {
    return adxf_ReadNw32(adxfHandle, requestedSectors, readMode);
  }

  /**
   * Address: 0x00B0B990 (FUN_00B0B990, _ADXF_ReadNw)
   *
   * What it does:
   * Runs one network-backed ADXF read request under ADXF enter/leave guards.
   */
  std::int32_t ADXF_ReadNw(void* const adxfHandle, const std::int32_t requestedSectors, const std::int32_t readMode)
  {
    adxf_enter();
    const std::int32_t result = adxf_ReadNw(adxfHandle, requestedSectors, readMode);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0B820 (FUN_00B0B820, _ADXF_ReadNw32)
   *
   * What it does:
   * Runs one 32-bit network-backed ADXF read request under ADXF enter/leave
   * guards.
   */
  std::int32_t ADXF_ReadNw32(void* const adxfHandle, const std::int32_t requestedSectors, const std::int32_t readMode)
  {
    adxf_enter();
    const std::int32_t result = adxf_ReadNw32(adxfHandle, requestedSectors, readMode);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0B9D0 (FUN_00B0B9D0, _ADXF_Stop)
   *
   * What it does:
   * Runs one ADXF stop request under ADXF enter/leave guards.
   */
  std::int32_t ADXF_Stop(void* const adxfHandle)
  {
    adxf_enter();
    const std::int32_t result = adxf_Stop(adxfHandle);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0BB30 (FUN_00B0BB30, _adxf_ExecOne)
   *
   * What it does:
   * Polls one ADXF runtime handle stream state, updates read-progress lanes,
   * and closes SJ transfer on terminal or stop-complete states.
   */
  void adxf_ExecOne(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    if (adxfHandle->status == 2u) {
      const auto streamStatus = static_cast<std::uint8_t>(ADXSTM_GetStat(adxfHandle->streamHandle));
      const std::int32_t readStartSector = adxfHandle->readStartSector;
      adxfHandle->status = streamStatus;
      const std::int32_t readProgressSectors = ADXSTM_Tell(adxfHandle->streamHandle) - readStartSector;
      adxfHandle->readProgressSectors = readProgressSectors;
      if (streamStatus == 3u || streamStatus == 4u) {
        adxfHandle->readStartSector = readStartSector + readProgressSectors;
        adxf_CloseSjStm(adxfHandle);
      }
    }

    if (adxfHandle->stopWithoutNetworkFlag == 1u && ADXSTM_GetStat(adxfHandle->streamHandle) == 1) {
      adxfHandle->readProgressSectors = ADXSTM_Tell(adxfHandle->streamHandle) - adxfHandle->readStartSector;
      adxf_CloseSjStm(adxfHandle);
      adxfHandle->status = 1;
      adxfHandle->stopWithoutNetworkFlag = 0;
    }
  }

  /**
   * Address: 0x00B0BBD0 (FUN_00B0BBD0, _adxf_ExecServer)
   *
   * What it does:
   * Runs ADXF handle polling over active handle lanes under ADXCRS lock.
   */
  void adxf_ExecServer()
  {
    ADXCRS_Lock();
    for (auto& adxfHandle : gAdxfHandlePool) {
      if (adxfHandle.used == 1u) {
        adxf_ExecOne(&adxfHandle);
      }
    }
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0BBC0 (FUN_00B0BBC0, _ADXF_ExecServer)
   *
   * What it does:
   * Runs ADXF server polling under ADXF enter/leave guard wrappers.
   */
  void ADXF_ExecServer()
  {
    adxf_enter();
    adxf_ExecServer();
    adxf_leave();
  }

  /**
   * Address: 0x00B0BC00 (FUN_00B0BC00, _ADXF_Seek)
   *
   * What it does:
   * Runs one ADXF seek request under ADXF enter/leave guards.
   */
  std::int32_t ADXF_Seek(void* const adxfHandle, const std::int32_t seekOffset, const std::int32_t seekOrigin)
  {
    adxf_enter();
    const std::int32_t result = adxf_Seek(adxfHandle, seekOffset, seekOrigin);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0BD00 (FUN_00B0BD00, _adxf_Tell)
   *
   * What it does:
   * Returns the current ADXF read-sector lane and reports null-handle errors.
   */
  std::int32_t adxf_Tell(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    if (adxfHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfTellNullHandleMessage);
      return -3;
    }
    return adxfHandle->readStartSector;
  }

  /**
   * Address: 0x00B0BCE0 (FUN_00B0BCE0, _ADXF_Tell)
   *
   * What it does:
   * Runs ADXF tell query under ADXF enter/leave guards.
   */
  std::int32_t ADXF_Tell(void* const adxfHandle)
  {
    adxf_enter();
    const std::int32_t tellSector = adxf_Tell(adxfHandle);
    adxf_leave();
    return tellSector;
  }

  /**
   * Address: 0x00B0BD40 (FUN_00B0BD40)
   *
   * What it does:
   * Refreshes cached ADXF file-size sectors from current byte-size lane.
   */
  std::int32_t adxf_RefreshFsizeSct(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    const std::int32_t sizeSectors = (adxf_GetFsizeSct(adxfHandleAddress) + 0x7FF) / 0x800;
    adxfHandle->fileSizeSectors = sizeSectors;
    return sizeSectors;
  }

  /**
   * Address: 0x00B0BD20 (FUN_00B0BD20)
   *
   * What it does:
   * Runs ADXF cached file-size-sector refresh under ADXF enter/leave guards.
   */
  std::int32_t ADXF_RefreshFsizeSct(void* const adxfHandleAddress)
  {
    adxf_enter();
    const std::int32_t sizeSectors = adxf_RefreshFsizeSct(adxfHandleAddress);
    adxf_leave();
    return sizeSectors;
  }

  /**
   * Address: 0x00B0BD90 (FUN_00B0BD90, _adxf_GetFsizeSct)
   *
   * What it does:
   * Returns current ADXF byte-size lane, probing ADXSTM file size when needed.
   */
  std::int32_t adxf_GetFsizeSct(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    if (adxfHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfGetFsizeSctNullHandleMessage);
      return -3;
    }

    if (adxfHandle->fileSizeBytes >= 0x7FFFF800) {
      adxf_wait_until_file_open(adxfHandle->streamHandle);
      if (ADXSTM_GetStat(adxfHandle->streamHandle) == 4) {
        return -5;
      }
    }

    const std::int32_t fileLengthBytes = ADXSTM_GetFileLen(adxfHandle->streamHandle);
    adxfHandle->fileSizeBytes = fileLengthBytes;
    return fileLengthBytes;
  }

  /**
   * Address: 0x00B0BD70 (FUN_00B0BD70, _ADXF_GetFsizeSct)
   *
   * What it does:
   * Runs ADXF file-size query under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetFsizeSct(void* const adxfHandleAddress)
  {
    adxf_enter();
    const std::int32_t fileLengthBytes = adxf_GetFsizeSct(adxfHandleAddress);
    adxf_leave();
    return fileLengthBytes;
  }

  /**
   * Address: 0x00B0BE20 (FUN_00B0BE20, _adxf_GetNumReqSct)
   *
   * What it does:
   * Returns pending ADXF read-window start/count lanes for one handle.
   */
  std::int32_t adxf_GetNumReqSct(void* const adxfHandleAddress, std::int32_t* const outRequestedSectorStart)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    if (adxfHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfGetNumReqSctNullHandleMessage);
      *outRequestedSectorStart = 0;
      return -3;
    }

    *outRequestedSectorStart = adxfHandle->requestSectorStart;
    return adxfHandle->requestSectorCount;
  }

  /**
   * Address: 0x00B0BDF0 (FUN_00B0BDF0, _ADXF_GetNumReqSct)
   *
   * What it does:
   * Runs ADXF requested-sector query under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetNumReqSct(void* const adxfHandleAddress, std::int32_t* const outRequestedSectorStart)
  {
    adxf_enter();
    const std::int32_t requestedSectorCount = adxf_GetNumReqSct(adxfHandleAddress, outRequestedSectorStart);
    adxf_leave();
    return requestedSectorCount;
  }

  /**
   * Address: 0x00B0BE80 (FUN_00B0BE80, _adxf_GetNumReadSct)
   *
   * What it does:
   * Returns accumulated ADXF read-progress sectors for one handle.
   */
  std::int32_t adxf_GetNumReadSct(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    if (adxfHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfGetNumReadSctNullHandleMessage);
      return -3;
    }
    return adxfHandle->readProgressSectors;
  }

  /**
   * Address: 0x00B0BE60 (FUN_00B0BE60, _ADXF_GetNumReadSct)
   *
   * What it does:
   * Runs ADXF read-progress query under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetNumReadSct(void* const adxfHandleAddress)
  {
    adxf_enter();
    const std::int32_t readProgressSectors = adxf_GetNumReadSct(adxfHandleAddress);
    adxf_leave();
    return readProgressSectors;
  }

  /**
   * Address: 0x00B0BEC0 (FUN_00B0BEC0, _adxf_GetStat)
   *
   * What it does:
   * Returns current ADXF status lane and reports null-handle errors.
   */
  std::int32_t adxf_GetStat(void* const adxfHandleAddress)
  {
    auto* const adxfHandle = static_cast<AdxfRuntimeHandleView*>(adxfHandleAddress);
    if (adxfHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfGetStatNullHandleMessage);
      return -3;
    }
    return static_cast<std::int8_t>(adxfHandle->status);
  }

  /**
   * Address: 0x00B0BEA0 (FUN_00B0BEA0, _ADXF_GetStat)
   *
   * What it does:
   * Runs ADXF status query under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetStat(void* const adxfHandleAddress)
  {
    adxf_enter();
    const std::int32_t status = adxf_GetStat(adxfHandleAddress);
    adxf_leave();
    return status;
  }

  /**
   * Address: 0x00B0BEE0 (FUN_00B0BEE0, _adxf_ChkPrmGfr)
   *
   * What it does:
   * Validates ADXF point/file indices for filename-range queries.
   */
  std::int32_t adxf_ChkPrmGfr(const std::int32_t afsHandle, const std::int32_t fileIndex)
  {
    if (afsHandle < 0 || afsHandle >= static_cast<std::int32_t>(kAdxfPointInfoCount)) {
      (void)ADXERR_CallErrFunc1_(kAdxfChkPrmGfrPtidOutOfRangeMessage);
      return -3;
    }

    const auto* const pointInfo = gAdxfPointInfoById[static_cast<std::size_t>(afsHandle)];
    if (pointInfo == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfChkPrmGfrPtidOutOfRangeMessage);
      return -3;
    }

    if (fileIndex < 0 || fileIndex >= pointInfo->fileCount) {
      (void)ADXERR_CallErrFunc1_(kAdxfChkPrmGfrFlidOutOfRangeMessage);
      return -3;
    }

    return 0;
  }

  /**
   * Address: 0x00B0BFE0 (FUN_00B0BFE0, _adxf_GetFnameRangeEx)
   *
   * What it does:
   * Resolves one ADXF point/file entry into archive filename, stream base
   * offset, and sector-range lane values.
   */
  std::int32_t adxf_GetFnameRangeEx(
    const std::int32_t afsHandle,
    const std::int32_t fileIndex,
    char* const outFileName,
    std::int32_t* const outStartOffset,
    std::int32_t* const outRangeStart,
    std::int32_t* const outRangeEnd
  )
  {
    const std::int32_t validationResult = adxf_ChkPrmGfr(afsHandle, fileIndex);
    if (validationResult < 0) {
      *outStartOffset = 0;
      *outRangeStart = -1;
      *outRangeEnd = -1;
      return validationResult;
    }

    const auto* const pointInfo = gAdxfPointInfoById[static_cast<std::size_t>(afsHandle)];

    std::int32_t rangeStart = 0;
    std::int32_t rangeLength = 0;
    if (pointInfo->UsesWideRangeTable()) {
      rangeStart = pointInfo->rangeTableHeader.rangeSeed32;
      const auto* const lengths = pointInfo->RangeLengths32();
      for (std::int32_t index = 0; index < fileIndex; ++index) {
        rangeStart += lengths[index];
      }
      rangeLength = lengths[fileIndex];
    } else {
      rangeStart = static_cast<std::int32_t>(pointInfo->rangeTableHeader.rangeSeed16);
      const auto* const lengths = pointInfo->RangeLengths16();
      for (std::int32_t index = 0; index < fileIndex; ++index) {
        rangeStart += static_cast<std::int32_t>(lengths[index]);
      }
      rangeLength = static_cast<std::int32_t>(lengths[fileIndex]);
    }

    *outRangeEnd = rangeLength;
    std::strncpy(outFileName, pointInfo->archiveFileName.data(), 0x100u);
    *outStartOffset = pointInfo->fileStartOffsetBytes;
    *outRangeStart = pointInfo->rangeBase + rangeStart;
    return validationResult;
  }

  /**
   * Address: 0x00B0BFA0 (FUN_00B0BFA0, _ADXF_GetFnameRangeEx)
   *
   * What it does:
   * Runs ADXF point-file range resolve under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetFnameRangeEx(
    const std::int32_t afsHandle,
    const std::int32_t fileIndex,
    char* const outFileName,
    std::int32_t* const outStartOffset,
    std::int32_t* const outRangeStart,
    std::int32_t* const outRangeEnd
  )
  {
    adxf_enter();
    const std::int32_t result =
      adxf_GetFnameRangeEx(afsHandle, fileIndex, outFileName, outStartOffset, outRangeStart, outRangeEnd);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0BF70 (FUN_00B0BF70, _adxf_GetFileSizeFromPt)
   *
   * What it does:
   * Resolves ADXF point/file range and returns only range-start/end lanes.
   */
  std::int32_t adxf_GetFileSizeFromPt(
    const std::int32_t afsHandle,
    const std::int32_t fileIndex,
    char* const outFileName,
    std::int32_t* const outRangeStart,
    std::int32_t* const outRangeEnd
  )
  {
    std::int32_t ignoredStartOffset = 0;
    return adxf_GetFnameRangeEx(
      afsHandle,
      fileIndex,
      outFileName,
      &ignoredStartOffset,
      outRangeStart,
      outRangeEnd
    );
  }

  /**
   * Address: 0x00B0BF30 (FUN_00B0BF30, _ADXF_GetFileSizeFromPt)
   *
   * What it does:
   * Runs ADXF point-file size resolve under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetFileSizeFromPt(
    const std::int32_t afsHandle,
    const std::int32_t fileIndex,
    char* const outFileName,
    std::int32_t* const outRangeStart,
    std::int32_t* const outRangeEnd
  )
  {
    adxf_enter();
    const std::int32_t result = adxf_GetFileSizeFromPt(afsHandle, fileIndex, outFileName, outRangeStart, outRangeEnd);
    adxf_leave();
    return result;
  }

  /**
   * Address: 0x00B0C0E0 (FUN_00B0C0E0, _adxf_GetFnameFromPt)
   *
   * What it does:
   * Returns archive filename lane for one ADXF point id.
   */
  const char* adxf_GetFnameFromPt(const std::int32_t afsHandle)
  {
    return gAdxfPointInfoById[static_cast<std::size_t>(afsHandle)]->archiveFileName.data();
  }

  /**
   * Address: 0x00B0C0C0 (FUN_00B0C0C0, _ADXF_GetFnameFromPt)
   *
   * What it does:
   * Returns archive filename lane for one ADXF point id under ADXF enter/leave guards.
   */
  const char* ADXF_GetFnameFromPt(const std::int32_t afsHandle)
  {
    adxf_enter();
    const char* const fileName = adxf_GetFnameFromPt(afsHandle);
    adxf_leave();
    return fileName;
  }

  /**
   * Address: 0x00B0C0F0 (FUN_00B0C0F0, _ADXF_SetOcbiSw)
   *
   * What it does:
   * Stores process-global ADXF OCBI enable lane.
   */
  std::int32_t ADXF_SetOcbiSw(const std::int32_t enabled)
  {
    gAdxfOcbiEnabled = enabled;
    return enabled;
  }

  /**
   * Address: 0x00B0C120 (FUN_00B0C120, _adxf_SetReqRdSct)
   *
   * What it does:
   * Updates one ADXF handle requested-read-sector lane unless the handle is in reading state.
   */
  void adxf_SetReqRdSct(AdxfRuntimeHandleView* const adxfHandle, const std::int32_t requestedSectors)
  {
    if (adxfHandle->status == 2u) {
      (void)ADXERR_CallErrFunc1_(kAdxfSetReqRdSctStateReadingMessage);
      return;
    }
    adxfHandle->requestedReadSizeSectors = requestedSectors;
  }

  /**
   * Address: 0x00B0C100 (FUN_00B0C100, _ADXF_SetReqRdSct)
   *
   * What it does:
   * Runs ADXF requested-read-sector update under ADXF enter/leave guards.
   */
  void ADXF_SetReqRdSct(void* const adxfHandle, const std::int32_t requestedSectors)
  {
    adxf_enter();
    adxf_SetReqRdSct(static_cast<AdxfRuntimeHandleView*>(adxfHandle), requestedSectors);
    adxf_leave();
  }

  /**
   * Address: 0x00B0C160 (FUN_00B0C160, _adxf_GetStatRead)
   *
   * What it does:
   * Returns ADXF handle read-flag lane, or zero when handle/stream is null.
   */
  std::int32_t adxf_GetStatRead(AdxfRuntimeHandleView* const adxfHandle)
  {
    if (adxfHandle != nullptr && adxfHandle->streamHandle != nullptr) {
      return ADXSTM_GetReadFlg(adxfHandle->streamHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B0C140 (FUN_00B0C140, _ADXF_GetStatRead)
   *
   * What it does:
   * Returns ADXF read-flag lane under ADXF enter/leave guards.
   */
  std::int32_t ADXF_GetStatRead(void* const adxfHandle)
  {
    adxf_enter();
    const std::int32_t readFlag = adxf_GetStatRead(static_cast<AdxfRuntimeHandleView*>(adxfHandle));
    adxf_leave();
    return readFlag;
  }

  /**
   * Address: 0x00B0C1D0 (FUN_00B0C1D0, _SVM_Lock)
   *
   * What it does:
   * Enters SVM lock lane with the default lock-domain type.
   */
  void SVM_Lock()
  {
    svm_lock(1);
  }

  /**
   * Address: 0x00B0C1E0 (FUN_00B0C1E0, _svm_lock)
   *
   * What it does:
   * Invokes registered SVM lock callback and tracks nested lock level/type.
   */
  void svm_lock(const std::int32_t lockType)
  {
    if (gSvmLockCallback.fn == nullptr) {
      return;
    }

    gSvmLockCallback.fn(gSvmLockCallback.callbackObject);
    if (gSvmLockLevel == 0) {
      gSvmLockingType = lockType;
    }
    ++gSvmLockLevel;
  }

  /**
   * Address: 0x00B0C220 (FUN_00B0C220, _SVM_Unlock)
   *
   * What it does:
   * Leaves SVM lock lane with the default lock-domain type.
   */
  void SVM_Unlock()
  {
    svm_unlock(1);
  }

  /**
   * Address: 0x00B0C290 (FUN_00B0C290, _SVM_LockVar)
   *
   * What it does:
   * Enters SVM lock lane using lock-domain type `2`.
   */
  void SVM_LockVar()
  {
    svm_lock(2);
  }

  /**
   * Address: 0x00B0C2A0 (FUN_00B0C2A0, _SVM_LockSync)
   *
   * What it does:
   * Enters SVM lock lane using lock-domain type `3`.
   */
  void SVM_LockSync()
  {
    svm_lock(3);
  }

  /**
   * Address: 0x00B0C2B0 (FUN_00B0C2B0, _SVM_LockRsc)
   *
   * What it does:
   * Enters SVM lock lane using lock-domain type `4`.
   */
  void SVM_LockRsc()
  {
    svm_lock(4);
  }

  /**
   * Address: 0x00B0C2C0 (FUN_00B0C2C0, _SVM_LockThrd)
   *
   * What it does:
   * Enters SVM lock lane using lock-domain type `5`.
   */
  void SVM_LockThrd()
  {
    svm_lock(5);
  }

  /**
   * Address: 0x00B0C2D0 (FUN_00B0C2D0, _SVM_LockEtc)
   *
   * What it does:
   * Enters SVM lock lane using lock-domain type `1000`.
   */
  void SVM_LockEtc()
  {
    svm_lock(1000);
  }

  /**
   * Address: 0x00B0C2E0 (FUN_00B0C2E0, _SVM_UnlockVar)
   *
   * What it does:
   * Leaves SVM lock lane using lock-domain type `2`.
   */
  void SVM_UnlockVar()
  {
    svm_unlock(2);
  }

  /**
   * Address: 0x00B0C2F0 (FUN_00B0C2F0, _SVM_UnlockSync)
   *
   * What it does:
   * Leaves SVM lock lane using lock-domain type `3`.
   */
  void SVM_UnlockSync()
  {
    svm_unlock(3);
  }

  /**
   * Address: 0x00B0C300 (FUN_00B0C300, _SVM_UnlockRsc)
   *
   * What it does:
   * Leaves SVM lock lane using lock-domain type `4`.
   */
  void SVM_UnlockRsc()
  {
    svm_unlock(4);
  }

  /**
   * Address: 0x00B06E20 (FUN_00B06E20, _ADXM_Lock)
   *
   * What it does:
   * ADXM compatibility thunk that enters the shared SVM lock.
   */
  void ADXM_Lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B06E30 (FUN_00B06E30, _ADXM_Unlock)
   *
   * What it does:
   * ADXM compatibility thunk that leaves the shared SVM lock.
   */
  void ADXM_Unlock()
  {
    SVM_Unlock();
  }

  using AdxstmEndOfStreamCallback = void(__cdecl*)(std::int32_t callbackContext);

  struct AdxstmServerSlotView
  {
    std::uint8_t slotState = 0; // +0x00
    std::int8_t streamStatus = 0; // +0x01
    std::int8_t readFlag = 0; // +0x02
    std::uint8_t mUnknown03 = 0; // +0x03
    moho::SofdecSjSupplyHandle* sourceJoinHandle = nullptr; // +0x04
    CvFsHandleView* cvfsHandle = nullptr; // +0x08
    std::int32_t baseOffset = 0; // +0x0C
    std::int32_t fileLengthBytes = 0; // +0x10
    std::int32_t fileLengthSectors = 0; // +0x14
    std::int32_t sourceReadableBytes = 0; // +0x18
    std::int32_t sourceWritableBytes = 0; // +0x1C
    std::int32_t pendingReadSectors = 0; // +0x20
    SjChunkRange pendingChunk{}; // +0x24
    std::int32_t requestedReadSectors = 0; // +0x2C
    std::int32_t eosSector = 0; // +0x30
    std::int32_t sourceStreamedBytes = 0; // +0x34
    AdxstmEndOfStreamCallback endOfStreamCallback = nullptr; // +0x38
    std::int32_t endOfStreamCallbackContext = 0; // +0x3C
    std::int32_t sourceTotalBytes = 0; // +0x40
    std::int8_t pauseState = 0; // +0x44
    std::uint8_t waitForFileOpen = 0; // +0x45
    std::uint8_t releaseFilePending = 0; // +0x46
    std::uint8_t clearStopRequested = 0; // +0x47
    std::uint8_t stopAfterRead = 0; // +0x48
    std::int8_t filesystemServiceActive = 0; // +0x49
    std::uint8_t mUnknown4A_4B[0x02]{}; // +0x4A
    std::int32_t streamErrorCount = 0; // +0x4C
    char* fileName = nullptr; // +0x50
    std::int32_t fileOpenMode = 0; // +0x54
    std::int32_t currentSectorOffset = 0; // +0x58
    std::int32_t streamSectorLimit = 0; // +0x5C
  };

  static_assert(sizeof(AdxstmServerSlotView) == 0x60, "AdxstmServerSlotView size must be 0x60");
  static_assert(offsetof(AdxstmServerSlotView, streamStatus) == 0x01, "AdxstmServerSlotView::streamStatus offset must be 0x01");
  static_assert(offsetof(AdxstmServerSlotView, readFlag) == 0x02, "AdxstmServerSlotView::readFlag offset must be 0x02");
  static_assert(
    offsetof(AdxstmServerSlotView, sourceJoinHandle) == 0x04,
    "AdxstmServerSlotView::sourceJoinHandle offset must be 0x04"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, cvfsHandle) == 0x08,
    "AdxstmServerSlotView::cvfsHandle offset must be 0x08"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, baseOffset) == 0x0C,
    "AdxstmServerSlotView::baseOffset offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, fileLengthSectors) == 0x14,
    "AdxstmServerSlotView::fileLengthSectors offset must be 0x14"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, sourceReadableBytes) == 0x18,
    "AdxstmServerSlotView::sourceReadableBytes offset must be 0x18"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, sourceWritableBytes) == 0x1C,
    "AdxstmServerSlotView::sourceWritableBytes offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, pendingReadSectors) == 0x20,
    "AdxstmServerSlotView::pendingReadSectors offset must be 0x20"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, pendingChunk) == 0x24,
    "AdxstmServerSlotView::pendingChunk offset must be 0x24"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, requestedReadSectors) == 0x2C,
    "AdxstmServerSlotView::requestedReadSectors offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, eosSector) == 0x30,
    "AdxstmServerSlotView::eosSector offset must be 0x30"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, sourceStreamedBytes) == 0x34,
    "AdxstmServerSlotView::sourceStreamedBytes offset must be 0x34"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, sourceTotalBytes) == 0x40,
    "AdxstmServerSlotView::sourceTotalBytes offset must be 0x40"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, pauseState) == 0x44,
    "AdxstmServerSlotView::pauseState offset must be 0x44"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, waitForFileOpen) == 0x45,
    "AdxstmServerSlotView::waitForFileOpen offset must be 0x45"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, streamErrorCount) == 0x4C,
    "AdxstmServerSlotView::streamErrorCount offset must be 0x4C"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, fileName) == 0x50,
    "AdxstmServerSlotView::fileName offset must be 0x50"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, fileOpenMode) == 0x54,
    "AdxstmServerSlotView::fileOpenMode offset must be 0x54"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, currentSectorOffset) == 0x58,
    "AdxstmServerSlotView::currentSectorOffset offset must be 0x58"
  );
  static_assert(
    offsetof(AdxstmServerSlotView, streamSectorLimit) == 0x5C,
    "AdxstmServerSlotView::streamSectorLimit offset must be 0x5C"
  );

  constexpr std::size_t kAdxstmServerSlotCount = 0x50;
  static_assert(
    (sizeof(AdxstmServerSlotView) * kAdxstmServerSlotCount) == 0x1E00,
    "ADXSTM server slot pool size must be 0x1E00 bytes"
  );
  std::int32_t gSfadxtAttachCount = 0;
  std::int32_t gAdxstmInitCount = 0;
  std::int32_t adxstmf_nrml_ofst = 0;
  std::int32_t adxstmf_nrml_num = 0;
  std::int32_t adxstmf_rtim_ofst = 0;
  std::int32_t adxstmf_rtim_num = 0;
  std::array<AdxstmServerSlotView, kAdxstmServerSlotCount> gAdxstmObjectPool{};

  /**
   * Address: 0x00B0F4A0 (FUN_00B0F4A0)
   *
   * What it does:
   * Increments SFADXT attach/reference count lane.
   */
  void sfadxt_IncrementAttachCount()
  {
    ++gSfadxtAttachCount;
  }

  /**
   * Address: 0x00B0F4B0 (FUN_00B0F4B0)
   *
   * What it does:
   * Decrements SFADXT attach/reference count lane.
   */
  void sfadxt_DecrementAttachCount()
  {
    --gSfadxtAttachCount;
  }

  /**
   * Address: 0x00B0F5E0 (FUN_00B0F5E0, _ADXT_SetupRtimeNumStm)
   *
   * What it does:
   * Stores ADXSTM realtime-partition slot count lane.
   */
  std::int32_t ADXT_SetupRtimeNumStm(const std::int32_t realtimeStreamCount)
  {
    adxstmf_rtim_num = realtimeStreamCount;
    return realtimeStreamCount;
  }

  /**
   * Address: 0x00B0F5F0 (FUN_00B0F5F0, _ADXT_SetupNrmlNumStm)
   *
   * What it does:
   * Stores ADXSTM normal-partition slot count and computes partition start
   * offset from the fixed 0x50-slot pool.
   */
  std::int32_t ADXT_SetupNrmlNumStm(const std::int32_t normalStreamCount)
  {
    adxstmf_nrml_num = normalStreamCount;
    adxstmf_nrml_ofst = static_cast<std::int32_t>(kAdxstmServerSlotCount) - normalStreamCount;
    return normalStreamCount;
  }

  /**
   * Address: 0x00B0F610 (FUN_00B0F610, _ADXSTM_Init)
   *
   * What it does:
   * Increments ADXSTM init counter and clears full runtime slot pool on first
   * initialization.
   */
  std::int32_t ADXSTM_Init()
  {
    if (++gAdxstmInitCount == 1) {
      std::memset(gAdxstmObjectPool.data(), 0, sizeof(gAdxstmObjectPool));
    }
    return 1;
  }

  /**
   * Address: 0x00B0F640 (FUN_00B0F640, _ADXSTM_Reset)
   *
   * What it does:
   * Compatibility reset entrypoint (no-op).
   */
  void ADXSTM_Reset()
  {
  }

  /**
   * Address: 0x00B0F6A0 (FUN_00B0F6A0, _adxstm_enter)
   *
   * What it does:
   * ADXSTM enter hook (no-op in this runtime variant).
   */
  void adxstm_enter()
  {
  }

  /**
   * Address: 0x00B0F6B0 (FUN_00B0F6B0, _adxstm_leave)
   *
   * What it does:
   * ADXSTM leave hook (no-op in this runtime variant).
   */
  void adxstm_leave()
  {
  }

  /**
   * Address: 0x00B0F670 (FUN_00B0F670, _ADXSTM_Create)
   *
   * What it does:
   * Calls ADXSTM core creator under enter/leave hook wrapper.
   */
  void* ADXSTM_Create(moho::SofdecSjSupplyHandle* const sourceJoinObject, const std::int32_t reserveSectors)
  {
    adxstm_enter();
    void* const created = adxstm_Create(sourceJoinObject, reserveSectors);
    adxstm_leave();
    return created;
  }

  /**
   * Address: 0x00B0F650 (FUN_00B0F650, _ADXSTM_Finish)
   *
   * What it does:
   * Decrements ADXSTM init counter and clears object pool when it reaches zero.
   */
  std::int32_t ADXSTM_Finish()
  {
    const std::int32_t result = --gAdxstmInitCount;
    if (gAdxstmInitCount == 0) {
      std::memset(gAdxstmObjectPool.data(), 0, sizeof(gAdxstmObjectPool));
      return 0;
    }
    return result;
  }

  [[nodiscard]] static std::int32_t adxstmf_CeilDivSigned2048(const std::int32_t byteCount)
  {
    std::int32_t laneMask = byteCount & static_cast<std::int32_t>(0x800007FFu);
    if (byteCount < 0) {
      --laneMask;
      laneMask |= static_cast<std::int32_t>(0xFFFFF800u);
      ++laneMask;
    }

    const std::int32_t roundCarry = (laneMask > 0) ? 1 : 0;
    std::int32_t signMask = byteCount >> 31;
    signMask &= 0x7FF;
    return ((byteCount + signMask) >> 11) + roundCarry;
  }

  [[nodiscard]] static AdxstmServerSlotView*
  ADXSTMF_FindFreeSlotInPartition(const std::int32_t slotOffset, const std::int32_t slotCount)
  {
    AdxstmServerSlotView* selectedSlot = nullptr;
    std::int32_t slotIndex = 0;

    if (slotCount > 0) {
      AdxstmServerSlotView* scanSlot = gAdxstmObjectPool.data() + slotOffset;
      do {
        selectedSlot = scanSlot;
        if (scanSlot->slotState == 0) {
          break;
        }
        ++slotIndex;
        ++scanSlot;
      } while (slotIndex < slotCount);
    }

    if (slotIndex == slotCount) {
      return nullptr;
    }
    return selectedSlot;
  }

  /**
   * Address: 0x00B0F6C0 (FUN_00B0F6C0, _adxstm_Create)
   *
   * What it does:
   * Routes ADXSTM creation to realtime or normal slot partition based on reserve
   * threshold (0x100 sectors).
   */
  void* adxstm_Create(moho::SofdecSjSupplyHandle* const sourceJoinObject, const std::int32_t reserveSectors)
  {
    if (reserveSectors >= 0x100) {
      return ADXSTMF_CreateCvfs(nullptr, 0, 0, sourceJoinObject);
    }
    return ADXSTMF_CreateCvfsRt(nullptr, 0, 0, sourceJoinObject);
  }

  /**
   * Address: 0x00B0F700 (FUN_00B0F700, _ADXSTMF_CreateCvfsRt)
   *
   * What it does:
   * Allocates one free ADXSTM slot from realtime partition and initializes it.
   */
  void* ADXSTMF_CreateCvfsRt(
    CvFsHandleView* const cvfsHandle,
    const std::int32_t baseOffset,
    const std::int32_t fileLengthBytes,
    moho::SofdecSjSupplyHandle* const sourceJoinObject
  )
  {
    AdxstmServerSlotView* const streamHandle = ADXSTMF_FindFreeSlotInPartition(adxstmf_rtim_ofst, adxstmf_rtim_num);
    if (streamHandle == nullptr) {
      return nullptr;
    }

    ADXSTMF_SetupHandleMember(streamHandle, cvfsHandle, baseOffset, fileLengthBytes, sourceJoinObject);
    streamHandle->mUnknown03 = 1;
    return streamHandle;
  }

  /**
   * Address: 0x00B0F760 (FUN_00B0F760, _ADXSTMF_SetupHandleMember)
   *
   * What it does:
   * Seeds one ADXSTM runtime slot with source/join state, file window lanes, and
   * default stream state under ADXCRS lock.
   */
  void ADXSTMF_SetupHandleMember(
    AdxstmServerSlotView* const streamHandle,
    CvFsHandleView* const cvfsHandle,
    const std::int32_t baseOffset,
    const std::int32_t fileLengthBytes,
    moho::SofdecSjSupplyHandle* const sourceJoinObject
  )
  {
    ADXCRS_Lock();

    streamHandle->cvfsHandle = cvfsHandle;
    streamHandle->streamStatus = 1;
    streamHandle->readFlag = 0;
    streamHandle->sourceJoinHandle = sourceJoinObject;
    streamHandle->baseOffset = baseOffset;
    streamHandle->fileLengthBytes = fileLengthBytes;
    streamHandle->requestedReadSectors = 0x200;
    streamHandle->currentSectorOffset = 0;
    streamHandle->streamSectorLimit = 0x000FFFFF;

    const std::int32_t fileLengthSectors = adxstmf_CeilDivSigned2048(fileLengthBytes);
    streamHandle->fileLengthSectors = fileLengthSectors;
    streamHandle->eosSector = fileLengthSectors;

    if (sourceJoinObject != nullptr) {
      const std::int32_t lane1Bytes = sourceJoinObject->dispatchTable->queryAvailableBytes(sourceJoinObject, 1);
      const std::int32_t totalBytes = sourceJoinObject->dispatchTable->queryAvailableBytes(sourceJoinObject, 0) + lane1Bytes;
      streamHandle->sourceTotalBytes = totalBytes;
      streamHandle->sourceReadableBytes = totalBytes;
      streamHandle->sourceWritableBytes = totalBytes;
    }

    streamHandle->pauseState = 0;
    streamHandle->slotState = 1;
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0F810 (FUN_00B0F810, _ADXSTMF_CreateCvfs)
   *
   * What it does:
   * Allocates one free ADXSTM slot from normal partition and initializes it.
   */
  void* ADXSTMF_CreateCvfs(
    CvFsHandleView* const cvfsHandle,
    const std::int32_t baseOffset,
    const std::int32_t fileLengthBytes,
    moho::SofdecSjSupplyHandle* const sourceJoinObject
  )
  {
    AdxstmServerSlotView* const streamHandle = ADXSTMF_FindFreeSlotInPartition(adxstmf_nrml_ofst, adxstmf_nrml_num);
    if (streamHandle == nullptr) {
      return nullptr;
    }

    ADXSTMF_SetupHandleMember(streamHandle, cvfsHandle, baseOffset, fileLengthBytes, sourceJoinObject);
    streamHandle->mUnknown03 = 0;
    return streamHandle;
  }

  /**
   * Address: 0x00B0F900 (FUN_00B0F900, _adxstm_lock)
   *
   * What it does:
   * ADXSTM compatibility thunk that enters the shared SVM lock.
   */
  void adxstm_lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B0F910 (FUN_00B0F910, _adxstm_unlock)
   *
   * What it does:
   * ADXSTM compatibility thunk that leaves the shared SVM lock.
   */
  void adxstm_unlock()
  {
    SVM_Unlock();
  }

  [[nodiscard]] AdxstmServerSlotView* AsAdxstmRuntimeView(void* const streamHandle)
  {
    return reinterpret_cast<AdxstmServerSlotView*>(streamHandle);
  }

  /**
   * Address: 0x00B100A0 (FUN_00B100A0, _adxstm_GetCurOfst)
   *
   * What it does:
   * Reads current stream offset via `ADXSTM_Tell` and stores it in caller lane.
   */
  std::int32_t adxstm_GetCurOfst(void* const streamHandle, std::int32_t* const outCurrentOffset)
  {
    *outCurrentOffset = ADXSTM_Tell(streamHandle);
    return 1;
  }

  /**
   * Address: 0x00B10090 (FUN_00B10090, _ADXSTM_GetCurOfst)
   *
   * What it does:
   * Export thunk that forwards current offset query into `adxstm_GetCurOfst`.
   */
  std::int32_t ADXSTM_GetCurOfst(void* const streamHandle, std::int32_t* const outCurrentOffset)
  {
    return adxstm_GetCurOfst(streamHandle, outCurrentOffset);
  }

  /**
   * Address: 0x00B100D0 (FUN_00B100D0, _adxstm_GetBufSize)
   *
   * What it does:
   * Writes ADXSTM writable/readable buffered byte lanes into caller outputs.
   */
  std::int32_t adxstm_GetBufSize(
    void* const streamHandle,
    std::int32_t* const outWritableBytes,
    std::int32_t* const outReadableBytes
  )
  {
    const AdxstmServerSlotView* const runtime = AsAdxstmRuntimeView(streamHandle);
    *outWritableBytes = runtime->sourceWritableBytes;
    *outReadableBytes = runtime->sourceReadableBytes;
    return 1;
  }

  /**
   * Address: 0x00B100C0 (FUN_00B100C0, _ADXSTM_GetBufSize)
   *
   * What it does:
   * Export thunk that forwards buffered size query into `adxstm_GetBufSize`.
   */
  std::int32_t ADXSTM_GetBufSize(
    void* const streamHandle,
    std::int32_t* const outWritableBytes,
    std::int32_t* const outReadableBytes
  )
  {
    return adxstm_GetBufSize(streamHandle, outWritableBytes, outReadableBytes);
  }

  /**
   * Address: 0x00B101F0 (FUN_00B101F0, _adxstm_SetPause)
   *
   * What it does:
   * Writes one pause-state byte lane in ADXSTM runtime and returns written byte.
   */
  std::int8_t adxstm_SetPause(void* const streamHandle, const std::int32_t paused)
  {
    const std::int8_t pauseByte = static_cast<std::int8_t>(paused);
    AsAdxstmRuntimeView(streamHandle)->pauseState = pauseByte;
    return pauseByte;
  }

  /**
   * Address: 0x00B101E0 (FUN_00B101E0, _ADXSTM_SetPause)
   *
   * What it does:
   * Forwards one pause-byte write into `adxstm_SetPause`.
   */
  std::int8_t ADXSTM_SetPause(void* const streamHandle, const std::int32_t paused)
  {
    return adxstm_SetPause(streamHandle, paused);
  }

  /**
   * Address: 0x00B10210 (FUN_00B10210, _adxstm_GetPause)
   *
   * What it does:
   * Returns sign-extended pause-state byte lane from ADXSTM runtime.
   */
  std::int32_t adxstm_GetPause(void* const streamHandle)
  {
    return static_cast<std::int32_t>(AsAdxstmRuntimeView(streamHandle)->pauseState);
  }

  /**
   * Address: 0x00B10200 (FUN_00B10200, _ADXSTM_GetPause)
   *
   * What it does:
   * Forwards one pause-byte read into `adxstm_GetPause`.
   */
  std::int32_t ADXSTM_GetPause(void* const streamHandle)
  {
    return adxstm_GetPause(streamHandle);
  }

  /**
   * Address: 0x00B10220 (FUN_00B10220, _ADXSTM_GetCvdfsStat)
   *
   * What it does:
   * Reads stream-attached CVFS status and stores it in caller output lane.
   */
  std::int32_t ADXSTM_GetCvdfsStat(void* const streamHandle, std::int32_t* const outStatus)
  {
    const std::int32_t status = cvFsGetStat(AsAdxstmRuntimeView(streamHandle)->cvfsHandle);
    *outStatus = status;
    return status;
  }

  /**
   * Address: 0x00B10240 (FUN_00B10240, _ADXSTM_GetFad)
   *
   * What it does:
   * Writes default FAD value `0` and reports success.
   */
  std::int32_t ADXSTM_GetFad(void* const streamHandle, std::int32_t* const outFad)
  {
    (void)streamHandle;
    *outFad = 0;
    return 1;
  }

  /**
   * Address: 0x00B10260 (FUN_00B10260, _adxstm_GetFsizeSct)
   *
   * What it does:
   * Converts file size in bytes into 2048-byte sector count with positive
   * remainder rounding.
   */
  std::int32_t adxstm_GetFsizeSct(char* const fileName, std::int32_t* const outSectorCount)
  {
    const std::int32_t fileSizeBytes = cvFsGetFileSize(fileName);
    std::int32_t sectorCount = fileSizeBytes / 2048;
    *outSectorCount = sectorCount;
    if ((fileSizeBytes % 2048) > 0) {
      ++sectorCount;
      *outSectorCount = sectorCount;
    }
    return 1;
  }

  /**
   * Address: 0x00B10250 (FUN_00B10250, _ADXSTM_GetFsizeSct)
   *
   * What it does:
   * Export thunk that forwards sector-size query into `adxstm_GetFsizeSct`.
   */
  std::int32_t ADXSTM_GetFsizeSct(char* const fileName, std::int32_t* const outSectorCount)
  {
    return adxstm_GetFsizeSct(fileName, outSectorCount);
  }

  /**
   * Address: 0x00B102B0 (FUN_00B102B0, _adxstm_GetFsizeByte)
   *
   * What it does:
   * Reads file size in bytes through CVFS and writes it to caller output lane.
   */
  std::int32_t adxstm_GetFsizeByte(char* const fileName, std::int32_t* const outFileSizeBytes)
  {
    *outFileSizeBytes = cvFsGetFileSize(fileName);
    return 1;
  }

  /**
   * Address: 0x00B102A0 (FUN_00B102A0, _ADXSTM_GetFsizeByte)
   *
   * What it does:
   * Export thunk that forwards file-size-in-bytes query into `adxstm_GetFsizeByte`.
   */
  std::int32_t ADXSTM_GetFsizeByte(char* const fileName, std::int32_t* const outFileSizeBytes)
  {
    return adxstm_GetFsizeByte(fileName, outFileSizeBytes);
  }

  /**
   * Address: 0x00B102E0 (FUN_00B102E0, _adxstm_SetSj)
   *
   * What it does:
   * Binds SJ supply handle to ADXSTM runtime and snapshots lane-0/1 source
   * byte totals under ADX critical-section lock.
   */
  std::int32_t adxstm_SetSj(void* const streamHandle, moho::SofdecSjSupplyHandle* const sourceJoinObject)
  {
    AdxstmServerSlotView* const runtime = AsAdxstmRuntimeView(streamHandle);
    runtime->sourceJoinHandle = sourceJoinObject;

    ADXCRS_Lock();
    const std::int32_t lane1Bytes = sourceJoinObject->dispatchTable->queryAvailableBytes(sourceJoinObject, 1);
    runtime->sourceTotalBytes = sourceJoinObject->dispatchTable->queryAvailableBytes(sourceJoinObject, 0) + lane1Bytes;
    ADXCRS_Unlock();

    const std::int32_t totalBytes = runtime->sourceTotalBytes;
    runtime->sourceReadableBytes = totalBytes;
    runtime->sourceWritableBytes = totalBytes;
    return totalBytes;
  }

  /**
   * Address: 0x00B102D0 (FUN_00B102D0, _ADXSTM_SetSj)
   *
   * What it does:
   * Export thunk that forwards SJ supply binding into `adxstm_SetSj`.
   */
  std::int32_t ADXSTM_SetSj(void* const streamHandle, void* const sourceJoinObject)
  {
    return adxstm_SetSj(streamHandle, reinterpret_cast<moho::SofdecSjSupplyHandle*>(sourceJoinObject));
  }

  /**
   * Address: 0x00B10330 (FUN_00B10330, _adxstm_SetRdSct)
   *
   * What it does:
   * Writes ADXSTM read-window lanes in bytes and sectors.
   */
  std::int32_t adxstm_SetRdSct(void* const streamHandle, const std::int32_t readSectors)
  {
    AdxstmServerSlotView* const runtime = AsAdxstmRuntimeView(streamHandle);
    runtime->fileLengthBytes = (readSectors << 11);
    runtime->fileLengthSectors = readSectors;
    return readSectors;
  }

  /**
   * Address: 0x00B10320 (FUN_00B10320, _ADXSTM_SetRdSct)
   *
   * What it does:
   * Export thunk that forwards read-window update into `adxstm_SetRdSct`.
   */
  std::int32_t ADXSTM_SetRdSct(void* const streamHandle, const std::int32_t readSectors)
  {
    return adxstm_SetRdSct(streamHandle, readSectors);
  }

  /**
   * Address: 0x00B10360 (FUN_00B10360, _adxstm_SetOfst)
   *
   * What it does:
   * Writes ADXSTM base-offset lane and seeks to current lane start.
   */
  std::int32_t adxstm_SetOfst(void* const streamHandle, const std::int32_t baseOffset)
  {
    AsAdxstmRuntimeView(streamHandle)->baseOffset = baseOffset;
    return ADXSTM_Seek(streamHandle, 0);
  }

  /**
   * Address: 0x00B10350 (FUN_00B10350, _ADXSTM_SetOfst)
   *
   * What it does:
   * Export thunk that forwards base-offset update into `adxstm_SetOfst`.
   */
  std::int32_t ADXSTM_SetOfst(void* const streamHandle, const std::int32_t baseOffset)
  {
    return adxstm_SetOfst(streamHandle, baseOffset);
  }

  /**
   * Address: 0x00B10440 (FUN_00B10440)
   *
   * What it does:
   * Waits until ADXF file-open polling lane clears by servicing ADXSTMF worker
   * execution under test-and-set guard.
   */
  void adxf_wait_until_file_open_internal(void* const streamHandle)
  {
    AdxstmServerSlotView* const runtime = AsAdxstmRuntimeView(streamHandle);
    if (runtime->fileName == nullptr || runtime->cvfsHandle != nullptr) {
      return;
    }

    runtime->waitForFileOpen = 1;
    do {
      if (adxstm_test_and_set(&adxstmf_execsvr_flg) == TRUE) {
        ADXSTMF_ExecHndl(streamHandle);
        adxstmf_execsvr_flg = 0;
      }
    } while (runtime->waitForFileOpen != 0);
  }

  /**
   * Address: 0x00B10430 (FUN_00B10430, _adxf_wait_until_file_open)
   *
   * What it does:
   * Thin ADXF thunk that forwards to internal file-open wait loop.
   */
  void adxf_wait_until_file_open(void* const streamHandle)
  {
    adxf_wait_until_file_open_internal(streamHandle);
  }

  /**
   * Address: 0x00B10420 (FUN_00B10420, _adxstm_GetReadFlg)
   *
   * What it does:
   * Returns sign-extended ADXSTM read-flag byte.
   */
  std::int32_t adxstm_GetReadFlg(void* const streamHandle)
  {
    return static_cast<std::int32_t>(AsAdxstmRuntimeView(streamHandle)->readFlag);
  }

  /**
   * Address: 0x00B10410 (FUN_00B10410, _ADXSTM_GetReadFlg)
   *
   * What it does:
   * Export thunk that forwards read-flag query into `adxstm_GetReadFlg`.
   */
  std::int32_t ADXSTM_GetReadFlg(void* const streamHandle)
  {
    return adxstm_GetReadFlg(streamHandle);
  }

  /**
   * Address: 0x00B10400 (FUN_00B10400, _adxt_GetNumErr)
   *
   * What it does:
   * Returns stream-side ADXSTM error-count lane for one ADXT runtime.
   */
  std::int32_t adxt_GetNumErr(void* const adxtRuntime)
  {
    const auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    return AsAdxstmRuntimeView(runtime->streamHandle)->streamErrorCount;
  }

  /**
   * Address: 0x00B103E0 (FUN_00B103E0, _ADXT_GetNumErr)
   *
   * What it does:
   * Lock-wrapped ADXT error-count query.
   */
  std::int32_t ADXT_GetNumErr(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    const std::int32_t errorCount = adxt_GetNumErr(adxtRuntime);
    ADXCRS_Leave();
    return errorCount;
  }

  /**
   * Address: 0x00B103D0 (FUN_00B103D0, _adxt_GetNumRetry)
   *
   * What it does:
   * Returns global ADXSTM filesystem retry-count lane.
   */
  std::int32_t adxt_GetNumRetry()
  {
    return adxstmf_num_rtry;
  }

  /**
   * Address: 0x00B103B0 (FUN_00B103B0, _ADXT_GetNumRetry)
   *
   * What it does:
   * Lock-wrapped ADXT retry-count query.
   */
  std::int32_t ADXT_GetNumRetry()
  {
    ADXCRS_Enter();
    const std::int32_t retryCount = adxt_GetNumRetry();
    ADXCRS_Leave();
    return retryCount;
  }

  /**
   * Address: 0x00B103A0 (FUN_00B103A0, _adxt_SetNumRetry)
   *
   * What it does:
   * Stores global ADXSTM filesystem retry-count lane and returns written value.
   */
  std::int32_t adxt_SetNumRetry(const std::int32_t retryCount)
  {
    adxstmf_num_rtry = retryCount;
    return retryCount;
  }

  /**
   * Address: 0x00B10380 (FUN_00B10380, _ADXT_SetNumRetry)
   *
   * What it does:
   * Lock-wrapped ADXT retry-count update.
   */
  void ADXT_SetNumRetry(const std::int32_t retryCount)
  {
    ADXCRS_Enter();
    adxt_SetNumRetry(retryCount);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B10100 (FUN_00B10100, _adxstm_GetSj)
   *
   * What it does:
   * Returns current ADXSTM source-SJ handle lane as 32-bit runtime address.
   */
  std::int32_t adxstm_GetSj(void* const streamHandle)
  {
    return SjPointerToAddress(AsAdxstmRuntimeView(streamHandle)->sourceJoinHandle);
  }

  /**
   * Address: 0x00B100F0 (FUN_00B100F0, _ADXSTM_GetSj)
   *
   * What it does:
   * Export thunk that forwards source-SJ lane query into `adxstm_GetSj`.
   */
  std::int32_t ADXSTM_GetSj(void* const streamHandle)
  {
    return adxstm_GetSj(streamHandle);
  }

  /**
   * Address: 0x00B10120 (FUN_00B10120, _adxstm_SetBufSize)
   *
   * What it does:
   * Writes ADXSTM buffer-size lanes (`+0x1C` and `+0x18`) and returns success.
   */
  std::int32_t adxstm_SetBufSize(
    void* const streamHandle,
    const std::int32_t minBufferSectors,
    const std::int32_t maxBufferSectors
  )
  {
    AdxstmServerSlotView* const runtime = AsAdxstmRuntimeView(streamHandle);
    runtime->sourceWritableBytes = minBufferSectors;
    runtime->sourceReadableBytes = maxBufferSectors;
    return 1;
  }

  /**
   * Address: 0x00B10110 (FUN_00B10110, _ADXSTM_SetBufSize)
   *
   * What it does:
   * Export thunk that forwards buffer-size lane update into `adxstm_SetBufSize`.
   */
  std::int32_t ADXSTM_SetBufSize(
    void* const streamHandle,
    const std::int32_t minBufferSectors,
    const std::int32_t maxBufferSectors
  )
  {
    return adxstm_SetBufSize(streamHandle, minBufferSectors, maxBufferSectors);
  }

  /**
   * Address: 0x00B10150 (FUN_00B10150, _adxstm_SetReqRdSize)
   *
   * What it does:
   * Writes requested-read sector lane at `+0x2C` and returns success.
   */
  std::int32_t adxstm_SetReqRdSize(void* const streamHandle, const std::int32_t requestedSectors)
  {
    AsAdxstmRuntimeView(streamHandle)->requestedReadSectors = requestedSectors;
    return 1;
  }

  /**
   * Address: 0x00B10140 (FUN_00B10140, _ADXSTM_SetReqRdSize)
   *
   * What it does:
   * Export thunk that forwards requested-read lane update into
   * `adxstm_SetReqRdSize`.
   */
  std::int32_t ADXSTM_SetReqRdSize(void* const streamHandle, const std::int32_t requestedSectors)
  {
    return adxstm_SetReqRdSize(streamHandle, requestedSectors);
  }

  /**
   * Address: 0x00B10190 (FUN_00B10190, _adxstm_GetFileLen)
   *
   * What it does:
   * Returns ADXSTM file-length byte lane.
   */
  std::int32_t adxstm_GetFileLen(void* const streamHandle)
  {
    return AsAdxstmRuntimeView(streamHandle)->fileLengthBytes;
  }

  /**
   * Address: 0x00B10180 (FUN_00B10180, _ADXSTM_GetFileLen)
   *
   * What it does:
   * Export thunk that forwards file-length byte query into `adxstm_GetFileLen`.
   */
  std::int32_t ADXSTM_GetFileLen(void* const streamHandle)
  {
    return adxstm_GetFileLen(streamHandle);
  }

  /**
   * Address: 0x00B101B0 (FUN_00B101B0, _adxstm_GetFileLen64)
   *
   * What it does:
   * Returns ADXSTM secondary file-length lane at offset `+0x14`.
   */
  std::int32_t adxstm_GetFileLen64(void* const streamHandle)
  {
    return AsAdxstmRuntimeView(streamHandle)->fileLengthSectors;
  }

  /**
   * Address: 0x00B101A0 (FUN_00B101A0, _ADXSTM_GetFileLen64)
   *
   * What it does:
   * Export thunk that forwards secondary file-length query into
   * `adxstm_GetFileLen64`.
   */
  std::int32_t ADXSTM_GetFileLen64(void* const streamHandle)
  {
    return adxstm_GetFileLen64(streamHandle);
  }

  /**
   * Address: 0x00B101D0 (FUN_00B101D0, _adxstm_GetFileSize)
   *
   * What it does:
   * Thin ADXSTM thunk that forwards file-size query to CVFS.
   */
  std::int32_t adxstm_GetFileSize(char* const fileName)
  {
    return cvFsGetFileSize(fileName);
  }

  /**
   * Address: 0x00B101C0 (FUN_00B101C0, _ADXSTM_GetFileSize)
   *
   * What it does:
   * Export thunk that forwards file-size query into `adxstm_GetFileSize`.
   */
  std::int32_t ADXSTM_GetFileSize(char* const fileName)
  {
    return adxstm_GetFileSize(fileName);
  }

  /**
   * Address: 0x00B0F9E0 (FUN_00B0F9E0)
   *
   * What it does:
   * Returns sign-extended ADXSTM filesystem service-active byte lane.
   */
  [[maybe_unused]] std::int32_t adxstm_GetFilesystemServiceActive(void* const streamHandle)
  {
    return static_cast<std::int32_t>(AsAdxstmRuntimeView(streamHandle)->filesystemServiceActive);
  }

  /**
   * Address: 0x00B0FA00 (FUN_00B0FA00, _adxstm_GetStat)
   *
   * What it does:
   * Returns sign-extended ADXSTM stream-status byte lane.
   */
  std::int32_t adxstm_GetStat(void* const streamHandle)
  {
    return static_cast<std::int32_t>(AsAdxstmRuntimeView(streamHandle)->streamStatus);
  }

  /**
   * Address: 0x00B0F9F0 (FUN_00B0F9F0, _ADXSTM_GetStat)
   *
   * What it does:
   * Export thunk that forwards stream-status query into `adxstm_GetStat`.
   */
  std::int32_t ADXSTM_GetStat(void* const streamHandle)
  {
    return adxstm_GetStat(streamHandle);
  }

  /**
   * Address: 0x00B0FA20 (FUN_00B0FA20, _adxstm_Seek)
   *
   * What it does:
   * Writes current ADXSTM sector offset and clamps it to total sector range.
   */
  std::int32_t adxstm_Seek(void* const streamHandle, const std::int32_t sectorOffset)
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    runtime->currentSectorOffset = sectorOffset;
    if (sectorOffset > runtime->fileLengthSectors) {
      runtime->currentSectorOffset = runtime->fileLengthSectors;
    }
    return runtime->currentSectorOffset;
  }

  /**
   * Address: 0x00B0FA10 (FUN_00B0FA10, _ADXSTM_Seek)
   *
   * What it does:
   * Export thunk that forwards sector-offset update into `adxstm_Seek`.
   */
  std::int32_t ADXSTM_Seek(void* const streamHandle, const std::int32_t sectorOffset)
  {
    return adxstm_Seek(streamHandle, sectorOffset);
  }

  /**
   * Address: 0x00B0FA50 (FUN_00B0FA50, _adxstm_Tell)
   *
   * What it does:
   * Returns current sector offset when CVFS handle is open, otherwise `0`.
   */
  std::int32_t adxstm_Tell(void* const streamHandle)
  {
    const auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    return (runtime->cvfsHandle != nullptr) ? runtime->currentSectorOffset : 0;
  }

  /**
   * Address: 0x00B0FA40 (FUN_00B0FA40, _ADXSTM_Tell)
   *
   * What it does:
   * Export thunk that forwards sector-offset query into `adxstm_Tell`.
   */
  std::int32_t ADXSTM_Tell(void* const streamHandle)
  {
    return adxstm_Tell(streamHandle);
  }

  /**
   * Address: 0x00B0FA70 (FUN_00B0FA70, _adxstm_start_sub)
   *
   * What it does:
   * Resets read-transfer lanes and transitions ADXSTM state for stream start.
   */
  AdxstmServerSlotView* adxstm_start_sub(void* const streamHandle)
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    runtime->sourceStreamedBytes = 0;
    runtime->streamErrorCount = 0;
    runtime->streamStatus = (runtime->pendingReadSectors != 0) ? 2 : 3;
    runtime->readFlag = 0;
    runtime->pendingChunk.bufferAddress = 0;
    runtime->pendingChunk.byteCount = 0;
    runtime->clearStopRequested = 1;
    return runtime;
  }

  /**
   * Address: 0x00B0FAC0 (FUN_00B0FAC0, _adxstm_Start)
   *
   * What it does:
   * Starts ADXSTM stream under ADXCRS lock with unbounded sector limit lane.
   */
  std::int32_t adxstm_Start(void* const streamHandle)
  {
    ADXCRS_Lock();
    adxstm_start_sub(streamHandle);
    AsAdxstmRuntimeView(streamHandle)->streamSectorLimit = 0x000FFFFF;
    ADXCRS_Unlock();
    return 1;
  }

  /**
   * Address: 0x00B0FAB0 (FUN_00B0FAB0, _ADXSTM_Start)
   *
   * What it does:
   * Export thunk that forwards default-limit start into `adxstm_Start`.
   */
  std::int32_t ADXSTM_Start(void* const streamHandle)
  {
    return adxstm_Start(streamHandle);
  }

  /**
   * Address: 0x00B0FB00 (FUN_00B0FB00, _adxstm_Start2)
   *
   * What it does:
   * Starts ADXSTM stream under ADXCRS lock with caller sector limit lane.
   */
  std::int32_t adxstm_Start2(void* const streamHandle, const std::int32_t sectorCount)
  {
    ADXCRS_Lock();
    adxstm_start_sub(streamHandle);
    AsAdxstmRuntimeView(streamHandle)->streamSectorLimit = sectorCount;
    ADXCRS_Unlock();
    return 1;
  }

  /**
   * Address: 0x00B0FAF0 (FUN_00B0FAF0, _ADXSTM_Start2)
   *
   * What it does:
   * Export thunk that forwards caller-limit start into `adxstm_Start2`.
   */
  std::int32_t ADXSTM_Start2(void* const streamHandle, const std::int32_t sectorCount)
  {
    return adxstm_Start2(streamHandle, sectorCount);
  }

  /**
   * Address: 0x00B0FB40 (FUN_00B0FB40, _adxstm_StopNw)
   *
   * What it does:
   * Applies non-blocking ADXSTM stop transition under SVM lock.
   */
  void adxstm_StopNw(void* const streamHandle)
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    adxstm_lock();
    if (runtime->streamStatus == 2 && runtime->readFlag == 1) {
      const std::uint8_t clearStopRequested = runtime->clearStopRequested;
      runtime->stopAfterRead = 1;
      if (clearStopRequested == 1) {
        runtime->clearStopRequested = 0;
      }
    } else {
      runtime->streamStatus = 1;
    }
    adxstm_unlock();
  }

  /**
   * Address: 0x00B0FB30 (FUN_00B0FB30, _ADXSTM_StopNw)
   *
   * What it does:
   * Export thunk that forwards non-blocking stop transition.
   */
  void ADXSTM_StopNw(void* const streamHandle)
  {
    adxstm_StopNw(streamHandle);
  }

  /**
   * Address: 0x00B0FB90 (FUN_00B0FB90, _adxstm_Stop)
   *
   * What it does:
   * Stops ADXSTM stream and pumps filesystem service until stop settles.
   */
  void adxstm_Stop(void* const streamHandle)
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    ADXSTM_StopNw(streamHandle);
    do {
      do {
        ADXT_ExecFsSvr();
      } while (runtime->streamStatus != 1);
    } while (runtime->filesystemServiceActive != 0);
  }

  /**
   * Address: 0x00B0FB80 (FUN_00B0FB80, _ADXSTM_Stop)
   *
   * What it does:
   * Export thunk that forwards stop/drain workflow into `adxstm_Stop`.
   */
  void ADXSTM_Stop(void* const streamHandle)
  {
    adxstm_Stop(streamHandle);
  }

  /**
   * Address: 0x00B0FBD0 (FUN_00B0FBD0, _adxstm_EntryEosFunc)
   *
   * What it does:
   * Writes ADXSTM EOS callback lanes and returns stream handle value.
   */
  std::int32_t adxstm_EntryEosFunc(
    void* const streamHandle,
    const std::int32_t callbackAddress,
    const std::int32_t callbackContext
  )
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    runtime->endOfStreamCallback =
      reinterpret_cast<AdxstmEndOfStreamCallback>(static_cast<std::uintptr_t>(callbackAddress));
    runtime->endOfStreamCallbackContext = callbackContext;
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(streamHandle));
  }

  /**
   * Address: 0x00B0FBC0 (FUN_00B0FBC0, _ADXSTM_EntryEosFunc)
   *
   * What it does:
   * Export thunk that forwards EOS callback registration.
   */
  std::int32_t
  ADXSTM_EntryEosFunc(const std::int32_t streamHandleAddress, const std::int32_t callbackAddress, const std::int32_t callbackContext)
  {
    return adxstm_EntryEosFunc(SjAddressToPointer(streamHandleAddress), callbackAddress, callbackContext);
  }

  /**
   * Address: 0x00B0FC00 (FUN_00B0FC00, _adxstm_SetEos)
   *
   * What it does:
   * Writes ADXSTM completion-sector lane; negative input maps to stream tail.
   */
  std::int32_t adxstm_SetEos(void* const streamHandle, const std::int32_t eosSector)
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    if (eosSector < 0) {
      runtime->eosSector = runtime->pendingReadSectors;
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(streamHandle));
    }

    runtime->eosSector = eosSector;
    return eosSector;
  }

  /**
   * Address: 0x00B0FBF0 (FUN_00B0FBF0, _ADXSTM_SetEos)
   *
   * What it does:
   * Export thunk that forwards completion-sector update into `adxstm_SetEos`.
   */
  std::int32_t ADXSTM_SetEos(void* const streamHandle, const std::int32_t eosSector)
  {
    return adxstm_SetEos(streamHandle, eosSector);
  }

  constexpr std::int32_t kAdxstmFileLengthUnknownBytes = 0x7FFFF800;
  constexpr std::int32_t kAdxstmStreamSectorLimitUnbounded = 0x000FFFFF;
  constexpr char kAdxstmStatExecOpenErrorPrefix[] = "E02110501 adxstmf_stat_exec: can't open ";

  [[nodiscard]] AdxstmServerSlotView* AsAdxstmServerSlot(void* const streamHandle)
  {
    return static_cast<AdxstmServerSlotView*>(streamHandle);
  }

  void adxstmf_stat_exec(AdxstmServerSlotView* runtime)
  {
    moho::SofdecSjSupplyHandle* const sourceHandle = runtime->sourceJoinHandle;
    const std::int32_t cvfsStatus = cvFsGetStat(runtime->cvfsHandle);

    adxstm_lock();
    if (runtime->readFlag == 1) {
      if (cvfsStatus == 1) {
        runtime->readFlag = 0;
        adxstm_unlock();

        const std::int32_t readByteCount = runtime->pendingReadSectors << 11;
        SjChunkRange submittedChunk{};
        SjChunkRange trailingChunk{};
        SJ_SplitChunk(&runtime->pendingChunk, readByteCount, &submittedChunk, &trailingChunk);
        sourceHandle->dispatchTable->submitChunk(sourceHandle, 1, &submittedChunk);
        sourceHandle->dispatchTable->putChunk(sourceHandle, 0, &trailingChunk);

        runtime->currentSectorOffset += runtime->pendingReadSectors;
        runtime->sourceStreamedBytes += readByteCount;
        runtime->pendingChunk.bufferAddress = 0;
        runtime->pendingChunk.byteCount = 0;

        if (runtime->currentSectorOffset == runtime->eosSector) {
          if (runtime->endOfStreamCallback != nullptr) {
            runtime->endOfStreamCallback(runtime->endOfStreamCallbackContext);
          }
        }

        if (
          runtime->currentSectorOffset >= runtime->fileLengthSectors
          || (
            (runtime->sourceStreamedBytes >> 11) >= runtime->streamSectorLimit
            && runtime->streamSectorLimit < kAdxstmStreamSectorLimitUnbounded
          )
        ) {
          runtime->streamStatus = 3;
        }

        runtime->streamErrorCount = 0;
        return;
      }

      if (cvfsStatus != 3) {
        adxstm_unlock();
        return;
      }

      runtime->readFlag = 0;
      adxstm_unlock();
      sourceHandle->dispatchTable->putChunk(sourceHandle, 0, &runtime->pendingChunk);
      runtime->pendingChunk.bufferAddress = 0;
      runtime->pendingChunk.byteCount = 0;

      if (adxstmf_num_rtry < 0 || runtime->streamErrorCount <= adxstmf_num_rtry) {
        if (runtime->streamErrorCount != 0x7FFFFFFF) {
          ++runtime->streamErrorCount;
        }
      } else {
        runtime->streamStatus = 4;
      }
      return;
    }

    runtime->readFlag = 1;
    runtime->pendingChunk.bufferAddress = 0;
    runtime->pendingChunk.byteCount = 0;
    adxstm_unlock();

    if (runtime->pauseState == 1 || runtime->stopAfterRead == 1) {
      runtime->readFlag = 0;
      return;
    }

    if (runtime->fileLengthSectors == 0) {
      runtime->pendingReadSectors = 0;
      runtime->streamStatus = 3;
      runtime->readFlag = 0;
      return;
    }

    if (sourceHandle == nullptr || sourceHandle->dispatchTable == nullptr) {
      runtime->readFlag = 0;
      ++adxstmf_invalid_source_handle_count;
      return;
    }

    const std::int32_t sourceBytesInUse =
      runtime->sourceTotalBytes - sourceHandle->dispatchTable->queryAvailableBytes(sourceHandle, 0);
    if (sourceBytesInUse >= runtime->sourceWritableBytes) {
      runtime->readFlag = 0;
      return;
    }

    SjChunkRange sourceChunk{};
    sourceHandle->dispatchTable->getChunk(sourceHandle, 0, runtime->sourceReadableBytes, &sourceChunk);

    const std::int32_t consumedSectors = runtime->currentSectorOffset;
    std::int32_t requestedSectors = sourceChunk.byteCount / 2048;
    const std::int32_t sectorsUntilCompletion = runtime->eosSector - consumedSectors;
    if (requestedSectors >= sectorsUntilCompletion) {
      requestedSectors = sectorsUntilCompletion;
    }

    const std::int32_t sectorsUntilTotal = runtime->fileLengthSectors - consumedSectors;
    if (requestedSectors >= sectorsUntilTotal) {
      requestedSectors = sectorsUntilTotal;
    }

    if (requestedSectors >= runtime->requestedReadSectors) {
      requestedSectors = runtime->requestedReadSectors;
    }

    cvFsSeek(runtime->cvfsHandle, consumedSectors + runtime->baseOffset, 0);
    if (runtime->streamSectorLimit != kAdxstmStreamSectorLimitUnbounded) {
      const std::int32_t sectorsUntilStreamLimit = runtime->streamSectorLimit - (runtime->sourceStreamedBytes / 2048);
      if (requestedSectors >= sectorsUntilStreamLimit) {
        requestedSectors = sectorsUntilStreamLimit;
      }
    }

    runtime->pendingReadSectors = cvFsReqRd(runtime->cvfsHandle, requestedSectors, sourceChunk.bufferAddress);
    runtime->pendingChunk = sourceChunk;
    if (runtime->pendingReadSectors > 0) {
      return;
    }

    sourceHandle->dispatchTable->putChunk(sourceHandle, 0, &runtime->pendingChunk);
    runtime->pendingChunk.bufferAddress = 0;
    runtime->pendingChunk.byteCount = 0;
    runtime->readFlag = 0;

    if (cvFsGetStat(runtime->cvfsHandle) == 3) {
      if (adxstmf_num_rtry < 0 || runtime->streamErrorCount <= adxstmf_num_rtry) {
        if (runtime->streamErrorCount != 0x7FFFFFFF) {
          ++runtime->streamErrorCount;
        }
      } else {
        runtime->streamStatus = 4;
      }
    }
  }

  /**
   * Address: 0x00B0FEC0 (FUN_00B0FEC0, _ADXSTMF_ExecHndl)
   *
   * What it does:
   * Drives one ADXSTM file-handle service slot through open/close/update
   * transitions and dispatches read-state execution.
   */
  std::int32_t ADXSTMF_ExecHndl(void* const streamHandle)
  {
    AdxstmServerSlotView* const runtime = AsAdxstmServerSlot(streamHandle);

    if (runtime->readFlag == 0) {
      if (runtime->stopAfterRead == 1) {
        const std::uint8_t clearStopRequested = runtime->clearStopRequested;
        runtime->stopAfterRead = 0;
        if (clearStopRequested == 0) {
          runtime->streamStatus = 1;
        }
      }

      if (runtime->releaseFilePending == 1) {
        if (runtime->cvfsHandle != nullptr) {
          CvFsHandleView* const closingHandle = runtime->cvfsHandle;
          runtime->cvfsHandle = nullptr;
          cvFsClose(closingHandle);
        }
        runtime->releaseFilePending = 0;
        runtime->filesystemServiceActive = 0;
      }

      adxstm_lock();
      if (runtime->waitForFileOpen == 1) {
        runtime->filesystemServiceActive = 1;
        adxstm_unlock();

        if (runtime->cvfsHandle == nullptr) {
          runtime->cvfsHandle = cvFsOpen(runtime->fileName, runtime->fileOpenMode, 0);
          if (runtime->cvfsHandle == nullptr) {
            ADXERR_CallErrFunc2_(kAdxstmStatExecOpenErrorPrefix, runtime->fileName);
            runtime->streamStatus = 4;
            runtime->filesystemServiceActive = 0;
            runtime->waitForFileOpen = 0;
            return 0;
          }

          cvFsSeek(runtime->cvfsHandle, 0, 2);
          const std::int32_t sectorCount = cvFsTell(runtime->cvfsHandle);
          std::int32_t fileSizeBytes = sectorCount << 11;
          if (runtime->fileOpenMode == 0) {
            fileSizeBytes = cvFsGetFileSize(runtime->fileName);
          }
          cvFsSeek(runtime->cvfsHandle, 0, 0);

          if (runtime->fileLengthBytes == kAdxstmFileLengthUnknownBytes) {
            runtime->fileLengthBytes = fileSizeBytes;
            runtime->fileLengthSectors = sectorCount;
          }

          if (runtime->baseOffset > sectorCount) {
            runtime->baseOffset = sectorCount;
          }

          if ((runtime->baseOffset + runtime->fileLengthSectors) > sectorCount) {
            runtime->fileLengthSectors = sectorCount - runtime->baseOffset;
            runtime->fileLengthBytes = runtime->fileLengthSectors << 11;
          }

          ADXSTM_Seek(runtime, 0);
          runtime->waitForFileOpen = 0;
        }
      } else {
        adxstm_unlock();
      }

      if (runtime->clearStopRequested == 1) {
        runtime->clearStopRequested = 0;
      }
    }

    if (runtime->streamStatus == 2 && runtime->filesystemServiceActive == 1) {
      adxstmf_stat_exec(runtime);
    }
    return 0;
  }

  /**
   * Address: 0x00B0F8C0 (FUN_00B0F8C0, _adxstm_BindFileNw)
   *
   * What it does:
   * Stores non-blocking bind-file lanes (start/range/file/open-mode) and arms
   * wait-for-open byte under ADXSTM lock.
   */
  void adxstm_BindFileNw(
    void* const streamHandle,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    adxstm_lock();
    runtime->baseOffset = rangeStart;
    runtime->fileLengthSectors = rangeEnd;
    runtime->waitForFileOpen = 1;
    runtime->fileLengthBytes = (rangeEnd << 11);
    runtime->fileName = const_cast<char*>(fileName);
    runtime->fileOpenMode = startOffset;
    adxstm_unlock();
  }

  /**
   * Address: 0x00B0F8B0 (FUN_00B0F8B0, _ADXSTM_BindFileNw)
   *
   * What it does:
   * Export thunk that forwards non-blocking bind-file setup.
   */
  void ADXSTM_BindFileNw(
    void* const streamHandle,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    adxstm_BindFileNw(streamHandle, fileName, startOffset, rangeStart, rangeEnd);
  }

  /**
   * Address: 0x00B0F880 (FUN_00B0F880, _adxstm_Destroy)
   *
   * What it does:
   * Stops and releases one ADXSTM stream, then clears the full 0x60-byte slot.
   */
  std::int32_t adxstm_Destroy(void* const streamHandle)
  {
    auto* const runtime = AsAdxstmRuntimeView(streamHandle);
    if (runtime == nullptr) {
      return 0;
    }

    ADXSTM_Stop(streamHandle);
    ADXSTM_ReleaseFile(streamHandle);
    runtime->slotState = 0;
    std::memset(runtime, 0, sizeof(AdxstmServerSlotView));
    return 0;
  }

  /**
   * Address: 0x00B0F870 (FUN_00B0F870, _ADXSTM_Destroy)
   *
   * What it does:
   * Export thunk that forwards ADXSTM teardown into `adxstm_Destroy`.
   */
  std::int32_t ADXSTM_Destroy(void* const streamHandle)
  {
    return adxstm_Destroy(streamHandle);
  }

  /**
   * Address: 0x00B0F930 (FUN_00B0F930, _adxstm_BindFile)
   *
   * What it does:
   * Binds file lanes and blocks by pumping filesystem server ticks until
   * waiting-for-open lane clears.
   */
  std::int8_t adxstm_BindFile(
    void* const streamHandle,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    ADXSTM_BindFileNw(streamHandle, fileName, startOffset, rangeStart, rangeEnd);

    AdxstmServerSlotView* const runtime = AsAdxstmServerSlot(streamHandle);
    do {
      ADXT_ExecFsSvr();
    } while (runtime->waitForFileOpen != 0);

    return static_cast<std::int8_t>(runtime->waitForFileOpen);
  }

  /**
   * Address: 0x00B0F920 (FUN_00B0F920, _ADXSTM_BindFile)
   *
   * What it does:
   * Export thunk that forwards blocking file-bind workflow into `adxstm_BindFile`.
   */
  std::int8_t ADXSTM_BindFile(
    void* const streamHandle,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    return adxstm_BindFile(streamHandle, fileName, startOffset, rangeStart, rangeEnd);
  }

  /**
   * Address: 0x00B0F970 (FUN_00B0F970, _adxstm_ReleaseFileNw)
   *
   * What it does:
   * Stops one ADXSTM stream without waiting and requests deferred close lane when
   * file-open transition is active.
   */
  void adxstm_ReleaseFileNw(void* const streamHandle)
  {
    ADXSTM_StopNw(streamHandle);

    AdxstmServerSlotView* const runtime = AsAdxstmServerSlot(streamHandle);
    adxstm_lock();
    if (runtime->filesystemServiceActive == 1) {
      runtime->releaseFilePending = 1;
    }
    runtime->waitForFileOpen = 0;
    adxstm_unlock();
  }

  /**
   * Address: 0x00B0F960 (FUN_00B0F960, _ADXSTM_ReleaseFileNw)
   *
   * What it does:
   * Export thunk that forwards non-blocking release-state transition.
   */
  void ADXSTM_ReleaseFileNw(void* const streamHandle)
  {
    adxstm_ReleaseFileNw(streamHandle);
  }

  /**
   * Address: 0x00B0F9B0 (FUN_00B0F9B0, _adxstm_ReleaseFile)
   *
   * What it does:
   * Stops one ADXSTM stream, releases file lanes, and drains service ticks until
   * open/close transition clears.
   */
  void adxstm_ReleaseFile(void* const streamHandle)
  {
    auto* const runtime = AsAdxstmServerSlot(streamHandle);
    ADXSTM_Stop(streamHandle);
    ADXSTM_ReleaseFileNw(streamHandle);
    while (runtime->filesystemServiceActive != 0) {
      ADXT_ExecFsSvr();
    }
  }

  /**
   * Address: 0x00B0F9A0 (FUN_00B0F9A0, _ADXSTM_ReleaseFile)
   *
   * What it does:
   * Export thunk that forwards release workflow into `adxstm_ReleaseFile`.
   */
  void ADXSTM_ReleaseFile(void* const streamHandle)
  {
    adxstm_ReleaseFile(streamHandle);
  }

  /**
   * Address: 0x00B10170 (FUN_00B10170, _ADXSTM_EntryErrFunc)
   *
   * What it does:
   * Compatibility no-op entrypoint for ADXSTM error callback lane wiring.
   */
  void ADXSTM_EntryErrFunc()
  {
  }

  /**
   * Address: 0x00B10020 (FUN_00B10020, _adxstm_ExecServer)
   *
   * What it does:
   * Runs ADXSTM filesystem service over all active 0x60-byte slots when the
   * global service guard can be acquired.
   */
  std::int32_t adxstm_ExecServer()
  {
    std::int32_t result = static_cast<std::int32_t>(adxstm_test_and_set(&adxstmf_execsvr_flg));
    if (result == 0) {
      return result;
    }

    for (AdxstmServerSlotView& slot : gAdxstmObjectPool) {
      if (slot.slotState == 1) {
        result = ADXSTMF_ExecHndl(&slot);
      }
    }

    adxstmf_execsvr_flg = 0;
    return result;
  }

  /**
   * Address: 0x00B10010 (FUN_00B10010, _ADXSTM_ExecServer)
   *
   * What it does:
   * Export thunk that forwards ADXSTM filesystem service dispatch.
   */
  void ADXSTM_ExecServer()
  {
    (void)adxstm_ExecServer();
  }

  /**
   * Address: 0x00B10080 (FUN_00B10080, _adxstm_ExecFsSvr)
   *
   * What it does:
   * Thin ADXSTM thunk that forwards one filesystem server pump into CVFS.
   */
  void adxstm_ExecFsSvr()
  {
    cvFsExecServer();
  }

  /**
   * Address: 0x00B10070 (FUN_00B10070, _ADXSTM_ExecFsSvr)
   *
   * What it does:
   * Export thunk that forwards ADXSTM filesystem pump to `adxstm_ExecFsSvr`.
   */
  void ADXSTM_ExecFsSvr()
  {
    adxstm_ExecFsSvr();
  }

  /**
   * Address: 0x00B13640 (FUN_00B13640, _mfCrsLock)
   *
   * What it does:
   * Media-file runtime lock thunk that enters the shared SVM lock.
   */
  void mfCrsLock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B13650 (FUN_00B13650, _mfCrsUnlock)
   *
   * What it does:
   * Media-file runtime unlock thunk that leaves the shared SVM lock.
   */
  void mfCrsUnlock()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B0C230 (FUN_00B0C230, _svm_unlock)
   *
   * What it does:
   * Invokes registered SVM unlock callback, decrements nested lock level,
   * validates final unlock type, and clears lock-type lane when fully released.
   */
  void svm_unlock(const std::int32_t lockType)
  {
    if (gSvmUnlockCallback.fn == nullptr) {
      return;
    }

    if (--gSvmLockLevel == 0) {
      if (gSvmLockingType != lockType) {
        SVM_CallErr(kSvmErrUnlockTypeMismatch, gSvmLockingType, lockType);
      }
      gSvmLockingType = 0;
    }

    gSvmUnlockCallback.fn(gSvmUnlockCallback.callbackObject);
  }

  /**
   * Address: 0x00B0C330 (FUN_00B0C330, _SVM_GetLockType)
   *
   * What it does:
   * Returns current SVM lock-domain type lane.
   */
  [[nodiscard]] std::int32_t SVM_GetLockType()
  {
    return gSvmLockingType;
  }

  /**
   * Address: 0x00B0C340 (FUN_00B0C340, _SVM_CallErr)
   *
   * What it does:
   * Formats one SVM error message and dispatches it through registered
   * SVM error callback lane.
   */
  void SVM_CallErr(const char* const format, ...)
  {
    va_list args;
    va_start(args, format);
    std::memset(gSvmErrorBuffer, 0, sizeof(gSvmErrorBuffer));
    (void)std::vsprintf(gSvmErrorBuffer, format, args);
    va_end(args);

    if (gSvmErrorCallback.fn != nullptr) {
      gSvmErrorCallback.fn(gSvmErrorCallback.callbackObject, gSvmErrorBuffer);
    }
  }

  /**
   * Address: 0x00B0C390 (FUN_00B0C390, _SVM_CallErr1)
   *
   * What it does:
   * Copies one raw error text lane into SVM error buffer and dispatches the
   * callback without format expansion.
   */
  void SVM_CallErr1(const char* const message)
  {
    std::strncpy(gSvmErrorBuffer, message, 0x7Fu);
    if (gSvmErrorCallback.fn != nullptr) {
      gSvmErrorCallback.fn(gSvmErrorCallback.callbackObject, gSvmErrorBuffer);
    }
  }

  /**
   * Address: 0x00B0C310 (FUN_00B0C310, _SVM_UnlockThrd)
   *
   * What it does:
   * Leaves SVM lock lane with thread-domain token `5`.
   */
  void SVM_UnlockThrd()
  {
    svm_unlock(kSvmUnlockTypeThread);
  }

  /**
   * Address: 0x00B0C320 (FUN_00B0C320, _SVM_UnlockEtc)
   *
   * What it does:
   * Leaves SVM lock lane with auxiliary-domain token `1000`.
   */
  void SVM_UnlockEtc()
  {
    svm_unlock(kSvmUnlockTypeEtc);
  }

  /**
   * Address: 0x00B0C3C0 (FUN_00B0C3C0, _SVM_CallErr2)
   *
   * What it does:
   * Builds SVM error text by concatenating `prefix + message` and dispatches
   * the registered SVM error callback lane when present.
   */
  void SVM_CallErr2(const char* const prefix, const char* const message)
  {
    std::strncpy(gSvmErrorBuffer, prefix, 0x7Fu);
    std::strncat(gSvmErrorBuffer, message, 0x7Fu);
    if (gSvmErrorCallback.fn != nullptr) {
      gSvmErrorCallback.fn(gSvmErrorCallback.callbackObject, gSvmErrorBuffer);
    }
  }

  /**
   * Address: 0x00B0C410 (FUN_00B0C410)
   *
   * What it does:
   * Encodes one integer lane into legacy SVM scratch format and copies a
   * reversed prefix from the SVM ItoA scratch buffer into caller output.
   */
  std::int32_t SVM_ItoA(std::int32_t value, char* const outText, const std::int32_t outBytes)
  {
    std::int32_t digitLane = 0;
    while (true) {
      const std::int32_t digitValue = value % 10;
      value /= 10;
      outText[digitLane] = static_cast<char>(digitValue);
      if (value == 0) {
        break;
      }
      if (++digitLane >= kSvmItoaReverseDigitCap) {
        goto reverse_copy;
      }
    }

    outText[digitLane] = '\0';

  reverse_copy:
    std::int32_t copyBytes = static_cast<std::int32_t>(std::strlen(gSvmItoaScratchBuffer));
    if (copyBytes >= outBytes - 1) {
      copyBytes = outBytes - 1;
    }

    std::int32_t result = 0;
    if (copyBytes > 0) {
      const char* sourceCursor = gSvmItoaScratchBuffer + copyBytes - 1;
      do {
        outText[result] = *sourceCursor;
        ++result;
        --sourceCursor;
      } while (result < copyBytes);
    }

    outText[result] = '\0';
    return result;
  }

  /**
   * Address: 0x00B0C470 (FUN_00B0C470)
   *
   * What it does:
   * Formats two integer lanes into one legacy SVM payload with a single-space
   * separator by chaining `SVM_ItoA`.
   */
  std::int32_t SVM_ItoA2(
    const std::int32_t highWord,
    const std::int32_t lowWord,
    char* const outText,
    const std::int32_t outBytes
  )
  {
    (void)SVM_ItoA(highWord, outText, outBytes);
    std::strncat(outText, kAdxerrSeparator, outBytes - (static_cast<std::int32_t>(std::strlen(outText)) + 1));
    return SVM_ItoA(lowWord, outText + std::strlen(outText), 4 - static_cast<std::int32_t>(std::strlen(outText)));
  }

  /**
   * Address: 0x00B0CA90 (FUN_00B0CA90, _SVM_ExecCbPreWaitV)
   *
   * What it does:
   * Dispatches registered SVM pre-wait callback lane when present.
   */
  void SVM_ExecCbPreWaitV()
  {
    if (gSvmPreWaitVCallback.fn != nullptr) {
      gSvmPreWaitVCallback.fn(gSvmPreWaitVCallback.callbackObject);
    }
  }

  /**
   * Address: 0x00B0CAB0 (FUN_00B0CAB0, _SVM_ExecCbPostWaitV)
   *
   * What it does:
   * Dispatches registered SVM post-wait callback lane when present and returns
   * callback pointer lane.
   */
  SvmLockCallback SVM_ExecCbPostWaitV()
  {
    const auto callback = gSvmPostWaitVCallback.fn;
    if (callback != nullptr) {
      callback(gSvmPostWaitVCallback.callbackObject);
    }
    return callback;
  }

  /**
   * Address: 0x00B0CAD0 (FUN_00B0CAD0, _SVM_GetPointerSvrFuncTable)
   *
   * What it does:
   * Returns raw pointer to SVM server callback table storage.
   */
  std::int32_t* SVM_GetPointerSvrFuncTable()
  {
    return reinterpret_cast<std::int32_t*>(gSvmServerCallbackTable.data());
  }

  /**
   * Address: 0x00ACCD20 (FUN_00ACCD20, _mwl_callErrCb)
   *
   * What it does:
   * Middleware callback thunk that forwards one message to SVM error sink.
   */
  void mwl_callErrCb(const char* const message)
  {
    SVM_CallErr1(message);
  }

  /**
   * Address: 0x00B0C530 (FUN_00B0C530, _svm_SetCbSvr)
   *
   * What it does:
   * Registers one server callback lane in the `8 x 6` SVM callback table and
   * returns slot index, or `-1` on error/full table.
   */
  std::int32_t SVM_SetCbSvr(
    const std::int32_t svtype,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrSetCbSvrIllegalSvType);
      return -1;
    }

    std::int32_t slotIndex = 0;
    SvmServerCallbackSlot* slot = &gSvmServerCallbackTable[svtype * kSvmServerSlotsPerType];
    while (slot->callbackFn != nullptr) {
      ++slotIndex;
      ++slot;
      if (slotIndex >= kSvmServerSlotsPerType) {
        break;
      }
    }

    if (slotIndex >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrSetCbSvrTooManyServerFuncs);
      return -1;
    }

    slot->callbackFn = reinterpret_cast<SvmServerCallbackFn>(static_cast<std::uintptr_t>(callbackAddress));
    slot->callbackObject = callbackObject;
    slot->callbackName = (callbackName != nullptr) ? callbackName : kSvmUnknownServerCallbackName;
    return slotIndex;
  }

  /**
   * Address: 0x00B0C500 (FUN_00B0C500, _SVM_SetCbSvrWithString)
   *
   * What it does:
   * Acquires SVM lock, writes one server callback-table entry, and returns
   * selected slot index or error status.
   */
  std::int32_t SVM_SetCbSvrWithString(
    const std::int32_t svtype,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    SVM_Lock();
    const std::int32_t result = SVM_SetCbSvr(svtype, callbackAddress, callbackObject, callbackName);
    SVM_Unlock();
    return result;
  }

  /**
   * Address: 0x00B0C4E0 (FUN_00B0C4E0, _SVM_SetCbSvr)
   *
   * What it does:
   * Registers one callback lane with default null callback-name lane.
   */
  std::int32_t SVM_SetCbSvrNoName(
    const std::int32_t svtype,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    return SVM_SetCbSvrWithString(svtype, callbackAddress, callbackObject, nullptr);
  }

  /**
   * Address: 0x00B0C680 (FUN_00B0C680, SVM_SetCbSvrId)
   *
   * What it does:
   * Registers or overwrites one exact `(svtype,id)` callback-table entry.
   */
  void SVM_SetCbSvrId(
    const std::int32_t svtype,
    const std::int32_t id,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    if (id < 0 || id >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrSetCbSvrIdIllegalId);
      return;
    }

    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrSetCbSvrIdIllegalSvType);
      return;
    }

    SvmServerCallbackSlot& slot = gSvmServerCallbackTable[(svtype * kSvmServerSlotsPerType) + id];
    if (slot.callbackFn != nullptr) {
      SVM_CallErr1(kSvmErrSetCbSvrIdOverwrite);
    }

    slot.callbackFn = reinterpret_cast<SvmServerCallbackFn>(static_cast<std::uintptr_t>(callbackAddress));
    slot.callbackObject = callbackObject;
    slot.callbackName = (callbackName != nullptr) ? callbackName : kSvmUnknownServerCallbackName;
  }

  /**
   * Address: 0x00B0C650 (FUN_00B0C650, _SVM_SetCbSvrIdWithString)
   *
   * What it does:
   * Acquires SVM lock and writes one exact callback-table entry.
   */
  void SVM_SetCbSvrIdWithString(
    const std::int32_t svtype,
    const std::int32_t id,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    SVM_Lock();
    SVM_SetCbSvrId(svtype, id, callbackAddress, callbackObject, callbackName);
    SVM_Unlock();
  }

  /**
   * Address: 0x00B0C630 (FUN_00B0C630, _SVM_SetCbSvrId)
   *
   * What it does:
   * Writes one exact callback-table entry with default null callback-name lane.
   */
  void SVM_SetCbSvrIdNoName(
    const std::int32_t svtype,
    const std::int32_t id,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    SVM_SetCbSvrIdWithString(svtype, id, callbackAddress, callbackObject, nullptr);
  }

  /**
   * Address: 0x00B0C710 (FUN_00B0C710, _SVM_SetCbBdr)
   *
   * What it does:
   * Registers one server-border callback lane under SVM lock.
   */
  void SVM_SetCbBdr(const std::int32_t borderLane, const std::int32_t callbackAddress, const std::int32_t callbackObject)
  {
    SVM_Lock();
    SvmCallbackBinding& callback = gSvmServerBorderCallbacks[static_cast<std::size_t>(borderLane)];
    callback.fn = reinterpret_cast<SvmLockCallback>(static_cast<std::uintptr_t>(callbackAddress));
    callback.callbackObject = callbackObject;
    SVM_Unlock();
  }

  /**
   * Address: 0x00B0C740 (FUN_00B0C740, _SVM_GotoSvrBorder)
   *
   * What it does:
   * Invokes one registered server-border callback lane when present.
   */
  void SVM_GotoSvrBorder(const std::int32_t borderLane)
  {
    const SvmCallbackBinding& callback = gSvmServerBorderCallbacks[static_cast<std::size_t>(borderLane)];
    if (callback.fn != nullptr) {
      callback.fn(callback.callbackObject);
    }
  }

  /**
   * Address: 0x00B0C780 (FUN_00B0C780, _SVM_SetCbLock)
   *
   * What it does:
   * Stores one process-global SVM lock callback lane and its callback object.
   */
  SvmLockCallback SVM_SetCbLock(const SvmLockCallback callback, const std::int32_t callbackObject)
  {
    gSvmLockCallback.fn = callback;
    gSvmLockCallback.callbackObject = callbackObject;
    return callback;
  }

  /**
   * Address: 0x00B0C7A0 (FUN_00B0C7A0, _SVM_SetCbUnlock)
   *
   * What it does:
   * Stores one process-global SVM unlock callback lane and its callback object.
   */
  SvmLockCallback SVM_SetCbUnlock(const SvmLockCallback callback, const std::int32_t callbackObject)
  {
    gSvmUnlockCallback.fn = callback;
    gSvmUnlockCallback.callbackObject = callbackObject;
    return callback;
  }

  /**
   * Address: 0x00B0C830 (FUN_00B0C830, _SVM_ExecSvrFuncId)
   *
   * What it does:
   * Executes one registered callback-table lane by `(svtype,id)` and returns
   * callback result, or `0` on validation/missing-callback paths.
   */
  std::int32_t SVM_ExecSvrFuncId(const std::int32_t svtype, const std::int32_t id)
  {
    if (id < 0 || id >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrExecSvrFuncIdIllegalId);
      return 0;
    }

    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrExecSvrFuncIdIllegalSvType);
      return 0;
    }

    SvmServerCallbackSlot& slot = gSvmServerCallbackTable[(svtype * kSvmServerSlotsPerType) + id];
    if (slot.callbackFn == nullptr) {
      return 0;
    }

    return slot.callbackFn(slot.callbackObject);
  }

  /**
   * Address: 0x00B0C7C0 (FUN_00B0C7C0, _SVM_ExecSvrFunc)
   *
   * What it does:
   * Executes all registered server callbacks for one service lane and updates
   * per-lane execution markers/counters.
   */
  std::int32_t SVM_ExecSvrFunc(const std::int32_t svtype)
  {
    std::int32_t mergedResult = 0;
    for (std::int32_t slotIndex = 0; slotIndex < kSvmServerSlotsPerType; ++slotIndex) {
      SvmServerCallbackSlot& slot = gSvmServerCallbackTable[(svtype * kSvmServerSlotsPerType) + slotIndex];
      if (slot.callbackFn != nullptr) {
        gSvmServerExecutingFlags[static_cast<std::size_t>(svtype)] = 1;
        mergedResult |= slot.callbackFn(slot.callbackObject);
        gSvmServerExecutingFlags[static_cast<std::size_t>(svtype)] = 0;
      }
    }

    ++gSvmServerExecutionCounts[static_cast<std::size_t>(svtype)];
    return mergedResult;
  }

  /**
   * Address: 0x00B0C8A0 (FUN_00B0C8A0, _SVM_ExecSvrVint)
   */
  std::int32_t SVM_ExecSvrVint()
  {
    return SVM_ExecSvrFunc(0);
  }

  /**
   * Address: 0x00B0C8B0 (FUN_00B0C8B0, _SVM_ExecSvrUsrVsync)
   */
  std::int32_t SVM_ExecSvrUsrVsync()
  {
    return SVM_ExecSvrFunc(1);
  }

  /**
   * Address: 0x00B0C8C0 (FUN_00B0C8C0, _SVM_ExecSvrVsync)
   */
  std::int32_t SVM_ExecSvrVsync()
  {
    return SVM_ExecSvrFunc(2);
  }

  /**
   * Address: 0x00B0C8D0 (FUN_00B0C8D0, _SVM_ExecSvrUhigh)
   */
  std::int32_t SVM_ExecSvrUhigh()
  {
    return SVM_ExecSvrFunc(3);
  }

  /**
   * Address: 0x00B0C8E0 (FUN_00B0C8E0, _SVM_ExecSvrFs)
   */
  std::int32_t SVM_ExecSvrFs()
  {
    return SVM_ExecSvrFunc(4);
  }

  /**
   * Address: 0x00B0C8F0 (FUN_00B0C8F0, _SVM_ExecSvrMain)
   */
  std::int32_t SVM_ExecSvrMain()
  {
    return SVM_ExecSvrFunc(5);
  }

  /**
   * Address: 0x00B0C900 (FUN_00B0C900, _SVM_ExecSvrMwIdle)
   */
  std::int32_t SVM_ExecSvrMwIdle()
  {
    return SVM_ExecSvrFunc(6);
  }

  /**
   * Address: 0x00B0C910 (FUN_00B0C910, _SVM_ExecSvrUsrIdle)
   */
  std::int32_t SVM_ExecSvrUsrIdle()
  {
    return SVM_ExecSvrFunc(7);
  }

  /**
   * Address: 0x00B0C920 (FUN_00B0C920, _SVM_GetExecCount)
   *
   * What it does:
   * Returns one SVM server execution-count lane for valid service indices.
   */
  std::int32_t SVM_GetExecCount(const std::int32_t serverType)
  {
    if (serverType > 6 || serverType < 0) {
      return 0;
    }
    return gSvmServerExecutionCounts[static_cast<std::size_t>(serverType)];
  }

  /**
   * Address: 0x00B0C960 (FUN_00B0C960, _svm_reset_variable)
   *
   * What it does:
   * Resets SVM callback bindings, execution marker/counter lanes, and test-and-set override hook.
   */
  void svm_reset_variable()
  {
    gSvmServerExecutingFlags.fill(0);

    gSvmLockCallback.fn = nullptr;
    gSvmLockCallback.callbackObject = 0;

    gSvmPostWaitVCallback.fn = nullptr;
    gSvmPostWaitVCallback.callbackObject = 0;

    gSvmUnlockCallback.fn = nullptr;
    gSvmUnlockCallback.callbackObject = 0;

    gSvmPreWaitVCallback.fn = nullptr;
    gSvmPreWaitVCallback.callbackObject = 0;

    for (std::size_t lane = 0; lane < 6; ++lane) {
      gSvmServerExecutionCounts[lane] = 0;
    }

    gSofdecTestAndSetOverride = nullptr;
  }

  /**
   * Address: 0x00B0C940 (FUN_00B0C940, _SVM_Init)
   *
   * What it does:
   * Initializes SVM runtime lanes on first entry and increments init reference count.
   */
  std::int32_t SVM_Init()
  {
    if (gSvmInitLevel == 0) {
      svm_reset_variable();
    }

    ++gSvmInitLevel;
    return gSvmInitLevel;
  }

  /**
   * Address: 0x00B0C9C0 (FUN_00B0C9C0, _SVM_Finish)
   *
   * What it does:
   * Decrements SVM init reference count and clears callback/reset lanes on final shutdown.
   */
  void SVM_Finish()
  {
    --gSvmInitLevel;
    if (gSvmInitLevel == 0) {
      svm_reset_variable();
      gSvmErrorCallback.fn = nullptr;
      gSvmErrorCallback.callbackObject = 0;
    }
  }

  /**
   * Address: 0x00B0CA20 (FUN_00B0CA20, _SVM_SetCbTestAndSet)
   *
   * What it does:
   * Registers one optional SVM test-and-set override callback lane if it is not already occupied.
   */
  std::int32_t SVM_SetCbTestAndSet(const SofdecTestAndSetOverride callback)
  {
    if (gSofdecTestAndSetOverride != nullptr) {
      return 0;
    }
    gSofdecTestAndSetOverride = callback;
    return 1;
  }

  /**
   * Address: 0x00B0CA40 (FUN_00B0CA40, _SVM_DelCbTestAndSet)
   *
   * What it does:
   * Clears the optional SVM test-and-set override callback lane.
   */
  std::int32_t SVM_DelCbTestAndSet()
  {
    return SVM_SetCbTestAndSet(nullptr);
  }

  /**
   * Address: 0x00B0CA50 (FUN_00B0CA50, _SVM_SetCbPreWaitV)
   *
   * What it does:
   * Stores one callback lane invoked before V-sync wait processing.
   */
  SvmLockCallback SVM_SetCbPreWaitV(const SvmLockCallback callback, const std::int32_t callbackObject)
  {
    gSvmPreWaitVCallback.fn = callback;
    gSvmPreWaitVCallback.callbackObject = callbackObject;
    return callback;
  }

  /**
   * Address: 0x00B0CA70 (FUN_00B0CA70, _SVM_SetCbPostWaitV)
   *
   * What it does:
   * Stores one callback lane invoked after V-sync wait processing.
   */
  SvmLockCallback SVM_SetCbPostWaitV(const SvmLockCallback callback, const std::int32_t callbackObject)
  {
    gSvmPostWaitVCallback.fn = callback;
    gSvmPostWaitVCallback.callbackObject = callbackObject;
    return callback;
  }

  /**
   * Address: 0x00B10660 (FUN_00B10660, _ADXM_ExecSvrAll)
   *
   * What it does:
   * Executes all ADXM/SVM service lanes in fixed order and returns success.
   */
  std::int32_t ADXM_ExecSvrAll()
  {
    (void)SVM_ExecSvrVint();
    (void)SVM_ExecSvrUsrVsync();
    (void)SVM_ExecSvrVsync();
    (void)SVM_ExecSvrUhigh();
    (void)SVM_ExecSvrFs();
    (void)SVM_ExecSvrMain();
    (void)SVM_ExecSvrMwIdle();
    (void)SVM_ExecSvrUsrIdle();
    return 0;
  }

  /**
   * Address: 0x00B10690 (FUN_00B10690, _ADXM_ExecSvrVint)
   *
   * What it does:
   * ADXM service thunk that executes one VINT server lane.
   */
  std::int32_t ADXM_ExecSvrVint()
  {
    return SVM_ExecSvrVint();
  }

  /**
   * Address: 0x00B106A0 (FUN_00B106A0, _ADXM_ExecSvrUsrVsync)
   *
   * What it does:
   * ADXM service thunk that executes one user-vsync server lane.
   */
  std::int32_t ADXM_ExecSvrUsrVsync()
  {
    return SVM_ExecSvrUsrVsync();
  }

  /**
   * Address: 0x00B106B0 (FUN_00B106B0, _ADXM_ExecSvrVsync)
   *
   * What it does:
   * ADXM service thunk that executes one vsync server lane.
   */
  std::int32_t ADXM_ExecSvrVsync()
  {
    return SVM_ExecSvrVsync();
  }

  /**
   * Address: 0x00B106C0 (FUN_00B106C0, _ADXM_ExecSvrUsrHigh)
   *
   * What it does:
   * ADXM service thunk that executes one user-high server lane.
   */
  std::int32_t ADXM_ExecSvrUsrHigh()
  {
    return SVM_ExecSvrUhigh();
  }

  /**
   * Address: 0x00B106D0 (FUN_00B106D0, _ADXM_ExecSvrFs)
   *
   * What it does:
   * ADXM service thunk that executes one filesystem server lane.
   */
  std::int32_t ADXM_ExecSvrFs()
  {
    return SVM_ExecSvrFs();
  }

  /**
   * Address: 0x00B106E0 (FUN_00B106E0, _ADXM_ExecSvrMain)
   *
   * What it does:
   * ADXM service thunk that executes one main server lane.
   */
  std::int32_t ADXM_ExecSvrMain()
  {
    return SVM_ExecSvrMain();
  }

  /**
   * Address: 0x00B106F0 (FUN_00B106F0, _ADXM_ExecSvrMwIdle)
   *
   * What it does:
   * ADXM service thunk that executes one middleware-idle server lane.
   */
  std::int32_t ADXM_ExecSvrMwIdle()
  {
    return SVM_ExecSvrMwIdle();
  }

  /**
   * Address: 0x00B10700 (FUN_00B10700, _ADXM_ExecSvrUsrIdle)
   *
   * What it does:
   * ADXM service thunk that executes one user-idle server lane.
   */
  std::int32_t ADXM_ExecSvrUsrIdle()
  {
    return SVM_ExecSvrUsrIdle();
  }

  /**
   * Address: 0x00B06BF0 (FUN_00B06BF0, _ADXM_IsSetupThrd)
   *
   * What it does:
   * Returns whether ADXM thread/setup init lane is active.
   */
  std::int32_t ADXM_IsSetupThrd()
  {
    return (gAdxmInitLevel != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00B10710 (FUN_00B10710, _adxmng_DecideFramework)
   *
   * What it does:
   * Resolves default framework lane when caller requests auto mode (`-1`).
   */
  std::int32_t adxmng_DecideFramework(const std::int32_t frameworkMode)
  {
    if (frameworkMode != -1) {
      return frameworkMode;
    }
    return (ADXM_IsSetupThrd() == 1) ? 1 : 2;
  }

  /**
   * Address: 0x00B105E0 (FUN_00B105E0, _ADXMNG_CallMainServerFunctions)
   *
   * What it does:
   * Dispatches ADXM main-idle server lanes according to selected framework mode.
   */
  std::int32_t ADXMNG_CallMainServerFunctions()
  {
    const std::int32_t frameworkLane = adxmng_DecideFramework(gAdxmFramework) - 1;
    if (frameworkLane == 0) {
      (void)ADXM_ExecSvrAll();
      return 0;
    }
    if (frameworkLane == 1) {
      (void)SVM_ExecSvrMain();
      return 0;
    }
    if (frameworkLane == 2) {
      (void)SVM_ExecSvrMwIdle();
      (void)SVM_ExecSvrUsrIdle();
    }
    return 0;
  }

  /**
   * Address: 0x00B10620 (FUN_00B10620, _ADXMNG_CallVintServerFunctions)
   *
   * What it does:
   * Dispatches ADXM VINT/vsync lanes according to selected framework mode.
   */
  std::int32_t ADXMNG_CallVintServerFunctions()
  {
    const std::int32_t frameworkLane = adxmng_DecideFramework(gAdxmFramework) - 2;
    if (frameworkLane == 0) {
      (void)SVM_ExecSvrVint();
      return 0;
    }
    if (frameworkLane == 1) {
      (void)SVM_ExecSvrVint();
      (void)SVM_ExecSvrUsrVsync();
      (void)SVM_ExecSvrVsync();
      (void)SVM_ExecSvrUhigh();
      (void)SVM_ExecSvrMain();
    }
    return 0;
  }

  /**
   * Address: 0x00B06990 (FUN_00B06990, func_SofdecEnterLock1)
   *
   * What it does:
   * Enters ADXM critical section and increments lock nesting level lane.
   */
  std::int32_t func_SofdecEnterLock1()
  {
    EnterCriticalSection(&gAdxmLock);
    return ++gAdxmLockLevel;
  }

  /**
   * Address: 0x00B069B0 (FUN_00B069B0, func_SofdecLeaveLock1)
   *
   * What it does:
   * Decrements ADXM lock nesting lane and leaves ADXM critical section.
   */
  void func_SofdecLeaveLock1()
  {
    --gAdxmLockLevel;
    LeaveCriticalSection(&gAdxmLock);
  }

  /**
   * Address: 0x00B069D0 (FUN_00B069D0, _adxm_test_and_set)
   *
   * What it does:
   * Atomically sets target lane to `1` and returns whether previous value was `0`.
   */
  BOOL adxm_test_and_set(volatile LONG* const target)
  {
    return InterlockedExchange(target, 1) == 0;
  }

  constexpr std::int32_t kAdxmGotoMwIdleBorderRetryLimit = 3000000;
  constexpr const char* kAdxmGotoMwIdleBorderInternalErrorMessage = "1060102: Internal Error: adxm_goto_mwidle_border";

  /**
   * Address: 0x00B069F0 (FUN_00B069F0, _adxm_goto_mwidle_border)
   *
   * What it does:
   * Forces mw-idle lane toward border handoff by raising thread priority/resume
   * pulses until border flag clears or retry limit is reached.
   */
  BOOL adxm_goto_mwidle_border()
  {
    gAdxmGotoMwIdleBorderFlag = 1;
    std::int32_t retryCount = 0;
    for (; retryCount < kAdxmGotoMwIdleBorderRetryLimit; ++retryCount) {
      SetThreadPriority(gAdxmMwIdleThreadHandle, gAdxmThreadStartupParams.nPriority);
      ResumeThread(gAdxmMwIdleThreadHandle);
      if (gAdxmGotoMwIdleBorderFlag == 0) {
        break;
      }
    }

    if (retryCount == kAdxmGotoMwIdleBorderRetryLimit) {
      SVM_CallErr1(kAdxmGotoMwIdleBorderInternalErrorMessage);
    }
    return SetThreadPriority(gAdxmMwIdleThreadHandle, gAdxmThreadStartupParams.mwidlePriority);
  }

  /**
   * Address: 0x00B06A60 (FUN_00B06A60, nullsub_3610)
   *
   * What it does:
   * Legacy no-op callback lane.
   */
  void adxm_noop_proc()
  {
  }

  /**
   * Address: 0x00B06A70 (FUN_00B06A70)
   *
   * What it does:
   * Spins until release flag lane becomes non-zero, then marks completion lane.
   */
  unsigned __stdcall adxm_spin_wait_proc([[maybe_unused]] void* const threadArgument)
  {
    while (gAdxmSpinWaitReleaseFlag == 0) {
      ++gAdxmSpinWaitIterationCount;
    }
    gAdxmSpinWaitCompletedFlag = 1;
    return 0;
  }

  /**
   * Address: 0x00B073F0 (FUN_00B073F0, _adxm_waitVsyncForThrd)
   *
   * What it does:
   * Waits on ADXT vsync event lane when event handle is present.
   */
  void adxm_waitVsyncForThrd()
  {
    if (gAdxtVsyncEventHandle != nullptr) {
      WaitForSingleObject(gAdxtVsyncEventHandle, INFINITE);
    }
  }

  /**
   * Address: 0x00B06AA0 (FUN_00B06AA0, _adxm_vsync_proc@4)
   *
   * What it does:
   * ADXM vsync thread entry that pumps VSYNC server lanes and wakes mw-idle lane.
   */
  unsigned __stdcall adxm_vsync_proc([[maybe_unused]] void* const threadArgument)
  {
    while (gAdxmVsyncLoop == 0) {
      adxm_waitVsyncForThrd();
      ++gAdxmVsyncCount;
      SVM_Lock();
      (void)SVM_ExecSvrVsync();
      SVM_Unlock();
      ResumeThread(gAdxmMwIdleThreadHandle);
      if (gAdxmMwIdleSleepCallback.callback != nullptr) {
        gAdxmMwIdleSleepCallback.callback(gAdxmMwIdleSleepCallback.callbackParam);
      }
    }
    gAdxmVsyncExit = 1;
    return 0;
  }

  /**
   * Address: 0x00B06B10 (FUN_00B06B10, _adxm_fs_proc@4)
   *
   * What it does:
   * ADXM filesystem thread entry that waits for vsync signal then executes FS server.
   */
  unsigned __stdcall adxm_fs_proc([[maybe_unused]] void* const threadArgument)
  {
    while (gAdxmFsLoop == 0) {
      adxm_waitVsyncForThrd();
      (void)SVM_ExecSvrFs();
    }
    gAdxmFsExit = 1;
    return 0;
  }

  /**
   * Address: 0x00B06B40 (FUN_00B06B40, _adxm_mwidle_proc@4)
   *
   * What it does:
   * ADXM mw-idle thread entry that executes idle server lane and self-suspends
   * when idle callback signals no work or border handoff is active.
   */
  unsigned __stdcall adxm_mwidle_proc([[maybe_unused]] void* const threadArgument)
  {
    if (gAdxmMwIdleLoop != 0) {
      gAdxmMwIdleExit = 1;
      return 0;
    }

    do {
      ++gAdxmMwIdleCount;
      if (SVM_ExecSvrMwIdle() == 0 || gAdxmGotoMwIdleBorderFlag == 1) {
        if (gAdxmGotoMwIdleBorderFlag == 1) {
          gAdxmGotoMwIdleBorderFlag = 0;
          SetThreadPriority(gAdxmMwIdleThreadHandle, gAdxmThreadStartupParams.mwidlePriority);
        }

        if (gAdxmMwIdleSleepCallback.callback != nullptr) {
          gAdxmMwIdleSleepCallback.callback(gAdxmMwIdleSleepCallback.callbackParam);
        }
        SuspendThread(gAdxmMwIdleThreadHandle);
      }
    } while (gAdxmMwIdleLoop == 0);

    gAdxmMwIdleExit = 1;
    return 0;
  }

  /**
   * Address: 0x00B06E40 (FUN_00B06E40, _ADXM_GetLockLevel)
   *
   * What it does:
   * Returns current ADXM lock nesting level lane.
   */
  std::int32_t ADXM_GetLockLevel()
  {
    return gAdxmLockLevel;
  }

  /**
   * Address: 0x00B06E50 (FUN_00B06E50, _ADXM_ExecMain)
   *
   * What it does:
   * Thunk that executes one ADXM main server-dispatch tick.
   */
  void ADXM_ExecMain()
  {
    (void)ADXMNG_CallMainServerFunctions();
  }

  /**
   * Address: 0x00B06FC0 (FUN_00B06FC0, _ADXM_SetCbSleepMwIdle)
   *
   * What it does:
   * Publishes mw-idle sleep callback lanes and returns assigned callback.
   */
  moho::AdxmMwIdleSleepCallback ADXM_SetCbSleepMwIdle(
    const moho::AdxmMwIdleSleepCallback callback,
    const std::int32_t callbackParam
  )
  {
    gAdxmMwIdleSleepCallback.callback = callback;
    gAdxmMwIdleSleepCallback.callbackParam = callbackParam;
    return callback;
  }

  /**
   * Address: 0x00B0C5D0 (FUN_00B0C5D0, SVM_DelCbSvr)
   *
   * What it does:
   * Clears one server callback-table slot by `(svtype, id)` with strict
   * range validation and SVM error reporting.
   */
  void SVM_DelCbSvr(const std::int32_t svtype, const std::int32_t id)
  {
    if (id < 0 || id >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrDelCbSvrIllegalId);
      return;
    }

    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrDelCbSvrIllegalSvType);
      return;
    }

    SvmServerCallbackSlot& slot = gSvmServerCallbackTable[(svtype * kSvmServerSlotsPerType) + id];
    slot.callbackFn = nullptr;
    slot.callbackObject = 0;
    slot.callbackName = nullptr;
  }

  /**
   * Address: 0x00B0C5B0 (FUN_00B0C5B0, _SVM_DelCbSvr)
   *
   * What it does:
   * Acquires SVM lock, clears one callback-table entry, and releases the lock.
   */
  void SVM_DelCbSvrWithLock(const std::int32_t svtype, const std::int32_t id)
  {
    SVM_Lock();
    SVM_DelCbSvr(svtype, id);
    SVM_Unlock();
  }

