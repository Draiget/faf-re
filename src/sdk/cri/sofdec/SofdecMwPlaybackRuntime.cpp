
  /**
   * Address: 0x00AD8F10 (FUN_00AD8F10, _SFLIB_LockCs)
   */
  void SFLIB_LockCs()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00AD8F20 (FUN_00AD8F20, _SFLIB_UnlockCs)
   */
  void SFLIB_UnlockCs()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00AD8F30 (FUN_00AD8F30, _MWSTM_Init)
   */
  std::int32_t MWSTM_Init()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F40 (FUN_00AD8F40, _MWSTM_InitStatic)
   */
  std::int32_t MWSTM_InitStatic()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F50 (FUN_00AD8F50, _MWSTM_Finish)
   */
  std::int32_t MWSTM_Finish()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F60 (FUN_00AD8F60, _MWSTM_FinishStatic)
   */
  std::int32_t MWSTM_FinishStatic()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F70 (FUN_00AD8F70, _MWSTM_SetRdSct)
   */
  std::int32_t MWSTM_SetRdSct(const std::int32_t streamHandleAddress, const std::int32_t requestedSectorCount)
  {
    if (streamHandleAddress != 0) {
      ADXSTM_SetReqRdSize(SjAddressToPointer(streamHandleAddress), requestedSectorCount);
    }
    return 0;
  }

  /**
   * Address: 0x00AD8F90 (FUN_00AD8F90, _MWSTM_SetTrSct)
   */
  std::int32_t MWSTM_SetTrSct(const std::int32_t streamHandleAddress, const std::int32_t transferSectorCount)
  {
    (void)streamHandleAddress;
    (void)transferSectorCount;
    return 0;
  }

  /**
   * Address: 0x00AD9020 (FUN_00AD9020, _MWSTM_Start)
   */
  std::int32_t MWSTM_Start(const std::int32_t streamHandleAddress)
  {
    ADXSTM_Start(SjAddressToPointer(streamHandleAddress));
    return 0;
  }

  /**
   * Address: 0x00AD9030 (FUN_00AD9030, _MWSTM_IsFsStatErr)
   */
  bool MWSTM_IsFsStatErr(const std::int32_t streamHandleAddress)
  {
    return ADXSTM_GetStat(SjAddressToPointer(streamHandleAddress)) == kAdxstmStatusFilesystemError;
  }

  std::int32_t ADXM_WaitVsync();

  /**
   * Address: 0x00AED7D0 (FUN_00AED7D0, _mwPlySwitchToIdle)
   *
   * What it does:
   * Thunk alias to ADXM vertical-sync wait lane.
   */
  extern "C" std::int32_t mwPlySwitchToIdle()
  {
    return ADXM_WaitVsync();
  }

  /**
   * Address: 0x00AED800 (FUN_00AED800, nullsub_39)
   *
   * What it does:
   * Reserved playback-resource save hook (no-op in this build).
   */
  void nullsub_39()
  {
  }

  /**
   * Address: 0x00AED810 (FUN_00AED810, nullsub_27)
   *
   * What it does:
   * Reserved playback-resource restore hook (no-op in this build).
   */
  void nullsub_27()
  {
  }

  /**
   * Address: 0x00AED7E0 (FUN_00AED7E0, _mwPlySaveRsc)
   *
   * What it does:
   * Dispatches playback-resource save hook.
   */
  extern "C" void mwPlySaveRsc()
  {
    nullsub_39();
  }

  /**
   * Address: 0x00AED7F0 (FUN_00AED7F0, _mwPlyRestoreRsc)
   *
   * What it does:
   * Dispatches playback-resource restore hook.
   */
  extern "C" void mwPlyRestoreRsc()
  {
    nullsub_27();
  }

  /**
   * Address: 0x00AED820 (FUN_00AED820, nullsub_3605)
   *
   * What it does:
   * Reserved no-op lane.
   */
  void nullsub_3605()
  {
  }

  /**
   * Address: 0x00B165D0 (FUN_00B165D0, sub_B165D0)
   *
   * What it does:
   * Stores ADXPC DVD-error reporting mode flag and returns the written value.
   */
  std::int32_t ADXPC_SetDvdErrorReportingEnabled(const std::int32_t enabled)
  {
    gAdxpcDvdErrorReportingEnabled = enabled;
    return enabled;
  }

  /**
   * Address: 0x00B162E0 (FUN_00B162E0, sub_B162E0)
   */
  std::int32_t SofdecWarmRestoreProbePlayback()
  {
    if (SofdecCreateRestoreProbeBuffer() != 1) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrCreatePlaybackFailed);
      SofdecShutdownRestoreProbeBuffer();
      return 0;
    }

    const std::int32_t playResult = gSofdecRestoreProbeBuffer->lpVtbl->Play(
      gSofdecRestoreProbeBuffer,
      0,
      0,
      DSBPLAY_LOOPING
    );
    if (playResult == 0) {
      SofdecPollBufferPlaybackState(gSofdecRestoreProbeBuffer, true);
    }
    return playResult;
  }

  /**
   * Address: 0x00B163D0 (FUN_00B163D0, sub_B163D0)
   */
  void SofdecStopWarmRestoreProbeAndShutdown()
  {
    if (gSofdecRestoreProbeBuffer->lpVtbl->Stop(gSofdecRestoreProbeBuffer) == 0) {
      SofdecPollBufferPlaybackState(gSofdecRestoreProbeBuffer, false);
      SofdecShutdownRestoreProbeBuffer();
    }
  }

  /**
   * Address: 0x00B16A20 (FUN_00B16A20, SofDecVirt2_Func4)
   */
  std::int32_t SofdecLockProbeWindowAndGetFrameSpan(moho::SofdecSoundPort* const soundPort)
  {
    void* lockedPrimary = soundPort;
    DWORD lockedPrimaryBytes = 0;
    void* lockedSecondary = nullptr;
    DWORD lockedSecondaryBytes = 0;

    const std::int32_t lockResult = soundPort->primaryBuffer->lpVtbl->Lock(
      soundPort->primaryBuffer,
      0,
      8,
      &lockedPrimary,
      &lockedPrimaryBytes,
      &lockedSecondary,
      &lockedSecondaryBytes,
      0
    );
    if (lockResult != 0 && SofdecRestoreBufferIfLost(soundPort->primaryBuffer, lockResult) == 0) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrLockFailed);
      return 0;
    }

    soundPort->primaryBuffer->lpVtbl->Unlock(
      soundPort->primaryBuffer,
      lockedPrimary,
      lockedPrimaryBytes,
      lockedSecondary,
      lockedSecondaryBytes
    );
    if (lockResult != 0) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrUnlockFailed);
    }

    soundPort->playbackCursorByteOffset = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(lockedPrimary));
    return static_cast<std::int32_t>((static_cast<std::int32_t>(gSofdecPortBufferBytesPerChannel) / soundPort->format.bitsPerSample) * 8);
  }

  /**
   * Address: 0x00B16DE0 (FUN_00B16DE0, sub_B16DE0)
   */
  std::int32_t SofdecApplySpatialPresetInternal(
    moho::SofdecSoundPort* const soundPort,
    const std::int32_t channelLane,
    const std::int32_t presetIndex
  )
  {
    if (soundPort->monoRoutingMode == 1) {
      return 1;
    }

    if (channelLane != 0 || soundPort->channelModeFlag != 1) {
      return ADXERR_CallErrFunc1_(kSofdecErrSetPanFailed);
    }

    soundPort->spatialPresetPrimaryIndex = presetIndex;
    const std::int32_t spatialOffset = SofdecLookupSpatialVolumeOffsetMillibel(presetIndex);
    soundPort->spatialPresetVolumeOffset = spatialOffset;
    const std::int32_t effectiveVolume = SofdecClampMillibel(soundPort->baseVolumeMilliBel + spatialOffset);

    soundPort->primaryBuffer->lpVtbl->SetPan(
      soundPort->primaryBuffer,
      SofdecLookupSpatialPanMillibel(presetIndex)
    );
    return soundPort->primaryBuffer->lpVtbl->SetVolume(soundPort->primaryBuffer, effectiveVolume);
  }

  /**
   * Address: 0x00B16E60 (FUN_00B16E60, sub_B16E60)
   */
  std::int32_t SofdecResetSpatialPreset(moho::SofdecSoundPort* const soundPort)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort));
    if (soundPort->monoRoutingMode != 1) {
      soundPort->spatialPresetVolumeOffset = 0;
      soundPort->primaryBuffer->lpVtbl->SetPan(soundPort->primaryBuffer, 0);
      result = soundPort->primaryBuffer->lpVtbl->SetVolume(soundPort->primaryBuffer, soundPort->baseVolumeMilliBel);
    }

    return result;
  }

  /**
   * Address: 0x00B16AD0 (FUN_00B16AD0, SofDecVirt2_Func5)
   */
  std::int32_t SofdecSetChannelMode(moho::SofdecSoundPort* const soundPort, const std::int32_t channelMode)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort));
    if (soundPort->used != 0) {
      if (soundPort->primaryBuffer == nullptr) {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }

      soundPort->channelModeFlag = channelMode;
      if (soundPort->monoRoutingMode != 1 && soundPort->spatialPresetEnabled == 1) {
        if (channelMode == 1 && soundPort->channelCountPrimary == 1) {
          return SofdecApplySpatialPresetInternal(soundPort, 0, soundPort->spatialPresetPrimaryIndex);
        }
        return SofdecResetSpatialPreset(soundPort);
      }
    }

    return result;
  }

  /**
   * Address: 0x00B16B10 (FUN_00B16B10, SofDecVirt2_Func6)
   */
  std::int32_t SofdecGetPlaybackFrameCursor(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return 0;
    }
    if (soundPort->playbackCursorResetPending == 1) {
      return 0;
    }

    DWORD playCursor = 0;
    DWORD writeCursor = 0;
    if (soundPort->primaryBuffer->lpVtbl->GetCurrentPosition(soundPort->primaryBuffer, &playCursor, &writeCursor) != 0) {
      return 0;
    }

    const std::uint32_t bytesPerSample = static_cast<std::uint32_t>(soundPort->format.bitsPerSample >> 3);
    return static_cast<std::int32_t>(playCursor / bytesPerSample / static_cast<std::uint32_t>(soundPort->channelCountPrimary));
  }

  /**
   * Address: 0x00B16B80 (FUN_00B16B80, SofDecVirt2_Func7)
   */
  std::int32_t SofdecSetPlaybackFrequencyHz(moho::SofdecSoundPort* const soundPort, const std::int32_t frequencyHz)
  {
    std::int32_t result = soundPort->used;
    if (result != 0) {
      if (soundPort->primaryBuffer == nullptr) {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }

      result = frequencyHz;
      if (frequencyHz > kSofdecFrequencyMaxHz) {
        result = kSofdecFrequencyMaxHz;
      } else if (frequencyHz < kSofdecFrequencyMinHz) {
        result = kSofdecFrequencyMinHz;
      }
      soundPort->format.samplesPerSecond = static_cast<std::uint32_t>(result);
    }
    return result;
  }

  /**
   * Address: 0x00B16BD0 (FUN_00B16BD0, SofDecVirt2_Func8)
   */
  std::int32_t SofdecGetPlaybackFrequencyHz(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer != nullptr) {
      return static_cast<std::int32_t>(soundPort->format.samplesPerSecond);
    }

    (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    return 0;
  }

  /**
   * Address: 0x00B16C00 (FUN_00B16C00, SofDecVirt2_Func9)
   */
  std::int32_t SofdecSetOutputBitsPerSample(moho::SofdecSoundPort* const soundPort, const std::int16_t bitsPerSample)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort));
    if (soundPort->used != 0) {
      if (soundPort->primaryBuffer != nullptr) {
        soundPort->format.bitsPerSample = static_cast<std::uint16_t>(bitsPerSample);
      } else {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }
    }

    return result;
  }

  /**
   * Address: 0x00B16C30 (FUN_00B16C30, SofDecVirt2_Func10)
   */
  std::int32_t SofdecGetOutputBitsPerSample(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer != nullptr) {
      return soundPort->format.bitsPerSample;
    }

    (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    return 0;
  }

  /**
   * Address: 0x00B16C60 (FUN_00B16C60, SofDecVirt2_Func11)
   */
  std::int32_t SofdecSetBaseVolumeLevel(moho::SofdecSoundPort* const soundPort, const std::int32_t volumeLane)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer == nullptr) {
      return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }

    const std::int32_t baseVolume = SofdecClampMillibel(10 * volumeLane);
    soundPort->baseVolumeMilliBel = baseVolume;
    const std::int32_t effectiveVolume = SofdecClampMillibel(baseVolume + soundPort->spatialPresetVolumeOffset);
    if (soundPort->primaryBuffer->lpVtbl->SetVolume(soundPort->primaryBuffer, effectiveVolume) != 0) {
      return ADXERR_CallErrFunc1_(kSofdecErrSetVolumeFailed);
    }

    return 0;
  }

  /**
   * Address: 0x00B16CE0 (FUN_00B16CE0, SofDecVirt2_Func12)
   */
  std::int32_t SofdecValidatePrimaryBufferForVolumeOps(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used != 0 && soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }
    return 0;
  }

  /**
   * Address: 0x00B16D60 (FUN_00B16D60, SofDecVirt2_Func13)
   */
  moho::SofdecSoundPort* SofdecConfigureSpatialPreset(
    moho::SofdecSoundPort* const soundPort,
    const std::int32_t channelLane,
    const std::int32_t presetIndex
  )
  {
    if (soundPort->used == 0) {
      return soundPort;
    }
    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return soundPort;
    }
    if (soundPort->monoRoutingMode == 1) {
      return soundPort;
    }

    soundPort->spatialPresetEnabled = 1;
    if (soundPort->channelCountPrimary == 1 && soundPort->channelModeFlag == 1) {
      (void)SofdecApplySpatialPresetInternal(soundPort, 0, presetIndex);
      return soundPort;
    }

    if (channelLane == 0) {
      soundPort->spatialPresetPrimaryIndex = presetIndex;
    } else if (channelLane == 1) {
      soundPort->spatialPresetSecondaryIndex = presetIndex;
    }
    soundPort->spatialPresetVolumeOffset = 0;
    return soundPort;
  }

  /**
   * Address: 0x00B16E90 (FUN_00B16E90, SofDecVirt2_Func14)
   */
  std::int32_t SofdecValidatePrimaryBufferForBalanceOps(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used != 0 && soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }
    return 0;
  }

  /**
   * Address: 0x00B16EC0 (FUN_00B16EC0, SofDecVirt2_Func15)
   */
  void SofdecSetBalanceIndex(moho::SofdecSoundPort* const soundPort, std::int32_t balanceIndex)
  {
    if (soundPort->monoRoutingMode == 1 || soundPort->used == 0) {
      return;
    }
    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return;
    }

    if (balanceIndex < kSofdecBalanceIndexMin) {
      balanceIndex = kSofdecBalanceIndexMin;
    } else if (balanceIndex > kSofdecBalanceIndexMax) {
      balanceIndex = kSofdecBalanceIndexMax;
    }
    soundPort->balanceIndex = balanceIndex;

    if (soundPort->primaryBuffer->lpVtbl->SetPan(soundPort->primaryBuffer, SofdecLookupBalancePanMillibel(balanceIndex)) != 0) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrSetPanFailed);
    }
  }

  /**
   * Address: 0x00B16F30 (FUN_00B16F30, SofDecVirt2_Func16)
   */
  std::int32_t SofdecGetBalanceIndex(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer != nullptr) {
      return soundPort->balanceIndex;
    }

    (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    return 0;
  }

  /**
   * Address: 0x00B16F60 (FUN_00B16F60, sub_B16F60)
   */
  std::int32_t SofdecApplyControlFrequencyInternal(moho::SofdecSoundPort* const soundPort, const std::int32_t frequencyHz)
  {
    std::int32_t result = soundPort->used;
    if (result != 0) {
      if (soundPort->primaryBuffer == nullptr) {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }

      (void)SofdecSetPlaybackFrequencyHz(soundPort, frequencyHz);
      result = SofdecGetPlaybackFrequencyHz(soundPort);
      if (soundPort->bufferPlacementMode == 0) {
        result = soundPort->primaryBuffer->lpVtbl->SetFrequency(soundPort->primaryBuffer, result);
        if (result != 0) {
          return ADXERR_CallErrFunc1_(kSofdecErrControlSetFrequencyFailed);
        }
      }
    }
    return result;
  }

  /**
   * Address: 0x00B16FC0 (FUN_00B16FC0, SofDecVirt2_Func17)
   */
  std::int32_t SofdecControlSetValue(
    moho::SofdecSoundPort* const soundPort,
    const std::int32_t controlCode,
    const std::int32_t controlValue
  )
  {
    if (controlCode == 5) {
      return SofdecApplyControlFrequencyInternal(soundPort, controlValue);
    }
    return 0;
  }

  /**
   * Address: 0x00B16FE0 (FUN_00B16FE0, SofDecVirt2_Func18)
   */
  std::int32_t* SofdecQueryPendingWindow(
    const std::int32_t contextLane,
    const std::int32_t queryLane,
    std::int32_t* const outPrimary,
    std::int32_t* const outSecondary
  )
  {
    (void)contextLane;
    (void)queryLane;
    *outPrimary = 0;
    *outSecondary = 0;
    return outPrimary;
  }

  /**
   * Address: 0x00B17000 (FUN_00B17000, sub_B17000)
   *
   * What it does:
   * Byte-copies one PCM payload window and returns copied byte count.
   */
  [[maybe_unused]] std::uint32_t SofdecCopyPcmBytes(
    void* const destination,
    const void* const source,
    const std::uint32_t byteCount
  )
  {
    std::memcpy(destination, source, byteCount);
    return byteCount;
  }

  /**
   * Address: 0x00B17020 (FUN_00B17020, sub_B17020)
   *
   * What it does:
   * Expands mono PCM into interleaved stereo with center gain (0.70710677).
   */
  [[maybe_unused]] void SofdecWriteStereoCenterMix(
    std::int16_t* const outInterleavedSamples,
    const std::int16_t* const monoSamples,
    const std::int32_t byteCount
  )
  {
    std::int16_t* outCursor = outInterleavedSamples;
    const std::int16_t* inCursor = monoSamples;

    std::uint32_t samplePairCount = SofdecComputeStereoSamplePairCount(byteCount);
    while (samplePairCount != 0u) {
      const float sample = static_cast<float>(*inCursor++);
      const std::int16_t mixed = static_cast<std::int16_t>(SofdecRoundFloatToInt(sample * kM2aCenterDownmixScale));
      *outCursor++ = mixed;
      *outCursor++ = mixed;
      --samplePairCount;
    }
  }

  /**
   * Address: 0x00B17080 (FUN_00B17080, sub_B17080)
   *
   * What it does:
   * Writes mono PCM into one interleaved stereo lane (stride-2 store).
   */
  [[maybe_unused]] void SofdecWriteMonoIntoInterleavedLane(
    std::int16_t* const outLaneSamples,
    const std::int16_t* const monoSamples,
    const std::int32_t byteCount
  )
  {
    std::int16_t* outCursor = outLaneSamples;
    const std::int16_t* inCursor = monoSamples;

    std::uint32_t samplePairCount = SofdecComputeStereoSamplePairCount(byteCount);
    while (samplePairCount != 0u) {
      *outCursor = *inCursor++;
      outCursor += 2;
      --samplePairCount;
    }
  }

  /**
   * Address: 0x00B170B0 (FUN_00B170B0, sub_B170B0)
   *
   * What it does:
   * Writes mono PCM into stereo using primary pan-lane gain lookup.
   */
  [[maybe_unused]] void SofdecWriteStereoPrimaryPanMix(
    const moho::SofdecSoundPort* const soundPort,
    std::int16_t* const outInterleavedSamples,
    const std::int16_t* const monoSamples,
    const std::int32_t byteCount
  )
  {
    const float leftGain = SofdecLookupLeftPanGain(soundPort->spatialPresetPrimaryIndex);
    const float rightGain = SofdecLookupRightPanGain(soundPort->spatialPresetPrimaryIndex);

    std::int16_t* outCursor = outInterleavedSamples;
    const std::int16_t* inCursor = monoSamples;

    std::uint32_t samplePairCount = SofdecComputeStereoSamplePairCount(byteCount);
    while (samplePairCount != 0u) {
      const float sample = static_cast<float>(*inCursor++);
      *outCursor++ = static_cast<std::int16_t>(SofdecRoundFloatToInt(sample * leftGain));
      *outCursor++ = static_cast<std::int16_t>(SofdecRoundFloatToInt(sample * rightGain));
      --samplePairCount;
    }
  }

  /**
   * Address: 0x00B17150 (FUN_00B17150, sub_B17150)
   *
   * What it does:
   * Builds one stereo pan scratch lane from mono PCM using primary pan gains.
   */
  [[maybe_unused]] void SofdecBuildStereoPanScratch(
    const moho::SofdecSoundPort* const soundPort,
    const std::int16_t* const monoSamples,
    const std::int32_t byteCount
  )
  {
    const float leftGain = SofdecLookupLeftPanGain(soundPort->spatialPresetPrimaryIndex);
    const float rightGain = SofdecLookupRightPanGain(soundPort->spatialPresetPrimaryIndex);

    std::int16_t* scratchCursor = gSofdecStereoPanScratch.data();
    const std::int16_t* inCursor = monoSamples;

    std::uint32_t samplePairCount = SofdecComputeStereoSamplePairCount(byteCount);
    while (samplePairCount != 0u) {
      const float sample = static_cast<float>(*inCursor++);
      *scratchCursor++ = static_cast<std::int16_t>(SofdecRoundFloatToInt(sample * leftGain));
      *scratchCursor++ = static_cast<std::int16_t>(SofdecRoundFloatToInt(sample * rightGain));
      --samplePairCount;
    }
  }

  /**
   * Address: 0x00B171F0 (FUN_00B171F0, sub_B171F0)
   *
   * What it does:
   * Mixes mono PCM with scratch stereo lane using secondary pan gains and
   * saturates results to signed 16-bit PCM.
   */
  [[maybe_unused]] void SofdecAccumulateStereoPanScratch(
    const moho::SofdecSoundPort* const soundPort,
    std::int16_t* const outInterleavedSamples,
    const std::int16_t* const monoSamples,
    const std::int32_t byteCount
  )
  {
    const float leftGain = SofdecLookupLeftPanGain(soundPort->spatialPresetSecondaryIndex);
    const float rightGain = SofdecLookupRightPanGain(soundPort->spatialPresetSecondaryIndex);

    std::int16_t* outCursor = outInterleavedSamples;
    const std::int16_t* inCursor = monoSamples;
    const std::int16_t* scratchCursor = gSofdecStereoPanScratch.data();

    std::uint32_t samplePairCount = SofdecComputeStereoSamplePairCount(byteCount);
    while (samplePairCount != 0u) {
      const float sample = static_cast<float>(*inCursor++);
      const float mixedLeft = (sample * leftGain) + static_cast<float>(*scratchCursor++);
      const float mixedRight = (sample * rightGain) + static_cast<float>(*scratchCursor++);

      *outCursor++ = SofdecClampSampleToPcm16(SofdecRoundFloatToInt(mixedLeft));
      *outCursor++ = SofdecClampSampleToPcm16(SofdecRoundFloatToInt(mixedRight));
      --samplePairCount;
    }
  }

  /**
   * Address: 0x00B17310 (FUN_00B17310, sub_B17310)
   *
   * What it does:
   * Swaps primary/secondary DirectSound buffers and primes aux-drain state.
   */
  [[maybe_unused]] void SofdecSwapPrimaryAndSecondaryBuffers(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->primaryBuffer == nullptr || soundPort->secondaryBuffer == nullptr) {
      return;
    }

    DWORD playCursor = 0;
    DWORD writeCursor = 0;
    if (soundPort->primaryBuffer->lpVtbl->GetCurrentPosition(soundPort->primaryBuffer, &playCursor, &writeCursor) == 0) {
      soundPort->auxDrainWriteCursorBytes = static_cast<std::int32_t>(writeCursor);
      soundPort->auxDrainReadCursorBytes = static_cast<std::int32_t>(playCursor);
    } else {
      soundPort->auxDrainWriteCursorBytes = 0;
      soundPort->auxDrainReadCursorBytes = 0;
    }

    IDirectSoundBuffer* const previousPrimary = soundPort->primaryBuffer;
    soundPort->primaryBuffer = soundPort->secondaryBuffer;
    soundPort->secondaryBuffer = previousPrimary;

    soundPort->auxDrainAccumulatedBytes = 0;
    soundPort->auxDrainPending = 1;
    soundPort->auxSwapPending = 0;
  }

  /**
   * Address: 0x00B17370 (FUN_00B17370, sub_B17370)
   *
   * What it does:
   * Zero-fills one pending aux-drain region on secondary buffer and clears
   * drain-pending flag after one full per-port buffer window.
   */
  [[maybe_unused]] void SofdecDrainAuxBufferToSilence(moho::SofdecSoundPort* const soundPort)
  {
    DWORD playCursor = 0;
    DWORD writeCursor = 0;
    if (soundPort->secondaryBuffer->lpVtbl->GetCurrentPosition(soundPort->secondaryBuffer, &playCursor, &writeCursor) != 0) {
      return;
    }

    std::int32_t pendingBytes = 0;
    if (writeCursor < static_cast<DWORD>(soundPort->auxDrainReadCursorBytes)) {
      pendingBytes = static_cast<std::int32_t>(writeCursor)
                     + (static_cast<std::int32_t>(gSofdecPortBufferBytesPerChannel) * soundPort->channelCountPrimary)
                     - soundPort->auxDrainReadCursorBytes;
    } else {
      pendingBytes = static_cast<std::int32_t>(writeCursor) - soundPort->auxDrainReadCursorBytes;
    }

    if (pendingBytes > 0) {
      void* lockRegion0 = nullptr;
      DWORD lockBytes0 = 0;
      void* lockRegion1 = nullptr;
      DWORD lockBytes1 = 0;

      const std::int32_t lockResult = soundPort->secondaryBuffer->lpVtbl->Lock(
        soundPort->secondaryBuffer,
        static_cast<DWORD>(soundPort->auxDrainReadCursorBytes),
        static_cast<DWORD>(pendingBytes),
        &lockRegion0,
        &lockBytes0,
        &lockRegion1,
        &lockBytes1,
        0
      );
      if (lockResult != 0 && SofdecRestoreBufferIfLost(soundPort->secondaryBuffer, lockResult) == 0) {
        CRIERR_CallErr(kSofdecErrLockFailed);
        return;
      }

      if (lockRegion0 != nullptr) {
        std::memset(lockRegion0, 0, lockBytes0);
      }
      if (lockRegion1 != nullptr) {
        std::memset(lockRegion1, 0, lockBytes1);
      }

      (void)soundPort->secondaryBuffer->lpVtbl->Unlock(
        soundPort->secondaryBuffer,
        lockRegion0,
        lockBytes0,
        lockRegion1,
        lockBytes1
      );

      soundPort->auxDrainReadCursorBytes = static_cast<std::int32_t>(writeCursor);
      soundPort->auxDrainAccumulatedBytes += static_cast<std::int32_t>(lockBytes0 + lockBytes1);
    }

    const std::int32_t fullWindowBytes = static_cast<std::int32_t>(gSofdecPortBufferBytesPerChannel)
                                         * soundPort->channelCountPrimary;
    if (soundPort->auxDrainAccumulatedBytes > fullWindowBytes) {
      soundPort->auxDrainPending = 0;
    }
  }

  /**
   * Address: 0x00B17680 (FUN_00B17680, SofDecVirt2_Func20)
   *
   * What it does:
   * Marks one sound-port lane to reset playback cursor on next update.
   */
  [[maybe_unused]] moho::SofdecSoundPort* SofdecMarkPlaybackCursorResetPending(moho::SofdecSoundPort* const soundPort)
  {
    soundPort->playbackCursorResetPending = 1;
    return soundPort;
  }

  /**
   * Address: 0x00B17690 (FUN_00B17690, SofDecVirt2_Func21)
   *
   * What it does:
   * Returns constant support flag `1` for optional Sofdec control lane.
   */
  [[maybe_unused]] std::int32_t SofdecControlLaneIsSupported()
  {
    return 1;
  }

  /**
   * Address: 0x00B176A0 (FUN_00B176A0, SofDecVirt2_Func22)
   *
   * What it does:
   * Clears one optional control output lane and returns success.
   */
  [[maybe_unused]] std::int32_t SofdecControlLaneQueryValue(
    const std::int32_t contextLane,
    const std::int32_t queryLane,
    std::int32_t* const outValue
  )
  {
    (void)contextLane;
    (void)queryLane;
    *outValue = 0;
    return 0;
  }

  /**
   * Address: 0x00B176B0 (FUN_00B176B0, SofDecVirt2_Func23)
   *
   * What it does:
   * No-op optional control lane; always returns success.
   */
  [[maybe_unused]] std::int32_t SofdecControlLaneNoOp()
  {
    return 0;
  }

  /**
   * Address: 0x00B176D0 (FUN_00B176D0, sub_B176D0)
   *
   * What it does:
   * Updates global per-channel Sofdec port buffer size when positive.
   */
  [[maybe_unused]] std::int32_t SofdecSetPortBufferBytesPerChannel(const std::int32_t bytesPerChannel)
  {
    if (bytesPerChannel > 0) {
      gSofdecPortBufferBytesPerChannel = static_cast<std::uint32_t>(bytesPerChannel);
    }
    return bytesPerChannel;
  }

  /**
   * Address: 0x00B176E0 (FUN_00B176E0, sub_B176E0)
   *
   * What it does:
   * Returns current global per-channel Sofdec port buffer size.
   */
  [[maybe_unused]] std::int32_t SofdecGetPortBufferBytesPerChannel()
  {
    return static_cast<std::int32_t>(gSofdecPortBufferBytesPerChannel);
  }

  /**
   * Address: 0x00B176F0 (FUN_00B176F0, sub_B176F0)
   *
   * What it does:
   * Sets global Sofdec mono-routing mode lane.
   */
  [[maybe_unused]] std::int32_t SofdecSetMonoRoutingMode(const std::int32_t monoRoutingMode)
  {
    gSofdecMonoRoutingMode = monoRoutingMode;
    return monoRoutingMode;
  }

  /**
   * Address: 0x00B17700 (FUN_00B17700, sub_B17700)
   *
   * What it does:
   * Returns global Sofdec mono-routing mode lane.
   */
  [[maybe_unused]] std::int32_t SofdecGetMonoRoutingMode()
  {
    return gSofdecMonoRoutingMode;
  }

  /**
   * Address: 0x00B17710 (FUN_00B17710, sub_B17710)
   *
   * What it does:
   * Sets global Sofdec buffer-placement mode lane.
   */
  [[maybe_unused]] std::int32_t SofdecSetBufferPlacementMode(const std::int32_t bufferPlacementMode)
  {
    gSofdecBufferPlacementMode = bufferPlacementMode;
    return bufferPlacementMode;
  }

  /**
   * Address: 0x00B0C9F0 (FUN_00B0C9F0, _SVM_TestAndSet)
   *
   * What it does:
   * Writes `1` into one signal lane under Sofdec lock semantics and returns
   * whether the lane was not already set.
   */
  BOOL SVM_TestAndSet(std::int32_t* const signalLane)
  {
    if (gSofdecTestAndSetOverride != nullptr) {
      return gSofdecTestAndSetOverride(signalLane);
    }

    SVM_Lock();
    const std::int32_t previousValue = *signalLane;
    *signalLane = 1;
    const BOOL changed = (previousValue != 1) ? TRUE : FALSE;
    SVM_Unlock();
    return changed;
  }

  /**
   * Address: 0x00B10060 (FUN_00B10060, _adxstm_test_and_set)
   *
   * What it does:
   * ADXSTM thunk wrapper around `SVM_TestAndSet`.
   */
  BOOL adxstm_test_and_set(std::int32_t* const signalLane)
  {
    return SVM_TestAndSet(signalLane);
  }

  /**
   * Address: 0x00B1F270 (FUN_00B1F270, j_func_SofdecSetTrue_1)
   *
   * What it does:
   * Forwards one signal lane to `_SVM_TestAndSet`.
   */
  BOOL SofdecSetTrueThunk(std::int32_t* const signalLane)
  {
    return SVM_TestAndSet(signalLane);
  }

  /**
   * Address: 0x00B07410 (FUN_00B07410, func_AdxmSetInterval1)
   *
   * What it does:
   * Sets ADXM interval lane #1 and returns the previous interval value.
   */
  std::int32_t ADXM_SetInterval1(const std::int32_t interval)
  {
    const std::int32_t previousValue = gAdxmInterval1;
    gAdxmInterval1 = interval;
    return previousValue;
  }

  /**
   * Address: 0x00B13F90 (FUN_00B13F90, j_func_sofdecSetInterval1)
   *
   * What it does:
   * Forwards interval update to `ADXM_SetInterval1`.
   */
  std::int32_t ADXM_SetInterval1Thunk(const std::int32_t interval)
  {
    return ADXM_SetInterval1(interval);
  }

  /**
   * Address: 0x00B07420 (FUN_00B07420, sub_B07420)
   *
   * What it does:
   * Returns current ADXM interval lane #1.
   */
  std::int32_t ADXM_GetInterval1()
  {
    return gAdxmInterval1;
  }

  /**
   * Address: 0x00B13FA0 (FUN_00B13FA0, sub_B13FA0)
   *
   * What it does:
   * Forwards ADXM interval lane #1 query to `ADXM_GetInterval1`.
   */
  std::int32_t ADXM_GetInterval1Thunk()
  {
    return ADXM_GetInterval1();
  }

  /**
   * Address: 0x00B074B0 (FUN_00B074B0, func_SofdecSetFunc1)
   *
   * What it does:
   * Publishes frame-read callback after signal acquisition handshake.
   */
  std::int32_t SofdecSetFrameReadCallback(std::uint32_t(__cdecl* const callback)())
  {
    const std::int32_t acquired = SofdecWaitForSignal2(gSofdecSignalLane2);
    if (acquired == 0) {
      return 0;
    }

    gSofdecFrameReadCallback = callback;
    SofdecSignalReleaseNoOp(gSofdecSignalLane2);
    return 1;
  }

  /**
   * Address: 0x00B074F0 (FUN_00B074F0, sub_B074F0)
   *
   * What it does:
   * Sets ADXM interval lane #2 and returns the written value.
   */
  std::int32_t ADXM_SetInterval2(const std::int32_t interval)
  {
    gAdxmInterval2 = interval;
    return interval;
  }

  /**
   * Address: 0x00B13F80 (FUN_00B13F80, sub_B13F80)
   *
   * What it does:
   * Forwards ADXM interval lane #2 update to `ADXM_SetInterval2`.
   */
  std::int32_t ADXM_SetInterval2Thunk(std::int32_t interval)
  {
    return ADXM_SetInterval2(interval);
  }

  /**
   * Address: 0x00B07500 (FUN_00B07500, func_SofdecSetScreenHeight2)
   *
   * What it does:
   * Sets Sofdec secondary screen-height lane and returns the written value.
   */
  std::int32_t SofdecSetScreenHeight2(const std::int32_t screenHeight)
  {
    gSofdecScreenHeight2 = screenHeight;
    return screenHeight;
  }

  /**
   * Address: 0x00B07870 (FUN_00B07870, func_SofdecWaitForSignal2)
   *
   * What it does:
   * Repeatedly tests-and-sets one local signal lane for up to 1000 retries.
   */
  std::int32_t SofdecWaitForSignal2(const std::int32_t signalLaneValue)
  {
    std::int32_t retries = 0;
    std::int32_t signalLane = signalLaneValue;
    while (SVM_TestAndSet(&signalLane) != TRUE) {
      Sleep(1u);
      ++retries;
      if (retries >= 1000) {
        return 0;
      }
    }

    return 1;
  }

  /**
   * Address: 0x00B078B0 (FUN_00B078B0, nullsub_30)
   *
   * What it does:
   * No-op signal-release callback lane.
   */
  void SofdecSignalReleaseNoOp(const std::int32_t signalLaneValue)
  {
    (void)signalLaneValue;
  }

  /**
   * Address: 0x00B078C0 (FUN_00B078C0, sub_B078C0)
   *
   * What it does:
   * Applies global scanline offset with underflow handling used by timing lanes.
   */
  std::uint32_t SofdecApplyScanlineOffset(std::uint32_t* const valueInOut, const std::uint32_t clampMax)
  {
    std::uint32_t result = static_cast<std::uint32_t>(gSofdecScanlineOffset);
    if (gSofdecScanlineOffset != 0) {
      result = *valueInOut;
      if (*valueInOut < clampMax) {
        if (gSofdecScanlineOffset >= 0) {
          *valueInOut = result + static_cast<std::uint32_t>(gSofdecScanlineOffset);
        } else {
          const std::uint32_t offsetMagnitude = 0u - static_cast<std::uint32_t>(gSofdecScanlineOffset);
          if (result >= offsetMagnitude) {
            *valueInOut = result + static_cast<std::uint32_t>(gSofdecScanlineOffset);
          } else {
            *valueInOut = 0xFFFFFFFFu;
          }
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00B07900 (FUN_00B07900, sub_B07900)
   *
   * What it does:
   * Sets global scanline offset lane and returns the written value.
   */
  std::int32_t SofdecSetScanlineOffset(const std::int32_t offset)
  {
    gSofdecScanlineOffset = offset;
    return offset;
  }

  /**
   * Address: 0x00B07430 (FUN_00B07430, sub_B07430)
   *
   * What it does:
   * Arms ADXM multimedia-timer switch lanes and returns previous state.
   */
  std::int32_t ADXM_ArmMultimediaTimerSwitch()
  {
    const std::int32_t previousState = gAdxmTimerSwitchState;
    if (gAdxmTimerSwitchState == 0) {
      gAdxmTimerSwitchSignal = 1;
      gAdxmTimerSwitchState = 1;
      return 1;
    }

    return previousState;
  }

  /**
   * Address: 0x00B07450 (FUN_00B07450, sub_B07450)
   *
   * What it does:
   * Disarms ADXM multimedia-timer switch lanes and starts 1ms multimedia timer.
   */
  void ADXM_StartMultimediaTimer()
  {
    if (gAdxmTimerSwitchState == 1) {
      gAdxmTimerSwitchState = 0;
      gAdxmTimerSwitchSignal = 0;
      timeBeginPeriod(1u);
      gAdxmMultimediaTimerId = timeSetEvent(1u, 0u, gAdxmMultimediaTimerCallback, 0u, 0u);
    }
  }

  /**
   * Address: 0x00B07490 (FUN_00B07490, sub_B07490)
   *
   * What it does:
   * Pulses ADXM sync event lane when present and returns event handle/result.
   */
  void* ADXM_PulseSyncEvent()
  {
    HANDLE result = gAdxmSyncEventHandle;
    if (gAdxmSyncEventHandle != nullptr) {
      result = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(PulseEvent(gAdxmSyncEventHandle)));
    }
    return result;
  }

  /**
   * Address: 0x00B13FB0 (FUN_00B13FB0, sub_B13FB0)
   *
   * What it does:
   * Thunk alias to `ADXM_ArmMultimediaTimerSwitch`.
   */
  [[maybe_unused]] std::int32_t ADXM_ArmMultimediaTimerSwitchThunk()
  {
    return ADXM_ArmMultimediaTimerSwitch();
  }

  /**
   * Address: 0x00B13FC0 (FUN_00B13FC0, sub_B13FC0)
   *
   * What it does:
   * Thunk alias to `ADXM_StartMultimediaTimer`.
   */
  [[maybe_unused]] void ADXM_StartMultimediaTimerThunk()
  {
    ADXM_StartMultimediaTimer();
  }

  /**
   * Address: 0x00B13FD0 (FUN_00B13FD0, sub_B13FD0)
   *
   * What it does:
   * Thunk alias to `ADXM_PulseSyncEvent`.
   */
  [[maybe_unused]] void* ADXM_PulseSyncEventThunk()
  {
    return ADXM_PulseSyncEvent();
  }

  /**
   * Address: 0x00B07750 (FUN_00B07750, sub_B07750)
   *
   * What it does:
   * Waits until current scanline reaches target window for one interval.
   */
  std::int32_t ADXM_WaitForScanlineTarget(const std::uint32_t interval, const std::uint32_t screenHeight)
  {
    std::uint32_t currentScanline = gSofdecFrameReadCallback();
    SofdecApplyScanlineOffset(&currentScanline, screenHeight);

    std::uint32_t boundedScanline = currentScanline;
    if (currentScanline > screenHeight) {
      boundedScanline = 0;
      currentScanline = 0;
    }

    const std::int32_t spinThresholdMicroseconds = AdxmComputeSpinThresholdMicroseconds(interval, screenHeight);
    const std::int32_t sleepMilliseconds = AdxmComputeSleepMilliseconds(interval, screenHeight, boundedScanline);
    if (sleepMilliseconds > 1) {
      timeBeginPeriod(1u);
      Sleep(static_cast<DWORD>(sleepMilliseconds));
      (void)timeEndPeriod(1u);
      boundedScanline = currentScanline;
    }

    if (boundedScanline < screenHeight) {
      LARGE_INTEGER spinStart{};
      LARGE_INTEGER spinEnd{};
      do {
        QueryPerformanceCounter(&spinStart);
        do {
          QueryPerformanceCounter(&spinEnd);
        } while (AdxmElapsedMicroseconds(spinStart, spinEnd, gAdxmPerformanceFrequency) < spinThresholdMicroseconds);

        currentScanline = gSofdecFrameReadCallback();
        SofdecApplyScanlineOffset(&currentScanline, screenHeight);
      } while (
        currentScanline <= screenHeight && currentScanline >= (screenHeight >> 1u) && currentScanline < screenHeight
      );
    }

    return static_cast<std::int32_t>(currentScanline);
  }

  /**
   * Address: 0x00B07A70 (FUN_00B07A70, sub_B07A70)
   *
   * What it does:
   * Waits until scanline drops to lower-half window for current interval.
   */
  std::uint32_t ADXM_WaitForScanlineHalfWindow(const std::uint32_t interval, const std::uint32_t screenHeight)
  {
    std::uint32_t currentScanline = gSofdecFrameReadCallback();
    SofdecApplyScanlineOffset(&currentScanline, screenHeight);

    std::uint32_t boundedScanline = currentScanline;
    if (currentScanline > screenHeight) {
      boundedScanline = 0;
    }

    const std::int32_t spinThresholdMicroseconds = AdxmComputeSpinThresholdMicroseconds(interval, screenHeight);
    const std::int32_t sleepMilliseconds = AdxmComputeSleepMilliseconds(interval, screenHeight, boundedScanline);
    if (sleepMilliseconds > 1) {
      timeBeginPeriod(1u);
      Sleep(static_cast<DWORD>(sleepMilliseconds));
      (void)timeEndPeriod(1u);
    }

    const std::uint32_t halfHeight = screenHeight >> 1u;
    LARGE_INTEGER spinStart{};
    LARGE_INTEGER spinEnd{};
    while (true) {
      currentScanline = gSofdecFrameReadCallback();
      SofdecApplyScanlineOffset(&currentScanline, screenHeight);
      if (currentScanline <= halfHeight) {
        break;
      }

      QueryPerformanceCounter(&spinStart);
      do {
        QueryPerformanceCounter(&spinEnd);
      } while (AdxmElapsedMicroseconds(spinStart, spinEnd, gAdxmPerformanceFrequency) < spinThresholdMicroseconds);
    }

    return currentScanline;
  }

  /**
   * Address: 0x00B07910 (FUN_00B07910, sub_B07910)
   *
   * What it does:
   * Updates ADXM scanline synchronization for active callback lane.
   */
  std::int32_t ADXM_UpdateScanlineSync()
  {
    if (gSofdecFrameReadCallback == nullptr) {
      if (gAdxmSyncEventHandle != nullptr) {
        WaitForSingleObject(gAdxmSyncEventHandle, INFINITE);
      }
      return static_cast<std::int32_t>(QueryPerformanceCounter(&gAdxmLastSyncCounter));
    }

    std::int32_t result = gAdxmInterval1;
    if (gAdxmInterval1 == 0) {
      return result;
    }

    if (gAdxmPerformanceFrequency == 0) {
      LARGE_INTEGER frequency{};
      QueryPerformanceFrequency(&frequency);
      gAdxmPerformanceFrequency = frequency.QuadPart;
    }

    result = SofdecWaitForSignal2(gSofdecSignalLane2);
    if (result == 0) {
      return result;
    }

    if (gSofdecFrameReadCallback != nullptr) {
      std::uint32_t currentScanline = gSofdecFrameReadCallback();
      SofdecApplyScanlineOffset(&currentScanline, static_cast<std::uint32_t>(gSofdecScreenHeight2));
      const std::uint32_t halfHeight = static_cast<std::uint32_t>(gSofdecScreenHeight2) >> 1u;

      if (currentScanline < halfHeight) {
        QueryPerformanceCounter(&gAdxmProbeCounter);
        const std::int64_t elapsedMicroseconds =
          (1000000LL * (gAdxmLastSyncCounter.QuadPart - gAdxmProbeCounter.QuadPart)) / gAdxmPerformanceFrequency;
        const std::int32_t halfIntervalMicroseconds = static_cast<std::int32_t>((100000000u / gAdxmInterval1) >> 1u);
        if (elapsedMicroseconds < halfIntervalMicroseconds) {
          (void)ADXM_WaitForScanlineHalfWindow(
            static_cast<std::uint32_t>(gAdxmInterval1), static_cast<std::uint32_t>(gSofdecScreenHeight2)
          );
        }
      } else {
        (void)ADXM_WaitForScanlineHalfWindow(
          static_cast<std::uint32_t>(gAdxmInterval1), static_cast<std::uint32_t>(gSofdecScreenHeight2)
        );
      }
    }

    return static_cast<std::int32_t>(QueryPerformanceCounter(&gAdxmLastSyncCounter));
  }

  /**
   * Address: 0x00B07C90 (FUN_00B07C90, j_func_NewThread)
   *
   * What it does:
   * Forwards thread creation to CRT `_beginthreadex`.
   */
  HANDLE ADXM_BeginThreadThunk(
    LPSECURITY_ATTRIBUTES threadAttributes,
    const SIZE_T stackSizeBytes,
    unsigned(__stdcall* threadEntry)(void*),
    void* threadArgument,
    const DWORD creationFlags,
    LPDWORD threadId
  )
  {
    return reinterpret_cast<HANDLE>(
      _beginthreadex(
        threadAttributes,
        static_cast<unsigned>(stackSizeBytes),
        threadEntry,
        threadArgument,
        static_cast<unsigned>(creationFlags),
        reinterpret_cast<unsigned*>(threadId)
      )
    );
  }

  /**
   * Address: 0x00B207F0 (adxrna_Init)
   *
   * What it does:
   * Clears active lanes for all fixed RNA timing-node pool slots.
   */
  moho::AdxrnaTimingState* adxrna_Init()
  {
    (void)kRnaVersionBanner;
    return ResetAdxrnaTimingPoolActiveFlags();
  }

  /**
   * Address: 0x00B20820 (SofDecVirt1::Func2)
   *
   * What it does:
   * Clears active lanes for all fixed RNA timing-node pool slots.
   */
