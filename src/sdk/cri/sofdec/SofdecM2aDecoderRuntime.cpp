  /**
   * Address: 0x00B23510 (_M2ADEC_Initialize)
   *
   * What it does:
   * Initializes M2A decoder dependency runtimes.
   */
  std::int32_t M2ADEC_Initialize()
  {
    M2ABSR_Initialize();
    M2AHUFFMAN_Initialize();
    M2AIMDCT_Initialize();
    return 0;
  }

  /**
   * Address: 0x00B23530 (_M2ADEC_Finalize)
   *
   * What it does:
   * Finalizes M2A decoder dependency runtimes.
   */
  std::int32_t M2ADEC_Finalize()
  {
    M2ABSR_Finalize();
    M2AHUFFMAN_Finalize();
    M2AIMDCT_Finalize();
    return 0;
  }

  /**
   * Address: 0x00B23550 (_M2ADEC_Create)
   *
   * What it does:
   * Allocates and initializes one M2A decoder context and bitstream object.
   */
  std::int32_t __cdecl M2ADEC_Create(const std::int32_t heapManagerHandle, M2aDecoderContext** outContext)
  {
    if (outContext == nullptr) {
      return -1;
    }

    *outContext = nullptr;

    auto* const context = static_cast<M2aDecoderContext*>(
      M2aAllocFromHeap(heapManagerHandle, kM2aDecoderContextSize)
    );
    if (context == nullptr) {
      return -1;
    }

    m2adec_clear(context, kM2aDecoderContextSize);

    std::int32_t* bitstream = nullptr;
    if (M2ABSR_Create(heapManagerHandle, &bitstream) >= 0 && bitstream != nullptr) {
      M2ADEC_Reset(context);
      auto* const contextWords = M2aContextWords(context);
      contextWords[kM2aContextHeapManagerIndex] = heapManagerHandle;
      contextWords[9] = M2aPtrToWord(bitstream);
      *outContext = context;
      return 0;
    }

    M2aFreeHeapAllocation(heapManagerHandle, context);
    return -1;
  }

  /**
   * Address: 0x00B235D0 (_M2ADEC_Destroy)
   *
   * What it does:
   * Destroys one M2A decoder context and releases all owned allocations.
   */
  std::int32_t __cdecl M2ADEC_Destroy(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    auto* const contextWords = M2aContextWords(context);
    const auto heapManagerHandle = contextWords[kM2aContextHeapManagerIndex];

    auto* const bitstream = M2aWordToPtr<std::int32_t>(contextWords[9]);
    if (bitstream != nullptr) {
      M2ABSR_Destroy(bitstream);
      contextWords[9] = 0;
    }

    M2ADEC_Reset(context);
    M2aFreeHeapAllocation(heapManagerHandle, context);
    return 0;
  }

  /**
   * Address: 0x00B23610 (_M2ADEC_Start)
   *
   * What it does:
   * Starts decoding by stopping any active run, resetting context, then
   * switching decoder state to running.
   */
  std::int32_t __cdecl M2ADEC_Start(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    std::int32_t currentStatus = 0;
    M2ADEC_GetStatus(context, &currentStatus);
    if (currentStatus != 0) {
      M2ADEC_Stop(context);
    }

    M2ADEC_Reset(context);
    M2aContextWords(context)[kM2aContextStatusIndex] = 1;
    return 0;
  }

  /**
   * Address: 0x00B23660 (_M2ADEC_Stop)
   *
   * What it does:
   * Stops decoding by clearing running status lane.
   */
  std::int32_t __cdecl M2ADEC_Stop(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    M2aContextWords(context)[kM2aContextStatusIndex] = 0;
    return 0;
  }

  /**
   * Address: 0x00B23680 (_M2ADEC_Reset)
   *
   * What it does:
   * Releases all transient M2A decode allocations and restores base runtime
   * control lanes.
   */
  std::int32_t __cdecl M2ADEC_Reset(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    auto* const contextWords = M2aContextWords(context);
    const auto heapManagerHandle = contextWords[kM2aContextHeapManagerIndex];

    auto* scratchMapping = M2aWordToPtr<void>(contextWords[kM2aContextScratchMappingIndex]);
    if (scratchMapping != nullptr) {
      m2adec_clear(scratchMapping, kM2aScratchMappingBytes);
      M2aFreeHeapAllocation(heapManagerHandle, scratchMapping);
      contextWords[kM2aContextScratchMappingIndex] = 0;
    }

    auto* pceMap = M2aWordToPtr<void>(contextWords[kM2aContextPceMapIndex]);
    if (pceMap != nullptr) {
      m2adec_clear(pceMap, kM2aPceMapBytes);
      M2aFreeHeapAllocation(heapManagerHandle, pceMap);
      contextWords[kM2aContextPceMapIndex] = 0;
    }

    for (std::int32_t index = 0; index < kM2aLocationEntryCapacity; ++index) {
      const auto laneIndex = kM2aContextLocationEntryBaseIndex + index;
      auto* const locationEntry = M2aWordToPtr<void>(contextWords[laneIndex]);
      if (locationEntry != nullptr) {
        m2adec_clear(locationEntry, kM2aLocationEntrySize);
        M2aFreeHeapAllocation(heapManagerHandle, locationEntry);
        contextWords[laneIndex] = 0;
      }
    }

    for (std::int32_t slotIndex = 0; slotIndex < kM2aDecoderSlotCount; ++slotIndex) {
      const auto icsLaneIndex = kM2aContextIcsTableBaseIndex + slotIndex;
      auto* const icsLane = M2aWordToPtr<void>(contextWords[icsLaneIndex]);
      if (icsLane != nullptr) {
        m2adec_clear(icsLane, kM2aIcsInfoSize);
        M2aFreeHeapAllocation(heapManagerHandle, icsLane);
        contextWords[icsLaneIndex] = 0;
      }

      const auto decodeStateIndex = kM2aContextPrimaryStateBaseIndex + slotIndex;
      auto* const decodeState = M2aWordToPtr<void>(contextWords[decodeStateIndex]);
      if (decodeState != nullptr) {
        m2adec_clear(decodeState, kM2aDecodeStateSize);
        M2aFreeHeapAllocation(heapManagerHandle, decodeState);
        contextWords[decodeStateIndex] = 0;
      }
    }

    auto* const bitstream = M2aWordToPtr<std::uint32_t>(contextWords[9]);
    if (bitstream != nullptr) {
      M2ABSR_Reset(bitstream);
    }

    contextWords[kM2aContextStatusIndex] = 0;
    contextWords[kM2aContextErrorCodeIndex] = 0;
    contextWords[kM2aContextInputBufferIndex] = 0;
    contextWords[kM2aContextInputByteCountIndex] = 0;
    contextWords[kM2aContextElementIndex] = 0;
    contextWords[kM2aContextWindowGroupIndex] = 0;
    contextWords[kM2aContextElementCounterIndex] = 0;
    contextWords[kM2aContextElementCounterLimitIndex] = 0;
    contextWords[kM2aContextFrameCounterIndex] = 0;
    contextWords[kM2aContextEndModeIndex] = 0;
    contextWords[17] = 0;
    contextWords[kM2aContextAudioObjectTypeIndex] = 1;
    contextWords[kM2aContextSampleRateIndex] = 0;
    contextWords[kM2aContextSampleRateTableIndex] = 0;
    contextWords[22] = 0;
    contextWords[kM2aContextDecodedChannelCountIndex] = 0;
    contextWords[kM2aContextDecodeCountInitializedIndex] = 0;
    contextWords[24] = 0;
    return 0;
  }

  /**
   * Address: 0x00B237F0 (_M2ADEC_GetStatus)
   *
   * What it does:
   * Reads current M2A decoder run-state lane.
   */
  std::int32_t __cdecl M2ADEC_GetStatus(M2aDecoderContext* context, std::int32_t* outStatus)
  {
    if (context == nullptr || outStatus == nullptr) {
      return -1;
    }

    *outStatus = M2aContextWords(context)[kM2aContextStatusIndex];
    return 0;
  }

  /**
   * Address: 0x00B23810 (_M2ADEC_GetErrorCode)
   *
   * What it does:
   * Reads current M2A decoder error-code lane.
   */
  std::int32_t __cdecl M2ADEC_GetErrorCode(M2aDecoderContext* context, std::int32_t* outErrorCode)
  {
    if (context == nullptr || outErrorCode == nullptr) {
      return -1;
    }

    *outErrorCode = M2aContextWords(context)[kM2aContextErrorCodeIndex];
    return 0;
  }

  /**
   * Address: 0x00B23830 (_M2ADEC_Process)
   *
   * What it does:
   * Decodes one AAC packet payload, updates frame/end bookkeeping lanes, and
   * reports consumed source bytes.
   */
  std::int32_t __cdecl M2ADEC_Process(
    M2aDecoderContext* context,
    const std::int32_t sourceAddress,
    const std::int32_t sourceBytes,
    std::int32_t* outConsumedBytes
  )
  {
    if (context == nullptr || sourceAddress == 0 || outConsumedBytes == nullptr) {
      return -1;
    }

    *outConsumedBytes = 0;
    auto* const contextWords = M2aContextWords(context);
    if (contextWords[kM2aContextStatusIndex] != 1) {
      return 0;
    }

    if (contextWords[kM2aContextEndModeIndex] == 1 && sourceBytes < 2) {
      contextWords[kM2aContextStatusIndex] = 2;
    }

    contextWords[kM2aContextInputByteCountIndex] = sourceBytes;
    contextWords[kM2aContextInputBufferIndex] = sourceAddress;
    M2ABSR_SetBuffer(
      M2aWordToPtr<std::uint32_t>(contextWords[kM2aContextBitstreamHandleIndex]),
      sourceAddress,
      sourceBytes
    );

    if (m2adec_decode_header(context) < 0) {
      return m2adec_find_sync_offset(context, outConsumedBytes);
    }

    std::int32_t decodeStatus = m2adec_decode_elements(context);
    if (decodeStatus < 0) {
      return m2adec_find_sync_offset(context, outConsumedBytes);
    }

    std::int32_t overrunFlag = 0;
    M2ABSR_Overruns(contextWords[kM2aContextBitstreamHandleIndex], &overrunFlag);
    if (overrunFlag == 1) {
      if (contextWords[kM2aContextEndModeIndex] == 1) {
        *outConsumedBytes = contextWords[kM2aContextInputByteCountIndex];
        contextWords[kM2aContextStatusIndex] = 2;
      } else {
        contextWords[kM2aContextPendingSupplyIndex] = 1;
        std::int32_t bitPosition = 0;
        M2ABSR_Tell(contextWords[kM2aContextBitstreamHandleIndex], &bitPosition);
        *outConsumedBytes = bitPosition / 8;
        contextWords[kM2aContextInputBitRemainderIndex] = bitPosition % 8;
      }

      return decodeStatus;
    }

    contextWords[kM2aContextPendingSupplyIndex] = 0;
    if (contextWords[kM2aContextWindowGroupIndex] != kM2aElementIdEnd) {
      return 0;
    }

    decodeStatus = m2adec_decode_pcm(context);
    if (decodeStatus < 0) {
      return decodeStatus;
    }

    M2ABSR_AlignToByteBoundary(contextWords[kM2aContextBitstreamHandleIndex]);

    std::int32_t bitPosition = 0;
    M2ABSR_Tell(contextWords[kM2aContextBitstreamHandleIndex], &bitPosition);

    if (contextWords[kM2aContextHeaderTypeIndex] == 2) {
      if (contextWords[kM2aContextElementCounterLimitIndex] != 0) {
        contextWords[kM2aContextElementCounterIndex] += bitPosition / -8;
        --contextWords[kM2aContextElementCounterLimitIndex];
      } else {
        M2ABSR_Seek(
          contextWords[kM2aContextBitstreamHandleIndex],
          8 * contextWords[kM2aContextElementCounterIndex],
          0
        );
      }
    }

    ++contextWords[kM2aContextFrameCounterIndex];
    if (contextWords[kM2aContextLayoutInitializedIndex] == 0) {
      m2adec_specify_location(context);
      contextWords[kM2aContextLayoutInitializedIndex] = 1;
    }

    *outConsumedBytes = bitPosition / 8;
    if (contextWords[kM2aContextEndModeIndex] == 1) {
      std::int32_t isEndOfBuffer = 0;
      M2ABSR_IsEndOfBuffer(contextWords[kM2aContextBitstreamHandleIndex], &isEndOfBuffer);
      if (isEndOfBuffer == 1) {
        contextWords[kM2aContextStatusIndex] = 2;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B23A30 (sub_B23A30)
   *
   * What it does:
   * Returns pending input-supply flag for one M2A decode context.
   */
  std::int32_t __cdecl M2ADEC_GetPendingSupply(M2aDecoderContext* context, std::int32_t* outPendingSupply)
  {
    if (context == nullptr || outPendingSupply == nullptr) {
      return -1;
    }

    *outPendingSupply = M2aContextWords(context)[kM2aContextPendingSupplyIndex];
    return 0;
  }

  /**
   * Address: 0x00B23A50 (_M2ADEC_BeginFlush)
   *
   * What it does:
   * Enables end/flush mode for one M2A decode context.
   */
  std::int32_t __cdecl M2ADEC_BeginFlush(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    M2aContextWords(context)[kM2aContextEndModeIndex] = 1;
    return 0;
  }

  /**
   * Address: 0x00B23A70 (_M2ADEC_GetNumFramesDecoded)
   *
   * What it does:
   * Returns decoded-frame counter lane from one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetNumFramesDecoded(M2aDecoderContext* context, std::int32_t* outFrameCount)
  {
    if (context == nullptr || outFrameCount == nullptr) {
      return -1;
    }

    *outFrameCount = M2aContextWords(context)[kM2aContextFrameCounterIndex];
    return 0;
  }

  /**
   * Address: 0x00B23A90 (_M2ADEC_GetNumSamplesDecoded)
   *
   * What it does:
   * Returns decoded PCM sample count derived from decoded frame count.
   */
  std::int32_t __cdecl M2ADEC_GetNumSamplesDecoded(M2aDecoderContext* context, std::int32_t* outSampleCount)
  {
    if (context == nullptr || outSampleCount == nullptr) {
      return -1;
    }

    const auto frameCount = M2aContextWords(context)[kM2aContextFrameCounterIndex];
    if (frameCount > 2) {
      *outSampleCount = (frameCount - 2) << 10;
    } else {
      *outSampleCount = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00B23AC0 (_M2ADEC_GetProfile)
   *
   * What it does:
   * Reports fixed AAC profile code used by this decoder lane.
   */
  std::int32_t __cdecl M2ADEC_GetProfile(M2aDecoderContext* context, std::int32_t* outProfile)
  {
    if (context == nullptr || outProfile == nullptr) {
      return -1;
    }

    *outProfile = kM2aMainProfile;
    return 0;
  }

  /**
   * Address: 0x00B23AE0 (_M2ADEC_GetFrequency)
   *
   * What it does:
   * Returns configured sample-rate lane for one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetFrequency(M2aDecoderContext* context, std::int32_t* outFrequency)
  {
    if (context == nullptr || outFrequency == nullptr) {
      return -1;
    }

    *outFrequency = M2aContextWords(context)[kM2aContextSampleRateIndex];
    return 0;
  }

  /**
   * Address: 0x00B23B00 (_M2ADEC_GetNumChannels)
   *
   * What it does:
   * Returns configured decoded-channel count for one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetNumChannels(M2aDecoderContext* context, std::int32_t* outChannelCount)
  {
    if (context == nullptr || outChannelCount == nullptr) {
      return -1;
    }

    *outChannelCount = M2aContextWords(context)[kM2aContextDecodedChannelCountIndex];
    return 0;
  }

  /**
   * Address: 0x00B23B20 (_M2ADEC_GetChannelConfiguration)
   *
   * What it does:
   * Returns ADTS channel-configuration lane for one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetChannelConfiguration(
    M2aDecoderContext* context,
    std::int32_t* outChannelConfiguration
  )
  {
    if (context == nullptr || outChannelConfiguration == nullptr) {
      return -1;
    }

    *outChannelConfiguration = M2aContextWords(context)[kM2aContextChannelConfigurationIndex];
    return 0;
  }

  /**
   * Address: 0x00B23B40 (_M2ADEC_GetPcm)
   *
   * What it does:
   * Exports one decoded PCM channel from active decode-state windows.
   */
  std::int32_t __cdecl M2ADEC_GetPcm(
    M2aDecoderContext* context,
    std::int32_t channelIndex,
    const std::int32_t destinationAddress
  )
  {
    if (context == nullptr || destinationAddress == 0) {
      return -1;
    }

    std::int32_t selectedChannel = channelIndex;
    for (std::int32_t entryIndex = 0; entryIndex < kM2aLocationEntryCapacity; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      if (locationEntry->channelClass == 0) {
        if (selectedChannel == 0) {
          const auto groupedSlot = locationEntry->channelPairType + (32 * locationEntry->channelClass);
          auto* const decodeState = M2aGetPrimaryStateBySlot(context, groupedSlot);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          m2adec_convert_to_pcm16(M2aGetDecodeStatePcmWindow(decodeState), destinationAddress);
        }

        --selectedChannel;
        continue;
      }

      if (locationEntry->channelClass == 1) {
        if (selectedChannel == 0) {
          auto* const decodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          m2adec_convert_to_pcm16(M2aGetDecodeStatePcmWindow(decodeState), destinationAddress);
        }

        if (selectedChannel == 1) {
          auto* const decodeState = M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          m2adec_convert_to_pcm16(M2aGetDecodeStatePcmWindow(decodeState), destinationAddress);
        }

        selectedChannel -= 2;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B23C20 (_M2ADEC_GetDownmixedPcm)
   *
   * What it does:
   * Builds one downmixed PCM lane from multi-channel decode-state windows.
   */
  std::int32_t __cdecl M2ADEC_GetDownmixedPcm(
    M2aDecoderContext* context,
    const std::int32_t outputChannelIndex,
    const std::int32_t destinationAddress
  )
  {
    if (context == nullptr || destinationAddress == 0 || outputChannelIndex > 2) {
      return -1;
    }

    if (M2aContextWords(context)[kM2aContextDecodedChannelCountIndex] <= 2) {
      return M2ADEC_GetPcm(context, outputChannelIndex, destinationAddress);
    }

    float downmixScale = kM2aMonoDownmixScale;
    auto* const pceMapWords = M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPceMapIndex]);
    if (pceMapWords != nullptr) {
      downmixScale = m2asjd_downmix_table[pceMapWords[kM2aPceMixdownTableIndex]];
    }

    m2adec_clear(m2asjd_downmix_buffer, kM2aDownmixBufferBytes);

    const bool useSecondaryChannel = outputChannelIndex != 0;
    for (std::int32_t entryIndex = 0; entryIndex < kM2aLocationEntryCapacity; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      if (locationEntry->channelClass == 1) {
        auto* const decodeState = useSecondaryChannel
                                    ? M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType)
                                    : M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
        if (!M2aHasReadyPcmWindow(decodeState)) {
          return -1;
        }

        const auto* const sourcePcm = M2aGetDecodeStatePcmWindow(decodeState);
        if (locationEntry->locationClass == 2) {
          M2aAccumulateScaledPcmWindow(m2asjd_downmix_buffer, sourcePcm, kM2aCenterDownmixScale);
        } else if (locationEntry->locationClass == 6) {
          M2aAccumulateScaledPcmWindow(m2asjd_downmix_buffer, sourcePcm, downmixScale);
        }
        continue;
      }

      if (locationEntry->channelClass == 0) {
        auto* const decodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
        if (!M2aHasReadyPcmWindow(decodeState)) {
          return -1;
        }

        M2aAccumulateScaledPcmWindow(
          m2asjd_downmix_buffer,
          M2aGetDecodeStatePcmWindow(decodeState),
          kM2aMonoDownmixScale
        );
      }
    }

    m2adec_convert_to_pcm16(m2asjd_downmix_buffer, destinationAddress);
    return 0;
  }

  /**
   * Address: 0x00B23DB0 (_M2ADEC_GetSurroundPcm)
   *
   * What it does:
   * Builds one surround-aware PCM lane using PCE surround mixdown metadata.
   */
  std::int32_t __cdecl M2ADEC_GetSurroundPcm(
    M2aDecoderContext* context,
    const std::int32_t outputChannelIndex,
    const std::int32_t destinationAddress
  )
  {
    if (context == nullptr || destinationAddress == 0 || outputChannelIndex > 2) {
      return -1;
    }

    if (M2aContextWords(context)[kM2aContextDecodedChannelCountIndex] <= 2) {
      return M2ADEC_GetPcm(context, outputChannelIndex, destinationAddress);
    }

    auto* const pceMapWords = M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPceMapIndex]);
    if (pceMapWords == nullptr || pceMapWords[kM2aPceSurroundMixdownEnabledIndex] == 0) {
      return M2ADEC_GetDownmixedPcm(context, outputChannelIndex, destinationAddress);
    }

    float surroundScale = m2asjd_downmix_table[pceMapWords[kM2aPceMixdownTableIndex]];
    if (outputChannelIndex == 0) {
      surroundScale *= -1.0f;
    }

    m2adec_clear(m2asjd_downmix_buffer, kM2aDownmixBufferBytes);

    const bool useSecondaryChannel = outputChannelIndex != 0;
    for (std::int32_t entryIndex = 0; entryIndex < kM2aLocationEntryCapacity; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      if (locationEntry->channelClass == 1) {
        if (locationEntry->locationClass == 2) {
          auto* const decodeState = useSecondaryChannel
                                      ? M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType)
                                      : M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          M2aAccumulateScaledPcmWindow(
            m2asjd_downmix_buffer,
            M2aGetDecodeStatePcmWindow(decodeState),
            kM2aCenterDownmixScale
          );
        } else if (locationEntry->locationClass == 6) {
          auto* const leftDecodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
          auto* const rightDecodeState = M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(leftDecodeState) || !M2aHasReadyPcmWindow(rightDecodeState)) {
            return -1;
          }

          M2aAccumulatePairedPcmWindow(
            m2asjd_downmix_buffer,
            M2aGetDecodeStatePcmWindow(leftDecodeState),
            M2aGetDecodeStatePcmWindow(rightDecodeState),
            surroundScale
          );
        }

        continue;
      }

      if (locationEntry->channelClass == 0) {
        auto* const decodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
        if (!M2aHasReadyPcmWindow(decodeState)) {
          return -1;
        }

        M2aAccumulateScaledPcmWindow(
          m2asjd_downmix_buffer,
          M2aGetDecodeStatePcmWindow(decodeState),
          kM2aMonoDownmixScale
        );
      }
    }

    m2adec_convert_to_pcm16(m2asjd_downmix_buffer, destinationAddress);
    return 0;
  }

  /**
   * Address: 0x00B23FC0 (_m2adec_malloc)
   *
   * What it does:
   * Allocates one decode helper block from heap-manager lane or process heap.
   */
  HANDLE __cdecl m2adec_malloc(std::int32_t heapManagerHandle, const SIZE_T byteCount)
  {
    if (heapManagerHandle != 0) {
      HEAPMNG_Allocate(heapManagerHandle, byteCount, &heapManagerHandle);
      return reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(heapManagerHandle))
      );
    }

    if (m2adec_global_heap != nullptr) {
      return HeapAlloc(m2adec_global_heap, 8u, byteCount);
    }

    m2adec_global_heap = GetProcessHeap();
    if (m2adec_global_heap != nullptr) {
      return HeapAlloc(m2adec_global_heap, 8u, byteCount);
    }

    return m2adec_global_heap;
  }

  /**
   * Address: 0x00B24010 (_m2adec_free)
   *
   * What it does:
   * Frees one decode helper block through heap-manager lane or process heap.
   */
  HANDLE __cdecl m2adec_free(const std::int32_t heapManagerHandle, LPVOID memoryBlock)
  {
    if (heapManagerHandle != 0) {
      return reinterpret_cast<HANDLE>(HEAPMNG_Free(heapManagerHandle, M2aPtrToWord(memoryBlock)));
    }

    if (m2adec_global_heap != nullptr) {
      return reinterpret_cast<HANDLE>(HeapFree(m2adec_global_heap, 0, memoryBlock));
    }

    m2adec_global_heap = GetProcessHeap();
    if (m2adec_global_heap != nullptr) {
      return reinterpret_cast<HANDLE>(HeapFree(m2adec_global_heap, 0, memoryBlock));
    }

    return m2adec_global_heap;
  }

  /**
   * Address: 0x00B24050 (_m2adec_clear)
   *
   * What it does:
   * Zero-fills one decode helper memory range.
   */
  std::int32_t __cdecl m2adec_clear(void* const destination, const std::uint32_t byteCount)
  {
    std::memset(destination, 0, byteCount);
    return 0;
  }

  /**
   * Address: 0x00B24070 (_m2adec_decode_header)
   *
   * What it does:
   * Identifies ADIF/ADTS header type and prepares per-stream header scratch
   * state.
   */
  std::int32_t __cdecl m2adec_decode_header(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);

    if (contextWords[kM2aContextPendingSupplyIndex] == 1 &&
        contextWords[kM2aContextWindowGroupIndex] != kM2aElementIdEnd) {
      M2ABSR_Seek(
        contextWords[kM2aContextBitstreamHandleIndex],
        contextWords[kM2aContextInputBitRemainderIndex],
        0
      );
      return 0;
    }

    if (contextWords[kM2aContextScratchMappingIndex] == 0) {
      const auto headerScratch = m2adec_malloc(
        contextWords[kM2aContextHeapManagerIndex],
        kM2aScratchMappingBytes
      );
      if (headerScratch == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      m2adec_clear(headerScratch, static_cast<std::uint32_t>(kM2aScratchMappingBytes));
      contextWords[kM2aContextScratchMappingIndex] = M2aPtrToWord(headerScratch);
    }

    const auto headerType = contextWords[kM2aContextHeaderTypeIndex];
    if (headerType == 1) {
      return 0;
    }

    if (headerType == 0) {
      m2adec_get_header_type(
        M2aWordToPtr<std::uint8_t>(contextWords[kM2aContextInputBufferIndex]),
        contextWords[kM2aContextInputByteCountIndex],
        contextWords + kM2aContextHeaderTypeIndex
      );
    }

    if (contextWords[kM2aContextHeaderTypeIndex] == 1) {
      return m2adec_get_adif_info(context);
    }
    if (contextWords[kM2aContextHeaderTypeIndex] == 2) {
      return m2adec_get_adts_info(context);
    }
    return -1;
  }

  /**
   * Address: 0x00B24130 (_m2adec_get_header_type)
   *
   * What it does:
   * Detects ADIF/ADTS header signature from source bytes.
   */
  std::int32_t __cdecl m2adec_get_header_type(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int32_t* const outHeaderType
  )
  {
    if (sourceLength < 4) {
      *outHeaderType = 0;
      return 0;
    }

    if (sourceBytes[0] == 0xFFu && (sourceBytes[1] == 0xF8u || sourceBytes[1] == 0xF9u)) {
      *outHeaderType = 2;
      return 0;
    }

    if (sourceBytes[0] == 'A' && sourceBytes[1] == 'D' && sourceBytes[2] == 'I' && sourceBytes[3] == 'F') {
      *outHeaderType = 1;
      return 0;
    }

    *outHeaderType = 0;
    return 0;
  }

  /**
   * Address: 0x00B241A0 (_m2adec_get_adif_info)
   *
   * What it does:
   * Parses ADIF stream header lanes and optional PCE payloads.
   */
  std::int32_t __cdecl m2adec_get_adif_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const headerWords =
      M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);
    std::uint8_t copyIdScratch[4]{};

    M2ABSR_Seek(contextWords[kM2aContextBitstreamHandleIndex], 32, 1);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 0);
    if (headerWords[0] != 0) {
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 8, headerWords + 1);
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 32, headerWords + 2);
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 32, headerWords + 3);
    }

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 11);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 12);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 4);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 23, headerWords + 5);

    std::int32_t programConfigCountMinusOne = 0;
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      &programConfigCountMinusOne
    );

    const auto programConfigCount = programConfigCountMinusOne + 1;
    if (programConfigCountMinusOne != -1) {
      for (std::int32_t programConfigIndex = 0;
           programConfigIndex < programConfigCount;
           ++programConfigIndex) {
        if (headerWords[4] == 0) {
          M2ABSR_Read(
            contextWords[kM2aContextBitstreamHandleIndex],
            20,
            copyIdScratch
          );
        }
        m2adec_decode_pce(context);
      }
    }

    M2ABSR_AlignToByteBoundary(contextWords[kM2aContextBitstreamHandleIndex]);
    return 0;
  }

  /**
   * Address: 0x00B242A0 (_m2adec_get_adts_info)
   *
   * What it does:
   * Parses ADTS fixed/variable header lanes and optional CRC lane.
   */
  std::int32_t __cdecl m2adec_get_adts_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    if (contextWords[kM2aContextAdtsRawBlockCountIndex] == 0) {
      auto* const adtsHeaderWords =
        M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);
      const auto status = m2adec_get_adts_fixed_info(context);
      if (status < 0) {
        return status;
      }

      m2adec_get_adts_variable_info(context);
      if (adtsHeaderWords[6] == 0) {
        m2adec_crc_check(context);
      }
    }

    M2ABSR_AlignToByteBoundary(contextWords[kM2aContextBitstreamHandleIndex]);
    return 0;
  }

  /**
   * Address: 0x00B24300 (_m2adec_get_adts_fixed_info)
   *
   * What it does:
   * Parses ADTS fixed header lanes and binds scalefactor-band tables.
   */
  std::int32_t __cdecl m2adec_get_adts_fixed_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const adtsHeaderWords =
      M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);

    M2ABSR_Seek(contextWords[kM2aContextBitstreamHandleIndex], 15, 1);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 6);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      2,
      contextWords + kM2aContextAudioObjectTypeIndex
    );
    if (contextWords[kM2aContextAudioObjectTypeIndex] != kM2aMainProfile) {
      return -1;
    }

    std::int32_t sampleRateTableIndex = 0;
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      &sampleRateTableIndex
    );
    if (contextWords[kM2aContextSampleRateTableIndex] == 0) {
      contextWords[kM2aContextSampleRateTableIndex] = sampleRateTableIndex;
      contextWords[kM2aContextSampleRateIndex] = m2adec_frequency_table[sampleRateTableIndex];
    } else if (contextWords[kM2aContextSampleRateTableIndex] != sampleRateTableIndex) {
      return -1;
    }

    const auto configuredSampleRateIndex = contextWords[kM2aContextSampleRateTableIndex];
    contextWords[kM2aContextScalefactorBandShortPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb8[64 * configuredSampleRateIndex]);
    contextWords[kM2aContextScalefactorBandLongPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb[256 * configuredSampleRateIndex]);

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 7);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      3,
      contextWords + kM2aContextChannelConfigurationIndex
    );
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 11);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 12);
    return 0;
  }

  /**
   * Address: 0x00B243F0 (_m2adec_get_adts_variable_info)
   *
   * What it does:
   * Parses ADTS variable header lanes for frame length and block count.
   */
  std::int32_t __cdecl m2adec_get_adts_variable_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const adtsHeaderWords =
      M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 8);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 9);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      13,
      contextWords + kM2aContextAdtsFrameLengthIndex
    );
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 11, adtsHeaderWords + 10);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      2,
      contextWords + kM2aContextAdtsRawBlockCountIndex
    );
    return 0;
  }

  /**
   * Address: 0x00B24450 (_m2adec_crc_check)
   *
   * What it does:
   * Skips ADTS CRC lane when protection field is present.
   */
  std::int32_t __cdecl m2adec_crc_check(M2aDecoderContext* context)
  {
    M2ABSR_Seek(M2aContextWords(context)[kM2aContextBitstreamHandleIndex], 16, 1);
    return 0;
  }

  /**
   * Address: 0x00B24470 (_m2adec_decode_elements)
   *
   * What it does:
   * Dispatches AAC element decode handlers until END tag or decode error.
   */
  std::int32_t __cdecl m2adec_decode_elements(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    std::int32_t elementStartBit = 0;
    auto status = M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      3,
      contextWords + kM2aContextWindowGroupIndex
    );

    if (status >= 0) {
      while (true) {
        M2ABSR_Tell(contextWords[kM2aContextBitstreamHandleIndex], &elementStartBit);
        elementStartBit -= 3;

        switch (contextWords[kM2aContextWindowGroupIndex]) {
          case 0:
          case 3:
            status = m2adec_decode_sce(context);
            break;
          case 1:
            status = m2adec_decode_cpe(context);
            break;
          case 4:
            status = m2adec_decode_dse(context);
            break;
          case 5:
            status = m2adec_decode_pce(context);
            break;
          case 6:
            status = m2adec_decode_fil(context);
            break;
          case 7:
            break;
          default:
            return -1;
        }

        if (status < 0 || contextWords[kM2aContextWindowGroupIndex] == kM2aElementIdEnd) {
          return status;
        }

        status = M2ABSR_Read(
          contextWords[kM2aContextBitstreamHandleIndex],
          3,
          contextWords + kM2aContextWindowGroupIndex
        );
        if (status < 0) {
          break;
        }
      }
    }

    M2ABSR_Seek(contextWords[kM2aContextBitstreamHandleIndex], elementStartBit, 0);
    return 0;
  }

  /**
   * Address: 0x00B24550 (_m2adec_decode_sce)
   *
   * What it does:
   * Decodes one SCE element and runs ICS payload decode for its state lane.
   */
  std::int32_t __cdecl m2adec_decode_sce(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      contextWords + kM2aContextElementIndex
    );

    const auto groupedStateLaneIndex =
      kM2aContextPrimaryStateBaseIndex +
      contextWords[kM2aContextElementIndex] +
      (32 * contextWords[kM2aContextWindowGroupIndex]);
    if (contextWords[groupedStateLaneIndex] == 0) {
      if (contextWords[kM2aContextFrameCounterIndex] != 0) {
        return -1;
      }

      const auto initStatus = m2adec_decode_sce_initialize(context);
      if (initStatus < 0) {
        return initStatus;
      }
    }

    m2adec_decode_ics(context);
    return 0;
  }

  /**
   * Address: 0x00B245B0 (_m2adec_decode_cpe)
   *
   * What it does:
   * Decodes one CPE element, including common-window/MS flags and twin ICS
   * payload lanes.
   */
  std::int32_t __cdecl m2adec_decode_cpe(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      contextWords + kM2aContextElementIndex
    );

    const auto groupedStateLaneIndex =
      kM2aContextPrimaryStateBaseIndex +
      contextWords[kM2aContextElementIndex] +
      (32 * contextWords[kM2aContextWindowGroupIndex]);
    if (contextWords[groupedStateLaneIndex] == 0) {
      if (contextWords[kM2aContextFrameCounterIndex] != 0) {
        return -1;
      }

      const auto initStatus = m2adec_decode_cpe_initialize(context);
      if (initStatus < 0) {
        return initStatus;
      }
    }

    const auto groupedIcsLaneIndex =
      kM2aContextIcsTableBaseIndex +
      contextWords[kM2aContextElementIndex] +
      (32 * contextWords[kM2aContextWindowGroupIndex]);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(contextWords[groupedIcsLaneIndex]);

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, icsInfo + 0);
    if (icsInfo[0] == 1) {
      m2adec_get_ics_info(context);
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 2, icsInfo + 1);
      if (icsInfo[1] != 0) {
        if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
          m2adec_get_ms_info8(context);
        } else {
          m2adec_get_ms_info(context);
        }
      }
    } else {
      icsInfo[1] = 0;
    }

    m2adec_decode_ics(context);
    contextWords[kM2aContextElementIndex] += 16;
    m2adec_decode_ics(context);
    return 0;
  }

  /**
   * Address: 0x00B25FB0 (_m2adec_inverse_transform)
   *
   * What it does:
   * Runs one M2A IMDCT inverse-transform lane and overlap-adds into current
   * PCM output window.
   */
  std::int32_t m2adec_inverse_transform(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    const auto overlapBufferIndex = decodeState[3640];

    void* const previousWindow =
      M2AIMDCT_GetWindow(icsInfo[kM2aIcsWindowSequenceIndex], decodeState[543]);
    void* const currentWindow =
      M2AIMDCT_GetWindow(icsInfo[kM2aIcsWindowSequenceIndex], icsInfo[kM2aIcsWindowShapeIndex]);

    auto* const spectralCoefficients = reinterpret_cast<float*>(decodeState + 2592);
    auto* const overlapBuffer = reinterpret_cast<float*>(decodeState + (2048 * overlapBufferIndex) + 3641);

    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      M2AIMDCT_TransformShort(spectralCoefficients, previousWindow, currentWindow, overlapBuffer);
    } else {
      M2AIMDCT_TransformLong(spectralCoefficients, previousWindow, currentWindow, overlapBuffer);
    }

    const auto historyOffsetA = static_cast<std::ptrdiff_t>(0x68E4 - (overlapBufferIndex << 13));
    const auto historyOffsetB = static_cast<std::ptrdiff_t>(0x38E4 + (overlapBufferIndex << 13));
    auto* const historyLaneA =
      reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + historyOffsetA);
    auto* const historyLaneB =
      reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + historyOffsetB);
    auto* const outputWindow = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + 0x78E4);

    for (std::int32_t sampleIndex = 0; sampleIndex < 1024; ++sampleIndex) {
      outputWindow[sampleIndex] = historyLaneA[sampleIndex] + historyLaneB[sampleIndex];
    }

    decodeState[3640] = 1 - overlapBufferIndex;
    decodeState[542] = icsInfo[kM2aIcsWindowSequenceIndex];
    decodeState[543] = icsInfo[kM2aIcsWindowShapeIndex];

    if (decodeState[8761] < 2048) {
      decodeState[8761] += 1024;
    } else {
      decodeState[8762] += 1024;
    }

    return 0;
  }

  /**
   * Address: 0x00B260E0 (_m2adec_get_pulse_data)
   *
   * What it does:
   * Reads AAC pulse-data lanes for current M2A decode state.
   */
  std::int32_t m2adec_get_pulse_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    M2ABSR_Read(context->bitstreamHandle, 2, &decodeState[243]);
    M2ABSR_Read(context->bitstreamHandle, 6, &decodeState[244]);

    for (std::uint32_t pulseIndex = 0; pulseIndex <= static_cast<std::uint32_t>(decodeState[243]); ++pulseIndex) {
      M2ABSR_Read(context->bitstreamHandle, 5, &decodeState[245 + pulseIndex]);
      M2ABSR_Read(context->bitstreamHandle, 4, &decodeState[249 + pulseIndex]);
    }

    return 0;
  }

  /**
   * Address: 0x00B26160 (_m2adec_pulse_proc)
   *
   * What it does:
   * Applies pulse-data offsets to current spectral coefficient lanes.
   */
  std::int32_t m2adec_pulse_proc(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    std::int32_t spectralOffset = 0;

    for (std::int32_t bandIndex = 0; bandIndex < decodeState[244]; ++bandIndex) {
      spectralOffset += context->scalefactorBandWidthsLong[bandIndex];
    }

    for (std::uint32_t pulseIndex = 0; pulseIndex <= static_cast<std::uint32_t>(decodeState[243]); ++pulseIndex) {
      const auto pulseAmplitude = decodeState[249 + pulseIndex];
      spectralOffset += decodeState[245 + pulseIndex];

      auto& spectralCoefficient = decodeState[544 + spectralOffset];
      if (spectralCoefficient <= 0) {
        spectralCoefficient -= pulseAmplitude;
      } else {
        spectralCoefficient += pulseAmplitude;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B261E0 (_m2adec_get_tns_data)
   *
   * What it does:
   * Reads TNS metadata for long-window M2A lane and builds filter
   * coefficients.
   */
  std::int32_t m2adec_get_tns_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    M2ABSR_Read(context->bitstreamHandle, 2, &decodeState[254]);
    if (decodeState[254] == 0) {
      return 0;
    }

    std::int32_t coefficientResolution = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &coefficientResolution);

    for (std::int32_t filterIndex = 0; filterIndex < decodeState[254]; ++filterIndex) {
      M2ABSR_Read(context->bitstreamHandle, 6, &decodeState[262 + filterIndex]);
      M2ABSR_Read(context->bitstreamHandle, 5, &decodeState[270 + filterIndex]);

      auto& filterOrder = decodeState[270 + filterIndex];
      if (filterOrder == 0) {
        return 0;
      }
      if (filterOrder > 20) {
        filterOrder = 20;
      }

      M2ABSR_Read(context->bitstreamHandle, 1, &decodeState[278 + filterIndex]);

      std::int32_t coefficientCompression = 0;
      M2ABSR_Read(context->bitstreamHandle, 1, &coefficientCompression);

      float decodedCoefficients[kM2aTnsCoefficientLaneCount]{};
      for (std::int32_t coefficientIndex = 0; coefficientIndex < filterOrder; ++coefficientIndex) {
        std::int32_t coefficientCode = 0;
        M2ABSR_Read(
          context->bitstreamHandle,
          coefficientResolution - coefficientCompression + 3,
          &coefficientCode
        );

        const auto decodeTableIndex =
          (32 * coefficientResolution) + (16 * coefficientCompression) + coefficientCode;
        decodedCoefficients[coefficientIndex] = m2adec_tns_decode_table[decodeTableIndex];
      }

      auto* const filterCoefficients =
        reinterpret_cast<float*>(decodeState + 286 + (filterIndex * kM2aTnsCoefficientLaneCount));
      M2aBuildTnsFilterCoefficients(filterCoefficients, decodedCoefficients, filterOrder);
    }

    return 0;
  }

  /**
   * Address: 0x00B263D0 (_m2adec_get_tns_data8)
   *
   * What it does:
   * Reads TNS metadata for short-window M2A lane and builds per-window filter
   * coefficients.
   */
  std::int32_t m2adec_get_tns_data8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, &decodeState[254 + windowIndex]);
      if (decodeState[254 + windowIndex] == 0) {
        continue;
      }

      std::int32_t coefficientResolution = 0;
      std::int32_t coefficientCompression = 0;
      M2ABSR_Read(context->bitstreamHandle, 1, &coefficientResolution);
      M2ABSR_Read(context->bitstreamHandle, 4, &decodeState[262 + windowIndex]);
      M2ABSR_Read(context->bitstreamHandle, 3, &decodeState[270 + windowIndex]);

      auto& filterOrder = decodeState[270 + windowIndex];
      if (filterOrder == 0) {
        continue;
      }
      if (filterOrder > 12) {
        filterOrder = 12;
      }

      M2ABSR_Read(context->bitstreamHandle, 1, &decodeState[278 + windowIndex]);
      M2ABSR_Read(context->bitstreamHandle, 1, &coefficientCompression);

      float decodedCoefficients[kM2aTnsCoefficientLaneCount]{};
      for (std::int32_t coefficientIndex = 0; coefficientIndex < filterOrder; ++coefficientIndex) {
        std::int32_t coefficientCode = 0;
        M2ABSR_Read(
          context->bitstreamHandle,
          coefficientResolution - coefficientCompression + 3,
          &coefficientCode
        );

        const auto decodeTableIndex =
          (32 * coefficientResolution) + (16 * coefficientCompression) + coefficientCode;
        decodedCoefficients[coefficientIndex] = m2adec_tns_decode_table[decodeTableIndex];
      }

      auto* const filterCoefficients =
        reinterpret_cast<float*>(decodeState + 286 + (windowIndex * kM2aTnsCoefficientLaneCount));
      M2aBuildTnsFilterCoefficients(filterCoefficients, decodedCoefficients, filterOrder);
    }

    return 0;
  }

  /**
   * Address: 0x00B265F0 (_m2adec_tns_filter_proc)
   *
   * What it does:
   * Applies long-window TNS filter lanes to spectral coefficients.
   */
  std::int32_t m2adec_tns_filter_proc(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    std::int32_t upperBand = kM2aMaxBandsLong;

    for (std::int32_t filterIndex = 0; filterIndex < decodeState[254]; ++filterIndex) {
      auto lowerBand = upperBand - decodeState[262 + filterIndex];
      const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

      if (lowerBand >= maxSfb) {
        lowerBand = maxSfb;
      }

      auto upperBandClamped = upperBand;
      if (upperBandClamped >= maxSfb) {
        upperBandClamped = maxSfb;
      }

      if (lowerBand < upperBandClamped) {
        const auto startLine = M2aSumScalefactorBandWidths(context->scalefactorBandWidthsLong, 0, lowerBand);
        const auto endLine =
          startLine + M2aSumScalefactorBandWidths(context->scalefactorBandWidthsLong, lowerBand, upperBandClamped);
        const auto lineCount = endLine - startLine;

        auto* const spectralCoefficients = reinterpret_cast<float*>(decodeState + 2592 + startLine);
        auto* const filterCoefficients =
          reinterpret_cast<float*>(decodeState + 286 + (filterIndex * kM2aTnsCoefficientLaneCount));
        const auto filterOrder = decodeState[270 + filterIndex];
        const auto reverseDirection = decodeState[278 + filterIndex] != 0;

        M2aApplyTnsFilter(spectralCoefficients, lineCount, filterCoefficients, filterOrder, reverseDirection);
      }

      upperBand = lowerBand;
    }

    return 0;
  }

  /**
   * Address: 0x00B267B0 (_m2adec_tns_filter_proc8)
   *
   * What it does:
   * Applies short-window TNS filter lanes to spectral coefficients.
   */
  std::int32_t m2adec_tns_filter_proc8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      if (decodeState[254 + windowIndex] == 0) {
        continue;
      }

      auto lowerBand = kM2aMaxBandsShort - decodeState[262 + windowIndex];
      if (lowerBand >= maxSfb) {
        lowerBand = maxSfb;
      }

      auto upperBand = kM2aMaxBandsShort;
      if (upperBand > maxSfb) {
        upperBand = maxSfb;
      }

      if (lowerBand >= upperBand) {
        continue;
      }

      const auto startLine = M2aSumScalefactorBandWidths(context->scalefactorBandWidthsShort, 0, lowerBand);
      const auto endLine =
        startLine + M2aSumScalefactorBandWidths(context->scalefactorBandWidthsShort, lowerBand, upperBand);
      const auto lineCount = endLine - startLine;

      auto* const windowSpectralBase = reinterpret_cast<float*>(static_cast<std::intptr_t>(decodeState[3632 + windowIndex]));
      auto* const spectralCoefficients = windowSpectralBase + startLine;
      auto* const filterCoefficients =
        reinterpret_cast<float*>(decodeState + 286 + (windowIndex * kM2aTnsCoefficientLaneCount));
      const auto filterOrder = decodeState[270 + windowIndex];
      const auto reverseDirection = decodeState[278 + windowIndex] != 0;

      M2aApplyTnsFilter(spectralCoefficients, lineCount, filterCoefficients, filterOrder, reverseDirection);
    }

    return 0;
  }

  /**
   * Address: 0x00B265A0 (_m2adec_tns_proc)
   *
   * What it does:
   * Dispatches TNS filter path for long/short-window decode lanes.
   */
  std::int32_t m2adec_tns_proc(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    if (decodeState[253] != 1) {
      return 0;
    }

    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_tns_filter_proc8(context);
    } else {
      m2adec_tns_filter_proc(context);
    }

    return 0;
  }

  /**
   * Address: 0x00B26950 (_m2adec_get_ms_info)
   *
   * What it does:
   * Reads M/S stereo flags for long-window decode lanes.
   */
  std::int32_t m2adec_get_ms_info(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    const auto msMaskMode = icsInfo[1];
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    if (msMaskMode == 0) {
      for (std::int32_t band = 0; band < maxSfb; ++band) {
        icsInfo[2 + band] = 0;
      }
      return 0;
    }

    if (msMaskMode == 1) {
      for (std::int32_t band = 0; band < maxSfb; ++band) {
        M2ABSR_Read(context->bitstreamHandle, 1, &icsInfo[2 + band]);
      }
      return 0;
    }

    if (msMaskMode == 2) {
      for (std::int32_t band = 0; band < maxSfb; ++band) {
        icsInfo[2 + band] = 1;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26A10 (_m2adec_get_ms_info8)
   *
   * What it does:
   * Reads M/S stereo flags for short-window decode lanes.
   */
  std::int32_t m2adec_get_ms_info8(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto** const shortWindowMaskLanes = reinterpret_cast<std::int32_t**>(icsInfo + 114);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* const maskLane = shortWindowMaskLanes[windowIndex];
      if (icsInfo[124 + windowIndex] == 1) {
        m2adec_copy(maskLane, shortWindowMaskLanes[windowIndex - 1], static_cast<std::size_t>(maxSfb) * sizeof(std::int32_t));
        continue;
      }

      const auto msMaskMode = icsInfo[1];
      if (msMaskMode == 0) {
        for (std::int32_t band = 0; band < maxSfb; ++band) {
          maskLane[band] = 0;
        }
      } else if (msMaskMode == 1) {
        for (std::int32_t band = 0; band < maxSfb; ++band) {
          M2ABSR_Read(context->bitstreamHandle, 1, &maskLane[band]);
        }
      } else if (msMaskMode == 2) {
        for (std::int32_t band = 0; band < maxSfb; ++band) {
          maskLane[band] = 1;
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26B50 (_m2adec_ms_convert)
   *
   * What it does:
   * Applies long-window M/S stereo conversion to spectral coefficients.
   */
  std::int32_t m2adec_ms_convert(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);

    auto* primarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x2880);
    auto* secondarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x2880);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t band = 0; band < maxSfb; ++band) {
      const auto bandWidth = context->scalefactorBandWidthsLong[band];
      const auto sectionCodebook = secondaryState[2 + band];

      if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
        return -1;
      }

      if (sectionCodebook != 0xE && sectionCodebook != 0xF && icsInfo[2 + band] == 1 && bandWidth > 0) {
        for (std::int32_t line = 0; line < bandWidth; ++line) {
          const auto leftValue = primarySpectral[line];
          const auto rightValue = secondarySpectral[line];
          primarySpectral[line] = leftValue + rightValue;
          secondarySpectral[line] = leftValue - rightValue;
        }
      }

      primarySpectral += bandWidth;
      secondarySpectral += bandWidth;
    }

    return 0;
  }

  /**
   * Address: 0x00B26C60 (_m2adec_ms_convert8)
   *
   * What it does:
   * Applies short-window M/S stereo conversion to spectral coefficients.
   */
  std::int32_t m2adec_ms_convert8(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);
    auto** const primaryWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x38C0);
    auto** const secondaryWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x38C0);
    auto** const sectionCodebooksByWindow = reinterpret_cast<std::int32_t**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x388);
    auto** const msMaskLanesByWindow = reinterpret_cast<std::int32_t**>(icsInfo + 114);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* primarySpectral = primaryWindowSpectralLanes[windowIndex];
      auto* secondarySpectral = secondaryWindowSpectralLanes[windowIndex];
      auto* const sectionCodebookLane = sectionCodebooksByWindow[windowIndex];
      auto* const msMaskLane = msMaskLanesByWindow[windowIndex];

      for (std::int32_t band = 0; band < maxSfb; ++band) {
        const auto bandWidth = context->scalefactorBandWidthsShort[band];
        const auto sectionCodebook = sectionCodebookLane[band];

        if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
          return -1;
        }

        if (sectionCodebook != 0xE && sectionCodebook != 0xF && msMaskLane[band] == 1 && bandWidth > 0) {
          for (std::int32_t line = 0; line < bandWidth; ++line) {
            const auto leftValue = primarySpectral[line];
            const auto rightValue = secondarySpectral[line];
            primarySpectral[line] = leftValue + rightValue;
            secondarySpectral[line] = leftValue - rightValue;
          }
        }

        primarySpectral += bandWidth;
        secondarySpectral += bandWidth;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26B00 (_m2adec_ms_proc)
   *
   * What it does:
   * Dispatches M/S stereo conversion path for long/short-window decode lanes.
   */
  std::int32_t m2adec_ms_proc(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    if (icsInfo[0] == 0 || icsInfo[1] == 0) {
      return 0;
    }

    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_ms_convert8(context);
    } else {
      m2adec_ms_convert(context);
    }
    return 0;
  }

  /**
   * Address: 0x00B26DD0 (_m2adec_intensity_convert)
   *
   * What it does:
   * Applies long-window AAC intensity stereo conversion to spectral
   * coefficients.
   */
  std::int32_t m2adec_intensity_convert(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);
    auto* primarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x2880);
    auto* secondarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x2880);
    const auto* const intensityScaleLane = icsInfo + kM2aIcsIntensityScaleBaseIndex;
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t band = 0; band < maxSfb; ++band) {
      const auto bandWidth = context->scalefactorBandWidthsLong[band];
      const auto sectionCodebook = secondaryState[2 + band];

      if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
        return -1;
      }

      if (sectionCodebook == 0xE || sectionCodebook == 0xF) {
        double intensityFactor =
          std::pow(kM2aIntensityPowBase, static_cast<double>(intensityScaleLane[band]) * kM2aIntensityPowScale);

        if (icsInfo[1] == 1) {
          intensityFactor *= (1.0 - (2.0 * static_cast<double>(icsInfo[2 + band])));
        }
        if (sectionCodebook == 0xE) {
          intensityFactor *= -1.0;
        }

        for (std::int32_t line = 0; line < bandWidth; ++line) {
          secondarySpectral[line] = static_cast<float>(intensityFactor * static_cast<double>(primarySpectral[line]));
        }
      }

      primarySpectral += bandWidth;
      secondarySpectral += bandWidth;
    }

    return 0;
  }

  /**
   * Address: 0x00B26FB0 (_m2adec_intensity_convert8)
   *
   * What it does:
   * Applies short-window AAC intensity stereo conversion to spectral
   * coefficients.
   */
  std::int32_t m2adec_intensity_convert8(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);
    auto** const sourceWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x38C0);
    auto** const destinationWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x38C0);
    auto** const sectionCodebookLanes = reinterpret_cast<std::int32_t**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x388);
    auto** const intensityScaleLanes = reinterpret_cast<std::int32_t**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x3A8);
    auto** const signLanes = reinterpret_cast<std::int32_t**>(icsInfo + 114);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* sourceSpectral = sourceWindowSpectralLanes[windowIndex];
      auto* destinationSpectral = destinationWindowSpectralLanes[windowIndex];
      auto* const sectionCodebookLane = sectionCodebookLanes[windowIndex];
      auto* const intensityScaleLane = intensityScaleLanes[windowIndex];
      auto* const signLane = signLanes[windowIndex];

      for (std::int32_t band = 0; band < maxSfb; ++band) {
        const auto bandWidth = context->scalefactorBandWidthsShort[band];
        const auto sectionCodebook = sectionCodebookLane[band];

        if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
          return -1;
        }

        if (sectionCodebook == 0xE || sectionCodebook == 0xF) {
          double intensityFactor =
            std::pow(kM2aIntensityPowBase, static_cast<double>(intensityScaleLane[band]) * kM2aIntensityPowScale);

          if (icsInfo[1] == 1) {
            intensityFactor *= (1.0 - (2.0 * static_cast<double>(signLane[band])));
          }
          if (sectionCodebook == 0xE) {
            intensityFactor *= -1.0;
          }

          for (std::int32_t line = 0; line < bandWidth; ++line) {
            destinationSpectral[line] =
              static_cast<float>(intensityFactor * static_cast<double>(sourceSpectral[line]));
          }
        }

        sourceSpectral += bandWidth;
        destinationSpectral += bandWidth;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26D90 (_m2adec_intensity_proc)
   *
   * What it does:
   * Dispatches intensity stereo conversion path for long/short-window decode
   * lanes.
   */
  std::int32_t m2adec_intensity_proc(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_intensity_convert8(context);
    } else {
      m2adec_intensity_convert(context);
    }
    return 0;
  }

  /**
   * Address: 0x00B271E0 (_m2adec_specify_location_from_pce)
   *
   * What it does:
   * Assigns per-entry channel location classes using active PCE map lanes.
   */
  std::int32_t m2adec_specify_location_from_pce(M2aDecoderContext* context)
  {
    auto* channelMapLane = reinterpret_cast<std::int32_t*>(context->pceMap);
    auto* frontPairLane = channelMapLane + 1;
    auto* pairLaneA = channelMapLane + 34;
    auto* pairLaneB = channelMapLane + 67;

    for (std::int32_t entryIndex = 0; entryIndex < 128; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      const auto channelClass = locationEntry->channelClass;
      if (channelClass == 0) {
        if (*frontPairLane != 0) {
          if (*pairLaneA == 0) {
            locationEntry->locationClass = 3;
            ++pairLaneA;
            ++context->locationCountClass3;
          } else if (*pairLaneB == 0) {
            locationEntry->locationClass = 5;
            ++pairLaneB;
            ++context->locationCountClass5;
          } else {
            locationEntry->locationClass = 1;
            ++context->locationCountClass0;
          }
        } else {
          locationEntry->locationClass = 1;
          ++context->locationCountClass0;
          ++frontPairLane;
        }
        continue;
      }

      if (channelClass == 1) {
        if (*frontPairLane == 1) {
          locationEntry->locationClass = 2;
          ++context->locationCountClass1;
          ++frontPairLane;
        } else if (*pairLaneA == 1) {
          locationEntry->locationClass = 4;
          ++pairLaneA;
          ++context->locationCountClass4;
        } else if (*pairLaneB == 1) {
          locationEntry->locationClass = 6;
          ++pairLaneB;
          ++context->locationCountClass6;
        } else {
          locationEntry->locationClass = 2;
          ++context->locationCountClass1;
          ++frontPairLane;
        }
        continue;
      }

      if (channelClass == 3) {
        locationEntry->locationClass = 7;
        ++context->locationCountClass7;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B27300 (_m2adec_infer_location)
   *
   * What it does:
   * Assigns per-entry channel location classes without PCE map, using
   * alternating class counters.
   */
  std::int32_t m2adec_infer_location(M2aDecoderContext* context)
  {
    for (std::int32_t entryIndex = 0; entryIndex < 128; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      const auto channelClass = locationEntry->channelClass;
      if (channelClass == 0) {
        if ((context->locationCountClass0 & 1) != 0) {
          locationEntry->locationClass = 5;
          ++context->locationCountClass5;
        } else {
          locationEntry->locationClass = 1;
          ++context->locationCountClass0;
        }
      } else if (channelClass == 1) {
        if ((context->locationCountClass1 & 1) != 0) {
          locationEntry->locationClass = 6;
          ++context->locationCountClass6;
        } else {
          locationEntry->locationClass = 2;
          ++context->locationCountClass1;
        }
      } else if (channelClass == 3) {
        locationEntry->locationClass = 7;
        ++context->locationCountClass7;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B271B0 (_m2adec_specify_location)
   *
   * What it does:
   * Selects PCE-driven or inferred location assignment for channel entries.
   */
  std::int32_t m2adec_specify_location(M2aDecoderContext* context)
  {
    if (context->pceMap != nullptr) {
      m2adec_specify_location_from_pce(context);
    } else {
      m2adec_infer_location(context);
    }
    return 0;
  }

  /**
   * Address: 0x00B273A0 (_m2adec_get_extension_payload)
   *
   * What it does:
   * Advances extension payload bits on current bitstream lane.
   */
  std::int32_t m2adec_get_extension_payload(M2aDecoderContext* context, const std::int32_t payloadWordCount)
  {
    std::int32_t bitPosition = 0;
    M2ABSR_Tell(context->bitstreamHandle, &bitPosition);

    const auto payloadEndBit = bitPosition + (8 * payloadWordCount);
    while (bitPosition < payloadEndBit) {
      std::uint8_t discardBytes[4]{};
      M2ABSR_Read(context->bitstreamHandle, 4, discardBytes);
      M2ABSR_Seek(context->bitstreamHandle, payloadEndBit, 0);
      M2ABSR_Tell(context->bitstreamHandle, &bitPosition);
    }

    return 0;
  }

  /**
   * Address: 0x00B255A0 (_m2adec_copy)
   *
   * What it does:
   * Copies one M2A runtime buffer lane and returns copied byte count.
   */
  std::uint32_t m2adec_copy(void* const destination, const void* const source, const std::size_t byteCount)
  {
    std::memcpy(destination, source, byteCount);
    return static_cast<std::uint32_t>(byteCount);
  }

  /**
   * Address: 0x00B24690 (_m2adec_decode_dse)
   *
   * What it does:
   * Parses one DSE element payload and advances bitstream cursor by payload
   * size (with optional byte-align).
   */
  std::int32_t m2adec_decode_dse(M2aDecoderContext* context)
  {
    std::uint8_t elementTag = 0;
    std::int32_t alignFlag = 0;
    std::int32_t payloadByteCount = 0;
    std::int32_t extendedByteCount = 0;

    M2ABSR_Read(context->bitstreamHandle, 4, &elementTag);
    M2ABSR_Read(context->bitstreamHandle, 1, &alignFlag);
    M2ABSR_Read(context->bitstreamHandle, 8, &payloadByteCount);
    if (payloadByteCount == 255) {
      M2ABSR_Read(context->bitstreamHandle, 8, &extendedByteCount);
      payloadByteCount += extendedByteCount;
    }

    if (alignFlag == 1) {
      M2ABSR_AlignToByteBoundary(context->bitstreamHandle);
    }

    M2ABSR_Seek(context->bitstreamHandle, 8 * payloadByteCount, 1);
    return 0;
  }

  /**
   * Address: 0x00B24730 (_m2adec_decode_pce)
   *
   * What it does:
   * Parses one PCE element, updates sample-rate/scalefactor tables, and
   * validates discovered channel layout count.
   */
  std::int32_t m2adec_decode_pce(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    std::uint8_t elementTag = 0;

    M2ABSR_Read(context->bitstreamHandle, 4, &elementTag);

    auto* pceMapWords = static_cast<std::int32_t*>(context->pceMap);
    if (pceMapWords == nullptr) {
      pceMapWords = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), 0x2B8u));
      if (pceMapWords == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      m2adec_clear(pceMapWords, 0x2B8u);
      context->pceMap = pceMapWords;
      contextWords[kM2aContextPceMapIndex] = M2aPtrToWord(pceMapWords);
    }

    M2ABSR_Read(context->bitstreamHandle, 2, contextWords + kM2aContextAudioObjectTypeIndex);

    std::int32_t sampleRateTableIndex = 0;
    M2ABSR_Read(context->bitstreamHandle, 4, &sampleRateTableIndex);

    if (contextWords[kM2aContextSampleRateTableIndex] != 0) {
      if (contextWords[kM2aContextSampleRateTableIndex] != sampleRateTableIndex) {
        return -1;
      }
    } else {
      contextWords[kM2aContextSampleRateTableIndex] = sampleRateTableIndex;
      contextWords[kM2aContextSampleRateIndex] = m2adec_frequency_table[sampleRateTableIndex];
    }

    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 0);
    std::int32_t totalChannelCount = pceMapWords[0];

    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 33);
    totalChannelCount += pceMapWords[33];

    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 66);
    totalChannelCount += pceMapWords[66];

    M2ABSR_Read(context->bitstreamHandle, 2, pceMapWords + 99);
    totalChannelCount += pceMapWords[99];

    M2ABSR_Read(context->bitstreamHandle, 3, pceMapWords + 116);
    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 133);

    M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 166);
    if (pceMapWords[166] == 1) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 167);
    } else {
      pceMapWords[167] = 0;
    }

    M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 168);
    if (pceMapWords[168] == 1) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 169);
    } else {
      pceMapWords[169] = 0;
    }

    M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 170);
    if (pceMapWords[170] == 1) {
      M2ABSR_Read(context->bitstreamHandle, 2, pceMapWords + 171);
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 172);
    } else {
      pceMapWords[171] = 0;
      pceMapWords[172] = 0;
    }

    for (std::int32_t frontIndex = 0; frontIndex < pceMapWords[0]; ++frontIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 1 + frontIndex);
      totalChannelCount += pceMapWords[1 + frontIndex];
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 17 + frontIndex);
    }

    for (std::int32_t sideIndex = 0; sideIndex < pceMapWords[33]; ++sideIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 34 + sideIndex);
      totalChannelCount += pceMapWords[34 + sideIndex];
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 50 + sideIndex);
    }

    for (std::int32_t backIndex = 0; backIndex < pceMapWords[66]; ++backIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 67 + backIndex);
      totalChannelCount += pceMapWords[67 + backIndex];
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 83 + backIndex);
    }

    for (std::int32_t lfeIndex = 0; lfeIndex < pceMapWords[99]; ++lfeIndex) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 100 + lfeIndex);
    }

    for (std::int32_t assocDataIndex = 0; assocDataIndex < pceMapWords[116]; ++assocDataIndex) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 117 + assocDataIndex);
    }

    for (std::int32_t ccIndex = 0; ccIndex < pceMapWords[133]; ++ccIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 134 + ccIndex);
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 150 + ccIndex);
    }

    M2ABSR_AlignToByteBoundary(context->bitstreamHandle);

    M2ABSR_Read(context->bitstreamHandle, 8, pceMapWords + 173);
    M2ABSR_Seek(context->bitstreamHandle, 8 * pceMapWords[173], 1);

    const auto configuredSampleRateIndex = contextWords[kM2aContextSampleRateTableIndex];
    contextWords[kM2aContextScalefactorBandShortPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb8[64 * configuredSampleRateIndex]);
    contextWords[kM2aContextScalefactorBandLongPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb[256 * configuredSampleRateIndex]);

    if (contextWords[kM2aContextDecodeCountInitializedIndex] == 0) {
      contextWords[kM2aContextDecodedChannelCountIndex] = totalChannelCount;
      contextWords[kM2aContextDecodeCountInitializedIndex] = 1;
      return 0;
    }

    return contextWords[kM2aContextDecodedChannelCountIndex] == totalChannelCount ? 0 : -1;
  }

  /**
   * Address: 0x00B24B70 (_m2adec_decode_fil)
   *
   * What it does:
   * Parses FIL payload length and delegates extension payload skipping/parsing.
   */
  std::int32_t m2adec_decode_fil(M2aDecoderContext* context)
  {
    std::int32_t payloadWordCount = 0;
    M2ABSR_Read(context->bitstreamHandle, 4, &payloadWordCount);
    if (payloadWordCount == 15) {
      std::int32_t extraWordCount = 0;
      M2ABSR_Read(context->bitstreamHandle, 8, &extraWordCount);
      payloadWordCount = payloadWordCount + extraWordCount - 1;
    }

    m2adec_get_extension_payload(context, payloadWordCount);
    return 0;
  }

  /**
   * Address: 0x00B24BD0 (_m2adec_decode_sce_initialize)
   *
   * What it does:
   * Ensures SCE location entry + ICS/decode-state lanes exist and resets them
   * for one decode pass.
   */
  std::int32_t m2adec_decode_sce_initialize(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    const auto locationEntryCount = contextWords[kM2aContextLocationEntryCountIndex];
    const auto activeElementIndex = contextWords[kM2aContextElementIndex];
    const auto activeWindowGroupIndex = contextWords[kM2aContextWindowGroupIndex];

    if (locationEntryCount == 0) {
      auto* const contextBytes = reinterpret_cast<std::uint8_t*>(context);
      const auto baseChannelPairTag = static_cast<std::uint8_t>(2 * (activeElementIndex + (16 * activeWindowGroupIndex)));
      contextBytes[72] = baseChannelPairTag;
      contextBytes[73] = static_cast<std::uint8_t>(baseChannelPairTag + 1);
    }

    auto* locationEntry = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextLocationAllocBaseIndex + locationEntryCount]);
    if (locationEntry == nullptr) {
      locationEntry = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aLocationEntrySize));
      if (locationEntry == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      const auto currentCount = contextWords[kM2aContextLocationEntryCountIndex];
      contextWords[kM2aContextLocationAllocBaseIndex + currentCount] = M2aPtrToWord(locationEntry);
      contextWords[kM2aContextLocationEntryCountIndex] = currentCount + 1;
    }

    m2adec_clear(locationEntry, kM2aLocationEntrySize);
    locationEntry[0] = activeElementIndex;
    locationEntry[1] = activeWindowGroupIndex;

    const auto slotIndex = M2aGetCurrentSlotIndex(context);

    auto* icsInfoLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + slotIndex]);
    if (icsInfoLane == nullptr) {
      icsInfoLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aIcsInfoSize));
      if (icsInfoLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      contextWords[kM2aContextIcsTableBaseIndex + slotIndex] = M2aPtrToWord(icsInfoLane);
    }

    m2adec_clear(icsInfoLane, kM2aIcsInfoSize);
    M2aInitializeIcsWindowPointers(icsInfoLane);

    auto* decodeStateLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex]);
    if (decodeStateLane == nullptr) {
      decodeStateLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aDecodeStateSize));
      if (decodeStateLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex] = M2aPtrToWord(decodeStateLane);
    }

    m2adec_clear(decodeStateLane, kM2aDecodeStateSize);
    M2aInitializeDecodeStateWindowPointers(decodeStateLane);
    return 0;
  }

  /**
   * Address: 0x00B24D40 (_m2adec_decode_cpe_initialize)
   *
   * What it does:
   * Ensures CPE location entry + dual ICS/decode-state lanes exist and resets
   * them for one decode pass.
   */
  std::int32_t m2adec_decode_cpe_initialize(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    const auto locationEntryCount = contextWords[kM2aContextLocationEntryCountIndex];
    const auto activeElementIndex = contextWords[kM2aContextElementIndex];
    const auto activeWindowGroupIndex = contextWords[kM2aContextWindowGroupIndex];

    if (locationEntryCount == 0) {
      auto* const contextBytes = reinterpret_cast<std::uint8_t*>(context);
      const auto baseChannelPairTag = static_cast<std::uint8_t>(2 * (activeElementIndex + (16 * activeWindowGroupIndex)));
      contextBytes[72] = baseChannelPairTag;
      contextBytes[73] = static_cast<std::uint8_t>(baseChannelPairTag + 1);
    }

    auto* locationEntry = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextLocationAllocBaseIndex + locationEntryCount]);
    if (locationEntry == nullptr) {
      locationEntry = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aLocationEntrySize));
      if (locationEntry == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      const auto currentCount = contextWords[kM2aContextLocationEntryCountIndex];
      contextWords[kM2aContextLocationAllocBaseIndex + currentCount] = M2aPtrToWord(locationEntry);
      contextWords[kM2aContextLocationEntryCountIndex] = currentCount + 1;
    }

    m2adec_clear(locationEntry, kM2aLocationEntrySize);
    locationEntry[0] = activeElementIndex;
    locationEntry[1] = activeWindowGroupIndex;

    const auto slotIndex = M2aGetCurrentSlotIndex(context);

    auto* primaryIcsLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + slotIndex]);
    if (primaryIcsLane == nullptr) {
      primaryIcsLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aIcsInfoSize));
      if (primaryIcsLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextIcsTableBaseIndex + slotIndex] = M2aPtrToWord(primaryIcsLane);
    }

    m2adec_clear(primaryIcsLane, kM2aIcsInfoSize);
    M2aInitializeIcsWindowPointers(primaryIcsLane);

    auto* secondaryIcsLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextSecondaryIcsTableBaseIndex + slotIndex]);
    if (secondaryIcsLane == nullptr) {
      secondaryIcsLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aIcsInfoSize));
      if (secondaryIcsLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextSecondaryIcsTableBaseIndex + slotIndex] = M2aPtrToWord(secondaryIcsLane);
    }

    m2adec_clear(secondaryIcsLane, kM2aIcsInfoSize);
    M2aInitializeIcsWindowPointers(secondaryIcsLane);

    auto* primaryDecodeState = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex]);
    if (primaryDecodeState == nullptr) {
      primaryDecodeState = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aDecodeStateSize));
      if (primaryDecodeState == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex] = M2aPtrToWord(primaryDecodeState);
    }

    m2adec_clear(primaryDecodeState, kM2aDecodeStateSize);
    M2aInitializeDecodeStateWindowPointers(primaryDecodeState);

    auto* secondaryDecodeState = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextSecondaryStateBaseIndex + slotIndex]);
    if (secondaryDecodeState == nullptr) {
      secondaryDecodeState = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aDecodeStateSize));
      if (secondaryDecodeState == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextSecondaryStateBaseIndex + slotIndex] = M2aPtrToWord(secondaryDecodeState);
    }

    m2adec_clear(secondaryDecodeState, kM2aDecodeStateSize);
    M2aInitializeDecodeStateWindowPointers(secondaryDecodeState);
    return 0;
  }

  /**
   * Address: 0x00B25030 (_m2adec_get_ics_info)
   *
   * What it does:
   * Reads ICS window metadata, window groups, and predictor bits for current
   * channel lane.
   */
  std::int32_t m2adec_get_ics_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const icsInfoLane = M2aGetIcsInfoLane(context);

    M2ABSR_Seek(context->bitstreamHandle, 1, 1);
    M2ABSR_Read(context->bitstreamHandle, 2, icsInfoLane + kM2aIcsWindowSequenceIndex);
    M2ABSR_Read(context->bitstreamHandle, 1, icsInfoLane + kM2aIcsWindowShapeIndex);

    auto& maxSfb = icsInfoLane[kM2aIcsMaxSfbIndex];
    if (icsInfoLane[kM2aIcsWindowSequenceIndex] == 2) {
      M2ABSR_Read(context->bitstreamHandle, 4, &maxSfb);
      if (maxSfb > kM2aMaxBandsShort) {
        maxSfb = kM2aMaxBandsShort;
      }

      icsInfoLane[124] = 0;
      for (std::int32_t windowIndex = 0; windowIndex < 7; ++windowIndex) {
        M2ABSR_Read(context->bitstreamHandle, 1, icsInfoLane + 125 + windowIndex);
      }

      for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; windowIndex += icsInfoLane[132 + windowIndex]) {
        icsInfoLane[132 + windowIndex] = 1;
        std::int32_t groupedWindow = windowIndex;
        while (groupedWindow < 7 && icsInfoLane[125 + groupedWindow] == 1) {
          ++groupedWindow;
          ++icsInfoLane[132 + windowIndex];
          icsInfoLane[125 + groupedWindow - 1] = 0;
        }
      }

      return 0;
    }

    M2ABSR_Read(context->bitstreamHandle, 6, &maxSfb);
    if (maxSfb > kM2aMaxBandsLong) {
      maxSfb = kM2aMaxBandsLong;
    }

    std::int32_t predictorDataPresent = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &predictorDataPresent);
    if (predictorDataPresent == 1) {
      std::int32_t predictorResetPresent = 0;
      M2ABSR_Read(context->bitstreamHandle, 1, &predictorResetPresent);

      std::int32_t predictorResetGroup = 0;
      if (predictorResetPresent == 1) {
        M2ABSR_Read(context->bitstreamHandle, 5, &predictorResetGroup);
      }

      const auto predictorBandCount = maxSfb <= 41 ? maxSfb : 41;
      for (std::int32_t predictorBand = 0; predictorBand < predictorBandCount; ++predictorBand) {
        std::int32_t predictorUsed = 0;
        M2ABSR_Read(context->bitstreamHandle, 1, &predictorUsed);
      }
    }

    icsInfoLane[132] = 1;
    return 0;
  }

  /**
   * Address: 0x00B25350 (_m2adec_get_section_data)
   *
   * What it does:
   * Decodes long-window section codebook ids for current ICS lane.
   */
  std::int32_t m2adec_get_section_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto* const sectionCodebooks = decodeState + 2;
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t consumedBands = 0;
    while (consumedBands < maxSfb) {
      std::int32_t sectionCodebook = 0;
      M2ABSR_Read(context->bitstreamHandle, 4, &sectionCodebook);

      std::int32_t sectionLength = 0;
      while (true) {
        std::int32_t sectionLengthDelta = 0;
        M2ABSR_Read(context->bitstreamHandle, 5, &sectionLengthDelta);
        sectionLength += sectionLengthDelta;

        std::int32_t overrunFlag = 0;
        M2ABSR_Overruns(context->bitstreamHandle, &overrunFlag);
        if (overrunFlag == 1) {
          return -1;
        }

        if (sectionLengthDelta != 31) {
          break;
        }
      }

      for (std::int32_t fillIndex = 0; fillIndex < sectionLength; ++fillIndex) {
        sectionCodebooks[consumedBands + fillIndex] = sectionCodebook;
      }
      consumedBands += static_cast<std::uint32_t>(sectionLength);
    }

    if (maxSfb < static_cast<std::uint32_t>(kM2aMaxBandsLong)) {
      std::memset(
        sectionCodebooks + maxSfb,
        0,
        static_cast<std::size_t>(kM2aMaxBandsLong - static_cast<std::int32_t>(maxSfb)) * sizeof(std::int32_t)
      );
    }

    return 0;
  }

  /**
   * Address: 0x00B25440 (_m2adec_get_section_data8)
   *
   * What it does:
   * Decodes short-window section codebook ids for each active window group.
   */
  std::int32_t m2adec_get_section_data8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto** const sectionCodebookWindows = reinterpret_cast<std::int32_t**>(decodeState + 226);
    const auto* const windowGroupFlags = reinterpret_cast<const std::uint32_t*>(icsInfo + 124);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* const sectionCodebooks = sectionCodebookWindows[windowIndex];
      if (windowIndex != 0 && windowGroupFlags[windowIndex] == 1) {
        m2adec_copy(sectionCodebooks, sectionCodebookWindows[windowIndex - 1], 0x38u);
      } else {
        std::uint32_t consumedBands = 0;
        while (consumedBands < maxSfb) {
          std::int32_t sectionCodebook = 0;
          M2ABSR_Read(context->bitstreamHandle, 4, &sectionCodebook);

          std::int32_t sectionLength = 0;
          while (true) {
            std::int32_t sectionLengthDelta = 0;
            M2ABSR_Read(context->bitstreamHandle, 3, &sectionLengthDelta);
            sectionLength += sectionLengthDelta;

            std::int32_t overrunFlag = 0;
            M2ABSR_Overruns(context->bitstreamHandle, &overrunFlag);
            if (overrunFlag == 1) {
              return -1;
            }

            if (sectionLengthDelta != 7) {
              break;
            }
          }

          for (std::int32_t fillIndex = 0; fillIndex < sectionLength; ++fillIndex) {
            sectionCodebooks[consumedBands + fillIndex] = sectionCodebook;
          }
          consumedBands += static_cast<std::uint32_t>(sectionLength);
        }
      }

      for (std::uint32_t band = maxSfb; band < static_cast<std::uint32_t>(kM2aMaxBandsShort); ++band) {
        sectionCodebooks[band] = 0;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B255C0 (_m2adec_get_scale_factor_data)
   *
   * What it does:
   * Huffman-decodes long-window scale-factor lanes for current channel.
   */
  std::int32_t m2adec_get_scale_factor_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);

    std::uintptr_t codebookHandle = 0;
    M2AHUFFMAN_GetCodebook(12, &codebookHandle);
    const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);

    std::int32_t globalGain = decodeState[1];
    std::int32_t intensityPosition = 0;
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t band = 0; band < maxSfb; ++band) {
      switch (decodeState[2 + band]) {
        case 0:
          break;
        case 12:
        case 13:
          return -1;
        case 14:
        case 15:
          intensityPosition += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
          decodeState[114 + band] = intensityPosition;
          break;
        default:
          globalGain += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
          decodeState[114 + band] = globalGain;
          break;
      }
    }

    if (maxSfb < static_cast<std::uint32_t>(kM2aMaxBandsLong)) {
      std::memset(
        decodeState + 114 + maxSfb,
        0,
        static_cast<std::size_t>(kM2aMaxBandsLong - static_cast<std::int32_t>(maxSfb)) * sizeof(std::int32_t)
      );
    }

    return 0;
  }

  /**
   * Address: 0x00B256E0 (_m2adec_get_scale_factor_data8)
   *
   * What it does:
   * Huffman-decodes short-window scale-factor lanes (with grouped-window copy
   * semantics).
   */
  std::int32_t m2adec_get_scale_factor_data8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);

    std::uintptr_t codebookHandle = 0;
    M2AHUFFMAN_GetCodebook(12, &codebookHandle);
    const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);

    std::int32_t globalGain = decodeState[1];
    std::int32_t intensityPosition = 0;
    auto** const sectionCodebookWindows = reinterpret_cast<std::int32_t**>(decodeState + 226);
    auto** const scaleFactorWindows = reinterpret_cast<std::int32_t**>(decodeState + 234);
    const auto* const windowGroupFlags = reinterpret_cast<const std::uint32_t*>(icsInfo + 124);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* const sectionCodebooks = sectionCodebookWindows[windowIndex];
      auto* const scaleFactors = scaleFactorWindows[windowIndex];

      for (std::uint32_t band = 0; band < maxSfb; ++band) {
        switch (sectionCodebooks[band]) {
          case 0:
            break;
          case 12:
          case 13:
            return -1;
          case 14:
          case 15:
            if (windowIndex != 0 && windowGroupFlags[windowIndex] == 1) {
              m2adec_copy(scaleFactors, scaleFactorWindows[windowIndex - 1], 0x38u);
            } else {
              intensityPosition += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
              scaleFactors[band] = intensityPosition;
            }
            break;
          default:
            if (windowIndex != 0 && windowGroupFlags[windowIndex] == 1) {
              m2adec_copy(scaleFactors, scaleFactorWindows[windowIndex - 1], 0x38u);
            } else {
              globalGain += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
              scaleFactors[band] = globalGain;
            }
            break;
        }
      }

      for (std::uint32_t band = maxSfb; band < static_cast<std::uint32_t>(kM2aMaxBandsShort); ++band) {
        scaleFactors[band] = 0;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B25CA0 (_m2adec_inverse_quantization)
   *
   * What it does:
   * Applies inverse-quantization power law to decoded spectral integers.
   */
  std::int32_t m2adec_inverse_quantization(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const quantizedSpectra = decodeState + 544;
    auto* const inverseQuantizedSpectra = reinterpret_cast<float*>(decodeState + 1568);

    for (std::int32_t spectrumIndex = 0; spectrumIndex < 1024; ++spectrumIndex) {
      const auto quantizedValue = quantizedSpectra[spectrumIndex];
      const auto magnitude = static_cast<double>(quantizedValue >= 0 ? quantizedValue : -quantizedValue);
      const auto sign = quantizedValue >= 0 ? 1.0 : -1.0;
      inverseQuantizedSpectra[spectrumIndex] = static_cast<float>(std::pow(magnitude, 1.333333333333333) * sign);
    }

    return 0;
  }

  /**
   * Address: 0x00B25D10 (_m2adec_calc_spectra)
   *
   * What it does:
   * Applies long-window scale factors onto inverse-quantized spectra lanes.
   */
  std::int32_t m2adec_calc_spectra(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto* const scaledSpectra = reinterpret_cast<float*>(decodeState + 2592);
    auto* const inverseQuantizedSpectra = reinterpret_cast<float*>(decodeState + 1568);
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandLongPtrIndex]);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t spectrumIndex = 0;
    for (std::uint32_t band = 0; band < maxSfb; ++band) {
      const auto scaleFactor = decodeState[114 + band];
      const auto scale = scaleFactor != 0
        ? std::pow(2.0, (static_cast<double>(scaleFactor) - 100.0) * 0.25)
        : 0.0;

      for (std::int32_t line = 0; line < bandWidths[band]; ++line) {
        scaledSpectra[spectrumIndex] = static_cast<float>(scale * inverseQuantizedSpectra[spectrumIndex]);
        ++spectrumIndex;
      }
    }

    if (spectrumIndex < 1024) {
      std::memset(
        scaledSpectra + spectrumIndex,
        0,
        static_cast<std::size_t>(1024u - spectrumIndex) * sizeof(float)
      );
    }

    return 0;
  }

  /**
   * Address: 0x00B25E00 (_m2adec_calc_spectra8)
   *
   * What it does:
   * Applies short-window scale factors onto per-window inverse-quantized
   * spectra lanes.
   */
  std::int32_t m2adec_calc_spectra8(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto** const scaleFactorWindows = reinterpret_cast<std::int32_t**>(decodeState + 234);
    auto** const inverseQuantizedWindows = reinterpret_cast<float**>(decodeState + 3624);
    auto** const scaledSpectraWindows = reinterpret_cast<float**>(decodeState + 3632);
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandShortPtrIndex]);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      std::uint32_t spectrumIndex = 0;

      for (std::uint32_t band = 0; band < maxSfb; ++band) {
        const auto scaleFactor = scaleFactorWindows[windowIndex][band];
        const auto scale = scaleFactor != 0
          ? std::pow(2.0, (static_cast<double>(scaleFactor) - 100.0) * 0.25)
          : 0.0;

        for (std::int32_t line = 0; line < bandWidths[band]; ++line) {
          scaledSpectraWindows[windowIndex][spectrumIndex] =
            static_cast<float>(scale * inverseQuantizedWindows[windowIndex][spectrumIndex]);
          ++spectrumIndex;
        }
      }

      for (; spectrumIndex < 128; ++spectrumIndex) {
        scaledSpectraWindows[windowIndex][spectrumIndex] = 0.0f;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B25860 (_m2adec_get_spectra_data)
   *
   * What it does:
   * Decodes long-window Huffman spectra, applies pulse processing, and runs
   * inverse-quantization/scaling.
   */
  std::int32_t m2adec_get_spectra_data(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto* const quantizedSpectra = decodeState + 544;
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandLongPtrIndex]);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t spectrumCursor = 0;
    for (std::uint32_t band = 0; band < maxSfb; ++band) {
      const auto codebookIndex = static_cast<std::uint32_t>(decodeState[2 + band]);
      const auto lineCount = bandWidths[band];

      if (codebookIndex > 0 && codebookIndex <= 11) {
        std::uintptr_t codebookHandle = 0;
        M2AHUFFMAN_GetCodebook(static_cast<int>(codebookIndex), &codebookHandle);
        const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);
        auto* const codebookWords = reinterpret_cast<std::uint32_t*>(codebookHandle);

        std::int32_t decodedLines = 0;
        while (decodedLines < lineCount) {
          const auto packedValue = M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle);

          std::int32_t unpackedValues[4]{};
          std::int32_t unpackedDimension = 0;
          M2AHUFFMAN_Unpack(
            codebookWords,
            packedValue,
            unpackedValues,
            &unpackedDimension,
            context->bitstreamHandle
          );

          if (codebookIndex == 11) {
            M2AHUFFMAN_GetEscValue(
              static_cast<int>(reinterpret_cast<std::uintptr_t>(unpackedValues)),
              context->bitstreamHandle
            );
          }

          for (std::int32_t unpackedIndex = 0; unpackedIndex < unpackedDimension; ++unpackedIndex) {
            quantizedSpectra[spectrumCursor] = unpackedValues[unpackedIndex];
            ++spectrumCursor;
          }

          decodedLines += unpackedDimension;
        }
      } else {
        for (std::int32_t line = 0; line < lineCount; ++line) {
          quantizedSpectra[spectrumCursor] = 0;
          ++spectrumCursor;
        }
      }
    }

    if (spectrumCursor < 1024) {
      std::memset(
        quantizedSpectra + spectrumCursor,
        0,
        static_cast<std::size_t>(1024u - spectrumCursor) * sizeof(std::int32_t)
      );
    }

    if (decodeState[242] == 1) {
      m2adec_pulse_proc(context);
    }

    m2adec_inverse_quantization(context);
    m2adec_calc_spectra(context);
    return 0;
  }

  /**
   * Address: 0x00B25A00 (_m2adec_get_spectra_data8)
   *
   * What it does:
   * Decodes short-window Huffman spectra for grouped windows and runs
   * inverse-quantization/scaling.
   */
  std::int32_t m2adec_get_spectra_data8(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto** const sectionCodebookWindows = reinterpret_cast<std::int32_t**>(decodeState + 226);
    auto** const quantizedSpectraWindows = reinterpret_cast<std::int32_t**>(decodeState + 3616);
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandShortPtrIndex]);
    const auto* const windowGroupLengths = reinterpret_cast<const std::uint32_t*>(icsInfo + 132);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t spectraWriteCounts[kM2aShortWindowCount]{};

    for (std::uint32_t windowStart = 0; windowStart < kM2aShortWindowCount; ++windowStart) {
      const auto groupedWindowCount = windowGroupLengths[windowStart];

      for (std::uint32_t band = 0; band < maxSfb; ++band) {
        const auto codebookIndex = static_cast<std::uint32_t>(sectionCodebookWindows[windowStart][band]);
        const auto lineCount = bandWidths[band];

        if (codebookIndex > 0 && codebookIndex <= 11) {
          std::uintptr_t codebookHandle = 0;
          M2AHUFFMAN_GetCodebook(static_cast<int>(codebookIndex), &codebookHandle);
          const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);
          auto* const codebookWords = reinterpret_cast<std::uint32_t*>(codebookHandle);

          for (std::uint32_t groupedOffset = 0; groupedOffset < groupedWindowCount; ++groupedOffset) {
            const auto targetWindow = windowStart + groupedOffset;
            std::int32_t decodedLines = 0;

            while (decodedLines < lineCount) {
              const auto packedValue = M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle);

              std::int32_t unpackedValues[4]{};
              std::int32_t unpackedDimension = 0;
              M2AHUFFMAN_Unpack(
                codebookWords,
                packedValue,
                unpackedValues,
                &unpackedDimension,
                context->bitstreamHandle
              );

              if (sectionCodebookWindows[targetWindow][band] == 11) {
                M2AHUFFMAN_GetEscValue(
                  static_cast<int>(reinterpret_cast<std::uintptr_t>(unpackedValues)),
                  context->bitstreamHandle
                );
              }

              auto& writeCount = spectraWriteCounts[targetWindow];
              for (std::int32_t unpackedIndex = 0; unpackedIndex < unpackedDimension; ++unpackedIndex) {
                quantizedSpectraWindows[targetWindow][writeCount] = unpackedValues[unpackedIndex];
                ++writeCount;
              }

              decodedLines += unpackedDimension;
            }
          }
        } else {
          for (std::uint32_t groupedOffset = 0; groupedOffset < groupedWindowCount; ++groupedOffset) {
            const auto targetWindow = windowStart + groupedOffset;
            auto& writeCount = spectraWriteCounts[targetWindow];
            for (std::int32_t line = 0; line < lineCount; ++line) {
              quantizedSpectraWindows[targetWindow][writeCount] = 0;
              ++writeCount;
            }
          }
        }
      }

      auto& writeCount = spectraWriteCounts[windowStart];
      while (writeCount < 128) {
        quantizedSpectraWindows[windowStart][writeCount] = 0;
        ++writeCount;
      }
    }

    m2adec_inverse_quantization(context);
    m2adec_calc_spectra8(context);
    return 0;
  }

  /**
   * Address: 0x00B251E0 (_m2adec_decode_spectra)
   *
   * What it does:
   * Runs long-window ICS spectral decode stages (section/scalefactor/pulse/tns)
   * then decodes spectral coefficients.
   */
  std::int32_t m2adec_decode_spectra(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    auto result = m2adec_get_section_data(context);
    if (result < 0) {
      return result;
    }

    result = m2adec_get_scale_factor_data(context);
    if (result < 0) {
      return result;
    }

    M2ABSR_Read(context->bitstreamHandle, 1, decodeState + 242);
    if (decodeState[242] == 1) {
      m2adec_get_pulse_data(context);
    }

    M2ABSR_Read(context->bitstreamHandle, 1, decodeState + 253);
    if (decodeState[253] == 1) {
      m2adec_get_tns_data(context);
    }

    std::int32_t gainControlPresent = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &gainControlPresent);
    if (gainControlPresent == 1 && contextWords[kM2aContextAudioObjectTypeIndex] == 2) {
      return -1;
    }

    m2adec_get_spectra_data(context);
    return 0;
  }

  /**
   * Address: 0x00B252A0 (_m2adec_decode_spectra8)
   *
   * What it does:
   * Runs short-window ICS spectral decode stages then decodes grouped-window
   * spectral coefficients.
   */
  std::int32_t m2adec_decode_spectra8(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    auto result = m2adec_get_section_data8(context);
    if (result < 0) {
      return result;
    }

    result = m2adec_get_scale_factor_data8(context);
    if (result < 0) {
      return result;
    }

    decodeState[242] = 0;
    M2ABSR_Seek(context->bitstreamHandle, 1, 1);

    M2ABSR_Read(context->bitstreamHandle, 1, decodeState + 253);
    if (decodeState[253] == 1) {
      m2adec_get_tns_data8(context);
    }

    std::int32_t gainControlPresent = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &gainControlPresent);
    if (gainControlPresent == 1 && contextWords[kM2aContextAudioObjectTypeIndex] == 2) {
      return -1;
    }

    m2adec_get_spectra_data8(context);
    return 0;
  }

  /**
   * Address: 0x00B24F90 (_m2adec_decode_ics)
   *
   * What it does:
   * Decodes one ICS element payload and dispatches long/short spectra path.
   */
  std::int32_t m2adec_decode_ics(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    const auto slotIndex = M2aGetCurrentSlotIndex(context);
    const auto groupedSlotBase = 32 * contextWords[kM2aContextWindowGroupIndex];
    const auto groupedElementSlot = groupedSlotBase + (contextWords[kM2aContextElementIndex] & 0xF);

    auto* const decodeState = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex]);
    auto* selectedIcsInfo = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + groupedElementSlot]);

    M2ABSR_Read(context->bitstreamHandle, 8, decodeState + 1);
    if (selectedIcsInfo[0] != 0) {
      decodeState[0] = contextWords[kM2aContextIcsTableBaseIndex + groupedElementSlot];
    } else {
      m2adec_get_ics_info(context);
      selectedIcsInfo = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + slotIndex]);
      decodeState[0] = M2aPtrToWord(selectedIcsInfo);
    }

    if (selectedIcsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_decode_spectra8(context);
    } else {
      m2adec_decode_spectra(context);
    }

    return 0;
  }

  /**
   * Address: 0x00B25EF0 (_m2adec_decode_pcm)
   *
   * What it does:
   * Runs post-spectral decode pipeline (MS/intensity/TNS/IMDCT) for all
   * queued element-location entries and validates channel count.
   */
  std::int32_t m2adec_decode_pcm(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    std::int32_t decodedChannelCount = 0;
    auto** const locationEntries = reinterpret_cast<M2aChannelPairLocation**>(contextWords + kM2aContextLocationEntryBaseIndex);

    for (std::int32_t entryIndex = 0; entryIndex < 128; ++entryIndex) {
      auto* const locationEntry = locationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      const auto channelClass = locationEntry->channelClass;
      if (channelClass == 0 || channelClass == 3) {
        contextWords[kM2aContextElementIndex] = locationEntry->channelPairType;
        contextWords[kM2aContextWindowGroupIndex] = locationEntry->channelClass;
        m2adec_tns_proc(context);
        m2adec_inverse_transform(context);
        ++decodedChannelCount;
        continue;
      }

      if (channelClass == 1) {
        contextWords[kM2aContextElementIndex] = locationEntry->channelPairType;
        contextWords[kM2aContextWindowGroupIndex] = locationEntry->channelClass;
        m2adec_ms_proc(context);
        m2adec_intensity_proc(context);
        m2adec_tns_proc(context);
        m2adec_inverse_transform(context);

        contextWords[kM2aContextElementIndex] += 16;
        m2adec_tns_proc(context);
        m2adec_inverse_transform(context);
        decodedChannelCount += 2;
      }
    }

    if (contextWords[kM2aContextDecodeCountInitializedIndex] != 0) {
      return contextWords[kM2aContextDecodedChannelCountIndex] == decodedChannelCount ? 0 : -1;
    }

    contextWords[kM2aContextDecodedChannelCountIndex] = decodedChannelCount;
    contextWords[kM2aContextDecodeCountInitializedIndex] = 1;
    return 0;
  }
}

