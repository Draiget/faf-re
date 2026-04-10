  /**
   * Address: 0x00B224F0 (_MPARBD_EntryErrFunc)
   *
   * What it does:
   * Installs MPARBD error callback and caller context lanes.
   */
  std::int32_t __cdecl MPARBD_EntryErrFunc(
    const std::int32_t callbackFunctionAddress,
    const std::int32_t callbackContext
  )
  {
    mparbd_err_func = reinterpret_cast<MparbdErrorCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackFunctionAddress))
    );
    mparbd_err_param = callbackContext;
    return 0;
  }

  /**
   * Address: 0x00B22510 (_mparbd_call_err_func)
   *
   * What it does:
   * Emits one MPARBD error callback when registered by the owner.
   */
  std::int32_t __cdecl mparbd_call_err_func(
    const char* functionName,
    const std::int32_t sourceLine,
    const char* message
  )
  {
    if (mparbd_err_func != nullptr) {
      mparbd_err_func(functionName, sourceLine, message, mparbd_err_param);
    }
    return 0;
  }

  /**
   * Address: 0x00B22540 (_MPARBD_SetUsrMallocFunc)
   *
   * What it does:
   * Updates MPARBD allocator callback and mirrors it into MPARBF runtime.
   */
  std::int32_t __cdecl MPARBD_SetUsrMallocFunc(const std::int32_t allocatorFunctionAddress)
  {
    mparbd_malloc_func = reinterpret_cast<MparbdUserMallocCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(allocatorFunctionAddress))
    );
    MPARBF_SetUsrMallocFunc(allocatorFunctionAddress);
    return 0;
  }

  /**
   * Address: 0x00B22560 (_MPARBD_SetUsrFreeFunc)
   *
   * What it does:
   * Updates MPARBD free callback and mirrors it into MPARBF runtime.
   */
  std::int32_t __cdecl MPARBD_SetUsrFreeFunc(const std::int32_t freeFunctionAddress)
  {
    mparbd_free_func = reinterpret_cast<MparbdUserFreeCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(freeFunctionAddress))
    );
    MPARBF_SetUsrFreeFunc(freeFunctionAddress);
    return 0;
  }

  /**
   * Address: 0x00B22580 (_MPARBD_Init)
   *
   * What it does:
   * Increments MPARBD init refcount and initializes bit-reader tables once.
   */
  std::int32_t MPARBD_Init()
  {
    if (++mparbd_init_count == 1) {
      mpabdr_Init();
    }
    return 0;
  }

  /**
   * Address: 0x00B225A0 (_MPARBD_Finish)
   *
   * What it does:
   * Decrements MPARBD init refcount and tears down active entries on last
   * release.
   */
  std::int32_t MPARBD_Finish()
  {
    if (--mparbd_init_count == 0) {
      while (mparbd_entry != nullptr) {
        mparbd_Destroy(mparbd_entry);
      }
      mpabdr_Finish();
    }
    return 0;
  }

  /**
   * Address: 0x00B225D0 (_MPARBD_Create)
   *
   * What it does:
   * Validates create output lane and dispatches to MPARBD internal allocator.
   */
  std::int32_t __cdecl MPARBD_Create(MparbdDecoderState** outDecoder)
  {
    if (outDecoder != nullptr) {
      return mparbd_Create(outDecoder);
    }

    mparbd_call_err_func(
      kMparbdCreateFunctionName,
      kMparbdCreateNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22600 (_mparbd_Create)
   *
   * What it does:
   * Allocates one MPARBD decoder state, creates its two MPARBF bit-reader
   * handles, links it into global decoder chain, and resets runtime lanes.
   */
  std::int32_t __cdecl mparbd_Create(MparbdDecoderState** outDecoder)
  {
    MparbdDecoderState* decoder = nullptr;
    auto status = mparbd_malloc_func(
      static_cast<std::int32_t>(sizeof(MparbdDecoderState)),
      reinterpret_cast<void**>(&decoder)
    );
    if (status < 0) {
      return status;
    }

    std::int32_t primaryBitReaderHandle = 0;
    status = MPARBF_Create(0x2000, &primaryBitReaderHandle);
    if (status < 0) {
      mparbd_free_func(reinterpret_cast<void**>(&decoder));
      return status;
    }

    std::int32_t secondaryBitReaderHandle = 0;
    status = MPARBF_Create(0x2000, &secondaryBitReaderHandle);
    if (status < 0) {
      MPARBF_Destroy(&primaryBitReaderHandle);
      mparbd_free_func(reinterpret_cast<void**>(&decoder));
      return status;
    }

    std::memset(decoder, 0, sizeof(MparbdDecoderState));

    if (mparbd_entry != nullptr) {
      mparbd_entry->nextNewer = decoder;
      decoder->previousOlder = mparbd_entry;
    }

    decoder->bitReaderHandlePrimary = primaryBitReaderHandle;
    decoder->bitReaderHandleSecondary = secondaryBitReaderHandle;
    mparbd_Reset(decoder);
    mparbd_entry = decoder;
    *outDecoder = decoder;
    return 0;
  }

  /**
   * Address: 0x00B22700 (_MPARBD_Destroy)
   *
   * What it does:
   * Validates MPARBD decoder pointer and dispatches to destroy routine.
   */
  std::int32_t __cdecl MPARBD_Destroy(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_Destroy(decoder);
    }

    mparbd_call_err_func(
      kMparbdDestroyFunctionName,
      kMparbdDestroyNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22730 (_mparbd_Destroy)
   *
   * What it does:
   * Unlinks one MPARBD decoder from global list, destroys MPARBF handles, and
   * releases decoder memory through registered user free callback.
   */
  std::int32_t __cdecl mparbd_Destroy(MparbdDecoderState* decoder)
  {
    auto* const nextNewer = decoder->nextNewer;
    auto* const previousOlder = decoder->previousOlder;
    auto primaryHandle = decoder->bitReaderHandlePrimary;
    auto secondaryHandle = decoder->bitReaderHandleSecondary;

    if (nextNewer != nullptr) {
      nextNewer->previousOlder = previousOlder;
    } else {
      mparbd_entry = nullptr;
    }

    if (previousOlder != nullptr) {
      previousOlder->nextNewer = nextNewer;
    }

    MPARBF_Destroy(&primaryHandle);
    MPARBF_Destroy(&secondaryHandle);

    std::memset(decoder, 0, sizeof(MparbdDecoderState));
    mparbd_free_func(reinterpret_cast<void**>(&decoder));
    return 0;
  }

  /**
   * Address: 0x00B227C0 (_MPARBD_Reset)
   *
   * What it does:
   * Validates MPARBD decoder pointer and dispatches to state reset routine.
   */
  std::int32_t __cdecl MPARBD_Reset(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_Reset(decoder);
    }

    mparbd_call_err_func(
      kMparbdResetFunctionName,
      kMparbdResetNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B227F0 (_mparbd_Reset)
   *
   * What it does:
   * Clears MPARBD frame/decode work lanes and resets both MPARBF bit-reader
   * handles to initial read positions.
   */
  std::int32_t __cdecl mparbd_Reset(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::uint32_t*>(decoder);

    for (std::size_t index = 0; index < kMparbdSyncStateCount; ++index) {
      decoderWords[kMparbdSyncStateBaseIndex + index] = 0;
    }
    decoderWords[kMparbdPendingReturnBytesIndex] = 0;

    std::memset(decoderWords + kMparbdHeaderScratchBaseIndex, 0, kMparbdHeaderScratchBytes);
    std::memset(decoderWords + kMparbdBitAllocBaseIndex, 0, kMparbdBitAllocBytes);
    std::memset(decoderWords + kMparbdScaleFactorSelectBaseIndex, 0, kMparbdScaleFactorSelectBytes);
    std::memset(decoderWords + kMparbdScaleFactorBaseIndex, 0, kMparbdScaleFactorBytes);
    std::memset(decoderWords + kMparbdDecodeTableDirectBaseIndex, 0, kMparbdDecodeTableDirectBytes);
    std::memset(decoderWords + kMparbdDecodeTableGroupedBitsBaseIndex, 0, kMparbdDecodeTableGroupedBitsBytes);
    std::memset(decoderWords + kMparbdDecodeTableGroupedBaseIndex, 0, kMparbdDecodeTableGroupedBytes);
    std::memset(decoderWords + kMparbdSampleBaseIndex, 0, kMparbdSampleBytes);
    std::memset(decoderWords + kMparbdDequantizedSampleBaseIndex, 0, kMparbdDequantizedSampleBytes);
    std::memset(decoderWords + kMparbdSynthesisHistoryBaseIndex, 0, kMparbdSynthesisHistoryBytes);
    std::memset(decoderWords + kMparbdSynthesisInputBaseIndex, 0, kMparbdSynthesisInputBytes);

    decoderWords[kMparbdSynthesisRingCursorIndex0] = 0;
    decoderWords[kMparbdSynthesisRingCursorIndex1] = 0;

    MPARBF_Reset(decoder->bitReaderHandlePrimary);
    MPARBF_Reset(decoder->bitReaderHandleSecondary);

    decoderWords[kMparbdExecErrorIndex] = 0;
    decoderWords[kMparbdSynthesisScaleCursorIndex] = 0;
    decoderWords[kMparbdPendingFrameIndex] = 0;
    return 0;
  }

  /**
   * Address: 0x00B22960 (_MPARBD_ExecHndl)
   *
   * What it does:
   * Validates MPARBD decoder pointer and dispatches one state-machine step.
   */
  std::int32_t __cdecl MPARBD_ExecHndl(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_ExecHndl(decoder);
    }

    mparbd_call_err_func(
      kMparbdExecHandleFunctionName,
      kMparbdExecHandleNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22990 (_mparbd_ExecHndl)
   *
   * What it does:
   * Executes one MPARBD decode-state transition, handling prep/header/sample/
   * end phases and reporting terminal errors.
   */
  std::int32_t __cdecl mparbd_ExecHndl(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);

    auto failWithErrorState = [&](const std::int32_t status) {
      decoderWords[kMparbdLastErrorCodeIndex] = status;
      decoderWords[kMparbdRunStateIndex] = kMparbdStateError;
      return status;
    };

    if (decoderWords[kMparbdSuspendFlagIndex] == 1) {
      return 0;
    }

    if (
      decoderWords[kMparbdRunStateIndex] == kMparbdStateStartup
      || decoderWords[kMparbdRunStateIndex] == kMparbdStateNeedMoreData
    ) {
      mparbd_start_proc(decoder);
    }

    if (decoderWords[kMparbdRunStateIndex] == kMparbdStatePrepare) {
      const auto prepareStatus = mparbd_prep_proc(decoder);
      if (prepareStatus < 0) {
        if (prepareStatus != kMparbdErrorMalformedFrame) {
          return failWithErrorState(prepareStatus);
        }

        std::uint32_t reloadedHeaderBytes = 0;
        MPARBF_ReturnData(
          decoder->bitReaderHandlePrimary,
          static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
          nullptr
        );
        MPARBF_ReadData(
          decoder->bitReaderHandlePrimary,
          reinterpret_cast<char*>(decoder) + 0x0C,
          static_cast<std::uint32_t>(kMparbdHeaderScratchBytes),
          &reloadedHeaderBytes
        );
        decoderWords[kMparbdLastErrorCodeIndex] = kMparbdErrorMalformedFrame;
        decoderWords[kMparbdSyncStateBaseIndex] = static_cast<std::int32_t>(reloadedHeaderBytes);
        decoderWords[kMparbdRunStateIndex] = kMparbdStateDecodeEnd;
      }
    } else {
      if (decoderWords[kMparbdRunStateIndex] == kMparbdStateDecodeHeader) {
        const auto decodeHeaderStatus = mparbd_dechdr_proc(decoder);
        if (decodeHeaderStatus < 0) {
          return failWithErrorState(decodeHeaderStatus);
        }
      }

      if (decoderWords[kMparbdRunStateIndex] == kMparbdStateDecodeSamples) {
        const auto decodeSampleStatus = mparbd_decsmpl_proc(decoder);
        if (decodeSampleStatus < 0) {
          return failWithErrorState(decodeSampleStatus);
        }
      }

      if (decoderWords[kMparbdRunStateIndex] != kMparbdStateDecodeEnd) {
        return 0;
      }
    }

    const auto decodeEndStatus = mparbd_decend_proc(decoder);
    if (decodeEndStatus < 0) {
      return failWithErrorState(decodeEndStatus);
    }
    return 0;
  }

  /**
   * Address: 0x00B22A80 (_mparbd_start_proc)
   *
   * What it does:
   * Advances MPARBD from idle to prepare when enough source bytes are queued,
   * or enters end-drain state after terminal supply.
   */
  std::int32_t __cdecl mparbd_start_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    std::uint32_t availableBytes = 0;
    MPARBF_GetDataSize(decoder->bitReaderHandlePrimary, &availableBytes);

    if (availableBytes >= kMparbdHeaderPrefixBytes) {
      decoderWords[kMparbdRunStateIndex] = kMparbdStatePrepare;
    } else if (decoderWords[kMparbdPendingReturnBytesIndex] == 1) {
      MPARBF_ReadData(
        decoder->bitReaderHandlePrimary,
        reinterpret_cast<char*>(decoder) + 0x0C,
        availableBytes,
        nullptr
      );
      decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;
    }

    return 0;
  }

  /**
   * Address: 0x00B22AE0 (_mparbd_prep_proc)
   *
   * What it does:
   * Reads MPA frame header/payload into decoder scratch lanes and transitions
   * to header decode when a complete frame is available.
   */
  std::int32_t __cdecl mparbd_prep_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    std::uint32_t availableBytes = 0;
    MPARBF_GetDataSize(decoder->bitReaderHandlePrimary, &availableBytes);

    if (availableBytes < kMparbdHeaderPrefixBytes) {
      if (decoderWords[kMparbdPendingReturnBytesIndex] == 1) {
        MPARBF_ReadData(
          decoder->bitReaderHandlePrimary,
          reinterpret_cast<char*>(decoder) + 0x0C,
          availableBytes,
          nullptr
        );
        decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;
      }
      return 0;
    }

    MPARBF_ReadData(
      decoder->bitReaderHandlePrimary,
      reinterpret_cast<char*>(decoder) + 0x0C,
      kMparbdHeaderPrefixBytes,
      nullptr
    );
    decoderWords[kMparbdSyncStateBaseIndex] = static_cast<std::int32_t>(kMparbdHeaderPrefixBytes);

    const auto headerStatus = mpadcd_GetHdrInfo(reinterpret_cast<std::uint32_t*>(decoder));
    if (headerStatus < 0) {
      return headerStatus;
    }

    if (decoderWords[kMparbdSuspendFlagIndex] != 0) {
      return 0;
    }

    const auto framePayloadBytes = (
      (144000u * static_cast<std::uint32_t>(decoderWords[441]))
      / static_cast<std::uint32_t>(decoderWords[442])
    ) + static_cast<std::uint32_t>(decoderWords[443]) - kMparbdHeaderPrefixBytes;

    MPARBF_GetDataSize(decoder->bitReaderHandlePrimary, &availableBytes);
    if (availableBytes >= framePayloadBytes && framePayloadBytes >= kMparbdMinimumFramePayloadBytes) {
      MPARBF_ReadData(
        decoder->bitReaderHandlePrimary,
        reinterpret_cast<char*>(decoder) + 0x10,
        framePayloadBytes,
        nullptr
      );
      decoderWords[kMparbdRunStateIndex] = kMparbdStateDecodeHeader;
      decoderWords[kMparbdSyncStateBaseIndex] += static_cast<std::int32_t>(framePayloadBytes);
      return 0;
    }

    if (decoderWords[kMparbdPendingReturnBytesIndex] != 0) {
      decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;
    } else {
      MPARBF_ReturnData(
        decoder->bitReaderHandlePrimary,
        kMparbdHeaderPrefixBytes,
        nullptr
      );
      decoderWords[kMparbdSyncStateBaseIndex] = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00B22C10 (_mparbd_dechdr_proc)
   *
   * What it does:
   * Runs bit-allocation/scalefactor/header decode passes and enters sample
   * decode phase.
   */
  std::int32_t __cdecl mparbd_dechdr_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::uint32_t*>(decoder);
    mpadcd_GetBitAllocInfo(decoderWords);
    mpadcd_GetScfInfo(decoderWords);
    mpadcd_GetSmpl(decoderWords);
    mpadcd_DequantizeSmpl(decoderWords);
    mpadcd_GetPcmSmpl(decoderWords);
    decoderWords[kMparbdRunStateIndex] = static_cast<std::uint32_t>(kMparbdStateDecodeSamples);
    return 0;
  }

  /**
   * Address: 0x00B22C40 (_mparbd_decsmpl_proc)
   *
   * What it does:
   * Streams decoded sample blocks into output ring buffer and verifies frame
   * terminus bounds before entering end phase.
   */
  std::int32_t __cdecl mparbd_decsmpl_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    const auto primaryBitReaderHandle = decoder->bitReaderHandlePrimary;
    const auto secondaryBitReaderHandle = decoder->bitReaderHandleSecondary;
    const auto requiredOutputBytes =
      kMparbdSamplesPerFrameBlock * static_cast<std::uint32_t>(decoderWords[445]);

    if (decoderWords[kMparbdPendingReloadFlagIndex] != 0) {
      MPARBF_ReadData(
        primaryBitReaderHandle,
        reinterpret_cast<char*>(decoder) + 0x0C,
        static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
        nullptr
      );
      decoderWords[kMparbdPendingReloadFlagIndex] = 0;
    }

    std::uint32_t freeBytes = 0;
    MPARBF_GetFreeSize(secondaryBitReaderHandle, &freeBytes);
    if (freeBytes < requiredOutputBytes) {
      MPARBF_ReturnData(
        primaryBitReaderHandle,
        static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
        nullptr
      );
      decoderWords[kMparbdPendingReloadFlagIndex] = 1;
      return 0;
    }

    while (true) {
      MPARBF_GetFreeSize(secondaryBitReaderHandle, &freeBytes);
      auto writeBytes = freeBytes;
      if (freeBytes >= requiredOutputBytes) {
        writeBytes = requiredOutputBytes;
      }

      MPARBF_WriteData(
        secondaryBitReaderHandle,
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoderWords + kMparbdSynthesisHistoryBaseIndex)),
        writeBytes,
        nullptr
      );

      const auto decodedBlockCount = static_cast<std::uint32_t>(++decoderWords[kMparbdSynthesisScaleCursorIndex]);
      if (decodedBlockCount >= kMparbdDecodeBlocksPerFrame) {
        break;
      }

      auto* const decodeState = reinterpret_cast<std::uint32_t*>(decoder);
      mpadcd_GetSmpl(decodeState);
      mpadcd_DequantizeSmpl(decodeState);
      mpadcd_GetPcmSmpl(decodeState);

      MPARBF_GetFreeSize(secondaryBitReaderHandle, &freeBytes);
      if (freeBytes < requiredOutputBytes) {
        MPARBF_ReturnData(
          primaryBitReaderHandle,
          static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
          nullptr
        );
        decoderWords[kMparbdPendingReloadFlagIndex] = 1;
        return 0;
      }
    }

    if (decoderWords[438] <= decoderWords[kMparbdSyncStateBaseIndex]) {
      decoderWords[kMparbdRunStateIndex] = kMparbdStateDecodeEnd;
      return 0;
    }

    mparbd_call_err_func(
      kMparbdDecodeSamplesProcFunctionName,
      kMparbdDecodeSamplesOverrunLine,
      kMparbdDecodeSamplesOverrunMessage
    );
    return kMparbdErrorSampleOverrun;
  }

  /**
   * Address: 0x00B22D80 (_mparbd_decend_proc)
   *
   * What it does:
   * Finalizes one decoded frame, returns unread source bytes, and updates
   * frame completion counters/end status.
   */
  std::int32_t __cdecl mparbd_decend_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);

    mpadcd_SkipToNextFrm(reinterpret_cast<std::uint32_t*>(decoder));
    MPARBF_ReturnData(
      decoder->bitReaderHandlePrimary,
      static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex] - decoderWords[438]),
      nullptr
    );

    const auto previousErrorCode = decoderWords[kMparbdLastErrorCodeIndex];
    decoderWords[kMparbdExecErrorIndex] += decoderWords[438];
    decoderWords[kMparbdSynthesisScaleCursorIndex] = 0;
    decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;

    if (previousErrorCode != 0) {
      decoderWords[kMparbdLastErrorCodeIndex] = 0;
    } else {
      ++decoderWords[kMparbdPendingFrameIndex];
    }

    return 0;
  }

  /**
   * Address: 0x00B22E00 (_MPARBD_GetDecStat)
   *
   * What it does:
   * Returns current MPARBD decode state machine status lane.
   */
  std::int32_t __cdecl MPARBD_GetDecStat(MparbdDecoderState* decoder, std::int32_t* outDecodeState)
  {
    if (decoder != nullptr && outDecodeState != nullptr) {
      *outDecodeState = *reinterpret_cast<std::int32_t*>(decoder);
      return 0;
    }

    mparbd_call_err_func(
      kMparbdGetDecodeStatusFunctionName,
      kMparbdGetDecodeStatusNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22E50 (_MPARBD_GetEndStat)
   *
   * What it does:
   * Returns MPARBD end-state lane used by caller-driven stream completion.
   */
  std::int32_t __cdecl MPARBD_GetEndStat(MparbdDecoderState* decoder, std::int32_t* outEndState)
  {
    if (decoder != nullptr && outEndState != nullptr) {
      *outEndState = reinterpret_cast<std::int32_t*>(decoder)[kMparbdSuspendFlagIndex];
      return 0;
    }

    mparbd_call_err_func(
      kMparbfGetEndStatusFunctionName,
      kMparbfGetEndStatusNullPointerLine,
      kMparbdNullPointerSentenceCaseMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22EA0 (_MPARBD_SetEndStat)
   *
   * What it does:
   * Updates MPARBD end-state lane for external stream completion control.
   */
  std::int32_t __cdecl MPARBD_SetEndStat(MparbdDecoderState* decoder, const std::int32_t endState)
  {
    if (decoder != nullptr) {
      reinterpret_cast<std::int32_t*>(decoder)[kMparbdSuspendFlagIndex] = endState;
      return 0;
    }

    mparbd_call_err_func(
      kMparbfGetEndStatusFunctionName,
      kMparbfSetEndStatusNullPointerLine,
      kMparbdNullPointerSentenceCaseMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22EE0 (_MPARBD_GetNumSmplDcd)
   *
   * What it does:
   * Validates output lanes and returns decoded frame/block counters.
   */
  std::int32_t __cdecl MPARBD_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  )
  {
    if (decoder != nullptr && outDecodedFrameCount != nullptr && outDecodedBlockCount != nullptr) {
      return mparbd_GetNumSmplDcd(decoder, outDecodedFrameCount, outDecodedBlockCount);
    }

    mparbd_call_err_func(
      kMparbdGetNumSamplesDecodedFunctionName,
      kMparbdGetNumSamplesDecodedNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22F30 (_mparbd_GetNumSmplDcd)
   *
   * What it does:
   * Returns total decoded-frame count and current decoded-block count.
   */
  std::int32_t __cdecl mparbd_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  )
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    *outDecodedFrameCount = decoderWords[kMparbdDecodedFrameCountIndex];
    *outDecodedBlockCount = decoderWords[kMparbdDecodedBlockCountIndex];
    return 0;
  }

  /**
   * Address: 0x00B22F50 (_MPARBD_GetNumByteDcd)
   *
   * What it does:
   * Returns accumulated decoded byte count from MPARBD state.
   */
  std::int32_t __cdecl MPARBD_GetNumByteDcd(MparbdDecoderState* decoder, std::int32_t* outDecodedBytes)
  {
    if (decoder != nullptr && outDecodedBytes != nullptr) {
      *outDecodedBytes = reinterpret_cast<std::int32_t*>(decoder)[kMparbdDecodedByteCountIndex];
      return 0;
    }

    mparbd_call_err_func(
      kMparbdGetNumBytesDecodedFunctionName,
      kMparbdGetNumBytesDecodedNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22FB0 (_MPARBD_GetSfreq)
   *
   * What it does:
   * Returns decoded sample-rate only after at least one frame/block has been
   * produced.
   */
  std::int32_t __cdecl MPARBD_GetSfreq(MparbdDecoderState* decoder, std::int32_t* outSampleRate)
  {
    if (decoder == nullptr || outSampleRate == nullptr) {
      mparbd_call_err_func(
        kMparbdGetSampleRateFunctionName,
        kMparbdGetSampleRateNullPointerLine,
        kMparbdNullPointerMessage
      );
      return -1;
    }

    std::int32_t decodedFrameCount = 0;
    std::int32_t decodedBlockCount = 0;
    mparbd_GetNumSmplDcd(decoder, &decodedFrameCount, &decodedBlockCount);
    if (decodedFrameCount != 0 || decodedBlockCount != 0) {
      *outSampleRate = reinterpret_cast<std::int32_t*>(decoder)[kMparbdSampleRateIndex];
      return 0;
    }

    *outSampleRate = 0;
    return kMparbdErrorNoDecodedSamples;
  }

  /**
   * Address: 0x00B23040 (_MPARBD_GetNumChannel)
   *
   * What it does:
   * Validates channel-count output lane and dispatches to internal getter.
   */
  std::int32_t __cdecl MPARBD_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount)
  {
    if (decoder != nullptr && outChannelCount != nullptr) {
      return mparbd_GetNumChannel(decoder, outChannelCount);
    }

    mparbd_call_err_func(
      kMparbdGetNumChannelFunctionName,
      kMparbdGetNumChannelNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B23080 (_mparbd_GetNumChannel)
   *
   * What it does:
   * Returns decoded channel count once decode progress counters are non-zero.
   */
  std::int32_t __cdecl mparbd_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount)
  {
    std::int32_t decodedFrameCount = 0;
    std::int32_t decodedBlockCount = 0;
    mparbd_GetNumSmplDcd(decoder, &decodedFrameCount, &decodedBlockCount);
    if (decodedFrameCount != 0 || decodedBlockCount != 0) {
      *outChannelCount = reinterpret_cast<std::int32_t*>(decoder)[kMparbdChannelCountIndex];
      return 0;
    }

    *outChannelCount = 0;
    return kMparbdErrorNoDecodedSamples;
  }

  /**
   * Address: 0x00B230D0 (_MPARBD_GetNumBit)
   *
   * What it does:
   * Validates output lane and returns fixed PCM output bit depth.
   */
  std::int32_t __cdecl MPARBD_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample)
  {
    if (decoder != nullptr && outBitsPerSample != nullptr) {
      return mparbd_GetNumBit(decoder, outBitsPerSample);
    }

    mparbd_call_err_func(
      kMparbdGetNumBitFunctionName,
      kMparbdGetNumBitNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B23110 (_mparbd_GetNumBit)
   *
   * What it does:
   * Returns fixed 16-bit PCM output depth for MPARBD decode path.
   */
  std::int32_t __cdecl mparbd_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample)
  {
    (void)decoder;
    *outBitsPerSample = kMparbdBitsPerSample;
    return 0;
  }

  /**
   * Address: 0x00B23120 (_MPARBD_TermSupply)
   *
   * What it does:
   * Marks decoder input supply as terminated so partial frame drain is
   * permitted.
   */
  std::int32_t __cdecl MPARBD_TermSupply(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_TermSupply(decoder);
    }

    mparbd_call_err_func(
      kMpardTermSupplyFunctionName,
      kMpardTermSupplyNullPointerLine,
      kMparbdNullPointerSentenceCaseMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B23150 (_mparbd_TermSupply)
   *
   * What it does:
   * Sets terminal-supply latch consumed by start/prep states.
   */
  std::int32_t __cdecl mparbd_TermSupply(MparbdDecoderState* decoder)
  {
    reinterpret_cast<std::int32_t*>(decoder)[kMparbdPendingReturnBytesIndex] = 1;
    return 0;
  }

  /**
   * Address: 0x00B23170 (_MPARBF_SetUsrMallocFunc)
   *
   * What it does:
   * Updates MPARBF user allocation callback pointer.
   */
  std::int32_t __cdecl MPARBF_SetUsrMallocFunc(const std::int32_t allocatorFunctionAddress)
  {
    mparbf_malloc_func = reinterpret_cast<MparbdUserMallocCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(allocatorFunctionAddress))
    );
    return 0;
  }

  /**
   * Address: 0x00B23180 (_MPARBF_SetUsrFreeFunc)
   *
   * What it does:
   * Updates MPARBF user free callback pointer.
   */
  std::int32_t __cdecl MPARBF_SetUsrFreeFunc(const std::int32_t freeFunctionAddress)
  {
    mparbf_free_func = reinterpret_cast<MparbdUserFreeCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(freeFunctionAddress))
    );
    return 0;
  }

  /**
   * Address: 0x00B23190 (_MPARBF_Create)
   *
   * What it does:
   * Allocates one MPARBF ring-buffer object and backing byte storage.
   */
  std::int32_t __cdecl MPARBF_Create(const std::int32_t bufferBytes, std::int32_t* outHandle)
  {
    MparbfRuntimeBuffer* ringBuffer = nullptr;
    auto status = mparbf_malloc_func(
      static_cast<std::int32_t>(sizeof(MparbfRuntimeBuffer)),
      reinterpret_cast<void**>(&ringBuffer)
    );
    if (status < 0) {
      return status;
    }

    std::memset(ringBuffer, 0, sizeof(MparbfRuntimeBuffer));

    std::uint8_t* storage = nullptr;
    status = mparbf_malloc_func(bufferBytes, reinterpret_cast<void**>(&storage));
    if (status < 0) {
      mparbf_free_func(reinterpret_cast<void**>(&ringBuffer));
      return status;
    }

    ringBuffer->capacityBytes = static_cast<std::uint32_t>(bufferBytes);
    ringBuffer->data = storage;
    MPARBF_Reset(
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ringBuffer)))
    );

    *outHandle = static_cast<std::int32_t>(
      static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ringBuffer))
    );
    return 0;
  }

  /**
   * Address: 0x00B23220 (_MPARBF_Destroy)
   *
   * What it does:
   * Clears and releases MPARBF ring-buffer storage and object instance.
   */
  std::int32_t __cdecl MPARBF_Destroy(std::int32_t* handleAddress)
  {
    auto* ringBuffer = AsMparbfRuntimeBuffer(*handleAddress);
    void* storageAddress = ringBuffer->data;
    std::memset(storageAddress, 0, ringBuffer->capacityBytes);
    mparbf_free_func(&storageAddress);

    std::memset(ringBuffer, 0, sizeof(MparbfRuntimeBuffer));
    void* ringBufferAddress = ringBuffer;
    mparbf_free_func(&ringBufferAddress);
    *handleAddress = 0;
    return 0;
  }

  /**
   * Address: 0x00B23280 (_MPARBF_Reset)
   *
   * What it does:
   * Clears ring-buffer bytes and resets all cursor/size lanes.
   */
  std::int32_t __cdecl MPARBF_Reset(const std::int32_t handleAddress)
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);
    std::memset(ringBuffer->data, 0, ringBuffer->capacityBytes);
    ringBuffer->readOffsetBytes = 0;
    ringBuffer->dataBytes = 0;
    ringBuffer->writeOffsetBytes = 0;
    ringBuffer->freeBytes = ringBuffer->capacityBytes;
    return 0;
  }

  /**
   * Address: 0x00B232C0 (_MPARBF_GetDataSize)
   *
   * What it does:
   * Returns currently queued byte count in MPARBF ring-buffer.
   */
  std::int32_t __cdecl MPARBF_GetDataSize(const std::int32_t handleAddress, std::uint32_t* outDataBytes)
  {
    *outDataBytes = AsMparbfRuntimeBuffer(handleAddress)->dataBytes;
    return 0;
  }

  /**
   * Address: 0x00B232D0 (_MPARBF_GetFreeSize)
   *
   * What it does:
   * Returns currently free byte capacity in MPARBF ring-buffer.
   */
  std::int32_t __cdecl MPARBF_GetFreeSize(const std::int32_t handleAddress, std::uint32_t* outFreeBytes)
  {
    *outFreeBytes = AsMparbfRuntimeBuffer(handleAddress)->freeBytes;
    return 0;
  }

  /**
   * Address: 0x00B232E0 (_MPARBF_ReadData)
   *
   * What it does:
   * Reads up to requested bytes from ring-buffer and advances read cursor.
   */
  std::int32_t __cdecl MPARBF_ReadData(
    const std::int32_t handleAddress,
    char* destinationBytes,
    const std::uint32_t byteCount,
    std::uint32_t* outReadBytes
  )
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);

    std::uint32_t availableBytes = 0;
    MPARBF_GetDataSize(handleAddress, &availableBytes);
    const auto readBytes = (availableBytes < byteCount) ? availableBytes : byteCount;

    const auto readOffset = ringBuffer->readOffsetBytes;
    const auto capacity = ringBuffer->capacityBytes;
    const auto endOffset = readOffset + readBytes;

    std::uint32_t firstChunkBytes = readBytes;
    std::uint32_t wrapChunkBytes = 0;
    if (endOffset > capacity) {
      firstChunkBytes = capacity - readOffset;
      wrapChunkBytes = endOffset - capacity;
    }

    std::memcpy(destinationBytes, ringBuffer->data + readOffset, firstChunkBytes);
    std::memcpy(destinationBytes + firstChunkBytes, ringBuffer->data, wrapChunkBytes);

    ringBuffer->dataBytes -= readBytes;
    ringBuffer->freeBytes += readBytes;
    ringBuffer->readOffsetBytes = (capacity == 0) ? 0 : (endOffset % capacity);
    if (outReadBytes != nullptr) {
      *outReadBytes = readBytes;
    }
    return 0;
  }

  /**
   * Address: 0x00B233A0 (_MPARBF_WriteData)
   *
   * What it does:
   * Writes up to available free bytes into ring-buffer and advances write
   * cursor.
   */
  std::int32_t __cdecl MPARBF_WriteData(
    const std::int32_t handleAddress,
    const std::int32_t sourceAddress,
    const std::uint32_t byteCount,
    std::uint32_t* outWrittenBytes
  )
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);
    const auto* const sourceBytes = reinterpret_cast<const std::uint8_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceAddress))
    );

    std::uint32_t freeBytes = 0;
    MPARBF_GetFreeSize(handleAddress, &freeBytes);
    const auto writeBytes = (freeBytes < byteCount) ? freeBytes : byteCount;

    const auto writeOffset = ringBuffer->writeOffsetBytes;
    const auto capacity = ringBuffer->capacityBytes;
    const auto endOffset = writeOffset + writeBytes;

    std::uint32_t firstChunkBytes = writeBytes;
    std::uint32_t wrapChunkBytes = 0;
    if (endOffset > capacity) {
      firstChunkBytes = capacity - writeOffset;
      wrapChunkBytes = endOffset - capacity;
    }

    std::memcpy(ringBuffer->data + writeOffset, sourceBytes, firstChunkBytes);
    std::memcpy(ringBuffer->data, sourceBytes + firstChunkBytes, wrapChunkBytes);

    ringBuffer->dataBytes += writeBytes;
    ringBuffer->freeBytes -= writeBytes;
    ringBuffer->writeOffsetBytes = (capacity == 0) ? 0 : (endOffset % capacity);
    if (outWrittenBytes != nullptr) {
      *outWrittenBytes = writeBytes;
    }
    return 0;
  }

  /**
   * Address: 0x00B23460 (_MPARBF_ReturnData)
   *
   * What it does:
   * Returns consumed bytes back to ring-buffer by rewinding read cursor.
   */
  std::int32_t __cdecl MPARBF_ReturnData(
    const std::int32_t handleAddress,
    const std::uint32_t returnBytes,
    std::uint32_t* outReturnedBytes
  )
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);

    std::uint32_t freeBytes = 0;
    MPARBF_GetFreeSize(handleAddress, &freeBytes);
    const auto rewoundBytes = (freeBytes < returnBytes) ? freeBytes : returnBytes;

    const auto capacity = ringBuffer->capacityBytes;
    std::uint32_t newReadOffset = capacity + ringBuffer->readOffsetBytes - rewoundBytes;
    if (newReadOffset > capacity) {
      newReadOffset = ringBuffer->readOffsetBytes - rewoundBytes;
    }

    ringBuffer->readOffsetBytes = newReadOffset;
    ringBuffer->freeBytes -= rewoundBytes;
    ringBuffer->dataBytes += rewoundBytes;

    if (outReturnedBytes != nullptr) {
      *outReturnedBytes = rewoundBytes;
    }
    return 0;
  }

