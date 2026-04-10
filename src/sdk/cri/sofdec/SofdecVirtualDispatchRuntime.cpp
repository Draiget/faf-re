// Extracted from SofdecRuntime.cpp for component-oriented maintenance.
// This file is included into SofdecRuntime.cpp and is not compiled as a standalone TU.

  moho::AdxrnaTimingState* SofDecVirtual1ResetTimingPool()
  {
    return ResetAdxrnaTimingPoolActiveFlags();
  }

  /**
   * Address: 0x00B20840 (func_NewAdxbObj)
   *
   * What it does:
   * Returns first free RNA timing-node pool slot by active-lane scan.
   */
  moho::AdxrnaTimingState* SofDecAcquireTimingStateSlot()
  {
    return AcquireFreeAdxrnaTimingState();
  }

  /**
   * Address: 0x00B20870 (SofDecVirt::Func4 body)
   *
   * What it does:
   * Resets one RNA timing-node runtime state lane.
   */
  std::int32_t SofDecVirtualResetTimingState(moho::AdxrnaTimingState* timingState)
  {
    std::memset(timingState, 0, sizeof(*timingState));
    timingState->activeFlag = 0;
    return 0;
  }

  /**
   * Address: 0x00B20890 (SofDecVirt1::Func3)
   *
   * What it does:
   * Acquires one RNA timing-node slot and seeds default dispatch/time lanes.
   */
  moho::AdxrnaTimingState* SofDecVirtual1CreateTimingState()
  {
    auto* const timingState = SofDecAcquireTimingStateSlot();
    timingState->dispatchTable = const_cast<void*>(static_cast<const void*>(GetSofDecVirtualDispatchTable()));
    timingState->sampleRate = 44100;
    timingState->phaseModulo = 0x4000;
    timingState->playheadSample = 0;
    timingState->latchedSample = 0;
    timingState->wrapPosition = 0;
    timingState->mode = 0;
    timingState->activeFlag = 1;
    return timingState;
  }

  /**
   * Address: 0x00B208C0 (SofDecVirt::Func4)
   *
   * What it does:
   * Thunk slot forwarding to timing-state reset helper.
   */
  std::int32_t SofDecVirtualResetStateThunk(moho::AdxrnaTimingState* timingState)
  {
    return SofDecVirtualResetTimingState(timingState);
  }

  /**
   * Address: 0x00B208D0 (SofDecVirt::Func5)
   *
   * What it does:
   * Updates current playhead sample lane from RNA clock or latched sample.
   */
  std::int32_t SofDecVirtualUpdatePlayheadSample(moho::AdxrnaTimingState* timingState)
  {
    std::int32_t micros = 0;
    if (adxrna_GetTime != nullptr) {
      micros = adxrna_GetTime();
    }

    if (timingState->mode == 1) {
      timingState->playheadSample = timingState->latchedSample;
      return timingState->playheadSample;
    }

    timingState->playheadSample = ConvertMicrosToSamples(micros, kMicrosToSamples);
    return timingState->playheadSample;
  }

  /**
   * Address: 0x00B20920 (SofDecVirt::Func6)
   *
   * What it does:
   * Captures RNA clock-derived sample lane into latched sample field.
   */
  std::int32_t SofDecVirtualCaptureLatchedSample(moho::AdxrnaTimingState* timingState)
  {
    std::int32_t micros = 0;
    if (adxrna_GetTime != nullptr) {
      micros = adxrna_GetTime();
    }

    const auto sample = ConvertMicrosToSamples(micros, kMicrosToSamples);
    timingState->latchedSample = sample;
    return sample;
  }

  /**
   * Address: 0x00B20960 (SofDecVirt::Func7)
   *
   * What it does:
   * Returns default phase-modulo lane constant.
   */
  std::int32_t SofDecVirtualGetDefaultPhaseModulo()
  {
    return 0x4000;
  }

  /**
   * Address: 0x00B20970 (SofDecVirt::Func8)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotA()
  {
  }

  /**
   * Address: 0x00B20980 (SofDecVirt::Func9)
   *
   * What it does:
   * Recomputes wrap-position lane and returns phase modulo remainder.
   */
  std::int32_t SofDecVirtualUpdateWrapPosition(moho::AdxrnaTimingState* timingState)
  {
    std::int32_t micros = 0;
    if (adxrna_GetTime != nullptr) {
      micros = adxrna_GetTime();
    }

    const auto sampleDelta = ConvertMicrosToSamples(micros, kMicrosToNegativeSamples);
    const auto wrapPosition =
      static_cast<std::uint32_t>(-timingState->playheadSample - sampleDelta);
    timingState->wrapPosition = wrapPosition;
    return static_cast<std::int32_t>(wrapPosition % timingState->phaseModulo);
  }

  /**
   * Address: 0x00B209D0 (SofDecVirt::Func10)
   *
   * What it does:
   * Sets sample-rate lane and returns assigned value.
   */
  std::int32_t SofDecVirtualSetSampleRate(moho::AdxrnaTimingState* timingState, const std::int32_t sampleRate)
  {
    timingState->sampleRate = sampleRate;
    return sampleRate;
  }

  /**
   * Address: 0x00B209E0 (SofDecVirt::Func11)
   *
   * What it does:
   * Returns current sample-rate lane.
   */
  std::int32_t SofDecVirtualGetSampleRate(const moho::AdxrnaTimingState* timingState)
  {
    return timingState->sampleRate;
  }

  /**
   * Address: 0x00B209F0 (SofDecVirt::Func12)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotB()
  {
  }

  /**
   * Address: 0x00B20A00 (SofDecVirt::Func13)
   *
   * What it does:
   * Returns constant bit-depth lane used by RNA decoder runtime.
   */
  std::int32_t SofDecVirtualGetOutputBitDepth()
  {
    return 16;
  }

  /**
   * Address: 0x00B20A10 (SofDecVirt::Func14)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotC()
  {
  }

  /**
   * Address: 0x00B20A20 (SofDecVirt::Func15)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualReturnZeroSlotD()
  {
    return 0;
  }

  /**
   * Address: 0x00B20A30 (SofDecVirt::Func16)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotE()
  {
  }

  /**
   * Address: 0x00B20A40 (SofDecVirt::Func17)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualStubReturnZeroA()
  {
    return 0;
  }

  /**
   * Address: 0x00B20A50 (SofDecVirt::Func18)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpA()
  {
  }

  /**
   * Address: 0x00B20A60 (SofDecVirt::Func19)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualStubReturnZeroB()
  {
    return 0;
  }

  /**
   * Address: 0x00B20A70 (SofDecVirt::Func20)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpB()
  {
  }

  /**
   * Address: 0x00B20A80 (SofDecVirt::Func21)
   *
   * What it does:
   * Stub virtual slot: clears both output lanes and returns first output lane.
   */
  std::int32_t* SofDecVirtualStubZeroRangeOutputs(
    std::int32_t /*self*/,
    std::int32_t /*unused*/,
    std::int32_t* outLane0,
    std::int32_t* outLane1
  )
  {
    *outLane0 = 0;
    *outLane1 = 0;
    return outLane0;
  }

  /**
   * Address: 0x00B20AA0 (SofDecVirt::Func22)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpC()
  {
  }

  /**
   * Address: 0x00B20AB0 (SofDecVirt::Func23)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpD()
  {
  }

  /**
   * Address: 0x00B20AC0 (SofDecVirt::Func24)
   *
   * What it does:
   * Stub virtual slot: returns one.
   */
  std::int32_t SofDecVirtualStubReturnOne()
  {
    return 1;
  }

  /**
   * Address: 0x00B20AD0 (SofDecVirt::Func25)
   *
   * What it does:
   * Marks `readyFlag` lane and returns zero.
   */
  std::int32_t SofDecVirtualStubSetReadyFlag(moho::SofDecVirtualStateSubobj* self)
  {
    self->readyFlag = 1;
    return 0;
  }

  /**
   * Address: 0x00B20AE0 (SofDecVirt::Func26)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualStubReturnZeroC()
  {
    return 0;
  }
