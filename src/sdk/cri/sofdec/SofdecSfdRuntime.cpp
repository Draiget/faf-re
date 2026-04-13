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

  std::int32_t sfmps_GetStmNum(
    std::int32_t workctrlAddress,
    std::int32_t* outVideoStreamIndex,
    std::int32_t* outAudioStreamIndex
  );
  std::int32_t sfmps_ChkPrepFlg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_SetMvInf(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_AdjustAvPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_SetMpsHd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfmps_SetAudioStreamType(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

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
    (void)sfmps_GetStmNum(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)),
      &videoStreamIndex,
      &audioStreamIndex
    );
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

